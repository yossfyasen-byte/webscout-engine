"""Transport: async HTTP client, rate limiter, soft-404 detection and cancellation."""

from __future__ import annotations

import asyncio
import hashlib
import time
from typing import Any
from urllib.parse import urljoin
import aiohttp
from pydantic import BaseModel, Field
from .events import EventBus, EventType
from .models import HttpResult
from .scope import Scope
import difflib
import random
import string
from dataclasses import dataclass, field


# -------------------------------------------------------------------------
# from http.py
# -------------------------------------------------------------------------

RETRY_STATUS = {408, 425, 429, 500, 502, 503, 504}
TEXT_CONTENT_TYPES = (
    "text/",
    "application/json",
    "application/xml",
    "application/javascript",
    "application/x-javascript",
    "application/x-www-form-urlencoded",
    "application/ld+json",
    "image/svg+xml",
)


class BudgetExceeded(Exception):
    """Raised when the configured request budget is exhausted."""


class HttpConfig(BaseModel):
    timeout: float = 10.0
    connect_timeout: float = 5.0
    max_body: int = 262_144
    retries: int = 2
    retry_backoff: float = 0.4
    max_redirects: int = 5
    max_requests: int = 20_000
    verify_tls: bool = True
    follow_redirects: bool = True
    user_agent: str = "webscout_engine/1.0 (authorized security assessment)"
    extra_headers: dict[str, str] = Field(default_factory=dict)


class ResponseDeduper:
    """Suppresses byte-identical responses (common with wildcard vhosts)."""

    def __init__(self) -> None:
        self._seen: dict[str, int] = {}

    @staticmethod
    def fingerprint(result: HttpResult) -> str:
        material = "\n".join(
            [
                str(result.status),
                result.content_type,
                str(result.body_length),
                " ".join(result.body[:1500].split()),
            ]
        )
        return hashlib.sha1(material.encode("utf-8", "replace")).hexdigest()

    def is_duplicate(self, result: HttpResult, key: str = "") -> bool:
        digest = self.fingerprint(result)
        if key:
            digest = f"{key}:{digest}"
        if digest in self._seen:
            return True
        self._seen[digest] = 1
        return False

    def reset(self) -> None:
        self._seen.clear()


class AsyncHttpClient:
    def __init__(
        self,
        scope: Scope,
        limiter: RateLimiter,
        config: HttpConfig | None = None,
        state: Any = None,
        bus: EventBus | None = None,
        cancel: CancellationToken | None = None,
    ) -> None:
        self.scope = scope
        self.limiter = limiter
        self.config = config or HttpConfig()
        self.state = state
        self.bus = bus
        self.cancel = cancel or CancellationToken()
        self.deduper = ResponseDeduper()
        self._session: aiohttp.ClientSession | None = None
        self._request_count = 0
        self.blocked_count = 0

    # --------------------------------------------------------------- lifecycle
    async def start(self) -> None:
        if self._session is not None and not self._session.closed:
            return
        timeout = aiohttp.ClientTimeout(
            total=self.config.timeout,
            connect=self.config.connect_timeout,
            sock_read=self.config.timeout,
        )
        connector_kwargs: dict[str, Any] = {
            "limit": 100,
            "limit_per_host": 30,
            "ttl_dns_cache": 120,
            "enable_cleanup_closed": True,
        }
        if not self.config.verify_tls:
            connector_kwargs["ssl"] = False
        connector = aiohttp.TCPConnector(**connector_kwargs)
        self._session = aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            headers={"User-Agent": self.config.user_agent, **self.config.extra_headers},
            trust_env=False,
        )

    async def close(self) -> None:
        if self._session is not None and not self._session.closed:
            await self._session.close()
            await asyncio.sleep(0.05)
        self._session = None

    async def __aenter__(self) -> AsyncHttpClient:
        await self.start()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()

    @property
    def request_count(self) -> int:
        return self._request_count

    # ------------------------------------------------------------------ public
    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        data: Any = None,
        allow_redirects: bool | None = None,
        max_body: int | None = None,
        retries: int | None = None,
    ) -> HttpResult:
        method = method.upper()
        follow = self.config.follow_redirects if allow_redirects is None else allow_redirects
        body_limit = max_body if max_body is not None else self.config.max_body
        attempts = self.config.retries if retries is None else retries

        if self.cancel.is_cancelled:
            raise ScanCancelled(self.cancel.reason or "cancelled")

        decision = await self.scope.ensure_allowed(url)
        if not decision.allowed:
            self.blocked_count += 1
            if self.state is not None:
                self.state.blocked_requests += 1
            if self.bus is not None:
                await self.bus.emit(
                    EventType.WARNING,
                    f"Blocked out-of-scope request: {url}",
                    {"reason": decision.reason, "url": url},
                    level="warning",
                )
            return HttpResult(url=url, error=f"blocked by scope: {decision.reason}", error_kind="scope")

        chain: list[str] = []
        current_url = url
        current_method = method
        current_data = data
        result = HttpResult(url=url)
        hops = self.scope.max_redirects if follow else 0

        for hop in range(hops + 1):
            self.cancel.raise_if_cancelled()
            if hop > 0:
                decision = await self.scope.ensure_allowed(current_url)
                if not decision.allowed:
                    self.blocked_count += 1
                    result.error = f"redirect blocked by scope: {decision.reason}"
                    result.error_kind = "scope"
                    break
            result = await self._fetch_with_retries(
                current_method, current_url, headers, current_data, body_limit, attempts
            )
            chain.append(current_url)
            if not (follow and result.is_redirect):
                break
            location = result.header("location")
            if not location:
                break
            next_url = urljoin(current_url, location)
            if next_url in chain:
                result.error = "redirect loop detected"
                result.error_kind = "redirect_loop"
                break
            if hop == hops:
                result.error = f"redirect limit reached ({hops})"
                result.error_kind = "redirect_limit"
                break
            if result.status in (301, 302, 303):
                current_method = "GET" if current_method != "HEAD" else "HEAD"
                current_data = None
            current_url = next_url

        result.url = url
        result.final_url = chain[-1] if chain else url
        result.redirect_chain = chain if len(chain) > 1 else []
        return result

    async def get(self, url: str, **kwargs: Any) -> HttpResult:
        return await self.request("GET", url, **kwargs)

    async def head(self, url: str, **kwargs: Any) -> HttpResult:
        return await self.request("HEAD", url, **kwargs)

    async def options(self, url: str, **kwargs: Any) -> HttpResult:
        return await self.request("OPTIONS", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> HttpResult:
        return await self.request("POST", url, **kwargs)

    # ----------------------------------------------------------------- internal
    async def _fetch_with_retries(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None,
        data: Any,
        max_body: int,
        attempts: int,
    ) -> HttpResult:
        last: HttpResult | None = None
        for attempt in range(1, attempts + 2):
            if self._request_count >= self.config.max_requests:
                raise BudgetExceeded(
                    f"request budget of {self.config.max_requests} exhausted"
                )
            self.cancel.raise_if_cancelled()
            await self.limiter.acquire()
            result = await self._attempt(method, url, headers, data, max_body)
            result.attempts = attempt
            self._request_count += 1
            last = result
            self._record(result)

            retryable = result.status in RETRY_STATUS or result.error_kind == "network"
            if result.error_kind == "timeout":
                retryable = True
            if not retryable or attempt > attempts:
                if result.status == 429 or result.status == 503:
                    self.limiter.record_throttle(pause_seconds=min(5.0, 1.0 * attempt))
                return result

            if self.state is not None:
                self.state.record_retry()
            if result.status in (429, 503):
                self.limiter.record_throttle(pause_seconds=min(5.0, 0.8 * attempt))
            delay = self.config.retry_backoff * (2 ** (attempt - 1))
            await self.cancel.sleep(delay)
        return last or HttpResult(url=url, error="request failed", error_kind="network")

    async def _attempt(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None,
        data: Any,
        max_body: int,
    ) -> HttpResult:
        await self.start()
        assert self._session is not None
        started = time.perf_counter()
        result = HttpResult(url=url)
        try:
            async with self._session.request(
                method, url, headers=headers, data=data, allow_redirects=False
            ) as response:
                result.status = response.status
                result.reason = response.reason or ""
                result.headers = {k.lower(): v for k, v in response.headers.items()}
                set_cookies = response.headers.getall("set-cookie", [])
                if set_cookies:
                    result.headers["set-cookie"] = "\n".join(set_cookies)
                result.content_type = result.headers.get("content-type", "")
                payload = b""
                if method != "HEAD":
                    payload = await response.content.read(max_body + 1)
                    if len(payload) > max_body:
                        result.truncated = True
                        payload = payload[:max_body]
                result.body_length = len(payload)
                if self.state is not None:
                    self.state.record_bytes(len(payload))
                result.body = self._decode(payload, result.content_type)
        except TimeoutError:
            result.error = "timeout"
            result.error_kind = "timeout"
        except aiohttp.ClientError as exc:
            result.error = f"{type(exc).__name__}: {exc}"
            result.error_kind = "network"
        except (OSError, ValueError) as exc:
            result.error = f"{type(exc).__name__}: {exc}"
            result.error_kind = "network"
        result.elapsed = time.perf_counter() - started
        if self.state is not None:
            self.state.record_probe(method, url, result.status or 0, result.elapsed)
        return result

    @staticmethod
    def _decode(payload: bytes, content_type: str) -> str:
        lowered = (content_type or "").lower()
        if not payload:
            return ""
        if lowered and not any(token in lowered for token in TEXT_CONTENT_TYPES):
            return ""
        charset = "utf-8"
        if "charset=" in lowered:
            charset = lowered.split("charset=", 1)[1].split(";")[0].strip() or "utf-8"
        try:
            return payload.decode(charset, errors="replace")
        except LookupError:
            return payload.decode("utf-8", errors="replace")

    def _record(self, result: HttpResult) -> None:
        if self.state is None:
            return
        self.state.record_request(result.status if result.status else None)
        if result.error_kind == "timeout":
            self.state.record_timeout()
        elif result.error:
            self.state.record_error()
        elif result.status and result.status not in RETRY_STATUS:
            self.limiter.record_success()


# -------------------------------------------------------------------------
# from ratelimit.py
# -------------------------------------------------------------------------

class RateLimiter:
    def __init__(self, rate: float, burst: int | None = None) -> None:
        self.base_rate = max(float(rate), 0.1)
        self.rate = self.base_rate
        self.capacity = max(1, int(burst if burst is not None else max(1, round(self.base_rate))))
        self._tokens = float(self.capacity)
        self._updated = time.monotonic()
        self._paused_until = 0.0
        self._lock = asyncio.Lock()
        self.acquired = 0
        self.throttle_events = 0

    # ------------------------------------------------------------------ core
    def _refill(self, now: float) -> None:
        elapsed = max(0.0, now - self._updated)
        self._updated = now
        self._tokens = min(float(self.capacity), self._tokens + elapsed * self.rate)

    async def acquire(self) -> None:
        while True:
            async with self._lock:
                now = time.monotonic()
                if now < self._paused_until:
                    wait = self._paused_until - now
                else:
                    self._refill(now)
                    if self._tokens >= 1.0:
                        self._tokens -= 1.0
                        self.acquired += 1
                        return
                    wait = (1.0 - self._tokens) / self.rate
            await asyncio.sleep(min(max(wait, 0.001), 1.0))

    # ------------------------------------------------------------- adaptation
    def pause(self, seconds: float) -> None:
        self._paused_until = max(self._paused_until, time.monotonic() + max(0.0, seconds))

    def record_throttle(self, pause_seconds: float = 1.0) -> None:
        """Called on 429/503: slow down and briefly pause."""
        self.throttle_events += 1
        self.rate = max(0.5, self.rate * 0.5)
        self.capacity = max(1, int(round(self.capacity * 0.5)))
        self._tokens = 0.0
        self._updated = time.monotonic()
        self.pause(pause_seconds)

    def record_success(self) -> None:
        """Gradually return to the configured rate after throttling."""
        if self.rate < self.base_rate:
            self.rate = min(self.base_rate, self.rate * 1.05)
            self.capacity = max(1, int(round(self.rate)))

    def set_rate(self, rate: float) -> None:
        self.base_rate = max(0.1, float(rate))
        self.rate = self.base_rate
        self.capacity = max(1, int(round(self.base_rate)))

    @property
    def effective_rate(self) -> float:
        return self.rate


# -------------------------------------------------------------------------
# from soft404.py
# -------------------------------------------------------------------------

@dataclass(slots=True)
class Soft404Verdict:
    is_soft: bool
    reason: str = ""
    similarity: float = 0.0


@dataclass(slots=True)
class Baseline:
    calibrated: bool = False
    statuses: set[int] = field(default_factory=set)
    mean_length: float = 0.0
    bodies: list[str] = field(default_factory=list)
    samples: int = 0
    uniform: bool = False

    def describe(self) -> str:
        if not self.calibrated:
            return "not calibrated"
        statuses = ",".join(str(s) for s in sorted(self.statuses)) or "none"
        return f"statuses={statuses} mean_length={self.mean_length:.0f} samples={self.samples}"


def _random_token(length: int = 12) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


def _normalise(body: str, token: str) -> str:
    text = " ".join(body.split())
    if token:
        text = text.replace(token, "TOKEN")
    return text[:3000]


class Soft404Detector:
    """Calibrate once per host, then classify responses."""

    def __init__(
        self,
        client: object,
        base_url: str,
        samples: int = 3,
        length_tolerance: float = 0.05,
        similarity_threshold: float = 0.95,
        token: str = "",
    ) -> None:
        self.client = client
        self.base_url = base_url
        self.samples = samples
        self.length_tolerance = length_tolerance
        self.similarity_threshold = similarity_threshold
        self.token = token or _random_token()
        self.baseline = Baseline()
        self._calibration_results: list[HttpResult] = []

    async def calibrate(self) -> Baseline:
        """Request random paths and derive a baseline. Never raises."""
        bodies: list[str] = []
        lengths: list[int] = []
        statuses: set[int] = set()
        for index in range(self.samples):
            path = f"{self.token}-{index}-{_random_token(8)}"
            url = self.base_url.rstrip("/") + "/" + path
            try:
                result = await self.client.get(url, allow_redirects=False)  # type: ignore[attr-defined]
            except Exception:
                continue
            if result.error:
                continue
            self._calibration_results.append(result)
            statuses.add(result.status)
            lengths.append(result.body_length)
            bodies.append(_normalise(result.body, self.token))

        if not bodies:
            self.baseline = Baseline(calibrated=False)
            return self.baseline

        uniform = False
        if len(bodies) > 1:
            uniform = all(
                difflib.SequenceMatcher(None, bodies[0], other).ratio() >= 0.9
                for other in bodies[1:]
            )
        self.baseline = Baseline(
            calibrated=True,
            statuses=statuses,
            mean_length=sum(lengths) / len(lengths),
            bodies=bodies,
            samples=len(bodies),
            uniform=uniform,
        )
        return self.baseline

    def evaluate(self, result: HttpResult, expected_status: int | None = None) -> Soft404Verdict:
        """Decide whether ``result`` is really the catch-all page."""
        if result.error:
            return Soft404Verdict(False, "request failed")
        if result.status == 404 or result.status == 410:
            return Soft404Verdict(True, f"explicit {result.status}")

        baseline = self.baseline
        if not baseline.calibrated:
            return Soft404Verdict(False, "baseline unavailable")

        normalised = _normalise(result.body, self.token)
        similarity = 0.0
        if normalised and baseline.bodies:
            similarity = max(
                difflib.SequenceMatcher(None, normalised, sample).ratio()
                for sample in baseline.bodies
            )

        if similarity >= self.similarity_threshold:
            return Soft404Verdict(True, "matches catch-all page content", similarity)

        if result.status in baseline.statuses:
            if baseline.mean_length > 0:
                delta = abs(result.body_length - baseline.mean_length)
                if delta <= self.length_tolerance * baseline.mean_length:
                    return Soft404Verdict(True, "status and length match catch-all", similarity)
            elif result.body_length == 0:
                return Soft404Verdict(True, "empty body matches catch-all", similarity)

        if expected_status is not None and result.status != expected_status:
            return Soft404Verdict(True, f"unexpected status {result.status}", similarity)

        return Soft404Verdict(False, "", similarity)


# -------------------------------------------------------------------------
# from cancel.py
# -------------------------------------------------------------------------

class ScanCancelled(Exception):
    """Raised at a cancellation checkpoint inside a scan."""


class CancellationToken:
    def __init__(self) -> None:
        self._event = asyncio.Event()
        self._reason = ""

    @property
    def is_cancelled(self) -> bool:
        return self._event.is_set()

    @property
    def reason(self) -> str:
        return self._reason

    def cancel(self, reason: str = "cancelled by user") -> None:
        if not self._event.is_set():
            self._reason = reason
            self._event.set()

    def reset(self) -> None:
        self._reason = ""
        self._event = asyncio.Event()

    def raise_if_cancelled(self) -> None:
        if self._event.is_set():
            raise ScanCancelled(self._reason or "cancelled")

    async def wait(self) -> None:
        await self._event.wait()

    async def sleep(self, seconds: float) -> None:
        """Sleep, but wake immediately when the scan is cancelled."""
        if seconds <= 0:
            self.raise_if_cancelled()
            return
        try:
            await asyncio.wait_for(self._event.wait(), timeout=seconds)
        except TimeoutError:
            return
        raise ScanCancelled(self._reason or "cancelled")
