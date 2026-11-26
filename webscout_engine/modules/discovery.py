"""Content discovery: sensitive files and directory enumeration."""

from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path
from pydantic import BaseModel, Field
from ..core.events import EventType
from ..core.models import Confidence, Observation, Severity
from ..core.redaction import redact_evidence
from ..recon.crawl import Crawler
from .base import BaseModule, ModuleOutcome
from urllib.parse import urljoin
from ..core.models import Confidence, HttpResult, Observation, Severity
from ..core.scope import join_url, origin


# -------------------------------------------------------------------------
# from files.py
# -------------------------------------------------------------------------

DATA_DIR = Path(__file__).resolve().parent.parent / "data"

GROUP_REMEDIATION: dict[str, str] = {
    "config": "Remove configuration files from the web root and keep secrets in environment variables or a secrets manager.",
    "vcs": "Block access to version-control metadata at the web server and deploy without the .git directory.",
    "backup": "Store backups outside the document root and disable directory listing for archive files.",
    "logs": "Never serve log files from the web root; ship logs to a collector instead.",
    "deployment": "Exclude deployment descriptors and CI configuration from release artefacts.",
    "api_docs": "Restrict API documentation to authenticated internal users or disable it in production.",
    "source_maps": "Publish source maps only to your error tracker, not to the public bundle.",
    "diagnostics": "Disable diagnostic and status endpoints in production builds.",
    "secrets": "Rotate any exposed credential immediately and remove the file from the deployment.",
}

DEFAULT_REFERENCES = [
    "https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration",
    "https://cwe.mitre.org/data/definitions/538.html",
]


class SensitiveEntry(BaseModel):
    path: str
    group: str = "config"
    severity: Severity = Severity.MEDIUM
    signatures: list[str] = Field(default_factory=list)
    description: str = ""
    remediation: str = ""
    references: list[str] = Field(default_factory=list)

    def compiled(self) -> list[re.Pattern[str]]:
        compiled: list[re.Pattern[str]] = []
        for pattern in self.signatures:
            try:
                compiled.append(re.compile(pattern, re.MULTILINE))
            except re.error:
                continue
        return compiled


class SensitiveFileModule(BaseModule):
    name = "files"
    title = "Sensitive File Discovery"
    description = "Probes for exposed configuration, VCS, backup, log and diagnostic files."

    def __init__(self, ctx=None, entries: list[SensitiveEntry] | None = None) -> None:
        super().__init__(ctx)
        self._entries = entries

    # ------------------------------------------------------------------ data
    @staticmethod
    def load_entries(path: Path | None = None) -> list[SensitiveEntry]:
        source = path or (DATA_DIR / "sensitive_paths.json")
        if not source.exists():
            return []
        payload = json.loads(source.read_text(encoding="utf-8"))
        raw = payload.get("entries", payload) if isinstance(payload, dict) else payload
        return [SensitiveEntry(**entry) for entry in raw]

    def _crawl_paths(self, crawl: object) -> list[SensitiveEntry]:
        """Turn crawled URLs and robots entries into extra probe candidates."""
        paths: dict[str, SensitiveEntry] = {}
        candidates: list[str] = []
        for value in getattr(crawl, "robots_paths", []) or []:
            candidates.append(value)
        for value in getattr(crawl, "links", []) or []:
            candidates.append(value)
        for value in getattr(crawl, "js_endpoints", []) or []:
            candidates.append(value)

        for candidate in candidates[:200]:
            path = candidate
            if "://" in path:
                path = "/" + path.split("://", 1)[1].split("/", 1)[-1] if "/" in path.split("://", 1)[1] else "/"
            path = path.split("?", 1)[0].strip()
            if not path or path == "/" or len(path) > 120:
                continue
            name = path.rsplit("/", 1)[-1]
            interesting = (
                "." in name
                and name.rsplit(".", 1)[-1].lower()
                in {"json", "xml", "yml", "yaml", "env", "bak", "sql", "log", "txt", "map", "ini", "conf", "cfg", "zip", "tar", "gz"}
            ) or name in {"config", "swagger", "graphql", "status", "debug"}
            if not interesting:
                continue
            normalised = path.lstrip("/")
            paths.setdefault(
                normalised,
                SensitiveEntry(
                    path=normalised,
                    group="config",
                    severity=Severity.LOW,
                    description="Path discovered by crawling the application.",
                    remediation=GROUP_REMEDIATION["config"],
                ),
            )
        return list(paths.values())[:25]

    # ------------------------------------------------------------------- run
    async def run(self, ctx) -> ModuleOutcome:
        outcome = self.new_outcome(ctx)
        entries = self._entries if self._entries is not None else self.load_entries()

        ctx.state.set_stage("discovery")
        await ctx.emit(EventType.STAGE, "Sensitive file discovery: collecting candidate paths")

        crawl = ctx.crawl_result
        if crawl is None:
            crawler = Crawler(ctx.http, ctx.base_url, max_pages=3, max_scripts=3, cancel=ctx.cancel)
            crawl = await crawler.crawl()
            ctx.crawl_result = crawl

        combined: dict[str, SensitiveEntry] = {}
        for entry in entries:
            combined.setdefault(entry.path.lstrip("/"), entry)
        for entry in self._crawl_paths(crawl):
            combined.setdefault(entry.path, entry)

        candidates = list(combined.values())
        ctx.add_total(len(candidates))
        await ctx.emit(
            EventType.OPERATION,
            f"Probing {len(candidates)} sensitive paths",
            {"count": len(candidates)},
        )

        semaphore = asyncio.Semaphore(max(1, min(ctx.options.threads, 20)))
        deduper = ctx.http.deduper

        async def worker(entry: SensitiveEntry) -> None:
            if ctx.cancel.is_cancelled:
                return
            async with semaphore:
                try:
                    await self._probe(ctx, entry, outcome, deduper)
                except Exception as exc:  # a single bad path must not abort the module
                    ctx.note(f"probe error on /{entry.path}: {type(exc).__name__}")
                finally:
                    ctx.progress()

        await asyncio.gather(*(worker(entry) for entry in candidates))

        accessible = sum(1 for o in outcome.observations if o.status == "accessible")
        protected = sum(1 for o in outcome.observations if o.status == "protected")
        outcome.notes.append(
            f"{len(candidates)} paths probed, {accessible} accessible, {protected} protected, "
            f"{len(outcome.findings)} finding(s)."
        )
        return outcome

    # --------------------------------------------------------------- internals
    async def _probe(self, ctx, entry: SensitiveEntry, outcome: ModuleOutcome, deduper) -> None:
        url = ctx.base_url.rstrip("/") + "/" + entry.path.lstrip("/")
        ctx.state.set_operation(f"GET /{entry.path}")

        head = await ctx.http.head(url, allow_redirects=False, retries=0)
        status = head.status if not head.error else 0

        if head.error or status in (405, 501) or status == 0 or status in (401, 403) or 200 <= status < 400:
            result = await ctx.http.get(url, allow_redirects=False, max_body=8192, retries=0)
        else:
            return  # 404/410 from HEAD: nothing to confirm

        if result.error:
            return
        if result.status in (401, 403):
            outcome.observe(
                Observation(
                    kind="file",
                    target=ctx.base_url,
                    label="/" + entry.path,
                    status="protected",
                    detail=f"HTTP {result.status} - resource exists but requires authorisation",
                    severity=Severity.INFO,
                    metadata={"module": self.name, "group": entry.group},
                )
            )
            return

        if result.status not in (200, 206):
            return

        verdict = ctx.soft404.evaluate(result)
        if verdict.is_soft:
            return

        content_type = result.content_type
        body = result.body
        matched: list[str] = []
        snippet = ""
        for pattern in entry.compiled():
            found = pattern.search(body)
            if found:
                matched.append(pattern.pattern)
                start = max(0, found.start() - 40)
                snippet = body[start : found.end() + 80]
                break

        if not matched:
            # Without a file-specific signature a 200 HTML or JSON body is just the
            # server answering with a page (a themed 404 or an ordinary API route).
            ctype = content_type.lower()
            if "html" in ctype or "json" in ctype:
                return
        if deduper.is_duplicate(result) and not matched:
            return

        outcome.observe(
            Observation(
                kind="file",
                target=ctx.base_url,
                label="/" + entry.path,
                status="accessible",
                detail=f"HTTP {result.status}, {result.body_length} bytes, {content_type or 'unknown type'}",
                severity=entry.severity,
                size=result.body_length,
                content_type=content_type,
                metadata={"module": self.name, "group": entry.group},
            )
        )

        confidence = Confidence.CERTAIN if matched else Confidence.LOW
        evidence_parts = [
            f"GET /{entry.path} -> {result.status} ({result.body_length} bytes, {content_type or 'unknown'})"
        ]
        if matched:
            evidence_parts.append(f"content signature matched: /{matched[0]}/")
        if snippet:
            evidence_parts.append(f"snippet: {redact_evidence(snippet, limit=200)}")
        elif not matched:
            evidence_parts.append("no file-specific signature matched; response may be a custom page")

        outcome.add(
            self.finding(
                title=f"Exposed sensitive file: /{entry.path}",
                severity=entry.severity,
                confidence=confidence,
                module=self.name,
                check="sensitive-file",
                endpoint=url,
                status_code=result.status,
                evidence=" | ".join(evidence_parts),
                impact=entry.description
                or "The file is served publicly and may disclose configuration, credentials or infrastructure detail.",
                remediation=entry.remediation or GROUP_REMEDIATION.get(entry.group, GROUP_REMEDIATION["config"]),
                references=entry.references or DEFAULT_REFERENCES,
                cwe="CWE-538",
            )
        )


# -------------------------------------------------------------------------
# from dirs.py
# -------------------------------------------------------------------------

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
WORDLIST_DIR = DATA_DIR / "wordlists"

TIER_FILES = {"small": "small.txt", "medium": "medium.txt", "large": "large.txt"}

DIRECTORY_MARKERS = ("index of /", "directory listing for", "parent directory</a>")

THROTTLE_PAUSE = 5
THROTTLE_ABORT = 12
MAX_CANDIDATES = 4000


class DirectoryDiscoveryModule(BaseModule):
    name = "dirs"
    title = "Directory and Content Discovery"
    description = "Enumerates directories and files using bundled or external wordlists."

    def __init__(self, ctx=None, words: list[str] | None = None) -> None:
        super().__init__(ctx)
        self._words = words

    # ------------------------------------------------------------------ data
    @staticmethod
    def load_words(tier: str = "small", external: str | None = None) -> list[str]:
        words: list[str] = []
        if external:
            path = Path(external).expanduser()
            if not path.exists():
                raise FileNotFoundError(f"wordlist not found: {external}")
            raw = path.read_text(encoding="utf-8", errors="replace").splitlines()
        else:
            name = TIER_FILES.get(tier, TIER_FILES["small"])
            source = WORDLIST_DIR / name
            if not source.exists():
                source = WORDLIST_DIR / TIER_FILES["small"]
            raw = source.read_text(encoding="utf-8", errors="replace").splitlines() if source.exists() else []
        for line in raw:
            entry = line.strip()
            if not entry or entry.startswith("#"):
                continue
            words.append(entry.strip("/"))
        # de-duplicate, preserve order
        return list(dict.fromkeys(words))

    # ------------------------------------------------------------------- run
    async def run(self, ctx) -> ModuleOutcome:
        outcome = self.new_outcome(ctx)
        words = self._words if self._words is not None else self.load_words(
            ctx.options.wordlist_tier, ctx.options.wordlist
        )
        if not words:
            outcome.notes.append("No wordlist entries available; directory discovery skipped.")
            return outcome

        extensions = [ext.lstrip(".") for ext in ctx.options.extensions if ext.strip()]
        depth_limit = max(0, ctx.options.depth)
        ctx.state.set_stage("enumeration")
        await ctx.emit(
            EventType.OPERATION,
            f"Directory discovery: {len(words)} words, depth {depth_limit}, tier {ctx.options.wordlist_tier}",
        )

        crawl = ctx.crawl_result
        if crawl is None:
            crawl = await Crawler(ctx.http, ctx.base_url, max_pages=2, max_scripts=2, cancel=ctx.cancel).crawl()
            ctx.crawl_result = crawl

        seeds: list[str] = [""]
        for path in list(crawl.robots_paths)[:5]:
            clean = path.strip("/")
            if clean and clean not in seeds:
                seeds.append(clean + "/")

        base_origin = origin(ctx.base_url)
        semaphore = asyncio.Semaphore(max(1, ctx.options.threads))
        deduper = ctx.http.deduper
        budget = {"count": 0}
        aborted = False

        async def probe(relative: str, depth: int) -> tuple[str, int] | None:
            nonlocal aborted
            if ctx.cancel.is_cancelled or aborted:
                return None
            if budget["count"] >= MAX_CANDIDATES:
                aborted = True
                return None
            budget["count"] += 1
            async with semaphore:
                if aborted:
                    return None
                url = join_url(ctx.base_url, relative)
                ctx.state.set_operation(f"GET /{relative}")
                result = await ctx.http.get(url, allow_redirects=False, max_body=16384, retries=1)
                try:
                    return await self._handle(ctx, result, relative, depth, outcome, deduper, base_origin)
                finally:
                    ctx.progress()

        frontier: list[str] = list(seeds)
        for depth in range(depth_limit + 1):
            if ctx.cancel.is_cancelled or aborted:
                break
            candidates: list[str] = []
            for prefix in frontier:
                for word in words:
                    candidates.append(f"{prefix}{word}")
                    if extensions:
                        for ext in extensions:
                            candidates.append(f"{prefix}{word}.{ext}")
            candidates = [c for c in dict.fromkeys(candidates) if c]
            if not candidates:
                break
            ctx.add_total(len(candidates))

            results = await asyncio.gather(*(probe(candidate, depth) for candidate in candidates))
            discovered = [item[0] for item in results if item]
            frontier = [path for path in discovered if path.endswith("/") and path.count("/") <= depth + 1]

            streak = ctx.state.rate_limited_streak
            if streak >= THROTTLE_ABORT:
                aborted = True
                outcome.notes.append(
                    f"Stopped after {streak} consecutive rate-limited responses; the target is throttling this assessment."
                )
                await ctx.emit(EventType.WARNING, "Aborting directory discovery: repeated rate limiting", level="warning")
                break
            if streak >= THROTTLE_PAUSE:
                await ctx.emit(
                    EventType.RATE_LIMIT,
                    f"Rate limiting detected ({streak} consecutive); pausing before continuing",
                    level="warning",
                )
                await ctx.cancel.sleep(2.0)

        if not frontier and not outcome.observations:
            outcome.notes.append("No additional paths discovered.")
        outcome.notes.append(
            f"{budget['count']} candidates probed, {len(outcome.observations)} path(s) observed, "
            f"{len(outcome.findings)} finding(s)."
        )
        return outcome

    # --------------------------------------------------------------- internals
    async def _handle(
        self,
        ctx,
        result: HttpResult,
        relative: str,
        depth: int,
        outcome: ModuleOutcome,
        deduper,
        base_origin: str,
    ) -> tuple[str, int] | None:
        if result.error:
            return None

        url = join_url(ctx.base_url, relative)

        if result.status in (401, 403):
            outcome.observe(
                Observation(
                    kind="directory",
                    target=ctx.base_url,
                    label="/" + relative,
                    status="protected",
                    detail=f"HTTP {result.status}",
                    metadata={"module": self.name, "depth": depth},
                )
            )
            return None

        if result.status in (301, 302, 307, 308):
            location = result.header("location")
            absolute = urljoin(url, location) if location else ""
            if absolute.endswith("/") and origin(absolute) == base_origin:
                target_path = absolute.split(base_origin, 1)[-1].strip("/")
                outcome.observe(
                    Observation(
                        kind="directory",
                        target=ctx.base_url,
                        label="/" + relative + "/",
                        status="redirect",
                        detail=f"HTTP {result.status} -> {location}",
                        metadata={"module": self.name, "depth": depth},
                    )
                )
                return (target_path + "/", depth + 1) if target_path else None
            return None

        if result.status not in (200, 204):
            return None

        if ctx.soft404.evaluate(result).is_soft:
            return None

        lowered = result.body.lower()
        listing = any(marker in lowered for marker in DIRECTORY_MARKERS)
        if deduper.is_duplicate(result) and not listing:
            return None

        outcome.observe(
            Observation(
                kind="directory",
                target=ctx.base_url,
                label="/" + relative,
                status="discovered",
                detail=f"HTTP {result.status}, {result.body_length} bytes, {result.content_type or 'unknown'}",
                size=result.body_length,
                content_type=result.content_type,
                severity=Severity.MEDIUM if listing else Severity.INFO,
                metadata={"module": self.name, "depth": depth, "listing": listing},
            )
        )

        if listing:
            outcome.add(
                self.finding(
                    title=f"Directory listing enabled at /{relative}",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CERTAIN,
                    module=self.name,
                    check="directory-listing",
                    endpoint=url,
                    status_code=result.status,
                    evidence=f"Auto-generated index returned for /{relative} ({result.body_length} bytes).",
                    impact="Every file in the directory is enumerable, including backups and configuration.",
                    remediation="Disable automatic index generation (Options -Indexes / autoindex off).",
                    references=["https://cwe.mitre.org/data/definitions/548.html"],
                    cwe="CWE-548",
                )
            )

        if relative.endswith("/"):
            return (relative, depth + 1)
        return None
