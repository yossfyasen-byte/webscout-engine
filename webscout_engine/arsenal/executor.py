"""Probe executor with differential judging, plus the shell-pack runner."""

from __future__ import annotations

import asyncio
import difflib
import time
from dataclasses import dataclass, field
from urllib.parse import quote, urlsplit
from ..core.events import EventType
from ..core.models import HttpResult, Severity
from ..core.scope import join_url
from .catalog import ArsenalResult, Probe, ProbeHit, SectionStat
from .catalog import SECTION_LABELS
import os
import re
import shlex
from urllib.parse import urlsplit


# -------------------------------------------------------------------------
# from executor.py
# -------------------------------------------------------------------------

@dataclass(slots=True)
class ExecutorConfig:
    concurrency: int = 16
    max_params: int = 4
    blind_delay: float = 5.0
    follow_redirects: bool = False
    max_probes: int = 0
    sections: tuple[str, ...] = ()


@dataclass(slots=True)
class _Job:
    probe: Probe
    url: str
    parameter: str | None = None
    order: int = 0


class ProbeExecutor:
    """Runs a probe list against one target."""

    def __init__(
        self,
        ctx,
        probes: list[Probe],
        config: ExecutorConfig | None = None,
        on_event=None,
        hit_sink=None,
    ) -> None:
        self.ctx = ctx
        self.config = config or ExecutorConfig()
        self.on_event = on_event
        self.hit_sink = hit_sink
        self.probes = self._filter(probes)
        self.result = ArsenalResult()
        self._hits: list[ProbeHit] = []
        self._seen: set[tuple[str, str]] = set()
        self._reported: set[tuple[str, str]] = set()
        self._controls: dict[str, HttpResult] = {}
        self._section_stats: dict[str, SectionStat] = {
            name: SectionStat(name=name, label=SECTION_LABELS.get(name, name))
            for name in SECTION_LABELS
        }
        self._done = 0
        self._total = 0

    # ------------------------------------------------------------------ setup
    def _filter(self, probes: list[Probe]) -> list[Probe]:
        wanted = set(self.config.sections)
        if not wanted:
            return list(probes)
        return [probe for probe in probes if probe.section in wanted]

    def _parameters(self) -> list[tuple[str, str | None]]:
        """(name, path) pairs for every discovered parameter, first path wins."""
        found: list[tuple[str, str | None]] = []
        seen: set[str] = set()
        for parameter in getattr(self.ctx, "params", []) or []:
            name = getattr(parameter, "name", None)
            if not name or not name.isidentifier() or name in seen:
                continue
            seen.add(name)
            url = getattr(parameter, "url", "") or ""
            path = None
            if url:
                path = urlsplit(url).path or "/"
                if urlsplit(url).query:
                    path = path
            found.append((name, path))
        return found

    def _expand(self) -> list[_Job]:
        params = self._parameters()
        jobs: list[_Job] = []
        order = 0
        for probe in self.probes:
            order += 1
            if probe.param_name and params:
                for name, path in params[: self.config.max_params]:
                    query = probe.query.replace(probe.param_name + "=", name + "=", 1)
                    jobs.append(
                        _Job(
                            probe=probe,
                            url=self._url(path or probe.path, query),
                            parameter=name,
                            order=order,
                        )
                    )
            else:
                jobs.append(
                    _Job(
                        probe=probe,
                        url=self._url(probe.path, probe.query),
                        parameter=probe.param_name,
                        order=order,
                    )
                )
        if self.config.max_probes:
            jobs = jobs[: self.config.max_probes]
        return jobs

    @staticmethod
    def _url(path: str, query: str) -> str:
        base = ""  # filled by the caller's base_url join
        return f"{path}?{query}" if query else path

    def _resolve(self, job: _Job) -> str:
        path, _, query = job.url.partition("?")
        url = join_url(self.ctx.base_url, path)
        return f"{url}?{query}" if query else url

    # ------------------------------------------------------------------- run
    async def run(self) -> ArsenalResult:
        jobs = self._expand()
        self._total = len(jobs)
        self.result.sections = [self._section_stats[name] for name in SECTION_LABELS
                                if self._section_stats[name].total or name in {p.section for p in self.probes}]
        for job in jobs:
            self._section_stats[job.probe.section].total += 1
        self.ctx.add_total(len(jobs))

        queue: asyncio.Queue[_Job] = asyncio.Queue()
        for job in jobs:
            queue.put_nowait(job)

        workers = [
            asyncio.create_task(self._worker(queue), name=f"arsenal-worker-{index}")
            for index in range(max(1, min(self.config.concurrency, len(jobs) or 1)))
        ]
        try:
            await queue.join()
        finally:
            for worker in workers:
                worker.cancel()
            await asyncio.gather(*workers, return_exceptions=True)

        for stat in self._section_stats.values():
            if stat.total:
                self.result.sections.append(stat)
        self.result.hits = self._hits
        self.result.requests = self._done
        return self.result

    async def _worker(self, queue: asyncio.Queue[_Job]) -> None:
        while True:
            try:
                job = queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            try:
                if not self.ctx.cancel.is_cancelled:
                    await self._run_job(job)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # one bad probe never stops the run
                self._section_stats[job.probe.section].errors += 1
                self.ctx.note(f"arsenal probe {job.probe.id} failed: {type(exc).__name__}: {exc}")
            finally:
                queue.task_done()

    async def _run_job(self, job: _Job) -> None:
        probe = job.probe
        url = self._resolve(job)
        started = time.perf_counter()
        result = await self._send(probe, url)
        elapsed = time.perf_counter() - started

        hit: ProbeHit | None = None
        if result is not None and result.error is None:
            hit = await self._judge(job, url, result)

        stat = self._section_stats[probe.section]
        stat.done += 1
        self._done += 1
        self.ctx.progress(failed=result is None or result.error is not None)
        reported = False
        if hit is not None:
            stat.hits += 1
            key = (probe.id, job.parameter or "")
            if key not in self._seen:
                self._seen.add(key)
                self._hits.append(hit)
                # One finding per endpoint + parameter: eighteen working XSS
                # payloads are one vulnerability, not eighteen. Later payloads
                # still count as confirmations in the stream and the notes.
                # Group by attack class + endpoint + parameter: eighteen XSS
                # payloads collapse, but CORS and a banner on the same path stay
                # separate findings because they are different weaknesses.
                group = (
                    probe.section,
                    hit.result.url.split("?", 1)[0],
                    job.parameter or "",
                )
                if group not in self._reported:
                    self._reported.add(group)
                    reported = probe.severity is not Severity.INFO
                    if self.hit_sink is not None:
                        self.hit_sink(hit)
                    elif probe.severity is Severity.INFO:
                        self.ctx.add_observation(hit.to_observation())
                    else:
                        self.ctx.add_finding(hit.to_finding())
        await self._emit(job, result, elapsed, hit is not None, reported)

    async def _send(self, probe: Probe, url: str) -> HttpResult | None:
        try:
            return await self.ctx.http.request(
                probe.method,
                url,
                headers=probe.header_dict() or None,
                data=probe.body,
                allow_redirects=self.config.follow_redirects,
            )
        except Exception:
            return None

    # ---------------------------------------------------------------- judging
    async def _judge(self, job: _Job, url: str, result: HttpResult) -> ProbeHit | None:
        probe = job.probe
        if not probe.matchers:
            return None
        for matcher in probe.matchers:
            if not matcher.evaluate(result):
                return None

        # A soft-404 host answers every path with 200; only a body signature can
        # still make the response meaningful, so require one for path probes.
        if self._is_soft404(result) and not any(
            matcher.kind in {"body-regex", "body-contains"} for matcher in probe.matchers
        ):
            return None

        if probe.differential == "time":
            confirmed = await self._confirm_time(job, url, result)
            if not confirmed:
                return None
        elif probe.differential == "boolean":
            confirmed = await self._confirm_boolean(job, url, result)
            if not confirmed:
                return None
        elif probe.differential == "control-negative":
            if not await self._confirm_control_negative(job, result):
                return None

        if not self._survives_reflection_strip(probe, result):
            return None

        evidence = self._evidence(probe, job, result)
        return ProbeHit(
            probe=probe,
            result=result,
            evidence=evidence,
            matched=[matcher.describe() for matcher in probe.matchers],
            extra={"parameter": job.parameter},
        )

    def _is_soft404(self, result: HttpResult) -> bool:
        detector = getattr(self.ctx, "soft404", None)
        if detector is None:
            return False
        try:
            return bool(detector.evaluate(result).is_soft)
        except Exception:
            return False

    async def _control(self, job: _Job) -> HttpResult | None:
        probe = job.probe
        if not probe.control_query:
            return None
        query = probe.control_query
        if job.parameter and probe.param_name:
            query = query.replace(probe.param_name + "=", job.parameter + "=", 1)
        path = job.url.split("?", 1)[0]
        key = f"{probe.method} {path}?{query}"
        if key in self._controls:
            return self._controls[key]
        url = join_url(self.ctx.base_url, path)
        url = f"{url}?{query}"
        control = await self._send(probe, url)
        if control is not None:
            self._controls[key] = control
        return control

    async def _confirm_time(self, job: _Job, url: str, result: HttpResult) -> bool:
        """A delay only counts if the control request was fast."""
        if result.elapsed < self.config.blind_delay:
            return False
        control = await self._control(job)
        if control is None:
            return True
        return control.elapsed < max(1.5, self.config.blind_delay / 2)

    async def _confirm_boolean(self, job: _Job, url: str, result: HttpResult) -> bool:
        """A boolean hit needs the false twin to differ measurably."""
        control = await self._control(job)
        if control is None or control.error is not None:
            return False
        if control.status != result.status:
            return False
        ratio = _similarity(result.body, control.body)
        if ratio >= 0.985:
            return False
        if abs(result.body_length - control.body_length) < 16 and ratio > 0.95:
            return False
        return True

    @staticmethod
    def _survives_reflection_strip(probe: Probe, result: HttpResult) -> bool:
        """Reject hits whose only evidence is the payload echoed back.

        On a reflective endpoint every payload appears verbatim in the body, so
        a signature like ``/etc/`` or ``security-credentials`` would "match"
        without the server having done anything. Removing the payload and
        re-testing separates the two cases. XSS is exempt: there, the
        unencoded echo *is* the finding.
        """
        if probe.section == "xss" or not probe.payload:
            return True
        if probe.payload not in (result.body or ""):
            return True
        stripped = result.body.replace(probe.payload, "")
        body_matchers = [
            matcher
            for matcher in probe.matchers
            if matcher.kind in {"body-regex", "body-contains"}
        ]
        if not body_matchers:
            return True
        clone = result.model_copy(update={"body": stripped})
        return any(matcher.evaluate(clone) for matcher in body_matchers)

    async def _confirm_control_negative(self, job: _Job, result: HttpResult) -> bool:
        """The signature must be absent from the control response.

        This is what separates "the server evaluated my payload" from "the page
        always contains this string". Without it, a generic signature such as
        ``<!doctype html>`` would flag every HTML page as SSRF.
        """
        control = await self._control(job)
        if control is None or control.error is not None:
            return True
        body_matchers = [
            matcher
            for matcher in job.probe.matchers
            if matcher.kind in {"body-regex", "body-contains"}
        ]
        if not body_matchers:
            return True
        return not all(matcher.evaluate(control) for matcher in body_matchers)

    @staticmethod
    def _evidence(probe: Probe, job: _Job, result: HttpResult) -> str:
        parts = [
            f"{probe.method} {result.url}",
            f"status={result.status}",
            f"len={result.body_length}",
            f"time={result.elapsed:.2f}s",
        ]
        if job.parameter:
            parts.append(f"param={job.parameter}")
        if probe.payload:
            parts.append(f"payload={probe.payload[:120]}")
        snippet = " ".join((result.body or "").split())[:200]
        if snippet:
            parts.append(f"body={snippet}")
        return " | ".join(parts)

    # ------------------------------------------------------------------ events
    async def _emit(
        self,
        job: _Job,
        result: HttpResult | None,
        elapsed: float,
        hit: bool,
        reported: bool = False,
    ) -> None:
        probe = job.probe
        status = result.status if result is not None else 0
        error = result.error if result is not None else "no response"
        payload = {
            "kind": "probe",
            "probe_id": probe.id,
            "section": probe.section,
            "section_label": SECTION_LABELS.get(probe.section, probe.section),
            "title": probe.title,
            "method": probe.method,
            "url": self._resolve(job),
            "status": status,
            "elapsed": round(elapsed, 3),
            # HIT marks a new finding; CONFIRMED marks a repeat that proves the
            # same endpoint again. Informational hits are neither.
            "hit": reported,
            "confirmed": hit and not reported,
            "severity": probe.severity.value,
            "done": self._done,
            "total": self._total,
            "error": error,
        }
        if self.on_event is not None:
            self.on_event(payload)
        await self.ctx.emit(
            EventType.OPERATION,
            f"{probe.id} {probe.method} {payload['url']} -> {status}"
            + (" [HIT]" if hit else ""),
            payload,
            level="warning" if hit else "info",
        )


def _similarity(left: str, right: str) -> float:
    if left == right:
        return 1.0
    if not left or not right:
        return 0.0
    return difflib.SequenceMatcher(None, left[:4000], right[:4000]).ratio()


def encode(value: str) -> str:
    return quote(value, safe="")


# -------------------------------------------------------------------------
# from pack.py
# -------------------------------------------------------------------------

# First token of a line must be one of these.
ALLOWED_BINARIES: frozenset[str] = frozenset(
    {
        "dig", "host", "whois", "nslookup", "openssl", "curl", "wget", "nc",
        "ncat", "ping", "timeout", "bash", "sh", "for", "seq", "echo",
        "printf", "python3", "time", "true", "cat", "head", "tail", "grep",
        "sort", "uniq", "cut", "tr", "xargs", "while", "if",
    }
)

# Substrings that make a line unsafe to run unattended.
DENY_PATTERNS: tuple[str, ...] = (
    "rm -rf", "rm -fr", "rm -f /", "mkfs", "dd if=", "dd of=", "shutdown",
    "reboot", "init 0", "init 6", "halt", "poweroff", ":(){", "chmod 777 /",
    "chown ", "> /etc/", ">> /etc/", "> /boot", "crontab", "useradd",
    "userdel", "passwd ", "systemctl", "service ", "iptables", "nft ",
    "kill -9", "pkill", "nc -l", "ncat -l", "socat", "curl -o /", "wget -O /",
    "eval ", "exec ", "base64 -d | sh", "| sh", "| bash", "sudo ",
)

TARGET_TOKEN = "target.com"

SECTION_RE = re.compile(r"^#\s*=+\s*$")
TITLE_RE = re.compile(r"^#\s*(\d+)\)\s*(.+?)\s*$")


@dataclass(frozen=True)
class PackLine:
    number: int
    text: str


@dataclass
class PackSection:
    name: str
    title: str
    lines: list[PackLine] = field(default_factory=list)


@dataclass
class PackOutcome:
    section: str
    line: str
    returncode: int
    output: str
    skipped: str = ""

    @property
    def ran(self) -> bool:
        return not self.skipped


def parse_pack(text: str) -> list[PackSection]:
    """Split the pack into titled sections of executable lines."""
    sections: list[PackSection] = []
    current = PackSection(name="general", title="General")
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.rstrip()
        title_match = TITLE_RE.match(line)
        if title_match:
            if current.lines:
                sections.append(current)
            name = re.sub(r"[^a-z0-9]+", "-", title_match.group(2).lower()).strip("-")
            current = PackSection(name=name or f"section-{title_match.group(1)}", title=title_match.group(2))
            continue
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        current.lines.append(PackLine(number=number, text=stripped))
    if current.lines:
        sections.append(current)
    return sections


def substitute(line: str, host: str) -> str:
    return line.replace(TARGET_TOKEN, host)


def first_token(line: str) -> str:
    try:
        parts = shlex.split(line, posix=True)
    except ValueError:
        parts = line.split()
    return parts[0] if parts else ""


def check_line(line: str) -> str:
    """Return a skip reason, or an empty string when the line may run."""
    token = first_token(line)
    if token not in ALLOWED_BINARIES:
        return f"binary {token!r} is not allowlisted"
    lowered = line.lower()
    for pattern in DENY_PATTERNS:
        if pattern in lowered:
            return f"blocked pattern {pattern!r}"
    return ""


class ShellPackRunner:
    """Runs pack lines sequentially, streaming output as it arrives."""

    def __init__(
        self,
        target_url: str,
        timeout: float = 25.0,
        on_output=None,
        cancel=None,
        scope=None,
    ) -> None:
        self.target_url = target_url
        self.host = urlsplit(target_url).hostname or ""
        self.timeout = timeout
        self.on_output = on_output
        self.cancel = cancel
        self.scope = scope
        self.outcomes: list[PackOutcome] = []

    async def run(
        self,
        sections: list[PackSection],
        only: tuple[str, ...] = (),
    ) -> list[PackOutcome]:
        selected = [s for s in sections if not only or s.name in only]
        for section in selected:
            for pack_line in section.lines:
                if self.cancel is not None and getattr(self.cancel, "is_cancelled", False):
                    break
                await self._run_line(section, pack_line)
        return self.outcomes

    async def _run_line(self, section: PackSection, pack_line: PackLine) -> None:
        command = substitute(pack_line.text, self.host)
        reason = check_line(command)
        if reason:
            self.outcomes.append(
                PackOutcome(section.name, pack_line.text, -1, "", skipped=reason)
            )
            return
        if self.scope is not None:
            for url in re.findall(r"https?://[^\s\"']+", command):
                decision = await self.scope.ensure_allowed(url)
                if not decision.allowed:
                    self.outcomes.append(
                        PackOutcome(
                            section.name, pack_line.text, -1, "",
                            skipped=f"out of scope: {decision.reason}",
                        )
                    )
                    return

        env = dict(os.environ)
        env["TARGET"] = self.host
        env["TARGET_URL"] = self.target_url
        env["LC_ALL"] = "C"
        process = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env=env,
            start_new_session=True,
        )
        collected: list[str] = []
        try:
            assert process.stdout is not None
            async with asyncio.timeout(self.timeout):
                async for raw in process.stdout:
                    text = raw.decode("utf-8", "replace").rstrip("\n")
                    collected.append(text)
                    if self.on_output is not None:
                        self.on_output(section.name, pack_line.text, text)
                await process.wait()
        except TimeoutError:
            collected.append(f"[timeout after {self.timeout:.0f}s]")
            try:
                os.killpg(process.pid, 9)
            except (ProcessLookupError, PermissionError):
                pass
        output = "\n".join(collected)[:8000]
        self.outcomes.append(
            PackOutcome(section.name, pack_line.text, process.returncode or 0, output)
        )


# Output signatures that turn a pack line into a finding.
PACK_SIGNATURES: tuple[tuple[str, str, str, str], ...] = (
    (r"POSSIBLE XSS", "Reflected XSS reported by the pack", "high", "CWE-79"),
    (r"root:x:0:0:", "Local file disclosure reported by the pack", "critical", "CWE-22"),
    (r"OPEN REDIRECT", "Open redirect reported by the pack", "medium", "CWE-601"),
    (r"POSSIBLE SSRF", "SSRF reported by the pack", "high", "CWE-918"),
    (r"uid=\d+\([^)]+\)", "Command execution reported by the pack", "critical", "CWE-78"),
    (r"BEGIN (RSA |OPENSSH )?PRIVATE KEY", "Private key disclosed by the pack", "critical", "CWE-798"),
    (r"AKIA[0-9A-Z]{16}", "AWS key disclosed by the pack", "critical", "CWE-798"),
    (r"Index of /", "Directory listing reported by the pack", "medium", "CWE-548"),
    (r"sql syntax|SQLSTATE|ORA-\d{5}", "SQL error reported by the pack", "high", "CWE-89"),
    (r"ami-[0-9a-f]{8,}|security-credentials", "Cloud metadata reachable per the pack", "critical", "CWE-918"),
)


# ---------------------------------------------------------------- integration
async def execute_pack(
    ctx,
    pack_path: str,
    only: tuple[str, ...] = (),
    timeout: float = 25.0,
    echo=None,
) -> list:
    """Run the operator pack against ``ctx`` and fold the results into the report.

    Returns the findings produced by output signatures; observations are added
    to the scan state directly so they appear in the live dashboard.
    """
    import re
    from pathlib import Path

    from ..core.models import Confidence, Finding, Observation, Severity, Verification

    path = Path(pack_path).expanduser()
    if not path.exists():
        ctx.note(f"shell pack not found: {path}")
        return []

    sections = parse_pack(path.read_text(encoding="utf-8", errors="replace"))
    runner = ShellPackRunner(
        ctx.base_url, timeout=timeout, on_output=echo, cancel=ctx.cancel, scope=ctx.scope
    )
    await ctx.emit(
        EventType.STAGE,
        f"Shell pack: {sum(len(s.lines) for s in sections)} command lines in {len(sections)} sections",
    )
    ctx.add_total(sum(len(s.lines) for s in sections))
    outcomes = await runner.run(sections, only)

    findings: list[Finding] = []
    for outcome in outcomes:
        ctx.progress(failed=not outcome.ran)
        if outcome.skipped:
            ctx.note(f"pack line {outcome.section}: skipped ({outcome.skipped})")
            continue
        if not outcome.output.strip():
            continue
        ctx.add_observation(
            Observation(
                kind="pack",
                target=ctx.base_url,
                label=outcome.section,
                status="ran" if outcome.returncode == 0 else f"exit {outcome.returncode}",
                detail=outcome.line[:300],
                metadata={"module": "arsenal", "output": outcome.output[:1500]},
            )
        )
        for pattern, title, severity, cwe in PACK_SIGNATURES:
            if re.search(pattern, outcome.output, re.IGNORECASE):
                findings.append(
                    Finding(
                        title=title,
                        severity=Severity(severity),
                        confidence=Confidence.MEDIUM,
                        module="arsenal",
                        check="shell-pack",
                        endpoint=ctx.base_url,
                        evidence=f"$ {outcome.line}\n{outcome.output[:400]}",
                        impact="Reported by the operator command pack.",
                        remediation="Confirm the observation manually, then fix the underlying weakness.",
                        cwe=cwe,
                        scan_type="active",
                        verification=Verification.INDICATOR,
                    )
                )
                break
    for finding in findings:
        ctx.add_finding(finding)
    return findings
