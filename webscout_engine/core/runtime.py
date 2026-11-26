"""Scan runtime: the engine and the dependency-injection context it drives."""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
from datetime import datetime
from pathlib import Path
from ..catalog import MODULE_ORDER, MODULE_SPECS, plan_modules
from ..config import home_dir
from .net import CancellationToken, ScanCancelled
from .events import EventBus, EventType
from .net import AsyncHttpClient, BudgetExceeded, HttpConfig
from .models import CoverageEntry, ModuleStatus, ScanReport, ScanStats, utcnow
from .net import RateLimiter
from .redaction import redact_value
from .scope import Scope
from .state import ScanState
from typing import Any
from pydantic import BaseModel, Field
from .net import CancellationToken
from .net import AsyncHttpClient
from .models import Finding, Observation
from .net import Soft404Detector


# -------------------------------------------------------------------------
# from engine.py
# -------------------------------------------------------------------------

logger = logging.getLogger("webscout_engine.engine")


def build_scope(target: str, options: ScanOptions) -> Scope:
    return Scope.for_target(
        target,
        lab_mode=options.lab_mode,
        include_subdomains=options.include_subdomains,
        verify_resolved=not options.lab_mode,
    )


async def create_context(
    target: str,
    options: ScanOptions,
    bus: EventBus | None = None,
    cancel: CancellationToken | None = None,
) -> ScanContext:
    """Wire every component together (dependency injection for modules)."""
    scope = build_scope(target, options)
    limiter = RateLimiter(options.rate)
    state = ScanState(target)
    event_bus = bus or EventBus()
    token = cancel or CancellationToken()
    http_config = HttpConfig(
        timeout=options.timeout,
        max_body=options.max_body,
        retries=options.retries,
        max_redirects=scope.max_redirects,
        max_requests=options.max_requests,
        verify_tls=options.verify_tls,
        user_agent=options.user_agent,
    )
    client = AsyncHttpClient(
        scope=scope,
        limiter=limiter,
        config=http_config,
        state=state,
        bus=event_bus,
        cancel=token,
    )
    await client.start()
    return ScanContext(
        target=target,
        scope=scope,
        http=client,
        state=state,
        bus=event_bus,
        cancel=token,
        options=options,
    )


def build_report(
    ctx: ScanContext,
    completed: bool,
    interrupted: bool,
    coverage: list[CoverageEntry] | None = None,
) -> ScanReport:
    state = ctx.state
    notes = list(ctx.notes)
    for result in state.modules.values():
        if result.error:
            notes.append(f"{result.module}: {result.error}")
    report = ScanReport(
        target=ctx.base_url,
        scan_id=state.scan_id,
        started_at=state.started_at,
        finished_at=state.finished_at or utcnow(),
        completed=completed,
        interrupted=interrupted,
        lab_mode=ctx.options.lab_mode,
        config_snapshot=redact_value(ctx.options.model_dump(mode="json")),
        modules=list(state.modules.values()),
        findings=sorted(state.findings, key=lambda f: f.sort_key()),
        observations=list(state.observations),
        stats=state.stats.model_copy(deep=True),
        coverage=coverage or [],
        notes=notes,
    )
    report.recount()
    return report


class ScanEngine:
    """Runs the requested modules sequentially, isolating failures."""

    def __init__(
        self,
        ctx: ScanContext,
        modules: list[str] | None = None,
        resume: bool = False,
    ) -> None:
        self.ctx = ctx
        requested = modules if modules is not None else list(ctx.options.modules)
        plan = plan_modules(list(requested), ctx.options)
        self.modules = plan.selected
        self.skipped = plan.skipped
        self.resume = resume
        self.completed_modules: set[str] = set()

    # ------------------------------------------------------------ checkpoints
    def checkpoint_path(self) -> Path:
        digest = hashlib.sha1(self.ctx.base_url.encode("utf-8")).hexdigest()[:12]
        return home_dir() / "resume" / f"{digest}.json"

    def _load_checkpoint(self) -> set[str]:
        path = self.checkpoint_path()
        if not path.exists():
            return set()
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return set()
        if payload.get("target") != self.ctx.base_url:
            return set()
        return {name for name in payload.get("completed", []) if name in self.modules}

    def _save_checkpoint(self) -> None:
        path = self.checkpoint_path()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                json.dumps(
                    {
                        "target": self.ctx.base_url,
                        "completed": sorted(self.completed_modules),
                        "updated_at": utcnow().isoformat(),
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
        except OSError:
            pass

    def _clear_checkpoint(self) -> None:
        with contextlib.suppress(OSError):
            self.checkpoint_path().unlink(missing_ok=True)

    async def run(self) -> ScanReport:
        from ..modules import MODULE_LABELS, MODULES  # local import avoids a cycle

        ctx = self.ctx
        state = ctx.state
        completed = False
        interrupted = False

        try:
            await ctx.emit(
                EventType.SCAN_START,
                f"Assessment started against {ctx.base_url}",
                {"target": ctx.base_url, "modules": self.modules},
            )
            state.set_status("calibrating")
            state.set_stage("calibration")
            state.set_operation("soft-404 baseline")
            state.add_total(1)
            await ctx.calibrate_soft404()
            state.task_done()
            await ctx.emit(
                EventType.INFO,
                f"Soft-404 baseline: {ctx.soft404.baseline.describe()}",
            )

            if self.resume:
                self.completed_modules = self._load_checkpoint()
                if self.completed_modules:
                    ctx.note(
                        "Resumed scan: skipping completed module(s) "
                        + ", ".join(sorted(self.completed_modules))
                    )
                    await ctx.emit(
                        EventType.INFO,
                        "Resume checkpoint found: "
                        + ", ".join(sorted(self.completed_modules))
                        + " already completed",
                    )

            for name, reason in self.skipped:
                ctx.note(f"module {name} skipped: {reason}")
                await ctx.emit(
                    EventType.WARNING,
                    f"Module skipped: {name} ({reason})",
                    {"module": name, "reason": reason},
                    level="warning",
                )

            for name in self.modules:
                if ctx.cancel.is_cancelled:
                    interrupted = True
                    break
                if name in self.completed_modules:
                    ctx.note(f"Skipped {name}: already completed in a previous run.")
                    continue
                await self._run_module(name, MODULES[name], MODULE_LABELS.get(name, name))
                self.completed_modules.add(name)
                self._save_checkpoint()
            completed = not interrupted and not ctx.cancel.is_cancelled
            if completed:
                self._clear_checkpoint()
        except ScanCancelled:
            interrupted = True
            state.cancelled = True
        except BudgetExceeded as exc:
            interrupted = True
            ctx.note(f"Request budget exhausted: {exc}")
        finally:
            state.finished_at = utcnow()
            for result in state.modules.values():
                if result.status == ModuleStatus.RUNNING:
                    result.status = ModuleStatus.PARTIAL if interrupted else ModuleStatus.COMPLETED
                    result.finished_at = result.finished_at or utcnow()
            state.set_status("interrupted" if interrupted else "finished")
            report = build_report(
                ctx,
                completed=completed,
                interrupted=interrupted,
                coverage=self.build_coverage(),
            )
            await ctx.emit(
                EventType.SCAN_END,
                (
                    f"Assessment {'interrupted' if interrupted else 'completed'}: "
                    f"{len(report.findings)} finding(s) in {report.duration_seconds:.1f}s"
                ),
                {"findings": len(report.findings), "completed": completed},
                level="warning" if interrupted else "info",
            )
        return report

    def build_coverage(self) -> list[CoverageEntry]:
        """Which modules ran, which were skipped, and why - in canonical order."""
        ctx = self.ctx
        entries: dict[str, CoverageEntry] = {}
        for name, reason in self.skipped:
            spec = MODULE_SPECS.get(name)
            entries[name] = CoverageEntry(
                module=name,
                module_id=spec.module_id if spec else "",
                title=spec.title if spec else name,
                status=ModuleStatus.SKIPPED,
                scan_type=spec.scan_type if spec else "",
                reason=reason,
            )
        for name, result in ctx.state.modules.items():
            spec = MODULE_SPECS.get(name)
            reason = ctx.skip_reasons.get(name, "")
            status = result.status
            if reason and status == ModuleStatus.COMPLETED:
                status = ModuleStatus.SKIPPED
            entries[name] = CoverageEntry(
                module=name,
                module_id=spec.module_id if spec else "",
                title=result.title or (spec.title if spec else name),
                status=status,
                scan_type=spec.scan_type if spec else "active",
                reason=reason or (result.error or ""),
                findings=len(result.findings),
                requests=result.stats.requests,
                duration_seconds=result.duration_seconds,
            )
        order = {name: index for index, name in enumerate(MODULE_ORDER)}
        return sorted(entries.values(), key=lambda entry: order.get(entry.module, 99))

    async def _run_module(self, name: str, module_cls, label: str) -> None:
        ctx = self.ctx
        state = ctx.state
        module = module_cls()
        state.set_module(name, label)
        state.set_stage(label)
        state.set_operation("starting")
        await ctx.emit(EventType.MODULE_START, f"Module started: {label}", {"module": name})

        before = state.stats.model_copy(deep=True)
        outcome = None
        status = ModuleStatus.COMPLETED
        error: str | None = None
        try:
            outcome = await module.run(ctx)
        except ScanCancelled:
            state.finish_module(name, ModuleStatus.CANCELLED)
            raise
        except BudgetExceeded:
            state.finish_module(name, ModuleStatus.PARTIAL, "request budget exhausted")
            raise
        except Exception as exc:  # module isolation: one failure never aborts the scan
            logger.exception("module %s failed", name)
            status = ModuleStatus.FAILED
            error = f"{type(exc).__name__}: {exc}"
            state.set_operation(f"failed: {error}")

        if outcome is not None:
            for finding in outcome.findings:
                ctx.add_finding(finding)  # de-duplicated inside ScanState
            for observation in outcome.observations:
                ctx.add_observation(observation)
            for note in outcome.notes:
                ctx.note(note)

        state.finish_module(name, status, error)
        result = state.modules[name]
        after = state.stats
        result.stats = ScanStats(
            requests=after.requests - before.requests,
            retries=after.retries - before.retries,
            timeouts=after.timeouts - before.timeouts,
            errors=after.errors - before.errors,
            rate_limited=after.rate_limited - before.rate_limited,
            bytes_received=after.bytes_received - before.bytes_received,
            tasks_completed=after.tasks_completed - before.tasks_completed,
            tasks_total=after.tasks_total - before.tasks_total,
            tasks_failed=after.tasks_failed - before.tasks_failed,
        )
        await ctx.emit(
            EventType.MODULE_END,
            f"Module finished: {label} ({result.stats.requests} requests, {len(result.findings)} findings)",
            {"module": name, "status": status.value},
            level="error" if status == ModuleStatus.FAILED else "info",
        )


async def run_scan(
    target: str,
    options: ScanOptions,
    bus: EventBus | None = None,
    cancel: CancellationToken | None = None,
    modules: list[str] | None = None,
) -> tuple[ScanReport, ScanContext]:
    """Convenience wrapper used by the CLI and the interactive UI."""
    ctx = await create_context(target, options, bus=bus, cancel=cancel)
    try:
        engine = ScanEngine(ctx, modules=modules)
        report = await engine.run()
    finally:
        await ctx.http.close()
    return report, ctx


def utc_stamp(value: datetime | None = None) -> str:
    return (value or utcnow()).strftime("%Y%m%dT%H%M%SZ")


# -------------------------------------------------------------------------
# from context.py
# -------------------------------------------------------------------------

class ScanOptions(BaseModel):
    """Runtime options for one scan (CLI flags land here)."""

    modules: list[str] = Field(default_factory=lambda: ["files", "dirs", "infra", "vuln"])
    threads: int = 20
    timeout: float = 10.0
    rate: float = 25.0
    depth: int = 2
    ports: str = "top100"
    wordlist: str | None = None
    wordlist_tier: str = "small"
    extensions: list[str] = Field(default_factory=list)
    include_subdomains: bool = False
    lab_mode: bool = False
    max_requests: int = 20_000
    max_body: int = 262_144
    retries: int = 2
    output_dir: str = "reports"
    formats: list[str] = Field(default_factory=lambda: ["json", "html", "csv", "sarif"])
    resume: bool = False
    json_stream: bool = False
    force: bool = False
    checks: list[str] = Field(default_factory=list)
    user_agent: str = "webscout_engine/1.0 (authorized security assessment)"
    verify_tls: bool = True
    source_path: str | None = None
    active_forms: bool = False
    osint: bool = False
    blind_delay: float = 2.0
    max_blind_params: int = 2
    arsenal_profile: str = "normal"
    arsenal_sections: list[str] = Field(default_factory=list)
    live_stream: bool = False
    open_report: bool = True
    shell_pack: str | None = None


class ScanContext:
    def __init__(
        self,
        *,
        target: str,
        scope: Scope,
        http: AsyncHttpClient,
        state: ScanState,
        bus: EventBus,
        cancel: CancellationToken,
        options: ScanOptions,
        logger: logging.Logger | None = None,
    ) -> None:
        self.target = target
        self.scope = scope
        self.http = http
        self.state = state
        self.bus = bus
        self.cancel = cancel
        self.options = options
        self.logger = logger or logging.getLogger("webscout_engine")

        self.base_url = scope.base_url
        self.soft404 = Soft404Detector(http, scope.base_url)
        self.crawl_result: Any = None
        self.params: list[Any] = []
        self.tls_info: Any = None
        self.tech_matches: list[Any] = []
        self.dns_result: Any = None
        self.port_results: list[Any] = []
        self.baseline_body: str = ""
        self.notes: list[str] = []
        self.skip_reasons: dict[str, str] = {}
        self._stream_handle: Any = None

    # ------------------------------------------------------------ json stream
    def open_stream(self, path: Any) -> None:
        """Append findings as JSON lines while the scan runs."""
        self._stream_handle = open(path, "w", encoding="utf-8")  # noqa: SIM115

    # ------------------------------------------------------------------ events
    async def emit(
        self,
        event_type: EventType,
        message: str,
        data: dict[str, Any] | None = None,
        level: str = "info",
    ) -> None:
        await self.bus.emit(event_type, message, data, level)

    # ---------------------------------------------------------------- findings
    def add_finding(self, finding: Finding) -> bool:
        added = self.state.add_finding(finding)
        if added:
            self.logger.info("finding %s %s %s", finding.severity.value, finding.check, finding.endpoint)
            if self._stream_handle is not None:
                import json

                self._stream_handle.write(json.dumps(finding.model_dump(mode="json")) + "\n")
                self._stream_handle.flush()
        return added

    def close_stream(self) -> None:
        if self._stream_handle is not None:
            try:
                self._stream_handle.close()
            finally:
                self._stream_handle = None

    def add_observation(self, observation: Observation) -> None:
        self.state.add_observation(observation)

    def note(self, message: str) -> None:
        if message not in self.notes:
            self.notes.append(message)

    def skip_module(self, name: str, reason: str) -> None:
        """Record that a module ran but had nothing applicable to do."""
        self.skip_reasons[name] = reason
        self.note(f"{name}: {reason}")

    # ---------------------------------------------------------------- progress
    def add_total(self, count: int) -> None:
        self.state.add_total(count)

    def progress(self, failed: bool = False) -> None:
        self.state.task_done(failed=failed)

    async def calibrate_soft404(self) -> None:
        try:
            await self.soft404.calibrate()
        except Exception as exc:  # calibration must never abort a scan
            self.logger.debug("soft-404 calibration failed: %s", exc)
