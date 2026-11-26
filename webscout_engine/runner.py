"""Scan execution shared by the CLI and the interactive interface."""

from __future__ import annotations

import asyncio
import contextlib
import signal
from dataclasses import dataclass, field
from pathlib import Path

from rich.console import Console

from .config import Settings, reports_dir
from .core.net import CancellationToken
from .core.runtime import ScanOptions
from .core.runtime import ScanEngine, create_context
from .core.events import EventBus
from .core.models import ScanReport
from .config import HistoryStore
from .report import generate_reports
from .ui.dashboard import Dashboard
from .ui.dashboard import LiveStream
from .ui.summary import open_report_in_browser, print_full_report, print_summary


@dataclass
class ScanResult:
    report: ScanReport | None = None
    paths: dict[str, Path] = field(default_factory=dict)
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.report is not None


def build_options(settings: Settings, **overrides: object) -> ScanOptions:
    """Merge persisted settings with explicit CLI overrides."""
    payload = settings.model_dump()
    payload.pop("ui", None)
    for key, value in overrides.items():
        if value is not None:
            payload[key] = value
    allowed = set(ScanOptions.model_fields)
    return ScanOptions(**{key: value for key, value in payload.items() if key in allowed})


async def execute_scan(
    console: Console,
    target: str,
    options: ScanOptions,
    modules: list[str] | None = None,
    show_dashboard: bool = True,
) -> ScanResult:
    """Run one assessment, render the dashboard, write reports and record history."""
    bus = EventBus()
    cancel = CancellationToken()
    loop = asyncio.get_running_loop()
    signal_installed = False
    with contextlib.suppress(NotImplementedError, RuntimeError, ValueError):
        loop.add_signal_handler(signal.SIGINT, cancel.cancel, "cancelled by user (Ctrl+C)")
        signal_installed = True

    result = ScanResult()
    ctx = None
    stream_path: Path | None = None
    try:
        ctx = await create_context(target, options, bus=bus, cancel=cancel)
        state = ctx.state
        if options.json_stream:
            out_dir = Path(options.output_dir).expanduser()
            out_dir.mkdir(parents=True, exist_ok=True)
            stream_path = out_dir / f"webscout_engine_{state.scan_id}_stream.jsonl"
            ctx.open_stream(stream_path)

        if options.shell_pack:
            from .arsenal.executor import execute_pack

            async def _echo(section: str, line: str, text: str) -> None:
                if options.live_stream:
                    console.print(f"[dim]{section}[/] $ {line[:110]}")
                    if text.strip():
                        console.print(f"    {text[:160]}")

            pack_findings = await execute_pack(
                ctx, options.shell_pack, echo=_echo if options.live_stream else None
            )
            if pack_findings:
                ctx.note(f"shell pack produced {len(pack_findings)} finding(s)")

        engine = ScanEngine(ctx, modules=modules)
        task = asyncio.create_task(engine.run(), name="webscout_engine-scan")
        if options.live_stream:
            stream = LiveStream(console, bus)
            await stream.watch(task, cancel)
        elif show_dashboard:
            dashboard = Dashboard(console, state, bus)
            await dashboard.watch(task, cancel)
        else:
            await task
        report = await task
        result.report = report
    except asyncio.CancelledError:
        result.error = "scan cancelled"
    except Exception as exc:  # surface a clean message instead of a traceback
        result.error = f"{type(exc).__name__}: {exc}"
    finally:
        if ctx is not None:
            ctx.close_stream()
            await ctx.http.close()
        if signal_installed:
            with contextlib.suppress(NotImplementedError, RuntimeError, ValueError):
                loop.remove_signal_handler(signal.SIGINT)

    if result.report is not None:
        report = result.report
        directory = reports_dir()
        if options.output_dir:
            directory = Path(options.output_dir).expanduser()
        try:
            result.paths = generate_reports(
                report, directory, formats=options.formats, force=options.force
            )
        except Exception as exc:
            result.error = f"report generation failed: {type(exc).__name__}: {exc}"
        try:
            with HistoryStore() as store:
                store.record(report, str(result.paths.get("json", "")))
        except Exception:
            pass  # history is a convenience, never a hard dependency
        if stream_path is not None:
            result.paths.setdefault("jsonl", stream_path)
    return result


def run_scan_sync(
    console: Console,
    target: str,
    options: ScanOptions,
    modules: list[str] | None = None,
    show_dashboard: bool = True,
) -> ScanResult:
    return asyncio.run(execute_scan(console, target, options, modules, show_dashboard))


def report_and_summarise(
    console: Console,
    result: ScanResult,
    print_report: bool = False,
    open_report: bool = True,
) -> None:
    if result.report is not None:
        print_summary(console, result.report, result.paths)
        if print_report:
            print_full_report(console, result.report)
        # A finished scan should end at its report, not at a file path to copy.
        open_report_in_browser(console, result.paths, enabled=open_report)
    if result.error:
        console.print(f"[#ff5c39]error:[/] {result.error}")
