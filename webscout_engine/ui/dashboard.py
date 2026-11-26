"""Live interfaces: the summary dashboard and the per-probe stream."""

from __future__ import annotations

import asyncio
from rich.align import Align
from rich.box import SIMPLE_HEAD
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from ..core.net import CancellationToken
from ..core.events import EventBus
from ..core.models import SEVERITY_ORDER
from ..core.state import ScanState
from .theme import format_bytes, format_duration, format_eta, format_rate, progress_bar
from .theme import CYAN, MUTED, PURPLE, WHITE, confidence_color, severity_color
import time
from collections import deque
from ..core.events import Event, EventBus, EventType
from ..core.models import Severity
from .theme import format_duration, format_rate, progress_bar
from .theme import CYAN, MUTED, PURPLE, WHITE, severity_color


# -------------------------------------------------------------------------
# from dashboard.py
# -------------------------------------------------------------------------

EVENT_STYLES = {
    "warning": "#ff7a45",
    "error": "#ff4d3d",
    "info": MUTED,
    "debug": MUTED,
}


class Dashboard:
    def __init__(
        self,
        console: Console,
        state: ScanState,
        bus: EventBus,
        title: str = "webscout_engine",
    ) -> None:
        self.console = console
        self.state = state
        self.bus = bus
        self.title = title

    # ------------------------------------------------------------------ render
    def render(self) -> Panel:
        state = self.state
        header = Table.grid(expand=True)
        header.add_column(ratio=1)
        header.add_column(justify="right")
        left = Text()
        left.append("target  ", style=MUTED)
        left.append(state.target, style=f"bold {WHITE}")
        right = Text()
        right.append("scan ", style=MUTED)
        right.append(state.scan_id, style=CYAN)
        header.add_row(left, right)

        stage = Text()
        stage.append("module  ", style=MUTED)
        stage.append(state.current_module or "-", style=f"bold {CYAN}")
        stage.append("   stage  ", style=MUTED)
        stage.append(state.current_stage or "-", style=WHITE)
        stage.append("   operation  ", style=MUTED)
        stage.append(state.current_operation or "-", style=WHITE)

        progress_row = Table.grid(expand=True)
        progress_row.add_column(ratio=1)
        progress_row.add_column(justify="right")
        progress_row.add_row(
            progress_bar(state.progress_fraction()),
            Text(
                f"{state.stats.tasks_completed}/{state.stats.tasks_total} tasks",
                style=WHITE,
            ),
        )

        timing = Text()
        timing.append("elapsed ", style=MUTED)
        timing.append(format_duration(state.elapsed), style=WHITE)
        timing.append("   eta ", style=MUTED)
        timing.append(format_eta(state.eta()), style=WHITE)
        timing.append("   rps ", style=MUTED)
        timing.append(format_rate(state.rps()), style=WHITE)
        timing.append("   status ", style=MUTED)
        timing.append(state.status_text, style=CYAN)

        counter_row = Table.grid(expand=True)
        for _ in range(5):
            counter_row.add_column(justify="center")
        counts = state.severity_counts()
        cells = []
        for severity in SEVERITY_ORDER:
            cell = Text()
            cell.append(f"{severity.value.upper()} ", style=MUTED)
            cell.append(str(counts.get(severity.value, 0)), style=f"bold {severity_color(severity)}")
            cells.append(cell)
        counter_row.add_row(*cells)

        stats = Table.grid(expand=True)
        for _ in range(6):
            stats.add_column(justify="left")
        stats.add_row(
            self._stat("requests", str(state.stats.requests)),
            self._stat("retries", str(state.stats.retries)),
            self._stat("timeouts", str(state.stats.timeouts)),
            self._stat("errors", str(state.stats.errors)),
            self._stat("rate limited", str(state.stats.rate_limited)),
            self._stat("received", format_bytes(state.stats.bytes_received)),
        )

        probes = Table(box=None, expand=True, show_header=True, header_style=MUTED, pad_edge=False)
        probes.add_column("m", width=5, no_wrap=True)
        probes.add_column("probe sent", ratio=1, overflow="ellipsis", no_wrap=True)
        probes.add_column("code", width=5, justify="right", no_wrap=True)
        probes.add_column("ms", width=6, justify="right", no_wrap=True)
        records = list(state.probe_log)[-8:]
        if records:
            for record in records:
                if record.status == 0:
                    style = MUTED
                elif record.status < 300:
                    style = WHITE
                elif record.status < 400:
                    style = CYAN
                else:
                    style = "#ff7a45"
                probes.add_row(
                    Text(record.method, style=MUTED),
                    Text(record.path, style=style),
                    Text(str(record.status or "-"), style=style),
                    Text(f"{record.elapsed * 1000:.0f}", style=MUTED),
                )
        else:
            probes.add_row(Text("-", style=MUTED), Text("waiting for the first request", style=MUTED), "", "")

        probes_caption = Text()
        probes_caption.append("probes sent ", style=MUTED)
        probes_caption.append(f"{state.probe_total}", style=f"bold {WHITE}")
        probes_caption.append("   ·   latest at the bottom", style=MUTED)

        findings_table = Table(box=SIMPLE_HEAD, expand=True, show_edge=False, pad_edge=False)
        findings_table.add_column("sev", width=8, no_wrap=True)
        findings_table.add_column("check", width=22, no_wrap=True)
        findings_table.add_column("endpoint", ratio=1, overflow="ellipsis", no_wrap=True)
        findings_table.add_column("status", width=6, justify="right")
        findings_table.add_column("conf", width=8, no_wrap=True)
        recent = state.findings[-7:]
        if recent:
            for finding in recent:
                findings_table.add_row(
                    Text(finding.severity.value.upper(), style=f"bold {severity_color(finding.severity)}"),
                    Text(finding.check, style=WHITE),
                    Text(finding.endpoint, style=MUTED),
                    Text(str(finding.status_code or "-"), style=WHITE),
                    Text(finding.confidence.value, style=confidence_color(finding.confidence)),
                )
        else:
            findings_table.add_row(Text("no findings yet", style=MUTED), "", "", "", "")

        events = Table.grid(expand=True)
        events.add_column(width=9)
        events.add_column(ratio=1)
        history = self.bus.history(5)
        if history:
            for event in history:
                events.add_row(
                    Text(event.type.value, style=EVENT_STYLES.get(event.level, MUTED)),
                    Text(event.message[:110], style=WHITE if event.level == "info" else EVENT_STYLES.get(event.level, WHITE)),
                )
        else:
            events.add_row(Text("starting", style=MUTED), Text("waiting for the first event", style=MUTED))

        body = Group(
            header,
            stage,
            Text(""),
            progress_row,
            timing,
            Text(""),
            counter_row,
            Text(""),
            stats,
            Text(""),
            probes_caption,
            probes,
            Text(""),
            findings_table,
            Text(""),
            events,
        )
        return Panel(
            body,
            title=f"[bold]{self.title}[/]",
            border_style=PURPLE,
            subtitle="Ctrl+C cancels cleanly and saves partial results",
            subtitle_align="right",
            padding=(0, 1),
        )

    @staticmethod
    def _stat(label: str, value: str) -> Text:
        text = Text()
        text.append(f"{label} ", style=MUTED)
        text.append(value, style=f"bold {WHITE}")
        return text

    # ------------------------------------------------------------------- watch
    async def watch(self, task: asyncio.Task, cancel: CancellationToken) -> None:
        """Render until ``task`` completes; Ctrl+C requests cooperative cancellation."""
        with Live(
            self.render(),
            console=self.console,
            refresh_per_second=8,
            transient=False,
            vertical_overflow="visible",
        ) as live:
            try:
                while not task.done():
                    live.update(self.render(), refresh=True)
                    await asyncio.sleep(0.15)
            except KeyboardInterrupt:
                cancel.cancel("cancelled by user (Ctrl+C)")
                try:
                    await asyncio.wait_for(asyncio.shield(task), timeout=20)
                except (TimeoutError, asyncio.CancelledError):
                    task.cancel()
            except asyncio.CancelledError:
                cancel.cancel("scan cancelled")
                raise
            live.update(self.render(), refresh=True)


def render_idle_summary(console: Console, target: str) -> None:
    console.print(Align.left(Text(f"No active scan for {target}", style=MUTED)))


# -------------------------------------------------------------------------
# from stream.py
# -------------------------------------------------------------------------

_MAX_LINES = 14


class LiveStream:
    """Subscribes to the bus and renders a rolling probe transcript."""

    def __init__(
        self,
        console: Console,
        bus: EventBus,
        title: str = "webscout_engine arsenal",
        max_lines: int = _MAX_LINES,
    ) -> None:
        self.console = console
        self.bus = bus
        self.title = title
        self.max_lines = max_lines
        self.lines: deque[Text] = deque(maxlen=max_lines)
        self.total = 0
        self.done = 0
        self.hits = 0
        self.errors = 0
        self.started = time.perf_counter()
        self.section = ""
        self.status = "starting"
        self._last_render = 0.0
        self._plain = not console.is_terminal

    # ------------------------------------------------------------------ events
    def on_event(self, event: Event) -> None:
        if event.type is EventType.OPERATION and event.data.get("kind") == "probe":
            self._on_probe(event.data)
        elif event.type is EventType.STAGE:
            self.section = event.message
        elif event.type is EventType.SCAN_END:
            self.status = "finished"
        elif event.type is EventType.SCAN_START:
            self.status = "running"

    def _on_probe(self, data: dict) -> None:
        self.done = int(data.get("done") or self.done)
        self.total = int(data.get("total") or self.total)
        self.section = data.get("section_label") or self.section
        status = data.get("status") or 0
        elapsed = float(data.get("elapsed") or 0.0)
        hit = bool(data.get("hit"))
        error = data.get("error") or ""
        if error and not status:
            self.errors += 1
        if hit:
            self.hits += 1
        line = self._render_line(data, status, elapsed, hit, error)
        self.lines.append(line)
        if self._plain:
            self.console.print(line)
        else:
            now = time.perf_counter()
            if now - self._last_render > 0.08:
                self._last_render = now

    def _render_line(
        self, data: dict, status: int, elapsed: float, hit: bool, error: str
    ) -> Text:
        severity = Severity(data.get("severity", "info"))
        colour = severity_color(severity) if hit else MUTED
        text = Text()
        text.append("◆ " if hit else "· ", style=colour if hit else MUTED)
        text.append(f"{data.get('probe_id', '----'):<8}", style=MUTED)
        if hit:
            text.append(f"{status:>3} ", style=colour)
        else:
            text.append(f"{status:>3} ", style=WHITE if status else MUTED)
        text.append(f"{elapsed * 1000:6.0f}ms ", style=MUTED)
        text.append(f"{data.get('method', 'GET'):<7}", style=CYAN)
        url = str(data.get("url", ""))
        if len(url) > 62:
            url = url[:59] + "..."
        text.append(url, style=WHITE if hit else MUTED)
        if hit:
            text.append("  HIT ", style=f"bold {colour}")
            text.append(str(data.get("title", ""))[:52], style=colour)
        elif error:
            text.append(f"  {error}"[:40], style="#ff7a45")
        return text

    # ----------------------------------------------------------------- render
    def render(self) -> Panel:
        elapsed = time.perf_counter() - self.started
        rate = self.done / elapsed if elapsed > 0 else 0.0
        header = Table.grid(expand=True)
        header.add_column(ratio=1)
        header.add_column(justify="right")
        left = Text()
        left.append("section  ", style=MUTED)
        left.append(self.section or "-", style=f"bold {CYAN}")
        right = Text()
        right.append(f"{self.done}", style=f"bold {WHITE}")
        right.append(f"/{self.total} probes", style=MUTED)
        header.add_row(left, right)

        fraction = (self.done / self.total) if self.total else 0.0
        body = list(self.lines) or [Text("waiting for the first response...", style=MUTED)]

        footer = Text()
        footer.append("hits ", style=MUTED)
        footer.append(str(self.hits), style=f"bold {PURPLE if self.hits else WHITE}")
        footer.append("   errors ", style=MUTED)
        footer.append(str(self.errors), style="#ff7a45" if self.errors else WHITE)
        footer.append("   rate ", style=MUTED)
        footer.append(format_rate(rate), style=WHITE)
        footer.append("   elapsed ", style=MUTED)
        footer.append(format_duration(elapsed), style=WHITE)
        footer.append("   ", style=MUTED)
        footer.append(self.status, style=CYAN)

        group = Group(
            header,
            progress_bar(fraction, width=48),
            *body,
            footer,
        )
        return Panel(group, border_style=PURPLE, title=self.title, subtitle="live probe stream")

    # ------------------------------------------------------------------- loop
    async def watch(self, task: asyncio.Task, cancel: CancellationToken | None = None) -> None:
        self.bus.subscribe(self.on_event)
        try:
            if self._plain:
                await task
                return
            with Live(self.render(), console=self.console, refresh_per_second=10,
                      transient=False, screen=False) as live:
                while not task.done():
                    live.update(self.render())
                    await asyncio.sleep(0.1)
                live.update(self.render())
        finally:
            self.bus.unsubscribe(self.on_event)
