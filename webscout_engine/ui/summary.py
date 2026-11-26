"""Post-scan summaries, report listing and the interactive menu."""

from __future__ import annotations

from pathlib import Path
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from ..core.models import SEVERITY_ORDER, ScanReport
from ..config import ScanSummary
from .theme import format_duration
from .theme import CYAN, MUTED, PURPLE, WHITE, severity_color
import os
import sys
from dataclasses import dataclass
from typing import Any
from rich.live import Live
from .theme import CYAN, MUTED, PURPLE, WHITE, gradient_text


# -------------------------------------------------------------------------
# from summary.py
# -------------------------------------------------------------------------

MAX_SUMMARY_FINDINGS = 15
MAX_NOTES = 4


def _severity_row(report: ScanReport) -> Table:
    row = Table.grid(expand=True)
    for _ in range(5):
        row.add_column(justify="center")
    cells = []
    for severity in SEVERITY_ORDER:
        cell = Text()
        cell.append(f"{severity.value.upper()}\n", style=MUTED)
        cell.append(str(report.severity_counts.get(severity.value, 0)), style=f"bold {severity_color(severity)}")
        cells.append(cell)
    row.add_row(*cells)
    return row


def _coverage_line(report: ScanReport) -> Text:
    ran = [entry for entry in report.coverage if not entry.reason]
    skipped = [entry for entry in report.coverage if entry.reason]
    text = Text()
    text.append("modules  ", style=MUTED)
    text.append(f"{len(ran)}/{len(report.coverage)} run", style=f"bold {WHITE}")
    if skipped:
        text.append("   skipped ", style=MUTED)
        text.append(", ".join(entry.module for entry in skipped[:6]), style=CYAN)
        if len(skipped) > 6:
            text.append(f" +{len(skipped) - 6}", style=MUTED)
        text.append("  (reasons in the report)", style=MUTED)
    return text


def summary_panel(report: ScanReport) -> Panel:
    header = Text()
    header.append("target   ", style=MUTED)
    header.append(report.target, style=f"bold {WHITE}")
    header.append("\nrun      ", style=MUTED)
    header.append(format_duration(report.duration_seconds), style=WHITE)
    header.append("   requests ", style=MUTED)
    header.append(str(report.stats.requests), style=WHITE)
    header.append("   status ", style=MUTED)
    if report.completed:
        header.append("completed", style="#ff2d55")
    else:
        header.append("interrupted - partial results", style="#ff7a45")

    findings = Table(box=None, expand=True, pad_edge=False, show_header=True, header_style=MUTED)
    findings.add_column("sev", width=8, no_wrap=True)
    findings.add_column("check", width=20, no_wrap=True)
    findings.add_column("finding", ratio=3, overflow="fold")
    findings.add_column("endpoint", ratio=2, overflow="fold")
    shown = report.sorted_findings()[:MAX_SUMMARY_FINDINGS]
    for finding in shown:
        findings.add_row(
            Text(finding.severity.value.upper(), style=f"bold {severity_color(finding.severity)}"),
            Text(finding.check, style=MUTED),
            Text(finding.title, style=WHITE),
            Text(finding.endpoint.replace(report.target.rstrip("/"), "") or "/", style=MUTED),
        )
    if not report.findings:
        findings.add_row(Text("-", style=MUTED), "", Text("no findings", style=MUTED), "")

    blocks: list = [header, Text(""), _severity_row(report), Text(""), _coverage_line(report), Text(""), findings]
    if len(report.findings) > MAX_SUMMARY_FINDINGS:
        blocks.append(
            Text(
                f"  +{len(report.findings) - MAX_SUMMARY_FINDINGS} more in the report "
                f"(use --print-report to show all)",
                style=MUTED,
            )
        )
    notes = [note for note in report.notes if note.strip()]
    if notes:
        block = Text()
        block.append("\nnotes\n", style=f"bold {MUTED}")
        for note in notes[:MAX_NOTES]:
            block.append(f"  - {note[:150]}\n", style=MUTED)
        if len(notes) > MAX_NOTES:
            block.append(f"  +{len(notes) - MAX_NOTES} more\n", style=MUTED)
        blocks.append(block)

    return Panel(
        Group(*blocks),
        title="[bold]Assessment summary[/]",
        border_style=CYAN if report.completed else "#ff7a45",
        padding=(1, 2),
    )


def _file_size(path: Path) -> str:
    try:
        size = float(path.stat().st_size)
    except OSError:
        return "-"
    for unit in ("B", "KiB", "MiB"):
        if size < 1024 or unit == "MiB":
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024
    return "-"


def reports_table(paths: dict[str, Path]) -> Table:
    """The four report files, as a table with clickable links."""
    table = Table(
        title="Reports",
        title_justify="left",
        title_style=f"bold {MUTED}",
        border_style=PURPLE,
        header_style=MUTED,
        expand=True,
        pad_edge=False,
    )
    table.add_column("format", width=7, no_wrap=True)
    table.add_column("file", ratio=1, overflow="fold")
    table.add_column("size", width=10, justify="right", no_wrap=True)
    labels = {
        "html": "HTML",
        "json": "JSON",
        "csv": "CSV",
        "sarif": "SARIF",
        "jsonl": "JSONL",
    }
    for fmt in ("html", "json", "csv", "sarif", "jsonl"):
        path = paths.get(fmt)
        if path is None:
            continue
        try:
            uri = Path(path).expanduser().resolve().as_uri()
        except (OSError, ValueError):
            uri = ""
        name = Path(path).name
        table.add_row(
            Text(labels.get(fmt, fmt.upper()), style=CYAN if fmt == "html" else MUTED),
            Text(name, style=f"link {uri}" if uri else WHITE),
            Text(_file_size(Path(path)), style=MUTED),
        )
    return table


def print_summary(console: Console, report: ScanReport, paths: dict[str, Path] | None = None) -> None:
    console.print(summary_panel(report))
    if not paths:
        return
    console.print(reports_table(paths))
    html = paths.get("html")
    if html is not None:
        try:
            uri = Path(html).expanduser().resolve().as_uri()
        except (OSError, ValueError):
            uri = str(html)
        console.print(Text("  open in a browser  ", style=MUTED), Text(uri, style=f"link {uri} {CYAN}"))


def open_report_in_browser(
    console: Console,
    paths: dict[str, Path] | None,
    enabled: bool = True,
) -> bool:
    """Open the HTML report when the run is interactive.

    Silently does nothing in CI, in a pipe, or when webscout_engine_NO_BROWSER is set,
    so scripted scans never try to launch a browser.
    """
    if not enabled or not paths:
        return False
    path = paths.get("html")
    if path is None:
        return False

    import os
    import sys
    import webbrowser

    if os.environ.get("webscout_engine_NO_BROWSER") or os.environ.get("CI"):
        return False
    if not (sys.stdout.isatty() or sys.stdin.isatty()):
        return False
    try:
        uri = Path(path).expanduser().resolve().as_uri()
    except (OSError, ValueError):
        return False
    try:
        opened = webbrowser.open(uri)
    except Exception:  # no browser, no display, no problem
        opened = False
    console.print(
        Text("  opened the HTML report in your browser" if opened else "  could not launch a browser",
             style=MUTED)
    )
    return bool(opened)


def print_full_report(console: Console, report: ScanReport) -> None:
    """Print every finding, grouped by severity (``--print-report``)."""
    console.print(
        Panel(
            Text.assemble(
                (report.target, f"bold {WHITE}"),
                ("\n", ""),
                (f"{len(report.findings)} findings · {format_duration(report.duration_seconds)} · "
                 f"{report.stats.requests} requests", MUTED),
            ),
            border_style=PURPLE,
            title="Full report",
        )
    )
    for severity in SEVERITY_ORDER:
        group = [f for f in report.sorted_findings() if f.severity == severity]
        if not group:
            continue
        table = Table(
            title=f"{severity.value.upper()} ({len(group)})",
            title_justify="left",
            title_style=f"bold {severity_color(severity)}",
            border_style=PURPLE,
            header_style=MUTED,
            expand=True,
            show_lines=False,
        )
        table.add_column("check", width=20, no_wrap=True)
        table.add_column("confidence", width=10, no_wrap=True)
        table.add_column("finding", ratio=2, overflow="fold")
        table.add_column("endpoint", ratio=2, overflow="fold")
        table.add_column("cwe", width=9, no_wrap=True)
        for finding in group:
            table.add_row(
                finding.check,
                finding.confidence.value,
                finding.title,
                finding.endpoint,
                finding.cwe or "-",
            )
        console.print(table)

    if report.coverage:
        coverage = Table(title="Coverage", border_style=PURPLE, header_style=MUTED, expand=True)
        coverage.add_column("module", width=10)
        coverage.add_column("id", width=16, no_wrap=True)
        coverage.add_column("type", width=8)
        coverage.add_column("status", width=10)
        coverage.add_column("findings", width=9, justify="right")
        coverage.add_column("reason", ratio=1, overflow="fold")
        for entry in report.coverage:
            coverage.add_row(
                entry.module,
                entry.module_id,
                entry.scan_type,
                entry.status.value,
                str(entry.findings),
                entry.reason,
            )
        console.print(coverage)


def history_table(scans: list[ScanSummary]) -> Table:
    table = Table(title="Scan history", border_style=PURPLE, header_style=MUTED, expand=True)
    table.add_column("scan id", style=CYAN, no_wrap=True)
    table.add_column("target", ratio=1, overflow="fold")
    table.add_column("started (UTC)", width=17, no_wrap=True)
    table.add_column("findings", justify="right", width=9)
    table.add_column("crit", justify="right", width=5)
    table.add_column("high", justify="right", width=5)
    table.add_column("duration", justify="right", width=9)
    table.add_column("status", width=12)
    for scan in scans:
        table.add_row(
            scan.scan_id,
            scan.target,
            scan.started_at[:16].replace("T", " "),
            str(scan.findings),
            Text(str(scan.critical), style=severity_color("critical")),
            Text(str(scan.high), style=severity_color("high")),
            format_duration(scan.duration),
            "completed" if scan.completed else ("interrupted" if scan.interrupted else "partial"),
        )
    return table


def print_history(console: Console, scans: list[ScanSummary]) -> None:
    if not scans:
        console.print(Panel(Text("No scans recorded yet.", style=MUTED), border_style=PURPLE))
        return
    console.print(history_table(scans))


# -------------------------------------------------------------------------
# from menu.py
# -------------------------------------------------------------------------

# Arrow keys arrive as CSI (ESC [ A) on most terminals and as SS3 (ESC O A) on
# several mobile terminals, including Termux. Both are accepted.
ARROW_FINALS = {
    "A": "up",
    "B": "down",
    "C": "right",
    "D": "left",
    "H": "home",
    "F": "end",
}


@dataclass(slots=True)
class MenuItem:
    key: str
    label: str
    description: str = ""


class _RawKeys:
    """Puts the terminal into cbreak mode so single keys can be read.

    If raw mode cannot be enabled (no termios, stdin is not a TTY, a terminal
    that refuses the ioctl) the object reports ``active == False`` and the menu
    falls back to a plain numbered prompt instead of misreading keystrokes.
    """

    def __init__(self) -> None:
        self._fd: int | None = None
        self._settings: list[Any] | None = None

    @property
    def active(self) -> bool:
        return self._fd is not None

    def __enter__(self) -> _RawKeys:
        try:
            import termios
            import tty

            fd = sys.stdin.fileno()
            if not sys.stdin.isatty():
                return self
            settings = termios.tcgetattr(fd)
            tty.setcbreak(fd)
            self._fd = fd
            self._settings = settings
        except Exception:
            self._fd = None
            self._settings = None
        return self

    def __exit__(self, *exc: object) -> None:
        if self._fd is not None and self._settings is not None:
            try:
                import termios

                termios.tcsetattr(self._fd, termios.TCSADRAIN, self._settings)
            except Exception:
                pass
        self._fd = None
        self._settings = None

    def _target_fd(self) -> int | None:
        if self._fd is not None:
            return self._fd
        try:
            return sys.stdin.fileno()
        except (AttributeError, ValueError, OSError):
            return None

    def _read_byte(self, timeout: float | None = None) -> bytes:
        """Read one raw byte from the terminal.

        Bytes are read straight from the file descriptor, never through a
        buffered text wrapper: a wrapper would swallow the rest of an escape
        sequence into its own buffer, where ``select`` cannot see it.
        """
        fd = self._target_fd()
        if fd is None:
            return b""
        if timeout is not None:
            import select

            ready, _, _ = select.select([fd], [], [], timeout)
            if not ready:
                return b""
        try:
            return os.read(fd, 1)
        except OSError:
            return b""

    def _read_escape_tail(self) -> str:
        """Collect the rest of an escape sequence (``[A``, ``OA``, ``[1;5C``...).

        ``O`` in an SS3 sequence is a letter but *not* a terminator, so only the
        known final bytes end the read.
        """
        terminators = set(ARROW_FINALS) | {"~", "Z"}
        buffer = ""
        for _ in range(6):
            chunk = self._read_byte(0.12)
            if not chunk:
                break
            buffer += chunk.decode("utf-8", "replace")
            if len(buffer) >= 2 and buffer[-1] in terminators:
                break
        return buffer

    @classmethod
    def classify_escape(cls, tail: str) -> str:
        if not tail:
            return "escape"
        return ARROW_FINALS.get(tail[-1], "escape")

    def read_key(self) -> str:
        raw = self._read_byte()
        if not raw:
            return "quit"  # EOF: stdin is gone, leave gracefully
        char = raw.decode("utf-8", "replace")
        if char == "\x1b":
            return self.classify_escape(self._read_escape_tail())
        if char in ("\r", "\n"):
            return "enter"
        if char == "\x03":
            raise KeyboardInterrupt
        if char in ("q", "Q"):
            return "quit"
        if char == " ":
            return "space"
        return char


def _render(items: list[MenuItem], selected: int, title: str, hint: str) -> Panel:
    table = Table.grid(padding=(0, 1))
    table.add_column(justify="right", width=3)
    table.add_column()
    for index, item in enumerate(items):
        marker = Text(">", style=f"bold {CYAN}") if index == selected else Text(" ")
        label = Text(item.label, style=f"bold {WHITE}" if index == selected else WHITE)
        if index == selected:
            label.stylize(f"on {PURPLE}")
        table.add_row(marker, label)
        if item.description and index == selected:
            table.add_row(Text(""), Text(item.description, style=MUTED))
    footer = Text(hint, style=MUTED)
    header = gradient_text(title, PURPLE, CYAN)
    return Panel(
        Group(header, Text(""), table, Text(""), footer),
        border_style=PURPLE,
        padding=(1, 2),
        title="webscout_engine",
        title_align="left",
    )


class Menu:
    def __init__(
        self,
        console: Console,
        items: list[MenuItem],
        title: str = "Main menu",
        allow_arrows: bool = True,
    ) -> None:
        self.console = console
        self.items = items
        self.title = title
        self.allow_arrows = allow_arrows

    def _interactive(self) -> bool:
        try:
            return bool(self.allow_arrows and sys.stdin.isatty() and sys.stdout.isatty())
        except (AttributeError, ValueError):
            return False

    async def choose(self) -> str | None:
        if not self._interactive():
            return self._numeric()
        return self._arrows()

    def _arrows(self) -> str | None:
        selected = 0
        hint = "arrows to move - enter to select - digits work too - q quits"
        try:
            with _RawKeys() as keys:
                if not keys.active:
                    # Raw mode unavailable: never guess at keystrokes, just ask.
                    return self._numeric()
                with Live(
                    _render(self.items, selected, self.title, hint),
                    console=self.console,
                    auto_refresh=False,
                    transient=False,
                ) as live:
                    while True:
                        live.update(_render(self.items, selected, self.title, hint), refresh=True)
                        key = keys.read_key()
                        if key == "up":
                            selected = (selected - 1) % len(self.items)
                        elif key == "down":
                            selected = (selected + 1) % len(self.items)
                        elif key in ("enter", "right", "space"):
                            return self.items[selected].key
                        elif key == "quit":
                            return None
                        elif key == "escape":
                            continue  # a stray ESC must never quit the program
                        elif key.isdigit():
                            index = int(key) - 1
                            if 0 <= index < len(self.items):
                                return self.items[index].key
        except KeyboardInterrupt:
            return None
        except Exception:
            # Any terminal quirk: degrade to the numbered prompt instead of dying.
            return self._numeric()

    def _numeric(self) -> str | None:
        self.console.print(_render(self.items, -1, self.title, "enter a number and press return"))
        try:
            answer = self.console.input("[bold cyan]selection > [/]").strip()
        except (EOFError, KeyboardInterrupt):
            return None
        if not answer:
            return None
        if answer.lower() in ("q", "quit", "exit"):
            return None
        if answer.isdigit():
            index = int(answer) - 1
            if 0 <= index < len(self.items):
                return self.items[index].key
        self.console.print(f"[#ff7a45]Invalid selection: {answer}[/]")
        return ""
