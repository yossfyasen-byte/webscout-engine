"""Terminal theme, colour helpers, progress formatting and the banner."""

from __future__ import annotations

from rich.console import Console
from rich.text import Text
from ..core.models import Confidence, Severity
from rich.progress_bar import ProgressBar
from rich.align import Align
from rich.console import Group
from rich.panel import Panel
from .. import DEVELOPER_GITHUB, DEVELOPER_TELEGRAM, __version__


# -------------------------------------------------------------------------
# from theme.py
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# from theme.py
# -------------------------------------------------------------------------

# Primary accents ------------------------------------------------------------
PURPLE = "#ff2d55"       # primary accent (borders, titles, table frames)
DEEP_PURPLE = "#8b0f1f"  # deep accent (separators, dimmed frames)
CYAN = "#ff6b81"         # secondary accent (labels, values, event lines)
TEAL = "#ff8a9b"
INK = "#0d0b1a"
MUTED = "#c98a92"        # muted rose: readable, still red
WHITE = "#ffe9ec"        # near-white with a warm tint
RED = "#ff2d55"
DEEP_RED = "#a3001b"
BRIGHT_RED = "#ff1f4b"

# Severity ramp: same family, decreasing intensity ---------------------------
SEVERITY_COLORS: dict[str, str] = {
    "critical": "#ff1f4b",
    "high": "#ff4d3d",
    "medium": "#ff7a45",
    "low": "#ff9d7a",
    "info": "#d9a0a8",
}

CONFIDENCE_COLORS: dict[str, str] = {
    "certain": "#ff2d55",
    "high": "#ff5c7a",
    "medium": "#ff8a9b",
    "low": "#d9a0a8",
}


def make_console(no_color: bool = False, ascii_only: bool = False) -> Console:
    return Console(
        no_color=no_color,
        highlight=False,
        soft_wrap=False,
        emoji=not ascii_only,
    )


def severity_color(severity: Severity | str) -> str:
    value = severity.value if isinstance(severity, Severity) else str(severity)
    return SEVERITY_COLORS.get(value, WHITE)


def confidence_color(confidence: Confidence | str) -> str:
    value = confidence.value if isinstance(confidence, Confidence) else str(confidence)
    return CONFIDENCE_COLORS.get(value, WHITE)


def gradient_text(text: str, start: str = PURPLE, end: str = CYAN) -> Text:
    """Colour ``text`` character by character from ``start`` to ``end``."""
    start_rgb = _hex_to_rgb(start)
    end_rgb = _hex_to_rgb(end)
    length = max(1, len(text) - 1)
    result = Text()
    for index, char in enumerate(text):
        ratio = index / length
        rgb = tuple(
            round(start_rgb[channel] + (end_rgb[channel] - start_rgb[channel]) * ratio)
            for channel in range(3)
        )
        result.append(char, style=f"#{rgb[0]:02x}{rgb[1]:02x}{rgb[2]:02x}")
    return result


def _hex_to_rgb(value: str) -> tuple[int, int, int]:
    value = value.lstrip("#")
    return int(value[0:2], 16), int(value[2:4], 16), int(value[4:6], 16)


def severity_badge(severity: Severity) -> Text:
    return Text(severity.value.upper(), style=f"bold {severity_color(severity)}")


# -------------------------------------------------------------------------
# from progress.py
# -------------------------------------------------------------------------

def format_duration(seconds: float | None) -> str:
    if seconds is None:
        return "--:--"
    seconds = max(0, int(seconds))
    hours, remainder = divmod(seconds, 3600)
    minutes, secs = divmod(remainder, 60)
    if hours:
        return f"{hours:02d}:{minutes:02d}:{secs:02d}"
    return f"{minutes:02d}:{secs:02d}"


def format_eta(seconds: float | None) -> str:
    return "estimating" if seconds is None else format_duration(seconds)


def format_rate(value: float) -> str:
    return f"{value:.1f}/s"


def format_bytes(count: int) -> str:
    size = float(count)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if size < 1024 or unit == "GiB":
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024
    return f"{size:.1f} GiB"


def progress_bar(fraction: float, width: int = 34) -> ProgressBar:
    return ProgressBar(
        total=100,
        completed=max(0.0, min(1.0, fraction)) * 100,
        width=width,
        complete_style=PURPLE,
        finished_style=CYAN,
        pulse_style=CYAN,
    )


def progress_line(completed: int, total: int, fraction: float) -> Text:
    text = Text()
    text.append(f"{completed}", style=f"bold {WHITE}")
    text.append("/", style=MUTED)
    text.append(f"{total}", style=WHITE)
    text.append(f"  {fraction * 100:5.1f}%", style=CYAN)
    return text


# -------------------------------------------------------------------------
# from banner.py
# -------------------------------------------------------------------------

TAGLINE = "Advanced Security Assessment Framework"
SUBTITLE = "authorised testing only - written permission required"

# The project logo. Kept verbatim: every line is a fixed-width block of braille
# and box-drawing characters, so it must never be reflowed.
LOGO: tuple[str, ...] = tuple(
    line.strip("\n")
    for line in """⠀⠀⠀⠀⢀⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⡀⢀⠀⠀⠀⠀
⠀⠀⠀⢠⠂⢰⠁⠀⠀⠀⠀⠀⠀⠀⠀⠰⡀⢣⡀⠀⠀
⠀⠀⢀⡏⢀⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣧⠀⢧⠀⠀
⠀⠀⣼⠀⣾⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡆⢸⡆⠀
⠀⢠⣿⠀⠙⣛⣋⣭⣳⣴⣦⣴⣴⣫⣭⣛⡛⠋⠈⣿⠀
⠀⠈⠻⠟⠋⢉⣴⠶⣾⣿⣿⣿⣿⡶⠶⣌⠉⠙⠻⠟⠁
⠀⠀⠀⣠⡴⠛⢡⡾⠋⣿⣿⣿⣧⠹⣦⡌⠳⣦⡀⠀⠀
⢠⣴⠞⠉⠀⠀⢸⡏⠀⢿⣿⣿⡇⠀⣿⡇⠀⠀⠙⢷⣤
⢸⣏⠀⠀⠀⠀⢸⡇⠀⠸⣿⣿⠁⠀⣿⡇⠀⠀⠀⠀⣿
⠀⣿⠀⠀⠀⠀⢸⡇⠀⠀⠙⠃⠀⠀⣿⠇⠀⠀⠀⢰⡟
⠀⢹⡄⠀⠀⠀⢸⡇⠀⠀⠀⠀⠀⠀⣿⠀⠀⠀⠀⣸⠃
⠀⠀⢣⠀⠀⠀⠀⣧⠀⠀⠀⠀⠀⢀⡏⠀⠀⠀⢀⠏⠀
⠀⠀⠈⢆⠀⠀⠀⢸⡀⠀⠀⠀⠀⢸⠁⠀⠀⠀⡜⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢡⠀⠀⠀⢀⠃⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀""".splitlines()
)

LOGO_WIDTH = max(len(line) for line in LOGO)


def _logo() -> Text:
    """Colour the logo line by line: bright red at the top, deep red at the base."""
    total = max(1, len(LOGO) - 1)
    text = Text(no_wrap=True, overflow="ignore")
    for index, line in enumerate(LOGO):
        ratio = index / total
        style = _blend(RED, DEEP_RED, ratio)
        text.append(line, style=style)
        if index != len(LOGO) - 1:
            text.append("\n")
    return text


def _blend(start: str, end: str, ratio: float) -> str:
    def rgb(value: str) -> tuple[int, int, int]:
        value = value.lstrip("#")
        return int(value[0:2], 16), int(value[2:4], 16), int(value[4:6], 16)

    left, right = rgb(start), rgb(end)
    mixed = tuple(round(left[i] + (right[i] - left[i]) * ratio) for i in range(3))
    return f"#{mixed[0]:02x}{mixed[1]:02x}{mixed[2]:02x}"


def credits() -> Text:
    text = Text(justify="center")
    text.append("developer  ", style=MUTED)
    text.append(DEVELOPER_TELEGRAM, style=f"bold {CYAN}")
    text.append("   ·   ", style=MUTED)
    text.append(DEVELOPER_GITHUB.replace("https://", "").rstrip("/"), style=CYAN)
    return text


def banner(ascii_only: bool = False) -> Group:
    if ascii_only:
        width = 58
        lines = Group(
            Text("=" * width, style=PURPLE),
            gradient_text("  Z E R O S P E C T E R", RED, "#ff8a9b"),
            Text(f"  {TAGLINE}", style=WHITE),
            Text(f"  v{__version__}  |  {SUBTITLE}", style=MUTED),
            Text("-" * width, style=CYAN),
            credits(),
        )
        return Group(lines)

    return Group(
        _logo(),
        Text(""),
        gradient_text("  Z E R O S P E C T E R", RED, "#ff8a9b"),
        Text(f"  {TAGLINE}", style=WHITE),
        Text(f"  v{__version__}  |  {SUBTITLE}", style=MUTED),
        Text(""),
        credits(),
    )


def banner_panel(ascii_only: bool = False) -> Panel:
    return Panel(
        Align.center(banner(ascii_only)),
        border_style=RED,
        padding=(0, 2),
    )


def section(title: str) -> Text:
    text = Text()
    text.append("  ", style="")
    text.append(title, style=f"bold {CYAN}")
    return text
