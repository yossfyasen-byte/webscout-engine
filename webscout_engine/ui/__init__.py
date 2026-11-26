"""Terminal user interface: banner, menu, dashboard and summaries."""

from __future__ import annotations

from .theme import banner_panel
from .dashboard import Dashboard
from .summary import Menu, MenuItem
from .summary import history_table, print_full_report, print_history, print_summary, summary_panel
from .theme import make_console

__all__ = [
    "banner_panel",
    "Dashboard",
    "Menu",
    "MenuItem",
    "make_console",
    "print_summary",
    "print_full_report",
    "print_history",
    "history_table",
    "summary_panel",
]
