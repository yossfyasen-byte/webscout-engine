"""Interactive terminal interface: menu loop, scan dispatch and settings."""

from __future__ import annotations

import asyncio

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text

from .config import Settings, save_settings
from .core.runtime import ScanOptions
from .core.scope import normalize_target
from .config import HistoryStore
from .modules import MODULE_LABELS, MODULE_ORDER, MODULE_SPECS, resolve_modules
from .runner import build_options, execute_scan, report_and_summarise
from .ui.theme import banner_panel
from .ui.summary import Menu, MenuItem
from .ui.summary import print_history
from .ui.theme import CYAN, MUTED, PURPLE, WHITE

MENU_ITEMS = [
    MenuItem("full", "1. Full Scan", "All modules: infrastructure, files, directories, technology, web checks"),
    MenuItem("files", "2. Sensitive File Discovery", "Exposed configuration, VCS, backup and diagnostic files"),
    MenuItem("dirs", "3. Directory Discovery", "Wordlist-based enumeration with recursion and soft-404 filtering"),
    MenuItem("infra", "4. Infrastructure Reconnaissance", "Ports, DNS metadata and technology fingerprinting"),
    MenuItem("vuln", "5. Deep Web Security Checks", "Headers, cookies, CORS, injection indicators, API and JWT checks"),
    MenuItem("settings", "6. Settings", "Review and change the persisted configuration"),
    MenuItem("history", "7. Scan History", "Previous assessments recorded in the local database"),
    MenuItem("multi", "8. Multi-Module Scan", "Pick any combination of modules"),
    MenuItem("exit", "9. Exit", "Quit webscout_engine"),
]

AUTHORISATION_TEXT = (
    "I confirm that I own this system or hold explicit written authorisation to test it, "
    "and that the assessment stays within the agreed scope."
)


class InteractiveSession:
    def __init__(self, console: Console, settings: Settings) -> None:
        self.console = console
        self.settings = settings

    # ------------------------------------------------------------------- loop
    async def run(self) -> int:
        self.console.print(banner_panel(self.settings.ui.ascii_only))
        while True:
            menu = Menu(
                self.console,
                MENU_ITEMS,
                title="Main menu",
                allow_arrows=self.settings.ui.arrow_keys,
            )
            choice = await menu.choose()
            if choice is None or choice == "exit":
                self.console.print(Text("Goodbye.", style=MUTED))
                return 0
            if choice == "":
                continue
            if choice == "settings":
                self._settings_screen()
                continue
            if choice == "history":
                self._history_screen()
                continue
            if choice == "multi":
                modules = self._choose_modules()
                if not modules:
                    continue
                await self._scan(modules)
                continue
            if choice == "full":
                await self._scan(list(MODULE_ORDER))
                continue
            await self._scan([choice])

    # ------------------------------------------------------------------ scans
    async def _scan(self, modules: list[str]) -> None:
        target = self._ask_target()
        if not target:
            return
        try:
            normalised = normalize_target(target)
        except ValueError as exc:
            self.console.print(f"[#ff4d3d]invalid target:[/] {exc}")
            return

        label = ", ".join(MODULE_LABELS[name] for name in modules)
        self.console.print(
            Panel(
                Text.assemble(
                    ("target  ", MUTED), (normalised, f"bold {WHITE}"), "\n",
                    ("modules ", MUTED), (label, CYAN),
                ),
                border_style=PURPLE,
                title="Scan plan",
            )
        )
        if not Confirm.ask(AUTHORISATION_TEXT, default=False, console=self.console):
            self.console.print(Text("Authorisation not confirmed - scan aborted.", style="#ff7a45"))
            return

        options = build_options(
            self.settings,
            modules=modules,
            output_dir=str(self.settings.output_dir) if self.settings.output_dir else None,
        )
        result = await execute_scan(self.console, normalised, options, modules=modules)
        report_and_summarise(self.console, result)

    def _ask_target(self) -> str | None:
        answer = Prompt.ask(
            "[bold cyan]target[/] (domain or URL, blank to cancel)",
            default="",
            console=self.console,
            show_default=False,
        ).strip()
        return answer or None

    def _choose_modules(self) -> list[str]:
        table = Table(box=None, show_header=False, pad_edge=False)
        table.add_column(width=4, style=CYAN)
        table.add_column(style=WHITE)
        table.add_column(style=MUTED)
        for index, name in enumerate(MODULE_ORDER, start=1):
            spec = MODULE_SPECS[name]
            table.add_row(str(index), MODULE_LABELS[name], f"{spec.scan_type} / {spec.module_id}")
        self.console.print(table)
        answer = Prompt.ask(
            "[bold cyan]modules[/] (comma separated numbers)",
            default="1,2,3,4",
            console=self.console,
        )
        selected: list[str] = []
        for chunk in answer.replace(" ", "").split(","):
            if not chunk.isdigit():
                continue
            index = int(chunk) - 1
            if 0 <= index < len(MODULE_ORDER):
                selected.append(MODULE_ORDER[index])
        if not selected:
            self.console.print(Text("No valid module selected.", style="#ff7a45"))
            return []
        return resolve_modules(selected)

    # --------------------------------------------------------------- settings
    def _settings_screen(self) -> None:
        table = Table(title="Settings", border_style=PURPLE, header_style=MUTED)
        table.add_column("key", style=CYAN)
        table.add_column("value", style=WHITE)
        for key, value in self.settings.model_dump().items():
            if key == "ui":
                continue
            table.add_row(key, str(value))
        self.console.print(table)

        if not Confirm.ask("Edit settings now?", default=False, console=self.console):
            return
        editable = {
            "threads": int,
            "timeout": float,
            "rate": float,
            "depth": int,
            "ports": str,
            "wordlist_tier": str,
            "output_dir": str,
            "lab_mode": bool,
            "include_subdomains": bool,
            "verify_tls": bool,
            "max_requests": int,
        }
        for key, caster in editable.items():
            current = getattr(self.settings, key)
            raw = Prompt.ask(f"{key}", default=str(current), console=self.console)
            if raw.strip() == str(current):
                continue
            try:
                if caster is bool:
                    value = raw.strip().lower() in ("1", "true", "yes", "y", "on")
                else:
                    value = caster(raw.strip())
            except ValueError:
                self.console.print(Text(f"invalid value for {key}; keeping {current}", style="#ff7a45"))
                continue
            setattr(self.settings, key, value)
        path = save_settings(self.settings)
        self.console.print(Text(f"settings saved to {path}", style=CYAN))

    # ---------------------------------------------------------------- history
    def _history_screen(self) -> None:
        try:
            with HistoryStore() as store:
                scans = store.list_scans(25)
        except Exception as exc:
            self.console.print(f"[#ff4d3d]history unavailable:[/] {exc}")
            return
        print_history(self.console, scans)


def run_interactive(console: Console, settings: Settings) -> int:
    return asyncio.run(InteractiveSession(console, settings).run())


def launch(console: Console, settings: Settings, target: str | None = None) -> int:
    if target:
        modules = list(MODULE_ORDER)
        options: ScanOptions = build_options(settings, modules=modules)
        result = asyncio.run(execute_scan(console, target, options, modules=modules))
        report_and_summarise(console, result)
        return 0 if result.ok else 1
    return run_interactive(console, settings)
