"""Command line interface (Typer).

The app exposes a single command so that ``webscout_engine <target> -m all`` works
exactly as documented, while still offering informational flags:

    webscout_engine example.com -m all
    webscout_engine https://example.com -m files,dirs --threads 30
    webscout_engine 127.0.0.1:8000 -m vuln --lab-mode --yes --i-have-authorization
    webscout_engine --version
    webscout_engine --list-checks
    webscout_engine --history
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import DEVELOPER_GITHUB, DEVELOPER_TELEGRAM, __version__
from .config import ensure_dirs, load_settings, write_default_config
from .core.runtime import ScanOptions
from .core.scope import normalize_target
from .interactive import run_interactive
from .modules import MODULE_LABELS, resolve_modules
from .runner import build_options, execute_scan, report_and_summarise
from .ui.theme import banner_panel
from .ui.theme import CYAN, MUTED, PURPLE, WHITE, make_console

app = typer.Typer(
    add_completion=False,
    rich_markup_mode="rich",
    help="webscout_engine - asynchronous, scope-aware security assessment framework.",
)

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_NO_AUTHORIZATION = 3


def _print_authorisation_notice(console: Console) -> None:
    console.print(
        Panel(
            Text.assemble(
                ("Authorisation required.\n\n", "bold #ff4d3d"),
                (
                    "Non-interactive scans must pass both --yes and --i-have-authorization.\n"
                    "Only scan systems you own or have explicit written permission to test.\n",
                    WHITE,
                ),
                ("\nExample:\n", MUTED),
                ("  webscout_engine example.com -m all --yes --i-have-authorization", CYAN),
            ),
            border_style="#ff4d3d",
            title="Blocked",
        )
    )


def _interactive_consent(console: Console, target: str) -> bool:
    """One-question confirmation when a target is given without the two flags.

    A scan needs consent, not ceremony: typing the target at a terminal is the
    consent, provided the operator confirms it explicitly. Non-interactive runs
    (CI, pipes, cron) still require ``--yes --i-have-authorization`` so nothing
    can scan silently.
    """
    if not sys.stdin.isatty():
        return False
    console.print(
        Panel(
            Text.assemble(
                ("Target  ", MUTED),
                (target, f"bold {WHITE}"),
                ("\n\nScan only systems you own or have written permission to test.", WHITE),
            ),
            border_style=PURPLE,
            title="Authorisation",
        )
    )
    try:
        return bool(
            typer.confirm(
                "Do you own this target or have written permission to test it?",
                default=False,
            )
        )
    except (typer.Abort, EOFError, KeyboardInterrupt):
        return False


def _print_checks(console: Console) -> None:
    from .checks import list_check_metadata

    table = Table(title="Registered checks", border_style=PURPLE, header_style=MUTED)
    table.add_column("name", style=CYAN, no_wrap=True)
    table.add_column("title", ratio=1)
    table.add_column("severity", width=9)
    table.add_column("cwe", width=9)
    table.add_column("type", width=8)
    table.add_column("category", width=14)
    for meta in list_check_metadata():
        table.add_row(
            meta.name,
            meta.title,
            meta.severity.value,
            meta.cwe or "-",
            meta.scan_type,
            meta.category,
        )
    console.print(table)
    console.print(
        f"[{MUTED}]{len(list_check_metadata())} checks; "
        f"source modules (code, deps) run with --source <path>[/]"
    )


def _print_history(console: Console, limit: int = 20) -> None:
    from .config import HistoryStore
    from .ui.summary import print_history

    try:
        with HistoryStore() as store:
            print_history(console, store.list_scans(limit))
    except Exception as exc:  # noqa: BLE001
        console.print(f"[#ff4d3d]history unavailable:[/] {exc}")


@app.command(name="webscout_engine")
def scan(
    target: str | None = typer.Argument(
        None, help="Domain, host:port or full URL. Omit for the interactive menu."
    ),
    module: str = typer.Option(
        "all", "--module", "-m",
        help="all | infra | files | dirs | tech | vuln | arsenal | code | deps (comma separated).",
    ),
    live: bool = typer.Option(
        False, "--live",
        help="Stream every probe as it lands instead of the summary dashboard.",
    ),
    arsenal_profile: str | None = typer.Option(
        None, "--arsenal-profile", help="stealth | normal - how many payload variants the arsenal runs.",
    ),
    arsenal_sections: str | None = typer.Option(
        None, "--arsenal-sections",
        help="Comma separated arsenal sections (default: all 28), e.g. files,sqli,xss,ssrf.",
    ),
    shell_pack: str | None = typer.Option(
        None, "--shell-pack",
        help="Path to an operator command pack (bash) to run line by line. Opt-in and allowlisted.",
    ),
    output: str | None = typer.Option(None, "--output", "-o", help="Directory for generated reports."),
    config: str | None = typer.Option(None, "--config", help="Path to an alternative config.yaml."),
    wordlist: str | None = typer.Option(None, "--wordlist", help="External wordlist for directory discovery."),
    wordlist_tier: str | None = typer.Option(None, "--wordlist-tier", help="small | medium | large."),
    threads: int | None = typer.Option(None, "--threads", min=1, max=200, help="Concurrency."),
    timeout: float | None = typer.Option(None, "--timeout", min=0.5, max=120, help="Per-request timeout in seconds."),
    rate: float | None = typer.Option(None, "--rate", min=0.5, max=500, help="Global requests per second."),
    depth: int | None = typer.Option(None, "--depth", min=0, max=5, help="Directory recursion depth."),
    ports: str | None = typer.Option(None, "--ports", help="Port profile or list: top100 | web | 22,80,443 | 1-1024."),
    extensions: str | None = typer.Option(None, "--extensions", help="Comma separated extensions to probe."),
    checks: str | None = typer.Option(None, "--checks", help="Comma separated web check names (default: all)."),
    source: str | None = typer.Option(
        None, "--source", help="Local project tree for the code (SAST) and deps (SCA) modules."
    ),
    active_forms: bool = typer.Option(
        False, "--active-forms",
        help="Enable checks that write to the target (stored reflection, mass assignment).",
    ),
    blind_delay: float | None = typer.Option(
        None, "--blind-delay", min=1.0, max=10.0, help="Sleep used by time-based probes (default 2s)."
    ),
    max_blind_params: int | None = typer.Option(
        None, "--max-blind-params", min=1, max=10, help="How many parameters time-based probes try."
    ),
    osint: bool = typer.Option(
        False, "--osint",
        help="Let origin discovery compare fingerprints by requesting candidate addresses.",
    ),
    print_report: bool = typer.Option(
        False, "--print-report", help="Print every finding, grouped by severity, after the scan."
    ),
    formats: str | None = typer.Option(None, "--formats", help="json,html,csv,sarif (comma separated)."),
    resume: bool = typer.Option(False, "--resume", help="Skip modules already completed for this target."),
    json_stream: bool = typer.Option(False, "--json-stream", help="Write findings as JSON lines while scanning."),
    no_ui: bool = typer.Option(False, "--no-ui", help="Disable the live dashboard."),
    no_open: bool = typer.Option(
        False, "--no-open",
        help="Do not open the HTML report in a browser when the scan finishes.",
    ),
    no_color: bool = typer.Option(False, "--no-color", help="Disable colour output."),
    ascii_only: bool = typer.Option(False, "--ascii", help="ASCII-only decorations."),
    include_subdomains: bool = typer.Option(False, "--include-subdomains", help="Allow subdomains of the target."),
    lab_mode: bool = typer.Option(False, "--lab-mode", help="Permit loopback/private targets (isolated testing)."),
    force: bool = typer.Option(False, "--force", help="Overwrite existing report files."),
    yes: bool = typer.Option(False, "--yes", help="Confirm non-interactively."),
    authorisation: bool = typer.Option(False, "--i-have-authorization", help="Confirm written authorisation."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose logging."),
    version: bool = typer.Option(False, "--version", help="Print the version and exit."),
    list_checks: bool = typer.Option(False, "--list-checks", help="List registered web checks and exit."),
    history: bool = typer.Option(False, "--history", help="Show recorded scans and exit."),
) -> None:
    """webscout_engine - asynchronous, scope-aware security assessment framework.

    Runs an assessment against TARGET, or opens the interactive menu when no
    target is given. Non-interactive scans require --yes and
    --i-have-authorization.
    """
    settings = load_settings(Path(config).expanduser() if config else None)
    console = make_console(no_color or settings.ui.no_color, ascii_only or settings.ui.ascii_only)

    if version:
        console.print(f"webscout_engine {__version__}")
        console.print(f"developer  {DEVELOPER_TELEGRAM}  ·  {DEVELOPER_GITHUB}", style=MUTED)
        raise typer.Exit(EXIT_OK)
    if list_checks:
        _print_checks(console)
        raise typer.Exit(EXIT_OK)
    if history:
        _print_history(console)
        raise typer.Exit(EXIT_OK)

    if target is None:
        ensure_dirs()
        write_default_config()
        raise typer.Exit(run_interactive(console, settings))

    try:
        normalised = normalize_target(target)
    except ValueError as exc:
        console.print(f"[#ff4d3d]invalid target:[/] {exc}")
        raise typer.Exit(EXIT_USAGE) from exc

    try:
        modules = resolve_modules(module)
    except ValueError as exc:
        console.print(f"[#ff4d3d]invalid module:[/] {exc}")
        raise typer.Exit(EXIT_USAGE) from exc

    if not (yes and authorisation):
        # Interactive: one question instead of two flags.
        if not _interactive_consent(console, normalised):
            _print_authorisation_notice(console)
            raise typer.Exit(EXIT_NO_AUTHORIZATION)

    if verbose:
        from .config import setup_logging

        setup_logging(verbose=True, quiet=True)

    ensure_dirs()
    write_default_config()

    overrides: dict[str, object] = {
        "modules": modules,
        "wordlist": wordlist,
        "wordlist_tier": wordlist_tier,
        "threads": threads,
        "timeout": timeout,
        "rate": rate,
        "depth": depth,
        "ports": ports,
        "include_subdomains": include_subdomains or None,
        "lab_mode": lab_mode or None,
        "force": force or None,
        "user_agent": settings.user_agent,
    }
    if output:
        overrides["output_dir"] = str(Path(output).expanduser())
    if extensions:
        overrides["extensions"] = [item.strip() for item in extensions.split(",") if item.strip()]
    if checks:
        overrides["checks"] = [item.strip() for item in checks.split(",") if item.strip()]
    if source:
        overrides["source_path"] = str(Path(source).expanduser().resolve())
    if active_forms:
        overrides["active_forms"] = True
    if blind_delay is not None:
        overrides["blind_delay"] = blind_delay
    if max_blind_params is not None:
        overrides["max_blind_params"] = max_blind_params
    if osint:
        overrides["osint"] = True
    if live:
        overrides["live_stream"] = True
    if no_open:
        overrides["open_report"] = False
    if arsenal_profile:
        overrides["arsenal_profile"] = arsenal_profile
    if arsenal_sections:
        overrides["arsenal_sections"] = [
            item.strip().lower() for item in arsenal_sections.split(",") if item.strip()
        ]
    if shell_pack:
        overrides["shell_pack"] = str(Path(shell_pack).expanduser())
    if formats:
        overrides["formats"] = [item.strip().lower() for item in formats.split(",") if item.strip()]
    if resume:
        overrides["resume"] = True
    if json_stream:
        overrides["json_stream"] = True

    options: ScanOptions = build_options(settings, **overrides)

    if not no_ui:
        console.print(banner_panel(ascii_only or settings.ui.ascii_only))

    plan = Text()
    plan.append("target   ", style=MUTED)
    plan.append(normalised, style=f"bold {WHITE}")
    plan.append("\nmodules  ", style=MUTED)
    plan.append(", ".join(MODULE_LABELS[name] for name in modules), style=CYAN)
    if source:
        plan.append("\nsource   ", style=MUTED)
        plan.append(str(Path(source).expanduser()), style=WHITE)
    if "arsenal" in modules:
        from .arsenal.catalog import PROBE_COUNT, SECTION_ORDER

        plan.append("\narsenal  ", style=MUTED)
        plan.append(f"{PROBE_COUNT} probes / {len(SECTION_ORDER)} sections", style=CYAN)
    plan.append("\nlimits   ", style=MUTED)
    plan.append(
        f"{options.threads} threads, {options.rate}/s, {options.timeout}s timeout, depth {options.depth}",
        WHITE,
    )
    console.print(Panel(plan, border_style=PURPLE, title="Scan plan"))

    try:
        result = asyncio.run(
            execute_scan(console, normalised, options, modules=modules, show_dashboard=not no_ui)
        )
    except KeyboardInterrupt:
        console.print(Text("Cancelled.", style="#ff7a45"))
        raise typer.Exit(130) from None

    report_and_summarise(
        console,
        result,
        print_report=print_report,
        open_report=options.open_report and not no_ui,
    )
    raise typer.Exit(EXIT_OK if result.report is not None else EXIT_ERROR)


main = app


if __name__ == "__main__":  # pragma: no cover
    app()
