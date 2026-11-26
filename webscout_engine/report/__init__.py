"""Report generation: JSON, HTML, CSV and SARIF."""

from __future__ import annotations

from pathlib import Path

from ..core.models import ScanReport
from .formats import BaseReportGenerator, sanitise_report
from .formats import CsvReportGenerator
from .formats import HtmlReportGenerator
from .formats import JsonReportGenerator
from .formats import SarifReportGenerator

GENERATORS: dict[str, type[BaseReportGenerator]] = {
    "json": JsonReportGenerator,
    "html": HtmlReportGenerator,
    "csv": CsvReportGenerator,
    "sarif": SarifReportGenerator,
}


def generate_reports(
    report: ScanReport,
    output_dir: Path | str,
    formats: list[str] | None = None,
    force: bool = False,
) -> dict[str, Path]:
    """Render every requested format and return ``{format: path}``."""
    directory = Path(output_dir).expanduser()
    directory.mkdir(parents=True, exist_ok=True)
    clean = sanitise_report(report)
    paths: dict[str, Path] = {}
    for name in formats or ["json", "html", "csv", "sarif"]:
        generator_cls = GENERATORS.get(name.lower())
        if generator_cls is None:
            continue
        generator = generator_cls(clean, directory, force=force)
        paths[name.lower()] = generator.write()
    return paths


__all__ = [
    "GENERATORS",
    "BaseReportGenerator",
    "generate_reports",
    "sanitise_report",
    "JsonReportGenerator",
    "HtmlReportGenerator",
    "CsvReportGenerator",
    "SarifReportGenerator",
]
