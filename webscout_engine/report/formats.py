"""Every report generator: JSON, CSV, SARIF and the self-contained HTML report."""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from pathlib import Path
from urllib.parse import urlsplit
from ..core.models import ScanReport
from ..core.redaction import redact
import json
from .. import DEVELOPER_GITHUB, DEVELOPER_TELEGRAM
from ..core.models import utcnow
import csv
import io
from ..core.models import Severity
import math
from collections import defaultdict
from datetime import UTC, datetime
from jinja2 import Environment, FileSystemLoader, select_autoescape
from ..core.models import SEVERITY_ORDER, Severity


# -------------------------------------------------------------------------
# from formats.py
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# from base.py
# -------------------------------------------------------------------------

def sanitise_host(url: str) -> str:
    host = urlsplit(url).hostname or "target"
    cleaned = re.sub(r"[^A-Za-z0-9.-]", "_", host)
    return cleaned or "target"


def sanitise_report(report: ScanReport) -> ScanReport:
    """Return a deep copy with every evidence string redacted (idempotent)."""
    clone = report.model_copy(deep=True)
    for finding in clone.findings:
        finding.evidence = redact(finding.evidence)
        finding.impact = redact(finding.impact)
    for module in clone.modules:
        for finding in module.findings:
            finding.evidence = redact(finding.evidence)
    for observation in clone.observations:
        observation.detail = redact(observation.detail)
    return clone


class BaseReportGenerator(ABC):
    format: str = "base"
    extension: str = "txt"

    def __init__(
        self,
        report: ScanReport,
        output_dir: Path,
        force: bool = False,
        filename: str | None = None,
    ) -> None:
        self.report = report
        self.output_dir = Path(output_dir)
        self.force = force
        self.filename = filename

    @property
    def default_filename(self) -> str:
        return f"webscout_engine_{sanitise_host(self.report.target)}_{self.report.scan_id}.{self.extension}"

    def resolve_path(self) -> Path:
        """Never overwrite an existing report unless ``force`` is set."""
        name = self.filename or self.default_filename
        path = self.output_dir / name
        if self.force or not path.exists():
            return path
        stem, suffix = path.stem, path.suffix
        for index in range(2, 100):
            candidate = self.output_dir / f"{stem}-{index}{suffix}"
            if not candidate.exists():
                return candidate
        return self.output_dir / f"{stem}-{len(self.report.scan_id)}{suffix}"

    @abstractmethod
    def render(self) -> str:
        """Return the complete report as text."""

    def write(self) -> Path:
        path = self.resolve_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.render(), encoding="utf-8")
        return path


# -------------------------------------------------------------------------
# from json_report.py
# -------------------------------------------------------------------------

class JsonReportGenerator(BaseReportGenerator):
    format = "json"
    extension = "json"

    def build_payload(self) -> dict:
        report = self.report
        return {
            "tool": report.tool,
            "version": report.version,
            "schema_version": report.schema_version,
            "generated_at": utcnow().isoformat(),
            "developer": {
                "telegram": DEVELOPER_TELEGRAM,
                "github": DEVELOPER_GITHUB,
            },
            "summary": {
                "target": report.target,
                "scan_id": report.scan_id,
                "started_at": report.started_at.isoformat(),
                "finished_at": (report.finished_at or utcnow()).isoformat(),
                "duration_seconds": round(report.duration_seconds, 3),
                "completed": report.completed,
                "interrupted": report.interrupted,
                "lab_mode": report.lab_mode,
                "modules": [
                    {
                        "name": module.module,
                        "title": module.title,
                        "status": module.status.value,
                        "duration_seconds": round(module.duration_seconds, 3),
                        "findings": len(module.findings),
                        "requests": module.stats.requests,
                    }
                    for module in report.modules
                ],
                "severity_counts": report.severity_counts,
                "coverage": {
                    "executed": [
                        entry.module for entry in report.coverage if not entry.reason
                    ],
                    "skipped": {
                        entry.module: entry.reason
                        for entry in report.coverage
                        if entry.reason
                    },
                    "modules": [entry.model_dump(mode="json") for entry in report.coverage],
                },
                "finding_count": len(report.findings),
                "observation_count": len(report.observations),
                "requests": report.stats.requests,
                "errors": report.stats.errors,
                "timeouts": report.stats.timeouts,
            },
            "report": report.model_dump(mode="json"),
        }

    def render(self) -> str:
        return json.dumps(self.build_payload(), indent=2, ensure_ascii=False, default=str)


# -------------------------------------------------------------------------
# from csv_report.py
# -------------------------------------------------------------------------

COLUMNS = ["kind", "target", "label", "status", "severity", "size", "content_type", "detail"]


class CsvReportGenerator(BaseReportGenerator):
    format = "csv"
    extension = "csv"

    def render(self) -> str:
        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=COLUMNS, lineterminator="\n")
        writer.writeheader()
        for observation in self.report.observations:
            writer.writerow(
                {
                    "kind": observation.kind,
                    "target": observation.target,
                    "label": observation.label,
                    "status": observation.status,
                    "severity": observation.severity.value,
                    "size": observation.size if observation.size is not None else "",
                    "content_type": observation.content_type or "",
                    "detail": " ".join(observation.detail.split())[:400],
                }
            )
        return buffer.getvalue()


# -------------------------------------------------------------------------
# from sarif_report.py
# -------------------------------------------------------------------------

LEVELS = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

SECURITY_SCORES = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "0.0",
}


class SarifReportGenerator(BaseReportGenerator):
    format = "sarif"
    extension = "sarif"

    def build_payload(self) -> dict:
        report = self.report
        rules: dict[str, dict] = {}
        results: list[dict] = []

        for finding in report.findings:
            rule_id = f"ZS/{finding.check}"
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": finding.check,
                    "shortDescription": {"text": finding.title},
                    "fullDescription": {"text": finding.impact or finding.title},
                    "help": {"text": finding.remediation or "Review the finding and remediate."},
                    "defaultConfiguration": {"level": LEVELS[finding.severity]},
                    "properties": {
                        "tags": ["security", finding.module, finding.severity.value]
                        + ([finding.cwe] if finding.cwe else []),
                        "security-severity": (
                            f"{finding.cvss:.1f}"
                            if finding.cvss is not None
                            else SECURITY_SCORES[finding.severity]
                        ),
                        "precision": finding.confidence.value,
                        "cwe": finding.cwe or "",
                        "scanType": finding.scan_type,
                    },
                }
            results.append(
                {
                    "ruleId": rule_id,
                    "level": LEVELS[finding.severity],
                    "message": {"text": f"{finding.title}. {finding.evidence}".strip()},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": finding.endpoint},
                                "region": {"startLine": 1},
                            }
                        }
                    ],
                    "partialFingerprints": {"webscout_engineFindingId": finding.id},
                    "properties": {
                        "severity": finding.severity.value,
                        "confidence": finding.confidence.value,
                        "verification": finding.verification.value,
                        "scanType": finding.scan_type,
                        "cwe": finding.cwe or "",
                        "module": finding.module,
                        "method": finding.method,
                        "parameter": finding.parameter or "",
                        "statusCode": finding.status_code,
                    },
                }
            )

        return {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "webscout_engine",
                            "version": report.version,
                            "informationUri": DEVELOPER_GITHUB,
                            "organization": "webscout_engine",
                            "properties": {
                                "telegram": DEVELOPER_TELEGRAM,
                                "github": DEVELOPER_GITHUB,
                            },
                            "rules": list(rules.values()),
                        }
                    },
                    "invocations": [
                        {
                            "executionSuccessful": report.completed,
                            "startTimeUtc": report.started_at.isoformat(),
                            "endTimeUtc": (report.finished_at or report.started_at).isoformat(),
                            "properties": {
                                "target": report.target,
                                "scanId": report.scan_id,
                                "interrupted": report.interrupted,
                                "requests": report.stats.requests,
                                "modulesExecuted": [
                                    entry.module for entry in report.coverage if not entry.reason
                                ],
                                "modulesSkipped": {
                                    entry.module: entry.reason
                                    for entry in report.coverage
                                    if entry.reason
                                },
                            },
                        }
                    ],
                    "originalUriBaseIds": {"SRCROOT": {"uri": report.target}},
                    "results": results,
                    "properties": {"severityCounts": report.severity_counts},
                }
            ],
        }

    def render(self) -> str:
        return json.dumps(self.build_payload(), indent=2, ensure_ascii=False, default=str)


# -------------------------------------------------------------------------
# from html_report.py
# -------------------------------------------------------------------------

TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"

SEVERITY_COLORS: dict[str, str] = {
    "critical": "#e01b5d",
    "high": "#ff5c39",
    "medium": "#f5a524",
    "low": "#3fb6d3",
    "info": "#8b93a7",
}

OBSERVATION_LABELS = {
    "file": "Sensitive file observations",
    "directory": "Directory observations",
    "port": "Open ports",
    "dns": "DNS records",
    "technology": "Technology and TLS",
    "header": "Disclosed headers",
    "crawl": "Crawl summary",
    "summary": "Module summaries",
}

RADIUS = 68.0


def donut_segments(counts: dict[str, int]) -> list[dict]:
    total = sum(counts.values())
    circumference = 2 * math.pi * RADIUS
    segments: list[dict] = []
    offset = 0.0
    for severity in SEVERITY_ORDER:
        count = counts.get(severity.value, 0)
        if count <= 0 or total <= 0:
            continue
        length = circumference * count / total
        segments.append(
            {
                "severity": severity.value,
                "count": count,
                "color": SEVERITY_COLORS[severity.value],
                "dash": f"{length:.2f} {circumference - length:.2f}",
                "offset": f"{-offset:.2f}",
            }
        )
        offset += length
    return segments


def format_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes, remainder = divmod(int(seconds), 60)
    if minutes < 60:
        return f"{minutes}m {remainder}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes}m {remainder}s"


class HtmlReportGenerator(BaseReportGenerator):
    format = "html"
    extension = "html"

    def build_context(self) -> dict:
        report = self.report
        grouped: dict[str, list] = defaultdict(list)
        for observation in report.observations:
            grouped[observation.kind].append(observation)
        checks = sorted({finding.check for finding in report.findings})
        return {
            "report": report,
            "generated_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "donut": donut_segments(report.severity_counts),
            "colors": SEVERITY_COLORS,
            "severity_order": [(sev.value, report.severity_counts.get(sev.value, 0)) for sev in SEVERITY_ORDER],
            "duration": format_duration(report.duration_seconds),
            "observations": dict(grouped),
            "observation_labels": OBSERVATION_LABELS,
            "observation_kinds": [kind for kind in OBSERVATION_LABELS if kind in grouped],
            "checks": checks,
            "modules": list(report.modules),
            "coverage": report.coverage,
            "executed": [entry for entry in report.coverage if not entry.reason],
            "skipped": [entry for entry in report.coverage if entry.reason],
            "cwe_count": len({finding.cwe for finding in report.findings if finding.cwe}),
            "severity_enum": Severity,
            "developer_telegram": DEVELOPER_TELEGRAM,
            "developer_github": DEVELOPER_GITHUB,
        }

    def render(self) -> str:
        env = Environment(
            loader=FileSystemLoader(str(TEMPLATE_DIR)),
            autoescape=select_autoescape(enabled_extensions=("html", "htm", "xml", "j2")),
            trim_blocks=True,
            lstrip_blocks=True,
        )
        template = env.get_template("report.html.j2")
        return template.render(**self.build_context())
