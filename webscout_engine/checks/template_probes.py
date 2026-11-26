"""Data-driven probe engine: 1000+ real product and path probes.

Each template is one HTTP request with its own status set and body signature.
The catalogue lives in ``data/probes.json`` and is generated from
``tools/generate_probes.py``; adding a product never means writing Python.

Every reported hit is backed by the exact signature that matched, so a reviewer
can re-request the URL and see the same thing.
"""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from ..core.models import Confidence, Observation, Severity, Verification
from .base import BaseCheck, CheckMeta
from .registry import register

DATA_DIR = Path(__file__).resolve().parent.parent / "data"

SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}

# Ports that speak HTTPS by convention.
TLS_PORTS = {443, 8443, 9443, 10443}


_SENSITIVE_PATHS: set[str] | None = None


def sensitive_path_set() -> set[str]:
    """Paths already covered by the dedicated file catalogue."""
    global _SENSITIVE_PATHS
    if _SENSITIVE_PATHS is not None:
        return _SENSITIVE_PATHS
    paths: set[str] = set()
    source = DATA_DIR / "sensitive_paths.json"
    if source.exists():
        try:
            payload = json.loads(source.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            payload = {}
        for entry in payload.get("entries", []):
            path = str(entry.get("path", "")).strip("/").lower()
            if path:
                paths.add(path)
    _SENSITIVE_PATHS = paths
    return paths


@dataclass(frozen=True)
class Template:
    id: str
    product: str
    category: str
    severity: Severity
    cwe: str
    path: str
    signature: str
    impact: str
    remediation: str


def load_templates(path: Path | None = None) -> list[Template]:
    source = path or (DATA_DIR / "probes.json")
    if not source.exists():
        return []
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return []
    templates: list[Template] = []
    for entry in payload.get("templates", []):
        try:
            templates.append(
                Template(
                    id=str(entry["id"]),
                    product=str(entry["product"]),
                    category=str(entry["category"]),
                    severity=SEVERITY_MAP.get(str(entry["severity"]), Severity.INFO),
                    cwe=str(entry.get("cwe", "CWE-200")),
                    path=str(entry["path"]),
                    signature=str(entry.get("signature", "")),
                    impact=str(entry.get("impact", "")),
                    remediation=str(entry.get("remediation", "")),
                )
            )
        except (KeyError, TypeError):
            continue
    return templates


@register
class TemplateProbesCheck(BaseCheck):
    meta = CheckMeta(
        name="template-probes",
        title="Product and path probe catalogue",
        description=(
            "Runs the bundled catalogue of product-specific and generic paths, each with its "
            "own signature, and reports the ones that answer with the expected content."
        ),
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        category="exposure",
        remediation=(
            "Remove or restrict the reported paths: default pages, admin consoles, backup "
            "archives, logs and diagnostic endpoints should never be public."
        ),
        references=["https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration"],
    )

    MAX_TEMPLATES = 2000

    def __init__(self, ctx) -> None:  # noqa: ANN001
        super().__init__(ctx)
        self._compiled: dict[str, re.Pattern[str] | None] = {}

    # ------------------------------------------------------------------ urls
    @staticmethod
    def build_url(base_url: str, path: str) -> str:
        """``:8080/dashboard/`` means "the same host on another port"."""
        base = base_url.rstrip("/")
        if not path.startswith(":"):
            return f"{base}/{path.lstrip('/')}"
        port_text, _, rest = path[1:].partition("/")
        parts = urlsplit(base_url)
        host = parts.hostname or ""
        try:
            port = int(port_text)
        except ValueError:
            return f"{base}/{path.lstrip('/')}"
        scheme = "https" if port in TLS_PORTS else "http"
        return f"{scheme}://{host}:{port}/{rest}"

    def _regex(self, pattern: str) -> re.Pattern[str] | None:
        if pattern in self._compiled:
            return self._compiled[pattern]
        compiled: re.Pattern[str] | None
        try:
            compiled = re.compile(pattern, re.IGNORECASE | re.MULTILINE) if pattern else None
        except re.error:
            compiled = None
        self._compiled[pattern] = compiled
        return compiled

    # ------------------------------------------------------------------- run
    async def run(self) -> list:
        findings: list = []
        covered = sensitive_path_set()
        templates = [
            template
            for template in load_templates()
            if template.path.strip("/").lower() not in covered
        ][: self.MAX_TEMPLATES]
        if not templates:
            self.ctx.note("template-probes skipped: the probe catalogue is missing")
            return findings

        concurrency = max(4, min(16, int(getattr(self.ctx, "concurrency", 8) or 8)))
        semaphore = asyncio.Semaphore(concurrency)
        state = self.ctx.state
        if state is not None:
            state.add_total(len(templates))

        async def probe(template: Template) -> None:
            if self.ctx.cancelled:
                return
            async with semaphore:
                if self.ctx.cancelled:
                    return
                url = self.build_url(self.ctx.base_url, template.path)
                if state is not None:
                    state.set_operation(f"{template.product}: {template.path}")
                try:
                    result = await self.get(url, allow_redirects=False, retries=0, max_body=32768)
                except Exception:
                    return
                finally:
                    if state is not None:
                        state.task_done()
                if result is None or result.error or not result.status:
                    return
                if result.status not in (200, 206):
                    if result.status in (401, 403) and self.ctx.state is not None:
                        self.ctx.state.add_observation(
                            Observation(
                                kind="probe",
                                target=url,
                                label=template.path,
                                status="protected",
                                detail=f"{template.product} path returned HTTP {result.status}",
                                metadata={"module": "vuln", "template": template.id},
                            )
                        )
                    return
                if self.is_soft_404(result):
                    return

                regex = self._regex(template.signature)
                matched = ""
                if regex is not None:
                    found = regex.search(result.body or "")
                    if not found:
                        return
                    start = max(0, found.start() - 40)
                    matched = " ".join((result.body[start : found.end() + 60]).split())
                else:
                    # No signature: only accept a non-HTML, non-JSON payload (archives, binaries).
                    lowered = (result.content_type or "").lower()
                    if "html" in lowered or "json" in lowered:
                        return

                confidence = Confidence.HIGH if matched else Confidence.MEDIUM
                findings.append(
                    self.make_finding(
                        title=f"{template.product}: /{template.path.lstrip('/')} is reachable",
                        severity=template.severity,
                        confidence=confidence,
                        endpoint=url,
                        status_code=result.status,
                        evidence=(
                            f"{result.status}, {result.body_length} bytes"
                            + (f", signature matched: {matched[:160]}" if matched else ", binary payload")
                        ),
                        impact=template.impact,
                        remediation=template.remediation,
                        verification=(
                            Verification.CONFIRMED if matched else Verification.OBSERVED
                        ),
                        cwe=template.cwe,
                    )
                )

        await asyncio.gather(*(probe(template) for template in templates))

        products = sorted({finding.title.split(":", 1)[0] for finding in findings})
        if products:
            self.ctx.note(f"template-probes: {len(products)} product(s) matched: {', '.join(products[:8])}")
        return findings
