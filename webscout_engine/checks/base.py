"""Check contract: metadata, context object and shared helpers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, Field

from ..core.models import Confidence, Finding, HttpResult, Severity, Verification
from ..core.redaction import redact_evidence
from ..recon.crawl import CrawlResult
from ..recon.crawl import Parameter
from ..recon.tech import TechMatch
from ..recon.tech import TlsInfo


class CheckMeta(BaseModel):
    name: str
    title: str
    description: str = ""
    severity: Severity = Severity.INFO
    confidence: Confidence = Confidence.MEDIUM
    category: str = "general"
    remediation: str = ""
    references: list[str] = Field(default_factory=list)
    requires: list[str] = Field(default_factory=list)
    cwe: str | None = None
    cvss: float | None = None
    scan_type: str = "active"
    impact: str = "low"
    technologies: list[str] = Field(default_factory=list)


@dataclass
class CheckContext:
    """Everything a check may read. Constructed by the vuln module."""

    http: Any
    base_url: str
    state: Any = None
    crawl: CrawlResult | None = None
    params: list[Parameter] = field(default_factory=list)
    tech: list[TechMatch] = field(default_factory=list)
    tls: TlsInfo | None = None
    soft404: Any = None
    cancel: Any = None
    baseline_body: str = ""
    blind_delay: float = 2.0
    max_blind_params: int = 2
    active_forms: bool = False
    concurrency: int = 8
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def cancelled(self) -> bool:
        return bool(self.cancel is not None and getattr(self.cancel, "is_cancelled", False))

    def note(self, message: str) -> None:
        if self.state is not None and hasattr(self.state, "notes"):
            self.state.notes.append(message)


async def safe_get(ctx: CheckContext, url: str, **kwargs: Any) -> HttpResult | None:
    """GET that never raises: cancellation and transport errors become ``None``."""
    if ctx.cancelled:
        return None
    try:
        return await ctx.http.get(url, **kwargs)
    except Exception:
        return None


class BaseCheck(ABC):
    meta: CheckMeta

    def __init__(self, ctx: CheckContext) -> None:
        self.ctx = ctx

    @abstractmethod
    async def run(self) -> list[Finding]:
        """Execute the check and return findings (empty list when clean)."""

    # ----------------------------------------------------------------- helpers
    def make_finding(
        self,
        *,
        title: str,
        severity: Severity | None = None,
        confidence: Confidence | None = None,
        endpoint: str | None = None,
        method: str = "GET",
        parameter: str | None = None,
        status_code: int | None = None,
        evidence: str = "",
        impact: str = "",
        remediation: str | None = None,
        references: list[str] | None = None,
        verification: Verification | None = None,
        cwe: str | None = None,
        cvss: float | None = None,
    ) -> Finding:
        meta = self.meta
        if verification is None:
            # Certain/high confidence means we saw the behaviour directly; a low
            # confidence finding is a heuristic that needs manual review.
            verification = (
                Verification.CONFIRMED
                if (confidence or meta.confidence).rank <= Confidence.HIGH.rank
                else Verification.INDICATOR
            )
        return Finding(
            title=title,
            severity=severity or meta.severity,
            confidence=confidence or meta.confidence,
            module="vuln",
            check=meta.name,
            endpoint=endpoint or self.ctx.base_url,
            method=method,
            parameter=parameter,
            status_code=status_code,
            evidence=redact_evidence(evidence),
            impact=impact,
            remediation=remediation or meta.remediation,
            references=references or meta.references,
            cwe=cwe or meta.cwe,
            cvss=cvss if cvss is not None else meta.cvss,
            scan_type=meta.scan_type,
            verification=verification,
        )

    async def get(self, url: str, **kwargs: Any) -> HttpResult | None:
        return await safe_get(self.ctx, url, **kwargs)

    def is_soft_404(self, result: HttpResult | None) -> bool:
        if result is None or self.ctx.soft404 is None:
            return False
        try:
            return bool(self.ctx.soft404.evaluate(result).is_soft)
        except Exception:
            return False

    @property
    def target_params(self) -> list[Parameter]:
        return [p for p in self.ctx.params if p.interesting]
