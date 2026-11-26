"""Pydantic data models shared by every layer of webscout_engine.

Every model is serialisable with ``model_dump(mode="json")`` so reports never
need a bespoke encoder.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, model_validator

TOOL_NAME = "webscout_engine"
TOOL_VERSION = "2.0.0"
REPORT_SCHEMA_VERSION = "1.0"


def utcnow() -> datetime:
    """Timezone-aware UTC timestamp used everywhere in the tool."""
    return datetime.now(UTC)


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self.value]

    @property
    def label(self) -> str:
        return self.value.upper()


_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)


class Confidence(str, Enum):
    CERTAIN = "certain"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        return _CONFIDENCE_RANK[self.value]


_CONFIDENCE_RANK = {"certain": 0, "high": 1, "medium": 2, "low": 3}


class Verification(str, Enum):
    """How strong the evidence behind a finding is."""

    CONFIRMED = "confirmed"   # direct evidence (error text, reflection, timing)
    OBSERVED = "observed"     # a measured fact (missing header, open port)
    INDICATOR = "indicator"   # heuristic that needs manual review


class ModuleStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    PARTIAL = "partial"
    SKIPPED = "skipped"


class ScanStats(BaseModel):
    """Counters that are incremented by the HTTP client and the engine."""

    requests: int = 0
    retries: int = 0
    timeouts: int = 0
    errors: int = 0
    rate_limited: int = 0
    bytes_received: int = 0
    tasks_completed: int = 0
    tasks_total: int = 0
    tasks_failed: int = 0

    def merge(self, other: ScanStats) -> None:
        self.requests += other.requests
        self.retries += other.retries
        self.timeouts += other.timeouts
        self.errors += other.errors
        self.rate_limited += other.rate_limited
        self.bytes_received += other.bytes_received
        self.tasks_completed += other.tasks_completed
        self.tasks_total += other.tasks_total
        self.tasks_failed += other.tasks_failed


class Finding(BaseModel):
    """A single security observation that carries severity and remediation."""

    id: str = ""
    title: str
    severity: Severity
    confidence: Confidence
    module: str
    check: str
    endpoint: str
    method: str = "GET"
    parameter: str | None = None
    status_code: int | None = None
    evidence: str = ""
    impact: str = ""
    remediation: str = ""
    references: list[str] = Field(default_factory=list)
    cwe: str | None = None
    cvss: float | None = None
    verification: Verification = Verification.OBSERVED
    scan_type: str = "active"
    timestamp: datetime = Field(default_factory=utcnow)

    @model_validator(mode="after")
    def _ensure_stable_id(self) -> Finding:
        if not self.id:
            self.id = self.compute_id()
        return self

    def compute_id(self) -> str:
        """Stable identifier derived from the check identity, not from time.

        Re-running the same scan against the same target yields the same ids,
        which lets CI systems de-duplicate findings between runs.
        """
        key = "|".join(
            [self.check, self.endpoint, self.parameter or "", self.title, self.severity.value]
        )
        return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]

    def sort_key(self) -> tuple[int, int, str]:
        return (self.severity.rank, self.confidence.rank, self.title)


class Observation(BaseModel):
    """Non-finding structured data (directories, ports, DNS records, tech)."""

    kind: str
    target: str
    label: str
    status: str
    detail: str = ""
    severity: Severity = Severity.INFO
    size: int | None = None
    content_type: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ModuleResult(BaseModel):
    module: str
    title: str = ""
    status: ModuleStatus = ModuleStatus.PENDING
    started_at: datetime | None = None
    finished_at: datetime | None = None
    findings: list[Finding] = Field(default_factory=list)
    observations: list[Observation] = Field(default_factory=list)
    stats: ScanStats = Field(default_factory=ScanStats)
    error: str | None = None

    @property
    def duration_seconds(self) -> float:
        if not self.started_at or not self.finished_at:
            return 0.0
        return max(0.0, (self.finished_at - self.started_at).total_seconds())


class CoverageEntry(BaseModel):
    """One module's fate in a scan: run, skipped, or failed."""

    module: str
    module_id: str = ""
    title: str = ""
    status: ModuleStatus = ModuleStatus.PENDING
    scan_type: str = "active"
    reason: str = ""
    findings: int = 0
    requests: int = 0
    duration_seconds: float = 0.0


class ScanReport(BaseModel):
    tool: str = TOOL_NAME
    version: str = TOOL_VERSION
    schema_version: str = REPORT_SCHEMA_VERSION
    scan_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    target: str
    started_at: datetime = Field(default_factory=utcnow)
    finished_at: datetime | None = None
    completed: bool = False
    interrupted: bool = False
    lab_mode: bool = False
    config_snapshot: dict[str, Any] = Field(default_factory=dict)
    modules: list[ModuleResult] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    observations: list[Observation] = Field(default_factory=list)
    stats: ScanStats = Field(default_factory=ScanStats)
    severity_counts: dict[str, int] = Field(default_factory=dict)
    coverage: list[CoverageEntry] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)

    @property
    def duration_seconds(self) -> float:
        end = self.finished_at or utcnow()
        return max(0.0, (end - self.started_at).total_seconds())

    def recount(self) -> None:
        counts = {sev.value: 0 for sev in SEVERITY_ORDER}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        self.severity_counts = counts

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: f.sort_key())

    @property
    def executed_modules(self) -> list[str]:
        return [entry.module for entry in self.coverage if entry.status != ModuleStatus.PENDING
                and entry.status != ModuleStatus.CANCELLED and not entry.reason]

    @property
    def skipped_modules(self) -> dict[str, str]:
        return {entry.module: entry.reason for entry in self.coverage if entry.reason}


class HttpResult(BaseModel):
    """Normalised result of one HTTP request (never the raw aiohttp object)."""

    url: str
    final_url: str = ""
    status: int = 0
    reason: str = ""
    headers: dict[str, str] = Field(default_factory=dict)
    body: str = ""
    body_length: int = 0
    content_type: str = ""
    elapsed: float = 0.0
    redirect_chain: list[str] = Field(default_factory=list)
    truncated: bool = False
    error: str | None = None
    error_kind: str = ""
    attempts: int = 1

    @property
    def ok(self) -> bool:
        return self.error is None and 200 <= self.status < 300

    @property
    def is_redirect(self) -> bool:
        return 300 <= self.status < 400

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)

    def short_body(self, limit: int = 400) -> str:
        text = " ".join(self.body.split())
        return text[:limit]
