"""Live scan state.

Single mutable object that the engine writes and the dashboard reads. All
mutators are synchronous and free of ``await`` so no locking is required inside
one event loop.
"""

from __future__ import annotations

import time
import uuid
from collections import deque
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from urllib.parse import unquote_plus, urlsplit

from .models import (
    Finding,
    ModuleResult,
    ModuleStatus,
    Observation,
    ScanStats,
    Severity,
    utcnow,
)


@dataclass(slots=True)
class ProbeRecord:
    """One HTTP probe, as shown in the live dashboard feed."""

    method: str
    path: str
    status: int
    elapsed: float


class ScanState:
    def __init__(self, target: str, scan_id: str | None = None) -> None:
        self.target = target
        self.scan_id = scan_id or uuid.uuid4().hex[:12]
        self.started_at: datetime = utcnow()
        self._started_mono = time.monotonic()
        self.finished_at: datetime | None = None

        self.stats = ScanStats()
        self.findings: list[Finding] = []
        self.observations: list[Observation] = []
        self.modules: dict[str, ModuleResult] = {}
        self.notes: list[str] = []
        self.probe_log: deque[ProbeRecord] = deque(maxlen=12)
        self.probe_total = 0

        self.current_module = ""
        self.current_stage = ""
        self.current_operation = ""
        self.status_text = "initialising"

        self._finding_ids: set[str] = set()
        self._request_times: deque[float] = deque(maxlen=4096)
        self.rate_limited_streak = 0
        self.blocked_requests = 0
        self.cancelled = False

    # ------------------------------------------------------------- progress
    def set_module(self, name: str, title: str = "") -> None:
        self.current_module = name
        result = self.modules.get(name)
        if result is None:
            self.modules[name] = ModuleResult(
                module=name,
                title=title or name,
                status=ModuleStatus.RUNNING,
                started_at=utcnow(),
            )
        else:
            result.status = ModuleStatus.RUNNING
            result.started_at = result.started_at or utcnow()

    def finish_module(self, name: str, status: ModuleStatus, error: str | None = None) -> None:
        result = self.modules.get(name)
        if result is None:
            return
        result.status = status
        result.finished_at = utcnow()
        result.error = error
        result.findings = [f for f in self.findings if f.module == name]
        result.observations = [o for o in self.observations if o.kind and self._obs_module(o) == name]

    @staticmethod
    def _obs_module(observation: Observation) -> str:
        return str(observation.metadata.get("module", ""))

    def set_stage(self, stage: str) -> None:
        self.current_stage = stage

    def set_operation(self, operation: str) -> None:
        self.current_operation = operation

    def set_status(self, text: str) -> None:
        self.status_text = text

    def add_total(self, count: int) -> None:
        self.stats.tasks_total += max(0, count)

    def task_done(self, failed: bool = False) -> None:
        self.stats.tasks_completed += 1
        if failed:
            self.stats.tasks_failed += 1

    # -------------------------------------------------------------- traffic
    def record_request(self, status: int | None = None) -> None:
        self.stats.requests += 1
        self._request_times.append(time.monotonic())
        if status == 429 or status == 503:
            self.stats.rate_limited += 1
            self.rate_limited_streak += 1
        else:
            self.rate_limited_streak = 0

    def record_bytes(self, count: int) -> None:
        self.stats.bytes_received += max(0, count)

    def record_timeout(self) -> None:
        self.stats.timeouts += 1
        self.stats.errors += 1

    def record_error(self) -> None:
        self.stats.errors += 1

    def record_retry(self) -> None:
        self.stats.retries += 1

    # ------------------------------------------------------------- findings
    def add_finding(self, finding: Finding) -> bool:
        if finding.id in self._finding_ids:
            return False
        self._finding_ids.add(finding.id)
        self.findings.append(finding)
        return True

    def add_observation(self, observation: Observation) -> None:
        self.observations.append(observation)

    # ------------------------------------------------------------------ math
    @property
    def elapsed(self) -> float:
        end = time.monotonic()
        return max(0.0, end - self._started_mono)

    def rps(self, window: float = 5.0) -> float:
        if not self._request_times:
            return 0.0
        now = time.monotonic()
        recent = [t for t in self._request_times if now - t <= window]
        if not recent:
            return 0.0
        span = max(min(window, now - recent[0]), 0.5)
        return len(recent) / span

    def eta(self) -> float | None:
        total = self.stats.tasks_total
        done = self.stats.tasks_completed
        if total <= 0 or done <= 0 or done >= total:
            return None
        return (self.elapsed / done) * (total - done)

    def progress_fraction(self) -> float:
        total = self.stats.tasks_total
        if total <= 0:
            return 0.0
        return min(1.0, self.stats.tasks_completed / total)

    @staticmethod
    def _short_path(url: str) -> str:
        parts = urlsplit(url)
        path = parts.path or "/"
        if parts.query:
            # Payloads are shown decoded so the operator can see what was sent.
            path = f"{path}?{unquote_plus(parts.query)}"
        if len(path) > 58:
            path = path[:55] + "..."
        return path

    def record_probe(self, method: str, url: str, status: int, elapsed: float) -> None:
        self.probe_log.append(
            ProbeRecord(method=method.upper()[:5], path=self._short_path(url), status=status, elapsed=elapsed)
        )
        self.probe_total += 1

    def severity_counts(self) -> dict[str, int]:
        counts = {sev.value: 0 for sev in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    def snapshot(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "scan_id": self.scan_id,
            "module": self.current_module,
            "stage": self.current_stage,
            "operation": self.current_operation,
            "status": self.status_text,
            "elapsed": self.elapsed,
            "eta": self.eta(),
            "fraction": self.progress_fraction(),
            "rps": self.rps(),
            "stats": self.stats.model_dump(),
            "severity": self.severity_counts(),
            "findings": len(self.findings),
        }
