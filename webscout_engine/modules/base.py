"""Module contract shared by the four scanning modules."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field

from ..core.runtime import ScanContext
from ..core.models import Confidence, Finding, Observation, Severity


@dataclass
class ModuleOutcome:
    """Results of one module plus optional live sinks.

    The sinks push findings and observations into :class:`ScanState` the moment
    they are produced, which is what makes the dashboard update in real time.
    """

    findings: list[Finding] = field(default_factory=list)
    observations: list[Observation] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    finding_sink: Callable[[Finding], object] | None = None
    observation_sink: Callable[[Observation], object] | None = None

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)
        if self.finding_sink is not None:
            self.finding_sink(finding)

    def observe(self, observation: Observation) -> None:
        self.observations.append(observation)
        if self.observation_sink is not None:
            self.observation_sink(observation)


class BaseModule(ABC):
    name: str = "base"
    title: str = "Base module"
    description: str = ""

    def __init__(self, ctx: ScanContext | None = None) -> None:
        self.ctx = ctx

    @abstractmethod
    async def run(self, ctx: ScanContext) -> ModuleOutcome:
        """Execute the module and return everything it discovered."""

    def new_outcome(self, ctx: ScanContext) -> ModuleOutcome:
        return ModuleOutcome(
            finding_sink=ctx.add_finding,
            observation_sink=ctx.add_observation,
        )

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def finding(
        *,
        title: str,
        severity: Severity,
        confidence: Confidence,
        module: str,
        check: str,
        endpoint: str,
        method: str = "GET",
        parameter: str | None = None,
        status_code: int | None = None,
        evidence: str = "",
        impact: str = "",
        remediation: str = "",
        references: list[str] | None = None,
        cwe: str | None = None,
    ) -> Finding:
        return Finding(
            title=title,
            severity=severity,
            confidence=confidence,
            module=module,
            check=check,
            endpoint=endpoint,
            method=method,
            parameter=parameter,
            status_code=status_code,
            evidence=evidence,
            impact=impact,
            remediation=remediation,
            references=references or [],
            cwe=cwe,
        )
