"""Arsenal package: the probe catalogue, the executor and the module."""

from __future__ import annotations

from .catalog import (
    CATALOGUE,
    PARAMETRIC_SECTIONS,
    PROBE_COUNT,
    SECTION_LABELS,
    SECTION_ORDER,
    build_probes,
    section_counts,
)
from .executor import ExecutorConfig, ProbeExecutor
from .catalog import ArsenalResult, Matcher, Probe, ProbeHit, SectionStat

__all__ = [
    "CATALOGUE",
    "PARAMETRIC_SECTIONS",
    "PROBE_COUNT",
    "SECTION_LABELS",
    "SECTION_ORDER",
    "build_probes",
    "section_counts",
    "ExecutorConfig",
    "ProbeExecutor",
    "ArsenalResult",
    "Matcher",
    "Probe",
    "ProbeHit",
    "SectionStat",
]
