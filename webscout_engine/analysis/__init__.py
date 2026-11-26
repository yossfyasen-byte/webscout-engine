"""Source and dependency analysis (SAST / SCA)."""

from __future__ import annotations

from .analysis import Advisory, Dependency, collect_dependencies, load_advisories, match_advisories
from .analysis import RULES, Rule, SourceMatch, scan_tree

__all__ = [
    "Advisory",
    "Dependency",
    "collect_dependencies",
    "load_advisories",
    "match_advisories",
    "RULES",
    "Rule",
    "SourceMatch",
    "scan_tree",
]
