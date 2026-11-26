"""Module registry: name resolution and the full-scan planner."""

from __future__ import annotations

from .arsenal import ArsenalModule
from ..catalog import MODULE_ORDER, MODULE_SPECS, Plan, plan_modules
from .base import BaseModule, ModuleOutcome
from .source import SourceCodeModule
from .source import DependencyModule
from .discovery import DirectoryDiscoveryModule
from .discovery import SensitiveFileModule
from .infra import InfraReconModule
from .origin import OriginDiscoveryModule
from .params import ParameterDiscoveryModule
from .tech import TechnologyProbeModule
from .vuln import WebSecurityModule

MODULES: dict[str, type[BaseModule]] = {
    "infra": InfraReconModule,
    "origin": OriginDiscoveryModule,
    "files": SensitiveFileModule,
    "dirs": DirectoryDiscoveryModule,
    "params": ParameterDiscoveryModule,
    "tech": TechnologyProbeModule,
    "vuln": WebSecurityModule,
    "arsenal": ArsenalModule,
    "code": SourceCodeModule,
    "deps": DependencyModule,
}

MODULE_LABELS: dict[str, str] = {name: MODULE_SPECS[name].title for name in MODULES}


def resolve_modules(spec: str | list[str] | None) -> list[str]:
    """Expand ``all`` / comma lists into a validated, canonically ordered list."""
    if spec is None:
        return list(MODULE_ORDER)
    if isinstance(spec, str):
        items = [part.strip().lower() for part in spec.split(",") if part.strip()]
    else:
        items = [str(part).strip().lower() for part in spec]
    if not items or "all" in items:
        return list(MODULE_ORDER)
    unknown = [item for item in items if item not in MODULES]
    if unknown:
        raise ValueError(f"unknown module(s): {', '.join(unknown)}")
    selected = set(items)
    return [name for name in MODULE_ORDER if name in selected]


__all__ = [
    "BaseModule",
    "ModuleOutcome",
    "MODULES",
    "MODULE_ORDER",
    "MODULE_LABELS",
    "MODULE_SPECS",
    "Plan",
    "plan_modules",
    "resolve_modules",
    "InfraReconModule",
    "OriginDiscoveryModule",
    "ParameterDiscoveryModule",
    "SensitiveFileModule",
    "DirectoryDiscoveryModule",
    "TechnologyProbeModule",
    "WebSecurityModule",
    "ArsenalModule",
    "SourceCodeModule",
    "DependencyModule",
]
