"""Plugin registry: decorator-based registration and discovery."""

from __future__ import annotations

import importlib
import pkgutil
from collections.abc import Iterable

from ..catalog import CHECK_INFO
from .base import BaseCheck, CheckContext, CheckMeta

_REGISTRY: dict[str, type[BaseCheck]] = {}
_LOAD_FAILURES: dict[str, str] = {}
_LOADED = False

# Modules that hold infrastructure, not checks.
_SKIP = {"base", "registry", "helpers", "__init__"}


def register(cls: type[BaseCheck]) -> type[BaseCheck]:
    """Class decorator that adds a check to the registry."""
    meta = getattr(cls, "meta", None)
    if not isinstance(meta, CheckMeta):
        raise TypeError(f"{cls.__name__} must define a CheckMeta 'meta' attribute")
    if meta.name in _REGISTRY and _REGISTRY[meta.name] is not cls:
        raise ValueError(f"duplicate check name: {meta.name!r}")
    info = CHECK_INFO.get(meta.name)
    if info is not None:
        # The catalog is the single source of truth for CWE/CVSS/scan type.
        meta.cwe = meta.cwe or info.cwe
        meta.cvss = meta.cvss if meta.cvss is not None else info.cvss
        meta.scan_type = info.scan_type
        meta.impact = info.impact
        meta.category = info.category if meta.category == "general" else meta.category
    _REGISTRY[meta.name] = cls
    return cls


def load_checks(force: bool = False) -> dict[str, type[BaseCheck]]:
    """Import every module in this package so decorators run.

    One unimportable module must never take the whole tool down: a check written
    against a different API, or a leftover file from another release, is skipped
    and recorded in :func:`load_failures` so the caller can surface it.
    """
    global _LOADED
    if _LOADED and not force:
        return dict(_REGISTRY)
    package = importlib.import_module(__package__ or "webscout_engine.checks")
    failures: dict[str, str] = {}
    for module_info in pkgutil.iter_modules(package.__path__):
        if module_info.name in _SKIP:
            continue
        try:
            importlib.import_module(f"{package.__name__}.{module_info.name}")
        except Exception as exc:  # a broken plugin is reported, never fatal
            failures[module_info.name] = f"{type(exc).__name__}: {exc}"
    _LOAD_FAILURES.clear()
    _LOAD_FAILURES.update(failures)
    _LOADED = True
    return dict(_REGISTRY)


def load_failures() -> dict[str, str]:
    """Check modules that could not be imported, mapped to the reason."""
    load_checks()
    return dict(_LOAD_FAILURES)


def get_registry() -> dict[str, type[BaseCheck]]:
    return load_checks()


def build_checks(
    ctx: CheckContext,
    names: Iterable[str] | None = None,
    exclude: Iterable[str] | None = None,
) -> list[BaseCheck]:
    """Instantiate the requested checks in stable name order."""
    registry = load_checks()
    selected = set(names) if names else set(registry)
    if exclude:
        selected -= set(exclude)
    unknown = selected - set(registry)
    if unknown and names:
        raise KeyError(f"unknown checks: {', '.join(sorted(unknown))}")
    return [registry[name](ctx) for name in sorted(selected & set(registry))]


def list_check_metadata() -> list[CheckMeta]:
    registry = load_checks()
    return [registry[name].meta for name in sorted(registry)]
