"""Reusable security checks with automatic plugin registration.

Adding a check is a two-step operation: create a module in this package, decorate
the class with ``@register``. :func:`load_checks` discovers it at import time -
no central list to edit, no import cycles.
"""

from __future__ import annotations

from .base import BaseCheck, CheckContext, CheckMeta, safe_get
from .registry import (
    build_checks,
    get_registry,
    list_check_metadata,
    load_checks,
    load_failures,
    register,
)

__all__ = [
    "BaseCheck",
    "CheckContext",
    "CheckMeta",
    "safe_get",
    "register",
    "load_checks",
    "load_failures",
    "get_registry",
    "build_checks",
    "list_check_metadata",
]
