"""webscout_engine - asynchronous, scope-aware security assessment framework.

The package is intentionally importable without side effects so that tests and
the ``--self-test`` launcher path can import individual layers cheaply.
"""

from __future__ import annotations

__all__ = [
    "__version__",
    "TOOL_NAME",
    "DEVELOPER_TELEGRAM",
    "DEVELOPER_GITHUB",
    "DEVELOPER_LINE",
]

TOOL_NAME = "webscout_engine"
__version__ = "2.0.0"

DEVELOPER_TELEGRAM = "@VlP_12"
DEVELOPER_GITHUB = "https://github.com//"
DEVELOPER_LINE = f"{DEVELOPER_TELEGRAM}  ·  {DEVELOPER_GITHUB}"
