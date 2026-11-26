"""Secret redaction helpers.

Nothing in webscout_engine ever stores a real secret value: evidence strings pass
through :func:`redact` before they reach a model, a log line or a report.
"""

from __future__ import annotations

import re
from typing import Any

REDACTED = "[REDACTED]"
MAX_EVIDENCE = 600

# (pattern, group index to replace). Group 0 means "replace the whole match".
_PATTERNS: list[tuple[re.Pattern[str], int]] = [
    (
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
            re.DOTALL,
        ),
        0,
    ),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), 0),
    (re.compile(r"\bASIA[0-9A-Z]{16}\b"), 0),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), 0),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), 0),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"), 0),
    (re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"), 0),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b"), 0),
    (re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/-]{10,}=*"), 1),
    (
        re.compile(
            r"(?i)(?<![A-Za-z0-9])(api[_-]?key|apikey|secret[_-]?key|secret|access[_-]?key|"
            r"auth[_-]?token|token|password|passwd|pwd|client[_-]?secret|"
            r"private[_-]?key|credentials?)\s*[:=]\s*[\"']?([^\s\"'&,;<]{6,})"
        ),
        2,
    ),
    (re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^/\s:@]+:([^/\s@]{4,})@"), 1),
]


def redact(text: str) -> str:
    """Return ``text`` with recognisable secret values replaced."""
    if not text:
        return ""
    result = text
    for pattern, group in _PATTERNS:
        def _sub(match: re.Match[str], _g: int = group) -> str:
            if _g == 0:
                return REDACTED
            whole = match.group(0)
            value = match.group(_g)
            if not value:
                return whole
            start, end = match.span(_g)
            offset = match.start(0)
            return whole[: start - offset] + REDACTED + whole[end - offset :]

        result = pattern.sub(_sub, result)
    return result


def redact_evidence(text: str, limit: int = MAX_EVIDENCE) -> str:
    """Redact, collapse whitespace and bound the length of an evidence string."""
    collapsed = " ".join(redact(text).split())
    if len(collapsed) > limit:
        return collapsed[:limit] + "... [truncated]"
    return collapsed


SENSITIVE_KEY_RE = re.compile(
    r"(?i)(password|passwd|pwd|secret|token|api[_-]?key|apikey|credential|private[_-]?key|auth)"
)


def redact_value(value: Any) -> Any:
    """Recursively redact strings inside dicts / lists (used for config snapshots).

    A value stored under a sensitive key name is replaced wholesale, because the
    value alone often carries no recognisable pattern (a bare password).
    """
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        cleaned: dict[Any, Any] = {}
        for key, item in value.items():
            if isinstance(key, str) and SENSITIVE_KEY_RE.search(key) and not isinstance(item, (dict, list, tuple)):
                cleaned[key] = REDACTED if item not in (None, "") else item
            else:
                cleaned[key] = redact_value(item)
        return cleaned
    if isinstance(value, (list, tuple)):
        return [redact_value(item) for item in value]
    return value
