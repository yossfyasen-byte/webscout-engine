"""Shared helpers for checks (not a check module itself)."""

from __future__ import annotations

import difflib
import json
import re
import time
from functools import lru_cache
from pathlib import Path

from ..core.models import HttpResult
from ..recon.crawl import Parameter

# Parameter names that commonly carry a server-side resource reference.
URL_PARAMS = {
    "url", "uri", "link", "src", "source", "dest", "destination", "target",
    "callback", "webhook", "feed", "host", "path", "image", "avatar", "proxy",
    "fetch", "load", "open", "site", "domain", "return", "next", "continue",
}
FILE_PARAMS = {
    "file", "filename", "path", "page", "template", "include", "doc", "document",
    "download", "view", "read", "load", "dir", "folder", "module", "lang",
}
AUTH_PARAMS = {"user", "username", "email", "login", "name", "account", "uid"}


def similarity(left: str, right: str, limit: int = 4000) -> float:
    return difflib.SequenceMatcher(None, (left or "")[:limit], (right or "")[:limit]).ratio()


def normalise(body: str) -> str:
    return " ".join((body or "").split())


def first_match(body: str, patterns: tuple[str, ...]) -> str | None:
    for pattern in patterns:
        found = re.search(pattern, body or "", re.IGNORECASE)
        if found:
            start = max(0, found.start() - 60)
            return " ".join((body[start : found.end() + 80]).split())
    return None


async def timed_get(check: object, url: str, **kwargs: object) -> tuple[HttpResult | None, float]:
    """GET that also reports how long it took, in seconds."""
    started = time.perf_counter()
    result = await check.get(url, **kwargs)  # type: ignore[attr-defined]
    return result, time.perf_counter() - started


DATA_DIR = Path(__file__).resolve().parent.parent / "data"


@lru_cache(maxsize=8)
def load_payloads(family: str) -> tuple[str, ...]:
    """Payload variants for a family, from data/payloads.json."""
    source = DATA_DIR / "payloads.json"
    if not source.exists():
        return ()
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return ()
    items = payload.get("families", {}).get(family, [])
    return tuple(str(item) for item in items if str(item))


# Cheap checks probe this many parameter instances; time-based checks stay at
# --max-blind-params because every probe costs a full delay.
MAX_PARAMS = 12


def pick(params: list[Parameter], names: set[str], limit: int = 2) -> list[Parameter]:
    return [param for param in params if param.name.lower() in names][:limit]


def any_param(params: list[Parameter], limit: int = 3) -> list[Parameter]:
    return [param for param in params if param.name][:limit]
