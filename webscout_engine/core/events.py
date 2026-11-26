"""Lightweight in-process event bus.

Modules publish events (stage changes, findings, warnings, rate limits) and the
UI subscribes. Subscribers may be sync or async callables; a failing subscriber
never breaks the scan.
"""

from __future__ import annotations

import inspect
from collections import deque
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from .models import utcnow


class EventType(str, Enum):
    SCAN_START = "scan.start"
    SCAN_END = "scan.end"
    MODULE_START = "module.start"
    MODULE_END = "module.end"
    STAGE = "stage"
    OPERATION = "operation"
    PROGRESS = "progress"
    FINDING = "finding"
    OBSERVATION = "observation"
    REQUEST = "request"
    RATE_LIMIT = "rate_limit"
    WARNING = "warning"
    ERROR = "error"
    CANCELLED = "cancelled"
    INFO = "info"


@dataclass(slots=True)
class Event:
    type: EventType
    message: str
    data: dict[str, Any] = field(default_factory=dict)
    level: str = "info"
    timestamp: datetime = field(default_factory=utcnow)


Subscriber = Callable[[Event], None | Awaitable[None]]


class EventBus:
    """Bounded history + fan-out. Deliberately not thread-safe (single loop)."""

    def __init__(self, maxlen: int = 500) -> None:
        self._history: deque[Event] = deque(maxlen=maxlen)
        self._subscribers: list[Subscriber] = []

    def subscribe(self, callback: Subscriber) -> None:
        if callback not in self._subscribers:
            self._subscribers.append(callback)

    def unsubscribe(self, callback: Subscriber) -> None:
        if callback in self._subscribers:
            self._subscribers.remove(callback)

    async def emit(
        self,
        event_type: EventType,
        message: str,
        data: dict[str, Any] | None = None,
        level: str = "info",
    ) -> Event:
        event = Event(type=event_type, message=message, data=data or {}, level=level)
        self._history.append(event)
        for callback in list(self._subscribers):
            try:
                result = callback(event)
                if inspect.isawaitable(result):
                    await result
            except Exception:  # pragma: no cover - subscriber isolation
                continue
        return event

    def history(self, limit: int | None = None) -> list[Event]:
        items = list(self._history)
        if limit is not None and limit > 0:
            return items[-limit:]
        return items

    def clear(self) -> None:
        self._history.clear()
