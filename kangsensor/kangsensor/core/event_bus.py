"""Lightweight synchronous pub-sub event bus used internally by sensors."""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Callable

logger = logging.getLogger(__name__)

EventHandler = Callable[[dict], None]


class EventBus:
    """Simple publish-subscribe bus. Subscribers run synchronously in the caller's thread."""

    def __init__(self) -> None:
        self._handlers: dict[str, list[EventHandler]] = defaultdict(list)

    def subscribe(self, event_type: str, handler: EventHandler) -> None:
        """Register *handler* to receive events of *event_type*."""
        self._handlers[event_type].append(handler)

    def publish(self, event_type: str, payload: dict) -> None:
        """Dispatch *payload* to all handlers registered for *event_type*."""
        for handler in self._handlers.get(event_type, []):
            try:
                handler(payload)
            except Exception:
                logger.exception("EventBus handler %s raised an exception", handler)

    def unsubscribe(self, event_type: str, handler: EventHandler) -> None:
        handlers = self._handlers.get(event_type, [])
        try:
            handlers.remove(handler)
        except ValueError:
            pass


# Module-level singleton used by sensors and actions
bus = EventBus()
