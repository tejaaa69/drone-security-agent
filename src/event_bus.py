"""
event_bus.py

A lightweight in-process publish/subscribe event bus.

All pipeline components communicate exclusively through this bus:
  simulator     → publishes RawFrameEvent
  analyzer      → subscribes RawFrameEvent, publishes AnalysisResult
  frame_indexer → subscribes AnalysisResult, writes to SQLite
  alert_engine  → subscribes AnalysisResult, publishes Alert
  event_logger  → subscribes AnalysisResult, writes event log
  reporter      → subscribes AnalysisResult (or end-of-day signal)

This decouples components completely — no component imports another directly.
Adding a new component is one subscribe() call.
"""

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Awaitable, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


# Typed event definitions

@dataclass
class RawFrameEvent:
    """Emitted by the simulator for each telemetry + video frame."""
    frame_id: int
    timestamp: str           # simulation time "HH:MM"
    location: str
    altitude_m: float
    drone_speed_kmh: float
    battery_pct: int
    frame_description: str
    wall_clock: datetime = field(default_factory=datetime.now)


@dataclass
class AnalysisResult:
    """
    AI-generated analysis of a single frame.
    Produced by analyzer.py using the Claude API.
    This is the component that satisfies 'AI to generate at least one component'.
    """
    frame_id: int
    timestamp: str
    location: str
    objects_detected: List[Dict]        # [{"type": "vehicle", "attributes": {...}}]
    event_category: str                 # ROUTINE / SUSPICIOUS / INTRUSION / EMERGENCY
    risk_level: str                     # LOW / MEDIUM / HIGH / CRITICAL
    alert_text: Optional[str]           # None if no alert warranted
    summary: str                        # One-line human-readable summary
    raw_frame_description: str


@dataclass
class Alert:
    """Produced by the alert engine when a rule fires."""
    alert_id: str
    frame_id: int
    timestamp: str
    location: str
    severity: str           # MEDIUM / HIGH / CRITICAL
    rule_triggered: str     # Name of the rule that fired
    message: str
    wall_clock: datetime = field(default_factory=datetime.now)


# Event bus implementation

class EventBus:
    """
    Async publish/subscribe bus.

    Usage:
        bus = EventBus()
        bus.subscribe(RawFrameEvent, my_handler)
        await bus.publish(RawFrameEvent(...))

    Handlers are async coroutines called in subscription order.
    """

    def __init__(self):
        self._subscribers: Dict[type, List[Callable[[Any], Awaitable[None]]]] = defaultdict(list)

    def subscribe(self, event_type: type, handler: Callable[[Any], Awaitable[None]]) -> None:
        self._subscribers[event_type].append(handler)

    async def publish(self, event: Any) -> None:
        handlers = self._subscribers.get(type(event), [])
        for handler in handlers:
            try:
                await handler(event)
            except Exception:
                logger.exception(
                    "Handler %s failed processing %s — continuing pipeline",
                    handler.__name__, type(event).__name__
                )
                # One bad handler never stops other subscribers on the same event