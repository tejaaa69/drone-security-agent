"""
alert_engine.py

Rule-based alert engine that consumes AnalysisResult events from the event bus
and produces Alert events.

Rules are evaluated in priority order. Multiple rules can fire on a single frame.
Each rule is a plain function — easy to add, test, and document.

Rule catalogue:
  1. NightTimeActivityRule    — any activity detected between 22:00 and 06:00
  2. LoiteringRule            — person stationary/loitering (any time)
  3. FenceIntrustionRule      — fence climbing or perimeter breach
  4. AfterHoursAccessRule     — access attempt at locked door after business hours
  5. RepeatVehicleRule        — same vehicle seen 3+ times in the session
  6. CriticalAIRule           — pass-through for CRITICAL AI risk assessments
  7. UnidentifiedNightPersonRule — person with no ID badge at night
"""

import uuid
from dataclasses import dataclass
from typing import List, Optional

from event_bus import AnalysisResult, Alert

# Rule base class

@dataclass
class RuleContext:
    """Shared context passed to every rule — allows rules to check history."""
    vehicle_appearances: dict   # "color make model" → count
    high_risk_locations: list   # locations with prior HIGH/CRITICAL events today


class AlertRule:
    name: str = "BaseRule"
    default_severity: str = "MEDIUM"

    def evaluate(self, result: AnalysisResult, ctx: RuleContext) -> Optional[Alert]:
        raise NotImplementedError


# Concrete rules

class NightTimeActivityRule(AlertRule):
    name = "NightTimeActivityRule"
    default_severity = "HIGH"

    def evaluate(self, result: AnalysisResult, ctx: RuleContext) -> Optional[Alert]:
        hour = int(result.timestamp.split(":")[0])
        is_night = hour >= 22 or hour < 6
        has_people_or_vehicles = any(
            obj.get("type") in ("person", "vehicle", "truck", "car", "van")
            for obj in result.objects_detected
        )
        if is_night and has_people_or_vehicles and result.event_category != "ROUTINE":
            return Alert(
                alert_id=str(uuid.uuid4())[:8],
                frame_id=result.frame_id,
                timestamp=result.timestamp,
                location=result.location,
                severity=self.default_severity,
                rule_triggered=self.name,
                message=(
                    f"[NIGHT ACTIVITY] Activity detected after hours at "
                    f"{result.location}, {result.timestamp}. "
                    f"{result.summary}"
                ),
            )
        return None


class LoiteringRule(AlertRule):
    name = "LoiteringRule"
    default_severity = "HIGH"

    def evaluate(self, result: AnalysisResult, ctx: RuleContext) -> Optional[Alert]:
        for obj in result.objects_detected:
            action = obj.get("attributes", {}).get("action", "")
            if action == "loitering" or "loiter" in result.raw_frame_description.lower():
                hour = int(result.timestamp.split(":")[0])
                severity = "CRITICAL" if (hour >= 22 or hour < 6) else "HIGH"
                return Alert(
                    alert_id=str(uuid.uuid4())[:8],
                    frame_id=result.frame_id,
                    timestamp=result.timestamp,
                    location=result.location,
                    severity=severity,
                    rule_triggered=self.name,
                    message=(
                        f"[LOITERING] Person loitering at {result.location}, "
                        f"{result.timestamp}. Review footage immediately."
                    ),
                )
        return None


class FenceIntrusionRule(AlertRule):
    name = "FenceIntrusionRule"
    default_severity = "CRITICAL"

    def evaluate(self, result: AnalysisResult, ctx: RuleContext) -> Optional[Alert]:
        desc = result.raw_frame_description.lower()
        if "climbing" in desc or "climb" in desc or (
            "fence" in desc and any(w in desc for w in ["breach", "over", "through"])
        ):
            return Alert(
                alert_id=str(uuid.uuid4())[:8],
                frame_id=result.frame_id,
                timestamp=result.timestamp,
                location=result.location,
                severity="CRITICAL",
                rule_triggered=self.name,
                message=(
                    f"[INTRUSION CRITICAL] Perimeter fence breach at "
                    f"{result.location}, {result.timestamp}. "
                    f"Dispatch security immediately."
                ),
            )
        return None


class AfterHoursAccessRule(AlertRule):
    name = "AfterHoursAccessRule"
    default_severity = "HIGH"
    BUSINESS_HOURS = (8, 19)  # 08:00–19:00

    def evaluate(self, result: AnalysisResult, ctx: RuleContext) -> Optional[Alert]:
        hour = int(result.timestamp.split(":")[0])
        is_after_hours = hour < self.BUSINESS_HOURS[0] or hour >= self.BUSINESS_HOURS[1]
        desc = result.raw_frame_description.lower()
        if is_after_hours and ("keypad" in desc or "access" in desc or "door" in desc):
            return Alert(
                alert_id=str(uuid.uuid4())[:8],
                frame_id=result.frame_id,
                timestamp=result.timestamp,
                location=result.location,
                severity=self.default_severity,
                rule_triggered=self.name,
                message=(
                    f"[ACCESS ATTEMPT] Unauthorized access attempt at "
                    f"{result.location}, {result.timestamp}."
                ),
            )
        return None


class RepeatVehicleRule(AlertRule):
    name = "RepeatVehicleRule"
    default_severity = "MEDIUM"
    THRESHOLD = 3  # Flag after this many appearances

    def evaluate(self, result: AnalysisResult, ctx: RuleContext) -> Optional[Alert]:
        for obj in result.objects_detected:
            if obj.get("type") in ("vehicle", "truck", "car", "van"):
                attrs = obj.get("attributes", {})
                key = " ".join(filter(None, [
                    attrs.get("color"), attrs.get("make"), attrs.get("model")
                ])).strip().lower()
                if not key:
                    continue
                count = ctx.vehicle_appearances.get(key, 0) + 1
                ctx.vehicle_appearances[key] = count
                if count >= self.THRESHOLD:
                    return Alert(
                        alert_id=str(uuid.uuid4())[:8],
                        frame_id=result.frame_id,
                        timestamp=result.timestamp,
                        location=result.location,
                        severity=self.default_severity,
                        rule_triggered=self.name,
                        message=(
                            f"[REPEAT VEHICLE] '{key.title()}' has been observed "
                            f"{count} times today. Last seen at "
                            f"{result.location}, {result.timestamp}. "
                            f"Verify vehicle authorization."
                        ),
                    )
        return None


class CriticalAIRule(AlertRule):
    """Pass-through: if Claude rated this CRITICAL, escalate regardless of other rules."""
    name = "CriticalAIRule"
    default_severity = "CRITICAL"

    def evaluate(self, result: AnalysisResult, ctx: RuleContext) -> Optional[Alert]:
        if result.risk_level == "CRITICAL" and result.alert_text:
            return Alert(
                alert_id=str(uuid.uuid4())[:8],
                frame_id=result.frame_id,
                timestamp=result.timestamp,
                location=result.location,
                severity="CRITICAL",
                rule_triggered=self.name,
                message=f"[AI CRITICAL] {result.alert_text}",
            )
        return None


class UnidentifiedNightPersonRule(AlertRule):
    name = "UnidentifiedNightPersonRule"
    default_severity = "HIGH"

    def evaluate(self, result: AnalysisResult, ctx: RuleContext) -> Optional[Alert]:
        hour = int(result.timestamp.split(":")[0])
        is_night = hour >= 22 or hour < 6
        for obj in result.objects_detected:
            if obj.get("type") == "person":
                has_badge = obj.get("attributes", {}).get("has_id_badge")
                if is_night and has_badge is False:
                    return Alert(
                        alert_id=str(uuid.uuid4())[:8],
                        frame_id=result.frame_id,
                        timestamp=result.timestamp,
                        location=result.location,
                        severity=self.default_severity,
                        rule_triggered=self.name,
                        message=(
                            f"[UNIDENTIFIED] Person without visible ID badge detected "
                            f"at night — {result.location}, {result.timestamp}."
                        ),
                    )
        return None


# Alert engine — aggregates all rules

class AlertEngine:
    """
    Evaluates all registered rules against each AnalysisResult.
    Returns a list of fired alerts (deduplicated by message).
    """

    def __init__(self):
        self._rules: List[AlertRule] = [
            FenceIntrusionRule(),       # highest priority first
            CriticalAIRule(),
            LoiteringRule(),
            NightTimeActivityRule(),
            AfterHoursAccessRule(),
            UnidentifiedNightPersonRule(),
            RepeatVehicleRule(),        # needs count context, last
        ]
        self._context = RuleContext(
            vehicle_appearances={},
            high_risk_locations=[],
        )

    def process(self, result: AnalysisResult) -> List[Alert]:
        alerts = []
        seen_messages = set()
        for rule in self._rules:
            alert = rule.evaluate(result, self._context)
            if alert and alert.message not in seen_messages:
                alerts.append(alert)
                seen_messages.add(alert.message)
                if alert.severity in ("HIGH", "CRITICAL"):
                    if result.location not in self._context.high_risk_locations:
                        self._context.high_risk_locations.append(result.location)
        return alerts

    def reset(self):
        """Reset daily context (call at start of each 24h simulation)."""
        self._context = RuleContext(
            vehicle_appearances={},
            high_risk_locations=[],
        )