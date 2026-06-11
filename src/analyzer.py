"""
analyzer.py

The AI-powered analysis component.

This module satisfies the assignment requirement:
  "Use AI to generate at least one component (e.g., object detection logic, alert rules)"

How it works:
  - Receives a RawFrameEvent from the event bus
  - Sends the frame description + telemetry context to Claude (claude-sonnet-4-20250514)
  - Claude extracts: detected objects with attributes, event category, risk level,
    alert recommendation, and a one-line summary
  - Returns a structured AnalysisResult

The Claude prompt is carefully engineered to return valid JSON every time,
enabling reliable downstream processing by the alert engine and indexer.

Why Claude for this?
  - Frame descriptions are natural language, not structured data
  - A vehicle described as "blue pickup" and "blue F150" and "Ford F150 truck"
    are the same object — Claude normalizes this where regex cannot
  - Risk assessment requires context (time of day + location + behavior + history)
    which Claude reasons over holistically
"""

import json
import os
import re
from typing import Optional

import anthropic

from event_bus import RawFrameEvent, AnalysisResult


SYSTEM_PROMPT = """You are a security analysis AI for a drone-based property monitoring system.

You will receive a video frame description and drone telemetry. Your job is to analyze the scene and return a JSON object with this exact structure — no preamble, no markdown, just JSON:

{
  "objects_detected": [
    {
      "type": "person | vehicle | truck | van | car | unknown",
      "count": 1,
      "attributes": {
        "color": "string or null",
        "make": "string or null",
        "model": "string or null",
        "action": "entering | exiting | parked | stationary | moving | loitering | climbing | unknown",
        "has_id_badge": true | false | null,
        "description": "brief physical description"
      }
    }
  ],
  "event_category": "ROUTINE | SUSPICIOUS | INTRUSION | EMERGENCY",
  "risk_level": "LOW | MEDIUM | HIGH | CRITICAL",
  "alert_text": "string if alert warranted, else null",
  "summary": "one sentence summary of this frame for the security log"
}

Risk level guidelines:
- LOW: Normal business hours, known activity, identified individuals
- MEDIUM: After-hours activity, unidentified individuals, vehicles behaving unusually
- HIGH: Late night activity (22:00–06:00), unauthorized access attempts, loitering
- CRITICAL: Active intrusion, fence climbing, multiple unidentified people at night

For alert_text: generate it when risk_level is HIGH or CRITICAL, or when behavior is explicitly suspicious regardless of time. Format: "[CATEGORY] [object] [behavior] at [location], [time]."

Return only valid JSON. No explanation."""


def _parse_claude_json(raw: str) -> dict:
    """
    Robustly extract JSON from Claude's response.
    Handles cases where the model wraps the output in markdown fences.
    """
    # Strip markdown code fences if present
    cleaned = re.sub(r"```(?:json)?", "", raw).strip()
    # Find first { to last } in case of any prefix/suffix text
    start = cleaned.find("{")
    end = cleaned.rfind("}") + 1
    if start == -1 or end == 0:
        raise ValueError(f"No JSON object found in response: {raw[:200]}")
    return json.loads(cleaned[start:end])


async def analyze_frame(
    event: RawFrameEvent,
    client: Optional[anthropic.Anthropic] = None,
) -> AnalysisResult:
    """
    Send a frame to Claude for AI analysis.
    Returns a fully structured AnalysisResult.

    This is the AI-generated component — Claude performs object detection,
    attribute extraction, and risk assessment from natural-language frame descriptions.
    """
    if client is None:
        client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY", ""))

    user_prompt = f"""Analyze this security camera frame:

FRAME DESCRIPTION:
{event.frame_description}

TELEMETRY CONTEXT:
- Simulation time: {event.timestamp}
- Location on property: {event.location}
- Drone altitude: {event.altitude_m}m
- Drone speed: {event.drone_speed_kmh} km/h
- Battery: {event.battery_pct}%

Return your analysis as JSON."""

    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1000,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_prompt}],
    )

    raw_text = response.content[0].text
    parsed = _parse_claude_json(raw_text)

    return AnalysisResult(
        frame_id=event.frame_id,
        timestamp=event.timestamp,
        location=event.location,
        objects_detected=parsed.get("objects_detected", []),
        event_category=parsed.get("event_category", "ROUTINE"),
        risk_level=parsed.get("risk_level", "LOW"),
        alert_text=parsed.get("alert_text"),
        summary=parsed.get("summary", ""),
        raw_frame_description=event.frame_description,
    )


def analyze_frame_mock(event: RawFrameEvent) -> AnalysisResult:
    """
    Deterministic mock analyzer for unit tests.
    Does NOT call the Claude API — parses frame descriptions using simple heuristics.
    Ensures tests are fast, free, and reproducible.
    """
    desc_lower = event.frame_description.lower()
    objects = []
    risk = "LOW"
    category = "ROUTINE"
    alert_text = None

    # Detect vehicles
    if any(w in desc_lower for w in ["truck", "f150", "van", "transit", "vehicle", "suv", "car", "sedan"]):
        color = None
        for c in ["blue", "white", "dark", "grey", "gray", "black"]:
            if c in desc_lower:
                color = c
                break
        make = "Ford" if "ford" in desc_lower else None
        model = "F150" if "f150" in desc_lower else ("Transit" if "transit" in desc_lower else None)
        action = "entering" if "enter" in desc_lower else \
                 "exiting" if "exit" in desc_lower or "depart" in desc_lower else \
                 "parked" if "park" in desc_lower else "stationary"
        objects.append({
            "type": "truck" if "truck" in desc_lower or "van" in desc_lower else "vehicle",
            "count": 1,
            "attributes": {
                "color": color, "make": make, "model": model,
                "action": action, "has_id_badge": None,
                "description": f"{color or ''} {model or 'vehicle'}".strip(),
            }
        })

    # Detect people
    if any(w in desc_lower for w in ["person", "individual", "driver", "employee", "people"]):
        action = "loitering" if "loiter" in desc_lower or "standing" in desc_lower else \
                 "climbing" if "climb" in desc_lower else "stationary"
        has_badge = True if "badge" in desc_lower or "uniform" in desc_lower or "lanyard" in desc_lower else \
                    False if "no badge" in desc_lower or "no visible" in desc_lower else None
        objects.append({
            "type": "person",
            "count": 1,
            "attributes": {
                "color": None, "make": None, "model": None,
                "action": action, "has_id_badge": has_badge,
                "description": "unidentified individual",
            }
        })

    # Determine risk based on time and behavior
    hour = int(event.timestamp.split(":")[0])
    is_night = hour >= 22 or hour < 6

    if "climb" in desc_lower or "fence" in desc_lower and is_night:
        risk, category = "CRITICAL", "INTRUSION"
        alert_text = f"INTRUSION: Individual climbing perimeter fence at {event.location}, {event.timestamp}."
    elif "loiter" in desc_lower and is_night:
        risk, category = "HIGH", "SUSPICIOUS"
        alert_text = f"ALERT: Person loitering at {event.location}, {event.timestamp}."
    elif is_night and objects:
        risk, category = "HIGH", "SUSPICIOUS"
        alert_text = f"ALERT: After-hours activity detected at {event.location}, {event.timestamp}."
    elif "keypad" in desc_lower or "access" in desc_lower and is_night:
        risk, category = "HIGH", "SUSPICIOUS"
        alert_text = f"ALERT: Unauthorized access attempt at {event.location}, {event.timestamp}."
    elif is_night:
        risk = "MEDIUM"
        category = "SUSPICIOUS"

    # Summary
    obj_str = ", ".join(
        f"{o['attributes'].get('color') or ''} {o['type']}".strip()
        for o in objects
    ) or "no notable objects"
    summary = f"{obj_str.capitalize()} observed at {event.location} at {event.timestamp}."

    return AnalysisResult(
        frame_id=event.frame_id,
        timestamp=event.timestamp,
        location=event.location,
        objects_detected=objects,
        event_category=category,
        risk_level=risk,
        alert_text=None,
        summary=summary,
        raw_frame_description=event.frame_description,
    )