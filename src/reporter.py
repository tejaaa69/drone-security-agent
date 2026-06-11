"""
reporter.py

Generates a daily intelligence report using Claude.

After all frames have been processed, this module:
  1. Collects all alerts, event summaries, and vehicle frequency data
  2. Sends the full day's data to Claude with a reporting prompt
  3. Writes a natural-language security briefing to sample_output/

This is the "executive summary" feature — what a property owner actually reads
instead of raw logs.
"""

import os
import json
from datetime import date
from pathlib import Path
from typing import List, Dict

import anthropic

from frame_indexer import get_all_frames, get_all_alerts, get_vehicle_frequency


OUTPUT_DIR = Path(__file__).parent.parent / "sample_output"


REPORT_SYSTEM_PROMPT = """You are a professional security analyst writing a daily intelligence briefing for a property owner.

You will receive structured data from a drone security system: frame summaries, triggered alerts, and vehicle tracking data.

Write a clear, professional security report in plain English. Structure it as:

## Daily Security Report — [DATE]

### Executive Summary
2-3 sentences covering the overall security status of the day.

### Key Incidents
List each significant event (HIGH/CRITICAL) with: time, location, what happened, recommended action.

### Vehicle Activity
Summarize all vehicle activity. Flag any that appeared more than once.

### Routine Activity
Brief note on normal activity observed.

### Recommendations
2-3 specific, actionable recommendations based on today's events.

Be direct and professional. Property owners want facts and actions, not speculation."""


def generate_daily_report(use_ai: bool = False) -> str:
    """
    Generate a full-day intelligence report.
    use_ai=False, falls back to a structured text report (for testing/no-API scenarios).
    """
    frames = get_all_frames()
    alerts = get_all_alerts()
    vehicles = get_vehicle_frequency()
    today = date.today().strftime("%B %d, %Y")

    if not use_ai or not os.environ.get("ANTHROPIC_API_KEY"):
        return _generate_text_report(frames, alerts, vehicles, today)

    # Build compact data payload for Claude
    alert_summary = [
        {"time": a["sim_timestamp"], "location": a["location"],
         "severity": a["severity"], "rule": a["rule_triggered"], "message": a["message"]}
        for a in alerts
    ]
    frame_summary = [
        {"time": f["sim_timestamp"], "location": f["location"],
         "risk": f["risk_level"], "summary": f["summary"]}
        for f in frames
    ]
    vehicle_summary = [
        {"vehicle": f"{v['vehicle_color']} {v['vehicle_make']} {v['vehicle_model']}".strip(),
         "appearances": v["appearances"], "times": v["times"], "locations": v["locations"]}
        for v in vehicles
    ]

    data_payload = json.dumps({
        "date": today,
        "total_frames": len(frames),
        "total_alerts": len(alerts),
        "critical_alerts": sum(1 for a in alerts if a["severity"] == "CRITICAL"),
        "high_alerts": sum(1 for a in alerts if a["severity"] == "HIGH"),
        "alerts": alert_summary,
        "frames": frame_summary,
        "vehicles": vehicle_summary,
    }, indent=2)

    client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1000,
        system=REPORT_SYSTEM_PROMPT,
        messages=[{
            "role": "user",
            "content": f"Generate the daily security report for this data:\n\n{data_payload}"
        }],
    )
    return response.content[0].text


def _generate_text_report(
    frames: List[Dict],
    alerts: List[Dict],
    vehicles: List[Dict],
    today: str,
) -> str:
    """Fallback structured text report (no API call required)."""
    lines = [
        f"## Daily Security Report — {today}",
        "",
        "### Executive Summary",
        f"Drone monitoring captured {len(frames)} frames over the 24-hour period. "
        f"{len(alerts)} alert(s) were triggered, including "
        f"{sum(1 for a in alerts if a['severity'] == 'CRITICAL')} CRITICAL and "
        f"{sum(1 for a in alerts if a['severity'] == 'HIGH')} HIGH severity events.",
        "",
        "### Alerts Fired",
    ]
    for a in alerts:
        lines.append(f"  [{a['severity']}] {a['sim_timestamp']} — {a['location']}")
        lines.append(f"    Rule: {a['rule_triggered']}")
        lines.append(f"    {a['message']}")
        lines.append("")

    lines.append("### Vehicle Activity")
    if vehicles:
        for v in vehicles:
            vehicle_name = " ".join(filter(None, [
                v["vehicle_color"], v["vehicle_make"], v["vehicle_model"]
            ])).title() or "Unknown Vehicle"
            lines.append(
                f"  {vehicle_name}: {v['appearances']} appearance(s) "
                f"at {v['times']} — {v['locations']}"
            )
    else:
        lines.append("  No vehicles logged.")

    lines.append("")
    lines.append("### Frame Log")
    for f in frames:
        lines.append(f"  [{f['sim_timestamp']}] [{f['risk_level']:8}] {f['location']}: {f['summary']}")

    return "\n".join(lines)


def write_report(content: str) -> Path:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    report_path = OUTPUT_DIR / "daily_report.txt"
    report_path.write_text(content, encoding="utf-8")
    return report_path