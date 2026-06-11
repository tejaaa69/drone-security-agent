"""
main.py
-------
Drone Security Analyst Agent — main orchestrator.

Pipeline flow (all components communicate via the EventBus):

  Simulator
     ↓  publishes RawFrameEvent
  EventBus
     ↓  fans out to:
     ├─ Analyzer (Claude API → AnalysisResult)
     │      ↓  publishes AnalysisResult
     │   EventBus
     │      ↓  fans out to:
     │      ├─ FrameIndexer  (SQLite FTS5 write)
     │      ├─ AlertEngine   (rule evaluation → Alert events)
     │      │      ↓  publishes Alert
     │      │   EventBus
     │      │      └─ AlertIndexer (SQLite write) + Console logger
     │      └─ EventLogger   (event_log.txt write)
     └─ (future: real-time dashboard websocket)

Run modes:
  --mock      Use local mock analyzer (no API key needed, great for testing)
  --live      Use Claude API (requires ANTHROPIC_API_KEY env var)
  --query     Interactive query mode after simulation
"""

import asyncio
import argparse
import os
import sys
import uuid
from pathlib import Path

# Add src/ to path when running from project root
sys.path.insert(0, str(Path(__file__).parent))

from simulator import get_simulation_frames
from event_bus import EventBus, RawFrameEvent, AnalysisResult, Alert
from analyzer import analyze_frame, analyze_frame_mock
from alert_engine import AlertEngine
from frame_indexer import init_db, index_frame, index_alert
from reporter import generate_daily_report, write_report


OUTPUT_DIR = Path(__file__).parent.parent / "sample_output"
EVENT_LOG_PATH = OUTPUT_DIR / "event_log.txt"
ALERT_LOG_PATH = OUTPUT_DIR / "alert_log.txt"


# Log file writers

def _open_logs():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    event_log = open(EVENT_LOG_PATH, "w", encoding="utf-8")
    alert_log = open(ALERT_LOG_PATH, "w", encoding="utf-8")
    event_log.write("=== DRONE SECURITY ANALYST — EVENT LOG ===\n\n")
    alert_log.write("=== DRONE SECURITY ANALYST — ALERT LOG ===\n\n")
    return event_log, alert_log


def _close_logs(event_log, alert_log):
    event_log.close()
    alert_log.close()

# Pipeline builder

def build_pipeline(
    bus: EventBus,
    use_mock: bool,
    event_log,
    alert_log,
) -> AlertEngine:
    """
    Subscribe all components to the event bus.
    Returns the alert engine (needed for daily stats).
    """
    alert_engine = AlertEngine()

    # ── STEP 1: RawFrameEvent → analysis
    async def on_raw_frame(event: RawFrameEvent):
        print(f"  ◈ Frame {event.frame_id:02d} [{event.timestamp}] {event.location}")
        if use_mock:
            result = analyze_frame_mock(event)
        else:
            result = await analyze_frame(event)
        await bus.publish(result)

    # ── STEP 2: AnalysisResult → index + alert evaluation + log
    async def on_analysis_result(result: AnalysisResult):
        # Index the frame
        index_frame(result)

        # Log to event_log.txt
        obj_str = ", ".join(
            f"{o['attributes'].get('color') or ''} {o['type']}".strip()
            for o in result.objects_detected
        ) or "no objects detected"
        event_line = (
            f"[{result.timestamp}] [{result.risk_level:8}] "
            f"{result.location} — {result.summary}"
        )
        event_log.write(event_line + "\n")
        print(f"    → {result.risk_level:8} | {result.summary}")

        # Run alert rules
        alerts = alert_engine.process(result)
        for alert in alerts:
            await bus.publish(alert)

    # ── STEP 3: Alert → index + log
    async def on_alert(alert: Alert):
        index_alert(alert)
        alert_line = (
            f"[{alert.timestamp}] [{alert.severity:8}] "
            f"{alert.location} | {alert.rule_triggered}\n"
            f"  → {alert.message}\n"
        )
        alert_log.write(alert_line)
        # Visual severity marker for terminal
        icon = "🚨" if alert.severity == "CRITICAL" else "⚠️ "
        print(f"    {icon} ALERT [{alert.severity}] {alert.message[:90]}")

    bus.subscribe(RawFrameEvent, on_raw_frame)
    bus.subscribe(AnalysisResult, on_analysis_result)
    bus.subscribe(Alert, on_alert)

    return alert_engine


# Main entry point

async def run_simulation(use_mock: bool = True):
    print("\n" + "═" * 65)
    print("  DRONE SECURITY ANALYST AGENT")
    print(f"  Mode: {'Mock (no API)' if use_mock else 'Live (Claude API)'}")
    print("═" * 65 + "\n")

    # Initialise SQLite schema
    init_db()

    # Open log files
    event_log, alert_log = _open_logs()

    # Build async pipeline
    bus = EventBus()
    alert_engine = build_pipeline(bus, use_mock, event_log, alert_log)

    # Run all simulation frames through the pipeline
    frames = get_simulation_frames()
    print(f"Processing {len(frames)} frames...\n")

    for frame in frames:
        event = RawFrameEvent(
            frame_id=frame.frame_id,
            timestamp=frame.timestamp,
            location=frame.location,
            altitude_m=frame.altitude_m,
            drone_speed_kmh=frame.drone_speed_kmh,
            battery_pct=frame.battery_pct,
            frame_description=frame.frame_description,
        )
        await bus.publish(event)
        # Small delay to simulate real-time processing
        await asyncio.sleep(0.05)

    _close_logs(event_log, alert_log)

    # Generate daily intelligence report
    print("\n" + "─" * 65)
    print("  Generating daily intelligence report...")
    use_ai_report = not use_mock and bool(os.environ.get("ANTHROPIC_API_KEY"))
    report = generate_daily_report(use_ai=use_ai_report)
    report_path = write_report(report)

    print("\n" + "═" * 65)
    print("  SIMULATION COMPLETE")
    print("═" * 65)
    print(f"\n  Event log  → {EVENT_LOG_PATH}")
    print(f"  Alert log  → {ALERT_LOG_PATH}")
    print(f"  Report     → {report_path}")
    print(f"  Database   → {Path(__file__).parent.parent / 'sample_output' / 'drone_security.db'}")
    print()


def main():
    parser = argparse.ArgumentParser(description="Drone Security Analyst Agent")
    parser.add_argument(
        "--mock", action="store_true", default=True,
        help="Use mock analyzer (no API key required)"
    )
    parser.add_argument(
        "--live", action="store_true", default=False,
        help="Use Claude API (requires ANTHROPIC_API_KEY)"
    )
    args = parser.parse_args()

    use_mock = not args.live
    if args.live and not os.environ.get("ANTHROPIC_API_KEY"):
        print("ERROR: --live requires ANTHROPIC_API_KEY environment variable.")
        sys.exit(1)

    asyncio.run(run_simulation(use_mock=use_mock))


if __name__ == "__main__":
    main()