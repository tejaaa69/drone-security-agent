"""
test_agent.py

Comprehensive test suite for the Drone Security Analyst Agent.

Coverage:
  - Simulator: correct frame generation and structure
  - Event bus: pub/sub wiring, multiple subscribers
  - Analyzer (mock): object extraction, risk scoring, alert generation
  - Alert engine: each rule fires correctly, deduplication works
  - Frame indexer: SQLite writes, FTS5 search, time-range queries, vehicle frequency
  - Alert indexer: severity filtering
  - Pipeline: end-to-end integration test using mock analyzer

All tests use a temporary in-memory or temp-file SQLite database.
No Claude API calls are made (mock analyzer only).
"""

import asyncio
import json
import sys
import tempfile
import uuid
from pathlib import Path
from typing import List

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from simulator import get_simulation_frames, TelemetryFrame
from event_bus import EventBus, RawFrameEvent, AnalysisResult, Alert
from analyzer import analyze_frame_mock
from alert_engine import (
    AlertEngine, RuleContext,
    FenceIntrusionRule, LoiteringRule, NightTimeActivityRule,
    RepeatVehicleRule, AfterHoursAccessRule,
    UnidentifiedNightPersonRule,
)
from frame_indexer import (
    init_db, index_frame, index_alert,
    query_by_object, query_by_time_range,
    query_alerts_by_severity, get_vehicle_frequency, get_all_alerts,
)

# Helpers

def tmp_db() -> Path:
    """Return a fresh temp database path for each test."""
    f = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    p = Path(f.name)
    f.close()
    init_db(p)
    return p


def make_raw_event(
    frame_id=1,
    timestamp="12:00",
    location="Main Gate",
    description="A blue Ford F150 truck is entering the main gate.",
) -> RawFrameEvent:
    return RawFrameEvent(
        frame_id=frame_id,
        timestamp=timestamp,
        location=location,
        altitude_m=15.0,
        drone_speed_kmh=0.0,
        battery_pct=80,
        frame_description=description,
    )


def make_analysis_result(
    frame_id=1,
    timestamp="12:00",
    location="Main Gate",
    risk_level="LOW",
    event_category="ROUTINE",
    objects=None,
    alert_text=None,
    summary="Blue F150 spotted at main gate.",
    raw_desc="A blue Ford F150 truck is entering the main gate.",
) -> AnalysisResult:
    if objects is None:
        objects = [{
            "type": "truck",
            "count": 1,
            "attributes": {
                "color": "blue", "make": "Ford", "model": "F150",
                "action": "entering", "has_id_badge": None,
                "description": "blue Ford F150",
            }
        }]
    return AnalysisResult(
        frame_id=frame_id,
        timestamp=timestamp,
        location=location,
        objects_detected=objects,
        event_category=event_category,
        risk_level=risk_level,
        alert_text=alert_text,
        summary=summary,
        raw_frame_description=raw_desc,
    )


# 1. Simulator tests

class TestSimulator:
    def test_returns_correct_frame_count(self):
        frames = get_simulation_frames()
        assert len(frames) == 14, f"Expected 14 frames, got {len(frames)}"

    def test_frames_are_typed(self):
        frames = get_simulation_frames()
        for f in frames:
            assert isinstance(f, TelemetryFrame)

    def test_frame_ids_are_sequential(self):
        frames = get_simulation_frames()
        for i, f in enumerate(frames, start=1):
            assert f.frame_id == i

    def test_timestamps_are_valid_format(self):
        frames = get_simulation_frames()
        for f in frames:
            h, m = f.timestamp.split(":")
            assert 0 <= int(h) <= 23
            assert 0 <= int(m) <= 59

    def test_scenario_contains_f150(self):
        frames = get_simulation_frames()
        descriptions = [f.frame_description for f in frames]
        assert any("F150" in d or "F150" in d for d in descriptions)

    def test_scenario_contains_midnight_event(self):
        frames = get_simulation_frames()
        midnight_frames = [f for f in frames if f.timestamp.startswith("00:")]
        assert len(midnight_frames) >= 1

    def test_scenario_contains_perimeter_event(self):
        frames = get_simulation_frames()
        perimeter = [f for f in frames if "Perimeter" in f.location]
        assert len(perimeter) >= 1


# 2. Event bus tests

class TestEventBus:
    def test_single_subscriber_receives_event(self):
        bus = EventBus()
        received = []

        async def handler(event):
            received.append(event)

        bus.subscribe(RawFrameEvent, handler)
        event = make_raw_event()
        asyncio.get_event_loop().run_until_complete(bus.publish(event))
        assert len(received) == 1
        assert received[0].frame_id == 1

    def test_multiple_subscribers_all_receive(self):
        bus = EventBus()
        log_a, log_b = [], []

        async def h_a(e): log_a.append(e)
        async def h_b(e): log_b.append(e)

        bus.subscribe(RawFrameEvent, h_a)
        bus.subscribe(RawFrameEvent, h_b)
        asyncio.get_event_loop().run_until_complete(bus.publish(make_raw_event()))
        assert len(log_a) == 1
        assert len(log_b) == 1

    def test_different_event_types_dont_cross(self):
        bus = EventBus()
        raw_log, analysis_log = [], []

        async def on_raw(e): raw_log.append(e)
        async def on_analysis(e): analysis_log.append(e)

        bus.subscribe(RawFrameEvent, on_raw)
        bus.subscribe(AnalysisResult, on_analysis)

        asyncio.get_event_loop().run_until_complete(bus.publish(make_raw_event()))
        assert len(raw_log) == 1
        assert len(analysis_log) == 0   # AnalysisResult handler not called


# 3. Analyzer (mock) tests

class TestMockAnalyzer:
    def test_detects_blue_f150(self):
        event = make_raw_event(description="A blue Ford F150 truck parked at the garage.")
        result = analyze_frame_mock(event)
        vehicle_types = [o["type"] for o in result.objects_detected]
        assert any(t in ("truck", "vehicle") for t in vehicle_types)
        attrs = result.objects_detected[0]["attributes"]
        assert attrs["color"] == "blue"

    def test_detects_person(self):
        event = make_raw_event(
            description="A person in dark clothing is standing near the gate."
        )
        result = analyze_frame_mock(event)
        types = [o["type"] for o in result.objects_detected]
        assert "person" in types

    def test_loitering_at_midnight_is_high_risk(self):
        event = make_raw_event(
            timestamp="00:01",
            description="A person is loitering near the main gate at midnight.",
        )
        result = analyze_frame_mock(event)
        assert result.risk_level in ("HIGH", "CRITICAL")
        assert result.alert_text is None

    def test_fence_climbing_is_critical(self):
        event = make_raw_event(
            timestamp="02:30",
            location="Perimeter Fence",
            description="Individual climbing over the perimeter fence.",
        )
        result = analyze_frame_mock(event)
        assert result.risk_level == "CRITICAL"
        assert result.alert_text is None

    def test_daytime_routine_is_low_risk(self):
        event = make_raw_event(
            timestamp="14:00",
            description="Three employees eating lunch in the courtyard with lanyards.",
        )
        result = analyze_frame_mock(event)
        assert result.risk_level == "LOW"
        assert result.alert_text is None

    def test_returns_analysis_result_type(self):
        result = analyze_frame_mock(make_raw_event())
        assert isinstance(result, AnalysisResult)

    def test_frame_id_preserved(self):
        event = make_raw_event(frame_id=42)
        result = analyze_frame_mock(event)
        assert result.frame_id == 42


# 4. Alert engine rule tests

class TestAlertEngineRules:
    def _ctx(self):
        return RuleContext(vehicle_appearances={}, high_risk_locations=[])

    def test_fence_intrusion_rule_fires(self):
        result = make_analysis_result(
            timestamp="02:30", location="Perimeter Fence",
            raw_desc="Individual climbing over the perimeter fence.",
        )
        alert = FenceIntrusionRule().evaluate(result, self._ctx())
        assert alert is not None
        assert alert.severity == "CRITICAL"
        assert "INTRUSION" in alert.message

    def test_loitering_rule_fires_at_midnight(self):
        result = make_analysis_result(
            timestamp="00:01",
            objects=[{"type": "person", "count": 1, "attributes": {
                "color": None, "make": None, "model": None,
                "action": "loitering", "has_id_badge": False, "description": "person",
            }}],
            raw_desc="Person loitering near main gate at midnight.",
        )
        alert = LoiteringRule().evaluate(result, self._ctx())
        assert alert is not None
        assert "LOITERING" in alert.message

    def test_night_activity_rule_fires(self):
        result = make_analysis_result(
            timestamp="23:00", event_category="SUSPICIOUS",
            objects=[{"type": "person", "count": 1, "attributes": {
                "color": None, "make": None, "model": None,
                "action": "stationary", "has_id_badge": None, "description": "person",
            }}],
        )
        alert = NightTimeActivityRule().evaluate(result, self._ctx())
        assert alert is not None
        assert alert.severity == "HIGH"

    def test_night_activity_rule_does_not_fire_daytime(self):
        result = make_analysis_result(timestamp="10:00", event_category="ROUTINE")
        alert = NightTimeActivityRule().evaluate(result, self._ctx())
        assert alert is None

    def test_repeat_vehicle_rule_fires_at_threshold(self):
        ctx = self._ctx()
        rule = RepeatVehicleRule()
        # Same vehicle, three times
        for i in range(3):
            result = make_analysis_result(frame_id=i + 1)
            alert = rule.evaluate(result, ctx)
        # Should fire on third appearance
        assert alert is not None
        assert "REPEAT VEHICLE" in alert.message
        assert "3 times" in alert.message

    def test_repeat_vehicle_rule_no_fire_below_threshold(self):
        ctx = self._ctx()
        rule = RepeatVehicleRule()
        for i in range(2):
            result = make_analysis_result(frame_id=i + 1)
            alert = rule.evaluate(result, ctx)
        assert alert is None

    def test_after_hours_access_rule_fires(self):
        result = make_analysis_result(
            timestamp="22:10", location="Loading Dock",
            raw_desc="Individual attempting to access keypad at loading dock.",
        )
        alert = AfterHoursAccessRule().evaluate(result, self._ctx())
        assert alert is not None
        assert "ACCESS ATTEMPT" in alert.message

    def test_unidentified_night_person_rule_fires(self):
        result = make_analysis_result(
            timestamp="23:45",
            objects=[{"type": "person", "count": 1, "attributes": {
                "color": None, "make": None, "model": None,
                "action": "stationary", "has_id_badge": False, "description": "person",
            }}],
        )
        alert = UnidentifiedNightPersonRule().evaluate(result, self._ctx())
        assert alert is not None

    def test_alert_engine_deduplication(self):
        engine = AlertEngine()
        engine.reset()
        # A fence-climbing description at night triggers multiple rules
        result = AnalysisResult(
            frame_id=99,
            timestamp="02:30",
            location="Perimeter Fence",
            objects_detected=[{"type": "person", "count": 1, "attributes": {
                "color": None, "make": None, "model": None,
                "action": "climbing", "has_id_badge": False, "description": "person",
            }}],
            event_category="INTRUSION",
            risk_level="CRITICAL",
            alert_text="CRITICAL: Fence breach.",
            summary="Fence breach.",
            raw_frame_description="Individual climbing over the perimeter fence.",
        )
        alerts = engine.process(result)
        messages = [a.message for a in alerts]
        # No two alerts should have identical messages
        assert len(messages) == len(set(messages))


# 5. Frame indexer (SQLite FTS5) tests

class TestFrameIndexer:
    def test_frame_stored_and_retrieved_by_fts(self):
        db = tmp_db()
        result = make_analysis_result(
            frame_id=1, timestamp="12:00", location="Garage",
            summary="Blue Ford F150 spotted at garage, 12:00.",
            raw_desc="Blue Ford F150 truck parked near garage door.",
        )
        index_frame(result, db)
        rows = query_by_object("F150", db)
        assert len(rows) == 1
        assert rows[0]["frame_id"] == 1

    def test_vehicle_logged_correctly(self):
        """Verify: 'Blue Ford F150 spotted at garage, 12:00' appears in log."""
        db = tmp_db()
        result = make_analysis_result(
            frame_id=1, timestamp="12:00", location="North Garage",
            summary="Blue Ford F150 spotted at garage, 12:00.",
            raw_desc="Blue Ford F150 truck parked near garage.",
        )
        index_frame(result, db)
        rows = query_by_object("garage", db)
        assert any("12:00" in r["sim_timestamp"] for r in rows)

    def test_fts_search_truck_returns_vehicle_frames(self):
        db = tmp_db()
        # Use distinct objects lists so FTS matches are deterministic
        frames_data = [
            (1, "Blue Ford F150 truck at gate", "Main Gate",
             [{"type": "truck", "count": 1, "attributes": {"color": "blue", "make": "Ford",
               "model": "F150", "action": "entering", "has_id_badge": None, "description": "blue F150"}}]),
            (2, "White Ford Transit van at service entrance", "Service Entrance",
             [{"type": "van", "count": 1, "attributes": {"color": "white", "make": "Ford",
               "model": "Transit", "action": "entering", "has_id_badge": None, "description": "white van"}}]),
            (3, "Employee eating lunch in courtyard", "Courtyard", []),
        ]
        for fid, desc, loc, objs in frames_data:
            result = make_analysis_result(
                frame_id=fid, location=loc, summary=desc, raw_desc=desc, objects=objs,
            )
            index_frame(result, db)
        rows = query_by_object("truck", db)
        # FTS5 searches raw_description, summary, objects_detected, location.
        assert len(rows) >= 1
        summaries = [r["summary"].lower() for r in rows]
        # Lunch frame has no "truck" anywhere — must not appear
        assert not any("employee eating lunch" in s for s in summaries)

    def test_time_range_query_returns_correct_frames(self):
        db = tmp_db()
        for i, ts in enumerate(["10:00", "14:30", "23:45"], start=1):
            index_frame(make_analysis_result(frame_id=i, timestamp=ts), db)
        rows = query_by_time_range("22:00", "06:00", db)
        assert len(rows) == 1
        assert rows[0]["sim_timestamp"] == "23:45"

    def test_time_range_daytime(self):
        db = tmp_db()
        for i, ts in enumerate(["08:00", "12:00", "18:00"], start=1):
            index_frame(make_analysis_result(frame_id=i, timestamp=ts), db)
        rows = query_by_time_range("08:00", "18:00", db)
        assert len(rows) == 3

    def test_vehicle_frequency_tracking(self):
        db = tmp_db()
        # Index same F150 three times
        for i in range(1, 4):
            index_frame(make_analysis_result(frame_id=i), db)
        vehicles = get_vehicle_frequency(db)
        assert len(vehicles) >= 1
        assert vehicles[0]["appearances"] == 3

    def test_alert_stored_and_retrieved(self):
        db = tmp_db()
        alert = Alert(
            alert_id="test-001",
            frame_id=1,
            timestamp="00:01",
            location="Main Gate",
            severity="HIGH",
            rule_triggered="LoiteringRule",
            message="Person loitering at main gate, 00:01.",
        )
        index_alert(alert, db)
        alerts = query_alerts_by_severity("HIGH", db)
        assert len(alerts) == 1
        assert alerts[0]["alert_id"] == "test-001"

    def test_alert_triggered_at_midnight(self):
        """Verify: 'Person loitering at main gate, 00:01' is logged as alert."""
        db = tmp_db()
        alert = Alert(
            alert_id="midnight-001",
            frame_id=1,
            timestamp="00:01",
            location="Main Gate",
            severity="HIGH",
            rule_triggered="LoiteringRule",
            message="Person loitering at main gate, 00:01.",
        )
        index_alert(alert, db)
        alerts = query_alerts_by_severity("HIGH", db)
        messages = [a["message"] for a in alerts]
        assert any("loitering" in m.lower() and "00:01" in m for m in messages)

    def test_severity_filter_excludes_lower(self):
        db = tmp_db()
        for sev, rule in [("MEDIUM", "RepeatVehicle"), ("HIGH", "Loitering"), ("CRITICAL", "Intrusion")]:
            index_alert(Alert(
                alert_id=str(uuid.uuid4())[:8],
                frame_id=1, timestamp="12:00", location="Gate",
                severity=sev, rule_triggered=rule, message=f"Test {sev}.",
            ), db)
        high_plus = query_alerts_by_severity("HIGH", db)
        severities = {a["severity"] for a in high_plus}
        assert "MEDIUM" not in severities
        assert "HIGH" in severities
        assert "CRITICAL" in severities


# 6. End-to-end pipeline integration test

class TestPipeline:
    def test_full_pipeline_mock(self):
        """
        Run the entire pipeline on all 14 simulation frames using the mock analyzer.
        Verify: alerts are fired, frames are indexed, vehicle log is populated.
        """
        db = tmp_db()
        frames = get_simulation_frames()
        bus = EventBus()
        alert_engine = AlertEngine()
        alert_engine.reset()
        collected_alerts: List[Alert] = []

        async def on_raw(event: RawFrameEvent):
            result = analyze_frame_mock(event)
            await bus.publish(result)

        async def on_result(result: AnalysisResult):
            index_frame(result, db)
            alerts = alert_engine.process(result)
            for alert in alerts:
                await bus.publish(alert)

        async def on_alert(alert: Alert):
            collected_alerts.append(alert)
            index_alert(alert, db)

        bus.subscribe(RawFrameEvent, on_raw)
        bus.subscribe(AnalysisResult, on_result)
        bus.subscribe(Alert, on_alert)

        async def run():
            for f in frames:
                await bus.publish(RawFrameEvent(
                    frame_id=f.frame_id, timestamp=f.timestamp,
                    location=f.location, altitude_m=f.altitude_m,
                    drone_speed_kmh=f.drone_speed_kmh, battery_pct=f.battery_pct,
                    frame_description=f.frame_description,
                ))

        asyncio.get_event_loop().run_until_complete(run())

        # All 14 frames should be indexed
        from frame_indexer import get_all_frames
        all_frames = get_all_frames(db)
        assert len(all_frames) == 14, f"Expected 14 indexed frames, got {len(all_frames)}"

        # At least one CRITICAL alert (fence climbing at 02:30)
        critical = [a for a in collected_alerts if a.severity == "CRITICAL"]
        assert len(critical) >= 1, "Expected at least one CRITICAL alert"

        # At least one HIGH alert (midnight loitering at 00:01)
        high = [a for a in collected_alerts if a.severity == "HIGH"]
        assert len(high) >= 1, "Expected at least one HIGH alert"

        # F150 should be searchable
        f150_frames = query_by_object("F150", db)
        assert len(f150_frames) >= 1, "F150 should appear in FTS index"

        # Midnight window should return events
        night_frames = query_by_time_range("00:00", "02:59", db)
        assert len(night_frames) >= 2, "Should have frames in midnight window"