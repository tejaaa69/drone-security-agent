"""
frame_indexer.py

Cross-domain component: frame-by-frame indexing using SQLite with FTS5
(Full-Text Search extension).

Why SQLite FTS5?
  - Zero external dependencies (ships with Python's stdlib sqlite3)
  - FTS5 provides full-text search over frame descriptions: "show all truck events"
  - Composite indexes on (timestamp, location) for time-range queries
  - JSON column stores structured AI-extracted objects for attribute filtering
  - Portable single-file database — the entire day's footage index fits in one .db

Schema design:
  frames        — one row per video frame, rich metadata + AI analysis
  frames_fts    — FTS5 virtual table mirroring frames for text search
  alerts        — all alerts with foreign key to frames
  vehicle_log   — denormalized vehicle appearances for frequency tracking
"""

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any

from event_bus import AnalysisResult, Alert


DB_PATH = Path(__file__).parent.parent / "sample_output" / "drone_security.db"

def _get_conn(db_path: Path = DB_PATH) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    # Enable WAL mode for concurrent reads during simulation
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db(db_path: Path = DB_PATH) -> None:
    """Create all tables and indexes. Safe to call multiple times (IF NOT EXISTS)."""
    conn = _get_conn(db_path)
    with conn:
        # Main frames table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS frames (
                id               INTEGER PRIMARY KEY,
                frame_id         INTEGER NOT NULL,
                sim_timestamp    TEXT NOT NULL,
                wall_clock       TEXT NOT NULL,
                location         TEXT NOT NULL,
                altitude_m       REAL,
                objects_detected TEXT,          -- JSON array
                event_category   TEXT,
                risk_level       TEXT,
                alert_triggered  INTEGER DEFAULT 0,
                alert_text       TEXT,
                summary          TEXT,
                raw_description  TEXT NOT NULL
            )
        """)

        # FTS5 virtual table for full-text search over descriptions + summaries
        # content= makes it a content table (no data duplication)
        conn.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS frames_fts
            USING fts5(
                raw_description,
                summary,
                objects_detected,
                location,
                content=frames,
                content_rowid=id
            )
        """)

        # Triggers to keep FTS index in sync with frames table
        conn.execute("""
            CREATE TRIGGER IF NOT EXISTS frames_ai AFTER INSERT ON frames BEGIN
                INSERT INTO frames_fts(rowid, raw_description, summary, objects_detected, location)
                VALUES (new.id, new.raw_description, new.summary, new.objects_detected, new.location);
            END
        """)
        conn.execute("""
            CREATE TRIGGER IF NOT EXISTS frames_ad AFTER DELETE ON frames BEGIN
                INSERT INTO frames_fts(frames_fts, rowid, raw_description, summary, objects_detected, location)
                VALUES ('delete', old.id, old.raw_description, old.summary, old.objects_detected, old.location);
            END
        """)

        # Alerts table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id      TEXT NOT NULL,
                frame_id      INTEGER NOT NULL,
                sim_timestamp TEXT NOT NULL,
                wall_clock    TEXT NOT NULL,
                location      TEXT NOT NULL,
                severity      TEXT NOT NULL,
                rule_triggered TEXT NOT NULL,
                message       TEXT NOT NULL
            )
        """)

        # Vehicle log for frequency tracking (cross-frame vehicle identity)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS vehicle_log (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                frame_id      INTEGER NOT NULL,
                sim_timestamp TEXT NOT NULL,
                location      TEXT NOT NULL,
                vehicle_type  TEXT,
                vehicle_color TEXT,
                vehicle_make  TEXT,
                vehicle_model TEXT,
                action        TEXT    -- 'entering', 'exiting', 'parked', 'stationary'
            )
        """)

        # Composite index for time-range queries
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_frames_time_loc
            ON frames(sim_timestamp, location)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_frames_risk
            ON frames(risk_level)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_vehicle_log_type_color
            ON vehicle_log(vehicle_type, vehicle_color)
        """)

    conn.close()


def index_frame(result: AnalysisResult, db_path: Path = DB_PATH) -> None:
    """Insert an AI analysis result into the frame index."""
    conn = _get_conn(db_path)
    with conn:
        conn.execute("""
            INSERT INTO frames
                (frame_id, sim_timestamp, wall_clock, location, altitude_m,
                 objects_detected, event_category, risk_level,
                 alert_triggered, alert_text, summary, raw_description)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            result.frame_id,
            result.timestamp,
            datetime.now().isoformat(),
            result.location,
            None,  # altitude stored in simulator, not in AnalysisResult
            json.dumps(result.objects_detected),
            result.event_category,
            result.risk_level,
            1 if result.alert_text else 0,
            result.alert_text,
            result.summary,
            result.raw_frame_description,
        ))

        # Log any vehicles for frequency tracking
        for obj in result.objects_detected:
            if obj.get("type") in ("vehicle", "truck", "car", "van"):
                attrs = obj.get("attributes", {})
                conn.execute("""
                    INSERT INTO vehicle_log
                        (frame_id, sim_timestamp, location, vehicle_type,
                         vehicle_color, vehicle_make, vehicle_model, action)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    result.frame_id,
                    result.timestamp,
                    result.location,
                    obj.get("type"),
                    attrs.get("color"),
                    attrs.get("make"),
                    attrs.get("model"),
                    attrs.get("action"),
                ))
    conn.close()


def index_alert(alert: Alert, db_path: Path = DB_PATH) -> None:
    """Persist a triggered alert."""
    conn = _get_conn(db_path)
    with conn:
        conn.execute("""
            INSERT INTO alerts
                (alert_id, frame_id, sim_timestamp, wall_clock,
                 location, severity, rule_triggered, message)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            alert.alert_id,
            alert.frame_id,
            alert.timestamp,
            alert.wall_clock.isoformat(),
            alert.location,
            alert.severity,
            alert.rule_triggered,
            alert.message,
        ))
    conn.close()


# Query interface — called by query.py and the daily reporter

def query_by_object(keyword: str, db_path: Path = DB_PATH) -> List[Dict]:
    """
    Full-text search over frame descriptions and summaries.
    Example: query_by_object("truck") returns all frames mentioning trucks.
    """
    conn = _get_conn(db_path)
    rows = conn.execute("""
        SELECT f.frame_id, f.sim_timestamp, f.location,
               f.risk_level, f.summary, f.alert_text
        FROM frames f
        JOIN frames_fts fts ON fts.rowid = f.id
        WHERE frames_fts MATCH ?
        ORDER BY f.sim_timestamp
    """, (keyword,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def query_by_time_range(start: str, end: str, db_path: Path = DB_PATH) -> List[Dict]:
    """
    Return all frames within a HH:MM time window.
    Handles midnight wraparound (e.g. 22:00–02:00).
    """
    conn = _get_conn(db_path)
    if start <= end:
        rows = conn.execute("""
            SELECT frame_id, sim_timestamp, location, risk_level, summary, alert_text
            FROM frames
            WHERE sim_timestamp BETWEEN ? AND ?
            ORDER BY sim_timestamp
        """, (start, end)).fetchall()
    else:
        # Midnight wraparound
        rows = conn.execute("""
            SELECT frame_id, sim_timestamp, location, risk_level, summary, alert_text
            FROM frames
            WHERE sim_timestamp >= ? OR sim_timestamp <= ?
            ORDER BY sim_timestamp
        """, (start, end)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def query_alerts_by_severity(severity: str, db_path: Path = DB_PATH) -> List[Dict]:
    """Return all alerts at or above a given severity."""
    order = {"MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    min_rank = order.get(severity.upper(), 1)
    conn = _get_conn(db_path)
    rows = conn.execute("""
        SELECT alert_id, frame_id, sim_timestamp, location,
               severity, rule_triggered, message
        FROM alerts
        ORDER BY sim_timestamp
    """).fetchall()
    conn.close()
    return [dict(r) for r in rows if order.get(r["severity"], 0) >= min_rank]


def get_vehicle_frequency(db_path: Path = DB_PATH) -> List[Dict]:
    """
    Return vehicles grouped by color+make+model with appearance counts.
    Used by the repeat-vehicle alert rule.
    """
    conn = _get_conn(db_path)
    rows = conn.execute("""
        SELECT vehicle_color, vehicle_make, vehicle_model,
               COUNT(*) as appearances,
               GROUP_CONCAT(sim_timestamp, ', ') as times,
               GROUP_CONCAT(location, ' → ') as locations
        FROM vehicle_log
        WHERE vehicle_color IS NOT NULL
        GROUP BY vehicle_color, vehicle_make, vehicle_model
        ORDER BY appearances DESC
    """).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_all_frames(db_path: Path = DB_PATH) -> List[Dict]:
    conn = _get_conn(db_path)
    rows = conn.execute(
        "SELECT * FROM frames ORDER BY sim_timestamp"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_all_alerts(db_path: Path = DB_PATH) -> List[Dict]:
    conn = _get_conn(db_path)
    rows = conn.execute(
        "SELECT * FROM alerts ORDER BY sim_timestamp"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]