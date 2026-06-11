# drone-security-agent


An AI-powered drone security monitoring prototype that processes simulated telemetry and video frames, indexes events frame-by-frame, and generates real-time security alerts using the Claude API.

---

## What It Does

A docked drone monitors a fixed property continuously. This agent:

1. **Ingests** simulated drone telemetry (GPS, altitude, battery) and video frame descriptions
2. **Analyzes** each frame using Claude (claude-sonnet-4-20250514) to extract objects, assess risk, and recommend alerts
3. **Indexes** every frame into a SQLite FTS5 database — queryable by object keyword, time range, or severity
4. **Fires alerts** through a rule-based engine (loitering, intrusion, repeat vehicles, after-hours access)
5. **Reports** a daily AI-generated intelligence briefing summarizing the day's events

---

## Architecture

```
Simulator
   ↓  RawFrameEvent (pub)
EventBus
   ├─ Analyzer (Claude API → AnalysisResult pub)
   │     EventBus
   │     ├─ FrameIndexer  (SQLite FTS5 write)
   │     ├─ AlertEngine   (7 rules → Alert pub)
   │     │     EventBus
   │     │     └─ AlertIndexer + Logger
   │     └─ EventLogger
   └─ Reporter (daily briefing via Claude)
```

All components communicate exclusively through the `EventBus` — no direct imports between modules.

---

## File Structure

```
drone-security-agent/
├── src/
│   ├── simulator.py       # 14-frame 24-hour security scenario
│   ├── event_bus.py       # Typed async pub/sub bus + event dataclasses
│   ├── analyzer.py        # Claude API integration (+ mock for testing)
│   ├── alert_engine.py    # 7 rule-based alert rules
│   ├── frame_indexer.py   # SQLite FTS5 indexing + query functions
│   ├── reporter.py        # AI daily intelligence report generator
│   ├── main.py            # Pipeline orchestrator
│   └── query.py           # CLI query interface
├── tests/
│   └── test_agent.py      # 37 pytest tests (no API calls)
├── sample_output/
│   ├── event_log.txt      # Per-frame event log
│   ├── alert_log.txt      # All fired alerts with rules
│   ├── daily_report.txt   # AI intelligence briefing
│   └── drone_security.db  # SQLite FTS5 database
├── requirements.txt
└── README.md
```

---

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run simulation (no API key needed)
python src/main.py --mock

# Run with Claude API (live AI analysis + AI daily report)
export ANTHROPIC_API_KEY=sk-ant-...
python src/main.py --live

# Run all 37 tests
python -m pytest tests/ -v
```

---

## Query Interface

After running the simulation, query the indexed frame database:

```bash
# Full-text search by object
python src/query.py --object "F150"
python src/query.py --object "truck"
python src/query.py --object "perimeter"

# Time range (handles midnight wraparound)
python src/query.py --time 22:00 06:00
python src/query.py --time 08:00 18:00

# Alerts by severity
python src/query.py --alerts HIGH
python src/query.py --alerts CRITICAL

# Vehicle frequency report (flags repeats)
python src/query.py --vehicles

# Daily summary
python src/query.py --summary
```

---

## Sample Output

**Event Log:**
```
[00:01] [HIGH    ] Main Gate — Person loitering at main gate at midnight.
[02:30] [CRITICAL] Perimeter Fence - NE Corner — Person observed at perimeter.
[12:00] [LOW     ] North Garage — Blue Ford F150 spotted at garage, 12:00.
```

**Alert Log:**
```
[00:01] [CRITICAL] Main Gate | LoiteringRule
  → [LOITERING] Person loitering at Main Gate, 00:01. Review footage immediately.

[02:30] [CRITICAL] Perimeter Fence - NE Corner | FenceIntrusionRule
  → [INTRUSION CRITICAL] Perimeter fence breach at NE Corner, 02:30. Dispatch security immediately.

[12:00] [MEDIUM  ] North Garage | RepeatVehicleRule
  → [REPEAT VEHICLE] 'Blue Ford F150' has been observed 3 times today.
```

---

## AI Component — The Analyzer

`analyzer.py` uses **Claude (claude-sonnet-4-20250514)** to perform object detection and risk assessment from natural-language frame descriptions. This satisfies the assignment requirement "Use AI to generate at least one component."

Claude extracts structured JSON containing:
- Detected objects with color, make, model, action attributes
- Event category (ROUTINE / SUSPICIOUS / INTRUSION / EMERGENCY)
- Risk level (LOW / MEDIUM / HIGH / CRITICAL)
- Alert text when warranted
- One-sentence summary for the security log

A `analyze_frame_mock()` function provides identical structure for offline testing without API calls.

---

## Cross-Domain: SQLite FTS5 Indexing

`frame_indexer.py` uses SQLite's **FTS5 (Full-Text Search 5)** extension for frame indexing:

- **Content table**: FTS5 index mirrors the `frames` table via triggers (no data duplication)
- **Indexed columns**: `raw_description`, `summary`, `objects_detected`, `location`
- **Composite indexes**: `(sim_timestamp, location)` for time-range queries
- **Vehicle log**: denormalized table for cross-frame frequency tracking
- **Query**: `SELECT ... FROM frames JOIN frames_fts ON fts.rowid = frames.id WHERE frames_fts MATCH 'truck'`

This enables queries like "show all truck events" or "what happened between 22:00 and 06:00" over the full day's footage.

---

## Alert Rules

| Rule | Trigger | Severity |
|---|---|---|
| `FenceIntrusionRule` | Climbing / breach language in description | CRITICAL |
| `LoiteringRule` | Person stationary / loitering | HIGH–CRITICAL |
| `NightTimeActivityRule` | Any activity 22:00–06:00 | HIGH |
| `AfterHoursAccessRule` | Keypad / door access outside 08:00–19:00 | HIGH |
| `UnidentifiedNightPersonRule` | Person without ID badge at night | HIGH |
| `RepeatVehicleRule` | Same vehicle seen ≥3 times in session | MEDIUM |

---

## Design Decisions

**Why SQLite FTS5 over a separate search engine?**
Zero dependencies, ships with Python's stdlib `sqlite3`, FTS5 provides real full-text ranking, and the entire day's index fits in a single portable `.db` file. Easily replaceable with Elasticsearch or pgvector for production.

**Why an event bus?**
Decouples all five components completely. Adding a new subscriber (e.g. a real-time dashboard WebSocket) is one `bus.subscribe()` call with no changes to other components.

**Why Claude for analysis?**
Frame descriptions are natural language. "Blue pickup near garage" and "blue F150 truck" and "Ford pickup stationary at north lot" all describe the same vehicle. Claude normalises this where regex cannot. Risk assessment also requires holistic context (time + location + behavior + description) that a rule engine cannot handle alone.

**Why mock + live modes?**
Tests run in milliseconds with no API cost. Live mode enables real Claude analysis when a key is available. Same `AnalysisResult` dataclass is returned by both — the pipeline doesn't know which mode it's running in.

---

## Test Coverage

```
37 tests across 6 test classes:
  TestSimulator         (7 tests)  — frame generation, scenario integrity
  TestEventBus          (3 tests)  — pub/sub wiring, event isolation
  TestMockAnalyzer      (7 tests)  — object detection, risk scoring
  TestAlertEngineRules  (10 tests) — each rule fires correctly, deduplication
  TestFrameIndexer      (8 tests)  — SQLite writes, FTS5 search, time queries
  TestPipeline          (1 test)   — end-to-end integration, all 14 frames
```

Run: `python -m pytest tests/ -v`

