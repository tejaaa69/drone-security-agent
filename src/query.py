"""
query.py

Command-line query interface for the drone security frame index.

Usage examples:
  python query.py --object "F150"
  python query.py --object "truck"
  python query.py --time "22:00" "06:00"
  python query.py --alerts HIGH
  python query.py --vehicles
  python query.py --summary

Requires the simulation to have been run first (drone_security.db must exist).
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from frame_indexer import (
    query_by_object,
    query_by_time_range,
    query_alerts_by_severity,
    get_vehicle_frequency,
    get_all_alerts,
    DB_PATH,
)


SEVERITY_ICON = {"CRITICAL": "🚨", "HIGH": "⚠️ ", "MEDIUM": "🔵", "LOW": "  "}


def _check_db():
    if not DB_PATH.exists():
        print("No database found. Run main.py first to generate the frame index.")
        sys.exit(1)


def cmd_object(keyword: str):
    _check_db()
    results = query_by_object(keyword)
    print(f"\n{'─'*60}")
    print(f"  FTS Search: '{keyword}' — {len(results)} frame(s) found")
    print(f"{'─'*60}")
    if not results:
        print("  No results.")
        return
    for r in results:
        icon = SEVERITY_ICON.get(r["risk_level"], "  ")
        print(f"\n  Frame {r['frame_id']:02d} [{r['sim_timestamp']}] {r['location']}")
        print(f"  {icon} Risk: {r['risk_level']}")
        print(f"  Summary: {r['summary']}")
        if r["alert_text"]:
            print(f"  Alert: {r['alert_text']}")


def cmd_time(start: str, end: str):
    _check_db()
    results = query_by_time_range(start, end)
    print(f"\n{'─'*60}")
    print(f"  Time Range: {start} – {end} — {len(results)} frame(s)")
    print(f"{'─'*60}")
    if not results:
        print("  No events in this window.")
        return
    for r in results:
        icon = SEVERITY_ICON.get(r["risk_level"], "  ")
        print(f"\n  [{r['sim_timestamp']}] {r['location']}")
        print(f"  {icon} {r['risk_level']} — {r['summary']}")


def cmd_alerts(severity: str):
    _check_db()
    results = query_alerts_by_severity(severity)
    print(f"\n{'─'*60}")
    print(f"  Alerts ≥ {severity.upper()} — {len(results)} alert(s)")
    print(f"{'─'*60}")
    if not results:
        print("  No alerts at this severity level.")
        return
    for a in results:
        icon = SEVERITY_ICON.get(a["severity"], "  ")
        print(f"\n  {icon} [{a['severity']}] {a['sim_timestamp']} — {a['location']}")
        print(f"  Rule: {a['rule_triggered']}")
        print(f"  {a['message']}")


def cmd_vehicles():
    _check_db()
    results = get_vehicle_frequency()
    print(f"\n{'─'*60}")
    print(f"  Vehicle Frequency Report — {len(results)} unique vehicle(s)")
    print(f"{'─'*60}")
    if not results:
        print("  No vehicles logged.")
        return
    for v in results:
        name = " ".join(filter(None, [
            v["vehicle_color"], v["vehicle_make"], v["vehicle_model"]
        ])).title() or "Unknown Vehicle"
        flag = " ⚑ REPEAT" if v["appearances"] >= 3 else ""
        print(f"\n  {name}{flag}")
        print(f"  Appearances: {v['appearances']}  |  Times: {v['times']}")
        print(f"  Locations: {v['locations']}")


def cmd_summary():
    _check_db()
    alerts = get_all_alerts()
    critical = [a for a in alerts if a["severity"] == "CRITICAL"]
    high = [a for a in alerts if a["severity"] == "HIGH"]
    medium = [a for a in alerts if a["severity"] == "MEDIUM"]

    print(f"\n{'═'*60}")
    print("  DAILY SECURITY SUMMARY")
    print(f"{'═'*60}")
    print(f"\n  Total alerts fired : {len(alerts)}")
    print(f"  🚨 CRITICAL        : {len(critical)}")
    print(f"  ⚠️  HIGH            : {len(high)}")
    print(f"  🔵 MEDIUM          : {len(medium)}")

    if critical or high:
        print(f"\n  Priority Incidents:")
        for a in (critical + high):
            print(f"    [{a['sim_timestamp']}] {a['location']} — {a['message'][:70]}")

    vehicles = get_vehicle_frequency()
    repeats = [v for v in vehicles if v["appearances"] >= 3]
    if repeats:
        print(f"\n  Repeat Vehicles ({len(repeats)}):")
        for v in repeats:
            name = " ".join(filter(None, [
                v["vehicle_color"], v["vehicle_make"], v["vehicle_model"]
            ])).title() or "Unknown"
            print(f"    {name} — seen {v['appearances']}x at {v['times']}")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Drone Security Agent — Query Interface",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python query.py --object "truck"
  python query.py --object "F150"
  python query.py --time 22:00 06:00
  python query.py --alerts HIGH
  python query.py --vehicles
  python query.py --summary
        """,
    )
    parser.add_argument("--object", metavar="KEYWORD", help="Full-text search by object keyword")
    parser.add_argument("--time", nargs=2, metavar=("START", "END"), help="Query by time range HH:MM")
    parser.add_argument("--alerts", metavar="SEVERITY", help="Show alerts (MEDIUM/HIGH/CRITICAL)")
    parser.add_argument("--vehicles", action="store_true", help="Show vehicle frequency report")
    parser.add_argument("--summary", action="store_true", help="Show daily summary")

    args = parser.parse_args()

    if args.object:
        cmd_object(args.object)
    elif args.time:
        cmd_time(args.time[0], args.time[1])
    elif args.alerts:
        cmd_alerts(args.alerts)
    elif args.vehicles:
        cmd_vehicles()
    elif args.summary:
        cmd_summary()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()