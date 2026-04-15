#!/usr/bin/env python3
"""
Monitor register_free_key conversions for task 1483 fix.
Exit criterion: N >= 5 register_free_key conversions in 48 hours post-deploy.
"""

import json
import sys
from pathlib import Path
from datetime import datetime, timezone, timedelta

def get_register_conversions(hours=48):
    """Count register_free_key successful conversions (conversion=True) in last N hours."""
    log_path = Path(__file__).parent.parent / "data" / "tool_calls.jsonl"

    if not log_path.exists():
        print(f"❌ Log file not found: {log_path}")
        return 0, []

    cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours)
    conversions = []

    try:
        with open(log_path) as f:
            for line in f:
                entry = json.loads(line.strip())
                if entry.get("tool") != "register_free_key":
                    continue

                ts_str = entry.get("ts", "")
                try:
                    ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                except:
                    continue

                if ts < cutoff_time:
                    continue

                if entry.get("conversion") is True:
                    conversions.append({
                        "ts": ts_str,
                        "source": entry.get("source", "unknown"),
                        "ip": entry.get("ip", "unknown"),
                        "plan": entry.get("plan", "unknown"),
                    })
    except Exception as e:
        print(f"❌ Error reading log file: {e}")
        return 0, []

    return len(conversions), conversions

def main():
    count_48h, entries_48h = get_register_conversions(hours=48)
    count_24h, entries_24h = get_register_conversions(hours=24)
    count_1h, entries_1h = get_register_conversions(hours=1)

    print(f"\n=== Register Free Key Conversion Monitoring ===")
    print(f"Exit Criterion: N >= 5 conversions in 48 hours")
    print(f"\n[48h] Conversions: {count_48h}/5 ✅" if count_48h >= 5 else f"\n[48h] Conversions: {count_48h}/5 ⏳")
    print(f"[24h] Conversions: {count_24h}")
    print(f"[1h]  Conversions: {count_1h}")

    if count_48h > 0:
        print(f"\nRecent conversions (48h):")
        for i, entry in enumerate(entries_48h[-5:], 1):
            print(f"  {i}. {entry['ts'][:19]} | {entry['source']} | {entry['plan']}")

    print(f"\nExit Criterion Status: {'✅ PASS' if count_48h >= 5 else '⏳ IN PROGRESS'}")
    return 0 if count_48h >= 5 else 1

if __name__ == "__main__":
    sys.exit(main())
