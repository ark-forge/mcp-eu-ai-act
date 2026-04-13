#!/usr/bin/env python3
"""Scan → register_free_key funnel analysis.

Reads tool_calls.jsonl + registration_log.jsonl + scan_history.json
to compute conversion rates over a rolling window (default 7 days).

Usage:
    python3 scripts/funnel_analysis.py [--days 7] [--data-dir data/]
"""
import json
import argparse
from datetime import datetime, timezone, timedelta
from pathlib import Path
from collections import defaultdict


def load_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    entries = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if line:
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return entries


def analyze_funnel(data_dir: Path, days: int) -> dict:
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()

    # Load tool calls
    tool_calls = load_jsonl(data_dir / "tool_calls.jsonl")
    registrations = load_jsonl(data_dir / "registration_log.jsonl")

    # Filter to window
    recent_calls = [c for c in tool_calls if c.get("ts", "") >= cutoff]
    recent_regs = [r for r in registrations if r.get("ts", "") >= cutoff]

    # Scans = tool calls where cta_included is True (scan tools that showed CTA)
    scans_with_cta = [c for c in recent_calls if c.get("cta_included")]
    conversions = [c for c in recent_calls if c.get("conversion")]

    # Session-level funnel: unique sessions that scanned vs registered
    scan_sessions = {c.get("session_id") or "unknown" for c in scans_with_cta if c.get("session_id")}
    reg_sessions = set()
    for r in recent_regs:
        sid = r.get("scan_id") or r.get("session_id")
        if sid:
            reg_sessions.add(sid)

    # Tool breakdown
    tool_counts = defaultdict(int)
    for c in recent_calls:
        tool_counts[c.get("tool", "unknown")] += 1

    # Daily breakdown
    daily = defaultdict(lambda: {"scans": 0, "registrations": 0})
    for c in scans_with_cta:
        day = c.get("ts", "")[:10]
        if day:
            daily[day]["scans"] += 1
    for r in recent_regs:
        day = r.get("ts", "")[:10]
        if day:
            daily[day]["registrations"] += 1

    total_scans = len(scans_with_cta)
    total_regs = len(recent_regs)
    session_conversion = (
        len(scan_sessions & reg_sessions) / len(scan_sessions) * 100
        if scan_sessions else 0
    )

    return {
        "window_days": days,
        "cutoff": cutoff,
        "total_tool_calls": len(recent_calls),
        "scans_with_cta": total_scans,
        "registrations": total_regs,
        "conversion_rate_pct": round(total_regs / total_scans * 100, 1) if total_scans else 0,
        "unique_scan_sessions": len(scan_sessions),
        "unique_reg_sessions": len(reg_sessions),
        "session_conversion_pct": round(session_conversion, 1),
        "tool_breakdown": dict(tool_counts),
        "daily": {k: dict(v) for k, v in sorted(daily.items())},
    }


def main():
    parser = argparse.ArgumentParser(description="MCP EU AI Act funnel analysis")
    parser.add_argument("--days", type=int, default=7, help="Rolling window in days")
    parser.add_argument("--data-dir", type=str, default="data/", help="Path to data directory")
    args = parser.parse_args()

    data_dir = Path(args.data_dir)
    result = analyze_funnel(data_dir, args.days)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
