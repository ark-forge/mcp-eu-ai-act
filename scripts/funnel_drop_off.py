#!/usr/bin/env python3
"""Drop-off report by standardized funnel step.

Reads tool_calls.jsonl and reports counts + drop-off rates across the
5 funnel steps instrumented by task 1570:

    mcp_scan_completed          → CTA viewed → CTA clicked → activation
    cta_register_free_key_viewed
    cta_register_free_key_clicked
    free_key_activation
    pricing_page_viewed

Usage:
    python3 scripts/funnel_drop_off.py [--days 7] [--data-dir data/] [--source external_ok]

`--source` filters by IP classification from _classify_ip (external_ok,
internal, bot, ...). Default: all.
"""
import argparse
import json
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path


STEPS = [
    "mcp_scan_completed",
    "cta_register_free_key_viewed",
    "cta_register_free_key_clicked",
    "free_key_activation",
    "pricing_page_viewed",
]


def load_jsonl(path: Path) -> list:
    if not path.exists():
        return []
    out = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def compute(data_dir: Path, days: int, source_filter: str | None) -> dict:
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    calls = load_jsonl(data_dir / "tool_calls.jsonl")
    recent = [c for c in calls if c.get("ts", "") >= cutoff]
    if source_filter:
        recent = [c for c in recent if c.get("source") == source_filter]

    step_counts = Counter()
    per_step_tools = defaultdict(Counter)
    daily = defaultdict(lambda: Counter())
    for c in recent:
        step = c.get("funnel_step")
        if not step:
            continue
        step_counts[step] += 1
        per_step_tools[step][c.get("tool", "unknown")] += 1
        day = c.get("ts", "")[:10]
        if day:
            daily[day][step] += 1

    # Drop-off between ordered steps (excluding pricing_page_viewed, side-channel)
    drop_off = []
    order = [s for s in STEPS if s != "pricing_page_viewed"]
    for i in range(len(order) - 1):
        a, b = order[i], order[i + 1]
        na, nb = step_counts.get(a, 0), step_counts.get(b, 0)
        rate = round(nb / na * 100, 1) if na else 0.0
        drop_off.append({
            "from": a,
            "to": b,
            "from_count": na,
            "to_count": nb,
            "conversion_pct": rate,
            "drop_off_pct": round(100 - rate, 1) if na else None,
        })

    return {
        "window_days": days,
        "cutoff": cutoff,
        "source_filter": source_filter,
        "step_counts": {s: step_counts.get(s, 0) for s in STEPS},
        "per_step_tools": {s: dict(per_step_tools[s]) for s in STEPS if s in per_step_tools},
        "drop_off": drop_off,
        "daily": {d: dict(v) for d, v in sorted(daily.items())},
    }


def main():
    parser = argparse.ArgumentParser(description="Funnel drop-off report (task 1570)")
    parser.add_argument("--days", type=int, default=7)
    parser.add_argument("--data-dir", type=str,
                        default=str(Path(__file__).parent.parent / "data"))
    parser.add_argument("--source", type=str, default=None,
                        help="Filter by IP classification (e.g. external_ok)")
    args = parser.parse_args()
    result = compute(Path(args.data_dir), args.days, args.source)
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
