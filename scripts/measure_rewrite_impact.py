#!/usr/bin/env python3
"""
Measure tool description rewrite impact (commit 958dbcdee, 2026-04-20T12:25:25Z).

Run after 7 days (2026-04-27) to compare pre/post external scan conversions.
Classification: keepalive vs one-time vs real prospect based on tool usage patterns.
"""

import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

TOOL_CALLS = Path(__file__).resolve().parent.parent / "data" / "tool_calls.jsonl"
REWRITE_TS = "2026-04-20T12:25:25"
INTERNAL_IPS = {"127.0.0.1", "2001:41d0:2005:100::6fd", "93.184.216.34", "192.168.1.1"}
PROTOCOL_TOOLS = {"__connection_initialize", "__connection_tools_list"}
SCAN_TOOLS = {
    "scan_project", "check_compliance", "generate_report",
    "combined_compliance_report", "gdpr_scan_project",
    "gdpr_check_compliance", "gdpr_generate_report",
}


def classify_client(events: list[dict]) -> str:
    tools_used = {e["tool"] for e in events}
    ips = {e.get("ip", "") for e in events}
    if ips <= INTERNAL_IPS or ips <= (INTERNAL_IPS | {"", "unknown"}):
        return "internal"
    non_protocol = tools_used - PROTOCOL_TOOLS
    if not non_protocol:
        if len(events) > 5:
            return "keepalive"
        return "one_time_discovery"
    # Mixed IP client (pre client_id era) — check if majority internal
    internal_ratio = sum(1 for e in events if e.get("ip", "") in INTERNAL_IPS | {"", "unknown"}) / len(events)
    if internal_ratio > 0.5:
        return "mixed_mostly_internal"
    if non_protocol & SCAN_TOOLS:
        return "converted_user"
    return "real_prospect"


def main():
    events = []
    with open(TOOL_CALLS) as f:
        for line in f:
            if line.strip():
                events.append(json.loads(line))

    pre = [e for e in events if e.get("ts", "") < REWRITE_TS]
    post = [e for e in events if e.get("ts", "") >= REWRITE_TS]

    for label, subset in [("PRE-REWRITE", pre), ("POST-REWRITE", post)]:
        by_client = defaultdict(list)
        for e in subset:
            by_client[e.get("client_id", "unknown")].append(e)

        classifications = {}
        for cid, evts in by_client.items():
            classifications[cid] = classify_client(evts)

        converted = {c: e for c, e in by_client.items() if classifications[c] == "converted_user"}
        real = {c: e for c, e in by_client.items() if classifications[c] in ("real_prospect", "converted_user")}
        scan_count = sum(1 for c, evts in real.items()
                        for e in evts if e["tool"] in SCAN_TOOLS)

        print(f"\n{'='*50}")
        print(f" {label} ({len(subset)} events)")
        print(f"{'='*50}")
        print(f"  Clients: {len(by_client)}")
        class_counts = Counter(classifications.values())
        for cls, cnt in sorted(class_counts.items()):
            print(f"    {cls}: {cnt}")
        print(f"  Scan calls from external users: {scan_count}")
        print(f"  Converted users (ran a scan): {len(converted)}")
        print(f"  Real prospect clients (any non-protocol tool): {len(real)}")
        if real:
            for cid in sorted(real):
                tools = Counter(e["tool"] for e in by_client[cid])
                cls = classifications[cid]
                print(f"    [{cls}] {cid}: {dict(tools)}")


if __name__ == "__main__":
    main()
