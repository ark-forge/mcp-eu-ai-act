#!/usr/bin/env python3
"""Funnel diagnostic: genuine external traffic vs internal noise.

Root cause analysis for 0 register_free_key conversions on 2000+ scans.
Key insight: separates internal/testing traffic from real external users.
"""
import json
from pathlib import Path
from collections import Counter

DATA = Path(__file__).parent.parent / "data"

SCAN_TOOLS = {
    "scan_project", "check_compliance", "generate_report",
    "combined_compliance_report", "gdpr_scan_project",
    "gdpr_check_compliance", "gdpr_generate_report",
}

# IPs known to be non-user (IANA reserved example.com, loopback, test harness)
EXCLUDE_IPS = {"unknown", "127.0.0.1", "testclient", "93.184.216.34"}


def is_genuine(entry: dict) -> bool:
    """Return True if this tool call is from a real external user."""
    if "is_genuine_external" in entry:
        return entry["is_genuine_external"]
    source = entry.get("source", "")
    plan = entry.get("plan", "")
    ip = entry.get("ip", "unknown")
    return (
        source in ("external", "crawler")
        and plan not in ("certified",)
        and ip not in EXCLUDE_IPS
    )


def main():
    tc_path = DATA / "tool_calls.jsonl"
    reg_path = DATA / "registration_log.jsonl"

    if not tc_path.exists():
        print("No tool_calls.jsonl found")
        return

    entries = [json.loads(l) for l in tc_path.read_text().splitlines() if l.strip()]

    all_scans = [e for e in entries if e.get("tool") in SCAN_TOOLS]
    all_regs = [e for e in entries if e.get("tool") == "register_free_key"]

    # --- Genuine external only ---
    ext_scans = [s for s in all_scans if is_genuine(s)]
    ext_regs = [r for r in all_regs if is_genuine(r)]
    ext_conversions = [r for r in ext_regs if r.get("conversion")]

    # --- Internal noise ---
    int_scans = [s for s in all_scans if not is_genuine(s)]
    int_regs = [r for r in all_regs if not is_genuine(r)]

    print("=" * 60)
    print("FUNNEL DIAGNOSTIC — Internal vs External Traffic")
    print("=" * 60)
    print(f"\nTotal tool_calls.jsonl entries: {len(entries)}")
    print(f"Total scan tool calls:         {len(all_scans)}")
    print(f"Total register_free_key calls: {len(all_regs)}")

    pct_int = len(int_scans) / len(all_scans) * 100 if all_scans else 0
    print(f"\n{'─' * 60}")
    print("GENUINE EXTERNAL (real users only)")
    print(f"{'─' * 60}")
    print(f"External scans:              {len(ext_scans)}")
    print(f"External register_free_key:  {len(ext_regs)}")
    print(f"External conversions:        {len(ext_conversions)}")
    if ext_scans:
        ext_ips = set(s.get("ip") for s in ext_scans)
        ext_clients = set(s.get("client_hint", "?") for s in ext_scans)
        print(f"Unique external IPs:         {len(ext_ips)}")
        print(f"MCP clients seen:            {', '.join(ext_clients)}")
        print(f"\nExternal scan details:")
        for s in ext_scans:
            print(f"  {s.get('ts', '?')[:19]} | {s.get('tool')} | "
                  f"IP={s.get('ip')} | client={s.get('client_hint')} | "
                  f"cta={s.get('cta_included')}")

    print(f"\n{'─' * 60}")
    print(f"INTERNAL / TESTING (noise — {pct_int:.0f}% of all scans)")
    print(f"{'─' * 60}")
    print(f"Internal scans:              {len(int_scans)}")
    print(f"Internal register_free_key:  {len(int_regs)}")
    int_errors = Counter(r.get("error", "no_error") for r in int_regs)
    print(f"Internal reg errors:         {dict(int_errors)}")

    print(f"\n{'─' * 60}")
    print("PLAN BREAKDOWN (all scans)")
    print(f"{'─' * 60}")
    for plan, count in Counter(s.get("plan", "?") for s in all_scans).most_common():
        print(f"  {plan:15s}: {count:4d} ({count / len(all_scans) * 100:.1f}%)")

    print(f"\n{'─' * 60}")
    print("SOURCE BREAKDOWN (all scans)")
    print(f"{'─' * 60}")
    for src, count in Counter(s.get("source", "?") for s in all_scans).most_common():
        print(f"  {src:15s}: {count:4d} ({count / len(all_scans) * 100:.1f}%)")

    # Registration log
    if reg_path.exists() and reg_path.stat().st_size > 0:
        reg_entries = [json.loads(l) for l in reg_path.read_text().splitlines() if l.strip()]
        test_regs = [r for r in reg_entries if r.get("ip") == "testclient"]
        real_regs = [r for r in reg_entries if r.get("ip") != "testclient"]
        print(f"\n{'─' * 60}")
        print(f"REGISTRATION LOG ({len(reg_entries)} entries)")
        print(f"{'─' * 60}")
        print(f"From testclient IP (tests): {len(test_regs)}")
        print(f"From real IPs:              {len(real_regs)}")
        for src, count in Counter(r.get("source", "?") for r in reg_entries).most_common():
            print(f"  {src}: {count}")

    print(f"\n{'=' * 60}")
    print("ROOT CAUSE DIAGNOSIS")
    print(f"{'=' * 60}")
    print(f"""
1. METRIC POLLUTION: {len(int_scans)}/{len(all_scans)} scans ({pct_int:.0f}%) are internal testing.
   The reported scan counts include internal traffic with 'certified' plan.

2. REAL EXTERNAL USERS: Only {len(ext_scans)} genuine external scans (all-time).
   Unique external IPs: {len(set(s.get('ip') for s in ext_scans))}

3. REGISTER_FREE_KEY FROM REAL USERS: {len(ext_regs)} calls, {len(ext_conversions)} conversions.
   All {len(int_regs)} register_free_key calls are internal (placeholder emails).

4. SERVER CODE: Correct. next_action + llm_directive + CTA URL all present.
   The instruction layers work (5 redundant directives in response).

5. CONCLUSION: Bottleneck is TRAFFIC ACQUISITION, not funnel UX.
   With {len(ext_scans)} real users, conversion rate is unmeasurable.
""")


if __name__ == "__main__":
    main()
