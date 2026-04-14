#!/usr/bin/env python3
"""Funnel diagnostic: scan → CTA shown → register_free_key → conversion."""
import json
from pathlib import Path
from collections import Counter

DATA = Path(__file__).parent.parent / "data"

def main():
    tc_path = DATA / "tool_calls.jsonl"
    reg_path = DATA / "registration_log.jsonl"

    if not tc_path.exists():
        print("No tool_calls.jsonl found")
        return

    entries = [json.loads(l) for l in tc_path.read_text().splitlines() if l.strip()]

    scans = [e for e in entries if e.get("tool") not in
             ("register_free_key", "get_pricing", "validate_api_key")]
    regs = [e for e in entries if e.get("tool") == "register_free_key"]

    ext_scans = [s for s in scans if s.get("source") == "external"]
    cta_shown = [s for s in scans if s.get("cta_included")]
    ext_cta = [s for s in cta_shown if s.get("source") == "external"]

    conversions = [r for r in regs if r.get("conversion")]
    errors = [r for r in regs if r.get("error")]

    print("=== FUNNEL DIAGNOSTIC ===")
    print(f"Total scan calls:          {len(scans)}")
    print(f"  External only:           {len(ext_scans)}")
    print(f"CTA shown (free tier):     {len(cta_shown)}")
    print(f"  External CTA:            {len(ext_cta)}")
    print(f"register_free_key calls:   {len(regs)}")
    print(f"  Successful conversions:  {len(conversions)}")
    print(f"  Errors:                  {len(errors)}")
    print()

    if errors:
        print("=== REGISTRATION ERRORS ===")
        for e in errors:
            print(f"  {e.get('ts','?')[:19]} | err={e.get('error')} "
                  f"| hash={e.get('email_hash','?')} | len={e.get('email_len','?')} "
                  f"| placeholder={e.get('is_placeholder','?')} "
                  f"| raw={e.get('raw_preview','?')} | sanitized={e.get('sanitized','?')}")
    print()

    if cta_shown:
        print("=== CTA BY SOURCE ===")
        for src, cnt in Counter(s.get("source", "?") for s in cta_shown).most_common():
            print(f"  {src}: {cnt}")

    print()
    print("=== CTA BY CLIENT ===")
    for client, cnt in Counter(s.get("client_hint", "?") for s in cta_shown).most_common():
        print(f"  {client}: {cnt}")

    print()
    drop_scan_to_cta = len(ext_scans) - len(ext_cta)
    drop_cta_to_reg = len(ext_cta) - len([r for r in regs if r.get("source") == "external"])
    print("=== DROP ANALYSIS (external only) ===")
    print(f"  Scan → CTA shown:       {len(ext_scans)} → {len(ext_cta)} (drop {drop_scan_to_cta})")
    print(f"  CTA shown → reg attempt: {len(ext_cta)} → {len([r for r in regs if r.get('source')=='external'])} (drop {drop_cta_to_reg})")
    print(f"  Reg attempt → success:  {len(regs)} → {len(conversions)}")

    # Registration log
    if reg_path.exists() and reg_path.stat().st_size > 0:
        reg_entries = [json.loads(l) for l in reg_path.read_text().splitlines() if l.strip()]
        print(f"\n=== REGISTRATION LOG: {len(reg_entries)} entries ===")
    else:
        print("\n=== REGISTRATION LOG: empty (0 successful registrations) ===")

if __name__ == "__main__":
    main()
