#!/usr/bin/env python3
import argparse
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

def parse_args():
    p = argparse.ArgumentParser(description="Analyze proxy decisions.log (JSON Lines).")
    p.add_argument("-f", "--file", default="decisions.log", help="Path to decisions log (default: decisions.log)")
    p.add_argument("--top", type=int, default=5, help="How many top items to show (default: 5)")
    p.add_argument("--since", type=str, default=None, help="ISO8601 timestamp filter (UTC), e.g. 2025-09-26T12:00:00Z")
    return p.parse_args()

def parse_ts(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    ts = ts.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(ts)
    except Exception:
        return None

def main():
    args = parse_args()
    path = Path(args.file)
    if not path.exists():
        print(f"File not found: {path}")
        return

    since_dt = parse_ts(args.since)

    total = 0
    allow = 0
    block = 0
    by_proto = Counter()
    by_host_allow = Counter()
    by_host_block = Counter()
    by_reason = Counter()

    errors = 0

    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj: Dict[str, Any] = json.loads(line)
            except Exception:
                errors += 1
                continue

            # Time filter
            ts_raw = obj.get("ts")
            if since_dt is not None and ts_raw:
                try:
                    ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
                    if ts < since_dt:
                        continue
                except Exception:
                    pass

            total += 1
            action = (obj.get("action") or "").upper()
            proto = (obj.get("proto") or "HTTP").upper()
            host = (obj.get("host") or "").lower()
            reason = (obj.get("reason") or "").strip()

            by_proto[proto] += 1

            if action == "ALLOW":
                allow += 1
                if host:
                    by_host_allow[host] += 1
            elif action == "BLOCK":
                block += 1
                if host:
                    by_host_block[host] += 1
                if reason:
                    by_reason[reason] += 1

    print("=== Decisions Summary ===")
    print(f"File: {path}")
    if since_dt:
        print(f"Since: {since_dt.isoformat()}")
    print(f"Total: {total}  |  ALLOW: {allow}  |  BLOCK: {block}")
    print(f"By protocol: " + ", ".join(f"{k}={v}" for k,v in by_proto.items()))

    top_n = args.top

    if by_host_block:
        print(f"\nTop {top_n} blocked hosts:")
        for host, cnt in by_host_block.most_common(top_n):
            print(f"  {host}: {cnt}")

    if by_reason:
        print(f"\nTop {top_n} block reasons:")
        for r, cnt in by_reason.most_common(top_n):
            print(f"  {cnt} × {r}")

    if by_host_allow:
        print(f"\nTop {top_n} allowed hosts:")
        for host, cnt in by_host_allow.most_common(top_n):
            print(f"  {host}: {cnt}")

    if errors:
        print(f"\nNote: {errors} malformed line(s) skipped.")

if __name__ == "__main__":
    main()
