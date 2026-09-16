"""Join a device run into the three values worth checking per press.

    selected_preset  -- NOT transmitted; inferred from amount (see PRESETS)
    amount           -- backend only
    final_status     -- backend decision

Usage:  python scripts/verify_device_run.py <atlas_service_log> [device_id_filter]

Reads the atlas_service stdout log. Nothing here is authoritative about the
device's own view -- `selected_preset` is a device-side concept the backend
never sees, so it is reconstructed from the amount and is only as trustworthy
as the preset table below.
"""
from __future__ import annotations
import re, sys

# Mirrors PRESETS[] in firmware/atlas_device/atlas_device.ino
PRESETS = {"1500.00": 0, "60000.00": 1, "150000.00": 2}


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    log, want = sys.argv[1], (sys.argv[2] if len(sys.argv) > 2 else "")

    txns: dict[str, dict] = {}
    order: list[str] = []
    for line in open(log, encoding="utf-8", errors="replace"):
        m = re.search(r"txn=(\S+)", line)
        if not m or (want and want not in m.group(1)):
            continue
        tid = m.group(1)
        if tid not in txns:
            txns[tid] = {}
            order.append(tid)
        t = txns[tid]
        if a := re.search(r"amount=([\d.]+)", line):     t["amount"] = a.group(1)
        if d := re.search(r"decision=(\w+)", line):      t["final"] = d.group(1)
        if r := re.search(r"reason=(\w+)", line):        t["reason"] = r.group(1)
        if u := re.search(r"matched_rules=(\S+)", line): t["rules"] = u.group(1)
        if b := re.search(r"band=(\w+)", line):          t["band"] = b.group(1)
        if "event=device_authenticated" in line:         t["auth"] = "OK"

    hdr = f"{'transaction_id':<34}{'preset':>7}{'amount':>11}{'auth':>6}  {'final_status':<13}{'why'}"
    print(hdr); print("-" * len(hdr))
    for tid in order:
        t = txns[tid]
        amt = t.get("amount", "-")
        print(f"{tid:<34}{str(PRESETS.get(amt, '?')):>7}{amt:>11}{t.get('auth','--'):>6}  "
              f"{t.get('final','-'):<13}{t.get('rules') or t.get('reason','')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
