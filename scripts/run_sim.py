"""Starts ATLAS in WOKWI SIMULATION MODE. Never use this for anything real.

WHY THIS SCRIPT EXISTS, AND WHY IT IS SEPARATE FROM run_dev.py
--------------------------------------------------------------
The Wokwi simulator does not reliably persist the ESP32's NVS flash between
sessions, so a restarted simulation sends counter=1 while atlas_service still
remembers a higher counter for that device. That is a correct
COUNTER_REGRESSION rejection -- the replay check working, not failing.

The narrow, audited accommodation for this is
ATLAS_SIMULATION_ALLOW_COUNTER_RESET, and it is DEFAULT OFF. This script is
the only thing in the repository that turns it on.

It is a SEPARATE script, not a flag on run_dev.py, on purpose: production and
production-like runs use run_dev.py and cannot inherit this setting by
forgetting an argument. The variable is passed to the child processes only --
it is never written to a file, never exported to your shell, and dies with
these processes.

WHAT THE ACCOMMODATION DOES NOT DO (verified in
atlas_service/device/envelope.py:_may_accept_counter_reset)
-----------------------------------------------------------
It accepts a LOWER counter only when the envelope carries a boot_id DIFFERENT
from the last one recorded, and boot_id is the first field of the signed
canonical bytes -- so it cannot be bolted onto a captured envelope. Therefore:

  * a replay of a real envelope still fails: its boot_id matches the stored one
  * the nonce layer still applies, unconditionally
  * the transaction_id layer still applies, unconditionally (claim_new)
  * signature verification is untouched and still gates everything
  * every acceptance writes a device_events audit row

Replay protection degrades from three independent layers to two. Never to zero,
and never for a real device, which persists its counter and never takes this
path.

TRANSPORT (2026-09-22)
----------------------
bank_service is served over mutual TLS and atlas_service calls it over https
with the bank's certificate verified (atlas_service/tls.py). atlas_service's own
listener stays plain HTTP on 127.0.0.1, because the ESP32 firmware has no TLS
client: its requests are Ed25519-signed end to end, but travel unencrypted
through the loopback Wokwi gateway.

DISPOSABLE STATE
----------------
--state-dir DIR runs both services against databases in DIR instead of the live
ones (ATLAS_STATE_DIR). The device registry and step-up enrollment are copied in
from the live databases through SQLite's read-only, immutable mode -- the live
files are never opened for writing -- so the enrolled device and authenticator
work, while every transaction, counter, challenge and bank outcome of the run
lands in DIR. Delete DIR afterwards; nothing else changed.

USAGE
-----
    python scripts/run_sim.py                      # services + gateway, Ctrl-C to stop
    python scripts/run_sim.py --no-gateway
    python scripts/run_sim.py --state-dir C:/tmp/atlas-sim   # disposable state

Contains no secrets and must never contain any. Device identity lives in
firmware/atlas_device/secrets.h, which is gitignored.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

ATLAS_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ATLAS_ROOT / "scripts"))
sys.path.insert(0, str(ATLAS_ROOT))

from run_dev import launch, missing_prerequisites, supervise  # noqa: E402

BANNER = """
================================================================
  ATLAS -- WOKWI SIMULATION MODE
================================================================
  ATLAS_SIMULATION_ALLOW_COUNTER_RESET = 1

  A restarted simulator may resume its counter from 1 and will be
  ACCEPTED, but ONLY with a boot_id it has not used before. The
  boot_id is inside the signed bytes, so this cannot be forged.

  Still fully enforced: signatures, nonce, transaction_id, and
  same-boot replay rejection. Every reset is audited.

  DO NOT use this script for anything that is not the simulator.
  Production and production-like runs use scripts/run_dev.py.
================================================================
"""


def _find_gateway() -> Path | None:
    """wokwigw lets the simulated device reach 127.0.0.1 via
    host.wokwi.internal, which is what removes the need for a public tunnel."""
    on_path = shutil.which("wokwigw")
    if on_path:
        return Path(on_path)
    fallback = Path.home() / ".wokwi" / "wokwigw.exe"
    return fallback if fallback.exists() else None


def seed_state_dir(state_dir: Path) -> list[str]:
    """Copies the live device registry and step-up enrollment into state_dir,
    reading the live files with SQLite's read-only, immutable URI so they are
    never opened for writing. Returns the names copied."""
    import sqlite3

    state_dir.mkdir(parents=True, exist_ok=True)
    copied = []
    for name in ("atlas_devices.db", "atlas_step_up.db"):
        live = ATLAS_ROOT / "atlas_service" / name
        target = state_dir / name
        if not live.exists() or target.exists():
            continue
        src = sqlite3.connect(f"file:{live.resolve().as_posix()}?mode=ro&immutable=1", uri=True)
        dst = sqlite3.connect(target)
        try:
            src.backup(dst)
        finally:
            dst.close()
            src.close()
        copied.append(name)
    return copied


def main() -> int:
    ap = argparse.ArgumentParser(description="Start ATLAS in Wokwi simulation mode.")
    ap.add_argument("--no-gateway", action="store_true",
                    help="do not start wokwigw (use if it is already running)")
    ap.add_argument("--state-dir", type=Path,
                    help="run against disposable databases in this folder, never the live ones")
    args = ap.parse_args()

    print(BANNER)
    problems = missing_prerequisites()
    if problems:
        for p in problems:
            print(f"[run_sim] {p}")
        return 2

    # Child-process environment only. Deliberately NOT os.environ[...] = ...,
    # so nothing leaks into anything this script did not start.
    env = os.environ.copy()
    env["ATLAS_SIMULATION_ALLOW_COUNTER_RESET"] = "1"
    if args.state_dir:
        state_dir = args.state_dir.resolve()
        if str(state_dir).startswith(str(ATLAS_ROOT.resolve())):
            print("[run_sim] refusing: --state-dir must be outside the repository")
            return 2
        copied = seed_state_dir(state_dir)
        env["ATLAS_STATE_DIR"] = str(state_dir)
        print(f"[run_sim] DISPOSABLE STATE in {state_dir} (live databases untouched)")
        print(f"[run_sim]   copied read-only from the live registry: {', '.join(copied) or 'nothing'}")

    specs = [
        ("bank_service", ["bank", "--port", "8100", "--tls", "--require-client-cert"]),
        ("atlas_service", ["atlas", "--port", "8000"]),
    ]
    print("[run_sim] starting bank_service on https://127.0.0.1:8100 (mutual TLS)")
    print("[run_sim] starting atlas_service on http://127.0.0.1:8000 (loopback; the firmware has no TLS)")
    processes = launch(specs, env=env)

    if args.no_gateway:
        print("[run_sim] --no-gateway: assuming wokwigw is already running")
    else:
        gw = _find_gateway()
        if gw is None:
            print("[run_sim] WARNING: wokwigw not found on PATH or in ~/.wokwi/")
            print("[run_sim]   Download it from github.com/wokwi/wokwigw/releases.")
            print("[run_sim]   Without it the simulator cannot reach 127.0.0.1.")
        else:
            print(f"[run_sim] starting gateway on ws://localhost:9011 ({gw})")
            processes.append(("wokwigw", subprocess.Popen([str(gw)], cwd=ATLAS_ROOT)))

    print("[run_sim] ready. Start the simulator from VS Code. Ctrl-C to stop.")
    return supervise(processes, "run_sim")


if __name__ == "__main__":
    raise SystemExit(main())
