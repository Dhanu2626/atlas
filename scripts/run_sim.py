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

USAGE
-----
    python scripts/run_sim.py          # services + gateway, Ctrl-C to stop
    python scripts/run_sim.py --no-gateway

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

from run_dev import SERVICES  # noqa: E402  -- one source of truth for ports

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


def main() -> int:
    ap = argparse.ArgumentParser(description="Start ATLAS in Wokwi simulation mode.")
    ap.add_argument("--no-gateway", action="store_true",
                    help="do not start wokwigw (use if it is already running)")
    args = ap.parse_args()

    print(BANNER)

    # Child-process environment only. Deliberately NOT os.environ[...] = ...,
    # so nothing leaks into anything this script did not start.
    env = os.environ.copy()
    env["ATLAS_SIMULATION_ALLOW_COUNTER_RESET"] = "1"
    env["ATLAS_REQUIRE_DEVICE_AUTH"] = "1"  # closes the legacy unsigned path

    processes: list[tuple[str, subprocess.Popen]] = []
    try:
        for name, target, port in SERVICES:
            print(f"[run_sim] starting {name} on http://127.0.0.1:{port}")
            processes.append((name, subprocess.Popen(
                [sys.executable, "-m", "uvicorn", target,
                 "--host", "127.0.0.1", "--port", str(port)],
                cwd=ATLAS_ROOT, env=env,
            )))

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
        while True:
            for name, proc in processes:
                if proc.poll() is not None:
                    print(f"[run_sim] {name} exited with code {proc.returncode}")
                    return proc.returncode or 1
            time.sleep(0.5)

    except KeyboardInterrupt:
        print("\n[run_sim] shutting down")
        return 0
    finally:
        for _, proc in processes:
            if proc.poll() is None:
                proc.terminate()
        for _, proc in processes:
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()


if __name__ == "__main__":
    raise SystemExit(main())
