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
with the bank's certificate verified (atlas_service/tls.py). Since 2026-09-27
atlas_service's own listener is TLS too (rebuild the firmware once after pulling this):
the ESP32 is written to connect to
https://host.wokwi.internal:8000 and verifies ATLAS against the local CA, whose
public certificate it reads from NVS with its identity (scripts/provision_nvs.py,
2026-10-09). Before starting, this script checks that atlas.crt names
host.wokwi.internal and that the local identity image carries this ca.crt, and says
which command fixes either.

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

Contains no secrets and must never contain any. The device's identity lives in the
git-ignored image firmware/atlas_device/local/atlas-wokwi-full.bin (provision_nvs.py).
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

import wokwi_gateway  # noqa: E402
from run_dev import launch, missing_prerequisites, supervise  # noqa: E402


IDENTITY_MANIFEST = ATLAS_ROOT / "firmware" / "atlas_device" / "local" / "identity.json"


def device_tls_problems(certs: Path | None = None, manifest: Path | None = None) -> list[str]:
    """What the ESP32's HTTPS connection needs (2026-09-27; CA from NVS since 2026-10-09).
    Reads public certificates and the image's public manifest only; changes nothing."""
    import hashlib
    import json

    import make_dev_ca
    from atlas_service.tls import DEFAULT_CERTS_DIR
    certs = certs or DEFAULT_CERTS_DIR
    manifest = manifest or IDENTITY_MANIFEST
    if not (certs / "atlas.crt").exists() or not (certs / "ca.crt").exists():
        return []            # missing_prerequisites() already reports missing TLS material
    problems = []
    if not make_dev_ca.atlas_names_device_host(certs):
        problems.append(f"atlas.crt does not name {make_dev_ca.DEVICE_HOSTNAME}, so the ESP32 "
                        "would refuse it -- run: python scripts/make_dev_ca.py --reissue-atlas")
    ca_sha = hashlib.sha256((certs / "ca.crt").read_text(encoding="ascii").encode("ascii")).hexdigest()
    recorded = json.loads(manifest.read_text(encoding="utf-8")).get("ca_sha256") if manifest.exists() else None
    if recorded != ca_sha:
        problems.append("the device's identity image is missing or carries another CA -- run: "
                        "python scripts/provision_nvs.py (see RUNBOOK section 2.1)")
    return problems

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


def wait_for_services(processes, ports=(8100, 8000), timeout: float = 120.0) -> str | None:
    """Waits until every service accepts connections on 127.0.0.1. Returns None when
    they all do, otherwise what went wrong. A service that has exited, or never opens
    its port, must not be followed by a 'ready' message."""
    deadline = time.monotonic() + timeout
    pending = list(ports)
    while pending and time.monotonic() < deadline:
        for name, proc in processes:
            if proc.poll() is not None:
                return f"{name} exited with code {proc.returncode} before it started listening"
        pending = [p for p in pending if not wokwi_gateway.port_listening(p, wokwi_gateway.HOST)]
        if pending:
            time.sleep(0.5)
    return None if not pending else f"nothing listened on 127.0.0.1:{pending[0]} within {timeout:.0f}s"


def seed_state_dir(state_dir: Path) -> list[str]:
    """Copies the live device registry, step-up enrollment and policy-owner
    enrolment (atlas_policy_state.db, 2026-09-27) into state_dir,
    reading the live files with SQLite's read-only, immutable URI so they are
    never opened for writing. Returns the names copied."""
    import sqlite3

    state_dir.mkdir(parents=True, exist_ok=True)
    copied = []
    for name in ("atlas_devices.db", "atlas_step_up.db", "atlas_policy_state.db"):
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
    problems = missing_prerequisites() + device_tls_problems()
    if problems:
        for p in problems:
            print(f"[run_sim] {p}")
        print("[run_sim] Nothing was started -- not ATLAS, not the bank, not the Wokwi gateway. Until the "
              "above is fixed,")
        print("[run_sim] Wokwi will report \"Failed to connect to the IoT Gateway at ws://localhost:9011\", "
              "because nothing is listening there.")
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
        ("atlas_service", ["atlas", "--port", "8000", "--tls"]),
    ]
    print("[run_sim] starting bank_service on https://127.0.0.1:8100 (mutual TLS)")
    print("[run_sim] starting atlas_service on https://127.0.0.1:8000 (TLS; the ESP32 verifies it)")
    processes = launch(specs, env=env)

    failure = wait_for_services(processes)
    if failure:
        print(f"[run_sim] {failure}. Stopping; the gateway was not started.")
        supervise_stop(processes)
        return 2
    print("[run_sim] bank_service and atlas_service are listening on 127.0.0.1")

    if args.no_gateway:
        print("[run_sim] --no-gateway: checking that a verified gateway is already answering")
        exe = wokwi_gateway.locate_binary()
        refusal = wokwi_gateway.verify_binary(exe)
        state = refusal or wokwi_gateway.port_state(exe, wokwi_gateway.read_configured_gateway()[1])
        print(f"[run_sim] gateway: {state.state}: {state.message}")
        if not state.ok:
            supervise_stop(processes)
            return 2
    else:
        print(f"[run_sim] starting the Wokwi gateway on {wokwi_gateway.GATEWAY_URL}")
        result = wokwi_gateway.start_gateway(detached=False)
        print(f"[run_sim] gateway: {result.state}: {result.message}")
        if not result.ok:
            supervise_stop(processes)
            return 3 if result.state == wokwi_gateway.BLOCKED else 2
        if result.process is not None:
            processes.append(("wokwigw", result.process))

    print("[run_sim] READY. Everything is up and verified. Now start Wokwi: F1 -> \"Wokwi: Start Simulator\".")
    print("[run_sim]   host.wokwi.internal -> 127.0.0.1 on this machine only. Ctrl-C stops everything it started.")
    return supervise(processes, "run_sim")


def supervise_stop(processes) -> None:
    """Stops what was started, without waiting on it (the failure path of main())."""
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
