"""Starts atlas_service and bank_service together for local development.

Since 2026-09-22 both are served over TLS by default, from the local test CA
(scripts/make_dev_ca.py):

    atlas_service  https://127.0.0.1:8000   TLS
    bank_service   https://127.0.0.1:8100   mutual TLS -- only atlas_service's client
                                            certificate is accepted
    ATLAS -> bank  https, bank certificate verified, no plaintext fallback

    python scripts/make_dev_ca.py        # once: creates dev-certs/ (gitignored)
    python scripts/train_models.py       # once: the explicit ML training step
    python scripts/run_dev.py
    python scripts/run_dev.py --host 0.0.0.0     # still TLS; transport.py allows it

Deliberately does NOT start a tunnel, and does NOT create credentials or train
models on its own: both are explicit steps, and it tells you which is missing.
For the Wokwi simulator use scripts/run_sim.py instead (the ESP32 firmware
speaks plain HTTP, so its listener is loopback HTTP).

This is a TLS-enabled software prototype on a local test PKI, not production
TLS: no public or enterprise CA and no HSM. It runs the development profile; set
ATLAS_TRANSPORT_PROFILE=production for TLS 1.3 only, CRL checks and the bank pin
(RUNBOOK.md §4.5).
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

ATLAS_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ATLAS_ROOT))

#: (name, service key for serve.py, port) -- one source of truth, shared with run_sim.py.
SERVICES = [
    ("atlas_service", "atlas", 8000),
    ("bank_service", "bank", 8100),
]


def missing_prerequisites() -> list[str]:
    """What must exist before the services can run as designed."""
    from atlas_service.ml import registry
    from atlas_service.policy.engine import POLICIES_DIR
    from atlas_service.tls import DEFAULT_CERTS_DIR, PASSWORD_FILE

    problems = []
    if not (DEFAULT_CERTS_DIR / "ca.crt").exists() or not (DEFAULT_CERTS_DIR / PASSWORD_FILE).exists():
        problems.append("no local TLS material -- run: python scripts/make_dev_ca.py")
    for policy in sorted(POLICIES_DIR.glob("*.yaml")):
        try:
            registry.load(policy.stem)
        except registry.ModelUnavailableError:
            problems.append(f"no verified model for {policy.stem} -- run: python scripts/train_models.py")
            break
    return problems


def launch(specs, env=None) -> list[tuple[str, subprocess.Popen]]:
    processes = []
    for name, argv in specs:
        processes.append((name, subprocess.Popen([sys.executable, str(ATLAS_ROOT / "scripts" / "serve.py"), *argv],
                                                 cwd=ATLAS_ROOT, env=env)))
    return processes


def supervise(processes: list[tuple[str, subprocess.Popen]], label: str) -> int:
    try:
        while True:
            for name, proc in processes:
                if proc.poll() is not None:
                    print(f"[{label}] {name} exited with code {proc.returncode}")
                    return proc.returncode or 1
            time.sleep(0.5)
    except KeyboardInterrupt:
        print(f"\n[{label}] shutting down")
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


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--host", default="127.0.0.1")
    args = ap.parse_args()

    problems = missing_prerequisites()
    if problems:
        for p in problems:
            print(f"[run_dev] {p}")
        return 2

    specs = [
        ("bank_service", ["bank", "--host", args.host, "--port", "8100", "--tls", "--require-client-cert"]),
        ("atlas_service", ["atlas", "--host", args.host, "--port", "8000", "--tls"]),
    ]
    for name, argv in specs:
        print(f"[run_dev] starting {name} on https://{args.host}:{argv[4]}")
    processes = launch(specs)
    print("[run_dev] both services running over TLS. Ctrl-C to stop.")
    return supervise(processes, "run_dev")


if __name__ == "__main__":
    raise SystemExit(main())
