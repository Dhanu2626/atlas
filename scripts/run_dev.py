"""Starts atlas_service and bank_service together for local development.

Listed in BUILD-PLAN.md's folder structure since the beginning; actually
needed as of Step 8, because the Wokwi demo requires both services running
at once.

Deliberately does NOT start a tunnel. Exposing atlas_service to the public
internet is a decision the operator makes consciously, with the caveats in
firmware/README.md in front of them -- not something a dev script does as a
side effect.

Binds to 127.0.0.1 only. If you need the device to reach this, use a tunnel
(see firmware/README.md), rather than binding to 0.0.0.0 and hoping.
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

ATLAS_ROOT = Path(__file__).resolve().parent.parent

SERVICES = [
    ("atlas_service", "atlas_service.main:app", 8000),
    ("bank_service", "bank_service.main:app", 8100),
]


def main() -> int:
    processes: list[tuple[str, subprocess.Popen]] = []
    try:
        for name, target, port in SERVICES:
            print(f"[run_dev] starting {name} on http://127.0.0.1:{port}")
            proc = subprocess.Popen(
                [sys.executable, "-m", "uvicorn", target,
                 "--host", "127.0.0.1", "--port", str(port)],
                cwd=ATLAS_ROOT,
            )
            processes.append((name, proc))

        print("[run_dev] both services running. Ctrl-C to stop.")
        while True:
            for name, proc in processes:
                if proc.poll() is not None:
                    print(f"[run_dev] {name} exited with code {proc.returncode}")
                    return proc.returncode or 1
            time.sleep(0.5)

    except KeyboardInterrupt:
        print("\n[run_dev] shutting down")
        return 0
    finally:
        for name, proc in processes:
            if proc.poll() is None:
                proc.terminate()
        for name, proc in processes:
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()


if __name__ == "__main__":
    raise SystemExit(main())
