"""Watches a test run from the outside and reports every file it really opened.

    python scripts/audit_file_access.py                 # the whole suite
    python scripts/audit_file_access.py tests/test_step_up.py -x

Exits 1 if the run touched anything it should not, or if the tests themselves
failed.

WHY THIS EXISTS. On 2026-09-17 ten tests were found to be opening the live
step-up and transaction databases on every run. Nothing was written and every
test passed, so nothing said so for months. tests/conftest.py now redirects the
default paths and fails a test that uses one, but that guard only sees what it
knows to patch: crypto.DEFAULT_KEYS_DIR and device_identity's key directory are
bound as default ARGUMENTS at import time, and no monkeypatch reaches those.
This script needs no cooperation from the code under test. Python's audit hooks
see the attempt itself -- open(), os.open, sqlite3.connect, directory listings,
removals, renames -- so a read is as visible as a write.

PROTECTED means what a developer's machine has that a test must not reach: the
four service databases and their sidecars, anything inside a keys, shared_keys
or device_keys* directory, the device secret, atlas.log, and the firmware build
output. Reads are reported as well as writes: a test that reads a live database
is testing the developer's data rather than its own fixture.

The file is both the runner and the pytest plugin it loads (-p audit_file_access).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from pathlib import Path

ROOT_ENV, OUT_ENV = "ATLAS_AUDIT_ROOT", "ATLAS_AUDIT_OUT"
DATABASES = (
    "atlas_service/atlas_transactions.db",
    "atlas_service/atlas_step_up.db",
    "atlas_service/atlas_devices.db",
    "bank_service/bank_replay_cache.db",
)
WATCHED_EVENTS = {
    "open", "sqlite3.connect", "os.listdir", "os.scandir", "os.mkdir",
    "os.remove", "os.rename", "os.replace", "os.rmdir", "shutil.rmtree",
    "shutil.copyfile", "shutil.move",
}


def classify(root: str, target: str) -> tuple[str, str] | None:
    """(kind, repo-relative path) if this path is protected, else None."""
    path = os.path.normcase(os.path.abspath(target))
    if not path.startswith(root + os.sep):
        return None
    rel = path[len(root) + 1:].replace("\\", "/")
    parts = rel.split("/")
    if parts[0] in (".venv", ".git") or "__pycache__" in parts:
        return None
    base = rel
    for suffix in ("-journal", "-wal", "-shm"):
        if base.endswith(suffix):
            base = base[: -len(suffix)]
    if base in DATABASES:
        return "database", rel
    if rel == "firmware/atlas_device/secrets.h":
        return "device secret", rel
    if rel == "atlas.log":
        return "log", rel
    if any(p in ("keys", "shared_keys") or p.startswith("device_keys") for p in parts):
        return "key directory", rel
    if rel.startswith("firmware/atlas_device/build"):
        return "firmware build output", rel
    return None


# --------------------------------------------------------------------------
# pytest plugin half: loaded with -p audit_file_access
# --------------------------------------------------------------------------

if ROOT_ENV in os.environ:
    _root = os.path.normcase(os.path.abspath(os.environ[ROOT_ENV]))
    _local = threading.local()
    _current = {"test": "(import and collection)"}
    _hits: dict = {}

    def _hook(event: str, args) -> None:
        if event not in WATCHED_EVENTS or getattr(_local, "busy", False):
            return
        _local.busy = True
        try:
            target = args[0] if args else None
            if target is None or isinstance(target, int):
                return
            target = os.fsdecode(os.fspath(target))
            how = f"open mode={args[1]!r}" if event == "open" and len(args) > 1 else event
            if event == "sqlite3.connect" and target.startswith("file:"):
                target, how = target[5:].split("?", 1)[0], "sqlite3.connect (URI)"
            if target in ("", ":memory:"):
                return
            found = classify(_root, target)
            if found:
                key = (_current["test"], found[0], found[1], how)
                _hits[key] = _hits.get(key, 0) + 1
        except Exception:  # noqa: BLE001 -- an audit hook must never break the run
            pass
        finally:
            _local.busy = False

    sys.addaudithook(_hook)

    def pytest_runtest_logstart(nodeid, location):  # noqa: D103
        _current["test"] = nodeid

    def pytest_runtest_logfinish(nodeid, location):  # noqa: D103
        _current["test"] = "(between tests)"

    def pytest_sessionfinish(session, exitstatus):  # noqa: D103
        rows = [{"test": t, "kind": k, "path": p, "how": h, "count": c}
                for (t, k, p, h), c in sorted(_hits.items())]
        Path(os.environ[OUT_ENV]).write_text(
            json.dumps({"exitstatus": int(exitstatus), "hits": rows}, indent=1), encoding="utf-8")


# --------------------------------------------------------------------------
# runner half
# --------------------------------------------------------------------------

def main(argv: list[str]) -> int:
    root = Path(__file__).resolve().parent.parent
    report = root / ".file-access-audit.json"
    env = dict(os.environ, **{
        ROOT_ENV: str(root), OUT_ENV: str(report),
        "PYTHONPATH": str(root / "scripts") + os.pathsep + os.environ.get("PYTHONPATH", ""),
    })

    print(f"[audit] running the tests with every file open recorded (root: {root})")
    run = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "audit_file_access", *argv],
                         cwd=root, env=env)
    if not report.exists():
        print("[audit] the run produced no report; did pytest start?")
        return 1

    data = json.loads(report.read_text(encoding="utf-8"))
    report.unlink()
    hits = data["hits"]
    opens = [h for h in hits if h["how"].startswith(("open", "sqlite3"))]

    print(f"\n[audit] protected-path access: {len(hits)} distinct, {len(opens)} of them opens")
    for hit in hits:
        print(f"  {hit['kind']:22} {hit['path']:44} {hit['how']:26} x{hit['count']}")
        print(f"      by {hit['test']}")
    if not hits:
        print("  none: the run opened no database, key, secret, log or build output")

    if opens:
        print("\n[audit] FAILED: a test opened protected state")
        return 1
    if hits:
        print("\n[audit] no file was opened; the entries above are directory operations only")
    return run.returncode


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
