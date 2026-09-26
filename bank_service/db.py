"""The sandbox bank's own durable record: payment outcomes and revoked ATLAS keys.

Until 2026-09-22 both lived in process memory. That made two guarantees quietly
conditional on the bank never restarting:

  * idempotency and reconciliation -- after a restart the bank no longer knew it
    had approved a payment, so ATLAS's /reconcile asked "what happened to this
    transaction?" and got NOT_FOUND, which settles as FAILED even though the bank
    had approved it;
  * revocation -- a revoked ATLAS key was trusted again after a restart.

Both now persist in one SQLite file (bank_service/bank_ledger.db, or
$ATLAS_STATE_DIR/bank_ledger.db for a disposable run). What the bank DECIDES is
unchanged: bank_service/ledger.py still applies the same sandbox account rules.
This is a sandbox authority's record, not a banking system: the accounts are
fixed test fixtures and no money moves.

The path is read at call time (DEFAULT_DB_PATH), so tests point it at a
temporary file per test (tests/conftest.py).
"""

from __future__ import annotations

import os
import sqlite3
import threading
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

_STATE_DIR = os.environ.get("ATLAS_STATE_DIR")
DEFAULT_DB_PATH = (Path(_STATE_DIR) if _STATE_DIR else Path(__file__).resolve().parent) / "bank_ledger.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS outcomes (
    transaction_id TEXT PRIMARY KEY,
    subject        TEXT NOT NULL,
    amount         TEXT NOT NULL,
    approved       INTEGER NOT NULL,
    reason         TEXT NOT NULL,
    recorded_at    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS revoked_keys (
    key_id      TEXT PRIMARY KEY,
    revoked_at  TEXT NOT NULL
);
"""

_lock = threading.RLock()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _connect() -> sqlite3.Connection:
    path = Path(DEFAULT_DB_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=5.0, isolation_level=None, check_same_thread=False)
    conn.executescript(_SCHEMA)
    return conn


def record_outcome(transaction_id: str, subject: str, amount: str,
                   approved: bool, reason: str) -> tuple[bool, str]:
    """Stores the FIRST outcome for a transaction_id and returns whatever is
    stored -- so a second, racing or repeated request gets the original answer."""
    with _lock, closing(_connect()) as conn:
        conn.execute(
            "INSERT OR IGNORE INTO outcomes (transaction_id, subject, amount, approved, reason, "
            "recorded_at) VALUES (?,?,?,?,?,?)",
            (transaction_id, subject, amount, int(approved), reason, _now()))
        row = conn.execute("SELECT approved, reason FROM outcomes WHERE transaction_id = ?",
                           (transaction_id,)).fetchone()
    return bool(row[0]), row[1]


def get_outcome(transaction_id: str) -> tuple[bool, str] | None:
    with _lock, closing(_connect()) as conn:
        row = conn.execute("SELECT approved, reason FROM outcomes WHERE transaction_id = ?",
                           (transaction_id,)).fetchone()
    return (bool(row[0]), row[1]) if row else None


def revoke_key(key_id: str) -> None:
    with _lock, closing(_connect()) as conn:
        conn.execute("INSERT OR IGNORE INTO revoked_keys (key_id, revoked_at) VALUES (?,?)",
                     (key_id, _now()))


def is_key_revoked(key_id: str) -> bool:
    with _lock, closing(_connect()) as conn:
        return conn.execute("SELECT 1 FROM revoked_keys WHERE key_id = ?",
                            (key_id,)).fetchone() is not None


def clear_revocations() -> None:
    with _lock, closing(_connect()) as conn:
        conn.execute("DELETE FROM revoked_keys")
