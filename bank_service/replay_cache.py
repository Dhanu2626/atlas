"""Persisted replay cache -- bank_service's defense against a valid,
untampered, unexpired assertion being resent. Deliberately separate from
signature checking (BUILD-PLAN.md Step 5): a resent assertion has a
perfectly valid signature, so signature verification alone can't catch a
replay. Only remembering "have I already accepted this exact
(transaction_id, nonce) pair" can.

SQLite-backed for the same reason atlas_service/db.py is: an in-memory set
would forget every consumed nonce on process restart, silently reopening
the exact replay window this exists to close.
"""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS consumed_assertions (
    transaction_id TEXT NOT NULL,
    nonce TEXT NOT NULL,
    consumed_at TEXT NOT NULL,
    PRIMARY KEY (transaction_id, nonce)
);
"""


class ReplayCache:
    def __init__(self, db_path: str | Path):
        # check_same_thread=False + busy timeout: bank_service's /verify builds
        # a ReplayCache through the same FastAPI sync-dependency mechanism as
        # atlas_service's stores, so it carries the identical thread-affinity
        # hazard. Fixed here too rather than waiting for it to surface as an
        # INTERNAL_ERROR in the bank leg. See atlas_service/db.py for the full
        # reasoning and the safety argument.
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False, timeout=10.0)
        # See atlas_service/db.py for why a lock is required alongside
        # check_same_thread=False.
        self._lock = threading.RLock()
        with self._lock:
            self._conn.execute(SCHEMA)
            self._conn.commit()

    def already_consumed(self, transaction_id: str, nonce: str) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM consumed_assertions WHERE transaction_id = ? AND nonce = ?",
                (transaction_id, nonce),
            ).fetchone()
        return row is not None

    def mark_consumed(self, transaction_id: str, nonce: str, now: str) -> None:
        """INSERT OR IGNORE, not INSERT: two racing requests for the same
        pair must not crash on a unique-constraint violation -- the second
        one just finds it already marked, which is the correct outcome."""
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO consumed_assertions "
                "(transaction_id, nonce, consumed_at) VALUES (?, ?, ?)",
                (transaction_id, nonce, now),
            )
            self._conn.commit()

    def claim(self, transaction_id: str, nonce: str, now: str) -> bool:
        """Atomically consume an assertion, returning True only for the caller
        that actually inserted it.

        F2: already_consumed() followed by mark_consumed() is a check-then-act
        race. This collapses both into one indivisible step so exactly one of N
        concurrent presentations of the same assertion can win.
        """
        with self._lock:
            cur = self._conn.execute(
                "INSERT OR IGNORE INTO consumed_assertions "
                "(transaction_id, nonce, consumed_at) VALUES (?, ?, ?)",
                (transaction_id, nonce, now),
            )
            self._conn.commit()
            return cur.rowcount == 1

    def close(self) -> None:
        with self._lock:
            self._conn.close()
