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
        self._conn = sqlite3.connect(str(db_path))
        self._conn.execute(SCHEMA)
        self._conn.commit()

    def already_consumed(self, transaction_id: str, nonce: str) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM consumed_assertions WHERE transaction_id = ? AND nonce = ?",
            (transaction_id, nonce),
        ).fetchone()
        return row is not None

    def mark_consumed(self, transaction_id: str, nonce: str, now: str) -> None:
        """INSERT OR IGNORE, not INSERT: two racing requests for the same
        pair must not crash on a unique-constraint violation -- the second
        one just finds it already marked, which is the correct outcome."""
        self._conn.execute(
            "INSERT OR IGNORE INTO consumed_assertions "
            "(transaction_id, nonce, consumed_at) VALUES (?, ?, ?)",
            (transaction_id, nonce, now),
        )
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()
