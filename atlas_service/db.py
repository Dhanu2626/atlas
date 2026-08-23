"""Persistent transaction state — SQLite-backed so it survives a process
restart, which is the entire point (Day 3's power-loss reasoning: RAM
disappears, disk doesn't).

Deliberately low-level and dumb: this module only knows how to persist and
retrieve state. It does not decide whether a transition is legal — that's
state_machine.py's job, kept separate so the storage layer can't accidentally
become the place business rules quietly live.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from contracts import TxnState

SCHEMA = """
CREATE TABLE IF NOT EXISTS transactions (
    transaction_id TEXT PRIMARY KEY,
    subject TEXT NOT NULL,
    amount TEXT NOT NULL,
    state TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""


class TransactionStore:
    def __init__(self, db_path: str | Path):
        self._conn = sqlite3.connect(str(db_path))
        self._conn.execute(SCHEMA)
        self._conn.commit()

    def create(self, transaction_id: str, subject: str, amount: str, now: str) -> None:
        """Idempotent: creating the same transaction_id twice is a no-op, not
        an error — a client retrying a request it's unsure about (the exact
        situation Day 3 worried about) must not blow up on the retry itself."""
        self._conn.execute(
            "INSERT OR IGNORE INTO transactions "
            "(transaction_id, subject, amount, state, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (transaction_id, subject, amount, TxnState.CREATED.value, now, now),
        )
        self._conn.commit()

    def set_state(self, transaction_id: str, state: TxnState, now: str) -> None:
        self._conn.execute(
            "UPDATE transactions SET state = ?, updated_at = ? WHERE transaction_id = ?",
            (state.value, now, transaction_id),
        )
        self._conn.commit()

    def get_state(self, transaction_id: str) -> TxnState | None:
        row = self._conn.execute(
            "SELECT state FROM transactions WHERE transaction_id = ?", (transaction_id,)
        ).fetchone()
        return TxnState(row[0]) if row else None

    def find_in_states(self, states: set[TxnState]) -> list[str]:
        """Used on "restart" to find transactions that never reached a
        terminal state — exactly what needs reconciliation."""
        placeholders = ",".join("?" for _ in states)
        rows = self._conn.execute(
            f"SELECT transaction_id FROM transactions WHERE state IN ({placeholders})",
            tuple(s.value for s in states),
        ).fetchall()
        return [r[0] for r in rows]

    def close(self) -> None:
        self._conn.close()
