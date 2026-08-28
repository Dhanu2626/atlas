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
import threading
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
        # check_same_thread=False (F2, 2026-08-27): FastAPI resolves a sync
        # dependency in one threadpool thread and then runs the endpoint body
        # in a *different* one, so a connection built in get_transaction_store()
        # was routinely used from another thread. Under light load the pool
        # reuses the same thread and it works; under concurrency it raises
        # sqlite3.ProgrammingError, which surfaced as INTERNAL_ERROR on 4-6 of
        # every 10 concurrent requests.
        #
        # Each request builds its own store, so in the HTTP path a connection is
        # only ever handed between threads sequentially. That is a usage
        # convention though, not a guarantee -- so the lock below makes the
        # store genuinely safe to share as well. Neither setting relaxes SQLite
        # locking; concurrent writers are still serialised by the database, and
        # the busy timeout makes them wait rather than error.
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False, timeout=10.0)
        # Required ALONGSIDE check_same_thread=False, not instead of it.
        # Removing sqlite3's thread guard does NOT make a connection safe to use
        # from two threads at once -- doing so raises InterfaceError ("bad
        # parameter or other API misuse") and can return corrupted rows. Caught
        # by tests/test_f2_concurrency.py, which deliberately shares one store
        # across threads.
        self._lock = threading.RLock()
        with self._lock:
            self._conn.execute(SCHEMA)
            self._conn.commit()

    def create(self, transaction_id: str, subject: str, amount: str, now: str) -> None:
        """Idempotent: creating the same transaction_id twice is a no-op, not
        an error — a client retrying a request it's unsure about (the exact
        situation Day 3 worried about) must not blow up on the retry itself."""
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO transactions "
                "(transaction_id, subject, amount, state, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (transaction_id, subject, amount, TxnState.CREATED.value, now, now),
            )
            self._conn.commit()

    def claim_new(self, transaction_id: str, subject: str, amount: str, now: str) -> bool:
        """Atomically create a transaction, returning True only for the caller
        that actually inserted it.

        F2: the existing get_state()-then-create() sequence in /transact is a
        check-then-act race -- two concurrent requests carrying the same
        transaction_id could both observe "absent" and both proceed. INSERT OR
        IGNORE plus rowcount makes the claim indivisible, so exactly one wins
        and the rest are correctly treated as duplicates.
        """
        with self._lock:
            cur = self._conn.execute(
                "INSERT OR IGNORE INTO transactions "
                "(transaction_id, subject, amount, state, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (transaction_id, subject, amount, TxnState.CREATED.value, now, now),
            )
            self._conn.commit()
            return cur.rowcount == 1

    def set_state(self, transaction_id: str, state: TxnState, now: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE transactions SET state = ?, updated_at = ? WHERE transaction_id = ?",
                (state.value, now, transaction_id),
            )
            self._conn.commit()

    def get_state(self, transaction_id: str) -> TxnState | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT state FROM transactions WHERE transaction_id = ?", (transaction_id,)
            ).fetchone()
        return TxnState(row[0]) if row else None

    def find_in_states(self, states: set[TxnState]) -> list[str]:
        """Used on "restart" to find transactions that never reached a
        terminal state — exactly what needs reconciliation."""
        placeholders = ",".join("?" for _ in states)
        with self._lock:
            rows = self._conn.execute(
                f"SELECT transaction_id FROM transactions WHERE state IN ({placeholders})",
                tuple(s.value for s in states),
            ).fetchall()
        return [r[0] for r in rows]

    def close(self) -> None:
        self._conn.close()
