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

#: The rest of a Transaction, added 2026-09-23 so a subject's OWN past payments can
#: be the history their next payment is judged against (velocity, new beneficiary,
#: and every history-derived ML feature). Before this the table kept only
#: id/subject/amount/state, so those features had nothing real to read and were
#: computed from generated history instead -- a live burst of payments moved nothing.
#:
#: Every column is nullable and added by ALTER TABLE on an existing database, so an
#: older store keeps all its rows and simply has no detail for them. A row without
#: detail is skipped by history_for() rather than guessed at: a fabricated
#: beneficiary or timestamp would corrupt exactly the decisions this exists to feed.
DETAIL_COLUMNS = (
    ("currency", "TEXT"),
    ("beneficiary", "TEXT"),
    ("location", "TEXT"),
    ("device_id", "TEXT"),
    ("merchant_category", "TEXT"),
    ("authentication_method", "TEXT"),
    ("occurred_at", "TEXT"),          # the transaction's own timestamp, not receipt time
    ("is_international", "INTEGER"),
    ("declared_travel_mode", "INTEGER"),
    ("is_emergency_request", "INTEGER"),
)

#: How many of a subject's most recent payments a decision looks back over. The
#: modelled baseline this replaces was 200 transactions (ml/registry.HISTORY_SIZE),
#: so the live window matches it rather than inventing a second number. Both the
#: 24-hour velocity window and the amount baseline are computed from these rows.
HISTORY_LIMIT = 200


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
            self._migrate_detail_columns()
            self._conn.commit()

    def _migrate_detail_columns(self) -> None:
        """Adds any missing detail column to an existing table, in place.

        Deterministic and backward compatible: ALTER TABLE ADD COLUMN on SQLite
        rewrites no rows and cannot fail on data, existing rows get NULL, and a
        store already carrying the columns is left alone. Nothing is deleted or
        rewritten, so a live database keeps every transaction it had."""
        present = {row[1] for row in self._conn.execute("PRAGMA table_info(transactions)")}
        for name, kind in DETAIL_COLUMNS:
            if name not in present:
                self._conn.execute(f"ALTER TABLE transactions ADD COLUMN {name} {kind}")

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

    def record_details(self, transaction: "Transaction") -> None:
        """Stores the rest of an already-claimed transaction, so it can serve as
        history later. Separate from claim_new() on purpose: the claim must stay a
        single indivisible INSERT (F2), and a caller that only has id/subject/amount
        -- the pre-Phase-3 contract -- must keep working unchanged."""
        with self._lock:
            self._conn.execute(
                "UPDATE transactions SET currency = ?, beneficiary = ?, location = ?, "
                "device_id = ?, merchant_category = ?, authentication_method = ?, "
                "occurred_at = ?, is_international = ?, declared_travel_mode = ?, "
                "is_emergency_request = ? WHERE transaction_id = ?",
                (transaction.currency, transaction.beneficiary, transaction.location,
                 transaction.device_id, transaction.merchant_category,
                 transaction.authentication_method, transaction.timestamp,
                 int(transaction.is_international), int(transaction.declared_travel_mode),
                 int(transaction.is_emergency_request), transaction.transaction_id),
            )
            self._conn.commit()

    def history_for(self, subject: str, *, exclude_transaction_id: str | None = None,
                    limit: int = HISTORY_LIMIT) -> list["Transaction"]:
        """This subject's own past payments, oldest first, as Transactions.

        THE HISTORICAL WINDOW, stated once so every feature reads the same thing:

          * only this subject's rows -- history is per subject, never global;
          * only rows carrying full detail. A row written before 2026-09-23, or by
            a caller that never supplied the detail, is SKIPPED, not guessed at;
          * `exclude_transaction_id` removes the payment being decided, so it can
            never appear in its own baseline (look-ahead leakage). Callers pass the
            transaction they are about to score;
          * the most recent `limit` rows, returned oldest-first, because
            extract_training_matrix and the 24-hour windows both read chronological
            order;
          * EVERY state is included -- an ALLOW, a DENY and a payment still waiting
            on step-up are all things this subject really did. Velocity in
            particular must count attempts: letting a denied payment drop out of
            the window would let anyone reset their own rate limit by being refused.

        An empty list is the honest answer for a subject ATLAS has never seen, and
        the features treat it as such: no amount baseline, nothing known, one
        transaction in the last 24 hours. It is never silently replaced by the
        generated history the model was trained on.
        """
        from contracts import Transaction  # local: contracts imports nothing from here

        names = [name for name, _ in DETAIL_COLUMNS]
        required = ("beneficiary", "location", "device_id", "occurred_at",
                    "currency", "authentication_method")
        with self._lock:
            rows = self._conn.execute(
                f"SELECT transaction_id, subject, amount, {', '.join(names)} "
                "FROM transactions WHERE subject = ? "
                + ("AND transaction_id != ? " if exclude_transaction_id else "")
                + "AND beneficiary IS NOT NULL AND occurred_at IS NOT NULL "
                "ORDER BY occurred_at DESC, created_at DESC LIMIT ?",
                ((subject, exclude_transaction_id, limit) if exclude_transaction_id
                 else (subject, limit)),
            ).fetchall()

        history: list[Transaction] = []
        for row in reversed(rows):                     # oldest first
            record = dict(zip(("transaction_id", "subject", "amount", *names), row))
            if any(record[field] is None for field in required):
                continue                               # pre-migration row: skipped, never invented
            history.append(Transaction(
                transaction_id=record["transaction_id"],
                subject=record["subject"],
                amount=record["amount"],
                currency=record["currency"],
                beneficiary=record["beneficiary"],
                location=record["location"],
                device_id=record["device_id"],
                merchant_category=record["merchant_category"],
                authentication_method=record["authentication_method"],
                timestamp=record["occurred_at"],
                is_international=bool(record["is_international"]),
                declared_travel_mode=bool(record["declared_travel_mode"]),
                is_emergency_request=bool(record["is_emergency_request"]),
            ))
        return history

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
