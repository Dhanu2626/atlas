"""Persistence for step-up challenges, frozen contexts and authenticator keys.

Same discipline as atlas_service/device/db.py: low-level and dumb. It stores
and retrieves; it decides nothing. The decision lives in resolver.py, and the
separation is the point -- a storage layer that could quietly decide things is
a storage layer where a bypass can hide.

Two atomicity requirements, both learned from F2's check-then-act bugs:

  * record_failed_attempt() -- incrementing and reading the count must be
    indivisible, or two concurrent failures both see the same count.
  * consume() -- exactly one caller may resolve a given challenge, or the same
    challenge could authorise twice.

Both are single UPDATE ... WHERE statements whose rowcount reports whether this
caller won, never SELECT-then-UPDATE.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path

from contracts import FrozenDecisionContext

#: Wall-clock budget for a customer to answer a challenge. Short on purpose:
#: an outstanding challenge is an outstanding authorisation opportunity.
STEP_UP_EXPIRY_SECONDS = 120

#: How many failed proofs are written to the audit trail per challenge.
#:
#: Until 2026-09-18 this was STEP_UP_MAX_ATTEMPTS = 3, an authorisation budget:
#: the third failure closed the challenge and denied the payment. Reaching it
#: needed no secret -- only the challenge and transaction ids, both shown on the
#: device and sent without TLS -- so anyone who saw them could cancel that
#: payment in three requests, while forging the Ed25519 proof that approves it
#: stayed infeasible. The budget bought no security and sold a denial.
#:
#: A failed proof now costs the customer nothing and changes nothing. This cap
#: only bounds how many failure rows one challenge can add to step_up_events,
#: so a flood cannot grow the database without limit. The count is kept in
#: attempt_count (same column, new meaning) and is never terminal.
STEP_UP_MAX_RECORDED_FAILURES = 10

SCHEMA = """
CREATE TABLE IF NOT EXISTS step_up_challenges (
    challenge_id   TEXT PRIMARY KEY,
    transaction_id TEXT NOT NULL UNIQUE,
    subject        TEXT NOT NULL,
    envelope_hash  TEXT NOT NULL,
    context_json   TEXT NOT NULL,
    issued_at      TEXT NOT NULL,
    expires_at     TEXT NOT NULL,
    attempt_count  INTEGER NOT NULL DEFAULT 0,
    consumed       INTEGER NOT NULL DEFAULT 0,
    outcome        TEXT
);

CREATE TABLE IF NOT EXISTS step_up_authenticators (
    subject     TEXT PRIMARY KEY,
    public_key  TEXT NOT NULL,
    enrolled_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS step_up_events (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    challenge_id   TEXT,
    transaction_id TEXT,
    event          TEXT NOT NULL,
    detail         TEXT,
    occurred_at    TEXT NOT NULL
);
"""


class StepUpStore:
    def __init__(self, db_path: str | Path):
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False, timeout=10.0)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    # --- authenticators ---------------------------------------------------

    def enroll_authenticator(self, subject: str, public_key: str, now: str) -> None:
        """Registers the PUBLIC key of the customer's out-of-band
        authenticator. ATLAS never sees, stores or transports a PIN, an OTP
        secret or a biometric -- only a public key it can verify a signature
        against. That is the whole trust model for this feature."""
        with self._lock:
            self._conn.execute(
                "INSERT INTO step_up_authenticators (subject, public_key, enrolled_at) "
                "VALUES (?,?,?) ON CONFLICT(subject) DO UPDATE SET "
                "public_key=excluded.public_key, enrolled_at=excluded.enrolled_at",
                (subject, public_key, now),
            )
            self._conn.commit()

    def get_authenticator(self, subject: str) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM step_up_authenticators WHERE subject = ?", (subject,)
            ).fetchone()

    # --- challenges -------------------------------------------------------

    def create_challenge(
        self,
        challenge_id: str,
        context: FrozenDecisionContext,
        issued_at: str,
        expires_at: str,
    ) -> bool:
        """Freezes the decision context. Returns False if this transaction
        already has a challenge -- one challenge per transaction, forever, so
        a second STEP_UP for the same id cannot mint fresh attempts."""
        with self._lock:
            try:
                self._conn.execute(
                    "INSERT INTO step_up_challenges "
                    "(challenge_id, transaction_id, subject, envelope_hash, "
                    " context_json, issued_at, expires_at) VALUES (?,?,?,?,?,?,?)",
                    (challenge_id, context.transaction_id, context.subject,
                     context.envelope_hash, context.model_dump_json(),
                     issued_at, expires_at),
                )
                self._conn.commit()
                return True
            except sqlite3.IntegrityError:
                return False

    def get_challenge(self, challenge_id: str) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM step_up_challenges WHERE challenge_id = ?", (challenge_id,)
            ).fetchone()

    def load_context(self, row: sqlite3.Row) -> FrozenDecisionContext:
        """The frozen context, exactly as written. Never rebuilt from live
        data -- that would be the recomputation this design forbids."""
        return FrozenDecisionContext(**json.loads(row["context_json"]))

    def record_failed_attempt(self, challenge_id: str) -> int | None:
        """Atomically counts one failed proof. Returns the count this caller
        got (1-based), or None once STEP_UP_MAX_RECORDED_FAILURES is reached.

        None means "stop writing audit rows for this challenge", never "stop
        accepting proofs": authenticate() carries on verifying, so a customer
        whose earlier attempts failed can still approve. One statement, so two
        concurrent failures cannot both read the same count. The WHERE clause
        is the guard, not a preceding SELECT.
        """
        with self._lock:
            cur = self._conn.execute(
                "UPDATE step_up_challenges SET attempt_count = attempt_count + 1 "
                "WHERE challenge_id = ? AND consumed = 0 AND attempt_count < ?",
                (challenge_id, STEP_UP_MAX_RECORDED_FAILURES),
            )
            self._conn.commit()
            if cur.rowcount == 0:
                return None
            row = self._conn.execute(
                "SELECT attempt_count FROM step_up_challenges WHERE challenge_id = ?",
                (challenge_id,),
            ).fetchone()
            return int(row["attempt_count"])

    def consume(self, challenge_id: str, outcome: str) -> bool:
        """Marks the challenge finished. Exactly one caller wins; every later
        attempt sees consumed=1 and is refused as UNKNOWN_CHALLENGE."""
        with self._lock:
            cur = self._conn.execute(
                "UPDATE step_up_challenges SET consumed = 1, outcome = ? "
                "WHERE challenge_id = ? AND consumed = 0",
                (outcome, challenge_id),
            )
            self._conn.commit()
            return cur.rowcount == 1

    def get_challenge_for_transaction(self, transaction_id: str) -> sqlite3.Row | None:
        """The challenge for one transaction, if any. At most one row:
        transaction_id is UNIQUE -- one challenge per transaction, forever.

        Used by the restart cleanup, which starts from the transactions left
        waiting rather than from the challenges, so that a waiting transaction
        whose challenge is consumed or missing is found too."""
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM step_up_challenges WHERE transaction_id = ?",
                (transaction_id,),
            ).fetchone()

    # --- audit ------------------------------------------------------------

    def record_event(
        self, challenge_id: str | None, transaction_id: str | None,
        event: str, detail: str, now: str,
    ) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO step_up_events "
                "(challenge_id, transaction_id, event, detail, occurred_at) "
                "VALUES (?,?,?,?,?)",
                (challenge_id, transaction_id, event, detail, now),
            )
            self._conn.commit()

    def events_for(self, transaction_id: str) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM step_up_events WHERE transaction_id = ? ORDER BY id",
                (transaction_id,),
            ).fetchall()

    def close(self) -> None:
        with self._lock:
            self._conn.close()
