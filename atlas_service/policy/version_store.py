"""Policy non-rollback, enforced on live requests (2026-09-25).

ARCHITECTURE.md principle 7: "Policy integrity requires versioning + hashing +
non-rollback ... a monotonically increasing version number, plus rejecting any
assertion produced under an older version once a newer one is active." Its
failure-mode table: "Policy rollback detected -> reject."

Until 2026-09-25 only half of that existed. engine.check_rollback() was the
comparison, unit-tested, but nothing remembered which version had been active and
no request ever called it, so replacing policies/<subject>.yaml with an older,
looser file changed every later decision without a word.

This store remembers, per subject, the highest policy version ATLAS has decided
under and the hash of that exact policy. Every deciding request goes through
admit() before anything is persisted:

  * an OLDER version than the one recorded  -> RolledBackPolicyError (reject);
  * the SAME version with a different hash  -> TamperedPolicyError (reject): the
    version number is the thing a rollback check trusts, so a same-numbered file
    with different rules is exactly the attack it would otherwise miss;
  * a NEWER version                         -> recorded, then used;
  * the first policy ever seen for a subject -> recorded (trust on first use).

Since 2026-09-27 every policy must also carry its owner's signature (signing.py),
and this file holds the enrolled owner keys (table policy_owners). Together: a
forged or edited policy -- including a HIGHER-numbered, looser one -- fails the
signature; an old policy the owner really signed passes the signature and is
refused here as a rollback. What remains trusted is the first enrolment of an
owner key, which is a deliberate operator step (scripts/policy_key.py enroll).
The bank does not check policy_version independently.

The state lives in its own file, atlas_policy_state.db, so adding it migrates no
existing database.
"""

from __future__ import annotations

import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from atlas_service.policy.engine import RolledBackPolicyError, check_rollback

SCHEMA = """
CREATE TABLE IF NOT EXISTS active_policy (
    subject      TEXT PRIMARY KEY,
    version      INTEGER NOT NULL,
    policy_hash  TEXT NOT NULL,
    recorded_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS policy_owners (
    subject      TEXT PRIMARY KEY,
    public_key   TEXT NOT NULL,
    enrolled_at  TEXT NOT NULL
);
"""


@dataclass(frozen=True)
class TamperedPolicyError(Exception):
    """The same version number, but not the same policy."""

    subject: str
    version: int

    def __str__(self) -> str:
        return (f"policy for {self.subject} claims version {self.version}, which is already "
                f"active with different content")


class PolicyStateUnavailableError(Exception):
    """The version store could not be read or written. Without it a rollback
    cannot be ruled out, so the caller must refuse rather than decide."""


class PolicyVersionStore:
    def __init__(self, db_path: str | Path):
        try:
            self._conn = sqlite3.connect(str(db_path), check_same_thread=False, timeout=10.0,
                                         isolation_level=None)
            self._conn.executescript(SCHEMA)
        except sqlite3.Error as exc:
            raise PolicyStateUnavailableError(str(exc)) from exc
        self._lock = threading.RLock()

    def admit(self, subject: str, version: int, policy_hash: str, *, record: bool = True) -> None:
        """Raises unless this policy may be decided under. With record=False
        (the read-only /evaluate path) nothing is written, and a newer version
        is simply allowed through without becoming the recorded one."""
        with self._lock:
            try:
                self._conn.execute("BEGIN IMMEDIATE")
                try:
                    row = self._conn.execute(
                        "SELECT version, policy_hash FROM active_policy WHERE subject = ?",
                        (subject,)).fetchone()
                    seen_version, seen_hash = (row[0], row[1]) if row else (None, None)
                    check_rollback(subject, seen_version, version)
                    if seen_version == version and seen_hash != policy_hash:
                        raise TamperedPolicyError(subject, version)
                    if record and (seen_version is None or version > seen_version):
                        self._conn.execute(
                            "INSERT INTO active_policy (subject, version, policy_hash, recorded_at) "
                            "VALUES (?,?,?,?) ON CONFLICT(subject) DO UPDATE SET "
                            "version=excluded.version, policy_hash=excluded.policy_hash, "
                            "recorded_at=excluded.recorded_at",
                            (subject, version, policy_hash, datetime.now(timezone.utc).isoformat()))
                    self._conn.execute("COMMIT")
                except BaseException:
                    self._conn.execute("ROLLBACK")
                    raise
            except (RolledBackPolicyError, TamperedPolicyError):
                raise
            except sqlite3.Error as exc:
                raise PolicyStateUnavailableError(str(exc)) from exc

    # ---- policy owners (signing.py, 2026-09-27) -----------------------------------

    def enroll_owner(self, subject: str, public_key_hex: str, *, replace: bool = False) -> None:
        """Records the public key whose signature a subject's policy must carry.
        Changing an enrolled key is refused unless `replace` is passed: a silent
        swap would be exactly the attack signing exists to stop."""
        bytes.fromhex(public_key_hex)                       # must be hex
        if len(public_key_hex) != 64:
            raise ValueError("an Ed25519 public key is 32 bytes (64 hex characters)")
        with self._lock:
            try:
                row = self._conn.execute("SELECT public_key FROM policy_owners WHERE subject = ?",
                                         (subject,)).fetchone()
                if row and row[0] != public_key_hex and not replace:
                    raise ValueError(f"{subject} already has a different enrolled policy owner; "
                                     f"pass replace=True to change it deliberately")
                self._conn.execute(
                    "INSERT INTO policy_owners (subject, public_key, enrolled_at) VALUES (?,?,?) "
                    "ON CONFLICT(subject) DO UPDATE SET public_key=excluded.public_key, "
                    "enrolled_at=excluded.enrolled_at",
                    (subject, public_key_hex, datetime.now(timezone.utc).isoformat()))
            except sqlite3.Error as exc:
                raise PolicyStateUnavailableError(str(exc)) from exc

    def owner_key(self, subject: str) -> str | None:
        with self._lock:
            try:
                row = self._conn.execute("SELECT public_key FROM policy_owners WHERE subject = ?",
                                         (subject,)).fetchone()
            except sqlite3.Error as exc:
                raise PolicyStateUnavailableError(str(exc)) from exc
        return row[0] if row else None

    def active(self, subject: str) -> tuple[int, str] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT version, policy_hash FROM active_policy WHERE subject = ?",
                (subject,)).fetchone()
        return (row[0], row[1]) if row else None

    def close(self) -> None:
        self._conn.close()
