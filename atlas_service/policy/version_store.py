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

What this does NOT do, stated rather than implied: it cannot tell a legitimate
new version from a malicious one. Anyone who can write policies/ can still write a
HIGHER-numbered, looser policy, and a rollback made before ATLAS first saw the
real policy is invisible. Closing that needs signed policy updates (the threat
table's "requires user auth + versioning + secure storage for updates"), which is
not built. The bank does not check policy_version independently either.

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

    def active(self, subject: str) -> tuple[int, str] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT version, policy_hash FROM active_policy WHERE subject = ?",
                (subject,)).fetchone()
        return (row[0], row[1]) if row else None

    def close(self) -> None:
        self._conn.close()
