"""Device registry storage (Phase 3.1).

Separate SQLite file from atlas_transactions.db on purpose: transaction state
and device trust have different lifetimes, different backup requirements, and
different blast radius if corrupted. Same deliberately-dumb split as
atlas_service/db.py -- this module persists and retrieves, it never decides
whether a device should be trusted. That is registry.py's job, and the
verification pipeline's.

NO PRIVATE KEY IS EVER STORED HERE. `public_key` is public material by
definition; device private keys exist only on the device.

Thread safety (F2): see atlas_service/db.py for the full reasoning behind
check_same_thread=False plus the lock. Short version -- FastAPI resolves a sync
dependency on one threadpool thread and runs the endpoint body on another, and
sqlite3's default thread guard turned that into INTERNAL_ERROR under load.
"""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    device_id              TEXT PRIMARY KEY,
    device_key_id          TEXT NOT NULL UNIQUE,
    public_key             TEXT NOT NULL,
    bound_subject          TEXT NOT NULL,
    status                 TEXT NOT NULL,
    firmware_version       TEXT,
    firmware_hash          TEXT,
    min_firmware_version   TEXT,
    registered_lat         REAL,
    registered_lon         REAL,
    geofence_radius_m      INTEGER,
    secure_element_present INTEGER NOT NULL DEFAULT 0,
    provisioning_mode      TEXT NOT NULL DEFAULT 'DEMO',
    created_at             TEXT NOT NULL,
    last_seen_at           TEXT,
    revoked_at             TEXT,
    revocation_reason      TEXT
);

CREATE TABLE IF NOT EXISTS device_counters (
    device_id     TEXT PRIMARY KEY,
    last_counter  INTEGER NOT NULL,
    last_boot_id  TEXT,
    updated_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS device_nonces (
    device_id   TEXT NOT NULL,
    nonce       TEXT NOT NULL,
    consumed_at TEXT NOT NULL,
    PRIMARY KEY (device_id, nonce)
);

CREATE TABLE IF NOT EXISTS device_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id   TEXT NOT NULL,
    event       TEXT NOT NULL,
    detail      TEXT,
    occurred_at TEXT NOT NULL
);
"""


class DeviceStore:
    def __init__(self, db_path: str | Path):
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False, timeout=10.0)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    # --- devices ----------------------------------------------------------

    def insert_device(self, **fields: object) -> None:
        columns = ", ".join(fields)
        placeholders = ", ".join("?" for _ in fields)
        with self._lock:
            self._conn.execute(
                f"INSERT INTO devices ({columns}) VALUES ({placeholders})",
                tuple(fields.values()),
            )
            self._conn.commit()

    def get_by_key_id(self, device_key_id: str) -> sqlite3.Row | None:
        """Lookup is by KEY id, not device_id: the key is the identity, and
        device_id is only a human-readable label that gets cross-checked
        after the signature verifies."""
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM devices WHERE device_key_id = ?", (device_key_id,)
            ).fetchone()

    def get_by_device_id(self, device_id: str) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM devices WHERE device_id = ?", (device_id,)
            ).fetchone()

    def list_devices(self) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM devices ORDER BY created_at"
            ).fetchall()

    def set_status(self, device_id: str, status: str, now: str, reason: str | None = None) -> None:
        revoked_at = now if status == "REVOKED" else None
        with self._lock:
            self._conn.execute(
                "UPDATE devices SET status = ?, revoked_at = ?, revocation_reason = ? "
                "WHERE device_id = ?",
                (status, revoked_at, reason, device_id),
            )
            self._conn.commit()

    def touch_last_seen(self, device_id: str, now: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE devices SET last_seen_at = ? WHERE device_id = ?", (now, device_id)
            )
            self._conn.commit()

    # --- monotonic counter ------------------------------------------------

    def get_counter(self, device_id: str) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM device_counters WHERE device_id = ?", (device_id,)
            ).fetchone()

    def set_counter(self, device_id: str, counter: int, boot_id: str, now: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO device_counters (device_id, last_counter, last_boot_id, updated_at) "
                "VALUES (?, ?, ?, ?) "
                "ON CONFLICT(device_id) DO UPDATE SET "
                "last_counter = excluded.last_counter, "
                "last_boot_id = excluded.last_boot_id, "
                "updated_at = excluded.updated_at",
                (device_id, counter, boot_id, now),
            )
            self._conn.commit()

    def claim_counter(self, device_id: str, counter: int, boot_id: str, now: str) -> bool:
        """Atomically advance the counter, but ONLY if it strictly increases.

        Returns True if this caller won the slot, False if another concurrent
        caller already claimed this counter value or a higher one.

        F2: the read-then-write sequence in envelope.py (get_counter, decide,
        set_counter) is not atomic on its own. Two threads could both read
        `last=4`, both accept `counter=5`, and both write. The lock below plus
        the conditional UPDATE make the check-and-advance a single indivisible
        step, so exactly one caller can ever claim a given counter value.
        """
        with self._lock:
            cur = self._conn.execute(
                "SELECT last_counter FROM device_counters WHERE device_id = ?", (device_id,)
            ).fetchone()
            if cur is None:
                self._conn.execute(
                    "INSERT INTO device_counters "
                    "(device_id, last_counter, last_boot_id, updated_at) VALUES (?, ?, ?, ?)",
                    (device_id, counter, boot_id, now),
                )
                self._conn.commit()
                return True
            if counter <= cur["last_counter"]:
                return False
            self._conn.execute(
                "UPDATE device_counters SET last_counter = ?, last_boot_id = ?, updated_at = ? "
                "WHERE device_id = ? AND last_counter < ?",
                (counter, boot_id, now, device_id, counter),
            )
            changed = self._conn.total_changes
            self._conn.commit()
            return changed > 0

    # --- nonces -----------------------------------------------------------

    def nonce_seen(self, device_id: str, nonce: str) -> bool:
        with self._lock:
            return self._conn.execute(
                "SELECT 1 FROM device_nonces WHERE device_id = ? AND nonce = ?",
                (device_id, nonce),
            ).fetchone() is not None

    def claim_nonce(self, device_id: str, nonce: str, now: str) -> bool:
        """Atomically consume a nonce. Returns True only for the caller that
        actually inserted it -- a concurrent duplicate gets False.

        F2: `nonce_seen()` followed by `consume_nonce()` is a check-then-act
        race. INSERT OR IGNORE plus rowcount makes claiming indivisible, so
        exactly one of N concurrent presentations of the same nonce wins.
        """
        with self._lock:
            cur = self._conn.execute(
                "INSERT OR IGNORE INTO device_nonces (device_id, nonce, consumed_at) "
                "VALUES (?, ?, ?)",
                (device_id, nonce, now),
            )
            self._conn.commit()
            return cur.rowcount == 1

    def consume_nonce(self, device_id: str, nonce: str, now: str) -> None:
        """INSERT OR IGNORE so two racing requests for the same nonce do not
        crash on the unique constraint -- the loser simply finds it already
        consumed, which is the correct outcome."""
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO device_nonces (device_id, nonce, consumed_at) "
                "VALUES (?, ?, ?)",
                (device_id, nonce, now),
            )
            self._conn.commit()

    # --- audit ------------------------------------------------------------

    def record_event(self, device_id: str, event: str, detail: str, now: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO device_events (device_id, event, detail, occurred_at) "
                "VALUES (?, ?, ?, ?)",
                (device_id, event, detail, now),
            )
            self._conn.commit()

    def events_for(self, device_id: str) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM device_events WHERE device_id = ? ORDER BY id", (device_id,)
            ).fetchall()

    def close(self) -> None:
        with self._lock:
            self._conn.close()
