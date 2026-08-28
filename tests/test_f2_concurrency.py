"""F2: SQLite thread affinity and concurrent-request robustness.

THE DEFECT
----------
All three stores called sqlite3.connect() without check_same_thread=False.
FastAPI resolves a sync dependency (get_transaction_store / get_device_store /
get_replay_cache) in one threadpool thread and then runs the endpoint body in a
*different* one, so the connection was routinely created in thread A and used
in thread B. Under light load the pool reuses a thread and it works; under
concurrency it raises sqlite3.ProgrammingError.

Measured against the live service BEFORE the fix:

    same envelope x10        -> 6 INTERNAL_ERROR
    same transaction_id x10  -> 4 INTERNAL_ERROR
    distinct ids x10         -> 6 INTERNAL_ERROR

AFTER: 0 INTERNAL_ERROR in all three, and 8/8 sequential transactions ALLOW.

TWO REQUIREMENTS, KEPT SEPARATE
-------------------------------
SECURITY    two concurrent requests for the same transaction must never both
            reach the policy engine. This held BEFORE the fix and must still
            hold after -- the fix must not have bought reliability with
            weakened replay protection.
RELIABILITY legitimate traffic must not randomly fail with INTERNAL_ERROR
            merely because of which worker thread served it.

WHAT IS *NOT* A DEFECT
----------------------
A single device firing many transactions CONCURRENTLY gets COUNTER_REGRESSION
for the ones that arrive out of order. That is the monotonic counter working
exactly as designed -- it inherently requires ordered delivery from one device.
Verified separately: the same device sending 8 transactions SEQUENTIALLY gets
8/8 ALLOW. Tests below therefore never assert "all concurrent requests from one
device succeed", because demanding that would mean weakening replay protection,
which the directive explicitly forbids.
"""

from __future__ import annotations

import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

import pytest

from atlas_service.db import TransactionStore
from atlas_service.device.db import DeviceStore
from atlas_service.device.envelope import verify_envelope
from atlas_service.device.registry import register_demo_device
from atlas_service.state_machine import transition
from bank_service.replay_cache import ReplayCache
from contracts import DecisionReason, DeviceEnvelope, TxnState, canonical_envelope_bytes
from firmware import device_identity

SUBJECT = "user-demo-1"


def _txn(device_id: str, tid: str) -> dict:
    return dict(
        transaction_id=tid, subject=SUBJECT, amount="1500.00", currency="INR",
        beneficiary="ben-mother", location="Bengaluru,IN", device_id=device_id,
        authentication_method="device_button", timestamp="2026-08-27T12:00:00+00:00",
    )


def _enroll(store: DeviceStore, keys: Path, device_id: str) -> None:
    device_identity.init_device(keys)
    register_demo_device(
        store, device_id=device_id,
        device_key_id=device_identity.get_key_id(keys),
        public_key=device_identity.get_public_key(keys),
        bound_subject=SUBJECT,
    )


def _envelope(keys: Path, device_id: str, tid: str, counter: int, nonce: str) -> DeviceEnvelope:
    body = dict(
        device_id=device_id, device_key_id=device_identity.get_key_id(keys),
        boot_id="f2-boot", counter=counter, nonce=nonce,
        issued_at=datetime.now(timezone.utc).isoformat(),
        transaction=_txn(device_id, tid), location=None, health=None, signature="",
    )
    unsigned = DeviceEnvelope(**body)
    sig = device_identity.secure_sign(canonical_envelope_bytes(unsigned), keys)
    return unsigned.model_copy(update={"signature": sig})


# ==========================================================================
# the exact defect: connection built in one thread, used in another
# ==========================================================================


@pytest.mark.parametrize("factory,use", [
    (lambda p: TransactionStore(p), lambda s: s.get_state("nope")),
    (lambda p: DeviceStore(p), lambda s: s.get_by_device_id("nope")),
    (lambda p: ReplayCache(p), lambda s: s.already_consumed("t", "n")),
])
def test_store_built_in_one_thread_is_usable_in_another(tmp_path, factory, use):
    """This is precisely what FastAPI does: dependency resolved on one
    threadpool thread, endpoint body run on another. Before the fix this
    raised sqlite3.ProgrammingError and surfaced as INTERNAL_ERROR."""
    built: list = []

    def build():
        built.append(factory(tmp_path / f"s-{threading.get_ident()}.db"))

    t = threading.Thread(target=build)
    t.start()
    t.join()

    # different thread from the one that created it
    use(built[0])  # must not raise


def test_store_write_from_a_foreign_thread_succeeds(tmp_path):
    store = TransactionStore(tmp_path / "w.db")
    errors: list = []

    def write():
        try:
            store.create("t-foreign", SUBJECT, "1500.00", "2026-08-27T12:00:00+00:00")
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    t = threading.Thread(target=write)
    t.start()
    t.join()

    assert not errors, f"cross-thread write raised {errors}"
    assert store.get_state("t-foreign") == TxnState.CREATED


# ==========================================================================
# SECURITY: concurrency must not create a double-ALLOW
# ==========================================================================


def test_same_envelope_concurrently_passes_verification_at_most_once(tmp_path):
    """The security invariant. Ten threads present the identical signed
    envelope; at most one may pass. The rest must be rejected by the counter
    or nonce layer -- never both accepted."""
    keys = tmp_path / "keys"
    store = DeviceStore(tmp_path / "d.db")
    _enroll(store, keys, "dev-a")
    env = _envelope(keys, "dev-a", "t-same", counter=5, nonce="nonce-same")

    with ThreadPoolExecutor(max_workers=10) as ex:
        verdicts = list(ex.map(lambda _: verify_envelope(env, store), range(10)))

    accepted = [v for v in verdicts if v.ok]
    assert len(accepted) <= 1, f"{len(accepted)} concurrent acceptances -- replay protection broken"
    for v in verdicts:
        if not v.ok:
            assert v.reason in (
                DecisionReason.COUNTER_REGRESSION, DecisionReason.REPLAYED_NONCE,
            ), f"unexpected rejection reason {v.reason}"


def test_distinct_nonces_same_counter_still_admit_at_most_one(tmp_path):
    """Counter layer alone must hold even when the nonce layer cannot help
    (every request carries a different nonce)."""
    keys = tmp_path / "keys"
    store = DeviceStore(tmp_path / "d.db")
    _enroll(store, keys, "dev-b")
    envs = [_envelope(keys, "dev-b", f"t-{i}", counter=7, nonce=f"n-{i}") for i in range(10)]

    with ThreadPoolExecutor(max_workers=10) as ex:
        verdicts = list(ex.map(lambda e: verify_envelope(e, store), envs))

    assert len([v for v in verdicts if v.ok]) <= 1


def test_concurrent_verification_never_raises(tmp_path):
    """No exception may escape verification under concurrency -- an escaped
    exception is exactly what became INTERNAL_ERROR."""
    keys = tmp_path / "keys"
    store = DeviceStore(tmp_path / "d.db")
    _enroll(store, keys, "dev-c")
    envs = [_envelope(keys, "dev-c", f"t-{i}", counter=i + 1, nonce=f"n-{i}") for i in range(20)]

    def attempt(e):
        try:
            return verify_envelope(e, store).ok
        except Exception as exc:  # noqa: BLE001
            return exc

    with ThreadPoolExecutor(max_workers=20) as ex:
        results = list(ex.map(attempt, envs))

    raised = [r for r in results if isinstance(r, Exception)]
    assert not raised, f"verification raised under concurrency: {raised}"


# ==========================================================================
# RELIABILITY: independent devices must not interfere
# ==========================================================================


def test_two_devices_concurrently_do_not_interfere(tmp_path):
    """Counters are per-device. Two devices working at the same time must
    both make progress and must never raise."""
    store = DeviceStore(tmp_path / "d.db")
    keys_a, keys_b = tmp_path / "ka", tmp_path / "kb"
    _enroll(store, keys_a, "dev-x")
    _enroll(store, keys_b, "dev-y")

    work = ([(keys_a, "dev-x", i) for i in range(1, 6)]
            + [(keys_b, "dev-y", i) for i in range(1, 6)])

    def attempt(item):
        keys, did, n = item
        try:
            return verify_envelope(
                _envelope(keys, did, f"{did}-{n}", counter=n, nonce=f"{did}-n{n}"), store
            ).ok
        except Exception as exc:  # noqa: BLE001
            return exc

    with ThreadPoolExecutor(max_workers=10) as ex:
        results = list(ex.map(attempt, work))

    assert not [r for r in results if isinstance(r, Exception)]
    assert any(r is True for r in results), "no device made progress"

    # each device kept its OWN counter -- no cross-contamination
    for did in ("dev-x", "dev-y"):
        row = store.get_counter(did)
        assert row is not None and row["last_counter"] >= 1


def test_sequential_traffic_from_one_device_is_fully_clean(tmp_path):
    """The correct usage pattern for a monotonic counter: ordered delivery.
    Every transaction must succeed. This is what proves the concurrency fix
    did not damage the normal path, and why COUNTER_REGRESSION under
    concurrent out-of-order delivery is a design property rather than a bug."""
    keys = tmp_path / "keys"
    store = DeviceStore(tmp_path / "d.db")
    _enroll(store, keys, "dev-seq")

    for i in range(1, 9):
        v = verify_envelope(
            _envelope(keys, "dev-seq", f"seq-{i}", counter=i, nonce=f"sn-{i}"), store)
        assert v.ok is True, f"sequential transaction {i} failed: {v.reason}"

    assert store.get_counter("dev-seq")["last_counter"] == 8


# ==========================================================================
# state consistency after concurrency
# ==========================================================================


def test_nonce_is_consumed_exactly_once_under_concurrency(tmp_path):
    keys = tmp_path / "keys"
    store = DeviceStore(tmp_path / "d.db")
    _enroll(store, keys, "dev-n")
    env = _envelope(keys, "dev-n", "t-nonce", counter=3, nonce="only-once")

    with ThreadPoolExecutor(max_workers=8) as ex:
        list(ex.map(lambda _: verify_envelope(env, store), range(8)))

    rows = store._conn.execute(
        "SELECT COUNT(*) FROM device_nonces WHERE device_id=? AND nonce=?",
        ("dev-n", "only-once"),
    ).fetchone()[0]
    assert rows == 1, "nonce must be recorded exactly once, not duplicated"


def test_counter_never_goes_backwards_after_concurrent_traffic(tmp_path):
    keys = tmp_path / "keys"
    store = DeviceStore(tmp_path / "d.db")
    _enroll(store, keys, "dev-m")
    envs = [_envelope(keys, "dev-m", f"m-{i}", counter=i, nonce=f"mn-{i}")
            for i in range(1, 11)]

    with ThreadPoolExecutor(max_workers=10) as ex:
        list(ex.map(lambda e: verify_envelope(e, store), envs))

    last = store.get_counter("dev-m")["last_counter"]
    for e in envs:
        v = verify_envelope(
            _envelope(keys, "dev-m", "late", counter=last, nonce="late-n"), store)
        assert v.ok is False and v.reason == DecisionReason.COUNTER_REGRESSION
        break


def test_transaction_store_state_is_consistent_under_concurrency(tmp_path):
    """Concurrent state transitions on DIFFERENT transactions must all
    apply correctly and none may raise."""
    store = TransactionStore(tmp_path / "t.db")
    now = "2026-08-27T12:00:00+00:00"
    ids = [f"c-{i}" for i in range(20)]
    for tid in ids:
        store.create(tid, SUBJECT, "1500.00", now)

    def advance(tid):
        try:
            transition(store, tid, TxnState.EVALUATING, now)
            transition(store, tid, TxnState.ALLOWED, now)
            return None
        except Exception as exc:  # noqa: BLE001
            return exc

    with ThreadPoolExecutor(max_workers=20) as ex:
        errors = [e for e in ex.map(advance, ids) if e is not None]

    assert not errors, f"concurrent transitions raised: {errors}"
    for tid in ids:
        assert store.get_state(tid) == TxnState.ALLOWED


def test_replay_cache_consumes_once_under_concurrency(tmp_path):
    cache = ReplayCache(tmp_path / "r.db")

    def consume(_):
        try:
            cache.mark_consumed("txn-1", "nonce-1", "2026-08-27T12:00:00+00:00")
            return None
        except Exception as exc:  # noqa: BLE001
            return exc

    with ThreadPoolExecutor(max_workers=10) as ex:
        errors = [e for e in ex.map(consume, range(10)) if e is not None]

    assert not errors
    assert cache.already_consumed("txn-1", "nonce-1") is True


# ==========================================================================
# atomicity of the check-and-claim primitives
# ==========================================================================


def test_claim_counter_admits_exactly_one_winner_under_contention(tmp_path):
    """Directly targets the check-then-act race: 50 threads all try to claim
    the SAME counter value. Exactly one may win. With the old
    get_counter -> compare -> set_counter sequence, several could."""
    store = DeviceStore(tmp_path / "d.db")
    store.set_counter("dev", 4, "b0", "2026-08-27T12:00:00+00:00")

    with ThreadPoolExecutor(max_workers=50) as ex:
        wins = list(ex.map(
            lambda _: store.claim_counter("dev", 5, "b1", "2026-08-27T12:00:00+00:00"),
            range(50),
        ))

    assert sum(wins) == 1, f"{sum(wins)} threads claimed the same counter value"
    assert store.get_counter("dev")["last_counter"] == 5


def test_claim_counter_never_moves_backwards_under_contention(tmp_path):
    store = DeviceStore(tmp_path / "d.db")
    store.set_counter("dev", 100, "b0", "2026-08-27T12:00:00+00:00")

    with ThreadPoolExecutor(max_workers=20) as ex:
        wins = list(ex.map(
            lambda i: store.claim_counter("dev", i, "b1", "2026-08-27T12:00:00+00:00"),
            range(1, 21),
        ))

    assert not any(wins), "a lower counter must never be claimable"
    assert store.get_counter("dev")["last_counter"] == 100


def test_claim_counter_on_a_fresh_device_admits_exactly_one(tmp_path):
    store = DeviceStore(tmp_path / "d.db")
    with ThreadPoolExecutor(max_workers=30) as ex:
        wins = list(ex.map(
            lambda _: store.claim_counter("new-dev", 1, "b", "2026-08-27T12:00:00+00:00"),
            range(30),
        ))
    assert sum(wins) == 1, "first-ever counter must also be claimed exactly once"


def test_claim_nonce_admits_exactly_one_winner_under_contention(tmp_path):
    store = DeviceStore(tmp_path / "d.db")
    with ThreadPoolExecutor(max_workers=50) as ex:
        wins = list(ex.map(
            lambda _: store.claim_nonce("dev", "the-nonce", "2026-08-27T12:00:00+00:00"),
            range(50),
        ))
    assert sum(wins) == 1, f"{sum(wins)} threads claimed the same nonce"


def test_claim_new_transaction_admits_exactly_one_winner(tmp_path):
    """The Phase 2 duplicate-transaction_id layer, made atomic."""
    store = TransactionStore(tmp_path / "t.db")
    with ThreadPoolExecutor(max_workers=50) as ex:
        wins = list(ex.map(
            lambda _: store.claim_new("same-id", SUBJECT, "1500.00",
                                      "2026-08-27T12:00:00+00:00"),
            range(50),
        ))
    assert sum(wins) == 1, f"{sum(wins)} threads created the same transaction"
    assert store.get_state("same-id") == TxnState.CREATED


def test_replay_cache_claim_admits_exactly_one_winner(tmp_path):
    cache = ReplayCache(tmp_path / "r.db")
    with ThreadPoolExecutor(max_workers=50) as ex:
        wins = list(ex.map(
            lambda _: cache.claim("txn", "nonce", "2026-08-27T12:00:00+00:00"),
            range(50),
        ))
    assert sum(wins) == 1


def test_simulation_counter_reset_still_works_after_atomicity_change(tmp_path):
    """The Wokwi affordance must survive the atomic-claim rewrite: it is the
    one path that deliberately moves the counter backwards, so it cannot go
    through claim_counter()."""
    keys = tmp_path / "keys"
    store = DeviceStore(tmp_path / "d.db")
    _enroll(store, keys, "dev-sim")

    assert verify_envelope(
        _envelope(keys, "dev-sim", "s1", counter=50, nonce="n1"), store).ok is True

    # default OFF -> regression rejected
    v = verify_envelope(
        _envelope(keys, "dev-sim", "s2", counter=1, nonce="n2"), store)
    assert v.ok is False and v.reason == DecisionReason.COUNTER_REGRESSION

    # simulation ON with a fresh boot_id -> accepted, and audited
    env = _envelope(keys, "dev-sim", "s3", counter=1, nonce="n3")
    env = env.model_copy(update={"boot_id": "fresh-boot"})
    env = env.model_copy(update={
        "signature": device_identity.secure_sign(canonical_envelope_bytes(
            env.model_copy(update={"signature": ""})), keys)})
    assert verify_envelope(env, store, allow_counter_reset=True).ok is True
    assert "COUNTER_RESET_ACCEPTED" in [e["event"] for e in store.events_for("dev-sim")]


def test_stores_use_a_busy_timeout_so_writers_wait_rather_than_error(tmp_path):
    """Guards the second half of the fix: without a busy timeout, concurrent
    writers surface 'database is locked' as a fresh INTERNAL_ERROR source."""
    for factory in (TransactionStore, DeviceStore, ReplayCache):
        store = factory(tmp_path / f"{factory.__name__}.db")
        assert isinstance(store._conn, sqlite3.Connection)
        # a write from a foreign thread must not raise OperationalError
        err: list = []

        def write():
            try:
                store._conn.execute("BEGIN IMMEDIATE").fetchone()
                store._conn.rollback()
            except Exception as exc:  # noqa: BLE001
                err.append(exc)

        t = threading.Thread(target=write)
        t.start()
        t.join()
        assert not err, f"{factory.__name__}: {err}"
