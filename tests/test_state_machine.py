"""Step 4: persistent state + reconciliation. The one test that matters most
(test_restart_after_submitted_reconciles_to_confirmed) uses a real SQLite file
and a genuinely fresh TransactionStore object, not the same Python object
reused — that's what actually simulates a process restart rather than just
asserting the same thing an in-memory dict would.

Step 6 additions: /verify now takes a real SignedAssertion (see
tests/test_bank_boundary.py's module docstring for why), so the restart/
reconcile tests here build one via the same build_signed_assertion()
production function /transact itself uses. Two new tests cover the two real
findings Step 6 surfaced: the previously-unhandled "bank rejected, discovered
via reconciliation" status, and the direct SUBMITTED -> FAILED transition a
synchronous bank rejection needs.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from atlas_service.db import TransactionStore
from atlas_service.main import build_signed_assertion
from atlas_service.state_machine import (
    NEEDS_RECONCILIATION,
    InvalidTransitionError,
    reconcile,
    transition,
)
from bank_service.main import app as bank_app
from contracts import Decision, PolicyDecision, Transaction, TxnState
from tests.conftest import wire_bank_app_to_keys

NOW = "2026-08-28T12:00:00+00:00"


@pytest.fixture
def db_path(tmp_path):
    return tmp_path / "atlas.db"


@pytest.fixture
def keys_dir(tmp_path) -> Path:
    return tmp_path / "atlas-keys"


@pytest.fixture(autouse=True)
def _wire_bank(keys_dir, tmp_path):
    wire_bank_app_to_keys(keys_dir, tmp_path / "replay.db")
    yield
    bank_app.dependency_overrides.clear()


@pytest.fixture
def bank_client() -> TestClient:
    return TestClient(bank_app)


def _signed(keys_dir: Path, *, subject: str, amount: str, transaction_id: str):
    """Same production path /transact uses to build a real signed assertion
    -- minimal Transaction fields, since only subject/amount/transaction_id
    matter to any test here."""
    tx = Transaction(
        transaction_id=transaction_id,
        subject=subject,
        amount=amount,
        currency="INR",
        beneficiary="ben-1",
        location="Bengaluru,IN",
        device_id="device-primary-01",
        authentication_method="pin",
        timestamp="2026-08-28T12:00:00+00:00",
    )
    policy_decision = PolicyDecision(
        transaction_id=transaction_id, decision=Decision.ALLOW,
        policy_version=1, policy_hash="test-hash",
    )
    return build_signed_assertion(tx, policy_decision, keys_dir=keys_dir)


# --- basic transition correctness -------------------------------------------


def test_full_allow_path_is_valid(db_path):
    store = TransactionStore(db_path)
    store.create("tx-1", "user-demo-1", "1000.00", NOW)
    for state in [TxnState.EVALUATING, TxnState.ALLOWED, TxnState.SIGNED,
                  TxnState.SUBMITTED, TxnState.CONFIRMED]:
        transition(store, "tx-1", state, NOW)
    assert store.get_state("tx-1") == TxnState.CONFIRMED


def test_full_deny_path_is_valid(db_path):
    store = TransactionStore(db_path)
    store.create("tx-2", "user-demo-1", "1000.00", NOW)
    transition(store, "tx-2", TxnState.EVALUATING, NOW)
    transition(store, "tx-2", TxnState.DENIED, NOW)
    assert store.get_state("tx-2") == TxnState.DENIED


def test_full_bank_rejects_after_submission_path_is_valid(db_path):
    """Step 6: a synchronous bank rejection (the answer arrives in the same
    request, nothing to reconcile) must be representable as a direct
    SUBMITTED -> FAILED transition, not just reachable via
    RECONCILING -> FAILED."""
    store = TransactionStore(db_path)
    store.create("tx-5", "user-demo-1", "1000.00", NOW)
    for state in [TxnState.EVALUATING, TxnState.ALLOWED, TxnState.SIGNED,
                  TxnState.SUBMITTED, TxnState.FAILED]:
        transition(store, "tx-5", state, NOW)
    assert store.get_state("tx-5") == TxnState.FAILED


# --- deliberate edge cases: invalid transitions -----------------------------


def test_cannot_skip_evaluating(db_path):
    """CREATED -> ALLOWED directly is not a legal transition, even though the
    end state 'sounds fine' -- the whole point of the state machine is that
    every transaction actually gets evaluated."""
    store = TransactionStore(db_path)
    store.create("tx-3", "user-demo-1", "1000.00", NOW)
    with pytest.raises(InvalidTransitionError):
        transition(store, "tx-3", TxnState.ALLOWED, NOW)


@pytest.mark.parametrize("terminal", [TxnState.DENIED, TxnState.CONFIRMED, TxnState.FAILED])
def test_cannot_leave_terminal_states(db_path, terminal):
    store = TransactionStore(db_path)
    tx_id = f"tx-terminal-{terminal.value}"
    store.create(tx_id, "user-demo-1", "1000.00", NOW)
    transition(store, tx_id, TxnState.EVALUATING, NOW)
    if terminal == TxnState.DENIED:
        transition(store, tx_id, TxnState.DENIED, NOW)
    else:
        transition(store, tx_id, TxnState.ALLOWED, NOW)
        transition(store, tx_id, TxnState.SIGNED, NOW)
        transition(store, tx_id, TxnState.SUBMITTED, NOW)
        if terminal == TxnState.CONFIRMED:
            transition(store, tx_id, TxnState.CONFIRMED, NOW)
        else:
            transition(store, tx_id, TxnState.UNKNOWN, NOW)
            transition(store, tx_id, TxnState.RECONCILING, NOW)
            transition(store, tx_id, TxnState.FAILED, NOW)

    with pytest.raises(InvalidTransitionError):
        transition(store, tx_id, TxnState.EVALUATING, NOW)


def test_transitioning_unknown_transaction_id_raises(db_path):
    store = TransactionStore(db_path)
    with pytest.raises(InvalidTransitionError):
        transition(store, "never-created", TxnState.EVALUATING, NOW)


# --- idempotent creation -----------------------------------------------------


def test_create_twice_is_a_no_op_not_an_error(db_path):
    store = TransactionStore(db_path)
    store.create("tx-4", "user-demo-1", "1000.00", NOW)
    transition(store, "tx-4", TxnState.EVALUATING, NOW)
    transition(store, "tx-4", TxnState.ALLOWED, NOW)
    # a client retrying its own "create" request must not reset progress
    store.create("tx-4", "user-demo-1", "1000.00", NOW)
    assert store.get_state("tx-4") == TxnState.ALLOWED


# --- the actual point of this step: kill mid-transaction, restart, reconcile


def test_restart_after_submitted_reconciles_to_confirmed(db_path, bank_client, keys_dir):
    """Day 3's Scenario C exactly: the bank processed the transaction, but the
    confirmation never made it back before the process died. A fresh store
    object (simulated restart) must find it, recognize it needs
    reconciliation, and resolve it correctly -- without resubmitting."""
    store = TransactionStore(db_path)
    store.create("tx-restart-1", "user-demo-1", "1000.00", NOW)
    for state in [TxnState.EVALUATING, TxnState.ALLOWED, TxnState.SIGNED, TxnState.SUBMITTED]:
        transition(store, "tx-restart-1", state, NOW)

    # the bank DID process it -- simulated via the real /verify endpoint,
    # exactly as atlas_service would have called it before "crashing"
    signed = _signed(keys_dir, subject="user-demo-1", amount="1000.00", transaction_id="tx-restart-1")
    r = bank_client.post("/verify", json=signed.model_dump(mode="json"))
    assert r.json()["approved"] is True
    store.close()  # the "crash" -- this Python object is gone

    # "restart": a brand new store object, same file on disk
    fresh_store = TransactionStore(db_path)
    stuck = fresh_store.find_in_states(NEEDS_RECONCILIATION)
    assert "tx-restart-1" in stuck, "restart must find the stuck transaction, not lose it"

    transition(fresh_store, "tx-restart-1", TxnState.UNKNOWN, NOW)
    resolved = reconcile(fresh_store, bank_client, "", "tx-restart-1", NOW)

    assert resolved == TxnState.CONFIRMED
    assert fresh_store.get_state("tx-restart-1") == TxnState.CONFIRMED

    # prove no duplicate submission: re-verifying the same ID with a
    # differently-signed assertion (fresh nonce, different claimed amount)
    # still returns the ORIGINAL cached ledger result, proving the bank
    # never re-ran the account check (what resubmission would look like)
    signed_2 = _signed(
        keys_dir, subject="user-demo-1", amount="999999.00", transaction_id="tx-restart-1"
    )
    r2 = bank_client.post("/verify", json=signed_2.model_dump(mode="json"))
    assert r2.json() == r.json(), "bank must return the cached original result, not re-evaluate"


def test_restart_after_submitted_reconciles_to_failed_when_bank_never_saw_it(db_path, bank_client):
    """Day 3's Scenario A: the bank never received it. Reconciliation must
    resolve to FAILED (safe to retry later with a fresh transaction), not be
    left ambiguous forever and not be guessed as CONFIRMED."""
    store = TransactionStore(db_path)
    store.create("tx-restart-2", "user-demo-1", "1000.00", NOW)
    for state in [TxnState.EVALUATING, TxnState.ALLOWED, TxnState.SIGNED, TxnState.SUBMITTED]:
        transition(store, "tx-restart-2", state, NOW)
    # deliberately never call /verify -- the bank genuinely never saw this one
    store.close()

    fresh_store = TransactionStore(db_path)
    transition(fresh_store, "tx-restart-2", TxnState.UNKNOWN, NOW)
    resolved = reconcile(fresh_store, bank_client, "", "tx-restart-2", NOW)

    assert resolved == TxnState.FAILED
    assert fresh_store.get_state("tx-restart-2") == TxnState.FAILED


def test_restart_after_submitted_reconciles_to_failed_when_bank_rejected_it(
    db_path, bank_client, keys_dir
):
    """Step 6 finding: the bank DID process the transaction and
    independently said no (frozen account) -- discovered only via
    reconciliation, not the synchronous response, since /verify's result is
    deliberately never checked before the simulated 'crash' below. Before
    the state_machine.py fix, ledger status "REJECTED" had no handling and
    this would stay stuck in RECONCILING forever; it must resolve to
    FAILED, same as any other now-resolved outcome."""
    store = TransactionStore(db_path)
    store.create("tx-restart-rejected", "user-frozen-1", "500.00", NOW)
    for state in [TxnState.EVALUATING, TxnState.ALLOWED, TxnState.SIGNED, TxnState.SUBMITTED]:
        transition(store, "tx-restart-rejected", state, NOW)

    signed = _signed(
        keys_dir, subject="user-frozen-1", amount="500.00", transaction_id="tx-restart-rejected"
    )
    r = bank_client.post("/verify", json=signed.model_dump(mode="json"))
    assert r.json()["approved"] is False
    assert r.json()["reason"] == "account restrictions"
    store.close()  # the "crash" -- the CONFIRMED-vs-REJECTED result never made it back

    fresh_store = TransactionStore(db_path)
    transition(fresh_store, "tx-restart-rejected", TxnState.UNKNOWN, NOW)
    resolved = reconcile(fresh_store, bank_client, "", "tx-restart-rejected", NOW)

    assert resolved == TxnState.FAILED, (
        "a bank rejection discovered via reconciliation must resolve to FAILED, "
        "not be left stuck in RECONCILING forever"
    )
    assert fresh_store.get_state("tx-restart-rejected") == TxnState.FAILED


def test_reconcile_stays_reconciling_when_bank_genuinely_unreachable(db_path):
    """Bank not just slow -- not there. Must not crash, must not guess, must
    stay in RECONCILING for a later retry."""
    import httpx

    store = TransactionStore(db_path)
    store.create("tx-restart-3", "user-demo-1", "1000.00", NOW)
    for state in [TxnState.EVALUATING, TxnState.ALLOWED, TxnState.SIGNED,
                  TxnState.SUBMITTED, TxnState.UNKNOWN]:
        transition(store, "tx-restart-3", state, NOW)

    unreachable_client = httpx.Client()
    resolved = reconcile(store, unreachable_client, "http://127.0.0.1:1", "tx-restart-3", NOW)

    assert resolved == TxnState.RECONCILING
    assert store.get_state("tx-restart-3") == TxnState.RECONCILING


# --- the bank's own idempotency ----------------------------------------------


def test_bank_verify_idempotent_by_transaction_id(bank_client, keys_dir):
    """Calling /verify twice for the same transaction_id must return the same
    result even if the second presentation claims a different amount -- the
    bank is answering "what happened to THIS transaction", not "what would
    happen right now". Deliberately two DIFFERENT signed assertions (a fresh
    nonce each): resending the IDENTICAL assertion is now caught by replay
    protection instead (tests/test_replay.py) -- a different concern from
    this test, which is about the ledger's own idempotency surviving being
    reached through the new signed-assertion endpoint."""
    signed_1 = _signed(keys_dir, subject="user-poor-1", amount="50.00", transaction_id="tx-idempotent-1")
    r1 = bank_client.post("/verify", json=signed_1.model_dump(mode="json"))
    assert r1.json()["approved"] is True  # user-poor-1 has Rs 100, this fits

    signed_2 = _signed(
        keys_dir, subject="user-poor-1", amount="99999.00", transaction_id="tx-idempotent-1"
    )
    r2 = bank_client.post("/verify", json=signed_2.model_dump(mode="json"))
    assert r2.json() == r1.json(), "must return the cached first result, not re-evaluate"


def test_bank_status_not_found_for_unknown_transaction(bank_client):
    r = bank_client.get("/status/never-submitted-anything")
    assert r.json()["status"] == "NOT_FOUND"
