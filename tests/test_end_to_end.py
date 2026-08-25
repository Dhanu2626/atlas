"""Step 6: the real end-to-end flow, both live apps together, exercising
BUILD-PLAN.md's test-scenario list for the first time genuinely end-to-end
(real signatures, real persisted state, real HTTP) rather than at the module
level. Deliberately does not re-prove things test_bank_boundary.py,
test_state_machine.py, and Step 5's crypto/replay/revocation/expiry test
files already cover well -- focuses on what's newly wired together: the
/reconcile endpoint, STEP_UP's live-response shape, persisted state after an
authority-hierarchy override, and tamper/expiry/revocation hitting the real
running bank_app rather than verify_assertion() called directly.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from atlas_service import crypto
from atlas_service.db import TransactionStore
from atlas_service.main import app as atlas_app
from atlas_service.main import (
    ATLAS_AUDIENCE,
    ATLAS_ISSUER,
    build_signed_assertion,
    get_bank_client,
    get_signing_keys_dir,
    get_transaction_store,
)
from atlas_service.state_machine import transition
from bank_service import revocation
from bank_service.main import app as bank_app
from contracts import (
    AssertionPayload,
    Decision,
    PolicyDecision,
    SignedAssertion,
    Transaction,
    TxnState,
)
from tests.conftest import wire_bank_app_to_keys


def _tx(**overrides) -> dict:
    defaults = dict(
        transaction_id="tx-e2e-1",
        subject="user-demo-1",
        amount="1500.00",
        currency="INR",
        beneficiary="ben-mother",
        location="Bengaluru,IN",
        device_id="device-primary-01",
        merchant_category="amazon",
        authentication_method="pin",
        is_new_beneficiary=False,
        is_new_device=False,
        is_international=False,
        declared_travel_mode=False,
        is_emergency_request=False,
        timestamp="2026-08-25T12:00:00+00:00",
    )
    defaults.update(overrides)
    return defaults


@pytest.fixture
def keys_dir(tmp_path) -> Path:
    return tmp_path / "atlas-keys"


@pytest.fixture(autouse=True)
def _wire_bank(keys_dir, tmp_path):
    wire_bank_app_to_keys(keys_dir, tmp_path / "replay.db")
    yield
    bank_app.dependency_overrides.clear()
    atlas_app.dependency_overrides.clear()


@pytest.fixture
def clients(keys_dir, tmp_path):
    """Both real apps, wired together the way a real deployment would be:
    atlas_app signs with keys_dir, bank_app (via the autouse fixture above)
    trusts that same key and uses an isolated replay cache; atlas_app's own
    transaction store is isolated per test too."""
    bank = TestClient(bank_app)
    atlas_app.dependency_overrides[get_bank_client] = lambda: bank
    atlas_app.dependency_overrides[get_signing_keys_dir] = lambda: keys_dir
    store_path = tmp_path / "atlas.db"
    atlas_app.dependency_overrides[get_transaction_store] = lambda: TransactionStore(store_path)
    atlas_client = TestClient(atlas_app)
    return atlas_client, bank, store_path


# --- Scenario 1: normal transaction, every layer checked --------------------


def test_normal_transaction_allow_persists_confirmed_state(clients):
    atlas_client, bank, store_path = clients
    r = atlas_client.post("/transact", json=_tx(transaction_id="tx-e2e-normal"))
    body = r.json()

    assert body["decision"]["decision"] == "ALLOW"
    assert body["final_status"] == "ALLOW"
    assert body["assertion"]["payload"]["transaction_id"] == "tx-e2e-normal"
    assert body["assertion"]["signature"]

    store = TransactionStore(store_path)
    assert store.get_state("tx-e2e-normal") == TxnState.CONFIRMED

    # the assertion /transact already sent to the bank internally is now
    # consumed -- resubmitting the identical one must be caught as a replay,
    # not silently re-approved
    r2 = bank.post("/verify", json=body["assertion"])
    body2 = r2.json()
    assert body2["approved"] is False
    assert body2["reason"] == "replayed assertion"


# --- Scenario 3: STEP_UP is reported as itself, not silently as DENY -------


def test_step_up_decision_is_reported_as_step_up_not_deny(clients):
    """user-demo-1's policy STEP_UPs on a large amount (see
    tests/test_policy_engine.py::test_large_amount_steps_up for the same
    threshold at the policy-engine level). Confirms the live endpoint
    surfaces STEP_UP correctly in the response even though -- a flagged,
    approved scoping choice -- it lands in the same DENIED transaction
    state as an outright DENY, since there's no separate STEP_UP state and
    no confirmation loop built yet."""
    atlas_client, _bank, store_path = clients
    r = atlas_client.post("/transact", json=_tx(
        transaction_id="tx-e2e-stepup", amount="60000.00",
    ))
    body = r.json()
    assert body["decision"]["decision"] == "STEP_UP"
    assert body["final_status"] == "STEP_UP"
    assert body["assertion"] is None, "STEP_UP never proceeds to signing"

    store = TransactionStore(store_path)
    assert store.get_state("tx-e2e-stepup") == TxnState.DENIED


# --- Scenario 4: authority hierarchy, now checked at the state level too ---


def test_bank_override_persists_failed_not_confirmed(clients):
    """test_bank_boundary.py already proves the response body; this adds
    the persisted-state check that file doesn't: the transaction must
    actually land in FAILED on disk, not just report DENY in the response."""
    atlas_client, _bank, store_path = clients
    r = atlas_client.post("/transact", json=_tx(
        transaction_id="tx-e2e-frozen", subject="user-frozen-1", amount="500.00",
    ))
    body = r.json()
    assert body["final_status"] == "DENY"

    store = TransactionStore(store_path)
    assert store.get_state("tx-e2e-frozen") == TxnState.FAILED


# --- Scenario 5: kill mid-transaction, restart, reconcile -- now over HTTP -


def test_reconcile_endpoint_resolves_a_transaction_stuck_in_unknown(clients, keys_dir):
    """The /reconcile/{id} endpoint itself, live, for the first time --
    test_state_machine.py already proves the underlying reconcile()
    function; this proves it's actually reachable and wired correctly."""
    atlas_client, bank, store_path = clients

    now = datetime.now(timezone.utc).isoformat()
    store = TransactionStore(store_path)
    store.create("tx-e2e-reconcile", "user-demo-1", "1000.00", now)
    for state in [TxnState.EVALUATING, TxnState.ALLOWED, TxnState.SIGNED,
                  TxnState.SUBMITTED, TxnState.UNKNOWN]:
        transition(store, "tx-e2e-reconcile", state, now)

    # the bank DID see it -- call bank directly, simulating what
    # atlas_service would have done before "crashing" right after submission
    tx = Transaction(**_tx(
        transaction_id="tx-e2e-reconcile", subject="user-demo-1", amount="1000.00",
    ))
    policy_decision = PolicyDecision(
        transaction_id="tx-e2e-reconcile", decision=Decision.ALLOW,
        policy_version=1, policy_hash="test-hash",
    )
    signed = build_signed_assertion(tx, policy_decision, keys_dir=keys_dir)
    verify_resp = bank.post("/verify", json=signed.model_dump(mode="json"))
    assert verify_resp.json()["approved"] is True

    r = atlas_client.post("/reconcile/tx-e2e-reconcile")
    body = r.json()
    assert body["state"] == "CONFIRMED"
    assert store.get_state("tx-e2e-reconcile") == TxnState.CONFIRMED


def test_reconcile_endpoint_reports_an_error_for_an_already_resolved_transaction(clients):
    atlas_client, _bank, _store_path = clients
    r1 = atlas_client.post("/transact", json=_tx(transaction_id="tx-e2e-already-done"))
    assert r1.json()["final_status"] == "ALLOW"

    r2 = atlas_client.post("/reconcile/tx-e2e-already-done")
    assert "error" in r2.json()


# --- Scenarios 6-9: tamper / expiry / revocation, against the live bank_app


def test_tampered_assertion_from_a_real_transact_call_is_rejected_live(clients):
    """Takes the actual signed assertion a real /transact call produced,
    tampers one field, and POSTs the tampered version to the live bank_app
    -- proving the real artifact this system produces, not a synthetic one,
    is rejected if altered in transit."""
    atlas_client, bank, _store_path = clients
    r = atlas_client.post("/transact", json=_tx(transaction_id="tx-e2e-tamper"))
    signed_dict = r.json()["assertion"]

    tampered = dict(signed_dict)
    tampered["payload"] = dict(tampered["payload"])
    tampered["payload"]["amount"] = "1.00"  # attacker tries to shrink the debited amount

    r2 = bank.post("/verify", json=tampered)
    body2 = r2.json()
    assert body2["approved"] is False
    assert body2["reason"] == "invalid signature"


def test_expired_assertion_rejected_by_the_live_bank_endpoint(keys_dir):
    bank = TestClient(bank_app)
    now = datetime.now(timezone.utc)
    payload = AssertionPayload(
        issuer=ATLAS_ISSUER,
        subject="user-demo-1",
        transaction_id="tx-e2e-expired",
        amount="1000.00",
        currency="INR",
        beneficiary="ben-1",
        policy_version=1,
        policy_hash="test-hash",
        decision=Decision.ALLOW,
        nonce="nonce-e2e-expired",
        issued_at=(now - timedelta(seconds=200)).isoformat(),
        expires_at=(now - timedelta(seconds=80)).isoformat(),
        audience=ATLAS_AUDIENCE,
        atlas_key_id=crypto.DEFAULT_KEY_ID,
    )
    signature = crypto.secure_sign(payload, keys_dir=keys_dir)
    signed = SignedAssertion(payload=payload, signature=signature)

    r = bank.post("/verify", json=signed.model_dump(mode="json"))
    body = r.json()
    assert body["approved"] is False
    assert body["reason"] == "assertion expired"


def test_revoked_key_rejected_by_the_live_bank_endpoint(keys_dir):
    bank = TestClient(bank_app)
    tx = Transaction(**_tx(transaction_id="tx-e2e-revoked"))
    policy_decision = PolicyDecision(
        transaction_id="tx-e2e-revoked", decision=Decision.ALLOW,
        policy_version=1, policy_hash="test-hash",
    )
    signed = build_signed_assertion(tx, policy_decision, keys_dir=keys_dir)

    revocation.revoke(crypto.DEFAULT_KEY_ID)
    try:
        r = bank.post("/verify", json=signed.model_dump(mode="json"))
        body = r.json()
        assert body["approved"] is False
        assert body["reason"] == "key revoked"
    finally:
        revocation.reset()
