"""The ATLAS -> sandbox-bank adapter under failure (2026-09-22).

The frozen failure table says: bank unavailable -> PENDING; unknown payment
status -> reconcile, never blindly retry; the bank's decision wins. These tests
drive that table through the real pipeline with bank replies that are late,
broken, lying or missing, and pin the sandbox bank's own durability: its record
of outcomes and revocations now survives a restart, which is what makes
idempotency and reconciliation hold rather than hold-until-restart.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
from decimal import Decimal

import httpx
import pytest
from fastapi.testclient import TestClient

from atlas_service import crypto
from atlas_service import main as atlas_main
from atlas_service.db import TransactionStore
from atlas_service.state_machine import reconcile, transition
from bank_service import db as bank_db
from bank_service import ledger, revocation
from bank_service.main import app as bank_app
from bank_service.main import get_atlas_public_key, get_replay_cache
from bank_service.replay_cache import ReplayCache
from contracts import TxnState


@pytest.fixture
def atlas_keys(tmp_path):
    keys = tmp_path / "keys"
    crypto.init_device(keys_dir=keys)
    return keys


@pytest.fixture(autouse=True)
def _clear():
    yield
    atlas_main.app.dependency_overrides.clear()
    bank_app.dependency_overrides.clear()


def _payment(txn_id: str) -> dict:
    return {
        "transaction_id": txn_id, "subject": "user-demo-1", "amount": "1500.00", "currency": "INR",
        "beneficiary": "ben-mother", "location": "Hyderabad,IN", "device_id": "device-primary-01",
        "merchant_category": "transfer", "authentication_method": "pin",
        "is_new_beneficiary": False, "is_new_device": False, "is_international": False,
        "declared_travel_mode": False, "is_emergency_request": False,
        "timestamp": "2026-09-22T04:30:00+00:00",
    }


def _run(tmp_path, atlas_keys, bank_handler, txn_id: str):
    store = TransactionStore(tmp_path / "atlas.db")
    client = httpx.Client(transport=httpx.MockTransport(bank_handler))
    atlas_main.app.dependency_overrides.update({
        atlas_main.get_bank_client: lambda: client,
        atlas_main.get_transaction_store: lambda: store,
        atlas_main.get_signing_keys_dir: lambda: atlas_keys,
        atlas_main.get_require_device_auth: lambda: False,
    })
    body = TestClient(atlas_main.app).post("/transact", json=_payment(txn_id)).json()
    state = store.get_state(txn_id)
    store.close()
    return body, state


def _reply(payload, status=200, raw=False):
    def handler(request: httpx.Request) -> httpx.Response:
        if raw:
            return httpx.Response(status, content=payload)
        return httpx.Response(status, json=payload)
    return handler


@pytest.mark.parametrize("label, handler", [
    ("not JSON", _reply(b"<html>gateway error</html>", raw=True)),
    ("missing fields", _reply({"approved": True})),
    ("approved is not a boolean", _reply({"transaction_id": "{TXN}", "approved": "true", "reason": "ok"})),
    ("a verdict for another transaction", _reply({"transaction_id": "someone-else", "approved": True, "reason": "approved"})),
    ("HTTP 500", _reply({"detail": "boom"}, status=500)),
    ("HTTP 422", _reply({"detail": "bad request"}, status=422)),
])
def test_an_unusable_bank_reply_settles_pending_never_approval(tmp_path, atlas_keys, label, handler):
    txn_id = f"adapter-{abs(hash(label)) % 10**8}"

    def patched(request):
        response = handler(request)
        if b"{TXN}" in response.content:
            response = httpx.Response(response.status_code,
                                      content=response.content.replace(b"{TXN}", txn_id.encode()),
                                      headers={"content-type": "application/json"})
        return response

    body, state = _run(tmp_path, atlas_keys, patched, txn_id)
    assert (body["final_status"], body["decision_reason"]) == ("PENDING", "BANK_UNREACHABLE"), label
    assert body["bank_verdict"] is None
    assert state == TxnState.UNKNOWN, f"{label}: left in {state}, not ready for reconciliation"


@pytest.mark.parametrize("error", [httpx.ReadTimeout, httpx.ConnectTimeout, httpx.RemoteProtocolError])
def test_a_slow_or_broken_connection_settles_pending(tmp_path, atlas_keys, error):
    def handler(request):
        raise error("simulated", request=request)
    body, state = _run(tmp_path, atlas_keys, handler, f"adapter-{error.__name__}")
    assert body["final_status"] == "PENDING" and state == TxnState.UNKNOWN


def test_reconciliation_survives_a_malformed_status_reply(tmp_path):
    store = TransactionStore(tmp_path / "atlas.db")
    now = "2026-09-22T00:00:00+00:00"
    assert store.claim_new("rec-1", "user-demo-1", "10.00", now)
    for state in (TxnState.EVALUATING, TxnState.ALLOWED, TxnState.SIGNED, TxnState.SUBMITTED, TxnState.UNKNOWN):
        transition(store, "rec-1", state, now)
    for handler in (_reply(b"not json", raw=True), _reply({"state": "CONFIRMED"}), _reply({"status": 7})):
        client = httpx.Client(transport=httpx.MockTransport(handler))
        assert reconcile(store, client, "https://bank.test", "rec-1", now) == TxnState.RECONCILING
    store.close()


def test_bank_outcomes_survive_a_restart_so_reconciliation_does_not_lie(tmp_path, atlas_keys):
    """Before 2026-09-22 the outcome lived in process memory: after a bank
    restart /status said NOT_FOUND and ATLAS settled an APPROVED payment as
    FAILED. The bank's record is now durable."""
    public = crypto.get_public_key(keys_dir=atlas_keys)
    bank_app.dependency_overrides[get_atlas_public_key] = lambda: public
    bank_app.dependency_overrides[get_replay_cache] = lambda: ReplayCache(tmp_path / "replay.db")
    bank = TestClient(bank_app)
    signed = atlas_main.build_signed_assertion(
        __import__("contracts").Transaction(**_payment("durable-1")),
        __import__("contracts").PolicyDecision(
            transaction_id="durable-1", decision="ALLOW", policy_version="4",
            policy_hash="h", matched_rules=[]),
        keys_dir=atlas_keys)
    assert bank.post("/verify", json=signed.model_dump(mode="json")).json()["approved"] is True
    # A "restart": nothing in memory survives; only the file does.
    with sqlite3.connect(bank_db.DEFAULT_DB_PATH) as conn:
        assert conn.execute("SELECT approved FROM outcomes WHERE transaction_id='durable-1'").fetchone() == (1,)
    assert TestClient(bank_app).get("/status/durable-1").json()["status"] == "CONFIRMED"


def test_the_ledger_is_idempotent_even_if_the_account_changes(monkeypatch):
    first = ledger.verify("user-demo-1", Decimal("10.00"), "idem-1")
    monkeypatch.setitem(ledger._ACCOUNTS, "user-demo-1",
                        ledger.Account(subject="user-demo-1", balance=Decimal("0"), frozen=True))
    assert ledger.verify("user-demo-1", Decimal("10.00"), "idem-1") == first == (True, "approved")


def test_the_first_recorded_outcome_is_the_one_that_stands():
    """Straight at bank_service/db.py, because ledger.verify() answers from the
    stored outcome before it ever gets here: the INSERT is the layer that decides
    a genuine race, where two callers both pass that check and both write. The
    first write must win and the second must be told what is stored -- otherwise
    the loser's answer would overwrite an outcome the bank already gave out."""
    assert bank_db.record_outcome("first-wins-1", "user-demo-1", "10.00", True, "approved") \
        == (True, "approved")
    assert bank_db.record_outcome("first-wins-1", "user-demo-1", "10.00", False, "insufficient funds") \
        == (True, "approved")
    assert bank_db.get_outcome("first-wins-1") == (True, "approved")


def test_concurrent_duplicates_store_exactly_one_outcome():
    results = []
    def worker():
        results.append(ledger.verify("user-demo-1", Decimal("10.00"), "race-1"))
    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert set(results) == {(True, "approved")}
    with sqlite3.connect(bank_db.DEFAULT_DB_PATH) as conn:
        assert conn.execute("SELECT COUNT(*) FROM outcomes WHERE transaction_id='race-1'").fetchone() == (1,)


def test_a_revocation_survives_a_restart():
    revocation.revoke("atlas-key-to-retire")
    with sqlite3.connect(bank_db.DEFAULT_DB_PATH) as conn:
        assert conn.execute("SELECT 1 FROM revoked_keys WHERE key_id='atlas-key-to-retire'").fetchone()
    assert revocation.is_revoked("atlas-key-to-retire")


def test_the_bank_audit_log_records_decisions_without_secrets(tmp_path, atlas_keys, caplog):
    bank_logger = logging.getLogger("bank")
    bank_logger.addHandler(caplog.handler)
    try:
        public = crypto.get_public_key(keys_dir=atlas_keys)
        bank_app.dependency_overrides[get_atlas_public_key] = lambda: public
        bank_app.dependency_overrides[get_replay_cache] = lambda: ReplayCache(tmp_path / "replay.db")
        from contracts import PolicyDecision, Transaction
        signed = atlas_main.build_signed_assertion(
            Transaction(**_payment("audit-1")),
            PolicyDecision(transaction_id="audit-1", decision="ALLOW", policy_version="4",
                           policy_hash="h", matched_rules=[]), keys_dir=atlas_keys)
        TestClient(bank_app).post("/verify", json=signed.model_dump(mode="json"))
    finally:
        bank_logger.removeHandler(caplog.handler)
    text = caplog.text
    assert "txn=audit-1 event=ledger_decision approved=True" in text
    assert signed.signature not in text and signed.payload.nonce not in text
