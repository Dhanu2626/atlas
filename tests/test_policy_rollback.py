"""Policy rollback is rejected on LIVE requests (2026-09-25).

ARCHITECTURE.md principle 7 and its failure-mode table ("Policy rollback detected ->
reject"). Until 2026-09-25 engine.check_rollback() existed only as a pure function
that no request called: replacing policies/<subject>.yaml with an older file changed
every later decision and nothing noticed. test_an_older_policy_file_is_refused_on_the_
next_real_payment is the regression test -- it fails if the gate is removed.

Everything here goes through the real signed /v2/transact endpoint on temporary
stores, with the policy directory copied into tmp_path so a test can roll it back.
"""

from __future__ import annotations

import secrets
import shutil
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from atlas_service import main as atlas_main
from atlas_service.db import TransactionStore
from atlas_service.device.db import DeviceStore
from atlas_service.device.registry import register_demo_device
from atlas_service.main import (
    app as atlas_app,
    get_allow_counter_reset,
    get_bank_client,
    get_device_store,
    get_policy_version_store,
    get_signing_keys_dir,
    get_step_up_store,
    get_transaction_store,
)
from atlas_service.policy.engine import POLICIES_DIR, RolledBackPolicyError
from atlas_service.policy.version_store import (
    PolicyStateUnavailableError,
    PolicyVersionStore,
    TamperedPolicyError,
)
from atlas_service.step_up.db import StepUpStore
from bank_service.main import app as bank_app
from contracts import DeviceEnvelope, canonical_envelope_bytes
from firmware import device_identity
from tests.conftest import wire_bank_app_to_keys

DEVICE_ID = "esp32-atlas-rollback-01"
SUBJECT = "user-demo-1"


@pytest.fixture
def rig(tmp_path, monkeypatch):
    keys = tmp_path / "device-keys"
    device_identity.init_device(keys)
    device_db = tmp_path / "devices.db"
    store = DeviceStore(device_db)
    register_demo_device(store, device_id=DEVICE_ID,
                         device_key_id=device_identity.get_key_id(keys),
                         public_key=device_identity.get_public_key(keys),
                         bound_subject=SUBJECT)
    store.close()

    policies = tmp_path / "policies"
    shutil.copytree(POLICIES_DIR, policies)
    monkeypatch.setattr(atlas_main, "POLICIES_DIR", policies)

    wire_bank_app_to_keys(tmp_path / "atlas-keys", tmp_path / "replay.db")
    bank = TestClient(bank_app)
    txn_db = tmp_path / "atlas.db"
    holder = {"store": TransactionStore(txn_db),
              "versions": PolicyVersionStore(tmp_path / "policy_state.db")}
    atlas_app.dependency_overrides.update({
        get_bank_client: lambda: bank,
        get_signing_keys_dir: lambda: tmp_path / "atlas-keys",
        get_transaction_store: lambda: holder["store"],
        get_device_store: lambda: DeviceStore(device_db),
        get_step_up_store: lambda: StepUpStore(tmp_path / "step_up.db"),
        get_allow_counter_reset: lambda: False,
        get_policy_version_store: lambda: holder["versions"],
    })
    yield {"client": TestClient(atlas_app), "keys": keys, "policy": policies / f"{SUBJECT}.yaml",
           "holder": holder, "tmp": tmp_path, "counter": [0]}
    holder["store"].close()
    if holder["versions"] is not None:
        holder["versions"].close()
    atlas_app.dependency_overrides.clear()
    bank_app.dependency_overrides.clear()


def _pay(rig, **overrides) -> dict:
    rig["counter"][0] += 1
    txn = dict(transaction_id=f"rb-{secrets.token_hex(4)}", subject=SUBJECT,
               amount="1500.00", currency="INR", beneficiary="ben-mother",
               location="Hyderabad,IN", device_id="device-primary-01",
               merchant_category="utilities", authentication_method="device_button",
               timestamp="2026-09-23T04:30:00+00:00")
    txn.update(overrides)
    keys = rig["keys"]
    unsigned = DeviceEnvelope(device_id=DEVICE_ID, device_key_id=device_identity.get_key_id(keys),
                              boot_id="boot-rollback", counter=rig["counter"][0],
                              nonce=secrets.token_hex(16),
                              issued_at=datetime.now(timezone.utc).isoformat(), transaction=txn,
                              location=None, health=None, signature="")
    signed = unsigned.model_copy(update={
        "signature": device_identity.secure_sign(canonical_envelope_bytes(unsigned), keys)})
    reply = rig["client"].post("/v2/transact", json=signed.model_dump(mode="json"))
    assert reply.status_code == 200, reply.text
    return {"sent_id": txn["transaction_id"], **reply.json()}


def _rewrite(policy_path: Path, **changes) -> None:
    """Rewrites the policy file. `version` sets the version; `loosen=True` raises
    the hard cap -- the looser policy a rollback attacker would want."""
    policy = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
    if "version" in changes:
        policy["version"] = changes["version"]
    if changes.get("loosen"):
        for rule in policy["rules"]:
            if "MAX_AMOUNT" in rule.get("condition", {}):
                rule["condition"]["MAX_AMOUNT"] = rule["condition"]["MAX_AMOUNT"] * 100
    policy_path.write_text(yaml.safe_dump(policy, sort_keys=False), encoding="utf-8")


def _version(rig) -> int:
    return yaml.safe_load(rig["policy"].read_text(encoding="utf-8"))["version"]


# ---- positive ------------------------------------------------------------------------

def test_the_first_payment_records_the_active_version_and_is_decided_normally(rig):
    reply = _pay(rig)
    assert reply["final_status"] == "ALLOW"
    assert "policy_refusal" not in reply
    assert rig["holder"]["versions"].active(SUBJECT)[0] == _version(rig)


def test_the_same_policy_again_is_accepted(rig):
    assert _pay(rig)["final_status"] == "ALLOW"
    assert _pay(rig)["final_status"] == "ALLOW"


def test_a_newer_version_is_accepted_and_becomes_the_recorded_one(rig):
    v = _version(rig)
    _pay(rig)
    _rewrite(rig["policy"], version=v + 1)
    assert _pay(rig)["final_status"] == "ALLOW"
    assert rig["holder"]["versions"].active(SUBJECT)[0] == v + 1


# ---- negative: the regression test ---------------------------------------------------

def test_an_older_policy_file_is_refused_on_the_next_real_payment(rig):
    """THE regression test: a live payment is decided under version v, the file is
    swapped for version v-1 with a hard cap 100x looser, and the next REAL payment
    is refused -- nothing persisted, nothing signed, the bank never contacted. Remove
    the gate from _run_transaction and this payment is decided under the looser
    policy instead."""
    v = _version(rig)
    assert _pay(rig)["final_status"] == "ALLOW"
    _rewrite(rig["policy"], version=v - 1, loosen=True)

    reply = _pay(rig, amount="150000.00")   # the frozen demo's hard-cap case
    assert reply["final_status"] == "FAIL_CLOSED"
    assert reply["policy_refusal"] == "policy_rollback"
    assert reply["decision"] is None and reply["assertion"] is None
    assert reply["bank_verdict"] is None
    assert rig["holder"]["store"].get_state(reply["sent_id"]) is None, "a refused request left state"
    assert rig["holder"]["versions"].active(SUBJECT)[0] == v, "the rollback overwrote the record"


def test_the_rollback_is_still_refused_after_the_version_store_is_reopened(rig):
    v = _version(rig)
    _pay(rig)
    rig["holder"]["versions"].close()
    rig["holder"]["versions"] = PolicyVersionStore(rig["tmp"] / "policy_state.db")
    _rewrite(rig["policy"], version=v - 1)
    assert _pay(rig)["policy_refusal"] == "policy_rollback"


# ---- tampering and mismatch ----------------------------------------------------------

def test_the_same_version_number_with_different_rules_is_refused_as_tampering(rig):
    v = _version(rig)
    _pay(rig)
    _rewrite(rig["policy"], version=v, loosen=True)
    reply = _pay(rig, amount="150000.00")
    assert reply["final_status"] == "FAIL_CLOSED"
    assert reply["policy_refusal"] == "policy_tampered"
    assert rig["holder"]["store"].get_state(reply["sent_id"]) is None


def test_restoring_the_real_file_after_a_refusal_decides_normally_again(rig):
    original = rig["policy"].read_text(encoding="utf-8")
    v = _version(rig)
    _pay(rig)
    _rewrite(rig["policy"], version=v - 1)
    assert _pay(rig)["policy_refusal"] == "policy_rollback"
    rig["policy"].write_text(original, encoding="utf-8")
    assert _pay(rig)["final_status"] == "ALLOW"


def test_evaluate_refuses_a_rollback_too_and_records_nothing(rig):
    v = _version(rig)
    _pay(rig)
    _rewrite(rig["policy"], version=v - 1)
    body = dict(transaction_id="rb-evaluate", subject=SUBJECT, amount="1500.00", currency="INR",
                beneficiary="ben-mother", location="Hyderabad,IN", device_id="device-primary-01",
                merchant_category="utilities", authentication_method="device_button",
                timestamp="2026-09-23T04:30:00+00:00")
    reply = rig["client"].post("/evaluate", json=body).json()
    assert reply["final_status"] == "FAIL_CLOSED" and reply["policy_refusal"] == "policy_rollback"


def test_evaluate_does_not_record_a_newer_version(rig):
    v = _version(rig)
    _pay(rig)
    _rewrite(rig["policy"], version=v + 5)
    body = dict(transaction_id="rb-evaluate-2", subject=SUBJECT, amount="1500.00", currency="INR",
                beneficiary="ben-mother", location="Hyderabad,IN", device_id="device-primary-01",
                merchant_category="utilities", authentication_method="device_button",
                timestamp="2026-09-23T04:30:00+00:00")
    assert rig["client"].post("/evaluate", json=body).json()["decision"] is not None
    assert rig["holder"]["versions"].active(SUBJECT)[0] == v, "/evaluate wrote the version record"


# ---- failure paths -------------------------------------------------------------------

def test_an_unopenable_version_store_refuses_rather_than_deciding(rig):
    atlas_app.dependency_overrides[get_policy_version_store] = lambda: None
    reply = _pay(rig)
    assert reply["final_status"] == "FAIL_CLOSED"
    assert reply["policy_refusal"] == "policy_state_unavailable"
    assert rig["holder"]["store"].get_state(reply["sent_id"]) is None


def test_a_corrupt_version_store_refuses_rather_than_deciding(rig):
    _pay(rig)
    path = rig["tmp"] / "policy_state.db"
    rig["holder"]["versions"].close()
    with sqlite3.connect(path) as conn:
        conn.execute("DROP TABLE active_policy")
        conn.execute("CREATE TABLE active_policy (junk TEXT)")
    rig["holder"]["versions"] = PolicyVersionStore(path)
    reply = _pay(rig)
    assert reply["final_status"] == "FAIL_CLOSED"
    assert reply["policy_refusal"] == "policy_state_unavailable"


def test_the_default_dependency_refuses_when_the_state_path_cannot_be_opened(tmp_path, monkeypatch):
    """The real dependency, not an override: a path whose parent is a FILE cannot be
    opened, and the dependency yields None, which the request path refuses on."""
    blocker = tmp_path / "not-a-directory"
    blocker.write_text("x", encoding="utf-8")
    monkeypatch.setattr(atlas_main, "POLICY_STATE_DB_PATH", blocker / "atlas_policy_state.db")
    gen = atlas_main.get_policy_version_store()
    assert next(gen) is None
    gen.close()


# ---- the store on its own ------------------------------------------------------------

def test_store_unit_semantics(tmp_path):
    store = PolicyVersionStore(tmp_path / "s.db")
    store.admit("u", 3, "h3")                            # first sight: recorded
    store.admit("u", 3, "h3")                            # same: fine
    with pytest.raises(RolledBackPolicyError):
        store.admit("u", 2, "h2")
    with pytest.raises(TamperedPolicyError):
        store.admit("u", 3, "other")
    store.admit("u", 4, "h4")
    assert store.active("u") == (4, "h4")
    store.admit("u", 9, "h9", record=False)
    assert store.active("u") == (4, "h4")
    store.admit("other-subject", 1, "x")                 # per subject
    assert store.active("u") == (4, "h4")
    store.close()


def test_an_unopenable_store_raises_the_named_error(tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("x", encoding="utf-8")
    with pytest.raises(PolicyStateUnavailableError):
        PolicyVersionStore(blocker / "s.db")
