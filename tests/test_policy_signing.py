"""Signed policy updates (2026-09-27).

Until 2026-09-27 ATLAS refused an OLDER policy but trusted any HIGHER-numbered one,
so anyone able to edit policies/<subject>.yaml could raise the version and loosen
every rule. test_a_forged_higher_version_looser_policy_is_refused is the regression
test: it is exactly that attack, and it fails if the signature check is removed.

Everything that reaches a decision goes through the real signed /v2/transact
endpoint, reusing the rollback suite's rig (a copied policy folder, a test owner key
enrolled in a temporary policy state).
"""

from __future__ import annotations

import shutil

import pytest
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import keystore
from atlas_service.policy import signing
from atlas_service.policy.engine import POLICIES_DIR
from atlas_service.policy.version_store import PolicyVersionStore
from tests.test_policy_rollback import SUBJECT, _OWNERS, _pay, _resign, _rewrite, _version, rig  # noqa: F401

LIVE_PAYMENT = dict(amount="150000.00")       # the frozen demo's hard-cap case: DENY under the real policy


def _loosen_without_the_owner(path, *, version):
    policy = yaml.safe_load(path.read_text(encoding="utf-8"))
    policy["version"] = version
    for rule in policy["rules"]:
        if "MAX_AMOUNT" in rule.get("condition", {}):
            rule["condition"]["MAX_AMOUNT"] *= 100
    path.write_text(yaml.safe_dump(policy, sort_keys=False), encoding="utf-8")   # signature left as it was


# ---- the attack that was open --------------------------------------------------------------

def test_a_forged_higher_version_looser_policy_is_refused(rig):
    """THE regression test. The attacker can write the policies folder but does not
    hold the owner's key: they raise the version (so the rollback check is happy)
    and raise the hard cap 100x. The next Rs 1,50,000 payment must be refused, not
    decided under the forged policy."""
    v = _version(rig)
    assert _pay(rig)["final_status"] == "ALLOW"
    _loosen_without_the_owner(rig["policy"], version=v + 1)
    reply = _pay(rig, **LIVE_PAYMENT)
    assert reply["final_status"] == "FAIL_CLOSED"
    assert reply["policy_refusal"] == "policy_signature_invalid"
    assert reply["decision"] is None and reply["bank_verdict"] is None
    assert rig["holder"]["store"].get_state(reply["sent_id"]) is None
    assert rig["holder"]["versions"].active(SUBJECT)[0] == v, "the forged version was recorded"


def test_the_same_edit_signed_by_the_real_owner_is_accepted(rig):
    """The control: a higher version the OWNER signed is a legitimate update."""
    v = _version(rig)
    _pay(rig)
    _rewrite(rig["policy"], version=v + 1, loosen=True)          # the rig's owner re-signs
    assert _pay(rig, **LIVE_PAYMENT)["final_status"] == "ALLOW"   # the looser cap now applies
    assert rig["holder"]["versions"].active(SUBJECT)[0] == v + 1


def test_a_policy_signed_by_someone_else_is_refused(rig):
    v = _version(rig)
    _pay(rig)
    _rewrite(rig["policy"], version=v + 1, loosen=True)
    attacker = Ed25519PrivateKey.generate()
    signing.signature_path(rig["policy"]).write_text(
        signing.sign(attacker, SUBJECT, rig["policy"].read_bytes()) + "\n", encoding="ascii")
    assert _pay(rig, **LIVE_PAYMENT)["policy_refusal"] == "policy_signature_invalid"


def test_an_old_policy_the_owner_really_signed_is_still_a_rollback(rig):
    """Signature and version together: a replayed file with a valid owner signature
    passes the signature check and is refused by the version check."""
    v = _version(rig)
    _pay(rig)
    _rewrite(rig["policy"], version=v - 1, loosen=True)          # owner-signed, but older
    assert _pay(rig, **LIVE_PAYMENT)["policy_refusal"] == "policy_rollback"


def test_an_unsigned_policy_is_refused(rig):
    signing.signature_path(rig["policy"]).unlink()
    reply = _pay(rig)
    assert reply["final_status"] == "FAIL_CLOSED" and reply["policy_refusal"] == "policy_unsigned"


def test_a_signature_cannot_be_moved_onto_another_customers_policy(rig):
    """The subject is inside the signed bytes."""
    other = rig["policy"].with_name("user-poor-1.yaml")
    key = _OWNERS[rig["policy"]]
    signing.signature_path(rig["policy"]).write_text(
        signing.sign(key, "user-poor-1", rig["policy"].read_bytes()) + "\n", encoding="ascii")
    assert _pay(rig)["policy_refusal"] == "policy_signature_invalid"
    assert other.exists()


def test_a_subject_with_no_enrolled_owner_is_refused(rig, tmp_path):
    rig["holder"]["versions"].close()
    rig["holder"]["versions"] = PolicyVersionStore(tmp_path / "empty_state.db")
    reply = _pay(rig)
    assert reply["final_status"] == "FAIL_CLOSED" and reply["policy_refusal"] == "policy_owner_not_enrolled"


def test_evaluate_applies_the_same_signature_check(rig):
    signing.signature_path(rig["policy"]).unlink()
    body = dict(transaction_id="sig-evaluate", subject=SUBJECT, amount="1500.00", currency="INR",
                beneficiary="ben-mother", location="Hyderabad,IN", device_id="device-primary-01",
                merchant_category="utilities", authentication_method="device_button",
                timestamp="2026-09-23T04:30:00+00:00")
    reply = rig["client"].post("/evaluate", json=body).json()
    assert reply["final_status"] == "FAIL_CLOSED" and reply["policy_refusal"] == "policy_unsigned"


# ---- the committed files, and the tools ----------------------------------------------------

def test_every_committed_policy_is_signed_by_its_committed_owner_key():
    for policy in sorted(POLICIES_DIR.glob("*.yaml")):
        pub = signing.public_key_path(policy).read_text(encoding="ascii").strip()
        signing.verify_file(policy, policy.stem, pub)
    assert not list(POLICIES_DIR.glob("*.key")), "a private key is in the policies folder"


def test_line_endings_do_not_change_the_signature(tmp_path):
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    lf = tmp_path / "user-x.yaml"
    lf.write_bytes(b"version: 1\nsubject: user-x\nrules: []\n")
    signing.signature_path(lf).write_text(signing.sign(key, "user-x", lf.read_bytes()), encoding="ascii")
    crlf = tmp_path / "crlf" / "user-x.yaml"
    crlf.parent.mkdir()
    crlf.write_bytes(lf.read_bytes().replace(b"\n", b"\r\n"))
    shutil.copy(signing.signature_path(lf), signing.signature_path(crlf))
    assert signing.verify_file(crlf, "user-x", pub) == lf.read_bytes()


def test_an_enrolled_owner_is_never_replaced_silently(tmp_path):
    store = PolicyVersionStore(tmp_path / "s.db")
    a, b = "11" * 32, "22" * 32
    store.enroll_owner("u", a)
    store.enroll_owner("u", a)                                    # the same key again is fine
    with pytest.raises(ValueError, match="different enrolled policy owner"):
        store.enroll_owner("u", b)
    assert store.owner_key("u") == a
    store.enroll_owner("u", b, replace=True)
    assert store.owner_key("u") == b
    with pytest.raises(ValueError):
        store.enroll_owner("v", "not-hex")
    store.close()


def test_the_policy_key_tool_creates_signs_enrolls_and_verifies(tmp_path, capsys):
    import importlib.util
    spec = importlib.util.spec_from_file_location("policy_key", POLICIES_DIR.parents[2] / "scripts" / "policy_key.py")
    tool = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tool)
    policies = tmp_path / "policies"
    shutil.copytree(POLICIES_DIR, policies)
    keys = tmp_path / "keys"
    key_path = tool.create(SUBJECT, keys)
    assert keystore.is_protected(key_path), "the owner key was written unprotected"
    with pytest.raises(FileExistsError):
        tool.create(SUBJECT, keys)                                # never overwritten
    tool.sign(SUBJECT, policies, keys)
    state = tmp_path / "state"
    state.mkdir()
    tool.enroll(SUBJECT, state, policies_dir=policies)
    tool.verify(SUBJECT, state, policies_dir=policies)
    private_hex = tool.load_private(SUBJECT, keys).private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()).hex()
    assert private_hex not in capsys.readouterr().out
