"""Step-up authentication, and the invariant that makes it safe.

The unit tests below exercise resolve_step_up() directly, because it is a pure
function with a small finite input space -- so it can be checked EXHAUSTIVELY
rather than by example. The integration tests then prove the same properties
survive the HTTP path, the state machine and the database.

STEP-UP-INVARIANT-1, the rule this whole file exists to defend:

    A successful step-up must NEVER convert a DENY into an ALLOW.
"""

from __future__ import annotations

import itertools
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from atlas_service.db import TransactionStore
from atlas_service.device.db import DeviceStore
from atlas_service.main import (
    app as atlas_app,
    get_allow_counter_reset,
    get_bank_client,
    get_device_store,
    get_enable_step_up,
    get_require_device_auth,
    get_signing_keys_dir,
    get_step_up_store,
    get_transaction_store,
)
from atlas_service.step_up.db import STEP_UP_MAX_ATTEMPTS, StepUpStore
from atlas_service.step_up.resolver import resolve_step_up
from atlas_service.step_up.service import proof_message
from contracts import (
    AuthResult,
    Decision,
    FrozenDecisionContext,
    MatchedRule,
    Transaction,
    TxnState,
)

POLICY_HASH = "hash-of-the-policy-that-decided"
OTHER_HASH = "a-different-policy-entirely"


def _txn(transaction_id="txn-step-up-1", amount="60000.00") -> Transaction:
    return Transaction(
        transaction_id=transaction_id,
        device_id="esp32-atlas-demo-01",
        subject="user-demo-1",
        amount=Decimal(amount),
        currency="INR",
        beneficiary="acct-9",
        location="Bengaluru,IN",
        authentication_method="device_button",
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


def _ctx(
    *,
    original=Decision.STEP_UP,
    rules=(("large_amount", Decision.STEP_UP),),
    policy_hash=POLICY_HASH,
    transaction_id="txn-step-up-1",
) -> FrozenDecisionContext:
    return FrozenDecisionContext(
        transaction_id=transaction_id,
        subject="user-demo-1",
        transaction=_txn(transaction_id),
        rail="UPI",
        original_decision=original,
        matched_rules=[MatchedRule(name=n, action=a) for n, a in rules],
        deciding_rule=rules[0][0] if rules else None,
        policy_version=4,
        policy_hash=policy_hash,
        risk_band="LOW",
        anomaly_score=0.1,
        envelope_hash="e" * 64,
    )


# ==========================================================================
# The pure resolver -- exhaustive, not by example
# ==========================================================================


def test_successful_step_up_produces_allow():
    """The one path that approves. Everything else in this file is about the
    paths that must not."""
    assert resolve_step_up(_ctx(), AuthResult.SUCCESS, POLICY_HASH) is Decision.ALLOW


@pytest.mark.parametrize("auth", [a for a in AuthResult if a is not AuthResult.SUCCESS])
def test_every_non_success_auth_result_denies(auth):
    """INVALID_PROOF, EXPIRED, ATTEMPTS_EXHAUSTED, BINDING_MISMATCH,
    UNKNOWN_CHALLENGE, NO_AUTHENTICATOR -- there is no partial credit."""
    assert resolve_step_up(_ctx(), auth, POLICY_HASH) is Decision.DENY


def test_original_deny_cannot_become_allow():
    """STEP-UP-INVARIANT-1, stated as directly as it can be stated.

    A DENY should never reach the resolver at all -- it never enters
    AWAITING_STEP_UP. This asserts what happens if a future bug lets one in:
    the answer is still no, even with a perfect proof.
    """
    ctx = _ctx(original=Decision.DENY, rules=(("hard_cap", Decision.DENY),))
    assert resolve_step_up(ctx, AuthResult.SUCCESS, POLICY_HASH) is Decision.DENY


def test_a_deny_rule_among_step_up_rules_still_denies():
    """The realistic shape of the attack: amount=150000 fires large_amount
    (STEP_UP) *and* hard_cap (DENY). MOST RESTRICTIVE WINS already said no, and
    authenticating does not raise a hard cap."""
    ctx = _ctx(rules=(("large_amount", Decision.STEP_UP), ("hard_cap", Decision.DENY)))
    assert resolve_step_up(ctx, AuthResult.SUCCESS, POLICY_HASH) is Decision.DENY


def test_original_delay_cannot_become_allow():
    """DELAY is about timing, not identity, so a proof of identity cannot
    satisfy it. Fail closed rather than invent semantics."""
    ctx = _ctx(original=Decision.DELAY, rules=(("cooling_off", Decision.DELAY),))
    assert resolve_step_up(ctx, AuthResult.SUCCESS, POLICY_HASH) is Decision.DENY

    mixed = _ctx(rules=(("large_amount", Decision.STEP_UP), ("cooling_off", Decision.DELAY)))
    assert resolve_step_up(mixed, AuthResult.SUCCESS, POLICY_HASH) is Decision.DENY


def test_changed_policy_hash_cannot_become_allow():
    """The frozen context describes a decision made under a policy that no
    longer exists. Honouring it would authorise under withdrawn rules."""
    assert resolve_step_up(_ctx(), AuthResult.SUCCESS, OTHER_HASH) is Decision.DENY


def test_resolver_is_exhaustively_safe():
    """Walk the ENTIRE input space, not a sample of it.

    4 original decisions x 4 rule-set shapes x every AuthResult x hash
    match/mismatch. Assert ALLOW appears if and only if the invariant permits
    it. If a future edit widens the ALLOW path anywhere in that space, this
    fails.
    """
    rule_shapes = {
        "none": (),
        "step_up_only": (("large_amount", Decision.STEP_UP),),
        "with_deny": (("large_amount", Decision.STEP_UP), ("hard_cap", Decision.DENY)),
        "with_delay": (("large_amount", Decision.STEP_UP), ("cool", Decision.DELAY)),
    }
    allowed, checked = 0, 0
    for original, (shape, rules), auth, hash_ok in itertools.product(
        Decision, rule_shapes.items(), AuthResult, (True, False)
    ):
        ctx = _ctx(original=original, rules=rules or (("x", Decision.STEP_UP),))
        if not rules:
            ctx = ctx.model_copy(update={"matched_rules": [], "deciding_rule": None})
        got = resolve_step_up(ctx, auth, POLICY_HASH if hash_ok else OTHER_HASH)
        checked += 1

        should_allow = (
            auth is AuthResult.SUCCESS
            and original is Decision.STEP_UP
            and not any(r.action is Decision.DENY for r in ctx.matched_rules)
            and not any(r.action is Decision.DELAY for r in ctx.matched_rules)
            and hash_ok
        )
        assert (got is Decision.ALLOW) == should_allow, (
            f"original={original} shape={shape} auth={auth} hash_ok={hash_ok} -> {got}"
        )
        allowed += got is Decision.ALLOW

    assert checked == 4 * 4 * len(AuthResult) * 2
    assert allowed > 0, "the exhaustive sweep never allowed anything -- test is vacuous"


def test_bounded_re_resolution_does_not_recompute_anything():
    """Structural guard, in the same spirit as
    test_firmware_never_contains_decision_logic.

    The resolver must not re-run ML or policy. Checked against the source
    rather than trusted, because a docstring promising purity is not purity.
    """
    src = Path(resolve_step_up.__module__.replace(".", "/") + ".py")
    text = (Path.cwd() / src).read_text(encoding="utf-8")
    body = text.split("def resolve_step_up(", 1)[1]

    for banned in ("evaluate(", ".score(", "datetime", "now(", "load_policy",
                   "PersonaAnomalyModel", "sqlite3", "requests", "httpx"):
        assert banned not in body, f"bounded re-resolution recomputes: {banned}"

    imports = re.findall(r"^\s*(?:from|import)\s+(\S+)", text, re.M)
    for mod in imports:
        assert not mod.startswith("atlas_service.ml"), f"resolver imports ML: {mod}"
        assert not mod.startswith("atlas_service.policy"), f"resolver imports policy: {mod}"


def test_clock_changes_cannot_alter_the_frozen_decision():
    """The 23:58 -> 06:01 case, which is the reason this design exists.

    A transaction that got STEP_UP from odd_hours must resolve identically
    whenever it is confirmed. resolve_step_up() takes no clock, so this is
    true by construction -- the test pins it so a future signature change that
    reintroduces one is caught.
    """
    ctx = _ctx(rules=(("odd_hours", Decision.STEP_UP),))
    first = resolve_step_up(ctx, AuthResult.SUCCESS, POLICY_HASH)
    for _ in range(5):
        assert resolve_step_up(ctx, AuthResult.SUCCESS, POLICY_HASH) is first

    import inspect
    params = inspect.signature(resolve_step_up).parameters
    assert set(params) == {"ctx", "auth", "current_policy_hash"}, (
        "resolve_step_up grew a parameter -- if it is a clock, the design is broken"
    )


def test_removing_the_deny_guard_makes_the_invariant_fail():
    """MUTATION TEST. A guard nothing can break is decoration.

    Loads the resolver source, deletes the DENY guard, executes the mutant in
    an isolated namespace, and asserts the mutant now ALLOWS a transaction the
    real resolver refuses. If this ever stops failing, the guard has become
    unreachable or redundant and the suite is no longer protecting anything.

    Nothing is written to disk; the real module is untouched.
    """
    path = Path.cwd() / "atlas_service/step_up/resolver.py"
    source = path.read_text(encoding="utf-8")

    guard = ("    if any(rule.action is Decision.DENY for rule in ctx.matched_rules):\n"
             "        return Decision.DENY\n")
    assert source.count(guard) == 1, "the DENY guard is not where the mutation test expects it"

    mutant_src = source.replace(guard, "")
    namespace: dict = {}
    exec(compile(mutant_src, "<resolver-mutant>", "exec"), namespace)
    mutant = namespace["resolve_step_up"]

    ctx = _ctx(rules=(("large_amount", Decision.STEP_UP), ("hard_cap", Decision.DENY)))

    assert resolve_step_up(ctx, AuthResult.SUCCESS, POLICY_HASH) is Decision.DENY
    assert mutant(ctx, AuthResult.SUCCESS, POLICY_HASH) is Decision.ALLOW, (
        "removing the DENY guard changed nothing -- it is not load-bearing"
    )


# ==========================================================================
# Through the real HTTP path
# ==========================================================================


@pytest.fixture
def step_up_store(tmp_path) -> StepUpStore:
    return StepUpStore(tmp_path / "step_up.db")


@pytest.fixture
def authenticator(step_up_store):
    """The customer's out-of-band authenticator -- a phone, in production.

    ATLAS is given only the PUBLIC key. It never holds a PIN, an OTP secret or
    a biometric, and could not leak one if the database were stolen.
    """
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes_raw().hex()
    step_up_store.enroll_authenticator("user-demo-1", pub,
                                       datetime.now(timezone.utc).isoformat())
    return key


def _sign(key, challenge_id, transaction_id, env_hash) -> str:
    return key.sign(proof_message(challenge_id, transaction_id, env_hash)).hex()


def test_authenticator_enrollment_stores_only_a_public_key(step_up_store, authenticator):
    row = step_up_store.get_authenticator("user-demo-1")
    assert row is not None
    stored = row["public_key"]
    assert len(stored) == 64
    assert stored == authenticator.public_key().public_bytes_raw().hex()
    private_hex = authenticator.private_bytes_raw().hex()
    assert private_hex not in stored, "a private key reached the authenticator table"


def test_challenge_is_single_use_per_transaction(step_up_store):
    ctx = _ctx()
    now = datetime.now(timezone.utc)
    assert step_up_store.create_challenge("c1", ctx, now.isoformat(),
                                          (now + timedelta(seconds=120)).isoformat())
    assert not step_up_store.create_challenge("c2", ctx, now.isoformat(),
                                              (now + timedelta(seconds=120)).isoformat()), (
        "a second challenge for the same transaction would mint fresh attempts"
    )


def test_three_failed_attempts_exhaust_the_challenge(step_up_store):
    """The attempt budget is per challenge, claimed atomically."""
    ctx = _ctx()
    now = datetime.now(timezone.utc)
    step_up_store.create_challenge("c1", ctx, now.isoformat(),
                                   (now + timedelta(seconds=120)).isoformat())
    got = [step_up_store.claim_attempt("c1") for _ in range(STEP_UP_MAX_ATTEMPTS + 2)]
    assert got[:STEP_UP_MAX_ATTEMPTS] == list(range(1, STEP_UP_MAX_ATTEMPTS + 1))
    assert all(g is None for g in got[STEP_UP_MAX_ATTEMPTS:]), (
        "attempts continued past the cap"
    )


def test_a_challenge_resolves_exactly_once(step_up_store):
    ctx = _ctx()
    now = datetime.now(timezone.utc)
    step_up_store.create_challenge("c1", ctx, now.isoformat(),
                                   (now + timedelta(seconds=120)).isoformat())
    assert step_up_store.consume("c1", "ALLOW") is True
    assert step_up_store.consume("c1", "ALLOW") is False, "challenge authorised twice"


def test_proof_for_one_transaction_does_not_verify_for_another(authenticator):
    """Binding. The message covers challenge_id, transaction_id AND
    envelope_hash, and the verifier rebuilds it from the challenge it looked
    up -- never from anything the caller supplied."""
    good = proof_message("chal-A", "txn-A", "a" * 64)
    for bad in (
        proof_message("chal-B", "txn-A", "a" * 64),
        proof_message("chal-A", "txn-B", "a" * 64),
        proof_message("chal-A", "txn-A", "b" * 64),
    ):
        assert bad != good

    sig = authenticator.sign(good)
    pub = authenticator.public_key()
    pub.verify(sig, good)
    for bad in (
        proof_message("chal-B", "txn-A", "a" * 64),
        proof_message("chal-A", "txn-B", "a" * 64),
        proof_message("chal-A", "txn-A", "b" * 64),
    ):
        with pytest.raises(Exception):
            pub.verify(sig, bad)


def _pause(txn_store: TransactionStore, transaction_id: str) -> None:
    """A transaction exactly as /v2/transact leaves it after issuing a
    challenge: CREATED -> EVALUATING -> AWAITING_STEP_UP, through the real
    state machine."""
    from atlas_service.state_machine import transition

    now = datetime.now(timezone.utc).isoformat()
    assert txn_store.claim_new(transaction_id, "user-demo-1", "60000.00", now)
    transition(txn_store, transaction_id, TxnState.EVALUATING, now)
    transition(txn_store, transaction_id, TxnState.AWAITING_STEP_UP, now)


def _expire(step_up_db: Path, challenge_id: str) -> None:
    """Moves a challenge's expiry into the past, directly in the tmp_path
    database. The endpoint reads the real clock, so this is the only way to
    reach expiry without waiting 120s."""
    conn = sqlite3.connect(str(step_up_db))
    try:
        past = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
        conn.execute("UPDATE step_up_challenges SET expires_at = ? WHERE challenge_id = ?",
                     (past, challenge_id))
        conn.commit()
    finally:
        conn.close()


def test_expired_challenge_is_swept_to_denied(step_up_store, tmp_path):
    """Expiry always means DENIED. There is no branch in expire_stale() that
    can produce an approval.

    Fixture corrected 2026-09-16, never weakened (docs/STEP-UP-EXPIRY-FIX.md).
    This test used to build only a challenge and assert only the challenge,
    so it passed while the real defect -- the TRANSACTION left in
    AWAITING_STEP_UP forever -- went unnoticed. It now builds the paused
    transaction as well, keeps every original assertion, and adds the one its
    name always promised.
    """
    from atlas_service.step_up.service import expire_stale

    ctx = _ctx()
    txn_store = TransactionStore(tmp_path / "atlas.db")
    _pause(txn_store, ctx.transaction_id)
    past = datetime.now(timezone.utc) - timedelta(seconds=300)
    step_up_store.create_challenge("c1", ctx, past.isoformat(),
                                   (past + timedelta(seconds=120)).isoformat())
    swept = expire_stale(step_up_store, txn_store, datetime.now(timezone.utc))
    assert swept == [ctx.transaction_id]
    row = step_up_store.get_challenge("c1")
    assert row["consumed"] == 1
    assert row["outcome"] == Decision.DENY.value
    assert txn_store.get_state(ctx.transaction_id) is TxnState.DENIED, (
        "the challenge was closed but the payment was left waiting"
    )


def test_step_up_disabled_keeps_the_old_terminal_behaviour():
    """With ATLAS_ENABLE_STEP_UP off -- the default -- a STEP_UP verdict must
    behave exactly as it did before this feature existed."""
    from atlas_service.main import get_enable_step_up as flag
    import os

    saved = os.environ.pop("ATLAS_ENABLE_STEP_UP", None)
    try:
        assert flag() is False
    finally:
        if saved is not None:
            os.environ["ATLAS_ENABLE_STEP_UP"] = saved


def test_awaiting_step_up_is_not_terminal_and_denied_still_is():
    """The state machine change, pinned. DENIED must remain a dead end -- that
    is what stops a step-up resurrecting a refused payment."""
    from atlas_service.state_machine import TERMINAL_STATES, VALID_TRANSITIONS

    assert VALID_TRANSITIONS[TxnState.DENIED] == set()
    assert TxnState.DENIED in TERMINAL_STATES
    assert TxnState.AWAITING_STEP_UP not in TERMINAL_STATES
    assert VALID_TRANSITIONS[TxnState.AWAITING_STEP_UP] == {
        TxnState.ALLOWED, TxnState.DENIED,
    }
    assert TxnState.EVALUATING not in VALID_TRANSITIONS[TxnState.AWAITING_STEP_UP], (
        "a path back to EVALUATING would allow re-evaluation"
    )


# ==========================================================================
# Full HTTP round trip: /v2/transact -> challenge -> /v2/step-up -> bank
# ==========================================================================


@pytest.fixture
def e2e(tmp_path, step_up_store, authenticator):
    """The whole flow wired end to end, with step-up ENABLED.

    Every store is a tmp_path instance, so this touches no real registry, no
    real transaction db and no real challenge db.
    """
    from atlas_service.device.registry import register_demo_device
    from bank_service.main import app as bank_app
    from firmware import device_identity
    from tests.conftest import wire_bank_app_to_keys

    device_keys = tmp_path / "device-keys"
    device_identity.init_device(device_keys)
    device_db = tmp_path / "devices.db"
    register_demo_device(
        DeviceStore(device_db),
        device_id="esp32-atlas-demo-01",
        device_key_id=device_identity.get_key_id(device_keys),
        public_key=device_identity.get_public_key(device_keys),
        bound_subject="user-demo-1",
    )

    wire_bank_app_to_keys(tmp_path / "atlas-keys", tmp_path / "replay.db")
    bank = TestClient(bank_app)
    txn_store = TransactionStore(tmp_path / "atlas.db")

    atlas_app.dependency_overrides[get_bank_client] = lambda: bank
    atlas_app.dependency_overrides[get_signing_keys_dir] = lambda: tmp_path / "atlas-keys"
    atlas_app.dependency_overrides[get_transaction_store] = lambda: txn_store
    atlas_app.dependency_overrides[get_device_store] = lambda: DeviceStore(device_db)
    atlas_app.dependency_overrides[get_step_up_store] = lambda: step_up_store
    atlas_app.dependency_overrides[get_allow_counter_reset] = lambda: False
    atlas_app.dependency_overrides[get_require_device_auth] = lambda: False
    atlas_app.dependency_overrides[get_enable_step_up] = lambda: True

    yield TestClient(atlas_app), device_keys, txn_store, step_up_store, authenticator

    atlas_app.dependency_overrides.clear()
    bank_app.dependency_overrides.clear()


def _submit(client, device_keys, amount="60000.00", counter=1, boot="bootstep"):
    """A signed 60000 transaction -- the amount that fires large_amount
    (STEP_UP) without firing hard_cap (DENY)."""
    from firmware import virtual_device as vd

    cfg = vd.DeviceConfig(device_id="esp32-atlas-demo-01", boot_id=boot)
    ev = vd.read_event(preset_id=1, sequence=counter)
    txn = vd.assemble_transaction(ev, cfg)
    txn["amount"] = amount
    env = vd.build_envelope(txn, cfg, device_keys, counter=counter)
    return client.post("/v2/transact", params={"rail": "UPI"}, json=env).json(), env


def test_step_up_round_trip_produces_allow(e2e):
    """Requirements 1-4 in the approved list, over real HTTP."""
    client, keys, txn_store, su_store, auth = e2e

    body, env = _submit(client, keys)
    assert body["final_status"] == "STEP_UP", body
    challenge_id = body["challenge_id"]
    txn_id = body["transaction_id"]

    assert txn_store.get_state(txn_id) is TxnState.AWAITING_STEP_UP, (
        "STEP_UP must pause, not die"
    )

    ctx = su_store.load_context(su_store.get_challenge(challenge_id))
    proof = _sign(auth, challenge_id, txn_id, ctx.envelope_hash)

    resolved = client.post("/v2/step-up", json={
        "challenge_id": challenge_id, "transaction_id": txn_id, "proof": proof,
    }).json()

    assert resolved["final_status"] == "ALLOW", resolved
    assert resolved["step_up"]["auth_result"] == "SUCCESS"
    assert txn_store.get_state(txn_id) is TxnState.CONFIRMED


def test_bad_proof_denies_and_does_not_advance_the_transaction(e2e):
    client, keys, txn_store, su_store, auth = e2e
    body, _ = _submit(client, keys)
    challenge_id, txn_id = body["challenge_id"], body["transaction_id"]

    wrong = Ed25519PrivateKey.generate()
    ctx = su_store.load_context(su_store.get_challenge(challenge_id))
    resolved = client.post("/v2/step-up", json={
        "challenge_id": challenge_id, "transaction_id": txn_id,
        "proof": _sign(wrong, challenge_id, txn_id, ctx.envelope_hash),
    }).json()

    assert resolved["final_status"] == "DENY"
    assert resolved["step_up"]["auth_result"] == "INVALID_PROOF"
    assert txn_store.get_state(txn_id) is TxnState.AWAITING_STEP_UP


def test_three_bad_proofs_terminate_the_transaction(e2e):
    """Requirement 6: max 3 attempts, then DENIED, and no late rescue."""
    client, keys, txn_store, su_store, auth = e2e
    body, _ = _submit(client, keys)
    challenge_id, txn_id = body["challenge_id"], body["transaction_id"]
    ctx = su_store.load_context(su_store.get_challenge(challenge_id))
    wrong = Ed25519PrivateKey.generate()

    for _ in range(STEP_UP_MAX_ATTEMPTS):
        client.post("/v2/step-up", json={
            "challenge_id": challenge_id, "transaction_id": txn_id,
            "proof": _sign(wrong, challenge_id, txn_id, ctx.envelope_hash),
        })

    assert txn_store.get_state(txn_id) is TxnState.DENIED

    late = client.post("/v2/step-up", json={
        "challenge_id": challenge_id, "transaction_id": txn_id,
        "proof": _sign(auth, challenge_id, txn_id, ctx.envelope_hash),
    }).json()
    assert late["final_status"] != "ALLOW"
    assert txn_store.get_state(txn_id) is TxnState.DENIED


def test_proof_for_transaction_a_cannot_authorise_transaction_b(e2e):
    """Requirement 3, over HTTP: a genuinely valid proof, aimed elsewhere."""
    client, keys, txn_store, su_store, auth = e2e

    a, _ = _submit(client, keys, counter=1, boot="bootA")
    b, _ = _submit(client, keys, counter=2, boot="bootA")
    assert a["final_status"] == b["final_status"] == "STEP_UP"

    ctx_a = su_store.load_context(su_store.get_challenge(a["challenge_id"]))
    proof_for_a = _sign(auth, a["challenge_id"], a["transaction_id"], ctx_a.envelope_hash)

    resolved = client.post("/v2/step-up", json={
        "challenge_id": b["challenge_id"],
        "transaction_id": b["transaction_id"],
        "proof": proof_for_a,
    }).json()

    assert resolved["final_status"] == "DENY"
    assert resolved["step_up"]["auth_result"] == "INVALID_PROOF"
    assert txn_store.get_state(b["transaction_id"]) is TxnState.AWAITING_STEP_UP
    assert txn_store.get_state(a["transaction_id"]) is TxnState.AWAITING_STEP_UP


def test_hard_cap_deny_never_reaches_step_up_at_all(e2e):
    """Requirement 7 at the system level: 150000 fires hard_cap (DENY), so no
    challenge is ever minted and the transaction is terminal immediately."""
    client, keys, txn_store, su_store, auth = e2e
    body, env = _submit(client, keys, amount="150000.00")
    txn_id = env["transaction"]["transaction_id"]

    assert body["final_status"] == "DENY"
    assert "challenge_id" not in body, "a DENY must never mint a challenge"
    assert txn_store.get_state(txn_id) is TxnState.DENIED


def test_replaying_a_consumed_challenge_is_refused(e2e):
    """A successful step-up is single-use; the same proof cannot authorise
    twice."""
    client, keys, txn_store, su_store, auth = e2e
    body, _ = _submit(client, keys)
    challenge_id, txn_id = body["challenge_id"], body["transaction_id"]
    ctx = su_store.load_context(su_store.get_challenge(challenge_id))
    proof = _sign(auth, challenge_id, txn_id, ctx.envelope_hash)

    first = client.post("/v2/step-up", json={
        "challenge_id": challenge_id, "transaction_id": txn_id, "proof": proof}).json()
    assert first["final_status"] == "ALLOW"

    second = client.post("/v2/step-up", json={
        "challenge_id": challenge_id, "transaction_id": txn_id, "proof": proof}).json()
    assert second["final_status"] != "ALLOW"


def test_step_up_disabled_falls_back_to_terminal_denied(e2e):
    """With the flag off, behaviour is exactly what it was before this
    feature: STEP_UP -> DENIED, no challenge, nothing to redeem."""
    client, keys, txn_store, su_store, auth = e2e
    atlas_app.dependency_overrides[get_enable_step_up] = lambda: False

    body, env = _submit(client, keys)
    txn_id = env["transaction"]["transaction_id"]
    assert body["final_status"] == "STEP_UP"
    assert "challenge_id" not in body, "no challenge may be minted while disabled"
    assert txn_store.get_state(txn_id) is TxnState.DENIED


# ==========================================================================
# Restart cleanup -- payments left waiting (docs/STEP-UP-EXPIRY-FIX.md)
# ==========================================================================


def _challenge(store: StepUpStore, challenge_id: str, transaction_id: str, *, expired: bool) -> None:
    issued = datetime.now(timezone.utc) - timedelta(seconds=300 if expired else 10)
    assert store.create_challenge(challenge_id, _ctx(transaction_id=transaction_id),
                                  issued.isoformat(),
                                  (issued + timedelta(seconds=120)).isoformat())


def test_restart_cleanup_leaves_a_live_challenge_alone(e2e):
    """The fix must never cancel a payment the customer can still confirm:
    after the cleanup, a valid proof still completes it."""
    from atlas_service.step_up.service import expire_stale

    client, keys, txn_store, su_store, auth = e2e
    body, _ = _submit(client, keys)
    challenge_id, txn_id = body["challenge_id"], body["transaction_id"]

    assert expire_stale(su_store, txn_store, datetime.now(timezone.utc)) == []
    assert txn_store.get_state(txn_id) is TxnState.AWAITING_STEP_UP
    row = su_store.get_challenge(challenge_id)
    assert row["consumed"] == 0 and row["attempt_count"] == 0

    resolved = client.post("/v2/step-up", json={
        "challenge_id": challenge_id, "transaction_id": txn_id,
        "proof": _sign(auth, challenge_id, txn_id, su_store.load_context(row).envelope_hash),
    }).json()
    assert resolved["final_status"] == "ALLOW", resolved
    assert txn_store.get_state(txn_id) is TxnState.CONFIRMED


def test_restart_cleanup_denies_a_consumed_but_unadvanced_transaction(e2e):
    """Case E. /v2/step-up consumed the challenge as ALLOW, then the process
    stopped before the transaction moved. A retry is refused as
    UNKNOWN_CHALLENGE and cannot move it, so only the restart cleanup can
    settle it -- as DENIED, never ALLOWED."""
    from atlas_service.step_up.service import expire_stale

    client, keys, txn_store, su_store, auth = e2e
    body, _ = _submit(client, keys)
    challenge_id, txn_id = body["challenge_id"], body["transaction_id"]
    assert su_store.consume(challenge_id, Decision.ALLOW.value)  # ...and the process stops

    ctx = su_store.load_context(su_store.get_challenge(challenge_id))
    retry = client.post("/v2/step-up", json={
        "challenge_id": challenge_id, "transaction_id": txn_id,
        "proof": _sign(auth, challenge_id, txn_id, ctx.envelope_hash),
    }).json()
    assert retry["final_status"] == "FAIL_CLOSED"
    assert txn_store.get_state(txn_id) is TxnState.AWAITING_STEP_UP, "precondition: stuck"

    assert expire_stale(su_store, txn_store, datetime.now(timezone.utc)) == [txn_id]
    assert txn_store.get_state(txn_id) is TxnState.DENIED
    last = su_store.events_for(txn_id)[-1]
    assert last["event"] == "RESOLVED_ON_RESTART"
    assert "reason=CONSUMED_NOT_ADVANCED" in last["detail"]


def test_restart_cleanup_fails_closed_when_the_challenge_is_missing(step_up_store, tmp_path):
    """The two stores disagree: a waiting payment with no challenge can never
    be redeemed, so it is denied rather than left waiting."""
    from atlas_service.step_up.service import expire_stale

    txn_store = TransactionStore(tmp_path / "atlas.db")
    _pause(txn_store, "txn-orphan")
    assert expire_stale(step_up_store, txn_store, datetime.now(timezone.utc)) == ["txn-orphan"]
    assert txn_store.get_state("txn-orphan") is TxnState.DENIED


def test_restart_cleanup_only_ever_leaves_waiting_or_denied(tmp_path):
    """Every shape a waiting payment's challenge can reach, not a sample.

    Exactly two outcomes are allowed: untouched, only when the challenge is
    live and unanswered; otherwise DENIED. If a future edit lets the cleanup
    produce any other state for any shape, this fails and names the shape.
    """
    from atlas_service.step_up.service import expire_stale

    shapes = [
        # (challenge row present, consumed with outcome, expired)
        (False, None, None),
        (True, None, True),
        (True, None, False),
        (True, "ALLOW", True),
        (True, "ALLOW", False),
        (True, "DENY", True),
        (True, "DENY", False),
    ]
    for i, (present, consumed_as, expired) in enumerate(shapes):
        base = tmp_path / f"shape-{i}"
        base.mkdir()
        txn_store = TransactionStore(base / "atlas.db")
        store = StepUpStore(base / "step_up.db")
        txn_id = f"txn-shape-{i}"
        _pause(txn_store, txn_id)
        if present:
            _challenge(store, f"c-{i}", txn_id, expired=expired)
            if consumed_as is not None:
                assert store.consume(f"c-{i}", consumed_as)

        expire_stale(store, txn_store, datetime.now(timezone.utc))

        live_and_unanswered = present and consumed_as is None and not expired
        expected = TxnState.AWAITING_STEP_UP if live_and_unanswered else TxnState.DENIED
        got = txn_store.get_state(txn_id)
        assert got is expected, (
            f"present={present} consumed_as={consumed_as} expired={expired} -> {got}"
        )


def test_restart_cleanup_cannot_approve_by_construction():
    """Structural guard, same spirit as the resolver's: the cleanup's source
    must not reach for any state or call that leads toward approval."""
    src = (Path.cwd() / "atlas_service/step_up/service.py").read_text(encoding="utf-8")
    body = src.split("def expire_stale(", 1)[1]
    for banned in ("TxnState.ALLOWED", "TxnState.SIGNED", "TxnState.SUBMITTED",
                   "TxnState.CONFIRMED", "Decision.ALLOW", "_complete_allowed",
                   "build_signed_assertion", "verify_with_bank", "httpx"):
        assert banned not in body, f"restart cleanup reaches for {banned}"


def test_restart_cleanup_ignores_transactions_that_already_finished(step_up_store, tmp_path):
    """Like the five CONFIRMED step-ups on the demo machine: a consumed
    challenge whose payment already finished must not be touched."""
    from atlas_service.state_machine import transition
    from atlas_service.step_up.service import expire_stale

    txn_store = TransactionStore(tmp_path / "atlas.db")
    now = datetime.now(timezone.utc).isoformat()
    finished = {
        "txn-confirmed": ("ALLOW", [TxnState.ALLOWED, TxnState.SIGNED,
                                     TxnState.SUBMITTED, TxnState.CONFIRMED]),
        "txn-denied": ("DENY", [TxnState.DENIED]),
    }
    for txn_id, (outcome, path) in finished.items():
        _pause(txn_store, txn_id)
        _challenge(step_up_store, f"c-{txn_id}", txn_id, expired=True)
        assert step_up_store.consume(f"c-{txn_id}", outcome)
        for state in path:
            transition(txn_store, txn_id, state, now)

    assert expire_stale(step_up_store, txn_store, datetime.now(timezone.utc)) == []
    assert txn_store.get_state("txn-confirmed") is TxnState.CONFIRMED
    assert txn_store.get_state("txn-denied") is TxnState.DENIED


def test_restart_cleanup_does_not_override_a_resolution_it_lost(step_up_store, tmp_path, monkeypatch):
    """consume() is the atomic claim. If another caller resolved the challenge
    between the cleanup reading it and claiming it, that answer stands and
    the cleanup moves nothing."""
    from atlas_service.step_up.service import expire_stale

    txn_store = TransactionStore(tmp_path / "atlas.db")
    _pause(txn_store, "txn-raced")
    _challenge(step_up_store, "c-raced", "txn-raced", expired=True)
    monkeypatch.setattr(step_up_store, "consume", lambda *args, **kwargs: False)

    assert expire_stale(step_up_store, txn_store, datetime.now(timezone.utc)) == []
    assert txn_store.get_state("txn-raced") is TxnState.AWAITING_STEP_UP


def test_restart_cleanup_is_idempotent(step_up_store, tmp_path):
    from atlas_service.step_up.service import expire_stale

    txn_store = TransactionStore(tmp_path / "atlas.db")
    _pause(txn_store, "txn-twice")
    _challenge(step_up_store, "c-twice", "txn-twice", expired=True)
    now = datetime.now(timezone.utc)

    assert expire_stale(step_up_store, txn_store, now) == ["txn-twice"]
    events = len(step_up_store.events_for("txn-twice"))
    assert expire_stale(step_up_store, txn_store, now) == []
    assert txn_store.get_state("txn-twice") is TxnState.DENIED
    assert len(step_up_store.events_for("txn-twice")) == events, "second run wrote again"


def test_restart_cleanup_touches_nothing_when_step_up_was_never_used(tmp_path):
    """No step-up database means step-up was never used here: nothing to
    settle, and no file may be created as a side effect."""
    from atlas_service.main import resolve_stale_step_ups

    txn_db = tmp_path / "atlas.db"
    TransactionStore(txn_db).close()
    never_used = tmp_path / "never-used-step-up.db"
    assert resolve_stale_step_ups(txn_db, never_used) == []
    assert not never_used.exists(), "the cleanup created a step-up database"

    no_txn_db = tmp_path / "no-transactions.db"
    assert resolve_stale_step_ups(no_txn_db, never_used) == []
    assert not no_txn_db.exists() and not never_used.exists()


def test_service_startup_settles_a_payment_left_waiting(tmp_path, monkeypatch):
    """Behavioural: start the real app, so its lifespan runs, with both
    database paths pointed at tmp_path and key publishing stubbed out -- no
    real key or database is touched -- and watch a stuck payment settle.
    The step-up flag is deliberately left unset: the cleanup runs regardless
    (approved 2026-09-16)."""
    import atlas_service.main as main_mod

    txn_db, su_db = tmp_path / "atlas.db", tmp_path / "step_up.db"
    txn_store = TransactionStore(txn_db)
    _pause(txn_store, "txn-left-waiting")
    _challenge(StepUpStore(su_db), "c-left", "txn-left-waiting", expired=True)

    monkeypatch.delenv("ATLAS_ENABLE_STEP_UP", raising=False)
    monkeypatch.setattr(main_mod, "publish_public_key", lambda: None)
    monkeypatch.setattr(main_mod, "DB_PATH", txn_db)
    monkeypatch.setattr(main_mod, "STEP_UP_DB_PATH", su_db)
    with TestClient(main_mod.app):
        pass

    assert txn_store.get_state("txn-left-waiting") is TxnState.DENIED


def test_service_still_starts_if_the_restart_cleanup_fails(monkeypatch):
    """Decision approved 2026-09-16: a failed cleanup is logged and startup
    continues. Late proofs are refused after expiry regardless, so this
    trades nothing for availability."""
    import atlas_service.main as main_mod

    def broken(*args, **kwargs):
        raise RuntimeError("simulated restart-cleanup failure")

    monkeypatch.setattr(main_mod, "publish_public_key", lambda: None)
    monkeypatch.setattr(main_mod, "resolve_stale_step_ups", broken)
    with TestClient(main_mod.app) as client:
        assert client.get("/openapi.json").status_code == 200


def test_redeeming_an_expired_challenge_ends_denied(e2e, tmp_path):
    """Case C, over HTTP: a valid proof that arrives after expiry is refused
    and the payment ends DENIED. This is what keeps a waiting payment safe
    between restarts."""
    client, keys, txn_store, su_store, auth = e2e
    body, _ = _submit(client, keys)
    challenge_id, txn_id = body["challenge_id"], body["transaction_id"]
    ctx = su_store.load_context(su_store.get_challenge(challenge_id))
    _expire(tmp_path / "step_up.db", challenge_id)

    resolved = client.post("/v2/step-up", json={
        "challenge_id": challenge_id, "transaction_id": txn_id,
        "proof": _sign(auth, challenge_id, txn_id, ctx.envelope_hash),
    }).json()
    assert resolved["final_status"] == "DENY"
    assert resolved["step_up"]["auth_result"] == "EXPIRED"
    assert txn_store.get_state(txn_id) is TxnState.DENIED


def test_after_restart_cleanup_a_late_valid_proof_cannot_allow(e2e, tmp_path):
    """Case B, fixed: the cleanup settles the payment, and a valid proof
    arriving afterwards changes nothing."""
    from atlas_service.step_up.service import expire_stale

    client, keys, txn_store, su_store, auth = e2e
    body, _ = _submit(client, keys)
    challenge_id, txn_id = body["challenge_id"], body["transaction_id"]
    ctx = su_store.load_context(su_store.get_challenge(challenge_id))
    _expire(tmp_path / "step_up.db", challenge_id)

    assert expire_stale(su_store, txn_store, datetime.now(timezone.utc)) == [txn_id]
    late = client.post("/v2/step-up", json={
        "challenge_id": challenge_id, "transaction_id": txn_id,
        "proof": _sign(auth, challenge_id, txn_id, ctx.envelope_hash),
    }).json()
    assert late["final_status"] != "ALLOW"
    assert txn_store.get_state(txn_id) is TxnState.DENIED
