"""The impure half of step-up: clock, storage, signature verification.

Everything here exists so that resolver.resolve_step_up() can stay pure. This
module reads the clock, touches the database and verifies cryptography; it then
hands the resolver a frozen context and a single decided AuthResult.

The split is deliberate and load-bearing. "Is this challenge still valid?" is a
question about the world and belongs here. "What is the answer?" is a question
about the frozen decision and belongs there. Mixing them is how a re-evaluation
sneaks back in.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from atlas_service.db import TransactionStore
from atlas_service.state_machine import NEEDS_STEP_UP_EXPIRY, transition
from atlas_service.step_up.db import (
    STEP_UP_EXPIRY_SECONDS,
    StepUpStore,
)
from contracts import (
    AuthResult,
    Decision,
    FrozenDecisionContext,
    MatchedRule,
    PolicyDecision,
    RiskEvidence,
    Transaction,
    TxnState,
    canonical_envelope_bytes,
)

#: Domain separator. Without it, a signature produced for a step-up proof
#: could in principle be replayed into any other protocol that signs a bare
#: concatenation with the same key -- and vice versa. Cheap, and the absence of
#: one is a classic cross-protocol bug.
_PROOF_DOMAIN = b"ATLAS-STEPUP-PROOF-v1"


def envelope_hash(envelope) -> str:
    """SHA-256 over the canonical signed bytes of the envelope.

    Uses canonical_envelope_bytes() -- the same bytes the device signed and
    atlas_service re-derived -- so the hash identifies exactly the request that
    was authenticated, and cannot be made to match a different one.
    """
    return hashlib.sha256(canonical_envelope_bytes(envelope)).hexdigest()


def proof_message(challenge_id: str, transaction_id: str, env_hash: str) -> bytes:
    """The exact bytes an authenticator signs.

    Binding all three together is what stops a valid proof for transaction A
    authorising transaction B: the verifier rebuilds this message from the
    challenge it looked up, not from anything the caller supplied.
    """
    return b"|".join([
        _PROOF_DOMAIN,
        challenge_id.encode("utf-8"),
        transaction_id.encode("utf-8"),
        env_hash.encode("utf-8"),
    ])


def freeze_context(
    transaction: Transaction,
    rail: str,
    decision: PolicyDecision,
    risk: RiskEvidence,
    policy: dict,
    env_hash: str,
) -> FrozenDecisionContext:
    """Captures the decision exactly as it stood, including each matched
    rule's ACTION.

    The actions are the reason this function exists. PolicyDecision carries
    rule names only; the resolver's DENY guard needs actions, and looking them
    up later would mean re-reading the policy -- recomputation, which is
    forbidden. `policy` is the dict already in hand at decision time, so
    nothing is loaded again here either.
    """
    action_by_name = {r["name"]: Decision(r["action"]) for r in policy.get("rules", [])}
    return FrozenDecisionContext(
        transaction_id=transaction.transaction_id,
        subject=transaction.subject,
        transaction=transaction,
        rail=rail,
        original_decision=decision.decision,
        matched_rules=[
            MatchedRule(name=n, action=action_by_name[n])
            for n in decision.matched_rules
            if n in action_by_name
        ],
        deciding_rule=decision.deciding_rule,
        policy_version=decision.policy_version,
        policy_hash=decision.policy_hash,
        risk_band=risk.risk_band,
        anomaly_score=risk.anomaly_score,
        envelope_hash=env_hash,
    )


def issue_challenge(
    store: StepUpStore,
    context: FrozenDecisionContext,
    now: datetime,
) -> tuple[str, str] | None:
    """Mints a single-use challenge. Returns (challenge_id, expires_at) or
    None if this transaction already has one.

    128 bits of randomness, so a challenge id cannot be guessed or enumerated.
    """
    challenge_id = secrets.token_hex(16)
    expires = now + timedelta(seconds=STEP_UP_EXPIRY_SECONDS)
    ok = store.create_challenge(
        challenge_id, context, now.isoformat(), expires.isoformat()
    )
    if not ok:
        return None
    store.record_event(challenge_id, context.transaction_id, "CHALLENGE_ISSUED",
                       f"expires_at={expires.isoformat()}", now.isoformat())
    return challenge_id, expires.isoformat()


def authenticate(
    store: StepUpStore,
    challenge_id: str,
    transaction_id: str,
    proof_hex: str,
    now: datetime,
) -> tuple[AuthResult, FrozenDecisionContext | None]:
    """Decides ONLY whether the proof is good and the challenge still live.

    Returns a single AuthResult plus the frozen context. It never decides the
    transaction's outcome -- that is resolve_step_up()'s job, and keeping the
    two apart is what keeps the resolver pure.

    Order matters: existence, then consumption, then expiry, then attempt
    budget, then cryptography. Cheap refusals first, and the attempt is only
    burned once we know the challenge is genuinely live.
    """
    row = store.get_challenge(challenge_id)
    if row is None or row["consumed"]:
        # Same answer for "never existed" and "already used", so the endpoint
        # cannot be used as an oracle to discover valid challenge ids.
        return AuthResult.UNKNOWN_CHALLENGE, None

    ctx = store.load_context(row)

    # The caller does not get to say which transaction this is for; the
    # challenge does. A mismatch means someone is trying to move a proof.
    if transaction_id != ctx.transaction_id:
        store.record_event(challenge_id, ctx.transaction_id, "BINDING_MISMATCH",
                           f"claimed={transaction_id}", now.isoformat())
        return AuthResult.BINDING_MISMATCH, ctx

    if now >= datetime.fromisoformat(row["expires_at"]):
        store.record_event(challenge_id, ctx.transaction_id, "EXPIRED", "", now.isoformat())
        return AuthResult.EXPIRED, ctx

    attempt = store.claim_attempt(challenge_id)
    if attempt is None:
        store.record_event(challenge_id, ctx.transaction_id, "ATTEMPTS_EXHAUSTED",
                           "", now.isoformat())
        return AuthResult.ATTEMPTS_EXHAUSTED, ctx

    auth_row = store.get_authenticator(ctx.subject)
    if auth_row is None:
        store.record_event(challenge_id, ctx.transaction_id, "NO_AUTHENTICATOR",
                           f"subject={ctx.subject}", now.isoformat())
        return AuthResult.NO_AUTHENTICATOR, ctx

    message = proof_message(challenge_id, ctx.transaction_id, ctx.envelope_hash)
    try:
        Ed25519PublicKey.from_public_bytes(
            bytes.fromhex(auth_row["public_key"])
        ).verify(bytes.fromhex(proof_hex), message)
    except (InvalidSignature, ValueError):
        store.record_event(challenge_id, ctx.transaction_id, "INVALID_PROOF",
                           f"attempt={attempt}", now.isoformat())
        return AuthResult.INVALID_PROOF, ctx

    store.record_event(challenge_id, ctx.transaction_id, "PROOF_VERIFIED",
                       f"attempt={attempt}", now.isoformat())
    return AuthResult.SUCCESS, ctx


def expire_stale(
    step_up_store: StepUpStore,
    txn_store: TransactionStore,
    now: datetime,
) -> list[str]:
    """Restart cleanup for transactions left in AWAITING_STEP_UP. Returns the
    ids it moved to DENIED.

    Runs once at startup, before the service accepts requests
    (main.resolve_stale_step_ups), so it never races a customer who is
    answering. Every transaction it touches ends in DENIED: there is no branch
    here that approves, signs or contacts the bank, by construction.

    Fixed 2026-09-16 (docs/STEP-UP-EXPIRY-FIX.md). The previous version walked
    expired CHALLENGES, consumed them and never moved their TRANSACTIONS -- and
    once a challenge is consumed, /v2/step-up refuses it as UNKNOWN_CHALLENGE
    without touching state, so calling that version would have stranded the
    transaction for good. This one starts from the waiting transactions
    instead, which also finds the ones whose challenge is consumed or missing.
    """
    denied: list[str] = []
    for txn_id in txn_store.find_in_states(NEEDS_STEP_UP_EXPIRY):
        row = step_up_store.get_challenge_for_transaction(txn_id)
        if row is None:
            # The two stores disagree. Nothing can ever redeem this
            # transaction, so fail closed.
            reason = "NO_CHALLENGE"
        elif row["consumed"]:
            # /v2/step-up resolved the challenge but the process stopped before
            # the transaction moved: two writes, two databases. A retry is
            # refused as UNKNOWN_CHALLENGE, so nothing else can settle it.
            # DENIED even if the recorded outcome was ALLOW -- the bank was
            # never contacted, and approving at startup, with no live request
            # behind it, is exactly the guess this service never makes.
            reason = "CONSUMED_NOT_ADVANCED"
        elif now >= datetime.fromisoformat(row["expires_at"]):
            if not step_up_store.consume(row["challenge_id"], Decision.DENY.value):
                continue  # resolved by someone else first; that answer stands
            reason = "EXPIRED"
        else:
            continue  # still live: the customer may yet answer

        transition(txn_store, txn_id, TxnState.DENIED, now.isoformat())
        step_up_store.record_event(
            row["challenge_id"] if row is not None else None, txn_id,
            "RESOLVED_ON_RESTART", f"reason={reason} state=DENIED", now.isoformat(),
        )
        denied.append(txn_id)
    return denied
