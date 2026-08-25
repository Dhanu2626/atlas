"""atlas_service -- the trusted core. Runs ML (Step 1) + policy (Step 2),
persists transaction state through the frozen lifecycle (Step 4), signs an
ATLAS Authorization Assertion for ALLOW decisions (Step 5), and calls out to
bank_service to independently check it (Step 3, now over the real signed
contract). Holds the private key; holds no bank-ledger data ever, by
construction (there is no ledger import here, and never will be).

Known, temporary simplification (unchanged from Step 3): with no per-subject
model caching, the ML model is fit fresh on each request from synth.py's demo
persona rather than loaded from a cached, previously-trained model.

Conservative, flagged design choice for the DENY side (unchanged from Step
3): if the policy engine's own decision is already non-ALLOW, this never
calls bank_service at all. Step 6 extends this the same way for STEP_UP and
DELAY, not just DENY -- none of the three proceed to signing, since only
ALLOW has anything to assert to the bank. Flagged scoping choice: STEP_UP and
DELAY both land in the TxnState.DENIED transaction state, same as DENY. The
frozen state list has no separate STEP_UP/DELAY state, and building the
interactive "user confirms a STEP_UP" loop is explicitly out of scope for
this step -- only the response body's own `decision` field distinguishes
them from an outright DENY.
"""

from __future__ import annotations

import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
from fastapi import Depends, FastAPI

from atlas_service import crypto
from atlas_service.bank_client import BankUnreachableError, verify_with_bank
from atlas_service.db import TransactionStore
from atlas_service.ml.model import PersonaAnomalyModel
from atlas_service.ml.synth import Persona, generate_normal_history
from atlas_service.policy.engine import POLICIES_DIR, evaluate, load_policy
from atlas_service.state_machine import InvalidTransitionError, reconcile, transition
from contracts import AssertionPayload, Decision, PolicyDecision, SignedAssertion, Transaction, TxnState

BANK_SERVICE_URL = "http://127.0.0.1:8100"

ATLAS_ISSUER = "atlas-demo"
ATLAS_AUDIENCE = "bank_service"
# BUILD-PLAN.md names a 60-120s test window for assertion expiry; 90s is the
# chosen concrete default (build-layer decision, not frozen research).
ASSERTION_TTL_SECONDS = 90

DB_PATH = Path(__file__).parent / "atlas_transactions.db"
SHARED_KEYS_DIR = Path(__file__).resolve().parent.parent / "shared_keys"
ATLAS_PUBLIC_KEY_PATH = SHARED_KEYS_DIR / "atlas_public_key.txt"


def publish_public_key(
    keys_dir: Path = crypto.DEFAULT_KEYS_DIR, shared_path: Path = ATLAS_PUBLIC_KEY_PATH
) -> None:
    """Writes this device's public key to the shared, non-Python location
    bank_service reads from (bank_service/main.py's get_atlas_public_key()).
    bank_service can't import atlas_service.crypto directly -- the enforced
    boundary -- so a plain file is the only hand-off point available. A toy
    stand-in for real key distribution/enrollment, not a solution to it;
    ARCHITECTURE.md's RQ-24 (key/policy provenance) stays unsolved by this."""
    crypto.init_device(keys_dir=keys_dir)
    shared_path.parent.mkdir(parents=True, exist_ok=True)
    shared_path.write_text(crypto.get_public_key(keys_dir=keys_dir))


@asynccontextmanager
async def _lifespan(app: FastAPI):
    publish_public_key()
    yield


app = FastAPI(title="atlas_service", lifespan=_lifespan)


def get_bank_client() -> httpx.Client:
    """Real network client by default. Tests override this (via FastAPI's
    dependency_overrides) to point at an in-process bank_service for the
    happy-path cases, or at a genuinely closed port for the failure case --
    the same production code path exercised either way, not a mock of it."""
    return httpx.Client()


def get_transaction_store() -> TransactionStore:
    """Real on-disk store by default; tests override with a tmp_path file
    for isolation, same pattern as get_bank_client()."""
    return TransactionStore(DB_PATH)


def get_signing_keys_dir() -> Path:
    """Real device identity by default; tests override this (via FastAPI's
    dependency_overrides) to point at an isolated tmp_path keys_dir instead
    -- same pattern as get_bank_client() and get_transaction_store(), and
    what lets a test's atlas-side signing and its bank-side verification
    (wired separately via conftest.py's wire_bank_app_to_keys()) agree on
    the same key without touching the real device identity on disk."""
    return crypto.DEFAULT_KEYS_DIR


def _demo_model_and_history(subject: str) -> tuple[PersonaAnomalyModel, list[Transaction]]:
    history = generate_normal_history(Persona(subject=subject), n=200, seed=42)
    model = PersonaAnomalyModel().fit(history)
    return model, history


def build_signed_assertion(
    transaction: Transaction,
    policy_decision: PolicyDecision,
    keys_dir: Path = crypto.DEFAULT_KEYS_DIR,
) -> SignedAssertion:
    """Assembles and signs the ATLAS Authorization Assertion -- the frozen
    field list from ARCHITECTURE.md, populated from this transaction plus
    the policy engine's already-computed decision. Only ever called for an
    ALLOW decision; STEP_UP/DELAY/DENY never reach this function, matching
    the module docstring's note that only ALLOW has anything to assert."""
    now = datetime.now(timezone.utc)
    payload = AssertionPayload(
        issuer=ATLAS_ISSUER,
        subject=transaction.subject,
        transaction_id=transaction.transaction_id,
        amount=str(transaction.amount),
        currency=transaction.currency,
        beneficiary=transaction.beneficiary,
        policy_version=policy_decision.policy_version,
        policy_hash=policy_decision.policy_hash,
        decision=policy_decision.decision,
        nonce=secrets.token_hex(16),
        issued_at=now.isoformat(),
        expires_at=(now + timedelta(seconds=ASSERTION_TTL_SECONDS)).isoformat(),
        audience=ATLAS_AUDIENCE,
        atlas_key_id=crypto.DEFAULT_KEY_ID,
    )
    signature = crypto.secure_sign(payload, keys_dir=keys_dir)
    return SignedAssertion(payload=payload, signature=signature)


@app.post("/evaluate")
def evaluate_endpoint(transaction: Transaction) -> dict:
    """ML + policy only -- no bank contact, no state persistence. Matches
    Step 1/2's already-verified behavior exactly; unchanged by Step 6."""
    model, history = _demo_model_and_history(transaction.subject)
    risk = model.score(transaction, history)
    policy = load_policy(POLICIES_DIR / f"{transaction.subject}.yaml")
    decision = evaluate(transaction, risk, history, policy)
    return {"risk": risk.model_dump(), "decision": decision.model_dump()}


@app.post("/transact")
def transact_endpoint(
    transaction: Transaction,
    bank_client: httpx.Client = Depends(get_bank_client),
    store: TransactionStore = Depends(get_transaction_store),
    keys_dir: Path = Depends(get_signing_keys_dir),
) -> dict:
    """The real end-to-end flow (Step 6): ML -> policy -> persist +
    transition through the frozen state machine -> (if ALLOW) sign a real
    assertion -> bank -> transition to the outcome. A network failure to the
    bank stops at UNKNOWN, deliberately not auto-reconciled here -- that's a
    separate, explicit /reconcile/{transaction_id} call, matching Step 4's
    own "restart, then reconcile" story rather than silently retrying
    within the same request."""
    now = datetime.now(timezone.utc).isoformat()
    store.create(transaction.transaction_id, transaction.subject, str(transaction.amount), now)
    transition(store, transaction.transaction_id, TxnState.EVALUATING, now)

    model, history = _demo_model_and_history(transaction.subject)
    risk = model.score(transaction, history)
    policy = load_policy(POLICIES_DIR / f"{transaction.subject}.yaml")
    decision = evaluate(transaction, risk, history, policy)

    result = {"risk": risk.model_dump(), "decision": decision.model_dump()}

    if decision.decision != Decision.ALLOW:
        transition(store, transaction.transaction_id, TxnState.DENIED, now)
        result["assertion"] = None
        result["bank_verdict"] = None
        result["final_status"] = decision.decision.value
        return result

    transition(store, transaction.transaction_id, TxnState.ALLOWED, now)
    signed = build_signed_assertion(transaction, decision, keys_dir=keys_dir)
    transition(store, transaction.transaction_id, TxnState.SIGNED, now)
    result["assertion"] = signed.model_dump(mode="json")

    transition(store, transaction.transaction_id, TxnState.SUBMITTED, now)
    try:
        verdict = verify_with_bank(bank_client, BANK_SERVICE_URL, signed)
    except BankUnreachableError:
        transition(store, transaction.transaction_id, TxnState.UNKNOWN, now)
        result["bank_verdict"] = None
        result["final_status"] = "PENDING"
        return result

    result["bank_verdict"] = verdict.model_dump()
    # ATLAS ALLOW + bank DENY -> DENY, always (the authority hierarchy, not a
    # judgment call -- ARCHITECTURE.md's "the bank wins" rule). A synchronous
    # bank rejection resolves straight to FAILED -- there's nothing ambiguous
    # left to reconcile, unlike an unreachable bank.
    if verdict.approved:
        transition(store, transaction.transaction_id, TxnState.CONFIRMED, now)
        result["final_status"] = "ALLOW"
    else:
        transition(store, transaction.transaction_id, TxnState.FAILED, now)
        result["final_status"] = "DENY"
    return result


@app.post("/reconcile/{transaction_id}")
def reconcile_endpoint(
    transaction_id: str,
    bank_client: httpx.Client = Depends(get_bank_client),
    store: TransactionStore = Depends(get_transaction_store),
) -> dict:
    """The explicit "restart, then check what actually happened" step (Day
    3's own reasoning, Step 4's mechanism, finally reachable over HTTP).
    Only meaningful for a transaction currently stuck in UNKNOWN or
    RECONCILING; anything else raises, surfaced here as a 200 with an error
    field rather than an unhandled 500, since asking to reconcile an
    already-resolved transaction is a caller mistake, not a server fault."""
    now = datetime.now(timezone.utc).isoformat()
    try:
        resolved = reconcile(store, bank_client, BANK_SERVICE_URL, transaction_id, now)
    except InvalidTransitionError as exc:
        return {"transaction_id": transaction_id, "error": str(exc)}
    return {"transaction_id": transaction_id, "state": resolved.value}
