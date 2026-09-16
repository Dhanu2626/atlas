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

Since 2026-09-11 that is still the default, with one opt-in exception: with
ATLAS_ENABLE_STEP_UP=1, a STEP_UP on the signed /v2/transact path pauses in
AWAITING_STEP_UP and is settled through /v2/step-up (atlas_service/step_up/).
A payment still waiting when the service stops is settled at the next start,
always to DENIED (resolve_stale_step_ups).
"""

from __future__ import annotations

import logging
import os
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
from fastapi import Depends, FastAPI, Request
from pydantic import BaseModel
from fastapi.responses import JSONResponse

from atlas_service import crypto
from atlas_service.adapters import (
    DEFAULT_RAIL,
    RAIL_ADAPTERS,
    SUPPORTED_RAILS,
    to_rail_payload,
)
from atlas_service.bank_client import BankUnreachableError, verify_with_bank
from atlas_service.db import TransactionStore
from atlas_service.device.db import DeviceStore
from atlas_service.device.envelope import verify_envelope
from atlas_service.ml.model import PersonaAnomalyModel
from atlas_service.ml.synth import Persona, generate_normal_history
from atlas_service.policy.engine import (
    POLICIES_DIR,
    compute_policy_hash,
    evaluate,
    load_policy,
)
from atlas_service.state_machine import InvalidTransitionError, reconcile, transition
from atlas_service.step_up.db import STEP_UP_MAX_ATTEMPTS, StepUpStore
from atlas_service.step_up.resolver import resolve_step_up
from atlas_service.step_up.service import (
    authenticate,
    envelope_hash as compute_envelope_hash,
    expire_stale,
    freeze_context,
    issue_challenge,
)
from contracts import (
    POLICY_DECISION_REASONS,
    AssertionPayload,
    AuthResult,
    DeviceEnvelope,
    Decision,
    DecisionReason,
    FinalStatus,
    PolicyDecision,
    SignedAssertion,
    Transaction,
    TxnState,
)

logger = logging.getLogger("atlas")

# Self-contained so the audit trail survives whatever the host does with
# logging. uvicorn installs its own dictConfig and does not know about this
# logger, so without an explicit handler these lines vanish -- which is how
# the first Phase 2 verification run produced no [POLICY]/[SECURITY] output
# at all. propagate=False keeps them from being duplicated if a host DOES
# configure the root logger.
if not logger.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(_handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False


def _log(transaction_id: str, stage: str, **fields: object) -> None:
    """One structured line per pipeline stage, correlated by transaction_id.

    Never logs keys, signatures, or authentication material -- only the
    decision-relevant facts an auditor needs to reconstruct why a
    transaction ended the way it did.
    """
    detail = " ".join(f"{k}={v}" for k, v in fields.items())
    logger.info("[%s] txn=%s %s", stage, transaction_id, detail)


def _outcome(
    result: dict,
    transaction_id: str,
    status: FinalStatus,
    reason: DecisionReason,
    **extra: object,
) -> dict:
    """Single place every /transact exit path goes through, so final_status
    and decision_reason can never drift apart or be forgotten."""
    result["final_status"] = status.value
    result["decision_reason"] = reason.value
    result.setdefault("assertion", None)
    result.setdefault("rail_payload", None)
    result.setdefault("bank_verdict", None)
    _log(transaction_id, "POLICY", decision=status.value, reason=reason.value, **extra)
    return result

BANK_SERVICE_URL = "http://127.0.0.1:8100"

ATLAS_ISSUER = "atlas-demo"
ATLAS_AUDIENCE = "bank_service"
# BUILD-PLAN.md names a 60-120s test window for assertion expiry; 90s is the
# chosen concrete default (build-layer decision, not frozen research).
ASSERTION_TTL_SECONDS = 90

DB_PATH = Path(__file__).parent / "atlas_transactions.db"
DEVICE_DB_PATH = Path(__file__).parent / "atlas_devices.db"
STEP_UP_DB_PATH = Path(__file__).parent / "atlas_step_up.db"
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


def resolve_stale_step_ups(
    txn_db_path: Path, step_up_db_path: Path, now: datetime | None = None
) -> list[str]:
    """Restart cleanup for step-up. Moves every transaction left in
    AWAITING_STEP_UP whose challenge has expired, was already resolved, or is
    missing to DENIED -- never to anything else -- and leaves live challenges
    for the customer to answer. See step_up.service.expire_stale().

    Runs whether or not ATLAS_ENABLE_STEP_UP is set: leftovers from earlier
    step-up use cannot be redeemed while the flag is off anyway. If either
    database does not exist yet there is nothing to settle, and it creates
    nothing -- a machine that never used step-up is not touched at all.

    Once, at startup. Deliberately not a timer (docs/STEP-UP-EXPIRY-FIX.md).
    """
    if not (txn_db_path.exists() and step_up_db_path.exists()):
        return []
    txn_store = TransactionStore(txn_db_path)
    step_up_store = StepUpStore(step_up_db_path)
    try:
        denied = expire_stale(step_up_store, txn_store, now or datetime.now(timezone.utc))
    finally:
        step_up_store.close()
        txn_store.close()
    for txn_id in denied:
        _log(txn_id, "SECURITY", event="step_up_resolved_on_restart",
             state=TxnState.DENIED.value)
    return denied


@asynccontextmanager
async def _lifespan(app: FastAPI):
    publish_public_key()
    try:
        resolve_stale_step_ups(DB_PATH, STEP_UP_DB_PATH)
    except Exception:
        # Record-keeping, not a security control: after expiry a late proof is
        # refused regardless (authenticate() checks the clock at redemption), so
        # a failure here leaves stored state stale until the next start, never
        # unsafe. Refusing to start would take the whole payment service down
        # for that. Logged loudly instead. (Decision approved 2026-09-16.)
        logger.exception("[SECURITY] step-up restart cleanup failed; continuing startup")
    yield


app = FastAPI(title="atlas_service", lifespan=_lifespan)


@app.exception_handler(Exception)
async def _fail_closed_handler(request: Request, exc: Exception) -> JSONResponse:
    """Classify any unhandled exception as FAIL_CLOSED rather than letting it
    surface as an opaque 500 with no machine-readable reason.

    The HTTP status stays 500 on purpose -- this genuinely IS a server error
    and hiding that behind a 200 would be dishonest, which is exactly what
    "do not hide the 500" rules out. What changes is that the body now says
    *what kind* of failure it was, so logs and any client that can read the
    body can distinguish "ATLAS broke" from "ATLAS said no". A device that
    only looks at the status code still fails closed, unchanged.
    """
    logger.exception("[SECURITY] unhandled exception -> FAIL_CLOSED: %s", exc)
    return JSONResponse(
        status_code=500,
        content={
            "final_status": FinalStatus.FAIL_CLOSED.value,
            "decision_reason": DecisionReason.INTERNAL_ERROR.value,
        },
    )


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


def get_device_store() -> DeviceStore:
    """Device registry, separate file from transaction state. Tests override
    with a tmp_path file, same pattern as the other dependencies."""
    return DeviceStore(DEVICE_DB_PATH)


def get_step_up_store() -> StepUpStore:
    """Challenges, frozen contexts and authenticator public keys. Separate
    file from the transaction and device stores, same pattern as those: tests
    override it with a tmp_path instance."""
    return StepUpStore(STEP_UP_DB_PATH)


def get_enable_step_up() -> bool:
    """DEFAULT OFF. With this false, a STEP_UP verdict behaves exactly as it
    did before 2026-09-11 -- straight to terminal DENIED.

    Off by default because turning it on changes what STEP_UP *does*: a
    payment that used to stop can now complete, after the customer proves
    themselves out of band. That is a real change to a financial path, so it
    ships dormant and is opted into deliberately, the same way
    ATLAS_REQUIRE_DEVICE_AUTH is.
    """
    return os.environ.get("ATLAS_ENABLE_STEP_UP", "") == "1"


def get_allow_counter_reset() -> bool:
    """SIMULATION/WOKWI ONLY -- default OFF, which is real-device behaviour.

    Enabled via ATLAS_SIMULATION_ALLOW_COUNTER_RESET=1 for the Wokwi demo,
    because Wokwi cannot reliably persist the NVS counter across simulator
    restarts. It relaxes exactly one of three independent replay defences
    (see atlas_service/device/envelope.py); the nonce layer and Phase 2's
    transaction_id layer remain fully enforced either way. Every acceptance
    is written to the device_events audit trail.
    """
    return os.environ.get("ATLAS_SIMULATION_ALLOW_COUNTER_RESET", "") == "1"


def get_require_device_auth() -> bool:
    """When true, the legacy unsigned /transact path is closed.

    Default FALSE in Phase 3.3 so every pre-existing test and the current
    Wokwi firmware keep working unchanged. While it is false, /transact is an
    authentication bypass -- that is stated plainly rather than hidden, and
    closing it is Phase 3.8's job.
    """
    return os.environ.get("ATLAS_REQUIRE_DEVICE_AUTH", "") == "1"


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


def _complete_allowed(
    transaction: Transaction,
    rail: str,
    decision: PolicyDecision,
    result: dict,
    txn_id: str,
    bank_client: httpx.Client,
    store: TransactionStore,
    keys_dir: Path,
    now: str,
) -> dict:
    """ALLOWED -> SIGNED -> SUBMITTED -> bank -> outcome.

    Extracted verbatim from _run_transaction (2026-09-11) with no behavioural
    change, so the step-up path can reach the bank through exactly the same
    code rather than a parallel copy. A second implementation of "sign and
    submit" is precisely where the two would drift.

    The caller must already have transitioned the transaction to ALLOWED --
    whether that came from a first-pass policy ALLOW or from bounded
    re-resolution is not this function's business, and deliberately so.
    """
    signed = build_signed_assertion(transaction, decision, keys_dir=keys_dir)
    transition(store, txn_id, TxnState.SIGNED, now)
    _log(txn_id, "SECURITY", event="assertion_signed", key_id=crypto.DEFAULT_KEY_ID)
    result["assertion"] = signed.model_dump(mode="json")
    result["rail_payload"] = to_rail_payload(rail, signed)

    transition(store, txn_id, TxnState.SUBMITTED, now)
    try:
        verdict = verify_with_bank(bank_client, BANK_SERVICE_URL, signed)
    except BankUnreachableError:
        # An AVAILABILITY failure, deliberately NOT folded into FAIL_CLOSED:
        # the frozen failure-mode table specifies "bank unavailable -> pending
        # -> reconciliation". The payment may yet have gone through, so the
        # outcome is genuinely unknown and must be reconciled, never guessed
        # in either direction.
        transition(store, txn_id, TxnState.UNKNOWN, now)
        return _outcome(result, txn_id, FinalStatus.PENDING,
                        DecisionReason.BANK_UNREACHABLE)

    result["bank_verdict"] = verdict.model_dump()
    # ATLAS ALLOW + bank DENY -> DENY, always (the authority hierarchy, not a
    # judgment call -- ARCHITECTURE.md's "the bank wins" rule). A synchronous
    # bank rejection resolves straight to FAILED -- there's nothing ambiguous
    # left to reconcile, unlike an unreachable bank.
    if verdict.approved:
        transition(store, txn_id, TxnState.CONFIRMED, now)
        return _outcome(result, txn_id, FinalStatus.ALLOW, DecisionReason.POLICY_ALLOW)

    transition(store, txn_id, TxnState.FAILED, now)
    return _outcome(result, txn_id, FinalStatus.DENY, DecisionReason.BANK_REJECTED,
                    bank_reason=verdict.reason)


def _run_transaction(
    transaction: Transaction,
    rail: str,
    bank_client: httpx.Client,
    store: TransactionStore,
    keys_dir: Path,
    *,
    step_up_store: StepUpStore | None = None,
    enable_step_up: bool = False,
    env_hash: str | None = None,
) -> dict:
    """The real end-to-end flow (Step 6): ML -> policy -> persist +
    transition through the frozen state machine -> (if ALLOW) sign a real
    assertion -> bank -> transition to the outcome. A network failure to the
    bank stops at UNKNOWN, deliberately not auto-reconciled here -- that's a
    separate, explicit /reconcile/{transaction_id} call, matching Step 4's
    own "restart, then reconcile" story rather than silently retrying
    within the same request.

    Step 7 adds `rail` (a query parameter, not a Transaction field -- which
    rail to submit over is routing context, not intrinsic transaction data,
    and keeping it out of the contract avoids churning a shared model both
    services depend on). It affects PRESENTATION only: bank_service still
    receives the canonical SignedAssertion, never a rail-shaped payload.
    Making the bank parse two shapes would add real risk without
    demonstrating anything the rail_payload in the response doesn't already
    show -- an approved scoping decision, not an oversight."""
    txn_id = transaction.transaction_id
    _log(txn_id, "DEVICE", event="transaction_received", subject=transaction.subject,
         amount=transaction.amount, rail=rail)

    if rail not in RAIL_ADAPTERS:
        # Validated before any state is created: a caller typo must not
        # leave a half-finished transaction persisted behind it. Now returns
        # a structured fail-closed outcome instead of a bare {"error": ...}
        # body with no final_status, which the device could only treat as
        # malformed.
        return _outcome(
            {"risk": None, "decision": None, "rail": rail},
            txn_id, FinalStatus.FAIL_CLOSED, DecisionReason.UNKNOWN_RAIL,
            supported=",".join(SUPPORTED_RAILS),
        )

    now = datetime.now(timezone.utc).isoformat()

    # --- duplicate / replayed transaction_id ------------------------------
    # Phase 2 defect fix. Previously: store.create() is INSERT OR IGNORE, so a
    # repeated id left the existing row untouched, and the very next line tried
    # to move a TERMINAL state back to EVALUATING -> InvalidTransitionError ->
    # unhandled -> HTTP 500. Reproduced against a real device id that a Wokwi
    # restart replayed (the firmware's sequence counter lives in RAM).
    #
    # This is a security-relevant condition, not a policy decision: the same id
    # arriving twice is either a replay attempt or a client that cannot
    # generate unique ids. Either way ATLAS cannot reach a trustworthy fresh
    # decision for it, so it fails closed rather than re-running policy (which
    # could return a DIFFERENT answer for an id the bank already settled) and
    # rather than echoing the cached verdict (which would mask a replay).
    # F2: this was get_state() -> create(), a check-then-act race. Two
    # concurrent requests carrying the same transaction_id could both observe
    # "absent" and both proceed to the policy engine. claim_new() makes the
    # creation indivisible -- exactly one caller inserts the row, and every
    # other caller is a duplicate by definition, whatever the state happens to
    # be at the moment it looks.
    if not store.claim_new(txn_id, transaction.subject, str(transaction.amount), now):
        existing_state = store.get_state(txn_id)
        _log(txn_id, "SECURITY", event="duplicate_transaction_id",
             existing_state=existing_state.value if existing_state else "unknown")
        return _outcome(
            {"risk": None, "decision": None, "rail": rail},
            txn_id, FinalStatus.FAIL_CLOSED, DecisionReason.DUPLICATE_TRANSACTION_ID,
            existing_state=existing_state.value if existing_state else "unknown",
        )

    transition(store, txn_id, TxnState.EVALUATING, now)

    model, history = _demo_model_and_history(transaction.subject)
    risk = model.score(transaction, history)
    policy = load_policy(POLICIES_DIR / f"{transaction.subject}.yaml")
    decision = evaluate(transaction, risk, history, policy)

    _log(txn_id, "RISK", score=round(risk.anomaly_score, 4), band=risk.risk_band,
         reasons="|".join(risk.reasons) or "none")

    result = {"risk": risk.model_dump(), "decision": decision.model_dump(), "rail": rail}

    if decision.decision != Decision.ALLOW:
        # STEP_UP with step-up enabled is the one non-ALLOW verdict that is not
        # the end of the story: the customer may still prove themselves out of
        # band. Everything else -- DENY, DELAY, and STEP_UP with the feature
        # off -- goes straight to terminal DENIED exactly as before.
        #
        # env_hash is None on the LEGACY unsigned endpoint, and that is what
        # keeps step-up off it: a challenge bound to an envelope that proves
        # nothing would be theatre, since anyone can claim any subject there.
        if (
            decision.decision == Decision.STEP_UP
            and enable_step_up
            and step_up_store is not None
            and env_hash is not None
        ):
            context = freeze_context(transaction, rail, decision, risk, policy, env_hash)
            issued = issue_challenge(step_up_store, context, datetime.now(timezone.utc))
            if issued is not None:
                challenge_id, expires_at = issued
                transition(store, txn_id, TxnState.AWAITING_STEP_UP, now)
                # _outcome()'s **extra goes to the audit LOG, not the body, so
                # the caller's half of the challenge is set on the result
                # directly. The device needs both to display and to be redeemed
                # against; neither is a secret.
                result["challenge_id"] = challenge_id
                result["step_up_expires_at"] = expires_at
                result["transaction_id"] = txn_id
                _log(txn_id, "SECURITY", event="step_up_challenge_issued",
                     challenge_id=challenge_id, expires_at=expires_at,
                     deciding_rule=decision.deciding_rule or "none")
                return _outcome(
                    result, txn_id,
                    FinalStatus.STEP_UP,
                    POLICY_DECISION_REASONS[decision.decision],
                    matched_rules="|".join(decision.matched_rules) or "none",
                    challenge_id=challenge_id,
                    step_up_expires_at=expires_at,
                )
            # Could not mint a challenge (this transaction already has one).
            # Fail closed rather than issue a second set of attempts.
            _log(txn_id, "SECURITY", event="step_up_challenge_refused",
                 detail="challenge already exists for this transaction")

        # A deliberate refusal by the policy engine. This is a DECISION, not a
        # failure -- decision_reason records which, and matched_rules says why.
        transition(store, txn_id, TxnState.DENIED, now)
        return _outcome(
            result, txn_id,
            FinalStatus(decision.decision.value),
            POLICY_DECISION_REASONS[decision.decision],
            matched_rules="|".join(decision.matched_rules) or "none",
        )

    transition(store, txn_id, TxnState.ALLOWED, now)
    return _complete_allowed(transaction, rail, decision, result, txn_id,
                             bank_client, store, keys_dir, now)


@app.post("/transact")
def transact_endpoint(
    transaction: Transaction,
    rail: str = DEFAULT_RAIL,
    bank_client: httpx.Client = Depends(get_bank_client),
    store: TransactionStore = Depends(get_transaction_store),
    keys_dir: Path = Depends(get_signing_keys_dir),
    require_device_auth: bool = Depends(get_require_device_auth),
) -> dict:
    """LEGACY, UNSIGNED path -- behaviour unchanged from Phase 2.

    This endpoint performs NO device authentication. Anyone who can reach it
    may submit any transaction claiming any device_id and any subject. That
    is stated plainly rather than hidden: it is exactly gap G1/G2 from
    docs/SECURITY-GAP-REPORT.md, and /v2/transact is the fixed path.

    It stays open by default so every pre-Phase-3 test and the currently
    flashed firmware keep working. Set ATLAS_REQUIRE_DEVICE_AUTH=1 to close
    it, which is Phase 3.8's intended end state.
    """
    if require_device_auth:
        return _outcome(
            {"risk": None, "decision": None, "rail": rail},
            transaction.transaction_id,
            FinalStatus.FAIL_CLOSED, DecisionReason.DEVICE_AUTH_REQUIRED,
            hint="use POST /v2/transact with a signed DeviceEnvelope",
        )
    return _run_transaction(transaction, rail, bank_client, store, keys_dir)


@app.post("/v2/transact")
def transact_v2_endpoint(
    envelope: DeviceEnvelope,
    rail: str = DEFAULT_RAIL,
    bank_client: httpx.Client = Depends(get_bank_client),
    store: TransactionStore = Depends(get_transaction_store),
    device_store: DeviceStore = Depends(get_device_store),
    keys_dir: Path = Depends(get_signing_keys_dir),
    allow_counter_reset: bool = Depends(get_allow_counter_reset),
    step_up_store: StepUpStore = Depends(get_step_up_store),
    enable_step_up: bool = Depends(get_enable_step_up),
) -> dict:
    """Authenticated path (Phase 3.3): a registered device cryptographically
    proves it authored this exact request before anything else happens.

    The envelope is verified FIRST -- signature, device standing, account
    binding, freshness, counter, nonce -- and only then does the identical
    decision pipeline the legacy endpoint uses run on the *contained*
    Transaction. ML, policy, thresholds, and the ALLOW/STEP_UP/DENY semantics
    are byte-for-byte the same code; Phase 3 adds authenticity in front of
    them and changes nothing about how decisions are made.
    """
    txn = envelope.transaction
    txn_id = txn.transaction_id
    _log(txn_id, "DEVICE", event="signed_envelope_received",
         device_id=envelope.device_id, device_key_id=envelope.device_key_id,
         counter=envelope.counter, rail=rail)

    verdict = verify_envelope(
        envelope, device_store, allow_counter_reset=allow_counter_reset
    )
    if not verdict.ok:
        # Authentication failure is never a policy DENY: nothing refused this
        # payment, ATLAS simply could not establish who was asking.
        _log(txn_id, "SECURITY", event="device_auth_failed",
             reason=verdict.reason.value, detail=verdict.detail)
        return _outcome(
            {"risk": None, "decision": None, "rail": rail},
            txn_id, FinalStatus.FAIL_CLOSED, verdict.reason,
            device_id=envelope.device_id,
        )

    _log(txn_id, "SECURITY", event="device_authenticated",
         device_id=verdict.device["device_id"],
         subject=verdict.device["bound_subject"],
         counter=envelope.counter)

    return _run_transaction(
        txn, rail, bank_client, store, keys_dir,
        step_up_store=step_up_store,
        enable_step_up=enable_step_up,
        # Hashing the CANONICAL bytes -- the same ones the device signed and
        # this endpoint just re-derived -- so the challenge is bound to this
        # exact request and a proof cannot be moved to another.
        env_hash=compute_envelope_hash(envelope),
    )


class StepUpProof(BaseModel):
    """What a customer's out-of-band authenticator sends back.

    Note what is NOT here: no PIN, no OTP, no biometric, no shared secret.
    ATLAS receives a SIGNATURE and a public key it already holds. It cannot
    learn the customer's credential even if this table is stolen, because it
    never had it.
    """

    challenge_id: str
    transaction_id: str
    #: Ed25519 signature, hex, over
    #: b"ATLAS-STEPUP-PROOF-v1|<challenge_id>|<transaction_id>|<envelope_hash>"
    proof: str


@app.post("/v2/step-up")
def step_up_endpoint(
    body: StepUpProof,
    bank_client: httpx.Client = Depends(get_bank_client),
    store: TransactionStore = Depends(get_transaction_store),
    keys_dir: Path = Depends(get_signing_keys_dir),
    step_up_store: StepUpStore = Depends(get_step_up_store),
    enable_step_up: bool = Depends(get_enable_step_up),
) -> dict:
    """Redeem a step-up challenge. BOUNDED RE-RESOLUTION ONLY.

    This endpoint deliberately does NOT call evaluate(), does not score the
    transaction, and does not consult the clock to decide anything. It:

      1. asks service.authenticate() whether the proof is good and the
         challenge still live -- that is where the clock and the 3-attempt cap
         live;
      2. hands the frozen context and the resulting AuthResult to
         resolve_step_up(), a pure function;
      3. obeys whatever that returns.

    The transaction that eventually reaches the bank is the one FROZEN at
    STEP_UP time, not one rebuilt from current state. That is the whole point:
    the customer authenticated a specific payment.
    """
    now_dt = datetime.now(timezone.utc)
    now = now_dt.isoformat()

    if not enable_step_up:
        return _outcome({"risk": None, "decision": None, "rail": DEFAULT_RAIL},
                        body.transaction_id, FinalStatus.FAIL_CLOSED,
                        DecisionReason.INTERNAL_ERROR,
                        hint="step-up is disabled (ATLAS_ENABLE_STEP_UP)")

    auth, context = authenticate(
        step_up_store, body.challenge_id, body.transaction_id, body.proof, now_dt
    )

    if context is None:
        # Unknown or already-consumed challenge. Nothing to resolve, and no
        # state to change -- deliberately indistinguishable from a wrong id.
        _log(body.transaction_id, "SECURITY", event="step_up_unknown_challenge")
        return _outcome({"risk": None, "decision": None, "rail": DEFAULT_RAIL},
                        body.transaction_id, FinalStatus.FAIL_CLOSED,
                        DecisionReason.DEVICE_AUTH_REQUIRED,
                        auth_result=auth.value)

    # The ONLY decision call. Pure: frozen context + auth result + the current
    # policy hash, which is read here rather than inside the resolver so the
    # resolver performs no I/O at all.
    current_hash = compute_policy_hash(load_policy(POLICIES_DIR / f"{context.subject}.yaml"))
    outcome_decision = resolve_step_up(context, auth, current_hash)

    _log(context.transaction_id, "SECURITY", event="step_up_resolved",
         auth_result=auth.value, decision=outcome_decision.value,
         original_decision=context.original_decision.value,
         deciding_rule=context.deciding_rule or "none")

    result = {
        "risk": {"risk_band": context.risk_band, "anomaly_score": context.anomaly_score},
        "decision": {
            "decision": context.original_decision.value,
            "matched_rules": [r.name for r in context.matched_rules],
            "deciding_rule": context.deciding_rule,
            "policy_version": context.policy_version,
            "policy_hash": context.policy_hash,
        },
        "rail": context.rail,
        "step_up": {"auth_result": auth.value, "resolved": outcome_decision.value},
        "transaction_id": context.transaction_id,
    }

    if outcome_decision != Decision.ALLOW:
        # Consume only on a terminal answer. A wrong proof with attempts left
        # leaves the challenge open so the customer can try again; an exhausted
        # or expired one is closed here for good.
        if auth in (AuthResult.INVALID_PROOF, AuthResult.NO_AUTHENTICATOR):
            row = step_up_store.get_challenge(body.challenge_id)
            if row is not None and row["attempt_count"] >= STEP_UP_MAX_ATTEMPTS:
                step_up_store.consume(body.challenge_id, Decision.DENY.value)
                transition(store, context.transaction_id, TxnState.DENIED, now)
        else:
            step_up_store.consume(body.challenge_id, Decision.DENY.value)
            if store.get_state(context.transaction_id) == TxnState.AWAITING_STEP_UP:
                transition(store, context.transaction_id, TxnState.DENIED, now)
        return _outcome(result, context.transaction_id, FinalStatus.DENY,
                        DecisionReason.POLICY_STEP_UP, auth_result=auth.value)

    # Success. Consume first: if this loses the race, another caller already
    # resolved this challenge and we must not authorise twice.
    if not step_up_store.consume(body.challenge_id, Decision.ALLOW.value):
        return _outcome(result, context.transaction_id, FinalStatus.FAIL_CLOSED,
                        DecisionReason.DUPLICATE_TRANSACTION_ID,
                        hint="challenge already resolved")

    transition(store, context.transaction_id, TxnState.ALLOWED, now)
    frozen_decision = PolicyDecision(
        transaction_id=context.transaction_id,
        decision=Decision.ALLOW,
        policy_version=context.policy_version,
        policy_hash=context.policy_hash,
        matched_rules=[r.name for r in context.matched_rules],
        deciding_rule=context.deciding_rule,
    )
    return _complete_allowed(context.transaction, context.rail, frozen_decision,
                             result, context.transaction_id,
                             bank_client, store, keys_dir, now)


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
