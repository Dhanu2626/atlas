"""atlas_service -- the trusted core. Runs ML (Step 1) + policy (Step 2),
persists transaction state through the frozen lifecycle (Step 4), signs an
ATLAS Authorization Assertion for ALLOW decisions (Step 5), and calls out to
bank_service to independently check it (Step 3, now over the real signed
contract). Holds the private key; holds no bank-ledger data ever, by
construction (there is no ledger import here, and never will be).

ML lifecycle (since 2026-09-22): the request path performs INFERENCE ONLY. Each
subject's model is trained by an explicit step (scripts/train_models.py), saved
with an integrity tag, and loaded once by a ModelRegistry (atlas_service/ml/
registry.py) that hands the same fitted model to every request. Until then the
model was refit from synth.py's demo persona on every request. A subject with no
trustworthy model fails closed before any state is created.

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
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel
from fastapi.responses import JSONResponse

from atlas_service import crypto, tls, transport
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
from atlas_service.ml.registry import ModelRegistry, ModelUnavailableError
from atlas_service.policy.engine import (
    POLICIES_DIR,
    compute_policy_hash,
    evaluate,
    load_policy,
    RolledBackPolicyError,
)
from atlas_service.policy.version_store import (
    PolicyStateUnavailableError,
    PolicyVersionStore,
    TamperedPolicyError,
)
from atlas_service.state_machine import InvalidTransitionError, reconcile, transition
from atlas_service.step_up.db import StepUpStore
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

#: HTTPS by default since 2026-09-22, with the bank's certificate verified
#: against the local test CA and mutual TLS (atlas_service/tls.py). Overridable
#: with ATLAS_BANK_URL; a plain-http URL is accepted only on loopback or with the
#: explicit development override (atlas_service/transport.py).
BANK_SERVICE_URL = os.environ.get("ATLAS_BANK_URL", "https://127.0.0.1:8100")

ATLAS_ISSUER = "atlas-demo"
ATLAS_AUDIENCE = "bank_service"
# BUILD-PLAN.md names a 60-120s test window for assertion expiry; 90s is the
# chosen concrete default (build-layer decision, not frozen research).
ASSERTION_TTL_SECONDS = 90

# ATLAS_STATE_DIR moves every database and the shared public-key file into one
# folder, for a disposable run that must not touch the live state
# (scripts/run_sim.py --state-dir). Unset, the defaults are unchanged. The
# signing key itself stays where it is: a disposable run uses it, never rewrites it.
_STATE_DIR = os.environ.get("ATLAS_STATE_DIR")
_STATE_BASE = Path(_STATE_DIR) if _STATE_DIR else Path(__file__).parent
DB_PATH = _STATE_BASE / "atlas_transactions.db"
DEVICE_DB_PATH = _STATE_BASE / "atlas_devices.db"
STEP_UP_DB_PATH = _STATE_BASE / "atlas_step_up.db"
#: The highest policy version decided under, per subject (policy/version_store.py,
#: 2026-09-25). Its own file: adding it migrates no existing database.
POLICY_STATE_DB_PATH = _STATE_BASE / "atlas_policy_state.db"
SHARED_KEYS_DIR = (Path(_STATE_DIR) / "shared_keys" if _STATE_DIR
                   else Path(__file__).resolve().parent.parent / "shared_keys")
ATLAS_PUBLIC_KEY_PATH = SHARED_KEYS_DIR / "atlas_public_key.txt"

#: Step-up outcomes that refuse and change nothing (D1, 2026-09-18). Each means
#: "no valid proof arrived": a wrong transaction_id, a bad or malformed
#: signature, or no enrolled authenticator. Producing any of them needs no
#: secret, only the two ids, so none of them may close a challenge, deny a
#: payment, or say anything about what was decided. Expiry is not in this set:
#: it is terminal by the clock, which no attacker controls.
REFUSED_WITHOUT_STATE_CHANGE = frozenset({
    AuthResult.BINDING_MISMATCH,
    AuthResult.INVALID_PROOF,
    AuthResult.NO_AUTHENTICATOR,
})


def publish_public_key(
    keys_dir: Path = crypto.DEFAULT_KEYS_DIR, shared_path: Path | None = None
) -> None:
    """Writes this device's public key to the shared, non-Python location
    bank_service reads from (bank_service/main.py's get_atlas_public_key()).
    bank_service can't import atlas_service.crypto directly -- the enforced
    boundary -- so a plain file is the only hand-off point available. A toy
    stand-in for real key distribution/enrollment, not a solution to it;
    ARCHITECTURE.md's RQ-24 (key/policy provenance) stays unsolved by this."""
    shared_path = Path(shared_path or ATLAS_PUBLIC_KEY_PATH)
    crypto.init_device(keys_dir=keys_dir)
    public_key = crypto.get_public_key(keys_dir=keys_dir)
    shared_path.parent.mkdir(parents=True, exist_ok=True)
    # Rewrite only if it changed: the file is the bank's trust anchor, and an
    # identical rewrite on every start served no purpose.
    if not shared_path.exists() or shared_path.read_text().strip() != public_key:
        shared_path.write_text(public_key)


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
    # Refuse to start rather than send signed decisions and risk evidence to a
    # non-loopback bank over plain HTTP (D6, 2026-09-18). Loopback stays plain
    # HTTP by documented default; https is accepted; anything else needs
    # ATLAS_ALLOW_INSECURE_HTTP=1 and says so in the log.
    logger.info("[SECURITY] %s", transport.check_outbound_url(BANK_SERVICE_URL, what="bank client"))
    if tls.is_production():
        # The production transport profile refuses to START without its material
        # (TLS 1.3 context, ca.crl, bank.pin): unlike development, it does not run
        # on and let payments settle PENDING. An unknown profile value raises above.
        tls.pinned_bank_transport().close()
        logger.info("[SECURITY] bank client: PRODUCTION profile -- mutual TLS 1.3, CRL checked, "
                    "bank public key pinned; local test CA, not a public PKI")
    elif BANK_SERVICE_URL.startswith("https://"):
        try:
            _bank_tls_context()
            logger.info("[SECURITY] bank client: mutual TLS, bank certificate verified against "
                        "the local test CA")
        except tls.TLSMaterialError as exc:
            logger.error("[SECURITY] %s -- payments that reach the bank will settle PENDING "
                         "(never approved) until it is fixed", exc)
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
    # LOAD (never train) each policy subject's model now, so a missing or
    # altered artifact is reported at startup instead of on the first payment.
    # A subject without a trustworthy model still fails closed per request.
    for policy_file in sorted(POLICIES_DIR.glob("*.yaml")):
        try:
            MODEL_REGISTRY.get(policy_file.stem)
            logger.info("[ML] model for %s loaded; requests infer only", policy_file.stem)
        except ModelUnavailableError as exc:
            logger.warning("[ML] %s -- requests for %s fail closed until "
                           "scripts/train_models.py runs", exc, policy_file.stem)
    yield


app = FastAPI(title="atlas_service", lifespan=_lifespan)

#: A signed DeviceEnvelope is about 1 KB. Anything over 64 KiB is refused before
#: it is parsed, so an oversized body costs the service nothing (red-team
#: attack 24, 2026-09-22).
MAX_REQUEST_BYTES = 64 * 1024


class _BodyTooLarge(Exception):
    pass


class _RequestSizeLimit:
    """Pure ASGI middleware: refuses a body over MAX_REQUEST_BYTES, whether it
    declares its length up front or streams it in chunks."""

    def __init__(self, inner):
        self.inner = inner

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.inner(scope, receive, send)
        declared = dict(scope.get("headers") or []).get(b"content-length")
        if declared is not None and declared.isdigit() and int(declared) > MAX_REQUEST_BYTES:
            return await _send_too_large(send)
        seen = 0

        async def limited_receive():
            nonlocal seen
            message = await receive()
            if message["type"] == "http.request":
                seen += len(message.get("body", b""))
                if seen > MAX_REQUEST_BYTES:
                    raise _BodyTooLarge()
            return message

        try:
            await self.inner(scope, limited_receive, send)
        except _BodyTooLarge:
            await _send_too_large(send)


async def _send_too_large(send) -> None:
    import json as _json
    body = _json.dumps({"final_status": FinalStatus.FAIL_CLOSED.value,
                        "decision_reason": DecisionReason.MALFORMED_ENVELOPE.value,
                        "detail": f"request body over {MAX_REQUEST_BYTES} bytes"}).encode()
    await send({"type": "http.response.start", "status": 413,
                "headers": [(b"content-type", b"application/json"),
                            (b"content-length", str(len(body)).encode())]})
    await send({"type": "http.response.body", "body": body})


app.add_middleware(_RequestSizeLimit)


@app.exception_handler(RequestValidationError)
async def _malformed_request_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """A body that is not valid JSON, or not the contract's shape, fails closed
    in ATLAS's own machine-readable form (red-team attack 23). FastAPI's default
    422 echoes the rejected input back; this reports only where it failed."""
    logger.info("[SECURITY] malformed request refused: %d validation error(s) on %s",
                len(exc.errors()), request.url.path)
    return JSONResponse(status_code=422, content={
        "final_status": FinalStatus.FAIL_CLOSED.value,
        "decision_reason": DecisionReason.MALFORMED_ENVELOPE.value,
        "errors": [{"loc": [str(part) for part in e.get("loc", ())], "type": e.get("type")}
                   for e in exc.errors()][:10],
    })


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


_BANK_TLS = {"context": None}


def _bank_tls_context():
    """Built once per process: CA verification plus the client certificate
    for mutual TLS. Raises tls.TLSMaterialError if the material is missing."""
    if _BANK_TLS["context"] is None:
        _BANK_TLS["context"] = tls.client_context()
    return _BANK_TLS["context"]


class _RefusingTransport(httpx.BaseTransport):
    """Used when the bank URL is https but the TLS material is unusable. Every
    request fails as unreachable -- which settles PENDING, never approval --
    rather than being retried over plain HTTP."""

    def __init__(self, reason: str):
        self.reason = reason

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(f"TLS to the bank unavailable: {self.reason}", request=request)


def get_bank_client():
    """Real network client by default: for an https bank URL, mutual TLS with
    the bank's certificate verified (atlas_service/tls.py); there is no
    plaintext fallback. Tests override this (via FastAPI's dependency_overrides)
    to point at an in-process bank_service, a real TLS server, or a genuinely
    closed port -- the same production code path exercised either way."""
    try:
        production = tls.is_production()
    except tls.TLSMaterialError as exc:        # an unrecognised profile value
        production, profile_error = True, str(exc)
    else:
        profile_error = None
    if production:
        # ATLAS_TRANSPORT_PROFILE=production (2026-09-25): TLS 1.3 only, the CRL
        # checked, the bank's public key pinned before any byte is sent, and no
        # plain HTTP at all. Anything missing refuses -- PENDING, never approval.
        if profile_error:
            client = httpx.Client(transport=_RefusingTransport(profile_error))
        elif not BANK_SERVICE_URL.startswith("https://"):
            client = httpx.Client(transport=_RefusingTransport(
                "the production transport profile never calls the bank over plain HTTP"))
        else:
            try:
                client = httpx.Client(transport=tls.pinned_bank_transport())
            except tls.TLSMaterialError as exc:
                client = httpx.Client(transport=_RefusingTransport(str(exc)))
    elif BANK_SERVICE_URL.startswith("https://"):
        try:
            client = httpx.Client(verify=_bank_tls_context())
        except tls.TLSMaterialError as exc:
            client = httpx.Client(transport=_RefusingTransport(str(exc)))
    else:
        client = httpx.Client()
    try:
        yield client
    finally:
        client.close()


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


def get_policy_version_store():
    """The non-rollback record (ARCHITECTURE.md principle 7). Same pattern as the
    other stores: tests override it, or conftest points the path at a temp file.
    An unopenable store is not skipped -- the request refuses instead."""
    try:
        store = PolicyVersionStore(POLICY_STATE_DB_PATH)
    except PolicyStateUnavailableError:
        yield None
        return
    try:
        yield store
    finally:
        store.close()


def _admitted_policy(subject: str, versions: PolicyVersionStore | None, txn_id: str,
                     *, record: bool) -> tuple[dict | None, str | None]:
    """Loads the subject's policy and checks it against the recorded active
    version BEFORE anything is decided or persisted. Returns (policy, None), or
    (None, reason) when ATLAS must refuse: an older version (rollback), the same
    version with different content (tampering), or a version store that cannot
    be read, in which case a rollback cannot be ruled out. Never falls through
    to a decision."""
    policy = load_policy(POLICIES_DIR / f"{subject}.yaml")
    if versions is None:
        _log(txn_id, "SECURITY", event="policy_state_unavailable", subject=subject)
        return None, "policy_state_unavailable"
    try:
        versions.admit(subject, policy["version"], compute_policy_hash(policy), record=record)
    except RolledBackPolicyError as exc:
        _log(txn_id, "SECURITY", event="policy_rollback_rejected", subject=subject,
             attempted_version=exc.attempted_version, active_version=exc.seen_version)
        return None, "policy_rollback"
    except TamperedPolicyError as exc:
        _log(txn_id, "SECURITY", event="policy_tamper_rejected", subject=subject,
             version=exc.version)
        return None, "policy_tampered"
    except PolicyStateUnavailableError:
        _log(txn_id, "SECURITY", event="policy_state_unavailable", subject=subject)
        return None, "policy_state_unavailable"
    return policy, None


def get_enable_step_up() -> bool:
    """DEFAULT OFF. With this false, a STEP_UP verdict behaves exactly as it
    did before 2026-09-11 -- straight to terminal DENIED.

    Off by default because turning it on changes what STEP_UP *does*: a
    payment that used to stop can now complete, after the customer proves
    themselves out of band. That is a real change to a financial path, so it
    ships dormant and is opted into deliberately.
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
    """Whether the legacy unsigned /transact path is closed. ALWAYS TRUE in a
    running service.

    History: open by default until 2026-09-18 (an authentication bypass beside
    the signed path); closed by default from 2026-09-18 with
    ATLAS_REQUIRE_DEVICE_AUTH=0 as a process-level escape hatch (D5); and since
    2026-09-22 there is no process-level switch at all. Nothing needs the path:
    the firmware has signed to /v2/transact since F3, and the dashboard export
    and run_sim.py use the signed path too.

    The route stays only for the pre-Phase-3 tests, which exercise the decision
    pipeline through the old contract and open it the one way that exists -- a
    FastAPI dependency override inside the test process. No environment
    variable, flag or configuration file can open it in a running service.
    """
    return True


#: One registry per process: models are loaded on first use and then shared by
#: every request. Tests point this at a registry trained into a temporary folder.
MODEL_REGISTRY = ModelRegistry()


def get_model_registry() -> ModelRegistry:
    """The trained models the request path scores with. Never trains."""
    return MODEL_REGISTRY


def get_signing_keys_dir() -> Path:
    """Real device identity by default; tests override this (via FastAPI's
    dependency_overrides) to point at an isolated tmp_path keys_dir instead
    -- same pattern as get_bank_client() and get_transaction_store(), and
    what lets a test's atlas-side signing and its bank-side verification
    (wired separately via conftest.py's wire_bank_app_to_keys()) agree on
    the same key without touching the real device identity on disk."""
    return crypto.DEFAULT_KEYS_DIR


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
def evaluate_endpoint(
    transaction: Transaction,
    registry: ModelRegistry = Depends(get_model_registry),
    store: TransactionStore = Depends(get_transaction_store),
    policy_versions: PolicyVersionStore | None = Depends(get_policy_version_store),
) -> dict:
    """ML + policy only -- no bank contact, no state persistence. Matches
    Step 1/2's already-verified behavior exactly; unchanged by Step 6.

    It reads the same live history the deciding path does (2026-09-23) so that
    asking "what would you decide?" cannot answer from a different world than the
    one /v2/transact decides in. It still persists nothing: this transaction is
    not recorded, and excluding its id keeps that true even if an earlier request
    already stored one with the same id."""
    try:
        trained = registry.get(transaction.subject)
    except ModelUnavailableError as exc:
        _log(transaction.transaction_id, "SECURITY", event="ml_unavailable", detail=str(exc))
        return _outcome({"risk": None, "decision": None}, transaction.transaction_id,
                        FinalStatus.FAIL_CLOSED, DecisionReason.INTERNAL_ERROR, detail="ml_unavailable")
    history = store.history_for(transaction.subject,
                                exclude_transaction_id=transaction.transaction_id)
    # Read-only: the same non-rollback check as the deciding path, but a newer
    # version seen here is not recorded -- /evaluate persists nothing.
    policy, refused = _admitted_policy(transaction.subject, policy_versions,
                                       transaction.transaction_id, record=False)
    if refused:
        return _outcome({"risk": None, "decision": None, "policy_refusal": refused},
                        transaction.transaction_id,
                        FinalStatus.FAIL_CLOSED, DecisionReason.INTERNAL_ERROR, detail=refused)
    risk = trained.score(transaction, history)
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
    except BankUnreachableError as exc:
        _log(txn_id, "SECURITY", event="bank_outcome_unknown", kind=type(exc).__name__)
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
    registry: ModelRegistry,
    policy_versions: PolicyVersionStore | None,
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

    # ML unavailable -- no artifact, or one that failed its integrity check --
    # fails closed BEFORE any state exists, like an unknown rail: nothing is
    # persisted, nothing is scored, and nothing can be approved. (The frozen
    # table's "fall back to deterministic policy" remains unbuilt; refusing is
    # the conservative reading, and it never yields ALLOW.)
    try:
        trained = registry.get(transaction.subject)
    except ModelUnavailableError as exc:
        _log(txn_id, "SECURITY", event="ml_unavailable", detail=str(exc))
        return _outcome(
            {"risk": None, "decision": None, "rail": rail},
            txn_id, FinalStatus.FAIL_CLOSED, DecisionReason.INTERNAL_ERROR,
            detail="ml_unavailable",
        )

    # Policy integrity -- version + hash + non-rollback (ARCHITECTURE.md principle
    # 7; "Policy rollback detected -> reject"). Checked here, before any state
    # exists, like the ML check above: a refused policy leaves nothing behind.
    # The policy admitted here is the exact object decided with below -- it is
    # not read from disk a second time.
    policy, refused = _admitted_policy(transaction.subject, policy_versions, txn_id, record=True)
    if refused:
        return _outcome(
            {"risk": None, "decision": None, "rail": rail, "policy_refusal": refused},
            txn_id, FinalStatus.FAIL_CLOSED, DecisionReason.INTERNAL_ERROR,
            detail=refused,
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

    # The rest of the transaction is stored the moment the claim succeeds, so this
    # payment becomes part of the subject's history for the NEXT one. Written
    # before the decision, not after, so a crash mid-decision still leaves a
    # complete record of what was attempted (2026-09-23).
    store.record_details(transaction)

    transition(store, txn_id, TxnState.EVALUATING, now)

    # THE HISTORY THIS DECISION IS MADE AGAINST: this subject's own persisted
    # payments, excluding the one being decided so it can never appear in its own
    # baseline. Until 2026-09-23 both the policy engine and the ML features read
    # the model's generated training history instead, so a burst of real payments
    # never moved velocity and a real beneficiary was never "known". The model
    # itself is still the one trained offline on reference data -- training and
    # inference stay separate; only what it scores AGAINST is now real.
    history = store.history_for(transaction.subject, exclude_transaction_id=txn_id)

    # Inference only: the model was trained and loaded before this request.
    risk = trained.score(transaction, history)
    decision = evaluate(transaction, risk, history, policy)

    # The separate burst evidence is logged on its own, fired or not, so an auditor
    # can see every time ATLAS found activity outside the customer's observed range
    # -- and that it was evidence only (2026-09-26).
    rsig = risk.range_signal
    _log(txn_id, "RISK",
         score=round(risk.anomaly_score, 4) if risk.anomaly_score is not None else "not_scored",
         band=risk.risk_band,
         beyond_observed_range=("not_evaluated" if rsig is None else
                                f"{'FIRED' if rsig.fired else 'not_fired'} current_24h={rsig.current_24h} "
                                f"observed_max_24h={rsig.observed_max_24h} x{rsig.multiplier:g}"),
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


@app.post("/transact", deprecated=True)
def transact_endpoint(
    transaction: Transaction,
    rail: str = DEFAULT_RAIL,
    bank_client: httpx.Client = Depends(get_bank_client),
    store: TransactionStore = Depends(get_transaction_store),
    keys_dir: Path = Depends(get_signing_keys_dir),
    require_device_auth: bool = Depends(get_require_device_auth),
    registry: ModelRegistry = Depends(get_model_registry),
    policy_versions: PolicyVersionStore | None = Depends(get_policy_version_store),
) -> dict:
    """LEGACY, UNSIGNED path -- CLOSED in every running service.

    It answers FAIL_CLOSED / DEVICE_AUTH_REQUIRED and scores nothing. When it
    was open it performed NO device authentication -- anyone could submit any
    transaction claiming any device_id and subject (gaps G1/G2 in
    docs/SECURITY-GAP-REPORT.md) -- which is why /v2/transact replaced it. Only
    the in-process test harness can open it, by overriding
    get_require_device_auth, to exercise the pre-Phase-3 decision contract.
    """
    if require_device_auth:
        return _outcome(
            {"risk": None, "decision": None, "rail": rail},
            transaction.transaction_id,
            FinalStatus.FAIL_CLOSED, DecisionReason.DEVICE_AUTH_REQUIRED,
            hint="use POST /v2/transact with a signed DeviceEnvelope",
        )
    return _run_transaction(transaction, rail, bank_client, store, keys_dir, registry=registry,
                            policy_versions=policy_versions)


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
    registry: ModelRegistry = Depends(get_model_registry),
    policy_versions: PolicyVersionStore | None = Depends(get_policy_version_store),
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
        registry=registry,
        policy_versions=policy_versions,
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
         challenge still live -- that is where the clock lives;
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

    if auth in REFUSED_WITHOUT_STATE_CHANGE:
        # No valid proof arrived, so this request proves nothing and may change
        # nothing. Reaching here needs only the challenge_id and transaction_id,
        # and both are shown on the device and travel without TLS -- so anything
        # that ended the challenge here would be a denial anyone who saw them
        # could trigger, while approving still needs the authenticator's Ed25519
        # signature. Until 2026-09-17 a wrong transaction_id cancelled the
        # payment outright, and until 2026-09-18 three failed proofs did
        # (docs/STEP-UP-EXPIRY-FIX.md sections 18-19). The challenge stays open
        # for the real authenticator; only the 120s expiry closes it.
        #
        # authenticate() has already audited the attempt. The reply is the
        # unknown-challenge reply, byte for byte: no risk band, no score, no
        # rules, no policy hash, and no way to tell a live challenge from one
        # that never existed.
        _log(context.transaction_id, "SECURITY",
             event=f"step_up_{auth.value.lower()}_refused")
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
        # Everything that reaches here is terminal by the clock, not by a failed
        # proof: an expired challenge (and, defensively, any future non-SUCCESS
        # result that is not a refusal above). It can never be approved again,
        # so it is closed and the payment settled to DENIED -- the same answer
        # the restart cleanup gives, arriving earlier.
        step_up_store.consume(body.challenge_id, Decision.DENY.value)
        if store.get_state(context.transaction_id) == TxnState.AWAITING_STEP_UP:
            transition(store, context.transaction_id, TxnState.DENIED, now)
        # Denied, and told why -- but still without the frozen risk context,
        # which only a caller holding the authenticator key gets to see.
        return _outcome({"risk": None, "decision": None, "rail": context.rail,
                         "step_up": {"auth_result": auth.value,
                                     "resolved": outcome_decision.value},
                         "transaction_id": context.transaction_id},
                        context.transaction_id, FinalStatus.DENY,
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
