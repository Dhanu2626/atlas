"""Shared data contracts used by both atlas_service and bank_service.

Defining these once, before either service exists, avoids retrofitting a shared
vocabulary onto four independently-shaped modules later. See ledger/ARCHITECTURE.md
for the reasoning behind every field here — nothing in this file is arbitrary.
"""

from __future__ import annotations

import json
from decimal import Decimal
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class TxnState(str, Enum):
    """ATLAS transaction lifecycle (ledger/ARCHITECTURE.md's failure-mode table).

    A security failure (bad signature, revoked key, policy hash mismatch, expired or
    replayed assertion) goes straight to DENIED/FAILED. An availability failure
    (network down, bank unreachable) goes to UNKNOWN and must be reconciled on
    restart — never silently retried, and ALLOWED must never be treated as
    "payment complete."
    """

    CREATED = "CREATED"
    EVALUATING = "EVALUATING"
    DENIED = "DENIED"
    ALLOWED = "ALLOWED"
    SIGNED = "SIGNED"
    SUBMITTED = "SUBMITTED"
    CONFIRMED = "CONFIRMED"
    UNKNOWN = "UNKNOWN"
    RECONCILING = "RECONCILING"
    FAILED = "FAILED"


class Decision(str, Enum):
    """The policy engine's verdict. Unchanged, frozen vocabulary."""

    ALLOW = "ALLOW"
    STEP_UP = "STEP_UP"
    DELAY = "DELAY"
    DENY = "DENY"


class FinalStatus(str, Enum):
    """What /transact reports as the transaction's outcome.

    Distinct from Decision because a transaction can end for reasons the
    policy engine never got to weigh in on. The critical separation, added
    after the Phase 1 audit found the two conflated:

      DENY        a decision was reached and it was "no" -- policy refused,
                  or the bank refused. The system worked.
      FAIL_CLOSED no trustworthy decision could be reached at all -- a
                  security, integrity, or internal failure. The system did
                  NOT work, and refusing is the safe default rather than the
                  answer.

    Conflating these hides outages inside what looks like normal risk
    behaviour. Both still refuse the payment; only one is a security event.

    PENDING stays its own status rather than folding into FAIL_CLOSED: the
    frozen failure-mode table specifies "bank unavailable -> pending ->
    reconciliation", and that is a genuinely different situation from a
    failure -- the transaction may yet have succeeded at the bank, so it must
    be reconciled, never guessed.
    """

    ALLOW = "ALLOW"
    STEP_UP = "STEP_UP"
    DELAY = "DELAY"
    DENY = "DENY"
    PENDING = "PENDING"
    FAIL_CLOSED = "FAIL_CLOSED"


class DecisionReason(str, Enum):
    """Why a FinalStatus was reached -- machine-readable, safe to log, and
    never containing secrets or authentication material."""

    # --- deliberate decisions: the system reached a real verdict -----------
    POLICY_ALLOW = "POLICY_ALLOW"
    POLICY_STEP_UP = "POLICY_STEP_UP"
    POLICY_DELAY = "POLICY_DELAY"
    POLICY_DENY = "POLICY_DENY"
    BANK_REJECTED = "BANK_REJECTED"

    # --- availability: outcome genuinely unknown, must be reconciled -------
    BANK_UNREACHABLE = "BANK_UNREACHABLE"

    # --- fail-closed: no trustworthy decision was possible -----------------
    DUPLICATE_TRANSACTION_ID = "DUPLICATE_TRANSACTION_ID"
    UNKNOWN_RAIL = "UNKNOWN_RAIL"
    INTERNAL_ERROR = "INTERNAL_ERROR"

    # --- fail-closed: device trust layer (Phase 3) -------------------------
    MALFORMED_ENVELOPE = "MALFORMED_ENVELOPE"
    DEVICE_UNKNOWN = "DEVICE_UNKNOWN"
    DEVICE_REVOKED = "DEVICE_REVOKED"
    DEVICE_SUSPENDED = "DEVICE_SUSPENDED"
    INVALID_DEVICE_SIGNATURE = "INVALID_DEVICE_SIGNATURE"
    MISSING_DEVICE_SIGNATURE = "MISSING_DEVICE_SIGNATURE"
    DEVICE_ID_MISMATCH = "DEVICE_ID_MISMATCH"
    DEVICE_SUBJECT_MISMATCH = "DEVICE_SUBJECT_MISMATCH"
    STALE_REQUEST = "STALE_REQUEST"
    FUTURE_TIMESTAMP = "FUTURE_TIMESTAMP"
    COUNTER_REGRESSION = "COUNTER_REGRESSION"
    REPLAYED_NONCE = "REPLAYED_NONCE"
    DEVICE_AUTH_REQUIRED = "DEVICE_AUTH_REQUIRED"


#: Reasons that mean "a security/integrity/internal failure stopped us", as
#: opposed to "we decided no". Used by tests to assert the separation holds.
FAIL_CLOSED_REASONS = frozenset({
    DecisionReason.DUPLICATE_TRANSACTION_ID,
    DecisionReason.UNKNOWN_RAIL,
    DecisionReason.INTERNAL_ERROR,
    DecisionReason.MALFORMED_ENVELOPE,
    DecisionReason.DEVICE_UNKNOWN,
    DecisionReason.DEVICE_REVOKED,
    DecisionReason.DEVICE_SUSPENDED,
    DecisionReason.INVALID_DEVICE_SIGNATURE,
    DecisionReason.MISSING_DEVICE_SIGNATURE,
    DecisionReason.DEVICE_ID_MISMATCH,
    DecisionReason.DEVICE_SUBJECT_MISMATCH,
    DecisionReason.STALE_REQUEST,
    DecisionReason.FUTURE_TIMESTAMP,
    DecisionReason.COUNTER_REGRESSION,
    DecisionReason.REPLAYED_NONCE,
    DecisionReason.DEVICE_AUTH_REQUIRED,
})


class DeviceStatus(str, Enum):
    """Registry lifecycle. UNKNOWN is deliberately NOT stored -- it is the
    ABSENCE of a registry row. A device cannot be marked unknown; it either
    has an enrolled key or it does not, and absence fails closed."""

    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    REVOKED = "REVOKED"

#: Maps a policy Decision onto the reason recorded for it.
POLICY_DECISION_REASONS: dict[Decision, DecisionReason] = {
    Decision.ALLOW: DecisionReason.POLICY_ALLOW,
    Decision.STEP_UP: DecisionReason.POLICY_STEP_UP,
    Decision.DELAY: DecisionReason.POLICY_DELAY,
    Decision.DENY: DecisionReason.POLICY_DENY,
}


class Transaction(BaseModel):
    """A payment intent, as it enters ATLAS.

    Amount is a Decimal, never a float — the signed bytes in AuthorizationAssertion
    have to be byte-identical between signing and verification, and float rounding
    isn't deterministic across platforms.

    Field list cross-checked against Day 7's own synthetic-dataset spec (Transaction
    ID/UserID/Timestamp/Amount/Currency/Location/DeviceID/BeneficiaryID/
    MerchantCategory/NewBeneficiary/NewDevice/TransactionFrequency/
    HistoricalAverage/DistanceFromNormalLocation/AuthenticationMethod) — the first
    version of this model was missing location, device_id, merchant_category,
    is_new_device, and authentication_method, which would have made several of the
    original behavioral patterns (Location Pattern, Device Pattern, Merchant Pattern)
    literally unimplementable. TransactionFrequency, HistoricalAverage, and
    DistanceFromNormalLocation aren't here on purpose: those are derived from a
    subject's transaction *history*, not intrinsic to one transaction, and belong in
    the (not-yet-built) feature-engineering step instead.

    declared_travel_mode and is_emergency_request aren't in Day 7's dataset list, but
    connect two other threads in the record: Day 7 Q4 designed "Travel Mode" as a
    context flag that reweights ML interpretation without disabling it (to prevent
    exactly the false-positive problem the research identified), and the original
    pre-Day-1 discussion's "Emergency Behaviour" pattern treats emergency-mode usage
    *frequency* as itself a signal worth tracking, not just a bypass button — neither
    is implementable without a field to carry the flag through.
    """

    transaction_id: str
    subject: str  # pseudonymous account binding — never raw name/phone/address
    amount: Decimal
    currency: str
    beneficiary: str
    location: str
    device_id: str
    merchant_category: Optional[str] = None  # not every transaction has one (e.g. a P2P transfer)
    authentication_method: str
    is_new_beneficiary: bool = False
    is_new_device: bool = False
    is_international: bool = False
    declared_travel_mode: bool = False
    is_emergency_request: bool = False
    timestamp: str  # ISO 8601


class RiskEvidence(BaseModel):
    """What the ML layer hands to the policy engine.

    Internal only. Per ARCHITECTURE.md principle 5, this never crosses the
    atlas_service -> bank_service boundary — the bank sees only the resulting
    Decision, never the score or the reasons that produced it.
    """

    anomaly_score: float
    risk_band: str  # LOW / MEDIUM / HIGH
    reasons: list[str] = Field(default_factory=list)  # e.g. "amount 15x baseline"


class PolicyDecision(BaseModel):
    """The policy engine's output for one transaction."""

    transaction_id: str
    decision: Decision
    policy_version: int
    policy_hash: str
    matched_rules: list[str] = Field(default_factory=list)


class AssertionPayload(BaseModel):
    """The part of the ATLAS Authorization Assertion that gets signed.

    Deliberately excludes: raw transaction history, ML feature vectors, the ML risk
    score itself, the private key, and the full policy text (only policy_version +
    policy_hash travel externally). Field list is frozen — see ARCHITECTURE.md's
    "ATLAS Assertion" section for why each field exists.

    Never add a `signature` field to this model — signing has to happen over a
    payload that doesn't already contain its own signature.
    """

    issuer: str
    subject: str
    transaction_id: str
    amount: str  # Decimal serialized as a string, same reasoning as Transaction.amount
    currency: str
    beneficiary: str
    policy_version: int
    policy_hash: str
    decision: Decision
    nonce: str
    issued_at: str
    expires_at: str
    audience: str
    atlas_key_id: str


class SignedAssertion(BaseModel):
    """What actually travels over the wire from atlas_service to bank_service."""

    payload: AssertionPayload
    signature: str


class LocationEvidence(BaseModel):
    """What the device claims about where it is, WITH its provenance.

    Deliberately not a bare string. "Bengaluru,IN" carries no source, no
    accuracy, and no capture time, so it cannot be graded -- it can only be
    believed or not. Every field here exists so the backend can decide HOW
    MUCH to believe it.

    Carried inside the signed envelope from Phase 3.3 so it is tamper-evident
    in transit. GRADING IS NOT IMPLEMENTED IN PHASE 3.3 -- these values are
    signature-covered and stored, and nothing reads them for any decision.
    Including them in the signed surface now avoids changing the signed bytes
    later, which would invalidate every already-enrolled device.

    A GNSS fix is the device ASSERTING what it believes it saw. Civilian GNSS
    is unauthenticated and spoofable with commodity hardware, so no value here
    ever proves physical presence.

    WHY Decimal AND NOT float (F1, 2026-08-27)
    ------------------------------------------
    These three coordinates sit INSIDE canonical_envelope_bytes(), so they are
    signed material, and this module's own rule for signed numerics already
    says (see Transaction.amount): *"never a float -- the signed bytes have to
    be byte-identical between signing and verification, and float rounding
    isn't deterministic across platforms."* Declaring them `float` broke that
    rule.

    The failure it would have caused, demonstrated before the fix:

        device sends 12.97160     Python float -> serialises 12.9716
        C printf("%.6f")          firmware     -> emits     12.971600
        -> different signed bytes -> INVALID_DEVICE_SIGNATURE on real hardware only

    Decimal fixes it because pydantic serialises Decimal to a JSON *string*
    and preserves the exact digits it was given -- "12.971600" round-trips as
    "12.971600", trailing zeros intact. Both sides then sign an opaque text
    token with no numeric conversion anywhere, which is the only
    representation that is provably identical across Python and C.

    This was latent, never live: `location` is None everywhere in Phase 3.3,
    so nothing has ever signed a float. It is fixed now because Phase 3.4
    populates these fields, at which point every ESP32 signature would fail.

    A device that sends a JSON *number* instead of a string still fails
    closed (its signed bytes will not match the re-serialised string) rather
    than verifying incorrectly.

    `satellites` stays int: JSON integers have one unambiguous textual form,
    so they carry none of this hazard.
    """

    source: str = "NONE"  # GNSS | WIFI | CELL | IP | DECLARED | NONE
    latitude: Optional[Decimal] = None
    longitude: Optional[Decimal] = None
    accuracy_m: Optional[Decimal] = None
    captured_at: Optional[str] = None
    satellites: Optional[int] = None


class DeviceHealth(BaseModel):
    """The device's SELF-REPORT of its own integrity.

    Worth stating plainly: a compromised device reports whatever it likes,
    including `secure_boot_enabled=True`. This is evidence about a
    cooperative device, never proof about a hostile one. Only verified boot
    plus remote attestation against a hardware root of trust would change
    that, and neither exists here.

    Same Phase 3.3 status as LocationEvidence: signature-covered, stored,
    and read by nothing that makes a decision.
    """

    firmware_version: str = "unknown"
    firmware_hash: Optional[str] = None
    secure_boot_enabled: bool = False
    flash_encryption_enabled: bool = False
    secure_element_present: bool = False
    tamper_detected: bool = False
    boot_count: Optional[int] = None
    reset_reason: Optional[str] = None


class DeviceEnvelope(BaseModel):
    """A registered device's signed wrapper around one Transaction.

    The existing Transaction model is carried UNMODIFIED inside. That is what
    keeps every pre-Phase-3 test and the legacy /transact contract working
    untouched -- the envelope adds authenticity around the payload rather
    than redesigning it.

    Four distinct identities meet here, and conflating any two of them would
    be a security bug:
      device_key_id  -- WHICH HARDWARE signed this (Phase 3, new)
      transaction_id -- WHICH PAYMENT this is        (inside `transaction`)
      subject        -- WHOSE MONEY moves            (inside `transaction`)
      atlas_key_id   -- who signed the bank assertion (AssertionPayload)

    `device_id` is a human-readable label. It is NOT the identity -- the
    enrolled key is. device_id is checked against the registry only AFTER the
    signature verifies, so a valid key cannot claim to be a different device.
    """

    device_id: str
    device_key_id: str
    boot_id: str
    counter: int
    nonce: str
    issued_at: str
    transaction: Transaction
    location: Optional[LocationEvidence] = None
    health: Optional[DeviceHealth] = None
    signature: str


def canonical_envelope_bytes(envelope: DeviceEnvelope) -> bytes:
    """The exact bytes a device signs and atlas_service re-derives.

    Covers every field EXCEPT `signature` -- including the nested
    transaction, location, and health. Anything left out of these bytes is a
    field an attacker could rewrite in flight without breaking the signature,
    so the exclusion list is exactly one item long by design.

    Same sort_keys + compact-separator discipline as
    canonical_assertion_bytes(), for the same reason: two independent
    implementations (Python model and ESP32 firmware) must agree
    byte-for-byte or every signature fails.
    """
    payload = envelope.model_dump(mode="json")
    payload.pop("signature", None)
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return canonical.encode("utf-8")


def canonical_assertion_bytes(payload: AssertionPayload) -> bytes:
    """The exact bytes atlas_service signs and bank_service re-derives to verify.

    Same sort_keys + compact-separator discipline as
    atlas_service/policy/engine.py's policy hashing, so two independent
    processes always agree byte-for-byte on one payload's canonical form.

    Lives here, not in atlas_service/crypto.py: bank_service must reproduce
    these exact bytes to check a signature, and tests/test_bank_boundary.py
    already enforces at the AST level that bank_service never imports
    atlas_service internals. A shared, crypto-free module is the only place
    both sides can import this from without breaking that boundary.
    """
    canonical = json.dumps(payload.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    return canonical.encode("utf-8")


class BankVerdict(BaseModel):
    """bank_service's independent response — it may disagree with ATLAS.

    See ARCHITECTURE.md's authority hierarchy: if atlas_allowed is True but this
    verdict is False, the bank wins. bank_service never imports atlas_service's
    policy internals or private key to reach this verdict.
    """

    transaction_id: str
    approved: bool
    reason: str
