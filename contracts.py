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
    #: Policy said STEP_UP and a challenge is outstanding. NOT terminal, and
    #: NOT an availability failure -- the transaction is waiting on a human,
    #: not on a network. It can only leave via ALLOWED (bounded re-resolution
    #: said yes) or DENIED (anything else, including expiry). See
    #: atlas_service/step_up/resolver.py.
    AWAITING_STEP_UP = "AWAITING_STEP_UP"
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


#: The ML layer's answer when it has too little of the customer's own history to
#: judge (2026-09-25, approved specification change). It is NOT a risk level: it
#: is never LOW, no RISK_THRESHOLD rule ever matches it, and it carries no anomaly
#: score. Until 2026-09-25 this case was reported as LOW with anomaly_score 0.0,
#: which read as "judged, and low risk" when the truth was "not judged".
INSUFFICIENT_HISTORY = "INSUFFICIENT_HISTORY"


class RangeSignal(BaseModel):
    """`beyond_observed_range` (2026-09-25): a SEPARATE evidence signal beside the
    Isolation Forest, not part of it. It compares the customer's payments in the
    24 hours up to this one with the busiest 24 hours in that customer's own
    earlier history (atlas_service/ml/range_signal.py). It does not change
    risk_band; since 2026-09-29 a policy can act on it with the condition
    BEYOND_OBSERVED_RANGE (atlas_service/policy/engine.py)."""

    name: str = "beyond_observed_range"
    fired: bool
    current_24h: int
    #: The busiest earlier 24 hours; None when no history lies outside the
    #: current 24-hour window, in which case the signal cannot fire.
    observed_max_24h: int | None
    multiplier: float


class RiskEvidence(BaseModel):
    """What the ML layer hands to the policy engine.

    Internal only. Per ARCHITECTURE.md principle 5, this never crosses the
    atlas_service -> bank_service boundary — the bank sees only the resulting
    Decision, never the score or the reasons that produced it.
    """

    #: None exactly when risk_band is INSUFFICIENT_HISTORY: nothing was scored.
    anomaly_score: float | None
    risk_band: str  # LOW / MEDIUM / HIGH, or INSUFFICIENT_HISTORY (not a risk level)
    reasons: list[str] = Field(default_factory=list)  # e.g. "amount 15x baseline"
    #: The separate beyond_observed_range signal, when the ML layer operated.
    range_signal: RangeSignal | None = None


class PolicyDecision(BaseModel):
    """The policy engine's output for one transaction."""

    transaction_id: str
    decision: Decision
    policy_version: int
    policy_hash: str
    matched_rules: list[str] = Field(default_factory=list)

    #: Which single rule supplied the winning action, when any rule matched.
    #:
    #: `matched_rules` lists everything that fired, in POLICY FILE order, which
    #: is not precedence order -- so a reader could not tell whether a DENY came
    #: from `hard_cap` or from `velocity_burst`. The engine already knows; it
    #: just used to discard the answer after taking max() over the actions.
    #:
    #: Optional and defaulted so this is purely additive: every existing caller,
    #: test and stored row stays valid. It is NOT part of AssertionPayload --
    #: that field list is frozen and the bank still sees only the Decision, per
    #: ARCHITECTURE principle 5.
    deciding_rule: str | None = None


class AuthResult(str, Enum):
    """Outcome of an out-of-band step-up authentication attempt.

    Everything time- or state-dependent is collapsed into this enum by the
    caller BEFORE bounded re-resolution runs. That is what lets
    resolve_step_up() be clock-free and still honour the 120s expiry: the
    caller decides whether the challenge is still valid, the resolver decides
    what the answer is.

    Only SUCCESS is a success. Every other member refuses.
    """

    SUCCESS = "SUCCESS"
    #: Signature did not verify, or was malformed, against the enrolled
    #: authenticator key. Refused without changing anything since 2026-09-18.
    INVALID_PROOF = "INVALID_PROOF"
    #: Proof verified, but against a different transaction/challenge/envelope.
    BINDING_MISMATCH = "BINDING_MISMATCH"
    #: RETIRED 2026-09-18 and never returned since: failed proofs no longer
    #: spend an authorisation budget (D1). Kept because the resolver must still
    #: answer DENY if an older stored value ever reaches it.
    ATTEMPTS_EXHAUSTED = "ATTEMPTS_EXHAUSTED"
    #: Past expires_at.
    EXPIRED = "EXPIRED"
    #: No such challenge, or it was already consumed.
    UNKNOWN_CHALLENGE = "UNKNOWN_CHALLENGE"
    #: No authenticator enrolled for this subject.
    NO_AUTHENTICATOR = "NO_AUTHENTICATOR"


class MatchedRule(BaseModel):
    """A rule that fired, WITH its action.

    PolicyDecision.matched_rules carries names only, which is enough to
    explain a decision but not enough to re-resolve one: the DENY guard in
    resolve_step_up() has to know each rule's action, and looking it up would
    mean re-reading the policy -- exactly the recomputation this design
    forbids. So the pairs are frozen at STEP_UP time and travel with the
    context.
    """

    name: str
    action: Decision


class FrozenDecisionContext(BaseModel):
    """The original decision, frozen at the moment STEP_UP was issued.

    Immutable by convention and by storage: written once when the challenge is
    created, read-only thereafter. Bounded re-resolution consumes ONLY this
    plus an AuthResult -- see atlas_service/step_up/resolver.py.

    `risk_band` and `anomaly_score` are carried but never re-derived; they are
    here so the audit trail can show what the ML said at decision time, not so
    anything can act on them later.
    """

    transaction_id: str
    subject: str
    #: The transaction EXACTLY as decided on. Frozen rather than re-read so
    #: that the assertion eventually signed describes the payment the customer
    #: authenticated, not whatever the store happens to hold later.
    transaction: Transaction
    rail: str
    original_decision: Decision
    matched_rules: list[MatchedRule] = Field(default_factory=list)
    deciding_rule: str | None = None
    policy_version: int
    policy_hash: str
    risk_band: str
    anomaly_score: float | None
    #: SHA-256 of the exact signed envelope bytes. Binds a proof to one
    #: request, so a valid proof cannot be moved to another transaction.
    envelope_hash: str


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
    in transit. Graded since Phase 3.4 (2026-10-09) by
    atlas_service/device/location.py into a LocationGrade -- evidence for the
    policy engine, never a decision of its own. Two paths fill it: "BROWSER"
    (a visitor's real position on the live page) and "GNSS" (the ESP32's
    receiver over UART, SIMULATED in Wokwi).

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

    source: str = "NONE"  # GNSS | WIFI | CELL | IP | BROWSER | DECLARED | NONE
    latitude: Optional[Decimal] = None
    longitude: Optional[Decimal] = None
    accuracy_m: Optional[Decimal] = None
    captured_at: Optional[str] = None
    satellites: Optional[int] = None


#: Where the location evidence places the device relative to its registered
#: home area (docs/PHASE3-SPEC.md, "Location grading"). Policy condition key
#: GEOFENCE takes exactly one of these.
GEOFENCE_WITHIN = "WITHIN_GEOFENCE"
GEOFENCE_OUTSIDE = "OUTSIDE_GEOFENCE"
GEOFENCE_LOCATION_UNKNOWN = "LOCATION_UNKNOWN"
GEOFENCE_LOCATION_STALE = "LOCATION_STALE"
GEOFENCE_VALUES = frozenset({GEOFENCE_WITHIN, GEOFENCE_OUTSIDE,
                             GEOFENCE_LOCATION_UNKNOWN, GEOFENCE_LOCATION_STALE})


class LocationGrade(BaseModel):
    """How much ATLAS believes a device's location claim (Phase 3.4, 2026-10-09).

    Evidence for the policy engine, like RiskEvidence: it decides nothing by
    itself. It deliberately carries NO coordinates -- only the grade, the
    geofence answer, a rounded distance from the home area and plain-language
    reasons -- so it can be returned to the device and logged without
    repeating anyone's position.

    confidence: MEDIUM | LOW | UNKNOWN. HIGH exists in the frozen table but
    needs a secure-element-signed fix, which this project does not have, so it
    is never produced.
    """

    source: str
    confidence: str
    geofence: str
    distance_from_home_km: Optional[float] = None
    fix_age_s: Optional[int] = None
    implausible_travel: bool = False
    implied_speed_kmh: Optional[int] = None
    reasons: list[str] = Field(default_factory=list)


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
