"""Shared data contracts used by both atlas_service and bank_service.

Defining these once, before either service exists, avoids retrofitting a shared
vocabulary onto four independently-shaped modules later. See ledger/ARCHITECTURE.md
for the reasoning behind every field here — nothing in this file is arbitrary.
"""

from __future__ import annotations

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
    ALLOW = "ALLOW"
    STEP_UP = "STEP_UP"
    DELAY = "DELAY"
    DENY = "DENY"


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


class BankVerdict(BaseModel):
    """bank_service's independent response — it may disagree with ATLAS.

    See ARCHITECTURE.md's authority hierarchy: if atlas_allowed is True but this
    verdict is False, the bank wins. bank_service never imports atlas_service's
    policy internals or private key to reach this verdict.
    """

    transaction_id: str
    approved: bool
    reason: str
