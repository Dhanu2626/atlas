"""The policy engine: deterministic, explainable, and — per ARCHITECTURE.md
principle 1 — the actual authority over ALLOW/STEP_UP/DELAY/DENY. ML only ever
supplies evidence into this.

Written in the frozen Policy Semantic Layer vocabulary (MAX_AMOUNT,
NEW_BENEFICIARY, INTERNATIONAL, TIME_WINDOW, VELOCITY, RISK_THRESHOLD) —
`REQUIRE_STEP_UP` isn't a condition here, it's the outcome a rule maps to
(Decision.STEP_UP), matching how the research's own worked examples use it
("IF amount > X THEN require confirmation").

Two decisions below are mine, not the frozen research's — flagged, not silently
folded in as if they were always decided:

1. Conflict resolution when multiple rules match: MOST RESTRICTIVE WINS
   (DENY > DELAY > STEP_UP > ALLOW). The freeze conversation never specifies
   this. Chosen because it's the only ordering consistent with the freeze's own
   principle that ATLAS can only make a transaction more restrictive — any other
   ordering would let a lenient rule silently override a protective one.
2. RISK_THRESHOLD compares against the categorical risk_band (LOW/MEDIUM/HIGH),
   not a raw numeric score. Day 7 Q5's own example used a raw threshold
   ("anomaly >= 70"), but different ML models produce incomparable raw scores —
   that's explicitly why the frozen assertion excludes the raw score. The band
   is what model.py actually produces and is the more defensible comparison.

Security note extending Day 13's own red-team finding from the ML layer to this
one: NEW_BENEFICIARY is verified against the subject's own history, never
trusted from Transaction.is_new_beneficiary directly — a compromised client
could otherwise just claim it's False. Deliberately NOT sharing this check with
atlas_service/ml/features.py's version: policy and ML are different domains per
the frozen three-domain split, and this is a one-line check — sharing code
across that boundary would cost more in coupling than it saves in duplication.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import yaml

from contracts import Decision, PolicyDecision, RiskEvidence, Transaction

POLICIES_DIR = Path(__file__).resolve().parent / "policies"

_SEVERITY = {
    Decision.ALLOW: 0,
    Decision.STEP_UP: 1,
    Decision.DELAY: 2,
    Decision.DENY: 3,
}

_RISK_LEVEL = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}


@dataclass(frozen=True)
class RolledBackPolicyError(Exception):
    """Raised when a policy claims a version older than one already seen for
    this subject. Per the failure-mode table: policy corrupted/invalid -> deny.
    A rollback attempt is exactly that category, not a normal decision path."""

    subject: str
    seen_version: int
    attempted_version: int

    def __str__(self) -> str:
        return (
            f"policy rollback rejected for {self.subject}: version "
            f"{self.attempted_version} attempted, but version {self.seen_version} "
            f"was already active"
        )


def load_policy(path: Path) -> dict:
    with open(path, encoding="utf-8") as f:
        policy = yaml.safe_load(f)
    if "version" not in policy or not isinstance(policy["version"], int):
        raise ValueError(f"{path}: policy must have an integer 'version'")
    return policy


def compute_policy_hash(policy: dict) -> str:
    """A commitment to one exact policy state, including its version — not just
    the rules. Canonical (sorted-key, fixed-separator) JSON, same discipline
    step 5's crypto signing will need for the assertion payload."""
    canonical = json.dumps(policy, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def check_rollback(subject: str, seen_version: int | None, attempted_version: int) -> None:
    """Pure function — the persistent tracking of "last seen version per
    subject" is step 4's job (SQLite), not built yet. This is the complete,
    testable check logic; storage gets wired to it later."""
    if seen_version is not None and attempted_version < seen_version:
        raise RolledBackPolicyError(subject, seen_version, attempted_version)


def _verified_new_beneficiary(transaction: Transaction, history: list[Transaction]) -> bool:
    known = {t.beneficiary for t in history}
    return transaction.beneficiary not in known


def _check_time_window(transaction: Transaction, window: list[int]) -> bool:
    start, end = window
    hour = datetime.fromisoformat(transaction.timestamp).hour
    if start <= end:
        return start <= hour < end
    return hour >= start or hour < end  # wraps past midnight, e.g. [22, 6]


def _check_velocity(transaction: Transaction, history: list[Transaction], limit: int) -> bool:
    tx_time = datetime.fromisoformat(transaction.timestamp)
    count = 1 + sum(
        1 for t in history
        if abs((tx_time - datetime.fromisoformat(t.timestamp)).total_seconds()) <= 86400
    )
    return count > limit


def _rule_matches(
    condition: dict, transaction: Transaction, risk: RiskEvidence, history: list[Transaction]
) -> bool:
    """All keys in a rule's condition are AND-combined — matches the research's
    own worked examples ("new beneficiary AND amount > X")."""
    for key, value in condition.items():
        if key == "MAX_AMOUNT":
            if not (transaction.amount > value):
                return False
        elif key == "NEW_BENEFICIARY":
            if _verified_new_beneficiary(transaction, history) != value:
                return False
        elif key == "INTERNATIONAL":
            if transaction.is_international != value:
                return False
        elif key == "TIME_WINDOW":
            if not _check_time_window(transaction, value):
                return False
        elif key == "VELOCITY":
            if not _check_velocity(transaction, history, value):
                return False
        elif key == "RISK_THRESHOLD":
            if _RISK_LEVEL[risk.risk_band] < _RISK_LEVEL[value]:
                return False
        else:
            raise ValueError(f"unknown policy condition key: {key!r}")
    return True


def evaluate(
    transaction: Transaction,
    risk: RiskEvidence,
    history: list[Transaction],
    policy: dict,
) -> PolicyDecision:
    """Deterministic: same transaction + same risk evidence + same history +
    same policy always produces the same PolicyDecision. No hidden state, no
    randomness — this is what makes the decision auditable.

    Note what this function does NOT take as input: bank risk. Per
    ledger/SYNTHESIS.md #1, the policy engine never sees the bank's assessment —
    the bank evaluates independently, after, on its own authority.
    """
    matched = [
        rule for rule in policy.get("rules", [])
        if _rule_matches(rule["condition"], transaction, risk, history)
    ]

    if not matched:
        decision = Decision.ALLOW
        matched_names: list[str] = []
    else:
        matched_names = [r["name"] for r in matched]
        decision = max(
            (Decision(r["action"]) for r in matched),
            key=lambda d: _SEVERITY[d],
        )

    return PolicyDecision(
        transaction_id=transaction.transaction_id,
        decision=decision,
        policy_version=policy["version"],
        policy_hash=compute_policy_hash(policy),
        matched_rules=matched_names,
    )
