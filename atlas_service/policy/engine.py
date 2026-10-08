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
   INSUFFICIENT_HISTORY (2026-09-25) is not a band: the ML layer did not judge
   the customer, so no RISK_THRESHOLD rule matches it at any level.
3. BEYOND_OBSERVED_RANGE (2026-09-29, approved by Dhanush) extends the vocabulary
   by one condition: the burst evidence ml/range_signal.py attaches beside the
   Isolation Forest -- this customer's payments in 24 hours above 6x their own
   busiest earlier 24 hours. The forest cannot see such bursts (it cannot score
   beyond the range it was trained on), so this is how a customer's policy can
   act on one. Same principle as RISK_THRESHOLD: ML supplies evidence, the rule
   decides. It matches only where the ML layer operated (200+ payments).
4. GEOFENCE (2026-10-09, approved by Dhanush with policy v6) is the first of the
   Phase 3.6 device-evidence keys: where the device's graded location evidence
   puts it relative to its registered home area (atlas_service/device/location.py).
   Same principle again -- the grade is evidence, the rule decides. No evidence
   means nothing was judged, so a GEOFENCE rule does not match it.

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
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

import yaml

from contracts import (
    GEOFENCE_VALUES, INSUFFICIENT_HISTORY, Decision, LocationGrade, PolicyDecision, RiskEvidence,
    Transaction,
)

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
    return load_policy_bytes(Path(path).read_bytes(), str(path))


def load_policy_bytes(data: bytes, source: str = "policy") -> dict:
    """Parses policy YAML from bytes. The deciding path parses the exact bytes
    whose signature it verified (signing.py), never a second read of the file."""
    policy = yaml.safe_load(data.decode("utf-8"))
    if not isinstance(policy, dict) or "version" not in policy or not isinstance(policy["version"], int):
        raise ValueError(f"{source}: policy must have an integer 'version'")
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


def policy_hour(timestamp: str, policy_timezone: str | None) -> int:
    """The hour a TIME_WINDOW rule is evaluated against.

    Defect fixed 2026-08-26 (Phase 1 audit): this previously used
    `datetime.fromisoformat(ts).hour` -- the raw hour of whatever offset the
    client happened to send. The ESP32 sends UTC, so `odd_hours: [22, 6]`,
    which plainly means local night, was firing at 03:54 UTC (09:24 IST,
    mid-morning) and NOT firing at 21:00 IST. Identical Rs 1,500
    transactions therefore got different decisions purely by wall-clock hour.

    A TIME_WINDOW is a statement about the *user's* day ("don't pay people at
    3am"), so it has to be evaluated in the user's own timezone, not the
    transport's. The rule semantics are untouched -- still [start, end),
    still wrapping past midnight; only the hour it reads changes.

    `policy_timezone` absent -> previous behaviour (use the timestamp as
    given). That keeps every policy without the new field bit-for-bit
    backward compatible.
    """
    dt = datetime.fromisoformat(timestamp)
    if policy_timezone is None:
        return dt.hour
    if dt.tzinfo is None:
        # A naive timestamp is treated as UTC rather than as already-local:
        # guessing "it's probably local" would silently shift decisions by
        # the offset, which is the exact class of bug being fixed here.
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(ZoneInfo(policy_timezone)).hour


def _check_time_window(
    transaction: Transaction, window: list[int], policy_timezone: str | None
) -> bool:
    start, end = window
    hour = policy_hour(transaction.timestamp, policy_timezone)
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
    condition: dict,
    transaction: Transaction,
    risk: RiskEvidence,
    history: list[Transaction],
    policy_timezone: str | None = None,
    location: LocationGrade | None = None,
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
            if not _check_time_window(transaction, value, policy_timezone):
                return False
        elif key == "VELOCITY":
            if not _check_velocity(transaction, history, value):
                return False
        elif key == "RISK_THRESHOLD":
            # INSUFFICIENT_HISTORY is not a risk level: the ML layer did not judge
            # this customer, so no threshold is met (approved 2026-09-25). Any
            # other unrecognised band still fails loudly on the lookup below.
            if risk.risk_band == INSUFFICIENT_HISTORY:
                return False
            if _RISK_LEVEL[risk.risk_band] < _RISK_LEVEL[value]:
                return False
        elif key == "BEYOND_OBSERVED_RANGE":
            # The burst evidence (2026-09-29, approved). It exists only where the ML
            # layer operated; absent, it is not "not fired" -- nothing was judged --
            # so a rule asking for it does not match, exactly as RISK_THRESHOLD
            # treats INSUFFICIENT_HISTORY.
            if not isinstance(value, bool):
                raise ValueError(f"BEYOND_OBSERVED_RANGE takes true or false, not {value!r}")
            if risk.range_signal is None or risk.range_signal.fired != value:
                return False
        elif key == "GEOFENCE":
            # Graded location evidence (2026-10-09, approved with policy v6). The value
            # is checked before the evidence, so a misspelt one fails loudly even on a
            # payment that carries no location.
            if value not in GEOFENCE_VALUES:
                raise ValueError(f"GEOFENCE takes one of {sorted(GEOFENCE_VALUES)}, not {value!r}")
            if location is None or location.geofence != value:
                return False
        else:
            raise ValueError(f"unknown policy condition key: {key!r}")
    return True


def evaluate(
    transaction: Transaction,
    risk: RiskEvidence,
    history: list[Transaction],
    policy: dict,
    location: LocationGrade | None = None,
) -> PolicyDecision:
    """Deterministic: same transaction + same risk evidence + same history +
    same policy always produces the same PolicyDecision. No hidden state, no
    randomness — this is what makes the decision auditable.

    `location` is the graded location evidence of an authenticated device
    envelope (None on paths that have none); only a GEOFENCE rule reads it.

    Note what this function does NOT take as input: bank risk. Per
    ledger/SYNTHESIS.md #1, the policy engine never sees the bank's assessment —
    the bank evaluates independently, after, on its own authority.
    """
    policy_timezone = policy.get("timezone")
    matched = [
        rule for rule in policy.get("rules", [])
        if _rule_matches(rule["condition"], transaction, risk, history, policy_timezone, location)
    ]

    if not matched:
        decision = Decision.ALLOW
        matched_names: list[str] = []
        deciding_rule: str | None = None
    else:
        matched_names = [r["name"] for r in matched]
        # Take max() over the RULES rather than over their actions, so the rule
        # that supplied the winning action survives instead of being discarded.
        # The resulting Decision is identical -- same comparison, same severity
        # table -- this only stops throwing away which rule it came from.
        #
        # Ties (two rules with the same winning action) resolve to the one
        # listed FIRST in the policy file, because max() returns the first
        # maximal element. Deterministic and auditable, which is what
        # evaluate()'s contract promises.
        winner = max(matched, key=lambda r: _SEVERITY[Decision(r["action"])])
        decision = Decision(winner["action"])
        deciding_rule = winner["name"]

    return PolicyDecision(
        transaction_id=transaction.transaction_id,
        decision=decision,
        policy_version=policy["version"],
        policy_hash=compute_policy_hash(policy),
        matched_rules=matched_names,
        deciding_rule=deciding_rule,
    )
