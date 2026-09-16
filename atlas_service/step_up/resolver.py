"""BOUNDED RE-RESOLUTION -- the pure function that resolves a step-up.

THE RULE, and the reason this module exists at all:

    Bounded re-resolution is a pure function of the frozen original context
    plus the authentication result. NOTHING IS RECOMPUTED.

It does not re-run the ML model. It does not re-run the policy engine. It does
not read the clock. It performs no I/O of any kind. Every input arrives as an
argument, and every argument was frozen when the STEP_UP verdict was issued.

WHY NOT JUST RE-EVALUATE WITH CONSTRAINTS
-----------------------------------------
An earlier design said "re-run evaluate() but constrain the result". That is a
trapdoor. `evaluate()`'s inputs are live -- the clock, the subject's history,
the ML score -- so a transaction that got STEP_UP from `odd_hours` at 23:58 and
is confirmed at 06:01 would re-evaluate to a clean ALLOW for a reason that has
nothing to do with the customer proving anything. main.py already warns about
this class of bug in its duplicate-transaction_id handling: re-running policy
"could return a DIFFERENT answer for an id the bank already settled".

Every constraint on a re-evaluation is also something a future change can get
wrong. A pure function of frozen data has nothing to get wrong.

STRUCTURAL GUARANTEE
--------------------
This module imports nothing from atlas_service.ml or atlas_service.policy, and
tests/test_step_up.py asserts that -- both by inspecting this module's source
for `evaluate(` / `.score(` and by checking its imports. If someone
reintroduces re-evaluation here, the suite fails and names the reason.
"""

from __future__ import annotations

from contracts import AuthResult, Decision, FrozenDecisionContext


def resolve_step_up(
    ctx: FrozenDecisionContext,
    auth: AuthResult,
    current_policy_hash: str,
) -> Decision:
    """Total and pure. Returns ALLOW only on the last line.

    `auth` has already absorbed everything time-dependent: expiry, attempt
    exhaustion, an unknown challenge, a proof bound to a different
    transaction. All of those arrive here as a non-SUCCESS AuthResult. That is
    what lets this function be clock-free while still honouring the 120s
    expiry and the 3-attempt cap -- the caller decides *whether the challenge
    is still valid*, this decides *what the answer is*.

    `current_policy_hash` is passed in rather than read, for the same reason.

    Ordering is deliberate: the cheapest and most absolute refusals come
    first, and the single ALLOW is unreachable except by falling through every
    guard.
    """
    # 1. Authentication itself. Anything that is not an unambiguous success --
    #    failure, expiry, exhausted attempts, unknown challenge, binding
    #    mismatch -- refuses. There is no "partial" success.
    if auth is not AuthResult.SUCCESS:
        return Decision.DENY

    # 2. Only a genuine STEP_UP may be resolved here. If a transaction reached
    #    this function with any other original decision, something upstream is
    #    wrong and the safe answer is no.
    if ctx.original_decision is not Decision.STEP_UP:
        return Decision.DENY

    # 3. STEP-UP-INVARIANT-1. If ANY originally matched rule said DENY, then
    #    MOST RESTRICTIVE WINS already answered, and no proof of identity
    #    overturns it. Authenticating perfectly does not raise a hard cap.
    #
    #    In normal operation this is unreachable -- a DENY transaction never
    #    enters AWAITING_STEP_UP. It is kept precisely because it is
    #    unreachable: it is the belt-and-braces guard against a future change
    #    that lets one in. Removing it must break the test suite, and
    #    tests/test_step_up.py mutation-tests exactly that.
    #
    #    THIS GUARD MUST NEVER ACQUIRE AN EXCEPTION, AN OVERRIDE, OR AN
    #    EMERGENCY BRANCH.
    if any(rule.action is Decision.DENY for rule in ctx.matched_rules):
        return Decision.DENY

    # 4. DELAY is about timing, not identity, so authentication cannot satisfy
    #    it. Rather than guess at semantics that were never designed, fail
    #    closed. Making DELAY resumable is deliberately out of scope.
    if any(rule.action is Decision.DELAY for rule in ctx.matched_rules):
        return Decision.DENY

    # 5. The policy must not have changed while the challenge was outstanding.
    #    If it did, the frozen context describes a decision made under a
    #    policy that no longer exists, and honouring it would authorise a
    #    payment under withdrawn rules.
    if ctx.policy_hash != current_policy_hash:
        return Decision.DENY

    # 6. Every rule that fired was STEP_UP, and the customer satisfied it.
    return Decision.ALLOW
