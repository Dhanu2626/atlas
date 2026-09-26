# Proposal: make STEP_UP mean something

**Status: IMPLEMENTED 2026-09-11**, approved by Dhanush. This document is now
the design record; `RUNBOOK.md` §9 is the operational guide. The corrections block
and "As built" table below are current as of 2026-09-21. Sections 0–12 and the two
closing sections are the proposal as approved on 2026-09-11, kept as written except
where marked; figures in them (such as "308 tests") are from that date.

> **Corrections since implementation (2026-09-16)**
>
> - **Defect fixed.** Payments left unanswered stayed in `AWAITING_STEP_UP`
>   indefinitely. The restart cleanup existed but was never called, and as written
>   it closed the challenge without moving the transaction. It now runs at startup
>   and settles every such payment to `DENIED`. Report, evidence and tests:
>   `docs/STEP-UP-EXPIRY-FIX.md`.
> - **Deviation fixed (2026-09-17).** As built, a `BINDING_MISMATCH` also cancelled the
>   real pending payment, although §4 below says a mismatch is only "rejected". It is
>   now refused and audited with no state change. See `STEP-UP-EXPIRY-FIX.md` §18.
> - **Design changed (2026-09-18).** The 3-attempt budget is retired: a failed proof is
>   refused and audited but ends nothing, because reaching the third failure needed no
>   secret and denied the customer's payment. Expiry remains the only thing that closes
>   a challenge without a valid proof. See `STEP-UP-EXPIRY-FIX.md` §18.
> - **Verification status, stated precisely:**
>   - The unit, exhaustive and mutation tests pass: 58 step-up tests, within a suite of
>     689 passed and 2 skipped (the opt-in firmware build, and Playwright's Firefox,
>     which will not start on the build machine), re-run 2026-09-24.
>   - A live-service run with the virtual device passed 15/15 checks (2026-09-11).
>   - In Wokwi, 7 of 10 checks were proven (2026-09-11), and the remaining three on
>     2026-09-23: **authentication success → ALLOW → CONFIRMED on a challenge issued
>     to the real firmware was observed** (challenge `032221ef4d525fc1e4f72731e8e2e1bb`,
>     transaction `esp32-atlas-fw-10-90135b7a-0001`, bank approved over mutual TLS).
>     That is **10 of 10**; the feature is end-to-end verified **in the simulator**,
>     never on physical hardware, and still ships off by default.

Shipped **dormant**: `ATLAS_ENABLE_STEP_UP` defaults to OFF, so a STEP_UP
verdict behaves exactly as it did before this feature until the flag is set.

### As built — what differs from the proposal

| Proposed | Built |
|---|---|
| "re-resolve only the authentication dimension" | **Withdrawn.** The resolver re-runs nothing at all — no ML, no policy, no clock. See §3 |
| context pins 7 fields | 12: the proposal's 7 plus each rule's **action**, the frozen `Transaction`, `rail`, `subject` and `anomaly_score` |
| step-up on any STEP_UP | **v2 endpoint only.** `env_hash` is None on the legacy unsigned path, so no challenge is minted there — a challenge bound to an envelope that proves nothing would be theatre |
| device may poll for the result | **Not built.** The device displays and stops, as the proposal recommended for v1 |

| File | Role |
|---|---|
| `atlas_service/step_up/resolver.py` | the pure function; imports no ML, no policy, no clock |
| `atlas_service/step_up/service.py` | clock, storage, Ed25519 verification |
| `atlas_service/step_up/db.py` | challenges, frozen contexts, authenticator public keys |
| `atlas_service/main.py` | STEP_UP branch + `POST /v2/step-up` |
| `atlas_service/state_machine.py` | `AWAITING_STEP_UP` and its two exits |
| `scripts/enroll_authenticator.py` | demo authenticator: enrol + sign |
| `tests/test_step_up.py` | 57 tests, including an exhaustive sweep and a mutation test |

**Verified 2026-09-11: 338 tests pass** (was 308), firmware compiles at
1,176,488 bytes, signed canonical template unchanged.

---

## 0. The problem, stated honestly

ATLAS emits four verdicts: ALLOW, STEP_UP, DELAY, DENY. Three of them do
something. STEP_UP does not.

Verified in the current code:

| Fact | Where |
|---|---|
| STEP_UP lands in `TxnState.DENIED` | `main.py` module docstring |
| `DENIED` is **terminal** — `TxnState.DENIED: set()` | `state_machine.py:24` |
| The bank is never contacted for non-ALLOW | `main.py:236` |
| No second factor is collected anywhere | no such code exists |
| *"building the interactive 'user confirms a STEP_UP' loop is explicitly out of scope"* | `main.py` docstring |

So today, at 00:17 IST, `odd_hours` fires, the LED turns yellow, and the
payment is dead. The only thing distinguishing it from DENY is a string in the
response body. **STEP_UP is a label on a dead end.**

This proposal gives it a second half. It deliberately does **not** touch how
decisions are made.

---

## 1. Customer authentication flow

### The hard constraint nobody can design around

`diagram.json` contains exactly: one ESP32, three LEDs, three resistors, two
pushbuttons. **There is no keypad, no fingerprint reader, no screen.**

Therefore the second factor **cannot be collected on the device**. Any design
that claims otherwise is either adding hardware or lying. Pressing a button
harder is not authentication — it proves *presence*, and a thief holding the
device has presence. Presence is what the first button press already proved.

This is not a simulator limitation to work around. It is true of the real
product too: a payment button is not an authenticator.

### Proposed flow — out-of-band, which is also what real banking does

```
1. Device  ──signed envelope──────────────►  ATLAS
2.                                            policy → STEP_UP
3.                                            create challenge, state → AWAITING_STEP_UP
4. Device  ◄──STEP_UP + challenge_id──────    (LED amber, "awaiting confirmation")
                                              ...device's job is over...

5. Companion ──challenge_id + proof───────►  ATLAS   (separate channel)
6.                                            verify proof, bind to txn
7a. success → BOUNDED RE-RESOLUTION → ALLOWED → SIGNED → bank → CONFIRMED (green)
7b. failure → refused, audited, NOTHING CHANGES (2026-09-18)     (still amber)
7c. expiry  → DENIED (terminal)                                  (LED red)
```

The device signs and displays. It never authenticates the human. That keeps
Blueprint §24.2 intact: *the device is a witness and a display, never a judge.*

### New state

`AWAITING_STEP_UP`, inserted between `EVALUATING` and the existing terminals:

```python
TxnState.EVALUATING:       {DENIED, ALLOWED, AWAITING_STEP_UP}   # + one entry
TxnState.AWAITING_STEP_UP: {ALLOWED, DENIED}                     # new
```

This is the single most consequential change in the proposal. It extends a
lifecycle taken from `ARCHITECTURE.md`'s failure-mode table. It also makes the
reconciliation story slightly larger: `AWAITING_STEP_UP` is a new way for a
transaction to be "stuck" after a crash, and the restart reconciler must treat
an expired one as DENIED, never as ALLOWED.

---

## 2. OTP / biometric / PIN handling

**Recommendation: ATLAS must never see a raw PIN, OTP secret, or biometric.**

This is the part of the proposal I feel most strongly about, because getting it
wrong turns a payment-decision service into a credential store.

| Factor | Who should verify it | Why not ATLAS |
|---|---|---|
| **Biometric** | The user's own phone (FIDO/WebAuthn model) | A fingerprint must never leave the device that captured it. ATLAS verifies a signed *attestation*, never an image or template |
| **PIN** | The bank / card issuer | The issuer already owns PIN verification, HSMs, and the regulatory obligation. ATLAS duplicating it creates a second breach target for no gain |
| **OTP** | ATLAS *could*, but should not by default | Generating and verifying OTPs makes ATLAS a credential issuer: secret storage, rate limiting, brute-force lockout, delivery channel security, SMS interception. That is a whole product, not a feature |

**What ATLAS should verify: a signed challenge-response.** ATLAS issues a
nonce; the authenticator (phone, or in simulation a script holding a separate
key) returns a signature over `challenge_id || transaction_id || envelope_hash`.
ATLAS checks the signature against an enrolled authenticator key.

That is the same primitive the project already uses for device identity, so it
adds no new cryptography and no new trust assumption — just a second enrolled
key with a different role.

**For the simulation**, the companion is a small script with its own key in its
own gitignored directory (proposed here as `scripts/step_up.py`; it shipped as
`scripts/enroll_authenticator.py`). It stands in for a phone. The
proposal document and the code must both say plainly that this proves the
*protocol*, not that a real second factor was present — exactly the same
honesty the project already applies to `secure_element_present=False`.

---

## 3. What happens after successful authentication — BOUNDED RE-RESOLUTION

This is the most security-critical part of the feature. An earlier draft of this
document said "re-resolve only the authentication dimension", which implied
calling the policy engine again with constraints. **That was too weak and is
withdrawn.**

Constrained re-evaluation is a trapdoor. Every constraint is something a future
change can get wrong, and `evaluate()`'s inputs — the clock, the subject's
history, the ML score — are all live. A transaction that got STEP_UP from
`odd_hours` at 23:58 and is confirmed at 06:01 would re-evaluate to a clean
ALLOW for a reason that has nothing to do with the customer proving anything.
`main.py:311` already warns about exactly this class of bug:

> …it fails closed rather than re-running policy (which could return a
> DIFFERENT answer for an id the bank already settled)

### The rule

> **Bounded re-resolution does not re-run ML. It does not re-run the policy
> engine. It does not read the clock for decision purposes. It is a pure,
> total function of the frozen decision context and the authentication result.**

Nothing is recomputed, so nothing can drift.

### The frozen decision context

Persisted atomically when the transaction enters `AWAITING_STEP_UP`, and
immutable thereafter:

| Field | Why it is pinned |
|---|---|
| `transaction_id` | identity; binds the challenge to one payment |
| `original_decision` | must be exactly `STEP_UP` for the flow to be legal at all |
| `matched_rules` **with each rule's action** | the actions are what make the DENY guard decidable without re-running the engine |
| `deciding_rule` | which rule supplied the winning action |
| `policy_version`, `policy_hash` | detects a policy edited while the challenge was open |
| `risk_band`, `anomaly_score` | the ML verdict as it stood; never recomputed |
| `envelope_hash` | binds the proof to the exact signed request |
| `challenge_id` | single-use, 128-bit random |
| `issued_at`, `expires_at` | absolute, not relative |
| `attempt_count` | brute-force bound, as proposed. *Since 2026-09-18 it only caps the audit trail at 10 failure rows and never ends a challenge.* |
| `auth_result` | the outcome being resolved |

Note `matched_rules` must be stored **with actions**, not just names. Today
`PolicyDecision.matched_rules` is `list[str]`. Storing the actions alongside is
what lets the guard below be a pure lookup instead of a policy re-read.

### The resolver, in full

```python
def resolve_step_up(ctx: FrozenDecisionContext, auth: AuthResult) -> Decision:
    """Total, pure, no I/O. Every path returns; the default is DENY."""

    # 1. Authentication itself
    if auth is not AuthResult.SUCCESS:
        return Decision.DENY

    # 2. Only a genuine STEP_UP may ever be resolved here.
    if ctx.original_decision is not Decision.STEP_UP:
        return Decision.DENY

    # 3. THE INVARIANT. If ANY matched rule said DENY, authentication is
    #    irrelevant. MOST RESTRICTIVE WINS already answered, and no proof of
    #    identity overturns a hard cap. This is unconditional and must never
    #    acquire an exception, an override, or an emergency branch.
    if any(r.action is Decision.DENY for r in ctx.matched_rules):
        return Decision.DENY

    # 4. DELAY is not satisfiable by authentication -- it is about timing,
    #    not identity. Out of scope for v1; fail closed rather than guess.
    if any(r.action is Decision.DELAY for r in ctx.matched_rules):
        return Decision.DENY

    # 5. The policy must not have changed underneath the challenge.
    if ctx.policy_hash != current_policy_hash():
        return Decision.DENY

    # 6. Only now, and only because every rule that fired was STEP_UP and the
    #    customer satisfied it.
    return Decision.ALLOW
```

Six guards, one `ALLOW`, and it is the last line. Anything unanticipated falls
through to DENY rather than to approval.

Step 3 is worth reading twice. It cannot be reached by a DENY transaction in
normal operation — a DENY never enters `AWAITING_STEP_UP` — so it is a
belt-and-braces check against a future bug that lets one in. That is exactly why
it must stay: the guard costs one line and defends against the worst possible
failure of this feature.

### The named invariant

> **STEP-UP-INVARIANT-1: a successful step-up must never convert a DENY into an
> ALLOW.**
>
> Formally: for all contexts and all auth results,
> `resolve_step_up(ctx, auth) == ALLOW` implies
> `no rule in ctx.matched_rules has action DENY`
> **and** `ctx.original_decision == STEP_UP`.

This is not a guideline. Any change that weakens it is a security regression
regardless of what it enables, and reviewers should treat a diff touching
`resolve_step_up` as they would a diff touching signature verification.

### How it is enforced, not merely documented

A prose rule decays. These must exist before the feature ships:

1. **Exhaustive enumeration.** `resolve_step_up` has a small, finite input
   space: 4 decisions × the DENY/DELAY/STEP_UP presence flags × auth outcomes ×
   policy-hash match. The test enumerates **every combination** and asserts
   `ALLOW` appears only where the invariant permits. Not examples — the whole
   space.

2. **A property test for the invariant itself**, phrased as the implication
   above, over randomly generated contexts.

3. **A structural guard**, in the same spirit as
   `test_firmware_never_contains_decision_logic`: `resolve_step_up` must call
   neither `evaluate(` nor `.score(`. If a future edit reintroduces
   re-evaluation, the test fails and names the reason.

4. **A mutation test in CI.** Deleting guard 3 must make the suite fail. A guard
   nothing tests is decoration — the same standard already applied to the
   `risk_band` boundary test, which was proven non-vacuous by injecting a
   violation and watching it fail.

5. **An audit assertion.** Every resolution writes its inputs and output; a test
   asserts an `ALLOW` resolution is never written without a matching successful
   authentication event.

### What still runs afterwards

On `ALLOW`, the **existing, unchanged** path takes over:
`AWAITING_STEP_UP → ALLOWED → SIGNED → SUBMITTED`. The assertion sent to the
bank is byte-identical in shape to any other allow — `AssertionPayload` stays
frozen, and the bank never learns a step-up occurred. That is ATLAS's business,
and it lives in ATLAS's audit trail.

## 4. What happens after failed authentication

| Case | Outcome |
|---|---|
| Wrong/invalid proof, malformed proof, or no enrolled authenticator | refused and audited, **no state change**; the challenge stays open until a valid proof or the 120 s expiry *(until 2026-09-18 an attempt was counted and the 3rd failure denied the payment — a denial anyone holding the two ids could trigger; see `STEP-UP-EXPIRY-FIX.md` §18)* |
| Challenge expired (proposed 120s) | `DENIED` (terminal) |
| Challenge id unknown | rejected, no state change, audited |
| Proof valid but bound to a *different* transaction | rejected, audited as a security event, no state change *(until 2026-09-17 the mismatch also cancelled the pending payment; fixed, see `STEP-UP-EXPIRY-FIX.md` §18)* |
| Crash while `AWAITING_STEP_UP` | reconciler finds it; expired → `DENIED` *(built 2026-09-16 as a startup cleanup rather than the bank reconciler; it also settles a challenge that was consumed before its transaction moved)* |

**Every terminal outcome is DENIED, never UNKNOWN.** A failed step-up is a
security failure, not an availability failure, and `TxnState`'s own docstring
draws exactly that line: security failures go straight to DENIED/FAILED.

No retry-with-a-new-challenge on the same transaction: one challenge per
transaction, forever. What bounds an attacker farming attempts against one
captured envelope is the 120 s expiry, not a failure count — and the envelope is
already spent, since its counter advanced when the payment was submitted.

---

## 5. How ML and the policy engine interact (unchanged)

Worth restating because it is already correct and this proposal must not disturb
it:

```
Transaction ──► ML (IsolationForest, 10 features) ──► RiskEvidence
                                                       {anomaly_score,
                                                        risk_band, reasons}
                        │
                        ▼
              Policy engine (frozen vocabulary:
              MAX_AMOUNT, NEW_BENEFICIARY, INTERNATIONAL,
              TIME_WINDOW, VELOCITY, RISK_THRESHOLD)
                        │
                        ▼
              Decision: ALLOW / STEP_UP / DELAY / DENY
              (MOST RESTRICTIVE WINS)
```

The ML **never decides**. It produces a band; a policy rule (`high_ml_risk`)
decides whether that band matters. Step-up sits entirely *downstream* of this
diagram. It changes nothing inside it.

---

## 6. Can emergency requests bypass security? **No. By design.**

This is a firm recommendation, not a preference.

*"It's urgent"* is the single most common pretext in social-engineering fraud.
An emergency flag that removes a check is an attacker's dream: it converts a
control into a bypass that anyone can invoke by asserting a feeling.

**Proposed rule: emergency may change WHICH factor is required. It may never
remove one, and it may never overturn a DENY.**

Legitimate uses of an emergency signal would be things like: shorten the
challenge expiry window, prefer a faster factor, raise the audit severity, or
notify a second channel. All of those *add* friction or visibility. None removes
a control.

Also note the three blockers that make emergency untestable today, all verified:

1. `"is_emergency_request":false` is hardcoded **inside the signed canonical
   template** (`atlas_device.ino:237`) — the device cannot assert it, and it
   cannot be flipped in transit because it is signed.
2. `synth.py` contains **0** training rows with `is_emergency_request=True` — the
   model has never seen one and cannot recognise it.
3. The frozen policy vocabulary has **no `EMERGENCY` key** — no rule could act
   on it even if the other two were fixed.

**Emergency handling is explicitly OUT OF SCOPE for this proposal.** It is
Phase 3.6 (see §12). Mentioning it here is to state that step-up must be built
so that a later emergency feature *cannot* become a bypass.

---

## 7. Replay and security implications

A new endpoint is new attack surface. What it must satisfy:

| Threat | Mitigation |
|---|---|
| Replay a captured step-up proof | Challenge nonce single-use, consumed atomically (`claim_nonce` pattern already exists) |
| Move a valid proof to another transaction | Proof signs `challenge_id \|\| transaction_id \|\| envelope_hash`; ATLAS re-derives and compares |
| Resurrect a DENIED transaction | Transition guard — `DENIED` is terminal and stays terminal; only `AWAITING_STEP_UP` accepts a step-up |
| Brute-force the challenge | Nothing to brute-force: the proof is an Ed25519 signature, and a failed one is refused without ending anything. The challenge id is 128-bit random, not sequential, and the 120 s expiry bounds the window *(until 2026-09-18 this row read "3 attempts, then terminal DENY" — that cap denied payments to anyone holding the two ids and stopped no attacker; see `STEP-UP-EXPIRY-FIX.md` §18)* |
| Hold a challenge open indefinitely | 120s expiry, checked at redemption and by the reconciler *(the startup cleanup, since 2026-09-16)* |
| Race two proofs for one challenge | Atomic claim — exactly one wins, same discipline as `claim_counter`/`claim_new` |
| Step-up as an oracle | Identical response shape and timing for "unknown challenge" and "wrong proof" |

**The device's original envelope is already spent** — its counter advanced and
its nonce burned on the first submission. So the step-up path cannot be used to
re-submit the original transaction. That existing property does real work here
and must not regress.

**Everything is audited**: challenge issued, each attempt, outcome, and the
identity of the authenticator key. `device_events` already has the shape.

---

## 8. Firmware changes required — minimal, and nothing signed changes

**The signed canonical template is NOT touched.** No re-enrollment, no parity
break, no re-flash of enrolled devices. This is the main reason to scope the
proposal this way.

| Change | Type |
|---|---|
| Recognise `final_status = STEP_UP` carrying a `challenge_id` | display only |
| Show "AWAITING CONFIRMATION" + challenge reference in the trace | display only |
| Amber LED **pulses** rather than solid, to distinguish "waiting" from "refused" | display only |
| *(optional v1.5)* poll a read-only `GET /v2/transaction/{id}/status` and show the final result | new read-only call |

`interpretStatus()` gains one branch mapping a new waiting state to the amber
LED. It still maps only `final_status` — it derives nothing, so
`test_firmware_never_contains_decision_logic` and the `risk_band` boundary test
both continue to hold unchanged.

**v1 recommendation: skip the polling.** The device shows amber and stops. The
outcome is visible in the logs and (once built) the dashboard. Zero protocol
change on the device side.

---

## 9. ML model changes required — **none**

Nothing. No new features, no retraining, no `synth.py` changes, no
`FEATURE_NAMES` edit.

Step-up is about what happens *after* the policy engine has decided. The ML has
already done its job by then. This is worth stating explicitly because it is the
main reason this proposal is smaller and safer than it first sounds.

---

## 10. Policy engine changes required — **none for v1**

The rules already emit STEP_UP. `evaluate()` is untouched. The frozen vocabulary
is untouched. The severity table and MOST-RESTRICTIVE-WINS are untouched.

All the new behaviour lives in `main.py`'s *handling* of a verdict the engine
already produces, plus the state machine.

*Deliberately excluded from v1*: a policy key describing which factor a rule
requires (e.g. `STEP_UP_FACTOR: biometric`). That is new vocabulary, which is
Phase 3.6. v1 uses one factor for every STEP_UP rule.

---

## 11. Does existing production behaviour stay untouched?

| Path | Impact |
|---|---|
| ALLOW → SIGNED → bank | **unchanged** |
| DENY | **unchanged** |
| DELAY | **unchanged** (still terminal; not in scope) |
| Device authentication, signature, counter, nonce, transaction_id | **unchanged** |
| `AssertionPayload` / what the bank sees | **unchanged, frozen** |
| Signed canonical bytes | **unchanged** |
| ML pipeline | **unchanged** |
| Policy engine | **unchanged** |
| **STEP_UP** | **CHANGED** — no longer terminal-DENIED |

That last row is a real behaviour change, so:

**Proposed gate: `ATLAS_ENABLE_STEP_UP`, default OFF.** With it off, STEP_UP
behaves exactly as it does today. This matches the codebase's existing
convention (`ATLAS_REQUIRE_DEVICE_AUTH`, `ATLAS_SIMULATION_ALLOW_COUNTER_RESET`)
and means the change ships dormant and is opted into deliberately.

Every one of the current 308 tests must still pass with the flag off, and that
should be the acceptance criterion before any step-up test is written.

---

## 12. Is this really Phase 3.6 / Phase 4?

**My assessment: no, it is not 3.6 — but it is not small either, and it should
not be smuggled in as a display fix.**

Phase 3.6 is *"Optional policy keys + ML features"*, marked **Highest risk —
touches decisions**. It means new policy vocabulary and new ML inputs. **This
proposal adds neither** (§9, §10). It completes a verdict the system already
emits.

The honest counter-argument, which I want on the record: this proposal *can*
turn a stopped payment into a completed one. That is a financial outcome
changing. It is not "just plumbing", and I would rather say so than let the
"no ML, no policy changes" framing make it sound safer than it is.

The distinction I would defend:

- **3.6 changes what the policy decides.** Different rules, different inputs,
  different verdicts for the same transaction.
- **This changes what happens after it decides.** Same verdict, same rules, same
  risk band — but STEP_UP finally has the second half its name implies.

**Recommended classification: its own step, sized between 3.3 and 3.4** — call
it 3.3b. Reasons:

1. It depends only on things already built (device auth, replay layers, state
   machine).
2. It does not depend on 3.4 (location grading) or 3.5 (integrity grading).
3. It should land **before** 3.6, because 3.6's emergency vocabulary needs a
   working step-up to escalate *into*. Building emergency first, with no
   step-up, is precisely how "emergency" becomes a bypass.
4. Its risk is concentrated in one place — the state machine — rather than
   spread across ML, policy and firmware.

**It is still a §20 change** requiring a pre-change report and explicit
approval: it touches decision handling, the transaction lifecycle, and adds an
authentication surface.

---

## Recommended scope if approved

**In scope (v1):**
`AWAITING_STEP_UP` state + transitions · challenge issue/redeem endpoints ·
signed challenge-response against an enrolled authenticator key · pinned
re-resolution (§3) · 120s expiry, failures refused without effect (2026-09-18) · full audit · display-only
firmware change · `ATLAS_ENABLE_STEP_UP` default OFF · reconciler handling.

**Out of scope (v1):**
Emergency handling · per-rule factor vocabulary · real OTP/PIN/biometric ·
DELAY becoming resumable · dashboard UI · device-side polling.

**Explicitly forbidden, in v1 and after:**
Any path where step-up overturns a DENY (**STEP-UP-INVARIANT-1**) · re-running
ML or `evaluate()` during resolution · ATLAS storing a PIN, OTP secret or
biometric template · emergency removing a control · changing the signed
canonical template or `AssertionPayload`.

---

## What was asked of Dhanush before any code was written (all approved 2026-09-11)

1. Approve or reject the **out-of-band** model (§1) — given the hardware, the
   alternative is adding a keypad to `diagram.json`, which I do not recommend.
2. Approve the **new `AWAITING_STEP_UP` state** (§1) — this extends a lifecycle
   drawn from `ARCHITECTURE.md`.
3. Confirm **ATLAS must not handle raw PIN/OTP/biometric** (§2).
4. Confirm **bounded re-resolution** as specified in §3 — specifically that it
   re-runs neither ML nor the policy engine, and that **STEP-UP-INVARIANT-1**
   (a successful step-up never converts a DENY into an ALLOW) is enforced by
   exhaustive enumeration, a structural guard and a mutation test, not by prose.
5. Approve **classification as 3.3b**, ahead of 3.4 and 3.6 (§12).
