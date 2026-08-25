# SYNTHESIS.md — connecting the research, not just archiving it

`ARCHITECTURE.md` records what was decided. `BUILD-PLAN.md` records what gets built.
This file is different: it's where separate pieces of the record — often days apart,
never explicitly linked to each other at the time — get connected, and where that
connection either resolves an ambiguity or exposes a real gap worth closing before it
surfaces as a testing problem. Same provenance discipline as everywhere else: each
item below states what it's connecting and why, and whether the fix (if any) touches
the frozen research (needs the evidence-first protocol) or my own build layer (fixed
directly, noted here).

## 1. Resolved: does the policy engine see bank risk at decision time?

**The tension.** Day 7's own Q5 research question hands the policy engine four
simultaneous signals including `Bank: Fraud risk=LOW` — implying bank risk is visible
*before* ATLAS decides. But Day 12's architecture note sequences it the other way —
`Local ML → Behavioral Risk → ATLAS Policy → Bank Risk Engine → Final Processing` —
and the frozen final architecture (`ATLAS TRUSTED CORE → ATLAS Assertion → PAYMENT
ADAPTER → BANK/PSP`) confirms the bank only ever sees ATLAS's *output*, never
participates in producing it.

**Resolution:** Day 7 Q5 was an early exploratory framing (category 1) that got
superseded by the freeze's finalized data flow (category 2) — it's not a contradiction
so much as research narrowing over time, the way "Day 7's version of the assertion
fields" also got refined by Day 10. For implementation, the frozen sequencing wins:
`atlas_service` never has bank risk as an input. This is exactly why `bank_service`
independently rejecting an ATLAS-approved transaction (Test 4) is the scenario that
actually demonstrates the authority hierarchy, and why BUILD-PLAN.md's Test 3 already
reframes the "conflicting signals" scenario around a user-declared rule vs. ML, not
bank risk vs. ML. Nothing to change — this note exists so the apparent contradiction
doesn't get rediscovered and second-guessed mid-build.

## 2. Fixed: `contracts.py`'s `Transaction` didn't support half the original behavioral patterns

Connecting Day 7's explicit synthetic-dataset field list (`Location`, `DeviceID`,
`MerchantCategory`, `NewDevice`, `AuthenticationMethod`, among others) against the
`Transaction` model I'd already written turned up a real gap, not a hypothetical one:
without `location`, the **Location Pattern** ("Normally Bangalore... suddenly another
country") from the very first pre-Day-1 discussion has nothing to compute against.
Without `device_id`/`is_new_device`, **Device Pattern** ("Normally Samsung S21 FE...
suddenly an unknown Android phone") is unimplementable. Without `merchant_category`,
**Merchant Pattern** ("Normally Amazon/Flipkart/Zomato... suddenly an unknown
cryptocurrency exchange") has no field to check. These aren't minor — they're three of
the ten original behavioral patterns that motivated ML's inclusion in ATLAS in the
first place, and the model as originally written couldn't express any of them.

**Fixed directly** in `contracts.py` (build layer, category 3 — no frozen-architecture
rule touched): added `location`, `device_id`, `merchant_category`,
`is_new_device`, `authentication_method`. Verified working against a transaction built
directly from the original pre-Day-1 example (₹70,000, 3:12 AM, unknown crypto
exchange, new device, international) — see the test run in this session.

## 3. Added, with provenance flagged: `declared_travel_mode` and `is_emergency_request`

Two more fields added to `Transaction` for the same reason, but their provenance is
less clean-cut than #2's, so flagging it explicitly rather than letting it blend in:

- **`declared_travel_mode`** connects Day 7 Q4 (which designed Travel Mode
  specifically to stop legitimate travel from reading as high anomaly) to Day 12's
  architecture diagram, which lists "Context" as an explicit input category alongside
  Identity and Transaction. Travel Mode is never re-confirmed by name in the freeze's
  final architecture or assertion fields — but it's never contradicted or dropped
  either, and it's the direct, already-designed answer to a false-positive problem the
  research identified and never revisited. Carrying it forward as a Context input.
- **`is_emergency_request`** connects the original pre-Day-1 "Emergency Behaviour"
  pattern (*"Suppose you use Emergency Mode only twice a year. Suddenly used 20 times
  today. Something is wrong."*) to the frozen emergency-override design. The freeze
  designed *how* an emergency request gets handled (extra auth, confirmation, audit,
  notification) but the field for actually flagging one — and for the original idea
  that *repeated* emergency-mode use is itself a signal ML should see — didn't exist
  anywhere in the contracts. Without it, the emergency flow can't be built at all, and
  the original idea (frequency of emergency use as its own anomaly) has nothing to
  compute against either.

Both are build-layer additions (category 3), grounded in category-1/2 material, not
independently invented.

## 4. Guidance for Step 1 (not yet built): use the original examples as the actual test fixtures

When the synthetic transaction generator gets built, its planted anomalies shouldn't
be generic — the research already handed over specific, concrete numbers that should
become the literal test cases, so the ML model is validated against the exact
scenarios that motivated its inclusion, not invented substitutes:

- Normal: ₹500-3,000, 8am-8pm, Bangalore, known beneficiaries/devices, Amazon/
  Flipkart/Zomato/Electricity merchant categories, ~5 transactions/day.
- Planted anomaly 1 (amount+time): 3:12 AM, ₹70,000.
- Planted anomaly 2 (velocity): 45 transactions within 2 minutes vs. normal ~5/day.
- Planted anomaly 3 (merchant): an unknown cryptocurrency exchange.
- Planted anomaly 4 (device+location): unknown Android phone, another country.
- Legitimate-but-unusual (should NOT trigger DENY, should STEP-UP at most, and is the
  actual test of the "anomaly ≠ fraud" principle from Day 7): a genuine ₹85,000
  laptop purchase — this exact example is what the research used to argue ATLAS
  should ask "is this intentional?" rather than block outright.
- Travel-mode true positive: an international transaction that should read as *less*
  anomalous specifically because `declared_travel_mode=True` — this is the concrete
  test that `declared_travel_mode` (item 3 above) actually does something, not just
  sits unused in the schema.

Also worth building into the generator: the "Financial Behaviour Timeline" idea from
the very first discussion (salary → rent → groceries → fuel, recurring monthly) —
recurring, expected transactions (rent, subscriptions) should be part of a persona's
normal pattern, not just random daily noise, so the baseline the model learns is
actually a *rhythm*, matching the original framing, not a flat average.

## 5. Closing a loop Day 1 opened and never explicitly answered: ATLAS's own bottleneck

Day 1's Rule #6 ("Always Find the Bottleneck") worked through ATM (bottleneck: cash)
and UPI (bottleneck: trust) and Blockchain (bottleneck: scalability), then said "ATLAS
— we'll discover it." Scanning Days 3 through the freeze, that question is never
explicitly answered in those terms again — but the research converges on one answer
repeatedly, independently, across multiple days, without ever naming it as *the*
bottleneck: Day 10 Q5 ("bank has never agreed to recognize ATLAS... nothing stops
[bypassing it]"), Day 12's bank-CTO challenge ("why would you integrate ATLAS?"), and
Day 13's red team (fake policy enrollment rated 🔴, the single unsolved-by-cryptography
category). Every one of these is a version of the same thing: **no amount of
cryptography, architecture, or ML manufactures institutional trust.** That's ATLAS's
bottleneck, in the same sense ATM's is cash — not a flaw to fix in code, a structural
constraint to design around and be honest about, the same way ATM design doesn't try
to "solve" needing physical cash on hand.

Worth having explicit for the interview-readiness angle too: "what's ATLAS's
bottleneck" is exactly the kind of question the record already trained you to ask
about *other* systems — an interviewer asking it about ATLAS itself deserves the same
directness the research gave ATM and UPI, not a vaguer answer than the ones already on
record for other systems.

## 6. The one perspective Day 1 promised but never actually ran against ATLAS itself

Of Day 1's five perspectives (Engineer, Researcher, Hacker, Founder, User), Hacker
(Day 13's red team), Engineer (the whole build), and Researcher (the novelty
investigation) are all thoroughly covered. Founder is partially covered via RQ-30 (why
would a *bank* pay/integrate), but never from "would Dhanush actually build a company
here." User — "would I actually use this?" — is never explicitly asked about ATLAS
itself anywhere in the record, only about existing systems in the early days.

Answering it honestly, using only what's already established rather than inventing new
opinions: friction is real and already on record — step-up confirmations, a policy
file to actually maintain, an emergency flow that's deliberately harder to use than a
plain bypass would be, and a privacy claim that's explicitly "minimizes disclosure,"
not "guarantees privacy." None of that is a flaw the record hid; it's what an honest,
security-first design costs in usability, and the research already named that tradeoff
directly (freeze: "there is always a trade-off between security, usability,
availability, privacy, complexity, cost and interoperability"). The honest User-lens
answer is: someone who already cares enough about a specific risk (frequent travel,
managing multiple accounts, wanting evidence of their own stated intent) opts in
knowingly, in exchange for that friction — not a mass-market convenience feature. Worth
saying that plainly if asked, rather than let it go unaddressed because it was never
asked internally.

## 7. Resolved: what exactly does a payment-rail adapter translate?

**The tension.** Day 12's Policy Semantic Layer diagram shows the **policy
vocabulary** (`MAX_AMOUNT`, `NEW_BENEFICIARY`, `INTERNATIONAL`, `TIME_WINDOW`,
`VELOCITY`, `RISK_THRESHOLD`, `REQUIRE_STEP_UP`) fanning out into UPI/Pix/FPS
adapters — i.e. adapters translate *policy rules*. But the frozen final architecture
sequences it as `ATLAS TRUSTED CORE → ATLAS Assertion → PAYMENT ADAPTER → BANK/PSP`,
putting the adapter *after* the decision — and `BUILD-PLAN.md`'s Step 7 line and its
test scenario 11 both say the adapter "takes the same `PolicyDecision` object,"
i.e. adapters translate *output*.

**Resolution:** not a contradiction — two halves of the same diagram, which turned out
to already be split across two build steps. The diagram's **top half** (a policy
vocabulary that is rail-independent in the first place) was achieved back in **Step 2**:
`atlas_service/policy/policies/*.yaml` is written entirely in the frozen semantic
vocabulary with zero UPI-specific terms, which is exactly what Day 12 was asking for.
The **bottom half** (three rail adapters) is **Step 7**, on the output side, matching
both the frozen data flow and `BUILD-PLAN.md`'s own wording. Nothing to change; noted
here so the apparent contradiction doesn't get rediscovered and re-litigated later.

One build-layer refinement worth recording (category 3, mine): the adapter takes the
**`SignedAssertion`**, not the bare `PolicyDecision`. The assertion already carries
every field a rail needs (subject, beneficiary, amount, currency, transaction_id,
decision, policy_version, policy_hash), it is what actually travels per the frozen
flow, and taking only it is what keeps adapters provably clear of ML/policy internals —
which matters because `ARCHITECTURE.md` places the payment adapter on the **untrusted
side** of the trust boundary ("Everything on the untrusted side (UI, network, payment
adapter) only ever calls through this interface — it never sees the private key or the
raw policy-evaluation internals"), while `BUILD-PLAN.md`'s folder structure puts
`adapters/` under `atlas_service/`. That tension is resolved not by moving the folder
but by enforcing the property structurally: `tests/test_adapters.py` fails the build if
any adapter imports `atlas_service.crypto`, `.policy`, or `.ml`.

Related: [[atlas-project]] memory, `ARCHITECTURE.md` (what these connections build on
top of), `BUILD-PLAN.md` (where #4's guidance lands once Step 1 starts).
