# ARCHITECTURE.md — ATLAS decisions & open research questions

Distilled from the ChatGPT Research Program sessions through Day 13 + the "Final
Architecture Freeze" conversation that followed it (captured into this repo across two
sessions: Day 1-10 on 2026-08-19, Day 11-13 + freeze on 2026-08-21). Raw source:
`ledger\CHATGPT-TRANSCRIPT.md` — if this file and the transcript ever disagree, the
transcript wins. Read this file before proposing any ATLAS design that touches ML,
policy, bank authority, or the crypto/authorization protocol.

**2026-08-21 note:** this file was substantially rewritten, not just appended to. Days
11-13 changed the novelty picture materially (see below) and the "freeze" conversation
sharpened several principles that were looser in the Day 1-10 version. Where something
here supersedes what an earlier build session might have assumed, that's intentional —
this is now the authoritative spec, per Dhanush's own instruction to treat the frozen
architecture as final unless implementation surfaces a genuine technical problem.

## Provenance convention (set 2026-08-22 — applies to this file and everything built from here)

Every claim in this project tracks as exactly one of three things, and that must stay
explicit going forward, not just inside the verification report that established it:

1. **Original ChatGPT research** — exploratory, Day 1 through Day 13's red team.
   Ideas here were sometimes floated, tested, and later revised or rejected *within
   the research itself* (e.g. "TEE+policy+ML+attestation" was explored Day 9-10, then
   explicitly killed as a novelty claim Day 11). Cite the day.
2. **The freeze conclusions** — the final, locked architecture, authority hierarchy,
   assertion fields, exclusion list, and the "8 things to carry forward," all from the
   single "make it stronger and freeze it" conversation. This is what "finalized
   architecture or research conclusions" means — the material that requires the
   evidence-first protocol (`..\PROJECT.md`) before it can be touched.
3. **Build decisions** — choices made afterward, turning (1) and (2) into running
   code (Wokwi, the literal two-process split, Ed25519, the toy rail-adapter shapes,
   the folder structure, the timeline, the V1-vs-deferred split). Mine, offered for
   confirmation, not part of the historical record — see `..\BUILD-PLAN.md`.

Sections below are already mostly day-cited (1) or explicitly marked "freeze" (2);
`BUILD-PLAN.md` already isolates (3) under "added afterward, not from the ChatGPT
conversation." Any new claim from here on states which of the three it is.

**Frozen historical gaps — do not fill these in, even plausibly, unless Dhanush
explicitly provides the missing material:** Day 2's verbatim lesson content, the 5
originally-uploaded reference images, RQ-1 through RQ-6's exact original wording, Day
13's own assignment answers (posed, never answered on record, including the
fill-in-the-blank survival sentence), and whether Module 7 (dedicated Security day) or
Module 8 (historical failures) ever actually ran. See the verification report
(2026-08-22) for the full accounting.

## Novelty status: OPEN / UNPROVEN — this is now explicit, not a hedge

Days 11-13 did real prior-art research (patents, existing products, standards) and
found that **most of ATLAS's individual pieces already exist**:

- A patent (US20210065194A1) already combines **policy ruleset + ML-based
  authentication + TEE + attestation + a transaction-authorization message** — i.e.
  most of ATLAS's original architecture, as a single filed claim.
- A second patent describes **policy-compliance checking inside a TEE with proof of
  execution attached to a transaction**.
- **Visa's Commercial Payment Controls** already give issuers/fintechs near-real-time
  spend/merchant/location/time/velocity controls tied into authorization.
- **Coinbase's Policy Engine** already applies rules (amount, destination, etc.) to
  wallet operations with accept/reject outcomes.
- **Apple Pay** already demonstrates Secure Element + Secure Enclave + dynamic
  transaction cryptograms in production, at scale.
- **EMV tokenization** already supports payment credentials constrained to a specific
  device/merchant/scenario.
- **NIST + Android Key Attestation** already establish hardware-backed attestation as a
  real, working mechanism.

**None of these individually can be ATLAS's novelty claim.** That list killed several
of the framings used earlier in this project (e.g. "TEE-based policy authorization,"
"local ML + policy engine," "cryptographically signed transaction decisions" — all
prior art). This is good news, not bad: it means the project is doing real novelty
research instead of assuming uniqueness, which is exactly what makes the eventual
"why does this deserve to exist" answer defensible instead of naive.

**What survives, as an unproven hypothesis, not a claim:** the specific combination of
*(a)* the policy being **user-owned** rather than institution-owned, *(b)* being
**portable across payment rails** (UPI/Pix/FPS) rather than tied to one provider, and
*(c)* keeping **behavioral ML strictly local**, disclosing only a minimal decision to
the bank. Individually, pieces of (a)/(b)/(c) also have partial precedent — so the
honest status is **"a narrower, harder question than originally posed, not yet shown to
be unsolved either."** Don't let this drift back into a "we invented X" claim without
re-running this check.

## Current core research question (final frozen version, supersedes earlier drafts)

> Can a trusted, user-controlled financial policy layer evaluate transaction intent
> using deterministic policies and local behavioral evidence, protect the resulting
> decision through a trusted security boundary and cryptographic identity, and produce
> a verifiable policy assertion that can be consumed by existing payment infrastructure
> — without replacing the payment rail?

Rejected framings, in order of when they were killed — don't regress to any of these:
- ~~"Can ML detect fraud?"~~ — Day 7, not novel
- ~~"Build an embedded fraud detector"~~ — Day 8, too generic
- ~~"ATLAS decides ALLOW/DENY and tells the bank what to do"~~ — Day 9, wrong authority
  model
- ~~"TEE + policy + ML + attestation for transaction authorization"~~ — Day 11, this
  exact combination is already patented

## The authority hierarchy (frozen, load-bearing — every module must respect this)

```
LAW / REGULATION
       ↓
BANK / PAYMENT SYSTEM
       ↓
USER ATLAS POLICY
       ↓
ML EVIDENCE
```

A layer can only ever make a transaction **more restrictive**, never grant something
the layer above it didn't already allow.

- `ATLAS = ALLOW`, `Bank = DENY` → **DENY**, always. ATLAS cannot override the bank.
- `ATLAS = DENY`, `Bank = LOW RISK` → **DENY only if the bank has formally agreed to
  treat a registered ATLAS policy as an enforceable constraint.** If the bank has never
  heard of ATLAS, nothing stops the payment going through some other path — this is not
  a bug to fix in code, it's an institutional-trust gap that cryptography alone cannot
  close (see RQ-13/RQ-23/RQ-30 below).

## What ATLAS explicitly is NOT (frozen exclusion list)

Not a new payment rail. Not a replacement for UPI/Pix/FPS. Not a bank. Not a wallet.
Not a fraud-detection replacement. Not an autonomous AI that decides whether money
moves. Not a blockchain project. Not something that requires physical hardware to
exist. ATLAS never holds user money, never modifies bank balances, never independently
settles a transaction, never lets ML have final authority, never blindly trusts the
untrusted mobile app layer.

## The three-domain split (frozen framing — use this instead of "embedded + ML + finance")

| Domain | Job | Provides |
|---|---|---|
| Embedded / Trusted Security | protects the *authority* | trusted execution, protected identity, key protection, attestation |
| Machine Learning | provides *evidence* | local behavioral anomaly detection only — never the final decision |
| FinTech / Finance | provides *meaning* | policy semantics, authorization logic, payment-rail integration |

The embedded layer exists because it's a genuine security requirement (protecting keys
and policy-evaluation integrity needs a stronger boundary than ordinary app code can
give), not because the project needed an Arduino somewhere in the diagram. Precise
wording to keep using: *"a suitable hardware-backed/trusted embedded security
environment can provide stronger guarantees... than ordinary application software"* —
not every embedded system automatically has these properties; a bare Arduino Uno
running ordinary firmware is not a secure element.

## Settled architecture principles

1. **ML is an advisor, never the judge.** Unchanged from Day 7, reinforced repeatedly
   through Day 13's red team: even a fully compromised ML model (poisoned, evaded, or
   just wrong) should not be able to authorize a transaction the policy engine
   wouldn't — ML failure degrades to "fall back to deterministic policy," not "fail
   open."
2. **ATLAS authority ≠ bank authority.** See the hierarchy above. This is now stated
   as a hard rule, not a design preference.
3. **Never assume a transaction's outcome after an interruption.** Unchanged from Day 3.
4. **The software-only prototype must never claim hardware-equivalent security.**
   Unchanged, reinforced: *"Physical security properties are identified as future
   hardware implementation requirements and are not claimed to be provided by the
   software-only prototype."*
5. **Minimum-necessary disclosure to the bank.** Sharpened: the ML risk score is now
   explicitly **excluded by default**, not just "probably shouldn't be sent." The
   external assertion carries `decision` (ALLOW/STEP_UP/DELAY/DENY), not the number
   that produced it — different ML models produce incomparable scores, and the bank
   doesn't need to understand ATLAS's model internals to consume its output.
6. **Fail-closed for security failures; reconcile for availability failures — these are
   different failure classes, handled differently (new, Day 13/freeze).** A security
   verification failure (bad signature, policy hash mismatch, revoked key, failed
   attestation) → deny or step-up, immediately. An availability failure (network down,
   bank unreachable) → `PENDING` → reconciliation, never a blind retry and never
   silently treated as `ALLOW`. Conflating these two is exactly the mistake that would
   make ATLAS either insecure (treating a bad signature as "just a glitch, retry") or
   unusable (treating a dropped WiFi packet as a security incident).
7. **Policy integrity requires versioning + hashing + non-rollback**, not just a
   `policy_version` field for bookkeeping. A monotonically increasing version number,
   plus rejecting any assertion produced under an older version once a newer one is
   active, is the concrete defense against an attacker forcing ATLAS back to a looser
   policy.
8. **Every non-trivial claim needs an external citation, not "I think."** Unchanged,
   and this is exactly the discipline that produced the novelty findings above — it
   cuts both ways: it kills naive novelty claims, and it's also what makes the
   remaining hypothesis defensible instead of hand-wavy.

## Policy Semantic Layer + payment-rail adapters (new, Day 12, directly serves the "global finance, not just India" goal)

Instead of writing the policy engine in UPI-specific terms, define a small,
rail-independent vocabulary and translate it per rail:

```
                    ATLAS POLICY (semantic layer)
                              │
                 MAX_AMOUNT, NEW_BENEFICIARY, INTERNATIONAL,
                 TIME_WINDOW, VELOCITY, RISK_THRESHOLD, REQUIRE_STEP_UP
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
          UPI Adapter     Pix Adapter     FPS Adapter
```

**Scoping note for the build (not in the original ChatGPT conversation, added when
reconciling this against the build plan):** the Pix/FPS "adapters" should be toy,
illustrative translations of the same policy object into a differently-shaped payload
— not attempts to replicate Brazil's or the UK's real payment-message formats. The
point being demonstrated is *"one policy, multiple rail-shaped outputs,"* not real
interoperability with foreign payment systems, which is far outside prototype scope.

## Embedded Interface Emulator — concrete API surface (new, Day 13/freeze)

The software-only trusted-core boundary, proposed as this function surface (maps
directly onto `atlas_service`'s crypto/state modules in the build plan):

```
init_device()
generate_identity()
get_public_key()
secure_sign(data)
verify_policy(policy)
attest()
revoke()
```

Everything on the untrusted side (UI, network, payment adapter) only ever calls through
this interface — it never sees the private key or the raw policy-evaluation internals.

## ATLAS Assertion — final field list (confirms/finalizes the Day 10 draft)

`issuer`, `subject` (pseudonymous account binding — never raw PII), `transaction_id`,
`amount`, `currency`, `beneficiary`, `policy_version`, `policy_hash`, `decision`,
`nonce`, `issued_at`, `expires_at`, `audience`, `atlas_key_id`, `signature`.

Deliberately excluded by default: raw transaction history, full behavioral profile, ML
feature vectors, ML risk score itself, private key, internal model parameters, full
policy text (only its version + hash travel externally).

**One correction from the freeze conversation worth remembering:** *policy hash alone
proves integrity, not legitimacy* — a hash proves "this exact policy text produced this
decision," not "the real account holder authored this policy." That gap (policy
*provenance*, not just policy *integrity*) is still open — see RQ-7/RQ-12 below.

## Red Team scorecard (Day 13 — full attack-by-attack pass)

| Attack | Status | Why |
|---|---|---|
| Compromised OS/malicious app | 🟡 mitigable | trusted layer re-verifies transaction data itself, doesn't trust what the untrusted app claims |
| Stolen phone | 🟡 layered | key protection helps, but if the attacker authenticates as the user, that's an identity problem, not a crypto failure |
| Stolen assertion (replay) | 🟢 strong | transaction ID + nonce + expiry + server-side "already consumed" state + signature |
| Malicious policy update | 🟡 mitigable | requires user auth + versioning + secure storage for updates |
| Fake policy enrollment | 🔴 unsolved | trust-bootstrap problem, not solvable by cryptography alone |
| Compromised/poisoned/evaded ML | 🟡 mitigable | ML is non-authoritative by design (principle 1); deterministic policy still applies even if ML is fully wrong |
| Policy rollback | 🟡 mitigable | monotonic versioning + reject-older-than-active |
| Compromised TEE | 🔴 serious | attestation gives evidence, not a mathematical guarantee — this is a genuine trust-boundary failure if it happens |
| Compromised Secure Element | 🔴 serious | needs key revocation + re-enrollment; no cryptographic trick prevents this, every trust system needs a compromise path |
| Fake attestation | 🟡 mitigable | verifier must check the full chain (cert chain + key binding + nonce + expected state) |
| Network failure | 🟢 solved | state machine + reconciliation (principle 6) |
| Bank rejects ATLAS's ALLOW | 🟢 — not actually an attack | this is the authority hierarchy working as designed |
| ATLAS/bank conflict when ATLAS says DENY | 🔴 unsolved | governance/integration problem — see authority hierarchy note above |
| Emergency override abuse | 🟡 mitigable | needs a *separate*, high-assurance flow — never a simple "emergency = bypass" button |
| Privacy leakage via the assertion itself | 🟡 open research area | even `decision=STEP_UP` leaks *something* happened; can minimize, can't fully eliminate |
| Cross-rail/cross-border incompatibility | 🔴 hardest problem | currency conversion timing, fees, rounding, differing local regulations — genuinely unresolved |

**Honest conclusion from the red team, not to be softened:** ATLAS survived several
attacks because existing security primitives (signatures, nonces, versioning, state
machines) mitigate them well. It did **not** survive several deeper attacks — trust
enrollment, policy authority/enforcement, cross-rail semantics, and TEE/Secure-Element
compromise are architectural problems that cryptography alone cannot close. Those four
are the project's genuine open frontier, not implementation details to patch later.

## Failure-mode table (frozen, Day 13/freeze — becomes the source of truth for test scenarios)

| Failure | ATLAS response |
|---|---|
| ML unavailable | fall back to deterministic policy |
| ML uncertain | step-up |
| Policy corrupted | deny |
| Key unavailable | step-up / deny |
| Attestation fails | step-up / deny |
| Device revoked | deny |
| Network unavailable | pending → reconciliation |
| Bank unavailable | pending |
| Bank rejects | bank's decision wins |
| Assertion expired | reject |
| Assertion replayed | reject |
| Policy rollback detected | reject |
| Model integrity failure | disable ML, use policy alone |
| Emergency request | separate high-assurance flow (auth + confirmation + risk check + audit + notification) |
| Unknown payment status | reconcile — never blindly retry |

## Test scenarios (spec — reconciled with `BUILD-PLAN.md`'s scenario list, that file has the build-order-appropriate subset)

Normal → ALLOW; policy violation (over limit) → DENY; behavioral anomaly → STEP-UP;
ML unavailable → policy still enforced deterministically; policy hash mismatch → DENY;
replayed assertion → REJECT; expired assertion → REJECT; assertion re-targeted at wrong
beneficiary → REJECT; revoked device → REJECT; network failure mid-transaction →
PENDING → reconcile; ATLAS ALLOW + bank DENY → final DENY; policy rollback attempt →
REJECT; same policy through UPI/Pix/FPS adapters → consistent semantic interpretation
in the simulation.

## Measurement dimensions (for the eventual report/demo — not just a working demo, a measured one)

**Security:** replay attacks blocked, modified-policy detection, revoked-identity
rejection, forged-signature rejection, rollback rejection — all as pass/fail tests with
recorded results, not just "it works."
**ML:** precision, recall, false-positive rate, false-negative rate on the synthetic
anomaly set.
**Privacy:** what leaves the trusted boundary — raw behavioral data sent externally
(should be zero), number of ML features disclosed (should be zero), what the assertion
itself reveals.
**Finance:** policy-violation detection accuracy, transaction-state correctness,
reconciliation success rate.
**Performance:** policy-evaluation latency, ML inference latency, signing latency,
verification latency.
**Interoperability:** same policy object, evaluated through each rail adapter, produces
consistent semantic results.

## Open research question backlog (ATLAS's own numbering — keep it)

**Resolved-ish:** RQ-1 through RQ-6, RQ-10 (see prior version of this file / the
transcript for detail — local ML without raw-data disclosure, attestation as the
mechanism for instance authenticity, policy hash for version-binding, what's
simulatable vs. needs hardware, distributed-but-hierarchical authority, transaction
reconciliation after network failure).

**Still genuinely open — now confirmed by the red team, not just flagged as
theoretical:**
- RQ-7 / RQ-12 / **RQ-24** — policy/device *provenance* (not just integrity): how does
  a bank know a policy or an ATLAS instance genuinely traces back to the real account
  holder? The red team's "fake enrollment" attack (🔴) is this exact gap.
- RQ-9 / RQ-15 / **RQ-27** — should ML risk ever reach the bank, at what granularity —
  now defaulting to "no," see principle 5.
- RQ-11 / **RQ-23** — who is the root of trust / who operates ATLAS identity
  infrastructure? Three candidate models floated (bank-operated / independent ATLAS
  authority / device-ecosystem-operated / hybrid) — no answer chosen.
- RQ-13 / **RQ-28** / **RQ-29** — the authority conflict when ATLAS says DENY and the
  bank hasn't agreed to honor it; where user policy sits relative to mandatory
  regulatory controls; who's liable if ATLAS says ALLOW and the transaction turns out
  fraudulent. All three are governance questions, not technical ones.
- RQ-14 — revocation lifecycle (ACTIVE → SUSPENDED → REVOKED) — designed, not yet built.
- RQ-16 / **RQ-18** / **RQ-19** / **RQ-25** / **RQ-26** — cross-rail policy
  portability: does the *semantic meaning* of a policy survive translation across
  UPI/Pix/FPS, and how does currency conversion (timing, fees, rounding) affect a
  cross-border limit? Marked by the red team as the single hardest open problem.
- **RQ-30** — what would make a bank/PSP *economically and operationally* willing to
  integrate ATLAS at all? (Candidate angles found during Day 12: ATLAS represents
  explicit user *preference*, distinct from the bank's own fraud-risk assessment;
  could reduce certain authorized-fraud disputes by providing cryptographic evidence of
  declared intent; privacy-by-minimal-disclosure as a differentiator; cross-provider
  policy portability as the strongest but hardest-to-realize argument.)
- **RQ-31** — which ATLAS guarantees need real hardware vs. can stay simulated
  indefinitely? Table from the freeze conversation: policy evaluation, ML, policy
  hashing, digital signatures, the payment API, and the policy compiler are all fine in
  software long-term; private-key protection, trusted execution, device identity,
  attestation, and secure boot are simulatable for a prototype but *should* eventually
  be hardware-backed for anything real.

## Known gaps / deliberate skips in the record

- **Day 5/6 (FinTech) explicitly skipped by Dhanush's own choice** — unchanged from the
  prior version of this file.
- **Day 2 (Cryptography kickoff)** referenced but never captured verbatim — unchanged.
- **Module 8 (Failures — Mondex/Avant/eNaira/Dinero) still hasn't run**, even after
  Days 11-13's much deeper novelty/gap work. Worth one direct question before treating
  research as fully closed: was this deliberately dropped once the patent-level
  prior-art search (Day 11) covered similar ground, or genuinely still pending? Not a
  blocker either way — flagging once, not re-litigating.

Related: [[atlas-project]] (memory pointer/status), [[ml-learning-track]] (the
*separate* general ML curriculum with Claude as mentor — don't merge).
