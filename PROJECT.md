# PROJECT.md — ATLAS operating file

**2026-08-28: for current build status, read `HANDOFF.md` first — it supersedes the
"Current" and "Status by module" sections below, which describe the pre-build research
phase and are now stale (Steps 0-4 of the actual build are done; see `HANDOFF.md` and
`BUILD-PLAN.md`).** The rest of this file (role split, architecture-change protocol,
rituals) still applies.

Read this first every session ("start day" ritual). Full plan: `..\ATLAS-PLAN.md`
(CareerForge root). Notebook: `ledger\NOTEBOOK.md`. Architecture decisions + open
research questions distilled from the sessions so far: `ledger\ARCHITECTURE.md` (added
2026-08-19 — read it before proposing any design touching ML/policy/bank authority/the
crypto protocol; a lot of that ground has already been argued through). Cross-day
connections, resolved ambiguities, and gaps found by connecting the research against
the actual build: `ledger\SYNTHESIS.md` (added 2026-08-22 — read before building Step
1/ML, it names the exact test fixtures to use).

## Current: research frozen (2026-08-21), moving into build

Research extended through Day 13 (prior-art/novelty investigation, gap analysis, red
team) plus a "final architecture freeze" pass, done since the 2026-08-19 note below —
materially stronger than it looked two days ago. Day 10's own assignment questions did
get answered in this later batch. The architecture, authority model, ATLAS assertion
fields, failure-mode table, and test scenarios are now explicitly frozen — see
`ledger\ARCHITECTURE.md`, which was substantially rewritten 2026-08-21 to reflect this
(not just appended to). Explicit instruction from Dhanush, echoed by his own research
mentor: don't casually change the research question or add unnecessary
architecture/technology — only deviate for a genuine technical glitch hit during
implementation. Build plan lives in `BUILD-PLAN.md`, reconciled against the frozen
scope 2026-08-21 (see its "V1 vs. documented-but-deferred" table — the frozen spec is
somewhat larger than a rushed timeline can fully build, so that split is explicit rather
than silently cutting corners). Claude is driving implementation for this phase.

## Role split (set 2026-08-06)

Dhanush self-directs Modules 1+ research via ChatGPT — deliberate, matches the plan's
own "researcher not student" ethos ("I wanted to know myself what's wrong instead of
everything depending upon you," his stated motto for ~2 weeks from 2026-08-06). Claude's
job here is infrastructure: keep this file and the notebook current, give honest
critique when asked, help with tooling/logistics. Don't proactively teach module content
or offer to run the next day's lesson.

**2026-08-19 note:** ~2 weeks from 2026-08-06 lands right about now — this is the point
the role split itself said to revisit, not a trigger to unilaterally start teaching.
Flagged to Dhanush; keep operating as infrastructure-only until he says otherwise.

## Architecture-change protocol (set 2026-08-22 — read before touching the frozen architecture)

Never silently change or "improve" the frozen architecture (`ledger\ARCHITECTURE.md`)
based on personal judgment. Rejected pattern, named explicitly by Dhanush: *"I think a
better architecture would be X, so I changed it."* Required pattern instead:

> "I found a concrete problem with [the frozen design]. Here is the evidence. Here is
> the affected component. Do you want me to modify it?"

Then **wait for the answer** — don't touch anything until he responds. A "concrete
problem" means something demonstrable (a bug, a contradiction, a scenario the design
can't handle) — not a stylistic preference or a hunch that another approach is
cleaner. This applies to the frozen research architecture itself; it does not block
normal implementation work (writing the code that realizes an already-agreed design is
not "changing the architecture"). Full reasoning:
[[feedback-architecture-change-protocol]] (memory).

**2026-08-22 refinement:** the historical-record gaps identified in the verification
report (Day 2's verbatim content, the 5 original images, RQ-1–6's exact wording, Day
13's unanswered assignment, Module 7/8's status) are frozen as gaps — do not fill them
in, even plausibly, unless Dhanush explicitly provides the missing material. Also:
track three provenance categories, not two — see `ledger\ARCHITECTURE.md`'s
"Provenance convention" — (1) original ChatGPT research, (2) the freeze conclusions,
(3) build decisions made afterward. Only (1) and (2) are covered by the
evidence-first-and-ask rule above; (3) is normal implementation judgment, though still
worth surfacing for confirmation rather than assumed.

## Status by module (best-effort reconstruction, 2026-08-19)

The actual delivery used continuous "Day N" numbering that interleaved modules rather
than strict per-module blocks, so this mapping is approximate. Full detail and caveats
in `ledger\ARCHITECTURE.md`.

| Module | Topic | Status |
|---|---|---|
| 0 | Research Thinking | Day 1 — done |
| 1 | Cryptography | Days 2-3 — done. ChatGPT explicitly called the crypto + basic secure-transaction portion complete at the end of Day 3 (authN vs authZ, digital signatures, PKI, certs, TLS, session keys, replay attacks, nonces/counters/timestamps/expiration, transaction IDs, idempotency, transaction state machines, power-loss recovery) |
| 2 | Finance | Day 4 — done (money, banks, transactions, clearing/settlement, credit, risk, liquidity) |
| 3 | FinTech | **explicitly skipped by Dhanush's own choice** — Day 4 closed with a Day 5/FinTech preview, his next instruction was literally "go for the day 7." Not a capture gap |
| 4 | Embedded Systems | Day 8 — done, extensive (MCU/firmware/secure boot/root of trust/hardware-backed keys/secure element/TEE/attestation, plus a real-world deep-dive: Android KeyMint/Keystore/StrongBox, EMV tokenization, PCI HSM). **Delivered after Day 7 (ML), reversing the roadmap's own Layer 4→5 order** — not necessarily a problem, just note the drift |
| 5 | Machine Learning | Day 7 — done, extensive (features, supervised/unsupervised, anomaly detection, behavioral baseline, precision/recall/F1/confusion matrix, model drift, adversarial ML, explainability, privacy, local-vs-cloud/hybrid ML). ChatGPT gave its own "DAY 7 CHECKPOINT" confirming completeness |
| 6 | Payment Systems | partial — Day 9 covered UPI-specific architecture (payment app/PSP/bank/payment rail roles, where ATLAS sits) in depth; Cards/SWIFT/CBDC from the original module scope are untouched so far |
| 7 | Security (fraud/attacks/risk/threat modeling as its own topic) | **unclear** — fraud concepts are woven into Day 7 (false pos/neg) and Day 3 (replay attacks) rather than run as the dedicated "Day 4: Fraud" the original pre-Layer plan called for. Ask Dhanush directly rather than assume |
| 8 | Failures (Mondex/Avant/eNaira/Dinero) | not started — still where the excluded reference images (see Open Items) are slated to return |
| 9 | ATLAS Architecture (gap analysis → ideas → red team → architecture → software architecture → testing → master review) | **not formally started as its own block, but substantial architecture work is already happening organically** inside Days 3, 8, 9, 10 — transaction state machine, trust hierarchy, authorization protocol draft, the sharpened core research question. The original "only after Module 9" gate hasn't held in practice; foundation-learning and architecture-in-progress have been running concurrently since Day 3. Full log: `ledger\ARCHITECTURE.md` |

Build phases (backend/firmware/simulator/cloud/dashboard/SDK) are still undefined —
Module 9's Master Review, whenever it formally happens, is still the intended gate for
deciding the project deserves to exist. Don't scaffold code yet.

## Rituals

- **start day** → read this file + the last `ledger\NOTEBOOK.md` entry → continue the
  current module (or start the next one) → work the day's lesson structure (Story →
  History → Fundamentals → How it works → Industry → Weaknesses → Research Questions →
  ATLAS Notes → Assignment → Review)
- **close day** → notebook entry for the day's topic → glance at the Working Hypothesis
  log in the notebook, update it only if today's research actually changed your
  thinking → tick the module status table above → note the next lesson
- Every lesson ends with: *"If this technology disappeared tomorrow, how would I
  redesign it from scratch?"*

## Open items

- The original ChatGPT thread's first message included 5 uploaded images — reference
  material on existing embedded-finance companies and their failures, not a professor's
  brief. Dhanush deliberately excluded them from Day 1 so first-principles thinking isn't
  anchored on existing players — reasonable for now, but they're exactly what Module 8
  (Failures) needs. Bring them back in whenever Module 8 actually runs. See ATLAS-PLAN.md.
- Day 2 (Cryptography kickoff) was referenced (via Day 3's recap) but never captured
  verbatim into `ledger\CHATGPT-TRANSCRIPT.md`. Not urgent, don't assume it didn't
  happen.
- Whether Module 7 (Security as its own dedicated topic) and Module 8 (Failures) ran at
  all is unclear from what's been captured — see status table. Worth a direct question
  rather than an assumption either way.
