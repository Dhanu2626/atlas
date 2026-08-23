# HANDOFF.md — start here in a fresh context

**Generated 2026-08-28**, at the end of a long session that took ATLAS from
research-complete through Steps 0-4 of the build. This file exists so a **fresh Claude
session with zero memory of that conversation** can pick up correctly. Read this file
fully before touching anything.

## Reading order for a fresh session

1. **This file** — status and rules.
2. `ledger/ARCHITECTURE.md` — the frozen research architecture. Read before proposing
   *anything* touching ML, policy, bank authority, or crypto.
3. `BUILD-PLAN.md` — the step-by-step build status table (Steps 0-4 marked ✅ with
   details; 5-9 not started).
4. `ledger/SYNTHESIS.md` — cross-references/resolved ambiguities between the research
   and the build. Short, worth the read.
5. `docs/ATLAS-Blueprint.md` — a full engineering-specification writeup. **Written after
   Step 3, before Step 4** — accurate for Steps 0-3, does not yet reflect Step 4
   (state machine/persistence) or this handoff's findings. Useful for the big picture,
   not the current source of truth for status — this file and `BUILD-PLAN.md` are.

Do not re-read `ledger/CHATGPT-TRANSCRIPT.md` (3700+ lines) unless specifically asked to
verify something against the original research — everything load-bearing from it is
already distilled into `ARCHITECTURE.md`.

## What ATLAS is, in one paragraph

A research prototype testing one narrow, frozen question: can a trusted,
user-controlled financial policy layer evaluate a transaction using deterministic
policy + local behavioral ML, protect that decision cryptographically, and produce a
verifiable assertion existing payment infrastructure can consume — without ATLAS ever
replacing the bank or the payment rail. Novelty is **explicitly unproven** — real
prior-art research found a patent combining most of the original architecture. See
`ARCHITECTURE.md`'s "Novelty status" section; do not let this drift back into a
stronger claim.

## Standing rules — do not violate these

1. **Never silently change the frozen architecture.** If you find a real problem: state
   the evidence, name the affected component, ask, then wait. Do not act first. Full
   text: `PROJECT.md`'s "Architecture-change protocol" section.
2. **Three provenance categories, always distinguished:** (1) original ChatGPT research,
   (2) the frozen freeze-conclusions, (3) build decisions made afterward (mine, offered
   for confirmation, not historical record). See `ARCHITECTURE.md`'s "Provenance
   convention."
3. **Do not fill historical gaps.** Day 2's verbatim content, the 5 original reference
   images, RQ-1–6's exact original wording, Day 13's unanswered assignment, and whether
   Module 7/8 ever ran are **frozen as gaps**. Only Dhanush providing the actual missing
   material resolves them — never reconstruct plausibly.
4. **The established build process, step by step:** explain the design (what and why,
   grounded in the frozen architecture) *before* writing code → implement → run the full
   test suite → deliberately test edge cases and adversarial/failure scenarios, not just
   the happy path → show real, actually-executed results (never claim a result without
   having run it) → **stop and wait for explicit approval before starting the next
   step.** This has been the pattern for every step so far and should continue.
5. **Never claim novelty merely because ATLAS implements something.** Implementation
   status and novelty status are unrelated axes.

## Implementation status — Steps 0-4 done and verified, 5-9 not started

| Step | What | Status |
|---|---|---|
| 0 | Shared contracts (`contracts.py`) + `docs/POSITIONING.md` | ✅ Done |
| 1 | ML anomaly layer (`atlas_service/ml/`) | ✅ Done |
| 2 | Policy engine (`atlas_service/policy/`) | ✅ Done |
| 3 | Two-service split, HTTP boundary (`atlas_service/main.py`, `bank_client.py`, `bank_service/`) | ✅ Done |
| 4 | Transaction state machine + SQLite persistence + reconciliation (`atlas_service/{db,state_machine}.py`) | ✅ Done |
| 5 | Ed25519 signing/verification, canonical serialization, replay cache, minimal revocation | ❌ Not started — **next step** |
| 6 | Full HTTP integration, all core scenarios | ❌ Not started |
| 7 | UPI-shaped + Pix-shaped payment-rail adapters | ❌ Not started |
| 8 | Wokwi ESP32 firmware | ❌ Not started |
| 9 | Dashboard | ❌ Not started |

Full detail, including real bugs found and fixed at each step, is in `BUILD-PLAN.md`'s
build-order table — read the Step 1/2/3/4 rows before touching those areas, they
contain hard-won specifics (e.g. Step 1's data-leakage fix, Step 4's transaction-ID
collision regression) that are easy to accidentally reintroduce.

## Current test status (verified fresh, 2026-08-28, immediately before writing this file)

```
58 passed in 50.65s
```
- `test_ml_model.py` — 8
- `test_policy_engine.py` — 24
- `test_bank_boundary.py` — 13
- `test_state_machine.py` — 13

Additionally, Step 3's authority-boundary and communication-failure claims were
re-verified with **two genuinely separate live `uvicorn` processes talking over real
HTTP** (not just `TestClient`), the session before this one — ATLAS ALLOW + bank
approves, ATLAS ALLOW + bank independently DENYs, and bank completely unreachable →
PENDING, all confirmed with real `curl` calls. Not re-run for this handoff (would
require starting two live servers); the 58-test suite above covers the same guarantees
at the automated-test level.

## Repository state — verified, with one real finding

All 32 project files are present on disk and match what `BUILD-PLAN.md` claims exists —
confirmed by a fresh `find` listing immediately before writing this file, not assumed:

```
atlas/
├── HANDOFF.md                      (this file)
├── PROJECT.md, BUILD-PLAN.md, requirements.txt, contracts.py, .gitignore
├── docs/{POSITIONING.md, ATLAS-Blueprint.md}
├── ledger/{ARCHITECTURE.md, CHATGPT-TRANSCRIPT.md, NOTEBOOK.md, SYNTHESIS.md}
├── atlas_service/
│   ├── main.py, bank_client.py, db.py, state_machine.py
│   ├── ml/{synth,features,model}.py
│   └── policy/engine.py + policies/{user-demo-1,user-frozen-1,user-poor-1}.yaml
├── bank_service/{main,ledger}.py
└── tests/{conftest,test_ml_model,test_policy_engine,test_bank_boundary,test_state_machine}.py
```

**⚠️ Not committed to git.** `git init` was run in Step 0, but `git status` shows **no
commits exist** — all 32 files are sitting as untracked. Everything is safely on disk
(this OneDrive-synced folder), but there is no version-control checkpoint of any of this
work. I have not committed anything myself — the standing rule is never to commit
without being explicitly asked. **Recommend asking Dhanush directly whether to make an
initial commit now**, rather than assuming either way.

## Known limitations (consolidated — full detail in `BUILD-PLAN.md`/`ATLAS-Blueprint.md`)

- No cryptographic signing/authentication exists yet — HTTP calls between the two
  services are unsigned. The `SIGNED` state in the state machine is structural only,
  not backed by real cryptography (that's Step 5).
- ML model is refit from scratch on every request — no per-subject model caching.
- Amount baseline in ML is per-subject-global, not per-beneficiary (documented, doesn't
  block any current test).
- `bank_service`'s ledger is in-memory, resets on restart, three hardcoded accounts.
- `BANK_SERVICE_URL` is a hardcoded constant in `atlas_service/main.py`, not config.
- No handling yet for ML raising an exception or malformed/missing policy YAML, except
  the one specific tested case (unknown condition key → `ValueError`).

## Open research questions

Not re-derived here — see `ARCHITECTURE.md`'s "Open research question backlog" (RQ-7
through RQ-31). None of them are answered by the implementation work done so far;
implementation tests the *mechanism*, not the *novelty claim* or the governance
questions (enrollment, root of trust, DENY-side authority conflict, cross-rail
semantics, bank economic incentive).

## Exactly where we stopped

Step 4 was implemented, explained before being built, tested (13 new tests, all
edge-cased: invalid transitions, terminal-state protection, idempotent creation, and
the actual kill-mid-transaction-restart-reconcile scenario using a real SQLite file and
a fresh store object), and verified against the full 58-test suite. A separate live,
two-real-process HTTP smoke test additionally re-confirmed Step 3's authority and
failure-handling claims. **Dhanush has not yet said go for Step 5.** This handoff was
requested immediately after Step 4's results were shown, before any Step 5 discussion.

## Next step (do not start without explicit approval)

**Step 5: cryptographic signing.** Per `BUILD-PLAN.md`: Ed25519 sign in `atlas_service`
(behind the `secure_sign()` interface name from `ARCHITECTURE.md`'s Embedded Interface
Emulator), verify in `bank_service`; canonical JSON serialization (the same
`sort_keys=True` discipline `atlas_service/policy/engine.py`'s hashing already uses);
a persisted replay cache in `bank_service`, separate from signature checking; a minimal
`revoke()` check. Test scenarios per `BUILD-PLAN.md`: tamper detection (flip one byte,
signature must fail) and replay detection (resend a valid, untampered, unexpired
assertion, must still be rejected — these are different attacks needing different
defenses, don't conflate them).

Follow the standing process: explain the design against `ARCHITECTURE.md`'s frozen
assertion-field list and signing principles first, then implement, then test edge cases
deliberately (not just happy path), then show real results, then stop for approval.

## Pending decisions still waiting on Dhanush (carried forward, not resolved)

- **Wokwi cost**: pay for the Private Gateway (~€8/mo) for Step 8, or use the free
  tunnel workaround? Not needed until Step 8.
- **Timeline/scope pressure**: does the original ~11-14 focused day estimate still hold?
  Never explicitly reconfirmed since Steps 0-4 actually happened.
- **Module 7/8 status** (`ARCHITECTURE.md`'s known gaps): whether dedicated
  Security/Failures research days ever ran — flagged multiple times, never answered,
  not currently blocking anything.
