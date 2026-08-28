# HANDOFF.md — start here in a fresh context

**Updated 2026-08-27**, at the end of hardening checkpoint F3. This file exists so a
**fresh Claude session with zero memory of that conversation** can pick up correctly.
Read it fully before touching anything.

> Staleness warning, twice earned. The Step-4 version of this file claimed Steps 5-9 were
> unstarted and 58 tests passed. The Step-8 version then claimed "Steps 0-8 done, 152
> passed" and stayed that way through Phase 3.1-3.3, F1, F2 and F3 — off by 152 tests and
> four completed checkpoints. **If this file ever disagrees with `git log` or a live
> `pytest` run, trust the repository, not this file**, and correct it.

## Reading order for a fresh session

1. **This file** — status and rules.
2. `docs/IMPROVEMENT-DIRECTIVE.md` — **the governing rules for all future work.** Read
   before proposing any change. It is why "this is a good security practice" is not, on
   its own, a reason to change anything here.
3. `ledger/ARCHITECTURE.md` — the frozen research architecture. Read before proposing
   *anything* touching ML, policy, bank authority, or crypto.
4. `BUILD-PLAN.md` — the step-by-step build status table (Steps 0-8 marked ✅ with
   hard-won detail; Step 9 not started). **Does not yet cover Phase 3 or F1-F3** — this
   file and `docs/IMPROVEMENT-DIRECTIVE.md` carry those.
5. `docs/PHASE3-SPEC.md` — the device-trust layer specification (registry, envelope,
   signing, replay, location, integrity). Phases 3.1-3.3 are built; 3.4-3.8 are not.
6. `docs/SECURITY-GAP-REPORT.md` — the Phase 1 audit that started the hardening work.
   Historical: several gaps it names (G4 the HTTP 500, G6 the timezone defect, G7
   DENY-vs-FAIL_CLOSED, G1/G2/G3 device auth) have since been closed.
7. `ledger/SYNTHESIS.md` — cross-references/resolved ambiguities between the research
   and the build. Short, worth the read; now 7 items.
8. `docs/ATLAS-Blueprint.md` — a full engineering-specification writeup. **Written after
   Step 3** and *not* updated since, so its status claims (45 tests, "no `firmware/`",
   "no `crypto.py`") are stale — but its **§24 is the design Step 8 and F3 actually
   implemented**, its §25 governs honest security claims, and its `[A]`-`[G]` provenance
   labelling is still the clearest statement of what's grounded vs. proposed. Read §24
   and §25; ignore its progress numbers.

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
6. **Never commit without being explicitly asked.** Every commit so far was requested
   directly by Dhanush.

## Implementation status

**Build steps 0-8 done. Step 9 (dashboard) not started. Then a separate hardening track
ran on top: Phase 2, Phase 3.1-3.3, and checkpoints F1, F2, F3 — all complete.**

| Step | What | Status |
|---|---|---|
| 0 | Shared contracts (`contracts.py`) + `docs/POSITIONING.md` | ✅ Done |
| 1 | ML anomaly layer (`atlas_service/ml/`) | ✅ Done |
| 2 | Policy engine (`atlas_service/policy/`) | ✅ Done |
| 3 | Two-service split, HTTP boundary | ✅ Done |
| 4 | Transaction state machine + SQLite persistence + reconciliation | ✅ Done |
| 5 | Ed25519 signing, bank-side verification, replay cache, revocation | ✅ Done |
| 6 | Real end-to-end HTTP flow, signed assertions, live `/reconcile` | ✅ Done |
| 7 | UPI-shaped + Pix-shaped payment-rail adapters | ✅ Done |
| 8 | Wokwi ESP32 firmware + tested `virtual_device.py` | ✅ Done |
| 9 | Dashboard | ❌ Not started |

### Hardening track (after Step 8)

| Checkpoint | What it did | Status |
|---|---|---|
| Phase 1 | Security audit → `docs/SECURITY-GAP-REPORT.md`. No code changed | ✅ Done |
| Phase 2 | Fixed the duplicate-`transaction_id` HTTP 500; fixed TIME_WINDOW timezone; separated DENY vs FAIL_CLOSED with `decision_reason`; structured audit logging | ✅ Done |
| Phase 3.1 | Device registry (`atlas_service/device/`) — enrollment, ACTIVE/SUSPENDED/REVOKED, audit trail | ✅ Done |
| Phase 3.2 | Device identity (`firmware/device_identity.py`) — per-device Ed25519 key, separate from the ATLAS key | ✅ Done |
| Phase 3.3 | Device authentication — `DeviceEnvelope`, signature-first verification, counter + nonce replay layers, `POST /v2/transact` | ✅ Done |
| Phase 3.4-3.8 | Location grading, integrity grading, policy vocabulary, firmware rollout, closing legacy `/transact` | ❌ **Deferred** — see `docs/PHASE3-SPEC.md` |
| **F1** | Canonicalization: `LocationEvidence` coordinates float → `Decimal` | ✅ Done |
| **F2** | Concurrency: SQLite thread affinity + atomic claim-and-advance | ✅ Done |
| **F3** | Firmware protocol convergence: `.ino` now signs a `DeviceEnvelope` | ✅ Done |

Full per-step detail is in `BUILD-PLAN.md`'s build-order table for Steps 0-8. **The
hardening track is not in `BUILD-PLAN.md`** — its record is the F1/F2/F3 section below
plus `docs/IMPROVEMENT-DIRECTIVE.md`.

Bugs that were real and are easy to reintroduce: Step 1's data-leakage fix, Step 4's
transaction-ID collision regression, Step 6's two latent state-machine bugs, Phase 2's
RAM-counter replay collision and UTC-vs-IST timezone defect, F1's float-in-signed-bytes,
F2's three check-then-act races.

## Current test status (verified fresh, 2026-08-27, immediately before writing this file)

```
304 passed
```

| File | Tests | | File | Tests |
|---|---|---|---|---|
| `test_phase3_device_trust.py` | 53 | | `test_bank_boundary.py` | 17 |
| `test_virtual_device.py` | 30 | | `test_state_machine.py` | 15 |
| `test_f1_canonicalization.py` | 30 | | `test_end_to_end.py` | 13 |
| `test_phase2_fixes.py` | 29 | | `test_crypto.py` | 9 |
| `test_policy_engine.py` | 24 | | `test_ml_model.py` | 8 |
| `test_f2_concurrency.py` | 21 | | `test_revocation.py` | 5 |
| `test_adapters.py` | 21 | | `test_replay.py` | 5 |
| `test_f3_firmware_parity.py` | 19 | | `test_expiry.py` | 5 |

Growth, each checkpoint preserving every prior test: 152 (Step 8) → 181 (Phase 2) →
234 (Phase 3.1-3.3) → 264 (F1) → 285 (F2) → 304 (F3).

**Firmware build:** compiles clean with `arduino-cli`, ESP32 core 3.3.11, ArduinoJson
7.2.0, libsodium (bundled in the core). **1168316 bytes = 89% of program storage**;
global variables 51248 bytes = 15% of dynamic memory.

## Git state

**Four commits, all from the Step 5-7 era. Everything after Step 7 is UNCOMMITTED.**

```
49f4461  Step 7: payment-rail adapters -- one signed decision, two rail shapes
451a9b8  Step 6: real end-to-end HTTP flow, signed assertions, live reconciliation
94ab742  Step 5: Ed25519 signing, bank-side verification, replay, revocation
bf53c8f  Initial checkpoint: frozen ATLAS research architecture + Steps 0-4
```

Uncommitted in the working tree: **Step 8, Phase 2, Phase 3.1-3.3, F1, F2, F3** — i.e.
`firmware/`, `scripts/`, `atlas_service/device/`, four `docs/` files, six test files, and
modifications to `contracts.py`, `atlas_service/{main,db,policy}`, `bank_service/`.
Dhanush reviews before each commit. **Verify with `git status`, not this line.**

## The six F3 limitations — the permanent improvement record

These are tracked, classified, and **must not be "fixed" reflexively.** Classification
follows `docs/IMPROVEMENT-DIRECTIVE.md` §19; under §19 only A/B/C normally warrant
immediate engineering work, and **none of these six are A/B/C.**

| # | Limitation | Class | Standing decision |
|---|---|---|---|
| 1 | **Wokwi round-trip not proven.** The `.ino` compiles and its canonical template is pinned byte-for-byte against the backend, but the compiled firmware has never *executed*. On-device signature bytes, NTP timestamp formatting, and NVS persistence are unverified | **E** verification gap | Requires a human to run the simulator. Do not claim runtime parity until it is actually demonstrated |
| 2 | **Private key seed in plaintext flash.** `DEVICE_KEY_SEED_HEX` is a compile-time constant, readable with `esptool`. A valid signature proves possession of the enrolled key, **not** that the physical ESP32 is genuine | **G** hardware | Document. A secure element (ATECC608-class) is an architecture change — §2 approval required first |
| 3 | **`firmware-config` exports the private-key seed.** Inherent to a software-key provisioning model: without a secure element the firmware has no way to hold a key except as bytes | **I** intentional | Do not remove in isolation. Understand the whole key lifecycle first (§8) |
| 4 | **Wokwi NVS persistence not guaranteed.** A restarted simulation may resume its counter from 0 and be rejected | **H** environment | Already handled correctly: `COUNTER_REGRESSION` → reject. `ATLAS_SIMULATION_ALLOW_COUNTER_RESET` exists, defaults **off**, is audited, and cannot bypass the nonce or `transaction_id` layers. **Never weaken replay protection for the simulator** |
| 5 | **89% flash utilisation.** libsodium added ~120KB; ~142KB headroom remains | **D** resource | Constraint, not defect. Measure flash/RAM before adding any firmware dependency. Do not remove security components to reclaim space |
| 6 | **Legacy `POST /transact` remains open by default.** It performs no device authentication; `ATLAS_REQUIRE_DEVICE_AUTH=1` closes it | **J** deferred | Phase 3.8. **Do not close prematurely** — verify clients, tests, and migration first |

## Other known limitations (full detail in `BUILD-PLAN.md`/`firmware/README.md`)

- **The Wokwi demo tunnel provides no authentication** and exposes the key-holding
  `atlas_service` publicly while running. Demo-only; kill it after demos.
- ML model is refit from scratch on every request — no per-subject model caching.
- Amount baseline in ML is per-subject-global, not per-beneficiary.
- `bank_service`'s ledger is in-memory, resets on restart, three hardcoded accounts.
- `bank_service`'s revocation table is in-memory too — a revoked key un-revokes itself
  on restart, unlike the SQLite-persisted replay cache. Deliberate, matching
  `BUILD-PLAN.md`'s "persisted replay cache" vs. "minimal revoke check" wording.
- `BANK_SERVICE_URL` is a hardcoded constant in `atlas_service/main.py`, not config.
- `bank_service` learns ATLAS's public key from a shared gitignored file — a toy stand-in
  for key distribution, explicitly not a solution to RQ-24.
- `STEP_UP`/`DELAY` land in the same `TxnState.DENIED` state as `DENY`. Since Phase 2 the
  response body carries both `final_status` and `decision_reason`, which do distinguish
  them; the persisted *state* still does not. No interactive confirmation loop exists.
- Concurrent transactions **from one device** trip `COUNTER_REGRESSION` when they arrive
  out of order. This is the monotonic counter working as designed, not a defect —
  8 sequential transactions from one device give 8/8 ALLOW. Do not "fix" it.
- F2's locks serialise access **per store instance**, not across processes. Multi-process
  deployment is untested and unclaimed.
- Cross-rail FX uses one hardcoded illustrative rate, and converting back does not
  round-trip — that divergence is deliberate and tested, demonstrating RQ-16/25/26
  rather than solving it.
- No handling yet for ML raising an exception or malformed/missing policy YAML, except
  the one specific tested case (unknown condition key → `ValueError`).

## Open research questions

Not re-derived here — see `ARCHITECTURE.md`'s "Open research question backlog" (RQ-7
through RQ-31). **None are answered by any implementation work done so far**, and Step 8
in particular answers none of them: it demonstrates where the trusted-embedded layer
sits, not that it protects anything. Implementation tests the *mechanism*, never the
*novelty claim* or the governance questions.

## What F1, F2 and F3 actually established — with the evidence

Recorded because §4 of the improvement directive requires stating what supports each
claim. **PROVEN** = demonstrated by an executed test or a live run in this repository.

### F1 — canonical representation of signed material
- **Defect:** `LocationEvidence.latitude/longitude/accuracy_m` were `float` inside
  `canonical_envelope_bytes()`, contradicting `contracts.py`'s own rule for signed
  numerics. Latent, never live — `location` is `None` everywhere in Phase 3.3.
- **Fix:** those three fields → `Optional[Decimal]`, which pydantic serialises to a JSON
  *string* preserving exact digits (`"12.971600"` stays `"12.971600"`).
- **PROVEN:** 30 tests; a mutation reverting to `float` failed 12 of them.
- **NOT proven:** anything about location *trustworthiness*. Deterministic representation
  and trustworthy evidence are different properties. GNSS spoofing is untouched.

### F2 — concurrency and atomicity
- **Defects:** (a) all three SQLite stores were opened without `check_same_thread=False`,
  and FastAPI resolves a sync dependency on one threadpool thread then runs the endpoint
  body on another → `sqlite3.ProgrammingError` surfacing as `INTERNAL_ERROR`;
  (b) `check_same_thread=False` alone permits genuinely concurrent use of one connection,
  producing `InterfaceError` and corrupted reads; (c) three check-then-act sequences
  (counter, nonce, transaction creation).
- **Fix:** `check_same_thread=False` + busy timeout + `RLock` on every operation, plus
  atomic `claim_counter()` / `claim_nonce()` / `claim_new()` / `ReplayCache.claim()`.
- **PROVEN:** measured live before → after: 6/4/6 `INTERNAL_ERROR` out of 10 concurrent
  requests → **0 in all three scenarios**; 8/8 sequential transactions ALLOW. 21 tests.
- **NOT proven:** absence of all races. A mutation making `claim_counter` non-atomic was
  **not** caught until a 2 ms interleaving window was added — the sub-microsecond window
  is not reliably reproducible under the GIL. **The atomicity guarantee rests on the
  structural argument (single locked compare-and-swap), not on the tests.**
- **NOT proven:** multi-process safety. Untested and unclaimed.

### F3 — firmware protocol convergence
- **Defect:** `.ino` sent a bare Transaction — only 9 of 15 fields, omitting every
  contract default — to the legacy unsigned `/transact`, and did no signing at all.
- **Fix:** hand-built canonical JSON (sorted keys, all 15 fields, no whitespace, defaults
  spelled out), Ed25519 via libsodium (bundled in ESP32 core 3.3.11; mbedTLS has no
  Ed25519), `POST /v2/transact`, NVS-persisted counter, random boot id, halt-on-no-identity.
- **PROVEN:** the firmware's own template, extracted from source and rendered in Python,
  is byte-identical to `canonical_envelope_bytes()` (605 bytes). 19 tests; a mutation
  removing one default field failed 4 of them. Firmware compiles. Live run with
  firmware-shaped bytes: ₹1,500 → ALLOW/GREEN, ₹60,000 → STEP_UP/AMBER, ₹1,50,000 →
  DENY/RED; tampered amount/beneficiary/subject/device_id/counter → `INVALID_DEVICE_SIGNATURE`;
  stripped signature → `MISSING_DEVICE_SIGNATURE`; verbatim replay → `COUNTER_REGRESSION`.
- **NOT proven:** that the *compiled firmware* produces those bytes at runtime. Parity is
  proven on the template, not on executed code. On-device libsodium signature bytes, NTP
  formatting, and NVS persistence are all unverified — that is Limitation 1.
- **NOT proven, and must never be claimed:** any hardware security property. A valid
  signature proves possession of the enrolled key, not the genuineness of the device.

## Exactly where we stopped

F3 completed and reported at its checkpoint; `HANDOFF.md` and
`docs/IMPROVEMENT-DIRECTIVE.md` were then written to record the hardening track.
**Nothing is committed** — the last commit is still Step 7 (`49f4461`).

## Next step (do not start without explicit approval)

There are two open tracks. **Neither should begin without Dhanush saying so**, and
`docs/IMPROVEMENT-DIRECTIVE.md` §20 requires a pre-change report first.

1. **Step 9: dashboard** — the last unbuilt item of the original build plan. Per
   `BUILD-PLAN.md`: static HTML/JS (matching `refundradar`'s no-Jinja convention),
   showing transactions, ML evidence, policy decision, crypto/replay status, active rail
   adapter, and the measurement numbers from `ARCHITECTURE.md`'s "Measurement dimensions".
2. **Phase 3.4-3.8** — location grading, integrity grading, policy vocabulary, firmware
   rollout, and finally closing legacy `/transact`. Specified in `docs/PHASE3-SPEC.md`.
   Note 3.6 (policy vocabulary) is the only one that can change financial decisions and
   was deliberately deferred to Phase 4.

A third, cheaper option: **run the Wokwi round-trip** to close Limitation 1. That needs
no code change at all — only a human at the simulator.

Follow the standing process: explain the design first, then implement, then test edge
cases deliberately, then show real results, then stop for approval.

## Pending decisions still waiting on Dhanush (carried forward, not resolved)

- **Wokwi cost**: **resolved as of Step 8** — the free/public gateway is sufficient
  (outbound-only is all the device needs); no paid Private Gateway dependency was added.
- **Timeline/scope pressure**: does the original ~11-14 focused day estimate still hold?
  Never explicitly reconfirmed since the build actually started.
- **Module 7/8 status** (`ARCHITECTURE.md`'s known gaps): whether dedicated
  Security/Failures research days ever ran — flagged multiple times, never answered,
  not currently blocking anything.
- **`docs/ATLAS-Blueprint.md` is stale** on progress (still describes Steps 0-3 and 45
  tests). Its Section 24 is current and was implemented; its status numbers are not.
  Worth deciding whether to refresh it or explicitly freeze it as a point-in-time
  document.
