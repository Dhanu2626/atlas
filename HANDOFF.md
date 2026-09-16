# HANDOFF.md — start here in a fresh context

**Updated 2026-09-16**, after the step-up restart-cleanup fix and the first GitHub
publish. Before that, **updated 2026-09-02**, after the daylight run observed ALLOW (closing Limitation 1)
and the NTP clock fix closed limitations 7 and 8. Previously updated 2026-09-01
(the Wokwi round trip) and 2026-08-27 (hardening checkpoint F3). This file exists so a
**fresh Claude session with zero memory of that conversation** can pick up correctly.
Read it fully before touching anything.

> Staleness warning, three times earned. The Step-4 version of this file claimed Steps
> 5-9 were unstarted and 58 tests passed. The Step-8 version then claimed "Steps 0-8
> done, 152 passed" and stayed that way through Phase 3.1-3.3, F1, F2 and F3 — off by
> 152 tests and four completed checkpoints. The F3 version then claimed nothing was
> committed past Step 7, while `e22a690` had committed the entire hardening track on
> 2026-08-28. Each time, the file was wrong and the repository was right.
> **If this file ever disagrees with `git log` or a live `pytest` run, trust the
> repository, not this file**, and correct it.

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

## Current test status (re-verified 2026-09-16: `351 passed`, 134s)

```
351 passed
```

| File | Tests | | File | Tests |
|---|---|---|---|---|
| `test_phase3_device_trust.py` | 53 | | `test_f3_firmware_parity.py` | 20 |
| `test_step_up.py` | 43 | | `test_bank_boundary.py` | 17 |
| `test_virtual_device.py` | 30 | | `test_state_machine.py` | 15 |
| `test_f1_canonicalization.py` | 30 | | `test_end_to_end.py` | 13 |
| `test_phase2_fixes.py` | 29 | | `test_crypto.py` | 9 |
| `test_policy_engine.py` | 27 | | `test_ml_model.py` | 8 |
| `test_f2_concurrency.py` | 21 | | `test_revocation.py` | 5 |
| `test_adapters.py` | 21 | | `test_replay.py` | 5 |
| | | | `test_expiry.py` | 5 |

Growth, each checkpoint preserving every prior test: 152 (Step 8) → 181 (Phase 2) →
234 (Phase 3.1-3.3) → 264 (F1) → 285 (F2) → 304 (F3) → 308 (2026-09-09:
`deciding_rule`, risk-band boundary) → 338 (step-up, 2026-09-11) → 351 (step-up
restart cleanup, 2026-09-16). One step-up test was strengthened on 2026-09-16, never
weakened; see `docs/STEP-UP-EXPIRY-FIX.md` §8.

**Firmware build:** compiles clean with `arduino-cli`, ESP32 core 3.3.11, ArduinoJson
7.2.0, libsodium (bundled in the core). **1168316 bytes = 89% of program storage**;
global variables 51248 bytes = 15% of dynamic memory.

## Git state

**Corrected 2026-09-01.** The previous text here claimed "Everything after Step 7 is
UNCOMMITTED" and that the last commit was `49f4461`. That was already wrong when written:
Step 8, Phase 2, Phase 3.1-3.3, F1, F2 and F3 were all committed as `e22a690` on
2026-08-28. This file's own staleness warning applied to itself. **Five commits:**

```
e22a690  feat: complete ATLAS Phase 3 device integration   (2026-08-28)
49f4461  Step 7: payment-rail adapters -- one signed decision, two rail shapes
451a9b8  Step 6: real end-to-end HTTP flow, signed assertions, live reconciliation
94ab742  Step 5: Ed25519 signing, bank-side verification, replay, revocation
bf53c8f  Initial checkpoint: frozen ATLAS research architecture + Steps 0-4
```

Uncommitted as of 2026-09-16: 11 modified tracked files and 10 untracked entries (21 in
`git status`). They cover:
- the NTP clock fix and the display layer
- the secrets split and the tunnel-free gateway
- `deciding_rule`, `run_sim.py` and `RUNBOOK.md`
- step-up, with its restart cleanup

The **public GitHub repo** (https://github.com/Dhanu2626/atlas) holds only `e22a690`'s
content plus a docs commit, **with rewritten history, so its commit IDs differ**. Never
push local `master` there.

**The sketch is safe to commit** — its identity and endpoint constants were reverted
to the committed placeholders on 2026-09-09 and the live seed never reached git
history. See "Security teardown" below. Dhanush reviews before each commit.
**Verify with `git status`, not this line.**

## The F3 limitations — the permanent improvement record

These are tracked, classified, and **must not be "fixed" reflexively.** Classification
follows `docs/IMPROVEMENT-DIRECTIVE.md` §19; under §19 only A/B/C normally warrant
immediate engineering work.

**Was six, now eight, and the shape has changed.** Limitation 1 is closed. Running the
firmware for the first time produced two new entries, **7 and 8, and unlike the original
six they ARE class A/B** — real correctness defects, not documented trade-offs. They are
the first entries in this table that genuinely warrant engineering work under §19.

| # | Limitation | Class | Standing decision |
|---|---|---|---|
| 1 | ~~**Wokwi round-trip not proven.**~~ **FULLY CLOSED 2026-09-02.** The firmware has executed in Wokwi and completed the full round trip: on-device libsodium signature verified by the backend, NVS counter advancing 1→2→3, and **all three decision branches observed at runtime — ALLOW, STEP_UP and DENY.** See "The Wokwi round-trip" below. NTP formatting is verified *and* was found defective — see new limitations 7 and 8 | **E** verification gap → **resolved** | Runtime parity may now be claimed for the signature path, the counter, and all three decision outcomes. It may still **never** be claimed for any hardware security property |
| 2 | **Private key seed in plaintext flash.** `DEVICE_KEY_SEED_HEX` is a compile-time constant, readable with `esptool`. A valid signature proves possession of the enrolled key, **not** that the physical ESP32 is genuine | **G** hardware | Document. A secure element (ATECC608-class) is an architecture change — §2 approval required first |
| 3 | **`firmware-config` exports the private-key seed.** Inherent to a software-key provisioning model: without a secure element the firmware has no way to hold a key except as bytes | **I** intentional | Do not remove in isolation. Understand the whole key lifecycle first (§8) |
| 4 | **Wokwi NVS persistence not guaranteed.** A restarted simulation may resume its counter from 0 and be rejected | **H** environment | Already handled correctly: `COUNTER_REGRESSION` → reject. `ATLAS_SIMULATION_ALLOW_COUNTER_RESET` exists, defaults **off**, is audited, and cannot bypass the nonce or `transaction_id` layers. **Never weaken replay protection for the simulator.** **Enabled 2026-09-09** with Dhanush's explicit approval, and isolated: `scripts/run_sim.py` is the only thing that sets it, and it passes the variable to its child processes only. `scripts/run_dev.py` is unchanged and sets nothing, so production-like runs cannot inherit it — verified by comparing both environments. Replay protection degrades from three independent layers to two (nonce + `transaction_id`), never to zero; same-boot replay is still rejected; every acceptance is audited. Proven by a nine-case replay matrix run against a live service — see `RUNBOOK.md` §5. Never set this outside the simulator |
| 5 | **89% flash utilisation.** libsodium added ~120KB; ~142KB headroom remains | **D** resource | Constraint, not defect. Measure flash/RAM before adding any firmware dependency. Do not remove security components to reclaim space |
| 6 | **Legacy `POST /transact` remains open by default.** It performs no device authentication; `ATLAS_REQUIRE_DEVICE_AUTH=1` closes it | **J** deferred | Phase 3.8. **Do not close prematurely** — verify clients, tests, and migration first |
| **7** | ~~**`configTime()` never waits for NTP.**~~ **FIXED 2026-09-02.** `setup()` now blocks on `waitForClock(30000)` before printing ready, and `loop()` re-checks `clockIsSet()` before every SEND. Original defect: a press before SNTP resolved sent `"issued_at":"1970-01-01T00:00:02+00:00"` (backend rejected it as `STALE_REQUEST`) | **A** correctness → **resolved** | Fixed, not worked around. The 25s delay in the `three-presets` scenario file (written for those runs, not committed here) is no longer load-bearing but was kept as belt-and-braces |
| **8** | ~~**Same root cause, worse symptom: a hard crash.**~~ **FIXED 2026-09-02** by the same change. Original: a DNS lookup issued while SNTP's was pending re-entered `sntp_dns_found` → `sntp_retry` → `sys_untimeout` → `__assert_func` → abort → reboot. The `loop()` guard returns **before any DNS or HTTP call**, so no request can be issued while SNTP is resolving | **A/C** correctness → **resolved** | The claim "fixing 7 also closes 8" was **verified by experiment, not assumed** — see the failure-path test below |

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
  them; the persisted *state* still does not. **With `ATLAS_ENABLE_STEP_UP` off (the
  default) that is still the whole story.** With it on, a STEP_UP on `/v2/transact`
  pauses in `AWAITING_STEP_UP` and can be confirmed out of band; see "Step-up
  authentication" below. DELAY is unchanged.
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
- ~~**NOT proven:** that the *compiled firmware* produces those bytes at runtime.~~
  **Superseded 2026-09-01 — now proven.** See the next section.
- **NOT proven, and must never be claimed:** any hardware security property. A valid
  signature proves possession of the enrolled key, not the genuineness of the device.

## The Wokwi round-trip (2026-08-30 / 2026-09-01) — Limitation 1 closed

The firmware has executed. This section is the evidence, and the honest limits of it.

### PROVEN, from real executing firmware

- **On-device Ed25519 signatures verify against the backend.** libsodium
  `crypto_sign_detached` on the simulated ESP32, over the hand-built canonical JSON,
  verified by Python's `cryptography` in `atlas_service/device/envelope.py`. Logged as
  `event=device_authenticated`. This was the single biggest unknown in Limitation 1.
- **The full decision path.** ML scored (`band=MEDIUM` / `HIGH`), the policy engine
  matched rules, the rail adapter tagged UPI, and the device rendered `final_status`.
- **NVS counter.** Advanced 1→2→3 across three presets in one boot, each accepted.
- **Replay protection, observed working for real.** Earlier runs on `fw-01`/`fw-02`
  produced `COUNTER_REGRESSION` after a simulator restart reset NVS to 0 — Limitation 4
  behaving exactly as designed, on real firmware rather than in a unit test.
- **Fail-closed.** `STALE_REQUEST` and `COUNTER_REGRESSION` both produced red with no
  decision emitted.
- **Compile reproducibility.** 1,168,544 B = 89% flash, globals 51,248 B = 15%. Matches
  this file's earlier numbers (the +228 B is two added `Serial` logging lines).

### The 2026-09-01 clean run — all three presets, one command

```
transaction_id                      preset   amount   auth  final_status  rules
esp32-atlas-fw-03-67759e23-0001       0     1500.00    OK   STEP_UP       odd_hours
esp32-atlas-fw-03-67759e23-0002       1    60000.00    OK   STEP_UP       large_amount|new_beneficiary_meaningful_amount|high_ml_risk|odd_hours
esp32-atlas-fw-03-67759e23-0003       2   150000.00    OK   DENY          hard_cap|large_amount|new_beneficiary_meaningful_amount|high_ml_risk|odd_hours
```

**DENY is proven from real firmware.** `hard_cap` fired and most-restrictive-wins
overrode the STEP_UP rules, exactly as `engine.py`'s conflict resolution specifies.

### The 2026-09-02 daylight run — ALLOW observed, all three branches closed

Re-ran at 10:38 IST on `esp32-atlas-fw-04` (fresh device, clean counter). Identical
firmware, identical amounts, identical policy. **Only the hour changed:**

```
transaction_id                      preset   amount   auth  final_status  rules
esp32-atlas-fw-04-8e59e28d-0001       0     1500.00    OK   ALLOW         POLICY_ALLOW
esp32-atlas-fw-04-8e59e28d-0002       1    60000.00    OK   STEP_UP       large_amount|new_beneficiary_meaningful_amount|high_ml_risk
esp32-atlas-fw-04-8e59e28d-0003       2   150000.00    OK   DENY          hard_cap|large_amount|new_beneficiary_meaningful_amount|high_ml_risk
```

`odd_hours` is absent from every row, where it appeared in all three rows of the
2026-09-01 night run. Preset 0 went amber → green with no code change. That is the
`odd_hours` diagnosis confirmed by controlled experiment, not by argument.

**All three decision branches — ALLOW, STEP_UP, DENY — are now observed at runtime
from executing firmware.** The green path is no longer an expectation.

### NOT proven, and must not be claimed

- **Any hardware security property.** Unchanged and unchangeable here. A valid
  signature proves possession of the enrolled key, never the genuineness of the device.
- **Multi-process safety** of the backend (unchanged from F2 — untested and unclaimed).

### A documentation gap this exposed

`firmware/README.md`'s demo table ("preset 0 → ALLOW → green") carries an **unstated
assumption: run it during normal hours.** At 01:00 or 23:00 IST preset 0 correctly
returns STEP_UP and the table looks wrong. The table should state the time dependency.
Presets 1 and 2 are time-independent; only preset 0's verdict moves.

### How to re-run it (no browser, no build queue, no human)

The web IDE path is no longer needed and Wokwi's free build servers timed out four
times on 2026-09-01. The reproducible path is local compile + headless `wokwi-cli`:

```
arduino-cli compile --fqbn esp32:esp32:esp32doit-devkit-v1 --output-dir build .
WOKWI_CLI_TOKEN=$(cat ~/.wokwi/ci-token.txt) wokwi-cli \
    --timeout 300000 --scenario three-presets.scenario.yaml \
    --serial-log-file serial.log .
```

Requires: ESP32 core 3.3.11 + `ArduinoJson@7.2.0` installed locally (both now are), a
Wokwi CI token from wokwi.com/dashboard/ci (**not** the VS Code extension's
`~/.wokwi/user.tok`, which `wokwi-cli` does not read), a public tunnel to
`atlas_service`, and a device enrolled with a clean counter. **The three
`*.scenario.yaml` files these runs used — `three-presets`,
`crash-repro-no-delay` and `clock-failure` — were written ad hoc for them and
are not committed to this repository.** The commands above record how the runs
were driven; they are not a ready-to-run recipe.

**Why not the browser:** Wokwi's simulator is `requestAnimationFrame`-driven, and a
hidden or backgrounded tab drops to ~0% speed — Chrome suspends the renderer entirely.
Every earlier attempt to drive it from an automated browser stalled on this.
`wokwi-cli` has no such dependency.

### Supporting tooling added

- `scripts/verify_device_run.py` — joins the serial and backend records into the three
  values worth checking per press: `selected_preset`, `amount`, `final_status`. Note
  **`selected_preset` is never transmitted**; the backend only ever sees amount and
  beneficiary, so the preset is reconstructed from the amount.
- `[ENVELOPE]` serial logging in `atlas_device.ino` — prints the exact signed bytes
  before submission, so amount/beneficiary/subject/location/timestamp are readable from
  the serial monitor. Logging only; `canonical` is already built and signed by that
  point, so echoing it cannot alter the signed bytes.

## The NTP clock fix (2026-09-02) — limitations 7 and 8

**The change.** Three additions to `atlas_device.ino`. `CANONICAL_FMT` untouched, so
signed bytes are unchanged and `test_f3_firmware_parity.py` still holds.

- `MIN_VALID_EPOCH` (2026-01-01Z) + `clockIsSet()` — an ESP32 boots at epoch 0, so
  anything below this means NTP has not run. A sanity floor, **not** a trust anchor;
  device time is still never trusted (see `nowIso8601`'s comment).
- `waitForClock(30000)` in `setup()` — bounded wait after `configTime()`. On timeout it
  does **not** halt forever the way a missing identity does: a clock can recover, a
  missing key cannot. It degrades to refusing transactions.
- A guard in `loop()` before SEND — refuses with `CLOCK_NOT_SET`, placed **before
  `readEvent()`** (so a refused press burns no counter value) and **before any DNS or
  HTTP call** (which is what actually removes the crash).

**Why two guards and not one.** The `setup()` wait fixes the common case. The `loop()`
guard is what closes limitation 8, because it is the thing that guarantees no network
call is ever issued while SNTP is still resolving — including if the clock is lost
later, which the `setup()` wait alone would not catch.

### Evidence — both defects verified fixed by execution

**Test 1, crash reproduction.** A scenario file written for that run
(`crash-repro-no-delay.scenario.yaml`, not committed here) pressed SEND 400ms
after ready — the exact timing that previously crashed 100% of the time.

```
[DEVICE] waiting for NTP................ clock set
[ENVELOPE] ... "issued_at":"2026-09-02T05:37:01+00:00" ...
[POLICY] txn=esp32-atlas-fw-05-e7f919c5-0001 final_status=ALLOW ... state=APPROVED
```

`assert failed`: 0 · `Rebooting`: 0 · `Backtrace`: 0 · `1970-01-01`: 0.

**Test 2, failure path — the important one.** A second scenario file
(`clock-failure.scenario.yaml`, also not committed here) ran against
a build whose NTP host is `nonexistent.invalid`, pinning SNTP in a permanent DNS retry
loop. **That is precisely the state that caused the crash.**

```
[DEVICE] waiting for NTP.......................(30s timeout)
[SECURITY] clock NOT set -> device will refuse to transact
[SECURITY] final_status=FAIL_CLOSED decision_reason=CLOCK_NOT_SET
```

`assert failed`: 0 · `Rebooting`: 0 · and **zero backend log entries** from that press,
confirming the guard returned before any network call rather than merely surviving one.

**Regression.** Full suite `304 passed` (106s) — same count as before, no test weakened
or skipped. Firmware compiles: 1,168,848 B = 89% flash (+304 B), globals 51,248 B =
15% (unchanged).

### Still true after the fix

- Device time is **still not trusted**. `MIN_VALID_EPOCH` only detects an unset clock;
  it cannot detect a *wrong* one. `MAX_CLOCK_SKEW` on the backend remains the real
  defence, and `TIME_WINDOW` rules still depend on a clock the device asserts.
- `CLOCK_NOT_SET` is a **device-local** serial reason, like `UNCONFIGURED_PRESET` and
  `ATLAS_UNREACHABLE`. It is not a backend `DecisionReason` and is never transmitted.

## Exactly where we stopped

**2026-09-16.** Step-up authentication (built 2026-09-11, `ATLAS_ENABLE_STEP_UP` off
by default) had a real defect: a payment nobody confirmed stayed in
`AWAITING_STEP_UP` forever. The fix was approved and implemented. The suite is **351
passed**, and 10 of 10 mutations are caught; see "Step-up authentication" below. The
project is published at github.com/Dhanu2626/atlas with rewritten history: the 28 Aug
snapshot, a docs commit, and this release. The working repository it is built from is
separate and still has nothing committed since `e22a690` — releases are made by
copying files into a fresh clone, never by pushing that repository.

**2026-09-09.** The Wokwi round-trip ran and Limitation 1 is closed. All three
presets executed on real firmware and **all three decision branches are now observed**
— ALLOW was captured in the 2026-09-02 daylight run. Limitations 7 and 8 (the NTP
race) were found by running and are **both fixed and verified by execution**; see "The
NTP clock fix" below. A presentation layer was added to the firmware on 2026-09-04
(decision trace, security rejection, infrastructure failure and device refusal formats).

### Security teardown — completed 2026-09-09

The working tree is dirty but is now **safe to commit**. State verified, not assumed:

- `firmware/atlas_device/atlas_device.ino` — identity and endpoint constants reverted
  to the committed placeholders (`DEVICE_KEY_SEED_HEX` = 64 zeros, `DEVICE_KEY_ID` =
  `dev-replace-me`, `DEVICE_ID` = `esp32-atlas-demo-01`, `ATLAS_URL` =
  `http://replace-me.example.com`). Byte-identical to HEAD for every config constant;
  the diff now contains only the clock fix and the display layer.
- **The live seed never entered git history.** HEAD (`e22a690`) always carried the
  zero placeholder. No history rewrite was needed or performed.
- `firmware/atlas_device/build/` deleted — the compiled `.bin`/`.elf`/`.merged.bin`
  had the seed baked in. Gitignored, so never committable, but removed anyway.
  **Recompile before the next Wokwi run.**
- All eight `fwconfig*.out` provisioning files (plaintext seeds for fw-01..fw-08)
  deleted from the session scratchpad.
- **Registry: 12 devices, 0 ACTIVE.** Every device is REVOKED, which is terminal and
  cannot be reactivated. A new run needs a freshly provisioned device.
- Only *hex-encoded* key material left on disk is `shared_keys/atlas_public_key.txt`,
  which is a **public** key by design. **This bullet was originally wrong** — it
  claimed no private key material remained. Raw-binary device keys were missed by the
  hex scan; see "Correction to the 2026-09-09 teardown claim" below.
- Services and tunnel are down; nothing is listening on :8000/:8100.

Verified after teardown, by execution rather than inspection:

- **304 tests pass** (99.6s) — unchanged from baseline.
- The signed canonical template is **byte-identical** before and after the edit; the
  revert script asserts this and refuses to write otherwise.
- The reverted sketch **still compiles**: 1,175,776 bytes (89%), exit 0. Sixteen bytes
  smaller than the fw-09 build, which is just the shorter placeholder string literals.
- `arduino-cli` writes to its own cache unless given `--build-path`, so that cache was
  swept too: 198 files, **zero** non-zero 64-hex. The old `firmware/atlas_device/build/`
  tree existed only because an earlier session passed an explicit build path.

## The tunnel removal and secrets split (2026-09-09)

Three changes landed together. None of them touches ATLAS security logic, the
signed canonical template, policy evaluation, replay semantics, or the API
contract. All three are simulator/hygiene changes.

### 1. The seed no longer lives in a tracked file

`DEVICE_KEY_SEED_HEX`, `DEVICE_KEY_ID` and `DEVICE_ID` moved out of
`atlas_device.ino` into **`firmware/atlas_device/secrets.h`**, which is
gitignored. `secrets.example.h` is tracked and holds the zero placeholder.

WHY: the sketch is tracked, so every provisioning run put a live private key
one `git commit -a` away from history, and the only defence was remembering to
revert first. That is a hazard that recurs forever. The include removes it.

This does **not** make the device trustworthy — the seed is still plaintext in
flash and readable with esptool. It is hygiene, not a trust anchor.

Note `build/` also contains the seed (it is compiled in) and is gitignored for
the same reason. Treat the built image as secret.

### 2. `host.wokwi.internal` replaces the tunnel

`ATLAS_URL` is now `http://host.wokwi.internal:8000`, and `wokwi.toml`
declares `[net] gateway = "ws://localhost:9011"`.

Proven from wokwigw's own source (`cmd/wokwigw/config.go`), not inferred:

```go
defaultHostAddr   = "10.13.37.254"
defaultListenAddr = "127.0.0.1"
DNS zone "wokwi.internal." -> record "host" -> 10.13.37.254
NAT: { "10.13.37.254": "127.0.0.1" }
```

So the simulated device reaches an `atlas_service` bound to **loopback**.
`scripts/run_dev.py` is unchanged — still `127.0.0.1`, never `0.0.0.0`, never
a LAN address. Nothing is exposed to the internet, which is strictly better
than the tunnel: a tunnel had no authentication of any kind.

It also removes every moving part that used to break: no URL to regenerate,
no subdomain to lose, no provider rate-limit, no expiry, and no dependence on
the current Wi-Fi network or DHCP lease.

**CONSTRAINT 1 — `wokwi-cli` cannot use this.** Verified by running it on
2026-09-09: it prints `Connected to Wokwi Simulation API` and simulates on
Wokwi's servers, where `ws://localhost:9011` would mean *their* localhost. The
run produced no serial output, the gateway logged no connection, and
`atlas_service` recorded **0** `/v2/transact` hits. The tunnel-free path is
**VS Code extension only**; `wokwi-cli` still needs the tunnel route.
This inverts the previous recommendation in `firmware/README.md`.

**CONSTRAINT 2 — the local gateway depends on your Wokwi plan.** Wokwi
documents the private/local gateway as a paid feature, and the free tier's
shared cloud gateway cannot reach this machine. **Verified working on
2026-09-11** from the VS Code GUI, on an account the simulator labels
*Community License*. What the plan tiers formally include is Wokwi's to
define; what this project established is that the path works here.

### 3. A fresh device

`esp32-atlas-fw-10` / `dev-43be9e1b9cb9303f`, subject `user-demo-1`, keys in
`firmware/device_keys_fw10/`. Enrolled because all 12 previous devices are
REVOKED and revocation is terminal.

**On the identifiers in this file.** Device ids, device key ids (`dev-...`) and
transaction ids are **public identifiers, not credentials**, and are kept here
as evidence. A device key id is a random label generated at provisioning
(`firmware/device_identity.py`: `dev-{secrets.token_hex(8)}`); it is not derived
from any key and reveals nothing about one. The secret is the 32-byte raw
private seed, which exists only in gitignored `device_keys*/` directories and in
`secrets.h`, and appears in no published file. Holding an identifier grants
nothing: `/v2/transact` verifies the signature before it trusts any field.

### Correction to the 2026-09-09 teardown claim

The teardown section above said "zero private key material on disk". **That
was wrong.** Device private keys are stored as **32 raw binary bytes**
(`device_ed25519.key`), not hex, so a hex-pattern scan structurally could not
see them. There are **11** such keys in `firmware/device_keys*/`.

Mitigating, and verified: every one belongs to a **REVOKED** device, they are
gitignored via `device_keys*/`, and `git log --all --name-only` confirms they
were **never committed**. Practical risk is low. They have not been deleted —
that decision is Dhanush's.

### Verified after these changes

- **304 tests pass** (103.25s), unchanged.
- Sketch compiles: **1,175,792 bytes (89%)**, exit 0, and `build/` now holds
  the `.bin` and `.elf` that `wokwi.toml` points at.
- Signed canonical template **byte-identical** — asserted before and after
  every edit; the edit scripts refuse to write otherwise.
- The live seed appears in **no tracked file**; `git status` does not list
  `secrets.h` or `build/`.
- Services and gateway all bind **loopback only**: `127.0.0.1:8000`,
  `127.0.0.1:8100`, `127.0.0.1:9011`.

## Obsolete device keys destroyed (2026-09-09)

Twelve `firmware/device_keys*/` directories were deleted, each holding a
32-byte raw Ed25519 **private** key. Recorded here before deletion, per the
rule that destructive changes are explained rather than discovered later.

| directory | device | status when deleted |
|---|---|---|
| `device_keys` | `esp32-atlas-demo-01` | REVOKED |
| `device_keys_dev3` | `esp32-atlas-demo-03` | REVOKED |
| `device_keys_fw01` | `esp32-atlas-fw-01` | REVOKED |
| `device_keys_fw02` | `esp32-atlas-fw-02` | REVOKED |
| `device_keys_fw03` | `esp32-atlas-fw-03` | REVOKED |
| `device_keys_fw04` | `esp32-atlas-fw-04` | REVOKED |
| `device_keys_fw05` | `esp32-atlas-fw-05` | REVOKED |
| `device_keys_fw06` | `esp32-atlas-fw-06` | REVOKED |
| `device_keys_fw07` | `esp32-atlas-fw-07` | REVOKED |
| `device_keys_fw08` | `esp32-atlas-fw-08` | REVOKED |
| `device_keys_fw09` | `esp32-atlas-fw-09` | REVOKED |
| `device_keys_simtest` | `esp32-atlas-simtest` | REVOKED |

**`firmware/device_keys_fw10/` was KEPT** — it is the only ACTIVE device and
the one the current build signs with.

Every precondition was checked and passed before deleting: all twelve devices
REVOKED (terminal), none is `esp32-atlas-fw-10`, none is referenced from any
tracked source file, none appears anywhere in `git log --all` (they were
gitignored via `device_keys*/` and never committed), and no test depends on
them — the suite constructs its own keys under `tmp_path`.

`esp32-atlas-simtest` was enrolled on 2026-09-09 purely to run the replay
matrix without advancing `fw-10`'s counter, then revoked immediately. It never
had a purpose beyond that test.

Note `firmware/device_keys/` was `device_identity.DEFAULT_DEVICE_KEYS_DIR`.
Deleting it is safe: the next `provision_device.py enroll` without an explicit
`--keys-dir` simply generates a fresh identity there.

## Where to start running it

**`RUNBOOK.md`** is the operational document: start, run, stop, provision, test.
Read it before touching anything. This file explains *why*; that one explains
*how*.

One command starts everything: `python scripts/run_sim.py`.

## Simulation isolation (2026-09-09)

`scripts/run_sim.py` is new and is the ONLY thing in the repository that turns
on `ATLAS_SIMULATION_ALLOW_COUNTER_RESET`. It passes the variable to its child
processes only -- never to a file, never to the shell.

`scripts/run_dev.py` is **unchanged** and sets neither simulation variable, so a
production-like run cannot inherit the accommodation by forgetting a flag. This
was verified rather than assumed:

```
clean env      -> counter_reset: False | require_auth: False
run_sim child  -> counter_reset: True  | require_auth: True
```

The nine-case replay matrix that proves the accommodation does not weaken
anything is recorded in `RUNBOOK.md` section 5, with the exact reason codes.

## Two contract/test changes (2026-09-09)

### `deciding_rule` on `PolicyDecision` -- additive

`engine.py` used to compute `max()` over the matched rules' ACTIONS, which threw
away which rule supplied the winning one. `matched_rules` lists everything that
fired in policy-file order, so a DENY could have come from `hard_cap` or
`velocity_burst` and a reader could not tell.

Now `max()` runs over the RULES instead -- same severity table, same comparison,
identical Decision -- and the winner's name is kept in a new
`deciding_rule: str | None = None` field. Ties resolve to the rule listed first
in the policy file, because `max()` returns the first maximal element.

Why this is safe, verified before making the change:

- **Not in the signed surface.** `AssertionPayload` is a separate model with an
  explicitly frozen field list; it carries `decision`, `policy_version` and
  `policy_hash` only. The bank still never sees rule names (ARCHITECTURE
  principle 5). Signed bytes are untouched.
- **Additive and defaulted**, so the four tests that construct `PolicyDecision`
  directly still work.
- **No test does exact-shape comparison** on the decision object -- every
  assertion is a field lookup like `body["decision"]["decision"]`.

Firmware reads `decision.deciding_rule` when present and falls back to the old
honest "NOT REPORTED BY BACKEND" when it is absent, so an older `atlas_service`
still works. Three new tests in `test_policy_engine.py` pin the behaviour,
including that `deciding_rule` never disagrees with the decision it explains.

### `risk_band` -- the guard test now checks the boundary, not the vocabulary

`test_firmware_never_contains_decision_logic` banned the literal `risk_band`
anywhere in firmware source. That was a proxy for Blueprint 24.2, and a poor one
in both directions: it blocked the trace from displaying a value
`atlas_service` **already sends to the device** (`main.py` returns
`{"risk": risk.model_dump(), ...}`), while still passing a firmware that
computed its own band under a different name.

The literal is no longer banned. A new test,
`test_firmware_may_display_risk_band_but_never_branches_on_it`, enforces the
real rule: the token may appear only as a JSON key being read, never on a line
containing `strcmp`, `==`, `!=`, `if`, `switch` or `while`.

**The architectural rule is unchanged and unweakened** -- firmware may render a
backend verdict and may not derive one. `interpretStatus()` still maps ONLY
`final_status` to an LED. The new guard was mutation-tested: injecting
`if (strcmp(risk["risk_band"], "HIGH") == 0)` into the sketch makes it fail, and
removing it makes it pass.

## Step-up authentication (2026-09-11) and its restart cleanup (2026-09-16)

**Not part of the original build plan.** Approved by Dhanush on 2026-09-11. Design record:
`docs/STEP-UP-PROPOSAL.md`. Operations: `RUNBOOK.md` §9.

**What it is.** With `ATLAS_ENABLE_STEP_UP=1` (default **off**), a STEP_UP on the signed
`/v2/transact` path no longer dies in `DENIED`. It pauses in `AWAITING_STEP_UP` while
the customer proves themselves out of band, with an Ed25519 signature from an enrolled
authenticator over `ATLAS-STEPUP-PROOF-v1|challenge_id|transaction_id|envelope_hash`.
ATLAS never sees a PIN, OTP or biometric.

Bounded re-resolution (`atlas_service/step_up/resolver.py`) is a pure function of the
frozen decision context plus the authentication result. It re-runs no ML and no policy,
and reads no clock. A successful step-up can never turn a DENY into an ALLOW
(STEP-UP-INVARIANT-1). Limits: 120 s expiry, 3 attempts, one challenge per transaction,
single-use.

**Evidence, by class:**
- **TESTED:** `tests/test_step_up.py`, 43 tests. These include an exhaustive resolver
  sweep, a structural "no recompute" guard, a DENY-guard mutation test and HTTP round
  trips.
- **OBSERVED:** a live-service run with the virtual device passed 15/15 checks
  (2026-09-11), and a Wokwi run on real firmware proved 7 of 10 checks (2026-09-11).
- **UNPROVEN:** authentication success → ALLOW → CONFIRMED on a challenge issued to the
  real firmware. Do not claim step-up is end-to-end verified on the device.

### The restart-cleanup defect, fixed 2026-09-16

**What was wrong.** A payment nobody confirmed stayed in `AWAITING_STEP_UP` forever.
- The cleanup, `expire_stale()`, was never called.
- As written, it closed the challenge without moving the transaction, which would have
  made the stuck state permanent.
- A crash between `consume()` and `transition()` after a good proof stranded payments
  the same way.

There was no security impact: a stuck payment could never be approved. The defect was
reproduced on temporary databases. The report, evidence and decisions are in
`docs/STEP-UP-EXPIRY-FIX.md`.

**The fix, as approved:**
- `expire_stale(step_up_store, txn_store, now)` now starts from transactions in
  `NEEDS_STEP_UP_EXPIRY`. An expired challenge, a consumed-but-unadvanced one, or a
  missing one leads to `DENIED`. A live challenge is left alone, and no branch approves.
- `main.resolve_stale_step_ups()` runs it once at startup, before requests, regardless
  of the flag. It creates nothing if step-up was never used. If it fails, the error is
  logged and startup continues.
- In the step-up store, `find_unconsumed_expired()` was removed and
  `get_challenge_for_transaction()` was added.
- There is no change to any endpoint, the resolver, ML, policy, firmware or contracts.

**Verified:**
- **351 passed**: 13 new tests, 1 strengthened, none weakened.
- **10/10 mutations caught**, with the files restored byte-for-byte.
- On **copies** of this machine's databases, exactly one of 138 transactions changes:
  `esp32-atlas-fw-10-803e2d6a-0001` (the 11 Sep Wokwi ₹60,000 run) becomes `DENIED`,
  with event `RESOLVED_ON_RESTART reason=EXPIRED`. A second run changes nothing.
- The real databases were not touched. The next real `atlas_service` start will make
  that one change.

**Not yet observed:** the cleanup inside a real `run_sim.py` or uvicorn start. The tests
drive the same ASGI lifespan through Starlette's `TestClient`.

### Finding D: open, deliberately not fixed

A `/v2/step-up` request naming a live `challenge_id` with the wrong `transaction_id`
cancels the real pending payment (`BINDING_MISMATCH` → `DENIED`) without a valid proof.
It can deny, never approve. Class **B, low**.

On 2026-09-16 Dhanush chose to document it now and decide later whether a mismatch
should count as one failed attempt instead. See `docs/STEP-UP-EXPIRY-FIX.md` §18.

## Project scope -- what is actually left (audited 2026-09-09)

Verified against the file tree and the code, not against old documentation.

| Item | Status | Classification |
|---|---|---|
| Steps 0-8 | built | **ALREADY COMPLETE** |
| Phase 3.1 registry + admin endpoints | built | **ALREADY COMPLETE** |
| Phase 3.2 envelope, canonical bytes, `/v2/transact` | built | **ALREADY COMPLETE** |
| Phase 3.3 counter + nonce replay layers | built, re-verified by execution | **ALREADY COMPLETE** |
| Step-up authentication (added 2026-09-11, outside the original plan) | built, flag OFF; restart cleanup fixed 2026-09-16; Wokwi ALLOW path unproven; finding D open | **BUILT, PARTLY VERIFIED** |
| **Step 9 dashboard** | absent -- no `dashboard/`, `static/` or `templates/` | **REQUIRED for the original build plan** |
| Phase 3.4 location grading | `LocationEvidence` exists in `contracts.py`; location is carried and SIGNED but graded by nothing | **OPTIONAL/FUTURE** |
| Phase 3.5 integrity grading + rollback | `DeviceHealth` exists; carried and signed, graded by nothing | **OPTIONAL/FUTURE** |
| Phase 3.6 policy vocabulary / ML features | not built | **DEFERRED BY DESIGN** -- the only step that can change financial decisions; `PHASE3-SPEC.md` marks it Highest risk and defers it to Phase 4 |
| Phase 3.7 firmware rollout | device key, envelope and NVS counter all built; **GNSS stub absent** (0 occurrences) | **OPTIONAL/FUTURE** |
| Phase 3.8 close legacy `/transact` | `ATLAS_REQUIRE_DEVICE_AUTH` built, default OFF; `run_sim.py` sets it to 1 | **OPTIONAL/FUTURE** -- the mechanism exists; flipping the default is the remaining act |

`PHASE3-SPEC.md` itself says *"Recommended checkpoint after 3.3"* -- which is
exactly where this project is. Stopping here is the spec's own recommendation,
not a shortfall.

**So the honest answer to "is ATLAS complete?": everything through Phase 3.3
works and is verified by execution. The dashboard is the one genuinely
outstanding item of the original build plan. 3.4-3.8 are specified but were
deliberately not started, and 3.6 must not be started casually.**

`docs/ATLAS-Blueprint.md` remains stale on progress numbers (says "four of ten
build steps", "45 passed in 13.00s", and that `firmware/`, `state_machine.py`,
`crypto.py` and `db.py` do not exist -- all four now do). Its Section 24 is
current. The document states it must be regenerated as steps land; that has not
been done and is tracked here rather than silently fixed.

## Next step (do not start without explicit approval)

**Updated 2026-09-16.** **None should begin without Dhanush saying so**, and
`docs/IMPROVEMENT-DIRECTIVE.md` §20 requires a pre-change report first.

1. ~~**Observe ALLOW.**~~ **DONE 2026-09-02** — see the daylight run above. All three
   decision branches are now observed at runtime. No runtime gap remains in the
   round trip.
2. ~~**Fix limitations 7 and 8**~~ **DONE 2026-09-02** — see "The NTP clock fix" below.
   Both verified by execution, including the failure path.
3. ~~**Fix the step-up expiry defect**~~ **DONE 2026-09-16** — see "Step-up
   authentication" above.
4. **Publish the newer local work to GitHub.** Dhanush chose on 2026-09-16 to do this
   after the step-up fix. The public repo's history was rewritten, so local `master`
   must never be pushed. The procedure is: fresh clone, copy the files across, full
   suite, secret scan, review the diff, then commit and push.
5. **Prove the step-up ALLOW path in Wokwi**, the 3 checks still unproven.
6. **Decide finding D:** should a `BINDING_MISMATCH` count as one failed attempt
   instead of cancelling the payment? (`docs/STEP-UP-EXPIRY-FIX.md` §18)
7. **Step 9: dashboard** — the last unbuilt item of the original build plan. Per
   `BUILD-PLAN.md`: static HTML/JS (matching `refundradar`'s no-Jinja convention),
   showing transactions, ML evidence, policy decision, crypto/replay status, active rail
   adapter, and the measurement numbers from `ARCHITECTURE.md`'s "Measurement dimensions".
8. **Phase 3.4-3.8** — location grading, integrity grading, policy vocabulary, firmware
   rollout, and finally closing legacy `/transact`. Specified in `docs/PHASE3-SPEC.md`.
   Note 3.6 (policy vocabulary) is the only one that can change financial decisions and
   was deliberately deferred to Phase 4.

Follow the standing process: explain the design first, then implement, then test edge
cases deliberately, then show real results, then stop for approval.

## Pending decisions still waiting on Dhanush (carried forward, not resolved)

- **Wokwi cost**: **resolved as of Step 8** — the free/public gateway is sufficient
  (outbound-only is all the device needs); no paid Private Gateway dependency was added.
  **Revisited 2026-09-01:** still no paid dependency, but the *free build servers* are
  now a practical problem — four "Build Servers Busy" timeouts in one session made the
  web IDE unusable. The local-compile + `wokwi-cli` path avoids them entirely and is
  the recommended route. It needs a free CI token from wokwi.com/dashboard/ci.
- **Timeline/scope pressure**: does the original ~11-14 focused day estimate still hold?
  Never explicitly reconfirmed since the build actually started.
- **Module 7/8 status** (`ARCHITECTURE.md`'s known gaps): whether dedicated
  Security/Failures research days ever ran — flagged multiple times, never answered,
  not currently blocking anything.
- **`docs/ATLAS-Blueprint.md` is stale** on progress (still describes Steps 0-3 and 45
  tests). Its Section 24 is current and was implemented; its status numbers are not.
  Worth deciding whether to refresh it or explicitly freeze it as a point-in-time
  document.
