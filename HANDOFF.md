# HANDOFF.md — start here in a fresh context

**Updated 2026-09-25**, the limitation-closure pass: policy rollback is rejected on live
requests, an opt-in production transport profile exists, the ML evaluations no longer
see the future, the "webkit teardown error" was traced to the dashboard export writing
the live bank ledger and fixed, and the test isolation guard now watches the real key
directories. Two approved specification changes followed the same day: an explicit
INSUFFICIENT_HISTORY state for cold start, and a separate `beyond_observed_range` burst
evidence signal. Physical hardware and a public PKI are recorded as scope boundaries,
not defects.
Earlier updates: 2026-09-21 (a documentation sync), 2026-09-18 (the security and correctness pass), 2026-09-16 (the
step-up restart-cleanup fix and the first GitHub publish), 2026-09-02 (the daylight
run observed ALLOW, closing Limitation 1, and the NTP clock fix closed limitations 7
and 8), 2026-09-01 (the Wokwi round trip) and 2026-08-27 (hardening checkpoint F3).
Dated sections further down are kept as the record of their day. This file exists so a
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
   hard-won detail; its Step 9 row is the original plan, written before the first
   version was built on 2026-09-17/18 — this file's status table is current).
   **Does not yet cover Phase 3 or F1-F3** — this
   file and `docs/IMPROVEMENT-DIRECTIVE.md` carry those.
5. `docs/PHASE3-SPEC.md` — the device-trust layer specification (registry, envelope,
   signing, replay, location, integrity). Phases 3.1-3.3 are built. Phase 3.8's
   enforcement is done — the legacy `/transact` is closed by default since 2026-09-18 —
   and its dedicated red-team suite was built on 2026-09-22 (`tests/test_red_team.py`). 3.4-3.6 are not
   built, and 3.7 is built except its GNSS stub.
6. `docs/SECURITY-GAP-REPORT.md` — the Phase 1 audit that started the hardening work.
   Historical: several gaps it names (G4 the HTTP 500, G6 the timezone defect, G7
   DENY-vs-FAIL_CLOSED, G1/G2/G3 device auth) have since been closed.
7. `ledger/SYNTHESIS.md` — cross-references/resolved ambiguities between the research
   and the build. Short, worth the read; now 7 items.
8. `docs/ATLAS-Blueprint.md` — a full engineering-specification writeup, **refreshed to
   this release** (the older copy's "45 tests", "no `firmware/`", "no `crypto.py`"
   claims are gone). Its §24 is the design Step 8 and F3 implemented, its §25 governs
   honest security claims, and its `[A]`-`[G]` provenance labelling is the clearest
   statement of what is grounded vs. proposed.

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

**Build steps 0-8 done. Step 9 (dashboard) is built but not deployed, and it covers
most — not all — of the measurement set `BUILD-PLAN.md` asks for; the Step 9 row says
exactly what is missing. A separate hardening track ran on top: Phase 2, Phase 3.1-3.3
and checkpoints F1, F2, F3 are complete, and Phase 3.8's legacy-path closure is done.**

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
| 9 | Dashboard | 🟡 **Built, not deployed** (2026-09-17/18): `docs/index.html` + `scripts/export_dashboard_data.py`, a dated snapshot. **Shows:** transactions (read-only database figures), ML evidence, the policy decision and the rule that decided it, signing and per-transaction replay status, the active rail, the same decision framed for a second rail, and measured ML precision, recall, false-positive rate and score latency. **Not measured:** policy-evaluation, signing and verification latency separately (only each scenario's whole round trip), reconciliation success rate, and what leaves the trust boundary; rollback rejection is live since 2026-09-25 but not measured by the page -- it was not wired into requests. Security checks appear as the test-suite total, not itemised. **Never hosted:** GitHub Pages has not been tried; the page was checked from the file and over a local static server, in Chromium browsers only |

### Hardening track (after Step 8)

| Checkpoint | What it did | Status |
|---|---|---|
| Phase 1 | Security audit → `docs/SECURITY-GAP-REPORT.md`. No code changed | ✅ Done |
| Phase 2 | Fixed the duplicate-`transaction_id` HTTP 500; fixed TIME_WINDOW timezone; separated DENY vs FAIL_CLOSED with `decision_reason`; structured audit logging | ✅ Done |
| Phase 3.1 | Device registry (`atlas_service/device/`) — enrollment, ACTIVE/SUSPENDED/REVOKED, audit trail | ✅ Done |
| Phase 3.2 | Device identity (`firmware/device_identity.py`) — per-device Ed25519 key, separate from the ATLAS key | ✅ Done |
| Phase 3.3 | Device authentication — `DeviceEnvelope`, signature-first verification, counter + nonce replay layers, `POST /v2/transact` | ✅ Done |
| Phase 3.4-3.7 | Location grading, integrity grading, policy vocabulary, firmware rollout | ❌ **Deferred** — see `docs/PHASE3-SPEC.md` |
| Phase 3.8 | Closing the legacy unsigned `/transact`; red-team suite | ✅ **Done** — closed 2026-09-18, and since 2026-09-22 no environment setting reopens it in a running service. The spec's dedicated red-team suite (its 25 listed attacks, each with an expected outcome) was **built 2026-09-22**: `tests/test_red_team.py` drives every one through the real signed endpoint and a real `bank_service`, and a catalogue test fails if an attack goes missing |
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

## Current test status (re-verified 2026-09-25: `689 passed, 2 skipped`)

```
689 passed, 2 skipped
```

691 tests are collected from 37 files, in about 5 to 11 minutes. Two skips, each naming its
reason: the opt-in firmware build (`ATLAS_FIRMWARE_BUILD=1`), which is opt-in because it
takes minutes and needs `arduino-cli` -- **run separately on 2026-09-23 and passed**, the
whole file 12/12, producing 1,176,472 bytes, 89% of program storage, the same figure as
2026-09-18; and Playwright's Firefox, which will not start here (`spawn UNKNOWN`), so
that engine is recorded as untested rather than passing. (The Application Control block
on `arduino-cli` seen on 2026-09-21 was gone by 2026-09-23.)

| File | Tests | | File | Tests |
|---|---|---|---|---|
| `test_phase3_device_trust.py` | 61 | | `test_f3_firmware_parity.py` | 20 |
| `test_step_up.py` | 58 | | `test_keystore.py` | 20 |
| `test_transport_security.py` | 36 | | `test_bank_boundary.py` | 18 |
| `test_export_dashboard_data.py` | 31 | | `test_bank_adapter.py` | 16 |
| `test_virtual_device.py` | 30 | | `test_state_machine.py` | 15 |
| `test_f1_canonicalization.py` | 30 | | `test_end_to_end.py` | 13 |
| `test_phase2_fixes.py` | 29 | | `test_tls.py` | 12 |
| `test_red_team.py` | 27 | | `test_firmware_behaviour.py` | 12 |
| `test_live_history.py` | 17 | | `test_range_signal.py` | 20 |
| | | | `test_tls_production.py` | 16 |
| | | | `test_insufficient_history.py` | 16 |
| `test_policy_engine.py` | 27 | | `test_policy_rollback.py` | 14 |
| `test_ml_model.py` | 22 | | `test_model_registry.py` | 11 |
| `test_f2_concurrency.py` | 21 | | `test_crypto.py` | 9 |
| `test_adapters.py` | 21 | | `test_dashboard_browsers.py` | 7 |
| | | | `test_ml_evaluation.py` | 6 |
| | | | `test_revocation.py`, `test_replay.py`, `test_expiry.py` | 5 each |
| | | | `test_ml_evaluation_no_lookahead.py` | 4 |
| | | | `test_device_diagrams.py` | 18 |
| | | | `test_policy_signing.py` | 12 |
| | | | `test_isolation_guard.py` | 2 |
| | | | `test_dashboard_page_js.py` | 1 |

`test_dashboard_page_js.py` is one pytest test that runs the page's own **34
JavaScript checks** (`tests/js/dashboard_page_tests.mjs`) through node, and skips
with a reason if node is absent. They cover scenario rendering and selection, the
signing, step-up and replay panels, warnings and failed runs, missing or empty
sections, escaping of hostile text, that the page makes no network request, that
recorded figures are labelled as recorded, the ML caveat, that the limits section
describes this release (including what the production transport profile does and
does not make true), and that the shipped export renders.

Growth, each checkpoint preserving every prior test: 152 (Step 8) → 181 (Phase 2) →
234 (Phase 3.1-3.3) → 264 (F1) → 285 (F2) → 304 (F3) → 308 (2026-09-09:
`deciding_rule`, risk-band boundary) → 338 (step-up, 2026-09-11) → 351 (step-up
restart cleanup, 2026-09-16) → 386 (the dashboard review, 2026-09-17) → 464 (the
security and correctness pass, 2026-09-18) → 564 (the hardening, verification and
release pass, 2026-09-22/23: key protection, the model registry, TLS, the bank
adapter, the red-team suite, held-out ML evaluation and the browser matrix) → 581 (live
payment history, 2026-09-23/24) → 621 (limitation closure, 2026-09-25: live policy
rollback rejection, the production transport profile, the evaluation look-ahead
removed, the isolation-guard and export-ledger fixes, and four more browser targets) → 657
(the two approved ML specification changes, 2026-09-25: INSUFFICIENT_HISTORY and the
`beyond_observed_range` signal) → 661 (the burst signal approved as implemented,
2026-09-26: end-to-end visibility, no-decision and restart tests) → 679 (the device
pictures checked against diagram.json, the firmware and Wokwi's pin order, 2026-09-26) → 691
(signed policy updates, 2026-09-27). One
step-up test was strengthened on
2026-09-16, never weakened (`docs/STEP-UP-EXPIRY-FIX.md` §8); one was replaced on
2026-09-18 because it encoded the retired three-attempt design (D1, below).

**Firmware build:** compiles clean with `arduino-cli`, ESP32 core 3.3.11, ArduinoJson
7.2.0, libsodium (bundled in the core). **1,176,472 bytes = 89% of program storage**,
built on 2026-09-18 from a copy of the sketch with `secrets.example.h` by
`test_the_sketch_compiles`. A build with a provisioned `secrets.h` differs by a few
bytes of string length (1,176,488 B). At F3 it was 1,168,316 B, with global variables
at 51,248 B = 15% of dynamic memory.

## Git state

**Updated 2026-09-21.** A snapshot; verify with `git log` and `git status`, which this
section has disagreed with before (see the staleness warning at the top).

ATLAS lives in two repositories with **different commit histories**:

- **The working repository** (not published):

  ```
  (2026-09-21)  docs: sync status documentation with the repository  <- this file
  596a974       feat: step-up refuses without a valid proof; UTC ML time; legacy path closed; transport policy   (2026-09-18)
  e22a690       feat: complete ATLAS Phase 3 device integration   (2026-08-28)
  49f4461       Step 7: payment-rail adapters -- one signed decision, two rail shapes
  451a9b8       Step 6: real end-to-end HTTP flow, signed assertions, live reconciliation
  94ab742       Step 5: Ed25519 signing, bank-side verification, replay, revocation
  bf53c8f       Initial checkpoint: frozen ATLAS research architecture + Steps 0-4
  ```

- **The public repository**, https://github.com/Dhanu2626/atlas, branch `main`. Its
  history was rewritten before the first push, so **none of its commit ids match**: two
  private research notes were withheld from every commit and `master` became `main`.
  Releases: the 28 Aug snapshot plus a docs commit (2026-09-16), the step-up release
  `48ff889` (2026-09-17), and this release, built from the working repository after
  the 2026-09-21 documentation sync and published only after Dhanush reviews it.

Releases are made by copying the working repository's tracked files, minus the two
private notes, into a fresh clone of the public repository, then running the full suite
and a secret scan there before committing. **Never push the working repository to
GitHub**: the histories share no commits, and forcing it would overwrite the public
history and re-expose the withheld notes.

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
| **6** | ~~**Legacy `POST /transact` remains open by default.**~~ **CLOSED BY DEFAULT 2026-09-18** (D5, Phase 3.8's enforcement): it answers `FAIL_CLOSED` / `DEVICE_AUTH_REQUIRED` and scores nothing. Since 2026-09-22 the `ATLAS_REQUIRE_DEVICE_AUTH=0` escape hatch is gone: no environment variable, flag or configuration file reopens it in a running service, and only an in-process test override reaches the pipeline behind it. Nothing in the release needed it — the firmware has signed to `/v2/transact` since F3, `run_sim.py` already set the flag, and the dashboard export now drives the signed path; the pre-Phase-3 tests that exercise the legacy contract opt in explicitly | **J** deferred → **resolved** | Was: Phase 3.8. **Do not close prematurely** — verify clients, tests, and migration first |
| **7** | ~~**`configTime()` never waits for NTP.**~~ **FIXED 2026-09-02.** `setup()` now blocks on `waitForClock(30000)` before printing ready, and `loop()` re-checks `clockIsSet()` before every SEND. Original defect: a press before SNTP resolved sent `"issued_at":"1970-01-01T00:00:02+00:00"` (backend rejected it as `STALE_REQUEST`) | **A** correctness → **resolved** | Fixed, not worked around. The 25s delay in the `three-presets` scenario file (written for those runs, not committed here) is no longer load-bearing but was kept as belt-and-braces |
| **8** | ~~**Same root cause, worse symptom: a hard crash.**~~ **FIXED 2026-09-02** by the same change. Original: a DNS lookup issued while SNTP's was pending re-entered `sntp_dns_found` → `sntp_retry` → `sys_untimeout` → `__assert_func` → abort → reboot. The `loop()` guard returns **before any DNS or HTTP call**, so no request can be issued while SNTP is resolving | **A/C** correctness → **resolved** | The claim "fixing 7 also closes 8" was **verified by experiment, not assumed** — see the failure-path test below |

## Other known limitations (full list: `docs/ATLAS-Blueprint.md` §19; firmware: `firmware/README.md`)

Status words used below (2026-09-25): **Fixed** = the condition is gone and a regression
test fails if it returns; **Narrowed** = part fixed and tested, the rest named; **Awaiting a
specification decision** = a fix is designed but would change specified behaviour, so it
is not built; **Scope boundary** = outside the frozen software-only scope, or needing
infrastructure outside this project -- documented, not a defect.

- **Scope boundary (frozen, by design): a software-only prototype.** ARCHITECTURE.md:
  "Not something that requires physical hardware to exist". No physical hardware: the
  firmware has run only in the Wokwi simulator. No secure element, TEE, secure boot or attestation. Since 2026-09-22
  ATLAS's server-side keys are encrypted at rest (`keystore.py`: Windows DPAPI, or
  AES-256-GCM under a passphrase-derived key) and decrypted only in process memory, so a
  stolen copy of the repository or of the OneDrive folder no longer hands over a usable
  key — but any process running as the same user can still decrypt them, and the
  **device** seed remains plaintext in ESP32 flash. A valid signature still proves
  possession of a key, not that a device is genuine.
- **No production TLS -- Narrowed 2026-09-25.** The ATLAS → bank hop is mutual TLS from a
  local test CA since 2026-09-22 (certificate and hostname verified, client certificate
  required, no plaintext fallback). Since 2026-09-25 an opt-in **production transport
  profile** (`ATLAS_TRANSPORT_PROFILE=production`, `atlas_service/tls.py`) enforces TLS 1.3
  only on both sides, checks the CA's CRL on every handshake in both directions, pins the
  bank's public key before any request byte is written, refuses plain HTTP everywhere
  (loopback included, the development override ignored) and refuses to start without its
  material. `tests/test_tls_production.py` (16, real servers) proves each against a
  development-profile control: a revoked bank or client certificate, a certificate the CA
  mis-issued to someone else (the bank received nothing), an expired certificate, a
  TLS-1.2-only peer and missing material all fail; 5 deliberate breaks were caught. The
  live `dev-certs/` has no CRL or pin yet, so the production profile refuses to start there
  until `python scripts/make_dev_ca.py --production-material` is run (not done: it writes
  into the live TLS folder). **Remaining, external requirement:** a publicly or
  enterprise-trusted certificate, OCSP run by an institution and a CA key in an HSM.
  **Remaining, not built:** the ESP32 has no TLS client, so the Wokwi device reaches
  `atlas_service` unencrypted through the loopback gateway and runs only in the
  development profile, where plain HTTP stays allowed on loopback only (D6, below).
- **The Wokwi private gateway is the supported path.** A public tunnel is needed only
  for the `wokwi-cli` fallback (`RUNBOOK.md` §7); it provides no authentication and
  exposes the key-holding `atlas_service` while it runs. Demo-only; kill it after demos.
- ~~**Step-up's device-side approve path is unobserved.**~~ **Observed 2026-09-23**, closing
  the last 3 of 10 Wokwi checks: challenge `032221ef4d525fc1e4f72731e8e2e1bb` was issued to
  transaction `esp32-atlas-fw-10-90135b7a-0001` on the real firmware, redeemed with the
  enrolled authenticator (`auth_result=SUCCESS`), resolved STEP_UP -> ALLOW, the assertion
  was signed, the bank approved over mutual TLS and the transaction reached CONFIRMED. The
  run used a disposable state directory; the live databases were byte-identical afterwards.
  Step-up still ships off by default, and this was the simulator, never physical hardware.
- **All data is synthetic**, and there is no real bank, payment rail or PSP. ML
  precision and recall (`scripts/evaluate_ml.py`) are measured against the same
  generator that trained the model: separation on generated data, not fraud detection.
  The held-out evaluation added on 2026-09-22 keeps train, validation and test on
  disjoint seeds with four unseen personas and an independent anomaly generator, which
  makes the number honest — but both sides are still synthetic.
- ~~ML model is refit from scratch on every request.~~ **Fixed 2026-09-22**:
  `scripts/train_models.py` trains and persists, `atlas_service/ml/registry.py` verifies
  an HMAC and loads once per process, and the request path only scores. A missing or
  tampered artifact fails closed before any state is created.
- ~~**Decisions read modelled history, not live payments.**~~ **Fixed 2026-09-23.**
  `TransactionStore` persists the whole transaction (nullable columns, migrated in place,
  existing rows kept), and `history_for()` reads a subject's own payments back: the most
  recent 200, oldest first, excluding the one being decided. The velocity check, the
  new-beneficiary check and every ML history feature now read that. Proven through the
  real signed endpoint: 21 real payments trip `velocity_burst`, a payee becomes known
  because the subject really paid it, and both survive closing and reopening the store.
  Cold start is explicit (see below): a customer with fewer than 200 known payments is
  not judged by the ML layer, and the deterministic rules are untouched.
- ~~**The ML layer does not see bursts.**~~
  **Burst detection: CLOSED as an implementation limitation** (built 2026-09-25 under an
  approved specification change; the behaviour approved as implemented on 2026-09-26),
  without touching the Isolation Forest. Root cause, measured: a
  forest never splits beyond its training range (the highest of 625 splits on the 24-hour
  count sits at the training maximum). Instead a separate `beyond_observed_range` evidence signal (`atlas_service/ml/range_signal.py`) compares the customer's payments in the 24 hours up to this one with the busiest 24 hours in that customer's own earlier history, using only rows dated no later than the payment; it fires above 6x. The multiplier was chosen on the validation split alone, by a rule fixed before it ran (the largest in a fixed grid with validation false-positive rate <= 1% among those with the best validation burst recall); every value from 1.5x to 6x separated the synthetic validation bursts perfectly, so 6x is the most conservative. On the test split it flagged 40 of 40 held-out bursts and 0 of 320 ordinary and hard-negative cases, and never fired on the other anomaly families. That is separation of synthetic bursts, not evidence about real payments. It is evidence only: it does not change risk_band, no policy rule reads it, and no payment decision changed. It runs only where the ML layer operates (200+ known payments), so in the current demo -- where no customer has 200 payments -- it never fires on a live request; `velocity_burst` is still what refuses a live burst. The Isolation Forest itself is untouched and still misses bursts (recall 0.0; its score does not rise from 13 to 103 payments).
  The current window is (t - 24h, t]: payments stamped at the same instant as this one count (they have already been received; excluding them would let many payments sharing one timestamp read as one), and nothing dated after it ever counts. Visible to an auditor every time: `risk.range_signal` in the `/v2/transact` reply (fired or not, with both counts), one reason line when it fires, a `beyond_observed_range=FIRED|not_fired|not_evaluated` field on every `[RISK]` log line, and the dashboard's scenario detail. Through the real signed endpoint, a customer with 200 real
  payments one per 25 hours who sends 8 in eight minutes fires on the 7th and 8th (above
  6 x 1), not on the 6th (the boundary), and the decision ATLAS returns equals the decision
  on the same evidence with the signal removed; a store restart and a model reload give
  the same signal. Tests: `tests/test_range_signal.py` (24); 12 deliberate breaks of the
  signal, its calibration, its visibility and its no-decision guarantee were caught.
  **Evidence boundary, not a defect:** the 40/40 and 0/320 are separation of synthetic bursts (15-30 payments in two hours) from synthetic normal days (1-3 payments); they say nothing about real-world burst-detection performance. The accurate claim is that ATLAS has a separately validated, customer-relative range signal demonstrated on synthetic data.
- ~~**Cold start reported LOW.**~~ **Resolved 2026-09-25 by an approved specification
  change:** below `MIN_HISTORY_FOR_BANDS` (200, unchanged: the repository holds no validated evidence for a different number) the ML layer returns `INSUFFICIENT_HISTORY` with no anomaly score and a reason saying how much history exists. It is not LOW and no `RISK_THRESHOLD` rule matches it, so every payment decision is exactly what it was when this case was reported as LOW (tests compare both answers rule by rule); the frozen step-up context round-trips it through SQLite unchanged. Tests: `tests/test_insufficient_history.py`
  (16); 3 deliberate breaks caught. What remains is a design fact, not a defect: the ML
  layer says nothing about a customer until 200 payments are known.
- ~~**The ML evaluations scored cases against their own future.**~~ **Fixed 2026-09-25.**
  Held-out cases dated 6 February, and the older evaluation's ordinary cases dated early
  January, were scored against a January-June history. Every case is now placed after the
  history it is scored against (`evaluation.place_after_history`), and
  `tests/test_ml_evaluation_no_lookahead.py` fails if any scored history row is later than
  its case (under the old code: all 1,120). **The published figures did not change**, and
  that was checked rather than assumed: the history rows are the same either way, so only
  the 24-hour count moved -- in 947 of 1,120 cases -- and not one anomaly score changed,
  because the model does not respond to that feature (the burst item above).
- Amount baseline in ML is per-subject-global, not per-beneficiary.
- ~~Policy rollback rejection is not live.~~ **Fixed 2026-09-25** (ARCHITECTURE.md
  principle 7). `atlas_service/policy/version_store.py` records each subject's highest
  policy version and its hash in a new file, `atlas_policy_state.db` (no existing
  database is migrated). Every deciding request -- signed and legacy -- and `/evaluate`
  (read-only) is checked before any state exists: an older version is refused
  (`policy_rollback`), the same version with different content is refused
  (`policy_tampered`), and an unreadable store refuses (`policy_state_unavailable`) --
  FAIL_CLOSED, nothing persisted, the bank never contacted. `tests/test_policy_rollback.py`
  (14) drives it through the real signed endpoint; removing the gate fails 10 of them. A
  traced run: v4 recorded, the file swapped for a v3 with a 100x hard cap, the next
  Rs 1,50,000 payment refused, v4 still recorded. **Signed since 2026-09-27:** every
  policy must carry its owner's Ed25519 signature (`policy/signing.py`), verified against
  an owner key enrolled in ATLAS's own policy state (`scripts/policy_key.py`), so a forged
  HIGHER-numbered, looser file is refused too (`tests/test_policy_signing.py`, 12; 5
  deliberate breaks caught). Owner private keys live outside the repository, encrypted, in
  `~/.atlas/policy-keys/`. Still trusted: the first enrolment of an owner key. The bank
  does not check `policy_version` itself. Editing a policy now REQUIRES bumping
  its version (RUNBOOK.md §4.4).
- **The dashboard is not hosted anywhere.** GitHub Pages has never been tried. Since
  2026-09-22 a committed browser matrix (`pytest tests/test_dashboard_browsers.py`)
  loads the page from the file, over local HTTP and in its failure state, at three
  widths in light and dark themes, clicking every scenario. On 2026-09-25 it passes in
  **Chromium, WebKit, the installed Google Chrome 153 and Microsoft Edge 153**, and in two
  **emulations** -- WebKit with the iPhone 13 profile and Chromium with the Pixel 7 profile
  (viewport, user agent, touch, taps), labelled as emulation in every result, not as
  phones. **Firefox is skipped on this machine** — Playwright's Firefox will not start
  here (it reports `spawn UNKNOWN`; diagnosed earlier as a missing Microsoft C++
  runtime), so it is recorded as untested, with its error, not as passing. **Not run, and
  each needs Dhanush's action or permission:** a stock Firefox (a download), Safari on
  Apple hardware (a macOS CI run, which needs a push), real phones, and a Pages copy
  (publishing). The deployment target in BUILD-PLAN.md is a page screen-shared from this
  PC, which the Chrome and Edge runs cover.
- ~~**An unexplained `webkit` teardown error.**~~ **Root cause found and fixed 2026-09-25.**
  This file previously said it happened once and did not reproduce; **that was wrong** --
  it happened three times (2026-09-23 19:56, 2026-09-24 00:35 and 00:38), each while
  another ATLAS process was running. It was not WebKit: the isolation guard correctly
  caught a concurrent write to the LIVE `bank_service/bank_ledger.db`, because the
  dashboard export's sweep never redirected the bank's ledger path (`bank_service/db.py`
  reads it at call time; the export's own test missed it because conftest.py redirects
  it for every test). WebKit is simply the longest test, so the likeliest to overlap.
  Reproduced in a throwaway clone (WebKit alone: passed; sweep started mid-test: 2 of 2
  errors), fixed in `scripts/export_dashboard_data.py`, and re-run: 10 of 10 passed with
  the clone's ledger never created. The export test now lists the ledger path and fails
  without the fix. **Consequence for live state:** the live `bank_ledger.db` holds 24
  outcome records written by these tools (5 `dash-*` from exports, 20 `trace-*` from a
  2026-09-23 trace script), none of them a real payment. It is untouched; cleaning it is
  Dhanush's decision.
- ~~**The isolation guard watched its own sandbox.**~~ **Fixed 2026-09-25.** It read the
  key directories' paths after redirecting them, so "the real key directories are
  unchanged" compared two empty sandbox folders. `tests/conftest.py` now captures them at
  import (`REAL_KEY_DIRS`), and `tests/test_isolation_guard.py` fails if they drift back.
- `requirements.txt` is unpinned.
- `bank_service`'s account balances are in-memory: three hardcoded accounts, reset on
  restart.
- ~~`bank_service`'s revocation table is in-memory too.~~ **Fixed 2026-09-22**:
  revocations and recorded outcomes are SQLite (`bank_ledger.db`, or `$ATLAS_STATE_DIR`),
  so a revoked key stays revoked across a restart. This also fixed a real defect: before
  it, a bank restart left reconciliation with no record of an approved payment and
  settled it FAILED.
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

### How it was re-run then (no browser, no build queue, no human)

> **Superseded on 2026-09-09.** `wokwi-cli` simulates on Wokwi's servers, so it can
> reach ATLAS only through a public tunnel. The supported route is now the VS Code
> extension with the local private gateway (`RUNBOOK.md` §2 and §7). The record below
> is how the 2026-09-01/02 runs were driven.

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

**2026-09-21.** Implementation stopped at `596a974` (2026-09-18): Steps 0-8, the
hardening track, step-up (off by default) with D1, the D2 UTC time basis, the closed
legacy path (D5) and the transport policy (D6), and the Step 9 dashboard, built and
not hosted. The 2026-09-21 pass changed documentation, the dashboard's limits text and
one JavaScript check that pins it (with the pytest wrapper's floor raised to match), and
brought `README.md`, `LICENSE` and `assets/` into the working repository so a release is
its tracked files minus the two private notes. No service, policy, ML or firmware code
changed. The 2026-09-22/23 pass then encrypted the keys at rest, separated ML training from
inference, put the ATLAS → bank hop on mutual TLS, made the sandbox bank's outcomes and
revocations durable, removed the legacy path's escape hatch and built Phase 3.8's
red-team suite. Decisions started reading live payment history on 2026-09-23/24, and the
2026-09-25 limitation-closure pass is described under "Other known limitations". The suite
is **689 passed, 2 skipped**, with 34 JavaScript checks. The next action is publishing this
release, which needs Dhanush's explicit approval; see "Git state" above for how.

Earlier checkpoints, kept as the record of their day:

**2026-09-16.** Step-up authentication (built 2026-09-11, `ATLAS_ENABLE_STEP_UP` off
by default) had a real defect: a payment nobody confirmed stayed in
`AWAITING_STEP_UP` forever. The fix was approved and implemented. The suite was **351
passed**, and 10 of 10 mutations were caught; see "Step-up authentication" below. The
project was published at github.com/Dhanu2626/atlas with rewritten history: the
28 Aug snapshot, a docs commit, and the step-up release, pushed on 2026-09-17
IST as `48ff889` — the commit timestamp itself reads 2026-09-16 UTC. At that point
nothing in the working repository had been committed since `e22a690`; `596a974`
followed on 2026-09-18.

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
(STEP-UP-INVARIANT-1). Limits: 120 s expiry, one challenge per transaction, single-use.
A failed proof is refused and audited but ends nothing (D1, 2026-09-18); the clock is
the only thing that closes a challenge without a valid proof.

**Evidence, by class:**
- **TESTED:** `tests/test_step_up.py`, **57 tests** (30 on 2026-09-11, 43 after the
  2026-09-16 cleanup fix, 57 after D1 on 2026-09-18). These include an exhaustive
  resolver sweep, a structural "no recompute" guard, a DENY-guard mutation test, HTTP
  round trips, the restart cleanup, and D1's refusals: twelve failed proofs followed by
  a valid one that still confirms, malformed proofs in six shapes, and two valid proofs
  at once authorising exactly once.
- **OBSERVED:** a live-service run with the virtual device passed 15/15 checks
  (2026-09-11); a Wokwi run on real firmware proved 7 of 10 checks (2026-09-11); and the
  remaining three -- authentication success → ALLOW → CONFIRMED on a challenge issued to
  the real firmware -- were observed on 2026-09-23, making it **10 of 10**.
- **STILL NOT CLAIMED:** anything about physical hardware. Every device run has been in
  the Wokwi simulator, and step-up ships off by default.

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
- **351 passed** on 2026-09-16: 13 new tests, 1 strengthened, none weakened.
- **10/10 mutations caught**, with the files restored byte-for-byte.
- On **copies** of this machine's databases, exactly one of 138 transactions changes:
  `esp32-atlas-fw-10-803e2d6a-0001` (the 11 Sep Wokwi ₹60,000 run) becomes `DENIED`,
  with event `RESOLVED_ON_RESTART reason=EXPIRED`. A second run changes nothing.
- The real databases were not touched. The next real `atlas_service` start will make
  that one change.

**Not yet observed:** the cleanup inside a real `run_sim.py` or uvicorn start. The tests
drive the same ASGI lifespan through Starlette's `TestClient`.

### Finding D: resolved (2026-09-17 and 2026-09-18)

Finding D had two halves, and both are closed. Neither needs a further decision.

- **The mismatch (fixed 2026-09-17).** A `/v2/step-up` request naming a live
  `challenge_id` with the wrong `transaction_id` used to cancel the real pending payment
  (`BINDING_MISMATCH` → `DENIED`) without a valid proof. It is now refused and audited
  with no state change, as `docs/STEP-UP-PROPOSAL.md` §4 always specified, and the
  customer can still approve.
- **The invalid-proof denial (retired 2026-09-18, D1).** Three invalid proofs with the
  right ids used to end the challenge and deny the payment. The three-attempt budget is
  gone: a request without a valid proof is refused, audited and changes nothing (see
  "2026-09-18: the security and correctness pass" below).

Only the 120 s expiry ends a challenge without a valid proof. Details and evidence:
`docs/STEP-UP-EXPIRY-FIX.md` §18.

### Test isolation: ten tests opened live databases (fixed 2026-09-17)

Three setups in `tests/test_phase3_device_trust.py` fell back to a default store path:
the `clients` fixture and the bank-unreachable test had no step-up store override, and
the closed-legacy test had no transaction store override. On every full run, ten tests
opened `atlas_service/atlas_step_up.db` or `atlas_service/atlas_transactions.db` -- the
live files. Nothing was written: their SHA-256, size and modification time were
unchanged at every check. All three now use the `clients` fixture with every store
overridden, and `test_http_tests_never_open_a_default_store_file` fails if a default
path is used (5 deliberate breaks, all caught). A full run under an audit hook recording
every file open, SQLite connection and directory operation opened no database, key file,
device secret, log or firmware build output; the only contact was pytest's test
discovery listing file names, key directories included. Since 2026-09-18 `pytest.ini`
sets `testpaths = tests`, which stops even that listing, and registers the `js` and
`firmware` markers.

## 2026-09-18: the security and correctness pass

Five changes, each with tests that fail without it. Deliberate breaks were run in an
isolated copy for all of them; the results are in that day's review.

**D1 -- a step-up request without a valid proof changes nothing.** The 3-attempt budget
is retired. A wrong `transaction_id`, an invalid or malformed signature, or a subject
with no enrolled authenticator is audited and refused, and the reply is byte-for-byte
the unknown-challenge reply: no risk band, no score, no rules, no policy hash. Reaching
the old third failure needed no secret -- only the two ids, both shown on the device and
sent without TLS -- so anyone who saw them could deny that payment while never being
able to approve it. `attempt_count` now bounds the audit trail (10 rows per challenge)
and is never terminal. Expiry is the only thing that still closes a challenge without a
proof. `AuthResult.ATTEMPTS_EXHAUSTED` is retired and never returned; the resolver still
maps it to DENY. See `docs/STEP-UP-EXPIRY-FIX.md` §18.

**D2 -- UTC is the canonical time basis for ML features.** `hour_of_day` used to be the
hour of whatever offset the caller wrote, while the training history is generated in
UTC, so one instant scored differently as `+05:30` and as `+00:00`. Timestamps are now
normalised to UTC before the hour is read, and a naive timestamp is read as UTC rather
than as the machine's local time. Decisions and bands did not move; scores shifted
slightly and the 23:30 IST scenario stopped listing "unusual time of day" because 18:00
UTC is inside this persona's modelled window -- the `odd_hours` policy rule, which is
evaluated in the user's own timezone, still fires. Policy semantics are untouched.

**D5 -- the legacy unsigned `POST /transact` is closed** (Phase 3.8). Nothing in the
release needed it. It was closed by default on 2026-09-18 with `ATLAS_REQUIRE_DEVICE_AUTH=0`
as a process-level escape hatch; on 2026-09-22 that hatch was removed, so the path cannot
be opened in a running service at all. The pre-Phase-3 tests open it the one way that
remains, a FastAPI dependency override inside the test process.

**D6 -- insecure transport is refused rather than assumed.** `atlas_service/transport.py`
allows plain HTTP on loopback, requires TLS anywhere else, and refuses at startup if the
bank URL is a plaintext non-loopback address. `ATLAS_ALLOW_INSECURE_HTTP=1` is the named
development override and logs itself every start. `scripts/run_dev.py` takes
`--tls-cert/--tls-key`. Since 2026-09-22 this is no longer only a policy: `scripts/make_dev_ca.py`
creates a local test CA, `scripts/serve.py` serves both services from it, and the
ATLAS -> bank hop is mutual TLS with the certificate and hostname verified and no
plaintext fallback. `scripts/make_dev_cert.py` was deleted with the same change -- it
wrote an unencrypted private key and a 30-day self-signed certificate. This is still not
a production TLS deployment (local CA, no HSM; revocation and pinning were added on
2026-09-25, in the opt-in production profile only, as a local CRL and pin) and the
documentation says so.

**Test infrastructure.** An autouse fixture in `tests/conftest.py` redirects every
default store path and key directory into a per-test sandbox and fails any test that
uses one, and watches the real paths too. `scripts/audit_file_access.py` runs the suite
under a Python audit hook and reports every protected file it opens -- it found this
pass's own transport test reading `secrets.h`, which is now pruned. The dashboard page
had 22 JavaScript tests (`tests/js/`) at the end of that day — **30 since 2026-09-23** —
and the firmware has 12 (wiring against
`diagram.json`, the LED whitelist, the debounce, the step-up display, plus an opt-in
`arduino-cli` build), and `pytest.ini` sets `testpaths = tests`.

**Step 9.** ML precision, recall and latency are measured by `scripts/evaluate_ml.py`
and carried on the page with their caveat; each scenario row records whether its signed
envelope was refused on replay and how long the round trip took; the sweep drives the
signed `/v2/transact` path.

## Project scope -- what is actually left (audited 2026-09-09, re-checked 2026-09-21)

Verified against the file tree and the code, not against old documentation.

| Item | Status | Classification |
|---|---|---|
| Steps 0-8 | built | **ALREADY COMPLETE** |
| Phase 3.1 registry | built; devices are administered with `scripts/provision_device.py` — the `/admin/devices` endpoints the spec proposed were not built | **ALREADY COMPLETE** |
| Phase 3.2 envelope, canonical bytes, `/v2/transact` | built | **ALREADY COMPLETE** |
| Phase 3.3 counter + nonce replay layers | built, re-verified by execution | **ALREADY COMPLETE** |
| Step-up authentication (added 2026-09-11, outside the original plan) | built, flag OFF; restart cleanup fixed 2026-09-16; finding D resolved (mismatch 2026-09-17, invalid-proof denial retired 2026-09-18); Wokwi approve path observed 2026-09-23 (10 of 10 checks) | **BUILT, VERIFIED IN SIMULATION** |
| **Step 9 dashboard** | **built 2026-09-17/18**: `docs/index.html` (self-contained page, 34 JavaScript checks) + `scripts/export_dashboard_data.py`. Read-only database figures, the Results scenarios re-run through both services on temporary stores over the signed path, per-transaction replay status, measured ML precision/recall and score latency. Not measured: separate policy, signing and verification latency, reconciliation success rate, what leaves the trust boundary. Not hosted; GitHub Pages untried | **BUILT, NOT DEPLOYED** |
| Phase 3.4 location grading | `LocationEvidence` exists in `contracts.py`; location is carried and SIGNED but graded by nothing | **OPTIONAL/FUTURE** |
| Phase 3.5 integrity grading + rollback | `DeviceHealth` exists; carried and signed, graded by nothing | **OPTIONAL/FUTURE** |
| Phase 3.6 policy vocabulary / ML features | not built | **DEFERRED BY DESIGN** -- the only step that can change financial decisions; `PHASE3-SPEC.md` marks it Highest risk and defers it to Phase 4 |
| Phase 3.7 firmware rollout | device key, envelope and NVS counter all built; **GNSS stub absent** (0 occurrences) | **OPTIONAL/FUTURE** |
| Phase 3.8 close legacy `/transact` + red-team suite | **done**: closed 2026-09-18, escape hatch removed 2026-09-22, and the spec's 25-attack red-team suite built 2026-09-22 (`tests/test_red_team.py`) | **COMPLETE** |

`PHASE3-SPEC.md` itself says *"Recommended checkpoint after 3.3"* -- which is
exactly where this project is. Stopping here is the spec's own recommendation,
not a shortfall.

**So the honest answer to "is ATLAS complete?": everything through Phase 3.3
works and is verified by execution, Phase 3.8 closed the legacy path on
2026-09-18, and the dashboard exists but is not hosted anywhere and does not
measure every dimension `BUILD-PLAN.md` lists. 3.4-3.6 are specified but were
deliberately not started, 3.7 is built except its GNSS stub (F3 delivered the device
key, envelope and NVS counter), and 3.6 must not be started casually.**

`docs/ATLAS-Blueprint.md` is current: it was refreshed for the 2026-09-18 work and
re-synced with the repository on 2026-09-21.

## Next step (do not start without explicit approval)

**Updated 2026-09-21.** **None should begin without Dhanush saying so**, and
`docs/IMPROVEMENT-DIRECTIVE.md` §20 requires a pre-change report first.

1. ~~**Observe ALLOW.**~~ **DONE 2026-09-02** — see the daylight run above. All three
   decision branches are now observed at runtime. No runtime gap remains in the
   round trip.
2. ~~**Fix limitations 7 and 8**~~ **DONE 2026-09-02** — see "The NTP clock fix" below.
   Both verified by execution, including the failure path.
3. ~~**Fix the step-up expiry defect**~~ **DONE 2026-09-16** — see "Step-up
   authentication" above.
4. **Publish to GitHub.** ~~The step-up work~~ **DONE 2026-09-17** as `48ff889`. The
   2026-09-18 work and the 2026-09-21 documentation sync form the next release, built
   the way "Git state" above describes; it is pushed only after Dhanush reviews it.
5. **Prove the step-up ALLOW path in Wokwi**, the 3 checks still unproven.
6. ~~**Decide finding D**~~ **Both parts resolved.** The mismatch was fixed 2026-09-17;
   the 3-attempt budget was retired 2026-09-18, so no request without a valid proof can
   end a challenge or deny a payment (`docs/STEP-UP-EXPIRY-FIX.md` §18).
7. **Step 9: dashboard** — **built 2026-09-17/18**: static HTML/JS with no Jinja,
   showing transactions, ML evidence, the policy decision, signing and per-transaction
   replay status and the active rail, with ML precision, recall and score latency
   measured by `scripts/evaluate_ml.py`. Left: hosting it (GitHub Pages untried), and
   the measurements it does not take — policy, signing and verification latency
   separately, reconciliation success rate, and what leaves the trust boundary.
8. **Phase 3.4-3.7** — location grading, integrity grading, policy vocabulary and the
   GNSS stub (3.8 is done: the legacy path is closed and the red-team suite was built on
   2026-09-22). Specified in `docs/PHASE3-SPEC.md`. Note 3.6 (policy vocabulary)
   is the only one that can change financial decisions and was deliberately deferred to
   Phase 4.

Follow the standing process: explain the design first, then implement, then test edge
cases deliberately, then show real results, then stop for approval.

## Earlier pending decisions, and where each stands (2026-09-21)

- **Wokwi cost — settled.** No paid dependency was added. Since 2026-09-09 the device
  reaches `atlas_service` through the local private gateway (`wokwigw`), verified
  working from the VS Code extension on 2026-09-11 on an account the simulator labels
  *Community License*. The web IDE's free build servers are not used: the sketch is
  compiled locally with `arduino-cli`.
- **Timeline/scope — superseded.** The estimate was for the original nine steps; Steps
  0-8 are done and Step 9 is built, so it no longer governs anything.
- **Module 7/8 status** (`ARCHITECTURE.md`'s known gaps): whether dedicated
  Security/Failures research days ever ran. A frozen historical gap — only Dhanush
  providing the actual material resolves it, and it blocks nothing.
- **`docs/ATLAS-Blueprint.md` — settled.** Refreshed for the 2026-09-18 work and
  re-synced on 2026-09-21; it is current.
