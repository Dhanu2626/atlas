# BUILD-PLAN.md — ATLAS, from research to a working prototype

> **This is the plan as written, and it is kept as a historical record.** It was
> authored before the build and has not been rewritten as the build progressed, so
> read its step rows as "what was intended", not "what exists". For current status —
> including the hardening track (Phase 2, Phase 3.1-3.3, F1-F3), the step-up work, the
> Step 9 dashboard built on 2026-09-17/18, and the security changes of 2026-09-18 —
> read `HANDOFF.md`. Where the two disagree, `HANDOFF.md` and a live `pytest` run are
> right.

**Context.** Research (Days 1-13 + a final "architecture freeze" pass) is being treated
as complete as of 2026-08-21 — Dhanush's own call. The freeze conversation did
something genuinely valuable that this plan has to respect: a real prior-art search
found that most of ATLAS's individual pieces already exist (see the Novelty Status
section in `ledger\ARCHITECTURE.md`), which sharpened the research question and
produced a "frozen" architecture spec that's now the authoritative reference. Dhanush's
explicit instruction: no more moving targets, build against this spec, only deviate for
a genuine technical glitch encountered during implementation — not by redesigning
things. This plan respects that.

**2026-08-21 update:** the frozen spec is somewhat larger than the original build plan
(multi-rail adapters, a revocation lifecycle, an emergency-override flow). Rather than
either quietly dropping pieces of the spec or quietly blowing the ~10-13 day timeline,
this file now makes the split explicit — see **"V1 vs. documented-but-deferred"** below.
That's not a change to the architecture; it's the same "identify the limitation, don't
hide it" discipline the research itself used throughout, applied to scheduling.

## The one architectural correction from the original sketch (unchanged, now doubly justified)

Split the backend into two independent services from day one — `atlas_service` (holds
the private key, runs ML + policy, signs decisions) and `bank_service` (holds only the
public key, has its own ledger rules, can independently override ATLAS). This was
already the right call for demoing "the bank has final authority"; the freeze
conversation's authority hierarchy (`LAW → BANK → USER POLICY → ML`, see
`ARCHITECTURE.md`) makes it non-negotiable — there's no other way to make that
hierarchy real in running code instead of a claim in a document.

## V1 vs. documented-but-deferred

| Piece | V1 (built, in the ~10-13 day window) | Deferred (designed, not built — documented as future work) |
|---|---|---|
| Policy engine | Full — using the Policy Semantic Layer vocabulary (`MAX_AMOUNT`, `NEW_BENEFICIARY`, `INTERNATIONAL`, `TIME_WINDOW`, `VELOCITY`, `RISK_THRESHOLD`, `REQUIRE_STEP_UP`) | — |
| ML | Full — Isolation Forest, as already decided | — |
| Crypto / trusted core | Full — Ed25519 sign/verify, exposed through the `init_device / generate_identity / get_public_key / secure_sign / verify_policy / attest / revoke` interface from `ARCHITECTURE.md` | Real hardware-backed attestation (stays simulated, by design — principle 4) |
| State machine + reconciliation | Full, including the fail-closed-vs-reconcile split (security failure → deny/step-up immediately; availability failure → pending → reconcile) | — |
| Payment-rail adapters | **Two** thin adapters (UPI-shaped + one more, Pix-shaped) proving "same policy, different rail output" | A third adapter (FPS) if time allows; anything resembling *real* Pix/UPI/FPS wire formats — these are toy/illustrative shapes only |
| Revocation | A `revoke()` call that flips a key to invalid in a small table, checked at verification | The full `ACTIVE → SUSPENDED → REVOKED` lifecycle with audit trail |
| Emergency override | Documented design only (separate high-assurance flow: extra auth + explicit confirmation + audit event) | Actual implementation — real risk if rushed, since a badly-built override is a worse security hole than not having one |
| Institutional trust / enrollment | Documented as an explicitly open problem (RQ-7/12/23/24) with a one-page explanation of *why* it's hard | Any attempt to actually solve it — this is a governance/legal question, not a coding one |
| Cross-border FX | A fixed, hardcoded conversion rate for the demo | Live FX feeds, timing/rounding edge cases |
| Wokwi firmware | Full, hard-timeboxed | — |
| Dashboard | Full, shows which rail-adapter is active + the measurement numbers below | — |
| Measurement dimensions | Logged and shown for security/ML/privacy/finance/performance (see `ARCHITECTURE.md`) | Interoperability numbers beyond "the two adapters agree on the same policy" |

## Build order

| # | Step | Why here / what it prevents |
|---|---|---|
| 0 | ✅ **Done.** Shared contracts (`Transaction`, `RiskEvidence`, `PolicyDecision`, `AssertionPayload`/`SignedAssertion`, `BankVerdict`, `TxnState`) + `docs/POSITIONING.md`. `Transaction` later expanded (see `ledger\SYNTHESIS.md` #2-3) with `location`/`device_id`/`merchant_category`/`authentication_method`/`declared_travel_mode`/`is_emergency_request` | — |
| 1 | ✅ **Done.** `atlas_service/ml/{synth,features,model}.py` — per-subject Isolation Forest (adapted from `launderlab`'s `Isolation` wrapper), synthetic personas with recurring monthly patterns, planted anomalies matching `ledger\SYNTHESIS.md` §4's exact fixtures. `tests/test_ml_model.py`, 8/8 passing. Two real bugs found and fixed during build, not just threshold tuning: an O(n²) + data-leakage bug in feature computation (transactions could "see" future transactions when computing is-new flags — fixed with a proper walk-forward `extract_training_matrix`, also ~10x faster), and Travel Mode initially made anomaly scores *worse* because sparse training density (~2.5%) sat right at the contamination rate, so the forest learned to isolate travel itself — fixed with a deterministic feature-neutralization adjustment instead of relying on density learning. Known, documented (not hidden) V1 simplification: the amount baseline is per-subject-global, not per-beneficiary, so a legitimately recurring large payment (rent) can read as mildly elevated — doesn't block any of the actual test scenarios | Reused `launderlab\src\launderlab\ml\models.py`'s wrapper pattern (scaler fit-on-train-only, negated `decision_function`) |
| 2 | ✅ **Done.** `atlas_service/policy/engine.py` — pure `evaluate()` function (adapted from `refundradar`'s `rules_engine.py` pattern), reads versioned YAML (`policies/user-demo-1.yaml`) in the frozen semantic-layer vocabulary, monotonic-version/no-rollback check, SHA-256 policy hashing. `tests/test_policy_engine.py`, 24/24 passing including boundary conditions, multi-rule conflicts, and an adversarial "client lies about is_new_beneficiary" case. Two design decisions made and flagged as mine, not the frozen research's: most-restrictive-wins conflict resolution (DENY>DELAY>STEP_UP>ALLOW), and RISK_THRESHOLD comparing against the categorical risk_band rather than a raw score | Reused `refundradar\refundradar\rules_engine.py`'s pure-function pattern |
| 3 | ✅ **Done.** `atlas_service/main.py` (`/evaluate`, `/transact`) and `bank_service/main.py` (`/verify` + a toy independent ledger) as two real FastAPI apps, connected by `atlas_service/bank_client.py`. `tests/test_bank_boundary.py`, 13/13 passing: an AST-level source check that `bank_service` never imports `atlas_service` internals, the bank independently overriding an ATLAS ALLOW for a frozen/insufficient-balance account (tested end-to-end through `/transact`, not just unit-level), a genuinely unreachable bank (real closed TCP port, not mocked) correctly producing PENDING rather than silent approval, and confirmation ATLAS never even contacts the bank when its own policy already says DENY. One real bug found and fixed during build: `httpx.ASGITransport` is async-only and silently can't be used with a sync `httpx.Client` (`AttributeError`, not a timeout) — fixed by using `TestClient` (the sync-compatible ASGI bridge) consistently instead of hand-rolling the transport | New — no direct prior-art file to reuse for the FastAPI wiring itself |
| 4 | ✅ **Done.** `atlas_service/{db,state_machine}.py` — SQLite-backed `TransactionStore`, a `VALID_TRANSITIONS` graph enforcing the frozen state list exactly (nothing can leave DENIED/CONFIRMED/FAILED), and `reconcile()`. One small, flagged extension to `bank_service`: `/verify` now records outcomes by `transaction_id` (idempotent — a resend returns the cached result, never re-evaluates) and a new `GET /status/{id}` lets reconciliation ask "what actually happened," which didn't exist before and was necessary for "reconcile, demonstrated for real" to mean anything. `tests/test_state_machine.py`, 13/13 passing, including the actual point of this step: a real SQLite file + a genuinely fresh `TransactionStore` object (simulating a process restart) correctly finds a transaction stuck in SUBMITTED, reconciles it against the bank's real record, and resolves to CONFIRMED or FAILED depending on what the bank actually saw — with proof of no duplicate submission. One real regression found and fixed, not just a fluke: the new bank-side idempotency exposed a pre-existing test-hygiene bug in `test_bank_boundary.py` — several Step-3 tests all shared one default `transaction_id`, harmless while the bank was stateless, but a real bug once it started genuinely remembering outcomes (an earlier test's cached "approved" leaked into a later test expecting a different answer for a different account). Fixed by giving each test its own transaction ID, matching how real usage would behave anyway | New — no direct prior-art file to reuse |
| 5 | ✅ **Done.** `atlas_service/crypto.py` — Ed25519 sign/identity behind `secure_sign()`/`init_device()`/`generate_identity()`/`get_public_key()`/`revoke()` (of the 7-function interface, `verify_policy` stays covered by Step 2's hash/rollback check, `attest()` stays deferred per the V1-vs-deferred table below). `contracts.py`'s new `canonical_assertion_bytes()` — shared, crypto-free canonicalization (same `sort_keys=True` discipline as `policy/engine.py`'s hashing) that both sides import, since `bank_service` must reproduce byte-identical signed bytes without importing `atlas_service` internals — kept living in `contracts.py` specifically so `test_bank_boundary.py`'s AST check stays honored. `bank_service/verify.py` checks signature → revocation → expiry → replay, in that order — signature first, since every other field (including `atlas_key_id`, which revocation keys off) is unauthenticated data until the signature proves it genuinely came from the claimed key. `bank_service/replay_cache.py` — SQLite-persisted, keyed on `(transaction_id, nonce)`. `bank_service/revocation.py` — in-memory, deliberately *not* persisted, matching this table's own wording distinction between a "persisted" replay cache and a "minimal" revoke check; documented, not hidden, as not surviving a `bank_service` restart. One real design split made and flagged, not silently assumed: `revoke()` exists on both sides but means different things — `atlas_service/crypto.py`'s is a device-side self-disable (deletes its own key, blocks further signing), `bank_service/revocation.py`'s is the actual enforcement, since a genuinely compromised device can't be trusted to revoke itself. `tests/{test_crypto,test_revocation,test_expiry}.py` new (`test_replay.py` was already planned by name here), 24 new tests, plus 3 more from extending `test_bank_boundary.py`'s AST boundary check to cover the 3 new `bank_service` files (that check was hardcoded to `["main.py", "ledger.py"]` and silently wouldn't have covered new files otherwise) — **85/85 full suite passing.** Adversarial cases proven, not just asserted: tamper (flip a field post-signing → rejected, both at the raw-signature level and through `verify_assertion`), replay (valid resend → rejected, proven to survive a simulated `ReplayCache` restart the same way Step 4 proved it for transaction state), revocation (rejected despite a genuinely valid signature; revoking one key doesn't affect another; a rejected assertion never burns its replay slot), and expiry (exact-instant boundary tested both sides of the line — verified for real by deliberately weakening the check to `>` and watching the boundary test catch it, then reverting). Not wired into `main.py`/`bank_service/main.py` yet — that live HTTP integration is Step 6, per the approved Step 5 scoping decision | New — no direct prior-art file to reuse; `contracts.py`'s existing hashing discipline reused for the canonicalization instead of inventing a second convention |
| 6 | ✅ **Done.** `atlas_service/main.py`'s `/transact` now actually drives the frozen state machine (persist -> EVALUATING -> ALLOWED/DENIED -> SIGNED -> SUBMITTED -> CONFIRMED/FAILED/UNKNOWN) and calls `build_signed_assertion()` to produce a real, signed `SignedAssertion` for ALLOW decisions instead of the Step 3 placeholder dict. `bank_service/main.py`'s `/verify` contract changed to accept a `SignedAssertion` (the old bare `{subject, amount, transaction_id}` shape was always a pre-crypto placeholder): it checks `verify_assertion()` (signature/revocation/expiry/replay) first, then `ledger.verify()` (the bank's own independent account decision) only if that passes. A new `/reconcile/{transaction_id}` endpoint makes Step 4's `reconcile()` reachable over HTTP for the first time. `bank_service` learns ATLAS's public key via a shared, non-Python file (`shared_keys/atlas_public_key.txt`, gitignored) that `atlas_service` writes on startup — `bank_service` cannot import `atlas_service.crypto` directly (the enforced boundary), so a plain file is the toy hand-off point; flagged plainly as not a solution to `ARCHITECTURE.md`'s still-open RQ-24 (key/policy provenance). New `get_signing_keys_dir()`/`get_transaction_store()` dependencies on `atlas_service`'s side and `get_atlas_public_key()`/`get_replay_cache()` on `bank_service`'s side, all overridable in tests the same way `get_bank_client()` already was. Two real, previously-latent bugs found and fixed, not just wiring: (1) `state_machine.py`'s `reconcile()` had no handling for bank status `"REJECTED"` — a transaction rejected by the bank but discovered only via reconciliation (not the synchronous response) fell through to "stay in RECONCILING" forever; fixed by treating `REJECTED` the same as `NOT_FOUND` (both resolve to `FAILED`), confirmed by deliberately reverting the fix and watching the new test catch the hang, then restoring it. (2) The transition graph had no `SUBMITTED -> FAILED` edge, so a *synchronous* bank rejection (the common case, answer arrives in the same request) had nowhere valid to go; added directly, since `RECONCILING -> FAILED` alone can't represent "resolved immediately, nothing to reconcile." One flagged scoping choice, not a frozen-architecture change: `STEP_UP`/`DELAY` decisions land in the same `TxnState.DENIED` transaction state as `DENY` (there's no separate `STEP_UP` state in the frozen list, and building the interactive confirmation loop is out of scope here) — only the response body's own `decision` field still distinguishes them. `tests/test_end_to_end.py` new (both real apps together: normal ALLOW with full state check, STEP_UP reported correctly, bank-override persisted to `FAILED`, `/reconcile` live, tamper/expiry/revocation against the real running `bank_app`); `tests/test_bank_boundary.py` and `tests/test_state_machine.py` updated wherever they built the old bare `/verify` shape, now via `build_signed_assertion()` — the same production function `/transact` itself calls, not a parallel hand-rolled one. Incidental fix, not part of Step 6's own scope but found while running the full suite: Step 5's `test_crypto.py`/`test_replay.py`/`test_revocation.py` had hardcoded absolute-date assertion timestamps (`2026-08-24`) that silently expired the moment the calendar rolled to `2026-08-25` between sessions — switched to relative `datetime.now()`-based timestamps, matching the pattern `test_expiry.py` already used correctly. **96/96 tests passing** (85 prior + 11 new). Not yet built: Wokwi firmware, dashboard, rail adapters (Steps 7-9) | De-risks the Wokwi step; a complete two-process system now genuinely exists, not just a claim |
| 7 | ✅ **Done.** `atlas_service/adapters/` — `base.py` (`RailSemantics`, `UnknownRailError`), `fx.py` (hardcoded illustrative INR→BRL rate), `upi_adapter.py`, `pix_adapter.py`, and an `__init__.py` registry with `to_rail_payload()`/`semantic_view()` dispatch that raises on an unknown rail rather than defaulting. Wired into `/transact` as a `rail` **query parameter** (not a `Transaction` field — which rail to submit over is routing context, not intrinsic transaction data, and keeping it out of the contract avoids churning a model both services depend on); the response gains `rail` and `rail_payload`. `bank_service` still receives the canonical `SignedAssertion` regardless of rail — an approved scoping decision: making the bank parse two payload shapes adds real risk without demonstrating anything `rail_payload` doesn't already show. One ambiguity in the record resolved rather than silently picked (now `SYNTHESIS.md` #7): Day 12's diagram shows the *policy vocabulary* fanning into adapters, while the frozen data flow and this file's own Step 7/test-11 wording put the adapter *after* the decision — resolved as two halves of one diagram already split across two steps, since Step 2 had already achieved the rail-independent vocabulary (the policy YAML contains zero UPI-specific terms), leaving Step 7 the output side. The load-bearing constraint, enforced by test rather than convention: an adapter **frames** the `SignedAssertion` and never edits through it, since Step 5's signature covers the canonical payload bytes — verified by extracting the assertion back out of each rail shape and re-running `bank_service`'s real `verify_assertion()`, and confirmed to have teeth by temporarily making `pix_adapter` "helpfully" rewrite the amount inside the assertion (the realistic careless bug) and watching the test fail naming PIX, then reverting. FX divergence built deliberately, not hidden: `valor` (BRL, converted) and `valor_origem` (INR, as signed) disagree on purpose, `semantic_view()` reports the signed original, and a test proves converting and converting back does **not** return the original amount — the concrete, runnable form of RQ-16/25/26, which this step points at and explicitly does not solve. `adapters/` is on the untrusted side per `ARCHITECTURE.md`, enforced by an AST-level test (full dotted paths, unlike `test_bank_boundary.py`'s root-level check, since adapters legitimately import `atlas_service.adapters.*`) that fails if any adapter imports `atlas_service.crypto`/`.policy`/`.ml`. FPS deliberately not built (deferred column); the registry makes adding it a one-line change. `tests/test_adapters.py` 21 new + 5 new in `test_end_to_end.py` — **122/122 passing** | Proves the "global finance, not just UPI" claim in running code, not just a diagram |
| 8 | ✅ **Done.** `firmware/virtual_device.py` (the tested artifact) + `firmware/atlas_device/{atlas_device.ino, diagram.json, wokwi.toml, libraries.txt}` (the visual demo) + `firmware/README.md` + `scripts/run_dev.py`. Implements `docs/ATLAS-Blueprint.md` §24's already-labelled `[C][F]` proposal rather than inventing a new design, and invents **no new protocol** — the device POSTs the existing `/transact` contract (§24.3's "mirroring the existing contract exactly"). Three logically separated layers, kept distinct in both the `.ino` and the Python even though Wokwi runs them on one board: event acquisition (a press → `RawEvent`, knows nothing about ATLAS) → assembly (`RawEvent` → Transaction-shaped **dict**, deliberately not a pydantic model, since an ESP32 emits JSON and building the model would test imports instead of the wire shape) → network/response. **The fallback was promoted to the primary**: correctness lives in `virtual_device.py`, which the suite actually runs against the real `atlas_service`+`bank_service`; Wokwi is presentation. Stated plainly and repeatedly, not buried: **the `.ino` was never compiled or executed** — no ESP32 toolchain in this environment — so nothing here claims the firmware works until someone runs it. Fail-closed core is a **whitelist, not a blacklist**: only the five known `final_status` values map to a state, everything else (unknown status, wrong type, missing key, `/transact`'s own unknown-rail `{"error": …}` reply, non-JSON body, HTTP 500, unreachable host) becomes `FAIL_CLOSED`. `DeviceState` is deliberately finer-grained than the three LEDs — `REFUSED` and `FAIL_CLOSED` both light red but stay distinct in the model, since "the bank said no" and "something broke" are different facts. Per approved scope: **no device-side/asymmetric signing in V1** — §24.3 proposes it, §24.6 already classes forged device identity as RQ-7/12/24 unresolved, and a symmetric shared secret was explicitly rejected rather than added to make the demo look more secure than it is; requests leave the device unauthenticated and the README says so. **Free/public Wokwi Gateway only** — verified against Wokwi's docs that outbound-to-public-internet works free while localhost/LAN needs the paid Private Gateway, and Step 8 needs only outbound, so no paid dependency was added; the public tunnel is documented as demo-only infrastructure providing zero authentication, and `scripts/run_dev.py` deliberately does **not** start one (binds 127.0.0.1 only — exposing the key-holding service is an operator decision, not a script side effect). Zero changes to `atlas_service` decision logic, `crypto.py`, `policy/`, `ml/`, `adapters/`, or `bank_service` — Step 8 is purely additive. `tests/test_virtual_device.py`, **30 tests**: raw event → contract-valid `Transaction` (fed to the real model), integer-minor-unit money with no float error, ALLOW→green / STEP_UP→amber / DENY→red end-to-end through the real services, bank-override still reaching the device only as DENY, unreachable ATLAS (real closed port) → fail closed, 13 parametrized malformed/partial bodies → fail closed, HTTP 500 → fail closed, non-JSON → fail closed, an AST check that the device imports no `atlas_service`/`bank_service`/`contracts` internals (untrusted edge, same discipline as `test_bank_boundary.py`/`test_adapters.py`), and the headline invariant — of every status the device might receive, **exactly one lights green**, plus a real DENY with `approved: true` decoy fields alongside it still showing red. Adversarial check performed: temporarily replaced the equality whitelist with substring matching (`"ALLOW" in status`, the realistic subtle bug), which made `"ALLOWED"` light green — caught by two tests with `assert ['ALLOW', 'ALLOWED'] == ['ALLOW']` — then reverted and confirmed no residue. **152/152 passing** (122 Steps 0-7, unchanged, + 30 new) | Fallback promoted to primary: `virtual_device.py` carries the correctness, Wokwi carries the demo |
| 9 | Dashboard | Shows transactions, ML evidence, policy decision, crypto/replay status, which rail adapter is active, and the measurement numbers. **Historical plan — a first version was built on 2026-09-17/18** (`docs/index.html` + `scripts/export_dashboard_data.py`) covering all of these, with ML precision, recall and latency measured by `scripts/evaluate_ml.py`. Current status lives in `HANDOFF.md`; it is not deployed anywhere |

## Test scenarios (full spec lives in `ARCHITECTURE.md`; this is the build-order-appropriate working subset)

1. Normal transaction → ALLOW
2. Unusual amount + new beneficiary → ML flags high anomaly → policy STEP-UP → user confirms → ALLOW
3. A user-declared trusted-beneficiary rule conflicting with a high ML score → STEP-UP (policy-engine-level conflict — corrected from an earlier draft that assumed the policy engine sees bank risk at decision time; it doesn't, per the settled sequencing)
4. **ATLAS says ALLOW, `bank_service` independently says no** (frozen account / insufficient balance) → fails at the bank — this is the one that proves the authority hierarchy is real
5. Simulated power loss mid-transaction → restart → RECONCILE, no duplicate payment
6. Tampered assertion (one byte changed) → signature check rejects it
7. Replayed assertion (valid, untampered, resent) → nonce/replay cache rejects it
8. Expired assertion (60-120s window) → rejected
9. Revoked device → rejected
10. Policy rollback attempt (resubmit a decision claiming an older policy version once a newer one is active) → rejected
11. Same `PolicyDecision` object run through both rail adapters → consistent semantic result in each shape

## Tools — unchanged from the previous version of this plan

Wokwi (ESP32, real Arduino C++, browser-compiled) for firmware; Python + FastAPI for
both backend services; scikit-learn (Isolation Forest) for ML; Python's `cryptography`
library (Ed25519) for signing; SQLite for persistence; static HTML/JS for the dashboard
(matches `refundradar`'s existing no-Jinja convention). Wokwi free-vs-paid tradeoff
(Public Gateway + tunnel vs. €8/mo Private Gateway) is still Dhanush's call, unchanged
from before.

## Timeline

Unchanged in shape from the previous version (~10-13 focused days); step 7
(rail adapters) adds roughly half a day, absorbed into the existing step-6/7 budget
rather than extending the total, since a "thin adapter" is a translation function over
data that already exists by that point, not new integration work.

| Phase | Days | Deliverable |
|---|---|---|
| 0 — contracts + positioning note | ~1 | shared schemas + the novelty-status paragraph |
| 1-2 — ML + policy engine | 1.5-2 | earliest honestly-real slice |
| 3 — two-service skeleton + boundary test | 0.5-1 | `atlas_service`/`bank_service` split, proven separate |
| 4 — state machine + SQLite | 1.5 | kill-mid-transaction → reconcile, for real |
| 5 — crypto (sign / verify / replay / revoke) | 1.5-2 | tamper, replay, and revocation all rejected |
| 6 — full integration, core scenarios | 1 | the interview-defensible core |
| 7 — rail adapters (UPI + Pix-shaped) | 0.5-1 | the "global finance" claim, demonstrated |
| 8 — Wokwi firmware (hard timebox) | 1-2 | LED demo or documented `virtual_device.py` fallback |
| 9 — dashboard | 1.5-2 | what gets screen-shared |
| buffer — rehearsal + demo recording | 1 | insurance against a live-demo failure |

**Total ≈ 11-14 focused days.**

## Deliberately left out (unchanged, plus the new frozen exclusions)

Everything from the previous version, plus — confirmed by the freeze conversation
independently arriving at the same list: no blockchain, no cryptocurrency, no
zero-knowledge proofs, no federated learning, no quantum cryptography, no custom
encryption algorithm, no literal new payment rail, no custom hardware PCB, no live bank
integration, no real UPI transactions, no autonomous AI deciding payments, no sprawl of
microservices. This convergence is worth mentioning out loud if it comes up in an
interview — two independent passes (this build plan's own scoping, and the research's
own "final frozen scope") landed on the same exclusion list.

## Folder structure

```
atlas/
  PROJECT.md
  BUILD-PLAN.md
  ledger/                           (research docs — don't touch)
  docs/
    THREAT-MODEL.md                 (the red-team scorecard from ARCHITECTURE.md, operationalized)
    DEMO-SCRIPT.md                  (rehearsed walkthrough of all test scenarios)
  contracts.py
  atlas_service/
    main.py
    ml/
      synth.py
      features.py
      model.py                     (adapt launderlab's Isolation Forest pattern)
    policy/
      engine.py                    (adapt refundradar's rules_engine.py pattern; semantic-layer vocabulary)
      policies/<user_id>.yaml
    adapters/
      upi_adapter.py
      pix_adapter.py
    state_machine.py
    crypto.py                      (init_device/generate_identity/secure_sign/attest/revoke)
    db.py
    keys/                          (gitignored)
  bank_service/
    main.py
    ledger.py
    verify.py
    replay_cache.py
    revocation.py
  firmware/
    atlas_device/
      atlas_device.ino
      diagram.json
      wokwi.toml
    virtual_device.py
  dashboard/
    index.html
    app.js
  tests/
    test_ml_model.py
    test_policy_engine.py
    test_state_machine.py
    test_crypto.py
    test_replay.py
    test_revocation.py
    test_bank_boundary.py
    test_adapters.py               (same PolicyDecision → both adapters → consistent semantics)
    test_end_to_end.py
  scripts/
    run_dev.py
  requirements.txt
  .gitignore
```

`git init` inside `atlas\` before writing code, matching `launderlab`/`refundradar`.

## Still open when this plan was written (2026-08-21) — Dhanush's call, not decided here

*Where each stands now: `HANDOFF.md`, "Earlier pending decisions, and where each stands".*

- **Wokwi cost**: pay for the Private Gateway, or use the free tunnel workaround?
- **Timeline pressure**: does ~11-14 focused days actually fit, or does scope need to
  shrink further (e.g. one adapter instead of two, skip revocation entirely)?
- **The one remaining research gap**: Module 8 (historical failures — Mondex, Avant,
  eNaira, Dinero) never got its own day, even through the Day 11-13 novelty work. Not a
  blocker, worth a direct answer on whether that's deliberate or just not gotten to.

Related: [[atlas-project]] memory, `ledger\ARCHITECTURE.md` (the settled principles and
full spec this plan builds against).
