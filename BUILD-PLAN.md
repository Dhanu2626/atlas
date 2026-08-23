# BUILD-PLAN.md — ATLAS, from research to a working prototype

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
| 5 | Crypto: Ed25519 sign in `atlas_service` (behind the `secure_sign()` interface), verify in `bank_service`; canonical JSON serialization; a persisted replay cache in `bank_service`, separate from signature checking; a minimal `revoke()` check | Tamper test **and** replay test — a valid resend passes signature verification, replay needs its own defense |
| 6 | Full HTTP integration, all core test scenarios passing headlessly, no hardware yet | De-risks the Wokwi step; this is also the point where a complete two-process system already exists even if nothing after this step gets finished |
| 7 | **Payment-rail adapters** — the UPI-shaped one first (already implicit in steps 0-6's data shapes), then a second, Pix-shaped adapter that takes the same `PolicyDecision` object and emits a differently-shaped payload | Proves the "global finance, not just UPI" claim in running code, not just a diagram |
| 8 | Wokwi ESP32 firmware — hard-timeboxed to 1-2 days | Falls back to `firmware\virtual_device.py` if it fights back close to a deadline |
| 9 | Dashboard | Shows transactions, ML evidence, policy decision, crypto/replay status, which rail adapter is active, and the measurement numbers |

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

## Still open — Dhanush's call, not decided here

- **Wokwi cost**: pay for the Private Gateway, or use the free tunnel workaround?
- **Timeline pressure**: does ~11-14 focused days actually fit, or does scope need to
  shrink further (e.g. one adapter instead of two, skip revocation entirely)?
- **The one remaining research gap**: Module 8 (historical failures — Mondex, Avant,
  eNaira, Dinero) never got its own day, even through the Day 11-13 novelty work. Not a
  blocker, worth a direct answer on whether that's deliberate or just not gotten to.

Related: [[atlas-project]] memory, `ledger\ARCHITECTURE.md` (the settled principles and
full spec this plan builds against).
