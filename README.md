<p align="center"><img src="assets/hero-atlas.svg" width="100%" alt="ATLAS"/></p>

![Part of Dhanush Labs](https://img.shields.io/badge/PART_OF-DHANUSH_LABS-6366F1?style=flat-square&labelColor=0A0B0D)
![Status](https://img.shields.io/badge/STATUS-RESEARCH_PROTOTYPE-3B82F6?style=flat-square&labelColor=0A0B0D)
![Tests](https://img.shields.io/badge/TESTS-304_PASSING-3B82F6?style=flat-square&labelColor=0A0B0D)
![License](https://img.shields.io/badge/LICENSE-MIT-6366F1?style=flat-square&labelColor=0A0B0D)

### A Signed Second Opinion Before Your Payment Leaves

A user-owned policy layer that evaluates a payment with deterministic rules and local ML evidence, signs its decision, and hands the bank something it can verify — without ever replacing the bank or the payment rail. Built by **Dhanush Jangadi**. All data synthetic; no real bank or payment rail is connected.

**[📐 Read the full Engineering Blueprint →](docs/ATLAS-Blueprint.md)** — every component, trust boundary, failure mode and known limitation, each tagged with how it is known.

---

## Problem Statement

> [!IMPORTANT]
> Spending controls, fraud scores and authorization rules already exist — but they belong to the bank, the card network or the wallet, not the account holder, and they don't travel between payment rails. ATLAS tests one narrow question: can a **user-owned** policy decide on a payment, protect that decision cryptographically, and hand existing payment infrastructure a **verifiable assertion** it can consume, while the behavioural evidence behind it stays **local**?

Novelty is **explicitly unproven**. Prior-art research found an existing patent (US20210065194A1) that combines most of the original architecture. What survives is a narrower, open hypothesis — user ownership, portability across rails, strictly local evidence — to be tested, not claimed.

## Architecture

<p align="center"><img src="assets/atlas-flow.svg" width="100%" alt="Animated walkthrough of the published code paths: a signed ESP32 envelope is verified by ATLAS, scored by ML, decided by policy and, only for ALLOW, signed and re-verified by the bank. Four scenes: ALLOW, STEP_UP, DENY, and a replayed envelope rejected with COUNTER_REGRESSION."/></p>

```
LAW / REGULATION  ─►  BANK  ─►  USER POLICY  ─►  ML EVIDENCE     (a layer can only add restriction)

ESP32 ──signed envelope──► ATLAS_SERVICE ──signed assertion, ALLOW only──► BANK_SERVICE
 sign · display             verify ─► ML ─► policy ─► sign                   verify ─► ledger
   ◄──────────────────────── final_status: ALLOW · STEP_UP · DENY ◄──────────────────┘
```

| Step | Subsystem | Result |
|---|---|---|
| 0–2 | Contracts, ML evidence, policy engine | Per-subject Isolation Forest; deterministic most-restrictive-wins; SHA-256 policy hash |
| 3–4 | Two-service authority split, state machine | AST-enforced boundary; a restart reconciles, never guesses |
| 5–6 | Ed25519 assertions, bank verification | Signature → revocation → expiry → replay, live over HTTP |
| 7 | UPI + Pix adapters | One signed decision, two rail shapes, FX divergence made visible |
| 8 | ESP32 firmware + virtual device | Fail-closed whitelist: exactly one status lights green |
| 3.1–3.3 | Device trust | Registry, per-device Ed25519 keys, counter + nonce replay layers, `/v2/transact` |
| 9 | Dashboard | Not started |

## How It Works

```bash
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
.venv\Scripts\python -m pytest -q
.venv\Scripts\python scripts\run_dev.py
```

`run_dev.py` starts `atlas_service` on `127.0.0.1:8000` and `bank_service` on `127.0.0.1:8100`. The ESP32 firmware, its Wokwi circuit and device provisioning are documented in [`firmware/README.md`](firmware/README.md).

## Features

- **User-owned, deterministic policy** — versioned YAML in a rail-neutral vocabulary (`MAX_AMOUNT`, `NEW_BENEFICIARY`, `INTERNATIONAL`, `TIME_WINDOW`, `VELOCITY`, `RISK_THRESHOLD`), most-restrictive-wins, SHA-256 hashed and rollback-checked.
- **ML as evidence, never the judge** — a per-subject Isolation Forest produces a risk band with plain-language reasons; a policy rule decides whether it matters. Client claims about new beneficiaries are recomputed from history, never trusted.
- **Signed decisions the bank can verify** — an ALLOW becomes an Ed25519-signed assertion carrying the decision, not the ML score. The bank checks signature, revocation, 90-second expiry and replay before its own ledger decides.
- **Fail closed vs. reconcile** — a bad signature is refused immediately; an unreachable bank becomes `PENDING` and is reconciled against the bank's own record, never blindly retried.
- **Device trust** — registered devices sign every request with their own key, verified through ordered checks with three independent replay defences: counter, nonce and `transaction_id`.
- **Firmware that only displays** — the ESP32 signs and submits with libsodium, then maps the reply through a whitelist; anything unrecognised lights red.

## Screenshots

> [!NOTE]
> The animation above is drawn from the published code paths and real serial output. Wokwi captures of this firmware version are still to be added — placeholders only for now.

## Interactive Demo

No hosted demo — ATLAS is two local services plus firmware. The quickest way to watch it work is the test suite, which drives both real services end to end, or the Wokwi circuit in [`firmware/atlas_device/`](firmware/atlas_device/).

## Engineering Decisions

| Question | Answer |
|---|---|
| Can ML approve a payment? | No. ML produces evidence and a policy rule decides. A poisoned or evaded model degrades to deterministic policy, never to "fail open". |
| Can ATLAS overrule the bank? | Only toward restriction. ATLAS ALLOW plus bank DENY is always DENY — proven end to end with frozen and insufficient-balance accounts. |
| What does the bank learn? | The decision, policy version and policy hash — never the ML score, features or history. |
| Why verify the signature first? | Every other field, including the key id revocation relies on, is attacker-controlled until the signature proves it. |
| What if the bank is unreachable? | `PENDING`, then reconciliation against the bank's record using the same `transaction_id`. |
| What does the device decide? | Nothing. It signs, submits and displays; only an exact `ALLOW` lights green. |

> [!WARNING]
> Several problems remain **unsolved by design**, not by oversight: trust enrollment (proving a key or policy belongs to the real account holder), authority when ATLAS says DENY but the bank never agreed to honour it, cross-rail semantics, and hardware compromise. Device keys live in plaintext flash — a valid signature proves possession of a key, not the genuineness of a device.

## Project Structure

```
atlas/
├── contracts.py       shared models + canonical signed bytes, imported by both services
├── atlas_service/     ML evidence, policy engine, state machine, crypto, rail adapters, device trust
├── bank_service/      independent verifier, replay cache, revocation, toy ledger
├── firmware/          ESP32 sketch + Wokwi circuit, virtual_device.py, device identity
├── scripts/           run_dev.py, provision_device.py
├── tests/             304 tests
├── docs/              Engineering Blueprint, security gap report, Phase 3 spec
├── ledger/            frozen research record: architecture, synthesis, notebook
├── HANDOFF.md         build status and known limitations as of this release
└── BUILD-PLAN.md      step-by-step build record
```

Two private research notes — the raw research transcript and an interview positioning note — are kept out of this repository; a few documents still refer to them by name.

## Tech Stack

Python 3.12 · FastAPI/Uvicorn · Pydantic v2 · scikit-learn · cryptography (Ed25519) · SQLite · httpx · pytest · ESP32 (Arduino core 3.3.11) · libsodium · ArduinoJson 7 · Wokwi

## Results

Measured against this exact code, with real signing and real bank verification:

| Payment | At 10:00 IST | At 23:30 IST |
|---|---|---|
| ₹1,500 to an existing beneficiary | **ALLOW** · bank approved | **STEP_UP** · `odd_hours` |
| ₹60,000 to a new beneficiary | **STEP_UP** · `large_amount` | **STEP_UP** |
| ₹1,50,000 to a new beneficiary | **DENY** · `hard_cap` | **DENY** |

| Attack or failure | Outcome |
|---|---|
| Tampered amount, beneficiary, subject, device or counter | `INVALID_DEVICE_SIGNATURE` |
| Verbatim replay of a signed envelope | `COUNTER_REGRESSION` |
| Bank unreachable | `PENDING` → reconciliation, never approval |
| 10 concurrent requests | 0 internal errors, down from 4–6 before the F2 atomicity fixes |

304 tests passing across 16 files. Several guards were mutation-tested: deliberately breaking a check — a non-atomic counter claim, an adapter rewriting a signed amount, a substring status match — and confirming a test fails before restoring it.

> [!CAUTION]
> **Known issue in this release's firmware:** it does not wait for NTP before signing. A SEND pressed in the first seconds after boot can carry a 1970 timestamp (rejected as `STALE_REQUEST`) or abort and reboot the ESP32 during SNTP start-up. This was found by running this firmware in Wokwi after the release was cut; the fix is not part of this release.

## Future Improvements

- **Step 9 dashboard** — transactions, ML evidence, policy decisions, replay status and the active rail in one view
- **Phase 3.4–3.8** — location and integrity grading (evidence, not gating), device evidence in the policy vocabulary (the only step that can change decisions, so deliberately last), a GNSS stub, and closing the legacy unsigned `/transact`
- **A real STEP_UP flow** — today STEP_UP is reported, but no second-factor confirmation loop exists
- **Waiting for NTP** before the first signed request
- **Hardware-backed device keys** (an ATECC608-class secure element) and a real enrollment story

## Lessons Learned

Tests prove the model that was written, not necessarily the device that ships. The firmware's signing template was pinned byte-for-byte against the backend, yet the first real simulator run still found a start-up clock race no test could see — compiling is not running. The backend showed the same pattern: a counter claim made deliberately non-atomic passed the suite until a 2 ms interleaving window was forced, so that guarantee rests on a single locked compare-and-swap rather than on the tests; and seven tests with hard-coded dates silently expired overnight. Each was caught by running something real or breaking something on purpose, which is why the mutation checks became part of the build.

## License

MIT © 2026 Dhanush Jangadi

## Contact

Dhanush Jangadi — [GitHub](https://github.com/Dhanu2626) · [LinkedIn](https://www.linkedin.com/in/jangadidhanush)

---
<p align="center"><sub>Part of the <b>Dhanush Labs</b> portfolio · engineered by <a href="https://github.com/Dhanu2626">Dhanush Jangadi</a></sub></p>
