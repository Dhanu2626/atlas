<p align="center"><img src="assets/hero-atlas.svg" width="100%" alt="ATLAS"/></p>

![Part of Dhanush Labs](https://img.shields.io/badge/PART_OF-DHANUSH_LABS-6366F1?style=flat-square&labelColor=0A0B0D)
![Status](https://img.shields.io/badge/STATUS-RESEARCH_PROTOTYPE-3B82F6?style=flat-square&labelColor=0A0B0D)
![Tests](https://img.shields.io/badge/TESTS-693_PASSING-3B82F6?style=flat-square&labelColor=0A0B0D)
![Device](https://img.shields.io/badge/DEVICE-ESP32_%C2%B7_WOKWI-22C55E?style=flat-square&labelColor=0A0B0D)
![License](https://img.shields.io/badge/LICENSE-MIT-6366F1?style=flat-square&labelColor=0A0B0D)

### A Signed Second Opinion Before Your Payment Leaves

A user-owned policy layer that evaluates a payment with deterministic rules and local ML evidence, signs its decision, and hands the bank something it can verify — without ever replacing the bank or the payment rail. Built by **Dhanush Jangadi**. All data synthetic; no real bank or payment rail is connected.

**[📐 Read the full Engineering Blueprint →](docs/ATLAS-Blueprint.md)** — every component, trust boundary, failure mode and known limitation, each tagged with how it is known. · **[🔌 Main circuit diagram →](docs/hardware/atlas-schematic.svg)** · **[▶️ Live dashboard →](https://dhanu2626.github.io/atlas/)**

---

## Try It Yourself

| | What you get | How |
|---|---|---|
| 👀 **Watch it** | Press SELECT and SEND on the device in your browser and see the LED ATLAS would light — a replay of real recorded runs, with every layer of each payment | **[Open the live dashboard →](https://dhanu2626.github.io/atlas/)** |
| ▶️ **Run it** | The real ATLAS and bank code decide three payments on your own computer in about 30 seconds — no hardware, no Wokwi, nothing saved | `pip install -r requirements.txt`, then `python scripts/demo.py` |
| ☁️ **Run it in the browser** | The same demo in your own GitHub Codespace — nothing to install | [![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/Dhanu2626/atlas?quickstart=1), then `python scripts/demo.py` |
| ✅ **See the latest run** | GitHub runs the demo on every push and fails unless it gets ALLOW, STEP_UP and DENY | [![demo](https://github.com/Dhanu2626/atlas/actions/workflows/demo.yml/badge.svg)](https://github.com/Dhanu2626/atlas/actions/workflows/demo.yml) |

What `python scripts/demo.py` prints, abridged:

```text
Press 1: SELECT preset 1, then SEND -- Rs 1,500.00 to ben-mother at 10:00 IST
   ATLAS says ALLOW   ->  device LED [GREEN]
   - bank: verified ATLAS's signed decision and approved the payment
Press 2: SELECT preset 2, then SEND -- Rs 60,000.00 to ben-newshop at 10:00 IST
   ATLAS says STEP_UP   ->  device LED [AMBER]
   - policy rule 'large_amount': the amount is over Rs 50,000 -> STEP_UP
Press 3: SELECT preset 3, then SEND -- Rs 1,50,000.00 to ben-newshop at 10:00 IST
   ATLAS says DENY   ->  device LED [RED]
   - policy rule 'hard_cap': the amount is over Rs 1,00,000 -> DENY
Replay: an attacker captures a validly signed request and sends it again
   first time: ALLOW   second time: FAIL_CLOSED (COUNTER_REGRESSION: that device counter was already used)
Result: ALLOW, STEP_UP, DENY  -- as the policy requires (green, amber, red).
```

What is simulated, plainly: the demo presses the buttons through the firmware's tested Python twin ([`firmware/virtual_device.py`](firmware/virtual_device.py)) rather than the C firmware in Wokwi, and runs both services in-process; everything that decides — the device-signature and replay checks, ML evidence, the owner-signed policy, ATLAS's signed decision and the bank's verification — is the real code. The full simulation of the real firmware in Wokwi is in [`firmware/README.md`](firmware/README.md); it needs VS Code, the ESP32 toolchain and Wokwi's local gateway.

---

## Problem Statement

> [!IMPORTANT]
> Spending controls, fraud scores and authorization rules already exist — but they belong to the bank, the card network or the wallet, not the account holder, and they don't travel between payment rails. ATLAS tests one narrow question: can a **user-owned** policy decide on a payment, protect that decision cryptographically, and hand existing payment infrastructure a **verifiable assertion** it can consume, while the behavioural evidence behind it stays **local**?

Novelty is **explicitly unproven**. Prior-art research found an existing patent (US20210065194A1) that combines most of the original architecture. What survives is a narrower, open hypothesis — user ownership, portability across rails, strictly local evidence — to be tested, not claimed.

## Architecture

<p align="center"><img src="assets/atlas-flow.svg" width="100%" alt="Animated walkthrough of the published code paths: a signed ESP32 envelope is verified by ATLAS, scored by ML, decided by policy and, only for ALLOW, signed and re-verified by the bank. Four scenes: ALLOW, STEP_UP, DENY, and a replayed envelope rejected with COUNTER_REGRESSION."/></p>

<sub>Drawn from the published code paths and real serial output.</sub>

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
| 3.3b | Step-up, off by default | A STEP_UP can pause for out-of-band confirmation; re-resolution recomputes nothing and can never rescue a DENY |
| 9 | Dashboard | A dated snapshot page: read-only database figures, the Results scenarios re-run through both services over the signed path, per-transaction replay status, and measured ML precision, recall and latency. Not deployed anywhere |

## The Device: ESP32 Circuit

The payment device ATLAS talks to, as wired in the Wokwi simulation. It signs requests and shows the answer; it never decides.

<p align="center"><img src="assets/atlas-device-board.svg" width="100%" alt="The ESP32 DevKit V1 drawn as a circuit board: three LEDs through 220 ohm resistors on GPIO 25, 26 and 27, SELECT and SEND buttons on GPIO 14 and 12. The LEDs cycle through the same four scenes as the architecture animation: ALLOW green, STEP_UP amber, DENY red, replay rejected red."/></p>

<p align="center"><img src="assets/atlas-device-pinout.svg" width="100%" alt="All 30 ESP32 header pins with name, GPIO number, type and what ATLAS wires to each; 9 are in use and 21 are free."/></p>

<p align="center"><img src="assets/atlas-device-parts.svg" width="100%" alt="What each part does: green LED ALLOW; amber LED STEP_UP, DELAY or PENDING; red LED DENY, FAIL-CLOSED or any unrecognised reply; SELECT and SEND buttons; and the serial monitor."/></p>

**[🔌 Main circuit diagram →](docs/hardware/atlas-schematic.svg)** · drawn from [`diagram.json`](firmware/atlas_device/diagram.json) · simulated in Wokwi, never built on physical hardware.

## How It Works

```bash
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
.venv\Scripts\python scripts\demo.py        # ALLOW, STEP_UP, DENY in about 30 s; nothing saved
.venv\Scripts\python -m pytest -q
.venv\Scripts\python scripts\run_dev.py
```

`run_dev.py` starts `atlas_service` on `127.0.0.1:8000` and `bank_service` on `127.0.0.1:8100`. The ESP32 firmware, its Wokwi circuit and device provisioning are documented in [`firmware/README.md`](firmware/README.md), and day-to-day operation — starting the simulator stack, provisioning a device, redeeming a step-up — is in [`RUNBOOK.md`](RUNBOOK.md).

## Features

- **User-owned, deterministic policy** — versioned YAML in a rail-neutral vocabulary (`MAX_AMOUNT`, `NEW_BENEFICIARY`, `INTERNATIONAL`, `TIME_WINDOW`, `VELOCITY`, `RISK_THRESHOLD`), most-restrictive-wins, SHA-256 hashed, rollback-checked and signed by its owner, so a forged or edited policy is refused before anything is decided.
- **ML as evidence, never the judge** — a per-subject Isolation Forest produces a risk band with plain-language reasons; a policy rule decides whether it matters. Client claims about new beneficiaries are recomputed from history, never trusted. Below 200 known payments the answer is `INSUFFICIENT_HISTORY` with no score — unknown is not treated as risky — and the deterministic rules decide alone. The forest does not catch bursts (held-out recall 0.0), so a separate `beyond_observed_range` signal, its 6× threshold chosen on the validation split only, flagged 40 of 40 synthetic test bursts and 0 of 320 ordinary cases; it is evidence only and changes no decision — the `velocity_burst` rule is what refuses a live burst.
- **Signed decisions the bank can verify** — an ALLOW becomes an Ed25519-signed assertion carrying the decision, not the ML score. The bank checks signature, revocation, 90-second expiry and replay before its own ledger decides.
- **Fail closed vs. reconcile** — a bad signature is refused immediately; an unreachable bank becomes `PENDING` and is reconciled against the bank's own record, never blindly retried.
- **Device trust** — registered devices sign every request with their own key, verified through ordered checks with three independent replay defences: counter, nonce and `transaction_id`.
- **Firmware that only displays** — the ESP32 signs and submits with libsodium, then maps the reply through a whitelist; anything unrecognised lights red.
- **Step-up that cannot rescue a DENY** — with `ATLAS_ENABLE_STEP_UP=1` (off by default), a STEP_UP pauses for an out-of-band Ed25519 confirmation. The re-resolution is a pure function of the frozen decision: no ML, no policy re-run, no clock. Anything unexpected resolves to DENY, and a payment left unanswered is settled to DENIED at the next start.
- **A request without a valid proof changes nothing** — a wrong transaction id, a bad or malformed signature, or no enrolled authenticator is refused and audited, and the reply carries no risk evidence at all. The challenge and transaction ids are not treated as secrets: only the authenticator's signature can complete a payment, and only the 120-second clock can end a challenge without one.
- **Nothing unsigned by default** — the legacy unsigned `POST /transact` is closed unless it is deliberately reopened, and a service will not serve a non-loopback address, or call a non-loopback bank, without TLS.

## Interactive Demo

**[The live dashboard](https://dhanu2626.github.io/atlas/)** is the Step 9 dashboard, served by GitHub Pages straight from [`docs/index.html`](docs/index.html): one self-contained page that needs no server and loads nothing from the network, so it also works opened from the file. It starts with the device: **SELECT**, **SEND** and a day/night switch light the LED the firmware would, replaying the results this export recorded through both real services — labelled a replay, never a live call, and a result it does not have fails closed, red. Then choose any of its seven scenarios to follow one payment through every layer: ML evidence, the policy decision and the rule that decided it, the signed assertion, the bank's verdict, the replay defence that refused the same envelope a second time, and the rail payload — next to aggregate figures from the local databases.

The page and its data are separate pieces: [`scripts/export_dashboard_data.py`](scripts/export_dashboard_data.py) writes the numbers into the page and into `docs/dashboard-data.json`, and the page only displays them:

```bash
.venv\Scripts\python scripts\export_dashboard_data.py --run-tests
```

- **Live databases, read-only.** Transaction states, step-up challenges and events, the device registry and the bank's replay cache are opened in SQLite's read-only mode and never written. Only aggregate figures reach the page; the database files themselves are never committed or published.
- **Scenarios on the signed path, on temporary stores.** The Results table below is re-run through both real services in-process, as signed `DeviceEnvelope`s posted to `/v2/transact` — the path the firmware itself uses — with the transaction, device and step-up stores, the replay cache and the signing key in a throwaway directory that is removed afterwards. The services' startup hook, which writes to the live databases, is never run. Each envelope is then sent a second time, and the page records which defence refused it.
- **Measured or recorded.** `--run-tests` runs the suite and the ML evaluation and records what it observed: the test count, and ML precision, recall and latency from [`scripts/evaluate_ml.py`](scripts/evaluate_ml.py). The firmware build size, the Wokwi step-up checks and the mutation results are not re-measured by the export; the page labels each one as recorded and names the document or test it came from.
- **Failures stay visible.** A dropped scenario, a failing test run or a page that could not be updated makes the export exit with status 1, and warnings are displayed on the page rather than dropped — including one for each database that could not be read, or a single one saying the snapshot was left out when the transaction database itself is missing.

The export in this release ran on 2026-09-27: all 689 tests passed (two skipped, each naming its reason — the opt-in firmware build, and Playwright's Firefox, which will not start on this machine), all 7 scenarios produced rows with no warnings, every replayed envelope was refused with `COUNTER_REGRESSION`, and all five live database files were byte-identical by SHA-256 before and after. That count now includes the bank's ledger: exports from 2026-09-22 to 2026-09-24 wrote their approved scenarios into the live `bank_ledger.db`, because the sweep never redirected the bank's ledger path. That was found and fixed on 2026-09-25, and a test now fails if it returns.

> [!NOTE]
> **What the dashboard is not.** A dated snapshot of a software-only prototype — not a live feed, a monitoring service or a production deployment. The services run locally on loopback and are never exposed publicly, all data is synthetic, and no real bank, payment rail or hardware is involved. The ML precision and recall it shows are measured against synthetic data produced by the same generator that trained the model: separation on generated data, never evidence of fraud detection.
>
> **How the page was checked, last on 2026-09-25.** A committed browser matrix ([`tests/test_dashboard_browsers.py`](tests/test_dashboard_browsers.py)) loads the page from the file, over a local static HTTP server and as a failure page, at the default window, 400 px and 1280 px, in light and dark, and clicks every scenario, checking each against the exported JSON: no console errors, no horizontal overflow, no request besides the page itself. It passes in Playwright's Chromium and WebKit, the installed **Google Chrome 153** and **Microsoft Edge 153**, and two **emulations** — WebKit with the iPhone 13 profile and Chromium with the Pixel 7 profile, tapping rather than clicking — which are labelled as emulation and are not phones. The page's own JavaScript has 34 automated checks ([`tests/js/`](tests/js/)). Firefox (Playwright's build will not start on this machine), Safari on Apple hardware, real phones and an actual GitHub Pages deployment were **not** tested.

The test suite also drives both real services end to end, and the Wokwi circuit is in [`firmware/atlas_device/`](firmware/atlas_device/).

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
├── atlas_service/     ML evidence, policy engine, state machine, crypto, rail adapters, device trust, step-up
├── bank_service/      independent verifier, replay cache, revocation, toy ledger
├── firmware/          ESP32 sketch + Wokwi circuit, virtual_device.py, device identity
├── assets/            hero, architecture animation, device board, pinout and parts images
├── keystore.py        protected-at-rest storage for every private key on disk
├── scripts/           run_dev.py, run_sim.py, serve.py, provision_device.py, enroll_authenticator.py,
│                   export_dashboard_data.py, evaluate_ml.py, audit_file_access.py, make_dev_ca.py,
│                   train_models.py, protect_keys.py, policy_key.py, benchmark_public_dataset.py,
│                   demo.py (the one-command run)
├── tests/             695 tests in 38 files, plus 41 JavaScript checks in tests/js/ and the browser matrix
├── docs/              Engineering Blueprint, security gap report, Phase 3 spec, dashboard (index.html),
│                   hardware/atlas-schematic.svg (the main circuit diagram)
├── ledger/            frozen research record: architecture, synthesis, notebook
├── .github/, .devcontainer/   the demo on every push; Open in GitHub Codespaces
├── RUNBOOK.md         start, run, stop, provision, test, step-up
├── HANDOFF.md         build status and known limitations as of this release
└── BUILD-PLAN.md      step-by-step build record
```

Two private research notes — the raw research transcript and an interview positioning note — are not published; a few documents still refer to them by name.

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

693 tests pass across 38 files, plus 41 JavaScript checks for the dashboard page and 12 for the firmware (wiring, the LED whitelist, the debounce, the step-up display, and an opt-in `arduino-cli` build). Two tests are skipped and each says why: the opt-in firmware build — run separately on 2026-09-23, 12/12 passing, producing 1,176,472 bytes, 89% of program storage — and Playwright's Firefox, which will not start on the build machine. They run on temporary stores and keys: an autouse fixture points every default database and key path into a per-test sandbox and fails any test that lands there, and `scripts/audit_file_access.py` re-runs the suite under a Python audit hook to confirm from the outside that nothing protected was opened. Guards are mutation-tested — a check is deliberately broken and the run must fail before it is restored: 10 of 10 on the step-up restart cleanup, 24 of 24 on the 2026-09-17 changes, 16 of 17 on the 2026-09-18 security pass, and 15 of 15 on the 2026-09-22 controls (key protection, the model registry, TLS and mutual TLS, bank reply validation, the durable ledger, the legacy lockdown, the size cap and the malformed-request handler). Two of that last set survived their first run, which is the point of running them: the bank ledger's idempotency and an echoed error body were real holes in the suite, and each was closed with a test before the break was caught. The one older survivor is honest and documented: removing the sandbox redirect alone changes nothing today, because every test already overrides its own stores. The 2026-09-25 closure work was broken deliberately 13 times — the rollback gate, the production TLS pin, CRL and TLS 1.3 settings, the export's ledger redirect, the isolation guard and the evaluation's no-look-ahead placement among them — and all 13 were caught; the two approved ML specification changes that followed were broken 15 more times, and all 15 were caught; the 2026-09-27 signed policy updates were broken 5 times, and all 5 were caught.

### Known limits

> [!NOTE]
> **Boundaries of a software-only prototype, by design.** The firmware runs in the Wokwi simulator and has never been built on hardware, so no hardware security property is claimed: the device key sits in ordinary flash, and ATLAS's own keys are encrypted at rest but readable by any process running as the same user. Transport uses a local test certificate authority; an opt-in production profile adds TLS 1.3, revocation checks and a pinned bank key, but a public or enterprise PKI and an HSM are outside this project. All data is synthetic, so the ML figures show separation on generated data, not fraud detection.

- **Open:** the ESP32 reaches ATLAS unencrypted through a local gateway, because the firmware has no TLS client yet. Its requests are signed end to end, so they can be read in transit but not altered.
- **A setting:** step-up confirmation ships off (`ATLAS_ENABLE_STEP_UP`); its approve path was observed end to end in Wokwi.

## Future Improvements

- **Test the dashboard on more browsers** — it is published on GitHub Pages, and a committed browser matrix covers Chromium, WebKit, installed Chrome and Edge, and iPhone and Pixel emulation; Firefox, Safari proper and real phones are untested
- **Finish Step 9's measurements** — the page does not yet show policy-evaluation, signing or verification latency separately (only each scenario's round trip), reconciliation success rate, or what leaves the trust boundary
- **Phase 3.4–3.6 and Phase 3.7's GNSS stub** — location and integrity grading (evidence, not gating), device evidence in the policy vocabulary (the only step that can change decisions, so deliberately last), and the firmware's GNSS stub; the rest of Phase 3.7 (device key, signed envelope, NVS counter) is built. Phase 3.8 is complete: the legacy path is closed and the 25-attack red-team suite is built
- **The ML-unavailable fallback** — the frozen design says that when the model cannot run, ATLAS should decide on deterministic policy alone; today it refuses the payment instead (`FAIL_CLOSED`, `ml_unavailable`) — safe, but stricter than specified
- **Let policy act on the burst signal** — `beyond_observed_range` is evidence only today; making a rule read it would change payment decisions and the frozen policy vocabulary, so it needs its own specification decision, and real (not synthetic) data to justify its threshold
- **An evidence-derived history threshold** — the ML layer judges no customer below 200 payments (reported as `INSUFFICIENT_HISTORY` since 2026-09-25). Lowering 200 needs measured false-positive rates at smaller history sizes, which have not been produced
- **Real transport security** — certificates from a public or enterprise CA, OCSP and a CA key in an HSM, and an ESP32 build with a TLS client; revocation (a local CRL), pinning and TLS 1.3 exist in the opt-in production profile, on a local test CA
- **Hardware-backed device keys** (an ATECC608-class secure element) and a real enrollment story — outside this project's frozen, software-only scope

## Lessons Learned

Tests prove the model that was written, not necessarily the device that ships. The firmware's signing template was pinned byte-for-byte against the backend, yet the first real simulator run still found a start-up clock race no test could see — compiling is not running. The backend showed the same pattern: a counter claim made deliberately non-atomic passed the suite until a 2 ms interleaving window was forced, so that guarantee rests on a single locked compare-and-swap rather than on the tests; and seven tests with hard-coded dates silently expired overnight. Each was caught by running something real or breaking something on purpose, which is why the mutation checks became part of the build. The step-up work repeated the lesson: a cleanup routine documented as the restart's safety net was never called by anything, and the test guarding it asserted only half of what its name promised — so a payment could sit waiting forever without a single test noticing.

## License

MIT © 2026 Dhanush Jangadi

## Contact

Dhanush Jangadi — [GitHub](https://github.com/Dhanu2626) · [LinkedIn](https://www.linkedin.com/in/jangadidhanush)

---
<p align="center"><sub>Part of the <b>Dhanush Labs</b> portfolio · engineered by <a href="https://github.com/Dhanu2626">Dhanush Jangadi</a></sub></p>
