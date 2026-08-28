# SECURITY-GAP-REPORT.md — Phase 1 audit of the working system

**Written 2026-08-26**, from a fresh full-repository inspection plus live probing of the
running services. No code was modified to produce this report. Every claim below is
either quoted from source or reproduced against the running system; where something is
unverified it says so.

Baseline audited: 4 commits (`bf53c8f` → `451a9b8` → Step 7 → Step 8 uncommitted),
152 passing Python tests, ESP32 firmware compiled against core 3.3.11 / ArduinoJson 7.2.0.

---

## 1. Architecture map

```
   ESP32 (Wokwi)                atlas_service :8000              bank_service :8100
   ─────────────                ───────────────────              ──────────────────
   BTN_SELECT (D14) ─┐
   BTN_SEND   (D12) ─┴─> RawEvent
                         │
                         ▼ assemble (layer 2)
                    Transaction JSON
                         │
                         │  POST /transact?rail=UPI
                         │  ***UNAUTHENTICATED, UNSIGNED, PLAINTEXT HTTP***
                         ▼
                                  ┌──────────────────────────┐
                                  │ store.create()           │  SQLite
                                  │ → EVALUATING             │  transactions
                                  ├──────────────────────────┤
                                  │ ML: PersonaAnomalyModel  │  refit per request
                                  │   IsolationForest        │  from synth seed=42
                                  │   → RiskEvidence         │  (score, band, reasons)
                                  ├──────────────────────────┤
                                  │ POLICY: engine.evaluate()│  YAML rules,
                                  │   most-restrictive-wins  │  deterministic
                                  │   → ALLOW/STEP_UP/       │
                                  │     DELAY/DENY           │
                                  ├──────────────────────────┤
                                  │ if ALLOW:                │
                                  │   build_signed_assertion │  Ed25519 sign
                                  │   → SIGNED → SUBMITTED   │
                                  │   rail adapter (UPI/PIX) │
                                  └───────────┬──────────────┘
                                              │ POST /verify {SignedAssertion}
                                              ▼
                                                    ┌─────────────────────────┐
                                                    │ verify_assertion():     │
                                                    │  1 signature (Ed25519)  │
                                                    │  2 revocation (memory)  │
                                                    │  3 expiry (90s TTL)     │
                                                    │  4 replay (SQLite)      │
                                                    ├─────────────────────────┤
                                                    │ ledger.verify():        │
                                                    │  balance / frozen /     │
                                                    │  unknown account        │
                                                    │  idempotent by txn_id   │
                                                    └───────────┬─────────────┘
                                              ┌─────────────────┘
                                              ▼ BankVerdict
                          CONFIRMED / FAILED / UNKNOWN(→ /reconcile)
                                              │
                         ◄────────────────────┘ final_status
                         │
                    interpretStatus() — whitelist, else FAIL_CLOSED
                         │
                    LED: GREEN / AMBER / RED
```

**Trust boundary reality:** the cryptography protects **atlas_service → bank_service**.
It does **not** protect **device → atlas_service**. That second hop — the one a physical
attacker actually touches — is entirely unauthenticated.

---

## 2. Honest capability classification

### Genuinely implemented and cryptographically verified

| Capability | Where | Verified how |
|---|---|---|
| Ed25519 assertion signing | `atlas_service/crypto.py` | 9 tests; tamper test flips a field → `invalid signature` |
| Canonical serialization | `contracts.py:canonical_assertion_bytes` | byte-identical across two processes, proven live |
| Signature verification | `bank_service/verify.py` | signature checked **before** any other field is trusted |
| Replay rejection | `bank_service/replay_cache.py` | SQLite-persisted `(transaction_id, nonce)`; survives restart |
| Assertion expiry | `verify.py` | 90 s TTL; exact-instant boundary tested both sides |
| Policy determinism | `policy/engine.py` | same inputs → same output; most-restrictive-wins |
| Policy integrity + rollback | `engine.py` | SHA-256 over canonical JSON; monotonic version check |
| Transaction state machine | `state_machine.py` | terminal states unleavable; reconciliation after restart |
| Bank independence | `bank_service/` | AST test: never imports `atlas_service` internals |
| Device fail-closed | `virtual_device.py`, `.ino` | whitelist; 30 tests; exactly one status lights green |

### Implemented but software-only (no hardware backing)

| Capability | Reality |
|---|---|
| ATLAS private key | **Plaintext file** at `atlas_service/keys/atlas_ed25519.key`. No encryption, no HSM, no secure element |
| Key distribution | `shared_keys/atlas_public_key.txt` — a file on disk. Not enrollment, not PKI |
| Device "identity" | A string constant compiled into firmware. Anyone can send it |
| Revocation | **In-memory `set()`** in `bank_service/revocation.py` — a revoked key un-revokes itself on restart |

### Simulated only

| Thing | Status |
|---|---|
| ESP32 hardware | Wokwi simulation. Proves firmware logic + integration. Proves **nothing** about secure boot, eFuses, flash encryption, or tamper resistance |
| Bank ledger | 3 hardcoded accounts, in-memory, resets on restart |
| ML training data | Synthetic personas, `seed=42`, refit from scratch every request |
| Cross-border FX | One hardcoded rate; round-trip conversion deliberately lossy |

### Present as a JSON field only — **no verification whatsoever**

These arrive from the device and are consumed as truth:

| Field | What it claims | What actually backs it |
|---|---|---|
| `device_id` | which device sent this | **Nothing.** A string. Not signed, not registered, not checked |
| `location` | `"Bengaluru,IN"` | **Nothing.** No GPS, no coordinates, no accuracy, no geofence |
| `authentication_method` | `"device_button"` | **Nothing.** Never validated; no factor was actually performed |
| `timestamp` | when it happened | Device NTP. Not signed. Freely forgeable |
| `subject` | whose account | **Nothing.** Any caller may claim any subject |
| `currency` | INR | Never validated against anything |

### Correctly *distrusted* already (good existing design)

`is_new_beneficiary` and `is_new_device` are **recomputed from history** and the client's
claim is ignored — `policy/engine.py:_verified_new_beneficiary` and
`ml/features.py`. Test: `test_client_lying_about_new_beneficiary_is_ignored`.
This is the right pattern and should be extended to the fields above.

---

## 3. Phase 2 — the HTTP 500, root-caused and reproduced

**Not intermittent. Not the tunnel. Not a timeout. A deterministic application defect.**

Reproduced on demand against the running service:

```
POST /transact  {"transaction_id": "esp32-atlas-demo-01-0001", ...}
→ HTTP 500 Internal Server Error
```

Server traceback:

```
File "atlas_service/main.py", line 188, in transact_endpoint
    transition(store, transaction.transaction_id, TxnState.EVALUATING, now)
File "atlas_service/state_machine.py", line 61, in transition
    raise InvalidTransitionError(transaction_id, current, new_state)
InvalidTransitionError: esp32-atlas-demo-01-0001: cannot transition DENIED -> EVALUATING
```

### Causal chain

1. Firmware builds the ID as `snprintf(..., "%s-%04ld", DEVICE_ID, event.sequence)`
   → `esp32-atlas-demo-01-0001` (`atlas_device.ino:185`).
2. `g_sequence` is a RAM global. **Restarting the Wokwi simulation resets it to 0.**
3. `store.create()` is `INSERT OR IGNORE` — the existing row survives untouched.
4. `transition(... EVALUATING)` is then attempted from a **terminal** state
   (`DENIED`/`CONFIRMED`) → `InvalidTransitionError`.
5. Nothing catches it → FastAPI 500 → firmware correctly fails closed (red).

Evidence from the live DB — your device's real traffic:

```
esp32-atlas-demo-01-0001 … DENIED     2026-08-26T03:54
esp32-atlas-demo-01-0005 … CONFIRMED  2026-08-26T17:46
```

Any simulator restart replays `-0001`.

### Contributing defect: the tested model does not match the shipped firmware

| Artifact | transaction_id format |
|---|---|
| `atlas_device.ino:185` | `esp32-atlas-demo-01-0001` — **no boot id** |
| `firmware/virtual_device.py:186` | `esp32-atlas-demo-01-boot0001-0001` — **has boot id** |

The 30 device tests exercise the Python format, which is collision-resistant across
reboots. The **firmware's** format is not. The tested model is not the shipped artifact —
so the suite was structurally incapable of catching this.

This also means the earlier pre-flight curl checks used the *Python* ID shape and
therefore never exercised the real firmware's collision path.

### Second real defect found while investigating: TIME_WINDOW timezone

`policy/engine.py:107` — `hour = datetime.fromisoformat(transaction.timestamp).hour` —
takes the **raw hour from the timestamp**, applying no timezone conversion. The firmware
sends **UTC** (`gmtime_r`). The `odd_hours: TIME_WINDOW: [22, 6]` rule is plainly
intended as *local* night hours.

Demonstrated live, identical ₹1,500 transaction, only the hour differs:

```
2026-08-26T03:54:00+00:00  ->  STEP_UP   matched: ['odd_hours']
2026-08-26T17:46:00+00:00  ->  ALLOW     matched: []
```

03:54 UTC is **09:24 IST — mid-morning** — yet it trips "odd hours". Meanwhile 21:00 IST
(15:30 UTC) does *not*. **This is why ₹1,500 sometimes showed amber instead of green.**
The rule currently fires at systematically wrong times for a device in IST.

### Third issue: `DENY` and `STEP_UP` are indistinguishable in persisted state

`main.py` maps every non-ALLOW decision to `TxnState.DENIED`. In the DB, a STEP_UP and a
DENY are the same row value. Only the (unpersisted) response body distinguishes them.
And there is **no `FAIL_CLOSED` concept at all** in `final_status` — the device invents
that distinction locally, and the backend never records it. This is exactly the
DECISION_DENY vs FAIL_CLOSED separation Phase 2 asks for.

---

## 4. Security gap summary, ranked by exploitability

| # | Gap | Severity | Today's reality |
|---|---|---|---|
| G1 | **No device authentication** | 🔴 Critical | `curl` can submit any transaction as any subject. `device_id` is decorative |
| G2 | **No request signing (device→ATLAS)** | 🔴 Critical | Amount, beneficiary, subject all tamperable in flight. Ed25519 exists but protects only ATLAS→bank |
| G3 | **No device registry** | 🔴 Critical | No ACTIVE/SUSPENDED/REVOKED. Unknown device = silently trusted |
| G4 | **Duplicate txn_id → 500** | 🟠 High | Reproduced above. Fails closed, but crashes and is trivially DoS-able |
| G5 | **Location is an unverified string** | 🟠 High | No coordinates/accuracy/geofence. Spoofable by editing one constant |
| G6 | **TIME_WINDOW timezone bug** | 🟠 High | Wrong decisions at wrong hours, demonstrated |
| G7 | **No FAIL_CLOSED vs DENY separation** | 🟠 High | Security failure and policy refusal are indistinguishable in state + logs |
| G8 | **No replay protection device→ATLAS** | 🟠 High | Nonce/replay cache exists only on the bank hop |
| G9 | **Revocation is in-memory** | 🟡 Medium | Revoked key silently un-revokes on bank restart |
| G10 | **Private key in plaintext flash** | 🟡 Medium | Software-only; acceptable for prototype, must be labelled |
| G11 | **No firmware integrity / secure boot** | 🟡 Medium | No measurement, no anti-rollback, no attestation |
| G12 | **Tested model ≠ shipped firmware** | 🟡 Medium | Two implementations drifted; suite can't catch firmware defects |
| G13 | **No structured/correlated logging** | 🟡 Medium | Cannot audit a decision end-to-end |
| G14 | **`authentication_method` never validated** | 🟡 Medium | STEP_UP has no actual second factor |

---

## 5. What must NOT change

- ML stays an **advisor**; policy stays the deterministic authority.
- Bank keeps **final** authority; ATLAS never overrides it.
- Fail-closed everywhere: unknown/unverified ⇒ **not trusted**, never ALLOW.
- The frozen architecture (`ledger/ARCHITECTURE.md`) is not to be redesigned.
- ₹1,500 → ALLOW, ₹60,000 → STEP_UP, ₹1,50,000 → DENY must keep working.
- 152 existing tests stay green unless a test is genuinely obsolete.

---

## 6. Honest limits of this audit

- I inspected source and probed the running system. I did **not** run the Wokwi
  simulation; the ALLOW/STEP_UP/DENY LED behaviour is reported from Dhanush's manual test.
- No penetration testing against the live tunnel was performed.
- ML model quality (precision/recall) was **not** evaluated — only its plumbing.
- The `.ino` compiles; its runtime behaviour on the simulated ESP32 is verified only by
  Dhanush's manual observation, not by any automated test in this repository.
