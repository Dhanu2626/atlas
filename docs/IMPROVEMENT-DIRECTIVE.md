# IMPROVEMENT-DIRECTIVE.md — governing rules for all future ATLAS work

**Recorded 2026-08-27.** Issued by Dhanush as the authoritative instruction for every
future change to ATLAS. It exists in the repository because a fresh session otherwise has
no way to know these rules apply, and would default to ordinary "fix every limitation"
software behaviour — which is explicitly wrong for this project.

This file is a **record of the directive and the hardening history it governs**. It is
documentation. It changes no code.

---

## The one rule that matters most

> **Do not continuously invent new changes for ATLAS. Do not assume every limitation must
> be fixed. Do not modify correct behaviour just to make the project "more secure."**

The default action when a proposed improvement is unnecessary, unsupported, conflicting,
untestable, or out of scope is: **do not change it — document why.**

"This is a good security practice" is **not** a reason to change anything here. Every
proposal must map to a concrete, demonstrated ATLAS problem.

---

## Before proposing any change

Inspect first: the architecture · `docs/ATLAS-Blueprint.md` · `ledger/ARCHITECTURE.md` ·
frozen policy semantics · API contracts · data models and schema · current implementation
· existing tests *and their intent* · security invariants · threat model and documented
limitations · firmware/software protocol relationship · hardware and flash/RAM budget ·
previous checkpoints · whether the defect is already fixed · whether the limitation is
intentional, deferred, environmental, theoretical, or genuinely actionable.

Then answer: does the problem actually exist here · can it be demonstrated · does the fix
fit this architecture · does it conflict with the Blueprint or frozen semantics · does it
change an API or behavioural contract · does it weaken a security invariant · does it add
attack surface · does it fit the resource budget · can it be tested · what exactly gets
better · what could break · **is it even in scope for the current phase.**

**If any answer is uncertain: do not change the code. Report and ask.**

## Security invariants that are never weakened

Signature verification · canonical-byte verification · device authentication · replay
protection · `transaction_id` protections · monotonic counter · nonce · FAIL_CLOSED ·
DENY · tamper rejection · unknown-device rejection · policy semantics · security
boundaries.

Never weakened to make tests pass, to make a simulator restart cleanly, to make a demo
look nicer, or to make implementation simpler. **If an environmental limitation makes a
demo fail, preserve the mechanism and document the limitation.** Security degrades
explicitly and safely, never silently.

## Evidence discipline

Distinguish **PROVEN / OBSERVED / TESTED / SIMULATED / INFERRED / UNPROVEN / THEORETICAL /
DEFERRED**. Never describe an untested property as proven; software key possession as
physical-device identity; simulator behaviour as hardware proof; successful compilation as
runtime proof; or passing tests as proof of properties those tests do not establish.

## Finding classification

**A** real defect · **B** security gap · **C** reliability gap · **D** performance/resource
· **E** testing/verification gap · **F** documentation gap · **G** hardware limitation ·
**H** simulator/environment limitation · **I** intentional design decision · **J**
deferred phase item · **K** not applicable.

Only **A/B/C** normally trigger immediate engineering work. **D/E/F** may warrant targeted
work. **G/H** usually mean documentation. **I** must not change without explicit
justification. **J** stays deferred until its phase. **K** is rejected.

## Scope discipline — no change authorises an unrelated one

A canonicalization defect does not authorise policy changes. A concurrency defect does not
authorise authentication redesign. A firmware parity defect does not authorise
secure-element migration. A simulator limitation does not authorise weakening replay. A
flash limitation does not authorise removing security dependencies. A legacy endpoint does
not authorise changing the API.

## Identity model — four identities, never collapsed

`device_key_id` (which hardware signed) · `transaction_id` (which payment) · `subject`
(whose money) · `atlas_key_id` (who signed the bank assertion). A valid device signature
establishes **possession of an enrolled key** — without hardware-backed key protection it
does **not** prove physical-device genuineness.

## Verification ordering

`receive bytes → verify signature/canonical representation → establish authenticated
origin → process authenticated fields → policy evaluation`. Never reversed for
convenience. An unauthenticated `device_id` is never treated as trustworthy.

## Telemetry is evidence, not authority

Location, GNSS, IMU, device health, and tamper signals are **graded evidence**. The policy
engine holds decision authority. Any change letting telemetry directly move
ALLOW/STEP_UP/DENY is a decision-semantic change requiring explicit approval.

---

## Hardening history

Each checkpoint preserved every prior test. No existing assertion was weakened at any
point. Verified counts:

| Checkpoint | Total tests | New | Preserved |
|---|---|---|---|
| Step 8 baseline | 152 | — | — |
| Phase 2 | 181 | 29 | 152 |
| Phase 3.1-3.3 | 234 | 53 | 181 |
| F1 canonicalization | 264 | 30 | 234 |
| F2 concurrency | 285 | 21 | 264 |
| F3 firmware parity | **304** | 19 | 285 |

Two test *fixtures* were corrected — never weakened — with the reason recorded in the test
file itself:

1. **Phase 2, three TIME_WINDOW tests.** Written with `+00:00` timestamps when the engine
   read the raw offset hour. Once `user-demo-1.yaml` declared `timezone: Asia/Kolkata`, a
   UTC timestamp no longer denoted the local hour those tests claimed to check (21:59Z is
   03:29 IST, inside `odd_hours`). Fixtures corrected to `+05:30`; assertions unchanged.
2. **F3, `test_firmware_and_python_model_use_the_same_id_format`.** Pinned the literal C
   identifier `event.sequence`, which F3 renamed to `e.counter` when the RAM sequence
   became the NVS-persisted counter. The id format it protects was never violated.
   Replaced with an argument check; coverage is strictly stronger, because
   `test_f3_firmware_parity.py` now pins the full 15-argument list exactly.

### Defects found and fixed, with evidence

| Checkpoint | Defect | Evidence it was real |
|---|---|---|
| Phase 2 | Duplicate `transaction_id` → unhandled `InvalidTransitionError` → HTTP 500 | Reproduced on demand against the live service with the device's own replayed id |
| Phase 2 | Firmware RAM counter reset on restart, colliding ids | The live DB showed `esp32-atlas-demo-01-0001` already terminal |
| Phase 2 | `TIME_WINDOW` compared UTC hour against local-night rules | Same ₹1,500: `STEP_UP` at 03:54Z (09:24 IST, morning), `ALLOW` at 17:46Z |
| Phase 2 | DENY and FAIL_CLOSED indistinguishable | `TxnState.DENIED` covered DENY, STEP_UP and DELAY; no FAIL_CLOSED existed |
| Phase 3.3 | Sparse device serialisation vs pydantic defaults | Every signature failed until the device emitted all 15 fields |
| F1 | `float` in signed bytes | Python emits `12.9716` where C `printf("%.6f")` emits `12.971600` |
| F2 | SQLite thread affinity | `sqlite3.ProgrammingError` in the server log; 6/4/6 `INTERNAL_ERROR` per 10 concurrent requests |
| F2 | `check_same_thread=False` alone is not thread-safe | Shared store produced `InterfaceError` and a corrupted read |
| F2 | Three check-then-act races | Structural: read → decide → write across separate calls |
| F3 | `.ino` sent 9 of 15 fields, unsigned, to the legacy endpoint | Source inspection |

### Mutation testing — scope stated honestly

Mutation testing here demonstrates **detection capability for the specific mutations
tried**. It does not prove the absence of defects.

| Mutation | Result |
|---|---|
| Expiry check `>=` → `>` | Caught — boundary test |
| Device whitelist → substring match (`"ALLOW" in status`) | Caught — `ALLOWED` lit green |
| Signature failures ignored | Caught — 10 tests |
| `LocationEvidence` reverted to `float` | Caught — 12 tests |
| Firmware omits one default field | Caught — 4 tests |
| `claim_counter` non-atomic (no delay) | **NOT caught** — window too narrow under the GIL |
| `claim_counter` non-atomic (2 ms window) | Caught — 3 tests |

The sixth row is the important one: **F2's atomicity guarantee rests on the structural
argument, not on the tests.** A concurrency test that fails to reproduce a race does not
prove the implementation is safe.

---

## The six F3 limitations

As recorded at F3 (2026-08-27). Reproduced in `HANDOFF.md` with the same classifications,
where their current standing is kept: limitation 1 was closed on 2026-09-02 and
limitation 6 on 2026-09-18. **None are class A/B/C, so under the classification rules
none warrant immediate engineering work.**

1. Runtime/Wokwi round-trip not proven — **E**
2. Private key seed in plaintext flash — **G**
3. `firmware-config` exports the seed — **I**
4. Wokwi NVS persistence not guaranteed — **H**
5. 89% flash utilisation — **D**
6. Legacy `POST /transact` open by default — **J**, Phase 3.8

## Threats: closed by software vs. hardware-dependent

**Addressed by the current software/firmware layer:** forged `device_id` · modified signed
fields · signature stripping · replay · unknown device keys · transaction/subject misuse ·
counter regression · concurrency-related security races.

**Hardware-dependent, and NOT closed:** private-key extraction from ordinary flash ·
stolen device/key cloning · firmware modification · secure-boot bypass · physical
tampering · GNSS spoofing · rollback resistance · hardware root of trust.

Do not mark a hardware-dependent threat closed because software authentication exists.

---

## Required reports

**Before** a change (§20 of the directive): finding · evidence · classification · current
implementation · why it matters · security/reliability/resource impact · Blueprint
compatibility · existing-test impact · proposed change · alternatives · why this one ·
what will deliberately not change · new tests · tests that must stay untouched ·
regression risk · reversibility · whether approval is required.

**Stop for approval** if the change touches architecture, policy semantics, thresholds,
decision logic, the authentication or identity model, API compatibility, replay semantics,
the hardware trust model, or key lifecycle.

**After** a change: full suite · new tests · mutation testing where applicable · confirm
no test was weakened · confirm no invariant changed unintentionally · API compatibility ·
firmware compilation if touched · resource usage · before/after behaviour · limitations ·
what is proven vs. unproven · `git diff` · `git status` · **do not commit unless
explicitly instructed.**

Work stops at checkpoints and waits for approval. It does not roll into the next phase.
