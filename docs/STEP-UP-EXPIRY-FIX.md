# Pre-change report: step-up payments can get stuck in `AWAITING_STEP_UP`

**Status: APPROVED and IMPLEMENTED 2026-09-16.** After-change report: §20. Nothing committed.

His decisions (§19):
1. Approved, with case E included.
2. The cleanup runs regardless of `ATLAS_ENABLE_STEP_UP`.
3. If the cleanup fails, log it and keep starting.
4. Finding D is documented now and decided later.

Written in the format `docs/IMPROVEMENT-DIRECTIVE.md` requires before a change
("Required reports"). The feature this report is about is described in
`docs/STEP-UP-PROPOSAL.md`.

---

## 1. Finding

When a customer never answers a step-up challenge, the payment is supposed to end
in `DENIED`. It does not. It stays in `AWAITING_STEP_UP` indefinitely.

The cleanup written for this, `expire_stale()`, is never called. Worse, if it
were called as written, it would make the problem permanent: it closes the
*challenge* but never moves the *transaction*, and once the challenge is closed no
later request can move the transaction either.

A second route to the same stuck state exists. If the service stops between its
two separate database writes after a good proof, the transaction is also left
behind for good.

## 2. Evidence

**Reproduced 2026-09-16 02:22 IST** through the real HTTP path, with every store in
a temporary directory, wired exactly like the `e2e` fixture in
`tests/test_step_up.py`. No real database, key or registry was touched. (The reproduction script was a
throwaway and is not committed; each scenario below became a permanent test
instead.)

| # | Scenario | Result |
|---|---|---|
| A | Challenge expires, nobody redeems, nothing calls `expire_stale()` | transaction stays **`AWAITING_STEP_UP`** |
| B | Same, then `expire_stale()` is called (what a startup cleanup would do) | challenge closed (`consumed=1`, outcome `DENY`); transaction still **`AWAITING_STEP_UP`**. A later redemption with a **valid** proof gets `FAIL_CLOSED` / `UNKNOWN_CHALLENGE`, and the transaction **stays `AWAITING_STEP_UP`**. No code path can move it after that. |
| C | Expired but not swept, then redeemed with a valid proof | `DENY` (`EXPIRED`), transaction **`DENIED`**. Correct: the check at redemption time works. |
| D | Live challenge; request names the **wrong** `transaction_id`, proof is junk | `DENY` (`BINDING_MISMATCH`), and the **real** pending transaction becomes **`DENIED`**. Separate finding, see §18. |
| E | Service stops between `consume()` and `transition()` after a good proof, then the customer retries | `FAIL_CLOSED` / `UNKNOWN_CHALLENGE`, transaction **stuck in `AWAITING_STEP_UP`** |

**Observed on this machine (live databases, read-only, 2026-09-16):** 138
transactions: 84 `CONFIRMED`, 53 `DENIED`, **1 `AWAITING_STEP_UP`**. That one is
`esp32-atlas-fw-10-803e2d6a-0001` (₹60,000, the Wokwi run of 11 Sep, 22:22 IST).
Its challenge expired two minutes later, with `consumed=0` and `attempt_count=0`,
and it has been stuck since.

## 3. Classification

- **A: real defect.** The code doesn't do what its own docstrings and the design
  record say ("Every expired challenge resolves to DENIED", `service.py:193`;
  "A restart resolves these by expiry", `state_machine.py:61`). Cases A, B and E.
- **E: testing gap.** `test_expired_challenge_is_swept_to_denied` checks only the
  challenge. Its name promises the transaction.
- **F: documentation gap.** `docs/STEP-UP-PROPOSAL.md` says IMPLEMENTED with no
  known-issue note. `RUNBOOK.md` §9 doesn't say what happens to unanswered
  challenges.
- **Not B.** No stuck transaction can be approved. Redeeming an expired challenge
  returns `EXPIRED`, so the resolver denies it (case C). A closed challenge refuses
  everything (cases B and E).

## 4. Current implementation

| Where | What it does today |
|---|---|
| `atlas_service/main.py:153-156` | `_lifespan` only publishes the public key; no step-up cleanup at startup |
| `atlas_service/step_up/service.py:192-201` | `expire_stale(store, now)` gets only the step-up store: it consumes expired challenges and **cannot** touch the transaction |
| `atlas_service/step_up/db.py:170-177` | `find_unconsumed_expired()`, used only by `expire_stale()` |
| `atlas_service/state_machine.py:59-62` | `NEEDS_STEP_UP_EXPIRY = {AWAITING_STEP_UP}` — "A restart resolves these by expiry". **Referenced nowhere.** |
| `atlas_service/db.py:107-116` | `TransactionStore.find_in_states()` — "Used on restart". The natural lookup for the line above; unused for step-up |
| `atlas_service/main.py:647-654` | `/v2/step-up` returns early, with no state change, for an unknown **or already consumed** challenge (deliberately identical, so it can't be used as an oracle) |
| `atlas_service/main.py:681-695` | non-ALLOW outcomes: `EXPIRED`, `ATTEMPTS_EXHAUSTED`, `BINDING_MISMATCH` consume the challenge and move `AWAITING_STEP_UP → DENIED` |
| `atlas_service/main.py:697-704` | success: `consume(ALLOW)` then `transition(ALLOWED)`. These are two writes to two separate databases, which is the window in case E |
| `tests/test_step_up.py:350-363` | the test that asserts only the challenge |

`expire_stale` appears only at `service.py:192` and in that one test (grep-verified).

## 5. Why it matters

- **The stored state is wrong.** A payment that can never be approved is recorded as
  still pending. Anything that reads state is misled: the Step 9 dashboard,
  reports, and the Wokwi verification itself.
- **The code promises a guarantee it doesn't keep**, in three docstrings and the
  design record.
- **Publishing the step-up work** with this unfixed and undocumented would break the
  rule that documentation must describe reality.

## 6. Security, reliability and resource impact

- **Security:** no weakness today (§3), and the fix only ever moves a transaction
  to `DENIED`. It adds no request path and no new input.
- **Reliability:** fixes cases A, B and E.
- **Resources:** one lookup per `AWAITING_STEP_UP` transaction at startup. Nothing
  changes on the request path.

## 7. Blueprint and design-record compatibility

- `STEP-UP-PROPOSAL.md` §4 specifies *"Crash while `AWAITING_STEP_UP` → reconciler
  finds it; expired → `DENIED`"*. §7 adds *"checked at redemption and by the
  reconciler"*. The fix implements that intent at startup. It doesn't involve the
  bank reconciler, which matches `state_machine.py:27-30` ("must never be
  reconciled against the bank").
- **No new state and no new transition.** `AWAITING_STEP_UP → DENIED` is already in
  `VALID_TRANSITIONS`.
- **No API change.** No endpoint, request field or response field changes.
- The frozen lifecycle in `ledger/ARCHITECTURE.md` is untouched beyond the addition
  already approved on 2026-09-11.

## 8. Existing-test impact

- All **338** tests must still pass.
- No existing test runs the startup hook: there is no `with TestClient(...)` anywhere
  in `tests/`, so a startup call cannot affect them.
- **One test changes:** `test_expired_challenge_is_swept_to_denied` is
  **strengthened**. Every current assertion stays, a transaction store is added,
  and it now also asserts the transaction is `DENIED`. The reason is recorded in the
  test, the same practice as the two fixture corrections listed in
  `IMPROVEMENT-DIRECTIVE.md`.

## 9. Proposed change

1. **Make `expire_stale()` the restart cleanup it claims to be.** New signature:
   `expire_stale(step_up_store, txn_store, now)`. It:
   - finds transactions in `NEEDS_STEP_UP_EXPIRY` with `txn_store.find_in_states()`;
   - looks up each one's challenge (new one-line store query,
     `get_challenge_for_transaction()`);
   - **challenge live and unanswered:** leaves it alone, since the customer may
     still answer;
   - **challenge expired and unanswered:** consumes it as `DENY` (atomically, and
     only if this call wins), then moves the transaction to `DENIED`;
   - **challenge already consumed but the transaction never moved** (case E): moves
     it to `DENIED`;
   - **no challenge row at all** (the two databases disagree): moves it to
     `DENIED`, because anything unexpected fails closed;
   - writes an audit event with the reason for every transaction it resolves.

   **No branch produces `ALLOWED`, signs anything, or contacts the bank.**
2. **Call it once at startup**, from `_lifespan`, before the service accepts
   requests. It goes through a small wrapper that does nothing if either database
   file doesn't exist yet, so a machine that never used step-up gets no new file
   and no change. It runs whether or not `ATLAS_ENABLE_STEP_UP` is set (decision
   2). If the cleanup itself fails, it logs loudly and startup continues
   (decision 3).
3. **Remove `find_unconsumed_expired()`**, whose only caller is replaced.
4. **Docs:**
   - `STEP-UP-PROPOSAL.md`: status header with the defect, the fix and the
     verification status, including Wokwi **7 of 10**.
   - `RUNBOOK.md` §9: what happens to unanswered challenges, and the limitation
     below.
   - `HANDOFF.md`.
   - One sentence in `main.py`'s module docstring, which still says STEP_UP always
     lands in `DENIED`.

**Limitation kept on purpose:** while the service keeps running, an unanswered
payment shows `AWAITING_STEP_UP` until the next start, or until someone tries to
redeem it, which returns DENY and records `DENIED` (case C). There is no
background timer, following Dhanush's rule against scheduled dependencies.

## 10. Alternatives considered

| Alternative | Verdict |
|---|---|
| Call the existing `expire_stale()` at startup as-is | **Rejected.** Case B shows it turns a recoverable state into a permanent one |
| Background timer that sweeps every N seconds | **Rejected.** It is a scheduled dependency, and it would race a customer answering: case E's repair is unsafe while a request is in flight |
| Sweep at the start of every `/v2/transact` or `/v2/step-up` request | **Rejected.** It touches the main decision path, which his rules say not to do unless required, and has the same in-flight race |
| Treat an expired `AWAITING_STEP_UP` as DENIED only when read | **Rejected.** The stored state stays wrong, and every reader must remember the rule |
| Let `/reconcile/{id}` settle `AWAITING_STEP_UP` on demand | **Not now.** The state machine deliberately keeps it apart from bank reconciliation; could be added later if the dashboard needs it |

## 11. Why this one

- It connects two pieces that were built for exactly this and never wired up:
  `NEEDS_STEP_UP_EXPIRY` and `find_in_states()`.
- It runs **before** the service accepts requests, so it can never race a customer
  answering.
- It adds no timer and doesn't touch `/v2/transact`, `/v2/step-up` or the resolver.
- It only ever fails closed.

## 12. What will deliberately NOT change

- `atlas_service/step_up/resolver.py`: bounded re-resolution is untouched.
- `/v2/step-up` logic, including the early return and its oracle resistance.
- `/v2/transact`, ML, the policy engine, thresholds, the signed canonical template,
  firmware, `AssertionPayload`, `bank_service`.
- The state machine's transition table.
- The 120 s expiry, the 3-attempt budget, and single-use challenges.
- `ATLAS_ENABLE_STEP_UP` stays OFF by default.
- Finding D (§18), unless approved separately.
- A crash during *evaluation* can leave a transaction in `EVALUATING`. That is a
  general, older issue not specific to step-up, and is out of scope here.

## 13. New tests

1. **Strengthened:** `test_expired_challenge_is_swept_to_denied` now also asserts
   the transaction ends `DENIED`.
2. A **live** challenge is left alone by the cleanup, and a valid proof afterwards
   still reaches `ALLOW` / `CONFIRMED` over HTTP.
3. **Case E:** a consumed-but-unadvanced transaction goes to `DENIED`, never
   `ALLOWED`.
4. **No challenge row:** the transaction goes to `DENIED`.
5. **Exhaustive sweep:** every combination of consumed yes/no × outcome
   none/ALLOW/DENY × expired yes/no × row present/absent ends in either
   `AWAITING_STEP_UP` (only when live and unanswered) or `DENIED`. Never anything
   else.
6. Transactions **not** in `AWAITING_STEP_UP` are ignored, including `CONFIRMED`
   ones with consumed challenges, like the 5 on this machine.
7. **Never used:** if the step-up database doesn't exist, the cleanup returns
   nothing and **creates no file**.
8. **Idempotent:** a second run changes nothing.
9. **Structural:** `_lifespan` calls the cleanup (source check, same style as the
   existing structural guards).
10. **HTTP:** redeeming an expired challenge ends `DENIED` (case C, currently
    untested).
11. **HTTP:** after the cleanup, a late valid proof can't produce ALLOW and the
    state stays `DENIED`.

**Mutation checks after implementation, reported:** changing the cleanup's target
to `ALLOWED` must fail test 5, and removing the transition must fail test 1.

## 14. Tests that must stay untouched

All resolver tests: the exhaustive sweep, the "no recompute" structural guard, the
DENY-guard mutation test and the clock test. Also every HTTP step-up test, and all
other suites.

## 15. Regression risk

**Low.** The only new behaviour is `AWAITING_STEP_UP → DENIED`, once, at startup.

- **Moving a live payment by mistake:** covered by test 2, which proves a live one
  still completes.
- **Startup failure:** handled by log-and-continue (decision 3).
- **Several worker processes sharing the databases:** not used today, since
  `run_sim.py` and `run_dev.py` start one uvicorn process each. If that ever
  changes, case E's repair must be revisited, because it could fail a payment
  another worker is completing.

## 16. Reversibility, and what it changes on this machine

*The transaction id below is a public identifier, not a credential; no key
material appears in this report. See `HANDOFF.md` for the distinction.*

- **Code:** a plain revert.
- **Data:** on the first start after the fix, **exactly one transaction changes.**
  `esp32-atlas-fw-10-803e2d6a-0001` moves `AWAITING_STEP_UP → DENIED`, and its
  challenge closes with outcome `DENY`. The other 137 are already terminal, and the
  5 other challenges belong to `CONFIRMED` payments, so nothing else moves.
  `DENIED` is terminal, so this one change is permanent. It is also the correct
  outcome: that challenge expired on 11 Sep and can never be approved.

## 17. Approval required

**Yes.** It changes how a transaction-lifecycle state is resolved on restart, which
is one of the "stop for approval" categories.

---

## 18. Separate finding, NOT part of this fix: a wrong `transaction_id` cancels a live step-up

**Evidence:** case D in §2.

**Cause:** `authenticate()` returns `BINDING_MISMATCH` together with the challenge's
real context. `/v2/step-up` then treats it like `EXPIRED` and `ATTEMPTS_EXHAUSTED`:
it consumes the challenge and moves the real transaction to `DENIED`
(`main.py:690-693`). The comment there mentions only "exhausted or expired".

**Impact:** anyone who knows a live `challenge_id` can cancel that customer's
pending payment with **one** request, without a valid proof and without knowing the
`transaction_id`. Nothing can be *approved* this way. The same cancellation is
already possible, by design, with three junk proofs plus the `transaction_id`. Both
ids are shown on the device and sent over plain HTTP in this prototype.
`STEP-UP-PROPOSAL.md` §4 said a mismatch is "rejected, audited as a security event".
It did not say the payment is cancelled.

**Classification:** B, low. It can deny, never approve.

**Recommendation:** don't bundle it into this fix (scope discipline). Record it in
`HANDOFF.md` now, and decide separately whether a mismatch should count as one
failed attempt instead of an instant cancellation.

---

## 19. Decisions needed from Dhanush

1. **Approve the fix in §9?** Recommended, with case E included.
2. **Run the startup cleanup even when `ATLAS_ENABLE_STEP_UP` is off?** Recommended:
   yes. Only leftovers from earlier step-up use are touched, and they can't be
   redeemed while the flag is off anyway.
3. **If the cleanup fails at startup: log and keep starting, or refuse to start?**
   Recommended: log and keep starting. Redemption still denies expired challenges,
   so nothing unsafe happens while the stored state waits for the next start.
4. **Finding D:** document now and decide later (recommended), or fix it next as its
   own change?

After approval, the order is: implement → full suite → new tests → mutation checks
→ docs → after-change report → **stop**. Publishing to GitHub is a separate step
with its own review of the diff.

---

## 20. After-change report (2026-09-16)

**Full suite: 351 passed** (was 338), 134 s. Firmware was not touched, so no compile was
needed.

### What changed

| File | Change |
|---|---|
| `atlas_service/step_up/service.py` | `expire_stale(step_up_store, txn_store, now)` rewritten as described in §9 |
| `atlas_service/step_up/db.py` | `get_challenge_for_transaction()` added; `find_unconsumed_expired()` removed |
| `atlas_service/main.py` | `resolve_stale_step_ups()` added and called from `_lifespan` (log and continue on failure); module docstring updated |
| `tests/test_step_up.py` | 1 test strengthened, 13 added (30 → 43) |
| `RUNBOOK.md` §9 | "If nobody answers" and "Known behaviour, not yet decided" |
| `docs/STEP-UP-PROPOSAL.md` | corrections block and three table notes |
| `HANDOFF.md` | status brought up to date |

Unchanged, as §12 promised:
- the resolver
- `/v2/step-up` and `/v2/transact`
- ML, policy and thresholds
- the signed canonical template, firmware, `AssertionPayload` and `bank_service`
- the state machine's transition table
- the 120 s expiry and the 3-attempt budget

### Tests compared with the plan in §13

Every planned test was written. There are three deliberate differences:

- **Test 9 is behavioural instead of a source check.** It starts the real app lifespan
  against `tmp_path`, with key publishing stubbed out. That is stronger, because it
  proves the call actually happens rather than that the text exists.
- **Three tests were added:**
  - a structural guard that the cleanup's source never reaches for `ALLOWED`, signing
    or the bank;
  - a test that a lost `consume()` race is not overridden;
  - a test that the service still starts when the cleanup raises (decision 3).

**No test was weakened.** The only change to an existing test is the strengthened
`test_expired_challenge_is_swept_to_denied`: every original assertion stays, and one
was added.

### Mutation checks: 10 of 10 caught

Every mutated file was restored byte-for-byte, verified by SHA-256. The mutation
driver was a throwaway and is not committed.

| Mutation | Caught by |
|---|---|
| M1 cleanup moves the payment to `ALLOWED` | 8 tests, including the structural guard and the exhaustive sweep |
| M2 the original defect: challenge closed, payment never moved | 7 tests, including the strengthened test |
| M3 case E not handled | case-E test, exhaustive sweep |
| M4 live challenges treated as expired | live-challenge test, exhaustive sweep |
| M5 a lost `consume()` race is overridden | lost-race test |
| M6 a payment with no challenge is left waiting | missing-challenge test, exhaustive sweep |
| M7 startup never calls the cleanup | startup test |
| M8 cleanup creates files when step-up was never used | never-used test |
| M9 cleanup runs only when the flag is on | startup test (flag deliberately unset) |
| M10 a failing cleanup stops startup | startup-failure test |

### Before and after

| Case | Before (§2) | After |
|---|---|---|
| A: expired, never redeemed | stuck in `AWAITING_STEP_UP` | settled to `DENIED` at the next start |
| B: cleanup, then a valid proof | stuck forever | `DENIED`; a late valid proof changes nothing |
| C: expired, then redeemed | `DENIED` | `DENIED`, unchanged and now pinned by a test |
| D: wrong `transaction_id` | real payment `DENIED` | **unchanged**; open decision (§18) |
| E: crash between the two writes | stuck forever | settled to `DENIED` at the next start |

**Dry run on copies of this machine's databases.** The real files were not touched:
their SHA-256 was identical before and after.

| | Transactions |
|---|---|
| Before | 84 `CONFIRMED` · 53 `DENIED` · 1 `AWAITING_STEP_UP` |
| After | 84 `CONFIRMED` · 54 `DENIED` |

- **Changed:** only `esp32-atlas-fw-10-803e2d6a-0001`, `AWAITING_STEP_UP → DENIED`.
- Its challenge is now consumed, with outcome `DENY` and 0 attempts.
- Audit event: `RESOLVED_ON_RESTART reason=EXPIRED state=DENIED`.
- The other 5 challenges are still consumed as `ALLOW`, and their payments are still
  `CONFIRMED`.
- A second run changed nothing.

### Proven and unproven

- **TESTED:**
  - all five cases above;
  - both approved decisions: the cleanup runs with the flag unset, and startup continues
    if it fails;
  - idempotency, and that nothing is created when step-up was never used;
  - that the cleanup never approves.
- **OBSERVED:** the dry run on copies of the real databases.
- **NOT YET OBSERVED:** the cleanup inside a real `run_sim.py` or uvicorn start. The tests
  drive the same ASGI lifespan through Starlette's `TestClient`. The first real start
  will make the one change shown above in the real database.
- **STILL UNPROVEN, unrelated to this fix:** authentication success → ALLOW → CONFIRMED
  on a challenge issued to the real firmware in Wokwi.

### Limitations that remain

- While the service keeps running, an unanswered payment shows `AWAITING_STEP_UP` until
  the next start or a redemption attempt. There is no timer, by design.
- Several worker processes sharing the databases would need case E's repair revisited.
  That setup is not used today.
- Finding D is still open (§18).

### Repository state

`git status`: 21 entries (11 modified, 10 untracked), and HEAD is still `e22a690`.
**Nothing committed.**
