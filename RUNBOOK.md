# ATLAS runbook — start, run, stop, test

Operational companion to `HANDOFF.md` (which records *why* things are the way
they are). Sections 0-8 were verified by running them on 2026-09-09. Section 9
(step-up) was added on 2026-09-11, and its restart-cleanup behaviour was
verified on 2026-09-16.

Nothing in this document depends on the date, on your current IP address, on a
public tunnel, or on a URL that expires. That is deliberate: the previous setup
depended on all four and broke repeatedly.

---

## 0. One-time setup

| Need | How |
|---|---|
| Python deps | `.venv` at the repo root, already provisioned |
| ESP32 toolchain | `arduino-cli` + core `esp32:esp32` + ArduinoJson 7.x |
| Wokwi VS Code extension | installed (verified: `wokwi.wokwi-vscode-3.7.0`) |
| Wokwi IoT gateway | `wokwigw` from <https://github.com/wokwi/wokwigw/releases>, on PATH or at `~/.wokwi/wokwigw.exe` |
| Device identity | `firmware/atlas_device/secrets.h` — see §4 |

**Wokwi plan requirement.** Wokwi documents the *local/private* IoT gateway as a
paid feature, and the free tier's shared cloud gateway cannot reach your machine.
It was **verified working on 2026-09-11** from the VS Code extension, on an
account the simulator labels *Community License*. If your plan does not include
it, see §7 for the fallback — and note the fallback is strictly worse, not
equivalent.

---

## 1. Start (normal, every time)

```bash
python scripts/run_sim.py
```

That single command starts, all on **loopback only**:

| Port | Process |
|---|---|
| `127.0.0.1:8000` | `atlas_service` |
| `127.0.0.1:8100` | `bank_service` |
| `127.0.0.1:9011` | `wokwigw` gateway |

It also sets, **for those child processes only**:

* `ATLAS_SIMULATION_ALLOW_COUNTER_RESET=1` — see §5
* `ATLAS_REQUIRE_DEVICE_AUTH=1` — closes the legacy unsigned `/transact`

Use `--no-gateway` if you are already running `wokwigw` yourself.

**For anything that is not the simulator, use `scripts/run_dev.py` instead.**
It sets neither variable. That separation is the whole point: production-like
runs cannot inherit the simulation accommodation by forgetting an argument.

## 2. Run the simulation

1. Open VS Code on the folder **`firmware/atlas_device`** (the extension looks
   for `wokwi.toml` at the workspace root).
2. `Ctrl+Shift+P` → **Wokwi: Start Simulator**.
3. Wait for `[DEVICE] Ready` in the serial pane.
4. **SELECT** cycles the preset — amber blinks 1x / 2x / 3x.
5. **SEND** submits.
6. Read the decision trace; the LED shows GREEN / YELLOW / RED.

No file needs editing between runs. No URL needs regenerating.

## 3. Stop

`Ctrl+C` in the `run_sim.py` terminal stops all three processes. If something
is orphaned:

```bash
taskkill /F /IM wokwigw.exe
```

---

## 4. Where secrets live — and where they must never live

| | |
|---|---|
| **Device seed belongs in** | `firmware/atlas_device/secrets.h` — gitignored |
| **Device private key belongs in** | `firmware/device_keys_<name>/` — gitignored |
| **Never** | `atlas_device.ino`, `wokwi.toml`, `secrets.example.h`, any tracked file, any commit message, any screenshot |

`build/` is also gitignored, because the compiled image **contains the seed**.
Treat a built `.bin`/`.elf` as secret.

### Provisioning a device

```bash
python scripts/provision_device.py enroll --device-id esp32-atlas-fw-NN --subject user-demo-1 --keys-dir firmware/device_keys_fwNN
```

```bash
python scripts/provision_device.py firmware-config --device-id esp32-atlas-fw-NN --keys-dir firmware/device_keys_fwNN
```

The second command **prints a private key seed**. Copy `secrets.example.h` to
`secrets.h` and paste the values there — never into the sketch. Then recompile:

```bash
arduino-cli compile --fqbn esp32:esp32:esp32doit-devkit-v1 --output-dir build firmware/atlas_device
```

Revocation is **terminal**. A revoked device can never be reactivated; enrol a
new one. Re-enrolling an existing device id is refused by design — silently
replacing an enrolled key is an account-takeover primitive.

---

## 5. Why the simulator may reset its counter, and why that is safe

The ESP32's anti-replay counter lives in NVS flash. Wokwi does not reliably
persist NVS between sessions, so a restarted simulation sends `counter=1` while
`atlas_service` remembers a higher value. Rejecting that is the replay check
**working**, not failing.

`ATLAS_SIMULATION_ALLOW_COUNTER_RESET=1` is the narrow, audited accommodation.
It accepts a lower counter **only** when the envelope carries a `boot_id`
different from the last one recorded — and `boot_id` is the first field of the
signed canonical bytes, so it cannot be attached to a captured envelope.

What is still fully enforced, with or without the flag:

| Layer | Status |
|---|---|
| Ed25519 signature over every field but the signature | enforced |
| Device registry standing (ACTIVE / REVOKED) | enforced |
| Subject binding | enforced |
| Freshness (5 min clock skew) | enforced |
| **Nonce** | enforced, unconditionally |
| **transaction_id** | enforced, unconditionally (`claim_new`) |
| Same-boot counter regression | **still rejected** |

Replay protection degrades from three independent layers to two. Never to zero,
and never for a real device — real hardware persists its counter and never
takes this path. Every acceptance writes a `device_events` audit row reading
`simulation_mode=true boot_id=... got=... last=...`.

**Verified by execution on 2026-09-09**, against a live service, on a throwaway
device (so the demo device's counter was untouched):

| Case | Result |
|---|---|
| first run, boot A, counter=1 | ALLOW |
| normal increment, boot A, counter=2 | ALLOW |
| **restart**, boot B, counter=1 | ALLOW (simulation reset) |
| normal increment, boot B, counter=5 | ALLOW |
| **same-boot regression**, boot B, counter=3 | `COUNTER_REGRESSION` |
| tampered amount | `INVALID_DEVICE_SIGNATURE` |
| reused nonce, higher counter, re-signed | `REPLAYED_NONCE` |
| duplicate transaction_id, fresh counter | `DUPLICATE_TRANSACTION_ID` |
| **verbatim replay** of the first envelope | `REPLAYED_NONCE` |

One ordering detail worth knowing: for a true replay the **counter** layer
usually fires before the `transaction_id` layer, because envelope verification
runs before the decision pipeline. `transaction_id` is therefore reachable as a
distinct rejection only when the counter is fresh but the id repeats — a client
generating colliding ids rather than a replay. It is defence in depth, not the
primary replay gate.

---

## 6. How Wokwi reaches a service on `127.0.0.1`

```
VS Code
  └─ Wokwi extension (simulates locally)
       └─ wokwigw on ws://localhost:9011
            └─ DNS zone "wokwi.internal." : host -> 10.13.37.254
                 └─ NAT 10.13.37.254 -> 127.0.0.1
                      └─ atlas_service on 127.0.0.1:8000
```

Those constants are from wokwigw's own `cmd/wokwigw/config.go`, not inferred.
The firmware targets `http://host.wokwi.internal:8000`, and `wokwi.toml`
declares `[net] gateway = "ws://localhost:9011"`.

Consequences that matter for long-term use:

* `atlas_service` stays bound to `127.0.0.1` — never `0.0.0.0`, never a LAN IP
* nothing is exposed to the internet
* no URL to regenerate, nothing to expire, no provider to rate-limit
* changing Wi-Fi network or DHCP lease changes nothing

## 7. Why `wokwi-cli` is NOT the gateway path

`wokwi-cli` simulates **on Wokwi's servers** — it prints `Connected to Wokwi
Simulation API` and requires `WOKWI_CLI_TOKEN`. It has no gateway option, and
`ws://localhost:9011` inside it would mean *Wokwi's* localhost, not yours.

Verified 2026-09-09: a `wokwi-cli` run against this project produced no serial
output, the local gateway logged no connection, and `atlas_service` recorded
**0** `/v2/transact` requests.

So `wokwi-cli` can only reach ATLAS through a public tunnel. That is the
fallback, and it is worse in every way that matters: the URL changes, free
providers rate-limit it, and while it runs ATLAS is exposed to the internet with
**no authentication of any kind**. Use it only if the private gateway is
unavailable, and stop the tunnel the moment the demo ends.

---

## 8. Tests

```bash
.venv/Scripts/python.exe -m pytest -q
```

Tests are isolated from your live state: they override the device store,
transaction store, bank client and signing keys with `tmp_path` fixtures, so
they neither read nor modify `atlas_service/*.db` or any real key directory.

---

## 9. Step-up authentication (OFF by default)

A STEP_UP verdict used to be a dead end: it landed in `DENIED`, which is
terminal. Now it can pause in `AWAITING_STEP_UP` while the customer confirms
out of band.

**It ships dormant.** `run_sim.py` and `run_dev.py` both leave
`ATLAS_ENABLE_STEP_UP` unset, so behaviour is unchanged until you opt in:

```bash
ATLAS_ENABLE_STEP_UP=1 python scripts/run_sim.py
```

### One-time: enrol an authenticator

```bash
python scripts/enroll_authenticator.py enroll --subject user-demo-1
```

ATLAS stores the **public** key only. It never receives a PIN, an OTP secret or
a biometric, so it cannot leak one.

### Redeeming a challenge

A STEP_UP response now carries `challenge_id` and `step_up_expires_at`, and the
device displays them. To confirm:

```bash
python scripts/enroll_authenticator.py sign --challenge-id <id> --transaction-id <id> --envelope-hash <hex>
```

then POST that proof to `/v2/step-up` with the challenge and transaction ids.

### The rule that makes it safe

Bounded re-resolution is a **pure function of the frozen context plus the
authentication result**. It re-runs neither ML nor the policy engine, and reads
no clock. A successful step-up can therefore never turn a DENY into an ALLOW,
and a confirmation at 06:01 resolves exactly as it would have at 23:58.

Limits: 120s expiry, 3 attempts per challenge, one challenge per transaction,
single-use. Anything unexpected resolves to DENY.

### If nobody answers

A challenge not redeemed within 120s can never be approved:

- **Redeemed late:** the proof is refused (`EXPIRED`) and the payment ends `DENIED`.
- **Never redeemed:** the payment stays `AWAITING_STEP_UP` while the service keeps
  running, and is settled to `DENIED` the next time `atlas_service` starts.

How the startup cleanup behaves:
- It runs once, before the service accepts requests, whether or not
  `ATLAS_ENABLE_STEP_UP` is set.
- It never approves anything, and it leaves a still-live challenge alone.
- If step-up was never used on this machine, it does nothing and creates no file.
- If the cleanup itself fails, the error is logged and the service starts anyway.

There is deliberately **no background timer**. To see what it did, look for
`event=step_up_resolved_on_restart` in the service log and `RESOLVED_ON_RESTART`
in `step_up_events`. Background: `docs/STEP-UP-EXPIRY-FIX.md`.

### Known behaviour, not yet decided

A `/v2/step-up` request naming a live `challenge_id` with the **wrong**
`transaction_id` cancels that pending payment (`BINDING_MISMATCH` → `DENIED`), even
without a valid proof. It can never approve anything. Recorded in
`docs/STEP-UP-EXPIRY-FIX.md` §18. Whether a mismatch should count as one failed
attempt instead is an open decision.
