# firmware/ — the ATLAS edge device (Step 8, F3, and the 2026-09-02 clock fix)

## What is actually verified, and what is not

Three different things get confused easily, so they are separated here:
**tested** (an automated test executes it) · **compiles** (the toolchain
builds it, which says nothing about runtime) · **executed** (it has actually
run). Nothing below claims more than it has.

| Artifact | Status |
|---|---|
| `virtual_device.py` | **Tested.** 30 tests in `tests/test_virtual_device.py`, run against the real `atlas_service` + `bank_service` |
| `atlas_device/atlas_device.ino` | **EXECUTED and verified, 2026-09-01/02.** Builds with `arduino-cli` (ESP32 core 3.3.11): 1,176,472 B = 89% flash from `secrets.example.h`, built on 2026-09-18 by the opt-in `test_the_sketch_compiles`; a provisioned `secrets.h` changes a few bytes of string length (1,176,488 B). RAM was last recorded at 51,248 B = 15%. The earlier 1,168,848 B figure predates the clock fix and the decision-trace display. Canonical template pinned byte-for-byte by `tests/test_f3_firmware_parity.py`. **It has now run in Wokwi**: on-device libsodium signatures verify against the backend, the NVS counter advances, and all three decision branches (ALLOW / STEP_UP / DENY) were observed. NTP formatting was verified *and found defective* — fixed, see "The device clock" below |
| `atlas_device/diagram.json` | **Verified.** Its five GPIO pins are checked against the `.ino` by test, and the circuit has now been simulated end to end. Drawn as the [main circuit diagram](../docs/hardware/atlas-schematic.svg) |
| `atlas_device/wokwi.toml` | **Verified.** `arduino-cli compile --output-dir build` produces exactly the `build/atlas_device.ino.bin` and `.elf` it names, and `wokwi-cli` simulates them |
| `atlas_device/libraries.txt` | Web-IDE path only; ArduinoJson **7.x** required. libsodium is **not** listed because it ships inside ESP32 core 3.3.11 rather than as an external library. For local builds use `arduino-cli lib install "ArduinoJson@7.2.0"` instead |

**Compiling is not running** — and that distinction earned its keep. Until
2026-09-01 nothing here had been executed, and the moment it was, running it
immediately exposed two defects that compiling and unit tests had both missed:
a 1970 timestamp and a hard crash (see "The device clock" under Known
limitations). Keep the three categories separate for exactly that reason.

What may now be said: the firmware **runs**, signs, authenticates, and drives
all three decision outcomes. What may **not** be said, ever: anything about
hardware security — see the next section.

## What Wokwi proves — and what it does not

**Proves:** firmware behaviour, integration with `atlas_service`, response
handling, and fail-closed behaviour.

**Does NOT prove:** secure boot · hardware-backed key protection · eFuses ·
flash encryption · physical tamper resistance · any real hardware security
property.

Wokwi simulates an MCU, not a secure element. This is frozen principle 4 —
*"the software-only prototype must never claim hardware-equivalent
security"* — and `docs/ATLAS-Blueprint.md` §24.3 says the same of the
hardware itself: a consumer ESP32 without a certified secure element is a
convenience choice for a prototype, explicitly not a hardware-backed
guarantee. `ARCHITECTURE.md`'s RQ-31 lists exactly which properties
(private-key protection, trusted execution, device identity, attestation,
secure boot) are *simulatable for a prototype but should eventually be
hardware-backed*. None of them are provided here.

## What the device must never do

No ALLOW/DENY/STEP_UP decision · no ML scoring · no policy evaluation · no
ATLAS assertion signing · no ATLAS private key · no copy of the policy.

It receives an event, assembles a `Transaction`, wraps it in a signed
`DeviceEnvelope`, POSTs that to `/v2/transact`, reads `final_status`, and
lights an LED. That is the whole job. A component closer to the physical
world is *more* exposed to tampering, so it earns *less* trust — the same
reasoning that makes ML an advisor rather than the judge, applied one layer
further out.

The device also cannot influence the outcome by lying: it never asserts
`is_new_beneficiary` and friends, and the policy engine recomputes those from
history regardless (`tests/test_policy_engine.py::test_client_lying_about_new_beneficiary_is_ignored`).

## Device-side signing (F3) — and exactly what it proves

Every request is signed. The device holds its **own** Ed25519 key, generated
at provisioning and entirely separate from the ATLAS key that signs bank
assertions — mixing them would let a compromised device mint bank assertions.

- **Algorithm:** Ed25519 via **libsodium** (`crypto_sign_detached`), which is
  bundled in ESP32 core 3.3.11. mbedTLS in that core has no Ed25519. It is
  byte-compatible with Python's `cryptography` Ed25519, which the backend
  verifies with.
- **What is signed:** the canonical bytes of the whole `DeviceEnvelope` —
  every field except the signature itself, including the nested transaction.
  The key id, boot id, counter, nonce and timestamp are all covered.
- **Backend order:** signature is verified *before* any field is trusted,
  `device_id` included. See `atlas_service/device/envelope.py`.

This implements Blueprint §24.3, which already specified device signing. It
is an implementation of that design, not a new authentication architecture.

### The limitation that has not gone away

**A valid signature proves possession of the enrolled private key. It does
not prove the identity of a physical device.** `DEVICE_KEY_SEED_HEX` in
`atlas_device.ino` is a compile-time constant in ordinary flash, readable
with `esptool` by anyone with physical access. Closing that gap requires
hardware-backed key storage — an ATECC608-class secure element where the key
provably never leaves the chip — which this project does not have and Wokwi
cannot simulate.

Blueprint §24.6's forged-device-identity problem (RQ-7/12/24) therefore
remains **open**. F3 closed the *protocol* gap, not the *hardware trust* gap.

## Networking: two routes, and which one to prefer

*These two are **routes** — how the simulated device reaches ATLAS. The
**Path A/B/C** labels further down mean something different: which Wokwi tool
you run. The two are independent choices.*

| | Public (free) Gateway | Private Gateway (runs locally) |
|---|---|---|
| Outbound to public internet | ✅ | ✅ |
| Reach `localhost` / your LAN | ❌ | ✅ |
| Incoming connections to the ESP32 | ❌ | ✅ |

### Gateway route — private gateway, no tunnel (preferred)

**This is the long-term answer.** `atlas_service` stays bound to `127.0.0.1`
and nothing is exposed to the internet.

`wokwigw` is the Wokwi IoT gateway. It runs on **your** machine and listens on
`:9011`. Its `config.go` declares a DNS zone `wokwi.internal.` mapping
`host` → `10.13.37.254`, plus `NAT{10.13.37.254: 127.0.0.1}`. So the
firmware's `http://host.wokwi.internal:8000` lands on `127.0.0.1:8000` here.

```
ESP32 (simulated)  →  wokwigw on :9011  →  host.wokwi.internal
                                          = 10.13.37.254
                                          → NAT → 127.0.0.1:8000  →  atlas_service
```

Why this is worth preferring over a tunnel:

* **No URL to regenerate.** `host.wokwi.internal` is a constant.
* **No IP is hardcoded.** A new Wi-Fi network or DHCP lease changes nothing.
* **Nothing is public.** The tunnel had *no authentication of any kind*;
  this removes that exposure rather than mitigating it.
* **No provider to rate-limit you**, and nothing that expires.
* `scripts/run_dev.py` is **unchanged** — still `127.0.0.1`, never `0.0.0.0`.

Two real constraints, stated plainly:

1. The **local** gateway is documented by Wokwi as a paid-plan feature, and the
   free tier's shared cloud gateway cannot reach your machine. In practice it
   worked here on 2026-09-11 from the VS Code extension, on an account the
   simulator labels *Community License* — so check your own plan rather than
   assuming it is unavailable.
2. It works with the **VS Code extension**, which simulates locally. It does
   **not** work with `wokwi-cli`, which simulates on Wokwi's servers and has
   no gateway option — there, `ws://localhost:9011` would mean *their*
   localhost. If you use `wokwi-cli`, you still need the tunnel route.

Setup, once:

```bash
# download wokwigw from github.com/wokwi/wokwigw/releases, then:
wokwigw            # listens on 127.0.0.1:9011, leave it running
```

`firmware/atlas_device/wokwi.toml` already declares `[net] gateway =
"ws://localhost:9011"`, and the sketch already points at
`http://host.wokwi.internal:8000`. Nothing else to configure.

### Tunnel route — optional, unsupported, and it exposes ATLAS publicly

**Not part of the supported workflow, and never a deployment method.** It
exists for one reason: `wokwi-cli` simulates on Wokwi's servers, so it cannot
reach your machine through the local gateway. Everything else — including the
whole demo below — uses the gateway route and needs no tunnel at all.

What it costs, stated plainly: while a tunnel is up, `atlas_service` — which
holds the signing key — is reachable by anyone with the URL, with **no
authentication of any kind** on the transport itself. The legacy `/transact`
endpoint has been closed by default since 2026-09-18, so an unsigned request
gets `FAIL_CLOSED`, but `/v2/transact` still accepts anything an enrolled
device key signs, and nothing is encrypted. Read "The tunnel is demo-only
infrastructure" below before using it.

If you accept that, run the tunnel yourself, deliberately:

```bash
npx localtunnel --port 8000 --subdomain <pick-one>
```

`cloudflared tunnel --url http://127.0.0.1:8000` also works, but on 2026-08-31
TryCloudflare rate-limited this machine and handed out hostnames that never
resolved (NXDOMAIN on 8.8.8.8, 1.1.1.1 *and* Cloudflare's own resolver) while
`cloudflared` still reported "Registered tunnel connection". Both drop every
20-40 minutes. On this route you must also change `ATLAS_URL` in the sketch to
the tunnel hostname and recompile, and **verify it answers over plain `http`**
— the firmware does no TLS, and this is simulation only. `atlas_service` itself
refuses to serve a non-loopback address without TLS since 2026-09-18
(`atlas_service/transport.py`); a tunnel in front of loopback bypasses that
check, which is one more reason the tunnel route is demo-only.

### Running the demo

**Steps 1–4 are the same whichever Wokwi path you pick. Step 5 differs — see
"Choosing a Wokwi path" below.**

1. Start both services. Redirect to a file so `verify_device_run.py` has
   something durable to read. The unauthenticated legacy endpoint is closed by
   default since 2026-09-18, so no flag is needed for that:
   ```bash
   python scripts/run_dev.py > atlas.log 2>&1
   ```
   (`scripts/run_sim.py`, described in `RUNBOOK.md` §1, starts the services and
   the gateway together instead.)
2. Start the gateway and leave it running. This is the supported route, and it
   needs no tunnel:
   ```bash
   wokwigw
   ```
   Nothing else. The sketch already targets `http://host.wokwi.internal:8000`
   and `wokwi.toml` already declares `[net] gateway = "ws://localhost:9011"`.

   Only `wokwi-cli` cannot use this, because it simulates on Wokwi's servers.
   If you specifically need it, see "Tunnel route" above — optional,
   unsupported, and it exposes `atlas_service` to the internet while it runs.
3. **Enrol a device with a clean counter.** A simulator restart resets NVS to
   0, so reusing a device that already reached counter N gives you N confusing
   `COUNTER_REGRESSION` rejections before anything works. A fresh device
   avoids that entirely — the replay check is working, not broken.
   ```bash
   python scripts/provision_device.py enroll        --device-id esp32-atlas-fw-NN --subject user-demo-1        --keys-dir firmware/device_keys_fwNN
   ```
4. Put the provisioned identity into **`secrets.h`**, not the sketch — copy
   `secrets.example.h` to `secrets.h` and paste the values in. `secrets.h` is
   gitignored precisely so a private key seed can never reach git. On the gateway
   route the endpoint needs no edit at all; the sketch's `ATLAS_URL` is already
   correct and stays correct across Wi-Fi and IP changes.
5. Compile, then start the simulation — **Path A, B or C below** (those name the
   *tool*, not the network route):
   ```bash
   cd firmware/atlas_device
   arduino-cli compile --fqbn esp32:esp32:esp32doit-devkit-v1 --output-dir build .
   ```
   `build/` is gitignored, and the image it produces **contains the seed** —
   treat it as secret, exactly like `secrets.h`.
6. `SELECT` cycles preset (amber blinks 1×/2×/3×), `SEND` submits.

## Choosing a Wokwi path

Three ways to run this. These A/B/C labels name the **tool**, not the network
route above. **Path B (VS Code extension) is now the recommended one**, because it is the only path that can reach `atlas_service` on
`127.0.0.1` without a public tunnel. Picking A or C wrongly is what produces
`firmware binary build/atlas_device.ino.bin not found in workspace`.

| | Path A — web IDE | **Path B — VS Code extension** | Path C — `wokwi-cli` |
|---|---|---|---|
| Who compiles | Wokwi, server-side | **You**, locally | **You**, locally |
| Where the SIMULATION runs | Wokwi's servers | **your machine** | Wokwi's servers |
| Local install needed | none | arduino-cli + ESP32 core + ArduinoJson | same as B |
| Uses `wokwi.toml` | ignored | **required** | **required** |
| Uses `libraries.txt` | yes | no (`arduino-cli lib install`) | no |
| Needs a visible browser | yes | yes | **no** |
| Scriptable / CI-able | no | no | **yes** |
| **Can reach `127.0.0.1` via the gateway** | **no** | **yes** | **no** |
| Needs a public tunnel | yes | **no** | yes |

### The recommendation changed on 2026-09-09, and why

Path C used to be recommended here, for the build-server and browser-throttling
reasons below — which are all still true. It is no longer recommended because
of something that outranks them: **`wokwi-cli` simulates on Wokwi's servers.**
It prints `Connected to Wokwi Simulation API`, and `ws://localhost:9011` inside
it would mean *Wokwi's* localhost, not yours. Verified by running it: no serial
output, no connection logged by the local gateway, and **0** `/v2/transact`
requests reaching `atlas_service`.

That means Path C can only reach ATLAS through a public tunnel, and the tunnel
is the thing this project spent weeks being broken by: URLs that changed,
providers that rate-limited, and ATLAS exposed to the internet with no
authentication at all while it ran.

Path B keeps the simulation on your machine, so `host.wokwi.internal` resolves
through the local gateway to `127.0.0.1`. Nothing is exposed and nothing
expires. Its cost is that it is not scriptable — you press the buttons.

**Use Path C only for unattended/CI runs where a tunnel is acceptable**, and
stop the tunnel the moment it finishes.

### The Path C advantages that are still real (2026-08-30/09-02)

- **Wokwi's free build servers are unreliable.** Four consecutive "Build
  Servers Busy" timeouts in one session made Path A unusable. Compiling
  locally takes ~30s and removes them from the loop entirely. Wokwi's own
  error dialog recommends this.
- **A backgrounded browser tab cannot run the simulation.** Wokwi's simulator
  is driven by `requestAnimationFrame`; Chrome suspends hidden tabs, so speed
  drops to ~0% and the simulated clock effectively stops. Every attempt to
  drive Paths A/B from an automated browser stalled on this. `wokwi-cli` has
  no such dependency.
- **Button presses need real simulated time.** The 50ms debounce in
  `pressed()` means a synthetic click on a throttled tab is never seen. A
  scenario file drives the buttons deterministically instead.

### Path C — `wokwi-cli`, headless

Needs a **CI token** from wokwi.com/dashboard/ci. Note this is *not* the VS
Code extension's `~/.wokwi/user.tok`, which `wokwi-cli` does not read.

```bash
arduino-cli compile --fqbn esp32:esp32:esp32doit-devkit-v1 --output-dir build .
WOKWI_CLI_TOKEN=$(cat ~/.wokwi/ci-token.txt) wokwi-cli \
    --timeout 300000 --scenario three-presets.scenario.yaml \
    --serial-log-file serial.log .
```

Verify the result from the backend rather than the LED — red means `DENY` *or*
`FAIL_CLOSED`, and the LED cannot tell you which:

```bash
python scripts/verify_device_run.py atlas.log
```

**The VS Code extension does not compile Arduino code.** Wokwi's own docs are
explicit: *"you need to compile the code and generate the firmware / ELF
file."* If `build/` does not exist, the extension has nothing to simulate and
reports exactly the error above. That is a missing build, not a broken config.

Nothing in this repository builds the firmware for you — deliberately, since
the ESP32 core is a large download and is not assumed present.

### Path A — wokwi.com web IDE (no local toolchain, but see the caveat above)

No local toolchain at all.

1. Go to wokwi.com → **New Project** → **ESP32** → Arduino.
2. Paste `atlas_device.ino` over `sketch.ino`.
3. Open the `diagram.json` tab and paste this project's `diagram.json` over it.
4. **Library Manager** panel → add **ArduinoJson** (must be **7.x** — see
   `libraries.txt` for why).
5. Press play.

`wokwi.toml` is not used here and can be ignored entirely.

### Path B — VS Code extension (what you have installed)

One-time setup:

```bash
arduino-cli config init
```

```bash
arduino-cli core update-index --additional-urls https://espressif.github.io/arduino-esp32/package_esp32_index.json
```

```bash
arduino-cli core install esp32:esp32 --additional-urls https://espressif.github.io/arduino-esp32/package_esp32_index.json
```

```bash
arduino-cli lib install "ArduinoJson@7.2.0"
```

Then, from `firmware/atlas_device/`, before every simulation run:

```bash
arduino-cli compile --fqbn esp32:esp32:esp32doit-devkit-v1 --output-dir build .
```

That produces `build/atlas_device.ino.bin` and `build/atlas_device.ino.elf` —
the exact two paths `wokwi.toml` names. Only then does **F1 → Wokwi: Start
Simulator** have anything to run. Re-run the compile after every edit to the
`.ino`; the extension simulates the last binary you built, not your source.

`build/` is gitignored.

### ⏰ Expected results depend on the time of day

This table used to say "preset 0 → ALLOW → green" with no qualification, which
cost real debugging time: every run between 22:00 and 06:00 IST returned amber
and the table looked wrong. It was not. `user-demo-1.yaml` has an `odd_hours`
rule (`TIME_WINDOW: [22, 6]`, evaluated in `Asia/Kolkata`) that forces STEP_UP
regardless of amount.

| Preset | Amount | 06:00-22:00 IST | 22:00-06:00 IST | Why |
|---|---|---|---|---|
| 0 | ₹1,500 | **ALLOW** (green) | STEP_UP (amber) | no rule matches by day; `odd_hours` matches by night |
| 1 | ₹60,000 | STEP_UP (amber) | STEP_UP (amber) | `large_amount` — time-independent |
| 2 | ₹1,50,000 | DENY (red) | DENY (red) | `hard_cap`, and most-restrictive-wins beats every STEP_UP |

**Only preset 0 moves.** If you want to demonstrate a green LED, run it during
the day. All three outcomes were observed from real firmware on 2026-09-02.

Stop `atlas_service` to see fail-closed: red, never green.

### ⚠️ The tunnel is demo-only infrastructure

A tunnel provides **no authentication whatsoever**. While it is running,
`atlas_service` — which holds the signing key — is reachable by anyone with
the URL.

F3's device signing protects `/v2/transact`, where an unenrolled key is
rejected. The **legacy `/transact` endpoint used to stay open by default** and
performed no device authentication at all, so anyone who found the URL could
submit transactions against the demo personas through it. **Closed since 2026-09-18**
(Phase 3.8): it answers `FAIL_CLOSED` / `DEVICE_AUTH_REQUIRED`. Since 2026-09-22
there is no way to reopen it in a running service either — the
`ATLAS_REQUIRE_DEVICE_AUTH=0` escape hatch was removed, and nothing in this
repository needs it.

Mitigations, in order of preference: keep the tunnel up only for the demo and
kill it immediately after; never point a tunnel at anything holding real
data; treat the URL as sensitive. Wokwi also notes free-gateway traffic is
*"monitored for security purposes"* — fine for synthetic demo data, worth
knowing before sending anything else through it.

This is **not** production authentication, **not** a deployment method, and
must never be presented as either.

## Known limitations

- **The device clock is not trustworthy.** `timestamp` feeds ATLAS's
  `TIME_WINDOW` policy rules, so a wrong clock changes which rules fire. NTP
  here is a demo convenience, not a trusted time source. **The firmware does
  now refuse to transact without a clock** (below), but that only detects an
  *unset* clock — it cannot detect a *wrong* one. The backend's
  `MAX_CLOCK_SKEW` (5 minutes) remains the real defence.
- **The device refuses to transact until NTP has set the clock.** Added
  2026-09-02 after two defects were found by actually running the firmware:
  `configTime()` is asynchronous and the code did not wait for it, so an early
  press sent `issued_at=1970-01-01` (backend: `STALE_REQUEST`) and — worse — a
  DNS lookup issued while SNTP's own lookup was still pending re-entered
  `sntp_dns_found → sntp_retry → sys_untimeout`, tripped an lwIP assert, and
  **rebooted the device mid-transaction**. `setup()` now waits up to 30s for a
  valid clock, and `loop()` re-checks before every SEND, refusing with
  `decision_reason=CLOCK_NOT_SET` *before any DNS or HTTP call*. On timeout the
  device does not halt permanently the way a missing signing key does: a clock
  can recover, a key cannot. Verified both ways, including against a
  deliberately unresolvable NTP host.
- **No retry on failure, on purpose.** A device silently retrying a payment
  is the "never blindly retry" mistake the frozen failure-mode table warns
  against. The user presses SEND again, consciously.
- **`transaction_id` uses a boot-scoped counter.** Across a reboot without
  changing `boot_id`, IDs can repeat; the bank's idempotency and the replay
  cache would then treat a new press as a duplicate. Fine for a demo, wrong
  for anything real.
- **`REFUSED` and `FAIL_CLOSED` share the red LED** — distinct in the state
  model, indistinguishable on three LEDs. "The bank said no" and "something
  broke" are different facts and a real device should show them differently.
