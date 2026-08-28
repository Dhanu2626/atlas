# firmware/ — the ATLAS edge device (Step 8, updated by F3)

## What is actually verified, and what is not

Three different things get confused easily, so they are separated here:
**tested** (an automated test executes it) · **compiles** (the toolchain
builds it, which says nothing about runtime) · **executed** (it has actually
run). Nothing below claims more than it has.

| Artifact | Status |
|---|---|
| `virtual_device.py` | **Tested.** 30 tests in `tests/test_virtual_device.py`, run against the real `atlas_service` + `bank_service` |
| `atlas_device/atlas_device.ino` | **Compiles, never executed.** Builds cleanly with `arduino-cli` (ESP32 core 3.3.11): 1168316 B = 89% flash, 51248 B = 15% RAM. Its canonical signing template is pinned byte-for-byte against the backend by `tests/test_f3_firmware_parity.py`. **It has never been run** — on-device signature bytes, NTP timestamp formatting, and NVS persistence are unverified |
| `atlas_device/diagram.json` | **Partially verified.** Its five GPIO pins are checked against the `.ino` by test; the circuit itself has not been opened in Wokwi |
| `atlas_device/wokwi.toml` | **Build verified.** `arduino-cli compile --output-dir build` produces exactly the `build/atlas_device.ino.bin` and `.elf` it names. The *simulation* has not been started |
| `atlas_device/libraries.txt` | Unverified. Web-IDE path only; ArduinoJson **7.x** required. libsodium is **not** listed because it ships inside ESP32 core 3.3.11 rather than as an external library |

**Compiling is not running.** No part of this directory has been executed on a
simulated or physical ESP32, so nothing here should be described as "working
firmware". `virtual_device.py` is where the executable correctness claims live.

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

## Networking: the free gateway is enough

Verified against Wokwi's current docs:

| | Public (free) Gateway | Private Gateway (paid) |
|---|---|---|
| Outbound to public internet | ✅ | ✅ |
| Reach `localhost` / your LAN | ❌ | ✅ |
| Incoming connections to the ESP32 | ❌ | ✅ |

Step 8 only needs **outbound**, so **the paid Private Gateway is not
required.** The simulated device must reach `atlas_service` at a *public*
address, which is what the tunnel below is for.

### Running the demo

**Steps 1–3 are the same whichever Wokwi path you pick. Step 4 differs — see
"Choosing a Wokwi path" below.**

1. Start both services:
   ```bash
   python scripts/run_dev.py
   ```
2. Expose `atlas_service` publicly — **run this yourself**, deliberately:
   ```bash
   cloudflared tunnel --url http://127.0.0.1:8000
   ```
   (`ngrok http 8000` works equally well.)
3. Put the public URL into `ATLAS_URL` in `atlas_device.ino`.
4. Start the simulation — **Path A or Path B below**.
5. `SELECT` cycles preset (amber blinks 1×/2×/3×), `SEND` submits.

## Choosing a Wokwi path

Wokwi has two front ends and they work completely differently. Picking the
wrong one is what produces the error
`firmware binary build/atlas_device.ino.bin not found in workspace`.

| | Path A — web IDE | Path B — VS Code extension |
|---|---|---|
| Who compiles | Wokwi, server-side | **You**, locally, before simulating |
| Local install needed | none | arduino-cli + ESP32 core + ArduinoJson |
| Uses `wokwi.toml` | ignored | **required** |
| Uses `libraries.txt` | yes | no (`arduino-cli lib install` instead) |

**The VS Code extension does not compile Arduino code.** Wokwi's own docs are
explicit: *"you need to compile the code and generate the firmware / ELF
file."* If `build/` does not exist, the extension has nothing to simulate and
reports exactly the error above. That is a missing build, not a broken config.

Nothing in this repository builds the firmware for you — deliberately, since
the ESP32 core is a large download and is not assumed present.

### Path A — wokwi.com web IDE (recommended for a first run)

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

| Preset | Amount | Expected | LED |
|---|---|---|---|
| 0 | ₹1,500 | ALLOW | green |
| 1 | ₹60,000 | STEP_UP (`large_amount`) | amber |
| 2 | ₹1,50,000 | DENY (`hard_cap`) | red |

Stop the simulation and kill the tunnel to see fail-closed: red, never green.

### ⚠️ The tunnel is demo-only infrastructure

A tunnel provides **no authentication whatsoever**. While it is running,
`atlas_service` — which holds the signing key — is reachable by anyone with
the URL.

F3's device signing does **not** close this. It protects `/v2/transact`,
where an unenrolled key is rejected — but the **legacy `/transact` endpoint
is still open by default** and performs no device authentication at all, so
anyone who finds the URL can submit transactions against the demo personas
through it. Closing that endpoint is deferred to Phase 3.8;
`ATLAS_REQUIRE_DEVICE_AUTH=1` closes it today if you want it shut.

Mitigations, in order of preference: keep the tunnel up only for the demo and
kill it immediately after; never point a tunnel at anything holding real
data; treat the URL as sensitive. Wokwi also notes free-gateway traffic is
*"monitored for security purposes"* — fine for synthetic demo data, worth
knowing before sending anything else through it.

This is **not** production authentication and must never be presented as
such.

## Known limitations

- **The device clock is not trustworthy.** `timestamp` feeds ATLAS's
  `TIME_WINDOW` policy rules, so a wrong clock changes which rules fire. NTP
  here is a demo convenience, not a trusted time source.
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
