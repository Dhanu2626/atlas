# ATLAS runbook — start, run, stop, test

Operational companion to `HANDOFF.md` (which records *why* things are the way
they are). Sections 0-8 were verified by running them on 2026-09-09. Section 9
(step-up) was added on 2026-09-11, and its restart-cleanup behaviour was
verified on 2026-09-16. The transport policy (§4) and the step-up refusal rules
(§9) follow the 2026-09-18 changes, and §8 was re-checked on 2026-09-21.

Nothing in this document depends on the date, on your current IP address, on a
public tunnel, or on a URL that expires. That is deliberate: the previous setup
depended on all four and broke repeatedly.

---

## Just want to see it work?

```bash
python scripts/demo.py
```

One command, about 30 seconds, after `pip install -r requirements.txt` and nothing else:
it presses the device's three presets through the real ATLAS and bank code on throwaway
state and prints ALLOW (green), STEP_UP (amber) and DENY (red), a late-night STEP_UP and a
refused replay. It needs none of the setup below and changes nothing: no live database,
key or certificate is opened. `--show-logs` adds the services' own log lines. Exit status
is 1 unless the three outcomes are ALLOW, STEP_UP, DENY, which is how GitHub Actions uses
it on every push. The same presses, replayed from the last export, are on the dashboard: https://dhanu2626.github.io/atlas/

## 0. One-time setup

| Need | How |
|---|---|
| Python deps | `.venv` at the repo root, already provisioned |
| ESP32 toolchain | `arduino-cli` + core `esp32:esp32` + ArduinoJson 7.x |
| Wokwi VS Code extension | installed (verified: `wokwi.wokwi-vscode-3.7.0`) |
| Wokwi IoT gateway | official `wokwigw` v2.0.1 from <https://github.com/wokwi/wokwigw/releases>, at `~/.wokwi/wokwigw.exe` (hash pinned, §1) |
| Device identity | `firmware/atlas_device/secrets.h` — see §4 |

**Wokwi plan requirement.** Wokwi documents the *local/private* IoT gateway as a
paid feature, and the free tier's shared cloud gateway cannot reach your machine.
It was **verified working on 2026-09-11** from the VS Code extension, on an
account the simulator labels *Community License*. If your plan does not include
it, see §7 for the fallback — and note the fallback is strictly worse, not
equivalent.

---

## 1. Start (normal, every time) -- the one Wokwi startup procedure

```bash
python scripts/run_sim.py
```

Run it, wait for the line **`READY`**, and only then start Wokwi. In order, it:

1. checks every prerequisite (TLS material, trained models, enrolled policy owners, the device
   certificate). If anything is missing it names it, says **"Nothing was started"**, and exits;
2. starts `bank_service` and `atlas_service` on loopback and waits until both accept connections;
3. verifies the Wokwi gateway, starts it, waits for `127.0.0.1:9011` and completes the WebSocket
   handshake the extension needs (`scripts/wokwi_gateway.py`);
4. prints `READY`.

Then open VS Code on **`firmware/atlas_device`** and press `Ctrl+Shift+P` → **Wokwi: Start Simulator**
(§2). `Ctrl+C` in the `run_sim.py` terminal stops everything it started (§3).

**If Wokwi says "Failed to connect to the IoT Gateway at ws://localhost:9011":** nothing is
listening on port 9011, so the gateway was never started or has stopped. It almost always means
`run_sim.py` stopped before printing `READY` -- read its output, fix what it names, run it again.
To diagnose without starting anything:

```bash
python scripts/wokwi_gateway.py check
```

| It reports | Meaning and what to do |
|---|---|
| `BINARY_MISSING` | `wokwigw.exe` is not at `~/.wokwi/`. Download `wokwigw_v2.0.1_Windows_64bit.zip` from the official releases page and extract it there. |
| `BINARY_HASH_MISMATCH` | The file is not the pinned official v2.0.1 and is not run. |
| `OCCUPIED` / `UNVERIFIED_OWNER` | Something else holds port 9011 (named by PID). It is left alone; close it and retry. |
| `BLOCKED_BY_WINDOWS` | **Windows Application Control refused to run the gateway** (error 4551 or 1260). ATLAS stops and does not work around it. Windows decides; Event Viewer > CodeIntegrity > Operational (events 3077 / 3033) names the rule. |

The gateway can also be handled on its own: `python scripts/wokwi_gateway.py start | status | stop`.
`stop` ends only a gateway ATLAS started itself, and only after confirming it is still the verified
binary. `run_sim.py --no-gateway` verifies that such a gateway is already answering instead of
starting one.

The binary is the official Wokwi IoT Gateway **v2.0.1**; its SHA-256 (`76bbd0d9...3c4a01`) is pinned in
`scripts/wokwi_gateway.py`, verified against GitHub's published digest for the release zip. The
helper never edits `wokwi.toml`, never uses a public gateway or tunnel, and only connects to
`127.0.0.1`. It cannot tell Windows what to allow, and it never suggests turning protection off.

The command starts, all on **loopback only**:

| Port | Process |
|---|---|
| `127.0.0.1:8000` | `atlas_service` |
| `127.0.0.1:8100` | `bank_service` |
| `127.0.0.1:9011` | `wokwigw` gateway |

It also sets, **for those child processes only**, `ATLAS_SIMULATION_ALLOW_COUNTER_RESET=1`
— see §5. Nothing else is injected into the environment.

`bank_service` is served over **mutual TLS** (§4.2) and `atlas_service` calls it over
`https://127.0.0.1:8100`. Since 2026-09-29 `atlas_service`'s own listener is **TLS** too: the
ESP32 connects to `https://host.wokwi.internal:8000` and checks ATLAS's certificate against
the local CA compiled into the firmware. Before the first run you therefore need the local
TLS material (§4.2), the trained models (§4.6), the policy owners enrolled (§4.4), and --
once -- the device's certificate material:

```bash
python scripts/make_dev_ca.py --reissue-atlas     # atlas.crt also names host.wokwi.internal
python scripts/make_dev_ca.py --firmware-header   # ca.crt (public) -> firmware/atlas_device/atlas_ca.h
```

then rebuild the firmware. `run_sim.py` refuses to start and names whichever is missing.

**The legacy unsigned `POST /transact` is closed and cannot be reopened.** It was closed
by default on 2026-09-18 (D5, Phase 3.8's remaining act) and since 2026-09-22 there is no
process-level switch at all: no environment variable, flag or configuration file opens it
in a running service, and it answers `FAIL_CLOSED` / `DEVICE_AUTH_REQUIRED`. The firmware
has signed its requests to `/v2/transact` since F3 and the dashboard export drives the
signed path too, so nothing in the release needs it.

**For anything that is not the simulator, use `scripts/run_dev.py` instead.**
It sets neither variable. That separation is the whole point: production-like
runs cannot inherit the simulation accommodation by forgetting an argument.

## 2. Run the simulation

1. Start `python scripts/run_sim.py` and wait for **`READY`** (§1). Wokwi connects to the gateway the
   moment it starts, so the gateway must already be up.
2. Open VS Code on the folder **`firmware/atlas_device`** (the extension looks
   for `wokwi.toml` at the workspace root), then `Ctrl+Shift+P` → **Wokwi: Start Simulator**.
3. Wait for `[DEVICE] Ready` in the serial pane.
4. **SELECT** cycles the preset — amber blinks 1x / 2x / 3x.
5. **SEND** submits.
6. Read the decision trace; the LED shows GREEN / YELLOW / RED.

No file needs editing between runs. No URL needs regenerating.

## 3. Stop

`Ctrl+C` in the `run_sim.py` terminal stops all three processes. If a gateway is
orphaned (for example after `wokwi_gateway.py start`):

```bash
python scripts/wokwi_gateway.py stop
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

### 4.1 Key protection at rest (`keystore.py`, 2026-09-22)

Every private key ATLAS keeps on disk is encrypted at rest: the ATLAS signing key, each
device key, the step-up authenticator key, the password that unlocks the local TLS keys,
and the model-integrity key. On Windows the backend is **DPAPI** under your signed-in
account (no password to remember, and a copy of the file on another machine or account —
including OneDrive's cloud copy — does not decrypt). Elsewhere, set
`ATLAS_KEYSTORE_PASSPHRASE` and the backend is AES-256-GCM under a scrypt-derived key.

```bash
python scripts/protect_keys.py status     # which key files are protected, and by which backend
python scripts/protect_keys.py migrate    # encrypt any plaintext key file in place
python scripts/protect_keys.py verify     # prove each protected key still matches its public record
```

`migrate` never deletes anything: it writes the plaintext original to a timestamped folder
**outside the repository** (`~/ATLAS-key-recovery/<UTC timestamp>/`) and reports where.
Keep that folder until `verify` passes, then delete it yourself — it is the only copy that
survives losing your Windows account.

`verify` checks the real bindings, not just that a file decrypts: the ATLAS key against the
public key the bank holds, each device key against the registry, the authenticator against
its enrollment.

**What this does not protect.** A process running as the same user can decrypt these keys,
and they are plaintext in memory while in use. The ESP32's own seed
(`firmware/atlas_device/secrets.h` and the compiled image) is outside the keystore — only
hardware (flash encryption or a secure element) changes that.

**Rotation — the real fix after any suspected exposure.** Encrypting in place does not
un-publish a key that was already plaintext on disk, in a backup, or in OneDrive's version
history. If a key may have been seen, rotate it:

| Key | Procedure |
|---|---|
| ATLAS signing key | Stop both services. Delete `atlas_service/keys/atlas_ed25519.key` and the shared public key file. Start `atlas_service`: it generates a new key, protected at rest, and republishes the public key the bank reads. Old assertions stop verifying, which is the point |
| Device key | `python scripts/provision_device.py revoke <device_id>` (the registry refuses to re-enrol an existing id, because silently replacing a device's key is an account-takeover primitive), then enrol a new device id, write its `secrets.h` and reflash |
| Step-up authenticator | Delete `firmware/device_keys_authenticator/` and run `python scripts/enroll_authenticator.py` again; the new public key replaces the enrollment |
| TLS material | Delete `dev-certs/` and re-run `python scripts/make_dev_ca.py` — a whole new local CA |
| Model-integrity key | Delete `atlas_service/ml/artifacts/` and re-run `python scripts/train_models.py` |

### 4.2 Local TLS material (`scripts/make_dev_ca.py`)

```bash
python scripts/make_dev_ca.py          # writes dev-certs/ (gitignored)
```

That creates a local test CA and, from it, the bank's server certificate, ATLAS's server
certificate and ATLAS's **client** certificate for mutual TLS, plus `tls-password.key` —
the password that decrypts the private keys, itself keystore-protected. Every private key
is encrypted PKCS#8; nothing is printed or exported.

`scripts/serve.py` starts one service with that material, decrypting the password inside
the serving process so it never appears on a command line or in the environment:

```bash
python scripts/serve.py bank  --port 8100 --tls --require-client-cert
python scripts/serve.py atlas --port 8000 --tls
```

`run_dev.py` starts both over TLS; `run_sim.py` starts the bank over mutual TLS and leaves
the ATLAS listener plain on loopback for the firmware. This is a **local test CA**, not
production PKI: no public trust and no HSM. Revocation and pinning exist only in the
production profile (§4.5), and there as a local CRL and a local pin.

### 4.3 Payment history, and what a decision reads

Since 2026-09-23 a decision is made against the subject's **own past payments**, not
against generated history. `atlas_service/db.py` persists the whole transaction, and
`TransactionStore.history_for()` reads it back:

* the subject's rows only, most recent 200, oldest first;
* the payment being decided is excluded, so it can never be in its own baseline;
* every state counts -- an allowed, denied or still-waiting payment all happened. A
  refusal must not let anyone reset their own velocity window;
* rows written before 2026-09-23 have no detail and are **skipped**, never guessed at.

Three things read it: the `VELOCITY` rule, the `NEW_BENEFICIARY` rule, and every
history-derived ML feature.

**A new customer is not judged.** Below `MIN_HISTORY_FOR_BANDS`
(`atlas_service/ml/registry.py`, 200 -- the history size the risk bands were calibrated
on) the ML layer returns `risk_band: INSUFFICIENT_HISTORY`, `anomaly_score: null` and the
reason "not enough payment history yet" (since 2026-09-25; before that it said LOW and
0.0). It is not a risk level: no `RISK_THRESHOLD` rule matches it, so decisions are exactly
what they were. The deterministic rules -- amount, new payee, velocity, time window,
international -- apply in full from the very first payment. The device and the dashboard
show the string as it comes.

**The burst signal.** With 200 or more known payments the ML layer also attaches
`range_signal` (`beyond_observed_range`, `atlas_service/ml/range_signal.py`): the payments
in the 24 hours up to this one, the busiest earlier 24 hours, and whether the first is more
than 6x the second -- in which case one extra reason line says so. It changes no risk band; since
2026-09-29 a policy can act on it with `BEYOND_OBSERVED_RANGE: true` (user-demo-1's v5 rule
`burst_beyond_own_history` asks for confirmation; `velocity_burst` still refuses more than 20 in 24 hours). Its 6x was chosen on
the evaluation's validation split only (`scripts/evaluate_ml.py` prints the calibration);
`tests/test_range_signal.py` fails if the constant drifts from what that calibration picks.
The window is (t - 24h, t]: payments stamped the same instant count, anything dated later
never does.

To audit it, look for the field on every `[RISK]` line in the service log:

```
beyond_observed_range=FIRED current_24h=8 observed_max_24h=1 x6
beyond_observed_range=not_fired current_24h=2 observed_max_24h=3 x6
beyond_observed_range=not_evaluated          # fewer than 200 payments: INSUFFICIENT_HISTORY
```

The same object is `risk.range_signal` in the `/v2/transact` reply. Its evidence is
synthetic only (40 of 40 held-out synthetic bursts, 0 of 320 ordinary cases): it is not a
measure of real-world burst detection.

**Migrating an existing database.** Nothing to run: opening a store adds the new columns
with `ALTER TABLE` and keeps every existing row. The old rows simply do not appear in
history until that subject makes new payments.

### 4.4 Policy versions: rollback is refused (2026-09-25)

Every deciding request checks the subject's policy file against the highest version ATLAS
has already decided under, recorded in `atlas_service/atlas_policy_state.db` (or
`$ATLAS_STATE_DIR/atlas_policy_state.db`) together with that policy's hash:

| The file on disk | What happens |
|---|---|
| the recorded version, same content | decided normally |
| a **higher** version | recorded, then decided under |
| a **lower** version | refused: `FAIL_CLOSED`, `policy_refusal: policy_rollback` |
| the recorded version, **different content** | refused: `policy_tampered` |
| the state file cannot be read | refused: `policy_state_unavailable` |

A refusal is made before anything is persisted, and the bank is never contacted.

**So: editing a policy REQUIRES bumping its `version`.** An edit that keeps the number is
treated as tampering, which is the point -- the version is what the rollback check
trusts. The file is created on the first decision after 2026-09-25 (the live one does not
exist yet), and it is a new file: no existing database is migrated.

**Every policy is also signed by its owner (2026-09-27).** Beside each
`policies/<subject>.yaml` sit `<subject>.yaml.sig` (the owner's Ed25519 signature) and
`<subject>.pub` (the owner's public key). ATLAS trusts only the key **enrolled** in its own
policy state, never the `.pub` file itself, so a forged or edited policy -- a higher-numbered,
looser one included -- is refused: `policy_owner_not_enrolled`, `policy_unsigned` or
`policy_signature_invalid`. One-time, per policy:

```bash
python scripts/policy_key.py enroll user-demo-1      # also user-frozen-1, user-poor-1
python scripts/policy_key.py verify user-demo-1
```

`run_dev.py` and `run_sim.py` refuse to start until every policy has an enrolled owner, and
`run_sim.py --state-dir` copies the live enrolment into the disposable folder. To change a
policy: edit it, raise its `version`, then `python scripts/policy_key.py sign <subject>`,
which needs the owner's private key (`~/.atlas/policy-keys/<subject>.key`, keystore-encrypted,
never in the repository; `create` makes one and never overwrites).

What stays trusted: the first enrolment of an owner key -- a deliberate operator step, and
`enroll` refuses to replace a different enrolled key without `--replace`. A deliberate
downgrade is an operator action: stop the service, back up `atlas_policy_state.db`, then
remove that subject's `active_policy` row.

### 4.5 The production transport profile (2026-09-25)

```bash
ATLAS_TRANSPORT_PROFILE=production    # default: development
```

| | development (default) | production |
|---|---|---|
| TLS versions | 1.2 or newer | **1.3 only**, client and server |
| Revocation | not checked | `dev-certs/ca.crl` checked on every handshake, both directions |
| Bank key | any certificate the CA issued for the name | must match `dev-certs/bank.pin`, checked before any request byte is sent |
| Plain HTTP | loopback only (override: `ATLAS_ALLOW_INSECURE_HTTP=1`) | **never**, loopback included; the override is ignored |
| Material missing | payments settle PENDING | the service **refuses to start** |

The CRL and the pin are not in the live `dev-certs/` yet. Adding them writes two new files
and replaces nothing (an existing CRL keeps its revocations):

```bash
python scripts/make_dev_ca.py --production-material   # ca.crl + bank.pin
python scripts/make_dev_ca.py --revoke bank           # put bank.crt on the CRL
```

ATLAS and the bank use mutual TLS from this local certificate authority, and the firmware is
written to verify ATLAS over HTTPS (2026-09-29). **Its run in the wokwi simulator is pending: the new firmware build was blocked by windows application control on 2026-10-01, so every wokwi observation on record was made on the earlier plain-http build.** `run_sim.py` serves ATLAS over
TLS only, so after pulling this change rebuild the firmware once (the command is at the top of
`firmware/atlas_device/wokwi.toml`); an old build speaks plain HTTP and cannot connect. `run_sim.py`
runs the development profile; the production profile's CRL and pin apply to the ATLAS -> bank hop.

### 4.6 Trained models (`scripts/train_models.py`)

The request path never fits a model. Train once per machine, and after any change to the
feature code or a scikit-learn upgrade:

```bash
python scripts/train_models.py            # trains and persists a model per policy subject
python scripts/train_models.py --check    # verifies what is on disk, trains nothing
```

Artifacts land in `atlas_service/ml/artifacts/` (gitignored): a joblib blob plus a manifest
carrying an HMAC-SHA256 over the artifact bytes, keyed by the keystore-protected
`model-integrity` key, with the scikit-learn version pinned. `atlas_service` loads and
verifies them at startup and logs each one. A missing, altered or version-mismatched
artifact makes that subject's requests fail closed — `FAIL_CLOSED` / `INTERNAL_ERROR`
before any state is created — never a silent refit.

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

### Transport: TLS, and what it costs to leave loopback

ATLAS's certificates come from its own local certificate authority. The firmware connects to
atlas_service over HTTPS (2026-09-29; simulator run pending, §6), the service-to-service hop is mutual TLS (§4.2), and
the opt-in production profile adds TLS 1.3, a CRL and a pinned bank key (§4.5). In the default development profile it has, since 2026-09-18 (D6), a policy that
refuses to drift into plain HTTP off loopback — `atlas_service/transport.py`:

| Where | Plain HTTP | Refused unless |
|---|---|---|
| Listening on `127.0.0.1` | fine, the packets never reach an interface | — |
| Listening on anything else | **refused** | you serve TLS (`scripts/serve.py --tls`), or set `ATLAS_ALLOW_INSECURE_HTTP=1` |
| Calling a loopback bank URL | fine | — |
| Calling any other bank URL | **refused at startup** | the URL is `https://`, or `ATLAS_ALLOW_INSECURE_HTTP=1` |

`ATLAS_ALLOW_INSECURE_HTTP=1` exists for a development gateway. It is never the
default, every start that uses it logs `INSECURE` in the posture line, and the production
profile ignores it: there, plain HTTP is refused everywhere, loopback included.

To run the services over TLS locally (§4.2 has the detail):

```bash
python scripts/make_dev_ca.py     # once: local test CA + certificates, in dev-certs/
python scripts/run_dev.py         # both services over TLS; the bank also requires ATLAS's client certificate
```

`scripts/make_dev_cert.py` was **deleted on 2026-09-22**: it wrote an unencrypted private
key and a 30-day self-signed certificate that nothing verified. The replacement issues
every key as encrypted PKCS#8 under a keystore-protected password, and the ATLAS → bank
hop now verifies the certificate and its hostname and presents a client certificate of its
own. It is still a **local test CA**, not a secure deployment: no public trust and no HSM;
revocation and pinning exist only in the production profile (§4.5), as a local CRL and a
local pin. The Wokwi simulator still reaches the host in the clear
through `wokwigw`, which is why §6 keeps the gateway on loopback.

What the refusal protects: the risk band and score, the matched policy rules and
the signed assertion the bank verifies. The step-up challenge and transaction
ids are **not** secrets — since D1 nothing an observer can do with them changes
a payment — and a refused step-up reply carries no risk context at all.

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

Those constants are from wokwigw's own `cmd/wokwigw/config.go`, not inferred. The gateway listens on
`127.0.0.1` only (IPv4): `localhost` may resolve to `::1` first, which it refuses, and the extension
retries IPv4. It answers `403` to a WebSocket client that sends no matching `Origin`, which is why the
helper's handshake sends `Origin: http://localhost:9011`.
The firmware targets `https://host.wokwi.internal:8000`, and `wokwi.toml`
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

Expected on 2026-10-01: **743 passed, 2 skipped** (745 collected, about 5 to 11 minutes). The
skips are the opt-in firmware build below -- run separately on 2026-09-23 and passing --
and Playwright's Firefox, which will not start on this machine. Both name their reason.

Tests are isolated from your live state: they override the transaction,
device and step-up stores, the bank client, the bank's replay cache and the
signing keys with `tmp_path` fixtures, so they neither read nor modify
`atlas_service/*.db`, `bank_service/*.db` or any real key directory.

Two corrections from 2026-09-25. The guard's check of the real key directories read their
paths after redirecting them, so it compared sandbox folders; it now captures them at
import (`tests/test_isolation_guard.py`). Because it now really watches them,
`scripts/audit_file_access.py` reports two directory listings per test -- of
`atlas_service/keys` and `shared_keys`, names, sizes and dates only -- and **0 file
opens** (on 2026-09-27: 1,358 listings for 679 tests, 0 opens; re-run the same day after signed policy updates, 689 tests: 0 opens). And the dashboard export -- a script, not a test
-- wrote the LIVE `bank_service/bank_ledger.db` from 2026-09-22 to 2026-09-25 because its
sweep never redirected the bank's ledger path; a test running at the same moment then
failed the guard, which is what the "webkit teardown error" was. Fixed and regression-
tested; the 24 records it left in the live ledger are untouched.

Until 2026-09-17 that was not quite true: ten tests in
`tests/test_phase3_device_trust.py` still opened `atlas_step_up.db` or
`atlas_transactions.db` at their default paths, without writing to either.
They were fixed, and since 2026-09-18 an autouse fixture in `tests/conftest.py`
guards **every** test: each default store path and key directory is pointed
into a per-test sandbox, and a test that leaves anything there fails. Run
`python scripts/audit_file_access.py` to watch a whole run from the outside —
it records every file open, SQLite connection and directory operation and
reports any that reached protected state.

`pytest.ini` sets `testpaths = tests`, so collection no longer walks the key
directories looking for test files.

Two parts of the suite need tools ATLAS does not depend on:

* **The dashboard page's JavaScript** (`tests/js/dashboard_page_tests.mjs`,
  44 checks) runs through `node` if it is installed, and is skipped with a
  reason if not. `node tests/js/dashboard_page_tests.mjs` runs it directly.
* **The browser matrix** (`tests/test_dashboard_browsers.py`, driven by
  `tests/browser/dashboard_matrix.mjs`) opens the real page in real engines — from the
  file, over a local HTTP server and in its failure state, at three widths in both light
  and dark themes, clicking every scenario. It needs Playwright, which ATLAS does not
  depend on, and skips with a reason when it is absent:

  ```bash
  npm install playwright && npx playwright install chromium webkit firefox
  # chrome and msedge use the browsers already installed on the machine
  .venv/Scripts/python.exe -m pytest tests/test_dashboard_browsers.py -q
  ```

  Set `ATLAS_PLAYWRIGHT_DIR` if Playwright lives somewhere other than the repository.
  Seven targets: Playwright's `chromium`, `webkit` and `firefox`; the installed Google Chrome
  and Microsoft Edge (`chrome`, `msedge`); and two EMULATIONS, `iphone-emulated` (WebKit, the
  iPhone 13 profile) and `android-emulated` (Chromium, the Pixel 7 profile), which tap
  rather than click and report `"emulated": true` -- they are not phones. On 2026-09-25 all
  six that start pass, with Chrome 153 and Edge 153; **Firefox does not start** — Playwright
  reports `spawn UNKNOWN`, diagnosed earlier as a missing Microsoft C++ runtime, which is a
  system install and not an ATLAS dependency — so that engine is skipped with its error
  recorded rather than claimed.
* **The firmware build** compiles the real sketch with `arduino-cli`, from a
  copy that uses `secrets.example.h`, so it never compiles the real seed. It
  takes about two minutes, so it is opt-in:

  ```bash
  ATLAS_FIRMWARE_BUILD=1 .venv/Scripts/python.exe -m pytest tests/test_firmware_behaviour.py -q -s
  ```

  The other firmware checks — wiring against `diagram.json`, the LED whitelist,
  the debounce, the step-up display — read the sketch and always run.

### Running the simulator against throwaway state

`run_sim.py --state-dir DIR` puts every database of the run in `DIR` instead of the live
ones, seeding the device registry and the step-up enrollment from the live files through
SQLite's read-only, immutable mode — they are never opened for writing:

```bash
python scripts/run_sim.py --state-dir C:/tmp/atlas-sim
```

The enrolled device and authenticator work, while every transaction, counter, challenge
and bank outcome of the run lands in `DIR`; delete `DIR` afterwards and nothing else
changed. It refuses a folder inside the repository. Use it for demos and experiments you
do not want in the real databases.

### The public-dataset benchmark

```bash
python scripts/benchmark_public_dataset.py      # writes docs/ml-public-benchmark.json
```

Downloads a public card-fraud dataset (OpenML #1597, ~66 MB, cached outside the
repository) and runs ATLAS's IsolationForest **configuration** on it, recording aggregates
only — never a row of the dataset, and never ATLAS's own features or history. It is an
outside reference point for the configuration, not a measurement of ATLAS.

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

Limits: 120s expiry, one challenge per transaction, single-use. Anything
unexpected resolves to DENY.

A failed proof costs the customer nothing (D1, 2026-09-18): it is audited and
refused, the challenge stays open, and the payment keeps waiting until a valid
proof arrives or the 120s runs out. Up to 10 failures per challenge are written
to `step_up_events`; past that the refusal still stands and only the audit rows
stop. Until that date the third failure closed the challenge and denied the
payment, which anyone holding the two ids could trigger.

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

### A request without a valid proof changes nothing

Neither the challenge id nor the transaction id is a secret. Both are shown on
the device, and both travel without TLS on the loopback path, so anything a
holder of those two ids could trigger is something an observer could trigger.
Since 2026-09-18 the answer is: nothing.

A `/v2/step-up` request that carries no valid proof — a **wrong
`transaction_id`**, an **invalid or malformed signature**, or **no enrolled
authenticator** — is refused and changes nothing. The challenge stays live, the
payment keeps waiting, the attempt is audited in `step_up_events`
(`BINDING_MISMATCH`, `INVALID_PROOF`, `NO_AUTHENTICATOR`), and the reply is
byte-for-byte the unknown-challenge reply: no risk band, no score, no rules, no
policy hash. Approving still requires the authenticator's Ed25519 signature.

Two earlier behaviours are gone: a wrong `transaction_id` cancelled the payment
until 2026-09-17, and three invalid proofs did until 2026-09-18
(`docs/STEP-UP-EXPIRY-FIX.md` §18–19).

**What still ends a challenge without a proof is the clock**, and only the
clock: at 120s the challenge expires, and the payment is denied — on the next
request naming it, or at the next service start.
