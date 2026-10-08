"""What the ESP32 sketch does, checked automatically (§10 B, 2026-09-18).

HONEST SCOPE, because this is easy to overstate. Three different things are
verified here, and none of them is "the firmware was run":

  * COMPILED. test_the_sketch_compiles builds the real sketch with arduino-cli
    and records the binary size. It proves the code builds for the target, not
    that it behaves.
  * READ. The rest are source-level checks of the shipped .ino against the
    wiring in diagram.json and against the security properties the sketch
    claims: which pin lights, what an unknown reply does, that a decision can
    only come from the server. A source check catches a change that breaks the
    property; it cannot catch a toolchain or hardware fault.
  * RUN, but only in Python. firmware/virtual_device.py is the tested twin of
    this protocol and tests/test_virtual_device.py executes it end to end
    against both services.

The sketch's own runtime has only ever been exercised by hand in the Wokwi
simulator (10 of 10 step-up checks observed as of 2026-09-23, the last three being
the approve path -- docs/ATLAS-Blueprint.md §5.10), and never on physical hardware.
That gap is real and stays documented.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SKETCH_DIR = ROOT / "firmware" / "atlas_device"
SKETCH = SKETCH_DIR / "atlas_device.ino"
DIAGRAM = SKETCH_DIR / "diagram.json"
FQBN = "esp32:esp32:esp32doit-devkit-v1"


def _code_only(source: str) -> str:
    """The sketch without its comments.

    The comments are where it explains what it does NOT do ("never sees a PIN,
    OTP or biometric"), so a check for forbidden behaviour has to read the code
    and not the prose about it.
    """
    without_block = re.sub(r"/\*.*?\*/", "", source, flags=re.S)
    return re.sub(r"//[^\n]*", "", without_block)


def _function_body(source: str, name: str) -> str:
    """The body of one C function, matched by braces rather than by a guessed
    end marker -- a nested block truncates a naive slice."""
    start = source.index("{", source.index(f"{name}(const") if f"{name}(const" in source
                         else source.index(f"{name}("))
    depth = 0
    for i in range(start, len(source)):
        depth += (source[i] == "{") - (source[i] == "}")
        if depth == 0:
            return source[start + 1:i]
    raise AssertionError(f"unbalanced braces around {name}")


@pytest.fixture(scope="module")
def source() -> str:
    return SKETCH.read_text(encoding="utf-8", errors="replace")


@pytest.fixture(scope="module")
def pins(source) -> dict[str, int]:
    return {m.group(1): int(m.group(2))
            for m in re.finditer(r"static const int (PIN_\w+)\s*=\s*(\d+);", source)}


# --------------------------------------------------------------------------
# Wiring: the sketch and the circuit have to agree on every pin
# --------------------------------------------------------------------------

def test_every_pin_the_sketch_drives_is_wired_in_the_circuit(pins):
    """A mismatch here is a demo that silently lights nothing."""
    diagram = json.loads(DIAGRAM.read_text(encoding="utf-8"))
    wired = {int(m.group(1))
             for connection in diagram["connections"]
             for endpoint in connection[:2]
             if (m := re.fullmatch(r"esp:D(\d+)", str(endpoint)))}

    assert set(pins.values()) == wired, (
        f"sketch drives {sorted(pins.values())}, circuit wires {sorted(wired)}"
    )


def test_the_three_leds_and_two_buttons_are_distinct_pins(pins):
    assert len(set(pins.values())) == len(pins) == 5, pins
    assert {"PIN_LED_GREEN", "PIN_LED_AMBER", "PIN_LED_RED",
            "PIN_BTN_SELECT", "PIN_BTN_SEND"} == set(pins)


def test_leds_are_outputs_and_buttons_are_pulled_up(source, pins):
    """A button read without INPUT_PULLUP floats, and a floating SEND pin
    submits payments on noise."""
    for led in ("PIN_LED_GREEN", "PIN_LED_AMBER", "PIN_LED_RED"):
        assert re.search(rf"pinMode\({led},\s*OUTPUT\)", source), f"{led} is never an output"
    for button in ("PIN_BTN_SELECT", "PIN_BTN_SEND"):
        assert re.search(rf"pinMode\({button},\s*INPUT_PULLUP\)", source), (
            f"{button} is not pulled up"
        )


def test_a_button_press_is_debounced_and_waits_for_release(source):
    """Otherwise one press sends several payments."""
    handler = source[source.index("digitalRead("):]
    assert re.search(r"if \(digitalRead\(pin\) == LOW\)[\s\S]{0,200}?delay\(", handler), (
        "no debounce delay after the first read"
    )
    assert "while (digitalRead(pin) == LOW)" in handler, (
        "the press is not held until release, so it repeats"
    )


# --------------------------------------------------------------------------
# The device displays; it never decides
# --------------------------------------------------------------------------

def test_only_the_exact_word_allow_can_light_green(source):
    """The whitelist, stated as a test: STATE_APPROVED has exactly one source,
    and that source is the server's own final_status."""
    mapping = _function_body(source, "interpretStatus")

    approving = [line for line in mapping.splitlines() if "STATE_APPROVED" in line]
    assert len(approving) == 1, f"more than one way to reach APPROVED: {approving}"
    assert 'strcmp(finalStatus, "ALLOW")' in approving[0], approving[0]

    # An assignment or a return, never a comparison: "st == STATE_APPROVED" only
    # reads the state that interpretStatus already decided.
    produced = re.findall(r"(?<![=!<>])=\s*STATE_APPROVED|return\s+STATE_APPROVED",
                          _code_only(source))
    assert len(produced) == 1, (
        f"the firmware can reach APPROVED without the server saying ALLOW: {produced}"
    )


def test_an_unrecognised_reply_fails_closed(source):
    """Every branch that cannot be understood ends dark-red, never green."""
    mapping = _function_body(source, "interpretStatus")

    assert mapping.strip().endswith("return STATE_FAIL_CLOSED;"), (
        "interpretStatus does not end in a fail-closed default"
    )
    assert "if (finalStatus == nullptr)" in mapping, "a missing status is not handled"


def test_exactly_one_led_is_lit_per_outcome(source):
    """All three are driven LOW first, so no stale light survives a new reply."""
    block = _function_body(source, "showState")
    cleared, lit = block[:block.index("switch")], block[block.index("switch"):]
    for led in ("PIN_LED_GREEN", "PIN_LED_AMBER", "PIN_LED_RED"):
        assert re.search(rf"digitalWrite\({led},\s*LOW\)", cleared), (
            f"{led} is not cleared before the new state is shown"
        )
    assert lit.count("HIGH") == 3, f"expected one HIGH per colour, got {lit.count('HIGH')}"
    green = [line for line in lit.splitlines() if "PIN_LED_GREEN" in line and "HIGH" in line]
    assert len(green) == 1, f"green is lit from {len(green)} places"
    assert "STATE_APPROVED" in lit[:lit.index(green[0])].splitlines()[-1], (
        "green is lit by something other than the approved state"
    )


def test_the_device_holds_no_decision_logic(source):
    """No thresholds, no scoring, no policy: the sketch may compare the reply
    to a whitelist and nothing else."""
    for forbidden in ("anomaly_score >", "risk_band ==", "amount >", "if (score",
                      "POLICY_ALLOW\") == 0 ? STATE_APPROVED"):
        assert forbidden not in source, f"decision logic in the firmware: {forbidden}"


# --------------------------------------------------------------------------
# Step-up on the device
# --------------------------------------------------------------------------

def test_the_device_shows_a_step_up_as_paused_and_never_confirms_it(source):
    """STEP_UP is an amber pause. The confirmation happens out of band, on the
    customer's own authenticator -- the device never holds a PIN, an OTP or a
    biometric, and never sends a proof."""
    assert re.search(r'strcmp\(finalStatus,\s*"STEP_UP"\)\s*==\s*0\)\s*return STATE_ATTENTION',
                     source), "STEP_UP is not shown as an amber pause"

    code = _code_only(source)
    for forbidden in ('/v2/step-up', 'step_up_proof', 'enterPin', 'readOtp', 'biometric',
                      '"proof"'):
        assert forbidden not in code, (
            f"the device takes part in step-up authentication: {forbidden}"
        )
    assert "never sees a PIN, OTP or biometric" in source, (
        "the sketch no longer states that the customer confirms out of band"
    )


def test_the_device_reports_a_security_refusal_as_itself(source):
    """A FAIL_CLOSED is an authentication failure, not a policy DENY, and the
    sketch must not dress one up as the other."""
    assert "dressed up as a policy deny" in source.lower(), (
        "the sketch does not say it keeps security refusals distinct from policy denials"
    )
    assert "isSecurityRejection(reason)" in source, "a FAIL_CLOSED is not routed by its reason"
    assert re.search(r'strcmp\(finalStatus,\s*"FAIL_CLOSED"\)\s*==\s*0\)\s*return STATE_FAIL_CLOSED',
                     source)


def test_the_sketch_states_what_is_and_is_not_encrypted(source):
    """D6 originally pinned "the Wokwi path is plain HTTP". That stopped being true on
    2026-09-27 (HTTPS only), and this test kept passing only because the word
    "plaintext" appeared in the old compiled-in-seed comment. Rewritten 2026-10-09 to
    pin what is true now, where someone changing the code will read it: the transport
    is HTTPS with no plain fallback, and the key in NVS is NOT encrypted at rest."""
    assert "There is no plain-HTTP fallback" in source
    assert "NVS is ordinary, UNENCRYPTED flash here" in source


# --------------------------------------------------------------------------
# Compilation
# --------------------------------------------------------------------------

def _repo_build_state() -> dict:
    """Modification times of the repository's own build outputs, if it has any.
    A compile that changes these has compiled in the wrong place."""
    build = SKETCH_DIR / "build"
    if not build.exists():
        return {}
    return {str(p): p.stat().st_mtime_ns for p in sorted(build.rglob("*")) if p.is_file()}


def _arduino_cli() -> str | None:
    found = shutil.which("arduino-cli")
    if found:
        return found
    candidate = Path.home() / ".local" / "bin" / "arduino-cli.exe"
    return str(candidate) if candidate.exists() else None


@pytest.mark.firmware
def test_the_sketch_compiles(tmp_path):
    """Builds the real sketch for the real target and records its size.

    Opt-in: about two minutes, and it needs the ESP32 core installed. It proves
    the sketch builds, which is the floor under every source check above -- not
    that the built firmware behaves.

    Built from a COPY: compiling in place rewrote the repository's own
    firmware/atlas_device/build/ artifacts (learned 2026-09-18). Since 2026-10-09
    the sketch needs no secret at all -- the identity and CA are loaded from NVS
    at start-up -- so the copy holds only the tracked sources, and a secrets.h or
    atlas_ca.h left in the folder is never copied in. The result carries no key.
    """
    cli = _arduino_cli()
    if cli is None:
        pytest.skip("arduino-cli not installed; cannot build the sketch")
    if os.environ.get("ATLAS_FIRMWARE_BUILD") != "1":
        pytest.skip("set ATLAS_FIRMWARE_BUILD=1 to build the sketch (takes about two minutes)")

    sketch_copy = tmp_path / "atlas_device"
    sketch_copy.mkdir()
    for name in ("atlas_device.ino", "diagram.json", "wokwi.toml", "gnss_nmea.h"):
        if (SKETCH_DIR / name).exists():
            shutil.copy2(SKETCH_DIR / name, sketch_copy / name)
    assert not (sketch_copy / "secrets.h").exists() and not (sketch_copy / "atlas_ca.h").exists()
    before_build = _repo_build_state()

    run = subprocess.run(
        [cli, "compile", "--fqbn", FQBN,
         "--build-path", str(tmp_path / "build"), "--output-dir", str(tmp_path / "out"),
         "--warnings", "default", "."],
        cwd=sketch_copy, capture_output=True, encoding="utf-8", errors="replace", timeout=900,
    )

    assert run.returncode == 0, f"{run.stdout}\n{run.stderr}"
    binary = tmp_path / "out" / "atlas_device.ino.bin"
    assert binary.exists(), (
        f"no binary produced: {sorted(p.name for p in (tmp_path / 'out').iterdir())}"
    )
    assert _repo_build_state() == before_build, (
        "the build wrote into the repository's own firmware build directory"
    )

    # arduino-cli reports the flash budget; a build that does not fit is a build
    # that cannot run, whatever the source says.
    usage = re.search(r"Sketch uses (\d+) bytes \((\d+)%\)", run.stdout + run.stderr)
    assert usage, f"arduino-cli did not report flash usage:\n{run.stdout}"
    used, percent = int(usage.group(1)), int(usage.group(2))
    print(f"\n[firmware] {binary.name}: {binary.stat().st_size} bytes; "
          f"sketch uses {used} bytes ({percent}% of program storage)")
    assert percent < 100, f"the sketch does not fit in flash: {percent}%"

    # GitHub's device-build workflow keeps the build as a downloadable artifact. It
    # holds no identity of any kind; a local NVS image supplies one (provision_nvs.py).
    keep = os.environ.get("ATLAS_FIRMWARE_OUT")
    if keep:
        Path(keep).mkdir(parents=True, exist_ok=True)
        for name in ("atlas_device.ino.bin", "atlas_device.ino.elf", "atlas_device.ino.merged.bin"):
            shutil.copy2(tmp_path / "out" / name, Path(keep) / name)


# --------------------------------------------------------------------------
# GNSS receiver on UART2 (2026-10-09)
# --------------------------------------------------------------------------

def test_the_gnss_receiver_is_wired_to_uart2(source):
    """The sketch reads GPIO16 and the circuit connects the receiver's TX there."""
    assert re.search(r"GNSS_UART_RX_PIN\s*=\s*16;", source)
    assert re.search(r"GNSS_UART_TX_PIN\s*=\s*17;", source)
    assert "Serial2.begin(GNSS_BAUD, SERIAL_8N1, GNSS_UART_RX_PIN, GNSS_UART_TX_PIN)" in source
    diagram = json.loads(DIAGRAM.read_text(encoding="utf-8"))
    parts = {p["id"]: p["type"] for p in diagram["parts"]}
    assert parts.get("gnss") == "chip-atlas-gnss"
    links = {tuple(c[:2]) for c in diagram["connections"]}
    for pair in (("gnss:TX", "esp:RX2"), ("gnss:RX", "esp:TX2"), ("gnss:VCC", "esp:3V3")):
        assert pair in links, pair
    toml = (SKETCH_DIR / "wokwi.toml").read_text(encoding="utf-8")
    assert 'name = "atlas-gnss"' in toml and 'binary = "chips/atlas-gnss.chip.wasm"' in toml


def test_the_gnss_reader_reports_and_never_judges(source):
    """No home area, grade or rule below the policy layer: the reader produces
    evidence, and the sketch displays ATLAS's grade without comparing it."""
    reader = (SKETCH_DIR / "gnss_nmea.h").read_text(encoding="utf-8")
    code = _code_only(reader) + _code_only(source)
    for forbidden in ("GEOFENCE", "OUTSIDE_", "WITHIN_", "radius", "home_lat", "confidence ==",
                      '"MEDIUM"', '"LOW"', "haversine"):
        assert forbidden not in code, f"location judgement on the device: {forbidden}"
    for line in source.splitlines():
        if '["confidence"]' in line or '["geofence"]' in line or '["implausible_travel"]' in line:
            for branch in ("strcmp", "==", "!=", "if (", "switch"):
                assert branch not in line, f"the device acts on ATLAS's location grade: {line.strip()}"


def test_the_device_sources_hold_no_raw_control_characters_or_broken_literals():
    """Found by the first GitHub build, 2026-10-09: an editing step had turned C escapes
    (backslash-r-backslash-n, backslash-n, backslash-0) into real line breaks and a real NUL
    inside string literals. No local test compiles the sketch, so this checks the text: no
    raw CR, NUL or other control character, and no string or character literal left open
    at the end of a line."""
    files = [SKETCH, SKETCH_DIR / "gnss_nmea.h", SKETCH_DIR / "chips" / "atlas-gnss.chip.c",
             ROOT / "tests" / "c" / "gnss_parity.c"]
    for path in files:
        raw = path.read_bytes().replace(b"\r\n", b"\n")
        bad = sorted({b for b in raw if b < 32 and b not in (9, 10)})
        assert not bad, f"{path.name} holds raw control characters {bad}"
        in_comment = False
        for number, line in enumerate(raw.decode("utf-8").split("\n"), 1):
            code = re.sub(r"\\.", "x", line)                          # escaped characters
            if in_comment:
                if "*/" not in code:
                    continue
                code, in_comment = code.split("*/", 1)[1], False
            code = re.sub(r'"[^"]*"', '""', code)                      # complete strings first
            code = re.sub(r"'[^']'", "''", code)                       # character literals
            code = re.sub(r"/\*.*?\*/", "", code)                      # one-line comments
            if "/*" in code:
                code, in_comment = code.split("/*", 1)[0], True
            code = code.split("//")[0]
            leftover = re.sub(r"''|\"\"", "", code)
            assert '"' not in leftover and "'" not in leftover, (
                f"{path.name}:{number}: a literal is left open: {line.strip()[:80]}")


def test_every_payment_signs_the_gnss_reading_it_has_now(source):
    send = source[source.index("if (pressed(PIN_BTN_SEND))"):]
    assert send.index("pollGnss();") < send.index("gnss_evidence_json(&g_gnss, locationJson")
    assert send.index("gnss_evidence_json(") < send.index("buildCanonical(e, locationJson")
    assert send.index("buildCanonical(") < send.index("signCanonical(canonical")
