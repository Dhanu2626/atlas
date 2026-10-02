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


def test_the_sketch_states_that_its_transport_is_unencrypted(source):
    """D6: the Wokwi path is plain HTTP to the host, and the file says so where
    someone changing the URL will read it."""
    assert re.search(r"no TLS|not encrypted|plaintext|simulation only", source, re.I)


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

    Built from a COPY, with secrets.example.h standing in for secrets.h, for two
    reasons learned on 2026-09-18: compiling in place rewrote the repository's
    own firmware/atlas_device/build/ artifacts, and compiling against the real
    secrets.h baked this device's private seed into a binary in the temp folder.
    The copy takes neither the repository's build directory nor its secret.
    """
    cli = _arduino_cli()
    if cli is None:
        pytest.skip("arduino-cli not installed; cannot build the sketch")
    if os.environ.get("ATLAS_FIRMWARE_BUILD") != "1":
        pytest.skip("set ATLAS_FIRMWARE_BUILD=1 to build the sketch (takes about two minutes)")

    sketch_copy = tmp_path / "atlas_device"
    sketch_copy.mkdir()
    for name in ("atlas_device.ino", "diagram.json", "wokwi.toml"):
        if (SKETCH_DIR / name).exists():
            shutil.copy2(SKETCH_DIR / name, sketch_copy / name)
    example = SKETCH_DIR / "secrets.example.h"
    assert example.exists(), "secrets.example.h is missing; the build has no stand-in secret"
    shutil.copy2(example, sketch_copy / "secrets.h")
    shutil.copy2(SKETCH_DIR / "atlas_ca.example.h", sketch_copy / "atlas_ca.h")
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
