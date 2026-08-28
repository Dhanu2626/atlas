"""Step 8: the ATLAS edge device, tested against the real atlas_service.

firmware/atlas_device/atlas_device.ino is NOT exercised here -- it cannot be
compiled or run in this environment, and no test in this suite should be read
as evidence that it works. What IS tested is firmware/virtual_device.py, the
executable model of the same three-layer logic, wired to the genuinely
running atlas_service and bank_service apps.

The test carrying the most weight is
test_green_is_reachable_only_from_an_explicit_allow: the device's entire
security contribution is that it cannot manufacture an approval, and that
test enumerates every status the device might ever see to prove it.
"""

from __future__ import annotations

import ast
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from atlas_service.db import TransactionStore
from atlas_service.main import app as atlas_app
from atlas_service.main import get_bank_client, get_signing_keys_dir, get_transaction_store
from bank_service.main import app as bank_app
from contracts import Transaction
from firmware.virtual_device import (
    DEFAULT_PRESETS,
    DeviceConfig,
    DeviceState,
    Led,
    RawEvent,
    UnknownPresetError,
    assemble_transaction,
    handle_event,
    interpret_response,
    led_for,
    read_event,
)
from tests.conftest import wire_bank_app_to_keys

ATLAS_ROOT = Path(__file__).resolve().parent.parent

NOW = datetime(2026, 8, 26, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def keys_dir(tmp_path) -> Path:
    return tmp_path / "atlas-keys"


@pytest.fixture(autouse=True)
def _wire(keys_dir, tmp_path):
    wire_bank_app_to_keys(keys_dir, tmp_path / "replay.db")
    yield
    bank_app.dependency_overrides.clear()
    atlas_app.dependency_overrides.clear()


@pytest.fixture
def atlas_client(keys_dir, tmp_path) -> TestClient:
    """The real atlas_service, wired to the real bank_service -- the device
    talks to the actual system, not a stub of it."""
    bank = TestClient(bank_app)
    atlas_app.dependency_overrides[get_bank_client] = lambda: bank
    atlas_app.dependency_overrides[get_signing_keys_dir] = lambda: keys_dir
    atlas_app.dependency_overrides[get_transaction_store] = lambda: TransactionStore(
        tmp_path / "atlas.db"
    )
    return TestClient(atlas_app)


@pytest.fixture
def config() -> DeviceConfig:
    return DeviceConfig(atlas_url="http://atlas")


# --- 1. raw event -> correct Transaction -------------------------------------


def test_raw_event_assembles_into_a_contract_valid_transaction(config):
    """The device emits a plain dict, exactly as the firmware emits JSON.
    Feeding that dict to the real Transaction model is what proves the wire
    shape is correct -- if the device ever drifted from the contract, this
    fails."""
    event = read_event(preset_id=0, sequence=7, now=NOW)
    body = assemble_transaction(event, config)

    transaction = Transaction(**body)  # raises if the device's shape is wrong

    assert transaction.subject == "user-demo-1"
    assert transaction.beneficiary == "ben-mother"
    assert str(transaction.amount) == "1500.00"
    assert transaction.currency == "INR"
    assert transaction.device_id == "esp32-atlas-demo-01"
    assert transaction.timestamp == NOW.isoformat()


def test_amount_is_derived_from_integer_minor_units_without_float_error(config):
    """Money on an MCU is integer minor units; a float would round wrong.
    6_000_000 paise must be exactly 60000.00, not 59999.99..."""
    body = assemble_transaction(read_event(preset_id=1, sequence=1, now=NOW), config)
    assert body["amount"] == "60000.00"


def test_transaction_ids_are_unique_per_press(config):
    ids = {
        assemble_transaction(read_event(0, seq, now=NOW), config)["transaction_id"]
        for seq in range(5)
    }
    assert len(ids) == 5


def test_device_does_not_assert_behavioral_flags(config):
    """The device must not claim is_new_beneficiary / is_emergency_request
    etc. Those are ATLAS's to determine from history; a device asserting
    them would be reaching for influence over a decision that is not its
    own."""
    body = assemble_transaction(read_event(0, 1, now=NOW), config)
    for flag in (
        "is_new_beneficiary", "is_new_device", "is_international",
        "declared_travel_mode", "is_emergency_request",
    ):
        assert flag not in body


def test_unconfigured_preset_fails_closed(config):
    with pytest.raises(UnknownPresetError):
        assemble_transaction(read_event(preset_id=99, sequence=1, now=NOW), config)


# --- 2. response -> device state, against the REAL atlas_service ------------


def test_allow_lights_green_end_to_end(atlas_client, config):
    result = handle_event(read_event(0, 1, now=NOW), config, atlas_client)
    assert result.final_status == "ALLOW"
    assert result.state == DeviceState.APPROVED
    assert result.led == Led.GREEN


def test_step_up_lights_amber_end_to_end(atlas_client, config):
    """Preset 1 (60000.00) crosses user-demo-1's large_amount rule."""
    result = handle_event(read_event(1, 2, now=NOW), config, atlas_client)
    assert result.final_status == "STEP_UP"
    assert result.state == DeviceState.ATTENTION
    assert result.led == Led.AMBER


def test_deny_lights_red_end_to_end(atlas_client, config):
    """Preset 2 (150000.00) crosses hard_cap; most-restrictive-wins makes it
    a DENY even though large_amount also matches."""
    result = handle_event(read_event(2, 3, now=NOW), config, atlas_client)
    assert result.final_status == "DENY"
    assert result.state == DeviceState.REFUSED
    assert result.led == Led.RED


def test_bank_override_still_only_reaches_the_device_as_deny(atlas_client):
    """Step 0-7 behavior seen from the edge: ATLAS says ALLOW, the bank
    independently refuses, and the device shows red. The device plays no
    part in resolving that conflict -- it only displays the result."""
    frozen_config = DeviceConfig(atlas_url="http://atlas", subject="user-frozen-1")
    result = handle_event(read_event(0, 4, now=NOW), frozen_config, atlas_client)
    assert result.final_status == "DENY"
    assert result.led == Led.RED


# --- 3. fail-closed: unreachable, malformed, partial ------------------------


def test_atlas_unreachable_fails_closed_and_never_signals_approval(config):
    """A genuinely closed TCP port, not a mock."""
    unreachable = DeviceConfig(atlas_url="http://127.0.0.1:1", timeout_seconds=1.0)
    result = handle_event(read_event(0, 1, now=NOW), unreachable, httpx.Client())

    assert result.state == DeviceState.FAIL_CLOSED
    assert result.led == Led.RED
    assert result.led is not Led.GREEN
    assert result.final_status is None


@pytest.mark.parametrize(
    "body",
    [
        {},                                   # empty object
        {"decision": {"decision": "ALLOW"}},  # decision present, final_status missing
        {"final_status": None},               # explicit null
        {"final_status": 200},                # wrong type
        {"final_status": ["ALLOW"]},          # wrong type, contains the magic word
        {"final_status": "allow"},            # wrong case
        {"final_status": "ALLOW "},           # trailing whitespace
        {"final_status": "APPROVED"},         # plausible but not a real status
        {"final_status": ""},                 # empty string
        # The pre-Phase-2 unknown-rail reply. /transact now returns a structured
        # {"final_status": "FAIL_CLOSED", "decision_reason": "UNKNOWN_RAIL", ...}
        # instead, so this is kept as a historical/legacy shape: any body lacking
        # final_status must still fail closed, whatever produced it.
        {"error": "unknown rail 'SWIFT'"},
        [],                                   # not an object at all
        "ALLOW",                              # bare string
        None,
    ],
)
def test_malformed_or_partial_responses_fail_closed(body):
    state = interpret_response(body)
    assert state == DeviceState.FAIL_CLOSED
    assert led_for(state) == Led.RED


def test_http_error_status_fails_closed(config):
    """A 500 from ATLAS must not be interpreted -- raise_for_status turns it
    into a transport failure, and the device fails closed."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"final_status": "ALLOW"})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    result = handle_event(read_event(0, 1, now=NOW), config, client)

    assert result.state == DeviceState.FAIL_CLOSED
    assert result.led == Led.RED


def test_non_json_body_fails_closed(config):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>gateway error</html>")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    result = handle_event(read_event(0, 1, now=NOW), config, client)

    assert result.state == DeviceState.FAIL_CLOSED
    assert result.led == Led.RED


# --- 4. the adversarial invariant -------------------------------------------


def test_green_is_reachable_only_from_an_explicit_allow():
    """The device's whole security contribution, stated as an enumeration:
    of every status it might ever receive, exactly one lights green. A
    device that cannot manufacture an approval cannot be turned into one by
    a compromised or malicious response."""
    candidates = [
        "ALLOW", "DENY", "STEP_UP", "DELAY", "PENDING",
        "APPROVED", "OK", "SUCCESS", "allow", "Allow", "ALLOWED", "TRUE", "1", "",
    ]
    green = [s for s in candidates if led_for(interpret_response({"final_status": s})) == Led.GREEN]
    assert green == ["ALLOW"]


def test_no_state_other_than_approved_lights_green():
    for state in DeviceState:
        if state != DeviceState.APPROVED:
            assert led_for(state) != Led.GREEN, f"{state} must not light green"
    assert led_for(DeviceState.APPROVED) == Led.GREEN


def test_a_deny_response_cannot_be_coerced_into_approval(atlas_client, config):
    """End-to-end version of the same guarantee: a real DENY from the real
    service, with an ALLOW-looking decoy field alongside it, still shows
    red. The device reads final_status and nothing else."""
    result = handle_event(read_event(2, 9, now=NOW), config, atlas_client)
    assert result.final_status == "DENY"

    decoyed = dict(result.raw_response or {})
    decoyed["decision"] = {"decision": "ALLOW"}
    decoyed["approved"] = True
    decoyed["bank_verdict"] = {"approved": True}

    assert interpret_response(decoyed) == DeviceState.REFUSED


# --- 5. the device is on the untrusted edge ---------------------------------


def _imported_module_paths(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    paths: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            paths.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            paths.add(node.module)
    return paths


def test_virtual_device_never_imports_atlas_internals():
    """The device is the untrusted edge (Blueprint 24.2). It must not reach
    into ATLAS's key handling, policy, or ML -- and notably does not import
    `contracts` either: a real ESP32 has no access to Python models, so
    importing one here would let the device drift from the JSON shape the
    firmware actually has to produce. Same discipline as
    test_bank_boundary.py and test_adapters.py."""
    imports = _imported_module_paths(ATLAS_ROOT / "firmware" / "virtual_device.py")
    forbidden = {"atlas_service", "bank_service", "contracts"}
    leaked = {i for i in imports if i.split(".")[0] in forbidden}
    assert not leaked, (
        f"firmware/virtual_device.py imports {leaked} -- the edge device must not "
        f"depend on ATLAS internals or server-side models"
    )


def test_presets_exercise_all_three_demo_outcomes():
    """Pins the demo presets so the Wokwi walkthrough cannot silently stop
    demonstrating ALLOW / STEP_UP / DENY."""
    assert [p.amount_minor for p in DEFAULT_PRESETS] == [150_000, 6_000_000, 15_000_000]
