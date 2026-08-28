"""virtual_device.py -- the ATLAS edge device, as testable Python.

This is the executable model of what firmware/atlas_device/atlas_device.ino
does on a simulated ESP32, and it is where the CORRECTNESS of Step 8 is
actually proven. The .ino is the visual demo; this file is the part covered
by the automated suite. BUILD-PLAN.md already named this file as the Step 8
fallback -- it is promoted here to the primary artifact for testing, with
Wokwi as presentation.

Layer separation (BUILD-PLAN.md requirement, and Blueprint 24.2/24.4): the
three sections below are kept logically distinct even though a single
simulated ESP32 board runs all of them in Wokwi --

  1. EVENT ACQUISITION   a physical press produces a RawEvent. Knows nothing
                         about transactions, HTTP, or ATLAS.
  2. ASSEMBLY            RawEvent + DeviceConfig -> a Transaction-shaped
                         dict. Deliberately a plain dict, not a pydantic
                         model: an ESP32 emits JSON, and building the model
                         here would test this file's imports rather than the
                         wire shape the firmware actually produces.
  3. NETWORK + RESPONSE  sign a DeviceEnvelope and POST it to
                         atlas_service's /v2/transact, read final_status,
                         map to a device state. No new protocol -- this is
                         Blueprint 24.3's already-specified device signing,
                         implemented rather than redesigned.

TWO PATHS EXIST, DELIBERATELY (both mirror the real system):

  handle_event_signed()  CURRENT. Signs a DeviceEnvelope with the device key
                         and POSTs to /v2/transact. This is what
                         atlas_device.ino does as of F3.
  handle_event()         LEGACY. Posts a bare Transaction to /transact with
                         no authentication. Kept because that endpoint is
                         still open in production -- closing it is deferred
                         to Phase 3.8 -- so a model that dropped it would
                         misrepresent the system rather than simplify it.

WHAT THIS DEVICE MUST NEVER DO (frozen, Blueprint 24.2/24.3):
no ALLOW/DENY/STEP_UP decision of its own, no ML scoring, no policy
evaluation, no ATLAS assertion signing, no ATLAS private key, no policy
file. It is a witness and a display, never a judge. The device cannot even
influence the decision by lying about transaction flags -- the policy engine
recomputes is_new_beneficiary from history and ignores what the client
claims (see tests/test_policy_engine.py::test_client_lying_about_new_
beneficiary_is_ignored).

DEVICE SIGNING, AND EXACTLY WHAT IT PROVES (F3). The device holds its OWN
Ed25519 key -- see firmware/device_identity.py -- entirely separate from the
ATLAS key that signs bank assertions. Every field of the envelope except the
signature is covered by it, so tampering in flight is rejected before the
policy engine ever runs.

A valid signature proves POSSESSION OF THE ENROLLED KEY. It does NOT prove
the identity of a physical device: the key sits in an ordinary file here, and
in ordinary flash on real hardware. Hardware-rooted identity needs a secure
element and does not exist in this project. Blueprint 24.6's forged-device-
identity gap (RQ-7/12/24) remains open and is not closed by this file.
"""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
from enum import Enum

import httpx

# ---------------------------------------------------------------------------
# Device states and indicators
# ---------------------------------------------------------------------------


class DeviceState(str, Enum):
    """What the device believes happened. Deliberately finer-grained than
    the three LED colors: REFUSED (ATLAS/bank said no) and FAIL_CLOSED
    (something broke, or the response could not be trusted) both light red,
    but conflating them in the model would lose the distinction that
    matters when reasoning about failures."""

    IDLE = "IDLE"
    APPROVED = "APPROVED"
    REFUSED = "REFUSED"
    ATTENTION = "ATTENTION"      # STEP_UP / DELAY -- user action needed
    UNRESOLVED = "UNRESOLVED"    # ATLAS reached, outcome genuinely not known yet
    FAIL_CLOSED = "FAIL_CLOSED"  # unreachable, malformed, or unrecognized


class Led(str, Enum):
    OFF = "OFF"
    GREEN = "GREEN"
    AMBER = "AMBER"
    RED = "RED"


_LED_FOR_STATE: dict[DeviceState, Led] = {
    DeviceState.IDLE: Led.OFF,
    DeviceState.APPROVED: Led.GREEN,
    DeviceState.REFUSED: Led.RED,
    DeviceState.ATTENTION: Led.AMBER,
    DeviceState.UNRESOLVED: Led.AMBER,
    DeviceState.FAIL_CLOSED: Led.RED,
}


def led_for(state: DeviceState) -> Led:
    """GREEN is reachable from exactly one state (APPROVED), which is itself
    reachable from exactly one final_status ("ALLOW"). That chain is the
    device's entire security contribution and is asserted directly in
    tests/test_virtual_device.py."""
    return _LED_FOR_STATE[state]


# ---------------------------------------------------------------------------
# 1. EVENT ACQUISITION -- knows nothing about ATLAS
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RawEvent:
    """What a physical press produces. Blueprint 24.4: the peripheral layer
    hands over "tag ID X read at time T" -- NOT a Transaction. Assembly is
    somebody else's job precisely so the sensor layer can never smuggle
    financial meaning into the pipeline."""

    preset_id: int
    pressed_at: str  # ISO 8601
    sequence: int


def read_event(preset_id: int, sequence: int, now: datetime | None = None) -> RawEvent:
    """Stands in for the button ISR in atlas_device.ino. `now` is injectable
    because a device's clock is not automatically trustworthy -- see
    firmware/README.md's note on why a wrong device clock changes which
    TIME_WINDOW policy rules fire."""
    now = now or datetime.now(timezone.utc)
    return RawEvent(preset_id=preset_id, pressed_at=now.isoformat(), sequence=sequence)


# ---------------------------------------------------------------------------
# 2. ASSEMBLY -- RawEvent -> Transaction-shaped dict
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Preset:
    """A button-selectable payment. Amounts are in minor units (paise), the
    way an embedded device would carry them -- integer arithmetic only, no
    floats anywhere near money on an MCU."""

    beneficiary: str
    amount_minor: int


# Chosen to exercise all three outcomes against the shipped user-demo-1
# policy: 1500 is under every threshold; 60000 crosses large_amount
# (STEP_UP); 150000 crosses hard_cap (DENY, most-restrictive-wins).
DEFAULT_PRESETS: tuple[Preset, ...] = (
    Preset(beneficiary="ben-mother", amount_minor=150_000),
    Preset(beneficiary="ben-newshop", amount_minor=6_000_000),
    Preset(beneficiary="ben-newshop", amount_minor=15_000_000),
)


def new_boot_id() -> str:
    """A fresh random id for one power-on, mirroring esp_random() in
    atlas_device.ino's setup().

    Phase 2 defect fix. The sequence counter lives in RAM and resets to 0 on
    every restart, so `<device>-0001` was re-sent after each Wokwi restart,
    collided with an already-terminal transaction, and crashed /transact with
    a 500. A per-boot random component makes ids unique across restarts
    without needing persistent storage on the device.

    DeviceConfig.boot_id deliberately keeps a FIXED default so tests stay
    deterministic; a real device calls this at boot.
    """
    return secrets.token_hex(4)


@dataclass(frozen=True)
class DeviceConfig:
    atlas_url: str = "http://127.0.0.1:8000"
    subject: str = "user-demo-1"
    device_id: str = "esp32-atlas-demo-01"
    boot_id: str = "boot0001"
    currency: str = "INR"
    location: str = "Bengaluru,IN"
    authentication_method: str = "device_button"
    rail: str = "UPI"
    presets: tuple[Preset, ...] = DEFAULT_PRESETS
    timeout_seconds: float = 5.0


class UnknownPresetError(Exception):
    """Fail-closed: a press mapping to no configured preset must not
    silently become some default payment."""


def assemble_transaction(event: RawEvent, config: DeviceConfig) -> dict:
    """Builds the exact JSON body the firmware POSTs.

    Every behavioral flag is left at its contract default. The device does
    not know and must not guess whether a beneficiary is new, whether the
    device is new, or whether this is an emergency -- those are ATLAS's to
    determine from history. Asserting them here would be the device
    reaching for influence over a decision that is not its to make.
    """
    if not 0 <= event.preset_id < len(config.presets):
        raise UnknownPresetError(
            f"preset {event.preset_id} is not configured (have {len(config.presets)})"
        )
    preset = config.presets[event.preset_id]

    # Integer minor units -> decimal string, without ever touching a float.
    amount = Decimal(preset.amount_minor).scaleb(-2)

    return {
        "transaction_id": f"{config.device_id}-{config.boot_id}-{event.sequence:04d}",
        "subject": config.subject,
        "amount": f"{amount:.2f}",
        "currency": config.currency,
        "beneficiary": preset.beneficiary,
        "location": config.location,
        "device_id": config.device_id,
        "authentication_method": config.authentication_method,
        "timestamp": event.pressed_at,
    }


# ---------------------------------------------------------------------------
# 3. NETWORK + RESPONSE HANDLING -- the fail-closed core
# ---------------------------------------------------------------------------

# Whitelist, deliberately not a blacklist. Anything not listed here -- a new
# status ATLAS might add later, a typo, a truncated body, an injected value
# -- lands in FAIL_CLOSED rather than being optimistically interpreted.
_STATUS_TO_STATE: dict[str, DeviceState] = {
    "ALLOW": DeviceState.APPROVED,
    "DENY": DeviceState.REFUSED,
    "STEP_UP": DeviceState.ATTENTION,
    "DELAY": DeviceState.ATTENTION,
    "PENDING": DeviceState.UNRESOLVED,
    # Explicit as of Phase 2: ATLAS now reports FAIL_CLOSED as a first-class
    # status. It already landed in FAIL_CLOSED via the unknown-status default,
    # but only by accident -- listing it makes the mapping intentional and
    # lets decision_reason be surfaced rather than discarded.
    "FAIL_CLOSED": DeviceState.FAIL_CLOSED,
}

# Reasons the DEVICE determines for itself, when the backend never got to
# speak. Kept separate from contracts.DecisionReason on purpose: the device
# must not import server-side models (see the untrusted-edge test), and these
# describe local conditions the backend cannot observe.
DEVICE_REASON_ATLAS_UNREACHABLE = "ATLAS_UNREACHABLE"
DEVICE_REASON_MALFORMED_RESPONSE = "MALFORMED_RESPONSE"
DEVICE_REASON_UNCONFIGURED_PRESET = "UNCONFIGURED_PRESET"


def interpret_response(body: object) -> DeviceState:
    """Maps an ATLAS response body to a device state, failing closed on
    anything it does not positively recognize.

    Note this also covers /transact's unknown-rail reply, which carries an
    "error" key and no final_status at all -- that is a malformed result
    from the device's point of view and must not be displayed as anything
    reassuring.
    """
    if not isinstance(body, dict):
        return DeviceState.FAIL_CLOSED

    status = body.get("final_status")
    if not isinstance(status, str):
        return DeviceState.FAIL_CLOSED

    return _STATUS_TO_STATE.get(status, DeviceState.FAIL_CLOSED)


@dataclass(frozen=True)
class DeviceResult:
    state: DeviceState
    led: Led
    transaction: dict
    final_status: str | None = None
    #: Why, in machine-readable form. Either echoed from the backend's
    #: decision_reason, or one of the DEVICE_REASON_* constants when the
    #: device decided locally (backend unreachable, response unusable).
    decision_reason: str | None = None
    detail: str = ""
    raw_response: dict | None = field(default=None, repr=False)


def build_envelope(
    transaction: dict,
    config: DeviceConfig,
    keys_dir,
    *,
    now: datetime | None = None,
    counter: int | None = None,
) -> dict:
    """Wraps an assembled Transaction in a signed DeviceEnvelope (Phase 3.3).

    Returns a plain dict for the same reason assemble_transaction does: the
    ESP32 emits JSON, and building a pydantic model here would test this
    file's imports rather than the wire shape the firmware must produce.

    The signature covers EVERY field except itself, via the shared
    canonical_envelope_bytes discipline -- so amount, beneficiary, device_id,
    counter, nonce, and timestamp are all tamper-evident in flight.

    location/health are carried and signed but are NOT graded by anything in
    Phase 3.3. They are in the signed surface now so adding grading later
    does not change the signed bytes and invalidate enrolled devices.
    """
    from firmware import device_identity

    now = now or datetime.now(timezone.utc)
    envelope = {
        "device_id": config.device_id,
        "device_key_id": device_identity.get_key_id(keys_dir),
        "boot_id": config.boot_id,
        "counter": counter if counter is not None else device_identity.next_counter(keys_dir),
        "nonce": secrets.token_hex(16),
        "issued_at": now.isoformat(),
        "transaction": _full_transaction_fields(transaction),
        "location": None,
        "health": None,
    }
    signing_input = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")
    envelope["signature"] = device_identity.secure_sign(signing_input, keys_dir)
    return envelope


#: Every Transaction field the device must emit, with the contract's own
#: defaults spelled out as literals.
#:
#: WHY THIS EXISTS: the server derives the signed bytes from the fully-parsed
#: Transaction model, which fills in defaults. A device that emitted only the
#: fields it cares about would sign a SHORTER byte string than the server
#: derives, and every signature would fail. Both sides must serialise the
#: same complete field set.
#:
#: The literals are duplicated here rather than imported because this module
#: must not depend on server-side models (the untrusted-edge boundary test) --
#: and because the real C firmware has no access to pydantic either and must
#: hardcode exactly these same defaults. If contracts.Transaction ever gains a
#: field, this dict and the .ino must both be updated; the round-trip test in
#: tests/test_phase3_device_trust.py is what catches it if they are not.
_TRANSACTION_DEFAULTS: dict[str, object] = {
    "merchant_category": None,
    "is_new_beneficiary": False,
    "is_new_device": False,
    "is_international": False,
    "declared_travel_mode": False,
    "is_emergency_request": False,
}


def _full_transaction_fields(transaction: dict) -> dict:
    """Fills in contract defaults the device did not set.

    This is NOT the device asserting anything about those flags -- they are
    the contract's own defaults, and the policy engine recomputes
    is_new_beneficiary / is_new_device from history regardless of what
    arrives (tests/test_policy_engine.py::test_client_lying_about_new_
    beneficiary_is_ignored). Emitting them is a serialisation requirement,
    not a truth claim.
    """
    full = dict(_TRANSACTION_DEFAULTS)
    full.update(transaction)
    return full


def submit_envelope(envelope: dict, config: DeviceConfig, client: httpx.Client) -> object:
    """POSTs a signed envelope to the authenticated /v2/transact path."""
    response = client.post(
        f"{config.atlas_url}/v2/transact",
        params={"rail": config.rail},
        json=envelope,
        timeout=config.timeout_seconds,
    )
    response.raise_for_status()
    return response.json()


def handle_event_signed(
    event: RawEvent, config: DeviceConfig, client: httpx.Client, keys_dir
) -> DeviceResult:
    """The Phase 3.3 device loop: assemble -> sign -> submit -> interpret.

    Identical fail-closed discipline to handle_event(); the only difference
    is that the request now proves who sent it.
    """
    try:
        transaction = assemble_transaction(event, config)
        envelope = build_envelope(transaction, config, keys_dir)
    except (UnknownPresetError, Exception) as exc:  # noqa: BLE001 - fail closed on anything
        if isinstance(exc, UnknownPresetError):
            reason = DEVICE_REASON_UNCONFIGURED_PRESET
        else:
            reason = DEVICE_REASON_MALFORMED_RESPONSE
        return DeviceResult(
            state=DeviceState.FAIL_CLOSED,
            led=led_for(DeviceState.FAIL_CLOSED),
            transaction={},
            decision_reason=reason,
            detail=f"{type(exc).__name__}: {exc}",
        )

    try:
        body = submit_envelope(envelope, config, client)
    except (httpx.HTTPError, json.JSONDecodeError, ValueError) as exc:
        return DeviceResult(
            state=DeviceState.FAIL_CLOSED,
            led=led_for(DeviceState.FAIL_CLOSED),
            transaction=transaction,
            decision_reason=DEVICE_REASON_ATLAS_UNREACHABLE,
            detail=f"{type(exc).__name__}: {exc}",
        )

    state = interpret_response(body)
    final_status = body.get("final_status") if isinstance(body, dict) else None
    final_status = final_status if isinstance(final_status, str) else None
    backend_reason = body.get("decision_reason") if isinstance(body, dict) else None
    return DeviceResult(
        state=state,
        led=led_for(state),
        transaction=transaction,
        final_status=final_status,
        decision_reason=backend_reason if isinstance(backend_reason, str)
        else DEVICE_REASON_MALFORMED_RESPONSE,
        raw_response=body if isinstance(body, dict) else None,
    )


def submit(transaction: dict, config: DeviceConfig, client: httpx.Client) -> object:
    """POSTs to atlas_service's existing /transact. Raises on any transport
    or HTTP-level failure; the caller turns that into FAIL_CLOSED. No
    retries here -- a device silently retrying a payment is exactly the
    "never blindly retry" mistake the frozen failure-mode table warns
    against."""
    response = client.post(
        f"{config.atlas_url}/transact",
        params={"rail": config.rail},
        json=transaction,
        timeout=config.timeout_seconds,
    )
    response.raise_for_status()
    return response.json()


def handle_event(event: RawEvent, config: DeviceConfig, client: httpx.Client) -> DeviceResult:
    """The full device loop for one press: assemble -> submit -> interpret
    -> light an LED. Every failure path below ends in FAIL_CLOSED, and
    FAIL_CLOSED never lights green."""
    try:
        transaction = assemble_transaction(event, config)
    except UnknownPresetError as exc:
        return DeviceResult(
            state=DeviceState.FAIL_CLOSED,
            led=led_for(DeviceState.FAIL_CLOSED),
            transaction={},
            decision_reason=DEVICE_REASON_UNCONFIGURED_PRESET,
            detail=str(exc),
        )

    try:
        body = submit(transaction, config, client)
    except (httpx.HTTPError, json.JSONDecodeError, ValueError) as exc:
        # httpx.HTTPError covers connect errors, timeouts, and raise_for_status;
        # a body that is not valid JSON surfaces as a ValueError subclass.
        # All of these mean the same thing to the device: ATLAS did not give a
        # usable answer, so no trustworthy decision exists. FAIL_CLOSED --
        # never DENY, because nothing actually refused this payment.
        return DeviceResult(
            state=DeviceState.FAIL_CLOSED,
            led=led_for(DeviceState.FAIL_CLOSED),
            transaction=transaction,
            decision_reason=DEVICE_REASON_ATLAS_UNREACHABLE,
            detail=f"{type(exc).__name__}: {exc}",
        )

    state = interpret_response(body)
    final_status = body.get("final_status") if isinstance(body, dict) else None
    final_status = final_status if isinstance(final_status, str) else None

    if final_status is None:
        # Reached ATLAS, but the reply carried no usable verdict.
        reason = DEVICE_REASON_MALFORMED_RESPONSE
    else:
        backend_reason = body.get("decision_reason") if isinstance(body, dict) else None
        reason = backend_reason if isinstance(backend_reason, str) else None

    return DeviceResult(
        state=state,
        led=led_for(state),
        transaction=transaction,
        final_status=final_status,
        decision_reason=reason,
        raw_response=body if isinstance(body, dict) else None,
    )
