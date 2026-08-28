"""F1: deterministic canonical representation of signed envelope material.

THE DEFECT THIS LOCKS DOWN
--------------------------
LocationEvidence's latitude/longitude/accuracy_m were declared `float` and sit
inside canonical_envelope_bytes(). contracts.py's own rule for signed numerics
(Transaction.amount) already forbids that: *"never a float -- the signed bytes
have to be byte-identical between signing and verification, and float rounding
isn't deterministic across platforms."*

Concretely, before the fix:

    device sends 12.97160  -> Python float serialises 12.9716
    C printf("%.6f")       -> firmware emits          12.971600
    -> different signed bytes -> INVALID_DEVICE_SIGNATURE, on hardware only

It was latent (location is None throughout Phase 3.3, so no float has ever
been signed) and is fixed before Phase 3.4 populates the field.

WHAT THESE TESTS PROVE, AND WHAT THEY DO NOT
--------------------------------------------
They prove that a value expressed as a JSON *string* survives the
Python round-trip byte-identically, which is what makes cross-language
agreement possible: both sides sign an opaque text token and neither performs
a numeric conversion.

They do NOT prove the ESP32 firmware agrees, because the firmware does not yet
emit envelopes at all -- that is F3. No test here should be read as evidence of
physical-device verification.
"""

from __future__ import annotations

import json
from decimal import Decimal
from pathlib import Path

import pytest

from atlas_service.device.db import DeviceStore
from atlas_service.device.envelope import verify_envelope
from atlas_service.device.registry import register_demo_device
from contracts import (
    DecisionReason,
    DeviceEnvelope,
    LocationEvidence,
    Transaction,
    canonical_envelope_bytes,
)
from firmware import device_identity

DEVICE_ID = "esp32-atlas-demo-01"
SUBJECT = "user-demo-1"


@pytest.fixture
def device_keys(tmp_path) -> Path:
    d = tmp_path / "device-keys"
    device_identity.init_device(d)
    return d


@pytest.fixture
def enrolled(tmp_path, device_keys) -> DeviceStore:
    store = DeviceStore(tmp_path / "devices.db")
    register_demo_device(
        store, device_id=DEVICE_ID,
        device_key_id=device_identity.get_key_id(device_keys),
        public_key=device_identity.get_public_key(device_keys),
        bound_subject=SUBJECT,
    )
    return store


def _txn(**overrides) -> dict:
    d = dict(
        transaction_id="f1-1", subject=SUBJECT, amount="1500.00", currency="INR",
        beneficiary="ben-mother", location="Bengaluru,IN", device_id=DEVICE_ID,
        authentication_method="device_button", timestamp="2026-08-27T12:00:00+00:00",
    )
    d.update(overrides)
    return d


def _signed(device_keys: Path, location=None, **overrides) -> DeviceEnvelope:
    from datetime import datetime, timezone
    import secrets

    body = dict(
        device_id=DEVICE_ID, device_key_id=device_identity.get_key_id(device_keys),
        boot_id="boot-f1", counter=1, nonce=secrets.token_hex(16),
        issued_at=datetime.now(timezone.utc).isoformat(),
        transaction=_txn(), location=location, health=None, signature="",
    )
    body.update(overrides)
    unsigned = DeviceEnvelope(**body)
    sig = device_identity.secure_sign(canonical_envelope_bytes(unsigned), device_keys)
    return unsigned.model_copy(update={"signature": sig})


# ==========================================================================
# representation: coordinates must serialise as STRINGS, never JSON numbers
# ==========================================================================


def test_coordinates_serialise_as_json_strings_not_numbers():
    """A JSON number is where platform float formatting leaks in. A string
    is an opaque token both languages reproduce identically."""
    le = LocationEvidence(source="GNSS", latitude="12.9716",
                          longitude="77.5946", accuracy_m="10.0")
    dumped = le.model_dump(mode="json")
    for field in ("latitude", "longitude", "accuracy_m"):
        assert isinstance(dumped[field], str), f"{field} must serialise as a string"


def test_coordinates_are_not_floats_in_the_model():
    """Guards the fix itself: if anyone re-declares these as float, the
    cross-language hazard silently returns."""
    for field in ("latitude", "longitude", "accuracy_m"):
        annotation = str(LocationEvidence.model_fields[field].annotation)
        assert "float" not in annotation, f"{field} must not be a float ({annotation})"
        assert "Decimal" in annotation


@pytest.mark.parametrize("raw", [
    "12.9716",        # plain
    "12.97160",       # ONE trailing zero -- float would collapse this
    "12.971600",      # firmware printf("%.6f") style
    "0.0",            # zero with decimal
    "0",              # bare zero
    "-33.8688",       # negative (southern hemisphere)
    "-0.1278",        # negative near zero (western hemisphere)
    "180",            # integer-valued boundary
    "-180.000000",    # negative boundary, firmware style
    "89.999999",      # precision boundary
])
def test_exact_digits_survive_the_round_trip(raw):
    """The whole basis of cross-language agreement: whatever text the device
    sent is exactly what gets re-serialised, so both sides sign the same
    bytes without either performing a numeric conversion."""
    le = LocationEvidence(source="GNSS", latitude=raw)
    assert le.model_dump(mode="json")["latitude"] == raw


def test_trailing_zeros_are_preserved_not_normalised():
    """The specific case that would have broken hardware: Python collapses
    12.97160 -> 12.9716 as a float, but a C firmware emits 12.971600."""
    a = LocationEvidence(latitude="12.9716").model_dump(mode="json")["latitude"]
    b = LocationEvidence(latitude="12.971600").model_dump(mode="json")["latitude"]
    assert a == "12.9716" and b == "12.971600"
    assert a != b, "distinct texts must stay distinct in signed bytes"


def test_float_repr_hazard_is_gone():
    """0.1+0.2 as a float reprs as 0.30000000000000004 in Python and
    0.300000 under printf("%.6f"). As a Decimal string neither happens."""
    assert LocationEvidence(accuracy_m="0.3").model_dump(mode="json")["accuracy_m"] == "0.3"


def test_non_numeric_coordinates_are_rejected():
    """Decimal validates numeric-ness, which a bare str field would not."""
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        LocationEvidence(latitude="not-a-number")


# ==========================================================================
# canonical bytes
# ==========================================================================


def test_identical_values_produce_identical_canonical_bytes(device_keys):
    loc = {"source": "GNSS", "latitude": "12.9716", "longitude": "77.5946",
           "accuracy_m": "10.0", "captured_at": "2026-08-27T12:00:00+00:00",
           "satellites": 9}
    a = _signed(device_keys, location=loc)
    b = a.model_copy(deep=True)
    assert canonical_envelope_bytes(a) == canonical_envelope_bytes(b)


def test_canonical_bytes_contain_the_coordinate_as_a_quoted_string(device_keys):
    """Byte-level proof there is no bare JSON number in signed material."""
    env = _signed(device_keys, location={"source": "GNSS", "latitude": "12.971600"})
    raw = canonical_envelope_bytes(env).decode()
    assert '"latitude":"12.971600"' in raw
    assert '"latitude":12.971600' not in raw


def test_canonical_bytes_exclude_only_the_signature(device_keys):
    env = _signed(device_keys, location={"source": "GNSS", "latitude": "12.9716"})
    payload = json.loads(canonical_envelope_bytes(env))
    assert "signature" not in payload
    assert payload["location"]["latitude"] == "12.9716"


def test_a_differently_written_coordinate_changes_the_signed_bytes(device_keys):
    """12.9716 and 12.97160 are the same number but different tokens -- they
    MUST produce different signed bytes, otherwise the representation is
    ambiguous and a firmware could sign one while the backend verified the
    other."""
    a = _signed(device_keys, location={"source": "GNSS", "latitude": "12.9716"})
    b = _signed(device_keys, location={"source": "GNSS", "latitude": "12.97160"},
                nonce=a.nonce, issued_at=a.issued_at)
    assert canonical_envelope_bytes(a) != canonical_envelope_bytes(b)


# ==========================================================================
# end-to-end signature behaviour with location present
# ==========================================================================


def test_signed_envelope_with_location_verifies(enrolled, device_keys):
    env = _signed(device_keys, location={
        "source": "GNSS", "latitude": "12.971600", "longitude": "77.594600",
        "accuracy_m": "8.5", "captured_at": "2026-08-27T12:00:00+00:00",
        "satellites": 11,
    })
    assert verify_envelope(env, enrolled).ok is True


@pytest.mark.parametrize("field,value", [
    ("latitude", "0.0"),
    ("longitude", "0.0"),
    ("accuracy_m", "99999"),
    ("source", "DECLARED"),
    ("captured_at", "2020-01-01T00:00:00+00:00"),
    ("satellites", 0),
])
def test_tampering_with_location_after_signing_is_rejected(enrolled, device_keys, field, value):
    """Location is signed material, so altering it in flight must break the
    signature BEFORE any policy evaluation -- not be silently accepted as
    'only evidence'."""
    env = _signed(device_keys, location={
        "source": "GNSS", "latitude": "12.9716", "longitude": "77.5946",
        "accuracy_m": "10.0", "captured_at": "2026-08-27T12:00:00+00:00",
        "satellites": 9,
    })
    tampered = env.model_copy(deep=True)
    setattr(tampered.location, field, value)
    v = verify_envelope(tampered, enrolled)
    assert v.ok is False
    assert v.reason == DecisionReason.INVALID_DEVICE_SIGNATURE


def test_adding_location_to_an_envelope_signed_without_it_is_rejected(enrolled, device_keys):
    env = _signed(device_keys, location=None)
    tampered = env.model_copy(update={
        "location": LocationEvidence(source="GNSS", latitude="12.9716")})
    v = verify_envelope(tampered, enrolled)
    assert v.ok is False and v.reason == DecisionReason.INVALID_DEVICE_SIGNATURE


def test_removing_location_from_a_signed_envelope_is_rejected(enrolled, device_keys):
    env = _signed(device_keys, location={"source": "GNSS", "latitude": "12.9716"})
    v = verify_envelope(env.model_copy(update={"location": None}), enrolled)
    assert v.ok is False and v.reason == DecisionReason.INVALID_DEVICE_SIGNATURE


def test_absent_location_still_verifies_unchanged(enrolled, device_keys):
    """Backward compatibility: every existing Phase 3.3 envelope sends
    location=None and must keep working exactly as before."""
    assert verify_envelope(_signed(device_keys, location=None), enrolled).ok is True


def test_transaction_amount_representation_is_untouched(device_keys):
    """F1 must not disturb the amount encoding that already worked."""
    env = _signed(device_keys)
    raw = canonical_envelope_bytes(env).decode()
    assert '"amount":"1500.00"' in raw
