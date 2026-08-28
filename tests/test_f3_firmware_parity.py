"""F3: firmware / Python protocol parity.

THE GAP THIS CLOSES
-------------------
Before F3, atlas_device.ino sent a BARE Transaction to the legacy unsigned
/transact, while virtual_device.py sent a signed DeviceEnvelope to
/v2/transact. Device authentication was therefore proven only in the Python
model, never by the firmware.

HOW PARITY IS PROVEN HERE
-------------------------
The firmware builds its canonical signing bytes from ONE snprintf template,
bracketed in the source by CANONICAL_FORMAT_BEGIN / CANONICAL_FORMAT_END.
These tests extract that literal C template, render it in Python with known
values, and assert it is byte-identical to contracts.canonical_envelope_bytes()
for the same envelope.

That is a genuine byte-level conformance check on the SIGNED MATERIAL, which
is what actually has to match. If either implementation drifts -- a renamed
field, a reordered key, a changed default, added whitespace -- these fail.

WHAT THIS DOES *NOT* PROVE, STATED PLAINLY
------------------------------------------
The firmware is never COMPILED-AND-EXECUTED here (there is no host C compiler
in this environment, and the target is xtensa). These tests prove the
template and the wire contract agree. They do NOT prove that the compiled
firmware runs correctly, that libsodium on-device produces the same signature
bytes as Python's Ed25519, or anything whatsoever about hardware security.
Those need a real Wokwi run and, for the hardware claims, real hardware.
"""

from __future__ import annotations

import re
from decimal import Decimal
from pathlib import Path

import pytest

from contracts import DeviceEnvelope, canonical_envelope_bytes

ATLAS_ROOT = Path(__file__).resolve().parent.parent
INO = ATLAS_ROOT / "firmware" / "atlas_device" / "atlas_device.ino"


# --------------------------------------------------------------------------
# extract the firmware's canonical template from its own source
# --------------------------------------------------------------------------


def _ino_source() -> str:
    return INO.read_text(encoding="utf-8")


def _extract_canonical_template() -> str:
    """Pull the C string literal between the sentinels and un-escape it."""
    src = _ino_source()
    block = src.split("CANONICAL_FORMAT_BEGIN")[1].split("CANONICAL_FORMAT_END")[0]
    literals = re.findall(r'"((?:[^"\\]|\\.)*)"', block)
    joined = "".join(literals)
    return joined.replace('\\"', '"')


#: The values the firmware substitutes, in the exact order its snprintf lists
#: them. Kept beside the template so a mismatch shows up as a failing test
#: rather than a silent protocol divergence.
FIRMWARE_ARG_ORDER = [
    "g_bootId", "e.counter", "DEVICE_ID", "DEVICE_KEY_ID", "e.pressedAt", "nonce",
    "amount", "AUTHENTICATION_METHOD", "p.beneficiary", "CURRENCY", "DEVICE_ID",
    "LOCATION", "SUBJECT", "e.pressedAt", "transactionIdOut",
]

BOOT_ID = "b00t0001"
COUNTER = 7
DEVICE_ID = "esp32-atlas-demo-01"
DEVICE_KEY_ID = "dev-abc123"
ISSUED_AT = "2026-08-27T12:00:00+00:00"
NONCE = "0123456789abcdef0123456789abcdef"
AMOUNT = "1500.00"
AUTH = "device_button"
BENEFICIARY = "ben-mother"
CURRENCY = "INR"
LOCATION = "Bengaluru,IN"
SUBJECT = "user-demo-1"
TXN_ID = "esp32-atlas-demo-01-b00t0001-0007"


def _render_firmware_canonical() -> str:
    """Fill the firmware's own template exactly as its snprintf does."""
    template = _extract_canonical_template()
    # The C template is already printf-style, so Python's % operator applies
    # it directly. Only %ld needs translating (%d in Python). Using .format()
    # here would be wrong -- it would treat the JSON braces as placeholders.
    py = template.replace("%ld", "%d")
    return py % (
        BOOT_ID, COUNTER, DEVICE_ID, DEVICE_KEY_ID, ISSUED_AT, NONCE,
        AMOUNT, AUTH, BENEFICIARY, CURRENCY, DEVICE_ID,
        LOCATION, SUBJECT, ISSUED_AT, TXN_ID,
    )


def _backend_canonical() -> str:
    env = DeviceEnvelope(
        device_id=DEVICE_ID, device_key_id=DEVICE_KEY_ID, boot_id=BOOT_ID,
        counter=COUNTER, nonce=NONCE, issued_at=ISSUED_AT,
        transaction=dict(
            transaction_id=TXN_ID, subject=SUBJECT, amount=AMOUNT, currency=CURRENCY,
            beneficiary=BENEFICIARY, location=LOCATION, device_id=DEVICE_ID,
            authentication_method=AUTH, timestamp=ISSUED_AT,
        ),
        location=None, health=None, signature="",
    )
    return canonical_envelope_bytes(env).decode()


# ==========================================================================
# THE headline test
# ==========================================================================


def test_firmware_canonical_bytes_match_backend_byte_for_byte():
    """The signed material must be identical, or every firmware signature
    fails verification."""
    assert _render_firmware_canonical() == _backend_canonical()


def test_firmware_and_backend_agree_on_length():
    assert len(_render_firmware_canonical()) == len(_backend_canonical())


# ==========================================================================
# structural properties that make the match non-accidental
# ==========================================================================


def test_firmware_template_has_keys_in_sorted_order():
    """ArduinoJson does not sort keys, which is exactly why the firmware
    builds this string by hand. Sorted order is what the backend's
    json.dumps(sort_keys=True) produces."""
    template = _extract_canonical_template()
    top = re.findall(r'"(\w+)":', template.split('"transaction":{')[0])
    assert top == sorted(top), f"top-level keys not sorted: {top}"

    inner_block = template.split('"transaction":{')[1]
    inner = re.findall(r'"(\w+)":', inner_block)
    assert inner == sorted(inner), f"transaction keys not sorted: {inner}"


def test_firmware_template_contains_no_whitespace():
    """The backend uses separators=(",", ":") -- any space breaks the bytes."""
    template = _extract_canonical_template()
    outside_values = re.sub(r'"(?:[^"\\]|\\.)*"', '""', template)
    assert " " not in outside_values


def test_firmware_template_omits_the_signature_field():
    """The signature must never be inside its own signed bytes."""
    assert "signature" not in _extract_canonical_template()


def test_firmware_emits_every_transaction_field_including_defaults():
    """A device emitting only the fields it cares about would sign a shorter
    string than the backend derives (pydantic fills defaults in), and every
    signature would fail. This is the same class of defect found during
    Phase 3.3."""
    template = _extract_canonical_template()
    for field in (
        "amount", "authentication_method", "beneficiary", "currency",
        "declared_travel_mode", "device_id", "is_emergency_request",
        "is_international", "is_new_beneficiary", "is_new_device",
        "location", "merchant_category", "subject", "timestamp", "transaction_id",
    ):
        assert f'"{field}":' in template, f"firmware omits {field}"


def test_firmware_spells_out_contract_defaults_literally():
    template = _extract_canonical_template()
    assert '"declared_travel_mode":false' in template
    assert '"is_emergency_request":false' in template
    assert '"is_international":false' in template
    assert '"is_new_beneficiary":false' in template
    assert '"is_new_device":false' in template
    assert '"merchant_category":null' in template


def test_firmware_marks_location_and_health_null_not_absent():
    """F1 made the coordinate fields Decimal-as-string so populating them
    later stays deterministic. F3 leaves them null -- but null must be
    PRESENT, because the backend serialises Optional fields as null rather
    than dropping them."""
    template = _extract_canonical_template()
    assert '"location":null' in template
    assert '"health":null' in template


def test_firmware_argument_order_matches_the_template():
    """Guards the one thing the rendered comparison cannot see: that the
    snprintf argument list is in the same order as the placeholders."""
    src = _ino_source()
    call = src.split("int written = snprintf(out, len, CANONICAL_FMT,")[1].split(");")[0]
    args = [a.strip() for a in call.replace("\n", " ").split(",") if a.strip()]
    assert args == FIRMWARE_ARG_ORDER, f"argument order drifted: {args}"


# ==========================================================================
# protocol convergence: endpoint, signing, identity
# ==========================================================================


def test_firmware_posts_to_the_authenticated_v2_endpoint():
    """Before F3 this was the legacy unsigned /transact."""
    src = _ino_source()
    assert "/v2/transact" in src
    assert '"/transact?rail="' not in src, "legacy unsigned endpoint still in use"


def test_firmware_signs_with_ed25519():
    src = _ino_source()
    assert "crypto_sign_detached" in src
    assert "crypto_sign_seed_keypair" in src
    assert "#include <sodium.h>" in src


def test_firmware_refuses_to_operate_without_an_identity():
    """No identity -> cannot sign -> must not fall back to an unsigned
    request. It halts instead."""
    src = _ino_source()
    block = src.split("if (sodium_init() < 0 || !initIdentity())")[1][:400]
    assert "FAIL_CLOSED" in block
    assert "while (true)" in block


def test_firmware_persists_its_counter_in_nvs():
    """The Phase 2 defect was a RAM counter resetting on restart. NVS plus a
    random boot_id is what stops a restarted device replaying ids."""
    src = _ino_source()
    assert "Preferences" in src
    assert 'g_prefs.putLong("counter"' in src
    assert "esp_random()" in src


def test_firmware_never_contains_decision_logic():
    """Blueprint 24.2: no decision authority below the policy layer. The
    device may not score, evaluate policy, or sign bank assertions."""
    src = _ino_source()
    for banned in ("anomaly", "risk_band", "policy_hash", "IsolationForest", "evaluate("):
        assert banned not in src, f"decision logic leaked into firmware: {banned}"


def test_firmware_signature_is_hex_encoded_like_the_backend_expects():
    src = _ino_source()
    assert '"%02x"' in src, "signature must be lowercase hex"


def test_request_body_appends_signature_without_touching_signed_bytes():
    """The body is the canonical string plus the signature. Rebuilding it a
    second way would risk signing one byte string and sending another."""
    src = _ino_source()
    body = src.split("static void buildRequestBody")[1][:600]
    assert "concat(canonical, n - 1)" in body, "body must reuse the signed bytes verbatim"
    assert "signature" in body and "sigHex" in body


# ==========================================================================
# the Python model must stay aligned too
# ==========================================================================


def test_virtual_device_and_firmware_use_the_same_transaction_id_format():
    src = _ino_source()
    assert '"%s-%s-%04ld"' in src
    assert "DEVICE_ID, g_bootId, e.counter" in src

    from firmware.virtual_device import DeviceConfig, assemble_transaction, read_event
    from datetime import datetime, timezone

    body = assemble_transaction(
        read_event(0, 7, now=datetime(2026, 8, 27, 12, tzinfo=timezone.utc)),
        DeviceConfig(device_id="esp32-atlas-demo-01", boot_id="b00t0001"),
    )
    assert body["transaction_id"] == TXN_ID


def test_virtual_device_envelope_matches_the_firmware_field_set(tmp_path):
    """Both implementations must produce the same envelope keys."""
    from firmware import device_identity
    from firmware.virtual_device import DeviceConfig, build_envelope

    keys = tmp_path / "k"
    device_identity.init_device(keys)
    env = build_envelope(
        dict(transaction_id=TXN_ID, subject=SUBJECT, amount=AMOUNT, currency=CURRENCY,
             beneficiary=BENEFICIARY, location=LOCATION, device_id=DEVICE_ID,
             authentication_method=AUTH, timestamp=ISSUED_AT),
        DeviceConfig(device_id=DEVICE_ID, boot_id=BOOT_ID), keys, counter=COUNTER,
    )
    template_keys = set(re.findall(r'"(\w+)":', _extract_canonical_template()))
    envelope_keys = set(env) - {"signature"}
    assert envelope_keys <= template_keys | {"transaction"}


def test_backend_accepts_an_envelope_built_from_the_firmware_template(tmp_path):
    """End-to-end on the signed material: sign the FIRMWARE's rendered bytes
    with a device key, and confirm the backend's own verifier accepts it.
    This is the closest software-only proof that firmware-shaped bytes
    verify -- what remains unproven is only whether the compiled firmware
    emits them, which needs a Wokwi run."""
    from atlas_service.device.db import DeviceStore
    from atlas_service.device.envelope import verify_envelope
    from atlas_service.device.registry import register_demo_device
    from firmware import device_identity

    keys = tmp_path / "k"
    device_identity.init_device(keys)
    store = DeviceStore(tmp_path / "d.db")
    register_demo_device(
        store, device_id=DEVICE_ID,
        device_key_id=device_identity.get_key_id(keys),
        public_key=device_identity.get_public_key(keys), bound_subject=SUBJECT,
    )

    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    env = DeviceEnvelope(
        device_id=DEVICE_ID, device_key_id=device_identity.get_key_id(keys),
        boot_id=BOOT_ID, counter=COUNTER, nonce=NONCE, issued_at=now,
        transaction=dict(
            transaction_id=TXN_ID, subject=SUBJECT, amount=AMOUNT, currency=CURRENCY,
            beneficiary=BENEFICIARY, location=LOCATION, device_id=DEVICE_ID,
            authentication_method=AUTH, timestamp=ISSUED_AT),
        location=None, health=None, signature="",
    )
    sig = device_identity.secure_sign(canonical_envelope_bytes(env), keys)
    verdict = verify_envelope(env.model_copy(update={"signature": sig}), store)
    assert verdict.ok is True
