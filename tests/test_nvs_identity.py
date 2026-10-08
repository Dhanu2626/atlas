"""The ESP32's identity in NVS, not in the firmware (approved key-lifecycle change, 2026-10-09).

The firmware is now key-free: it reads its identity from NVS namespace "atlas-id" at
start-up. scripts/provision_nvs.py builds that NVS image from the device's EXISTING
enrolled key -- verified against ATLAS's registry first -- with Espressif's own generator
(vendored, hash-pinned), reads it back with an independent reader, and joins it with the
key-free firmware into a full flash image that stays in a git-ignored folder.

Everything here runs with THROWAWAY keys and temporary files. The real device's key is
only ever touched by provision_nvs.py on the owner's machine.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import sqlite3
import struct
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from atlas_service.device.db import DeviceStore
from atlas_service.device.registry import register_demo_device, revoke
from firmware import device_identity, nvs_identity
from firmware.nvs_identity import Identity, IdentityImageError

ROOT = Path(__file__).resolve().parent.parent
SKETCH = ROOT / "firmware" / "atlas_device" / "atlas_device.ino"
sys.path.insert(0, str(ROOT / "scripts"))
import provision_nvs  # noqa: E402

CA = ("-----BEGIN CERTIFICATE-----\nMIIBdzCCAR2gAwIBAgIUXtest\n-----END CERTIFICATE-----\n")
NVS_OFFSET, NVS_SIZE = 0x9000, 0x5000


def _keypair():
    private = Ed25519PrivateKey.generate()
    seed = private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                 serialization.NoEncryption())
    return seed, private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _partition_table(entries) -> bytes:
    out = b""
    for label, ptype, subtype, offset, size in entries:
        out += b"\xAA\x50" + struct.pack("<BBII", ptype, subtype, offset, size) + label.encode().ljust(16, b"\0") + b"\0" * 4
    return out


def _fake_firmware(blank_nvs: bool = True) -> bytes:
    """A 4 MB image laid out like the core's default partition table (default.csv)."""
    image = bytearray(b"\xff" * (4 * 1024 * 1024))
    image[0x1000:0x1010] = b"BOOTLOADER-BYTES"
    table = _partition_table([("nvs", 1, 2, 0x9000, 0x5000), ("otadata", 1, 0, 0xE000, 0x2000),
                              ("app0", 0, 0x10, 0x10000, 0x140000), ("app1", 0, 0x11, 0x150000, 0x140000),
                              ("spiffs", 1, 0x82, 0x290000, 0x160000), ("coredump", 1, 3, 0x3F0000, 0x10000)])
    image[0x8000:0x8000 + len(table)] = table
    image[0x10000:0x10010] = b"APPLICATION-CODE"
    if not blank_nvs:
        image[0x9000] = 0x00
    return bytes(image)


# ---------------------------------------------------------------- the generator and the reader

def test_the_vendored_generator_is_espressifs_file_unchanged():
    vendored = nvs_identity.VENDOR_DIR / "nvs_partition_gen.py"
    assert hashlib.sha256(vendored.read_bytes().replace(b"\r\n", b"\n")).hexdigest() == nvs_identity.VENDORED_SHA256
    record = base64.urlsafe_b64encode(bytes.fromhex(nvs_identity.VENDORED_SHA256)).rstrip(b"=").decode()
    assert record == "7tWheO81E3V82EHy0FQlqFLHI5dBVt8Mz5IYhQAo9pY"      # the wheel's own RECORD entry
    assert "Apache License" in (nvs_identity.VENDOR_DIR / "LICENSE").read_text(encoding="utf-8")


def test_a_changed_generator_is_refused_before_it_runs(monkeypatch):
    """Found by the 2026-10-09 deliberate-break run: the hash was checked by a test but
    nothing proved the loader ENFORCES it. A generator that is not the pinned file must
    never be imported, let alone given a key."""
    monkeypatch.setattr(nvs_identity, "VENDORED_SHA256", "0" * 64)
    seed, pk = _keypair()
    with pytest.raises(IdentityImageError, match="pinned hash"):
        nvs_identity.build_identity_nvs(Identity(seed, pk, "dev-0123456789abcdef", "d", CA), NVS_SIZE)


def test_espressifs_image_reads_back_exactly_through_the_independent_reader():
    seed, pk = _keypair()
    ident = Identity(seed, pk, "dev-0123456789abcdef", "esp32-test-01", CA)
    image = nvs_identity.build_identity_nvs(ident, NVS_SIZE)
    assert len(image) == NVS_SIZE
    stored = nvs_identity.read_nvs(image)["atlas-id"]
    assert stored == {"seed": seed, "public_key": pk, "key_id": "dev-0123456789abcdef",
                      "device_id": "esp32-test-01", "ca_pem": CA}


def test_the_reader_refuses_a_damaged_image():
    seed, pk = _keypair()
    image = bytearray(nvs_identity.build_identity_nvs(Identity(seed, pk, "dev-0123456789abcdef", "d", CA), NVS_SIZE))
    image[64 + 40] ^= 0xFF                                  # inside the first data entry
    with pytest.raises(IdentityImageError):
        nvs_identity.read_nvs(bytes(image))


def test_the_generator_refuses_a_partition_too_small_to_stay_writable():
    seed, pk = _keypair()
    with pytest.raises(IdentityImageError):
        nvs_identity.build_identity_nvs(Identity(seed, pk, "dev-0123456789abcdef", "d", CA), 0x2000)


# ---------------------------------------------------------------- layout and joining

def test_the_nvs_partition_comes_from_the_image_own_table():
    part = nvs_identity.nvs_partition(_fake_firmware())
    assert (part.label, part.offset, part.size) == ("nvs", NVS_OFFSET, NVS_SIZE)


def test_the_core_default_partition_table_is_the_one_assumed_nowhere():
    """The offsets above are only the test's fixture; provision_nvs reads the real ones
    from the downloaded firmware's own partition table, so nothing assumes them."""
    src = (ROOT / "scripts" / "provision_nvs.py").read_text(encoding="utf-8")
    assert "0x9000" not in src and "0x5000" not in src
    assert "nvs_identity.nvs_partition(full)" in src


def test_joining_changes_only_the_nvs_partition():
    seed, pk = _keypair()
    firmware = _fake_firmware()
    nvs = nvs_identity.build_identity_nvs(Identity(seed, pk, "dev-0123456789abcdef", "d", CA), NVS_SIZE)
    joined, part = nvs_identity.join(firmware, nvs)
    assert len(joined) == len(firmware)
    assert joined[:part.offset] == firmware[:part.offset]
    assert joined[part.offset + part.size:] == firmware[part.offset + part.size:]
    assert joined[part.offset:part.offset + part.size] == nvs


def test_joining_refuses_a_firmware_whose_nvs_is_not_blank():
    seed, pk = _keypair()
    nvs = nvs_identity.build_identity_nvs(Identity(seed, pk, "dev-0123456789abcdef", "d", CA), NVS_SIZE)
    with pytest.raises(IdentityImageError):
        nvs_identity.join(_fake_firmware(blank_nvs=False), nvs)


# ---------------------------------------------------------------- provision_nvs.py end to end

class _Args:
    def __init__(self, **kw):
        self.__dict__.update(dict(variant="enrolled", check=False), **kw)


@pytest.fixture
def rig(tmp_path, monkeypatch):
    """A throwaway enrolled device, a key-free firmware folder, a CA, and an output dir.
    The output dir is in tmp, so the git-ignore guard is bypassed here and tested apart."""
    import make_dev_ca
    keys = tmp_path / "device-keys"
    key_id = device_identity.init_device(keys)
    db = tmp_path / "devices.db"
    store = DeviceStore(db)
    register_demo_device(store, device_id="esp32-test-01", device_key_id=key_id,
                         public_key=device_identity.get_public_key(keys), bound_subject="user-demo-1")
    store.close()
    fw = tmp_path / "fw"
    fw.mkdir()
    _write_firmware(fw, _fake_firmware())
    certs = tmp_path / "certs"
    make_dev_ca.create_pki(certs)
    monkeypatch.setattr(provision_nvs, "must_be_ignored", lambda path: None)
    out = tmp_path / "out"
    args = dict(firmware=str(fw), keys_dir=str(keys), device_id="esp32-test-01", db=str(db),
                certs=str(certs), out=str(out))
    seed = device_identity._load_private_key(keys).private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    return {"args": args, "out": out, "keys": keys, "db": db, "fw": fw, "seed": seed, "key_id": key_id,
            "public": device_identity.get_public_key(keys)}


def _write_firmware(folder: Path, merged: bytes) -> None:
    (folder / "atlas_device.ino.merged.bin").write_bytes(merged)
    (folder / "atlas_device.ino.elf").write_bytes(b"\x7fELF no key here")
    (folder / "SHA256SUMS").write_text("".join(
        f"{hashlib.sha256((folder / n).read_bytes()).hexdigest()}  {n}\n"
        for n in ("atlas_device.ino.merged.bin", "atlas_device.ino.elf")), encoding="utf-8")


def _run(rig, capsys, **overrides) -> tuple[int, str]:
    argv = []
    for k, v in {**rig["args"], **overrides}.items():
        if v is True:
            argv.append(f"--{k.replace('_', '-')}")
        elif v is not None:
            argv += [f"--{k.replace('_', '-')}", str(v)]
    code = provision_nvs.main(argv)
    return code, capsys.readouterr().out


def _no_secret_in(text: str, seed: bytes) -> bool:
    data = text.encode()
    return not any(form in data for form in provision_nvs._forms(seed))


def _stored(out: Path) -> dict:
    image = (out / provision_nvs.IMAGE_NAME).read_bytes()
    part = nvs_identity.nvs_partition(image)
    return nvs_identity.read_nvs(image[part.offset:part.offset + part.size]).get("atlas-id", {})


def test_the_existing_identity_goes_into_the_image_unchanged(rig, capsys):
    code, out = _run(rig, capsys)
    assert code == 0, out
    stored = _stored(rig["out"])
    derived = Ed25519PrivateKey.from_private_bytes(stored["seed"]).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    assert derived == rig["public"] and stored["public_key"].hex() == rig["public"]
    assert stored["key_id"] == rig["key_id"] and stored["device_id"] == "esp32-test-01"
    assert device_identity.get_key_id(rig["keys"]) == rig["key_id"]            # the identity was kept
    manifest = json.loads((rig["out"] / provision_nvs.MANIFEST_NAME).read_text(encoding="utf-8"))
    assert manifest["device_key_id"] == manifest["enrolled_key_id"] == rig["key_id"]
    assert _no_secret_in(out, rig["seed"]) and _no_secret_in(json.dumps(manifest), rig["seed"])
    assert "6 of 6 identity checks passed" in out


def test_the_check_mode_confirms_the_image_against_the_registry(rig, capsys):
    _run(rig, capsys)
    code, out = _run(rig, capsys, firmware=None, keys_dir=None, check=True)
    assert code == 0 and out.count(": True") == 3 and _no_secret_in(out, rig["seed"])


@pytest.mark.parametrize("change,expected", [
    (dict(device_id="esp32-not-enrolled"), "is not enrolled"),
    (dict(keys_dir="__missing__"), "could not be read"),
])
def test_it_stops_and_writes_nothing_when_the_identity_cannot_be_verified(rig, capsys, change, expected):
    if change.get("keys_dir") == "__missing__":
        change = dict(keys_dir=str(rig["out"].parent / "no-such-keys"))
    code, out = _run(rig, capsys, **change)
    assert code == 1 and "STOPPED" in out and expected in out
    assert not (rig["out"] / provision_nvs.IMAGE_NAME).exists()
    assert "NO new identity" in out or "nothing was generated" in out


def test_it_stops_when_the_key_is_not_the_enrolled_one(rig, capsys, tmp_path):
    other = tmp_path / "other-keys"
    device_identity.init_device(other)
    code, out = _run(rig, capsys, keys_dir=str(other))
    assert code == 1 and "not the key ATLAS has enrolled" in out
    assert not (rig["out"] / provision_nvs.IMAGE_NAME).exists()


def test_it_stops_for_a_revoked_device(rig, capsys):
    store = DeviceStore(rig["db"])
    revoke(store, "esp32-test-01", "test")
    store.close()
    code, out = _run(rig, capsys)
    assert code == 1 and "REVOKED" in out


def test_it_stops_for_firmware_that_does_not_match_its_hashes(rig, capsys):
    merged = rig["fw"] / "atlas_device.ino.merged.bin"
    merged.write_bytes(merged.read_bytes()[:-1] + b"\x00")
    code, out = _run(rig, capsys)
    assert code == 1 and "does not match its SHA256SUMS" in out


def test_it_stops_for_firmware_that_contains_the_key(rig, capsys):
    image = bytearray(_fake_firmware())
    image[0x20000:0x20040] = rig["seed"].hex().encode()        # a key compiled into the app
    _write_firmware(rig["fw"], bytes(image))
    code, out = _run(rig, capsys)
    assert code == 1 and "not the key-free build" in out and _no_secret_in(out, rig["seed"])


def test_it_refuses_to_write_where_git_would_track_the_key():
    with pytest.raises(provision_nvs.Stop):
        provision_nvs.must_be_ignored(ROOT / "firmware" / "atlas_device" / "not-ignored.bin")
    provision_nvs.must_be_ignored(ROOT / "firmware" / "atlas_device" / "local" / "atlas-wokwi-full.bin")


def test_the_speaker_refuses_to_print_a_secret():
    say = provision_nvs.Speaker()
    seed = os.urandom(32)
    say.secrets.append(seed)
    for leak in (seed.hex(), seed.hex().upper(), base64.b64encode(seed).decode().rstrip("=")):
        with pytest.raises(provision_nvs.Stop):
            say(f"value {leak}")


# ---------------------------------------------------------------- the image's key against ATLAS

def _signed_by_image(rig, now=None):
    """Signs an envelope with whatever key the image holds -- what the firmware does with it."""
    from datetime import datetime, timezone
    from contracts import DeviceEnvelope, canonical_envelope_bytes
    stored = _stored(rig["out"])
    now = now or datetime.now(timezone.utc).isoformat()
    env = DeviceEnvelope(device_id=stored["device_id"], device_key_id=stored["key_id"], boot_id="b00t0001",
                         counter=1, nonce=os.urandom(16).hex(), issued_at=now, location=None, health=None,
                         signature="", transaction=dict(
                             transaction_id="esp32-test-01-b00t0001-0001", subject="user-demo-1", amount="1500.00",
                             currency="INR", beneficiary="ben-mother", location="x", device_id=stored["device_id"],
                             authentication_method="device_button", timestamp=now))
    signature = Ed25519PrivateKey.from_private_bytes(stored["seed"]).sign(canonical_envelope_bytes(env)).hex()
    return env.model_copy(update={"signature": signature})


@pytest.mark.parametrize("variant,ok,reason", [
    ("enrolled", True, None),
    ("unenrolled-key", False, "DEVICE_UNKNOWN"),
    ("damaged-seed", False, "INVALID_DEVICE_SIGNATURE"),
])
def test_atlas_accepts_only_the_enrolled_key_from_the_image(rig, capsys, variant, ok, reason):
    from atlas_service.device.envelope import verify_envelope
    code, out = _run(rig, capsys, variant=variant)
    assert code == 0, out
    verdict = verify_envelope(_signed_by_image(rig), DeviceStore(rig["db"]))
    assert verdict.ok is ok
    assert (verdict.reason.value if verdict.reason else None) == reason


def test_the_damaged_seed_image_fails_the_device_self_check(rig, capsys):
    """The firmware compares the key it derives with the enrolled public key stored beside
    it; a damaged seed makes them differ, so the device refuses to start."""
    _run(rig, capsys, variant="damaged-seed")
    stored = _stored(rig["out"])
    derived = Ed25519PrivateKey.from_private_bytes(stored["seed"]).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    assert stored["public_key"].hex() == rig["public"] and derived.hex() != rig["public"]


def test_the_no_identity_image_is_the_key_free_firmware_unchanged(rig, capsys):
    _run(rig, capsys, variant="no-identity")
    assert (rig["out"] / provision_nvs.IMAGE_NAME).read_bytes() == _fake_firmware()


# ---------------------------------------------------------------- the firmware source

def _code(src: str) -> str:
    return re.sub(r"//[^\n]*", "", re.sub(r"/\*.*?\*/", "", src, flags=re.S))


def test_the_sketch_holds_no_key_and_includes_no_secret_header():
    src = SKETCH.read_text(encoding="utf-8")
    code = _code(src)
    assert "DEVICE_KEY_SEED_HEX" not in code and '#include "secrets.h"' not in code
    assert '#include "atlas_ca.h"' not in code
    assert not re.search(r'"[0-9a-fA-F]{64}"', src), "a 32-byte hex constant is in the sketch"
    assert not (ROOT / "firmware" / "atlas_device" / "secrets.example.h").exists()


def test_the_sketch_loads_its_identity_from_nvs_and_checks_it():
    code = _code(SKETCH.read_text(encoding="utf-8"))
    assert 'IDENTITY_NAMESPACE = "atlas-id"' in code and "id.begin(IDENTITY_NAMESPACE, true)" in code
    for key in ('"seed"', '"public_key"', '"key_id"', '"device_id"', '"ca_pem"'):
        assert key in code, key
    assert "memcmp(pk, storedPk, 32) != 0" in code               # the self-check
    assert "sodium_memzero(seed, sizeof(seed));" in code and "sodium_memzero(g_sk, sizeof(g_sk));" in code
    body = code[code.index("if (sodium_init() < 0 || !initIdentity())"):][:500]
    assert "FAIL_CLOSED" in body and "while (true)" in body       # no identity -> never transacts


def test_the_sketch_prints_only_public_identity():
    code = _code(SKETCH.read_text(encoding="utf-8"))
    for line in code.splitlines():
        if "Serial.print" in line:
            assert not re.search(r"\b(seed|g_sk|storedPk)\b", line), line.strip()


def test_the_github_build_is_key_free_by_construction():
    wf = (ROOT / ".github" / "workflows" / "device-build.yml").read_text(encoding="utf-8")
    assert "secrets.example.h" not in wf and "secrets.h" not in wf.replace("no secrets.h", "")
    assert "name: atlas-firmware-key-free" in wf
    assert "${{ secrets." not in wf
