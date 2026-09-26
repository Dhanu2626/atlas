"""Private keys are encrypted at rest (keystore.py, 2026-09-22).

What these pin, in order: both backends round-trip; the stored file never
contains the key in any common encoding; a file cannot be reused for another
purpose, edited, or opened with the wrong passphrase; an unprotected legacy key
is refused rather than used; errors never carry key material; every key holder
(ATLAS, the device, the step-up authenticator) now writes protected files and
still signs correctly; and the migration tool keeps a verified recovery copy
outside the repository and never deletes anything.
"""

from __future__ import annotations

import base64
import logging
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

import keystore
from atlas_service import crypto
from firmware import device_identity

WINDOWS = sys.platform == "win32"
BACKENDS = [keystore.BACKEND_SCRYPT] + ([keystore.BACKEND_DPAPI] if WINDOWS else [])


@pytest.fixture(autouse=True)
def passphrase(monkeypatch):
    monkeypatch.setenv(keystore.PASSPHRASE_ENV, "keystore-test-passphrase")


def _encodings(secret: bytes) -> list[bytes]:
    return [secret, secret.hex().encode(), secret.hex().upper().encode(),
            base64.b64encode(secret), base64.b64encode(secret).rstrip(b"="),
            base64.urlsafe_b64encode(secret).rstrip(b"=")]


def _never_contains(blob: bytes, secret: bytes) -> None:
    for form in _encodings(secret):
        assert form not in blob, "key material found in a protected file"


@pytest.mark.parametrize("backend", BACKENDS)
def test_round_trip(backend):
    secret = Ed25519PrivateKey.generate().private_bytes_raw()
    blob = keystore.protect(secret, "atlas-signing", backend)
    assert keystore.unprotect(blob, "atlas-signing") == secret
    _never_contains(blob, secret)


@pytest.mark.parametrize("backend", BACKENDS)
def test_a_file_cannot_be_used_for_another_purpose(backend):
    secret = b"\x07" * 32
    blob = keystore.protect(secret, "device-signing", backend)
    with pytest.raises(keystore.KeystoreError):
        keystore.unprotect(blob, "atlas-signing")
    # Relabelling the header does not help either: the purpose is bound into
    # the ciphertext (DPAPI entropy / AES-GCM associated data).
    relabelled = blob.replace(b"purpose=device-signing", b"purpose=atlas-signing")
    with pytest.raises(keystore.KeystoreError):
        keystore.unprotect(relabelled, "atlas-signing")


@pytest.mark.parametrize("backend", BACKENDS)
def test_an_edited_file_is_refused(backend):
    blob = keystore.protect(b"\x11" * 32, "atlas-signing", backend)
    head, _, body = blob.partition(b"\n\n")
    payload = bytearray(base64.b64decode(body.strip()))
    payload[-1] ^= 0x01
    with pytest.raises(keystore.KeystoreError):
        keystore.unprotect(head + b"\n\n" + base64.b64encode(bytes(payload)), "atlas-signing")


def test_the_wrong_passphrase_is_refused(monkeypatch):
    blob = keystore.protect(b"\x22" * 32, "atlas-signing", keystore.BACKEND_SCRYPT)
    monkeypatch.setenv(keystore.PASSPHRASE_ENV, "not-the-passphrase")
    with pytest.raises(keystore.KeystoreError, match="failed authentication"):
        keystore.unprotect(blob, "atlas-signing")


def test_the_portable_backend_refuses_to_run_without_a_passphrase(monkeypatch):
    monkeypatch.delenv(keystore.PASSPHRASE_ENV, raising=False)
    with pytest.raises(keystore.KeystoreError, match=keystore.PASSPHRASE_ENV):
        keystore.protect(b"\x33" * 32, "atlas-signing", keystore.BACKEND_SCRYPT)


def test_an_unknown_backend_or_purpose_is_refused(monkeypatch):
    monkeypatch.setenv(keystore.BACKEND_ENV, "rot13")
    with pytest.raises(keystore.KeystoreError):
        keystore.default_backend()
    with pytest.raises(keystore.KeystoreError):
        keystore.protect(b"\x44" * 32, "not-a-purpose", keystore.BACKEND_SCRYPT)


def test_dpapi_is_refused_off_windows(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    with pytest.raises(keystore.KeystoreError, match="only on Windows"):
        keystore.protect(b"\x55" * 32, "atlas-signing", keystore.BACKEND_DPAPI)


def test_an_unprotected_legacy_key_is_refused_not_used(tmp_path):
    secret = Ed25519PrivateKey.generate().private_bytes_raw()
    legacy = tmp_path / "atlas_ed25519.key"
    legacy.write_bytes(secret)
    with pytest.raises(keystore.PlaintextKeyError, match="protect_keys.py migrate") as info:
        keystore.read_secret(legacy, "atlas-signing")
    for form in _encodings(secret):
        assert form.decode("latin-1") not in str(info.value)
    # And the key holders refuse it too, rather than signing with it.
    with pytest.raises(keystore.PlaintextKeyError):
        crypto.get_public_key(keys_dir=tmp_path)


def test_errors_never_carry_key_material(tmp_path, monkeypatch):
    secret = Ed25519PrivateKey.generate().private_bytes_raw()
    path = tmp_path / "k.key"
    keystore.write_secret(path, secret, "atlas-signing", keystore.BACKEND_SCRYPT)
    messages = []
    for purpose in ("device-signing",):
        with pytest.raises(keystore.KeystoreError) as info:
            keystore.read_secret(path, purpose)
        messages.append(str(info.value))
    monkeypatch.setenv(keystore.PASSPHRASE_ENV, "wrong")
    with pytest.raises(keystore.KeystoreError) as info:
        keystore.read_secret(path, "atlas-signing")
    messages.append(str(info.value))
    for message in messages:
        for form in _encodings(secret):
            assert form.decode("latin-1") not in message


def test_write_is_atomic_and_leaves_no_temporary_files(tmp_path):
    path = tmp_path / "keys" / "a.key"
    keystore.write_secret(path, b"\x66" * 32, "atlas-signing")
    keystore.write_secret(path, b"\x67" * 32, "atlas-signing")
    assert keystore.read_secret(path, "atlas-signing") == b"\x67" * 32
    assert [p.name for p in path.parent.iterdir()] == ["a.key"]


# ---- every key holder uses it ---------------------------------------------------

def test_the_atlas_signing_key_is_written_protected_and_still_signs(tmp_path, caplog):
    caplog.set_level(logging.DEBUG)
    crypto.generate_identity(keys_dir=tmp_path)
    key_file = tmp_path / "atlas_ed25519.key"
    assert keystore.is_protected(key_file)
    private = crypto._load_private_key(tmp_path)
    _never_contains(key_file.read_bytes(), private.private_bytes_raw())
    public = Ed25519PublicKey.from_public_bytes(bytes.fromhex(crypto.get_public_key(keys_dir=tmp_path)))
    message = b"any bytes"
    public.verify(private.sign(message), message)
    for form in _encodings(private.private_bytes_raw()):
        assert form.decode("latin-1") not in caplog.text


def test_the_device_key_is_written_protected_and_still_signs(tmp_path):
    device_identity.generate_identity(tmp_path)
    key_file = tmp_path / "device_ed25519.key"
    assert keystore.is_protected(key_file)
    private = device_identity._load_private_key(tmp_path)
    _never_contains(key_file.read_bytes(), private.private_bytes_raw())
    signature = bytes.fromhex(device_identity.secure_sign(b"envelope", keys_dir=tmp_path))
    Ed25519PublicKey.from_public_bytes(
        bytes.fromhex(device_identity.get_public_key(tmp_path))).verify(signature, b"envelope")


def test_the_authenticator_key_is_written_protected(tmp_path):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
    import enroll_authenticator
    key = enroll_authenticator._load_or_create(tmp_path)
    key_file = tmp_path / "authenticator_ed25519.key"
    assert keystore.is_protected(key_file)
    _never_contains(key_file.read_bytes(), key.private_bytes_raw())
    assert enroll_authenticator._load_or_create(tmp_path).private_bytes_raw() == key.private_bytes_raw()


# ---- migration ------------------------------------------------------------------

def _plaintext_repo(root: Path) -> dict[Path, bytes]:
    files = {
        root / "atlas_service" / "keys" / "atlas_ed25519.key": Ed25519PrivateKey.generate(),
        root / "firmware" / "device_keys_fw99" / "device_ed25519.key": Ed25519PrivateKey.generate(),
        root / "firmware" / "device_keys_authenticator" / "authenticator_ed25519.key": Ed25519PrivateKey.generate(),
    }
    raw = {}
    for path, key in files.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        raw[path] = key.private_bytes_raw()
        path.write_bytes(raw[path])
    return raw


def _protect_keys():
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
    import protect_keys
    return protect_keys


def test_migration_encrypts_verifies_and_keeps_a_recovery_copy(tmp_path):
    protect_keys = _protect_keys()
    repo, recovery = tmp_path / "repo", tmp_path / "outside" / "recovery"
    originals = _plaintext_repo(repo)
    assert protect_keys.main(["--root", str(repo), "migrate", "--recovery-dir", str(recovery)]) == 0
    purposes = dict((p, purpose) for p, purpose in protect_keys.discover(repo))
    for path, raw in originals.items():
        assert keystore.is_protected(path)
        _never_contains(path.read_bytes(), raw)
        assert keystore.read_secret(path, purposes[path]) == raw
        backups = list(recovery.rglob(path.name))
        assert len(backups) == 1 and backups[0].read_bytes() == raw, "recovery copy missing or wrong"
    # A second run changes nothing and makes no further copies.
    before = {p: p.read_bytes() for p in originals}
    assert protect_keys.main(["--root", str(repo), "migrate", "--recovery-dir", str(recovery)]) == 0
    assert {p: p.read_bytes() for p in originals} == before
    assert len(list(recovery.rglob("*.key"))) == len(originals)


def test_migration_refuses_a_recovery_folder_inside_the_repository(tmp_path):
    protect_keys = _protect_keys()
    repo = tmp_path / "repo"
    originals = _plaintext_repo(repo)
    assert protect_keys.main(["--root", str(repo), "migrate",
                              "--recovery-dir", str(repo / "backup")]) == 2
    assert all(path.read_bytes() == raw for path, raw in originals.items())


def test_migration_leaves_the_original_untouched_if_read_back_fails(tmp_path, monkeypatch):
    protect_keys = _protect_keys()
    repo, recovery = tmp_path / "repo", tmp_path / "recovery"
    originals = _plaintext_repo(repo)
    monkeypatch.setattr(keystore, "read_secret", lambda path, purpose: b"\x00" * 32)
    assert protect_keys.main(["--root", str(repo), "migrate", "--recovery-dir", str(recovery)]) == 1
    for path, raw in originals.items():
        assert path.read_bytes() == raw, "a failed migration changed the original"
        assert [p.name for p in path.parent.iterdir()] == [path.name], "temporary file left behind"


def test_verify_reports_plaintext_and_passes_once_protected(tmp_path, capsys):
    protect_keys = _protect_keys()
    repo, recovery = tmp_path / "repo", tmp_path / "recovery"
    originals = _plaintext_repo(repo)
    assert protect_keys.main(["--root", str(repo), "verify"]) == 1
    assert protect_keys.main(["--root", str(repo), "migrate", "--recovery-dir", str(recovery)]) == 0
    # The ATLAS key must match the bank's copy of its public key.
    shared = repo / "shared_keys" / "atlas_public_key.txt"
    shared.parent.mkdir()
    shared.write_text(crypto.get_public_key(keys_dir=repo / "atlas_service" / "keys"))
    capsys.readouterr()
    assert protect_keys.main(["--root", str(repo), "verify"]) == 0
    out = capsys.readouterr().out
    assert "matches the bank's copy" in out
    for raw in originals.values():
        for form in _encodings(raw):
            assert form.decode("latin-1") not in out
