"""Protected-at-rest storage for ATLAS's private keys -- software only.

Every private key ATLAS keeps on disk goes through this module: the ATLAS
assertion-signing key (atlas_service/crypto.py), each device key
(firmware/device_identity.py), the step-up authenticator key
(scripts/enroll_authenticator.py) and the password that unlocks the local TLS
private keys (scripts/make_dev_ca.py). Callers ask for a key by path and
purpose; they never see how it is stored.

    application  ->  keystore.read_secret(path, purpose)  ->  encrypted file
                                                          ->  bytes in memory, only while needed

TWO BACKENDS, chosen per file and recorded in its header:

  * "dpapi" (default on Windows) -- the Windows Data Protection API, user scope.
    The operating system encrypts the key with a master key derived from the
    signed-in user's credentials. No password is created or stored, and a copy of
    the file on another machine or another account (OneDrive's cloud copy, a
    backup, a stolen laptop image without the user's login) does not decrypt.
    The flip side is deliberate: moving to a new PC means restoring or rotating
    keys (RUNBOOK.md, "Key protection").
  * "scrypt-aesgcm" -- AES-256-GCM under a key derived with scrypt from a
    passphrase in ATLAS_KEYSTORE_PASSPHRASE. Portable, for non-Windows machines
    and CI. The passphrase is the operator's secret and never lives in the repo.

Each file binds its PURPOSE (DPAPI entropy / AES-GCM associated data), so a
device key cannot be substituted for the ATLAS signing key even by someone who
can decrypt both. A plaintext 32-byte key file -- the format before 2026-09-22 --
is refused with a pointer to `scripts/protect_keys.py migrate`, never silently
used: an unprotected key is an error, not a fallback.

WHAT THIS IS NOT: hardware protection. A process running as the same user can
decrypt these keys, and the decrypted bytes live in ordinary process memory
while in use. There is no secure element, TEE or HSM, and the ESP32's own seed
(firmware/atlas_device/secrets.h and the compiled image) is outside this module
entirely -- the firmware carries its key in flash in the clear, which only
hardware (flash encryption or a secure element) can change.

Nothing in this module ever prints, logs or raises with key material in it.
"""

from __future__ import annotations

import base64
import hashlib
import os
import secrets
import sys
import tempfile
from pathlib import Path

MAGIC = b"ATLAS-KEYSTORE/1"
BACKEND_DPAPI = "dpapi"
BACKEND_SCRYPT = "scrypt-aesgcm"
BACKENDS = (BACKEND_DPAPI, BACKEND_SCRYPT)

BACKEND_ENV = "ATLAS_KEYSTORE_BACKEND"
PASSPHRASE_ENV = "ATLAS_KEYSTORE_PASSPHRASE"

#: scrypt cost. 2**15 * 8 * 128 bytes = 32 MiB and roughly 0.1 s per derivation
#: on a laptop; derived keys are cached per (passphrase, salt) for the process.
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2**15, 8, 1

PURPOSES = frozenset({
    "atlas-signing",          # ATLAS -> bank assertion key (atlas_service/crypto.py)
    "device-signing",         # a device's envelope key (firmware/device_identity.py)
    "authenticator-signing",  # the step-up authenticator (scripts/enroll_authenticator.py)
    "tls-key-password",       # unlocks the local TLS private keys (scripts/make_dev_ca.py)
    "model-integrity",        # HMAC key for trained ML artifacts (atlas_service/ml/registry.py)
    "policy-signing",         # a policy owner's key (scripts/policy_key.py, 2026-09-27)
})


class KeystoreError(Exception):
    """Any failure to protect or recover a key. Never carries key material."""


class PlaintextKeyError(KeystoreError):
    """A key file is still in the unprotected pre-2026-09-22 format."""


# ---- backend selection ----------------------------------------------------------

def default_backend() -> str:
    chosen = os.environ.get(BACKEND_ENV, "").strip()
    if chosen:
        if chosen not in BACKENDS:
            raise KeystoreError(f"{BACKEND_ENV}={chosen!r} is not one of {', '.join(BACKENDS)}")
        return chosen
    return BACKEND_DPAPI if sys.platform == "win32" else BACKEND_SCRYPT


def _check_purpose(purpose: str) -> None:
    if purpose not in PURPOSES:
        raise KeystoreError(f"unknown key purpose {purpose!r}")


# ---- DPAPI (Windows) ------------------------------------------------------------

def _dpapi(data: bytes, entropy: bytes, *, protect: bool) -> bytes:
    if sys.platform != "win32":
        raise KeystoreError("the dpapi backend exists only on Windows; use "
                            f"{BACKEND_ENV}={BACKEND_SCRYPT} with {PASSPHRASE_ENV}")
    import ctypes
    from ctypes import wintypes

    class _Blob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    def _in(buf: bytes):
        raw = ctypes.create_string_buffer(buf, len(buf))
        return _Blob(len(buf), ctypes.cast(raw, ctypes.POINTER(ctypes.c_char))), raw

    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    ui_forbidden = 0x1
    blob_in, keep_in = _in(data)
    blob_entropy, keep_entropy = _in(entropy)
    blob_out = _Blob()
    if protect:
        ok = crypt32.CryptProtectData(ctypes.byref(blob_in), "ATLAS key", ctypes.byref(blob_entropy),
                                      None, None, ui_forbidden, ctypes.byref(blob_out))
    else:
        ok = crypt32.CryptUnprotectData(ctypes.byref(blob_in), None, ctypes.byref(blob_entropy),
                                        None, None, ui_forbidden, ctypes.byref(blob_out))
    ctypes.memset(keep_in, 0, len(data))
    del keep_entropy
    if not ok:
        err = ctypes.get_last_error()
        raise KeystoreError(
            "DPAPI refused to " + ("protect" if protect else "unprotect") +
            f" the key (Windows error {err}); a DPAPI key only opens for the same Windows user "
            "on the same machine, with the same purpose")
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        ctypes.memset(blob_out.pbData, 0, blob_out.cbData)
        kernel32.LocalFree(blob_out.pbData)


# ---- scrypt + AES-256-GCM (portable) --------------------------------------------

_derived: dict[tuple[bytes, bytes], bytes] = {}


def _passphrase() -> bytes:
    value = os.environ.get(PASSPHRASE_ENV, "")
    if not value:
        raise KeystoreError(f"the {BACKEND_SCRYPT} backend needs {PASSPHRASE_ENV} to be set")
    return value.encode("utf-8")


def _kek(salt: bytes) -> bytes:
    passphrase = _passphrase()
    cache_key = (hashlib.sha256(passphrase).digest(), salt)
    if cache_key not in _derived:
        _derived[cache_key] = hashlib.scrypt(passphrase, salt=salt, n=SCRYPT_N, r=SCRYPT_R,
                                             p=SCRYPT_P, maxmem=64 * 1024 * 1024, dklen=32)
    return _derived[cache_key]


def _aesgcm():
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    return AESGCM


# ---- the file format ------------------------------------------------------------

def _header(backend: str, purpose: str) -> bytes:
    return MAGIC + b"\nbackend=" + backend.encode() + b"\npurpose=" + purpose.encode() + b"\n\n"


def protect(secret: bytes, purpose: str, backend: str | None = None) -> bytes:
    """Returns the complete protected file contents for `secret`."""
    _check_purpose(purpose)
    backend = backend or default_backend()
    if backend not in BACKENDS:
        raise KeystoreError(f"unknown keystore backend {backend!r}")
    header = _header(backend, purpose)
    if backend == BACKEND_DPAPI:
        payload = _dpapi(secret, header, protect=True)
    else:
        salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
        payload = salt + nonce + _aesgcm()(_kek(salt)).encrypt(nonce, secret, header)
    return header + base64.b64encode(payload) + b"\n"


def _parse(blob: bytes) -> tuple[str, str, bytes, bytes]:
    if not blob.startswith(MAGIC + b"\n"):
        raise PlaintextKeyError("not a protected key file")
    head, sep, body = blob.partition(b"\n\n")
    if not sep:
        raise KeystoreError("protected key file is truncated (no header terminator)")
    fields = dict(line.split(b"=", 1) for line in head.split(b"\n")[1:] if b"=" in line)
    backend = fields.get(b"backend", b"").decode()
    purpose = fields.get(b"purpose", b"").decode()
    if backend not in BACKENDS:
        raise KeystoreError(f"protected key file names an unknown backend {backend!r}")
    try:
        payload = base64.b64decode(body.strip(), validate=True)
    except ValueError as exc:
        raise KeystoreError("protected key file payload is not valid base64") from exc
    return backend, purpose, head + b"\n\n", payload


def unprotect(blob: bytes, purpose: str) -> bytes:
    """Recovers the secret from protected file contents, or raises."""
    _check_purpose(purpose)
    backend, stored_purpose, header, payload = _parse(blob)
    if stored_purpose != purpose:
        raise KeystoreError(f"key file is for purpose {stored_purpose!r}, not {purpose!r}")
    if backend == BACKEND_DPAPI:
        return _dpapi(payload, header, protect=False)
    if len(payload) < 16 + 12 + 16:
        raise KeystoreError("protected key file payload is too short")
    salt, nonce, ciphertext = payload[:16], payload[16:28], payload[28:]
    from cryptography.exceptions import InvalidTag
    try:
        return _aesgcm()(_kek(salt)).decrypt(nonce, ciphertext, header)
    except InvalidTag as exc:
        raise KeystoreError("key file failed authentication: wrong passphrase, wrong purpose, "
                            "or the file was modified") from exc


# ---- files ----------------------------------------------------------------------

def is_protected(path: Path) -> bool:
    try:
        with open(path, "rb") as fh:
            return fh.read(len(MAGIC) + 1) == MAGIC + b"\n"
    except FileNotFoundError:
        return False


def write_secret(path: Path, secret: bytes, purpose: str, backend: str | None = None) -> None:
    """Writes `secret` protected, atomically: the file is either the old
    contents or the complete new contents, never a half-written key."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = protect(secret, purpose, backend)
    fd, tmp = tempfile.mkstemp(prefix=".keystore-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def read_secret(path: Path, purpose: str) -> bytes:
    """Returns the secret stored at `path`. An unprotected legacy file is
    refused, never read as a fallback."""
    path = Path(path)
    blob = path.read_bytes()
    if not blob.startswith(MAGIC + b"\n"):
        raise PlaintextKeyError(
            f"{path.name} is an unprotected key file; run `python scripts/protect_keys.py "
            "migrate` to encrypt it (the plaintext original is moved out of the repository, "
            "not deleted)")
    return unprotect(blob, purpose)


def file_backend(path: Path) -> str | None:
    """The backend a protected file uses, or None for an unprotected file."""
    try:
        backend, _, _, _ = _parse(Path(path).read_bytes())
    except PlaintextKeyError:
        return None
    return backend
