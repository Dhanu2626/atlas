"""TLS material and contexts for ATLAS's local test PKI (2026-09-22).

scripts/make_dev_ca.py creates a small certificate authority that exists only on
this machine, and from it:

    ca.crt                     the trust anchor both services verify against
    bank.crt   / bank.key      bank_service's server certificate
    atlas.crt  / atlas.key     atlas_service's server certificate (its own listener)
    atlas-client.crt / .key    atlas_service's CLIENT certificate for mutual TLS to the bank
    tls-password.key           keystore-protected password that decrypts every *.key above

Every private key is written as encrypted PKCS#8 PEM; the password that opens
them is itself encrypted at rest by keystore.py (purpose "tls-key-password").
Nothing is exported or printed.

WHAT IS ENFORCED on the normal ATLAS -> bank path:
  * TLS 1.2 or newer, with the bank's certificate verified against ca.crt and its
    hostname checked -- an untrusted, expired or mismatched certificate fails the
    handshake, and a failed handshake is an availability failure (PENDING, then
    reconciliation), never an approval;
  * mutual TLS: bank_service accepts only clients presenting a certificate issued
    by this CA, so a caller without atlas-client.key cannot reach /verify at all;
  * no plaintext fallback: the client is built for https only, and if the TLS
    material is missing the request fails instead of retrying over http.

THE PRODUCTION PROFILE (2026-09-25). ATLAS_TRANSPORT_PROFILE=production turns on the
settings a production deployment would use, all enforced and tested here:
  * TLS 1.3 only, on the client and on the served side;
  * revocation: the CA's CRL (ca.crl) is checked on every handshake, both ways --
    a revoked bank certificate, or a revoked ATLAS client certificate, fails;
  * pinning: the bank's public key must match bank.pin. The pin is checked when
    the TLS session is established and BEFORE any request byte is written, so a
    certificate the CA mis-issued to someone else never receives an assertion;
  * no plain HTTP anywhere, loopback included, and the development override
    (ATLAS_ALLOW_INSECURE_HTTP) is ignored;
  * missing material (CRL or pin) refuses rather than degrading.
The default profile, "development", is unchanged. The Wokwi device path is plain
HTTP, so it runs only in development.

WHAT IT IS NOT, IN EITHER PROFILE: production TLS. The CA is a local test
authority, not a public or enterprise PKI; there is no HSM for the CA key; the
CRL is a file signed by that local CA, not OCSP run by an institution; and the
ESP32 firmware still speaks plain HTTP to atlas_service through the loopback
Wokwi gateway (the device's own requests are Ed25519-signed
end to end, but not encrypted in transit).
"""

from __future__ import annotations

import ssl
from pathlib import Path

import keystore

ATLAS_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CERTS_DIR = ATLAS_ROOT / "dev-certs"
PASSWORD_FILE = "tls-password.key"
CRL_FILE = "ca.crl"
BANK_PIN_FILE = "bank.pin"

#: "development" (the default) or "production". Anything else refuses to start.
PROFILE_ENV = "ATLAS_TRANSPORT_PROFILE"
PROFILES = ("development", "production")


def transport_profile() -> str:
    import os
    value = os.environ.get(PROFILE_ENV, "development").strip().lower() or "development"
    if value not in PROFILES:
        raise TLSMaterialError(f"{PROFILE_ENV}={value!r} is not one of {PROFILES}")
    return value


def is_production() -> bool:
    return transport_profile() == "production"


class TLSMaterialError(RuntimeError):
    """The local TLS material is missing or unusable."""


def certs_dir(explicit: Path | None = None) -> Path:
    return Path(explicit) if explicit else DEFAULT_CERTS_DIR


def key_password(directory: Path | None = None) -> bytes:
    path = certs_dir(directory) / PASSWORD_FILE
    if not path.exists():
        raise TLSMaterialError("no local TLS material; run `python scripts/make_dev_ca.py`")
    try:
        return keystore.read_secret(path, "tls-key-password")
    except keystore.KeystoreError as exc:
        raise TLSMaterialError(f"TLS key password unusable: {exc}") from exc


def _require(directory: Path, *names: str) -> None:
    missing = [n for n in names if not (directory / n).exists()]
    if missing:
        raise TLSMaterialError(f"missing TLS files {missing}; run `python scripts/make_dev_ca.py`")


def _check_revocation(ctx: ssl.SSLContext, d: Path) -> None:
    """Loads the CA's CRL and makes every handshake check the peer against it."""
    ctx.load_verify_locations(cafile=str(d / CRL_FILE))
    ctx.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF


def client_context(directory: Path | None = None, *, production: bool | None = None) -> ssl.SSLContext:
    """What atlas_service uses to call the bank: verifies the bank against
    ca.crt (hostname checked) and presents atlas-client.crt for mutual TLS.
    production=True (default: the ATLAS_TRANSPORT_PROFILE) adds TLS 1.3 only and
    CRL checking; the pin is enforced by pinned_bank_transport()."""
    production = is_production() if production is None else production
    d = certs_dir(directory)
    _require(d, "ca.crt", "atlas-client.crt", "atlas-client.key", PASSWORD_FILE,
             *((CRL_FILE,) if production else ()))
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(d / "ca.crt"))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3 if production else ssl.TLSVersion.TLSv1_2
    if production:
        _check_revocation(ctx, d)
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_cert_chain(str(d / "atlas-client.crt"), str(d / "atlas-client.key"),
                        password=key_password(d))
    return ctx


def bank_pin(directory: Path | None = None) -> str:
    d = certs_dir(directory)
    _require(d, BANK_PIN_FILE)
    pin = (d / BANK_PIN_FILE).read_text(encoding="ascii").strip()
    if not pin:
        raise TLSMaterialError(f"{BANK_PIN_FILE} is empty")
    return pin


def spki_sha256(der_certificate: bytes) -> str:
    import base64
    import hashlib
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    spki = x509.load_der_x509_certificate(der_certificate).public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return base64.b64encode(hashlib.sha256(spki).digest()).decode("ascii")


class PinMismatchError(Exception):
    pass


def _pinning_backend(pin: str):
    """An httpcore network backend whose TLS streams are checked against `pin`
    the moment the handshake completes -- before httpcore writes the request."""
    import httpcore

    class _PinnedBackend(httpcore.SyncBackend):
        def connect_tcp(self, *args, **kwargs):
            stream = super().connect_tcp(*args, **kwargs)
            original_start_tls = stream.start_tls

            def start_tls(*a, **kw):
                tls_stream = original_start_tls(*a, **kw)
                der = tls_stream.get_extra_info("ssl_object").getpeercert(True)
                if spki_sha256(der) != pin:
                    tls_stream.close()
                    raise httpcore.ConnectError(
                        "bank certificate does not match the pinned public key (bank.pin)")
                return tls_stream

            stream.start_tls = start_tls
            return stream

    return _PinnedBackend()


def pinned_bank_transport(directory: Path | None = None):
    """The production client transport: the production SSL context (TLS 1.3, CRL)
    plus the bank's public-key pin. Raises TLSMaterialError if any of it is
    missing -- the caller refuses rather than falling back."""
    import httpcore
    import httpx

    ctx = client_context(directory, production=True)
    pin = bank_pin(directory)
    transport = httpx.HTTPTransport(verify=ctx)
    # httpx exposes no public hook for the network backend; its connection pool
    # does. tests/test_tls_production.py fails if this stops taking effect.
    transport._pool = httpcore.ConnectionPool(ssl_context=ctx,
                                              network_backend=_pinning_backend(pin))
    return transport


def harden_server_config(config, directory: Path | None = None) -> None:
    """Production profile for a served endpoint: loads the uvicorn config, then
    raises its SSL context to TLS 1.3 only and makes it check client
    certificates against the CRL. uvicorn's own options cannot express either."""
    d = certs_dir(directory)
    _require(d, CRL_FILE)
    if not config.loaded:
        config.load()
    if config.ssl is None:
        raise TLSMaterialError("the production profile serves TLS only")
    config.ssl.minimum_version = ssl.TLSVersion.TLSv1_3
    _check_revocation(config.ssl, d)


def server_settings(service: str, directory: Path | None = None, *,
                    require_client_cert: bool) -> dict:
    """uvicorn.Config keyword arguments for serving `service` ("bank" or
    "atlas") over TLS. The key password is decrypted here, in the serving
    process, and never appears on a command line or in the environment."""
    d = certs_dir(directory)
    _require(d, "ca.crt", f"{service}.crt", f"{service}.key", PASSWORD_FILE)
    return {
        "ssl_certfile": str(d / f"{service}.crt"),
        "ssl_keyfile": str(d / f"{service}.key"),
        "ssl_keyfile_password": key_password(d).decode("ascii"),
        "ssl_ca_certs": str(d / "ca.crt"),
        "ssl_cert_reqs": ssl.CERT_REQUIRED if require_client_cert else ssl.CERT_NONE,
    }
