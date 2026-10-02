"""Create ATLAS's local TEST certificate authority and service certificates.

    python scripts/make_dev_ca.py            # -> dev-certs/ (gitignored)
    python scripts/make_dev_ca.py --force    # replace existing material
    python scripts/make_dev_ca.py --production-material   # add ca.crl + bank.pin to an existing PKI
    python scripts/make_dev_ca.py --revoke bank           # put bank.crt on the CRL
    python scripts/make_dev_ca.py --reissue-atlas         # atlas.crt also names host.wokwi.internal
    python scripts/make_dev_ca.py --firmware-header       # ca.crt -> firmware/atlas_device/atlas_ca.h

Writes the files atlas_service/tls.py describes: a CA, server certificates for
bank_service and atlas_service (SANs localhost and 127.0.0.1; atlas_service's also
host.wokwi.internal, the name the Wokwi ESP32 connects to) and a client
certificate atlas_service presents to the bank for mutual TLS. Keys are ECDSA
P-256, written as encrypted PKCS#8 PEM; the password that opens them is a random
value stored encrypted by keystore.py. No private key or password is printed.

Validity is ten years ON PURPOSE: a local test PKI that expired after a month
would quietly break the project later, and the project must stay runnable at any
time. This is a development authority, not a production PKI -- it has no
revocation, no HSM and no public trust, and nothing outside this machine should
ever be asked to trust ca.crt.

Since 2026-09-25 it also writes what the PRODUCTION transport profile requires
(atlas_service/tls.py, ATLAS_TRANSPORT_PROFILE=production): ca.crl, a certificate
revocation list signed by this CA, and bank.pin, the SHA-256 of bank_service's
public key. --revoke adds a certificate's serial to the CRL. Revocation here is a
CRL file on this machine, checked at every handshake -- not OCSP, and not run by an
institution. It is still a local test authority.

Since 2026-09-27 the ESP32 firmware reaches atlas_service over HTTPS as well. It
verifies ATLAS against ca.crt, which --firmware-header writes into the gitignored
firmware/atlas_device/atlas_ca.h (a PUBLIC certificate, never a key), and checks
the name host.wokwi.internal, which --reissue-atlas adds to an existing
atlas.crt without touching the CA or any other certificate.
"""

from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import secrets
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ATLAS_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ATLAS_ROOT))

import keystore  # noqa: E402
from atlas_service.tls import DEFAULT_CERTS_DIR, PASSWORD_FILE  # noqa: E402

VALID_DAYS = 3650
DEVICE_HOSTNAME = "host.wokwi.internal"      # what the Wokwi ESP32 connects to
FIRMWARE_CA_HEADER = ATLAS_ROOT / "firmware" / "atlas_device" / "atlas_ca.h"
ORG = "ATLAS local test PKI -- not for production"


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORG)])


def _write_key(path: Path, key, password: bytes) -> None:
    path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(password)))


def _issue(ca_key, ca_name, common_name: str, *, server: bool, days: int,
           expired: bool = False, extra_dns: tuple[str, ...] = ()):
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.timezone.utc)
    if expired:                     # valid for one day, ten days ago -- tests only
        now -= dt.timedelta(days=days + 10)
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(common_name))
        .issuer_name(ca_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=False,
                                     content_commitment=False, data_encipherment=False,
                                     key_agreement=True, key_cert_sign=False, crl_sign=False,
                                     encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage(
            [ExtendedKeyUsageOID.SERVER_AUTH if server else ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False)
    )
    if server:
        builder = builder.add_extension(x509.SubjectAlternativeName([
            x509.DNSName("localhost"), *(x509.DNSName(n) for n in extra_dns),
            x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False)
    return key, builder.sign(ca_key, hashes.SHA256())


def spki_sha256(cert: x509.Certificate) -> str:
    """Base64 SHA-256 of the certificate's SubjectPublicKeyInfo -- the usual pin
    format (the same value HPKP and most pinning libraries use)."""
    import base64
    spki = cert.public_key().public_bytes(serialization.Encoding.DER,
                                          serialization.PublicFormat.SubjectPublicKeyInfo)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(spki)
    return base64.b64encode(digest.finalize()).decode("ascii")


def _load_ca(directory: Path):
    password = keystore.read_secret(directory / PASSWORD_FILE, "tls-key-password")
    ca_key = serialization.load_pem_private_key((directory / "ca.key").read_bytes(), password)
    ca_cert = x509.load_pem_x509_certificate((directory / "ca.crt").read_bytes())
    return ca_key, ca_cert, password


def write_crl(directory: Path, revoked_serials=(), *, days: int = VALID_DAYS) -> None:
    """(Re)writes ca.crl, listing `revoked_serials`, signed by the CA."""
    directory = Path(directory)
    ca_key, ca_cert, _ = _load_ca(directory)
    now = dt.datetime.now(dt.timezone.utc)
    builder = (x509.CertificateRevocationListBuilder()
               .issuer_name(ca_cert.subject)
               .last_update(now - dt.timedelta(minutes=5))
               .next_update(now + dt.timedelta(days=days)))
    for serial in sorted(set(revoked_serials)):
        builder = builder.add_revoked_certificate(
            x509.RevokedCertificateBuilder().serial_number(serial)
            .revocation_date(now - dt.timedelta(minutes=1)).build())
    crl = builder.sign(ca_key, hashes.SHA256())
    (directory / "ca.crl").write_bytes(crl.public_bytes(serialization.Encoding.PEM))


def revoked_serials(directory: Path) -> set[int]:
    path = Path(directory) / "ca.crl"
    if not path.exists():
        return set()
    return {r.serial_number for r in x509.load_pem_x509_crl(path.read_bytes())}


def revoke(directory: Path, stem: str) -> int:
    """Adds <stem>.crt's serial to the CRL. Returns the serial."""
    directory = Path(directory)
    cert = x509.load_pem_x509_certificate((directory / f"{stem}.crt").read_bytes())
    write_crl(directory, revoked_serials(directory) | {cert.serial_number})
    return cert.serial_number


def write_pin(directory: Path, stem: str = "bank") -> str:
    directory = Path(directory)
    pin = spki_sha256(x509.load_pem_x509_certificate((directory / f"{stem}.crt").read_bytes()))
    (directory / f"{stem}.pin").write_text(pin + "\n", encoding="ascii")
    return pin


def issue(directory: Path, stem: str, common_name: str, *, server: bool,
          days: int = VALID_DAYS, expired: bool = False) -> None:
    """Issues one more certificate from this CA. Used by the tests to build what an
    attacker with a mis-issued certificate, or an expired one, would present."""
    directory = Path(directory)
    ca_key, ca_cert, password = _load_ca(directory)
    key, cert = _issue(ca_key, ca_cert.subject, common_name, server=server,
                       days=1 if expired else days, expired=expired)
    (directory / f"{stem}.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    _write_key(directory / f"{stem}.key", key, password)


def add_production_material(directory: Path) -> list[str]:
    """ca.crl (nothing revoked yet) and bank.pin, for a PKI that predates them.
    Replaces nothing that exists: an existing CRL keeps its revocations."""
    directory = Path(directory)
    written = []
    if not (directory / "ca.crl").exists():
        write_crl(directory)
        written.append("ca.crl")
    write_pin(directory, "bank")
    written.append("bank.pin")
    return written


def dns_names(cert: x509.Certificate) -> list[str]:
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return []
    return san.get_values_for_type(x509.DNSName)


def atlas_names_device_host(directory: Path) -> bool:
    cert = x509.load_pem_x509_certificate((Path(directory) / "atlas.crt").read_bytes())
    return DEVICE_HOSTNAME in dns_names(cert)


def reissue_atlas(directory: Path) -> list[str]:
    """Re-issues atlas.crt/atlas.key from the EXISTING CA so the certificate also
    names DEVICE_HOSTNAME. The CA, bank.crt, atlas-client.crt, the CRL and the pin
    are untouched. The previous pair is kept beside it as *.replaced-<UTC time>
    (the key stays encrypted); deleting those is the operator's call."""
    import shutil
    directory = Path(directory)
    ca_key, ca_cert, password = _load_ca(directory)
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    written = []
    for name in ("atlas.crt", "atlas.key"):
        if (directory / name).exists():
            shutil.copy2(directory / name, directory / f"{name}.replaced-{stamp}")
            written.append(f"{name}.replaced-{stamp}")
    key, cert = _issue(ca_key, ca_cert.subject, "localhost", server=True, days=VALID_DAYS,
                       extra_dns=(DEVICE_HOSTNAME,))
    (directory / "atlas.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    _write_key(directory / "atlas.key", key, password)
    return written + ["atlas.crt", "atlas.key"]


HEADER_PREAMBLE = """// atlas_ca.h -- GENERATED by `python scripts/make_dev_ca.py --firmware-header`.
// Gitignored: it is this machine's local test CA. PUBLIC certificate only --
// the ESP32 verifies atlas_service against it before sending anything, and
// refuses (fails closed) if the server is not signed by this CA or does not
// carry the name host.wokwi.internal. Never put a private key here.
#pragma once

"""


def firmware_header_text(directory: Path) -> str:
    pem = (Path(directory) / "ca.crt").read_text(encoding="ascii").strip()
    cert = x509.load_pem_x509_certificate(pem.encode("ascii"))
    if not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
        raise ValueError("ca.crt is not a CA certificate")
    lines = pem.splitlines()
    body = "\n".join(f'    "{line}\\n"' for line in lines)
    return HEADER_PREAMBLE + "static const char ATLAS_CA_PEM[] =\n" + body + ";\n"


def firmware_header(directory: Path, dest: Path = FIRMWARE_CA_HEADER) -> Path:
    """Writes ca.crt, as a C string, where the sketch includes it."""
    dest = Path(dest)
    dest.write_text(firmware_header_text(directory), encoding="ascii", newline="\n")
    return dest


def firmware_header_is_current(directory: Path, dest: Path = FIRMWARE_CA_HEADER) -> bool:
    dest = Path(dest)
    return dest.exists() and dest.read_text(encoding="ascii") == firmware_header_text(directory)


def create_pki(directory: Path, *, days: int = VALID_DAYS, force: bool = False) -> list[str]:
    """Creates the whole local PKI in `directory`. Returns the file names written."""
    directory = Path(directory)
    if (directory / "ca.crt").exists() and not force:
        raise FileExistsError(f"{directory} already holds a local CA; pass --force to replace it")
    directory.mkdir(parents=True, exist_ok=True)
    password = secrets.token_urlsafe(32).encode("ascii")
    keystore.write_secret(directory / PASSWORD_FILE, password, "tls-key-password")

    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = _name("ATLAS local test CA")
    now = dt.datetime.now(dt.timezone.utc)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name).issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=False, key_encipherment=False,
                                     content_commitment=False, data_encipherment=False,
                                     key_agreement=False, key_cert_sign=True, crl_sign=True,
                                     encipher_only=False, decipher_only=False), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    (directory / "ca.crt").write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    _write_key(directory / "ca.key", ca_key, password)
    written = [PASSWORD_FILE, "ca.crt", "ca.key"]
    for stem, common_name, server, extra in (("bank", "localhost", True, ()),
                                             ("atlas", "localhost", True, (DEVICE_HOSTNAME,)),
                                             ("atlas-client", "atlas_service", False, ())):
        key, cert = _issue(ca_key, ca_name, common_name, server=server, days=days,
                           extra_dns=extra)
        (directory / f"{stem}.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        _write_key(directory / f"{stem}.key", key, password)
        written += [f"{stem}.crt", f"{stem}.key"]
    written += add_production_material(directory)
    return written


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--dir", type=Path, default=DEFAULT_CERTS_DIR, help=argparse.SUPPRESS)
    ap.add_argument("--force", action="store_true", help="replace an existing local CA")
    ap.add_argument("--production-material", action="store_true",
                    help="add ca.crl and bank.pin to an existing PKI, replacing nothing else")
    ap.add_argument("--revoke", metavar="STEM", help="add STEM.crt (e.g. bank) to the CRL")
    ap.add_argument("--reissue-atlas", action="store_true",
                    help=f"re-issue atlas.crt so it also names {DEVICE_HOSTNAME}; nothing else changes")
    ap.add_argument("--firmware-header", action="store_true",
                    help="write ca.crt (public) to firmware/atlas_device/atlas_ca.h for the ESP32")
    args = ap.parse_args(argv)
    if args.reissue_atlas:
        print(f"[make_dev_ca] wrote {', '.join(reissue_atlas(args.dir))} to {args.dir}")
        return 0
    if args.firmware_header:
        print(f"[make_dev_ca] wrote {firmware_header(args.dir)} (the CA's public certificate)")
        return 0
    if args.production_material:
        print(f"[make_dev_ca] wrote {', '.join(add_production_material(args.dir))} to {args.dir}")
        return 0
    if args.revoke:
        serial = revoke(args.dir, args.revoke)
        print(f"[make_dev_ca] {args.revoke}.crt (serial {serial:x}) is now on {args.dir / 'ca.crl'}")
        return 0
    try:
        written = create_pki(args.dir, force=args.force)
    except FileExistsError as exc:
        print(f"[make_dev_ca] {exc}")
        return 2
    print(f"[make_dev_ca] wrote {', '.join(written)} to {args.dir}")
    print(f"[make_dev_ca] valid {VALID_DAYS} days; private keys are encrypted PEM, their password "
          "is protected by keystore.py; local test PKI only, not production")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
