"""Encrypt ATLAS's private key files at rest, and check they still work.

    python scripts/protect_keys.py status              # which key files are protected
    python scripts/protect_keys.py migrate             # encrypt every plaintext key file
    python scripts/protect_keys.py verify              # load, sign and cross-check each key

Before 2026-09-22 each private key was 32 raw bytes on disk. `migrate` converts
every such file in place to keystore.py's protected format, one at a time:

  1. read the plaintext key and derive its public key;
  2. write the protected version to a temporary file and read it back through
     keystore.read_secret(), requiring the same bytes and the same public key;
  3. copy the plaintext original to a RECOVERY folder outside the repository and
     outside OneDrive (~/ATLAS-key-recovery/<time>/);
  4. only then replace the key file with the protected version.

Nothing is deleted. The recovery copies are plaintext on this machine's local
disk, deliberately outside the synced project folder, so a failed migration can
always be undone. Delete them yourself once `verify` passes and you are
satisfied; until then this machine still holds a plaintext copy. Earlier
plaintext versions may also survive in OneDrive's version history or recycle
bin -- this script cannot see or clear those, and says so instead of claiming
otherwise. Rotating a key (a new identity) is the only way to retire material
that may already have been copied; RUNBOOK.md, "Key protection", has the steps.

Output names files and public-key fingerprints (the first 16 hex digits of
SHA-256 over the PUBLIC key). No private key value is ever printed.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import sqlite3
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

ATLAS_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ATLAS_ROOT))

import keystore  # noqa: E402

#: (glob relative to the repository root, purpose)
KEY_FILES = (
    ("atlas_service/keys/atlas_ed25519.key", "atlas-signing"),
    ("firmware/device_keys*/device_ed25519.key", "device-signing"),
    ("firmware/device_keys_authenticator/authenticator_ed25519.key", "authenticator-signing"),
)


def discover(root: Path) -> list[tuple[Path, str]]:
    found = []
    for pattern, purpose in KEY_FILES:
        found.extend((p, purpose) for p in sorted(root.glob(pattern)) if p.is_file())
    return found


def _public_raw(private: Ed25519PrivateKey) -> bytes:
    return private.public_key().public_bytes(serialization.Encoding.Raw,
                                             serialization.PublicFormat.Raw)


def fingerprint(public_raw: bytes) -> str:
    return hashlib.sha256(public_raw).hexdigest()[:16]


def default_recovery_root() -> Path:
    """~/ATLAS-key-recovery: outside the repository and OneDrive, and NOT under
    %LOCALAPPDATA% -- a packaged Windows app (such as the Claude desktop app)
    has its AppData writes silently redirected into a private per-app cache,
    where recovery material would be invisible in Explorer and lost if that app
    were reset. The user's profile root is neither synced nor redirected."""
    return Path.home() / "ATLAS-key-recovery"


def _inside(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def migrate_file(path: Path, purpose: str, recovery_dir: Path, root: Path) -> str:
    """Protects one key file. Returns what happened; raises on any doubt,
    leaving the original untouched."""
    if keystore.is_protected(path):
        return "already protected"
    raw = path.read_bytes()
    if len(raw) != 32:
        raise keystore.KeystoreError(f"{path.name} is neither protected nor a 32-byte raw key; "
                                     "refusing to guess")
    expected_public = _public_raw(Ed25519PrivateKey.from_private_bytes(raw))

    fd, tmp_name = tempfile.mkstemp(prefix=".keystore-migrate-", dir=path.parent)
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(keystore.protect(raw, purpose))
        recovered = keystore.read_secret(tmp, purpose)
        if recovered != raw or _public_raw(Ed25519PrivateKey.from_private_bytes(recovered)) != expected_public:
            raise keystore.KeystoreError(f"{path.name}: the protected copy did not read back "
                                         "identically; original left untouched")
        backup = recovery_dir / path.relative_to(root)
        backup.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, backup)
        if backup.read_bytes() != raw:
            raise keystore.KeystoreError(f"{path.name}: recovery copy did not verify; "
                                         "original left untouched")
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)
    return f"protected ({keystore.file_backend(path)}); recovery copy at {backup}"


def cmd_status(args: argparse.Namespace) -> int:
    root = Path(args.root)
    files = discover(root)
    if not files:
        print("[keys] no private key files found")
    for path, purpose in files:
        backend = keystore.file_backend(path)
        state = f"PROTECTED ({backend})" if backend else "PLAINTEXT -- run migrate"
        print(f"  {path.relative_to(root)}  [{purpose}]  {state}")
    return 0 if all(keystore.is_protected(p) for p, _ in files) else 1


def cmd_migrate(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    recovery_root = Path(args.recovery_dir) if args.recovery_dir else default_recovery_root()
    if _inside(recovery_root, root):
        print(f"[keys] refusing: the recovery folder must be outside the repository ({root})")
        return 2
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    recovery_dir = recovery_root / stamp
    failures = 0
    for path, purpose in discover(root):
        try:
            print(f"  {path.relative_to(root)}: {migrate_file(path, purpose, recovery_dir, root)}")
        except keystore.KeystoreError as exc:
            failures += 1
            print(f"  {path.relative_to(root)}: FAILED -- {exc}")
    if recovery_dir.exists():
        print(f"[keys] plaintext recovery copies: {recovery_dir}")
        print("[keys] they are NOT deleted. Remove them yourself once `verify` passes.")
    return 1 if failures else 0


def _registry_public_key(root: Path, keys_dir: Path) -> str | None:
    key_id_file = keys_dir / "device_key_id.txt"
    db = root / "atlas_service" / "atlas_devices.db"
    if not (key_id_file.exists() and db.exists()):
        return None
    uri = f"file:{db.resolve().as_posix()}?mode=ro&immutable=1"
    with sqlite3.connect(uri, uri=True) as conn:
        row = conn.execute("SELECT public_key FROM devices WHERE device_key_id = ?",
                           (key_id_file.read_text().strip(),)).fetchone()
    return row[0] if row else None


def _enrolled_authenticators(root: Path) -> set[str]:
    db = root / "atlas_service" / "atlas_step_up.db"
    if not db.exists():
        return set()
    uri = f"file:{db.resolve().as_posix()}?mode=ro&immutable=1"
    with sqlite3.connect(uri, uri=True) as conn:
        return {r[0] for r in conn.execute("SELECT public_key FROM step_up_authenticators")}


def cmd_verify(args: argparse.Namespace) -> int:
    """For each key: it is protected, it decrypts, it signs, the signature
    verifies, and its public key matches the copy the rest of ATLAS trusts.
    Databases are opened read-only and immutable; nothing is written."""
    root = Path(args.root).resolve()
    problems = 0
    message = b"ATLAS-KEYSTORE-VERIFY|" + datetime.now(timezone.utc).isoformat().encode()
    for path, purpose in discover(root):
        label = path.relative_to(root)
        if not keystore.is_protected(path):
            print(f"  {label}: PLAINTEXT -- not protected")
            problems += 1
            continue
        try:
            private = Ed25519PrivateKey.from_private_bytes(keystore.read_secret(path, purpose))
        except keystore.KeystoreError as exc:
            print(f"  {label}: does not decrypt -- {exc}")
            problems += 1
            continue
        public = _public_raw(private)
        Ed25519PublicKey.from_public_bytes(public).verify(private.sign(message), message)
        checks = ["decrypts", "signs and verifies"]
        if purpose == "atlas-signing":
            shared = root / "shared_keys" / "atlas_public_key.txt"
            ok = shared.exists() and shared.read_text().strip() == public.hex()
            checks.append("matches the bank's copy" if ok else "DOES NOT match shared_keys/atlas_public_key.txt")
            problems += 0 if ok else 1
        elif purpose == "device-signing":
            registered = _registry_public_key(root, path.parent)
            if registered is not None:
                ok = registered == public.hex()
                checks.append("matches the device registry" if ok else "DOES NOT match the device registry")
                problems += 0 if ok else 1
        elif purpose == "authenticator-signing":
            enrolled = _enrolled_authenticators(root)
            if enrolled:
                ok = public.hex() in enrolled
                checks.append("matches the enrolled authenticator" if ok else "is NOT enrolled")
                problems += 0 if ok else 1
        print(f"  {label}: {keystore.file_backend(path)}, " + ", ".join(checks) +
              f"  (public key fingerprint {fingerprint(public)})")
    print("[keys] verify:", "all keys OK" if not problems else f"{problems} problem(s)")
    return 1 if problems else 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", default=str(ATLAS_ROOT), help=argparse.SUPPRESS)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status").set_defaults(fn=cmd_status)
    m = sub.add_parser("migrate")
    m.add_argument("--recovery-dir", help="where plaintext originals are copied (outside the repo)")
    m.set_defaults(fn=cmd_migrate)
    sub.add_parser("verify").set_defaults(fn=cmd_verify)
    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
