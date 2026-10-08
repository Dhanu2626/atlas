"""Gives the key-free ESP32 firmware its EXISTING enrolled identity, as an NVS image (local only).

    python scripts/provision_nvs.py --firmware <folder> --keys-dir firmware/device_keys_fw10 \
        --device-id esp32-atlas-fw-10

<folder> holds the key-free build from GitHub's device-build workflow (the artifact
"atlas-firmware-key-free": atlas_device.ino.merged.bin, atlas_device.ino.elf, SHA256SUMS).

What it does, in order, and it stops at the first thing that is not right -- writing
nothing and never generating a new identity:
  1. checks every firmware file against SHA256SUMS, and that the firmware contains no
     trace of this device's key (it must be the key-free build);
  2. reads the device's row from ATLAS's registry, read-only: it must exist and be ACTIVE;
  3. reads the EXISTING key from --keys-dir (decrypted in memory by keystore.py) and
     requires its public key and device_key_id to equal the registry's;
  4. builds the NVS image with Espressif's generator (firmware/nvs_identity.py), reads it
     back with an independent reader, and requires the seed read back to derive the
     enrolled public key;
  5. places it into the firmware image at the offset the image's OWN partition table
     gives, and writes the result only into a folder git ignores
     (firmware/atlas_device/local/ by default), with a manifest of public facts.

It prints public facts only: device id, key id, public-key prefix, offsets, hashes of the
key-free inputs. The seed is never printed, logged or written anywhere but that image.

--variant builds the images the fail-closed checks need (each replaces the active image):
  enrolled        the real identity (default)
  no-identity     the key-free firmware unchanged: the device must refuse to start
  damaged-seed    the enrolled public key with one bit of the seed flipped: the device's
                  self-check must refuse to start
  unenrolled-key  a fresh key ATLAS has never seen (made in memory, enrolled nowhere): the
                  device starts, and ATLAS must answer DEVICE_UNKNOWN
--check re-reads the active image and repeats the identity checks, writing nothing.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ATLAS_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ATLAS_ROOT))

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from firmware import device_identity, nvs_identity  # noqa: E402

DEFAULT_OUT = ATLAS_ROOT / "firmware" / "atlas_device" / "local"
IMAGE_NAME = "atlas-wokwi-full.bin"
ELF_NAME = "atlas_device.ino.elf"
MANIFEST_NAME = "identity.json"
FIRMWARE_FILES = ("atlas_device.ino.merged.bin", "atlas_device.ino.elf")
VARIANTS = ("enrolled", "no-identity", "damaged-seed", "unenrolled-key")


class Stop(Exception):
    """A reason to stop. Its message never carries key material."""


def _public(private: Ed25519PrivateKey) -> bytes:
    return private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _forms(secret: bytes) -> list[bytes]:
    """The encodings a secret could appear in, to search for it."""
    return [secret, secret.hex().encode(), secret.hex().upper().encode(),
            base64.b64encode(secret).rstrip(b"="), base64.urlsafe_b64encode(secret).rstrip(b"=")]


class Speaker:
    """Every line this script prints goes through here, and is refused if it holds a secret."""

    def __init__(self) -> None:
        self.secrets: list[bytes] = []

    def __call__(self, text: str) -> None:
        encoded = text.encode("utf-8")
        if any(form in encoded for s in self.secrets for form in _forms(s)):
            raise Stop("refused to print a line containing key material")
        print(text)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_firmware(folder: Path) -> dict[str, bytes]:
    sums_file = folder / "SHA256SUMS"
    if not sums_file.exists():
        raise Stop(f"{sums_file} is missing -- download the whole atlas-firmware-key-free artifact")
    listed = {}
    for line in sums_file.read_text(encoding="utf-8").splitlines():
        if line.strip():
            digest, name = line.split(maxsplit=1)
            listed[name.lstrip("*").strip()] = digest.lower()
    files = {}
    for name in FIRMWARE_FILES:
        path = folder / name
        if not path.exists():
            raise Stop(f"{path} is missing")
        data = path.read_bytes()
        if listed.get(name) != sha256(data):
            raise Stop(f"{name} does not match its SHA256SUMS entry")
        files[name] = data
    if len(files["atlas_device.ino.merged.bin"]) != 4 * 1024 * 1024:
        raise Stop("atlas_device.ino.merged.bin is not a full 4 MB flash image")
    return files


def registry_row(db: Path, device_id: str) -> sqlite3.Row:
    if not db.exists():
        raise Stop(f"ATLAS's device registry {db} does not exist")
    conn = sqlite3.connect(f"file:{db.as_posix()}?mode=ro&immutable=1", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute("SELECT device_id, device_key_id, public_key, status FROM devices "
                           "WHERE device_id = ?", (device_id,)).fetchone()
    finally:
        conn.close()
    if row is None:
        raise Stop(f"{device_id} is not enrolled in {db}; nothing was generated or written")
    if row["status"] != "ACTIVE":
        raise Stop(f"{device_id} is {row['status']} in the registry, not ACTIVE")
    return row


def existing_key(keys_dir: Path) -> tuple[Ed25519PrivateKey, str]:
    try:
        key_id = device_identity.get_key_id(keys_dir)
        private = device_identity._load_private_key(keys_dir)
    except Exception as exc:                                  # noqa: BLE001 - reported, not re-raised
        raise Stop(f"the existing key could not be read from {keys_dir} ({type(exc).__name__}). "
                   "Nothing was written and NO new identity was generated.") from None
    return private, key_id


def ca_certificate(certs: Path) -> str:
    path = certs / "ca.crt"
    if not path.exists():
        raise Stop(f"{path} is missing -- the device needs the local CA's public certificate")
    pem = path.read_text(encoding="ascii")
    x509.load_pem_x509_certificate(pem.encode("ascii"))       # raises if it is not one
    if "PRIVATE" in pem:
        raise Stop(f"{path} contains private material; refusing")
    return pem


def must_be_ignored(path: Path) -> None:
    rel = path.resolve().relative_to(ATLAS_ROOT.resolve()).as_posix()
    result = subprocess.run(["git", "-C", str(ATLAS_ROOT), "check-ignore", "-q", rel])
    if result.returncode != 0:
        raise Stop(f"{rel} is not ignored by git; refusing to write a key there")


def provision(args, say: Speaker) -> dict:
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    must_be_ignored(out / IMAGE_NAME)

    firmware = load_firmware(Path(args.firmware))
    full = firmware["atlas_device.ino.merged.bin"]
    part = nvs_identity.nvs_partition(full)
    say(f"[provision_nvs] key-free firmware verified against SHA256SUMS; NVS partition from its own "
        f"partition table: offset {part.offset:#x}, size {part.size:#x}")

    row = registry_row(Path(args.db), args.device_id)
    private, key_id = existing_key(Path(args.keys_dir))
    seed = private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                 serialization.NoEncryption())
    say.secrets.append(seed)
    public = _public(private)
    if public.hex() != row["public_key"]:
        raise Stop("the key in --keys-dir is not the key ATLAS has enrolled for this device")
    if key_id != row["device_key_id"]:
        raise Stop(f"--keys-dir holds key id {key_id}, the registry has {row['device_key_id']}")
    say(f"[provision_nvs] existing identity verified against ATLAS's registry: {args.device_id}, "
        f"key {key_id}, public key {public.hex()[:16]}..., ACTIVE")

    for name, data in firmware.items():
        if any(form in data for form in _forms(seed)):
            raise Stop(f"{name} contains this device's key -- it is not the key-free build")
    say("[provision_nvs] the firmware contains no trace of this device's key (5 encodings searched)")

    ca = ca_certificate(Path(args.certs))
    variant = args.variant
    if variant == "unenrolled-key":
        stranger = Ed25519PrivateKey.generate()
        s_seed = stranger.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                        serialization.NoEncryption())
        say.secrets.append(s_seed)
        identity = nvs_identity.Identity(s_seed, _public(stranger), "dev-" + os.urandom(8).hex(),
                                         args.device_id, ca)
    elif variant == "damaged-seed":
        identity = nvs_identity.Identity(bytes([seed[0] ^ 0x01]) + seed[1:], public, key_id, args.device_id, ca)
    else:
        identity = nvs_identity.Identity(seed, public, key_id, args.device_id, ca)

    if variant == "no-identity":
        image = full
    else:
        nvs = nvs_identity.build_identity_nvs(identity, part.size)
        image, _ = nvs_identity.join(full, nvs)
        verify_image(image, identity, say, expect_enrolled=(variant == "enrolled"))

    (out / IMAGE_NAME).write_bytes(image)
    shutil.copy2(Path(args.firmware) / ELF_NAME, out / ELF_NAME)
    manifest = {
        "variant": variant, "device_id": args.device_id,
        "device_key_id": identity.device_key_id if variant != "no-identity" else None,
        "public_key": identity.public_key.hex() if variant != "no-identity" else None,
        "enrolled_public_key": row["public_key"], "enrolled_key_id": row["device_key_id"],
        "ca_sha256": sha256(ca.encode("ascii")),
        "firmware_merged_sha256": sha256(full), "firmware_elf_sha256": sha256(firmware[ELF_NAME]),
        "nvs_offset": part.offset, "nvs_size": part.size, "image": IMAGE_NAME,
        "written_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    (out / MANIFEST_NAME).write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    target = (out / IMAGE_NAME).resolve()
    shown = target.relative_to(ATLAS_ROOT.resolve()).as_posix() if target.is_relative_to(ATLAS_ROOT.resolve()) else str(target)
    say(f"[provision_nvs] wrote {variant} image -> {shown} (git-ignored; holds a key; never upload it)")
    return manifest


def verify_image(image: bytes, identity: nvs_identity.Identity, say: Speaker, expect_enrolled: bool) -> None:
    part = nvs_identity.nvs_partition(image)
    stored = nvs_identity.read_nvs(image[part.offset:part.offset + part.size]).get(nvs_identity.NAMESPACE, {})
    seed = stored.get("seed")
    checks = {
        "seed is 32 bytes": isinstance(seed, bytes) and len(seed) == 32,
        "public key stored as written": stored.get("public_key") == identity.public_key,
        "key id stored as written": stored.get("key_id") == identity.device_key_id,
        "device id stored as written": stored.get("device_id") == identity.device_id,
        "CA certificate stored as written": stored.get("ca_pem") == identity.ca_pem,
    }
    if expect_enrolled:
        checks["seed read back derives the enrolled public key"] = (
            isinstance(seed, bytes) and _public(Ed25519PrivateKey.from_private_bytes(seed)) == identity.public_key)
    failed = [name for name, ok in checks.items() if not ok]
    if failed:
        raise Stop("the NVS image did not read back correctly: " + "; ".join(failed))
    say(f"[provision_nvs] read back independently: {len(checks)} of {len(checks)} identity checks passed")


def check(args, say: Speaker) -> None:
    out = Path(args.out)
    manifest = json.loads((out / MANIFEST_NAME).read_text(encoding="utf-8"))
    image = (out / IMAGE_NAME).read_bytes()
    row = registry_row(Path(args.db), manifest["device_id"])
    part = nvs_identity.nvs_partition(image)
    stored = nvs_identity.read_nvs(image[part.offset:part.offset + part.size]).get(nvs_identity.NAMESPACE, {})
    if not stored:
        say(f"[provision_nvs] active image ({manifest['variant']}): no identity in NVS")
        return
    seed = stored["seed"]
    say.secrets.append(seed)
    derived = _public(Ed25519PrivateKey.from_private_bytes(seed)).hex()
    say(f"[provision_nvs] active image ({manifest['variant']}): device {stored['device_id']}, key {stored['key_id']}")
    say(f"  seed derives the enrolled public key : {derived == row['public_key']}")
    say(f"  stored public key is the enrolled one: {stored['public_key'].hex() == row['public_key']}")
    say(f"  key id is the enrolled one           : {stored['key_id'] == row['device_key_id']}")


def main(argv: list[str] | None = None) -> int:
    from atlas_service.main import DEVICE_DB_PATH
    from atlas_service.tls import DEFAULT_CERTS_DIR
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--firmware", help="folder with the key-free build (artifact atlas-firmware-key-free)")
    ap.add_argument("--keys-dir", help="the device's existing key folder, e.g. firmware/device_keys_fw10")
    ap.add_argument("--device-id", help="the enrolled device_id, e.g. esp32-atlas-fw-10")
    ap.add_argument("--db", default=str(DEVICE_DB_PATH), help="ATLAS's device registry (read-only)")
    ap.add_argument("--certs", default=str(DEFAULT_CERTS_DIR), help="folder with the local CA's ca.crt")
    ap.add_argument("--out", default=str(DEFAULT_OUT), help="git-ignored output folder")
    ap.add_argument("--variant", choices=VARIANTS, default="enrolled")
    ap.add_argument("--check", action="store_true", help="verify the active image; write nothing")
    args = ap.parse_args(argv)
    say = Speaker()
    try:
        if args.check:
            check(args, say)
        else:
            missing = [f"--{n.replace('_', '-')}" for n in ("firmware", "keys_dir", "device_id") if not getattr(args, n)]
            if missing:
                raise Stop("needs " + ", ".join(missing))
            provision(args, say)
    except (Stop, nvs_identity.IdentityImageError) as exc:
        print(f"[provision_nvs] STOPPED: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
