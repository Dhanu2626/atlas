"""nvs_identity.py -- the ESP32's identity as an NVS image, built and checked locally.

Since 2026-10-09 the firmware carries no key: atlas_device.ino reads its identity from NVS
namespace "atlas-id" at start-up. This module builds that NVS image from the device's
EXISTING enrolled key, reads it back independently, and joins it with a key-free
firmware image into the full flash image the simulator loads.

    full flash image (4 MB) = key-free firmware from GitHub     (bootloader, partition
                              table, application -- no secret)
                            + this NVS image at the NVS offset   (built HERE, never
                              uploaded: it holds the private seed)

Three independent pieces of evidence, none trusting the next:
  * the NVS partition's offset and size are read from the firmware image's OWN
    partition table, never assumed;
  * the NVS bytes are produced by Espressif's own generator (vendored, hash-pinned:
    firmware/vendor/esp_idf_nvs_partition_gen/PROVENANCE.md);
  * they are read back by read_nvs() below, written separately from that generator,
    and the seed read back must derive the public key ATLAS has enrolled.

Nothing here prints, logs or returns a secret except build_identity_nvs()'s output bytes
and read_nvs()'s parsed entries, which callers keep in memory and write only to a
gitignored file (scripts/provision_nvs.py enforces that).
"""

from __future__ import annotations

import hashlib
import importlib.util
import io
import struct
import sys
import types
import zlib
from dataclasses import dataclass
from pathlib import Path

NAMESPACE = "atlas-id"
SEED_LEN = 32
VENDOR_DIR = Path(__file__).resolve().parent / "vendor" / "esp_idf_nvs_partition_gen"
VENDORED_SHA256 = "eed5a178ef3513757cd841f2d05425a852c723974156df0ccf9218850028f696"

PARTITION_TABLE_OFFSET = 0x8000
PAGE = 4096
NVS_TYPE_DATA, NVS_SUBTYPE_NVS = 0x01, 0x02


class IdentityImageError(Exception):
    """Raised with a message that never contains key material."""


# ---------------------------------------------------------------- partition table
@dataclass(frozen=True)
class Partition:
    label: str
    type: int
    subtype: int
    offset: int
    size: int


def read_partition_table(image: bytes) -> list[Partition]:
    """The ESP-IDF partition table at 0x8000: 32-byte entries, magic AA 50."""
    parts = []
    for i in range(0, 0xC00, 32):
        entry = image[PARTITION_TABLE_OFFSET + i:PARTITION_TABLE_OFFSET + i + 32]
        if len(entry) < 32 or entry[:2] != b"\xAA\x50":
            break
        ptype, subtype, offset, size = struct.unpack_from("<BBII", entry, 2)
        label = entry[12:28].split(b"\0", 1)[0].decode("ascii", "replace")
        parts.append(Partition(label, ptype, subtype, offset, size))
    return parts


def nvs_partition(image: bytes) -> Partition:
    found = [p for p in read_partition_table(image) if p.type == NVS_TYPE_DATA and p.subtype == NVS_SUBTYPE_NVS]
    if len(found) != 1:
        raise IdentityImageError(f"expected one NVS partition in the firmware image, found {len(found)}")
    p = found[0]
    if p.offset % PAGE or p.size % PAGE or p.size < 3 * PAGE or p.offset + p.size > len(image):
        raise IdentityImageError(f"NVS partition at {p.offset:#x} size {p.size:#x} does not fit this image")
    return p


# ---------------------------------------------------------------- building (Espressif's code)
def _load_generator():
    """Imports the vendored generator with inert stand-ins for its CLI-only imports."""
    source = VENDOR_DIR / "nvs_partition_gen.py"
    digest = hashlib.sha256(source.read_bytes().replace(b"\r\n", b"\n")).hexdigest()
    if digest != VENDORED_SHA256:
        raise IdentityImageError("the vendored NVS generator does not match its pinned hash")

    class _Quiet:
        def __getattr__(self, name):
            def _swallow(*args, **kwargs):
                if name == "die":
                    raise IdentityImageError("the NVS generator refused its input")
            return _swallow

    class _Anything:
        def __getattr__(self, name):
            return _Anything()

        def __call__(self, *args, **kwargs):
            return _Anything()

    stubs = {"rich_click": _Anything(), "esp_pylib": types.ModuleType("esp_pylib"),
             "esp_pylib.cli_options": types.ModuleType("esp_pylib.cli_options"),
             "esp_pylib.logger": types.ModuleType("esp_pylib.logger")}
    stubs["esp_pylib.cli_options"].EspRichGroup = object
    stubs["esp_pylib.cli_options"].MutuallyExclusiveOption = object
    stubs["esp_pylib.logger"].log = _Quiet()
    saved = {name: sys.modules.get(name) for name in stubs}
    sys.modules.update(stubs)
    try:
        spec = importlib.util.spec_from_file_location("_atlas_vendored_nvs_gen", source)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        for name, previous in saved.items():
            if previous is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = previous


@dataclass(frozen=True)
class Identity:
    """Everything the device reads from NVS. `seed` is the only secret."""
    seed: bytes
    public_key: bytes
    device_key_id: str
    device_id: str
    ca_pem: str


def build_identity_nvs(identity: Identity, size: int) -> bytes:
    """The NVS partition image (format version 2), in memory."""
    if len(identity.seed) != SEED_LEN or len(identity.public_key) != 32:
        raise IdentityImageError("the seed and public key must be 32 bytes each")
    gen = _load_generator()
    out = io.BytesIO()
    # Exactly as the generator's own command line does: check_size() reserves the one
    # page NVS keeps free, and says whether the partition is big enough to be writable.
    usable, read_only = gen.check_size(str(size))
    if read_only:
        raise IdentityImageError("the NVS partition is too small to stay writable")
    nvs = gen.nvs_open(out, usable, gen.Page.VERSION2)
    gen.write_entry(nvs, NAMESPACE, "namespace", "", "")
    gen.write_entry(nvs, "seed", "data", "hex2bin", identity.seed.hex())
    gen.write_entry(nvs, "public_key", "data", "hex2bin", identity.public_key.hex())
    gen.write_entry(nvs, "key_id", "data", "string", identity.device_key_id)
    gen.write_entry(nvs, "device_id", "data", "string", identity.device_id)
    gen.write_entry(nvs, "ca_pem", "data", "string", identity.ca_pem)
    gen.nvs_close(nvs)
    data = out.getvalue()
    if len(data) != size:
        raise IdentityImageError(f"the generator produced {len(data)} bytes for a {size}-byte partition")
    return data


# ---------------------------------------------------------------- reading (independent)
def _crc(data: bytes) -> int:
    return zlib.crc32(data, 0xFFFFFFFF) & 0xFFFFFFFF


def read_nvs(image: bytes) -> dict[str, dict[str, bytes | str]]:
    """Parses an NVS (version 2) partition image: {namespace: {key: value}}.

    Written apart from the generator, from the published format: page header with
    CRC, 2-bit entry-state bitmap, 32-byte entries with their own CRC, strings (0x21)
    and multi-page blobs (0x42 data chunks + 0x48 index). Every CRC is checked."""
    if len(image) % PAGE:
        raise IdentityImageError("an NVS image is a whole number of 4 KB pages")
    namespaces: dict[int, str] = {}
    strings: dict[tuple[int, str], str] = {}
    chunks: dict[tuple[int, str], dict[int, bytes]] = {}
    indexes: dict[tuple[int, str], tuple[int, int, int]] = {}
    for base in range(0, len(image), PAGE):
        page = image[base:base + PAGE]
        state = struct.unpack_from("<I", page, 0)[0]
        if state == 0xFFFFFFFF:
            continue                                            # empty page
        if _crc(page[4:28]) != struct.unpack_from("<I", page, 28)[0]:
            raise IdentityImageError(f"page header CRC wrong at {base:#x}")
        if page[8] != 0xFE:
            raise IdentityImageError(f"page at {base:#x} is not NVS format version 2")
        bitmap = page[32:64]
        i = 0
        while i < 126:
            if (bitmap[i // 4] >> ((i % 4) * 2)) & 3 != 2:      # only "written" entries
                i += 1
                continue
            entry = page[64 + 32 * i:64 + 32 * (i + 1)]
            ns, etype, span, chunk = entry[0], entry[1], entry[2], entry[3]
            if _crc(entry[0:4] + entry[8:32]) != struct.unpack_from("<I", entry, 4)[0]:
                raise IdentityImageError(f"entry CRC wrong at {base:#x} entry {i}")
            key = entry[8:24].split(b"\0", 1)[0].decode("ascii")
            payload = page[64 + 32 * (i + 1):64 + 32 * (i + span)]
            if ns == 0 and etype == 0x01:
                namespaces[entry[24]] = key
            elif etype in (0x21, 0x42):
                size = struct.unpack_from("<H", entry, 24)[0]
                body = payload[:size]
                if _crc(body) != struct.unpack_from("<I", entry, 28)[0]:
                    raise IdentityImageError(f"data CRC wrong for an entry at {base:#x}")
                if etype == 0x21:
                    strings[(ns, key)] = body.rstrip(b"\0").decode("utf-8")
                else:
                    chunks.setdefault((ns, key), {})[chunk] = body
            elif etype == 0x48:
                total, count, start = struct.unpack_from("<IBB", entry, 24)
                indexes[(ns, key)] = (total, count, start)
            i += max(1, span)
    result: dict[str, dict[str, bytes | str]] = {}
    for (ns, key), text in strings.items():
        result.setdefault(namespaces.get(ns, f"#{ns}"), {})[key] = text
    for (ns, key), (total, count, start) in indexes.items():
        parts = chunks.get((ns, key), {})
        blob = b"".join(parts[c] for c in range(start, start + count) if c in parts)
        if len(blob) != total:
            raise IdentityImageError("a blob's chunks do not add up to its declared size")
        result.setdefault(namespaces.get(ns, f"#{ns}"), {})[key] = blob
    return result


# ---------------------------------------------------------------- joining
def join(firmware_image: bytes, nvs_image: bytes) -> tuple[bytes, Partition]:
    """Places the NVS image into the key-free full firmware image, at the offset its own
    partition table gives. Refuses if that region is not blank in the firmware image."""
    part = nvs_partition(firmware_image)
    if len(nvs_image) != part.size:
        raise IdentityImageError(f"the NVS image is {len(nvs_image)} bytes; the partition is {part.size}")
    region = firmware_image[part.offset:part.offset + part.size]
    if region != b"\xff" * part.size:
        raise IdentityImageError("the firmware image's NVS region is not blank -- it is not the key-free build")
    return firmware_image[:part.offset] + nvs_image + firmware_image[part.offset + part.size:], part
