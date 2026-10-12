"""provision_device.py firmware-config is retired (2026-10-12).

ATLAS is software-only from 2026-10-12 (Dhanush's decision): the device in every
supported workflow is the firmware's Python twin (firmware/virtual_device.py, driven by
scripts/demo.py and the live page), whose key stays in the keystore. firmware-config
existed only to print an enrolled device's private key seed for pasting into the ESP32
sketch's secrets.h, so it now refuses. These tests pin the refusal in the one case that
used to print a seed -- an enrolled device with its matching key folder -- and prove the
command does not even read the key.
"""

from __future__ import annotations

import base64
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import provision_device  # noqa: E402

import keystore  # noqa: E402
from atlas_service.device.db import DeviceStore  # noqa: E402
from atlas_service.device.registry import register_demo_device  # noqa: E402
from firmware import device_identity  # noqa: E402

DEVICE_ID = "device-firmware-config-check"


def _enrolled_device(tmp_path: Path) -> tuple[Path, Path]:
    keys = tmp_path / "device-keys"
    device_identity.init_device(keys)
    db = tmp_path / "devices.db"
    store = DeviceStore(db)
    try:
        register_demo_device(store, device_id=DEVICE_ID,
                             device_key_id=device_identity.get_key_id(keys),
                             public_key=device_identity.get_public_key(keys),
                             bound_subject="user-demo-1")
    finally:
        store.close()
    return db, keys


def _firmware_config(monkeypatch, capsys, db: Path, keys: Path) -> tuple[int, str]:
    monkeypatch.setattr(sys, "argv", ["provision_device.py", "--db", str(db), "firmware-config",
                                      "--device-id", DEVICE_ID, "--keys-dir", str(keys)])
    code = provision_device.main()
    return code, capsys.readouterr().out


def test_firmware_config_refuses_and_prints_no_key_for_an_enrolled_device(tmp_path, monkeypatch, capsys):
    db, keys = _enrolled_device(tmp_path)
    seed = device_identity._load_private_key(keys).private_bytes_raw()

    code, out = _firmware_config(monkeypatch, capsys, db, keys)

    assert code == 1
    assert "retired" in out
    printed = out.encode()
    for form in (seed.hex().encode(), seed.hex().upper().encode(),
                 base64.b64encode(seed).rstrip(b"="), base64.urlsafe_b64encode(seed).rstrip(b"=")):
        assert form not in printed
    assert "DEVICE_KEY_SEED" not in out


def test_firmware_config_never_reads_the_private_key(tmp_path, monkeypatch, capsys):
    db, keys = _enrolled_device(tmp_path)

    def tripwire(*args, **kwargs):
        raise AssertionError("firmware-config read a private key")

    monkeypatch.setattr(device_identity, "_load_private_key", tripwire)
    monkeypatch.setattr(keystore, "read_secret", tripwire)

    code, _ = _firmware_config(monkeypatch, capsys, db, keys)

    assert code == 1
