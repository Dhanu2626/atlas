"""DEMO device provisioning -- a LOCAL CLI, deliberately not an HTTP endpoint.

===========================================================================
 THIS IS NOT PRODUCTION DEVICE ENROLLMENT AND MUST NEVER BE PRESENTED AS IT.
===========================================================================

What this proves:      someone with filesystem access to this machine
                       generated a keypair and wrote its public half into the
                       local registry.
What it does NOT prove: that the device belongs to the account holder, that
                       the key lives in tamper-resistant hardware, or that
                       the person running it is authorised to bind a device
                       to `--subject`.

That gap is ARCHITECTURE.md's RQ-7/12/24 and Blueprint 24.6's "forged device
identity", both rated unresolved. Cryptography cannot close it; identity
proofing and an auditable operator are organisational problems.

WHY A CLI AND NOT AN ENDPOINT: an unauthenticated HTTP enrollment route is an
account-takeover primitive -- anyone who could reach it could enrol their own
key against any subject. Keeping provisioning off the network surface means
there is no such route to mistake for a secure mechanism. Enrolling requires
local access, which is at least an honest trust boundary for a prototype.

A production path would need: identity proofing of the account holder, an
attestation certificate from a secure element proving the key was generated
in hardware and cannot be exported, an authenticated operator, and an audit
record naming who authorised the binding. None of that is implemented.

Usage
-----
  python scripts/provision_device.py enroll  --device-id esp32-atlas-demo-01 \
                                             --subject user-demo-1
  python scripts/provision_device.py list
  python scripts/provision_device.py show    --device-id esp32-atlas-demo-01
  python scripts/provision_device.py suspend --device-id esp32-atlas-demo-01
  python scripts/provision_device.py revoke  --device-id esp32-atlas-demo-01
  python scripts/provision_device.py --db <state-dir>/atlas_devices.db set-home
         --device-id esp32-atlas-fw-10 --lat 17.385044 --lon 78.486671 --radius-m 10000

`set-home` records the home area the location grade measures against
(atlas_service/device/location.py). For the Wokwi GNSS demo, point --db at a
disposable run's copy (scripts/run_sim.py --state-dir), never the live file.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ATLAS_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ATLAS_ROOT))

from atlas_service.device.db import DeviceStore  # noqa: E402
from atlas_service.device.registry import (  # noqa: E402
    DeviceAlreadyRegisteredError,
    register_demo_device,
    revoke,
    set_home_area,
    suspend,
)
from atlas_service.main import DEVICE_DB_PATH  # noqa: E402
from firmware import device_identity  # noqa: E402

BANNER = "  [DEMO PROVISIONING -- proves key possession only, not device ownership]"


def cmd_enroll(args: argparse.Namespace) -> int:
    keys_dir = Path(args.keys_dir) if args.keys_dir else device_identity.DEFAULT_DEVICE_KEYS_DIR
    key_id = device_identity.init_device(keys_dir)
    public_key = device_identity.get_public_key(keys_dir)

    store = DeviceStore(args.db)
    try:
        register_demo_device(
            store,
            device_id=args.device_id,
            device_key_id=key_id,
            public_key=public_key,
            bound_subject=args.subject,
            firmware_version=args.firmware_version,
            registered_lat=args.lat,
            registered_lon=args.lon,
            geofence_radius_m=args.geofence_m,
            secure_element_present=False,  # never claimed -- no secure element exists
        )
    except DeviceAlreadyRegisteredError as exc:
        print(f"REFUSED: {exc}")
        print("  Re-enrolling would silently replace an enrolled key, which is an")
        print("  account-takeover primitive. Revoke the old device first.")
        return 1

    print(BANNER)
    print(f"  device_id      : {args.device_id}")
    print(f"  device_key_id  : {key_id}")
    print(f"  bound subject  : {args.subject}")
    print(f"  public key     : {public_key[:32]}...")
    print(f"  private key    : {keys_dir / 'device_ed25519.key'}")
    print("                   ^ ORDINARY FILE. Readable by anyone with access.")
    print("                     A signature proves possession of THIS KEY, not")
    print("                     the identity of a physical device.")
    return 0


def cmd_firmware_config(args: argparse.Namespace) -> int:
    """RETIRED 2026-10-09: it printed the private key seed to paste into the sketch.

    The firmware no longer holds a key. It loads its identity from NVS at start-up,
    and scripts/provision_nvs.py puts the EXISTING enrolled key into a local,
    git-ignored NVS image after checking it against this registry -- the seed is never
    printed. This command now says so and prints nothing secret (approved key-lifecycle
    change; see HANDOFF.md limitation 3)."""
    print("firmware-config is retired: the firmware reads its identity from NVS now.")
    print("Put this device's existing key into the simulator image with:")
    print(f"  python scripts/provision_nvs.py --firmware <key-free build folder> "
          f"--keys-dir <this device's key folder> --device-id {args.device_id}")
    print("It never prints the key.")
    return 1


def cmd_list(args: argparse.Namespace) -> int:
    store = DeviceStore(args.db)
    rows = store.list_devices()
    if not rows:
        print("no devices enrolled")
        return 0
    print(f"{'device_id':28} {'status':10} {'subject':16} {'mode':10} key_id")
    for r in rows:
        print(f"{r['device_id']:28} {r['status']:10} {r['bound_subject']:16} "
              f"{r['provisioning_mode']:10} {r['device_key_id']}")
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    store = DeviceStore(args.db)
    row = store.get_by_device_id(args.device_id)
    if row is None:
        print(f"unknown device {args.device_id!r} (absence fails closed)")
        return 1
    for key in row.keys():
        print(f"  {key:24}: {row[key]}")
    print("  --- audit trail ---")
    for e in store.events_for(args.device_id):
        print(f"  {e['occurred_at']}  {e['event']:24} {e['detail']}")
    return 0


def cmd_set_home(args: argparse.Namespace) -> int:
    store = DeviceStore(args.db)
    try:
        set_home_area(store, args.device_id, args.lat, args.lon, args.radius_m)
    except (LookupError, ValueError) as exc:
        print(f"REFUSED: {exc}")
        return 1
    print(f"HOME AREA set for {args.device_id}: radius {args.radius_m / 1000:g} km (centre not echoed)")
    return 0


def cmd_revoke(args: argparse.Namespace) -> int:
    store = DeviceStore(args.db)
    if store.get_by_device_id(args.device_id) is None:
        print(f"unknown device {args.device_id!r}")
        return 1
    revoke(store, args.device_id, args.reason)
    print(f"REVOKED {args.device_id} ({args.reason}) -- terminal, cannot be reactivated")
    return 0


def cmd_suspend(args: argparse.Namespace) -> int:
    store = DeviceStore(args.db)
    if store.get_by_device_id(args.device_id) is None:
        print(f"unknown device {args.device_id!r}")
        return 1
    suspend(store, args.device_id, args.reason)
    print(f"SUSPENDED {args.device_id} ({args.reason}) -- reversible")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--db", default=str(DEVICE_DB_PATH))
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("enroll", help="DEMO enrollment (see module docstring)")
    p.add_argument("--device-id", required=True)
    p.add_argument("--subject", required=True)
    p.add_argument("--keys-dir")
    p.add_argument("--firmware-version", default="0.3.0")
    p.add_argument("--lat", type=float)
    p.add_argument("--lon", type=float)
    p.add_argument("--geofence-m", type=int)
    p.set_defaults(func=cmd_enroll)

    p = sub.add_parser("firmware-config",
                       help="RETIRED: points to scripts/provision_nvs.py; prints no key")
    p.add_argument("--device-id", required=True)
    p.add_argument("--keys-dir")
    p.set_defaults(func=cmd_firmware_config)

    p = sub.add_parser("list"); p.set_defaults(func=cmd_list)

    p = sub.add_parser("show")
    p.add_argument("--device-id", required=True)
    p.set_defaults(func=cmd_show)

    p = sub.add_parser("set-home", help="record the device's home area (geofence centre and radius)")
    p.add_argument("--device-id", required=True)
    p.add_argument("--lat", type=float, required=True)
    p.add_argument("--lon", type=float, required=True)
    p.add_argument("--radius-m", type=int, required=True)
    p.set_defaults(func=cmd_set_home)

    p = sub.add_parser("revoke")
    p.add_argument("--device-id", required=True)
    p.add_argument("--reason", default="manual")
    p.set_defaults(func=cmd_revoke)

    p = sub.add_parser("suspend")
    p.add_argument("--device-id", required=True)
    p.add_argument("--reason", default="manual")
    p.set_defaults(func=cmd_suspend)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
