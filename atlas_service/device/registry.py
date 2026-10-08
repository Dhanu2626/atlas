"""Device registry (Phase 3.1) -- who is this device, and is it still trusted.

Answers exactly one question: *"is this cryptographic key enrolled, and what
is its current standing?"*

It emphatically does NOT answer *"does this device genuinely belong to the
real account holder?"* That is enrollment/identity-proofing, which
ARCHITECTURE.md rates RQ-7/12/24 and the Day 13 red team rates RED
(unsolved-by-cryptography). Blueprint 24.6 says the same one layer down:
"Forged device identity -- exactly RQ-7/12/24's enrollment problem, one layer
down; genuinely unresolved, not solved here." Nothing in this module closes
that gap, and it must never be described as if it does.

PROVISIONING MODES are recorded per device and are deliberately visible:

  DEMO       provisioned by scripts/provision_device.py, on this machine, by
             whoever had filesystem access. Proves possession of a key. Proves
             NOTHING about who owns the account.
  PRODUCTION reserved. Would require identity proofing, an attested key from a
             secure element, and an auditable operator. NOT IMPLEMENTED --
             the constant exists so demo devices can never be silently
             mistaken for production-enrolled ones.
"""

from __future__ import annotations

from datetime import datetime, timezone

from atlas_service.device.db import DeviceStore
from contracts import DeviceStatus

PROVISIONING_DEMO = "DEMO"
PROVISIONING_PRODUCTION = "PRODUCTION"  # reserved; never issued by this code


class DeviceAlreadyRegisteredError(Exception):
    """Re-registering an existing device_id or key is refused rather than
    silently overwritten -- quietly replacing an enrolled key would be an
    account-takeover primitive, not a convenience."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def register_demo_device(
    store: DeviceStore,
    *,
    device_id: str,
    device_key_id: str,
    public_key: str,
    bound_subject: str,
    firmware_version: str | None = None,
    registered_lat: float | None = None,
    registered_lon: float | None = None,
    geofence_radius_m: int | None = None,
    secure_element_present: bool = False,
) -> None:
    """Enroll a device for the DEMO. See the module docstring for exactly how
    little this proves.

    `secure_element_present` is recorded but NOT verified -- nothing here can
    check whether a key really lives in an ATECC608 or in ordinary flash. It
    is a declaration for later hardware work, not evidence.
    """
    if store.get_by_device_id(device_id) is not None:
        raise DeviceAlreadyRegisteredError(f"device_id {device_id!r} is already registered")
    if store.get_by_key_id(device_key_id) is not None:
        raise DeviceAlreadyRegisteredError(f"device_key_id {device_key_id!r} is already registered")

    now = _now()
    store.insert_device(
        device_id=device_id,
        device_key_id=device_key_id,
        public_key=public_key,
        bound_subject=bound_subject,
        status=DeviceStatus.ACTIVE.value,
        firmware_version=firmware_version,
        registered_lat=registered_lat,
        registered_lon=registered_lon,
        geofence_radius_m=geofence_radius_m,
        secure_element_present=int(secure_element_present),
        provisioning_mode=PROVISIONING_DEMO,
        created_at=now,
    )
    store.record_event(device_id, "REGISTERED", f"mode={PROVISIONING_DEMO}", now)


def set_home_area(store: DeviceStore, device_id: str, lat: float, lon: float, radius_m: int) -> None:
    """Records the device's home area -- the centre and radius the geofence grade
    (atlas_service/device/location.py) measures against. A DEMO operator action,
    like enrolment: it proves nothing about where the account holder lives.

    The audit event says THAT the home area changed and its radius, never where
    it is: the centre is a home location and stays out of the event log."""
    if store.get_by_device_id(device_id) is None:
        raise LookupError(f"unknown device {device_id!r}")
    if not (-90 <= lat <= 90 and -180 <= lon <= 180):
        raise ValueError("home area centre is out of range")
    if not 100 <= int(radius_m) <= 1_000_000:
        raise ValueError("home area radius must be 100 m to 1,000 km")
    now = _now()
    store.set_home_area(device_id, float(lat), float(lon), int(radius_m))
    store.record_event(device_id, "HOME_AREA_SET", f"radius_m={int(radius_m)}", now)


def revoke(store: DeviceStore, device_id: str, reason: str = "manual") -> None:
    """Terminal. A revoked device is never silently re-trusted: there is no
    un-revoke, matching the frozen 'device revoked -> deny' failure mode.
    Recovering a device means enrolling a NEW key, which is what
    re-enrollment actually means."""
    now = _now()
    store.set_status(device_id, DeviceStatus.REVOKED.value, now, reason)
    store.record_event(device_id, "REVOKED", reason, now)


def suspend(store: DeviceStore, device_id: str, reason: str = "manual") -> None:
    """Reversible, unlike revocation -- for 'something looks wrong, stop
    trusting this for now' rather than 'this key is compromised'."""
    now = _now()
    store.set_status(device_id, DeviceStatus.SUSPENDED.value, now, reason)
    store.record_event(device_id, "SUSPENDED", reason, now)


def reactivate(store: DeviceStore, device_id: str) -> None:
    """Only from SUSPENDED. Refusing to reactivate a REVOKED device is the
    whole point of having two states rather than one."""
    row = store.get_by_device_id(device_id)
    if row is None:
        raise LookupError(f"unknown device {device_id!r}")
    if row["status"] == DeviceStatus.REVOKED.value:
        raise ValueError(
            f"{device_id!r} is REVOKED and cannot be reactivated; enroll a new key instead"
        )
    now = _now()
    store.set_status(device_id, DeviceStatus.ACTIVE.value, now)
    store.record_event(device_id, "REACTIVATED", "", now)
