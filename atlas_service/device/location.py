"""Location grading (Phase 3.4): how much to believe a location claim -- never whether to pay.

Every device envelope may carry LocationEvidence (contracts.py): where the device says it
is, with the provenance needed to judge that claim -- source, accuracy, capture time,
satellites. Two paths produce it, and they are kept apart on purpose:

  BROWSER   the "Run it live" page, after the visitor allows it: the visitor's REAL current
            position, from their own browser. The browser does not say whether satellites,
            Wi-Fi or the mobile network placed it.
  GNSS      the ESP32 reading a GNSS receiver over UART (firmware/atlas_device/gnss_nmea.h).
            In the Wokwi simulator that receiver is SIMULATED and its coordinates scripted.

This module grades either one, after the envelope's signature has verified (so the claim is
the device's own, unaltered in transit) and before the policy engine runs. It produces
evidence, not a decision. The policy engine holds decision authority, and a policy rule
can act on the geofence result (condition key GEOFENCE) only if the owner put one there.

THE GRADES ARE THE FROZEN ONES (docs/PHASE3-SPEC.md, "Location grading")
------------------------------------------------------------------------
  HIGH     secure-element-signed GNSS, <=50 m, <60 s -- NOT REACHABLE: no secure element
           exists here, so no code path in this module can return it
  MEDIUM   GNSS fix, <=500 m, under five minutes old, from a device with integrity OK
  LOW      Wi-Fi / cell / IP / browser-reported, or GNSS without integrity evidence
  UNKNOWN  no evidence, or nothing usable in it

Integrity grading (Phase 3.5) is not built, so no device has integrity evidence yet and a
GNSS fix grades LOW under the frozen table. That is the table working, not a defect: the
grade says how much ATLAS can believe, and today it cannot believe more.

Geofence: WITHIN_GEOFENCE / OUTSIDE_GEOFENCE / LOCATION_UNKNOWN / LOCATION_STALE, measured
against the home area registered for the device (registry columns registered_lat /
registered_lon / geofence_radius_m).

WHAT NONE OF THIS CAN DO
------------------------
Prove where anyone is. Civilian GNSS is unauthenticated and spoofable with commodity
radios, and a browser reports whatever the operating system tells it. A spoofed but
plausible position is indistinguishable from a real one here. That is why location may
only ever ADD friction: being "at home" relaxes no rule, so faking home gains an attacker
nothing, while being somewhere unusual can ask the customer to confirm.

PRIVACY
-------
Raw coordinates never leave this module's caller: they are not logged, not put in the
response, and never reach the bank (the signed assertion's field list is frozen and has no
location). For impossible-travel checks the device's previous fix is kept, rounded to two
decimals (about 1 km), in the device registry -- one row per device, overwritten each time.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation

from contracts import (
    GEOFENCE_LOCATION_STALE, GEOFENCE_LOCATION_UNKNOWN, GEOFENCE_OUTSIDE, GEOFENCE_WITHIN,
    LocationEvidence, LocationGrade,
)

LOW, MEDIUM, UNKNOWN = "LOW", "MEDIUM", "UNKNOWN"

#: Frozen MEDIUM limits.
MEDIUM_MAX_ACCURACY_M = Decimal(500)
MAX_FIX_AGE = timedelta(minutes=5)
#: A capture time this far in the future is not a clock wobble (the envelope allows the
#: same five minutes of skew).
MAX_FUTURE_SKEW = timedelta(minutes=5)

#: Impossible travel: faster than any airliner, over a distance no fix error or network
#: fallback explains. Evidence only -- no shipped policy acts on it.
IMPOSSIBLE_SPEED_KMH = 1000
IMPOSSIBLE_MIN_DISTANCE_KM = 100

EARTH_RADIUS_KM = 6371.0088

SOURCE_GNSS = "GNSS"
#: Sources that are LOW by definition: none of them says how the position was obtained
#: precisely enough to be trusted further.
LOW_SOURCES = {"WIFI": "Wi-Fi-derived", "CELL": "mobile-network-derived", "IP": "IP-derived",
               "BROWSER": "browser-reported (satellites, Wi-Fi or network -- the browser does not say which)",
               "DECLARED": "typed in by the user"}


@dataclass(frozen=True)
class HomeArea:
    latitude: float
    longitude: float
    radius_m: int


@dataclass(frozen=True)
class PreviousFix:
    latitude: float
    longitude: float
    captured_at: datetime


def distance_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle (haversine) distance."""
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = p2 - p1, math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * EARTH_RADIUS_KM * math.asin(min(1.0, math.sqrt(a)))


def _number(value: Decimal | None) -> float | None:
    if value is None:
        return None
    try:
        if not value.is_finite():
            return None
        return float(value)
    except (InvalidOperation, ValueError):
        return None


def _when(text: str | None) -> datetime | None:
    if not text:
        return None
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _unknown(source: str, why: str, geofence: str = GEOFENCE_LOCATION_UNKNOWN) -> LocationGrade:
    return LocationGrade(source=source, confidence=UNKNOWN, geofence=geofence, reasons=[why])


def grade(
    evidence: LocationEvidence | None,
    *,
    home: HomeArea | None,
    previous: PreviousFix | None = None,
    integrity_ok: bool = False,
    now: datetime | None = None,
) -> LocationGrade:
    """Grades one location claim. Pure: same inputs, same grade."""
    now = now or datetime.now(timezone.utc)
    if evidence is None or evidence.source == "NONE":
        return _unknown("NONE", "the device sent no location evidence")
    source = evidence.source
    if source != SOURCE_GNSS and source not in LOW_SOURCES:
        return _unknown(source, f"unrecognised location source {source!r}")

    lat, lon = _number(evidence.latitude), _number(evidence.longitude)
    if lat is None or lon is None:
        if source == SOURCE_GNSS:
            sats = evidence.satellites
            return _unknown(source, "the GNSS receiver reports no position fix"
                            + (f" ({sats} satellites in use)" if sats is not None else ""))
        return _unknown(source, "no usable coordinates")
    if not (-90 <= lat <= 90 and -180 <= lon <= 180):
        return _unknown(source, "coordinates are out of range")

    captured = _when(evidence.captured_at)
    if captured is None:
        return _unknown(source, "no usable capture time, so its age cannot be judged")
    age = now - captured
    if age < -MAX_FUTURE_SKEW:
        return _unknown(source, "the capture time is in the future")
    age_s = max(0, int(age.total_seconds()))
    stale = age > MAX_FIX_AGE

    accuracy = _number(evidence.accuracy_m)
    if accuracy is not None and accuracy < 0:
        accuracy = None

    # --- confidence (the frozen table; HIGH is unreachable by construction) ----------
    reasons: list[str] = []
    if source == SOURCE_GNSS:
        held_back = []
        if accuracy is None:
            held_back.append("the receiver gave no accuracy estimate")
        elif accuracy > float(MEDIUM_MAX_ACCURACY_M):
            held_back.append(f"accuracy {accuracy:,.0f} m is worse than the 500 m MEDIUM limit")
        if stale:
            held_back.append("the fix is more than five minutes old")
        if not integrity_ok:
            held_back.append("no device integrity evidence (Phase 3.5 is not built), so GNSS "
                             "cannot grade above LOW")
        confidence = LOW if held_back else MEDIUM
        sats = evidence.satellites
        reasons.append("GNSS fix" + (f" from {sats} satellites" if sats is not None else "")
                       + (f", accuracy {accuracy:,.1f} m" if accuracy is not None else ""))
        reasons.extend(held_back)
    else:
        confidence = LOW
        reasons.append(LOW_SOURCES[source]
                       + (f", accuracy {accuracy:,.0f} m" if accuracy is not None else ""))

    # --- geofence ---------------------------------------------------------------------
    distance = None
    if stale:
        geofence = GEOFENCE_LOCATION_STALE
        reasons.append(f"captured {age_s // 60} min ago: too old to place the device now")
    elif home is None:
        geofence = GEOFENCE_LOCATION_UNKNOWN
        reasons.append("no home area is registered for this device")
    else:
        distance = distance_km(home.latitude, home.longitude, lat, lon)
        if accuracy is None or accuracy > home.radius_m:
            geofence = GEOFENCE_LOCATION_UNKNOWN
            reasons.append(f"too imprecise to place against a {home.radius_m / 1000:g} km home area")
        elif distance * 1000 <= home.radius_m:
            geofence = GEOFENCE_WITHIN
            reasons.append(f"inside the home area ({distance:,.1f} km from its centre)")
        else:
            geofence = GEOFENCE_OUTSIDE
            reasons.append(f"outside the home area ({distance:,.0f} km from its centre, "
                           f"radius {home.radius_m / 1000:g} km)")

    # --- impossible travel (evidence only) ----------------------------------------------
    implausible, speed = False, None
    if previous is not None and not stale:
        moved = distance_km(previous.latitude, previous.longitude, lat, lon)
        hours = (captured - previous.captured_at).total_seconds() / 3600
        if moved >= IMPOSSIBLE_MIN_DISTANCE_KM:
            speed_value = math.inf if hours <= 0 else moved / hours
            if speed_value > IMPOSSIBLE_SPEED_KMH:
                implausible = True
                speed = None if math.isinf(speed_value) else int(speed_value)
                reasons.append(f"impossible travel: {moved:,.0f} km since the last fix"
                               + (f", about {speed:,} km/h" if speed is not None else ", in no time at all"))

    return LocationGrade(
        source=source, confidence=confidence, geofence=geofence,
        distance_from_home_km=None if distance is None else round(distance, 1),
        fix_age_s=age_s, implausible_travel=implausible, implied_speed_kmh=speed,
        reasons=reasons,
    )


def home_of(device: dict) -> HomeArea | None:
    """The registered home area of a device row, if it has a complete one."""
    lat, lon, radius = device.get("registered_lat"), device.get("registered_lon"), device.get("geofence_radius_m")
    if lat is None or lon is None or not radius or radius <= 0:
        return None
    return HomeArea(float(lat), float(lon), int(radius))


def grade_for_device(evidence: LocationEvidence | None, device: dict, store, *,
                     now: datetime | None = None) -> LocationGrade:
    """Grades an AUTHENTICATED envelope's location against its device's home area and
    previous fix, then remembers this fix (rounded) for the next impossible-travel check.

    Call only after verify_envelope() succeeded: `device` is the registry's own row, and the
    evidence is the device's own signed claim.
    """
    now = now or datetime.now(timezone.utc)
    row = store.get_last_fix(device["device_id"])
    previous = None
    if row is not None:
        when = _when(row["captured_at"])
        if when is not None:
            previous = PreviousFix(float(row["latitude"]), float(row["longitude"]), when)
    # integrity_ok stays False until Phase 3.5 grades device health (see module docstring).
    result = grade(evidence, home=home_of(device), previous=previous, integrity_ok=False, now=now)
    if result.confidence != UNKNOWN and result.geofence != GEOFENCE_LOCATION_STALE:
        store.set_last_fix(device["device_id"], round(float(evidence.latitude), 2),
                           round(float(evidence.longitude), 2), evidence.captured_at, now.isoformat())
    return result
