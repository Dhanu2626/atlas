"""gnss.py -- the device's GNSS reader, as testable Python (the twin of gnss_nmea.h).

firmware/atlas_device/gnss_nmea.h is what the ESP32 runs: it reads NMEA sentences from a
GNSS receiver over UART and turns them into the location EVIDENCE the device signs. This
file is the same logic, line for line, so the automated suite can run it -- and so
tests/test_gnss.py can feed both implementations identical sentences and require
byte-identical evidence (the C side is compiled and compared on GitHub's Linux machines).

In the simulator the receiver is SIMULATED (firmware/atlas_device/chips/atlas-gnss.chip.c):
no satellite is ever received, the coordinates are scripted. What is real is everything
from the UART onwards -- parsing, checksum validation, fix handling, signing, grading.

The reader decides nothing. It reports what the receiver said; atlas_service grades it
(atlas_service/device/location.py) and the customer's policy decides. A sentence that
passes its checksum proves only that it was not garbled on the wire -- civilian GNSS is
unauthenticated, so no position here ever proves where the device really is.

Integer arithmetic only, as in the C: millionths of a degree, tenths of a metre.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone

MAX_SENTENCE = 80       # NMEA 0183: 82 characters including the CR LF
MAX_FIELDS = 24

OK, IGNORED, BAD_CHECKSUM, MALFORMED = 0, 1, 2, 3


def _digits(s: str) -> bool:
    return len(s) > 0 and all("0" <= c <= "9" for c in s)


def _uint(s: str) -> int | None:
    if not 0 < len(s) <= 9 or not _digits(s):
        return None
    return int(s)


def _coord(f: str, hemi: str, deg_digits: int, max_deg: int, pos: str, neg: str) -> int | None:
    """ddmm.mmmmm / dddmm.mmmmm to signed millionths of a degree (see gnss_coord)."""
    if len(f) < deg_digits + 2 or not _digits(f[:deg_digits + 2]):
        return None
    deg = int(f[:deg_digits])
    mm = int(f[deg_digits:deg_digits + 2])
    if mm >= 60:
        return None
    rest = f[deg_digits + 2:]
    frac_digits = ""
    if rest.startswith("."):
        tail = rest[1:]
        if not _digits(tail):
            return None
        frac_digits = tail[:5]
    elif rest:
        return None
    frac = int(frac_digits.ljust(5, "0"))
    e6 = deg * 1_000_000 + (mm * 100_000 + frac + 3) // 6
    if e6 > max_deg * 1_000_000:
        return None
    if len(hemi) != 1 or hemi not in (pos, neg):
        return None
    return -e6 if (hemi == neg and e6 != 0) else e6


def _err_dm(f: str) -> int | None:
    """Metres ("2.34") to tenths of a metre, half up on the second decimal."""
    whole, dot, tail = f.partition(".")
    if not 0 < len(whole) <= 7 or not _digits(whole):
        return None
    d1 = d2 = 0
    if dot:
        if not _digits(tail):
            return None
        d1 = int(tail[0])
        d2 = int(tail[1]) if len(tail) > 1 else 0
    return int(whole) * 10 + d1 + (1 if d2 >= 5 else 0)


def _utc(f: str) -> bool:
    if f == "":
        return True
    if not 6 <= len(f) <= 11 or not _digits(f[:6]):
        return False
    return len(f) == 6 or (f[6] == "." and _digits(f[7:]))


def _degrees(e6: int) -> str:
    a = abs(e6)
    return f"{'-' if e6 < 0 else ''}{a // 1_000_000}.{a % 1_000_000:06d}"


def checksum(body: str) -> str:
    """The two hex digits after '*': XOR of every character between '$' and '*'."""
    value = 0
    for c in body:
        value ^= ord(c)
    return f"{value:02X}"


def sentence(body: str) -> str:
    """A well-formed sentence from its body, e.g. sentence("GNRMC,...")."""
    return f"${body}*{checksum(body)}"


@dataclass
class GnssReader:
    any_valid: bool = False
    have_fix: bool = False
    fix_now: bool = False
    fix_lat_e6: int = 0
    fix_lon_e6: int = 0
    fix_acc_dm: int = -1
    fix_sats: int = 0
    fix_utc: str = ""
    fix_epoch: int = 0
    sats_now: int = 0
    gst_acc_dm: int = -1
    gst_utc: str = ""
    accepted: int = 0
    rejected_checksum: int = 0
    rejected_malformed: int = 0

    def _reject(self) -> int:
        self.rejected_malformed += 1
        return MALFORMED

    def feed_line(self, line: str, device_epoch: int) -> int:
        """One sentence, with or without CR/LF. `device_epoch` (seconds, UTC) stamps a new fix."""
        line = line.rstrip("\r\n")
        if line == "":
            return IGNORED
        if len(line) > MAX_SENTENCE or not line.startswith("$"):
            return self._reject()
        star = line.find("*")
        if star == -1 or star != len(line) - 3:
            return self._reject()
        given = line[star + 1:]
        if not all(c in "0123456789ABCDEFabcdef" for c in given):
            return self._reject()
        body = line[1:star]
        if checksum(body) != given.upper():
            self.rejected_checksum += 1
            return BAD_CHECKSUM

        field = body.split(",")
        if len(field) > MAX_FIELDS:
            return self._reject()
        kind_full = field[0]
        if kind_full.startswith("P"):
            self.accepted += 1
            self.any_valid = True
            return IGNORED
        if len(kind_full) != 5 or not all("A" <= c <= "Z" for c in kind_full):
            return self._reject()
        kind = kind_full[2:]

        if kind == "GGA":
            if len(field) < 9 or not _utc(field[1]):
                return self._reject()
            quality = _uint(field[6]) if len(field[6]) == 1 else None
            if quality is None:
                return self._reject()
            sats = 0
            if field[7] != "":
                sats = _uint(field[7])
                if sats is None:
                    return self._reject()
            if sats > 99:
                return self._reject()
            if not 1 <= quality <= 5:
                self.accepted += 1
                self.any_valid, self.fix_now, self.sats_now = True, False, sats
                return OK
            lat = _coord(field[2], field[3], 2, 90, "N", "S")
            lon = _coord(field[4], field[5], 3, 180, "E", "W") if lat is not None else None
            if lat is None or lon is None:
                return self._reject()
            self.accepted += 1
            self.any_valid, self.fix_now, self.sats_now = True, True, sats
            self.have_fix = True
            self.fix_lat_e6, self.fix_lon_e6, self.fix_sats = lat, lon, sats
            self.fix_epoch = int(device_epoch)
            self.fix_utc = field[1][:11]
            self.fix_acc_dm = self.gst_acc_dm if (field[1] != "" and self.gst_utc == field[1]) else -1
            return OK

        if kind == "RMC":
            if len(field) < 3 or not _utc(field[1]):
                return self._reject()
            if field[2] not in ("A", "V"):
                return self._reject()
            self.accepted += 1
            self.any_valid, self.fix_now = True, field[2] == "A"
            return OK

        if kind == "GST":
            if len(field) < 8 or not _utc(field[1]):
                return self._reject()
            lat_dm, lon_dm = _err_dm(field[6]), _err_dm(field[7])
            if lat_dm is None or lon_dm is None:
                return self._reject()
            self.accepted += 1
            self.any_valid = True
            self.gst_acc_dm = max(lat_dm, lon_dm)
            self.gst_utc = field[1][:11]
            if self.have_fix and field[1] != "" and self.fix_utc == field[1]:
                self.fix_acc_dm = self.gst_acc_dm
            return OK

        self.accepted += 1
        self.any_valid = True
        return IGNORED

    def evidence(self) -> dict | None:
        """The LocationEvidence the device signs, as the plain dict the envelope carries."""
        if not self.any_valid:
            return None
        if not self.have_fix:
            return {"accuracy_m": None, "captured_at": None, "latitude": None, "longitude": None,
                    "satellites": self.sats_now, "source": "GNSS"}
        when = datetime.fromtimestamp(self.fix_epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")
        acc = None if self.fix_acc_dm < 0 else f"{self.fix_acc_dm // 10}.{self.fix_acc_dm % 10}"
        return {"accuracy_m": acc, "captured_at": when, "latitude": _degrees(self.fix_lat_e6),
                "longitude": _degrees(self.fix_lon_e6), "satellites": self.fix_sats, "source": "GNSS"}

    def evidence_json(self) -> str:
        """Exactly what gnss_evidence_json() writes in C."""
        return json.dumps(self.evidence(), sort_keys=True, separators=(",", ":"))
