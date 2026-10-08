"""The device's GNSS reader: NMEA in, signed location evidence out (2026-10-09).

Path B of ATLAS's two location paths: a GNSS receiver wired to the ESP32 over UART. In
Wokwi the receiver is SIMULATED (firmware/atlas_device/chips/atlas-gnss.chip.c) -- no
satellite is received and every coordinate is scripted. What these tests check is the
real part: the reader in firmware/atlas_device/gnss_nmea.h and its Python twin
firmware/gnss.py.

  * the twin, sentence by sentence: checksums, malformed lines, fixes, no-fix, accuracy
  * the simulated chip's seven scenarios, through the twin, into evidence ATLAS accepts
  * C == Python, byte for byte, on the same script -- compiled with the host C compiler.
    This Windows PC has none, so it runs on GitHub's Linux machines (ATLAS_C_PARITY=1
    there turns a missing compiler into a failure, never a skip).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest

from contracts import DeviceEnvelope, LocationEvidence, canonical_envelope_bytes
from firmware import gnss
from firmware.gnss import BAD_CHECKSUM, IGNORED, MALFORMED, OK, GnssReader, sentence

ROOT = Path(__file__).resolve().parent.parent
FW = ROOT / "firmware" / "atlas_device"
CHIP_C = FW / "chips" / "atlas-gnss.chip.c"
CHIP_JSON = FW / "chips" / "atlas-gnss.chip.json"
T0 = int(datetime(2026, 10, 9, 6, 30, tzinfo=timezone.utc).timestamp())


# --------------------------------------------------------------------------
# A Python model of the simulated chip's output, checked against its C source
# --------------------------------------------------------------------------

HOME, OUTSIDE_HOME, IMPOSSIBLE, NO_FIX, SILENT, POOR_ACCURACY, BAD_NMEA = range(7)
COORDS = {HOME: (17385044, 78486671), OUTSIDE_HOME: (17624800, 78086700), IMPOSSIBLE: (28613939, 77209023)}


def _nmea(e6: int, deg_digits: int) -> str:
    a = abs(e6)
    min_e5 = (a % 1_000_000) * 6
    return f"{a // 1_000_000:0{deg_digits}d}{min_e5 // 100_000:02d}.{min_e5 % 100_000:05d}"


def chip_burst(scenario: int, t: int) -> list[str]:
    """What atlas-gnss.chip.c writes in second `t` of a scenario (same text, same order)."""
    if scenario == SILENT:
        return []
    utc = f"{(t // 3600) % 24:02d}{(t // 60) % 60:02d}{t % 60:02d}.00"
    if scenario == NO_FIX:
        return [sentence(f"GNRMC,{utc},V,,,,,,,010126,,,N"), sentence(f"GNGGA,{utc},,,,,0,02,99.99,,,,,,")]
    la, lo = COORDS.get(scenario, COORDS[HOME])
    wander = t % 20 - 10
    lat, lon = _nmea(la + wander * 2, 2), _nmea(lo - wander * 2, 3)
    poor, bad = scenario == POOR_ACCURACY, scenario == BAD_NMEA
    rmc = f"GNRMC,{utc},A,{lat},N,{lon},E,0.02,,010126,,,A"
    gga = f"GNGGA,{utc},{lat},N,{lon},E,1,{'04' if poor else '12'},{'12.4' if poor else '0.8'},542.0,M,-73.6,M,,"
    gst = (f"GNGST,{utc},{'1650.0' if poor else '2.1'},{'1800.0' if poor else '1.6'},{'1500.0' if poor else '1.2'},"
           f"45.0,{'1800.0' if poor else '1.8'},{'1500.0' if poor else '2.3'},{'2500.0' if poor else '3.9'}")
    if not bad:
        return [sentence(rmc), sentence(gga), sentence(gst)]
    wrong = lambda body: f"${body}*{int(gnss.checksum(body), 16) ^ 0x5A:02X}"  # noqa: E731
    good_gga = sentence(gga)
    i = good_gga.index("1", 18)
    return [wrong(rmc), good_gga[:i] + "9" + good_gga[i + 1:], wrong(gst)]


def run(scenario_seconds: list[tuple[int, int]], start: int = T0) -> GnssReader:
    """Feeds (scenario, seconds) segments into a fresh reader, one burst per second."""
    reader, now, t = GnssReader(), start, 0
    for scenario, seconds in scenario_seconds:
        for _ in range(seconds):
            t += 1
            now += 1
            for line in chip_burst(scenario, t):
                reader.feed_line(line + "\r\n", now)
    return reader


def test_the_python_chip_model_matches_the_chip_source():
    src = CHIP_C.read_text(encoding="utf-8")
    for name, (la, lo) in (("HOME", COORDS[HOME]), ("AWAY", COORDS[OUTSIDE_HOME]), ("FAR", COORDS[IMPOSSIBLE])):
        assert re.search(rf"{name}_LAT\s*=\s*{la}L?,\s*{name}_LON\s*=\s*{lo}", src), name
    for fragment in ("GNRMC,%s,V,,,,,,,010126,,,N", "GNGGA,%s,,,,,0,02,99.99,,,,,,",
                     "GNRMC,%s,A,%s,N,%s,E,0.02,,010126,,,A", "GNGGA,%s,%s,N,%s,E,1,%s,%s,542.0,M,-73.6,M,,",
                     '"1800.0" : "1.8"', '"1500.0" : "2.3"', "0x5A", "(long)(t % 20) - 10", "baud_rate = 9600"):
        assert fragment in src, fragment


def test_the_chip_says_it_is_simulated_and_offers_seven_scenarios():
    src = CHIP_C.read_text(encoding="utf-8")
    assert "NOTHING HERE RECEIVES A SATELLITE" in src and "SIMULATED" in src
    chip = json.loads(CHIP_JSON.read_text(encoding="utf-8"))
    assert "SIMULATED" in chip["name"]
    (control,) = chip["controls"]
    assert (control["id"], control["min"], control["max"], control["step"]) == ("scenario", 0, 6, 1)
    assert 'attr_init("scenario", HOME)' in src and "SCENARIOS };" in src
    assert chip["pins"] == ["VCC", "GND", "TX", "RX"]


def test_the_vendored_wokwi_header_is_unchanged():
    text = (FW / "chips" / "wokwi-api.h").read_bytes().replace(b"\r\n", b"\n")
    body = b"\n".join(text.split(b"\n")[7:])
    # a4031b0f9c6b8b9b... as published with CRLF line endings; this is the same text with LF.
    assert hashlib.sha256(body).hexdigest() == "24aad9fc00c08f9bf0b3b934ea4bf61dd383981a0a15232f43e02069d7a9b735"


# --------------------------------------------------------------------------
# The reader, one sentence at a time
# --------------------------------------------------------------------------

def test_a_full_fix_becomes_evidence_with_the_device_time():
    r = GnssReader()
    assert r.feed_line(sentence("GNGGA,063001.00,1723.10264,N,07829.20026,E,1,12,0.8,542.0,M,-73.6,M,,"), T0) == OK
    assert r.feed_line(sentence("GNGST,063001.00,2.1,1.6,1.2,45.0,1.8,2.3,3.9"), T0) == OK
    assert r.evidence() == {"accuracy_m": "2.3", "captured_at": "2026-10-09T06:30:00+00:00",
                            "latitude": "17.385044", "longitude": "78.486671", "satellites": 12, "source": "GNSS"}


def test_accuracy_pairs_with_the_gga_of_the_same_second_in_either_order():
    gst_first, gga_first = GnssReader(), GnssReader()
    gst = sentence("GNGST,063001.00,2.1,1.6,1.2,45.0,1.8,2.3,3.9")
    gga = sentence("GNGGA,063001.00,1723.10264,N,07829.20026,E,1,12,0.8,542.0,M,-73.6,M,,")
    for line in (gst, gga):
        gst_first.feed_line(line, T0)
    for line in (gga, gst):
        gga_first.feed_line(line, T0)
    assert gst_first.evidence()["accuracy_m"] == gga_first.evidence()["accuracy_m"] == "2.3"
    other_second = GnssReader()
    other_second.feed_line(sentence("GNGST,063000.00,2.1,1.6,1.2,45.0,1.8,2.3,3.9"), T0)
    other_second.feed_line(gga, T0)
    assert other_second.evidence()["accuracy_m"] is None       # never borrowed from another fix


def test_a_wrong_checksum_is_refused_and_changes_nothing():
    r = GnssReader()
    good = sentence("GNGGA,063001.00,1723.10264,N,07829.20026,E,1,12,0.8,542.0,M,-73.6,M,,")
    r.feed_line(good, T0)
    before = r.evidence()
    tampered = good.replace("1723.10264", "1723.90264")       # coordinate changed, checksum kept
    assert r.feed_line(tampered, T0 + 5) == BAD_CHECKSUM
    assert r.evidence() == before and r.rejected_checksum == 1


@pytest.mark.parametrize("line", [
    "GNGGA,063001.00,1723.10264,N,07829.20026,E,1,12,0.8,542.0,M,-73.6,M,,*00x",  # no '$'
    "$GNGGA,063001.00*4",                                                     # one hex digit
    "$GNGGA,063001.00*ZZ",                                                    # not hex
    "$" + "A" * 90 + "*00",                                                   # longer than NMEA allows
])
def test_malformed_lines_are_refused(line):
    r = GnssReader()
    assert r.feed_line(line, T0) == MALFORMED
    assert r.evidence() is None


@pytest.mark.parametrize("body", [
    "GNGGA,063001.00,1773.10264,N,07829.20026,E,1,12,0.8,542.0,M,-73.6,M,,",   # 73 minutes
    "GNGGA,063001.00,9123.10264,N,07829.20026,E,1,12,0.8,542.0,M,-73.6,M,,",   # latitude 91
    "GNGGA,063001.00,1723.10264,X,07829.20026,E,1,12,0.8,542.0,M,-73.6,M,,",   # hemisphere X
    "GNGGA,063001.00,,N,07829.20026,E,1,12,0.8,542.0,M,-73.6,M,,",             # a fix with no latitude
    "GNGGA,063001.00,1723.10264,N,07829.20026,E,12,12,0.8,542.0,M",            # quality 12
    "GNGST,063001.00,2.1,1.6,1.2,45.0,1.8",                                    # too few fields
    "GNRMC,063001.00,X,1723.10264,N",                                          # status X
    "gnGGA,063001.00,,,,,0,00,99.99,,,,,,",                                    # lower-case talker
])
def test_well_checksummed_nonsense_is_refused(body):
    r = GnssReader()
    assert r.feed_line(sentence(body), T0) == MALFORMED
    assert r.evidence() is None


def test_no_fix_from_the_start_reports_no_coordinates():
    r = run([(NO_FIX, 5)])
    assert r.evidence() == {"accuracy_m": None, "captured_at": None, "latitude": None, "longitude": None,
                            "satellites": 2, "source": "GNSS"}


def test_dead_reckoning_and_simulator_fixes_are_not_satellite_fixes():
    for quality in "678":
        r = GnssReader()
        r.feed_line(sentence(f"GNGGA,063001.00,1723.10264,N,07829.20026,E,{quality},05,1.0,0,M,0,M,,"), T0)
        assert r.evidence()["latitude"] is None, quality


def test_sentences_atlas_does_not_use_are_accepted_but_ignored():
    r = GnssReader()
    assert r.feed_line(sentence("GPGSV,3,1,12,01,40,083,46"), T0) == IGNORED
    assert r.feed_line(sentence("PUBX,00,063001.00"), T0) == IGNORED
    assert r.evidence()["latitude"] is None and r.accepted == 2


def test_a_lower_case_checksum_is_accepted():
    body = "GNRMC,063001.00,V,,,,,,,010126,,,N"
    assert GnssReader().feed_line(f"${body}*{gnss.checksum(body).lower()}", T0) == OK


def test_southern_and_western_coordinates_are_negative():
    r = GnssReader()
    r.feed_line(sentence("GNGGA,000001.00,3352.12345,S,15112.54321,W,1,08,0.9,10,M,0,M,,"), T0)
    ev = r.evidence()
    assert ev["latitude"].startswith("-33.8") and ev["longitude"].startswith("-151.2")


# --------------------------------------------------------------------------
# The seven scenarios, through the reader
# --------------------------------------------------------------------------

def test_home_outside_and_far_produce_the_scripted_positions():
    for scenario, (la, lo) in COORDS.items():
        ev = run([(scenario, 3)]).evidence()
        assert abs(float(ev["latitude"]) - la / 1e6) < 0.0001 and abs(float(ev["longitude"]) - lo / 1e6) < 0.0001
        assert ev["satellites"] == 12 and ev["accuracy_m"] == "2.3"


def test_poor_accuracy_reports_the_receivers_own_large_error():
    ev = run([(POOR_ACCURACY, 3)]).evidence()
    assert ev["accuracy_m"] == "1800.0" and ev["satellites"] == 4


def test_bad_nmea_is_refused_entirely_and_leaves_the_last_good_fix():
    r = run([(HOME, 3), (BAD_NMEA, 10)])
    assert r.rejected_checksum == 30            # every damaged sentence, none believed
    assert r.evidence()["captured_at"] == datetime.fromtimestamp(T0 + 3, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")


def test_silence_and_no_fix_keep_the_last_fix_with_its_true_age():
    """The device does not pretend a fix is current: it keeps the one it had, stamped
    with when it arrived, and ATLAS judges the age (stale after five minutes)."""
    for later in (SILENT, NO_FIX):
        r = run([(HOME, 2), (later, 400)])
        assert r.evidence()["captured_at"] == datetime.fromtimestamp(T0 + 2, timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%S+00:00")


def test_the_evidence_is_exactly_what_the_backend_signs():
    """The reader's JSON is byte-identical to the backend's canonical form of the same
    evidence, inside a full envelope -- so a device signing it verifies."""
    ev = run([(HOME, 3)]).evidence()
    as_backend = json.dumps(LocationEvidence(**ev).model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    assert run([(HOME, 3)]).evidence_json() == as_backend
    env = DeviceEnvelope(device_id="d", device_key_id="k", boot_id="b", counter=1, nonce="n",
                         issued_at="2026-10-09T06:30:00+00:00", location=ev, health=None, signature="",
                         transaction=dict(transaction_id="t", subject="s", amount="1.00", currency="INR",
                                          beneficiary="b", location="x", device_id="d",
                                          authentication_method="device_button", timestamp="2026-10-09T06:30:00+00:00"))
    assert f'"location":{as_backend}' in canonical_envelope_bytes(env).decode()


# --------------------------------------------------------------------------
# C == Python
# --------------------------------------------------------------------------

def _script() -> list[str]:
    """Every scenario, transitions between them, and the malformed cases above."""
    lines, now, t = [], T0, 0
    for scenario, seconds in ((NO_FIX, 3), (HOME, 4), (POOR_ACCURACY, 3), (OUTSIDE_HOME, 3), (IMPOSSIBLE, 2),
                              (BAD_NMEA, 3), (SILENT, 5), (NO_FIX, 3), (HOME, 2)):
        for _ in range(seconds):
            t += 1
            now += 1
            lines += [f"F {now} {s}" for s in chip_burst(scenario, t)]
            lines.append("Q")
    extras = ["GNGGA,063001.00,1773.10264,N,07829.20026,E,1,12,0.8,542.0,M,-73.6,M,,",
              "GNGGA,063001.00,9000.00000,N,18000.00000,W,1,12,0.8,0,M,0,M,,",
              "GNGGA,063001.00,0000.00000,S,00000.00000,W,1,03,0.8,0,M,0,M,,",
              "GNGST,063001.00,2.1,1.6,1.2,45.0,0.05,0.149,3.9", "GNGST,063001.00,1,1,1,1,12.,3,3",
              "GPGSV,3,1,12", "PUBX,00", "GNRMC,063001.00,A", "GNGGA,1,,,,,0,,,", "GNGGA,063001.123,,,,,0,7,,"]
    for body in extras:
        lines += [f"F {now} {sentence(body)}", "Q"]
    lines += [f"F {now} $GNGGA*ZZ", f"F {now} nonsense", f"F {now} $" + "B" * 90 + "*00", "Q"]
    return lines


def _python_transcript(script: list[str]) -> str:
    r, out = GnssReader(), []
    for line in script:
        if line.startswith("F "):
            _, epoch, rest = line.split(" ", 2)
            out.append(str(r.feed_line(rest, int(epoch))))
        else:
            out.append(f"{r.evidence_json()} {r.accepted} {r.rejected_checksum} {r.rejected_malformed}")
    return "\n".join(out) + "\n"


def test_the_c_reader_and_the_python_twin_agree_byte_for_byte(tmp_path):
    cc = shutil.which("gcc") or shutil.which("cc") or shutil.which("clang")
    if cc is None:
        if os.environ.get("ATLAS_C_PARITY") == "1":
            pytest.fail("ATLAS_C_PARITY=1 but no C compiler was found")
        pytest.skip("no host C compiler here (GitHub's Linux machines run this with ATLAS_C_PARITY=1)")
    exe = tmp_path / "gnss_parity"
    build = subprocess.run([cc, "-std=c99", "-D_POSIX_C_SOURCE=200809L", "-Wall", "-Wextra", "-Werror",
                            "-o", str(exe), str(ROOT / "tests" / "c" / "gnss_parity.c")],
                           capture_output=True, text=True)
    assert build.returncode == 0, build.stderr
    script = _script()
    ran = subprocess.run([str(exe)], input="\n".join(script) + "\n", capture_output=True, text=True, timeout=60)
    assert ran.returncode == 0, ran.stderr
    expected = _python_transcript(script)
    assert ran.stdout == expected
    report = os.environ.get("ATLAS_C_PARITY_REPORT")
    if report:
        Path(report).write_text(json.dumps({"compiler": Path(cc).name, "lines": len(script),
                                            "queries": script.count("Q"), "identical": True}), encoding="utf-8")
