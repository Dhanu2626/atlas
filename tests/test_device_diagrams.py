"""The device pictures agree with the simulation they show (2026-09-26).

assets/atlas-device-board.svg, assets/atlas-device-pinout.svg,
assets/atlas-device-parts.svg and docs/hardware/atlas-schematic.svg are drawings of
firmware/atlas_device/diagram.json. A drawing can be wrong in ways nobody notices, so
these tests read each one back and check it against three sources it does not
control:

  * diagram.json -- which pin drives which part, which ground each part returns to;
  * the firmware -- the GPIO numbers, and which answers light which LED;
  * Wokwi's own ESP32 DevKit V1 definition -- the order of the 30 header pins
    (wokwi-elements 1.9.2, esp32-devkit-v1 pinInfo sorted by y; checked 2026-09-26
    by rendering diagram.json with Wokwi's element library).

The board view is checked by its geometry, not by labels: a track must start on the
pad of the pin that drives it, end at an LED of the right colour or the right
button, and keep clear of every other pad and track.

CHANGED 2026-10-09 (recorded as the directive asks): the circuit gained a SIMULATED GNSS
receiver on UART2 -- RX2 (GPIO16) <- its TX, TX2 (GPIO17) -> its RX, its power from 3V3
and its ground on GND.1. The expected wiring below grew by exactly those connections, the
no-connect count fell from 21 to 18, and new checks require every picture to show the
receiver and to call it simulated. No existing check was loosened.
"""

from __future__ import annotations

import json
import math
import re
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
DIAGRAM = ROOT / "firmware" / "atlas_device" / "diagram.json"
SKETCH = ROOT / "firmware" / "atlas_device" / "atlas_device.ino"
BOARD = ROOT / "assets" / "atlas-device-board.svg"
PINOUT = ROOT / "assets" / "atlas-device-pinout.svg"
PARTS = ROOT / "assets" / "atlas-device-parts.svg"
SCHEMATIC = ROOT / "docs" / "hardware" / "atlas-schematic.svg"
FLOW = ROOT / "assets" / "atlas-flow.svg"

WOKWI_LEFT = ["EN", "VP", "VN", "D34", "D35", "D32", "D33", "D25", "D26", "D27",
              "D14", "D12", "D13", "GND.2", "VIN"]
WOKWI_RIGHT = ["D23", "D22", "TX0", "RX0", "D21", "D19", "D18", "D5", "TX2", "RX2",
               "D4", "D2", "D15", "GND.1", "3V3"]
COLOUR_OF_PART = {"led_green": "green", "led_amber": "amber", "led_red": "red"}
BUTTON_OF_PART = {"btn_select": "select", "btn_send": "send"}
GNSS_OF_PIN = {"RX2": "gnss-tx", "TX2": "gnss-rx", "3V3": "gnss-power"}   # what the receiver puts on each ESP pin


def _svg(path: Path) -> ET.Element:
    return ET.parse(path).getroot()


def _all(root, tag):
    return [e for e in root.iter() if e.tag.split("}")[-1] == tag]


def _points(el) -> list[tuple[float, float]]:
    return [tuple(map(float, p.split(","))) for p in el.get("points").split()]


def _text(el) -> str:
    return "".join(el.itertext())


# ---- what the simulation actually wires ------------------------------------------------

@pytest.fixture(scope="module")
def wiring():
    """esp pin -> what it drives, followed through resistors to the LED."""
    diagram = json.loads(DIAGRAM.read_text(encoding="utf-8"))
    edges = [(a, b) for a, b, *_ in diagram["connections"]]
    through = {}
    for a, b in edges:
        through.setdefault(a.split(":")[0], set()).add(b.split(":")[0])
        through.setdefault(b.split(":")[0], set()).add(a.split(":")[0])
    drives, grounds = {}, {}
    for a, b in edges:
        for pin_end, other in ((a, b), (b, a)):
            if not pin_end.startswith("esp:"):
                continue
            pin, part = pin_end.split(":")[1], other.split(":")[0]
            if pin.startswith("GND"):
                grounds.setdefault(pin, set()).add(part)
            elif part.startswith("r_"):
                led = next(p for p in through[part] if p.startswith("led_"))
                drives[pin] = COLOUR_OF_PART[led]
            elif part.startswith("btn_"):
                drives[pin] = BUTTON_OF_PART[part]
            elif part == "$serialMonitor":
                drives[pin] = "serial"
            elif part == "gnss":
                drives[pin] = GNSS_OF_PIN[pin]
    resistors = {p["id"]: p["attrs"]["value"] for p in diagram["parts"] if p["type"] == "wokwi-resistor"}
    return {"drives": drives, "grounds": grounds, "resistors": resistors,
            "used": set(drives) | set(grounds)}


@pytest.fixture(scope="module")
def firmware_pins():
    source = SKETCH.read_text(encoding="utf-8")
    return {name: int(n) for name, n in re.findall(r"static const int (PIN_\w+)\s*=\s*(\d+);", source)}


def test_the_simulation_wiring_is_the_one_the_pictures_were_drawn_from(wiring):
    assert wiring["drives"] == {"D25": "green", "D26": "amber", "D27": "red",
                                "D14": "select", "D12": "send", "TX0": "serial", "RX0": "serial",
                                "RX2": "gnss-tx", "TX2": "gnss-rx", "3V3": "gnss-power"}
    assert wiring["grounds"] == {"GND.2": {"led_green", "led_amber", "led_red"},
                                 "GND.1": {"btn_select", "btn_send", "gnss"}}
    assert set(wiring["resistors"].values()) == {"220"}


def test_the_firmware_drives_the_pins_the_pictures_show(wiring, firmware_pins):
    by_gpio = {f"D{v}": k for k, v in firmware_pins.items()}
    assert by_gpio == {"D25": "PIN_LED_GREEN", "D26": "PIN_LED_AMBER", "D27": "PIN_LED_RED",
                       "D14": "PIN_BTN_SELECT", "D12": "PIN_BTN_SEND"}
    for pin, name in by_gpio.items():
        expected = {"PIN_LED_GREEN": "green", "PIN_LED_AMBER": "amber", "PIN_LED_RED": "red",
                    "PIN_BTN_SELECT": "select", "PIN_BTN_SEND": "send"}[name]
        assert wiring["drives"][pin] == expected


# ---- pinout card --------------------------------------------------------------------

def _pinout_rows():
    rows = [g for g in _all(_svg(PINOUT), "g") if g.get("data-pin")]
    return {side: [g for g in sorted((g for g in rows if g.get("data-side") == side),
                                      key=lambda g: float(g.get("data-y")))]
            for side in ("L", "R")}


def test_the_pinout_lists_all_30_pins_in_wokwi_order():
    rows = _pinout_rows()
    assert [g.get("data-pin") for g in rows["L"]] == WOKWI_LEFT
    assert [g.get("data-pin") for g in rows["R"]] == WOKWI_RIGHT


def test_the_pinout_lights_exactly_the_pins_the_simulation_wires(wiring):
    rows = _pinout_rows()["L"] + _pinout_rows()["R"]
    used = {g.get("data-pin") for g in rows if g.get("data-used") == "true"}
    assert used == wiring["used"]
    for g in rows:
        texts = [_text(t) for t in _all(g, "text")]
        assert ("free" in texts) is (g.get("data-pin") not in wiring["used"]), g.get("data-pin")


def test_the_pinout_says_what_each_wired_pin_drives(wiring):
    words = {"green": "green LED", "amber": "amber LED", "red": "red LED", "select": "SELECT",
             "send": "SEND", "gnss-tx": "GNSS receiver TX", "gnss-rx": "GNSS receiver RX",
             "gnss-power": "GNSS receiver power"}
    gnss_io = {"RX2": "IO16", "TX2": "IO17"}
    rows = {g.get("data-pin"): " ".join(_text(t) for t in _all(g, "text"))
            for side in _pinout_rows().values() for g in side}
    for pin, what in wiring["drives"].items():
        if what == "serial":
            assert "Serial monitor " + ("RX" if pin == "TX0" else "TX") in rows[pin]
        elif what.startswith("gnss"):
            assert words[what] in rows[pin], (pin, rows[pin])
            if pin in gnss_io:
                assert gnss_io[pin] in rows[pin], (pin, rows[pin])
        else:
            assert words[what] in rows[pin], (pin, rows[pin])
            assert f"IO{pin[1:]}" in rows[pin], (pin, rows[pin])
    assert "LED returns" in rows["GND.2"] and "Button returns" in rows["GND.1"]


# ---- board view, by geometry -----------------------------------------------------------

@pytest.fixture(scope="module")
def board():
    root = _svg(BOARD)
    circles = _all(root, "circle")
    pads = {c.get("data-pad"): (float(c.get("cx")), float(c.get("cy"))) for c in circles if c.get("data-pad")}
    leds = {float(c.get("cy")): c.get("data-led") for c in circles if c.get("data-led")}
    buttons = {float(c.get("cy")): c.get("data-button") for c in circles if c.get("data-button")}
    traces = [(p.get("data-trace"), _points(p)) for p in _all(root, "polyline") if p.get("data-trace")]
    return {"pads": pads, "leds": leds, "buttons": buttons, "traces": traces, "root": root}


def _pad_at(pads, point, tol=10.0):
    hits = [n for n, (x, y) in pads.items() if math.dist((x, y), point) <= tol]
    return hits[0] if len(hits) == 1 else None


def test_the_board_pads_are_in_wokwi_order(board):
    left = sorted((n for n, (x, _) in board["pads"].items() if x < 480), key=lambda n: board["pads"][n][1])
    right = sorted((n for n, (x, _) in board["pads"].items() if x >= 480), key=lambda n: board["pads"][n][1])
    assert left == WOKWI_LEFT and right == WOKWI_RIGHT


def test_each_led_track_runs_from_its_pin_to_an_led_of_the_right_colour(board, wiring):
    found = {}
    for kind, pts in board["traces"]:
        if kind != "led":
            continue
        pin = _pad_at(board["pads"], pts[0])
        assert pin, f"an LED track starts on no pad: {pts[0]}"
        row = pts[-1][1]
        onward = [p for k, p in board["traces"] if k == "led2" and p[0][1] == row]
        assert len(onward) == 1, f"no resistor-to-LED track on row {row}"
        assert board["leds"].get(row), f"no LED at the end of the {pin} track"
        found[pin] = board["leds"][row]
    assert found == {p: c for p, c in wiring["drives"].items() if c in ("green", "amber", "red")}


def test_each_button_track_runs_from_its_pin_to_the_right_button(board, wiring):
    found = {}
    for kind, pts in board["traces"]:
        if kind != "btn":
            continue
        pin = _pad_at(board["pads"], pts[0])
        assert pin, f"a button track starts on no pad: {pts[0]}"
        found[pin] = board["buttons"].get(pts[-1][1])
    assert found == {p: c for p, c in wiring["drives"].items() if c in ("select", "send")}


def test_the_serial_tracks_start_on_tx0_and_rx0(board):
    starts = {_pad_at(board["pads"], pts[0]) for k, pts in board["traces"] if k == "uart"}
    assert starts == {"TX0", "RX0"}


def _seg_dist(p, a, b):
    ax, ay = a; bx, by = b; px, py = p
    dx, dy = bx - ax, by - ay
    if dx == dy == 0:
        return math.dist(p, a)
    t = max(0.0, min(1.0, ((px - ax) * dx + (py - ay) * dy) / (dx * dx + dy * dy)))
    return math.dist(p, (ax + t * dx, ay + t * dy))


def test_no_track_touches_a_pad_it_does_not_start_on(board):
    """Pad radius 9, track half-width 2.5: anything nearer than 13 px would short."""
    for kind, pts in board["traces"]:
        own = _pad_at(board["pads"], pts[0])
        for name, centre in board["pads"].items():
            if name == own:
                continue
            nearest = min(_seg_dist(centre, a, b) for a, b in zip(pts, pts[1:]))
            assert nearest >= 13, f"{kind} track from {own} passes {nearest:.1f}px from pad {name}"


def _crosses(p1, p2, q1, q2):
    def orient(a, b, c):
        v = (b[0] - a[0]) * (c[1] - a[1]) - (b[1] - a[1]) * (c[0] - a[0])
        return (v > 1e-9) - (v < -1e-9)
    return (orient(p1, p2, q1) * orient(p1, p2, q2) < 0) and (orient(q1, q2, p1) * orient(q1, q2, p2) < 0)


def _seg_seg_dist(a, b, c, d):
    if _crosses(a, b, c, d):
        return 0.0
    return min(_seg_dist(a, c, d), _seg_dist(b, c, d), _seg_dist(c, a, b), _seg_dist(d, a, b))


def test_no_two_tracks_cross_or_touch(board):
    """Two different tracks that cross, overlap or run closer than 6 px would short.
    (An end-to-end overlap in one lane is not a crossing, so gaps are measured too.)"""
    segs = [(i, a, b) for i, (_, pts) in enumerate(board["traces"]) for a, b in zip(pts, pts[1:])]
    for i, a, b in segs:
        for j, c, d in segs:
            if i < j:
                gap = _seg_seg_dist(a, b, c, d)
                assert gap >= 6, f"tracks {i} and {j} come within {gap:.1f}px"


def test_the_board_animation_keeps_the_architecture_cycle():
    cycle = set(re.findall(r"animation:\w+ (\d+)s", FLOW.read_text(encoding="utf-8")))
    # the scene animations only; the 1 s "flow" dash along a lit track is not a scene
    board_cycle = set(re.findall(r"animation:(?:g|a|r|c[1-4]|p) (\d+)s", BOARD.read_text(encoding="utf-8")))
    assert cycle == board_cycle == {"28"}


# ---- parts card --------------------------------------------------------------------------

def test_the_parts_card_matches_the_firmware(firmware_pins):
    words = " ".join(_text(t) for t in _all(_svg(PARTS), "text"))
    for pin in firmware_pins.values():
        assert f"GPIO{pin}" in words
    source = SKETCH.read_text(encoding="utf-8")
    state = dict(re.findall(r'strcmp\(finalStatus, "(\w+)"\)\s*== 0\)\s*return (STATE_\w+);', source))
    lit = {"STATE_APPROVED": "green", "STATE_ATTENTION": "amber", "STATE_UNRESOLVED": "amber",
           "STATE_REFUSED": "red", "STATE_FAIL_CLOSED": "red"}
    colour = {status: lit[s] for status, s in state.items()}
    assert colour == {"ALLOW": "green", "DENY": "red", "STEP_UP": "amber", "DELAY": "amber",
                      "PENDING": "amber", "FAIL_CLOSED": "red"}
    assert "Green · ALLOW" in words
    assert "STEP_UP, DELAY or PENDING" in words
    assert "Red · DENY / FAIL-CLOSED" in words and "unrecognised reply" in words
    assert re.search(r"return STATE_FAIL_CLOSED;\s*\n\}", source[source.index("strcmp(finalStatus"):]), \
        "an unrecognised reply no longer fails closed, so the red card would be wrong"


# ---- schematic -----------------------------------------------------------------------------

@pytest.fixture(scope="module")
def schematic():
    root = _svg(SCHEMATIC)
    pins = {}
    for g in _all(root, "g"):
        if g.get("class") != "pin":
            continue
        stub = next(l for l in _all(g, "line") if l.get("stroke") == "#8A1C1C")
        xs = (float(stub.get("x1")), float(stub.get("x2")))
        nc = any(l.get("stroke") == "#1F3FAF" for l in _all(g, "line"))
        pins[g.get("data-pin")] = {"y": float(stub.get("y1")), "side": "L" if min(xs) < 700 else "R", "nc": nc}
    return {"root": root, "pins": pins}


def test_the_schematic_shows_all_30_pins_in_wokwi_order(schematic):
    p = schematic["pins"]
    assert sorted((n for n in p if p[n]["side"] == "L"), key=lambda n: p[n]["y"]) == WOKWI_LEFT
    assert sorted((n for n in p if p[n]["side"] == "R"), key=lambda n: p[n]["y"]) == WOKWI_RIGHT


def test_the_schematic_marks_every_unwired_pin_no_connect(schematic, wiring):
    nc = {n for n, v in schematic["pins"].items() if v["nc"]}
    assert nc == set(WOKWI_LEFT + WOKWI_RIGHT) - wiring["used"]
    assert len(nc) == 18


def test_the_schematic_leds_sit_on_the_pins_that_drive_them(schematic, wiring):
    fills = {"#2BD66B": "green", "#F2B92C": "amber", "#F2463B": "red"}
    rows = {v["y"]: n for n, v in schematic["pins"].items() if v["side"] == "L"}
    found = {}
    for poly in _all(schematic["root"], "polygon"):
        if poly.get("fill") in fills:
            ys = [float(q.split(",")[1]) for q in poly.get("points").split()]
            centre = (max(ys) + min(ys)) / 2
            found[rows[centre]] = fills[poly.get("fill")]
    assert found == {p: c for p, c in wiring["drives"].items() if c in ("green", "amber", "red")}


def test_the_schematic_returns_leds_to_gnd2_and_buttons_to_gnd1(schematic):
    p = schematic["pins"]
    root = schematic["root"]
    lines = [(float(l.get("x1")), float(l.get("y1")), float(l.get("x2")), float(l.get("y2"))) for l in _all(root, "line")]
    assert (250, p["GND.2"]["y"], 520, p["GND.2"]["y"]) in lines, "the LED return does not reach GND.2"
    ends = [_points(pl)[-1] for pl in _all(root, "polyline")]
    assert (960.0, p["GND.1"]["y"]) in ends, "the button return does not reach GND.1"
    words = " ".join(_text(t) for t in _all(root, "text"))
    for ref in ("R1 220 Ω", "R2 220 Ω", "R3 220 Ω", "SW1 SELECT", "SW2 SEND", "Serial monitor", "115200 baud"):
        assert ref in words, ref


def test_the_readme_and_blueprint_point_at_files_that_exist():
    for doc in ("README.md", "docs/ATLAS-Blueprint.md", "firmware/README.md"):
        base = (ROOT / doc).parent
        text = (ROOT / doc).read_text(encoding="utf-8")
        for target in re.findall(r'(?:src="|\]\()((?:\.\./)*(?:assets|docs|hardware)/[^")#]*device[^")#]*|(?:\.\./)*(?:docs/)?hardware/atlas-schematic\.svg)', text):
            assert (base / target).resolve().exists(), f"{doc} points at a missing {target}"


# ---- the GNSS receiver (2026-10-09) --------------------------------------------------------

def test_the_board_routes_uart2_and_power_to_the_receiver(board):
    starts = sorted(_pad_at(board["pads"], pts[0]) or "via" for k, pts in board["traces"] if k == "gnss")
    assert starts == ["3V3", "RX2", "TX2", "via"]
    words = " ".join(_text(t) for t in _all(board["root"], "text"))
    assert "GNSS" in words and "SIMU-" in words and "12 of 30 pins in use" in words


def test_every_picture_shows_the_receiver_as_simulated():
    for path in (BOARD, PINOUT, PARTS, SCHEMATIC):
        text = path.read_text(encoding="utf-8")
        assert "GNSS" in text, path.name
        assert re.search(r"simulated|SIMULATED|SIMU-", text), path.name
    words = " ".join(_text(t) for t in _all(_svg(SCHEMATIC), "text"))
    assert "U2 GNSS" in words and "+3V3 → U2 VCC" in words and "(18 of 30)" in words
