"""ATLAS, running in the visitor's browser (Pyodide) -- or on CPython, for the parity test.

The "Run it live" page (docs/live/index.html) loads this file and the bundle of ATLAS's
real source (scripts/build_live_bundle.py). Everything below drives the REAL code: the
FastAPI app and its /v2/transact endpoint (device signature, replay checks, the
owner-signed policy, the ML layer, assertion signing) and the bank's real
verify_endpoint(). Keys, stores and the ML model are created fresh for each visitor, in
the browser's own memory; nothing is sent anywhere.

Three browser adapters, and only these -- the ATLAS code itself is not modified:

  1. No threads in a browser. FastAPI runs a plain `def` endpoint on a thread pool;
     here that pool becomes a direct call (same function, same arguments).
  2. No synchronous HTTP inside a browser tab. ATLAS's bank client posts the signed
     assertion; here the post is handed to the bank's real verify_endpoint() and its
     answer comes back as the HTTP response.
  3. The browser's hashlib has no scrypt (used to protect keys at rest); the same
     RFC 7914 scrypt from `cryptography` gives byte-identical output.

tests/test_live_parity.py proves the adapters change no decision: the same payments
through this runner and through the real desktop services give identical answers.

REAL LOCATION (2026-10-09). If the visitor allows it, the page asks their browser for
their current position and passes it to pay(): the device twin signs it as location
evidence with source "BROWSER", and ATLAS grades it against the home area the visitor
chose. It is the visitor's real position -- each visitor's own, never a fixed city -- and
it stays in this tab: nothing here sends anything anywhere. ATLAS's answer carries only
the grade (inside / outside the home area, LOW confidence), never the coordinates.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

IST = timezone(timedelta(hours=5, minutes=30))
SUBJECT = "user-demo-1"
DEVICE_ID = "device-primary-01"
PAYEE_RE = re.compile(r"[A-Za-z0-9._-]{1,40}")
MAX_RUPEES = 10_00_00_000                      # 10 crore: far past every rule, still sane

#: The legacy free-text place label inside the Transaction. The browser path does not
#: claim a city for its visitors; real location travels as graded evidence instead.
PLACE_LABEL = "unstated"

#: The home area's radius on the live page: wide enough for a browser's Wi-Fi or network
#: positioning, narrow enough that another city is plainly outside it.
HOME_RADIUS_M = 25_000

#: Home areas a visitor can pick instead of "where I am now". Public city-centre
#: coordinates -- nobody's address.
CITIES = {
    "Hyderabad": (17.385044, 78.486671), "Bengaluru": (12.971599, 77.594566),
    "Chennai": (13.082680, 80.270721), "Delhi": (28.613939, 77.209023),
    "Kolkata": (22.572645, 88.363892), "Mumbai": (19.076090, 72.877426),
}

#: Fixed positions for the PARITY TEST ONLY (lat, lon, accuracy m) -- what the test's
#: browser is told to report. A visitor's payments carry their own real position.
PARITY_SPOTS = {"home": (17.385100, 78.486600, 20.0), "away": (17.624800, 78.086700, 20.0)}

#: The payments the parity test sends both ways: (label, payee, rupees, local time, where).
#: `where` is None (no location shared) or a PARITY_SPOTS key; the first one with a
#: location also sets the home area to that spot.
SCENARIOS = [
    ("everyday", "ben-mother", "1500", "10:00", None),
    ("large new payee", "ben-newshop", "60000", "10:00", None),
    ("over the hard cap", "ben-newshop", "150000", "10:00", None),
    ("late night", "ben-mother", "1500", "23:30", None),
    ("new payee, meaningful amount", "ben-freshvendor", "25000", "14:00", None),
    ("small, known by now", "ben-newshop", "500", "11:15", None),
    ("at home, location shared", "ben-mother", "1500", "10:00", "home"),
    ("away from the home area", "ben-mother", "1500", "10:00", "away"),
]

_ADAPTERS: list[str] = []


def install_adapters() -> list[str]:
    """The three browser adapters. Idempotent. Never imported into the test process
    itself: the parity test runs this in a separate interpreter."""
    if _ADAPTERS:
        return _ADAPTERS
    import fastapi.concurrency
    import fastapi.dependencies.utils
    import fastapi.routing
    import starlette.concurrency

    async def run_inline(func, *args, **kwargs):
        return func(*args, **kwargs)

    for mod in (starlette.concurrency, fastapi.concurrency, fastapi.routing, fastapi.dependencies.utils):
        if hasattr(mod, "run_in_threadpool"):
            mod.run_in_threadpool = run_inline
            _ADAPTERS.append(f"{mod.__name__}.run_in_threadpool")

    import hashlib
    if not hasattr(hashlib, "scrypt"):
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

        def _scrypt(password, *, salt, n, r, p, maxmem=0, dklen=64):
            return Scrypt(salt=salt, length=dklen, n=n, r=r, p=p).derive(password)

        hashlib.scrypt = _scrypt
        _ADAPTERS.append("hashlib.scrypt")
    _ADAPTERS.append("bank: in-process verify_endpoint")
    return _ADAPTERS


def _yesterday_at(hhmm: str) -> str:
    """The payment's local time, yesterday -- always in the past, and the same rule
    answers whenever the page is used."""
    if not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", hhmm):
        raise ValueError("time must be HH:MM, 00:00 to 23:59")
    h, m = map(int, hhmm.split(":"))
    day = (datetime.now(IST) - timedelta(days=1)).date()
    return datetime(day.year, day.month, day.day, h, m, tzinfo=IST).isoformat()


def _finite(value, name: str, low: float, high: float) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        raise ValueError(f"{name} is not a number") from None
    if number != number or not low <= number <= high:     # NaN, or out of range
        raise ValueError(f"{name} must be between {low:g} and {high:g}")
    return number


def browser_evidence(lat, lon, accuracy_m, captured_ms) -> dict:
    """The browser's position as the LocationEvidence the device twin signs: coordinates
    as strings, as the C firmware writes them, and source BROWSER -- the browser does not
    say whether satellites, Wi-Fi or the network placed it, so ATLAS grades it LOW."""
    lat = _finite(lat, "latitude", -90, 90)
    lon = _finite(lon, "longitude", -180, 180)
    accuracy = _finite(accuracy_m, "accuracy", 0, 10_000_000)
    when = datetime.fromtimestamp(_finite(captured_ms, "position time", 0, 4e12) / 1000, tz=timezone.utc)
    return {"accuracy_m": f"{accuracy:.1f}", "captured_at": when.isoformat(timespec="seconds"),
            "latitude": f"{lat:.6f}", "longitude": f"{lon:.6f}", "satellites": None, "source": "BROWSER"}


class LiveAtlas:
    def __init__(self, workdir: str):
        self.dir = Path(workdir)
        self.timings: dict[str, float] = {}
        self.sequence = 0
        self.paid: list[str] = []
        self.last_envelope: dict | None = None
        self.home: str | None = None

    # ------------------------------------------------------------------ setup
    #: The setup steps, in order, as (what the page shows, method). The page calls them
    #: one at a time so it can repaint its progress bar between them.
    STEPS = [("Loading ATLAS", "step_import"), ("Making this visitor's keys", "step_keys"),
             ("Training this visitor's model", "step_train"), ("Wiring ATLAS and the bank", "step_wire")]

    def setup(self) -> str:
        """All steps at once (CPython and the tests)."""
        for _label, method in self.STEPS:
            getattr(self, method)()
        return self.info()

    def step_import(self) -> None:
        t = time.perf_counter()
        install_adapters()
        if "pyodide" in sys.modules or sys.platform == "emscripten":
            os.environ.setdefault("ATLAS_KEYSTORE_PASSPHRASE", secrets.token_urlsafe(24))
        import httpx  # noqa: F401
        from atlas_service import crypto
        from atlas_service.db import TransactionStore
        from atlas_service.device.db import DeviceStore
        from atlas_service.device.registry import register_demo_device
        from atlas_service.main import (
            app, get_allow_counter_reset, get_bank_client, get_device_store, get_model_registry,
            get_policy_version_store, get_signing_keys_dir, get_step_up_store, get_transaction_store,
        )
        from atlas_service.ml import registry as model_registry
        from atlas_service.policy.engine import POLICIES_DIR
        from atlas_service.policy.version_store import PolicyVersionStore
        from atlas_service.step_up.db import StepUpStore
        from bank_service import db as bank_db
        from firmware import device_identity, virtual_device as vd
        import keystore
        self._m = dict(crypto=crypto, TransactionStore=TransactionStore, DeviceStore=DeviceStore,
                       register_demo_device=register_demo_device, app=app,
                       get_allow_counter_reset=get_allow_counter_reset, get_bank_client=get_bank_client,
                       get_device_store=get_device_store, get_model_registry=get_model_registry,
                       get_policy_version_store=get_policy_version_store,
                       get_signing_keys_dir=get_signing_keys_dir, get_step_up_store=get_step_up_store,
                       get_transaction_store=get_transaction_store, model_registry=model_registry,
                       POLICIES_DIR=POLICIES_DIR, PolicyVersionStore=PolicyVersionStore,
                       StepUpStore=StepUpStore, bank_db=bank_db, device_identity=device_identity,
                       vd=vd, keystore=keystore)
        self.timings["import_s"] = round(time.perf_counter() - t, 2)

    def step_keys(self) -> None:
        m = self._m
        crypto, keystore, bank_db, device_identity = m["crypto"], m["keystore"], m["bank_db"], m["device_identity"]
        t = time.perf_counter()
        self.dir.mkdir(parents=True, exist_ok=True)
        if keystore.default_backend() == keystore.BACKEND_SCRYPT:
            os.environ.setdefault(keystore.PASSPHRASE_ENV, secrets.token_urlsafe(24))
        bank_db.DEFAULT_DB_PATH = self.dir / "bank_ledger.db"
        self.keys = self.dir / "atlas-keys"
        crypto.init_device(keys_dir=self.keys)
        self.device_keys = self.dir / "device-keys"
        device_identity.init_device(self.device_keys)
        self.timings["keys_s"] = round(time.perf_counter() - t, 2)

    def step_train(self) -> None:
        model_registry = self._m["model_registry"]
        t = time.perf_counter()
        models = self.dir / "models"
        model_registry.save(model_registry.train_subject(SUBJECT), models)
        self.registry = model_registry.ModelRegistry(models)
        self.timings["train_s"] = round(time.perf_counter() - t, 2)

    def step_wire(self) -> None:
        m = self._m
        app, vd, DeviceStore = m["app"], m["vd"], m["DeviceStore"]
        TransactionStore, StepUpStore, PolicyVersionStore = m["TransactionStore"], m["StepUpStore"], m["PolicyVersionStore"]
        registry, POLICIES_DIR, device_identity = self.registry, m["POLICIES_DIR"], m["device_identity"]
        policy_state = PolicyVersionStore(self.dir / "policy_state.db")
        for pub in sorted(POLICIES_DIR.glob("*.pub")):
            policy_state.enroll_owner(pub.stem, pub.read_text(encoding="ascii").strip())
        bank = _InProcessBank(self.keys, self.dir / "replay.db")
        d = self.dir
        app.dependency_overrides.update({
            m["get_bank_client"]: lambda: bank,
            m["get_signing_keys_dir"]: lambda: self.keys,
            m["get_transaction_store"]: lambda: TransactionStore(d / "atlas.db"),
            m["get_device_store"]: lambda: DeviceStore(d / "devices.db"),
            m["get_step_up_store"]: lambda: StepUpStore(d / "step_up.db"),
            m["get_allow_counter_reset"]: lambda: False,
            m["get_model_registry"]: lambda: registry,
            m["get_policy_version_store"]: lambda: policy_state,
        })
        self.policy_rules = json.dumps(_load_rules(POLICIES_DIR / f"{SUBJECT}.yaml"))
        m["register_demo_device"](DeviceStore(d / "devices.db"), device_id=DEVICE_ID,
                             device_key_id=device_identity.get_key_id(self.device_keys),
                             public_key=device_identity.get_public_key(self.device_keys),
                             bound_subject=SUBJECT)
        self.app, self.vd = app, vd
        self.boot_id = vd.new_boot_id()

    def info(self) -> str:
        import platform
        return json.dumps({"python": platform.python_version(), "platform": sys.platform,
                           "adapters": _ADAPTERS, "timings": self.timings})

    # ------------------------------------------------------------------ home area
    def set_home_city(self, city: str) -> str:
        """The home area ATLAS measures the visitor's location against: a named city."""
        if city not in CITIES:
            raise ValueError(f"unknown city {city!r}")
        return self._set_home(*CITIES[city], city)

    def set_home_here(self, lat, lon) -> str:
        """The home area: "where I am now" -- the visitor's own position, kept in this tab."""
        return self._set_home(_finite(lat, "latitude", -90, 90), _finite(lon, "longitude", -180, 180),
                              "where you were when you set it")

    def _set_home(self, lat: float, lon: float, label: str) -> str:
        from atlas_service.device.registry import set_home_area
        set_home_area(self._m["DeviceStore"](self.dir / "devices.db"), DEVICE_ID, lat, lon, HOME_RADIUS_M)
        self.home = label
        return json.dumps({"home": label, "radius_km": HOME_RADIUS_M / 1000})

    # ------------------------------------------------------------------ paying
    async def pay(self, payee: str, rupees: str, hhmm: str, lat=None, lon=None, accuracy=None,
                  captured_ms=None) -> str:
        """One press of SEND: the firmware twin builds and signs the envelope -- with the
        browser's position, if the visitor shared it; ATLAS's real endpoint decides.
        Returns every layer as JSON."""
        payee = str(payee).strip()
        if not PAYEE_RE.fullmatch(payee):
            raise ValueError("payee: 1-40 letters, digits, dot, dash or underscore")
        amount = round(float(rupees), 2)
        if not 0 < amount <= MAX_RUPEES:
            raise ValueError("amount must be more than Rs 0 and at most Rs 10 crore")
        when = _yesterday_at(hhmm)
        location = None if lat is None else browser_evidence(lat, lon, accuracy, captured_ms)
        vd = self.vd                                  # every check above, before anything is built or signed
        self.sequence += 1
        config = vd.DeviceConfig(atlas_url="http://atlas", device_id=DEVICE_ID, subject=SUBJECT,
                                 boot_id=self.boot_id, location=PLACE_LABEL,
                                 presets=(vd.Preset(beneficiary=payee, amount_minor=round(amount * 100)),))
        body = vd.assemble_transaction(vd.RawEvent(preset_id=0, pressed_at=when, sequence=self.sequence), config)
        envelope = vd.build_envelope(body, config, self.device_keys, location=location)
        first_time = payee not in self.paid
        self.paid.append(payee)
        self.last_envelope = envelope
        return json.dumps(await self._post(envelope, payee=payee, rupees=amount, hhmm=hhmm, first_time=first_time))

    async def replay_last(self) -> str:
        """Sends the last signed request again, byte for byte -- what an attacker who
        captured it would do."""
        if self.last_envelope is None:
            raise ValueError("send a payment first")
        tx = self.last_envelope["transaction"]
        return json.dumps(await self._post(self.last_envelope, payee=tx["beneficiary"],
                                           rupees=float(tx["amount"]), hhmm=tx["timestamp"][11:16],
                                           first_time=False, replay=True))

    async def _post(self, envelope, **shown) -> dict:
        import httpx
        started = time.perf_counter()
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app), base_url="http://atlas") as c:
            r = await c.post("/v2/transact", params={"rail": "UPI"}, json=envelope)
        out = r.json()
        ms = round((time.perf_counter() - started) * 1000)
        state = self.vd.interpret_response(out)
        decision, risk = out.get("decision") or {}, out.get("risk") or {}
        assertion, verdict = out.get("assertion") or {}, out.get("bank_verdict") or {}
        payload = assertion.get("payload") or {}
        return {
            **shown, "http": r.status_code, "ms": ms,
            "final_status": out.get("final_status"), "decision_reason": out.get("decision_reason"),
            "led": self.vd.led_for(state).value, "device_state": state.value,
            "deciding_rule": decision.get("deciding_rule"), "matched_rules": decision.get("matched_rules") or [],
            "policy_version": decision.get("policy_version"),
            "policy_hash": (decision.get("policy_hash") or "")[:12],
            "risk_band": risk.get("risk_band"), "risk_reasons": risk.get("reasons") or [],
            "signed": bool(assertion.get("signature")), "key_id": payload.get("atlas_key_id"),
            "signature_hex": len(assertion.get("signature") or ""),
            "bank_contacted": bool(verdict), "bank_approved": verdict.get("approved"),
            "bank_reason": verdict.get("reason"), "counter": envelope.get("counter"),
            "location_sent": envelope.get("location") is not None, "location": out.get("location"),
            "home": self.home,
        }


def _load_rules(path: Path) -> dict:
    """The customer's policy as the page shows it: version, timezone and rules."""
    import yaml
    policy = yaml.safe_load(path.read_text(encoding="utf-8"))
    return {"version": policy.get("version"), "timezone": policy.get("timezone"),
            "rules": [{"name": r["name"], "condition": r["condition"], "action": r["action"]}
                      for r in policy.get("rules", [])]}


class _InProcessBank:
    """Adapter 2: the shape of an httpx client, handing /verify to the bank's real
    endpoint function with this visitor's ATLAS public key and replay cache."""

    def __init__(self, keys_dir: Path, replay_db: Path):
        self.keys_dir, self.replay_db = keys_dir, replay_db

    def post(self, url, json=None, timeout=None):
        import httpx
        from atlas_service import crypto
        from bank_service import main as bank_main
        from bank_service.replay_cache import ReplayCache
        from contracts import SignedAssertion
        if not url.endswith("/verify"):
            raise ValueError(f"the in-browser bank only answers /verify, not {url}")
        body = bank_main.verify_endpoint(
            SignedAssertion.model_validate(json),
            atlas_public_key=crypto.get_public_key(keys_dir=self.keys_dir),
            replay_cache=ReplayCache(self.replay_db),
        )
        return httpx.Response(200, json=body, request=httpx.Request("POST", url))


async def run_scenarios(workdir: str) -> str:
    """Every SCENARIO, then a replay of the last one. Used by the parity tests."""
    live = LiveAtlas(workdir)
    info = json.loads(live.setup())
    results = []
    for label, payee, rupees, hhmm, where in SCENARIOS:
        spot = {}
        if where is not None:
            lat, lon, accuracy = PARITY_SPOTS[where]
            if live.home is None:
                live.set_home_here(lat, lon)
            spot = dict(lat=lat, lon=lon, accuracy=accuracy, captured_ms=time.time() * 1000)
        results.append({"label": label, **json.loads(await live.pay(payee, rupees, hhmm, **spot))})
    results.append({"label": "replay", **json.loads(await live.replay_last())})
    return json.dumps({"info": info, "results": results})


if __name__ == "__main__":                     # CPython: python docs/live/atlas_browser.py <workdir>
    import asyncio
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    print(asyncio.run(run_scenarios(sys.argv[1])))
