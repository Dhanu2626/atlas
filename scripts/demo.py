"""Run ATLAS end to end with one command -- no hardware, no Wokwi, no setup.

    python scripts/demo.py

What it does, in about a minute:

  1. Builds a throwaway world in a temporary folder: ATLAS's signing key, a
     device key, the device registry, the transaction, step-up and replay
     stores, the bank's ledger, a freshly trained ML model, and the policy
     owners' enrolment (from the public keys committed beside the policies).
  2. Presses the ESP32's buttons -- through firmware/virtual_device.py, the
     tested Python twin of atlas_device.ino: the same three preset payments,
     the same signed envelope, the same rule for which LED lights.
  3. Each press goes through the REAL ATLAS code (device signature check,
     replay check, ML evidence, the owner-signed policy, the signed assertion)
     and, for an ALLOW, the REAL bank code verifying ATLAS's signature.
  4. Prints what the device would show -- green, amber or red -- and why.
  5. Sends one signed request a second time, to show the replay defence.
  6. Deletes the temporary folder. Nothing on this machine is changed.

What is simulated, and said so on screen: the ESP32 is the Python twin, not
the C firmware in Wokwi, and the two services run in-process (FastAPI's test
client, as the test suite and the dashboard export run them), so there is no
network hop or TLS between them. Everything that DECIDES is the real code.

Exit status 0 when the three presses give ALLOW, STEP_UP and DENY, as the
shipped policy for user-demo-1 says they must; 1 otherwise. That makes the
demo usable as a check (CI runs it on every push).

It never opens the live databases, key folders or certificates: every store
is redirected into the temporary folder (the same overrides as
scripts/export_dashboard_data.py's sweep), and the services' startup hook --
which writes to the live databases -- is never run.
"""

from __future__ import annotations

import os
import secrets
import shutil
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

ATLAS_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ATLAS_ROOT))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

IST = timezone(timedelta(hours=5, minutes=30))
SUBJECT = "user-demo-1"
#: A device_id the demo customer's history already knows (ml/synth.py), as in
#: the dashboard sweep, so "new device" never colours the evidence.
DEVICE_ID = "device-primary-01"
EXPECTED = ("ALLOW", "STEP_UP", "DENY")

_COLOUR = {"GREEN": "32", "AMBER": "33", "RED": "31", "OFF": "90"}


def _use_colour() -> bool:
    if os.environ.get("NO_COLOR") or not sys.stdout.isatty():
        return False
    if sys.platform == "win32":
        os.system("")          # switches the Windows console into ANSI mode
    return True


def _led(name: str, colour: bool) -> str:
    dot = f"● {name}"
    return f"\033[{_COLOUR.get(name, '0')}m{dot}\033[0m" if colour else f"[{name}]"


def _yesterday_at(hour: int, minute: int) -> str:
    """The payment's local time. Yesterday, so it is always in the past, at a
    fixed hour, so the time-of-day rule gives the same answer whenever the
    demo is run."""
    day = (datetime.now(IST) - timedelta(days=1)).date()
    return datetime(day.year, day.month, day.day, hour, minute, tzinfo=IST).isoformat()


def rupees(amount: float) -> str:
    """Indian digit grouping: 150000 -> 1,50,000.00."""
    whole, paise = f"{amount:.2f}".split(".")
    head, tail = whole[:-3], whole[-3:]
    groups = []
    while len(head) > 2:
        groups.insert(0, head[-2:])
        head = head[:-2]
    if head:
        groups.insert(0, head)
    return "Rs " + ",".join(groups + [tail]) + "." + paise


def rule_in_words(rule: dict, timezone_name: str | None) -> str:
    """One policy rule, read from the policy file itself, in plain words."""
    parts = []
    for key, value in (rule.get("condition") or {}).items():
        if key == "MAX_AMOUNT":
            parts.append(f"the amount is over {rupees(value)[:-3]}")
        elif key == "NEW_BENEFICIARY":
            parts.append("the payee is new to this customer")
        elif key == "INTERNATIONAL":
            parts.append("the payment is international")
        elif key == "TIME_WINDOW":
            start, end = value
            parts.append(f"it is between {start:02d}:00 and {end:02d}:00"
                         + (f" ({timezone_name})" if timezone_name else ""))
        elif key == "VELOCITY":
            parts.append(f"there are more than {value} payments in 24 hours")
        elif key == "RISK_THRESHOLD":
            parts.append(f"the ML evidence is {value}")
        else:
            parts.append(f"{key}: {value}")
    return f"{' and '.join(parts)} -> {rule.get('action')}"


def _why(body: dict, policy: dict) -> list[str]:
    decision = body.get("decision") or {}
    rules = {r["name"]: r for r in policy.get("rules", [])}
    tz = policy.get("timezone")
    lines = []
    deciding = decision.get("deciding_rule")
    if deciding:
        lines.append(f"policy rule '{deciding}': {rule_in_words(rules.get(deciding, {}), tz)}")
        others = [r for r in decision.get("matched_rules", []) if r != deciding]
        if others:
            lines.append(f"also matched: {', '.join(others)} (the strictest rule wins)")
    elif body.get("final_status") == "ALLOW":
        lines.append("no rule in the customer's signed policy objected")
    risk = (body.get("risk") or {}).get("risk_band")
    if risk == "INSUFFICIENT_HISTORY":
        lines.append("ML: not enough payment history yet to judge, so the rules decide alone")
    elif risk:
        lines.append(f"ML evidence: {risk}")
    verdict = body.get("bank_verdict") or {}
    if verdict:
        lines.append("bank: verified ATLAS's signed decision and "
                     + ("approved the payment" if verdict.get("approved") else f"refused ({verdict.get('reason')})"))
    elif body.get("final_status") in ("STEP_UP", "DENY"):
        lines.append("bank: not contacted -- nothing leaves until ATLAS allows it")
    return lines or [str(body.get("decision_reason"))]


def run(out=print, *, show_logs: bool = False) -> int:
    """The demo. Service log lines and library warnings are hidden unless
    show_logs, so a first-time reader sees the story, not the plumbing."""
    import logging
    import warnings

    if show_logs:
        return _run(out)
    logging.disable(logging.INFO)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            return _run(out)
    finally:
        logging.disable(logging.NOTSET)


def _run(out) -> int:
    import yaml
    from fastapi.testclient import TestClient

    import keystore
    from atlas_service import crypto
    from atlas_service.db import TransactionStore
    from atlas_service.device.db import DeviceStore
    from atlas_service.device.registry import register_demo_device
    from atlas_service.main import (
        app as atlas_app,
        get_allow_counter_reset,
        get_bank_client,
        get_device_store,
        get_model_registry,
        get_policy_version_store,
        get_signing_keys_dir,
        get_step_up_store,
        get_transaction_store,
    )
    from atlas_service.ml import registry as model_registry
    from atlas_service.policy.engine import POLICIES_DIR
    from atlas_service.policy.version_store import PolicyVersionStore
    from atlas_service.step_up.db import StepUpStore
    from bank_service import db as bank_db
    from bank_service.main import app as bank_app
    from bank_service.main import get_atlas_public_key, get_replay_cache
    from bank_service.replay_cache import ReplayCache
    from firmware import device_identity, virtual_device as vd

    colour = _use_colour()
    out("ATLAS demo -- a signed second opinion before a payment leaves")
    out("Real: ATLAS's checks, ML evidence, owner-signed policy and signed decision; the bank's verification.")
    out("Simulated: the ESP32 (its tested Python twin) and the network (services run in-process).")
    out("")

    # Keys on Linux/macOS are protected with a passphrase (keystore.py's scrypt
    # backend); on Windows with DPAPI. The demo's keys are throwaway, so a
    # random passphrase for this process alone is enough.
    if keystore.default_backend() == keystore.BACKEND_SCRYPT:
        os.environ.setdefault(keystore.PASSPHRASE_ENV, secrets.token_urlsafe(24))

    tmp = Path(tempfile.mkdtemp(prefix="atlas-demo-"))
    opened: list = []
    atlas = bank = None
    live_ledger = bank_db.DEFAULT_DB_PATH
    bank_db.DEFAULT_DB_PATH = tmp / "bank_ledger.db"
    outcomes: list[str] = []
    try:
        out("Setting up a throwaway world (keys, stores, a freshly trained model)...")
        keys_dir = tmp / "atlas-keys"
        crypto.init_device(keys_dir=keys_dir)
        models = tmp / "models"
        model_registry.save(model_registry.train_subject(SUBJECT), models)
        registry = model_registry.ModelRegistry(models)

        def _track(handle):
            opened.append(handle)
            return handle

        bank_app.dependency_overrides[get_atlas_public_key] = lambda: crypto.get_public_key(keys_dir=keys_dir)
        bank_app.dependency_overrides[get_replay_cache] = lambda: _track(ReplayCache(tmp / "replay.db"))
        bank = TestClient(bank_app)             # never entered: the startup hook is not run

        policy_state = _track(PolicyVersionStore(tmp / "policy_state.db"))
        for pub in sorted(POLICIES_DIR.glob("*.pub")):
            policy_state.enroll_owner(pub.stem, pub.read_text(encoding="ascii").strip())

        atlas_app.dependency_overrides.update({
            get_bank_client: lambda: bank,
            get_signing_keys_dir: lambda: keys_dir,
            get_transaction_store: lambda: _track(TransactionStore(tmp / "atlas.db")),
            get_device_store: lambda: _track(DeviceStore(tmp / "devices.db")),
            get_step_up_store: lambda: _track(StepUpStore(tmp / "step_up.db")),
            get_allow_counter_reset: lambda: False,
            get_model_registry: lambda: registry,
            get_policy_version_store: lambda: policy_state,
        })
        atlas = TestClient(atlas_app)

        device_keys = tmp / "device-keys"
        device_identity.init_device(device_keys)
        register_demo_device(
            _track(DeviceStore(tmp / "devices.db")),
            device_id=DEVICE_ID,
            device_key_id=device_identity.get_key_id(device_keys),
            public_key=device_identity.get_public_key(device_keys),
            bound_subject=SUBJECT,
        )
        config = vd.DeviceConfig(atlas_url="http://atlas", device_id=DEVICE_ID, subject=SUBJECT,
                                 boot_id=vd.new_boot_id(), location="Hyderabad,IN")
        policy = yaml.safe_load((POLICIES_DIR / f"{SUBJECT}.yaml").read_text(encoding="utf-8"))
        out(f"Ready: customer {SUBJECT}, policy version {policy.get('version')} (signed by its owner), "
            f"device {DEVICE_ID}.")
        out("")

        def press(title: str, preset_id: int, when: str, sequence: int) -> str | None:
            preset = config.presets[preset_id]
            out(f"{title} -- {rupees(preset.amount_minor / 100)} to {preset.beneficiary} "
                f"at {when[11:16]} IST")
            result = vd.handle_event_signed(vd.RawEvent(preset_id=preset_id, pressed_at=when,
                                                        sequence=sequence),
                                            config, atlas, device_keys)
            out(f"   ATLAS says {result.final_status or result.decision_reason}"
                f"   ->  device LED {_led(result.led.value, colour)}")
            for line in _why(result.raw_response or {}, policy):
                out(f"   - {line}")
            out("")
            return result.final_status

        daytime = _yesterday_at(10, 0)
        for n in range(3):
            outcomes.append(press(f"Press {n + 1}: SELECT preset {n + 1}, then SEND", n, daytime, n + 1)
                            or "NONE")

        # The time-of-day rule, shown rather than described.
        press("Bonus: preset 1 again, late at night", 0, _yesterday_at(23, 30), 4)

        # The replay defence: a captured, validly signed request sent twice.
        out("Replay: an attacker captures a validly signed request and sends it again")
        body = vd.assemble_transaction(vd.RawEvent(preset_id=0, pressed_at=daytime, sequence=5), config)
        envelope = vd.build_envelope(body, config, device_keys)
        first = atlas.post("/v2/transact", json=envelope, params={"rail": "UPI"}).json()
        second = atlas.post("/v2/transact", json=envelope, params={"rail": "UPI"}).json()
        out(f"   first time: {first.get('final_status')}   second time: {second.get('final_status')} "
            f"({second.get('decision_reason')}: that device counter was already used)")
        out("")
    finally:
        bank_db.DEFAULT_DB_PATH = live_ledger
        atlas_app.dependency_overrides.clear()
        bank_app.dependency_overrides.clear()
        for client in (atlas, bank):
            if client is not None:
                client.close()
        for handle in opened:
            try:
                handle.close()
            except Exception:  # noqa: BLE001 -- tidying up must not hide the result
                pass
        shutil.rmtree(tmp, ignore_errors=True)

    ok, line = verdict(outcomes)
    out(line)
    out("Temporary folder deleted; nothing on this machine was changed." if not tmp.exists()
        else f"Could not delete {tmp}; it holds only throwaway keys and stores.")
    return 0 if ok else 1


def verdict(outcomes: list[str]) -> tuple[bool, str]:
    """Passes only on exactly ALLOW, STEP_UP, DENY -- in that order."""
    ok = tuple(outcomes) == EXPECTED
    return ok, ("Result: " + ", ".join(outcomes)
                + ("  -- as the policy requires (green, amber, red)." if ok
                   else f"  -- EXPECTED {', '.join(EXPECTED)}."))


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Run ATLAS end to end: ALLOW, STEP_UP and DENY.")
    parser.add_argument("--show-logs", action="store_true",
                        help="also print the services' own log lines ([DEVICE], [SECURITY], [POLICY], ...)")
    raise SystemExit(run(show_logs=parser.parse_args().show_logs))
