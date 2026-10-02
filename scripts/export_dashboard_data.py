"""Exports a timestamped snapshot of real ATLAS numbers for the Step 9 dashboard.

Two sources, deliberately kept separate, because they are different KINDS of
evidence and the dashboard labels them differently:

  A. SNAPSHOT -- the live databases, opened READ-ONLY (sqlite `?mode=ro`).
     This is "what actually happened on this machine": transaction states,
     step-up challenges and their event trail, the device registry, and the
     bank's replay cache. Nothing is ever written back.

  B. SWEEP -- a deterministic re-run of README.md's own Results table through
     BOTH real services, in-process via FastAPI's TestClient, with every store
     pointed at a throwaway temporary directory.

Why a sweep is necessary at all: the `transactions` table stores what a payment WAS
-- since 2026-09-23 the whole transaction, so it can serve as the subject's history --
but not what ATLAS CONCLUDED about it. The ML evidence, the policy decision, the
deciding rule, the signed assertion and the rail payload live ONLY in the /transact
response and were never persisted. BUILD-PLAN.md step 9 asks the dashboard to show exactly those, so
they have to be produced by running the real pipeline rather than read back
out of storage. The run is reproducible: the demo model is fit on
generate_normal_history(..., seed=42).

Why the sweep must be isolated: _run_transaction() writes -- claim_new() then
transition(). atlas_service.main.DB_PATH is a module-level constant, not an
environment variable, so the only way to redirect it is FastAPI
dependency_overrides. That is exactly what tests/test_end_to_end.py's
`clients` fixture does, and this script mirrors it rather than inventing a
second way. Nothing here writes to the live databases.

Why a file and not an endpoint: atlas_service exposes no read-only list route,
and adding one is a change to a service that holds signing keys. GitHub Pages
is static and cannot reach 127.0.0.1 anyway, and exposing atlas_service
publicly is out of bounds. So the published page carries a DATED SNAPSHOT of
real numbers and says so on its face -- it is not live, and must never claim
to be.

Usage:
    .venv\\Scripts\\python scripts\\export_dashboard_data.py
    .venv\\Scripts\\python scripts\\export_dashboard_data.py --run-tests

--run-tests executes the full suite and records the count it actually
observed. Without it, the test count is recorded as not-run rather than
copied from a document.

Exit status is 1 when the export cannot stand as a complete record: the sweep
failed or dropped a scenario, a requested test run did not pass, or index.html
could not be updated to match the JSON. Warnings raised before the page is
written are embedded in it and displayed. A missing database is not a failure
-- a fresh clone has none -- and is reported as a warning only.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

ATLAS_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ATLAS_ROOT))

# Windows consoles default to cp1252 and die on any non-ASCII in output.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

IST = timezone(timedelta(hours=5, minutes=30))

TXN_DB = ATLAS_ROOT / "atlas_service" / "atlas_transactions.db"
STEP_UP_DB = ATLAS_ROOT / "atlas_service" / "atlas_step_up.db"
DEVICE_DB = ATLAS_ROOT / "atlas_service" / "atlas_devices.db"
BANK_DB = ATLAS_ROOT / "bank_service" / "bank_replay_cache.db"

OUT_PATH = ATLAS_ROOT / "docs" / "dashboard-data.json"

#: The device the sweep enrols and signs with. Deliberately the device_id the
#: demo history already contains (ml/synth.py's Persona.devices), so the signed
#: path changes who is asking, not what the evidence says: a fresh device_id
#: would make is_new_device true and move every score.
DEMO_DEVICE_ID = "device-primary-01"

# Figures this script cannot measure travel with the document they come from,
# so the page can never present them as numbers the export produced itself.
RECORDED = "recorded, not re-measured by this export"
FQBN_NOTE = "esp32:esp32:esp32doit-devkit-v1"


# --------------------------------------------------------------------------
# A. Snapshot -- read-only reads of the live databases
# --------------------------------------------------------------------------

def _ro(path: Path) -> sqlite3.Connection | None:
    """Read-only connection, or None if the database does not exist.

    mode=ro makes accidental writes an error rather than a silent success.
    A missing database is normal -- a fresh clone has none of them, since
    *.db is gitignored -- so it degrades to "no snapshot" instead of failing.
    """
    if not path.exists():
        return None
    return sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)


def _counts(cur, table: str, column: str) -> dict:
    return {
        str(row[0]): row[1]
        for row in cur.execute(
            f"SELECT {column}, COUNT(*) FROM {table} GROUP BY 1 ORDER BY 2 DESC"
        )
    }


def _classify_awaiting(cur, awaiting_ids: list[str], now: datetime) -> dict:
    """Why each AWAITING_STEP_UP payment is still waiting, read-only.

    The count alone misleads: a payment whose challenge expired days ago is
    not waiting on anyone. This mirrors the classification
    step_up.service.expire_stale() applies when atlas_service next starts --
    without calling it, because that function writes. Every kind except
    "live" is settled to DENIED at that start.
    """
    kinds = {"live": 0, "expired": 0, "no_challenge": 0, "consumed_not_advanced": 0}
    for txn_id in awaiting_ids:
        row = cur.execute(
            "SELECT consumed, expires_at FROM step_up_challenges WHERE transaction_id = ?",
            (txn_id,),
        ).fetchone()
        if row is None:
            kinds["no_challenge"] += 1
        elif row[0]:
            kinds["consumed_not_advanced"] += 1
        elif now >= datetime.fromisoformat(row[1]):
            kinds["expired"] += 1
        else:
            kinds["live"] += 1
    return kinds


def collect_snapshot(warnings: list[str], now: datetime) -> dict:
    snap: dict = {"available": False}

    conn = _ro(TXN_DB)
    if conn is None:
        warnings.append("no transaction database on this machine; snapshot omitted")
        return snap
    cur = conn.cursor()
    total, first, last, subjects = cur.execute(
        "SELECT COUNT(*), MIN(created_at), MAX(created_at), COUNT(DISTINCT subject) "
        "FROM transactions"
    ).fetchone()
    lo, hi = cur.execute(
        "SELECT MIN(CAST(amount AS REAL)), MAX(CAST(amount AS REAL)) FROM transactions"
    ).fetchone()
    snap["transactions"] = {
        "total": total,
        "by_state": _counts(cur, "transactions", "state"),
        "first_seen": first,
        "last_seen": last,
        "distinct_subjects": subjects,
        "amount_min": lo,
        "amount_max": hi,
    }
    awaiting_ids = [
        row[0] for row in cur.execute(
            "SELECT transaction_id FROM transactions WHERE state = 'AWAITING_STEP_UP'"
        )
    ]
    conn.close()
    snap["available"] = True

    conn = _ro(STEP_UP_DB)
    if conn is not None:
        cur = conn.cursor()
        challenges = cur.execute("SELECT COUNT(*) FROM step_up_challenges").fetchone()[0]
        outcomes = {
            (row[0] or "UNRESOLVED"): row[1]
            for row in cur.execute(
                "SELECT outcome, COUNT(*) FROM step_up_challenges GROUP BY 1"
            )
        }
        open_count = cur.execute(
            "SELECT COUNT(*) FROM step_up_challenges WHERE consumed = 0"
        ).fetchone()[0]
        unconsumed_expired = sum(
            1
            for (expires_at,) in cur.execute(
                "SELECT expires_at FROM step_up_challenges WHERE consumed = 0"
            ).fetchall()
            if now >= datetime.fromisoformat(expires_at)
        )
        snap["step_up"] = {
            "challenges": challenges,
            "by_outcome": outcomes,
            "unconsumed": open_count,
            "unconsumed_expired": unconsumed_expired,
            "awaiting": _classify_awaiting(cur, awaiting_ids, now),
            "events": _counts(cur, "step_up_events", "event"),
            "authenticators_enrolled": cur.execute(
                "SELECT COUNT(*) FROM step_up_authenticators"
            ).fetchone()[0],
        }
        conn.close()
    else:
        # Said, not silently skipped: without it the page just loses a section.
        warnings.append("no step-up database on this machine; step-up figures omitted")

    conn = _ro(DEVICE_DB)
    if conn is not None:
        cur = conn.cursor()
        # Aggregates only. Individual device_key_id / public_key values are
        # deliberately NOT exported: they are public identifiers rather than
        # secrets, but a published page has no use for them and the safest
        # export is the one that cannot be misread as a credential dump.
        snap["devices"] = {
            "total": cur.execute("SELECT COUNT(*) FROM devices").fetchone()[0],
            "by_status": _counts(cur, "devices", "status"),
            "by_provisioning_mode": _counts(cur, "devices", "provisioning_mode"),
            "with_secure_element": cur.execute(
                "SELECT COUNT(*) FROM devices WHERE secure_element_present = 1"
            ).fetchone()[0],
            "firmware_versions": sorted(
                r[0] for r in cur.execute(
                    "SELECT DISTINCT firmware_version FROM devices "
                    "WHERE firmware_version IS NOT NULL"
                )
            ),
        }
        conn.close()
    else:
        warnings.append("no device database on this machine; device registry omitted")

    conn = _ro(BANK_DB)
    if conn is not None:
        cur = conn.cursor()
        snap["bank"] = {
            "consumed_assertions": cur.execute(
                "SELECT COUNT(*) FROM consumed_assertions"
            ).fetchone()[0]
        }
        conn.close()
    else:
        warnings.append("no bank replay database on this machine; verified-assertion count omitted")

    return snap


# --------------------------------------------------------------------------
# B. Sweep -- the real pipeline, isolated stores
# --------------------------------------------------------------------------

def _scenarios(known_beneficiary: str) -> list[dict]:
    """README.md's Results table, expressed as inputs.

    Three amounts against two local times, plus the same baseline payment sent
    over the second rail so the dashboard can show that one signed decision
    frames into two rail shapes without the assertion changing.
    """
    morning = "2026-09-17T10:00:00+05:30"
    late_night = "2026-09-17T23:30:00+05:30"
    rows = []
    # Each scenario that is ABOUT a new payee gets its OWN unseen payee. Since
    # 2026-09-23 the decision reads real history, so a shared name would be new for
    # the first scenario and familiar for the rest -- correct behaviour, but it would
    # make every later row's "new payee" label a lie.
    unseen = 0
    for label, amount, ben, new in (
        ("Everyday payment", "1500.00", known_beneficiary, False),
        ("Large amount", "60000.00", None, True),
        ("Over the hard cap", "150000.00", None, True),
    ):
        for when, when_label in ((morning, "10:00 IST"), (late_night, "23:30 IST")):
            if new:
                unseen += 1
                payee = f"ben-unseen-vendor-{unseen:02d}"
            else:
                payee = ben
            rows.append({
                "label": label, "amount": amount, "beneficiary": payee,
                "is_new_beneficiary": new, "timestamp": when,
                "local_time": when_label, "rail": "UPI",
            })
    rows.append({
        "label": "Everyday payment, second rail", "amount": "1500.00",
        "beneficiary": known_beneficiary, "is_new_beneficiary": False,
        "timestamp": morning, "local_time": "10:00 IST", "rail": "PIX",
    })
    return rows


def run_sweep(warnings: list[str]) -> dict:
    """Drives both real services over the SIGNED path. Never touches the live
    databases.

    Every scenario is a DeviceEnvelope signed by a throwaway device key and
    posted to /v2/transact, the authoritative path: device authentication, then
    the unchanged decision pipeline. Until 2026-09-18 the sweep posted bare
    transactions to the legacy unsigned /transact, which D5 closed by default --
    a dashboard demonstrating the pipeline should demonstrate the path the
    firmware actually uses, not the one being retired.
    """
    from fastapi.testclient import TestClient

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
    from atlas_service.policy.version_store import PolicyVersionStore
    from atlas_service.policy.engine import POLICIES_DIR
    from atlas_service.step_up.db import StepUpStore
    from bank_service.main import app as bank_app
    from bank_service.main import get_atlas_public_key, get_replay_cache
    from bank_service.replay_cache import ReplayCache
    from firmware import device_identity, virtual_device as vd

    subject = "user-demo-1"
    # Ask the service's OWN history generator which beneficiary is genuinely
    # familiar, rather than hardcoding a name and hoping. The policy engine
    # recomputes is_new_beneficiary from history and never trusts the client,
    # so a guess here would silently turn the baseline ALLOW into a STEP_UP.
    history = model_registry.training_history(subject)
    known = Counter(t.beneficiary for t in history).most_common(1)[0][0]
    scenarios = _scenarios(known)

    rows: list[dict] = []
    # mkdtemp and an explicit finally rather than TemporaryDirectory. On Windows
    # rmtree fails on any SQLite file still held open, and a context manager
    # either raises -- taking a successful sweep down with it -- or, told to
    # ignore cleanup errors, leaves the directory behind without a word. Here
    # every handle is closed first, and anything that still survives is reported.
    tmp_path = Path(tempfile.mkdtemp(prefix="atlas-dash-"))
    opened: list = []
    atlas = bank = None
    # The bank's durable ledger is not a FastAPI dependency: bank_service/db.py reads
    # DEFAULT_DB_PATH at call time. Left alone it is the LIVE bank_ledger.db, and it
    # was, from 2026-09-22 to 2026-09-25 -- every approved scenario recorded its
    # outcome there. Redirected for the sweep and put back in the finally.
    from bank_service import db as bank_db
    live_ledger_path = bank_db.DEFAULT_DB_PATH
    bank_db.DEFAULT_DB_PATH = tmp_path / "bank_ledger.db"
    try:
        keys_dir = tmp_path / "keys"
        crypto.init_device(keys_dir=keys_dir)

        # The explicit training step, into the throwaway folder: the service's
        # own artifacts are never read or written by an export, and the sweep's
        # requests then only infer -- the same lifecycle the service follows.
        models = tmp_path / "models"
        model_registry.save(model_registry.train_subject(subject), models)
        sweep_registry = model_registry.ModelRegistry(models)

        # Mirrors tests/conftest.py's wire_bank_app_to_keys() -- inlined so a
        # script in scripts/ does not import from tests/.
        bank_app.dependency_overrides[get_atlas_public_key] = (
            lambda: crypto.get_public_key(keys_dir=keys_dir)
        )

        # Each request builds its own store, so each request opens another
        # SQLite connection. Every one is tracked and closed in the finally.
        def _replay_cache() -> ReplayCache:
            cache = ReplayCache(tmp_path / "replay.db")
            opened.append(cache)
            return cache

        def _txn_store() -> TransactionStore:
            store = TransactionStore(tmp_path / "atlas.db")
            opened.append(store)
            return store

        def _device_store() -> DeviceStore:
            store = DeviceStore(tmp_path / "devices.db")
            opened.append(store)
            return store

        def _step_up_store() -> StepUpStore:
            # /v2/transact resolves this on every request, used or not. Left at
            # its default it would be the live atlas_step_up.db.
            store = StepUpStore(tmp_path / "step_up.db")
            opened.append(store)
            return store

        bank_app.dependency_overrides[get_replay_cache] = _replay_cache

        # Neither TestClient is entered as a context manager, and that is
        # load-bearing. Entering one runs the app's lifespan, and atlas_service's
        # startup hook WRITES: it publishes the signing public key and settles
        # stale step-ups in the live databases (resolve_stale_step_ups). A plain
        # TestClient(...) never starts the lifespan.
        bank = TestClient(bank_app)
        atlas_app.dependency_overrides[get_bank_client] = lambda: bank
        atlas_app.dependency_overrides[get_signing_keys_dir] = lambda: keys_dir
        atlas_app.dependency_overrides[get_transaction_store] = _txn_store
        atlas_app.dependency_overrides[get_device_store] = _device_store
        atlas_app.dependency_overrides[get_step_up_store] = _step_up_store
        atlas_app.dependency_overrides[get_allow_counter_reset] = lambda: False
        atlas_app.dependency_overrides[get_model_registry] = lambda: sweep_registry
        # The policy non-rollback record (2026-09-25). Left at its default it would
        # create the live atlas_policy_state.db.
        policy_versions = PolicyVersionStore(tmp_path / "policy_state.db")
        opened.append(policy_versions)
        # Every policy must carry its owner's signature (2026-09-27). The sweep
        # enrols the owner keys committed beside the policies, into its own store.
        for pub in sorted(POLICIES_DIR.glob("*.pub")):
            policy_versions.enroll_owner(pub.stem, pub.read_text(encoding="ascii").strip())
        atlas_app.dependency_overrides[get_policy_version_store] = lambda: policy_versions
        atlas = TestClient(atlas_app)

        # A throwaway device, enrolled in the throwaway registry. Its device_id
        # is the one the demo history already knows, so is_new_device stays
        # false and the evidence is the evidence the scenarios are about.
        device_keys = tmp_path / "device-keys"
        device_identity.init_device(device_keys)
        register_demo_device(
            _device_store(),
            device_id=DEMO_DEVICE_ID,
            device_key_id=device_identity.get_key_id(device_keys),
            public_key=device_identity.get_public_key(device_keys),
            bound_subject=subject,
        )
        config = vd.DeviceConfig(device_id=DEMO_DEVICE_ID, subject=subject,
                                 location="Hyderabad,IN", authentication_method="pin")

        # Since 2026-09-23 a decision reads the SUBJECT'S OWN persisted payments, so a
        # scenario labelled "existing beneficiary" is only true if this subject really
        # has paid them. These warm-up payments create that history the same way any
        # other payment does -- signed, through /v2/transact -- rather than pre-loading
        # rows or falling back to the generated history. They are not scenarios and are
        # not reported; they are this customer's past.
        warm_up_days = 3
        for w in range(warm_up_days):
            when = f"2026-09-{14 + w:02d}T10:00:00+05:30"
            warm_body = {
                "transaction_id": f"dash-history-{w:02d}", "subject": subject,
                "amount": "1500.00", "currency": "INR", "beneficiary": known,
                "location": "Hyderabad,IN", "device_id": DEMO_DEVICE_ID,
                "merchant_category": "transfer", "authentication_method": "pin",
                "is_new_beneficiary": False, "is_new_device": False,
                "is_international": False, "declared_travel_mode": False,
                "is_emergency_request": False, "timestamp": when,
            }
            atlas.post("/v2/transact",
                       json=vd.build_envelope(warm_body, config, device_keys, counter=w + 1),
                       params={"rail": "UPI"})

        for i, sc in enumerate(scenarios):
            body = {
                "transaction_id": f"dash-{i:02d}-{sc['rail'].lower()}",
                "subject": subject,
                "amount": sc["amount"],
                "currency": "INR",
                "beneficiary": sc["beneficiary"],
                "location": "Hyderabad,IN",
                "device_id": DEMO_DEVICE_ID,
                "merchant_category": "transfer",
                "authentication_method": "pin",
                "is_new_beneficiary": sc["is_new_beneficiary"],
                "is_new_device": False,
                "is_international": False,
                "declared_travel_mode": False,
                "is_emergency_request": False,
                "timestamp": sc["timestamp"],
            }
            envelope = vd.build_envelope(body, config, device_keys,
                                         counter=warm_up_days + i + 1)
            started = time.perf_counter()
            resp = atlas.post("/v2/transact", json=envelope, params={"rail": sc["rail"]})
            elapsed_ms = (time.perf_counter() - started) * 1000
            if resp.status_code != 200:
                warnings.append(
                    f"scenario {sc['label']} ({sc['local_time']}, {sc['rail']}) "
                    f"returned HTTP {resp.status_code}"
                )
                continue
            row = _row(sc, resp.json())
            row["elapsed_ms"] = round(elapsed_ms, 1)

            # Per-transaction replay status (Step 9's measurement set): send the
            # very same signed envelope again and record what stopped it. Three
            # independent defences could: the device counter, the nonce, and the
            # transaction_id. Whichever answers first, the answer must not be a
            # second approval.
            replay = atlas.post("/v2/transact", json=envelope, params={"rail": sc["rail"]})
            replayed = replay.json() if replay.status_code == 200 else {}
            row["replay"] = {
                "final_status": replayed.get("final_status"),
                "decision_reason": replayed.get("decision_reason"),
                "refused": replayed.get("final_status") not in ("ALLOW", None),
            }
            if not row["replay"]["refused"]:
                warnings.append(
                    f"replaying {sc['label']} ({sc['local_time']}, {sc['rail']}) was not refused"
                )
            rows.append(row)
    finally:
        bank_db.DEFAULT_DB_PATH = live_ledger_path
        atlas_app.dependency_overrides.clear()
        bank_app.dependency_overrides.clear()
        for client in (atlas, bank):
            if client is not None:
                client.close()
        for handle in opened:
            try:
                handle.close()
            except Exception:  # noqa: BLE001 -- tidy-up must not mask results
                pass
        shutil.rmtree(tmp_path, ignore_errors=True)
        if tmp_path.exists():
            print(f"[export] could not remove {tmp_path}")
            warnings.append(
                "the sweep's temporary directory could not be removed; it holds "
                "only throwaway stores and a throwaway signing key"
            )

    return {
        "available": bool(rows),
        "ran_at_utc": datetime.now(timezone.utc).isoformat(),
        "known_beneficiary": known,
        "scenarios_attempted": len(scenarios),
        "rows": rows,
    }


def _row(scenario: dict, out: dict) -> dict:
    """Flattens one /transact response into what the dashboard renders.

    The signature itself is reduced to present/absent and a length. A reader
    needs to know an assertion was genuinely signed; nobody needs the bytes.
    """
    risk = out.get("risk") or {}
    decision = out.get("decision") or {}
    assertion = out.get("assertion") or {}
    payload = assertion.get("payload") or {}
    verdict = out.get("bank_verdict") or {}
    rail_payload = out.get("rail_payload") or {}

    return {
        "label": scenario["label"],
        "amount": scenario["amount"],
        "local_time": scenario["local_time"],
        "beneficiary_is_new": scenario["is_new_beneficiary"],
        "rail": out.get("rail"),
        "final_status": out.get("final_status"),
        "decision_reason": out.get("decision_reason"),
        "policy": {
            "decision": decision.get("decision"),
            "deciding_rule": decision.get("deciding_rule"),
            "matched_rules": decision.get("matched_rules", []),
            "version": decision.get("policy_version"),
            "hash_prefix": (decision.get("policy_hash") or "")[:12],
        },
        "ml": {
            "risk_band": risk.get("risk_band"),
            "anomaly_score": (
                round(risk["anomaly_score"], 4) if risk.get("anomaly_score") is not None else None
            ),
            "reasons": risk.get("reasons", []),
            # The separate burst evidence (2026-09-26); None when the ML layer did
            # not operate, which is every sweep scenario (they have < 200 payments).
            "range_signal": risk.get("range_signal"),
        },
        "crypto": {
            "assertion_signed": bool(assertion.get("signature")),
            "signature_hex_len": len(assertion.get("signature") or ""),
            "nonce_present": bool(payload.get("nonce")),
            "issued_at": payload.get("issued_at"),
            "expires_at": payload.get("expires_at"),
            "key_id": payload.get("atlas_key_id"),
        },
        "bank": {
            "contacted": bool(verdict),
            "approved": verdict.get("approved"),
            "reason": verdict.get("reason"),
        },
        "rail_payload_fields": sorted(rail_payload.keys()) if rail_payload else [],
    }


# --------------------------------------------------------------------------
# C. Measurements
# --------------------------------------------------------------------------

def _parse_pytest_summary(stdout: str, returncode: int) -> dict | None:
    """Counts from pytest -q's closing summary line, or None if there is none.

    A run counts as passing only when pytest exited 0 AND the summary shows no
    failures and no errors. A collection error can leave "N passed" on that
    line while the run as a whole failed, so the passed count alone is never
    trusted.
    """
    summary = next(
        (
            line for line in reversed(stdout.splitlines())
            if re.search(r"\b\d+ (passed|failed|errors?)\b", line)
        ),
        None,
    )
    if summary is None:
        return None

    def count(word: str) -> int:
        match = re.search(rf"\b(\d+) {word}\b", summary)
        return int(match.group(1)) if match else 0

    failed, errors = count("failed"), count("errors?")
    return {
        "total": count("passed"),
        "failed_count": failed,
        "error_count": errors,
        "returncode": returncode,
        "failed": returncode != 0 or failed > 0 or errors > 0,
    }


def _evaluate_ml(warnings: list[str]) -> dict:
    """Precision, recall and latency for the anomaly model (D4, 2026-09-18).

    Runs scripts/evaluate_ml.py in this process. Read that file before quoting
    a number from it: both classes come from the same synthetic generator, so
    it measures separation on generated data, never fraud detection.
    """
    try:
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "atlas_evaluate_ml", Path(__file__).resolve().parent / "evaluate_ml.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return {**module.evaluate(), "method": "measured by this export"}
    except Exception as exc:  # noqa: BLE001 -- reported, never silently dropped
        warnings.append(f"the ML evaluation did not run: {type(exc).__name__}: {exc}")
        return {"method": "did not run in this export"}


def _public_benchmark(warnings: list[str]) -> dict:
    """The independent public-dataset benchmark, as RECORDED by
    scripts/benchmark_public_dataset.py (it downloads a 66 MB dataset, so the
    export reads its saved aggregate figures instead of re-running it)."""
    path = ATLAS_ROOT / "docs" / "ml-public-benchmark.json"
    if not path.exists():
        return {"method": "not recorded"}
    try:
        saved = json.loads(path.read_text(encoding="utf-8"))
        test = saved["results"]["test"]
        return {
            "method": "recorded",
            "dataset": saved["dataset"]["name"],
            "rows": saved["dataset"]["rows"], "frauds": saved["dataset"]["frauds"],
            "benchmarked": saved["benchmarked"],
            "roc_auc": test["roc_auc"], "average_precision": test["average_precision"],
            "at_medium_and_above": test["at_medium_and_above"], "at_high_only": test["at_high_only"],
            "source": f"{saved['measured_by']} on {saved['measured_at_utc'][:10]} — {RECORDED}",
        }
    except (ValueError, KeyError) as exc:
        warnings.append(f"docs/ml-public-benchmark.json is unreadable: {type(exc).__name__}")
        return {"method": "unreadable"}


def _real_data(warnings: list[str]) -> dict:
    """ATLAS's own ML layer on real bank customers (2026-09-29), as RECORDED by
    scripts/evaluate_real_data.py: false alarms on ordinary payments, not fraud
    detection. The dataset stays outside the repository, so the export reads the
    saved aggregate figures instead of re-running it."""
    path = ATLAS_ROOT / "docs" / "ml-real-data.json"
    if not path.exists():
        return {"method": "not recorded"}
    try:
        saved = json.loads(path.read_text(encoding="utf-8"))
        return {
            "method": "recorded",
            "dataset": saved["dataset"]["name"],
            "what_it_measures": saved["what_it_measures"],
            "accounts": saved["accounts"], "test_payments": saved["test_payments"],
            "by_history_size": saved["by_history_size"],
            "burst_signal": saved["burst_signal"],
            "constant_features": saved["constant_features"],
            "source": f"scripts/evaluate_real_data.py on {saved['measured_at_utc'][:10]} — {RECORDED}",
        }
    except (ValueError, KeyError) as exc:
        warnings.append(f"docs/ml-real-data.json is unreadable: {type(exc).__name__}")
        return {"method": "unreadable"}


def collect_measurements(run_tests: bool, warnings: list[str]) -> dict:
    """Numbers that describe the build rather than any one transaction."""
    tests: dict = {"total": None, "method": "not run in this export"}
    if run_tests:
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", "-q"],
            cwd=ATLAS_ROOT, capture_output=True, text=True,
        )
        parsed = _parse_pytest_summary(proc.stdout, proc.returncode)
        if parsed is None:
            warnings.append(
                f"the test run printed no summary (pytest exit status {proc.returncode})"
            )
            parsed = {
                "total": None, "failed_count": None, "error_count": None,
                "returncode": proc.returncode, "failed": True,
            }
        elif parsed["failed"]:
            warnings.append(
                f"the test run did not pass: {parsed['total']} passed, "
                f"{parsed['failed_count']} failed, {parsed['error_count']} errors "
                f"(pytest exit status {parsed['returncode']})"
            )
        tests = {
            **parsed,
            "method": "executed by this export",
            "ran_at_utc": datetime.now(timezone.utc).isoformat(),
        }

    return {
        "tests": tests,
        # Measured when the suite runs, because the evaluation takes about as
        # long as the suite itself. Without --run-tests the page says so rather
        # than repeating an older number as if it were fresh.
        "ml": _evaluate_ml(warnings) if run_tests else {"method": "not run in this export"},
        "ml_public_benchmark": _public_benchmark(warnings),
        "ml_real_data": _real_data(warnings),
        "firmware": {
            # Built from the sketch with secrets.example.h and atlas_ca.example.h,
            # so anyone can reproduce it. 2026-09-29: with the HTTPS client, 1175976
            # bytes -- smaller than the plain-HTTP build (1176472), because the
            # ESP32 core already linked its TLS code.
            "build_bytes": 1175976,
            "flash_percent": 89,
            "canonical_envelope_bytes": 605,
            "parity_tests": 20,
            "note": "built locally with arduino-cli, HTTPS client included; the Wokwi runs on record are of the earlier plain-HTTP build, this one is pending",
            "source": ("built and re-measured on 2026-09-29 by "
                       "tests/test_firmware_behaviour.py::test_the_sketch_compiles "
                       f"(arduino-cli, {FQBN_NOTE}) — {RECORDED}"),
        },
        "step_up_device_checks": {
            "observed": 10,
            "total": 10,
            "source": ("Wokwi runs on the real firmware (the earlier plain-HTTP build): 7 checks on 2026-09-11 (boot, preset, "
                       "AWAITING_STEP_UP, the device's step-up block, the challenge id matching "
                       "the database, the audited counter reset, device/backend agreement) and "
                       "the three approve-path checks on 2026-09-23 — proof accepted, resolved "
                       f"to ALLOW, completed to CONFIRMED — {RECORDED}"),
        },
        "mutation_checks": {
            "step_up_restart_cleanup": {
                "introduced": 10,
                "caught": 10,
                "source": f"docs/ATLAS-Blueprint.md §17 — {RECORDED}",
            },
            "hardening_pass_2026_09_23": {
                "introduced": 15,
                "caught": 15,
                "source": ("the controls added on 2026-09-22 (key protection, the model "
                           "registry, TLS and mutual TLS, bank reply validation, the durable "
                           "bank ledger, the legacy-path lockdown, the request size cap and "
                           "the malformed-request handler); 13 were caught at once and the "
                           "2 survivors were holes in the suite, closed by 2 new tests and a "
                           f"strengthened one before all 15 were caught — {RECORDED}"),
            },
        },
    }


# --------------------------------------------------------------------------

def _scrub(text: str) -> str:
    """Keeps this machine's account path out of a page meant to be published.

    Warnings are embedded in index.html, and an exception message can carry an
    absolute path -- the first export run's did.
    """
    home = str(Path.home())
    for form in (home.replace("\\", "\\\\"), home, home.replace("\\", "/")):
        text = text.replace(form, "~")
    return text


def _shown(path: Path) -> str:
    """A path relative to the repository when it lies inside it."""
    try:
        return str(path.resolve().relative_to(ATLAS_ROOT))
    except ValueError:
        return str(path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--run-tests", action="store_true",
        help="execute the full suite and record the observed count",
    )
    parser.add_argument("--out", type=Path, default=OUT_PATH)
    args = parser.parse_args()

    warnings: list[str] = []
    failures: list[str] = []
    now = datetime.now(timezone.utc)

    print("[export] reading live databases (read-only)")
    snapshot = collect_snapshot(warnings, now)

    print("[export] running scenario sweep through both services (temporary stores)")
    try:
        sweep = run_sweep(warnings)
    except Exception as exc:  # noqa: BLE001 -- recorded and failed below, never passed off
        warnings.append(f"scenario sweep failed: {type(exc).__name__}: {exc}")
        sweep = {"available": False, "rows": []}
    made, attempted = len(sweep.get("rows", [])), sweep.get("scenarios_attempted")
    if not sweep.get("available"):
        failures.append("the scenario sweep produced no rows")
    elif attempted is not None and made < attempted:
        failures.append(f"the scenario sweep produced {made} of {attempted} rows")

    if args.run_tests:
        print("[export] running the full test suite")
    measurements = collect_measurements(args.run_tests, warnings)
    if measurements["tests"].get("failed"):
        failures.append("the test run did not pass")

    data = {
        "exported_at_utc": now.isoformat(),
        "exported_at_ist": now.astimezone(IST).isoformat(),
        "generator": "scripts/export_dashboard_data.py",
        "is_live": False,
        "provenance": (
            "Read-only snapshot of the local databases, plus a deterministic re-run "
            "of the documented scenarios through both services on temporary stores. "
            "Not a live feed: ATLAS runs on loopback and is never exposed publicly."
        ),
        "snapshot": snapshot,
        "sweep": sweep,
        "measurements": measurements,
        "warnings": [_scrub(w) for w in warnings],
    }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    body = json.dumps(data, indent=2, ensure_ascii=False)
    args.out.write_text(body + "\n", encoding="utf-8")
    print(f"[export] wrote {_shown(args.out)}")

    # The page carries its own data. index.html holds a JSON island that this
    # rewrites in place, which keeps the published dashboard a SINGLE
    # self-contained file: no fetch() (CORS-blocked when the page is opened off
    # disk) and no relative <script src> (unresolvable when a viewer or tool
    # renders the page from a data: URL). Only the island is touched; every
    # hand-written line around it survives regeneration. The .json stays as
    # the artifact worth reading and diffing.
    page = args.out.parent / "index.html"
    page_updated = False
    if not page.exists():
        warnings.append(f"{_shown(page)} not found; only the JSON was written")
    else:
        original = page.read_text(encoding="utf-8")
        start = '<script id="atlas-data" type="application/json">'
        i = original.find(start)
        j = original.find("</script>", i) if i != -1 else -1
        if i == -1 or j == -1:
            warnings.append(f"{_shown(page)} has no atlas-data island; page not updated")
        else:
            # "</" cannot appear raw inside a <script> block or it ends the
            # element early. "<\/" is valid JSON and parses back identically.
            page.write_text(
                original[: i + len(start)] + body.replace("</", "<\\/") + original[j:],
                encoding="utf-8",
            )
            page_updated = True
            print(f"[export] updated {_shown(page)}")
    if not page_updated:
        failures.append("index.html was not updated, so the page does not match the JSON")

    for w in warnings:
        print(f"[export] WARNING: {w}")
    if failures:
        print("[export] FAILED: " + "; ".join(failures))
        return 1
    print("[export] OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
