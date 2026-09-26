"""scripts/export_dashboard_data.py -- the Step 9 dashboard exporter.

The exporter reads the live databases and writes into docs/, so every test here
is built to touch neither. Databases are created in tmp_path by the real store
classes, so their schemas are the real ones; the exporter's database paths are
pointed at those copies; pages are written to tmp_path; and the one test that
drives both real services redirects every default store path and then proves
that none of those files was ever created.

What is pinned, and why each matters:
  - the snapshot is read-only, and it says WHY a payment is still waiting;
  - a row keeps the evidence and drops the signature bytes;
  - pytest's summary is trusted only when the run itself passed;
  - a crashed or partial sweep, a failing test run, or a page that could not be
    updated exits 1 -- never a quiet 0;
  - a published warning cannot close the page's data island early, and carries
    no home-folder path;
  - the sweep uses temporary stores only, and removes them or says it could not.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import sqlite3
import sys
import tempfile
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

ATLAS_ROOT = Path(__file__).resolve().parent.parent
EXPORTER = ATLAS_ROOT / "scripts" / "export_dashboard_data.py"
ISLAND = '<script id="atlas-data" type="application/json">'
MINIMAL_PAGE = f'<html><body>{ISLAND}{{}}</script><p id="tail">tail</p></body></html>'

#: README.md's Results table, in the order the exporter runs it.
DOCUMENTED_OUTCOMES = ["ALLOW", "STEP_UP", "STEP_UP", "STEP_UP", "DENY", "DENY", "ALLOW"]
DOCUMENTED_RULES = [None, "odd_hours", "large_amount", "large_amount", "hard_cap", "hard_cap", None]


@pytest.fixture(scope="module")
def ex():
    spec = importlib.util.spec_from_file_location("export_dashboard_data", EXPORTER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _insert(path: Path, sql: str, rows: list[tuple]) -> None:
    with closing(sqlite3.connect(path)) as conn:
        conn.executemany(sql, rows)
        conn.commit()


# ==========================================================================
# A. Snapshot of the databases
# ==========================================================================


@pytest.fixture
def databases(tmp_path):
    """Four databases shaped exactly like the live ones, with known contents."""
    from atlas_service.db import TransactionStore
    from atlas_service.device.db import DeviceStore
    from atlas_service.step_up.db import StepUpStore
    from bank_service.replay_cache import ReplayCache

    now = datetime.now(timezone.utc)
    paths = {
        "TXN_DB": tmp_path / "atlas_transactions.db",
        "STEP_UP_DB": tmp_path / "atlas_step_up.db",
        "DEVICE_DB": tmp_path / "atlas_devices.db",
        "BANK_DB": tmp_path / "bank_replay_cache.db",
    }
    for store, name in ((TransactionStore, "TXN_DB"), (StepUpStore, "STEP_UP_DB"),
                        (DeviceStore, "DEVICE_DB"), (ReplayCache, "BANK_DB")):
        store(paths[name]).close()  # the real classes create the real schemas

    t = now.isoformat()
    past = (now - timedelta(minutes=10)).isoformat()
    future = (now + timedelta(minutes=10)).isoformat()
    _insert(paths["TXN_DB"], "INSERT INTO transactions (transaction_id, subject, amount, "
                             "state, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)", [
        ("t-confirmed", "user-demo-1", "1500.00", "CONFIRMED", t, t),
        ("t-denied", "user-demo-1", "150000.00", "DENIED", t, t),
        ("t-live", "user-demo-1", "60000.00", "AWAITING_STEP_UP", t, t),
        ("t-expired", "user-demo-1", "60000.00", "AWAITING_STEP_UP", t, t),
        ("t-expired-2", "user-demo-1", "60000.00", "AWAITING_STEP_UP", t, t),
        ("t-no-challenge", "user-demo-1", "60000.00", "AWAITING_STEP_UP", t, t),
        ("t-consumed", "user-demo-1", "60000.00", "AWAITING_STEP_UP", t, t),
    ])
    _insert(
        paths["STEP_UP_DB"],
        "INSERT INTO step_up_challenges (challenge_id, transaction_id, subject, envelope_hash, "
        "context_json, issued_at, expires_at, attempt_count, consumed, outcome) "
        "VALUES (?, ?, 'user-demo-1', 'h', '{}', ?, ?, ?, ?, ?)",
        [
            ("c-live", "t-live", t, future, 0, 0, None),
            ("c-expired", "t-expired", past, past, 1, 0, None),
            # Two expired against one live, so a comparison that swapped the two
            # labels could not produce the same counts.
            ("c-expired-2", "t-expired-2", past, past, 0, 0, None),
            ("c-consumed", "t-consumed", t, future, 1, 1, "ALLOW"),
        ],
    )
    _insert(
        paths["STEP_UP_DB"],
        "INSERT INTO step_up_events (challenge_id, transaction_id, event, detail, occurred_at) "
        "VALUES (?, ?, ?, '', ?)",
        [
            ("c-live", "t-live", "CHALLENGE_ISSUED", t),
            ("c-expired", "t-expired", "CHALLENGE_ISSUED", t),
            ("c-expired", "t-expired", "INVALID_PROOF", t),
        ],
    )
    _insert(
        paths["DEVICE_DB"],
        "INSERT INTO devices (device_id, device_key_id, public_key, bound_subject, status, "
        "firmware_version, created_at) VALUES (?, ?, ?, 'user-demo-1', ?, ?, ?)",
        [
            ("dev-a", "key-a", "aa" * 32, "ACTIVE", "0.5.0", t),
            ("dev-b", "key-b", "bb" * 32, "REVOKED", "0.4.0", t),
        ],
    )
    _insert(paths["BANK_DB"], "INSERT INTO consumed_assertions VALUES (?, ?, ?)", [
        ("t-confirmed", "n1", t), ("t-other", "n2", t),
    ])
    return now, paths


def test_snapshot_counts_what_the_databases_hold_and_writes_nothing(ex, databases, monkeypatch):
    now, paths = databases
    for name, path in paths.items():
        monkeypatch.setattr(ex, name, path)
    before = {name: _sha(path) for name, path in paths.items()}
    warnings: list[str] = []

    snap = ex.collect_snapshot(warnings, now)

    assert warnings == []
    assert snap["available"] is True
    assert snap["transactions"]["total"] == 7
    assert snap["transactions"]["by_state"] == {"AWAITING_STEP_UP": 5, "CONFIRMED": 1, "DENIED": 1}
    step_up = snap["step_up"]
    assert step_up["challenges"] == 4
    assert step_up["by_outcome"] == {"UNRESOLVED": 3, "ALLOW": 1}
    assert (step_up["unconsumed"], step_up["unconsumed_expired"]) == (3, 2)
    assert step_up["events"] == {"CHALLENGE_ISSUED": 2, "INVALID_PROOF": 1}
    assert step_up["authenticators_enrolled"] == 0
    assert snap["devices"]["total"] == 2
    assert snap["devices"]["by_status"] == {"ACTIVE": 1, "REVOKED": 1}
    assert snap["devices"]["firmware_versions"] == ["0.4.0", "0.5.0"]
    assert snap["devices"]["with_secure_element"] == 0
    assert snap["bank"] == {"consumed_assertions": 2}
    assert {name: _sha(path) for name, path in paths.items()} == before, (
        "taking the snapshot changed a database"
    )


def test_a_waiting_payment_is_classified_by_why_it_is_waiting(ex, databases, monkeypatch):
    """Only a live challenge waits on a person. Expired, missing and
    consumed-but-not-advanced challenges are all settled to DENIED the next time
    atlas_service starts -- which is what the dashboard has to say, instead of
    'waiting on a human'."""
    now, paths = databases
    for name, path in paths.items():
        monkeypatch.setattr(ex, name, path)

    snap = ex.collect_snapshot([], now)

    assert snap["step_up"]["awaiting"] == {
        "live": 1, "expired": 2, "no_challenge": 1, "consumed_not_advanced": 1,
    }


def test_databases_are_opened_read_only(ex, databases):
    _, paths = databases
    with closing(ex._ro(paths["TXN_DB"])) as conn:
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            conn.execute("DELETE FROM transactions")


def test_a_clone_without_databases_gets_a_warning_and_no_new_file(ex, tmp_path, monkeypatch):
    absent = tmp_path / "absent.db"
    monkeypatch.setattr(ex, "TXN_DB", absent)
    warnings: list[str] = []

    assert ex.collect_snapshot(warnings, datetime.now(timezone.utc)) == {"available": False}
    assert warnings == ["no transaction database on this machine; snapshot omitted"]
    assert not absent.exists(), "opening a missing database created one"


@pytest.mark.parametrize("missing,section,warning", [
    ("STEP_UP_DB", "step_up", "no step-up database on this machine; step-up figures omitted"),
    ("DEVICE_DB", "devices", "no device database on this machine; device registry omitted"),
    ("BANK_DB", "bank",
     "no bank replay database on this machine; verified-assertion count omitted"),
])
def test_a_missing_second_database_is_warned_about_not_silently_dropped(
    ex, databases, tmp_path, monkeypatch, missing, section, warning
):
    """The page renders a section only when its figures exist. Before
    2026-09-17 a missing step-up, device or bank database dropped its section
    with no warning at all, so the page looked complete when it was not."""
    now, paths = databases
    for name, path in paths.items():
        monkeypatch.setattr(ex, name, path)
    absent = tmp_path / "absent.db"
    monkeypatch.setattr(ex, missing, absent)
    warnings: list[str] = []

    snap = ex.collect_snapshot(warnings, now)

    assert warnings == [warning]
    assert section not in snap
    assert snap["available"] is True and snap["transactions"]["total"] == 7
    assert {"step_up", "devices", "bank"} - {section} <= set(snap)
    assert not absent.exists(), "opening a missing database created one"


# ==========================================================================
# B. One scenario row
# ==========================================================================


def test_a_row_keeps_the_evidence_and_drops_the_signature_bytes(ex):
    signature, nonce = "ab" * 64, "cd" * 16
    response = {
        "rail": "UPI", "final_status": "ALLOW", "decision_reason": "POLICY_ALLOW",
        "risk": {"anomaly_score": -0.032912, "risk_band": "MEDIUM", "reasons": ["new location"],
                 "range_signal": {"name": "beyond_observed_range", "fired": False, "current_24h": 2,
                                  "observed_max_24h": 3, "multiplier": 6.0}},
        "decision": {"decision": "ALLOW", "deciding_rule": None, "matched_rules": [],
                     "policy_version": 4, "policy_hash": "09b170c65114" + "0" * 52},
        "assertion": {"signature": signature, "payload": {
            "nonce": nonce, "issued_at": "i", "expires_at": "e", "atlas_key_id": "atlas-demo-key-1"}},
        "bank_verdict": {"approved": True, "reason": "approved"},
        "rail_payload": {"rail": "UPI", "amount": "1500.00", "atlas_assertion": {"signature": signature}},
    }
    scenario = {"label": "Everyday payment", "amount": "1500.00", "local_time": "10:00 IST",
                "is_new_beneficiary": False}

    row = ex._row(scenario, response)

    assert row["crypto"] == {"assertion_signed": True, "signature_hex_len": 128, "nonce_present": True,
                             "issued_at": "i", "expires_at": "e", "key_id": "atlas-demo-key-1"}
    assert row["policy"]["hash_prefix"] == "09b170c65114"
    assert row["ml"] == {"risk_band": "MEDIUM", "anomaly_score": -0.0329, "reasons": ["new location"],
                         "range_signal": {"name": "beyond_observed_range", "fired": False, "current_24h": 2,
                                          "observed_max_24h": 3, "multiplier": 6.0}}
    assert row["bank"] == {"contacted": True, "approved": True, "reason": "approved"}
    assert row["rail_payload_fields"] == ["amount", "atlas_assertion", "rail"]
    exported = json.dumps(row)
    assert signature not in exported and nonce not in exported, "secret-looking bytes reached the page"

    refused = ex._row(scenario, {**response, "final_status": "STEP_UP", "assertion": None,
                                 "bank_verdict": None, "rail_payload": None})
    assert refused["crypto"]["assertion_signed"] is False
    assert refused["crypto"]["signature_hex_len"] == 0
    assert refused["bank"] == {"contacted": False, "approved": None, "reason": None}
    assert refused["rail_payload_fields"] == []


# ==========================================================================
# C. Reading pytest's result
# ==========================================================================


@pytest.mark.parametrize(
    "stdout, returncode, expected",
    [
        ("....\n351 passed, 43 warnings in 115.13s (0:01:55)\n", 0,
         {"total": 351, "failed_count": 0, "error_count": 0, "failed": False}),
        ("FAILED tests/t.py::x - assert '3 passed'\n340 passed, 11 failed in 9.1s\n", 1,
         {"total": 340, "failed_count": 11, "error_count": 0, "failed": True}),
        ("349 passed, 2 errors in 9.0s\n", 1,
         {"total": 349, "failed_count": 0, "error_count": 2, "failed": True}),
        ("1 passed, 1 error in 1.0s\n", 1,
         {"total": 1, "failed_count": 0, "error_count": 1, "failed": True}),
        ("351 passed in 1.0s\n", 3,
         {"total": 351, "failed_count": 0, "error_count": 0, "failed": True}),
        ("10 passed, 3 xfailed in 1.0s\n", 0,
         {"total": 10, "failed_count": 0, "error_count": 0, "failed": False}),
        ("no tests ran in 0.01s\n", 5, None),
    ],
    ids=["clean", "failures-after-a-decoy-line", "collection-errors", "one-error",
         "nonzero-exit-alone", "xfailed-is-not-failed", "no-summary"],
)
def test_the_test_count_is_trusted_only_when_the_run_passed(ex, stdout, returncode, expected):
    parsed = ex._parse_pytest_summary(stdout, returncode)
    if expected is None:
        assert parsed is None
    else:
        assert {key: parsed[key] for key in expected} == expected
        assert parsed["returncode"] == returncode


def test_every_spelling_of_the_home_folder_is_scrubbed(ex):
    home = str(Path.home())
    text = " | ".join([home + "\\a", home.replace("\\", "\\\\") + "\\\\b", home.replace("\\", "/") + "/c"])

    scrubbed = ex._scrub(text)

    assert home not in scrubbed and home.replace("\\", "/") not in scrubbed
    assert scrubbed.count("~") == 3


# ==========================================================================
# D. main(): exit status, warnings, and the page it writes
# ==========================================================================


@pytest.fixture
def export(ex, tmp_path, monkeypatch):
    """main() with nothing live: absent databases, a scratch page, and whatever
    sweep and test run the test supplies."""
    for name in ("TXN_DB", "STEP_UP_DB", "DEVICE_DB", "BANK_DB"):
        monkeypatch.setattr(ex, name, tmp_path / "absent" / f"{name}.db")
    out = tmp_path / "docs" / "dashboard-data.json"
    out.parent.mkdir()

    def run(sweep, *, page=MINIMAL_PAGE, pytest_run=None):
        page_path = out.parent / "index.html"
        if page is not None:
            page_path.write_text(page, encoding="utf-8")
        monkeypatch.setattr(ex, "run_sweep", sweep)
        argv = ["export_dashboard_data.py", "--out", str(out)]
        if pytest_run is not None:
            monkeypatch.setattr(ex, "subprocess", SimpleNamespace(run=lambda *a, **k: pytest_run))
            # These tests are about the exit status and the recorded test run;
            # the ML figures are measured by their own tests, and computing them
            # here only cost time (about 40 s per test).
            monkeypatch.setattr(ex, "_evaluate_ml",
                                lambda warnings: {"method": "measured by this export", "stubbed": True})
            argv.append("--run-tests")
        monkeypatch.setattr(sys, "argv", argv)
        code = ex.main()
        return code, json.loads(out.read_text(encoding="utf-8")), page_path

    return run


def _complete(warnings):
    return {"available": True, "rows": [{}] * 7, "scenarios_attempted": 7}


def _crashes(warnings):
    raise RuntimeError("simulated sweep crash")


def _drops_a_scenario(warnings):
    warnings.append("scenario Large amount (23:30 IST, UPI) returned HTTP 500")
    return {"available": True, "rows": [{}] * 6, "scenarios_attempted": 7}


def test_a_complete_export_exits_0_and_the_page_carries_exactly_the_json(export, capsys):
    code, data, page = export(_complete)

    html = page.read_text(encoding="utf-8")
    island = html.split(ISLAND, 1)[1].split("</script>", 1)[0]
    assert code == 0
    assert "[export] OK" in capsys.readouterr().out
    assert json.loads(island) == data
    assert '<p id="tail">tail</p>' in html, "regenerating the data damaged the hand-written page"
    assert data["warnings"] == ["no transaction database on this machine; snapshot omitted"], (
        "a missing database is a warning, not a failure"
    )


@pytest.mark.parametrize(
    "sweep, reason, warning",
    [
        (_crashes, "the scenario sweep produced no rows",
         "scenario sweep failed: RuntimeError: simulated sweep crash"),
        (_drops_a_scenario, "the scenario sweep produced 6 of 7 rows",
         "scenario Large amount (23:30 IST, UPI) returned HTTP 500"),
    ],
    ids=["crashed", "dropped-a-scenario"],
)
def test_a_failed_or_partial_sweep_exits_1_and_is_shown(export, capsys, sweep, reason, warning):
    code, data, _ = export(sweep)

    printed = capsys.readouterr().out
    assert code == 1
    assert "[export] FAILED" in printed and reason in printed
    assert warning in data["warnings"], "the page would not show why the export failed"


@pytest.mark.parametrize(
    "stdout, returncode, failed_count, error_count",
    [("340 passed, 11 failed in 9.0s\n", 1, 11, 0), ("349 passed, 2 errors in 9.0s\n", 1, 0, 2)],
    ids=["failures", "errors"],
)
def test_a_failing_test_run_exits_1_and_is_recorded(export, capsys, stdout, returncode,
                                                    failed_count, error_count):
    code, data, _ = export(_complete, pytest_run=SimpleNamespace(stdout=stdout, returncode=returncode))

    tests = data["measurements"]["tests"]
    assert code == 1
    assert "the test run did not pass" in capsys.readouterr().out
    assert tests["failed"] is True and tests["method"] == "executed by this export"
    assert (tests["failed_count"], tests["error_count"], tests["returncode"]) == (
        failed_count, error_count, returncode)
    assert any(w.startswith("the test run did not pass") for w in data["warnings"])


def test_a_test_run_with_no_summary_is_a_failure_not_a_blank(export):
    code, data, _ = export(
        _complete, pytest_run=SimpleNamespace(stdout="ImportError while loading conftest\n", returncode=4))

    assert code == 1
    assert data["measurements"]["tests"]["failed"] is True
    assert data["measurements"]["tests"]["total"] is None


def test_a_passing_test_run_is_recorded_as_executed(export):
    code, data, _ = export(
        _complete, pytest_run=SimpleNamespace(stdout="381 passed, 43 warnings in 120.00s\n", returncode=0))

    tests = data["measurements"]["tests"]
    assert code == 0
    assert (tests["total"], tests["failed"], tests["method"]) == (381, False, "executed by this export")


@pytest.mark.parametrize("page", [None, "<html><body>no data island here</body></html>"],
                         ids=["page-missing", "no-data-island"])
def test_a_page_that_cannot_be_updated_exits_1(export, capsys, page):
    code, _, _ = export(_complete, page=page)

    assert code == 1
    assert "index.html was not updated" in capsys.readouterr().out


def test_a_warning_cannot_close_the_data_island_or_leak_the_home_folder(export):
    home = str(Path.home())
    forward = home.replace("\\", "/")

    def hostile(warnings):
        warnings.append("</script><script>alert(1)</script>")
        warnings.append(f"cannot open {home}\\AppData\\x.db or {forward}/y.db")
        return _complete(warnings)

    code, data, page = export(hostile)

    html = page.read_text(encoding="utf-8")
    assert code == 0
    assert html.count("</script>") == 1, "a warning ended the data island early"
    island = json.loads(html.split(ISLAND, 1)[1].split("</script>", 1)[0])
    assert "</script><script>alert(1)</script>" in island["warnings"]
    assert all(home not in w and forward not in w for w in data["warnings"])
    assert "cannot open ~\\AppData\\x.db or ~/y.db" in data["warnings"]


# ==========================================================================
# E. The sweep itself
# ==========================================================================


def test_the_sweep_runs_both_services_on_temporary_stores_only(ex, tmp_path, monkeypatch):
    """README.md's Results table, re-run for real through both services -- and
    nowhere near their own databases or atlas_service's startup hook, which
    publishes the public key and settles stale step-ups in the LIVE databases.
    Every default store path points at a file that must still not exist
    afterwards, and running the startup hook fails the test outright."""
    import atlas_service.main as atlas_main
    import bank_service.main as bank_main
    from bank_service import db as bank_db

    # bank_db.DEFAULT_DB_PATH was missing from this list until 2026-09-25, and the
    # sweep really did write the LIVE bank_service/bank_ledger.db: every approved
    # scenario recorded its outcome there. conftest.py points that path at a temp
    # file per test, so the write landed somewhere harmless and nothing noticed.
    defaults = {
        (atlas_main, "DB_PATH"): tmp_path / "default-transactions.db",
        (atlas_main, "STEP_UP_DB_PATH"): tmp_path / "default-step-up.db",
        (atlas_main, "DEVICE_DB_PATH"): tmp_path / "default-devices.db",
        (bank_main, "REPLAY_DB_PATH"): tmp_path / "default-replay.db",
        (bank_db, "DEFAULT_DB_PATH"): tmp_path / "default-bank-ledger.db",
        (atlas_main, "POLICY_STATE_DB_PATH"): tmp_path / "default-policy-state.db",
    }
    for (module, name), path in defaults.items():
        monkeypatch.setattr(module, name, path)

    def startup_hook(*args, **kwargs):
        pytest.fail("the sweep ran atlas_service's startup hook")

    monkeypatch.setattr(atlas_main, "publish_public_key", startup_hook)
    monkeypatch.setattr(atlas_main, "resolve_stale_step_ups", startup_hook)
    temp_root = Path(tempfile.gettempdir())
    before = set(temp_root.glob("atlas-dash-*"))
    warnings: list[str] = []

    sweep = ex.run_sweep(warnings)

    assert warnings == []
    assert sweep["available"] is True and sweep["scenarios_attempted"] == 7
    rows = sweep["rows"]
    assert [r["final_status"] for r in rows] == DOCUMENTED_OUTCOMES
    assert [r["policy"]["deciding_rule"] for r in rows] == DOCUMENTED_RULES
    assert [r["rail"] for r in rows] == ["UPI"] * 6 + ["PIX"]
    for row in rows:
        allowed = row["final_status"] == "ALLOW"
        assert row["crypto"]["assertion_signed"] is allowed, "only an ALLOW may be signed"
        assert row["bank"]["contacted"] is allowed, "the bank is contacted only after an ALLOW"
        assert (row["bank"]["approved"] is True) is allowed
        # Sent twice, refused the second time. The reason can only come from a
        # device-layer defence, which is itself the proof that the sweep drove
        # the signed /v2/transact path: the legacy endpoint has no counter, no
        # nonce and no envelope to replay (D5, 2026-09-18).
        assert row["replay"]["refused"] is True, f"a replayed envelope was accepted: {row}"
        assert row["replay"]["decision_reason"] in (
            "COUNTER_REGRESSION", "NONCE_REPLAY", "DUPLICATE_TRANSACTION_ID",
        ), row["replay"]
        assert isinstance(row["elapsed_ms"], float) and row["elapsed_ms"] > 0
    assert not [p for p in defaults.values() if p.exists()], "the sweep opened a default store"
    assert bank_db.DEFAULT_DB_PATH == defaults[(bank_db, "DEFAULT_DB_PATH")], (
        "the sweep did not restore the bank ledger path it redirected")
    assert set(temp_root.glob("atlas-dash-*")) == before, "the sweep left its temporary directory"


def test_a_temporary_directory_that_survives_is_reported_without_its_path(ex, monkeypatch):
    temp_root = Path(tempfile.gettempdir())
    before = set(temp_root.glob("atlas-dash-*"))
    monkeypatch.setattr(ex, "_scenarios", lambda known: [])
    monkeypatch.setattr(ex, "shutil", SimpleNamespace(rmtree=lambda *a, **k: None))
    warnings: list[str] = []
    try:
        ex.run_sweep(warnings)
        survived = set(temp_root.glob("atlas-dash-*")) - before
    finally:
        for leftover in set(temp_root.glob("atlas-dash-*")) - before:
            shutil.rmtree(leftover, ignore_errors=True)

    assert len(survived) == 1
    assert warnings == [
        "the sweep's temporary directory could not be removed; it holds "
        "only throwaway stores and a throwaway signing key"
    ]
    assert str(temp_root) not in warnings[0]


# ==========================================================================
# E. ML evaluation (D4, 2026-09-18)
# ==========================================================================

def test_without_run_tests_the_ml_figures_say_they_were_not_measured(ex):
    """The evaluation costs about as much as the suite, so a quick export does
    not run it -- and must not leave an older number looking fresh."""
    measurements = ex.collect_measurements(False, [])

    assert measurements["ml"] == {"method": "not run in this export"}


def test_an_ml_evaluation_that_fails_is_reported_not_swallowed(ex, monkeypatch, tmp_path):
    """A silent 'no ML figures' section would read as 'never asked'."""
    monkeypatch.setattr(ex, "__file__", str(tmp_path / "export_dashboard_data.py"))
    warnings: list[str] = []

    result = ex._evaluate_ml(warnings)

    assert result == {"method": "did not run in this export"}
    assert len(warnings) == 1 and warnings[0].startswith("the ML evaluation did not run")


def test_the_ml_evaluation_is_deterministic_and_reports_both_framings(monkeypatch):
    """Same seeds, same numbers -- a measurement that drifts run to run cannot
    be published. Kept small here; scripts/evaluate_ml.py runs the full set."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "atlas_evaluate_ml_test", Path(__file__).resolve().parent.parent / "scripts" / "evaluate_ml.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "TRAINING_SEEDS", (42,))
    monkeypatch.setattr(module, "ORDINARY_PER_PERSONA", 3)
    # The held-out evaluation has its own tests (tests/test_ml_evaluation.py).
    monkeypatch.setattr(module, "INCLUDE_HELD_OUT", False)

    first, second = module.evaluate(), module.evaluate()

    for key in ("at_medium_and_above", "at_high_only",
                "at_medium_and_above_excluding_the_legitimate_large_purchase"):
        assert first[key] == second[key], f"{key} changed between identical runs"
        block = first[key]
        assert block["planted"] + block["ordinary"] > 0
        assert 0.0 <= (block["precision"] or 0.0) <= 1.0
        assert 0.0 <= (block["recall"] or 0.0) <= 1.0
    assert first["at_medium_and_above"]["ordinary"] == 3
    assert "same generator" in first["data"], "the synthetic caveat left the measurement"
    assert first["latency"]["score_ms_median"] > 0
