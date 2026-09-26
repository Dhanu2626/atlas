"""The ML lifecycle: train once, persist, verify, load, infer (2026-09-22).

Until this date every request fitted a fresh Isolation Forest. These tests pin
the replacement: the request path never fits; repeated requests share one loaded
model; a loaded model scores exactly as a fresh fit does (so no decision moved);
an artifact or manifest that was altered, or built by another scikit-learn, is
refused; ML-unavailable fails closed before any transaction state exists; and
retraining happens only when explicitly asked for.
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import keystore
from atlas_service.db import TransactionStore
from atlas_service.main import (
    app as atlas_app,
    get_model_registry,
    get_require_device_auth,
    get_transaction_store,
)
from atlas_service.ml import registry
from atlas_service.ml.model import PersonaAnomalyModel
from atlas_service.ml.synth import Persona, planted_anomalies

SUBJECT = "user-demo-1"


@pytest.fixture(autouse=True)
def _clear_overrides(tmp_path):
    """/evaluate reads the subject's live history since 2026-09-23, so every request
    in this file needs a transaction store; a temporary one keeps these tests about
    the model registry and nothing else. A test that wants its own store overrides
    this again."""
    atlas_app.dependency_overrides[get_transaction_store] = lambda: TransactionStore(
        tmp_path / "registry-tests.db")
    yield
    atlas_app.dependency_overrides.clear()


def _tx(amount: str = "1500.00", txn_id: str = "reg-1", beneficiary: str = "ben-mother",
        timestamp: str = "2026-09-22T04:30:00+00:00") -> dict:
    return {
        "transaction_id": txn_id, "subject": SUBJECT, "amount": amount, "currency": "INR",
        "beneficiary": beneficiary, "location": "Hyderabad,IN",
        "device_id": "device-primary-01", "merchant_category": "transfer",
        "authentication_method": "pin", "is_new_beneficiary": False, "is_new_device": False,
        "is_international": False, "declared_travel_mode": False, "is_emergency_request": False,
        "timestamp": timestamp,
    }


def _copy(trained_model_dir: Path, tmp_path: Path) -> Path:
    target = tmp_path / "models"
    shutil.copytree(trained_model_dir, target)
    return target


def test_the_request_path_never_fits(monkeypatch):
    def fit_forbidden(self, history):
        raise AssertionError("a request tried to fit a model")
    monkeypatch.setattr(PersonaAnomalyModel, "fit", fit_forbidden)
    client = TestClient(atlas_app)
    for i, amount in enumerate(("1500.00", "60000.00", "150000.00", "20.00", "999.00")):
        reply = client.post("/evaluate", json=_tx(amount, f"nofit-{i}"))
        assert reply.status_code == 200 and reply.json()["risk"] is not None


def test_repeated_requests_share_one_loaded_model(trained_model_dir):
    served = registry.ModelRegistry(trained_model_dir)
    atlas_app.dependency_overrides[get_model_registry] = lambda: served
    client = TestClient(atlas_app)
    for i in range(6):
        assert client.post("/evaluate", json=_tx(txn_id=f"share-{i}")).status_code == 200
    assert served.loads == 1, "the model was loaded more than once"
    assert served.get(SUBJECT) is served.get(SUBJECT)


def test_a_loaded_model_scores_exactly_like_a_fresh_fit(trained_model_dir):
    """Same data, same seed, same random_state: moving from per-request fitting
    to a persisted model must not move a single score, band or reason."""
    loaded = registry.load(SUBJECT, trained_model_dir)
    fresh = registry.train_subject(SUBJECT)
    from contracts import Transaction
    probes = [Transaction(**_tx(a, f"p-{i}", b, ts)) for i, (a, b, ts) in enumerate([
        ("1500.00", "ben-mother", "2026-09-22T04:30:00+00:00"),
        ("1500.00", "ben-mother", "2026-09-22T18:00:00+00:00"),
        ("60000.00", "ben-newshop", "2026-09-22T04:30:00+00:00"),
        ("150000.00", "ben-newshop", "2026-09-22T18:00:00+00:00"),
    ])]
    for batch in planted_anomalies(Persona(subject=SUBJECT)).values():
        probes.append(batch[-1])
    for tx in probes:
        a, b = loaded.score(tx, loaded.history), fresh.score(tx, fresh.history)
        assert (a.anomaly_score, a.risk_band, a.reasons) == (b.anomaly_score, b.risk_band, b.reasons)


def test_predictions_are_deterministic_across_calls_and_loads(trained_model_dir):
    from contracts import Transaction
    tx = Transaction(**_tx("60000.00", "det-1", "ben-newshop"))
    first, second = registry.load(SUBJECT, trained_model_dir), registry.load(SUBJECT, trained_model_dir)
    scores = ({first.score(tx, first.history).anomaly_score for _ in range(5)}
              | {second.score(tx, second.history).anomaly_score})
    assert len(scores) == 1


def test_a_tampered_artifact_is_refused_and_the_request_fails_closed(trained_model_dir, tmp_path):
    models = _copy(trained_model_dir, tmp_path)
    artifact = models / f"{SUBJECT}.joblib"
    data = bytearray(artifact.read_bytes())
    data[len(data) // 2] ^= 0x01
    artifact.write_bytes(bytes(data))
    with pytest.raises(registry.ModelUnavailableError, match="integrity"):
        registry.load(SUBJECT, models)
    atlas_app.dependency_overrides[get_model_registry] = lambda: registry.ModelRegistry(models)
    body = TestClient(atlas_app).post("/evaluate", json=_tx()).json()
    assert body["final_status"] == "FAIL_CLOSED" and body["risk"] is None


def test_an_edited_manifest_is_refused(trained_model_dir, tmp_path):
    models = _copy(trained_model_dir, tmp_path)
    manifest_path = models / f"{SUBJECT}.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["history_size"] = 999
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(registry.ModelUnavailableError, match="integrity"):
        registry.load(SUBJECT, models)


def test_a_model_from_another_scikit_learn_is_refused(trained_model_dir, tmp_path):
    """Correctly signed but built by a different library version: refused, so a
    model is never scored by code it was not trained with."""
    models = _copy(trained_model_dir, tmp_path)
    manifest_path = models / f"{SUBJECT}.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["sklearn_version"] = "0.0.1"
    key = keystore.read_secret(models / registry.INTEGRITY_KEY_FILE, "model-integrity")
    manifest["hmac_sha256"] = registry._mac(key, manifest, (models / f"{SUBJECT}.joblib").read_bytes())
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(registry.ModelUnavailableError, match="scikit-learn"):
        registry.load(SUBJECT, models)


def test_ml_unavailable_fails_closed_before_any_state_exists(tmp_path):
    empty = registry.ModelRegistry(tmp_path / "no-models")
    store = TransactionStore(tmp_path / "atlas.db")
    atlas_app.dependency_overrides[get_model_registry] = lambda: empty
    atlas_app.dependency_overrides[get_transaction_store] = lambda: store
    atlas_app.dependency_overrides[get_require_device_auth] = lambda: False
    body = TestClient(atlas_app).post("/transact", json=_tx(txn_id="ml-down-1")).json()
    assert (body["final_status"], body["decision_reason"]) == ("FAIL_CLOSED", "INTERNAL_ERROR")
    assert body["assertion"] is None and body["bank_verdict"] is None
    assert store.get_state("ml-down-1") is None, "a half-finished transaction was persisted"
    store.close()


def test_retraining_happens_only_when_asked(trained_model_dir, tmp_path):
    models = _copy(trained_model_dir, tmp_path)
    served = registry.ModelRegistry(models)
    before = served.get(SUBJECT)
    assert served.get(SUBJECT) is before, "a lookup retrained or reloaded the model"
    after = served.retrain(SUBJECT)
    assert after is not before and served.get(SUBJECT) is after
    from contracts import Transaction
    tx = Transaction(**_tx("60000.00", "rt-1", "ben-newshop"))
    assert (after.score(tx, after.history).anomaly_score
            == before.score(tx, before.history).anomaly_score)


def test_the_integrity_key_is_itself_protected(trained_model_dir):
    assert keystore.is_protected(trained_model_dir / registry.INTEGRITY_KEY_FILE)


def test_train_models_script_trains_verifies_and_detects_tampering(tmp_path, capsys):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
    import train_models
    models = tmp_path / "models"
    assert train_models.main(["--artifact-dir", str(models), "--subject", SUBJECT]) == 0
    assert "scores identical" in capsys.readouterr().out
    assert train_models.main(["--artifact-dir", str(models), "--subject", SUBJECT, "--check"]) == 0
    (models / f"{SUBJECT}.joblib").write_bytes(b"not a model")
    assert train_models.main(["--artifact-dir", str(models), "--subject", SUBJECT, "--check"]) == 1
