"""Trained-model lifecycle: train once, persist, verify, load, then infer.

Until 2026-09-22 every request fitted a fresh Isolation Forest on the subject's
history (about 0.36 s of a 0.37-0.50 s round trip in the 2026-09-18 export).
Now the two are separate operations:

    training  (explicit)   train_subject() -> save()          scripts/train_models.py
    serving   (per request) ModelRegistry.get() -> model.score()   atlas_service/main.py

The request path never fits. A registry loads each subject's artifact from disk
the first time it is asked for it, keeps it in memory, and hands the same
fitted object to every later request. Retraining is a separate, explicit call
(ModelRegistry.retrain / scripts/train_models.py); nothing on the request path
triggers it. A subject with no artifact is ML-unavailable, which fails closed
(ModelUnavailableError -> FAIL_CLOSED / INTERNAL_ERROR), never ALLOW.

WHAT IS PERSISTED: the fitted PersonaAnomalyModel (scaler, forest, the
training-score percentiles that set the risk bands) together with the history it
was trained on, because the same history drives the history-based features
(new beneficiary, velocity) at scoring time. Training data, features,
hyperparameters and bands are exactly what they were: same generator, same seed,
same random_state -- so a loaded model scores identically to a fresh fit, and a
test pins that.

WHY THE ARTIFACT IS SIGNED: joblib/pickle files execute code when loaded, so an
artifact is only unpickled after its HMAC-SHA256 checks out. The HMAC key is a
keystore-protected secret (purpose "model-integrity") created on first training,
so replacing an artifact requires the key, not merely write access to the folder.
The manifest also records the scikit-learn version; a different version is
refused rather than loaded with possibly different behaviour.
"""

from __future__ import annotations

import hashlib
import hmac
import io
import json
import secrets
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import joblib
import sklearn

import keystore
from atlas_service.ml.model import PersonaAnomalyModel
from atlas_service.ml.synth import Persona, generate_normal_history
from atlas_service.ml.range_signal import beyond_observed_range, range_reason
from contracts import INSUFFICIENT_HISTORY, RiskEvidence, Transaction

#: Gitignored: artifacts are derived data, rebuilt by scripts/train_models.py.
DEFAULT_ARTIFACT_DIR = Path(__file__).parent / "artifacts"

#: The frozen demo training set: the persona generator, 200 transactions, seed 42.
#: Unchanged from the per-request code this replaces.
HISTORY_SIZE = 200

#: How much of a subject's OWN payment history ATLAS must hold before it will grade
#: their risk into a band (2026-09-23). Set to HISTORY_SIZE on purpose rather than to
#: a smaller round number: the bands are percentiles of scores computed over
#: histories of exactly this size, so this is the point at which a live feature
#: vector is comparable with the distribution it is being ranked against. Any lower
#: value would be arbitrary. Below it the ML layer returns INSUFFICIENT_HISTORY (since
#: 2026-09-25; LOW before) and says why, and the deterministic policy rules decide
#: alone -- see TrainedModel.score.
MIN_HISTORY_FOR_BANDS = HISTORY_SIZE
HISTORY_SEED = 42

INTEGRITY_KEY_FILE = "model-integrity.key"
FORMAT_VERSION = 1


class ModelUnavailableError(RuntimeError):
    """No trustworthy trained model exists for this subject. Fails closed."""


@dataclass(frozen=True)
class TrainedModel:
    subject: str
    model: PersonaAnomalyModel
    history: list[Transaction] = field(repr=False)
    trained_at: str
    sklearn_version: str

    def score(self, transaction: Transaction, history: list[Transaction]):
        """Scores `transaction` against the history the caller supplies.

        `history` is REQUIRED, and deliberately has no default (2026-09-23). At
        inference time it is the subject's own persisted payments; `self.history`
        is the model's training/reference data, which is what the fitted scaler,
        the forest and the risk bands were built from. Defaulting to the latter is
        exactly the substitution that made a live burst of payments invisible, so
        the signature now forces every caller to say which one it means.

        UNKNOWN IS NOT ANOMALOUS. A risk band is a percentile of this model's own
        training scores, and those were computed over histories of
        MIN_HISTORY_FOR_BANDS transactions. A subject ATLAS has barely seen produces
        a vector where every "is this new?" feature is 1 and there is no amount
        baseline -- which scores as an outlier for a reason that has nothing to do
        with the customer's behaviour: ATLAS simply does not know them yet. Grading
        that would turn ignorance into evidence and step up every first payment.
        So below the threshold the ML layer says exactly that: risk_band is
        INSUFFICIENT_HISTORY -- not LOW, which would claim a judgement that was never
        made -- anomaly_score is None, and the reason says how much history exists.
        No RISK_THRESHOLD rule matches it (policy/engine.py), so the deterministic
        rules (amount, new payee, velocity, time window, international) decide
        exactly as they did when this case read LOW (approved 2026-09-25).

        With enough history the Isolation Forest scores as before, and the separate
        beyond_observed_range signal (range_signal.py) is attached beside it. That
        signal never changes the band.
        """
        if len(history) < MIN_HISTORY_FOR_BANDS:
            return RiskEvidence(
                anomaly_score=None,
                risk_band=INSUFFICIENT_HISTORY,
                reasons=[f"not enough payment history yet to judge this transaction "
                         f"({len(history)} of {MIN_HISTORY_FOR_BANDS} payments known)"],
            )
        evidence = self.model.score(transaction, history)
        signal = beyond_observed_range(transaction, history)
        reasons = evidence.reasons + ([range_reason(signal)] if signal.fired else [])
        return evidence.model_copy(update={"range_signal": signal, "reasons": reasons})


def training_history(subject: str) -> list[Transaction]:
    """The deterministic history a subject's model is trained on."""
    return generate_normal_history(Persona(subject=subject), n=HISTORY_SIZE, seed=HISTORY_SEED)


def train_subject(subject: str) -> TrainedModel:
    """TRAINING. Never called from the request path."""
    history = training_history(subject)
    return TrainedModel(
        subject=subject,
        model=PersonaAnomalyModel().fit(history),
        history=history,
        trained_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        sklearn_version=sklearn.__version__,
    )


def _safe(subject: str) -> str:
    if not subject or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-_" for c in subject.lower()):
        raise ModelUnavailableError(f"subject {subject!r} is not a valid artifact name")
    return subject


def _integrity_key(artifact_dir: Path, *, create: bool) -> bytes:
    path = artifact_dir / INTEGRITY_KEY_FILE
    if not path.exists():
        if not create:
            raise ModelUnavailableError("no model-integrity key; run scripts/train_models.py")
        keystore.write_secret(path, secrets.token_bytes(32), "model-integrity")
    try:
        return keystore.read_secret(path, "model-integrity")
    except keystore.KeystoreError as exc:
        raise ModelUnavailableError(f"model-integrity key unusable: {exc}") from exc


def _mac(key: bytes, manifest: dict, blob: bytes) -> str:
    """HMAC over the manifest's identifying fields AND the artifact bytes, so
    neither can be swapped or edited without the model-integrity key."""
    signed = {k: manifest.get(k) for k in ("format", "subject", "sklearn_version",
                                           "history_size", "history_seed", "sha256")}
    separator = b"\n"
    return hmac.new(key, json.dumps(signed, sort_keys=True).encode() + separator + blob,
                    hashlib.sha256).hexdigest()


def save(trained: TrainedModel, artifact_dir: Path | None = None) -> Path:
    artifact_dir = Path(artifact_dir or DEFAULT_ARTIFACT_DIR)
    artifact_dir.mkdir(parents=True, exist_ok=True)
    name = _safe(trained.subject)
    buffer = io.BytesIO()
    joblib.dump({"model": trained.model, "history": trained.history}, buffer)
    blob = buffer.getvalue()
    key = _integrity_key(artifact_dir, create=True)
    manifest = {
        "format": FORMAT_VERSION,
        "subject": trained.subject,
        "trained_at": trained.trained_at,
        "sklearn_version": trained.sklearn_version,
        "history_size": len(trained.history),
        "history_seed": HISTORY_SEED,
        "sha256": hashlib.sha256(blob).hexdigest(),
    }
    manifest["hmac_sha256"] = _mac(key, manifest, blob)
    artifact = artifact_dir / f"{name}.joblib"
    tmp = artifact.with_suffix(".joblib.tmp")
    tmp.write_bytes(blob)
    tmp.replace(artifact)
    (artifact_dir / f"{name}.json").write_text(json.dumps(manifest, indent=1), encoding="utf-8")
    return artifact


def load(subject: str, artifact_dir: Path | None = None) -> TrainedModel:
    """LOADING, not training: verifies, then unpickles. Raises
    ModelUnavailableError on anything missing, altered or incompatible."""
    artifact_dir = Path(artifact_dir or DEFAULT_ARTIFACT_DIR)
    name = _safe(subject)
    artifact, manifest_path = artifact_dir / f"{name}.joblib", artifact_dir / f"{name}.json"
    if not (artifact.exists() and manifest_path.exists()):
        raise ModelUnavailableError(f"no trained model for {subject!r}; run scripts/train_models.py")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    blob = artifact.read_bytes()
    expected = _mac(_integrity_key(artifact_dir, create=False), manifest, blob)
    if (hashlib.sha256(blob).hexdigest() != manifest.get("sha256")
            or not hmac.compare_digest(expected, str(manifest.get("hmac_sha256", "")))):
        raise ModelUnavailableError(f"model artifact for {subject!r} failed its integrity check")
    if manifest.get("subject") != subject or manifest.get("format") != FORMAT_VERSION:
        raise ModelUnavailableError(f"model manifest for {subject!r} does not match")
    if manifest.get("sklearn_version") != sklearn.__version__:
        raise ModelUnavailableError(
            f"model for {subject!r} was trained with scikit-learn {manifest.get('sklearn_version')}, "
            f"this is {sklearn.__version__}; retrain rather than load it")
    payload = joblib.load(io.BytesIO(blob))  # only after the HMAC matched
    return TrainedModel(subject=subject, model=payload["model"], history=payload["history"],
                        trained_at=manifest["trained_at"], sklearn_version=manifest["sklearn_version"])


class ModelRegistry:
    """Serves trained models to the request path. Loads, never fits."""

    def __init__(self, artifact_dir: Path | None = None):
        # Resolved at construction, not bound at import, so a test can point the
        # default elsewhere (tests/conftest.py).
        self.artifact_dir = Path(artifact_dir or DEFAULT_ARTIFACT_DIR)
        self._models: dict[str, TrainedModel] = {}
        self._lock = threading.Lock()
        self.loads = 0

    def get(self, subject: str) -> TrainedModel:
        cached = self._models.get(subject)
        if cached is not None:
            return cached
        with self._lock:
            if subject not in self._models:
                self._models[subject] = load(subject, self.artifact_dir)
                self.loads += 1
            return self._models[subject]

    def retrain(self, subject: str) -> TrainedModel:
        """EXPLICIT retraining: trains, persists, and replaces the served model."""
        trained = train_subject(subject)
        save(trained, self.artifact_dir)
        with self._lock:
            self._models[subject] = load(subject, self.artifact_dir)
        return self._models[subject]

    def loaded_subjects(self) -> list[str]:
        return sorted(self._models)
