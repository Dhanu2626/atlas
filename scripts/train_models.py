"""Train, persist and verify ATLAS's per-subject ML models -- the explicit
training step that the request path no longer performs.

    python scripts/train_models.py                 # every subject with a policy file
    python scripts/train_models.py --subject user-demo-1
    python scripts/train_models.py --check         # verify existing artifacts, train nothing

Training data, features, hyperparameters and risk bands are unchanged: the
demo persona generator, 200 transactions, seed 42, IsolationForest with
random_state 0 (atlas_service/ml/registry.py). Artifacts go to
atlas_service/ml/artifacts/ (gitignored), each with a manifest whose HMAC is
keyed by a keystore-protected secret. After training, every artifact is loaded
back through the same verification the service uses, and its scores are
compared with the in-memory model that produced it.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

ATLAS_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ATLAS_ROOT))

from atlas_service.ml import registry  # noqa: E402
from atlas_service.policy.engine import POLICIES_DIR  # noqa: E402


def policy_subjects() -> list[str]:
    return sorted(p.stem for p in POLICIES_DIR.glob("*.yaml"))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--subject", action="append", help="train only this subject (repeatable)")
    ap.add_argument("--artifact-dir", type=Path, default=None, help=argparse.SUPPRESS)
    ap.add_argument("--check", action="store_true", help="verify existing artifacts only")
    args = ap.parse_args(argv)
    subjects = args.subject or policy_subjects()
    artifact_dir = args.artifact_dir or registry.DEFAULT_ARTIFACT_DIR
    failures = 0
    for subject in subjects:
        if args.check:
            try:
                registry.load(subject, artifact_dir)
                print(f"[train] {subject}: artifact verifies")
            except registry.ModelUnavailableError as exc:
                failures += 1
                print(f"[train] {subject}: {exc}")
            continue
        started = time.perf_counter()
        trained = registry.train_subject(subject)
        registry.save(trained, artifact_dir)
        loaded = registry.load(subject, artifact_dir)
        probe = trained.history[-5:]
        # Scored against the model's own training history on both sides: this check is
        # "does the artifact reload identically", not "what a live request would decide".
        same = all(trained.score(t, trained.history).anomaly_score
                   == loaded.score(t, loaded.history).anomaly_score for t in probe)
        elapsed = (time.perf_counter() - started) * 1000
        print(f"[train] {subject}: trained on {len(trained.history)} transactions, saved, "
              f"verified on load, scores {'identical' if same else 'DIFFER'} ({elapsed:.0f} ms)")
        failures += 0 if same else 1
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
