"""Makes `atlas/` importable from every test file without each one repeating a
sys.path hack — `import contracts`, `from atlas_service.ml... import ...`, and
`from bank_service... import ...` all work directly once this loads.

Also provides wire_bank_app_to_keys(), a Step 6 addition: three different
test files now need to point bank_app's crypto-dependent /verify endpoint at
an isolated, per-test key + replay cache instead of the real shared-file/db
defaults, and that wiring is identical each time -- worth one shared helper
instead of copying it three times.
"""

import sys
from pathlib import Path

import pytest

ATLAS_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ATLAS_ROOT))

# Keys are encrypted at rest (keystore.py). On Windows the suite uses the real
# default, DPAPI; elsewhere there is no DPAPI, so the portable backend runs with
# a passphrase that exists only inside this test process.
if sys.platform != "win32":
    import os as _os
    _os.environ.setdefault("ATLAS_KEYSTORE_BACKEND", "scrypt-aesgcm")
    _os.environ.setdefault("ATLAS_KEYSTORE_PASSPHRASE", "atlas-test-suite-only")

from atlas_service import crypto  # noqa: E402  (after the sys.path fix-up above)
from firmware import device_identity as _device_identity  # noqa: E402
import atlas_service.main as _atlas_main  # noqa: E402

#: The directories the isolation guard must never see change, captured HERE --
#: at import, before any fixture redirects the module constants they come from.
#: Until 2026-09-25 the guard read crypto.DEFAULT_KEYS_DIR and
#: device_identity.DEFAULT_DEVICE_KEYS_DIR *after* pointing them into its own
#: sandbox, so "the real key directories are unchanged" was a check on two empty
#: sandbox folders. tests/test_isolation_guard.py pins this.
REAL_KEY_DIRS = (
    crypto.DEFAULT_KEYS_DIR,
    _device_identity.DEFAULT_DEVICE_KEYS_DIR,
    _atlas_main.SHARED_KEYS_DIR,
    ATLAS_ROOT / "atlas_service" / "ml" / "artifacts",
)


@pytest.fixture(scope="session")
def trained_model_dir(tmp_path_factory):
    """Trains each policy subject's model ONCE for the whole run, into a
    temporary folder -- the explicit training step scripts/train_models.py
    performs for a real service. Requests in every test then only load and
    infer, exactly as they do in production."""
    from atlas_service.ml import registry
    from atlas_service.policy.engine import POLICIES_DIR

    folder = tmp_path_factory.mktemp("trained-models")
    for policy_file in sorted(POLICIES_DIR.glob("*.yaml")):
        registry.save(registry.train_subject(policy_file.stem), folder)
    return folder


@pytest.fixture(scope="session")
def shared_model_registry(trained_model_dir):
    from atlas_service.ml.registry import ModelRegistry
    return ModelRegistry(trained_model_dir)


def _key_dir_state(*dirs: Path) -> dict:
    """Name, size and modification time of every file in the real key
    directories -- enough to notice a test writing into one."""
    return {
        str(p): (p.stat().st_size, p.stat().st_mtime_ns)
        for d in dirs if d.exists()
        for p in sorted(d.rglob("*")) if p.is_file()
    }


@pytest.fixture(autouse=True)
def live_state_is_off_limits(monkeypatch, tmp_path_factory, shared_model_registry):
    """No test may reach the services' default stores or key directories.

    On a developer's machine those defaults ARE the live databases and the real
    signing keys. Ten tests in tests/test_phase3_device_trust.py opened two of
    them on every run until 2026-09-17 -- nothing was written, but nothing
    stopped a write either, and the leak was invisible because each test passed.

    Two halves, because one is not enough:

      * every default path that is read at call time is pointed into a fresh
        sandbox, so a forgotten dependency override lands there instead of on
        real data;
      * the sandbox must still be empty afterwards, and the real key
        directories unchanged, so the forgotten override fails the test that
        caused it instead of passing quietly.

    crypto.DEFAULT_KEYS_DIR and device_identity.DEFAULT_DEVICE_KEYS_DIR are also
    bound as default ARGUMENTS at import time, which no patch can redirect;
    that is what the second half covers. A test that genuinely needs a default
    path can monkeypatch it back for its own duration.
    """
    from firmware import device_identity
    import atlas_service.main as atlas_main
    import bank_service.main as bank_main
    from atlas_service.ml import registry as model_registry
    from bank_service import db as bank_db

    sandbox = tmp_path_factory.mktemp("default-paths-must-stay-empty")
    for module, attribute, name in (
        (atlas_main, "DB_PATH", "atlas_transactions.db"),
        (atlas_main, "DEVICE_DB_PATH", "atlas_devices.db"),
        (atlas_main, "STEP_UP_DB_PATH", "atlas_step_up.db"),
        (atlas_main, "SHARED_KEYS_DIR", "shared_keys"),
        (atlas_main, "ATLAS_PUBLIC_KEY_PATH", "shared_keys/atlas_public_key.txt"),
        (bank_main, "REPLAY_DB_PATH", "bank_replay_cache.db"),
        (bank_main, "ATLAS_PUBLIC_KEY_PATH", "shared_keys/atlas_public_key.txt"),
        (crypto, "DEFAULT_KEYS_DIR", "keys"),
        (device_identity, "DEFAULT_DEVICE_KEYS_DIR", "device_keys"),
        (model_registry, "DEFAULT_ARTIFACT_DIR", "ml-artifacts"),
    ):
        monkeypatch.setattr(module, attribute, sandbox.joinpath(*name.split("/")))
    # The service's registry serves the session's trained models: tests infer,
    # they never train on the request path (atlas_service/ml/registry.py).
    monkeypatch.setattr(atlas_main, "MODEL_REGISTRY", shared_model_registry)
    # The sandbox bank's durable ledger: a fresh file per test, the way the old
    # in-memory ledger behaved, but never the live bank_ledger.db.
    monkeypatch.setattr(bank_db, "DEFAULT_DB_PATH",
                        tmp_path_factory.mktemp("bank-ledger") / "bank_ledger.db")
    # The policy non-rollback record (2026-09-25): a fresh file per test, so each
    # test starts with no recorded version, exactly like a new installation.
    monkeypatch.setattr(atlas_main, "POLICY_STATE_DB_PATH",
                        tmp_path_factory.mktemp("policy-state") / "atlas_policy_state.db")

    real_key_dirs = REAL_KEY_DIRS
    before_keys = _key_dir_state(*real_key_dirs)
    # The sandbox only catches what the redirect covers, so the real paths are
    # watched too: if someone removes a redirect above, the live file appears
    # where it always did and this notices, rather than the guard passing
    # because its own sandbox stayed empty.
    real_stores = (ATLAS_ROOT / "atlas_service" / "atlas_transactions.db",
                   ATLAS_ROOT / "atlas_service" / "atlas_devices.db",
                   ATLAS_ROOT / "atlas_service" / "atlas_step_up.db",
                   ATLAS_ROOT / "atlas_service" / "atlas_policy_state.db",
                   ATLAS_ROOT / "bank_service" / "bank_replay_cache.db",
                   ATLAS_ROOT / "bank_service" / "bank_ledger.db")
    before_stores = {str(p): (p.exists(), p.stat().st_mtime_ns if p.exists() else 0)
                     for p in real_stores}

    yield

    used = sorted(str(p.relative_to(sandbox)) for p in sandbox.rglob("*") if p.is_file())
    assert not used, (
        f"this test reached a default store path: {used}. On a real machine that is the "
        f"live database or key directory -- override the dependency with a tmp_path one."
    )
    assert _key_dir_state(*real_key_dirs) == before_keys, (
        "this test wrote into a real key directory or the real model artifacts"
    )
    assert {str(p): (p.exists(), p.stat().st_mtime_ns if p.exists() else 0)
            for p in real_stores} == before_stores, (
        "this test created or modified one of the services' real databases"
    )


def wire_bank_app_to_keys(keys_dir: Path, replay_db_path: Path) -> None:
    """Overrides bank_app's get_atlas_public_key/get_replay_cache
    dependencies to match a specific test's keys_dir and an isolated replay
    cache file, so /verify's real signature check passes against the same
    key a test actually signed with, without touching the real shared_keys
    file or a shared on-disk replay cache. Caller must clear
    bank_app.dependency_overrides afterward (typically via an autouse
    fixture, same pattern atlas_app's tests already use)."""
    from bank_service.main import app as bank_app
    from bank_service.main import get_atlas_public_key, get_replay_cache
    from bank_service.replay_cache import ReplayCache

    public_key_hex = crypto.get_public_key(keys_dir=keys_dir)
    bank_app.dependency_overrides[get_atlas_public_key] = lambda: public_key_hex
    bank_app.dependency_overrides[get_replay_cache] = lambda: ReplayCache(replay_db_path)
