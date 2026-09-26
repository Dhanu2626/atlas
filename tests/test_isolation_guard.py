"""The isolation guard in tests/conftest.py watches the REAL directories (2026-09-25).

Until 2026-09-25 the guard captured its "real key directories" after redirecting
the constants they come from, so it compared two sandbox folders with themselves
and a test writing into the real atlas_service/keys would have passed. These tests
fail if the watched set ever drifts back into the sandbox.
"""

from pathlib import Path

import atlas_service.main as atlas_main
from tests import conftest
from atlas_service import crypto
from firmware import device_identity

ATLAS_ROOT = Path(__file__).resolve().parent.parent


def test_the_guard_watches_the_real_key_directories_not_its_sandbox(tmp_path_factory):
    base = tmp_path_factory.getbasetemp().resolve()
    expected = (
        ATLAS_ROOT / "atlas_service" / "keys",
        ATLAS_ROOT / "firmware" / "device_keys",
        ATLAS_ROOT / "atlas_service" / "ml" / "artifacts",
    )
    watched = [Path(d).resolve() for d in conftest.REAL_KEY_DIRS]
    for directory in expected:
        assert directory.resolve() in watched, f"{directory} is not watched"
    for directory in watched:
        assert base not in directory.parents, f"the guard watches a sandbox folder: {directory}"


def test_inside_a_test_the_constants_point_at_the_sandbox_and_the_guard_does_not():
    """The redirect and the watch must be different places -- that is the whole
    point: a forgotten override lands in the sandbox, a bypassed one lands in a
    watched real folder."""
    assert crypto.DEFAULT_KEYS_DIR != conftest.REAL_KEY_DIRS[0]
    assert device_identity.DEFAULT_DEVICE_KEYS_DIR != conftest.REAL_KEY_DIRS[1]
    assert atlas_main.SHARED_KEYS_DIR != conftest.REAL_KEY_DIRS[2]
