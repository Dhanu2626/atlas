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

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from atlas_service import crypto  # noqa: E402  (after the sys.path fix-up above)


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
