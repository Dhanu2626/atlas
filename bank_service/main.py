"""bank_service -- the independent verifier. Holds only what it needs to make
its own decision; never imports atlas_service.policy, atlas_service.ml, or
atlas_service.crypto (see tests/test_bank_boundary.py's source-level check
for this, extended in Step 6 to cover verify.py/replay_cache.py/revocation.py
too).
"""

from __future__ import annotations

from decimal import Decimal
from pathlib import Path

from fastapi import Depends, FastAPI

from bank_service.ledger import status, verify
from bank_service.replay_cache import ReplayCache
from bank_service.verify import verify_assertion
from contracts import SignedAssertion

app = FastAPI(title="bank_service")

SHARED_KEYS_DIR = Path(__file__).resolve().parent.parent / "shared_keys"
ATLAS_PUBLIC_KEY_PATH = SHARED_KEYS_DIR / "atlas_public_key.txt"
REPLAY_DB_PATH = Path(__file__).resolve().parent / "bank_replay_cache.db"


def get_atlas_public_key() -> str:
    """Reads ATLAS's public key from a shared, non-Python file. bank_service
    cannot import atlas_service.crypto directly -- that's exactly the
    boundary tests/test_bank_boundary.py enforces -- so a plain file is the
    hand-off point between the two processes. This is a toy stand-in for
    real key distribution: it solves "how does this demo's bank process
    learn the key," not "how does a bank know an ATLAS instance is
    legitimate" (ARCHITECTURE.md's RQ-24, still unsolved)."""
    if not ATLAS_PUBLIC_KEY_PATH.exists():
        raise RuntimeError(
            f"ATLAS public key not found at {ATLAS_PUBLIC_KEY_PATH} -- "
            "atlas_service must publish its key (see main.py's startup hook) "
            "before bank_service can verify anything"
        )
    return ATLAS_PUBLIC_KEY_PATH.read_text().strip()


def get_replay_cache() -> ReplayCache:
    """Real network client-equivalent for the replay cache: a fresh
    connection to the real on-disk file by default. Tests override this
    (via FastAPI's dependency_overrides) to point at an isolated tmp_path
    file instead -- same pattern atlas_service/main.py already uses for
    get_bank_client()."""
    return ReplayCache(REPLAY_DB_PATH)


@app.post("/verify")
def verify_endpoint(
    signed: SignedAssertion,
    atlas_public_key: str = Depends(get_atlas_public_key),
    replay_cache: ReplayCache = Depends(get_replay_cache),
) -> dict:
    """Two independent checks, in sequence: first, is this assertion
    genuinely from ATLAS, unmodified, unexpired, unused, and from a
    still-trusted key (verify_assertion -- signature/revocation/expiry/
    replay, Step 5's work). Only if that passes does the bank's own ledger
    get to decide whether the account can actually support it (verify --
    Step 3's work, unchanged). A cryptographically perfect assertion can
    still be refused by the ledger; an otherwise-fine account is never even
    asked about if the assertion itself doesn't check out."""
    transaction_id = signed.payload.transaction_id

    assertion_ok, assertion_reason = verify_assertion(signed, atlas_public_key, replay_cache)
    if not assertion_ok:
        return {"transaction_id": transaction_id, "approved": False, "reason": assertion_reason}

    approved, reason = verify(
        signed.payload.subject, Decimal(signed.payload.amount), transaction_id
    )
    return {"transaction_id": transaction_id, "approved": approved, "reason": reason}


@app.get("/status/{transaction_id}")
def status_endpoint(transaction_id: str) -> dict:
    return {"transaction_id": transaction_id, "status": status(transaction_id)}
