"""Step 3: the two-service trust boundary. Three kinds of test, deliberately:
(1) a source-level check that the boundary can't be crossed at all, (2) real
authority-conflict scenarios (bank overrides an ATLAS ALLOW), (3) real
communication failure (bank genuinely unreachable), checked against actual
network behavior, not a mock standing in for one.

Step 6 update: /verify now takes a real SignedAssertion instead of a bare
{subject, amount, transaction_id} dict (that shape was always a Step-3
placeholder -- a real bank only ever receives a signed assertion). Every
test that talks to /verify, directly or through /transact, now builds one
for real via atlas_service.main.build_signed_assertion() -- the same
production code path /transact itself uses, not a hand-rolled parallel --
and wires bank_app to the matching key via conftest.py's
wire_bank_app_to_keys().
"""

from __future__ import annotations

import ast
import socket
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from atlas_service.bank_client import BankUnreachableError, verify_with_bank
from atlas_service.db import TransactionStore
from atlas_service.main import app as atlas_app
from atlas_service.main import (
    build_signed_assertion,
    get_bank_client,
    get_signing_keys_dir,
    get_transaction_store,
)
from bank_service.main import app as bank_app
from contracts import Decision, PolicyDecision, Transaction
from tests.conftest import wire_bank_app_to_keys

ATLAS_ROOT = Path(__file__).resolve().parent.parent


def _tx(**overrides) -> dict:
    defaults = dict(
        transaction_id="tx-boundary-1",
        subject="user-demo-1",
        amount="1500.00",
        currency="INR",
        beneficiary="ben-mother",
        location="Bengaluru,IN",
        device_id="device-primary-01",
        merchant_category="amazon",
        authentication_method="pin",
        is_new_beneficiary=False,
        is_new_device=False,
        is_international=False,
        declared_travel_mode=False,
        is_emergency_request=False,
        timestamp="2026-08-25T12:00:00+00:00",
    )
    defaults.update(overrides)
    return defaults


def _signed_assertion(keys_dir: Path, **tx_overrides):
    """Builds a real signed assertion via the same production function
    /transact uses -- not a parallel hand-rolled payload -- so these tests
    exercise the actual signing path, just without going through the full
    ML/policy pipeline first."""
    tx = Transaction(**_tx(**tx_overrides))
    policy_decision = PolicyDecision(
        transaction_id=tx.transaction_id,
        decision=Decision.ALLOW,
        policy_version=1,
        policy_hash="test-hash",
    )
    return build_signed_assertion(tx, policy_decision, keys_dir=keys_dir)


def _unused_local_port() -> int:
    """A real port with nothing bound to it, for genuine connection-refused
    testing — not simulated, an actual closed socket."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def keys_dir(tmp_path) -> Path:
    return tmp_path / "atlas-keys"


@pytest.fixture(autouse=True)
def _wire_bank(keys_dir, tmp_path):
    """Every test below that reaches /verify, directly or through
    /transact, needs bank_app pointed at the same key atlas-side signing
    will use, plus an isolated replay cache -- doing this once, autoused,
    keeps individual tests focused on what they're actually proving rather
    than repeating wiring boilerplate."""
    wire_bank_app_to_keys(keys_dir, tmp_path / "replay.db")
    yield
    bank_app.dependency_overrides.clear()


# --- source-level boundary: this is checked, not just asserted in a comment --


def _imported_module_roots(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            roots.add(node.module.split(".")[0])
    return roots


@pytest.mark.parametrize(
    "filename", ["main.py", "ledger.py", "verify.py", "replay_cache.py", "revocation.py"]
)
def test_bank_service_never_imports_atlas_internals(filename):
    imports = _imported_module_roots(ATLAS_ROOT / "bank_service" / filename)
    assert "atlas_service" not in imports, (
        f"bank_service/{filename} imports atlas_service — this is exactly the "
        f"boundary that must never be crossed, per ARCHITECTURE.md's authority "
        f"hierarchy (the bank must be independent, not just conventionally "
        f"kept separate)"
    )


# --- bank_service's own decision, tested directly and independently ---------


@pytest.fixture
def bank_client_direct() -> TestClient:
    return TestClient(bank_app)


def test_bank_approves_normal_account(bank_client_direct, keys_dir):
    signed = _signed_assertion(keys_dir, subject="user-demo-1", amount="1500.00", transaction_id="t1")
    r = bank_client_direct.post("/verify", json=signed.model_dump(mode="json"))
    assert r.json() == {"transaction_id": "t1", "approved": True, "reason": "approved"}


def test_bank_rejects_frozen_account(bank_client_direct, keys_dir):
    signed = _signed_assertion(keys_dir, subject="user-frozen-1", amount="500.00", transaction_id="t2")
    r = bank_client_direct.post("/verify", json=signed.model_dump(mode="json"))
    body = r.json()
    assert body["approved"] is False
    assert body["reason"] == "account restrictions"


def test_bank_rejects_insufficient_funds(bank_client_direct, keys_dir):
    signed = _signed_assertion(keys_dir, subject="user-poor-1", amount="5000.00", transaction_id="t3")
    r = bank_client_direct.post("/verify", json=signed.model_dump(mode="json"))
    body = r.json()
    assert body["approved"] is False
    assert body["reason"] == "insufficient funds"


def test_bank_refuses_unknown_account(bank_client_direct, keys_dir):
    """Doesn't guess, doesn't default to approve for an account it's never
    heard of — refuses, same as a frozen one."""
    signed = _signed_assertion(
        keys_dir, subject="user-does-not-exist", amount="10.00", transaction_id="t4"
    )
    r = bank_client_direct.post("/verify", json=signed.model_dump(mode="json"))
    assert r.json()["approved"] is False


def test_bank_rejects_a_cryptographically_invalid_assertion_before_touching_the_ledger(tmp_path):
    """New in Step 6: an assertion signed by a different key than the one
    bank_app is wired to trust (the autouse _wire_bank fixture wires it to
    `keys_dir`; this deliberately signs with a different one) must be refused
    at the assertion layer -- never reach the ledger, and never be confused
    with a legitimate account-level rejection like "insufficient funds"."""
    wrong_keys_dir = tmp_path / "not-the-wired-key"
    signed = _signed_assertion(wrong_keys_dir, subject="user-demo-1", amount="1500.00")
    bank_client = TestClient(bank_app)
    r = bank_client.post("/verify", json=signed.model_dump(mode="json"))
    body = r.json()
    assert body["approved"] is False
    assert body["reason"] == "invalid signature"


# --- bank_client.py: same function, tested against a real ASGI bank AND a --
# --- genuinely closed port, proving the failure path is real, not mocked ---


def test_verify_with_bank_succeeds_against_real_asgi_bank(keys_dir):
    client = TestClient(bank_app)
    signed = _signed_assertion(keys_dir)
    verdict = verify_with_bank(client, "http://bank", signed)
    assert verdict.approved is True


def test_verify_with_bank_raises_on_genuinely_unreachable_port(keys_dir):
    """Not a mock — an actual closed TCP port on localhost. This is the test
    that would catch the real security bug: unreachable silently becoming
    'approved' instead of raising."""
    closed_port = _unused_local_port()
    client = httpx.Client()
    signed = _signed_assertion(keys_dir)
    with pytest.raises(BankUnreachableError):
        verify_with_bank(client, f"http://127.0.0.1:{closed_port}", signed, timeout=1.0)


# --- full /transact flow: authority boundary + communication failure -------


def _atlas_client_with_bank_override(
    bank_transport_client: httpx.Client, keys_dir: Path, store_path: Path
) -> TestClient:
    atlas_app.dependency_overrides[get_bank_client] = lambda: bank_transport_client
    atlas_app.dependency_overrides[get_signing_keys_dir] = lambda: keys_dir
    atlas_app.dependency_overrides[get_transaction_store] = lambda: TransactionStore(store_path)
    return TestClient(atlas_app)


@pytest.fixture(autouse=True)
def _clear_atlas_overrides():
    yield
    atlas_app.dependency_overrides.clear()


def test_transact_allows_when_atlas_and_bank_both_agree(keys_dir, tmp_path):
    bank = TestClient(bank_app)
    client = _atlas_client_with_bank_override(bank, keys_dir, tmp_path / "atlas.db")
    r = client.post("/transact", json=_tx(
        transaction_id="tx-both-agree", subject="user-demo-1", amount="1500.00",
    ))
    body = r.json()
    assert body["decision"]["decision"] == "ALLOW"
    assert body["assertion"] is not None, "an ALLOW must actually produce a signed assertion now"
    assert body["bank_verdict"]["approved"] is True
    assert body["final_status"] == "ALLOW"


def test_transact_bank_overrides_atlas_allow_frozen_account(keys_dir, tmp_path):
    """THE test: ATLAS's own policy for user-frozen-1 is deliberately
    permissive (see the policy YAML) — it says ALLOW. The bank independently
    says no anyway, because the account is frozen, and that must win. This is
    the authority hierarchy from ARCHITECTURE.md made to actually happen in
    running code, not just asserted -- now through a real signed assertion,
    not the old bare pre-crypto shape."""
    bank = TestClient(bank_app)
    client = _atlas_client_with_bank_override(bank, keys_dir, tmp_path / "atlas.db")
    r = client.post("/transact", json=_tx(
        transaction_id="tx-frozen-override", subject="user-frozen-1", amount="500.00",
    ))
    body = r.json()
    assert body["decision"]["decision"] == "ALLOW", "ATLAS's own policy should have said ALLOW here"
    assert body["bank_verdict"]["approved"] is False
    assert body["bank_verdict"]["reason"] == "account restrictions"
    assert body["final_status"] == "DENY", "bank's independent rejection must win over ATLAS's ALLOW"


def test_transact_bank_overrides_atlas_allow_insufficient_funds(keys_dir, tmp_path):
    bank = TestClient(bank_app)
    client = _atlas_client_with_bank_override(bank, keys_dir, tmp_path / "atlas.db")
    r = client.post("/transact", json=_tx(
        transaction_id="tx-poor-override", subject="user-poor-1", amount="5000.00",
    ))
    body = r.json()
    assert body["decision"]["decision"] == "ALLOW"
    assert body["final_status"] == "DENY"


def test_transact_atlas_deny_never_contacts_bank(tmp_path):
    """amount=150000 triggers user-demo-1's hard_cap -> ATLAS DENY. The bank
    client is deliberately pointed at a closed port: if the endpoint tried to
    reach the bank anyway, this would come back PENDING (unreachable), not
    DENY. Getting DENY back proves the bank was never contacted, not just that
    the final answer happened to be right. Also confirms no assertion is
    built or signed for a DENY -- there's nothing to assert."""
    closed_port = _unused_local_port()
    unreachable_bank = httpx.Client()
    atlas_app.dependency_overrides[get_bank_client] = lambda: unreachable_bank
    atlas_app.dependency_overrides[get_transaction_store] = lambda: TransactionStore(tmp_path / "atlas.db")
    import atlas_service.main as atlas_main
    original_url = atlas_main.BANK_SERVICE_URL
    atlas_main.BANK_SERVICE_URL = f"http://127.0.0.1:{closed_port}"
    try:
        client = TestClient(atlas_app)
        r = client.post("/transact", json=_tx(subject="user-demo-1", amount="150000.00"))
        body = r.json()
        assert body["decision"]["decision"] == "DENY"
        assert body["assertion"] is None
        assert body["bank_verdict"] is None
        assert body["final_status"] == "DENY"
    finally:
        atlas_main.BANK_SERVICE_URL = original_url


def test_transact_pending_when_bank_unreachable_despite_atlas_allow(keys_dir, tmp_path):
    """ATLAS says ALLOW, but the bank is genuinely unreachable this time (a
    real closed port, not a mock). Must come back PENDING, never silently
    ALLOW — this is ARCHITECTURE.md's failure-mode table, made to actually
    happen."""
    closed_port = _unused_local_port()
    unreachable_bank = httpx.Client()
    atlas_app.dependency_overrides[get_bank_client] = lambda: unreachable_bank
    atlas_app.dependency_overrides[get_signing_keys_dir] = lambda: keys_dir
    atlas_app.dependency_overrides[get_transaction_store] = lambda: TransactionStore(tmp_path / "atlas.db")
    import atlas_service.main as atlas_main
    original_url = atlas_main.BANK_SERVICE_URL
    atlas_main.BANK_SERVICE_URL = f"http://127.0.0.1:{closed_port}"
    try:
        client = TestClient(atlas_app)
        r = client.post("/transact", json=_tx(subject="user-demo-1", amount="1500.00"))
        body = r.json()
        assert body["decision"]["decision"] == "ALLOW", "ATLAS's own decision should still be ALLOW"
        assert body["assertion"] is not None, "ATLAS still signs before attempting to reach the bank"
        assert body["bank_verdict"] is None
        assert body["final_status"] == "PENDING", (
            "an unreachable bank must never be silently treated as approval"
        )
    finally:
        atlas_main.BANK_SERVICE_URL = original_url
