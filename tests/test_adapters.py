"""Step 7: payment-rail adapters. BUILD-PLAN.md's test scenario 11 -- "same
PolicyDecision object run through both rail adapters -> consistent semantic
result in each shape" -- plus the adversarial cases that make that claim
mean something.

The two tests carrying the most weight here:

- test_signature_still_verifies_after_framing_through_each_rail proves an
  adapter FRAMES rather than MUTATES. Step 5's signature covers the canonical
  AssertionPayload bytes, so any adapter that edited through the assertion
  would silently break verification at the bank.
- test_an_adapter_that_mutates_the_signed_assertion_breaks_verification
  proves that constraint is load-bearing rather than assumed, by doing the
  forbidden thing on purpose and watching verification fail.

What these tests deliberately do NOT claim: that policy semantics survive
translation across real payment rails. Two toy adapters agreeing in a
simulation is not that. See atlas_service/adapters/__init__.py's docstring
and RQ-16/18/19/25/26, still open.
"""

from __future__ import annotations

import ast
from decimal import Decimal
from pathlib import Path

import pytest

from atlas_service.adapters import (
    RAIL_ADAPTERS,
    SUPPORTED_RAILS,
    UnknownRailError,
    fx,
    pix_adapter,
    semantic_view,
    to_rail_payload,
    upi_adapter,
)
from atlas_service.main import build_signed_assertion
from bank_service.replay_cache import ReplayCache
from bank_service.verify import verify_assertion
from contracts import Decision, PolicyDecision, SignedAssertion, Transaction

ATLAS_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def keys_dir(tmp_path) -> Path:
    return tmp_path / "atlas-keys"


def _signed(keys_dir: Path, *, amount="1500.00", currency="INR",
            decision=Decision.ALLOW, **tx_overrides) -> SignedAssertion:
    """Builds a real signed assertion via the same production function
    /transact uses."""
    fields = dict(
        transaction_id="tx-rail-1",
        subject="user-demo-1",
        amount=amount,
        currency=currency,
        beneficiary="ben-mother",
        location="Bengaluru,IN",
        device_id="device-primary-01",
        authentication_method="pin",
        timestamp="2026-08-25T12:00:00+00:00",
    )
    fields.update(tx_overrides)
    tx = Transaction(**fields)
    policy_decision = PolicyDecision(
        transaction_id=tx.transaction_id,
        decision=decision,
        policy_version=3,
        policy_hash="test-policy-hash",
    )
    return build_signed_assertion(tx, policy_decision, keys_dir=keys_dir)


# --- each rail produces its own shape ----------------------------------------


def test_upi_payload_has_the_expected_upi_shape(keys_dir):
    payload = upi_adapter.to_payload(_signed(keys_dir))
    assert payload["rail"] == "UPI"
    assert payload["txn_ref"] == "tx-rail-1"
    assert payload["payer_vpa"] == "user-demo-1@atlasbank"
    assert payload["payee_vpa"] == "ben-mother@atlasbank"
    assert payload["amount"] == {"value": "1500.00", "currency": "INR"}


def test_pix_payload_has_the_expected_pix_shape(keys_dir):
    payload = pix_adapter.to_payload(_signed(keys_dir))
    assert payload["rail"] == "PIX"
    assert payload["txid"] == "tx-rail-1"
    assert payload["pagador"]["chave"] == "user-demo-1@atlas.br"
    assert payload["recebedor"]["chave"] == "ben-mother@atlas.br"
    assert payload["valor"]["moeda"] == "BRL"
    assert payload["valor_origem"] == {"original": "1500.00", "moeda": "INR"}


def test_the_two_rail_shapes_are_genuinely_different(keys_dir):
    """Guards against the whole step degrading into two near-identical
    dicts, which would make "same policy, different rail output" a claim
    rather than a demonstration."""
    signed = _signed(keys_dir)
    upi = upi_adapter.to_payload(signed)
    pix = pix_adapter.to_payload(signed)

    shared_keys = set(upi) & set(pix)
    # only the two structural fields every rail payload carries
    assert shared_keys == {"rail", "atlas_assertion"}
    assert upi["rail"] != pix["rail"]


# --- BUILD-PLAN.md test 11: consistent semantics across both shapes ---------


def test_both_rails_reduce_to_identical_semantics(keys_dir):
    """The actual point of Step 7. Each adapter's semantic_view() reverses
    its OWN shape (neither reads the embedded assertion -- see
    pix_adapter's docstring for why that matters), so this compares two
    independent translations agreeing, not one extractor echoing itself."""
    signed = _signed(keys_dir)

    upi_semantics = upi_adapter.semantic_view(upi_adapter.to_payload(signed))
    pix_semantics = pix_adapter.semantic_view(pix_adapter.to_payload(signed))

    assert upi_semantics == pix_semantics
    assert upi_semantics.transaction_id == "tx-rail-1"
    assert upi_semantics.subject == "user-demo-1"
    assert upi_semantics.beneficiary == "ben-mother"
    assert upi_semantics.signed_amount == "1500.00"
    assert upi_semantics.signed_currency == "INR"


@pytest.mark.parametrize("decision", [Decision.ALLOW, Decision.STEP_UP, Decision.DENY])
def test_decision_never_flips_between_rails(keys_dir, decision):
    """An adapter must carry the decision faithfully -- never "normalize" a
    non-ALLOW decision into a payment instruction on the assumption that
    anything being adapted must already be approved."""
    signed = _signed(keys_dir, decision=decision)

    for rail in SUPPORTED_RAILS:
        semantics = semantic_view(rail, to_rail_payload(rail, signed))
        assert semantics.decision == decision.value


def test_policy_version_and_hash_survive_both_translations(keys_dir):
    signed = _signed(keys_dir)
    for rail in SUPPORTED_RAILS:
        semantics = semantic_view(rail, to_rail_payload(rail, signed))
        assert semantics.policy_version == 3
        assert semantics.policy_hash == "test-policy-hash"


# --- the load-bearing constraint: framing, not mutation ---------------------


def test_signature_still_verifies_after_framing_through_each_rail(keys_dir, tmp_path):
    """Extract the assertion back out of each rail payload and run it
    through bank_service's real verification. Both must still verify --
    proving the adapter framed the assertion rather than editing through
    it."""
    from atlas_service import crypto

    signed = _signed(keys_dir)
    public_key_hex = crypto.get_public_key(keys_dir=keys_dir)

    for rail in SUPPORTED_RAILS:
        payload = to_rail_payload(rail, signed)
        recovered = SignedAssertion(**payload["atlas_assertion"])
        # a fresh cache per rail -- otherwise the second rail would be
        # rejected as a replay of the first, which is correct behavior but
        # not what this test is about
        cache = ReplayCache(tmp_path / f"replay-{rail}.db")
        ok, reason = verify_assertion(recovered, public_key_hex, cache)
        assert ok is True, f"{rail} broke signature verification: {reason}"


def test_an_adapter_that_mutates_the_signed_assertion_breaks_verification(keys_dir, tmp_path):
    """Proves the constraint above is load-bearing, not decorative, by
    doing the forbidden thing deliberately: edit a field INSIDE the carried
    assertion, exactly as a careless adapter "translating" an amount would,
    and confirm the bank rejects it."""
    from atlas_service import crypto

    signed = _signed(keys_dir)
    public_key_hex = crypto.get_public_key(keys_dir=keys_dir)

    payload = upi_adapter.to_payload(signed)
    payload["atlas_assertion"]["payload"]["amount"] = "1.00"  # the forbidden edit

    recovered = SignedAssertion(**payload["atlas_assertion"])
    cache = ReplayCache(tmp_path / "replay.db")
    ok, reason = verify_assertion(recovered, public_key_hex, cache)

    assert ok is False
    assert reason == "invalid signature"


# --- cross-border FX: the divergence, demonstrated rather than hidden -------


def test_pix_rail_amount_diverges_from_the_signed_amount(keys_dir):
    signed = _signed(keys_dir, amount="1500.00", currency="INR")
    payload = pix_adapter.to_payload(signed)

    assert payload["valor"]["original"] != payload["valor_origem"]["original"]
    assert payload["valor"]["moeda"] == "BRL"
    assert payload["valor_origem"]["moeda"] == "INR"


def test_converting_and_converting_back_does_not_return_the_original_amount():
    """The concrete, runnable form of ARCHITECTURE.md's hardest open problem
    (RQ-16/25/26): two-decimal money rounding alone means a limit expressed
    in INR does not cleanly become a limit in BRL. Nothing here fixes that;
    this test exists so the gap is visible and measurable instead of
    quietly absorbed."""
    original = Decimal("1234.56")
    converted = fx.convert(original, "INR", "BRL")
    back = fx.convert(converted, "BRL", "INR")

    assert back != original, (
        "if this ever passes, the demo has stopped demonstrating the rounding "
        "problem it is supposed to make visible"
    )


def test_semantic_view_reports_the_signed_amount_not_the_converted_one(keys_dir):
    """The signed amount is what the bank verifies and what the policy limit
    was evaluated against -- so it, not the local BRL presentation, is what
    the transaction means."""
    signed = _signed(keys_dir, amount="1500.00", currency="INR")
    semantics = pix_adapter.semantic_view(pix_adapter.to_payload(signed))

    assert semantics.signed_amount == "1500.00"
    assert semantics.signed_currency == "INR"


def test_unsupported_currency_pair_raises_rather_than_passing_through():
    with pytest.raises(fx.UnsupportedCurrencyPairError):
        fx.convert(Decimal("100.00"), "INR", "JPY")


# --- fail-closed dispatch ----------------------------------------------------


def test_unknown_rail_raises_rather_than_defaulting(keys_dir):
    """An unrecognized rail must never quietly fall back to UPI -- that
    would mean sending a payment over a rail nobody selected."""
    signed = _signed(keys_dir)
    with pytest.raises(UnknownRailError):
        to_rail_payload("SWIFT", signed)


def test_registry_exposes_exactly_the_two_v1_rails():
    """FPS is deliberately deferred (BUILD-PLAN.md's V1-vs-deferred table);
    this pins that so a third rail can't appear unnoticed."""
    assert set(RAIL_ADAPTERS) == {"UPI", "PIX"}


# --- the untrusted-side property, enforced structurally ---------------------


def _imported_module_paths(path: Path) -> set[str]:
    """Full dotted paths, unlike test_bank_boundary.py's root-only version --
    adapters legitimately import atlas_service.adapters.*, so a root-level
    check would be useless here."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    paths: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            paths.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            paths.add(node.module)
    return paths


@pytest.mark.parametrize(
    "filename", ["__init__.py", "base.py", "fx.py", "upi_adapter.py", "pix_adapter.py"]
)
def test_adapters_never_import_trusted_core_internals(filename):
    """ARCHITECTURE.md puts the payment adapter on the UNTRUSTED side of the
    trust boundary: it "never sees the private key or the raw
    policy-evaluation internals." BUILD-PLAN.md's folder structure places
    adapters under atlas_service/ anyway, so that property is enforced here
    rather than left to convention -- same discipline as
    test_bank_boundary.py's source-level check on bank_service."""
    forbidden = {"atlas_service.crypto", "atlas_service.policy", "atlas_service.ml"}
    imports = _imported_module_paths(ATLAS_ROOT / "atlas_service" / "adapters" / filename)
    leaked = {i for i in imports if any(i == f or i.startswith(f + ".") for f in forbidden)}
    assert not leaked, (
        f"atlas_service/adapters/{filename} imports {leaked} -- adapters are on the "
        f"untrusted side of the trust boundary and must never reach into the trusted "
        f"core's key handling or policy internals"
    )
