"""scripts/demo.py -- the one-command run for visitors (2026-09-29).

The demo is what a stranger runs to see ATLAS decide, so it must be right in
two ways: it shows the real outcomes (ALLOW, STEP_UP, DENY, and a refused
replay), and it changes nothing on the machine it runs on. The second is also
enforced by conftest.py's guard, which fails any test that touches a live
store or key folder.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import demo  # noqa: E402


def test_the_demo_shows_allow_step_up_deny_and_a_refused_replay():
    from atlas_service.main import app as atlas_app
    from bank_service import db as bank_db
    from bank_service.main import app as bank_app

    ledger_before = bank_db.DEFAULT_DB_PATH
    lines: list[str] = []
    assert demo.run(out=lines.append) == 0
    text = "\n".join(lines)

    assert "ATLAS says ALLOW   ->  device LED [GREEN]" in text
    assert "ATLAS says STEP_UP   ->  device LED [AMBER]" in text
    assert "ATLAS says DENY   ->  device LED [RED]" in text
    assert "policy rule 'hard_cap': the amount is over Rs 1,00,000 -> DENY" in text
    assert "policy rule 'odd_hours'" in text                       # the late-night bonus press
    assert "bank: verified ATLAS's signed decision and approved the payment" in text
    assert "second time: FAIL_CLOSED (COUNTER_REGRESSION" in text
    assert "Result: ALLOW, STEP_UP, DENY  -- as the policy requires" in text
    assert "Temporary folder deleted" in text
    # It says what is simulated, not only what is real.
    assert "Simulated: the ESP32" in text

    # Nothing it redirected is left redirected.
    assert atlas_app.dependency_overrides == {} and bank_app.dependency_overrides == {}
    assert bank_db.DEFAULT_DB_PATH == ledger_before


def test_the_verdict_fails_on_anything_but_allow_step_up_deny_in_order():
    assert demo.verdict(["ALLOW", "STEP_UP", "DENY"])[0]
    for wrong in (["ALLOW", "ALLOW", "DENY"], ["DENY", "STEP_UP", "ALLOW"],
                  ["ALLOW", "STEP_UP"], ["ALLOW", "STEP_UP", "DENY", "DENY"]):
        ok, line = demo.verdict(wrong)
        assert not ok and "EXPECTED ALLOW, STEP_UP, DENY" in line


def test_rupees_use_indian_grouping():
    assert demo.rupees(1500) == "Rs 1,500.00"
    assert demo.rupees(150000) == "Rs 1,50,000.00"
    assert demo.rupees(12345678.9) == "Rs 1,23,45,678.90"
    assert demo.rupees(999) == "Rs 999.00"


def test_rules_are_explained_from_the_policy_file_itself():
    import yaml

    policy = yaml.safe_load((ROOT / "atlas_service/policy/policies/user-demo-1.yaml").read_text(encoding="utf-8"))
    words = {r["name"]: demo.rule_in_words(r, policy.get("timezone")) for r in policy["rules"]}
    assert words["large_amount"] == "the amount is over Rs 50,000 -> STEP_UP"
    assert words["new_beneficiary_meaningful_amount"] == (
        "the payee is new to this customer and the amount is over Rs 20,000 -> STEP_UP")
    assert words["odd_hours"] == "it is between 22:00 and 06:00 (Asia/Kolkata) -> STEP_UP"
    assert words["velocity_burst"] == "there are more than 20 payments in 24 hours -> DENY"
    assert words["high_ml_risk"] == "the ML evidence is HIGH -> STEP_UP"
    assert words["international_txn"] == "the payment is international -> STEP_UP"
