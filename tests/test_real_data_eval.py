"""scripts/evaluate_real_data.py -- ATLAS's own ML on real bank customers (2026-09-29).

The dataset itself is not in the repository, so these tests pin the two things
that decide whether the published figures mean what they say: how a raw bank row
becomes an ATLAS payment, and whether docs/ml-real-data.json is internally
consistent and honest about what it measures.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import evaluate_real_data as erd  # noqa: E402

ROWS = [
    # trans_id account date amount balance type operation k_symbol bank partner
    ("3", "7", "2015-01-05", "120.00", "900.00", "D", "ROB", "HH", "AB", "41403269"),
    ("1", "7", "2015-01-02", "50.00", "1000.00", "D", "WIC", "", "", ""),
    ("2", "7", "2015-01-02", "9.90", "990.00", "D", "WIC", "ST", "", ""),       # statement fee
    ("4", "7", "2015-01-06", "700.00", "1600.00", "C", "CIC", "", "", ""),       # money in
    ("5", "7", "2015-01-07", "30.00", "1570.00", "D", "CCW", "", "", ""),
    ("6", "7", "2015-01-08", "2.10", "1567.90", "D", "WIC", "IO", "", ""),       # penalty interest
    ("7", "8", "2015-02-01", "80.00", "500.00", "P", "WIC", "", "", ""),
]


def _write(tmp_path):
    path = tmp_path / "fin_trans.tsv"
    path.write_text("".join("\t".join(r) + "\n" for r in ROWS), encoding="utf-8")
    return path


def test_only_customer_payments_count_oldest_first(tmp_path):
    accounts = erd.payments_by_account(_write(tmp_path))
    assert [r["trans_id"] for r in accounts["7"]] == ["1", "3", "5"]    # no fee, no credit, no interest
    assert [r["trans_id"] for r in accounts["8"]] == ["7"]


def test_a_bank_row_becomes_an_atlas_payment_with_its_real_payee(tmp_path):
    rows = erd.payments_by_account(_write(tmp_path))["7"]
    cash, transfer, card = (erd.to_transaction(r, "cz-7") for r in rows)
    assert transfer.beneficiary == "acct-AB:41403269" and transfer.merchant_category == "HH"
    assert cash.beneficiary == "cash-withdrawal" and cash.merchant_category == "cash"
    assert card.beneficiary == "card-payment" and card.merchant_category == "card"
    assert transfer.timestamp == "2015-01-05T12:00:00+00:00"           # dates only: noon
    assert str(transfer.amount) == "120.00" and transfer.subject == "cz-7" and transfer.currency == "CZK"


def test_the_published_figures_are_consistent_and_say_what_they_measure():
    saved = json.loads((ROOT / "docs" / "ml-real-data.json").read_text(encoding="utf-8"))
    assert saved["dataset"]["real"] is True and saved["dataset"]["fraud_labels"] is False
    assert saved["dataset"]["committed"] is False
    assert "not fraud detection" in saved["what_it_measures"]
    assert "hour_of_day" in saved["constant_features"]
    n = saved["test_payments"]
    assert n == saved["accounts"] * (erd.TEST_END - erd.TEST_START)
    assert [r["history_size"] for r in saved["by_history_size"]] == list(erd.HISTORY_SIZES)
    for r in saved["by_history_size"]:
        assert 0 <= r["high"] <= r["medium_or_high"] <= n
        assert r["high_rate"] == round(r["high"] / n, 4)
        assert r["medium_or_high_rate"] == round(r["medium_or_high"] / n, 4)
    assert 0 <= saved["burst_signal"]["fired"] <= n


def test_the_dataset_never_enters_the_repository():
    tracked = subprocess.run(["git", "-C", str(ROOT), "ls-files"], capture_output=True, text=True,
                             check=True).stdout.split()
    assert not [f for f in tracked if "fin_trans" in f or "pkdd" in f.lower()]
    assert ROOT not in erd.DATA.parents
