"""Reject dishonest formal proof and negative-control receipts at the P0 gate.

Only receipt validation is tested here. Passing does not prove language soundness.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
from pathlib import Path
import re
import unittest

from tools.release_check import require_qualification

ROOT = Path(__file__).resolve().parents[1]


def valid_receipt():
    source = (ROOT / "formal/HeptaCore.lean").read_bytes()
    names = re.findall(r"(?m)^theorem\s+([A-Za-z0-9_]+)", source.decode())
    assert len(names) == 11, "The frozen abstract proof corpus has changed"
    return {
        "source": "formal/HeptaCore.lean",
        "source_sha256": hashlib.sha256(source).hexdigest(),
        "theorems": {name: ["propext"] for name in names},
        "negative_mutations": [
            {
                "mutation": name,
                "status": "rejected_as_expected",
                "source_sha256": "1" * 64,
                "log_sha256": "2" * 64,
            }
            for name in ("release_while_borrowed", "unbounded_task_admission")
        ],
    }


class FormalReceiptGateTests(unittest.TestCase):
    def test_valid_receipt_accepted(self):
        require_qualification("formal_core", valid_receipt())

    def test_negative_case_must_have_executed(self):
        report = valid_receipt()
        report["negative_mutations"][0]["status"] = "not_run"
        with self.assertRaises(ValueError):
            require_qualification("formal_core", report)

    def test_duplicate_negative_cases_rejected(self):
        report = valid_receipt()
        report["negative_mutations"][1] = deepcopy(report["negative_mutations"][0])
        with self.assertRaises(ValueError):
            require_qualification("formal_core", report)

    def test_negative_missing_log_hash_rejected(self):
        report = valid_receipt()
        report["negative_mutations"][0]["log_sha256"] = ""
        with self.assertRaises(ValueError):
            require_qualification("formal_core", report)

    def test_negative_non_object_rejected(self):
        report = valid_receipt()
        report["negative_mutations"][0] = None
        with self.assertRaises(ValueError):
            require_qualification("formal_core", report)

    def test_swapped_theorem_name_rejected(self):
        report = valid_receipt()
        first = next(iter(report["theorems"]))
        report["theorems"]["unrelated_proof"] = report["theorems"].pop(first)
        with self.assertRaises(ValueError):
            require_qualification("formal_core", report)

    def test_untrusted_axiom_rejected(self):
        report = valid_receipt()
        first = next(iter(report["theorems"]))
        report["theorems"][first] = ["sorryAx"]
        with self.assertRaises(ValueError):
            require_qualification("formal_core", report)

    def test_mismatched_formal_source_rejected(self):
        report = valid_receipt()
        report["source_sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            require_qualification("formal_core", report)


if __name__ == "__main__":
    unittest.main()
