"""Check structural integrity of formal receipts, not Lean soundness itself.

The positive receipt here is a synthetic schema fixture; only a real pinned
Lean execution and its captured artifacts qualify the formal subset gate.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
from pathlib import Path
import re
import unittest

from tools.release_check import require_qualification
from tools.verify_formal import negative_sources

ROOT = Path(__file__).resolve().parents[1]


def structurally_valid_receipt():
    source = (ROOT / "formal/HeptaCore.lean").read_text()
    names = re.findall(r"(?m)^theorem\s+([A-Za-z0-9_]+)", source)
    assert len(names) == 11, "The frozen abstract proof corpus has changed"
    negative = []
    for name, broken in negative_sources(source).items():
        log = f"error: synthetic negative control {name} was rejected\n"
        negative.append({
            "mutation": name, "status": "rejected_as_expected",
            "source_sha256": hashlib.sha256(broken.encode()).hexdigest(),
            "exit_code": 1, "log": log,
            "log_sha256": hashlib.sha256(log.encode()).hexdigest(),
        })
    return {
        "schema": "hepta.formal.v1",
        "status": "passed",
        "lean": "Lean (version 4.19.0, synthetic-test-fixture)",
        "source": "formal/HeptaCore.lean",
        "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
        "theorems": {name: ["propext"] for name in names},
        "kernel_output": "".join(
            f"'Hepta.{name}' depends on axioms: [propext]\n" for name in names
        ),
        "negative_mutations": negative,
    }


class FormalReceiptGateTests(unittest.TestCase):
    def test_structurally_valid_fixture_accepted(self):
        require_qualification("formal_core", structurally_valid_receipt())

    def test_negative_case_must_have_executed(self):
        report = structurally_valid_receipt()
        report["negative_mutations"][0]["status"] = "not_run"
        with self.assertRaises(ValueError):
            require_qualification("formal_core", report)

    def test_duplicate_negative_cases_rejected(self):
        report = structurally_valid_receipt()
        report["negative_mutations"][1] = deepcopy(report["negative_mutations"][0])
        with self.assertRaises(ValueError):
            require_qualification("formal_core", report)

    def test_negative_missing_log_hash_rejected(self):
        report = structurally_valid_receipt()
        report["negative_mutations"][0]["log_sha256"] = ""
        with self.assertRaises(ValueError):
            require_qualification("formal_core", report)

    def test_negative_non_object_rejected(self):
        report = structurally_valid_receipt()
        report["negative_mutations"][0] = None
        with self.assertRaises(ValueError):
            require_qualification("formal_core", report)

    def test_swapped_theorem_name_rejected(self):
        report = structurally_valid_receipt()
        first = next(iter(report["theorems"]))
        report["theorems"]["unrelated_proof"] = report["theorems"].pop(first)
        with self.assertRaises(ValueError):
            require_qualification("formal_core", report)

    def test_untrusted_axiom_rejected(self):
        report = structurally_valid_receipt()
        first = next(iter(report["theorems"]))
        report["theorems"][first] = ["sorryAx"]
        with self.assertRaises(ValueError):
            require_qualification("formal_core", report)

    def test_mismatched_formal_source_rejected(self):
        report = structurally_valid_receipt()
        report["source_sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            require_qualification("formal_core", report)

    def test_forged_negative_source_hash_rejected(self):
        report = structurally_valid_receipt()
        report["negative_mutations"][0]["source_sha256"] = "1" * 64
        with self.assertRaises(ValueError):
            require_qualification("formal_core", report)

    def test_forged_negative_log_hash_rejected(self):
        report = structurally_valid_receipt()
        report["negative_mutations"][0]["log_sha256"] = "2" * 64
        with self.assertRaises(ValueError):
            require_qualification("formal_core", report)

    def test_missing_negative_log_rejected(self):
        report = structurally_valid_receipt()
        del report["negative_mutations"][0]["log"]
        with self.assertRaises(ValueError):
            require_qualification("formal_core", report)

    def test_successful_negative_exit_rejected(self):
        report = structurally_valid_receipt()
        report["negative_mutations"][0]["exit_code"] = 0
        with self.assertRaises(ValueError):
            require_qualification("formal_core", report)

    def test_missing_kernel_dependency_output_rejected(self):
        report = structurally_valid_receipt()
        report["kernel_output"] = ""
        with self.assertRaises(ValueError):
            require_qualification("formal_core", report)

    def test_changed_claimed_axioms_without_kernel_output_rejected(self):
        report = structurally_valid_receipt()
        first = next(iter(report["theorems"]))
        report["theorems"][first] = ["Quot.sound"]
        with self.assertRaises(ValueError):
            require_qualification("formal_core", report)


if __name__ == "__main__":
    unittest.main()
