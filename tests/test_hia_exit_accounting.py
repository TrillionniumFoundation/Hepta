"""Independent model proof obligations and solver refusal behavior."""
from importlib.util import find_spec
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools.verify_hia_exit_accounting import check


@unittest.skipUnless(find_spec("z3"), "Z3 required for ledger induction; NOT qualified")
class ExitAccountingProofTests(unittest.TestCase):
    def test_each_inductive_obligation_is_nonvacuous_and_mutants_have_countermodels(self):
        with tempfile.TemporaryDirectory(prefix="hia-exit-proof-") as directory:
            report = check(directory)
            self.assertTrue(report["passed"])
            self.assertEqual((report["inductive_obligations"], report["nonvacuity_checks"], report["negative_controls"]),
                             (15, 15, 4))
            self.assertEqual(json.loads((Path(directory) / "report.json").read_text()), report)
            self.assertEqual(len(list(Path(directory).glob("*.smt2"))), 34)
            self.assertTrue(all(row["expected"] == row["answer"] for row in report["results"]))
            self.assertFalse(report["claims"]["production_runtime_refinement_proved"])

    def test_solver_unknown_never_becomes_success_or_a_proof_claim(self):
        with tempfile.TemporaryDirectory(prefix="hia-exit-unknown-") as directory, patch("z3.Solver") as factory:
            factory.return_value.to_smt2.return_value = "; injected solver unavailable\n"
            factory.return_value.check.return_value = "unknown"
            factory.return_value.reason_unknown.return_value = "injected timeout"
            report = check(directory)
            self.assertFalse(report["passed"])
            self.assertFalse(report["claims"]["abstract_integer_ledger_event_invariants_inductive"])
            self.assertFalse(report["claims"]["guarded_scalar_return_balances_resource_counts"])
            self.assertTrue(all(row["answer"] == "unknown" for row in report["results"]))


if __name__ == "__main__":
    unittest.main()
