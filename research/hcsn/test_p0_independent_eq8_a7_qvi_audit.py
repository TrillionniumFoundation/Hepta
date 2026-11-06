"""Tests for the standalone P0 iteration-45 numerical reference."""
from __future__ import annotations
import unittest
from research.hcsn.p0_independent_eq8_a7_qvi_audit import run_audit


class IndependentHXAndQVIAudit(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = run_audit()

    def test_eq12_matches_direct_eq11_smooth_fit_roots(self):
        hx = self.result["original_hx"]
        self.assertEqual(hx["accepted_rows"], 40)
        self.assertLess(hx["max_boundary_relative_error"], 1e-9)

    def test_literal_a7_matches_independent_green_integrals(self):
        hx = self.result["original_hx"]
        self.assertLess(hx["max_a7_green_relative_error"], 1e-8)
        self.assertLess(max(x["relative_error"] for x in hx["baseline"]["points"]), 1e-8)

    def test_fp32_information_loss_pair_is_preserved(self):
        pair = self.result["fp32_information_loss"]
        self.assertTrue(pair["same_fp32_tax_bits"])
        self.assertTrue(pair["same_fp32_boundary_bits"])
        self.assertTrue(pair["opposite_qB_signs"])
        self.assertFalse(self.result["original_hx"].get("full_domain_certified", False))

    def test_separate_qvi_mesh_refinement_and_complementarity(self):
        qvi = self.result["separate_fixed_reset_qvi"]
        rows = qvi["mesh_results"]
        self.assertEqual(len(rows), 3)
        self.assertTrue(qvi["boundary_refinement_monotone"])
        self.assertTrue(qvi["value_refinement_monotone"])
        self.assertTrue(all(x["max_complementarity_residual"] < 1e-7 for x in rows))
        self.assertFalse(self.result["general_endogenous_qvi_proved"])

    def test_every_scientific_gate_stays_open(self):
        self.assertEqual(set(self.result["gates"].values()), {"OPEN"})
        self.assertFalse(self.result["external_scientific_attestation"])
        self.assertFalse(self.result["production_activation"])


if __name__ == "__main__":
    unittest.main()
