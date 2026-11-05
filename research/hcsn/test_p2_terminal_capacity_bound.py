"""Independent finite-codebook and adversarial contract tests (no training)."""
import unittest
from fractions import Fraction
from p2_terminal_capacity_bound import (
    analytic_random_query_accuracy, independent_codebook_optimum,
    full_sequence_upper_bound, independent_monte_carlo, evidence)

class TerminalCapacityTest(unittest.TestCase):
    def test_bayes_exact_small(self):
        self.assertEqual(analytic_random_query_accuracy(1),Fraction(1))
        self.assertEqual(analytic_random_query_accuracy(2),Fraction(3,4))
        self.assertEqual(analytic_random_query_accuracy(3),Fraction(3,4))
        self.assertEqual(analytic_random_query_accuracy(4),Fraction(11,16))

    def test_independent_exhaustive_codebooks(self):
        for k in range(1,7):
            self.assertEqual(independent_codebook_optimum(k),analytic_random_query_accuracy(k))

    def test_one_mode_gives_chance(self):
        for k in range(1,8):
            self.assertEqual(full_sequence_upper_bound(k,1),Fraction(1,1<<k))

    def test_two_state_whole_sequence_bound(self):
        self.assertEqual(full_sequence_upper_bound(4),Fraction(1,8))
        self.assertEqual(full_sequence_upper_bound(8),Fraction(1,128))

    def test_more_states_needed_for_perfect_vector(self):
        self.assertEqual(full_sequence_upper_bound(4,16),Fraction(1))
        self.assertEqual(full_sequence_upper_bound(4,8),Fraction(1,2))

    def test_random_query_decreases_with_load(self):
        self.assertGreater(analytic_random_query_accuracy(4),analytic_random_query_accuracy(16))
        self.assertGreater(analytic_random_query_accuracy(16),analytic_random_query_accuracy(32))

    def test_validation_fails_closed(self):
        for bad in [0,-1,129,True,2.5]:
            with self.assertRaises(ValueError): analytic_random_query_accuracy(bad)
        for bad in [0,-1,True]:
            with self.assertRaises(ValueError): full_sequence_upper_bound(3,bad)
        with self.assertRaises(ValueError): independent_codebook_optimum(8)

    def test_deterministic_monte_carlo(self):
        a=independent_monte_carlo(8,2000,23)
        self.assertEqual(a,independent_monte_carlo(8,2000,23))
        self.assertLess(abs(a['normal_z']),5)

    def test_gate_open_and_no_production(self):
        x=evidence()
        self.assertEqual(set(x['gate'].values()),{'OPEN'})
        self.assertFalse(x['production_activation'])
        self.assertFalse(x['external_independent_acceptance'])
        self.assertFalse(x['proved_full_hcsn'])

if __name__=='__main__': unittest.main()
