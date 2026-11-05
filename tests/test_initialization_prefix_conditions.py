"""Abstract scalar lemmas do not grant initialization-elision authority."""
import unittest
from unittest.mock import patch
from tools.prove_initialization_prefix_conditions import prove_prefix_conditions
try:
    import z3
    PINNED = z3.get_version_string() == '4.15.4'
except ImportError:
    PINNED = False


class InitializationPrefixConditionsTests(unittest.TestCase):
    def denied(self, report):
        self.assertEqual(report['authority'], 'DENY_ALL')
        for flag in ('initialization_elision_authorized', 'production_admission', 'native_admission',
                     'performance_qualified', 'quota_equivalence', 'actual_core_bridge_proved',
                     'backend_refinement_proved'):
            self.assertFalse(report[flag])

    @unittest.skipUnless(PINNED, 'existing pinned solver required')
    def test_six_conditional_lemmas_and_four_counterexamples(self):
        report = prove_prefix_conditions()
        self.denied(report)
        self.assertEqual(report['status'], 'checked', report)
        self.assertEqual(len(report['obligations']), 10)
        self.assertEqual(sum(row['status'] == 'unsat' for row in report['obligations']), 6)
        self.assertEqual(sum(row['status'] == 'sat' for row in report['obligations']), 4)
        self.assertTrue(all('(check-sat)' in row['smt2'] for row in report['obligations']))

    def test_missing_solver_is_unknown_never_authority(self):
        with patch.dict('sys.modules', {'z3': None}):
            report = prove_prefix_conditions()
        self.denied(report)
        self.assertEqual(report['status'], 'unknown')

    @unittest.skipUnless(PINNED, 'existing pinned solver required')
    def test_wrong_solver_version_is_unknown(self):
        with patch.object(z3, 'get_version_string', return_value='not-pinned'):
            report = prove_prefix_conditions()
        self.denied(report)
        self.assertEqual(report['status'], 'unknown')

    @unittest.skipUnless(PINNED, 'existing pinned solver required')
    def test_solver_exception_is_unknown(self):
        with patch.object(z3, 'Solver', side_effect=RuntimeError('synthetic solver failure')):
            report = prove_prefix_conditions()
        self.denied(report)
        self.assertEqual(report['status'], 'unknown')

    @unittest.skipUnless(PINNED, 'existing pinned solver required')
    def test_solver_unknown_is_not_a_matched_obligation(self):
        with patch.object(type(z3.Solver()), 'check', return_value=z3.unknown):
            report = prove_prefix_conditions()
        self.denied(report)
        self.assertEqual(report['status'], 'unknown')
        self.assertTrue(any(row['status'] == 'unknown' for row in report['obligations']))
