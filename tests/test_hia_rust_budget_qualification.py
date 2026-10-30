"""The finite qualification gate must reject real unittest non-pass outcomes."""
import io
import unittest

from tools import qualify_hia_rust_budget_v3 as qualification


def run_cases(case, names):
    suite = unittest.TestSuite(case(name) for name in names)
    return unittest.TextTestRunner(stream=io.StringIO(), verbosity=0).run(suite)


class RustBudgetQualificationResultTests(unittest.TestCase):
    def test_complete_ordinary_success_is_the_only_positive_result(self):
        class Cases(unittest.TestCase):
            def test_first(self):
                self.assertEqual(2 + 3, 5)

            def test_second(self):
                self.assertIsNone(None)

        result = run_cases(Cases, ["test_first", "test_second"])
        self.assertTrue(qualification._complete_test_success(result, 2))
        self.assertFalse(qualification._complete_test_success(result, 3))
        self.assertEqual(qualification._test_counts(result), {
            "run": 2, "failures": 0, "errors": 0, "skipped": 0,
            "expected_failures": 0, "unexpected_successes": 0})

    def test_late_expected_failure_cannot_promote_recorded_observations(self):
        observations = []

        class Cases(unittest.TestCase):
            @unittest.expectedFailure
            def test_observed_then_failed(self):
                observations.append({"actually_reached": True})
                self.fail("failure after retaining an observation")

        result = run_cases(Cases, ["test_observed_then_failed"])
        self.assertEqual(observations, [{"actually_reached": True}])
        self.assertTrue(result.wasSuccessful())
        self.assertEqual(result.testsRun, 1)
        self.assertFalse(qualification._complete_test_success(result, 1))
        self.assertEqual(qualification._test_counts(result), {
            "run": 1, "failures": 0, "errors": 0, "skipped": 0,
            "expected_failures": 1, "unexpected_successes": 0})

    def test_unexpected_success_is_explicitly_reported_and_rejected(self):
        class Cases(unittest.TestCase):
            @unittest.expectedFailure
            def test_unexpected_success(self):
                self.assertEqual(3 * 4, 12)

        result = run_cases(Cases, ["test_unexpected_success"])
        self.assertFalse(qualification._complete_test_success(result, 1))
        self.assertEqual(qualification._test_counts(result), {
            "run": 1, "failures": 0, "errors": 0, "skipped": 0,
            "expected_failures": 0, "unexpected_successes": 1})

    def test_failures_errors_and_skips_cannot_satisfy_the_gate(self):
        class Cases(unittest.TestCase):
            def test_failure(self):
                self.fail("deliberate failed test")

            def test_error(self):
                raise RuntimeError("deliberate test error")

            @unittest.skip("deliberate skipped test")
            def test_skip(self):
                self.fail("a skipped method must not execute")

        for name, field in (("test_failure", "failures"), ("test_error", "errors"),
                            ("test_skip", "skipped")):
            with self.subTest(outcome=field):
                result = run_cases(Cases, [name])
                self.assertEqual(qualification._test_counts(result)[field], 1)
                self.assertFalse(qualification._complete_test_success(result, 1))


if __name__ == "__main__":
    unittest.main()
