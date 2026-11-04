import unittest
from .calibrate_examples import observe


class HeadroomAudit(unittest.TestCase):
    def test_examples_include_same_owner_final_revalidation_without_policy_claim(self):
        result = observe()
        self.assertEqual(result['graphs'], 68)
        self.assertEqual(len(result['diagnostics']), 12)
        self.assertFalse(result['policy_selected'])
        self.assertFalse(result['runtime_checkout_attested'])
        self.assertFalse(result['diagnostic_case_counters_measured'])
        self.assertTrue(result['checkout_path_dependent'])
        self.assertIn('parser_depth', result['unmeasured_limit_dimensions'])
        self.assertIn('source', result['unmeasured_limit_dimensions'])
        for name, item in result['peaks'].items():
            self.assertLessEqual(item['after_load'], item['max_observed'], name)
            self.assertLessEqual(item['max_observed'], item['current_limit'], name)
        self.assertGreater(result['peaks']['reads']['max_observed'], result['peaks']['reads']['after_load'])
        self.assertGreater(result['peaks']['total_bytes']['max_observed'], result['peaks']['total_bytes']['after_load'])


if __name__ == '__main__':unittest.main()
