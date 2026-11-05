"""Small executed integration smoke; never an efficacy/production qualification."""
import math
import unittest
try:
    from .p1_paired_policy_audit import run
except ImportError:
    from p1_paired_policy_audit import run

class P1PairedAuditSmoke(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=run(smoke=True)

    def test_frozen_protocol_and_no_false_closure(self):
        r=self.data
        self.assertEqual(r['protocol']['seeds'],[11,23,37])
        self.assertTrue(r['protocol']['exploratory_smoke'])
        self.assertFalse(r['matched_backward_flops_proven'])
        self.assertFalse(r['externally_attested'])
        self.assertFalse(r['independent_gain_demonstrated'])
        self.assertEqual(r['p1_scientific_gate'],'OPEN')
        self.assertFalse(r['production_activation'])
        self.assertEqual(len(r['train_logs']),18)
        for tag in ('id','ood'):
            self.assertEqual(len(r['protocol']['holdout_input_sha256'][tag]),64)
            values=r['by_distribution'][tag]['mean_exact_policy_regret']
            self.assertEqual(len(values),6)
            self.assertTrue(all(math.isfinite(x) and x>=0 for x in values.values()))

    def test_heldout_signed_slope_and_trainable_parity(self):
        r=self.data
        self.assertTrue(r['trainable_parameters_matched'])
        self.assertTrue(r['optimizer_updates_matched'])
        self.assertTrue(r['trained_on_identical_seed_rows'])
        self.assertEqual(r['signed_slope_control']['features_and_jacobians_checked_on_heldout'],512)
        self.assertLess(r['signed_slope_control']['max_abs_signed_jacobian_difference'],1e-3)
        self.assertFalse(r['signed_slope_control']['equivalence_global_certified'])

if __name__=='__main__':unittest.main()
