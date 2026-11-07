import unittest
from hia_candidate.study import exact_dp,oracle_enumerate,q32_advisory_proxy,qualify_finite_planners,plan_cost

class PlannerTests(unittest.TestCase):
    def test_exact_dp_and_enumeration_agree(self):
        self.assertEqual(exact_dp(),oracle_enumerate())
        self.assertEqual(exact_dp(),q32_advisory_proxy())
    def test_switch_cost_accounted(self):
        self.assertEqual(plan_cost((0,0,0,0,0,0,0,0)),sum(row[0] for row in (
            (1100,1000),(1050,1020),(1200,900),(850,1000),(1300,950),(1000,1010),(900,1050),(1250,920))))
    def test_proxy_does_not_claim_ndu(self):
        result=qualify_finite_planners()
        self.assertFalse(result['actual_native_ndu_used'])
        self.assertFalse(result['NDU_additional_value_proven'])
        self.assertEqual(result['enumeration']['plan'],result['exact_dp']['plan'])
if __name__=='__main__':unittest.main()
