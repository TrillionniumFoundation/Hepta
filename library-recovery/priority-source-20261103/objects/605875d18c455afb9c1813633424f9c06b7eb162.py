import copy
import random
import unittest
from economic_probe import (COST_FIELDS, comparison, exact_dp, exact_exhaustive,
                            same_information_greedy, strong_fixed)
from hia_probe import Rejected

D='a'*64

def candidate(name,run,**costs):
    base={'id':name,'run_ns':run,'verified_core_digest':D}
    base.update({k:costs.get(k,0) for k in COST_FIELDS})
    return base

def study():
    return {'schema':'hepta.audit.net-benefit.v1', 'study_kind':'synthetic',
            'frozen_source_digest':D, 'objective_digest':D,
            'max_one_time_ns':20,
            'jobs':[{'id':'a','invocations':10,'baseline_run_ns':100,
                     'candidates':[candidate('fast',60,compile_ns=15),candidate('tiny',99,compile_ns=4)]},
                    {'id':'b','invocations':10,'baseline_run_ns':100,
                     'candidates':[candidate('fast',90,compile_ns=15),candidate('tiny',30,compile_ns=4)]}]}

class EconomicTests(unittest.TestCase):
    def test_oracle_agreement(self):
        a=exact_dp(study());b=exact_exhaustive(study())
        self.assertEqual(a['net_savings_ns'],b['net_savings_ns'])
        self.assertEqual(a['one_time_ns'],b['one_time_ns'])
        self.assertGreater(a['net_savings_ns'],0)

    def test_compare_same_information(self):
        result=comparison(study())
        self.assertEqual(len(result['results']),4)
        self.assertEqual(result['native_ndu']['status'],'UNAVAILABLE')
        self.assertFalse(result['acceptance']['ndu_incremental_value_proved'])
        self.assertTrue(all(r['authority']=='DENY_ALL' for r in result['results']))

    def test_negative_costs_reject(self):
        t=study();t['jobs'][0]['candidates'][0]['compile_ns']=-1
        with self.assertRaises(Rejected) as e:comparison(t)
        self.assertEqual(e.exception.code,'E_COST')

    def test_unknown_costs_reject(self):
        t=study();t['jobs'][0]['candidates'][0].pop('rollback_reserve_ns')
        with self.assertRaises(Rejected) as e:comparison(t)
        self.assertEqual(e.exception.code,'E_CANDIDATE')

    def test_missing_source_identity_reject(self):
        t=study();t['objective_digest']=''
        with self.assertRaises(Rejected) as e:comparison(t)
        self.assertEqual(e.exception.code,'E_PROVENANCE')

    def test_negative_benefit_keeps_baseline(self):
        t=study()
        for j in t['jobs']:
            for c in j['candidates']:
                c['run_ns']=j['baseline_run_ns']+1
        for solve in (exact_dp,exact_exhaustive,strong_fixed,same_information_greedy):
            self.assertEqual(solve(t)['net_savings_ns'],0)
            self.assertEqual(solve(t)['one_time_ns'],0)

    def test_budget_is_a_hard_constraint(self):
        t=study();t['max_one_time_ns']=0
        for solve in (exact_dp,exact_exhaustive,strong_fixed,same_information_greedy):
            self.assertEqual(solve(t)['one_time_ns'],0)

    def test_exact_randomized_against_exhaustive(self):
        rng=random.Random(20261031)
        for _ in range(70):
            t=study();t['max_one_time_ns']=rng.randrange(0,100)
            t['jobs']=[]
            for j in range(rng.randrange(1,6)):
                t['jobs'].append({'id':f'j{j}', 'invocations':rng.randrange(1,200),
                    'baseline_run_ns':rng.randrange(1,10000),
                    'candidates':[candidate(f'v{i}',rng.randrange(0,10000),
                                             compile_ns=rng.randrange(0,30),
                                             verify_ns=rng.randrange(0,15),
                                             switch_ns=rng.randrange(0,10))
                                  for i in range(rng.randrange(0,4))]})
            d=exact_dp(t);e=exact_exhaustive(t)
            self.assertEqual((d['one_time_ns'],d['net_savings_ns']),
                             (e['one_time_ns'],e['net_savings_ns']))

if __name__=='__main__':unittest.main()
