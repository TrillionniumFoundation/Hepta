"""Independent-focused tests for the research decision/physical-READ bridge."""
import json
import math
import random
import unittest

try:
    from .boundary_content_bridge import (PublicState, SealedEpisode, advantage,
        boundary_intervention,execute,observation_plus_probability,ordinary_one_step,
        oracle,policy_value,posterior,run_panel,value)
except ImportError:
    from boundary_content_bridge import (PublicState, SealedEpisode, advantage,
        boundary_intervention,execute,observation_plus_probability,ordinary_one_step,
        oracle,policy_value,posterior,run_panel,value)


class BridgeTests(unittest.TestCase):
    def test_single_observation_voi(self):
        rng=random.Random(12)
        for _ in range(500):
            p=rng.uniform(.01,.99);q=rng.uniform(.50,.999);c=rng.uniform(0,.20)
            s=PublicState(p,q,c,1)
            target=max(max(p,1-p),q-c)
            self.assertAlmostEqual(value(p,q,c,1),target,places=12)
            self.assertEqual(oracle(s),ordinary_one_step(s))

    def test_bayes_martingale(self):
        for p in (.05,.2,.51,.75,.98):
            for q in (.5,.6,.9,.99):
                w=observation_plus_probability(p,q)
                self.assertAlmostEqual(w*posterior(p,q,1)+(1-w)*posterior(p,q,-1),p,places=13)

    def test_value_decreases_with_cost_and_increases_with_budget(self):
        rng=random.Random(31)
        for _ in range(200):
            p=rng.uniform(.05,.95);q=rng.uniform(.55,.99);c=rng.uniform(.005,.15)
            v=[value(p,q,c,j) for j in range(5)]
            self.assertTrue(all(v[i+1]+1e-13>=v[i] for i in range(4)))
            self.assertLessEqual(value(p,q,c+0.01,4),v[-1]+1e-13)

    def test_policy_independent_regret(self):
        rng=random.Random(9)
        for _ in range(200):
            s=PublicState(rng.uniform(.15,.90),rng.uniform(.53,.98),rng.uniform(0,.18),3)
            v=value(s.p,s.q,s.cost,s.remaining)
            self.assertAlmostEqual(policy_value(s,oracle),v,places=12)
            for policy in (ordinary_one_step,boundary_intervention(.03),lambda _:False):
                self.assertGreaterEqual(v-policy_value(s,policy),-1e-11)

    def test_physical_read_is_gated_before_observation(self):
        s=PublicState(.50,.92,.01,3)
        never=SealedEpisode(s,1,123)
        a=execute(never,lambda _:False)
        self.assertEqual(a['reads'],0)
        self.assertEqual(a['journal'][0]['action'],'FIRE')
        yes=execute(SealedEpisode(s,1,123),oracle)
        self.assertGreater(yes['reads'],0)
        self.assertEqual(yes['journal'][0]['action'],'READ')
        self.assertGreater(yes['paid_cost'],0)
        with self.assertRaises(RuntimeError):never.read()

    def test_checkpoint_private_rng_suffix_exact(self):
        ep=SealedEpisode(PublicState(.51,.81,.04,4),-1,456)
        ep.read()
        snapshot=ep.checkpoint()
        restored=SealedEpisode.restore(snapshot)
        self.assertEqual(ep.state,restored.state)
        while ep.state.remaining:
            self.assertEqual(ep.read(),restored.read())
        self.assertEqual(ep.stop(),restored.stop())
        wrap=json.loads(snapshot)
        wrap['payload']['truth']*=-1
        with self.assertRaises(ValueError):SealedEpisode.restore(json.dumps(wrap))

    def test_no_future_suffix_leak(self):
        s=PublicState(.55,.82,.03,4)
        a=SealedEpisode(s,1,8);b=SealedEpisode(s,1,8)
        self.assertEqual(a.state,b.state)
        self.assertEqual(a.read(),b.read())
        self.assertEqual(a.state,b.state)
        # Future differs only after the shared first read.
        c=SealedEpisode(s,-1,123)
        self.assertEqual(s,c.state)

    def test_boundary_intervention_changes_actual_read_calls(self):
        p=run_panel(n=250,seed=30)
        rows=p['results']
        self.assertGreater(rows['boundary_loose']['actual_read_calls'],
                           rows['boundary_tight']['actual_read_calls'])
        self.assertGreater(rows['oracle']['actual_read_calls'],0)
        self.assertEqual(rows['never_read']['actual_read_calls'],0)
        self.assertFalse(p['production_activation'])

    def test_reject_invalid_domains(self):
        for args in [(.5,1.0,.1,2),(.5,.4,.1,2),(.5,.8,-.01,2),
                     (.5,.8,.01,-1),(0.,.8,.01,2),(.5,.8,.01,13),
                     (math.nan,.8,.01,2)]:
            with self.assertRaises(ValueError):PublicState(*args)
        with self.assertRaises(ValueError):boundary_intervention(math.nan)

if __name__=='__main__':
    unittest.main(verbosity=2)
