"""Independent P1 evaluator tests; no pretrained encoder/production assertions."""
import math
import unittest
from functools import lru_cache
import numpy as np
import torch
try:
    from .p1_exact_policy_eval import exact_policy_regret, paired_seed_state_ci
except ImportError:
    from p1_exact_policy_eval import exact_policy_regret, paired_seed_state_ci

class Constant(torch.nn.Module):
    def __init__(self, read):
        super().__init__()
        self.read=read
    def forward(self, x):
        return torch.full((x.shape[0],),1. if self.read else -1.)

class ApproxOneLook(torch.nn.Module):
    def forward(self,x):
        p,q,c,n=x.unbind(-1)
        return (q-torch.maximum(p,1-p)-c)*1000.


def independent_value(p,q,c,n,act):
    stop=max(p,1-p)
    if n==0 or not act(p,q,c,n): return stop
    plus=p*q+(1-p)*(1-q)
    return (-c+plus*independent_value(p*q/plus,q,c,n-1,act)
             +(1-plus)*independent_value(p*(1-q)/(1-plus),q,c,n-1,act))


def independent_oracle(p,q,c,n):
    stop=max(p,1-p)
    if n==0:return stop
    plus=p*q+(1-p)*(1-q)
    return max(stop,-c+plus*independent_oracle(p*q/plus,q,c,n-1)
               +(1-plus)*independent_oracle(p*(1-q)/(1-plus),q,c,n-1))

class P1ExactDPTests(unittest.TestCase):
    def setUp(self):
        self.x=torch.tensor([[.3,.9,.04,4],[.9,.85,.15,2],
                             [.51,.7,.02,5],[.1,.9,0,0]],dtype=torch.float32)

    def test_always_read_and_never_read_against_independent_recursion(self):
        for action in (True,False):
            model=Constant(action).eval()
            got=exact_policy_regret(model,self.x)
            self.assertEqual(got['total_tree_leaves'],16+4+32+1)
            for j,(p,q,c,n) in enumerate(self.x.tolist()):
                expected=independent_value(p,q,c,int(n),lambda *args:action)
                oracle=independent_oracle(p,q,c,int(n))
                self.assertAlmostEqual(got['policy'][j],expected,places=11)
                self.assertAlmostEqual(got['optimal'][j],oracle,places=11)
                self.assertGreaterEqual(got['regret'][j],0.)

    def test_state_conditioned_nested_policy(self):
        m=ApproxOneLook().eval()
        got=exact_policy_regret(m,self.x)
        def decide(p,q,c,n):
            z=m(torch.tensor([[p,q,c,n]],dtype=torch.float32))
            return z.item()>0
        for j,(p,q,c,n) in enumerate(self.x.tolist()):
            self.assertAlmostEqual(got['policy'][j],independent_value(p,q,c,int(n),decide),places=11)

    def test_input_validation_and_resource_bound(self):
        m=Constant(False).eval()
        for invalid in (torch.tensor([[float('nan'),.9,.02,3]]),
                        torch.tensor([[.5,1.,.02,3]]),
                        torch.tensor([[.5,.9,-.02,3]]),
                        torch.tensor([[.5,.9,.02,2.5]]),
                        torch.tensor([[.5,.9,.02,13]])):
            with self.assertRaises(ValueError):exact_policy_regret(m,invalid)
        with self.assertRaises(ValueError):exact_policy_regret(m,torch.tensor([[.5,.9,.02,12]]).repeat(33,1))
        with self.assertRaises(ValueError):exact_policy_regret(m,torch.tensor([[.5,.9,.02,3]],device='cpu').long())
        with self.assertRaises(ValueError):exact_policy_regret(Constant(False),self.x)

    def test_bad_logits_rejected(self):
        class Bad(torch.nn.Module):
            def forward(self,x):return x.new_full((len(x),),float('nan'))
        with self.assertRaises(ArithmeticError):exact_policy_regret(Bad().eval(),self.x)

    def test_bootstrap_determinism_pairing_and_no_fake_certification(self):
        rng=np.random.default_rng(33)
        d=rng.normal(size=(3,40))
        a=paired_seed_state_ci(d,draws=200)
        self.assertEqual(a,paired_seed_state_ci(d,draws=200))
        self.assertAlmostEqual(a['mean'],float(d.mean()))
        self.assertFalse(a['independent_preregistration'])
        for bad in (np.ones((2,40)), np.ones((3,3)),np.full((3,50),np.nan)):
            with self.assertRaises(ValueError):paired_seed_state_ci(bad)

if __name__=='__main__':unittest.main()
