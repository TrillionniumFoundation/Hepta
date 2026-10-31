"""Focused event-time surrogate diagnostic; no scientific gate assertion."""
import unittest
import torch
from .p2_multiquery_noevent import make_mqar,rollout
from .p2_hard_forward_soft_gradient import rollout_st,train_one_st
from .p2_learned_autonomous_content import AutonomousBoundaryMemory

class HardForwardTests(unittest.TestCase):
    def test_hard_forward_equivalence_all_modes(self):
        for mode in ('analytic','ordinary','no_reset'):
            model=AutonomousBoundaryMemory(mode)
            x,_,_,_=make_mqar(4,56,4,912)
            st,_=rollout_st(model,x)
            hard,_,_=rollout(model,x,hard=True)
            self.assertTrue(torch.allclose(st,hard,atol=1e-7,rtol=1e-6))

    def test_surrogate_backward_finite_through_boundary(self):
        model=AutonomousBoundaryMemory('analytic')
        x,y,q,_=make_mqar(4,56,4,992)
        st,_=rollout_st(model,x)
        torch.nn.functional.binary_cross_entropy_with_logits(st[q],y[q]).backward()
        self.assertIsNotNone(model.novelty_raw.grad)
        self.assertTrue(torch.isfinite(model.novelty_raw.grad).all())

    def test_streamed_surrogate_equals_whole_forward(self):
        model=AutonomousBoundaryMemory('ordinary')
        x,_,_,_=make_mqar(5,56,4,923)
        whole,_=rollout_st(model,x)
        first,state=rollout_st(model,x[:,:31])
        second,_=rollout_st(model,x[:,31:],state=state)
        self.assertTrue(torch.allclose(torch.cat([first,second],1),whole,atol=1e-7,rtol=1e-6))

    def test_train_one(self):
        r=train_one_st('analytic',11,steps=3,batch=6,eval_n=8)
        self.assertEqual(r['total_declared_parameters'],17)
        self.assertTrue(r['results']['ood_long_irregular']['hard_vs_surrogate_max_logit_abs']<1e-5)

if __name__=='__main__':unittest.main()
