import unittest
import torch
try:
    from .p2_regen_recall import RegenerativeRNN,make_joint_reset,_hitting_probability
except ImportError:
    from p2_regen_recall import RegenerativeRNN,make_joint_reset,_hitting_probability

class MultiResetTests(unittest.TestCase):
    def test_forced_events_and_deterministic_replay(self):
        x,y=make_joint_reset(8,30,8,irregular=True)
        for mode in ('analytic','ordinary'):
            torch.manual_seed(4)
            m=RegenerativeRNN(mode=mode).eval()
            with torch.no_grad():
                a,trace=m(x,hard=True,trace=True)
                b=m(x,hard=True)
                self.assertTrue(torch.equal(a,b))
                for t in (10,20):
                    self.assertTrue(bool(trace[t]['event'].all()))

    def test_history_before_final_reset_is_erased_hard(self):
        x,_=make_joint_reset(5,30,81,irregular=False)
        z=x.clone()
        z[:,:20,:]=0.
        z[:,:20,11]=1.
        z[:,10,12]=1.
        z[:,20,12]=1.
        model=RegenerativeRNN().eval()
        with torch.no_grad():
            left=model(x,hard=True)
            right=model(z,hard=True)
        self.assertLess(float((left-right).abs().max()),1e-6)

    def test_bptt_gradients_and_nonfinite_rejection(self):
        x,y=make_joint_reset(10,26,127,irregular=True)
        for mode in ('analytic','ordinary'):
            m=RegenerativeRNN(mode=mode)
            loss=torch.nn.functional.binary_cross_entropy_with_logits(m(x),y)
            loss.backward()
            self.assertTrue(all(p.grad is not None and torch.isfinite(p.grad).all().item()
                for p in m.parameters()))
        x[0,0,1]=float('nan')
        with self.assertRaises(ValueError):m(x)

    def test_first_passage_probability_bounds_and_gradient(self):
        m=torch.tensor([[.2],[.5],[.9]],requires_grad=True)
        d=torch.tensor([[.5],[.8],[1.]])
        sigma=torch.tensor(.3,requires_grad=True)
        q=_hitting_probability(m,d,torch.tensor(-.02),sigma)
        self.assertTrue(bool((q>=0).all() and (q<=1).all()))
        q.sum().backward()
        self.assertTrue(torch.isfinite(m.grad).all())
        self.assertGreater(float(m.grad.abs().sum()),0.)
        self.assertGreater(float(sigma.grad.abs()),0.)

if __name__=='__main__':unittest.main()
