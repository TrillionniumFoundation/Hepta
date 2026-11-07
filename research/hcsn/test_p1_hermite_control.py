"""Analytical channel vs regular tabular C1 null: numerical Jacobian checks."""
import unittest
import torch
try:
 from .p1_hermite_control import HermiteGate,HermiteMatchedHead
 from .train_study import MatchedHead,make_data,two_features
except ImportError:
 from p1_hermite_control import HermiteGate,HermiteMatchedHead
 from train_study import MatchedHead,make_data,two_features

class HermiteP1Tests(unittest.TestCase):
 def test_heldout_value_and_signed_input_jacobian(self):
    x,_=make_data(202010,200,ood=True)
    a=x.detach().clone().requires_grad_(True)
    g=HermiteMatchedHead()
    v=g.transformed(a)
    ref=two_features(a,'dual_call_put')
    self.assertLess((v-ref).abs().max().item(),2e-5)
    j1=torch.autograd.grad(v.sum(),a,retain_graph=True)[0]
    j2=torch.autograd.grad(ref.sum(),a)[0]
    self.assertLess((j1-j2).abs().max().item(),1e-3)
 def test_knots_paste_signed_derivative_and_trainables(self):
    torch.manual_seed(90)
    a=HermiteMatchedHead()
    torch.manual_seed(90)
    b=MatchedHead('dual_call_put')
    self.assertEqual(sum(z.numel() for z in a.parameters()),161)
    self.assertEqual(sum(z.numel() for z in b.parameters()),161)
    self.assertTrue(torch.equal(a.proj.weight,b.proj.weight))
    g=HermiteGate()
    for v in (-1.,-.5,0.,.5,1.):
        margin=torch.tensor([v-1e-5,v+1e-5],requires_grad=True)
        features=g(margin)
        self.assertTrue(torch.isfinite(features).all())
        self.assertTrue(torch.isfinite(torch.autograd.grad(features.sum(),margin)[0]).all())
 def test_fail_closed_outside_lut_domain(self):
    g=HermiteGate()
    with self.assertRaises(ValueError):g(torch.tensor([-13.]))
    with self.assertRaises(ValueError):g(torch.tensor([float('nan')]))

if __name__=='__main__':unittest.main()
