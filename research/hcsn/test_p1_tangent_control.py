import unittest
import torch
try:
    from .p1_tangent_control import TangentMatchedHead,ANCHOR
    from .train_study import MatchedHead,two_features
except ImportError:
    from p1_tangent_control import TangentMatchedHead,ANCHOR
    from train_study import MatchedHead,two_features

class TangentControlTests(unittest.TestCase):
    def test_local_value_and_full_signed_jacobian_match(self):
        x=torch.tensor([ANCHOR],dtype=torch.float32,requires_grad=True)
        t=TangentMatchedHead()
        y=t.transformed(x)
        ref=two_features(x,'dual_call_put')
        self.assertLess(float((y-ref).abs().max()),3e-7)
        jt=torch.autograd.functional.jacobian(lambda z:t.transformed(z)[0],x).reshape(2,4)
        jr=torch.autograd.functional.jacobian(lambda z:two_features(z,'dual_call_put')[0],x).reshape(2,4)
        self.assertLess(float((jt-jr).abs().max()),5e-6)
    def test_trainable_count_equal_and_tangent_away_not_identical(self):
        torch.manual_seed(15)
        a=TangentMatchedHead()
        torch.manual_seed(15)
        b=MatchedHead('dual_call_put')
        self.assertEqual(sum(z.numel() for z in a.parameters()),161)
        for z,w in zip(a.parameters(),b.parameters()):self.assertTrue(torch.equal(z,w))
        x=torch.tensor([[.64,.75,.11,2.],[.1,.91,.02,4.]])
        y=a(x)
        self.assertTrue(torch.isfinite(y).all())
        self.assertGreater(float((a.transformed(x)-two_features(x,'dual_call_put')).abs().max()),1e-3)

if __name__=='__main__':unittest.main()
