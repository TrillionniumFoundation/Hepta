import unittest
import torch
try:
 from .temporal_bench import make_sequences,model_for,BoundaryRNN,GRUControl
except ImportError:
 from temporal_bench import make_sequences,model_for,BoundaryRNN,GRUControl

class TemporalTests(unittest.TestCase):
 def test_frozen_split_reproducible_and_no_query_answer_leak(self):
    for mode in ('selective_copy','mqar'):
        x,y=make_sequences(mode,16,24,seed=1)
        x2,y2=make_sequences(mode,16,24,seed=1)
        self.assertTrue(torch.equal(x,x2))
        self.assertTrue(torch.equal(y,y2))
        self.assertEqual(x.shape,(16,24,12))
        self.assertTrue(torch.all(x[:,-1,8].abs()==1))
        self.assertTrue(torch.all(x[:,-1,9]==0))
        self.assertTrue(torch.all(x[:,-1,10]==1))
        self.assertTrue(torch.all((y==1) | (y==0)))
        self.assertTrue(torch.all(x[:,:,11]>0))

 def test_same_parameter_count_and_all_gradient_paths(self):
    torch.set_num_threads(1)
    a=model_for('hcsn');b=model_for('ordinary');c=model_for('gru')
    self.assertEqual(sum(p.numel() for p in a.parameters()),
                     sum(p.numel() for p in b.parameters()))
    self.assertLess(abs(sum(p.numel() for p in a.parameters())-
                        sum(p.numel() for p in c.parameters()))/sum(p.numel() for p in c.parameters()),.1)
    x,y=make_sequences('selective_copy',8,16,1)
    for model in (a,b,c):
        z=model(x)
        loss=torch.nn.functional.binary_cross_entropy_with_logits(z,y)
        loss.backward()
        self.assertTrue(all(t.grad is not None and torch.isfinite(t.grad).all() for t in model.parameters()))

if __name__=='__main__':unittest.main(verbosity=2)
