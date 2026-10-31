import unittest
import torch
try:
    from .train_study import MatchedHead,MODES,two_features,train_one,vector_features
except ImportError:
    from train_study import MatchedHead,MODES,two_features,train_one,vector_features

class StudyTests(unittest.TestCase):
    def test_all_features_and_params(self):
        x=torch.tensor([[.51,.82,.04,3.],[.92,.65,.09,1.],[.12,.75,.1,4.]],requires_grad=True)
        counts=[]
        for mode in MODES:
            feats=vector_features(x,mode)
            self.assertEqual(feats.shape,(3,6))
            self.assertTrue(bool(torch.isfinite(feats).all()))
            model=MatchedHead(mode)
            y=model(x)
            self.assertEqual(y.shape,(3,))
            counts.append(sum(p.numel() for p in model.parameters()))
            grad=torch.autograd.grad(y.sum(),x,retain_graph=True)[0]
            self.assertTrue(bool(torch.isfinite(grad).all()))
        self.assertEqual(len(set(counts)),1)
    def test_training_gradients_and_updates(self):
        for mode in (MODES[0],MODES[-1]):
            model,report=train_one(mode,3,train_rows=30,steps=3)
            self.assertGreater(report['train_process_cpu_ns'],0)
            self.assertEqual(report['optimizer_updates'],3)
            self.assertEqual(report['trainable_parameters'],161)

if __name__=='__main__':unittest.main(verbosity=2)
