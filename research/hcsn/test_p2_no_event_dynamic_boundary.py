"""Independent, bounded local tests for P2 task-only dynamic boundary diagnostic."""
import unittest
import torch

from research.hcsn.p2_no_event_dynamic_boundary import (samples,CausalBoundary,
    DIM,NKEYS,MODES,_metrics,dictionary_oracle)


class TestDynamicBoundary(unittest.TestCase):
    def setUp(self):
        torch.set_num_threads(1)

    def test_generator_deterministic_and_masked(self):
        a=samples(3,64,4,11)
        b=samples(3,64,4,11)
        for x,y in zip(a,b):self.assertTrue(torch.equal(x,y))
        x,y,q,e=a
        self.assertEqual(x.shape,(3,64,DIM))
        self.assertTrue(torch.equal(q,x[:,:,NKEYS+2].bool()))
        self.assertEqual(int(e.sum()),9)
        self.assertTrue(torch.equal(e[:,0],torch.zeros(3,dtype=torch.bool)))
        self.assertEqual(int(q.sum()),36)
        self.assertFalse(bool((x[:,:,NKEYS+3]==0).all()))

    def test_evaluation_only_exact_oracle(self):
        for noise,irregular,length,segments in ((.08,False,64,4),(.23,True,112,6)):
            x,y,q,e=samples(4,length,segments,22,noise=noise,irregular=irregular)
            answer=dictionary_oracle(x,e)
            self.assertTrue(torch.equal(answer[q],y[q]))
            with self.assertRaises(ValueError):dictionary_oracle(x,e[:,:-1])

    def test_synthetic_ood_raises_noise(self):
        x,_,q,e=samples(2,112,6,71,noise=.23,irregular=True)
        self.assertEqual(int(e.sum()),10)
        self.assertEqual(int(q.sum()),36)
        self.assertGreater(float(x[:,:,NKEYS+4].max()),1.3)
        self.assertLess(float(x[:,:,NKEYS+4].min()),.8)

    def test_causal_prefix_independent_of_future(self):
        x,*_=samples(2,64,4,13)
        for mode in MODES:
            m=CausalBoundary(mode)
            out,ev,_=m.rollout(x,hard=True)
            altered=x.clone(); altered[:,30:,NKEYS+3]*=-3
            out2,ev2,_=m.rollout(altered,hard=True)
            self.assertTrue(torch.equal(out[:,:30],out2[:,:30]))
            self.assertTrue(torch.equal(ev[:,:30],ev2[:,:30]))

    def test_chunk_vs_full_stream(self):
        x,*_=samples(2,64,4,14)
        for mode in MODES:
            m=CausalBoundary(mode)
            for hard in (False,True):
                full,events,_=m.rollout(x,hard=hard)
                a,ea,st=m.rollout(x[:,:23],hard=hard)
                b,eb,_=m.rollout(x[:,23:],state=st,hard=hard)
                self.assertTrue(torch.equal(full,torch.cat([a,b],1)))
                self.assertTrue(torch.equal(events,torch.cat([ea,eb],1)))

    def test_finite_task_only_gradients(self):
        x,y,q,e=samples(3,64,4,17)
        self.assertGreater(int(e.sum()),0)
        for mode in MODES:
            m=CausalBoundary(mode)
            z,_,_=m.rollout(x,hard=False)
            loss=torch.nn.functional.binary_cross_entropy_with_logits(z[q],y[q]);loss.backward()
            for name,p in m.named_parameters():
                if mode=='no_reset' and name in ('threshold','sensitivity'):
                    self.assertIsNone(p.grad)
                else:
                    self.assertIsNotNone(p.grad)
                    self.assertTrue(bool(torch.isfinite(p.grad).all()))

    def test_reject_bad_time_and_shapes(self):
        x,*_=samples(2,64,4,18)
        m=CausalBoundary('dynamic')
        with self.assertRaises(ValueError):CausalBoundary('unknown')
        with self.assertRaises(ValueError):m.rollout(x[:,:,:-1],hard=True)
        with self.assertRaises(ValueError):m.rollout(x[:,:0],hard=True)
        damaged=x.clone();damaged[:,0,NKEYS+4]=0
        with self.assertRaises(ValueError):m.rollout(damaged,hard=True)
        damaged=x.clone();damaged[:,0,NKEYS+3]=float('nan')
        with self.assertRaises(ValueError):m.rollout(damaged,hard=True)

    def test_no_reset_is_actual_no_erasure(self):
        x,*_=samples(4,64,4,19)
        m=CausalBoundary('no_reset')
        _,ev,st=m.rollout(x,hard=True)
        self.assertEqual(st.memory.shape,(4,NKEYS))
        self.assertGreaterEqual(int(ev.sum()),0) # detector only, never applied
        metrics=_metrics(m,samples(4,64,4,20))
        self.assertEqual(metrics['true_events_per_stream'],3.)
        self.assertEqual(metrics['applied_resets_per_stream'],0.)
        self.assertTrue(metrics['event_precision_is_detector_only'])

    def test_multiple_events_are_finite(self):
        x,*_=samples(4,112,6,21,irregular=True,noise=.23)
        m=CausalBoundary('dynamic')
        logits,ev,st=m.rollout(x,hard=True)
        self.assertTrue(bool(torch.isfinite(logits).all()))
        self.assertTrue(bool(torch.isfinite(st.memory).all()))
        self.assertEqual(ev.shape,(4,112))
        self.assertEqual(int(ev[:,0].sum()),0)

if __name__=='__main__':unittest.main()
