"""Focused P2 test: query schedule, causal streaming, reset semantics and gradients."""
import unittest
import torch
from .p2_multiquery_noevent import make_mqar,rollout,train_one,run,exact_stream_oracle
from .p2_learned_autonomous_content import AutonomousBoundaryMemory,NKEYS

class MQARStressTests(unittest.TestCase):
    def test_generator_determinism_shape_balance(self):
        a=make_mqar(7,64,4,123)
        b=make_mqar(7,64,4,123)
        for u,v in zip(a,b):self.assertTrue(torch.equal(u,v))
        x,y,q,ev=a
        self.assertEqual(tuple(x.shape),(7,64,NKEYS+5))
        self.assertTrue(torch.equal(q.sum(1),torch.full((7,),12)))
        self.assertEqual(int(ev.sum()),21)
        self.assertTrue((y[q].mean()>0.2).item() and (y[q].mean()<0.6).item())

    def test_independent_oracle_and_stale_counterexample(self):
        for length,segments in [(56,4),(112,6)]:
            x,y,q,ev=make_mqar(12,length,segments,77)
            exact=exact_stream_oracle(x,reset=True)
            stale=exact_stream_oracle(x,reset=False)
            self.assertTrue(torch.equal(exact[q],y[q]))
            # Exactly one stale-positive query in each segment after first.
            self.assertEqual(int((stale[q]!=y[q]).sum()),12*(segments-1))
            expected=1-(segments-1)/(3*segments)
            self.assertAlmostEqual(float((stale[q]==y[q]).float().mean()),expected)

    def test_generator_rejects_illegal(self):
        for v in [(0,64,4,1),(4,53,4,1),(4,72,9,1),(4,64,4,2.4)]:
            with self.assertRaises(ValueError):make_mqar(*v)

    def test_no_future_labels_or_event_markers(self):
        x,y,q,ev=make_mqar(10,64,4,193)
        self.assertTrue(torch.equal(q,x[:,:,NKEYS+2].bool()))
        self.assertEqual(int((x[:,:,NKEYS+1]*x[:,:,NKEYS+2]).sum()),0)
        # No separate event target input; each change comes from visible context.
        ctx=x[:,:,NKEYS+3]
        self.assertTrue(torch.equal(ev[:,1:],ctx[:,1:]!=ctx[:,:-1]))
        self.assertTrue(torch.equal(ev[:,0],torch.zeros(10,dtype=torch.bool)))

    def test_chunked_equals_full_and_causal_prefix(self):
        torch.manual_seed(11)
        model=AutonomousBoundaryMemory('analytic')
        x,_,_,_=make_mqar(4,64,4,92)
        with torch.no_grad():
            whole,s,_=rollout(model,x,hard=False)
            first,st,_=rollout(model,x[:,:19],hard=False)
            tail,st,_=rollout(model,x[:,19:],hard=False,state=st)
        self.assertTrue(torch.allclose(whole,torch.cat([first,tail],1),atol=1e-7,rtol=1e-6))
        self.assertTrue(torch.allclose(s.memory,st.memory))

    def test_hard_event_applied_vs_detector_only(self):
        x,_,_,_=make_mqar(3,64,4,92)
        analytic=AutonomousBoundaryMemory('analytic')
        no_reset=AutonomousBoundaryMemory('no_reset')
        analytic.load_state_dict(no_reset.state_dict())
        with torch.no_grad():
            _,a,events=rollout(analytic,x,hard=True,trace=True)
            _,n,detector=rollout(no_reset,x,hard=True,trace=True)
        self.assertTrue(torch.equal(events,detector))
        # As long as at least one crossing happens, state should differ.
        if bool(events.any()):self.assertFalse(torch.allclose(a.memory,n.memory))

    def test_end_to_end_bptt_no_event_supervision(self):
        for mode in ('analytic','ordinary','no_reset'):
            out=train_one(mode,11,steps=3,batch=5,length=56,eval_n=8)
            self.assertFalse(out['event_supervision'])
            self.assertEqual(out['trainable_parameter_count'],17)
            self.assertTrue(0<=out['results']['id']['hard_query_accuracy']<=1)
            self.assertGreaterEqual(out['max_gradient_absolute'],0.)
            if mode=='no_reset':
                self.assertEqual(out['results']['ood_long_irregular']['applied_hard_resets_per_sequence'],0)

if __name__=='__main__':unittest.main()
