"""Independent P2 learned-context-reset functional checks (not scientific signoff)."""
from __future__ import annotations
import unittest
import io
import torch
try:
    from .p2_learned_autonomous_content import (
        AutonomousBoundaryMemory, NKEYS, make_context_recall, train_one)
except ImportError:
    from p2_learned_autonomous_content import (
        AutonomousBoundaryMemory, NKEYS, make_context_recall, train_one)


class AutonomousContentTests(unittest.TestCase):
    def setUp(self):
        torch.set_num_threads(1)

    def test_episode_has_no_explicit_reset_column_and_four_contexts(self):
        x,y,ev=make_context_recall(40,42,14)
        self.assertEqual(x.shape,(40,42,NKEYS+5))
        self.assertTrue(bool((ev.sum(1)==3).all()))
        self.assertTrue(bool((x[:,-1,NKEYS+2]==1).all()))
        self.assertTrue(bool((x[:,-1,NKEYS+1]==0).all()))
        self.assertTrue(bool(((y==0)|(y==1)).all()))
        # No future query answer in input: same prefix can have variable labels.
        self.assertFalse(bool(torch.any(x[:,:,NKEYS+2]>1)))
        # Input has dt but no ground truth event bit; events are derived from
        # changes in observed context code, never supplied as a special flag.
        ctx=x[:,:,NKEYS+3]
        self.assertTrue(torch.equal((ctx[:,1:]!=ctx[:,:-1]).float(),ev[:,1:]))

    def test_hard_streaming_chunk_invariance_for_all_modes(self):
        x,_,_=make_context_recall(7,49,41,segments=5,irregular=True)
        for mode in ('analytic','ordinary','no_reset'):
            model=AutonomousBoundaryMemory(mode).eval()
            for hard in (False,True):
                with torch.no_grad():
                    full,full_state,_=model(x,hard=hard,trace=True)
                    state=None
                    for start,end in ((0,4),(4,16),(16,30),(30,41),(41,49)):
                        chunk,state=model(x[:,start:end],state=state,hard=hard)
                self.assertTrue(torch.allclose(full,chunk,atol=1e-7,rtol=1e-7),mode)
                self.assertTrue(torch.allclose(full_state.memory,state.memory,atol=1e-7,rtol=1e-7))
                self.assertTrue(torch.equal(full_state.context,state.context))

    def test_causal_prefix_no_future_peeking(self):
        x,_,_=make_context_recall(7,42,51)
        perturbed=x.clone()
        perturbed[:,20:,NKEYS]=1.
        perturbed[:,25:,NKEYS+3]*=-1
        model=AutonomousBoundaryMemory()
        with torch.no_grad():
            _,_,a=model(x,trace=True)
            _,_,b=model(perturbed,trace=True)
        self.assertTrue(torch.equal(a.event_logits[:,:20],b.event_logits[:,:20]))
        self.assertTrue(torch.equal(a.margins[:,:20],b.margins[:,:20]))

    def test_untrained_boundary_does_not_spuriously_claim_autonomous_resets(self):
        x,_,ev=make_context_recall(20,42,61)
        model=AutonomousBoundaryMemory('analytic')
        with torch.no_grad():
            _,_,tr=model(x,hard=True,trace=True)
        self.assertLess(float(((tr.hard_events)&(ev>.5)).float().mean()),.01)
        self.assertEqual(sum(p.numel() for p in model.parameters()),
                         sum(p.numel() for p in AutonomousBoundaryMemory('ordinary').parameters()))

    def test_learnable_true_boundary_and_gradients(self):
        x,y,ev=make_context_recall(20,42,71,irregular=True)
        for mode in ('analytic','ordinary','no_reset'):
            model=AutonomousBoundaryMemory(mode)
            output,_,trace=model(x,trace=True)
            loss=torch.nn.functional.binary_cross_entropy_with_logits(output,y)
            loss+=.2*torch.nn.functional.binary_cross_entropy_with_logits(trace.event_logits,ev,
                pos_weight=torch.tensor(8.))
            loss.backward()
            for name,p in model.named_parameters():
                self.assertIsNotNone(p.grad,name)
                self.assertTrue(bool(p.grad.isfinite().all()),name)
                self.assertGreater(float(p.grad.abs().sum()),1e-12,name)
            self.assertTrue(bool(trace.call.isfinite().all()))
            self.assertTrue(bool(trace.put.isfinite().all()))
            self.assertTrue(bool(trace.margins.isfinite().all()))

    def test_implicit_boundary_learned_from_context_labels(self):
        outcome=train_one('analytic',11,steps=55,batch=32,eval_n=64)
        self.assertGreater(outcome['results']['id']['event_recall'],.90)
        self.assertGreater(outcome['results']['id']['hard_accuracy'],.85)
        self.assertGreater(outcome['results']['long_irregular']['event_recall'],.90)
        self.assertFalse(outcome.get('scientific_acceptance',False))

    def test_invalid_input_rejected(self):
        x,_,_=make_context_recall(3,42,17)
        model=AutonomousBoundaryMemory()
        for bad in (torch.full_like(x,float('nan')),
                    torch.full_like(x,float('inf')),
                    x[:,:,:-1],
                    x.clone()):
            if bad.shape==x.shape and torch.isfinite(bad).all():
                bad[:,:,NKEYS+4]=-1
            with self.assertRaises(ValueError):model(bad)
        with self.assertRaises(ValueError):model(x,state=model.initial(x[:1]))

    def test_state_dict_restart_is_deterministic(self):
        x,_,_=make_context_recall(4,42,7)
        model=AutonomousBoundaryMemory('analytic').eval()
        buf=io.BytesIO()
        torch.save(model.state_dict(),buf)
        buf.seek(0)
        recovered=AutonomousBoundaryMemory('analytic').eval()
        recovered.load_state_dict(torch.load(buf,weights_only=True))
        with torch.no_grad():
            a,_=model(x,hard=True)
            b,_=recovered(x,hard=True)
        self.assertTrue(torch.equal(a,b))


if __name__=='__main__':unittest.main()
