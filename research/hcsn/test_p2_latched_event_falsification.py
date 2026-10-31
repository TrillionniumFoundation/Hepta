"""Independent, scenario-specific checks for causal latching; no P2 closure."""
import unittest
import torch
from .p2_learned_autonomous_content import AutonomousBoundaryMemory,NKEYS
from .p2_multiquery_noevent import make_mqar,rollout
from .p2_latched_event_falsification import rollout_latched,train_one

class TestCausalLatch(unittest.TestCase):
    def test_chunk_parity_hard_all_modes(self):
        for mode in ('analytic','ordinary','no_reset'):
            model=AutonomousBoundaryMemory(mode)
            x,_,_,_=make_mqar(5,56,4,1002)
            whole,_,evt=rollout_latched(model,x,trace=True)
            a,state,ev_a=rollout_latched(model,x[:,:21],trace=True)
            b,_,ev_b=rollout_latched(model,x[:,21:],state=state,trace=True)
            torch.testing.assert_close(torch.cat((a,b),1),whole,atol=1e-6,rtol=0)
            self.assertTrue(torch.equal(torch.cat((ev_a,ev_b),1),evt))

    def test_chunk_parity_st_all_modes(self):
        for mode in ('analytic','ordinary','no_reset'):
            model=AutonomousBoundaryMemory(mode)
            x,_,_,_=make_mqar(5,56,4,1102)
            whole,_,_=rollout_latched(model,x,surrogate=True)
            a,s,_=rollout_latched(model,x[:,:19],surrogate=True)
            b,_,_=rollout_latched(model,x[:,19:],state=s,surrogate=True)
            torch.testing.assert_close(torch.cat((a,b),1),whole,atol=1e-6,rtol=0)

    def test_exact_hard_ST_forward_all_modes(self):
        for mode in ('analytic','ordinary','no_reset'):
            model=AutonomousBoundaryMemory(mode)
            x,_,_,_=make_mqar(4,56,4,1122,irregular=True)
            hard,_,_=rollout_latched(model,x)
            st,_,_=rollout_latched(model,x,surrogate=True)
            torch.testing.assert_close(hard,st,atol=1e-7,rtol=0)

    def test_releases_only_after_positive_margin(self):
        model=AutonomousBoundaryMemory('analytic')
        x,_,_,_=make_mqar(2,56,4,827)
        # Set a consistently negative margin (no rearm). One initial fire only.
        with torch.no_grad():
            model.reserve_bias.fill_(-50.0)
        _,state,hit=rollout_latched(model,x,trace=True)
        self.assertEqual(int(hit.sum()),2)
        self.assertFalse(bool(state.armed.any()))
        _,_,base=rollout(model,x,hard=True,trace=True)
        self.assertEqual(int(base.sum()),112)

    def test_finite_surrogate_gradients(self):
        model=AutonomousBoundaryMemory('analytic')
        x,y,q,_=make_mqar(4,56,4,1322)
        pred,_,_=rollout_latched(model,x,surrogate=True)
        torch.nn.functional.binary_cross_entropy_with_logits(pred[q],y[q]).backward()
        self.assertIsNotNone(model.novelty_raw.grad)
        self.assertTrue(torch.isfinite(model.novelty_raw.grad).all())

    def test_causal_prefix_and_no_future_labels(self):
        model=AutonomousBoundaryMemory('ordinary')
        x,_,_,_=make_mqar(4,56,4,1722)
        out,_,_=rollout_latched(model,x)
        yy=x.clone();yy[:,35:,:].zero_();yy[:,35:,NKEYS+4]=1.
        pref,_,_=rollout_latched(model,yy[:,:34])
        torch.testing.assert_close(out[:,:34],pref,atol=0,rtol=0)

    def test_invalid_inputs(self):
        model=AutonomousBoundaryMemory('analytic')
        x,_,_,_=make_mqar(2,56,4,1222)
        for bad in (-1.0,2.01,float('nan')):
            with self.assertRaises(ValueError):
                rollout_latched(model,x,release_margin=bad)
        y=x.clone();y[0,0,-1]=0
        with self.assertRaises(ValueError):rollout_latched(model,y)

    def test_small_train(self):
        result=train_one('analytic',11,latch=True,steps=2,batch=5,eval_n=5)
        self.assertEqual(result['trainable_parameters_declared'],17)
        self.assertLess(result['metrics']['ood_long_irregular']['st_hard_max_abs'],1e-6)

if __name__=='__main__':unittest.main()
