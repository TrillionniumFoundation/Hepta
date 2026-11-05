"""Independent interface/property tests for causal filters; gates remain open."""
import unittest
import torch
from .p2_event_refractory_diagnostic import rollout_filtered, run, initial_filter_state
from .p2_learned_autonomous_content import AutonomousBoundaryMemory, NKEYS
from .p2_multiquery_noevent import make_mqar, rollout


class EventFilterTests(unittest.TestCase):
    def test_raw_exactly_matches_upstream_hard_for_all_modes(self):
        x,_,_,_=make_mqar(4,56,4,912)
        for mode in ('analytic','ordinary','no_reset'):
            model=AutonomousBoundaryMemory(mode)
            with torch.no_grad():
                logits,state,tr=rollout_filtered(model,x,policy='raw',trace=True)
                expected,hard_state,raw=rollout(model,x,hard=True,trace=True)
            self.assertTrue(torch.equal(logits,expected))
            self.assertTrue(torch.equal(state.memory_state.memory,hard_state.memory))
            self.assertTrue(torch.equal(tr.raw_events,raw))
            if mode=='no_reset':self.assertFalse(bool(tr.applied_events.any()))
            else:self.assertTrue(torch.equal(tr.applied_events,raw))

    def test_stuck_negative_margin_causes_one_edge_not_repeated_resets(self):
        model=AutonomousBoundaryMemory('analytic')
        with torch.no_grad():model.reserve_bias.fill_(-10.)
        x,_,_,_=make_mqar(3,56,4,12)
        with torch.no_grad():
            _,_,raw=rollout_filtered(model,x,policy='raw',trace=True)
            _,_,edge=rollout_filtered(model,x,policy='edge',trace=True)
            _,_,refr=rollout_filtered(model,x,policy='edge_refractory',refractory_tokens=8,trace=True)
        self.assertEqual(int(raw.raw_events.sum()),3*56)
        self.assertEqual(int(edge.applied_events.sum()),3)
        self.assertEqual(int(refr.applied_events.sum()),3)
        self.assertTrue(bool((raw.applied_events & ~edge.applied_events).any()))

    def test_chunking_invariance_and_causal_prefix(self):
        model=AutonomousBoundaryMemory('ordinary')
        x,_,_,_=make_mqar(4,112,6,88,irregular=True)
        with torch.no_grad():
            whole,state,all_events=rollout_filtered(model,x,trace=True)
            front,s,t1=rollout_filtered(model,x[:,:31],trace=True)
            tail,last,t2=rollout_filtered(model,x[:,31:],state=s,trace=True)
            changed=x.clone();changed[:,31:,:]=0.;changed[:,31:,NKEYS+4]=1.
            same_front,_,_=rollout_filtered(model,changed[:,:31])
        self.assertTrue(torch.equal(front,same_front))
        self.assertTrue(torch.equal(torch.cat((front,tail),1),whole))
        self.assertTrue(torch.equal(last.memory_state.memory,state.memory_state.memory))
        self.assertTrue(torch.equal(last.cooldown,state.cooldown))
        self.assertTrue(torch.equal(torch.cat((t1.applied_events,t2.applied_events),1),all_events.applied_events))

    def test_batch_independence(self):
        model=AutonomousBoundaryMemory('analytic')
        x,_,_,_=make_mqar(3,56,4,88)
        with torch.no_grad():
            batch,_,trace=rollout_filtered(model,x,trace=True)
            for i in range(3):
                solo,_,t=rollout_filtered(model,x[i:i+1],trace=True)
                self.assertTrue(torch.equal(batch[i:i+1],solo))
                self.assertTrue(torch.equal(trace.applied_events[i:i+1],t.applied_events))

    def test_excessive_cooldown_cannot_create_additional_events(self):
        model=AutonomousBoundaryMemory('analytic')
        x,_,_,_=make_mqar(5,56,4,97)
        with torch.no_grad():
            _,_,edge=rollout_filtered(model,x,policy='edge',trace=True)
            _,_,gated=rollout_filtered(model,x,policy='edge_refractory',refractory_tokens=8,trace=True)
        self.assertTrue(bool((gated.applied_events <= edge.applied_events).all()))

    def test_fail_closed_invalid_args(self):
        model=AutonomousBoundaryMemory('analytic')
        x,_,_,_=make_mqar(2,56,4,97)
        for args in ({'policy':'unknown'},{'refractory_tokens':-1},
                     {'refractory_tokens':1.5},{'refractory_tokens':True}):
            with self.assertRaises(ValueError):rollout_filtered(model,x,**args)
        invalid=x.clone();invalid[0,1,0]=float('nan')
        with self.assertRaises(ValueError):rollout_filtered(model,invalid)
        invalid=x.clone();invalid[0,1,NKEYS+4]=0
        with self.assertRaises(ValueError):rollout_filtered(model,invalid)
        state=initial_filter_state(model,x)
        with self.assertRaises(ValueError):rollout_filtered(model,x,state=state._replace(cooldown=state.cooldown[:,0]))

    def test_same_weight_evaluation_smoke(self):
        result=run(seeds=(11,),steps=2,batch=4,length=56,eval_n=4)
        self.assertFalse(result['scientific_gates_closed'])
        self.assertFalse(result['production_activation'])
        self.assertEqual(len(result['rows']),3)
        for row in result['rows']:
            self.assertEqual(row['declared_parameters'],17)
            self.assertGreaterEqual(row['results']['id']['raw']['applied_resets_per_stream'],0.)

if __name__=='__main__':unittest.main()
