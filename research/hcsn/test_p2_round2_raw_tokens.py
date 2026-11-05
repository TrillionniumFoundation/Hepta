"""Causal, language, attribution and numerical checks for round-2 raw tokens."""
import dataclasses
import inspect
import math
import unittest
import numpy as np
import torch

try:
    from .p2_round2_raw_tokens import *
except ImportError:
    from p2_round2_raw_tokens import *


class RawTokenTests(unittest.TestCase):
    def setUp(self): torch.set_num_threads(1)

    def test_generated_labels_match_independent_interpreter(self):
        for task in TASKS:
            data=make_batch(31001,n=9,kind=task,episodes=3,overwrites=6)
            for row,length in enumerate(data.lengths):
                self.assertEqual(interpret(data.tokens[row,:length].tolist()),data.targets[row,:length].tolist())
            self.assertGreater(int((data.targets!=-100).sum()),0)

    def test_copy_requires_ordered_joint_recall_not_just_last(self):
        a=[COPY_BEGIN,VALUE_BASE,NOISE_BASE,VALUE_BASE+1,VALUE_BASE+2,RECALL,READ,READ,READ]
        b=a.copy();b[1]=VALUE_BASE+3
        labels_a=interpret(a);labels_b=interpret(b)
        self.assertEqual(labels_a[-3:],[0,1,2]);self.assertEqual(labels_b[-3:],[3,1,2])

    def test_overwrite_tracking_and_visible_reset_semantics(self):
        seq=[MAP_BEGIN,WRITE,KEY_BASE,VALUE_BASE,ASK,KEY_BASE,READ,
             WRITE,KEY_BASE,VALUE_BASE+2,ASK,KEY_BASE,READ,
             RESET,ASK,KEY_BASE,READ,
             WRITE,KEY_BASE,VALUE_BASE+1,ASK,KEY_BASE,READ]
        self.assertEqual([x for x in interpret(seq) if x!=-100],[0,2,UNKNOWN,1])

    def test_clock_rng_cannot_change_token_answers(self):
        a=make_batch(31002,n=12,duration_min=.5,duration_max=2.)
        b=make_batch(31002,n=12,duration_min=.005,duration_max=.02)
        self.assertTrue(torch.equal(a.tokens,b.tokens));self.assertTrue(torch.equal(a.targets,b.targets))
        self.assertFalse(torch.equal(a.duration,b.duration))

    def test_model_interface_excludes_labels_and_episode_metadata(self):
        signature=inspect.signature(RawTokenMemory.forward)
        self.assertEqual(set(signature.parameters),{'self','tokens','duration','initial','return_state'})
        data=make_batch(31003,n=5)
        model=RawTokenMemory('hcsn',width=16)
        changed=dataclasses.replace(data,targets=(data.targets+1)%5,task_names=('wrong',)*5)
        self.assertTrue(torch.equal(model(data.tokens,data.duration),model(changed.tokens,changed.duration)))

    def test_causal_prefix_chunk_equivalence_and_initial_nonmutation(self):
        data=make_batch(31004,n=3)
        model=RawTokenMemory('hcsn',width=16)
        full=model(data.tokens,data.duration)
        split=17
        left,state=model(data.tokens[:,:split],data.duration[:,:split],return_state=True)
        snapshot=state.clone()
        right=model(data.tokens[:,split:],data.duration[:,split:],state)
        torch.testing.assert_close(torch.cat((left,right),1),full,atol=2e-7,rtol=0)
        torch.testing.assert_close(state,snapshot,atol=0,rtol=0)
        changed=data.tokens.clone();changed[:,split:]=NOISE_BASE
        torch.testing.assert_close(model(changed,data.duration)[:,:split],full[:,:split],atol=0,rtol=0)

    def test_batch_independence(self):
        data=make_batch(31005,n=3)
        model=RawTokenMemory('ordinary',width=16)
        full=model(data.tokens,data.duration)
        for i in range(3):
            torch.testing.assert_close(model(data.tokens[i:i+1],data.duration[i:i+1]),full[i:i+1],atol=3e-7,rtol=0)

    def test_matched_parameter_initialization_and_bptt(self):
        torch.manual_seed(71);a=RawTokenMemory('hcsn')
        torch.manual_seed(71);b=RawTokenMemory('ordinary')
        self.assertEqual(sum(p.numel() for p in a.parameters()),10197)
        self.assertEqual(sum(p.numel() for p in b.parameters()),10197)
        for pa,pb in zip(a.parameters(),b.parameters()):self.assertTrue(torch.equal(pa,pb))
        data=make_batch(31006,n=10)
        for model in (a,b):
            logits=model(data.tokens,data.duration)
            F.cross_entropy(logits.flatten(0,1),data.targets.flatten()).backward()
            for parameter in model.parameters():
                self.assertIsNotNone(parameter.grad)
                self.assertTrue(bool(torch.isfinite(parameter.grad).all()))
                self.assertGreater(float(parameter.grad.abs().sum()),0.)

    def test_put_linear_exact_reparameterization_values_and_gradients(self):
        torch.manual_seed(72);a=RawTokenMemory('hcsn',width=16).double()
        b=RawTokenMemory('put_linear_equivalent',width=16).double();b.load_state_dict(a.state_dict())
        data=make_batch(31007,n=4)
        ya=a(data.tokens,data.duration);yb=b(data.tokens,data.duration)
        torch.testing.assert_close(ya,yb,atol=3e-14,rtol=0)
        F.cross_entropy(ya.flatten(0,1),data.targets.flatten()).backward()
        F.cross_entropy(yb.flatten(0,1),data.targets.flatten()).backward()
        for pa,pb in zip(a.parameters(),b.parameters()):
            torch.testing.assert_close(pa.grad,pb.grad,atol=3e-14,rtol=0)

    def test_signed_initial_local_logit_slopes_match(self):
        for mode in MODES:
            u=torch.tensor(0.,dtype=torch.float64,requires_grad=True)
            first,second=gate_channels(u,mode)
            value=first-second
            value.backward()
            self.assertAlmostEqual(float(value.detach()),0.,delta=1e-14)
            self.assertAlmostEqual(float(u.grad),1.,delta=1e-14)

    def test_missing_update_information_bound(self):
        for mode in MODES:
            r=missing_write_panel(RawTokenMemory(mode,width=16))
            self.assertLessEqual(r['hard_accuracy'],.25)
            self.assertLessEqual(r['mean_probability_assigned_to_true_missing_value'],.25+1e-7)

    def test_old_short_write_noise_requirements_are_incompatible(self):
        r=previous_flow_operating_domain()
        self.assertAlmostEqual(r['necessary_write_rate_lower_bound'],math.log(100)/.02,places=10)
        self.assertAlmostEqual(r['necessary_noise_rate_upper_bound'],-math.log(.98)/(.01**2*4096),places=12)
        self.assertFalse(r['simultaneous_rate_interval_nonempty'])
        self.assertGreater(r['necessary_write_rate_lower_bound']/r['necessary_noise_rate_upper_bound'],4000)

    def test_malformed_inputs_are_rejected(self):
        model=RawTokenMemory('hcsn',width=16)
        data=make_batch(31008,n=2)
        for tokens in (data.tokens.float(),data.tokens[:,:0],data.tokens+VOCAB_SIZE):
            with self.assertRaises(ValueError):model(tokens,data.duration)
        for dt in (data.duration*0,data.duration*-1,data.duration+float('nan'),data.duration[:,:2]):
            with self.assertRaises(ValueError):model(data.tokens,dt)
        with self.assertRaises(ValueError):interpret([MAP_BEGIN,WRITE,KEY_BASE])
        with self.assertRaises(ValueError):make_batch(31009,copy_count=4,copy_length=3)

    def test_small_budget_trains_from_query_loss_only(self):
        model,report=train_one('ordinary',73,steps=18,batch_size=10,width=16)
        self.assertLess(report['development_final_nll'],report['development_initial_nll'])
        self.assertEqual(report['nonfinite_events'],0)

if __name__=='__main__':unittest.main()
