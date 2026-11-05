"""Causal data and learned-routing contracts for the associative experiment."""
import copy
import unittest
import numpy as np
import torch
from .p2_associative_memory import RawDeltaMemory,delta_batch,interpret_delta,IGNORE,DELTA_VOCAB_SIZE
from .p2_round2_raw_tokens import WRITE,ASK,READ,RESET,MAP_BEGIN,KEY_BASE,VALUE_BASE,UNKNOWN
from .p2_associative_campaign import metrics_from_logits

class AssociativeContracts(unittest.TestCase):
    def setUp(self):
        torch.set_num_threads(1);torch.manual_seed(571)
        self.model=RawDeltaMemory('hcsn_delta').double()
        self.b=delta_batch(571019,n=4,kinds=('mqar','overwrite','state_tracking','multi_reset'))
    def test_independent_interpreter_ignore_overwrite_reset(self):
        k=KEY_BASE;v=VALUE_BASE
        seq=[MAP_BEGIN,WRITE,k,v+1,IGNORE,k,v+2,ASK,k,READ,WRITE,k,v+3,ASK,k,READ,RESET,ASK,k,READ]
        labels=interpret_delta(seq)
        self.assertEqual([x for x in labels if x!=-100],[1,3,UNKNOWN])
    def test_labels_do_not_enter_forward(self):
        b=self.b
        with torch.no_grad():x=self.model(b.tokens,b.duration.double())
        b.targets.fill_(0);b.stale_answers.fill_(3)
        with torch.no_grad():y=self.model(b.tokens,b.duration.double())
        torch.testing.assert_close(x,y,rtol=0,atol=0)
    def test_causal_prefix_and_streaming(self):
        b=self.b;k=15
        with torch.no_grad():
            allx=self.model(b.tokens,b.duration.double())
            first,state=self.model(b.tokens[:,:k],b.duration[:,:k].double(),return_state=True)
            second=self.model(b.tokens[:,k:],b.duration[:,k:].double(),initial=state)
        torch.testing.assert_close(first,allx[:,:k],rtol=0,atol=0)
        torch.testing.assert_close(torch.cat((first,second),1),allx,rtol=0,atol=0)
    def test_semantic_id_permutation_equivariance(self):
        # A semantic-ID branch in forward would break this exact equivariance.
        permutation=torch.randperm(DELTA_VOCAB_SIZE)
        clone=copy.deepcopy(self.model)
        with torch.no_grad():clone.embedding.weight[permutation]=self.model.embedding.weight
        with torch.no_grad():
            a=self.model(self.b.tokens,self.b.duration.double())
            b=clone(permutation[self.b.tokens],self.b.duration.double())
        torch.testing.assert_close(a,b,rtol=0,atol=0)
    def test_batch_independence(self):
        with torch.no_grad():
            full=self.model(self.b.tokens,self.b.duration.double())
            solo=self.model(self.b.tokens[:1],self.b.duration[:1].double())
        torch.testing.assert_close(full[:1],solo,rtol=1e-12,atol=1e-12)
    def test_mapped_values_and_gradients(self):
        mapped=RawDeltaMemory('put_linear_delta').double();mapped.load_state_dict(self.model.state_dict())
        x=self.model(self.b.tokens,self.b.duration.double());y=mapped(self.b.tokens,self.b.duration.double())
        torch.testing.assert_close(x,y,rtol=1e-11,atol=1e-11)
        x.square().sum().backward();y.square().sum().backward()
        for a,b in zip(self.model.parameters(),mapped.parameters()):
            self.assertIsNotNone(a.grad);torch.testing.assert_close(a.grad,b.grad,rtol=1e-9,atol=1e-9)
    def test_real_query_loss_reaches_all_parameters(self):
        scores=self.model(self.b.tokens,self.b.duration.double())
        torch.nn.functional.cross_entropy(scores.flatten(0,1),self.b.targets.flatten()).backward()
        for p in self.model.parameters():
            self.assertIsNotNone(p.grad);self.assertTrue(torch.isfinite(p.grad).all())
        self.assertGreater(float(self.model.address.weight.grad.norm()),0)
    def test_metrics_score_whole_sequences(self):
        b=delta_batch(67011,n=3,kinds=('multi_reset',),episodes=2)
        logits=torch.full((*b.tokens.shape,5),-20.)
        mask=b.targets!=-100
        logits[mask]=torch.nn.functional.one_hot(b.targets[mask],5).float()*40-20
        r=metrics_from_logits(logits,b);self.assertEqual(r['sequence_exact_accuracy'],1)
        row,col=mask.nonzero()[0];logits[row,col]=0;logits[row,col,(int(b.targets[row,col])+1)%5]=1
        r=metrics_from_logits(logits,b);self.assertEqual(r['exact_sequences'],2)
    def test_invalid_input_rejected(self):
        with self.assertRaises(ValueError):self.model(self.b.tokens,self.b.duration.double()*0)
        with self.assertRaises(ValueError):self.model(self.b.tokens+100,self.b.duration.double())
        with self.assertRaises(ValueError):delta_batch(1,n=1,kinds=('selective_copy',))
    def test_pair_counts_and_initialization(self):
        for mode in ['ordinary_delta','hcsn_delta']:
            torch.manual_seed(571);model=RawDeltaMemory(mode)
            self.assertEqual(sum(x.numel() for x in model.parameters()),2301)
        with self.assertRaises(ValueError):interpret_delta([IGNORE,KEY_BASE])

if __name__=='__main__':unittest.main()
