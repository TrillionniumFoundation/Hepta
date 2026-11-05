"""Completion guards must reject even one changed prefix value or tensor."""
import math
from pathlib import Path
import tempfile
import unittest
import torch
from .p2_reset_validity import RawResetValidityMemory
from .p2_reset_validity_campaign import save_model
from .p2_reset_validity_completion import verify_prefix_number,verify_prefix_checkpoint


class CompletionGuards(unittest.TestCase):
    def test_changed_loss_or_gradient_is_rejected_exactly(self):
        for label in ('loss','gradient norm'):
            verify_prefix_number(1.,1.,label,173)
            with self.assertRaises(AssertionError):
                verify_prefix_number(math.nextafter(1.,2.),1.,label,173)

    def test_nonfinite_prefix_is_never_accepted(self):
        for value in (float('nan'),float('inf'),-float('inf')):
            with self.assertRaises(AssertionError):verify_prefix_number(value,value,'loss',1)

    def test_prefix_checkpoint_bitwise_match_and_mismatch(self):
        torch.manual_seed(719);model=RawResetValidityMemory('hcsn_reset_validity')
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'weights.npz';save_model(model,path)
            self.assertTrue(verify_prefix_checkpoint(model,path)['all_tensors_bitwise_equal'])
            with torch.no_grad():model.embedding.weight[0,0]+=1
            with self.assertRaises(AssertionError):verify_prefix_checkpoint(model,path)

    def test_prefix_checkpoint_distinguishes_signed_zero(self):
        model=RawResetValidityMemory('hcsn_reset_validity')
        with torch.no_grad():model.embedding.weight[0,0]=0.
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'weights.npz';save_model(model,path)
            with torch.no_grad():model.embedding.weight[0,0]=-0.
            with self.assertRaises(AssertionError):verify_prefix_checkpoint(model,path)


if __name__=='__main__':unittest.main()
