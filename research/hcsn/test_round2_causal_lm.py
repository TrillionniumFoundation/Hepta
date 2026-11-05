"""Causal whole-network and optimizer-isomorphism checks, not efficacy tests."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import torch

try:
    from .round2_causal_lm import (
        BOUNDARY, CausalByteLM, call_put, load_corpus, loss_for,
        native_gradient_in_canonical, ordinary_put, parameter_groups_changed,
        training_windows, variant_from_dual,
    )
except ImportError:
    from round2_causal_lm import (
        BOUNDARY, CausalByteLM, call_put, load_corpus, loss_for,
        native_gradient_in_canonical, ordinary_put, parameter_groups_changed,
        training_windows, variant_from_dual,
    )


class CausalModuleControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        torch.set_num_threads(1)

    def model(self, replaced=1):
        torch.manual_seed(92)
        return CausalByteLM("dual", replaced, width=16, hidden=8, context=16, heads=2).double()

    def data(self):
        return torch.randint(0, 256, (2, 13), generator=torch.Generator().manual_seed(100))

    def test_global_pair_identity_and_local_only_ordinary_slope(self):
        u = torch.tensor([1e-7, .2, BOUNDARY, .9, 2., 100., 1e5], dtype=torch.float64,
                         requires_grad=True)
        c, p = call_put(u)
        torch.testing.assert_close(c - p, u - 1, atol=3e-16, rtol=3e-16)
        slope = torch.autograd.grad((c - p).sum(), u)[0]
        torch.testing.assert_close(slope, torch.ones_like(u), atol=2e-15, rtol=0)
        anchor = torch.tensor([BOUNDARY], dtype=torch.float64, requires_grad=True)
        _, put = call_put(anchor)
        ordinary = ordinary_put(anchor)
        torch.testing.assert_close(ordinary, put, atol=2e-16, rtol=0)
        gp = torch.autograd.grad(put.sum(), anchor)[0]
        go = torch.autograd.grad(ordinary.sum(), anchor)[0]
        torch.testing.assert_close(go, gp, atol=2e-15, rtol=0)
        off = torch.tensor([.1, 2.], dtype=torch.float64)
        self.assertGreater(float((ordinary_put(off) - call_put(off)[1]).abs().max()), .01)

    def test_whole_network_functions_and_full_gradient_pullback(self):
        for replaced in (1, 2):
            dual = self.model(replaced)
            canonical = variant_from_dual(dual, "put_linear_canonical")
            native = variant_from_dual(dual, "put_linear_native")
            results = {}
            for name, model in (("dual", dual), ("canonical", canonical), ("native", native)):
                logits, loss = loss_for(model, self.data())
                loss.backward()
                results[name] = (logits, {n: p.grad.clone() for n, p in model.named_parameters()})
            for mode, model in (("canonical", canonical), ("native", native)):
                torch.testing.assert_close(results["dual"][0], results[mode][0], atol=5e-14, rtol=2e-12)
                for name, gradient in results["dual"][1].items():
                    actual = native_gradient_in_canonical(name, results[mode][1][name], model)
                    torch.testing.assert_close(gradient, actual, atol=5e-13, rtol=2e-10,
                                               msg=lambda x: name + ": " + x)

    def test_canonical_adam_trajectory_and_native_coordinate_counterexample(self):
        dual = self.model(2)
        canonical = variant_from_dual(dual, "put_linear_canonical")
        native = variant_from_dual(dual, "put_linear_native")
        initial = {n: p.detach().clone() for n, p in dual.named_parameters()}
        models = [dual, canonical, native]
        optimizers = [torch.optim.Adam(m.parameters(), lr=.003, eps=1e-8, weight_decay=0.) for m in models]
        for step in range(4):
            pairs = self.data().roll(step, dims=1)
            for model, optimizer in zip(models, optimizers):
                optimizer.zero_grad(set_to_none=True)
                _, loss = loss_for(model, pairs)
                loss.backward()
                optimizer.step()
            for a, b in zip(dual.parameters(), canonical.parameters()):
                torch.testing.assert_close(a, b, atol=3e-10, rtol=3e-9)
        for name, value in parameter_groups_changed(dual, initial).items():
            self.assertGreater(value, 0, name)
        a, _ = loss_for(dual, self.data())
        b, _ = loss_for(native, self.data())
        self.assertGreater(float((a - b).abs().max().detach()), 1e-5)

    def test_no_future_token_leakage_after_internal_replacement(self):
        x = self.data()[:, :-1]
        altered = x.clone()
        altered[:, 6:] = (altered[:, 6:] + 51) % 256
        for replaced in (1, 2):
            dual = self.model(replaced)
            for mode in ("dual", "put_linear_native", "put_linear_canonical", "ordinary_sigmoid_tangent"):
                model = dual if mode == "dual" else variant_from_dual(dual, mode)
                torch.testing.assert_close(model(x)[:, :6], model(altered)[:, :6], rtol=0, atol=0)

    def test_document_holdout_and_training_windows_do_not_cross_documents(self):
        docs = [b"abcdefghijABCDEFGHIJ" * 3, b"1234567890!@#$%^&*()" * 3]
        samples, receipt = training_windows(docs, seed=7, updates=4, batch=3, context=8)
        flat = samples.reshape(-1, 9)
        for row, (document, offset) in zip(flat, receipt["document_index_and_offset"]):
            self.assertEqual(bytes(row.tolist()), docs[document][offset:offset + 9])
        self.assertEqual(len(receipt["sample_uint8_sha256"]), 64)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            train = b"abcdefghi" * 6
            heldout = train[:16] + b"ZYXWVUTSRQPONMLKJIHGFEDCBA"
            (root / "a.txt").write_bytes(train)
            (root / "b.txt").write_bytes(heldout)
            entry = lambda name, data: {"path": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
            protocol = {"corpus": {"train": [entry("a.txt", train)], "heldout": [entry("b.txt", heldout)]},
                        "architecture": {"context": 8}, "evaluation": {"max_windows_per_document": 20}}
            _, windows, audit = load_corpus(root, protocol)
            self.assertGreater(audit[0]["exact_train_overlap_windows_excluded"], 0)
            for row in windows[0][1]:
                self.assertNotIn(bytes(row.tolist()), train)
            (root / "a.txt").write_bytes(train + b"changed")
            with self.assertRaises(ValueError):
                load_corpus(root, protocol)


if __name__ == "__main__":
    unittest.main()
