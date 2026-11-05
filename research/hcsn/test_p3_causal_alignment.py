"""Semantic regressions for the causal real-feature alignment path."""
import copy
import unittest

import numpy as np
import torch

try:
    from .p3_causal_alignment import (CausalMatcher, SLOTS, PANELS, source_targets,
        mapped_put_linear, make_stream, marginal_loss, forward_batch, decisions, train_model)
except ImportError:
    from p3_causal_alignment import (CausalMatcher, SLOTS, PANELS, source_targets,
        mapped_put_linear, make_stream, marginal_loss, forward_batch, decisions, train_model)


def fixture():
    rng = np.random.default_rng(441)
    def normalized(n):
        x = rng.normal(size=(n, 512)).astype(np.float32)
        return x / np.linalg.norm(x, axis=-1, keepdims=True)
    image = normalized(48)
    return {"coco_image": image, "sugar_positive": image.copy(), "sugar_negative": normalized(48),
            "sugar_split": np.repeat(np.arange(3), 16), "sugar_image_index": np.arange(48)}


class CausalAlignmentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        torch.set_num_threads(1)

    def setUp(self):
        torch.manual_seed(123)
        self.a = fixture()
        self.batch = make_stream(self.a, split=0, seed=71, batch=3, length=12)

    def test_prefix_and_chunk_equivalence_all_controls(self):
        for mode in ("call_put", "ordinary_tangent", "put_linear", "cosine", "time_only_newest"):
            model = CausalMatcher(mode)
            x = [self.batch[k] for k in ("image", "text", "observed", "dt")]
            full, state = model(*x)
            prefix, middle = model(*(v[:, :5] for v in x))
            suffix, end = model(*(v[:, 5:] for v in x), state=middle)
            torch.testing.assert_close(full[:, :5], prefix, rtol=0, atol=0)
            torch.testing.assert_close(full[:, 5:], suffix, rtol=0, atol=0)
            for actual, expected in zip(end, state):
                torch.testing.assert_close(actual, expected, rtol=0, atol=0)
            changed = [v.clone() for v in x]
            changed[0][:, 5:] += 7
            changed[1][:, 5:] -= 4
            altered, _ = model(*changed)
            torch.testing.assert_close(altered[:, :5], prefix, rtol=0, atol=0)

    def test_unobserved_payloads_and_targets_do_not_enter_forward(self):
        model = CausalMatcher()
        expected, state = forward_batch(model, self.batch)
        data = copy.deepcopy(self.batch)
        data["image"][~data["observed"][..., 0]] = 123.
        data["text"][~data["observed"][..., 1]] = -53.
        data["query_source"][:] = -1000
        data["slot_ids"][:] = -2000
        data["target"][:] = ~data["target"]
        actual, end = forward_batch(model, data)
        torch.testing.assert_close(actual, expected, rtol=0, atol=0)
        for a, b in zip(state, end):
            torch.testing.assert_close(a, b, rtol=0, atol=0)

    def test_label_fifo_multi_positive_and_eviction(self):
        ids = np.array([[8, 8, 9, 10, 11, 12]])
        queries = np.full_like(ids, 8)
        obs = np.ones(ids.shape + (2,), dtype=bool)
        labels, slots = source_targets(ids, queries, obs)
        self.assertEqual(labels[0, 1, :SLOTS].sum(), 2)
        self.assertEqual(slots[0, -1].tolist(), [12, 11, 10, 9])
        self.assertTrue(labels[0, -1, SLOTS])
        obs[0, 3, 1] = False
        labels, _ = source_targets(ids, queries, obs)
        self.assertFalse(labels[0, 3].any())
        logits = torch.zeros(1, 1, 5)
        target = torch.tensor([[[True, True, False, False, False]]])
        self.assertAlmostEqual(float(marginal_loss(logits, target, torch.tensor([[True]]))), -np.log(2/5), places=6)

    def test_whole_mapped_forward_and_input_gradient(self):
        model = CausalMatcher().double()
        mapped = mapped_put_linear(model)
        x = [self.batch[k].double() if k != "observed" else self.batch[k] for k in ("image", "text", "observed", "dt")]
        x[0].requires_grad_(); x[1].requires_grad_()
        a, _ = model(*x)
        ga = torch.autograd.grad(a.sum(), (x[0], x[1]), retain_graph=True)
        b, _ = mapped(*x)
        gb = torch.autograd.grad(b.sum(), (x[0], x[1]))
        torch.testing.assert_close(a, b, atol=2e-12, rtol=2e-12)
        for lhs, rhs in zip(ga, gb):
            torch.testing.assert_close(lhs, rhs, atol=3e-11, rtol=3e-11)

    def test_blank_subdivision_preserves_physical_clock(self):
        model = CausalMatcher()
        image = torch.from_numpy(self.a["coco_image"][:1]).reshape(1, 1, 512)
        text = image.clone()
        _, state = model(image, text, torch.tensor([[[True, False]]]), torch.ones(1, 1))
        _, one = model(image, text, torch.tensor([[[False, False]]]), torch.tensor([[4.]]), state)
        _, many = model(image.repeat(1, 4, 1), text.repeat(1, 4, 1), torch.zeros(1, 4, 2, dtype=torch.bool), torch.ones(1, 4), state)
        final_obs = torch.tensor([[[False, True]]])
        a, _ = model(image, text, final_obs, torch.ones(1, 1), one)
        b, _ = model(image, text, final_obs, torch.ones(1, 1), many)
        torch.testing.assert_close(a, b, atol=0, rtol=0)

    def test_panels_source_contract_and_split_separation(self):
        anchors = np.arange(32, 48)
        for panel in PANELS:
            data = make_stream(self.a, split=2, seed=72, batch=16, length=12, scenario=panel, anchors=anchors)
            self.assertTrue((self.a["sugar_split"][data["image_rows"]] == 2).all())
            self.assertTrue((self.a["sugar_split"][data["text_rows"]] == 2).all())
            self.assertTrue(data["observed"][:, -1, 1].all())
            present = data["target"][:, -1, :SLOTS].any(-1)
            self.assertEqual(bool(present.all()), panel not in ("missing_source_frame", "evicted_source"))
            if panel in ("missing_source_frame", "evicted_source"):
                self.assertFalse(present.any())

    def test_missing_text_unscored_and_no_slot_never_accepted(self):
        model = CausalMatcher("cosine")
        data = copy.deepcopy(self.batch)
        data["observed"][:] = False
        data["observed"][0, -1, 1] = True
        target, slots = source_targets(data["query_source"], data["query_source"], data["observed"].numpy())
        data["target"], data["slot_ids"] = torch.from_numpy(target), slots
        result = decisions(model, data, -1e9)
        self.assertEqual(result["observed_queries"], 1)
        self.assertEqual(result["unscored_missing_text"], 2)
        self.assertEqual(result["source_absent_count"], 1)
        self.assertEqual(result["absent_false_match_count"], 0)

    def test_pair_readout_really_consumes_both_modalities(self):
        model = CausalMatcher("cosine")
        image = torch.from_numpy(self.a["coco_image"][:2]).reshape(1, 2, 512)
        age = torch.zeros(1, 2)
        first = model.score_pairs(image, image[:, 0], age)
        other = model.score_pairs(image, image[:, 1], age)
        self.assertEqual(int(first.argmax(-1)), 0)
        self.assertEqual(int(other.argmax(-1)), 1)
        self.assertGreater(float((first-other).abs().max()), 10)
        time_only = CausalMatcher("time_only_newest")
        torch.testing.assert_close(time_only.score_pairs(image, image[:, 0], age), time_only.score_pairs(image, image[:, 1], age))

    def test_decision_adapter_never_uses_label_occupancy(self):
        model = CausalMatcher("cosine")
        for final_only in (False, True):
            expected = decisions(model, self.batch, -1e8, final_only=final_only)
            altered = copy.deepcopy(self.batch)
            altered["slot_ids"][:] = -1
            altered["query_source"][:] = -10000
            altered["target"][:] = ~altered["target"]
            actual = decisions(model, altered, -1e8, final_only=final_only)
            for key in ("accept", "chosen_slot", "margin", "observed_queries", "unscored_missing_text"):
                self.assertEqual(expected[key], actual[key])

    def test_invalid_domains_are_rejected(self):
        model = CausalMatcher()
        for key, replacement in (("dt", torch.zeros_like(self.batch["dt"])),
                                 ("text", torch.full_like(self.batch["text"], float("nan"))),
                                 ("observed", self.batch["observed"].int())):
            data = {**self.batch, key: replacement}
            with self.assertRaises(ValueError): forward_batch(model, data)
        with self.assertRaises(ValueError): CausalMatcher("unknown")
        with self.assertRaises(ValueError): make_stream(self.a, split=2, seed=1, anchors=np.arange(16))

    def test_actual_training_smoke_has_finite_full_gradient_path(self):
        for mode in ("call_put", "ordinary_tangent"):
            model, trace = train_model(self.a, 79, mode, updates=2, batch_size=3)
            self.assertEqual(sum(p.numel() for p in model.parameters()), 322)
            self.assertEqual(len(trace), 2)
            self.assertTrue(all(np.isfinite(x["loss"]) and x["preclip_gradient_norm"] > 0 for x in trace))


if __name__ == "__main__":
    unittest.main()
