"""Causality and data contracts. Synthetic fixtures are not quality evidence."""
import copy
import unittest
import numpy as np
import torch
from .p3_frozen_clip_features import select_indices
from .p3_frozen_temporal_fusion import MODES, TemporalFusion, evaluate, model_output, streams, training_loss


def fixture_bundle():
    labels = np.repeat(np.arange(10), 4)
    g = torch.Generator().manual_seed(412)
    pool = torch.randn(40, 8, generator=g).softmax(-1)
    result = {"text_prob": torch.randn(10, 8, generator=g).softmax(-1)}
    for split in ("train", "calibration", "test"):
        result[split + "_prob"] = pool
        result[split + "_labels"] = labels
    return result


class FrozenTemporalContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        torch.set_num_threads(1)

    def batch(self):
        return streams(fixture_bundle(), split="train", seed=34, batch=6, length=10)

    def test_streaming_and_no_future_leakage(self):
        b = self.batch()
        for mode in MODES:
            torch.manual_seed(8)
            m = TemporalFusion(mode)
            full = model_output(m, b)
            prefix = m(b["image"][:, :4], b["text"][:, :4], b["observed"][:, :4], b["dt"][:, :4])
            suffix = m(b["image"][:, 4:], b["text"][:, 4:], b["observed"][:, 4:], b["dt"][:, 4:], prefix[2])
            torch.testing.assert_close(full[0][:, :4], prefix[0], rtol=0, atol=0)
            torch.testing.assert_close(full[1], torch.cat((prefix[1], suffix[1]), 1), rtol=0, atol=0)
            changed = copy.deepcopy(b)
            changed["image"][:, 4:] = 1 - changed["image"][:, 4:]
            torch.testing.assert_close(model_output(m, changed)[0][:, :4], prefix[0], rtol=0, atol=0)

    def test_missing_payload_cannot_change_logits(self):
        b = self.batch()
        for mode in MODES:
            m = TemporalFusion(mode)
            original = model_output(m, b)
            altered = copy.deepcopy(b)
            for j, key in enumerate(("image", "text")):
                altered[key][~b["observed"][:, :, j]] = 1000.
            for a, c in zip(original[:2], model_output(m, altered)[:2]):
                torch.testing.assert_close(a, c, rtol=0, atol=0)

    def test_blank_physical_time_is_exact_identity(self):
        for mode in MODES:
            m = TemporalFusion(mode)
            state = model_output(m, self.batch())[2]
            empty = torch.zeros((6, 5, 8))
            mask = torch.zeros((6, 5, 2), dtype=torch.bool)
            after = m(empty, empty, mask, torch.full((6, 5), 1.e6), state)[2]
            for x, y in zip(state[:4], after[:4]):
                torch.testing.assert_close(x, y, rtol=0, atol=0)
            for x, y in zip(state[4:], after[4:]):
                torch.testing.assert_close(y - x, torch.full_like(x, 5.e6), rtol=0, atol=0)

    def test_missing_interval_subdivision_preserves_next_observation(self):
        b = self.batch()
        for mode in MODES:
            m = TemporalFusion(mode)
            present = torch.ones((6, 1, 2), dtype=torch.bool)
            initial = m(b["image"][:, :1], b["text"][:, :1], present, torch.ones((6, 1)))[2]
            direct = m(b["image"][:, 1:2], b["text"][:, 1:2], present, torch.full((6, 1), 4.), initial)
            absent = torch.zeros_like(present)
            blank = m(b["image"][:, 1:2], b["text"][:, 1:2], absent, torch.full((6, 1), 3.), initial)[2]
            divided = m(b["image"][:, 1:2], b["text"][:, 1:2], present, torch.ones((6, 1)), blank)
            for x, y in zip(direct[:2], divided[:2]):
                torch.testing.assert_close(x, y, rtol=0, atol=0)

    def test_missing_metric_class_is_not_balanced_success(self):
        b = self.batch()
        b["text_label"] = b["image_label"].clone()
        result, _ = evaluate(TemporalFusion("ordinary"), b)
        self.assertEqual(result["match_support"]["False"], 0)
        self.assertIsNone(result["match_balanced_accuracy"])
        b["image_label"].fill_(-1)
        b["text_label"].fill_(-1)
        result, _ = evaluate(TemporalFusion("ordinary"), b)
        self.assertIsNone(result["match_accuracy"])

    def test_batch_independence(self):
        b = self.batch()
        for mode in MODES:
            m = TemporalFusion(mode)
            whole = model_output(m, b)
            one = {k: v[2:3] for k, v in b.items()}
            for a, c in zip(whole[:2], model_output(m, one)[:2]):
                torch.testing.assert_close(a[2:3], c, rtol=1e-5, atol=1e-6)

    def test_put_linear_weight_mapping_preserves_full_sequence(self):
        torch.manual_seed(97)
        dual = TemporalFusion("call_put").double()
        linear = TemporalFusion("put_linear").double()
        linear.load_state_dict(dual.state_dict())
        with torch.no_grad():
            weights = dual.gate_readout.weight.clone()
            linear.gate_readout.weight[:, 0] = weights[:, 0] + weights[:, 1]
            linear.gate_readout.weight[:, 1] = weights[:, 0]
        batch = {k: v.double() if v.is_floating_point() else v for k, v in self.batch().items()}
        for x, y in zip(model_output(dual, batch)[:2], model_output(linear, batch)[:2]):
            torch.testing.assert_close(x, y, atol=2.e-13, rtol=1.e-12)

    def test_paired_head_active_capacity_and_training_gradients(self):
        models = []
        for mode in MODES:
            torch.manual_seed(19)
            models.append(TemporalFusion(mode))
        for m in models[1:]:
            for a, b in zip(models[0].contradiction.parameters(), m.contradiction.parameters()):
                torch.testing.assert_close(a, b, rtol=0, atol=0)
        counts = [sum(p.numel() for p in m.parameters()) for m in models]
        self.assertEqual(counts[:3], [counts[0]] * 3)
        self.assertEqual(counts[0] - counts[-1], 8)
        for m in models:
            training_loss(m, self.batch()).backward()
            self.assertTrue(all(p.grad is not None and bool(torch.isfinite(p.grad).all()) for p in m.parameters()))

    def test_training_excludes_unknown_classes(self):
        bundle = fixture_bundle()
        for split in ("train", "calibration"):
            b = streams(bundle, split=split, seed=91, batch=16, length=12)
            self.assertLess(int(b["image_label"].max()), 8)
            self.assertLess(int(b["text_label"].max()), 8)
        unknown = streams(bundle, split="test", seed=91, unknown=True, batch=16, length=12)
        self.assertGreaterEqual(int(unknown["image_label"].min()), 8)
        with self.assertRaises(ValueError):
            training_loss(TemporalFusion("ordinary"), unknown)
        with self.assertRaises(ValueError):
            streams(bundle, split="train", seed=91, unknown=True)

    def test_labels_track_observations_without_hidden_updates(self):
        for scenario in ("missing_image", "missing_text", "long_blank"):
            b = streams(fixture_bundle(), split="test", seed=42, batch=8, length=12, scenario=scenario)
            for axis, key in enumerate(("image_label", "text_label")):
                for t in range(1, 12):
                    hidden = ~b["observed"][:, t, axis]
                    torch.testing.assert_close(b[key][hidden, t], b[key][hidden, t - 1], rtol=0, atol=0)

    def test_calibration_disjoint_and_invalid_domain(self):
        labels = list(range(10)) * 8
        self.assertFalse(set(select_indices(labels, 3)) & set(select_indices(labels, 2, 3)))
        b = self.batch()
        b["dt"][0, 0] = 0
        with self.assertRaises(ValueError):
            model_output(TemporalFusion("call_put"), b)
        with self.assertRaises(ValueError):
            TemporalFusion("full_hx")


if __name__ == "__main__":
    unittest.main()
