"""Independent algebra, signed gradients, and policy checks for the P1 control."""
import copy
import math
import unittest

import numpy as np
import torch

try:
    from .train_study import MatchedHead, make_data, two_features
    from .p1_exact_policy_eval import exact_policy_regret
    from .p1_hermite_control import HermiteMatchedHead
    from .p1_put_linear_control import (
        PutLinearHead, capacity, feature_identity_check, mapped_from_dual,
        mapped_to_dual, put_linear_features, run, train_put_linear,
    )
except ImportError:
    from train_study import MatchedHead, make_data, two_features
    from p1_exact_policy_eval import exact_policy_regret
    from p1_hermite_control import HermiteMatchedHead
    from p1_put_linear_control import (
        PutLinearHead, capacity, feature_identity_check, mapped_from_dual,
        mapped_to_dual, put_linear_features, run, train_put_linear,
    )


class PutLinearControlTests(unittest.TestCase):
    def setUp(self):
        torch.set_num_threads(1)
        self.x = torch.tensor([
            [.02, .51, .001, 1.], [.30, .88, .04, 3.], [.49, .97, .199, 5.],
            [.51, .75, .14, 2.], [.88, .66, .08, 4.],
        ], dtype=torch.float64)

    def test_payoff_identity_both_regions_and_at_boundary(self):
        # Independent scalar parameters locate the three boundary-side probes.
        beta = math.sqrt(2 * .05 * .20 ** 2) / .20 ** 2
        k = 1 + .5 * .05
        p_boundary = beta / (beta + 1) * k / 2
        edge = torch.tensor([[p_boundary + d, .85, .05, 3.]
                             for d in (-1e-9, 0., 1e-9)], dtype=torch.float64)
        x = torch.cat((self.x, edge))
        cp, pl = two_features(x, "dual_call_put"), put_linear_features(x)
        self.assertTrue(torch.equal(cp[:, 1], pl[:, 0]))
        # L is computed independently from NumPy input values here.
        p = x.numpy()[:, 0]
        scalar_l = 2 * np.maximum(np.minimum(p, 1 - p), 1e-5) / (1 + .5 * x.numpy()[:, 2]) - 1
        np.testing.assert_allclose((cp[:, 0] - cp[:, 1]).numpy(), scalar_l, atol=3e-16, rtol=0)
        np.testing.assert_allclose(pl[:, 1].numpy(), scalar_l, atol=0, rtol=0)
        self.assertEqual(cp[-3, 0].item(), 0.)
        self.assertLess(abs(cp[-1, 0].item()), 1e-15)

    def test_full_signed_feature_jacobian_and_independent_finite_differences(self):
        stats = feature_identity_check(self.x)
        self.assertLess(stats["max_abs_signed_jacobian_difference"], 2e-14)
        for row in self.x:
            x = row[None].clone().requires_grad_(True)
            # The transformed pair reconstructed into C/P coordinates.
            def reconstruct(z):
                pl = put_linear_features(z)
                return torch.stack((pl[:, 0] + pl[:, 1], pl[:, 0]), -1)[0]
            actual = torch.autograd.functional.jacobian(reconstruct, x).reshape(2, 4)
            for j in range(4):
                h = 2e-6
                plus, minus = x.detach().clone(), x.detach().clone()
                plus[0, j] += h
                minus[0, j] -= h
                fd = (two_features(plus, "dual_call_put")[0]
                      - two_features(minus, "dual_call_put")[0]) / (2 * h)
                torch.testing.assert_close(actual[:, j], fd, atol=2e-8, rtol=2e-8)
        # The Put slope changes sign with the belief reflection, not just magnitude.
        z = self.x.clone().requires_grad_(True)
        slope = torch.autograd.grad(put_linear_features(z)[:, 0].sum(), z)[0][:, 0]
        self.assertLess(slope[0].item(), 0.)
        self.assertGreater(slope[-1].item(), 0.)

    def test_bidirectional_function_class_mapping_preserves_rng_and_source(self):
        for width in (1, 7, 20):
            torch.manual_seed(712 + width)
            dual = MatchedHead("dual_call_put", width=width).double().eval()
            previous = copy.deepcopy(dual.state_dict())
            rng = torch.random.get_rng_state().clone()
            mapped = mapped_from_dual(dual)
            self.assertTrue(torch.equal(rng, torch.random.get_rng_state()))
            restored = mapped_to_dual(mapped)
            for key, tensor in dual.state_dict().items():
                self.assertTrue(torch.equal(previous[key], tensor))
            torch.testing.assert_close(dual(self.x), mapped(self.x), atol=2e-15, rtol=2e-15)
            torch.testing.assert_close(dual(self.x), restored(self.x), atol=2e-15, rtol=2e-15)
            self.assertFalse(mapped.training)
            self.assertEqual(capacity(dual), capacity(mapped))
            # Mapping works in the opposite direction for an arbitrary PL head too.
            arbitrary = PutLinearHead(width).double().eval()
            torch.testing.assert_close(arbitrary(self.x), mapped_to_dual(arbitrary)(self.x),
                                       atol=2e-15, rtol=2e-15)

    def test_same_parameter_seed_is_not_same_function_initialization(self):
        torch.manual_seed(11)
        dual = MatchedHead("dual_call_put").double().eval()
        torch.manual_seed(11)
        raw = PutLinearHead().double().eval()
        self.assertTrue(all(torch.equal(a, b) for a, b in zip(dual.parameters(), raw.parameters())))
        self.assertGreater(float((dual(self.x) - raw(self.x)).abs().max()), .001)
        z = self.x.clone().requires_grad_(True)
        mapped = mapped_from_dual(dual)
        ja = torch.autograd.grad(dual(z).sum(), z)[0]
        jb = torch.autograd.grad(mapped(z).sum(), z)[0]
        torch.testing.assert_close(ja, jb, atol=2e-15, rtol=2e-15)

    def test_exact_policy_reference_and_nonzero_training_gradients(self):
        for flag in (False, True):
            model, rec = train_put_linear(23, function_matched_init=flag, steps=4, train_rows=40)
            self.assertEqual(rec["trainable_parameters"], 161)
            self.assertEqual(rec["optimizer_updates"], 4)
            self.assertFalse(rec["adam_update_equivalence_claimed"])
            self.assertTrue(all(p.grad is not None and bool(p.grad.abs().sum() > 0)
                                for p in model.parameters()))
            inverse = mapped_to_dual(model)
            x, _ = make_data(201771, 50, ood=True)
            a = exact_policy_regret(model, x)
            b = exact_policy_regret(inverse, x)
            np.testing.assert_array_equal(a["policy"], b["policy"])
            np.testing.assert_array_equal(a["regret"], b["regret"])

    def test_reject_inapplicable_model_and_disclose_fixed_table_storage(self):
        for bad in (MatchedHead("ordinary_two_gate"), PutLinearHead(), HermiteMatchedHead()):
            with self.assertRaises(ValueError):
                mapped_from_dual(bad)
        with self.assertRaises(ValueError):
            mapped_to_dual(MatchedHead("dual_call_put"))
        with self.assertRaises(ValueError):
            put_linear_features(torch.zeros(2, 3))
        self.assertEqual(capacity(PutLinearHead())["fixed_buffer_bytes"], 0)
        hermite = capacity(HermiteMatchedHead())
        self.assertEqual(hermite["trainable_parameters"], 161)
        self.assertGreater(hermite["fixed_buffer_bytes"], 50000)


class PutLinearAuditIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = run(smoke=True)

    def test_pipeline_records_every_seed_and_keeps_scientific_gate_open(self):
        r = self.report
        self.assertTrue(r["protocol"]["smoke"])
        self.assertEqual(len(r["train_logs"]), 27)  # Nine trained models per seed.
        self.assertEqual(r["protocol"]["seeds"], [11, 23, 37])
        self.assertFalse(r["protocol"]["adam_equivalence_under_reparameterization_claimed"])
        self.assertFalse(r["matched_backward_flops_proven"])
        self.assertFalse(r["real_encoder_used"])
        self.assertFalse(r["production_activation"])
        self.assertEqual(r["p1_scientific_gate"], "OPEN")
        for tag in ("id", "ood"):
            raw = r["raw_exact_policy_regret_by_distribution_model_seed_state"][tag]
            self.assertEqual(len(raw), 10)
            for values in raw.values():
                self.assertEqual(np.shape(values), (3, 24))
                self.assertTrue(np.isfinite(values).all())
            np.testing.assert_array_equal(raw["put_linear_mapped_after_training"], raw["dual_call_put"])


if __name__ == "__main__":
    unittest.main()
