"""2026-11-05 round 2: substantive HX interval and mixed-precision checks."""
from dataclasses import replace
from fractions import Fraction
import math
import unittest

import mpmath as mp
import torch

try:
    from .hx_original import HXParams, closed_boundary
    from .hx_a7_mp_regularized import equity_a7_mp
    from .hx_uniform import equity_logmargin
    from .hx_precision_audit import high_precision_boundary
    from .test_hx_precision_audit import WITNESSES
    from .hx_interval_domain import (normal_cdf_enclosure, boundary_domain_enclosure,
        local_equity_enclosure, evaluate_local_mixed_precision, round_binary,
        rounding_cell, parameter_box)
    from .hx_round2_precision import (mp_local_equity, native_literal_hx,
                                     quantized_state_diagnostic)
except ImportError:
    from hx_original import HXParams, closed_boundary
    from hx_a7_mp_regularized import equity_a7_mp
    from hx_uniform import equity_logmargin
    from hx_precision_audit import high_precision_boundary
    from test_hx_precision_audit import WITNESSES
    from hx_interval_domain import (normal_cdf_enclosure, boundary_domain_enclosure,
        local_equity_enclosure, evaluate_local_mixed_precision, round_binary,
        rounding_cell, parameter_box)
    from hx_round2_precision import (mp_local_equity, native_literal_hx,
                                    quantized_state_diagnostic)


INVALID_LOCAL = HXParams(r=.10, delta=.075, sigma=.20, alpha=.40, tax=.27,
                        xi=4., k=.20, maturity=3., coupon_total=5., face_total=100.)
COLLISION_MINUS = replace(INVALID_LOCAL, face_total=20., tax=.39990773048821086)
COLLISION_PLUS = replace(INVALID_LOCAL, face_total=20., tax=.3999077379072307)
OVERFLOW_WITNESS = HXParams(r=.30, delta=.001, sigma=.03, xi=0.)


class HXRound2DomainTests(unittest.TestCase):
    def assertEncloses(self, interval, reference):
        c = reference.context
        self.assertLessEqual(c.mpf(interval['lower']), reference)
        self.assertGreaterEqual(c.mpf(interval['upper']), reference)

    def test_green_legal_low_sigma_overflow_fixed_against_mp_a7(self):
        p = OVERFLOW_WITNESS
        b = closed_boundary(p)
        self.assertGreater(p.gamma*2, 709.)
        for x in (2., 8.):
            with self.subTest(x=x):
                actual = equity_logmargin(x, p)
                reference = equity_a7_mp(b*math.exp(x), p, b, dps=90)
                self.assertEqual(actual.method, 'quadrature_green_limit')
                self.assertLess(abs(actual.equity-reference), 3e-14*reference)
                self.assertFalse(actual.production_activation)

    def test_normal_enclosure_taylor_mills_switch_and_subnormal_export(self):
        c = mp.mp.clone(); c.dps = 150
        for x in (-1000., -100., -40., -20., -12.000000001, -12., -5., -1.,
                  0., 1., 5., 12., 12.000000001, 20., 40., 1000.):
            with self.subTest(x=x):
                result = normal_cdf_enclosure(x, x)
                self.assertEncloses(result, c.erfc(-c.mpf(x)/c.sqrt(2))/2)
        result = normal_cdf_enclosure(-40., -40.)
        self.assertEqual(result['lower'], 0.)
        self.assertEqual(result['upper'], math.ulp(0.))
        wide = normal_cdf_enclosure(-2., 3.)
        for x in (-2., -.1, 0., 2.9, 3.):
            self.assertEncloses(wide, c.erfc(-c.mpf(x)/c.sqrt(2))/2)

    def test_boundary_intervals_enclose_mp120_and_preserve_old_raw_counterexamples(self):
        points = (HXParams(), *WITNESSES, HXParams(xi=0.),
                  HXParams(xi=1e-20, k=1e-15), OVERFLOW_WITNESS, INVALID_LOCAL,
                  HXParams(maturity=.05), HXParams(maturity=10.), HXParams(alpha=0.))
        for p in points:
            with self.subTest(p=p):
                result = boundary_domain_enclosure(p)
                self.assertEncloses(result['boundary'], high_precision_boundary(p, digits=120))
                self.assertFalse(result['general_hx_parameter_domain_closed'])
        for p in WITNESSES:
            result = boundary_domain_enclosure(p)
            raw = closed_boundary(p)
            self.assertFalse(result['boundary']['lower'] <= raw <= result['boundary']['upper'])
            self.assertEqual(result['status'], 'SUFFICIENT_FIXED_DEBT_OBSTACLE')

    def test_full_low_precision_input_boxes_are_distinct_from_point_checks(self):
        for dtype in ('fp32', 'bf16'):
            result = boundary_domain_enclosure(HXParams(), dtype=dtype)
            self.assertEqual(result['status'], 'SUFFICIENT_FIXED_DEBT_OBSTACLE')
            # Smoke checks of the enclosure implementation, not the proof:
            # the continuum guarantee comes from interval inclusion/monotonicity.
            box = result['input_box']
            for side in ('lower', 'upper'):
                corner = HXParams(**{n: cell[side] for n, cell in box.items()})
                self.assertEncloses(result['boundary'], high_precision_boundary(corner, digits=120))
            self.assertGreater(result['boundary']['upper']-result['boundary']['lower'], 1e-6)
        for p in WITNESSES:
            result = boundary_domain_enclosure(p, dtype='bf16')
            self.assertTrue(result['status'].startswith('UNRESOLVED_'))

    def test_opposite_sign_same_encoding_cannot_receive_pointwise_verdict(self):
        minus = boundary_domain_enclosure(COLLISION_MINUS)
        plus = boundary_domain_enclosure(COLLISION_PLUS)
        self.assertGreater(minus['local_cashflow']['lower'], 0.)
        self.assertLess(plus['local_cashflow']['upper'], 0.)
        for dtype in ('fp32', 'bf16'):
            a = boundary_domain_enclosure(COLLISION_MINUS, dtype=dtype)
            b = boundary_domain_enclosure(COLLISION_PLUS, dtype=dtype)
            self.assertEqual(a['input_box'], b['input_box'])
            self.assertEqual(a['status'], 'UNRESOLVED_LOCAL_SIGN')
            self.assertLess(a['local_cashflow']['lower'], 0.)
            self.assertGreater(a['local_cashflow']['upper'], 0.)

    def test_negative_obstacle_witness_remains_signed_and_refused(self):
        result = boundary_domain_enclosure(INVALID_LOCAL)
        self.assertEqual(result['status'], 'REFUTED_LOCAL_OBSTACLE')
        certificate = local_equity_enclosure(1e-6, INVALID_LOCAL)
        self.assertLess(certificate['equity']['upper'], 0.)
        candidate = evaluate_local_mixed_precision(1e-6, INVALID_LOCAL)
        self.assertEqual(candidate['status'], 'REFUSED_UNRESOLVED_GLOBAL_DOMAIN')
        self.assertIsNone(candidate['value'])
        self.assertLess(candidate['candidate_value'], 0.)

    def test_legal_constructor_domain_does_not_guarantee_positive_eq12_candidate(self):
        p = HXParams(tax=.99, coupon_total=500., face_total=.0001)
        with self.assertRaises(ValueError):
            closed_boundary(p)
        for dtype in (None, 'fp32', 'bf16'):
            result = boundary_domain_enclosure(p, dtype=dtype)
            self.assertEqual(result['status'], 'NO_POSITIVE_EQ12_CANDIDATE')
            self.assertLess(result['boundary']['upper'], 0.)
        with self.assertRaisesRegex(ArithmeticError, 'Positive exact Eq12'):
            local_equity_enclosure(.001, p)

    def test_local_taylor_remainder_contains_independent_mp_green_integral(self):
        for p in (HXParams(), *WITNESSES, OVERFLOW_WITNESS):
            for x in (1e-8, 1e-3):
                with self.subTest(p=p, x=x):
                    certificate = local_equity_enclosure(x, p)
                    self.assertEncloses(certificate['equity'], mp_local_equity(x, p))
                    self.assertGreater(certificate['absolute_taylor_remainder_bound'], 0.)

    def test_native_fp32_and_bf16_output_error_is_bounded_against_independent_integral(self):
        for x in (1e-8, 1e-5, 1e-3):
            reference = mp_local_equity(x, HXParams())
            for dtype in ('fp32', 'bf16'):
                with self.subTest(x=x, dtype=dtype):
                    result = evaluate_local_mixed_precision(x, HXParams(), output_dtype=dtype)
                    self.assertEqual(result['status'], 'ACCEPTED_WITH_ERROR_ENCLOSURE')
                    c = reference.context
                    self.assertLessEqual(abs(c.mpf(result['value'])-reference),
                                         c.mpf(result['absolute_error_bound']))
                    self.assertLessEqual(result['relative_error_bound'], result['relative_tolerance'])
                    self.assertEqual(result['accumulation_dtype'], 'fp32')
                    self.assertFalse(result['production_activation'])

    def test_native_error_and_underflow_refuse_without_silent_projection(self):
        strict = evaluate_local_mixed_precision(.001, HXParams(), relative_tolerance=1e-12)
        self.assertEqual(strict['status'], 'REFUSED_ERROR_TOLERANCE')
        self.assertIsNone(strict['value'])
        underflow = evaluate_local_mixed_precision(1e-30, HXParams(), output_dtype='bf16')
        self.assertEqual(underflow['candidate_value'], 0.)
        self.assertEqual(underflow['status'], 'REFUSED_ERROR_TOLERANCE')
        self.assertIsNone(underflow['value'])
        zero = evaluate_local_mixed_precision(0., HXParams(), output_dtype='bf16')
        self.assertEqual(zero['value'], 0.)
        self.assertEqual(zero['absolute_error_bound'], 0.)

    def test_direct_native_a7_is_not_confused_with_validated_local_path(self):
        x = 1e-8
        direct = native_literal_hx(x, HXParams(), 'fp32')
        reference = float(mp_local_equity(x, HXParams()))
        self.assertEqual(direct['status'], 'FINITE_NATIVE_RESULT')
        self.assertGreater(abs(direct['equity']-reference), 1e-6)
        mixed = evaluate_local_mixed_precision(x, HXParams())
        self.assertLess(abs(mixed['value']-reference), 1e-19)

    def test_rounding_cells_match_actual_backend_and_ties_even(self):
        for dtype, td, bits in (('fp32', torch.float32, 24), ('bf16', torch.bfloat16, 8)):
            midpoint = 1.+2.**-bits
            self.assertEqual(round_binary(midpoint, dtype), 1.)
            self.assertGreater(round_binary(math.nextafter(midpoint, math.inf), dtype), 1.)
            for x in (0., .001, .03, .3, 1., 1.5, 61.68, 500., 1000., -1.):
                with self.subTest(dtype=dtype, x=x):
                    q, lo, hi = rounding_cell(x, dtype)
                    self.assertEqual(q, float(torch.tensor(x, dtype=td)))
                    self.assertLessEqual(lo, x)
                    self.assertGreaterEqual(hi, x)
        # A known-legal input may encode outside the constructor's domain;
        # the certificate covers its legal preimage, never silently clamps it.
        box = parameter_box(OVERFLOW_WITNESS, 'bf16')
        self.assertGreater(box['r']['encoded'], .3)
        self.assertEqual(box['r']['upper'], .3)

    def test_quantized_ratio_does_not_turn_information_loss_into_stopping(self):
        for dtype in ('fp32', 'bf16'):
            result = quantized_state_diagnostic(1e-8, HXParams(), dtype)
            self.assertEqual(result['actual_reconstructed_log_margin'], 0.)
            self.assertEqual(result['state_verdict'], 'UNRESOLVED_QUANTIZED_STATE')
            self.assertEqual(result['direct_margin_verdict'], 'CONTINUATION_PROVED')

    def test_precision_contexts_and_domain_guards_are_explicit(self):
        saved_mp, saved_iv = mp.mp.dps, mp.iv.dps
        a = boundary_domain_enclosure(HXParams(), digits=90)
        b = boundary_domain_enclosure(HXParams(), digits=140)
        reference = high_precision_boundary(HXParams(), digits=150)
        self.assertEncloses(a['boundary'], reference)
        self.assertEncloses(b['boundary'], reference)
        self.assertEqual((mp.mp.dps, mp.iv.dps), (saved_mp, saved_iv))
        for bad in (float('nan'), float('inf'), -1., .0011, True):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                local_equity_enclosure(bad, HXParams())
        for digits in (89, 181, True, 100.):
            with self.assertRaises(ValueError):
                boundary_domain_enclosure(HXParams(), digits=digits)
        with self.assertRaises(ValueError):
            parameter_box(HXParams(alpha=True))
        with self.assertRaisesRegex(ValueError, 'exactly representable'):
            parameter_box(HXParams(r=Fraction(2, 25)))
        with self.assertRaises(TypeError):
            boundary_domain_enclosure(None)
        with self.assertRaises(ValueError):
            evaluate_local_mixed_precision(.001, HXParams(), relative_tolerance=float('nan'))


if __name__ == '__main__':
    unittest.main()
