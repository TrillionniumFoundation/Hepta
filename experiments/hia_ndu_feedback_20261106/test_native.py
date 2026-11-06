"""Exact numeric, intake and native integration controls for live value backups."""
from __future__ import annotations
from hashlib import sha256
import json
import os
from pathlib import Path
import random
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from experiments.hia_ndu_feedback_20261106.native import (
    Q32, LIMIT, NativeValueBackend, ValueBackendError, q32_product,
    normalize_candidates, independent_values,
)

def _hash(value):
    return sha256(value.encode()).hexdigest()

def _row(name, instant=0, continuation=0, discount=Q32, **kw):
    return dict(id=name, instant_q32=instant, terminal_q32=continuation, discount_q32=discount, **kw)

class ExactArithmeticTests(unittest.TestCase):
    def test_ties_even_signed(self):
        self.assertEqual([q32_product(Q32 // 2, n) for n in [-5, -3, -1, 1, 3, 5]], [-2, -2, 0, 0, 2, 2])

    def test_exact_integer_fraction_reference(self):
        from fractions import Fraction
        r = random.Random(73)
        for _ in range(2000):
            a, b = r.randrange(0, Q32 + 1), r.randrange(-LIMIT // 4, LIMIT // 4)
            self.assertEqual(q32_product(a, b), round(Fraction(a * b, Q32)))

    def test_no_projection(self):
        with self.assertRaises(ValueBackendError):
            normalize_candidates([_row('abstain'), _row('clipped', LIMIT, 1)])

    def test_reject_bool_numbers(self):
        for key in ('instant_q32', 'terminal_q32', 'discount_q32', 'resource_q32', 'risk_q32'):
            with self.subTest(key=key), self.assertRaises(ValueBackendError):
                normalize_candidates([_row('abstain'), dict(_row('bad'), **{key: True})])

    def test_reject_duplicates_unknown_fields(self):
        with self.assertRaises(ValueBackendError):
            normalize_candidates([_row('abstain'), _row('abstain')])
        with self.assertRaises(ValueBackendError):
            normalize_candidates([dict(_row('abstain'), future_outcome=1)])

    def test_full_tie_preserved(self):
        got = independent_values([_row('abstain', -10), _row('b', 3), _row('a', 3)])
        self.assertEqual(got['winners'], ['a', 'b'])

    def test_feasibility_risk_resource_constraints(self):
        got = independent_values([_row('abstain'), _row('unsafe', 10, feasible=False),
            _row('risk', 20, risk_q32=Q32), _row('cost', 30, resource_q32=Q32)],
            resource_budget_q32=0, risk_ceiling_q32=0)
        self.assertEqual(got['winners'], ['abstain'])

class NativeIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = os.environ.get('HIA_NDU_VALUE_BINARY')
        cls.manifest = os.environ.get('HIA_NDU_VALUE_MANIFEST')
        if not cls.binary or not cls.manifest:
            raise unittest.SkipTest('set exact native value binary and manifest for native controls')
        cls.output = Path(os.environ.get('HIA_NDU_VALUE_EVIDENCE') or tempfile.mkdtemp(prefix='ndu-value-controls-'))
        cls.output.mkdir(parents=True, exist_ok=True)

    def backend(self, suffix=''):
        return NativeValueBackend(self.binary, self.manifest, log=self.output / (self._testMethodName + suffix + '.jsonl'))

    def evaluate(self, backend, rows, **kw):
        return backend.evaluate(rows, _hash('observed-state'), _hash('numeric-preference'), **kw)

    def test_native_exact_randomized_differential(self):
        randomizer = random.Random(175943)
        with self.backend() as backend:
            for index in range(3000):
                rows = [_row('abstain', -100 * Q32)]
                for action in range(1 + index % 7):
                    rows.append(_row('action-' + str(action), randomizer.randrange(-20 * Q32, 20 * Q32),
                        randomizer.randrange(-20 * Q32, 20 * Q32), randomizer.randrange(Q32 + 1),
                        feasible=randomizer.randrange(10) != 0, risk_q32=randomizer.randrange(Q32 + 1),
                        resource_q32=randomizer.randrange(10 * Q32)))
                budget, risk = randomizer.randrange(10 * Q32), randomizer.randrange(Q32 + 1)
                result = self.evaluate(backend, rows, resource_budget_q32=budget, risk_ceiling_q32=risk)
                expected = independent_values(rows, resource_budget_q32=budget, risk_ceiling_q32=risk)
                self.assertEqual(result['winners'], expected['winners'])
                self.assertEqual(result['values_q32'], expected['values_q32'])
        self.assertEqual(backend.returncode, 0)
        self.assertEqual(backend.calls, 3000)

    def test_preference_digest_is_binding_not_numeric_reward(self):
        rows = [_row('abstain', -100), _row('a', 3), _row('b', 4)]
        with self.backend() as backend:
            first = backend.evaluate(rows, _hash('state'), _hash('pref-1'))
            second = backend.evaluate(rows, _hash('state'), _hash('pref-2'))
        self.assertEqual(first['values_q32'], second['values_q32'])
        self.assertEqual(first['winners'], second['winners'])
        self.assertNotEqual(first['evaluation_digest'], second['evaluation_digest'])

    def test_numeric_preference_reverses_actual_native_winner(self):
        with self.backend() as backend:
            low = self.evaluate(backend, [_row('abstain', -100), _row('fast', 8), _row('frugal', 5)])
            high = backend.evaluate([_row('abstain', -100), _row('fast', 2), _row('frugal', 5)], _hash('changed-state'), _hash('changed-weight'))
        self.assertEqual(low['chosen_id'], 'fast')
        self.assertEqual(high['chosen_id'], 'frugal')

    def test_fractional_continuation_reverses(self):
        with self.backend() as backend:
            now = self.evaluate(backend, [_row('abstain', -100), _row('future', 0, 20, Q32), _row('now', 6)])
            urgent = self.evaluate(backend, [_row('abstain', -100), _row('future', 0, 20, Q32 // 4), _row('now', 6)])
        self.assertEqual(now['chosen_id'], 'future')
        self.assertEqual(urgent['chosen_id'], 'now')

    def test_rejected_actions_remain_in_receipt(self):
        with self.backend() as backend:
            result = self.evaluate(backend, [_row('abstain'), _row('illegal', 100, feasible=False),
                _row('risky', 100, risk_q32=Q32), _row('resource', 100, resource_q32=Q32)],
                resource_budget_q32=0, risk_ceiling_q32=0)
        self.assertEqual(result['chosen_id'], 'abstain')
        self.assertEqual(sorted(r['id'] for r in result['rejected']), ['illegal', 'resource', 'risky'])

    def test_altered_sequence_rejected_and_session_dead(self):
        backend = self.backend()
        original = backend._send
        def altered(raw, deadline):
            request = json.loads(raw)
            request['sequence'] += 1
            changed = json.dumps(request, sort_keys=True, separators=(',', ':')).encode() + b'\n'
            return original(changed, deadline)
        with patch.object(backend, '_send', side_effect=altered):
            with self.assertRaises(ValueBackendError):
                self.evaluate(backend, [_row('abstain')])
        self.assertTrue(backend.closed)
        self.assertEqual(backend.returncode, 2)

    def test_request_hash_corruption_detected(self):
        backend = self.backend()
        original = backend._readline
        def altered(deadline):
            response = json.loads(original(deadline))
            response['request_sha256'] = '0' * 64
            return json.dumps(response, sort_keys=True, separators=(',', ':')).encode()
        with patch.object(backend, '_readline', side_effect=altered):
            with self.assertRaises(ValueBackendError):
                self.evaluate(backend, [_row('abstain')])
        self.assertTrue(backend.closed)

    def test_fake_native_value_detected(self):
        backend = self.backend()
        original = backend._readline
        def altered(deadline):
            response = json.loads(original(deadline))
            response['values_q32']['abstain'] += 1
            return json.dumps(response, sort_keys=True, separators=(',', ':')).encode()
        with patch.object(backend, '_readline', side_effect=altered):
            with self.assertRaises(ValueBackendError):
                self.evaluate(backend, [_row('abstain')])
        self.assertTrue(backend.closed)

    def test_all_ties_not_arbitrarily_dropped(self):
        with self.backend() as backend:
            result = self.evaluate(backend, [_row('abstain', -3), _row('a', 8), _row('b', 8)])
        self.assertEqual(result['winners'], ['a', 'b'])

if __name__ == '__main__':
    unittest.main()
