"""Stand-alone JSON admission tests; no Clang/Rust/CI dependency."""
from __future__ import annotations

import json
import random
import unittest
from unittest.mock import patch

from hepta.hia_json_preflight import preflight_hia_json


class HIAPreflightTests(unittest.TestCase):
    def admit(self, text, *, nodes=262144, depth=64):
        preflight_hia_json(text, max_nodes=nodes, max_depth=depth)

    def test_valid_json_and_scalar_shape_coverage(self):
        examples = [
            '{}', '[]', 'null', 'false', 'true', '0', '-1',
            '{"\\u0061": [true, null, {"x": -42}]}',
            ' { "literal": "bracket [ } , \\\" test", "escaped": "\\\\u0041" } ',
            json.dumps({'schema': 'hepta.hia.program.v6', 'module': 'm',
                        'functions': [{'name': 'f', 'params': [], 'returns': [],
                                      'effects': [], 'entry': 'entry',
                                      'blocks': [{'id': 'entry', 'params': [],
                                                  'ops': [], 'term': {'op': 'ret', 'values': []}}]}]}),
        ]
        for value in examples:
            with self.subTest(value=value[:50]):
                self.admit(value)
                json.loads(value)

    def test_early_node_limit_refuses_before_any_full_json_load(self):
        dense = '[' + ','.join('0' for _ in range(262145)) + ']'
        with patch('hepta.hia_json_preflight.json.loads', side_effect=AssertionError('full decode occurred')) as loads:
            with self.assertRaisesRegex(OverflowError, 'node/depth budget'):
                self.admit(dense)
            loads.assert_not_called()
        self.admit('[' + ','.join('0' for _ in range(262143)) + ']')

    def test_depth_limit_exactly_matches_root_zero_valuation(self):
        self.admit('[' * 64 + '0' + ']' * 64)
        with self.assertRaises(OverflowError):
            self.admit('[' * 65 + '0' + ']' * 65)
        with self.assertRaises(OverflowError):
            self.admit('{"a":' * 65 + '0' + '}' * 65)

    def test_early_duplicate_decoded_keys(self):
        for text in ('{"a":1,"a":2}', '{"a":1,"\\u0061":2}',
                     '{"x":1,"x":' + '[' + ','.join('1' for _ in range(40000)) + ']}'):
            with self.subTest(text=text[:60]), self.assertRaisesRegex(ValueError, 'duplicate'):
                self.admit(text)

    def test_invalid_grammar_and_float_rejection(self):
        for text in ('', '{', '[', '[1,]', '{"k":1,}', '[,]',
                     '{"k" 1}', '01', '-01', '-0.5', '1e2', 'NaN',
                     'Infinity', '{"a": 1, "b": }', '[] []',
                     '"\\z"', '"\\uG001"', '"unterminated',
                     '"\x00"', '{"a":true} garbage'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                self.admit(text)

    def test_randomized_grammar_and_budget_equivalence_to_stdlib(self):
        rng = random.Random(1776)
        def value(depth=0):
            if depth < 6 and rng.randrange(3):
                if rng.randrange(2):
                    return [value(depth + 1) for _ in range(rng.randrange(5))]
                return {f'k{index}': value(depth + 1) for index in range(rng.randrange(5))}
            return rng.choice([None, False, True, rng.randrange(-100, 100), 'x}[],\\"'])
        for _ in range(2000):
            obj = value()
            text = json.dumps(obj, ensure_ascii=False)
            self.admit(text)
            self.assertEqual(json.loads(text), obj)
        with self.assertRaises(ValueError):
            self.admit(0)
        with self.assertRaises(ValueError):
            self.admit('[]', nodes=True)


if __name__ == '__main__':
    unittest.main()
