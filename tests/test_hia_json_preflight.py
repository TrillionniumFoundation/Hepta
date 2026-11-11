"""Stand-alone JSON admission tests; no Clang/Rust/CI dependency."""
from __future__ import annotations

import json
import os
import random
import unittest
from unittest.mock import patch

from hepta.hia_json_preflight import (_preflight_hia_json_reference,
                                     preflight_hia_json)


class HIAPreflightTests(unittest.TestCase):
    def admit(self, text, *, nodes=262144, depth=64):
        preflight_hia_json(text, max_nodes=nodes, max_depth=depth)

    def assert_syntax_refusal_routes(self, text, reference_reason):
        # The span optimization preserves the independent scanner's exact
        # diagnostic. The selected native ABI separately promises status 1's
        # existing syntax/Unicode diagnostic; it does not encode each English
        # scanner reason. Exercise both routes instead of hiding the selector.
        with self.assertRaises(ValueError) as reference:
            _preflight_hia_json_reference(text, max_nodes=1, max_depth=0)
        self.assertEqual(str(reference.exception),
                         'HIA JSON preflight: ' + reference_reason)
        try:
            wire = text.encode('utf-8')
        except UnicodeEncodeError:
            # These caller-owned strings remain outside the native wire ABI.
            native_wire = False
        else:
            self.assertLessEqual(len(wire), 8388608)
            native_wire = True
        expected = ('invalid JSON syntax or Unicode' if native_wire and
                    os.environ.get('HEPTA_HIA_JSON_PREFLIGHT_MANIFEST') else reference_reason)
        with self.assertRaises(ValueError) as dispatched:
            self.admit(text, nodes=1, depth=0)
        self.assertEqual(str(dispatched.exception), 'HIA JSON preflight: ' + expected)

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

    def test_long_strings_keep_exact_escape_and_unicode_refusals(self):
        prefix = 'ordinary ASCII and Greek Ω and astral 𐐷 ' * 2048
        for suffix in ('"', '\\n"', '\\u0041"', '\\uD800\\uDC00"', '\\\\"', '\\""'):
            with self.subTest(suffix=suffix):
                self.admit('"' + prefix + suffix, nodes=1, depth=0)
        bad_suffixes = (
            ('', 'unterminated JSON string'),
            ('\x1f"', 'unescaped control or isolated Unicode surrogate'),
            ('\ud800"', 'unescaped control or isolated Unicode surrogate'),
            ('\udfff"', 'unescaped control or isolated Unicode surrogate'),
            ('\\', 'unterminated JSON escape'),
            ('\\x"', 'invalid JSON escape'),
            ('\\u00G0"', 'invalid Unicode escape'),
            ('\\uD800"', 'unpaired high Unicode surrogate'),
            ('\\uD800\\u0041"', 'unpaired high Unicode surrogate'),
            ('\\uDC00"', 'unpaired low Unicode surrogate'),
        )
        for suffix, reason in bad_suffixes:
            with self.subTest(suffix=repr(suffix)):
                self.assert_syntax_refusal_routes('"' + prefix + suffix, reason)

    def test_long_spans_preserve_budget_and_duplicate_error_order(self):
        key = 'long-key-Ω' * 4096
        escaped = json.dumps(key, ensure_ascii=True)
        wire = '{' + json.dumps(key, ensure_ascii=False) + ':0,' + escaped + ':"\ud800"}'
        with self.assertRaises(ValueError) as caught:
            self.admit(wire, nodes=2, depth=1)
        self.assertEqual(str(caught.exception),
                         'HIA JSON preflight: duplicate decoded object key')
        wire = '[' + json.dumps(key, ensure_ascii=False) + ',"\ud800"]'
        with self.assertRaises(OverflowError):
            self.admit(wire, nodes=2, depth=1)
        with self.assertRaises(OverflowError):
            self.admit(wire, nodes=3, depth=0)
        with self.assertRaisesRegex(ValueError, 'isolated Unicode surrogate'):
            self.admit(wire, nodes=3, depth=1)

    def test_only_ascii_digits_and_json_whitespace_form_spans(self):
        space = ' \t\r\n' * 4096
        digits = '1234567890' * 4096
        self.admit(space + '-' + digits + space, nodes=1, depth=0)
        for wire, reason in (
            (space + '٠', 'expected JSON integer or literal'),
            (space + '１', 'expected JSON integer or literal'),
            (space + '\u00a0' + '0', 'expected JSON integer or literal'),
            (space + '0' + '\u00a0', 'extra JSON data'),
            (space + digits + '１', 'extra JSON data'),
            (space + '0' + digits, 'extra JSON data'),
            (space + '-' + space + '1', 'expected JSON integer or literal'),
        ):
            with self.subTest(reason=reason):
                self.assert_syntax_refusal_routes(wire, reason)

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
