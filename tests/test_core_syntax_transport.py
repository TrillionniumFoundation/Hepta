"""Restricted transport controls, not Lean kernel acceptance or Core refinement.

These tests exercise only inert Python transport preparation. They do not run
Lean, native execution, installation, publication or production admission.
"""
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from hepta.hia_program import verify_program
from hepta.hia_program_source import lower_source
from hepta.hia_reduction import propose_reduction_pipeline
from tools.experimental_deferred_guard_proposer import propose_deferred_guard
from tools import check_core_syntax_lean as transport


ROOT = Path(__file__).resolve().parents[1]
MAX_BYTES = 32768
MAX_NODES = 4096
MAX_DEPTH = 32
MAX_SOURCE = 2 * 1024 * 1024


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode('utf-8')


class CoreSyntaxCanonicalTests(unittest.TestCase):
    def test_complete_real_candidates_roundtrip_without_projection(self):
        fixtures = {
            'linear': (14466, 'c7b8b9ef7619700fd9c5ec0dedb06fbf7ecc801563813b6cb7abaf7e08a467d3'),
            'affine': (15228, '91f11c6cf67610dc0682640d0c24cbd2572a0fcbdea25fdf94ff7671cf1cc861'),
        }
        for workload, (size, digest) in fixtures.items():
            with self.subTest(workload=workload):
                base = lower_source((ROOT / 'benchmarks/hia_reduction_release' /
                                     (workload + '.hepta')).read_text())
                proposal = propose_reduction_pipeline(base, include_induction=True)
                candidate = propose_deferred_guard(base, proposal)['candidate_core']
                checked = verify_program(candidate)
                raw = checked.canonical_bytes
                self.assertEqual(len(raw), size)
                self.assertEqual(sha256(raw).hexdigest(), digest)
                decoded = transport.strict_canonical(raw)
                self.assertEqual(decoded, checked.as_dict())
                self.assertEqual(canonical(decoded), raw)
                self.assertEqual(transport.render_raw(decoded),
                                 transport.render_raw(deepcopy(decoded)))

    def test_allowed_domain_preserves_empty_containers_order_and_ascii(self):
        value = {'a': [], 'b': {}, 'c': [0, 1, 255, 2**64 - 1],
                 'd': ''.join(chr(n) for n in range(32, 127) if n not in (34, 92))}
        self.assertEqual(transport.strict_canonical(canonical(value)), value)
        self.assertEqual(transport.strict_canonical(b'[2,1,0]'), [2, 1, 0])

    def test_duplicate_object_keys_reject_before_json_collapses_them(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":1,"a":1}',
                    b'{"a":{"b":0,"b":1}}', b'[{"a":[],"a":[]}]'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                transport.strict_canonical(raw)

    def test_noncanonical_original_bytes_are_not_normalized(self):
        for raw in (b' {"a":1}', b'{"a":1}\n', b'{ "a":1}', b'{"a": 1}',
                    b'{"b":0,"a":1}', b'{"a":{"c":0,"b":1}}',
                    b'[01]', b'[+1]', b'[-0]', b'[1e0]', b'[1.0]',
                    b'[0.0]', b'[1E+0]', b'[] []', b'\xef\xbb\xbf[]'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                transport.strict_canonical(raw)

    def test_unsupported_json_values_and_string_encodings_reject(self):
        for raw in (b'[-1]', b'[true]', b'[false]', b'[null]', b'[NaN]',
                    b'[Infinity]', b'[-Infinity]', b'["\\u0061"]',
                    b'["\\u00e9"]', '["é"]'.encode(), b'["\\n"]',
                    b'["\\\""]', b'["\\\\"]', b'["\\/"]', b'["\x1f"]',
                    b'["\x7f"]', b'["\xff"]', b'{"\\u0061":0}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                transport.strict_canonical(raw)

    def test_input_byte_budget_is_exact(self):
        accepted = b'["' + b'a' * (MAX_BYTES - 4) + b'"]'
        self.assertEqual(len(accepted), MAX_BYTES)
        self.assertEqual(transport.strict_canonical(accepted), ['a' * (MAX_BYTES - 4)])
        with self.assertRaises(ValueError):
            transport.strict_canonical(accepted[:-2] + b'a"]')

    def test_value_node_budget_counts_containers_and_values(self):
        accepted = [0] * (MAX_NODES - 1)
        self.assertEqual(transport.strict_canonical(canonical(accepted)), accepted)
        with self.assertRaises(ValueError):
            transport.strict_canonical(canonical(accepted + [0]))
        # A small byte count does not bypass the independent node budget.
        with self.assertRaises(ValueError):
            transport.strict_canonical(canonical([[] for _ in range(MAX_NODES)]))

    def test_excessive_depth_is_rejected_without_python_recursion_failure(self):
        for depth in (MAX_DEPTH + 2, 1000):
            with self.subTest(depth=depth), self.assertRaises(ValueError):
                transport.strict_canonical(b'[' * depth + b'0' + b']' * depth)

    def test_exact_depth_boundary_counts_root_and_leaf(self):
        accepted = b'[' * (MAX_DEPTH - 1) + b'0' + b']' * (MAX_DEPTH - 1)
        self.assertEqual(canonical(transport.strict_canonical(accepted)), accepted)
        with self.assertRaises(ValueError):
            transport.strict_canonical(b'[' + accepted + b']')

    def test_integer_boundary_is_finite_and_decimal(self):
        self.assertEqual(transport.strict_canonical(canonical([2**64 - 1])), [2**64 - 1])
        for raw in (canonical([2**64]), b'[' + b'9' * 4000 + b']'):
            with self.subTest(size=len(raw)), self.assertRaises(ValueError):
                transport.strict_canonical(raw)

    def test_nonbytes_input_is_not_coerced(self):
        for raw in ('[]', bytearray(b'[]'), memoryview(b'[]'), [], None):
            with self.subTest(kind=type(raw).__name__), self.assertRaises(ValueError):
                transport.strict_canonical(raw)


class CoreSyntaxRendererTests(unittest.TestCase):
    def test_raw_tree_uses_inert_constructors_and_numeric_string_bytes(self):
        value = {'a': [0, 'Z'], 'b': {}}
        self.assertEqual(transport.render_raw(value),
                         '(.obj [([97],(.arr [(.num 0),(.str [90])])),([98],(.obj []))])')
        # Lean-looking ASCII content remains a byte list, never source text.
        rendered = transport.render_raw(['axiom bad : False'])
        self.assertNotIn('axiom', rendered)
        self.assertEqual(rendered, '(.arr [(.str [97,120,105,111,109,32,98,97,100,32,58,32,70,97,108,115,101])])')

    def test_raw_renderer_rejects_unsupported_python_types_recursively(self):
        for bad in (True, False, None, -1, 1.0, float('nan'), float('inf'),
                    b'abc', bytearray(b'abc'), (1,), {1}, object(), {0: 'value'},
                    {0: 0, 'a': 0}, 2**64):
            for value in (bad, [bad], {'a': bad}):
                with self.subTest(kind=type(bad).__name__), self.assertRaises(ValueError):
                    transport.render_raw(value)

    def test_raw_renderer_rejects_quoted_backslashed_unicode_control_injection(self):
        for bad in ('"; axiom injected : False --', '\\', '\n', '\x00', '\x7f', 'é', '\ud800'):
            for value in ([bad], {bad: 0}):
                with self.subTest(value=repr(value)), self.assertRaises(ValueError):
                    transport.render_raw(value)

    def test_raw_renderer_applies_transport_budgets_without_prior_parser(self):
        deep = 0
        for _ in range(MAX_DEPTH + 2):
            deep = [deep]
        cycle = []
        cycle.append(cycle)
        for value in ([0] * MAX_NODES, ['a' * MAX_BYTES], deep, cycle):
            with self.subTest(kind=type(value).__name__), self.assertRaises(ValueError):
                transport.render_raw(value)

    def test_direct_large_trees_reject_before_literal_generation(self):
        cases = ([0] * (MAX_NODES * 2), ['a' * 1024] * 33,
                 {'a' * 16384: 0, 'b' * 16384: 0},
                 ['a' * 1024] * 32)
        for value in cases:
            with self.subTest(size=len(value)):
                with patch.object(transport, 'render_bytes',
                                  side_effect=AssertionError('literal generation started')) as render:
                    with self.assertRaises(ValueError):
                        transport.render_raw(value)
                render.assert_not_called()

    def test_raw_renderer_rejects_unsorted_keys_instead_of_sorting(self):
        for value in ({'z': 0, 'a': 0}, [{'a': {'z': 0, 'a': 0}}]):
            with self.subTest(value=value), self.assertRaises(ValueError):
                transport.render_raw(value)

    def test_raw_renderer_obeys_generated_source_budget(self):
        with patch.object(transport, 'MAX_PROOF_BYTES', 12):
            with self.assertRaises(ValueError):
                transport.render_raw(['safe string'])

    def test_byte_literal_budget_is_checked_separately(self):
        self.assertEqual(json.loads(transport.render_bytes(bytes(MAX_BYTES))), [0] * MAX_BYTES)
        with self.assertRaises(ValueError):
            transport.render_bytes(bytes(MAX_BYTES + 1))
        for value in ('0', bytearray(b'0'), iter([0])):
            with self.subTest(kind=type(value).__name__), self.assertRaises(ValueError):
                transport.render_bytes(value)

    def test_byte_literals_are_exact_nat_lists_including_255(self):
        for values in ([], [0], [0, 1, 127, 128, 255], bytes(range(256))):
            rendered = transport.render_bytes(values)
            self.assertRegex(rendered, r'^\[\s*(?:[0-9]+\s*(?:,\s*[0-9]+\s*)*)?\]$')
            self.assertEqual(json.loads(rendered), list(values))

    def test_byte_literals_reject_coercible_or_out_of_range_values(self):
        for bad in (True, False, 0.0, 255.0, -1, 256, 2**64, '0', None):
            with self.subTest(value=bad), self.assertRaises(ValueError):
                transport.render_bytes([0, bad, 255])

    def test_source_budget_is_inclusive_and_checks_total_not_only_parts(self):
        self.assertEqual(transport.checked_source([]), '')
        self.assertEqual(transport.checked_source(['a', 'b']), 'ab')
        parts = ['a' * (MAX_SOURCE // 2), 'b' * (MAX_SOURCE // 2)]
        self.assertEqual(transport.checked_source(iter(parts)), ''.join(parts))
        with self.assertRaises(ValueError):
            transport.checked_source(iter(parts + ['c']))
        with self.assertRaises(ValueError):
            transport.checked_source(['a' * (MAX_SOURCE + 1)])

    def test_source_budget_counts_utf8_bytes_and_rejects_nontext(self):
        with patch.object(transport, 'MAX_PROOF_BYTES', 4):
            self.assertEqual(transport.checked_source(['é', 'é']), 'éé')
            with self.assertRaises(ValueError):
                transport.checked_source(['é', 'é', 'a'])
        for part in (None, 1, b'a'):
            with self.subTest(kind=type(part).__name__), self.assertRaises(ValueError):
                transport.checked_source(['valid', part])

    def test_source_budget_stops_consuming_as_soon_as_it_is_exceeded(self):
        def parts():
            yield 'a' * MAX_SOURCE
            yield 'b'
            self.fail('proof source iterator consumed beyond exceeded budget')
        with self.assertRaises(ValueError):
            transport.checked_source(parts())


if __name__ == '__main__':
    unittest.main()
