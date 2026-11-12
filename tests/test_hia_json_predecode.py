"""Actual HIA verifier predecode admission; complete checkout required."""
from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from hepta.hia_program import HIAProgramRejected, _decode, verify_program


def empty_core(version=6):
    return {"schema": f"hepta.hia.program.v{version}", "module": "admission",
            "functions": [{"name": "run", "params": [], "returns": [],
                           "effects": [], "entry": "entry",
                           "blocks": [{"id": "entry", "params": [], "ops": [],
                                       "term": {"op": "ret", "values": []}}]}]}


class HIAJSONBeforeDecodeTests(unittest.TestCase):
    def test_existing_program_versions_still_admitted(self):
        for version in range(1, 7):
            with self.subTest(version=version):
                core = empty_core(version)
                first = verify_program(core)
                raw = json.dumps(core, separators=(",", ":")).encode("utf-8")
                self.assertEqual(first.sha256, verify_program(raw).sha256)
                self.assertEqual(first.as_dict(), core)

    def test_early_oversized_structure_refuses_before_stdlib_full_parse(self):
        dense = '[' + ','.join('0' for _ in range(262145)) + ']'
        # No object keys exist in this input, so the preflight performs zero
        # per-key scalar json.loads calls. Any json.loads call would mean the
        # huge array was materialized before the budget was enforced.
        with patch('hepta.hia_program.json.loads', side_effect=AssertionError('premature materialization')) as loaded:
            with self.assertRaises(HIAProgramRejected) as rejected:
                verify_program(dense)
            self.assertEqual(rejected.exception.code, 'E_HIA_LIMIT')
            loaded.assert_not_called()

    def test_exact_depth_and_node_boundaries_remain_consistent(self):
        _decode('[' * 64 + '0' + ']' * 64)
        with self.assertRaises(HIAProgramRejected) as deep:
            _decode('[' * 65 + '0' + ']' * 65)
        self.assertEqual(deep.exception.code, 'E_HIA_LIMIT')
        _decode('[' + ','.join('0' for _ in range(262143)) + ']')
        with self.assertRaises(HIAProgramRejected) as many:
            _decode('[' + ','.join('0' for _ in range(262144)) + ']')
        self.assertEqual(many.exception.code, 'E_HIA_LIMIT')

    def test_duplicate_escaped_key_refuses_without_accepting_claims(self):
        doubled = '{"schema":"hepta.hia.program.v6","\\u0073chema":"forged"}'
        with self.assertRaises(HIAProgramRejected) as duplicate:
            verify_program(doubled)
        self.assertEqual(duplicate.exception.code, 'E_HIA_FORMAT')


if __name__ == '__main__':
    unittest.main()
