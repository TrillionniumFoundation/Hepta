"""P7 pre-decode quotas apply to the actual integrated HIA v7 Core."""
from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from hepta.hia_program import _decode, HIAProgramRejected, verify_program


def scalar_v7():
    return {
        "schema": "hepta.hia.program.v7",
        "module": "predecode_v7",
        "functions": [{
            "name": "run", "params": [], "returns": [], "effects": [],
            "entry": "entry", "blocks": [{
                "id": "entry", "params": [], "ops": [],
                "term": {"op": "ret", "values": []},
            }],
        }],
    }


class V7JSONPredecodeTests(unittest.TestCase):
    def test_actual_v7_verifier_preserves_valid_canonical_identity(self):
        source = scalar_v7()
        raw = json.dumps(source, sort_keys=True, separators=(",", ":")).encode("utf-8")
        self.assertEqual(verify_program(source).sha256, verify_program(raw).sha256)
        self.assertEqual(verify_program(raw).as_dict(), source)

    def test_composite_v2_wire_is_not_reclassified_by_the_preflight(self):
        # This only exercises _decode. Full nominal elaboration remains a
        # separate semantic responsibility of verify_program.
        composite = {
            "schema": "hepta.hia.composite.v2",
            "module": "wire",
            "types": [], "functions": [],
        }
        parsed, _ = _decode(json.dumps(composite))
        self.assertEqual(parsed, composite)

    def test_dense_json_is_rejected_before_full_document_materialization(self):
        dense = "[" + ",".join("0" for _ in range(262145)) + "]"
        with patch("hepta.hia_program.json.loads", side_effect=AssertionError("full parse occurred")) as loads:
            with self.assertRaises(HIAProgramRejected) as rejected:
                verify_program(dense)
            self.assertEqual(rejected.exception.code, "E_HIA_LIMIT")
            loads.assert_not_called()

    def test_depth_violation_is_limit_not_format_success(self):
        with self.assertRaises(HIAProgramRejected) as rejected:
            _decode("[" * 65 + "0" + "]" * 65)
        self.assertEqual(rejected.exception.code, "E_HIA_LIMIT")

    def test_unicode_equivalent_duplicate_keys_reject_without_claims(self):
        with self.assertRaises(HIAProgramRejected) as rejected:
            _decode('{"schema":"hepta.hia.program.v7","\\u0073chema":"forged"}')
        self.assertEqual(rejected.exception.code, "E_HIA_FORMAT")


if __name__ == "__main__":
    unittest.main()
