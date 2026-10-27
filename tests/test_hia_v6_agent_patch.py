"""v6 Agent edits preserve the single verified program and reject unsafe ranges."""
from __future__ import annotations

from copy import deepcopy
import unittest
from unittest.mock import patch

from hepta.hia_patch_impact import HIAImpactRejected, analyze_patch_impact
from hepta.hia_program import HIAProgramRejected, SCHEMA_V6, verify_program
from hepta.hia_program_runtime import execute_program
from tests.test_hia_range_fill_v6 import fill_program, ins


def v6_edit(document, *, invalid=False):
    original = verify_program(document)
    ops = document["functions"][0]["blocks"][0]["ops"]
    index = next(i for i, op in enumerate(ops) if op["op"] == "buffer.fill_range")
    edited = (ins("buffer.fill_range", ["owner", "offset", "count", "value"])
              if invalid else ins("buffer.fill", ["writer", "value"]))
    return {
        "schema": "hepta.hia.patch.v2",
        "expected_sha256": original.sha256,
        "interface_policy": "preserve",
        "edits": [{"action": "replace_operation", "function": "fill_range",
                   "block": "entry", "index": index, "operation": edited}],
    }


class V6AgentPatchTests(unittest.TestCase):
    def test_source_bound_patch_impact_with_v6_native_mem(self):
        source = fill_program()
        request = v6_edit(source)
        candidate, receipt, impact = analyze_patch_impact(source, request)
        self.assertEqual(candidate.as_dict()["schema"], SCHEMA_V6)
        self.assertEqual(impact["direct_changed_functions"], ["fill_range"])
        self.assertEqual(impact["potentially_affected_functions"], ["fill_range"])
        self.assertEqual(impact["interface_changed_functions"], [])
        self.assertEqual(impact["before_sha256"], verify_program(source).sha256)
        self.assertEqual(impact["after_sha256"], candidate.sha256)
        self.assertFalse(impact["claims"]["functional_equivalence_proved"])
        self.assertFalse(receipt["claims"]["external_callers_revalidated"])
        args = [5, 1, 3, 7, 0]
        self.assertEqual(execute_program(source, "fill_range", args)["result"], 0)
        self.assertEqual(execute_program(candidate, "fill_range", args)["result"], 7)

    def test_forged_owner_write_rejected_even_under_preserve_policy(self):
        with self.assertRaises(HIAProgramRejected):
            analyze_patch_impact(fill_program(), v6_edit(fill_program(), invalid=True))

    def test_unsupported_unhashable_claim_receipt_fails_closed(self):
        source = verify_program(fill_program())
        with patch("hepta.hia_patch_impact.apply_program_patch",
                   return_value=(source, {"schema": ["unhashable"]})):
            with self.assertRaisesRegex(HIAImpactRejected, "E_HIA_IMPACT"):
                analyze_patch_impact(source, v6_edit(source.as_dict()))

    def test_true_schema_downgrade_is_forbidden(self):
        candidate = fill_program()
        candidate["schema"] = "hepta.hia.program.v5"
        with self.assertRaisesRegex(HIAProgramRejected, "E_HIA_OPCODE"):
            verify_program(candidate)


if __name__ == "__main__":
    unittest.main()
