"""Cross-line HIA v2 bulk memory and explicit Agent interface migration policy.

The patch proposal never waives standalone semantic verification.
"""
from __future__ import annotations

from copy import deepcopy
import unittest

from hepta.hia_program import HIAProgramRejected, verify_program
from hepta.hia_program_runtime import execute_program
from hepta.hia_program_tools import HIAEditRejected, apply_program_patch
from tests.test_hia_bulk_memory import bulk_program, ins


def packet(program, edits, policy="preserve"):
    return {"schema": "hepta.hia.patch.v2",
            "expected_sha256": verify_program(program).sha256,
            "interface_policy": policy, "edits": edits}


class HIAAgentBulkIntegrationTests(unittest.TestCase):
    def test_v2_semantic_body_patch_preserves_interface_without_equivalence_claim(self):
        original = bulk_program()
        before = execute_program(original, "bulk", [2, 1, 73])
        op = ins("const", out=[("zero", "usize")], value=1)
        edits = [{"action": "replace_operation", "function": "bulk",
                  "block": "entry", "index": 11, "operation": op}]
        patched, receipt = apply_program_patch(original, packet(original, edits))
        self.assertEqual(receipt["schema"], "hepta.hia.patch-result.v2")
        self.assertTrue(receipt["claims"]["whole_module_rechecked"])
        self.assertTrue(receipt["claims"]["interface_preserved"])
        self.assertFalse(receipt["claims"]["behavior_equivalence_proved"])
        self.assertFalse(receipt["claims"]["external_callers_revalidated"])
        self.assertEqual(before["result"], 73)
        self.assertEqual(execute_program(patched, "bulk", [2, 1, 73])["result"], 0)
        self.assertEqual(patched.as_dict()["schema"], "hepta.hia.program.v2")
        with self.assertRaisesRegex(HIAEditRejected, "stale"):
            apply_program_patch(patched, packet(original, edits))

    def test_signature_change_needs_explicit_migration(self):
        original = bulk_program()
        changed = deepcopy(original["functions"][0])
        changed["returns"] = []
        changed["blocks"][0]["term"]["values"] = []
        edits = [{"action": "replace_function", "function": "bulk",
                  "definition": changed}]
        with self.assertRaisesRegex(HIAEditRejected, "interface change"):
            apply_program_patch(original, packet(original, edits, "preserve"))
        migrated, receipt = apply_program_patch(original, packet(original, edits, "migrate"))
        self.assertEqual(receipt["interface_changes"], ["bulk"])
        self.assertFalse(receipt["claims"]["interface_preserved"])
        self.assertFalse(receipt["claims"]["external_callers_revalidated"])
        self.assertEqual(execute_program(migrated, "bulk", [2, 1, 73])["values"], [])

    def test_migrate_policy_cannot_authorize_invalid_borrowed_copy(self):
        original = bulk_program()
        op = ins("buffer.copy", ["target", "target", "count"])
        edits = [{"action": "replace_operation", "function": "bulk",
                  "block": "entry", "index": 7, "operation": op}]
        with self.assertRaises(HIAProgramRejected):
            apply_program_patch(original, packet(original, edits, "migrate"))


if __name__ == "__main__":
    unittest.main()
