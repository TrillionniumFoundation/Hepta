"""Agent Patch v1/v2 policy applied to the independently verified HIA v3 Core.

No additional patch authority: the existing whole-module verifier decides.
"""
from __future__ import annotations

from copy import deepcopy
import unittest

from hepta.hia_program import HIAProgramRejected, SCHEMA_V3, verify_program
from hepta.hia_program_runtime import execute_program
from hepta.hia_program_tools import HIAEditRejected, apply_program_patch
from tests.test_hia_overlap_v3 import overlap_program, ins


def request(program, edits, policy="preserve", schema="hepta.hia.patch.v2"):
    packet = {"schema": schema, "expected_sha256": verify_program(program).sha256,
              "edits": edits}
    if schema == "hepta.hia.patch.v2":
        packet["interface_policy"] = policy
    return packet


def move_index(program):
    operations = program["functions"][0]["blocks"][0]["ops"]
    return next(i for i, operation in enumerate(operations)
                if operation["op"] == "buffer.move_within")


class HIAAgentOverlapV3Tests(unittest.TestCase):
    def test_version_three_body_patch_keeps_schema_and_interface(self):
        original = overlap_program()
        operations = original["functions"][0]["blocks"][0]["ops"]
        modified = deepcopy(operations[4])
        self.assertEqual(modified["op"], "const")
        modified["attrs"]["value"] = 99
        edits = [{"action": "replace_operation", "function": "move_bytes",
                  "block": "entry", "index": 4, "operation": modified}]
        before = execute_program(original, "move_bytes", [0, 0, 0, 0])
        changed, receipt = apply_program_patch(original, request(original, edits))
        self.assertEqual(changed.as_dict()["schema"], SCHEMA_V3)
        self.assertEqual(receipt["schema"], "hepta.hia.patch-result.v2")
        self.assertEqual(receipt["status"], "verified_unpublished")
        self.assertTrue(receipt["claims"]["interface_preserved"])
        self.assertFalse(receipt["claims"]["external_callers_revalidated"])
        self.assertFalse(receipt["claims"]["behavior_equivalence_proved"])
        self.assertEqual(before["result"], 11)
        self.assertEqual(execute_program(changed, "move_bytes", [0, 0, 0, 0])["result"], 99)
        with self.assertRaisesRegex(HIAEditRejected, "stale"):
            apply_program_patch(changed, request(original, edits))

    def test_migrate_cannot_waive_unique_borrow_or_usize_types(self):
        original = overlap_program()
        idx = move_index(original)
        for unsafe in (
            ins("buffer.move_within", ["owner", "dst", "src", "count"]),
            ins("buffer.move_within", ["writer", "dst", "src", "v0"]),
        ):
            edit = {"action": "replace_operation", "function": "move_bytes",
                    "block": "entry", "index": idx, "operation": unsafe}
            with self.subTest(operation=unsafe["args"]), self.assertRaises(HIAProgramRejected):
                apply_program_patch(original, request(original, [edit], "migrate"))

    def test_return_interface_change_needs_explicit_migration(self):
        original = overlap_program()
        revised = deepcopy(original["functions"][0])
        revised["returns"] = []
        revised["blocks"][0]["term"]["values"] = []
        edits = [{"action": "replace_function", "function": "move_bytes",
                  "definition": revised}]
        with self.assertRaisesRegex(HIAEditRejected, "interface change"):
            apply_program_patch(original, request(original, edits, "preserve"))
        changed, receipt = apply_program_patch(original, request(original, edits, "migrate"))
        self.assertEqual(changed.as_dict()["schema"], SCHEMA_V3)
        self.assertEqual(receipt["interface_changes"], ["move_bytes"])
        self.assertFalse(receipt["claims"]["interface_preserved"])
        self.assertFalse(receipt["claims"]["external_callers_revalidated"])
        self.assertEqual(execute_program(changed, "move_bytes", [0, 0, 0, 0])["values"], [])

    def test_policy_cannot_authorize_missing_memmove_effect(self):
        original = overlap_program()
        revised = deepcopy(original["functions"][0])
        revised["effects"].remove("write")
        edit = {"action": "replace_function", "function": "move_bytes",
                "definition": revised}
        with self.assertRaisesRegex(HIAProgramRejected, "E_HIA_EFFECT"):
            apply_program_patch(original, request(original, [edit], "migrate"))

    def test_legacy_patch_does_not_change_core_schema(self):
        original = overlap_program()
        operation = deepcopy(original["functions"][0]["blocks"][0]["ops"][4])
        operation["attrs"]["value"] = 89
        edit = {"action": "replace_operation", "function": "move_bytes",
                "block": "entry", "index": 4, "operation": operation}
        changed, receipt = apply_program_patch(
            original, request(original, [edit], schema="hepta.hia.patch.v1"))
        self.assertEqual(changed.as_dict()["schema"], SCHEMA_V3)
        self.assertEqual(receipt["schema"], "hepta.hia.patch-result.v1")
        forged = request(original, [edit])
        forged["schema"] = SCHEMA_V3
        with self.assertRaisesRegex(HIAEditRejected, "unsupported patch schema"):
            apply_program_patch(original, forged)


if __name__ == "__main__":
    unittest.main()
