"""Agent HIA interface policy: no unapproved ABI/effect changes.

Exercises the real standalone verifier, not an Agent mock. A whole-module
SSA/borrow check does not itself authorize a public API migration.
"""
from __future__ import annotations

from copy import deepcopy
import unittest

from hepta.hia_program import verify_program
from hepta.hia_program_runtime import execute_program
from hepta.hia_program_tools import HIAEditRejected, apply_program_patch


def core():
    params = [{"name": "x", "type": "u32"}]
    return {"schema": "hepta.hia.program.v1", "module": "contract", "functions": [{
        "name": "increment", "params": params, "returns": ["u32"], "effects": ["trap"],
        "entry": "entry", "blocks": [{"id": "entry", "params": params, "ops": [
            {"op": "const", "args": [], "out": [{"name": "one", "type": "u32"}],
             "attrs": {"value": 1}},
            {"op": "int.add.checked", "args": ["x", "one"],
             "out": [{"name": "result", "type": "u32"}], "attrs": {}},
        ], "term": {"op": "ret", "values": ["result"]}}]}]}


def request(program, edits, *, schema="hepta.hia.patch.v1", policy=None):
    payload = {"schema": schema, "expected_sha256": verify_program(program).sha256,
               "edits": edits}
    if policy is not None:
        payload["interface_policy"] = policy
    return payload


def replacement(program, fn):
    return [{"action": "replace_function", "function": "increment", "definition": fn}]


def add_function(program):
    second = deepcopy(program["functions"][0])
    second["name"] = "increment2"
    return [{"action": "add_function", "function": "increment2", "definition": second}]


class HIAInterfacePolicyTests(unittest.TestCase):
    def test_v1_keeps_prior_verified_body_patches(self):
        original = core()
        op = deepcopy(original["functions"][0]["blocks"][0]["ops"][0])
        op["attrs"]["value"] = 2
        edit = [{"action": "replace_operation", "function": "increment",
                 "block": "entry", "index": 0, "operation": op}]
        result, receipt = apply_program_patch(original, request(original, edit))
        self.assertEqual(receipt["schema"], "hepta.hia.patch-result.v1")
        self.assertEqual(receipt["interface_changes"], [])
        self.assertEqual(execute_program(result, "increment", [40])["result"], 42)

    def test_v2_preserve_accepts_body_change_and_reports_no_interface_drift(self):
        original = core()
        op = deepcopy(original["functions"][0]["blocks"][0]["ops"][0])
        op["attrs"]["value"] = 2
        edits = [{"action": "replace_operation", "function": "increment",
                  "block": "entry", "index": 0, "operation": op}]
        changed, receipt = apply_program_patch(original, request(
            original, edits, schema="hepta.hia.patch.v2", policy="preserve"))
        self.assertEqual(receipt["schema"], "hepta.hia.patch-result.v2")
        self.assertEqual(receipt["interface_policy"], "preserve")
        self.assertTrue(receipt["claims"]["interface_preserved"])
        self.assertFalse(receipt["claims"]["external_callers_revalidated"])
        self.assertEqual(receipt["interface_changes"], [])
        self.assertEqual(execute_program(changed, "increment", [40])["result"], 42)

    def test_implicit_v1_and_explicit_v2_preserve_reject_broadened_effects(self):
        original = core()
        changed = deepcopy(original["functions"][0])
        changed["effects"] = ["trap", "read"]  # valid overapproximation, but ABI contract changed
        self.assertTrue(verify_program({**original, "functions": [changed]}))
        edits = replacement(original, changed)
        for schema, policy in (
            ("hepta.hia.patch.v1", None),
            ("hepta.hia.patch.v2", "preserve"),
        ):
            with self.subTest(schema=schema):
                with self.assertRaisesRegex(HIAEditRejected, "interface change"):
                    apply_program_patch(original, request(original, edits, schema=schema, policy=policy))

    def test_explicit_migrate_is_source_bound_and_discloses_external_callers(self):
        original = core()
        changed = deepcopy(original["functions"][0])
        changed["effects"] = ["trap", "read"]
        edits = replacement(original, changed)
        patched, receipt = apply_program_patch(
            original, request(original, edits, schema="hepta.hia.patch.v2", policy="migrate"))
        self.assertEqual(receipt["schema"], "hepta.hia.patch-result.v2")
        self.assertEqual(receipt["interface_policy"], "migrate")
        self.assertEqual(receipt["interface_changes"], ["increment"])
        self.assertFalse(receipt["claims"]["interface_preserved"])
        self.assertFalse(receipt["claims"]["external_callers_revalidated"])
        self.assertFalse(receipt["claims"]["behavior_equivalence_proved"])
        self.assertEqual(execute_program(patched, "increment", [40])["result"], 41)
        with self.assertRaisesRegex(HIAEditRejected, "stale"):
            apply_program_patch(patched, request(original, edits,
                                   schema="hepta.hia.patch.v2", policy="migrate"))

    def test_new_export_needs_v2_explicit_migrate(self):
        original = core()
        edits = add_function(original)
        with self.assertRaisesRegex(HIAEditRejected, "interface change"):
            apply_program_patch(original, request(original, edits))
        result, report = apply_program_patch(original, request(
            original, edits, schema="hepta.hia.patch.v2", policy="migrate"))
        self.assertEqual(report["interface_changes"], ["increment2"])
        self.assertEqual(execute_program(result, "increment2", [6])["result"], 7)

    def test_return_signature_requires_explicit_migrate(self):
        original = core()
        changed = deepcopy(original["functions"][0])
        changed["returns"] = []
        changed["blocks"][0]["term"]["values"] = []
        edits = replacement(original, changed)
        with self.assertRaisesRegex(HIAEditRejected, "interface change"):
            apply_program_patch(original, request(original, edits))
        result, report = apply_program_patch(original, request(
            original, edits, schema="hepta.hia.patch.v2", policy="migrate"))
        self.assertEqual(report["interface_changes"], ["increment"])
        self.assertEqual(execute_program(result, "increment", [4])["values"], [])

    def test_v2_fail_closed_schema_and_policy_type(self):
        original = core()
        op = deepcopy(original["functions"][0]["blocks"][0]["ops"][0])
        op["attrs"]["value"] = 2
        edits = [{"action": "replace_operation", "function": "increment",
                  "block": "entry", "index": 0, "operation": op}]
        for policy in (None, True, 1, ["migrate"], "Migrate", "unknown"):
            with self.subTest(policy=policy):
                packet = request(original, edits, schema="hepta.hia.patch.v2")
                if policy is not None:
                    packet["interface_policy"] = policy
                with self.assertRaisesRegex(HIAEditRejected, "policy|exactly"):
                    apply_program_patch(original, packet)
        packet = request(original, edits, schema="hepta.hia.patch.v1", policy="migrate")
        with self.assertRaisesRegex(HIAEditRejected, "exactly"):
            apply_program_patch(original, packet)


if __name__ == "__main__":
    unittest.main()
