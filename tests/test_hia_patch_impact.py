"""Agent-facing v3 Core patch impact, without another mutation/verification engine."""
from __future__ import annotations

from copy import deepcopy
import unittest
from unittest.mock import patch

from hepta.hia_patch_impact import HIAImpactRejected, analyze_patch_impact
from hepta.hia_program import HIAProgramRejected, SCHEMA_V3, verify_program
from hepta.hia_program_runtime import execute_program
from hepta.hia_program_tools import HIAEditRejected
from tests.test_hia_overlap_move import ins, move_program, param


def patch_packet(program, edits, policy="preserve"):
    return {"schema": "hepta.hia.patch.v2",
            "expected_sha256": verify_program(program).sha256,
            "interface_policy": policy, "edits": edits}


def append_wrapper(program, name, callee):
    params = [param(k, "usize") for k in
              ("length", "destination", "source", "count", "probe")]
    body = [ins("call", [p["name"] for p in params], [("result", "u8")], function=callee)]
    program["functions"].append({"name": name, "params": params, "returns": ["u8"],
        "effects": ["alloc", "read", "write", "trap"], "entry": "entry",
        "blocks": [{"id": "entry", "params": deepcopy(params), "ops": body,
                    "term": {"op": "ret", "values": ["result"]}}]})


def isolated_program(program):
    fn = {"name": "isolated", "params": [], "returns": ["u8"],
          "effects": [], "entry": "entry",
          "blocks": [{"id": "entry", "params": [],
                      "ops": [ins("const", out=[("seven", "u8")], value=7)],
                      "term": {"op": "ret", "values": ["seven"]}}]}
    program["functions"].append(fn)


def patch_initial_byte(program, byte=99):
    operations = program["functions"][0]["blocks"][0]["ops"]
    index = next(i for i, op in enumerate(operations)
                 if op["op"] == "const" and op["out"] == [param("byte0", "u8")])
    changed = deepcopy(operations[index])
    changed["attrs"]["value"] = byte
    return [{"action": "replace_operation", "function": "move_bytes",
             "block": "entry", "index": index, "operation": changed}]


class HIAPatchImpactTests(unittest.TestCase):
    def test_body_edit_version_and_exact_behavior_nonclaim(self):
        original = move_program()
        changed, receipt, impact = analyze_patch_impact(
            original, patch_packet(original, patch_initial_byte(original)))
        self.assertEqual(changed.as_dict()["schema"], SCHEMA_V3)
        self.assertEqual(impact["schema"], "hepta.hia.patch-impact.v1")
        self.assertEqual(impact["direct_changed_functions"], ["move_bytes"])
        self.assertEqual(impact["potentially_affected_functions"], ["move_bytes"])
        self.assertEqual(impact["interface_changed_functions"], [])
        self.assertTrue(receipt["claims"]["interface_preserved"])
        self.assertFalse(impact["claims"]["functional_equivalence_proved"])
        self.assertFalse(impact["claims"]["external_callers_revalidated"])
        self.assertEqual(execute_program(changed, "move_bytes", [5, 0, 0, 0, 0])["result"], 99)
        self.assertEqual(execute_program(original, "move_bytes", [5, 0, 0, 0, 0])["result"], 11)

    def test_transitive_callers_and_independent_callee_are_scanned(self):
        original = move_program()
        append_wrapper(original, "wrapper", "move_bytes")
        append_wrapper(original, "top", "wrapper")
        isolated_program(original)
        original = verify_program(original)
        candidate, receipt, impact = analyze_patch_impact(
            original, patch_packet(original, patch_initial_byte(original.as_dict())))
        self.assertEqual(impact["direct_changed_functions"], ["move_bytes"])
        self.assertEqual(impact["potentially_affected_functions"],
                         ["move_bytes", "top", "wrapper"])
        self.assertEqual(impact["unaffected_by_static_callgraph"], ["isolated"])
        self.assertEqual(impact["old_call_edges"], impact["new_call_edges"])
        self.assertEqual(len(impact["old_call_edges"]), 2)
        self.assertEqual(execute_program(candidate, "top", [5, 0, 0, 0, 0])["result"], 99)

    def test_before_and_after_callgraph_union_on_changed_callee(self):
        original = move_program()
        append_wrapper(original, "wrapper", "move_bytes")
        # Replace caller with independently returning value; previous caller
        # must still be shown affected because old call graph is reviewed.
        wrapper = deepcopy(original["functions"][1])
        wrapper["blocks"][0]["ops"] = [ins("const", out=[("result", "u8")], value=9)]
        edit = {"action": "replace_function", "function": "wrapper", "definition": wrapper}
        _, _, impact = analyze_patch_impact(original, patch_packet(original, [edit]))
        self.assertEqual(impact["direct_changed_functions"], ["wrapper"])
        self.assertIn({"caller": "wrapper", "callee": "move_bytes"}, impact["old_call_edges"])
        self.assertEqual(impact["new_call_edges"], [])

    def test_interface_migration_still_explicitly_unqualified(self):
        original = move_program()
        changed_fn = deepcopy(original["functions"][0])
        changed_fn["returns"] = []
        changed_fn["blocks"][0]["term"] = {"op": "ret", "values": []}
        edits = [{"action": "replace_function", "function": "move_bytes",
                  "definition": changed_fn}]
        with self.assertRaisesRegex(HIAEditRejected, "interface change"):
            analyze_patch_impact(original, patch_packet(original, edits))
        _, receipt, impact = analyze_patch_impact(original, patch_packet(original, edits, "migrate"))
        self.assertEqual(impact["interface_changed_functions"], ["move_bytes"])
        self.assertEqual(receipt["interface_policy"], "migrate")
        self.assertFalse(impact["claims"]["native_execution_qualified"])

    def test_invalid_owner_loan_patch_never_receives_impact_receipt(self):
        original = move_program()
        operations = original["functions"][0]["blocks"][0]["ops"]
        idx = next(i for i, op in enumerate(operations) if op["op"] == "buffer.move_within")
        invalid = {"action": "replace_operation", "function": "move_bytes", "block": "entry",
                   "index": idx, "operation": ins("buffer.move_within", ["owned", "destination", "source", "count"])}
        with self.assertRaisesRegex(HIAProgramRejected, "E_HIA_TYPE"):
            analyze_patch_impact(original, patch_packet(original, [invalid], "migrate"))

    def test_missing_effect_and_legacy_v1_protection(self):
        original = move_program()
        invalid = deepcopy(original["functions"][0])
        invalid["effects"].remove("write")
        edit = {"action": "replace_function", "function": "move_bytes", "definition": invalid}
        with self.assertRaisesRegex(HIAProgramRejected, "E_HIA_EFFECT"):
            analyze_patch_impact(original, patch_packet(original, [edit], "migrate"))
        legacy = {"schema": "hepta.hia.patch.v1",
                  "expected_sha256": verify_program(original).sha256,
                  "edits": patch_initial_byte(original, 89)}
        checked, receipt, impact = analyze_patch_impact(original, legacy)
        self.assertEqual(checked.as_dict()["schema"], SCHEMA_V3)
        self.assertEqual(receipt["schema"], "hepta.hia.patch-result.v1")
        self.assertEqual(impact["patch_result_schema"], "hepta.hia.patch-result.v1")
        self.assertEqual(execute_program(checked, "move_bytes", [5, 0, 0, 0, 0])["result"], 89)

    def test_read_only_cli_impact_for_v3(self):
        from contextlib import redirect_stdout
        import io
        import json
        from pathlib import Path
        import tempfile
        from hepta.cli import main

        original = move_program()
        request = patch_packet(original, patch_initial_byte(original))
        with tempfile.TemporaryDirectory(prefix="hia-impact-cli-") as root:
            source = Path(root) / "program.hia"
            request_path = Path(root) / "patch.json"
            source.write_text(json.dumps(original), encoding="utf-8")
            request_path.write_text(json.dumps(request), encoding="utf-8")
            with io.StringIO() as stream, redirect_stdout(stream):
                rc = main(["hia", "impact", str(source), "--request", str(request_path)])
                output = json.loads(stream.getvalue())
            self.assertEqual(rc, 0, output)
            self.assertEqual(output["schema"], "hepta.hia.impact-query.v1")
            self.assertEqual(output["status"], "verified_unpublished")
            self.assertEqual(output["impact"]["direct_changed_functions"], ["move_bytes"])
            self.assertFalse(output["impact"]["claims"]["native_execution_qualified"])
            self.assertNotIn("publication", output)
            self.assertEqual(sorted(path.name for path in Path(root).iterdir()),
                             ["patch.json", "program.hia"])

    def test_stale_digest_and_untrusted_receipt_fail_closed(self):
        original = move_program()
        request = patch_packet(original, patch_initial_byte(original))
        stale = deepcopy(request)
        stale["expected_sha256"] = "0" * 64
        with self.assertRaisesRegex(HIAEditRejected, "stale"):
            analyze_patch_impact(original, stale)
        from hepta.hia_program_tools import apply_program_patch as authentic
        for attack in (
            lambda value: value.update(after_sha256="0" * 64),
            lambda value: value["claims"].update(behavior_equivalence_proved=0),
            lambda value: value.update(interface_changes=["unexpected"]),
            lambda value: value["claims"].update(external_callers_revalidated=True),
            lambda value: value["claims"].update(native_execution_proved=True),
            lambda value: value.update(publication={"unreviewed": True}),
            lambda value: value.update(schema=["unhashable"]),
            lambda value: value["claims"].pop("native_executed"),
        ):
            with self.subTest(attack=attack):
                def fake(document, packet):
                    candidate, receipt = authentic(document, packet)
                    receipt = deepcopy(receipt)
                    attack(receipt)
                    return candidate, receipt
                with patch("hepta.hia_patch_impact.apply_program_patch", side_effect=fake):
                    with self.assertRaisesRegex(HIAImpactRejected, "E_HIA_IMPACT"):
                        analyze_patch_impact(original, request)


if __name__ == "__main__":
    unittest.main()
