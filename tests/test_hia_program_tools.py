"""Independent HIA CLI and snapshot patch behaviour, without source/rustc."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from hepta.hia_program import verify_program
from hepta.hia_program_runtime import execute_program
from hepta.hia_program_tools import (HIAEditRejected, apply_program_patch,
                                     decode_json, publish_program, read_bounded)


def scalar_program():
    params = [{"name": "x", "type": "u32"}]
    return {"schema": "hepta.hia.program.v1", "module": "counter", "functions": [{
        "name": "increment", "params": params, "returns": ["u32"], "effects": ["trap"],
        "entry": "entry", "blocks": [{"id": "entry", "params": params, "ops": [
            {"op": "const", "args": [], "out": [{"name": "one", "type": "u32"}], "attrs": {"value": 1}},
            {"op": "int.add.checked", "args": ["x", "one"], "out": [{"name": "answer", "type": "u32"}], "attrs": {}},
        ], "term": {"op": "ret", "values": ["answer"]}}]}]}


def add_two_patch(program):
    operation = copy.deepcopy(program["functions"][0]["blocks"][0]["ops"][0])
    operation["attrs"]["value"] = 2
    return {"schema": "hepta.hia.patch.v1", "expected_sha256": verify_program(program).sha256,
            "edits": [{"action": "replace_operation", "function": "increment", "block": "entry",
                       "index": 0, "operation": operation}]}


class HIAProgramToolsTests(unittest.TestCase):
    def test_patch_rechecks_and_executes_changed_operations_without_source(self):
        source = scalar_program()
        before = verify_program(source)
        changed, receipt = apply_program_patch(before, add_two_patch(source))
        self.assertNotEqual(before.sha256, changed.sha256)
        original = execute_program(before, "increment", [40])
        revised = execute_program(changed, "increment", [40])
        self.assertEqual(original["status"], "returned")
        self.assertEqual(revised["status"], "returned")
        self.assertNotEqual(original["result"], revised["result"])
        self.assertEqual(source, scalar_program())
        self.assertTrue(receipt["claims"]["whole_module_rechecked"])
        self.assertFalse(receipt["claims"]["behavior_equivalence_proved"])

    def test_stale_duplicate_and_overlapping_edits_reject(self):
        document = scalar_program()
        patch = add_two_patch(document)
        changed, _ = apply_program_patch(document, patch)
        with self.assertRaisesRegex(HIAEditRejected, "stale"):
            apply_program_patch(changed, patch)
        patch["edits"] *= 2
        with self.assertRaisesRegex(HIAEditRejected, "duplicate"):
            apply_program_patch(document, patch)
        patch = add_two_patch(document)
        patch["edits"].append({"action": "replace_function", "function": "increment",
                               "definition": document["functions"][0]})
        with self.assertRaisesRegex(HIAEditRejected, "overlapping"):
            apply_program_patch(document, patch)

    def test_patch_cannot_remove_required_effect_or_use_undefined_value(self):
        document = scalar_program()
        patch = add_two_patch(document)
        definition = copy.deepcopy(document["functions"][0])
        definition["effects"] = []
        patch["edits"] = [{"action": "replace_function", "function": "increment", "definition": definition}]
        with self.assertRaises(ValueError):
            apply_program_patch(document, patch)
        patch = add_two_patch(document)
        patch["edits"][0]["operation"] = {
            "op": "int.add.wrap", "args": ["x", "missing"],
            "out": [{"name": "one", "type": "u32"}], "attrs": {}}
        with self.assertRaises(ValueError):
            apply_program_patch(document, patch)

    def test_patch_rejects_unknown_fields_bool_indices_and_nonfinite(self):
        document = scalar_program()
        for change in (lambda p: p.update(approved=True),
                       lambda p: p["edits"][0].update(index=False),
                       lambda p: p["edits"][0]["operation"]["attrs"].update(value=float("nan"))):
            patch = add_two_patch(document)
            change(patch)
            with self.assertRaises(ValueError):
                apply_program_patch(document, patch)
        for duplicate in ('{"x": 1, "x": 2}', '{"x": 1, "\\u0078": 2}'):
            with self.subTest(duplicate=duplicate), self.assertRaisesRegex(HIAEditRejected, "duplicate"):
                decode_json(duplicate)
        from unittest.mock import patch
        with patch("hepta.hia_program_tools.MAX_INPUT_BYTES", 16):
            with self.assertRaisesRegex(HIAEditRejected, "byte limit"):
                decode_json('"' + "雪" * 6 + '"')

    def test_publication_is_a_complete_verified_new_snapshot(self):
        document = verify_program(scalar_program())
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "program.hia"
            receipt = publish_program(document, output)
            self.assertEqual(verify_program(read_bounded(output)).sha256, document.sha256)
            self.assertEqual(receipt["publication"]["sha256"], document.sha256)
            with self.assertRaisesRegex(HIAEditRejected, "new file"):
                publish_program(document, output)
            alias = Path(folder) / "alias.hia"
            alias.symlink_to(output)
            with self.assertRaises(ValueError):
                publish_program(document, alias)
            with self.assertRaises(ValueError):
                read_bounded(alias)
            self.assertEqual(output.read_bytes(), document.canonical_bytes)

    def test_cli_verify_run_inspect_and_patch_need_no_rust_or_high_level_source(self):
        with tempfile.TemporaryDirectory() as folder:
            source, request, output = (Path(folder) / n for n in ["input.hia", "edit.json", "new.hia"])
            source.write_text(json.dumps(scalar_program()))
            request.write_text(json.dumps(add_two_patch(scalar_program())))
            env = {**os.environ, "RUSTC": "/does/not/exist", "PYTHONDONTWRITEBYTECODE": "1"}
            commands = [["verify", str(source)], ["inspect", str(source)],
                        ["run", str(source), "--function", "increment", "--arguments", "[40]"],
                        ["patch", str(source), "--request", str(request), "-o", str(output)]]
            for command in commands:
                with self.subTest(command=command[0]):
                    result = subprocess.run([sys.executable, "-m", "hepta", "hia", *command],
                                            env=env, capture_output=True, text=True, timeout=20)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    json.loads(result.stdout)
            self.assertNotEqual(verify_program(read_bounded(source)).sha256,
                                verify_program(read_bounded(output)).sha256)

    def test_cli_bad_program_returns_structured_error(self):
        document = scalar_program()
        document["functions"][0]["blocks"][0]["term"]["values"] = ["undefined"]
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "bad.hia"
            source.write_text(json.dumps(document))
            result = subprocess.run([sys.executable, "-m", "hepta", "hia", "verify", str(source)],
                                    capture_output=True, text=True, timeout=20)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(json.loads(result.stdout)["ok"])

    def test_cli_trap_and_budget_are_distinct_structured_outcomes(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "input.hia"
            source.write_text(json.dumps(scalar_program()))
            for arguments, extra, expected in (("[4294967295]", [], "trapped"),
                    ("[0]", ["--max-steps", "1"], "budget_exceeded")):
                result = subprocess.run([sys.executable, "-m", "hepta", "hia", "run", str(source),
                    "--function", "increment", "--arguments", arguments, *extra],
                    capture_output=True, text=True, timeout=20)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertEqual(json.loads(result.stdout)["status"], expected)


if __name__ == "__main__":
    unittest.main()
