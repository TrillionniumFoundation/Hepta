"""Complete, non-overlapping build variants retain independent semantics."""
from copy import deepcopy
from contextlib import redirect_stdout, redirect_stderr
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest

from hepta.c_migrate import MigrationRejected
from hepta.c_project import capture_project, verify_capture
from hepta.c_project_matrix import capture_project_matrix, verify_project_matrix
from hepta.c_translation import CTranslator
from hepta.cpp_project_migrate import lower_cpp_project_matrix
from hepta.hia_program import execute_program
from tools.qualify_cpp_project_matrix import make_inputs, qualify_cpp_matrix, validate_matrix_receipt

CLANG = os.environ.get("CLANG") or shutil.which("clang")
CLANGXX = os.environ.get("CLANGXX") or (str(Path(CLANG).with_name("clang++")) if CLANG else None)


def reseal(value):
    value["sha256"] = hashlib.sha256(json.dumps({key: item for key, item in value.items() if key != "sha256"},
                                               sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


@unittest.skipUnless(CLANG and CLANGXX, "Actual Clang toolchain required")
class CProjectMatrixTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hepta-matrix-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_two_configurations_two_units_native_without_original_target_objects(self):
        report = qualify_cpp_matrix(self.root / "run", clang=CLANG, clangxx=CLANGXX)
        self.assertTrue(report["ok"], report.get("diagnostic"))
        self.assertEqual(report["cases_per_variant"], 204)
        self.assertEqual(report["native_result_executions"], 816)
        self.assertEqual(report["matrix_capture"]["command_count"], 4)
        self.assertEqual([row["command_indices"] for row in report["variants"]], [[0, 1], [2, 3]])
        for row in report["variants"]:
            self.assertFalse(any(item["status"].endswith("pending") for item in row["declarations"]))
        self.assertNotEqual(report["variants"][0]["program_sha256"], report["variants"][1]["program_sha256"])
        forged = deepcopy(report)
        row = forged["variants"][0]
        row["target_link_argv"].append(str(self.root / "run/small/original-0.o"))
        row["processes"][row["target_link_process"]]["argv"] = row["target_link_argv"][:]
        with self.assertRaisesRegex(ValueError, "only directly generated HIA"):
            validate_matrix_receipt(forged)
        forged = deepcopy(report)
        forged["variants"][0]["observed"]["standalone_hia"][0] = -1
        with self.assertRaisesRegex(ValueError, "oracle"):
            validate_matrix_receipt(forged)

    def test_missing_overlap_repeated_source_and_driver_mismatch_fail_closed(self):
        path = make_inputs(self.root)
        original = json.loads(path.read_text())
        mutations = [
            ("missing", lambda doc: doc["variants"][1].update(command_indices=[2])),
            ("overlap", lambda doc: doc["variants"][1].update(command_indices=[1, 2, 3])),
            ("duplicate_index", lambda doc: doc["variants"][0].update(command_indices=[0, 0, 1])),
            ("bool_index", lambda doc: doc["variants"][0].update(command_indices=[False, 1])),
            ("same_source_twice", lambda doc: doc["variants"][0].update(command_indices=[0, 2])),
            ("incomplete_partition", lambda doc: doc["variants"].pop()),
            ("unknown_field", lambda doc: doc.update(approved=True)),
        ]
        for name, mutate in mutations:
            document = deepcopy(original)
            mutate(document)
            candidate = self.root / (name + ".json")
            candidate.write_text(json.dumps(document))
            with self.subTest(case=name), self.assertRaises(MigrationRejected):
                capture_project_matrix(candidate, clang=CLANGXX)
        database = self.root / "compile_commands.json"
        commands = json.loads(database.read_text())
        commands[2]["arguments"][0] = "g++"
        database.write_text(json.dumps(commands))
        with self.assertRaisesRegex(MigrationRejected, "consistent source compiler driver"):
            capture_project_matrix(path, clang=CLANGXX)

    def test_resealed_scope_selection_or_omission_does_not_grant_coverage(self):
        path = make_inputs(self.root)
        captured = capture_project_matrix(path, clang=CLANGXX)
        for mutate in (
            lambda obj: obj["variants"].pop(),
            lambda obj: obj["variants"][0].update(command_indices=[0, 3]),
            lambda obj: obj.update(command_count=2),
        ):
            forged = deepcopy(captured)
            mutate(forged)
            reseal(forged)
            with self.assertRaises(MigrationRejected):
                verify_project_matrix(forged)
        selected = deepcopy(captured["variants"][0]["capture"])
        self.assertEqual(selected["schema"], "hepta.cpp-build-selection.v1")
        selected["schema"] = "hepta.cpp-build.v1"
        selected["scope"] = "all_listed_commands_only_not_unlisted_platforms_or_configurations"
        del selected["command_indices"]
        reseal(selected)
        with self.assertRaises(MigrationRejected):
            verify_capture(selected)
        with self.assertRaises(MigrationRejected):
            capture_project(self.root / "compile_commands.json", clang=CLANGXX, language="c++")

    def test_matrix_manifest_or_header_mutation_invalidates_all_builds(self):
        path = make_inputs(self.root)
        captured = capture_project_matrix(path, clang=CLANGXX)
        original = path.read_text()
        changed = json.loads(original)
        changed["variants"][0]["name"] = "renamed"
        path.write_text(json.dumps(changed))
        with self.assertRaises(MigrationRejected):
            verify_project_matrix(captured)
        path.write_text(original)
        header = self.root / "source/model.hpp"
        header.write_text(header.read_text().replace("PROJECT_BIAS 3u", "PROJECT_BIAS 4u"))
        with self.assertRaises(MigrationRejected):
            verify_project_matrix(captured)

    def test_c_frontend_can_reuse_noncontiguous_original_database_indices(self):
        (self.root / "one.c").write_text("unsigned step(unsigned x) {return x+BIAS;}\n")
        (self.root / "two.c").write_text("unsigned step(unsigned x); unsigned twice(unsigned x) {return step(x)+step(x);}\n")
        commands = [{"directory": str(self.root), "file": unit,
                     "arguments": ["clang", "-std=c17", f"-DBIAS={bias}u", "-c", unit]}
                    for bias in (3, 17) for unit in ("one.c", "two.c")]
        database = self.root / "compile_commands.json"
        database.write_text(json.dumps(commands))
        selected = capture_project(database, clang=CLANG, command_indices=[2, 3])
        self.assertEqual([row["index"] for row in selected["configurations"]], [2, 3])
        translator = CTranslator(selected)
        source, _, functions = translator.emit()
        from hepta.hia_program_source import lower_source
        program = lower_source(source)
        entry = next(fn["hepta_name"] for fn in functions if fn["name"] == "twice")
        self.assertEqual(execute_program(program, entry, [5])["result"], 44)

    def test_cli_requires_named_variant_and_reports_complete_partition(self):
        from hepta.cli import main
        from hepta.hia_program import verify_program
        path = make_inputs(self.root)
        target, report = self.root / "selected.hia", self.root / "matrix-report.json"
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(["hia", "import-cpp-matrix", str(path), "--clangxx", CLANGXX,
                         "--variant", "large", "--output", str(target), "--report", str(report)])
        self.assertEqual(code, 0, (out.getvalue(), err.getvalue()))
        result = json.loads(report.read_text())
        self.assertEqual([variant["name"] for variant in result["variants"]], ["small", "large"])
        self.assertEqual(result["matrix_capture"]["command_count"], 4)
        program = verify_program(target.read_bytes())
        self.assertEqual(program.sha256, result["variants"][1]["program_sha256"])
        self.assertNotEqual(result["variants"][0]["program_sha256"], result["variants"][1]["program_sha256"])


if __name__ == "__main__":
    unittest.main()
