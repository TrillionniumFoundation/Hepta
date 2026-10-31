"""Adversarial P3 migration gates: completeness and atomic publication."""
from __future__ import annotations

from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from hepta.c_migrate import migrate_c


class CMigrationAdversarial(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(shutil.which("clang"), "Clang required")
        self.temp = tempfile.TemporaryDirectory(prefix="hepta-c-migrate-adversarial-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "input.c"
        self.output = self.root / "translated.hepta"

    def migrate(self, text: str) -> dict:
        self.source.write_text(text, encoding="utf-8")
        return migrate_c(self.source, self.output)

    def reject(self, text: str, code: str):
        result = self.migrate(text)
        self.assertFalse(result["ok"], result)
        self.assertFalse(self.output.exists())
        self.assertIn(code, [item["code"] for item in result["rejected"]], result)
        if code == "E_C_TOPLEVEL":
            self.assertEqual(result["status"], "unsupported_source", result)

    def test_unused_global_must_not_be_silently_dropped(self):
        self.reject("int hidden = 7; int pure(int x){ return x + 1; }", "E_C_TOPLEVEL")

    def test_global_following_translated_function_is_rejected(self):
        self.reject("int pure(int x){return x;} int hidden = 7;", "E_C_TOPLEVEL")

    def test_extra_c_prototype_cannot_disappear(self):
        self.reject("int legacy(int x); int pure(int x){return x;}", "E_C_TOPLEVEL")

    def test_user_typedef_cannot_disappear(self):
        self.reject("typedef int Custom; int pure(int x){return x;}", "E_C_TOPLEVEL")

    def test_builtin_stdint_header_does_not_trigger_false_rejection(self):
        result = self.migrate("#include <stdint.h>\nint32_t add(int32_t x, int32_t y){return x+y;}")
        self.assertTrue(result["ok"], result)
        self.assertTrue(self.output.exists())

    def test_existing_output_is_not_overwritten(self):
        self.output.write_text("old")
        self.source.write_text("int f(int x){return x;}")
        result = migrate_c(self.source, self.output)
        self.assertFalse(result["ok"])
        self.assertEqual(self.output.read_text(), "old")

    def test_dangling_symlink_output_is_rejected(self):
        dangling = self.root / "absent.hepta"
        self.output.symlink_to(dangling)
        self.source.write_text("int f(int x){return x;}")
        result = migrate_c(self.source, self.output)
        self.assertFalse(result["ok"], result)
        self.assertFalse(dangling.exists())
        self.assertTrue(self.output.is_symlink())

    def test_frontend_mutation_of_equal_size_source_is_rejected(self):
        # Changes after Clang and the first digest check must not produce
        # a successfully published artifact labeled with the old source hash.
        before = "int f(int x){return x;}\n"
        after = "int f(int x){return 0;}\n"
        self.assertEqual(len(before), len(after))
        self.source.write_text(before, encoding="utf-8")
        from hepta.checker import check as actual_check

        def check_and_replace(*args, **kwargs):
            result = actual_check(*args, **kwargs)
            self.source.write_text(after, encoding="utf-8")
            return result

        with patch("hepta.checker.check", side_effect=check_and_replace):
            result = migrate_c(self.source, self.output)
        self.assertFalse(result["ok"], result)
        self.assertIn("E_C_SOURCE_RACE",
                      [item["code"] for item in result["rejected"]], result)
        self.assertFalse(self.output.exists())
        self.assertEqual(list(self.root.glob(".hepta-migrate-*")), [])

    def test_unchanged_source_keeps_successful_frontend_gate(self):
        result = self.migrate("int f(int x){return x;}\n")
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["status"], "frontend_checked_not_native_qualified")
        self.assertTrue(self.output.is_file())

    def test_atomic_publish_failure_leaves_no_partial_output(self):
        self.source.write_text("int f(int x){return x;}")
        with patch("hepta.c_migrate.os.link", side_effect=OSError("simulated filesystem failure")):
            result = migrate_c(self.source, self.output)
        self.assertFalse(result["ok"], result)
        self.assertIn("E_C_PUBLISH", [item["code"] for item in result["rejected"]])
        self.assertFalse(self.output.exists())
        self.assertEqual(list(self.root.glob(".hepta-migrate-*")), [])


    def test_clang_stdout_limit_does_not_capture_full_output_in_ram(self):
        # Clang AST JSON can grow far beyond the 256 KiB C source size.
        # A post-communicate length check cannot undo subprocess.run's
        # in-memory capture. Require file-backed output before checking size.
        import subprocess
        from hepta.c_migrate import MigrationRejected, _run

        def oversized_result(command, **kwargs):
            self.assertFalse(kwargs.get("capture_output"), kwargs)
            self.assertIn("stdout", kwargs)
            self.assertIn("stderr", kwargs)
            # Sparse 32 MB+ output file; no 32 MB allocation in this test.
            kwargs["stdout"].truncate(32_000_001)
            return subprocess.CompletedProcess(command, 0)

        with patch("hepta.c_migrate.subprocess.run", side_effect=oversized_result):
            with self.assertRaises(MigrationRejected) as rejected:
                _run(["clang", "-ast-dump=json"])
        self.assertEqual(rejected.exception.code, "E_CLANG_SIZE")

    def test_clang_stderr_tail_is_bounded_without_memory_capture(self):
        import subprocess
        from hepta.c_migrate import MigrationRejected, _run

        def failed_result(command, **kwargs):
            self.assertFalse(kwargs.get("capture_output"), kwargs)
            self.assertIn("stderr", kwargs)
            kwargs["stderr"].write(b"x" * 20_000 + b"fatal: rejected")
            return subprocess.CompletedProcess(command, 1)

        with patch("hepta.c_migrate.subprocess.run", side_effect=failed_result):
            with self.assertRaises(MigrationRejected) as rejected:
                _run(["clang", "-bad-option"])
        self.assertEqual(rejected.exception.code, "E_CLANG_REJECT")
        self.assertLessEqual(len(str(rejected.exception)), 5_000)
        self.assertTrue(str(rejected.exception).endswith("fatal: rejected"))

    def test_clang_subprocess_stdin_remains_supported(self):
        import sys
        from hepta.c_migrate import _run

        output = _run([sys.executable, "-c",
                       "import sys; sys.stdout.write(sys.stdin.read().upper())"],
                      input_text="hello")
        self.assertEqual(output, "HELLO")


    def test_oversized_source_rejected_before_unbounded_read(self):
        # A caller may point the converter at an arbitrarily large file.
        # Do not load the entire file merely to discover it exceeds 256 KB.
        self.source.write_bytes(b"x" * 256_001)
        with patch("hepta.c_migrate.Path.read_bytes",
                   side_effect=AssertionError("unbounded source read")):
            result = migrate_c(self.source, self.output)
        self.assertFalse(result["ok"], result)
        self.assertIn("E_C_SIZE",
                      [item["code"] for item in result["rejected"]], result)
        self.assertFalse(self.output.exists())

    def test_source_read_error_is_controlled_rejection(self):
        # Revalidate read access at use; a file may become unreadable
        # after is_file(), and the public API must not leak an OSError.
        self.source.write_text("int f(int x){return x;}\\n", encoding="utf-8")
        with patch("hepta.c_migrate.Path.open",
                   side_effect=PermissionError("simulated read denial")):
            result = migrate_c(self.source, self.output)
        self.assertFalse(result["ok"], result)
        self.assertIn("E_C_SOURCE_RACE",
                      [item["code"] for item in result["rejected"]], result)
        self.assertFalse(self.output.exists())


    def test_source_growth_during_clang_does_not_trigger_unbounded_reread(self):
        # Clang already parsed the original file when a noncooperating writer
        # replaces it with an oversize source. Rechecks must be size-bounded.
        self.source.write_text("int f(int x){return x;}\n", encoding="utf-8")
        from hepta.c_migrate import _run as actual_run

        def run_then_grow(args, **kwargs):
            result = actual_run(args, **kwargs)
            if "-ast-dump=json" in args:
                self.source.write_bytes(b"x" * 256_001)
            return result

        with patch("hepta.c_migrate._run", side_effect=run_then_grow), \
             patch("hepta.c_migrate.Path.read_bytes",
                   side_effect=AssertionError("unbounded post-Clang source read")):
            result = migrate_c(self.source, self.output)
        self.assertFalse(result["ok"], result)
        self.assertIn("E_C_SOURCE_RACE", [x["code"] for x in result["rejected"]], result)
        self.assertFalse(self.output.exists())

    def test_source_growth_during_frontend_does_not_trigger_unbounded_reread(self):
        # This exercises the second (prepublication) freshness check.
        self.source.write_text("int f(int x){return x;}\n", encoding="utf-8")
        from hepta.checker import check as actual_check

        def check_then_grow(*args, **kwargs):
            result = actual_check(*args, **kwargs)
            self.source.write_bytes(b"x" * 256_001)
            return result

        with patch("hepta.checker.check", side_effect=check_then_grow), \
             patch("hepta.c_migrate.Path.read_bytes",
                   side_effect=AssertionError("unbounded prepublication source read")):
            result = migrate_c(self.source, self.output)
        self.assertFalse(result["ok"], result)
        self.assertIn("E_C_SOURCE_RACE", [x["code"] for x in result["rejected"]], result)
        self.assertFalse(self.output.exists())
        self.assertEqual(list(self.root.glob(".hepta-migrate-*")), [])


    def test_deep_expression_ast_fails_closed(self):
        # A deeply nested Clang expression must not leak RecursionError.
        from hepta.c_migrate import MigrationRejected, _expr

        expression = {"kind": "IntegerLiteral", "value": "1"}
        for _ in range(1500):
            expression = {"kind": "ParenExpr", "inner": [expression]}
        with self.assertRaises(MigrationRejected) as rejected:
            _expr(expression, {}, {}, "i32")
        self.assertEqual(rejected.exception.code, "E_C_AST_DEPTH")

    def test_deep_compound_ast_fails_closed(self):
        # Source-derived AST nesting must have a bounded traversal depth.
        from hepta.c_migrate import MigrationRejected, _stmt

        statement = {"kind": "ReturnStmt", "inner": [{"kind": "IntegerLiteral", "value": "1"}]}
        for _ in range(1500):
            statement = {"kind": "CompoundStmt", "inner": [statement]}
        with self.assertRaises(MigrationRejected) as rejected:
            _stmt(statement, {}, {}, "i32")
        self.assertEqual(rejected.exception.code, "E_C_AST_DEPTH")

    def test_deep_clang_json_fails_closed_at_public_entrypoint(self):
        # json.loads can raise RecursionError before returning an AST tree.
        self.source.write_text("int f(int x){return x;}\n", encoding="utf-8")
        with patch("hepta.c_migrate._data_model", return_value={}), \
             patch("hepta.c_migrate._run", return_value="{}"), \
             patch("hepta.c_migrate.json.loads", side_effect=RecursionError("deep JSON")):
            report = migrate_c(self.source, self.output)
        self.assertFalse(report["ok"], report)
        self.assertIn("E_C_AST_DEPTH", [item["code"] for item in report["rejected"]])
        self.assertFalse(self.output.exists())


    def test_oversized_flat_function_ast_fails_closed(self):
        # A shallow function with thousands of sibling statements bypasses
        # the depth-only guard. The converter must reject its node budget.
        from hepta.c_migrate import MigrationRejected, _function

        statement = {"kind": "ReturnStmt",
                     "inner": [{"kind": "IntegerLiteral", "value": "1"}]}
        declaration = {
            "kind": "FunctionDecl",
            "name": "f",
            "type": {"qualType": "int (void)"},
            "inner": [{"kind": "CompoundStmt",
                       "inner": [statement for _ in range(2200)]}],
        }
        with self.assertRaises(MigrationRejected) as rejected:
            _function(declaration, {"sizeof_long": 8})
        self.assertEqual(rejected.exception.code, "E_C_AST_BUDGET")

    def test_small_function_ast_still_translates(self):
        from hepta.c_migrate import _function

        declaration = {
            "kind": "FunctionDecl",
            "name": "f",
            "type": {"qualType": "int (void)"},
            "inner": [{"kind": "CompoundStmt",
                       "inner": [{"kind": "ReturnStmt",
                                  "inner": [{"kind": "IntegerLiteral", "value": "1"}]}]}],
        }
        result = _function(declaration, {"sizeof_long": 8})
        self.assertEqual(result["name"], "f")
        self.assertIn("return 1;", result["source"])

    def test_real_clang_wide_function_rejected_without_output(self):
        # Clang emits thousands of AST siblings for a C function with many
        # returns, even though its nesting is shallow and input is < 256 KiB.
        source = "int f(int x) {\n" + "return x;\n" * 2200 + "}\n"
        self.reject(source, "E_C_AST_BUDGET")

    def test_malformed_function_ast_children_fail_closed(self):
        from hepta.c_migrate import MigrationRejected, _function

        declaration = {
            "kind": "FunctionDecl",
            "name": "f",
            "type": {"qualType": "int (void)"},
            "inner": [{"kind": "CompoundStmt", "inner": "not-a-node-list"}],
        }
        with self.assertRaises(MigrationRejected) as rejected:
            _function(declaration, {"sizeof_long": 8})
        self.assertEqual(rejected.exception.code, "E_C_AST")



    def test_translation_unit_aggregate_ast_budget_fails_closed(self):
        # Function names avoid Hepta f32/f64 type collisions, so the test\n        # isolates the translation-unit AST budget, not frontend naming checks.\n        # Every individual C function is tiny; their aggregate AST work is not.
        # An input under the 256 KiB gate can otherwise trigger thousands of
        # separate AST traversals and arbitrarily large generated Hepta source.
        program = "\n".join(
            f"int aggregate_budget_fn_{i}(int x) {{ return x + 1; }}" for i in range(1500)
        )
        self.assertLess(len(program.encode("utf-8")), 256_000)
        self.reject(program, "E_C_AST_UNIT_BUDGET")

    def test_small_multi_function_translation_unit_remains_supported(self):
        program = "\n".join(
            f"int f{i}(int x) {{ return x + 1; }}" for i in range(8)
        )
        result = self.migrate(program)
        self.assertTrue(result["ok"], result)
        self.assertEqual(len(result["converted"]), 8)
        self.assertTrue(self.output.exists())

if __name__ == "__main__":
    unittest.main()
