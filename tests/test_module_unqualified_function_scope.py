"""Source-module scalar names must not bind through the flattened program.

These controls use finite scalar functions only. They do not claim to repair
the separate cross-module local-binding collision restriction or qualify
objects, worker execution, recursive programs, or foreign implementations.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

import hepta
from hepta.ast import HeptaError
from hepta.backend import compile_rust, find_rustc
from hepta.c_backend import compile_c
from hepta.modules import load_project
from hepta.pipeline import analyze_project


# Follow the actual imported compiler so the identical tests can also be run
# against an unchanged source checkout without accidentally using new CLI code.
ROOT = Path(hepta.__file__).resolve().parents[1]


class ModuleUnqualifiedFunctionScopeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hepta-module-scope-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def project(self, files):
        for name, source in files.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(source, encoding="utf-8")
        return self.root / "main.hepta"

    def reject_scope(self, files, *, source="lib.hepta", symbol="secret"):
        entry = self.project(files)
        with self.assertRaises(HeptaError) as caught:
            load_project(entry)
        diagnostic = caught.exception.diagnostic
        self.assertEqual(diagnostic.code, "E_MODULE_SCOPE")
        self.assertEqual(diagnostic.phase, "module")
        self.assertEqual(diagnostic.span.path, str(self.root / source))
        self.assertIn(symbol, diagnostic.message)

    def execute_c(self, files):
        if not shutil.which("gcc"):
            self.skipTest("GCC required for actual C execution")
        entry = self.project(files)
        analysis = analyze_project(entry, backend="c", native=False,
                                   crate_type="bin")
        self.assertTrue(analysis.report["ok"], analysis.report)
        self.assertIsNotNone(analysis.c)
        for optimize in (False, True):
            with self.subTest(optimize=optimize):
                compiled = compile_c(analysis.c, cc="gcc", crate_type="bin",
                                     output=self.root / ("o3" if optimize else "o0"),
                                     optimize=optimize, sanitize=True)
                self.assertTrue(compiled["ok"], compiled)
                self.assertFalse(compiled["rustc_used"])
                result = subprocess.run([compiled["artifact"]],
                                        capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, "")
                self.assertEqual(result.stderr, "")

    def test_library_cannot_call_private_entry_helper_without_import(self):
        self.reject_scope({
            "lib.hepta": "pub fn answer() -> i32 effects {} { return secret(); }",
            "main.hepta": "import lib; fn secret() -> i32 effects {} { return 42; } "
                          "fn main() -> i32 effects {} { return lib::answer(); }",
        })

    def test_library_cannot_call_public_entry_helper_without_import(self):
        self.reject_scope({
            "lib.hepta": "pub fn answer() -> i32 effects {} { return secret(); }",
            "main.hepta": "import lib; pub fn secret() -> i32 effects {} { return 42; } "
                          "fn main() -> i32 effects {} { return lib::answer(); }",
        })

    def test_sibling_cannot_call_export_without_own_import(self):
        self.reject_scope({
            "lib.hepta": "pub fn answer() -> i32 effects {} { return secret(); }",
            "helper.hepta": "export \"C\" fn secret() -> i32 effects {} { return 42; }",
            "main.hepta": "import lib; import helper; "
                          "fn main() -> i32 effects {} { return lib::answer(); }",
        })

    def test_sibling_import_does_not_authorize_unqualified_export_call(self):
        self.reject_scope({
            "lib.hepta": "import helper; "
                         "pub fn answer() -> i32 effects {} { return secret(); }",
            "helper.hepta": "export \"C\" fn secret() -> i32 effects {} { return 42; }",
            "main.hepta": "import lib; "
                          "fn main() -> i32 effects {} { return lib::answer(); }",
        })

    def test_entry_cannot_call_imported_export_unqualified(self):
        self.reject_scope({
            "helper.hepta": "export \"C\" fn secret() -> i32 effects {} { return 42; }",
            "main.hepta": "import helper; "
                          "fn main() -> i32 effects {} { return secret(); }",
        }, source="main.hepta")

    def test_entry_alias_does_not_authorize_unqualified_export_call(self):
        self.reject_scope({
            "helper.hepta": "export \"C\" fn secret() -> i32 effects {} { return 42; }",
            "main.hepta": "import helper as boundary; "
                          "fn main() -> i32 effects {} { return secret(); }",
        }, source="main.hepta")

    def test_unqualified_imported_extern_rejects_during_loading_only(self):
        # The scope check must happen before foreign-call checking. This test
        # never checks a foreign contract, links, or executes an extern call.
        self.reject_scope({
            "helper.hepta": "extern \"C\" fn foreign_secret() -> i32 effects { ffi };",
            "main.hepta": "import helper; "
                          "fn main() -> i32 effects {} { return foreign_secret(); }",
        }, source="main.hepta", symbol="foreign_secret")

    def test_plain_cross_module_function_names_reject_during_loading_only(self):
        # Exercise name-expression resolution without worker/indirect-call or
        # native execution. A function is not a source-level scalar value.
        cases = {
            "entry_private": {
                "lib.hepta": "pub fn answer() -> i32 effects {} { return secret; }",
                "main.hepta": "import lib; fn secret() -> i32 effects {} { return 42; } "
                              "fn main() -> i32 effects {} { return lib::answer(); }",
            },
            "sibling_export": {
                "lib.hepta": "pub fn answer() -> i32 effects {} { return secret; }",
                "helper.hepta": "export \"C\" fn secret() -> i32 effects {} { return 42; }",
                "main.hepta": "import lib; import helper; "
                              "fn main() -> i32 effects {} { return lib::answer(); }",
            },
        }
        for label, files in cases.items():
            with self.subTest(case=label):
                self.reject_scope(files)

    def test_transitive_import_does_not_expose_export_to_entry(self):
        self.reject_scope({
            "helper.hepta": "export \"C\" fn secret() -> i32 effects {} { return 42; }",
            "lib.hepta": "import helper; "
                         "pub fn answer() -> i32 effects {} { return helper::secret(); }",
            "main.hepta": "import lib; "
                          "fn main() -> i32 effects {} { return secret(); }",
        }, source="main.hepta")

    def test_truly_unknown_function_keeps_checker_diagnostic(self):
        entry = self.project({
            "lib.hepta": "pub fn answer() -> i32 effects {} { return missing(); }",
            "main.hepta": "import lib; fn main() -> i32 effects {} { return lib::answer(); }",
        })
        load_project(entry)
        analysis = analyze_project(entry, backend="c", native=False, crate_type="bin")
        self.assertFalse(analysis.report["ok"])
        self.assertEqual([d["code"] for d in analysis.report["diagnostics"]],
                         ["E_UNKNOWN_FUNCTION"])

    def test_qualified_unknown_function_keeps_module_diagnostic(self):
        entry = self.project({
            "helper.hepta": "pub fn known() -> i32 effects {} { return 42; }",
            "main.hepta": "import helper; fn main() -> i32 effects {} { return helper::missing(); }",
        })
        with self.assertRaises(HeptaError) as caught:
            load_project(entry)
        self.assertEqual(caught.exception.diagnostic.code, "E_MODULE_SYMBOL")

    def test_unknown_namespace_keeps_parser_diagnostic(self):
        entry = self.project({
            "main.hepta": "fn main() -> i32 effects {} { return missing::secret(); }",
        })
        with self.assertRaises(HeptaError) as caught:
            load_project(entry)
        self.assertEqual(caught.exception.diagnostic.code, "E_PARSE_NAMESPACE")

    def test_qualified_private_function_stays_private(self):
        entry = self.project({
            "helper.hepta": "fn secret() -> i32 effects {} { return 42; }",
            "main.hepta": "import helper; fn main() -> i32 effects {} { return helper::secret(); }",
        })
        with self.assertRaises(HeptaError) as caught:
            load_project(entry)
        self.assertEqual(caught.exception.diagnostic.code, "E_MODULE_PRIVATE")

    def test_qualified_public_alias_executes(self):
        self.execute_c({
            "helper.hepta": "pub fn answer() -> i32 effects {} { return 42; }",
            "main.hepta": "import helper as h; fn main() -> i32 effects { panic } "
                          "{ assert(h::answer() == 42); return 0; }",
        })

    def test_qualified_sibling_export_alias_executes(self):
        self.execute_c({
            "helper.hepta": "export \"C\" fn secret() -> i32 effects {} { return 42; }",
            "lib.hepta": "import helper as boundary; "
                         "pub fn answer() -> i32 effects {} { return boundary::secret(); }",
            "main.hepta": "import lib; fn main() -> i32 effects { panic } "
                          "{ assert(lib::answer() == 42); return 0; }",
        })

    def test_same_module_private_helpers_execute(self):
        self.execute_c({
            "lib.hepta": "pub fn answer() -> i32 effects {} { return secret(); } "
                         "fn secret() -> i32 effects {} { return 42; }",
            "main.hepta": "import lib; fn secret() -> i32 effects {} { return 91; } "
                          "fn main() -> i32 effects { panic } "
                          "{ assert(lib::answer() == 42); assert(secret() == 91); return 0; }",
        })

    def test_same_module_export_helper_executes(self):
        self.execute_c({
            "lib.hepta": "export \"C\" fn secret() -> i32 effects {} { return 42; } "
                         "pub fn answer() -> i32 effects {} { return secret(); }",
            "main.hepta": "import lib; fn main() -> i32 effects { panic } "
                          "{ assert(lib::answer() == 42); return 0; }",
        })

    def test_builtin_calls_and_scalar_generic_parameters_execute(self):
        self.execute_c({
            "lib.hepta": "fn identity<T>(value: T) -> T effects {} { return value; } "
                         "pub fn answer() -> i32 effects {} "
                         "{ return max(identity::<i32>(41), wrapping_add(40, 2)); }",
            "main.hepta": "import lib; fn main() -> i32 effects { panic } "
                          "{ assert(lib::answer() == 42); return 0; }",
        })

    def test_distinct_modules_keep_same_named_functions_distinct(self):
        self.execute_c({
            "left.hepta": "pub fn value() -> i32 effects {} { return 11; }",
            "right.hepta": "pub fn value() -> i32 effects {} { return 31; }",
            "main.hepta": "import left as a; import right as b; "
                          "fn main() -> i32 effects { panic } "
                          "{ assert(wrapping_add(a::value(), b::value()) == 42); return 0; }",
        })

    def test_pinned_rust_and_c_execute_same_qualified_scalar_program(self):
        files = {
            "helper.hepta": "export \"C\" fn external_answer() -> i32 effects {} { return 21; }",
            "lib.hepta": "import helper as boundary; "
                         "fn secret() -> i32 effects {} { return 21; } "
                         "pub fn answer() -> i32 effects {} "
                         "{ return wrapping_add(secret(), boundary::external_answer()); }",
            "main.hepta": "import lib as library; "
                          "fn secret() -> i32 effects {} { return 91; } "
                          "fn main() -> i32 effects { panic } "
                          "{ assert(library::answer() == 42); assert(secret() == 91); return 0; }",
        }
        # C/frontend regressions remain real failures even when local Rust is
        # absent. Only the independent native-Rust portion may be skipped.
        self.execute_c(files)
        entry = self.root / "main.hepta"
        analysis = analyze_project(entry, backend="rust", native=False, crate_type="bin")
        self.assertTrue(analysis.report["ok"], analysis.report)
        self.assertIsNotNone(analysis.rust)
        try:
            rustc = find_rustc()
        except HeptaError as error:
            if error.diagnostic.code != "E_TOOLCHAIN":
                raise
            self.skipTest("Pinned Rust 1.90.0 compiler unavailable")
        for optimize in (False, True):
            with self.subTest(optimize=optimize):
                compiled = compile_rust(
                    analysis.rust, rustc=rustc, crate_type="bin", optimize=optimize,
                    output=self.root / ("rust_o3" if optimize else "rust_o0"))
                self.assertTrue(compiled["ok"], compiled)
                result = subprocess.run([compiled["artifact"]], capture_output=True,
                                        text=True, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, "")
                self.assertEqual(result.stderr, "")

    def test_public_cli_rejects_accidental_cross_module_calls(self):
        cases = {
            "entry_private": {
                "lib.hepta": "pub fn answer() -> i32 effects {} { return secret(); }",
                "main.hepta": "import lib; fn secret() -> i32 effects {} { return 42; } "
                              "fn main() -> i32 effects {} { return lib::answer(); }",
            },
            "sibling_export": {
                "lib.hepta": "pub fn answer() -> i32 effects {} { return secret(); }",
                "helper.hepta": "export \"C\" fn secret() -> i32 effects {} { return 42; }",
                "main.hepta": "import lib; import helper; "
                              "fn main() -> i32 effects {} { return lib::answer(); }",
            },
            "entry_export": {
                "helper.hepta": "export \"C\" fn secret() -> i32 effects {} { return 42; }",
                "main.hepta": "import helper; fn main() -> i32 effects {} { return secret(); }",
            },
        }
        for label, files in cases.items():
            with self.subTest(case=label):
                entry = self.project(files)
                env = dict(os.environ, PYTHONPATH=str(ROOT), PYTHONDONTWRITEBYTECODE="1")
                result = subprocess.run(
                    [sys.executable, "-m", "hepta", "run", str(entry), "--backend", "c", "--json"],
                    cwd=ROOT, env=env, capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertEqual(result.stderr, "")
                report = json.loads(result.stdout)
                self.assertFalse(report["ok"])
                self.assertEqual([d["code"] for d in report["diagnostics"]], ["E_MODULE_SCOPE"])


if __name__ == "__main__":
    unittest.main()
