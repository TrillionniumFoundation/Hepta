"""Finite local bindings must not collide with unrelated flattened functions.

Only lexical naming is exercised: scalar calls, finite loops, scalar borrowed
returns and a scalar Result match. No recursive or worker execution is used.
C controls execute real GCC at O0/O3 with UBSan. Rust parity is separate and
must explicitly skip when the actual compiler is unavailable.
"""
from __future__ import annotations

from dataclasses import fields, is_dataclass
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

import hepta
from hepta.ast import Expr, HeptaError, Span
from hepta.backend import compile_rust, emit_header, find_rustc
from hepta.c_backend import compile_c
from hepta.modules import load_project
from hepta.parser import parse
from hepta.pipeline import analyze, analyze_project, interface, interface_hash


# Baseline runs must use the actual imported compiler for public CLI checks.
ROOT = Path(hepta.__file__).resolve().parents[1]
HELPER = "fn secret() -> i64 effects {} { return 19; }"
EXPORT = 'export "C" fn secret() -> i64 effects {} { return 19; }'


def walk(value):
    yield value
    if isinstance(value, dict):
        for child in value.values():
            yield from walk(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            yield from walk(child)
    elif is_dataclass(value) and not isinstance(value, Span):
        for field in fields(value):
            yield from walk(getattr(value, field.name))


class ModuleLocalBindingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hepta-local-bindings-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def project(self, files):
        # Avoid leaking an earlier control's sibling files into a later graph.
        for path in self.root.glob("*.hepta"):
            path.unlink()
        for name, source in files.items():
            (self.root / name).write_text(source, encoding="utf-8")
        return self.root / "main.hepta"

    @staticmethod
    def main(call, expected=7, prefix="import lib; " + HELPER):
        return prefix + " fn main() -> i32 effects {} { if " + call + " == " + str(expected) + " { return 0; } else { return 1; } }"

    def matrix_files(self, binder, location):
        bodies = {
            "parameter": ("pub fn answer(secret: i64) -> i64 effects {} { return secret; }", "lib::answer(7)", 7),
            "let": ("pub fn answer() -> i64 effects {} { let secret: i64 = 7; return secret; }", "lib::answer()", 7),
            "for": ("pub fn answer() -> i64 effects {} { let mut sum: i64 = 0; for secret in 0..4 { sum = wrapping_add(sum, secret); } return sum; }", "lib::answer()", 6),
        }
        lib, call, expected = bodies[binder]
        files = {"lib.hepta": lib}
        prefix = "import lib; " + HELPER
        if location == "root_export":
            prefix = "import lib; " + EXPORT
        elif location == "sibling_export":
            prefix = "import lib; import boundary; "
            files["boundary.hepta"] = EXPORT
        files["main.hepta"] = self.main(call, expected, prefix)
        return files

    def frontend(self, files, backend="c"):
        result = analyze_project(self.project(files), backend=backend, native=False, crate_type="bin")
        self.assertTrue(result.report["ok"], result.report)
        self.assertEqual(result.report["status"], "frontend_only")
        return result

    def execute_c(self, files):
        self.assertIsNotNone(shutil.which("gcc"), "Actual GCC is required")
        result = self.frontend(files)
        self.assertIsNotNone(result.c)
        for optimize in (False, True):
            with self.subTest(optimize=optimize):
                built = compile_c(result.c, cc="gcc", output=self.root / ("o3" if optimize else "o0"), optimize=optimize, sanitize=True)
                self.assertTrue(built["ok"], built)
                self.assertFalse(built["check_only"])
                self.assertFalse(built["rustc_used"])
                self.assertIn("-O3" if optimize else "-O0", built["flags"])
                self.assertIn("-fsanitize=undefined", built["flags"])
                self.run_artifact(built["artifact"])
        return result

    def run_artifact(self, artifact):
        proc = subprocess.run([artifact], capture_output=True, text=True, timeout=5)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(proc.stdout, "")
        self.assertEqual(proc.stderr, "")

    def reject(self, files, code, *, without=()):
        result = analyze_project(self.project(files), backend="c", native=False, crate_type="bin")
        self.assertFalse(result.report["ok"], result.report)
        codes = [d["code"] for d in result.report["diagnostics"]]
        self.assertIn(code, codes, result.report)
        for forbidden in without:
            self.assertNotIn(forbidden, codes, result.report)
        return result

    def library_function(self, result, name="answer"):
        return next(f for f in result.program.functions if f.span.path == str(self.root / "lib.hepta") and f.name.endswith("_" + name))

    def test_root_private_parameter(self):
        files = self.matrix_files("parameter", "root_private")
        result = self.execute_c(files)
        fn = self.library_function(result)
        original = parse(files["lib.hepta"], str(self.root / "lib.hepta")).functions[0]
        self.assertNotEqual(fn.params[0].name, "secret")
        self.assertRegex(fn.params[0].name, r"^M[0-9a-f]{16}_[0-9]+_secret$")
        self.assertEqual(fn.params[0].span, original.params[0].span)
        self.assertEqual(fn.span, original.span)
        self.assertEqual(fn.body_span, original.body_span)
        self.assertEqual([x.span for x in walk(fn) if isinstance(x, Expr)], [x.span for x in walk(original) if isinstance(x, Expr)])
        self.assertIn("secret", {f.name for f in result.program.functions})
        self.assertEqual(fn.name, result.project.modules[0]["symbols"]["answer"])

    def test_root_private_let(self):
        self.execute_c(self.matrix_files("let", "root_private"))

    def test_root_private_for(self):
        self.execute_c(self.matrix_files("for", "root_private"))

    def test_root_export_parameter(self):
        self.execute_c(self.matrix_files("parameter", "root_export"))

    def test_root_export_let(self):
        self.execute_c(self.matrix_files("let", "root_export"))

    def test_root_export_for(self):
        self.execute_c(self.matrix_files("for", "root_export"))

    def test_sibling_export_parameter(self):
        self.execute_c(self.matrix_files("parameter", "sibling_export"))

    def test_sibling_export_let(self):
        self.execute_c(self.matrix_files("let", "sibling_export"))

    def test_sibling_export_for(self):
        self.execute_c(self.matrix_files("for", "sibling_export"))

    def qualified_files(self):
        return {"boundary.hepta": 'export "C" fn secret() -> i64 effects {} { return 7; }',
                "main.hepta": "import boundary; fn main() -> i32 effects {} { let secret: i64 = 7; if boundary::secret() == secret { return 0; } else { return 1; } }"}

    def test_qualified_call_and_same_spelled_local_keep_distinct_names(self):
        files = self.qualified_files()
        result = self.execute_c(files)
        main = next(f for f in result.program.functions if f.name == "main")
        self.assertNotEqual(main.body[0].data["name"], "secret")
        self.assertIn("secret", [x.value for x in walk(main) if isinstance(x, Expr) and x.kind == "call"])
        self.assertIn("int64_t secret(void);", emit_header(result.program))
        rust = self.frontend(files, "rust")
        self.assertIn('#[export_name = "secret"]', rust.rust)
        self.assertIn("h_secret()", rust.rust)
        self.assertNotIn("let h_secret:", rust.rust)

    def test_same_module_entry_collision_still_rejects(self):
        self.reject({"main.hepta": HELPER + " fn main() -> i32 effects {} { let secret: i64 = 7; return secret as i32; }"}, "E_NAME_COLLISION")

    def test_same_module_imported_used_collision_keeps_existing_rejection(self):
        self.reject({"lib.hepta": HELPER + " pub fn answer(secret: i64) -> i64 effects {} { return secret; }",
                     "main.hepta": self.main("lib::answer(7)", prefix="import lib;")}, "E_UNKNOWN_NAME")

    def test_same_module_imported_unused_parameter_keeps_existing_acceptance(self):
        files = {"lib.hepta": HELPER + " pub fn answer(secret: i64) -> i64 effects {} { return 7; }",
                 "main.hepta": self.main("lib::answer(7)", prefix="import lib;")}
        result = self.execute_c(files)
        self.assertEqual(self.library_function(result).params[0].name, "secret")

    def test_duplicate_locals_and_parameters_still_reject(self):
        cases = [
            ("pub fn answer() -> i64 effects {} { let secret: i64 = 1; let secret: i64 = 7; return secret; }", "E_DUPLICATE_LOCAL"),
            ("pub fn answer(secret: i64, secret: i64) -> i64 effects {} { return secret; }", "E_DUPLICATE"),
            ("pub fn answer(secret: i64) -> i64 effects {} { for secret in 0..1 {} return secret; }", "E_DUPLICATE_LOCAL"),
        ]
        for lib, code in cases:
            with self.subTest(lib=lib):
                self.reject({"lib.hepta": lib, "main.hepta": self.main("7")}, code, without=("E_NAME_COLLISION",))

    def test_out_of_scope_and_predeclaration_names_still_reject(self):
        bodies = [
            "if true { let secret: i64 = 7; } return secret;",
            "let before: i64 = secret; let secret: i64 = 7; return before;",
            "for secret in 0..1 {} return secret;",
        ]
        for body in bodies:
            with self.subTest(body=body):
                self.reject({"lib.hepta": "pub fn answer() -> i64 effects {} { " + body + " }", "main.hepta": self.main("7")}, "E_UNKNOWN_NAME", without=("E_NAME_COLLISION",))

    def test_noncolliding_interface_and_emitted_source_are_unchanged(self):
        source = "fn identity(value: i64) -> i64 effects {} { let other: i64 = value; return other; } fn main() -> i32 effects {} { return 0; }"
        entry = self.project({"main.hepta": source})
        for backend in ("c", "rust"):
            with self.subTest(backend=backend):
                direct = analyze(source, str(entry), backend=backend, native=False, crate_type="bin")
                project = analyze_project(entry, backend=backend, native=False, crate_type="bin")
                self.assertTrue(direct.report["ok"], direct.report)
                self.assertTrue(project.report["ok"], project.report)
                self.assertEqual(interface(direct.program), interface(project.program))
                self.assertEqual(interface_hash(direct.program), interface_hash(project.program))
                self.assertEqual(direct.c, project.c)
                self.assertEqual(direct.rust, project.rust)

    def test_export_parameter_spelling_excludes_all_same_named_locals(self):
        files = {"lib.hepta": 'export "C" fn answer(secret: i64) -> i64 effects {} { let secret: i64 = 7; return secret; }',
                 "main.hepta": self.main("7")}
        result = self.reject(files, "E_NAME_COLLISION")
        self.assertIn("E_DUPLICATE_LOCAL", [d["code"] for d in result.report["diagnostics"]])
        fn = next(f for f in result.program.functions if f.name == "answer")
        self.assertEqual(fn.params[0].name, "secret")
        self.assertEqual(fn.body[0].data["name"], "secret")
        self.assertIn("int64_t answer(int64_t secret);", emit_header(result.program))

    def test_export_body_local_can_be_renamed_without_changing_abi(self):
        files = {"lib.hepta": 'export "C" fn answer(value: i64) -> i64 effects {} { let secret: i64 = value; return secret; }',
                 "main.hepta": self.main("lib::answer(7)")}
        result = self.execute_c(files)
        fn = next(f for f in result.program.functions if f.name == "answer")
        self.assertEqual(fn.params[0].name, "value")
        self.assertNotEqual(fn.body[0].data["name"], "secret")
        self.assertIn("int64_t answer(int64_t value);", emit_header(result.program))

    def test_c_identifier_rejection_is_not_laundered(self):
        for declaration in (
            'export "C" fn answer(switch: i64) -> i64 effects {} { return switch; }',
            'extern "C" fn answer(switch: i64) -> i64 effects {ffi};',
        ):
            with self.subTest(declaration=declaration):
                files = {"lib.hepta": declaration, "main.hepta": self.main("7", prefix="import lib; " + HELPER.replace("secret", "switch"))}
                result = self.reject(files, "E_C_IDENTIFIER")
                fn = next(f for f in result.program.functions if f.name == "answer")
                self.assertEqual(fn.params[0].name, "switch")

    def test_extern_parameter_interface_and_assumption_labels_are_unchanged(self):
        declaration = 'extern "C" fn remote(secret: i64) -> i64 effects {ffi};'
        files = {"lib.hepta": declaration, "main.hepta": self.main("7")}
        result = self.frontend(files)
        expected = interface(parse(declaration, str(self.root / "lib.hepta")))["functions"][0]
        actual = next(f for f in interface(result.program)["functions"] if f["name"] == "remote")
        self.assertEqual(actual, expected)
        assumption = next(a for a in result.report["assumptions"] if a.get("function") == "remote")
        self.assertEqual(assumption["parameters"][0]["name"], "secret")
        self.assertIn("int64_t remote(int64_t secret);", emit_header(result.program))

    def borrowed_files(self):
        return {"lib.hepta": "pub fn pick(secret: read i64, other: read i64) -> read i64 from secret effects {} { return read secret; }",
                "main.hepta": "import lib; " + HELPER + " fn main() -> i32 effects {} { let a: i64 = 7; let b: i64 = 9; if lib::pick(read a, read b) == 7 { return 0; } else { return 1; } }"}

    def test_scalar_borrowed_return_origin_tracks_renamed_parameter(self):
        files = self.borrowed_files()
        result = self.execute_c(files)
        fn = self.library_function(result, "pick")
        self.assertNotEqual(fn.params[0].name, "secret")
        self.assertEqual(fn.return_origin, fn.params[0].name)
        self.assertEqual(fn.params[1].name, "other")
        rust = self.frontend(files, "rust")
        self.assertIn("'hepta_return", rust.rust)

    def test_invalid_borrowed_origin_is_not_laundered(self):
        for origin in ("missing", "other"):
            with self.subTest(origin=origin):
                files = self.borrowed_files()
                files["lib.hepta"] = files["lib.hepta"].replace("from secret", "from " + origin)
                self.reject(files, "E_BORROW_RETURN_SOURCE", without=("E_NAME_COLLISION",))

    def match_files(self):
        return {"lib.hepta": "pub fn answer() -> i64 effects {} { let result: Result<i64,u8> = Result::Ok(7); match result { Result::Ok(secret) => { return secret; }, Result::Err(_) => { return 1; } } }",
                "main.hepta": self.main("lib::answer()")}

    def test_scalar_match_binder_is_renamed_and_wildcard_is_unchanged(self):
        result = self.execute_c(self.match_files())
        arms = self.library_function(result).body[1].data["arms"]
        self.assertNotEqual(arms[0].pattern.bindings, ["secret"])
        self.assertEqual(arms[1].pattern.bindings, ["_"])
        self.assertEqual(arms[0].pattern.enum_name, "Result")
        self.assertEqual(arms[0].pattern.variant, "Ok")

    def test_ordinary_underscore_binding_is_renamed_but_match_wildcard_is_not(self):
        files = {"lib.hepta": "pub fn answer(_: i64) -> i64 effects {} { let result: Result<i64,u8> = Result::Err(1); match result { Result::Ok(value) => { return value; }, Result::Err(_) => { return _; } } }",
                 "main.hepta": self.main("lib::answer(7)", prefix="import lib; " + HELPER.replace("secret", "_"))}
        result = self.execute_c(files)
        fn = self.library_function(result)
        renamed = fn.params[0].name
        self.assertNotEqual(renamed, "_")
        arms = fn.body[1].data["arms"]
        self.assertEqual(arms[1].pattern.bindings, ["_"])
        self.assertEqual(arms[1].body[0].data["expr"].kind, "name")
        self.assertEqual(arms[1].body[0].data["expr"].value, renamed)
        self.assertIn("_", {f.name for f in result.program.functions})

    def alias_files(self):
        return {"helper.hepta": "pub fn increment() -> i64 effects {} { return 1; }",
                "lib.hepta": "import helper as secret; pub fn answer(secret: i64) -> i64 effects {} { return wrapping_add(secret, secret::increment()); }",
                "main.hepta": self.main("lib::answer(7)", 8)}

    def test_qualified_import_alias_is_not_renamed_with_local(self):
        result = self.execute_c(self.alias_files())
        fn = self.library_function(result)
        self.assertNotEqual(fn.params[0].name, "secret")
        helper = next(f for f in result.program.functions if f.span.path == str(self.root / "helper.hepta"))
        self.assertIn(helper.name, [x.value for x in walk(fn) if isinstance(x, Expr) and x.kind == "call"])

    def test_type_parameter_spelling_is_not_renamed(self):
        files = {"lib.hepta": "pub fn answer<secret>(secret: secret) -> secret effects {} { return secret; }",
                 "main.hepta": self.main("lib::answer::<i64>(7)")}
        result = self.execute_c(files)
        fn = self.library_function(result)
        self.assertEqual(fn.type_params, ("secret",))
        self.assertEqual(fn.params[0].type.name, "secret")
        self.assertEqual(fn.return_type.name, "secret")
        self.assertNotEqual(fn.params[0].name, "secret")

    def test_generated_local_prefix_is_disjoint_from_module_declarations(self):
        files = {"lib.hepta": "fn _0_secret() -> i64 effects {} { return 1; } pub fn answer(secret: i64) -> i64 effects {} { return wrapping_add(secret, _0_secret()); }",
                 "main.hepta": self.main("lib::answer(7)", 8)}
        result = self.execute_c(files)
        fn = self.library_function(result)
        self.assertNotIn(fn.params[0].name, {f.name for f in result.program.functions})
        self.assertTrue(any(f.name.endswith("__0_secret") for f in result.program.functions))

    def test_source_cannot_spell_generated_local_namespace(self):
        files = {"main.hepta": "fn main() -> i32 effects {} { let M0123456789abcdef_0_secret: i32 = 0; return 0; }"}
        with self.assertRaises(HeptaError) as caught:
            load_project(self.project(files))
        self.assertEqual(caught.exception.diagnostic.code, "E_MODULE_RESERVED")

    def freshness_files(self, own_unit):
        prefix = "M" + hashlib.sha256(b"lib.hepta").hexdigest()[:16]
        symbols = ["h_" + prefix + "_" + str(n) + "_secret" for n in (0, 1)]
        declarations = " ".join('export "C" fn ' + name + '() -> i64 effects {} { return ' + str(i + 1) + '; }' for i, name in enumerate(symbols))
        qualify = "" if own_unit else "boundary::"
        calls = [qualify + name + "()" for name in symbols]
        answer = "pub fn answer(secret: i64) -> i64 effects {} { return wrapping_add(wrapping_add(secret, " + calls[0] + "), " + calls[1] + "); }"
        files = {"lib.hepta": declarations + " " + answer if own_unit else "import boundary; " + answer,
                 "main.hepta": self.main("lib::answer(7)", 10)}
        if not own_unit:
            files["boundary.hepta"] = declarations
        return files, symbols

    def check_freshness(self, own_unit):
        files, symbols = self.freshness_files(own_unit)
        result = self.execute_c(files)
        binding = self.library_function(result).params[0].name
        self.assertNotIn("h_" + binding, symbols)
        self.assertRegex(binding, r"^M[0-9a-f]{16}_[0-9]+_secret$")
        self.assertTrue(set(symbols) <= {f.name for f in result.program.functions})
        self.assertTrue(set(symbols) <= {x.value for x in walk(result.program) if isinstance(x, Expr) and x.kind == "call"})

    def test_generated_name_avoids_sibling_raw_c_symbols(self):
        self.check_freshness(False)

    def test_generated_name_avoids_own_unit_raw_c_symbols(self):
        self.check_freshness(True)

    def test_public_cli_accepts_colliding_locals_and_preserves_boundaries(self):
        entry = self.project(self.matrix_files("parameter", "root_private"))
        for backend in ("c", "rust"):
            with self.subTest(backend=backend, control="accepted"):
                proc = subprocess.run([sys.executable, "-m", "hepta", "check", str(entry), "--backend", backend, "--frontend-only"], cwd=ROOT, capture_output=True, text=True, timeout=30)
                self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
                self.assertTrue(json.loads(proc.stdout)["ok"])
        entry = self.project({"lib.hepta": 'export "C" fn answer(switch: i64) -> i64 effects {} { return switch; }',
                              "main.hepta": self.main("7", prefix="import lib; " + HELPER.replace("secret", "switch"))})
        proc = subprocess.run([sys.executable, "-m", "hepta", "check", str(entry), "--backend", "c", "--frontend-only"], cwd=ROOT, capture_output=True, text=True, timeout=30)
        self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("E_C_IDENTIFIER", [d["code"] for d in json.loads(proc.stdout)["diagnostics"]])

    def test_native_rust_parity_after_actual_c_controls(self):
        cases = [self.matrix_files(binder, "root_private") for binder in ("parameter", "let", "for")]
        cases += [self.qualified_files(), self.borrowed_files(), self.match_files(), self.freshness_files(False)[0], self.alias_files()]
        # Fail before any skip if a prerequisite frontend/native C control
        # fails. A Rust skip must not claim failed C controls completed.
        for files in cases:
            self.execute_c(files)
            self.frontend(files, "rust")
        self.assertEqual(len(cases), 8)
        try:
            rustc = find_rustc(os.environ.get("RUSTC"))
        except HeptaError as error:
            if error.diagnostic.code != "E_TOOLCHAIN":
                raise
            self.skipTest("Eight frontend and sixteen actual GCC O0/O3+UBSan controls passed; real Rust compiler unavailable")
        for index, files in enumerate(cases):
            with self.subTest(case=index, backend="rust"):
                result = self.frontend(files, "rust")
                built = compile_rust(result.rust, rustc=rustc, crate_type="bin", output=self.root / ("rust-" + str(index)))
                self.assertTrue(built["ok"], built)
                self.run_artifact(built["artifact"])


if __name__ == "__main__":
    unittest.main()
