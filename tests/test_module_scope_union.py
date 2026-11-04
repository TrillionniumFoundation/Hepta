"""Independent intersections of module scope and lexical binding isolation.

Native fixtures contain only finite scalar calls. Nominal references are
inspected at module/frontend boundaries, never compiled or executed here.
Public CLI checks import the actual on-disk checkout, without monkeypatches.
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
from hepta.pipeline import analyze_project, interface


ROOT = Path(hepta.__file__).resolve().parents[1]
PRIVATE = "fn secret() -> i64 effects {} { return 91; }"


def nodes(value):
    yield value
    if isinstance(value, dict):
        for child in value.values():
            yield from nodes(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            yield from nodes(child)
    elif is_dataclass(value) and not isinstance(value, Span):
        for field in fields(value):
            yield from nodes(getattr(value, field.name))


class ModuleScopeUnionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hepta-scope-union-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def project(self, files):
        for old in self.root.glob("*.hepta"):
            old.unlink()
        for name, source in files.items():
            (self.root / name).write_text(source, encoding="utf-8")
        return self.root / "main.hepta"

    def main(self, call="lib::answer(7)", expected=12, declarations=PRIVATE):
        return ("import lib; " + declarations + "\n"
                "fn main() -> i32 effects {} { if " + call + " == " + str(expected)
                + " { return 0; } else { return 1; } }")

    def qualified_files(self):
        return {
            "api.hepta": "pub fn increment() -> i64 effects {} { return 5; }",
            "lib.hepta": "import api as secret;\n"
                         "pub fn answer(secret: i64) -> i64 effects {} {\n"
                         "    return wrapping_add(secret, secret::increment());\n}",
            "main.hepta": self.main(),
        }

    def private_call_files(self):
        files = self.qualified_files()
        files["lib.hepta"] = files["lib.hepta"].replace("secret::increment()", "secret()")
        return files

    def nominal_files(self):
        return {
            "lib.hepta": "fn ignore<T>(value: i64) -> i64 effects {} { return value; }\n"
                         "pub fn answer(secret: i64) -> i64 effects {} {\n"
                         "    return ignore::<Secret>(secret);\n}",
            "main.hepta": self.main(expected=7, declarations=PRIVATE + " struct Secret { value: i64 }"),
        }

    def freshness_files(self):
        prefix = "M" + hashlib.sha256(b"lib.hepta").hexdigest()[:16]
        raw_symbol = "h_" + prefix + "_0_secret"
        files = {
            "api.hepta": 'export "C" fn ' + raw_symbol + '() -> i64 effects {} { return 5; }',
            "lib.hepta": "import api as secret;\n"
                         "pub fn answer(secret: i64) -> i64 effects {} {\n"
                         "    return wrapping_add(secret, secret::" + raw_symbol + "());\n}",
            "main.hepta": self.main(),
        }
        return files, raw_symbol

    def library_function(self, program, name="answer"):
        return next(f for f in program.functions
                    if f.span.path == str(self.root / "lib.hepta") and f.name.endswith("_" + name))

    def frontend(self, files, backend="c"):
        result = analyze_project(self.project(files), backend=backend, native=False, crate_type="bin")
        self.assertTrue(result.report["ok"], result.report)
        self.assertEqual(result.report["status"], "frontend_only")
        return result

    def run_artifact(self, artifact):
        result = subprocess.run([artifact], capture_output=True, text=True, timeout=5)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, "", ""))

    def execute_c(self, files):
        self.assertIsNotNone(shutil.which("gcc"), "Actual GCC is a prerequisite, not an optional skip")
        result = self.frontend(files)
        self.assertIsNotNone(result.c)
        for optimize in (False, True):
            with self.subTest(backend="c", optimize=optimize):
                built = compile_c(result.c, cc="gcc", crate_type="bin", optimize=optimize,
                                  sanitize=True, output=self.root / ("o3" if optimize else "o0"))
                self.assertTrue(built["ok"], built)
                self.assertFalse(built["check_only"])
                self.assertFalse(built["rustc_used"])
                self.assertIn("-O3" if optimize else "-O0", built["flags"])
                self.assertIn("-fsanitize=undefined", built["flags"])
                self.run_artifact(built["artifact"])
        return result

    def scope_diagnostic(self, files, *, symbol="secret", role="symbol", source_span=None):
        entry = self.project(files)
        diagnostics = []
        for _ in range(2):
            with self.assertRaises(HeptaError) as caught:
                load_project(entry)
            diagnostic = caught.exception.diagnostic
            self.assertEqual(diagnostic.code, "E_MODULE_SCOPE")
            self.assertEqual(diagnostic.phase, "module")
            self.assertEqual(diagnostic.message,
                             "Unqualified " + role + " is not declared in this module: " + symbol)
            self.assertEqual(diagnostic.span.path, str(self.root / "lib.hepta"))
            if source_span is not None:
                self.assertEqual(diagnostic.span, source_span)
            diagnostics.append(diagnostic.to_dict())
        self.assertEqual(diagnostics[0], diagnostics[1])
        return diagnostics[0]

    def test_qualified_public_call_and_colliding_alias_local_execute(self):
        result = self.execute_c(self.qualified_files())
        fn = self.library_function(result.program)
        local = fn.params[0].name
        target = next(f.name for f in result.program.functions
                      if f.span.path == str(self.root / "api.hepta"))
        self.assertRegex(local, r"^M[0-9a-f]{16}_[0-9]+_secret$")
        calls = [node.value for node in nodes(fn) if isinstance(node, Expr) and node.kind == "call"]
        self.assertIn(target, calls)
        self.assertNotIn(local, calls)
        self.assertIn(local, [node.value for node in nodes(fn)
                              if isinstance(node, Expr) and node.kind == "name"])

    def test_colliding_local_never_launders_unqualified_private_call(self):
        files = self.private_call_files()
        parsed = parse(files["lib.hepta"], str(self.root / "lib.hepta"))
        call = next(node for node in nodes(parsed)
                    if isinstance(node, Expr) and node.kind == "call" and node.value == "secret")
        self.scope_diagnostic(files, source_span=call.span)

    def test_scalar_local_never_launders_nominal_type_argument(self):
        # Only the module loader runs: no object construction, layout, native
        # compilation or execution is needed to establish this rejection.
        self.scope_diagnostic(self.nominal_files(), symbol="Secret", role="type",
                              source_span=Span(path=str(self.root / "lib.hepta")))

    def test_nominal_scope_controls_keep_local_isolation_frontend_only(self):
        cases = {
            "same_module": ("struct Secret { value: i64 } ", "Secret", {}),
            "explicit_alias": ("import model as m; ", "m::Secret",
                               {"model.hepta": "pub struct Secret { value: i64 }"}),
        }
        for label, (prefix, typename, extra) in cases.items():
            with self.subTest(case=label):
                files = {"lib.hepta": prefix + "pub fn answer(secret: i64, unused: " + typename
                         + ") -> i64 effects {} { return secret; }",
                         "main.hepta": self.main("7", 7, PRIVATE + " struct Secret { value: i64 }"),
                         **extra}
                result = self.frontend(files)
                fn = self.library_function(result.program)
                self.assertNotEqual(fn.params[0].name, "secret")
                self.assertRegex(fn.params[1].type.name, r"^M[0-9a-f]{16}_Secret$")
                type_source = "lib.hepta" if label == "same_module" else "model.hepta"
                expected = next(item["symbols"]["Secret"] for item in result.project.modules
                                if item["path"] == str(self.root / type_source))
                self.assertEqual(fn.params[1].type.name, expected)
        # A generic parameter is not an undeclared nominal reference. The
        # independent checker restriction on shadowing a root type remains.
        files = {"lib.hepta": "pub fn answer<Secret>(secret: Secret) -> Secret effects {} { return secret; }",
                 "main.hepta": self.main("7", 7, PRIVATE + " struct Secret { value: i64 }")}
        entry = self.project(files)
        loaded = load_project(entry)
        fn = self.library_function(loaded.program)
        self.assertEqual((fn.type_params, fn.params[0].type.name, fn.return_type.name),
                         (("Secret",), "Secret", "Secret"))
        self.assertNotEqual(fn.params[0].name, "secret")
        checked = analyze_project(entry, backend="c", native=False, crate_type="bin")
        self.assertFalse(checked.report["ok"])
        self.assertEqual([d["code"] for d in checked.report["diagnostics"]], ["E_GENERIC_PARAMETER"])

    def test_protected_export_precedes_c_keyword_checks_without_changing_abi(self):
        for name in ("secret", "switch"):
            with self.subTest(protected=name):
                declaration = 'export "C" fn boundary(' + name + ': i64) -> i64 effects {} { return ' + name + '; }'
                files = {"lib.hepta": declaration,
                         "main.hepta": self.main("7", 7, PRIVATE.replace("secret", name))}
                original = parse(declaration, str(self.root / "lib.hepta"))
                reference = next(node for node in nodes(original)
                                 if isinstance(node, Expr) and node.kind == "name")
                self.scope_diagnostic(files, symbol=name, source_span=reference.span)
                self.assertIn("int64_t boundary(int64_t " + name + ");", emit_header(original))
                # A literal return does not resolve the protected parameter.
                # Its spelling still reaches the existing checker unchanged.
                files["lib.hepta"] = declaration.replace("return " + name + ";", "return 7;")
                result = analyze_project(self.project(files), backend="c", native=False, crate_type="bin")
                self.assertFalse(result.report["ok"])
                expected_codes = ["E_NAME_COLLISION"] if name == "secret" else ["E_C_IDENTIFIER", "E_NAME_COLLISION"]
                self.assertEqual([d["code"] for d in result.report["diagnostics"]], expected_codes)
                fn = next(f for f in result.program.functions if f.name == "boundary")
                self.assertEqual(fn.params[0].name, name)
                self.assertIn("int64_t boundary(int64_t " + name + ");", emit_header(result.program))
        for label, declaration, declarations in (
            ("extern_collision", 'extern "C" fn boundary(switch: i64) -> i64 effects {ffi};', PRIVATE.replace("secret", "switch")),
            ("noncolliding_export", 'export "C" fn boundary(switch: i64) -> i64 effects {} { return switch; }', PRIVATE),
        ):
            with self.subTest(case=label):
                files = {"lib.hepta": declaration, "main.hepta": self.main("7", 7, declarations)}
                result = analyze_project(self.project(files), backend="c", native=False, crate_type="bin")
                self.assertFalse(result.report["ok"])
                self.assertEqual([d["code"] for d in result.report["diagnostics"]], ["E_C_IDENTIFIER"])
                fn = next(f for f in result.program.functions if f.name == "boundary")
                self.assertEqual(fn.params[0].name, "switch")
                self.assertIn("int64_t boundary(int64_t switch);", emit_header(result.program))
                public = next(f for f in interface(result.program)["functions"] if f["name"] == "boundary")
                self.assertEqual(public["params"][0]["name"], "switch")

    def test_raw_c_freshness_survives_scope_guard_and_alias_collision(self):
        files, raw_symbol = self.freshness_files()
        result = self.execute_c(files)
        fn = self.library_function(result.program)
        local = fn.params[0].name
        self.assertNotEqual("h_" + local, raw_symbol)
        self.assertNotIn(local, {f.name for f in result.program.functions})
        self.assertIn(raw_symbol, [node.value for node in nodes(fn)
                                  if isinstance(node, Expr) and node.kind == "call"])
        self.assertIn("int64_t " + raw_symbol + "(void);", result.c)
        self.assertIn("h_" + local, result.c)
        self.assertIn("int64_t " + raw_symbol + "(void);", emit_header(result.program))

    def test_repeated_load_retains_resolved_identity_and_original_spans(self):
        files = self.qualified_files()
        entry = self.project(files)
        first, second = load_project(entry), load_project(entry)
        self.assertEqual(first.program, second.program)
        self.assertEqual(first.identity, second.identity)
        self.assertEqual(first.modules, second.modules)
        self.assertTrue(first.unchanged())
        resolved = self.library_function(first.program)
        original = parse(files["lib.hepta"], str(self.root / "lib.hepta")).functions[0]
        self.assertNotEqual(resolved.params[0].name, original.params[0].name)
        self.assertEqual((resolved.span, resolved.body_span, resolved.params[0].span),
                         (original.span, original.body_span, original.params[0].span))
        self.assertEqual([node.span for node in nodes(resolved) if isinstance(node, Expr)],
                         [node.span for node in nodes(original) if isinstance(node, Expr)])
        one = analyze_project(entry, backend="c", native=False, crate_type="bin")
        two = analyze_project(entry, backend="c", native=False, crate_type="bin")
        self.assertTrue(one.report["ok"], one.report)
        self.assertTrue(two.report["ok"], two.report)
        self.assertEqual(one.c, two.c)
        self.assertEqual(interface(one.program), interface(two.program))

    def test_public_cli_uses_disk_candidate_for_intersections(self):
        cases = (("accepted", self.qualified_files(), None),
                 ("private_call", self.private_call_files(), "Unqualified symbol is not declared in this module: secret"),
                 ("nominal", self.nominal_files(), "Unqualified type is not declared in this module: Secret"),
                 ("protected_export", {"lib.hepta": 'export "C" fn boundary(switch: i64) -> i64 effects {} { return switch; }',
                                       "main.hepta": self.main("7", 7, PRIVATE.replace("secret", "switch"))},
                  "Unqualified symbol is not declared in this module: switch"))
        for label, files, message in cases:
            entry = self.project(files)
            for backend in ("c", "rust"):
                with self.subTest(case=label, backend=backend):
                    result = subprocess.run(
                        [sys.executable, "-m", "hepta", "check", str(entry), "--backend", backend, "--frontend-only"],
                        cwd=ROOT, env=dict(os.environ, PYTHONPATH=str(ROOT), PYTHONDONTWRITEBYTECODE="1"),
                        capture_output=True, text=True, timeout=30)
                    self.assertEqual(result.stderr, "")
                    report = json.loads(result.stdout)
                    self.assertEqual(result.returncode, 0 if message is None else 1, report)
                    self.assertEqual(report["ok"], message is None)
                    if message is None:
                        self.assertEqual(report["status"], "frontend_only")
                    else:
                        self.assertEqual([d["code"] for d in report["diagnostics"]], ["E_MODULE_SCOPE"])
                        self.assertEqual(report["diagnostics"][0]["message"], message)
                        self.assertEqual(report["diagnostics"][0]["phase"], "module")
                        self.assertEqual(report["diagnostics"][0]["span"]["path"], str(self.root / "lib.hepta"))

    def test_native_rust_parity_only_after_scalar_c_prerequisites(self):
        cases = (self.qualified_files(), self.freshness_files()[0])
        for files in cases:
            self.execute_c(files)
            self.frontend(files, "rust")
        try:
            rustc = find_rustc(os.environ.get("RUSTC"))
        except HeptaError as error:
            if error.diagnostic.code != "E_TOOLCHAIN":
                raise
            self.skipTest("Two scalar controls passed C/Rust frontends and four actual GCC O0/O3+UBSan executions; real Rust compiler unavailable")
        for index, files in enumerate(cases):
            result = self.frontend(files, "rust")
            for optimize in (False, True):
                with self.subTest(case=index, backend="rust", optimize=optimize):
                    built = compile_rust(result.rust, rustc=rustc, crate_type="bin", optimize=optimize,
                                         output=self.root / ("rust-" + str(index) + "-" + str(optimize)))
                    self.assertTrue(built["ok"], built)
                    self.run_artifact(built["artifact"])


if __name__ == "__main__":
    unittest.main()
