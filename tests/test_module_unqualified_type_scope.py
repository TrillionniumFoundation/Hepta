"""Source-module nominal types must not bind unrelated flattened declarations.

Fixtures are finite and nonrecursive and make no unsafe foreign calls.
Native controls run real GCC at O0/O3 with UBSan before an optional Rust
parity check; frontend success is not execution.
"""
from __future__ import annotations

import json
from pathlib import Path
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


SECRET = "struct Secret { value: i32 }"
ANSWER = "pub fn answer() -> i32 effects {} { let value: Secret = Secret { value: 42 }; return value.value; }"
MAIN = "import lib; %s fn main() -> i32 effects {} { return lib::answer(); }"


class ModuleUnqualifiedTypeScopeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="hepta-type-scope-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def project(self, lib, main=None, **extra):
        sources = {"lib": lib, "main": main if main is not None else MAIN % SECRET, **extra}
        for name, source in sources.items():
            (self.root / (name + ".hepta")).write_text(source)
        return self.root / "main.hepta"

    def reject_scope(self, lib, main=None):
        entry = self.project(lib, main or (MAIN % SECRET).replace("return lib::answer();", "return 42;"))
        with self.assertRaises(HeptaError) as caught:
            load_project(entry)
        diagnostic = caught.exception.diagnostic
        self.assertEqual(diagnostic.code, "E_MODULE_SCOPE")
        self.assertEqual(diagnostic.phase, "module")
        self.assertEqual(diagnostic.span.path, str(self.root / "lib.hepta"))
        self.assertIn("Secret", diagnostic.message)

    def test_private_entry_struct_annotation_and_constructor(self):
        self.reject_scope(ANSWER)

    def test_public_entry_struct_is_still_not_imported(self):
        self.reject_scope(ANSWER, MAIN % ("pub " + SECRET))

    def test_constructor_without_annotation(self):
        self.reject_scope("pub fn answer()->i32 effects {} { let value=Secret{value:42}; return value.value; }")

    def test_parameter_annotation_without_constructor(self):
        self.reject_scope("pub fn consume(value:Secret)->i32 effects {} {return value.value;}")

    def test_return_annotation_without_constructor(self):
        self.reject_scope("pub fn identity(value:i32)->Secret effects {} {return value;}")

    def test_struct_field_annotation_without_constructor(self):
        self.reject_scope("struct Envelope {value:Secret}")

    def test_enum_payload_annotation_without_constructor(self):
        self.reject_scope("enum Envelope {Empty,Value(Secret)}")

    def test_entry_enum_parameter_annotation(self):
        self.reject_scope("pub fn consume(value:Secret)->i32 effects {} {return 42;}", (MAIN % "enum Secret {Value}").replace("return lib::answer();", "return 42;"))

    def test_nested_generic_annotation(self):
        self.reject_scope("struct Wrapper<T>{value:T} pub fn consume(value:Wrapper<Wrapper<Secret>>)->i32 effects {} {return 42;}")

    def test_generic_constructor_type_argument(self):
        self.reject_scope("struct Wrapper<T>{value:T} pub fn answer()->i32 effects {} {let value=Wrapper::<Secret>{value:42};return 42;}")

    def test_generic_call_type_argument_without_constructor(self):
        self.reject_scope("fn ignore<T>()->i32 effects {} {return 42;} pub fn answer()->i32 effects {} {return ignore::<Secret>();}")

    def test_array_element_annotation(self):
        self.reject_scope("pub fn consume(value:[Secret;1])->i32 effects {} {return 42;}")

    def test_cli_rejects_before_native_backend(self):
        entry = self.project(ANSWER)
        for backend in ("c", "rust"):
            with self.subTest(backend=backend):
                proc = subprocess.run([sys.executable, "-m", "hepta", "check", str(entry), "--backend", backend, "--frontend-only"], cwd=Path(hepta.__file__).resolve().parents[1], capture_output=True, text=True, timeout=30)
                self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
                report = json.loads(proc.stdout)
                self.assertEqual(report["diagnostics"][0]["code"], "E_MODULE_SCOPE")

    def test_private_explicit_alias_still_rejects(self):
        for declaration in (SECRET, "enum Secret {Value}"):
            with self.subTest(declaration=declaration):
                entry = self.project("import model as m; pub fn consume(value:m::Secret)->i32 effects {} {return 42;}", MAIN % "", model=declaration)
                with self.assertRaises(HeptaError) as caught:
                    load_project(entry)
                self.assertEqual(caught.exception.diagnostic.code, "E_MODULE_PRIVATE")

    def test_genuinely_unknown_type_retains_checker_diagnostic(self):
        for declaration in ("", "struct Renamed {value:i32}"):
            with self.subTest(declaration=declaration):
                entry = self.project(ANSWER, MAIN % declaration)
                load_project(entry)  # The module pass must not invent an unknown-type error.
                result = analyze_project(entry, backend="c", native=False)
                self.assertFalse(result.report["ok"])
                codes = [item["code"] for item in result.report["diagnostics"]]
                self.assertNotIn("E_MODULE_SCOPE", codes)
                self.assertIn("E_UNKNOWN_TYPE", codes)

    def test_generic_parameter_collision_keeps_existing_checker_restriction(self):
        entry = self.project("pub fn answer<Secret>(value:Secret)->Secret effects {} {return value;}", (MAIN % SECRET).replace("lib::answer()", "lib::answer::<i32>(42)"))
        result = analyze_project(entry, backend="c", native=False)
        self.assertTrue(result.report["ok"], result.report)
        function = next(fn for fn in result.program.functions if fn.type_params)
        parameter = function.type_params[0]
        self.assertNotEqual(parameter, "Secret")
        self.assertEqual((function.params[0].type.name, function.return_type.name),
                         (parameter, parameter))
        # Keep this inherited method's same-module checker restriction while
        # explicitly reconciling its former unrelated-entry false refusal.
        entry = self.project("", SECRET + " fn answer<Secret>(value:Secret)->Secret effects {} {return value;} fn main()->i32 effects {} {return answer::<i32>(42);}")
        result = analyze_project(entry, backend="c", native=False)
        self.assertFalse(result.report["ok"])
        self.assertEqual([d["code"] for d in result.report["diagnostics"]], ["E_GENERIC_PARAMETER"])
        self.assertIn("Secret", result.report["diagnostics"][0]["message"])

    def test_unimported_sibling_type_remains_unknown(self):
        entry = self.project(ANSWER, "import model; " + MAIN % "", model="pub " + SECRET)
        load_project(entry)
        result = analyze_project(entry, backend="c", native=False)
        self.assertFalse(result.report["ok"])
        self.assertIn("E_UNKNOWN_TYPE", [d["code"] for d in result.report["diagnostics"]])

    def native_controls(self):
        cases = {
            "same_module_struct": (SECRET + ANSWER, MAIN % SECRET, {}),
            "public_alias_struct": ("import model as m; " + ANSWER.replace("Secret", "m::Secret"), MAIN % SECRET, {"model": "pub " + SECRET}),
            "same_module_enum": ("enum Secret{Value(i32)} pub fn answer()->i32 effects {} {let v:Secret=Secret::Value(42);match v {Secret::Value(n)=>{return n;}}}", MAIN % SECRET, {}),
            "public_alias_enum": ("import model as m; pub fn answer()->i32 effects {} {let v:m::Secret=m::Secret::Value(42);match v {m::Secret::Value(n)=>{return n;}}}", MAIN % SECRET, {"model": "pub enum Secret{Value(i32)}"}),
            "generic_parameter": ("pub fn answer<Secret>(value:Secret)->Secret effects {} {return value;}", (MAIN % "").replace("lib::answer()", "lib::answer::<i32>(42)"), {}),
            "generic_struct_parameter": ("struct Wrapper<Secret>{value:Secret} pub fn answer()->i32 effects {} {let v=Wrapper::<i32>{value:42};return v.value;}", MAIN % "", {}),
            "generic_enum_parameter": ("enum Wrapper<Secret>{Value(Secret)} pub fn answer()->i32 effects {} {let v=Wrapper::<i32>::Value(42);match v {Wrapper::Value(n)=>{return n;}}}", MAIN % "", {}),
            "nested_generic": ("struct Wrapper<T>{value:T} pub fn answer()->i32 effects {} {let v:Wrapper<Wrapper<i32>>=Wrapper::<Wrapper<i32>>{value:Wrapper::<i32>{value:42}};return v.value.value;}", MAIN % "", {}),
            "builtin_result_array_primitive": ("pub fn answer()->i32 effects {panic} {let a:[i32;1]=[42];let r:Result<i32,u8>=Result::Ok(a[0]);match r {Result::Ok(n)=>{return n;},Result::Err(e)=>{return 1;}}}", (MAIN % "").replace("effects {}", "effects {panic}"), {}),
        }
        for name, (lib, main, extra) in cases.items():
            with self.subTest(case=name):
                entry = self.project(lib, main, **extra)
                result = analyze_project(entry, backend="c", native=False, crate_type="bin")
                self.assertTrue(result.report["ok"], result.report)
                self.assertTrue(result.c)
                for optimize in (False, True):
                    native = compile_c(result.c, cc="gcc", output=self.root / (name + str(optimize)), optimize=optimize, sanitize=True)
                    self.assertTrue(native["ok"], native)
                    self.assertIn("-O3" if optimize else "-O0", native["flags"])
                    self.assertIn("-fsanitize=undefined", native["flags"])
                    self.assertFalse(native["check_only"])
                    self.assertFalse(native["rustc_used"])
                    self.run_artifact(native["artifact"])
                yield name, entry

    def run_artifact(self, artifact):
        proc = subprocess.run([artifact], capture_output=True, text=True, timeout=5)
        self.assertEqual(proc.returncode, 42, proc.stdout + proc.stderr)
        self.assertEqual(proc.stdout, "")
        self.assertEqual(proc.stderr, "")

    def test_native_gcc_controls_and_optional_rust_parity(self):
        # Do not class-decorate with a Rust skip: all C controls must run first.
        controls = []
        for name, entry in self.native_controls():
            controls.append((name, {p.name: p.read_text() for p in self.root.glob("*.hepta")}))
        self.assertEqual(len(controls), 9)
        try:
            rustc = find_rustc()
        except HeptaError as exc:
            if exc.diagnostic.code != "E_TOOLCHAIN":
                raise
            self.skipTest("All 9 frontend and 18 GCC O0/O3 UBSan controls passed; Rust compiler unavailable")
        for name, sources in controls:
            with self.subTest(case=name, backend="rust"):
                for filename, source in sources.items():
                    (self.root / filename).write_text(source)
                result = analyze_project(self.root / "main.hepta", backend="rust", native=False, crate_type="bin")
                self.assertTrue(result.report["ok"], result.report)
                native = compile_rust(result.rust, rustc=rustc, crate_type="bin", output=self.root / (name + "-rust"))
                self.assertTrue(native["ok"], native)
                self.run_artifact(native["artifact"])


if __name__ == "__main__":
    unittest.main()
