"""Cross-module generic identities, bounded finite native controls and refusals.

All executed programs are finite scalar/record/enum programs. Owned capability
checks are frontend-only. CLI subprocesses use the imported compiler's root,
so the identical tests can also be loaded against an independent baseline.
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
from hepta.ast import Expr, HeptaError, Span, Type
from hepta.backend import compile_rust, find_rustc
from hepta.c_backend import compile_c
from hepta.checker import check
from hepta.modules import load_project
from hepta.parser import parse
from hepta.pipeline import analyze_project, interface

ROOT = Path(hepta.__file__).resolve().parents[1]
IDENTITY = "pub fn answer<Secret>(value:Secret)->Secret effects {} {return value;}"
NOMINAL = "struct Secret {value:i32}"


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


class ModuleGenericParameterScopeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hepta-generic-scope-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def files(self, library=IDENTITY, call="lib::answer::<i32>(42)", nominal=NOMINAL, **extra):
        return {"lib.hepta": library,
                "main.hepta": "import lib; " + nominal + " fn main()->i32 effects {} {return " + call + ";}",
                **extra}

    def project(self, files):
        for old in self.root.glob("*.hepta"):
            old.unlink()
        for name, source in files.items():
            (self.root / name).write_text(source, encoding="utf-8")
        return self.root / "main.hepta"

    def frontend(self, files, backend="c"):
        result = analyze_project(self.project(files), backend=backend, native=False, crate_type="bin")
        self.assertTrue(result.report["ok"], result.report)
        self.assertEqual(result.report["status"], "frontend_only")
        return result

    def reject(self, files, code, message=None):
        try:
            result = analyze_project(self.project(files), backend="c", native=False, crate_type="bin")
        except HeptaError as error:
            self.assertEqual(error.diagnostic.code, code)
            if message is not None:
                self.assertIn(message, error.diagnostic.message)
            return None
        self.assertFalse(result.report["ok"], result.report)
        diagnostics = result.report["diagnostics"]
        self.assertIn(code, [d["code"] for d in diagnostics], diagnostics)
        if message is not None:
            self.assertTrue(any(d["code"] == code and message in d["message"] for d in diagnostics), diagnostics)
        return result

    def run_artifact(self, artifact):
        run = subprocess.run([artifact], capture_output=True, text=True, timeout=5)
        self.assertEqual((run.returncode, run.stdout, run.stderr), (42, "", ""))

    def execute_c(self, files):
        self.assertIsNotNone(shutil.which("gcc"), "Actual GCC is required")
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

    def function(self, program, name="answer"):
        return next(f for f in program.functions if f.span.path == str(self.root / "lib.hepta")
                    and f.name.endswith("_" + name))

    def record_files(self):
        return self.files("pub struct Box<Secret>{value:Secret} pub fn answer()->i32 effects {} "
                          "{let v=Box::<i32>{value:42};return v.value;}", "lib::answer()")

    def enum_files(self):
        return self.files("pub enum Box<Secret>{Value(Secret)} pub fn answer()->i32 effects {} "
                          "{let v=Box::<i32>::Value(42);match v{Box::Value(n)=>{return n;}}}", "lib::answer()")

    def test_scalar_root_private_public_struct_and_enum_collisions_execute(self):
        for nominal in (NOMINAL, "pub " + NOMINAL, "enum Secret{Value}"):
            with self.subTest(nominal=nominal):
                self.execute_c(self.files(nominal=nominal))

    def test_renamed_root_parameter_and_unrelated_sibling_controls_execute(self):
        for files in (self.files(nominal=NOMINAL.replace("Secret", "Renamed")),
                      self.files(library=IDENTITY.replace("Secret", "T")),
                      self.files(nominal="import model;", **{"model.hepta": NOMINAL})):
            with self.subTest(files=files):
                self.execute_c(files)

    def test_generic_record_and_enum_collisions_execute(self):
        for files in (self.record_files(), self.enum_files()):
            with self.subTest(library=files["lib.hepta"]):
                self.execute_c(files)

    def test_copy_bounds_keys_and_finite_forwarding_execute(self):
        library = ("fn helper<T:Copy>(value:T)->T effects {} {return value;} "
                   "pub fn answer<Secret:Copy>(value:Secret)->Secret effects {} {return helper::<Secret>(value);}")
        result = self.execute_c(self.files(library))
        fn = self.function(result.program)
        bound = fn.type_params[0]
        self.assertNotEqual(bound, "Secret")
        self.assertEqual(fn.type_bounds, {bound: "Copy"})
        call = next(n for n in nodes(fn) if isinstance(n, Expr) and n.kind == "call")
        self.assertEqual(call.type_args, (Type(bound),))

    def test_nested_types_and_explicit_record_enum_constructor_arguments_execute(self):
        library = ("struct Box<T>{value:T} enum Choice<T>{Value(T)} "
                   "fn wrap<Secret>(value:Secret)->Box<Secret> effects {} {return Box::<Secret>{value:value};} "
                   "fn select<Secret>(value:Secret)->Choice<Secret> effects {} {return Choice::<Secret>::Value(value);} "
                   "pub fn answer()->i32 effects {} {let box=wrap::<i32>(42);"
                   "let chosen=select::<Box<i32>>(box);match chosen{Choice::Value(v)=>{return v.value;}}}")
        result = self.execute_c(self.files(library, "lib::answer()"))
        for name in ("wrap", "select"):
            fn = self.function(result.program, name)
            bound = fn.type_params[0]
            self.assertNotEqual(bound, "Secret")
            self.assertEqual(fn.return_type.args, (Type(bound),))
            self.assertTrue(any(isinstance(n, Expr) and n.type_args == (Type(bound),) for n in nodes(fn)))

    def test_qualified_public_nominal_argument_executes(self):
        files = self.files(call="42", **{"model.hepta": "pub struct Cell{value:i32}"})
        files["main.hepta"] = ("import lib;import model as m;" + NOMINAL + " fn main()->i32 effects {} "
                               "{let v=lib::answer::<m::Cell>(m::Cell{value:42});return v.value;}")
        self.execute_c(files)

    def test_generic_parameter_never_grants_unqualified_or_private_nominal_access(self):
        for type_name, expected in (("Hidden", "E_MODULE_SCOPE"), ("m::Hidden", "E_MODULE_PRIVATE")):
            with self.subTest(type_name=type_name):
                files = self.files("import model as m; fn helper<T>(value:T)->T effects {} {return value;} "
                                   "pub fn answer<Secret>(value:Secret)->Secret effects {} "
                                   "{return helper::<" + type_name + ">(value);}", call="42",
                                   nominal=NOMINAL + " struct Hidden{value:i32}",
                                   **{"model.hepta": "struct Hidden{value:i32}"})
                self.reject(files, expected)

    def test_generic_field_access_cannot_inherit_root_nominal_fields(self):
        files = self.files("pub fn answer<Secret>(value:Secret)->i32 effects {} {return value.value;}", call="42")
        result = self.reject(files, "E_UNKNOWN_FIELD")
        self.assertNotIn("E_GENERIC_PARAMETER", [d["code"] for d in result.report["diagnostics"]])

    def test_owned_bound_identity_and_capability_refusals_remain(self):
        declaration = "pub fn answer<Secret:Owned>(value:take Secret)->Secret effects {} {return move value;}"
        result = self.frontend(self.files(declaration, call="42"))
        fn = self.function(result.program)
        self.assertNotEqual(fn.type_params, ("Secret",))
        self.assertEqual(fn.type_bounds, {fn.type_params[0]: "Owned"})
        self.assertEqual(fn.params[0].type.name, fn.type_params[0])
        cases = ((declaration.replace("return move value", "return value"), "E_MOVE_REQUIRED"),
                 (declaration.replace("value:take Secret", "value:Secret"), "E_LINEAR_MODE"),
                 ("fn copy<T:Copy>(value:T)->T effects {} {return value;} " + declaration.replace("return move value", "return move copy::<Secret>(move value)"), "E_GENERIC_COPY"))
        for library, code in cases:
            with self.subTest(code=code):
                self.reject(self.files(library, call="42"), code)
        self.reject(self.files(declaration, call="lib::answer::<i32>(move 42)"), "E_GENERIC_OWNED")

    def test_abstract_copy_cannot_be_forwarded_as_owned_or_accept_an_owner(self):
        library = ("fn owned<T:Owned>(value:take T)->T effects {} {return move value;} "
                   "pub fn answer<Secret:Copy>(value:Secret)->Secret effects {} "
                   "{return owned::<Secret>(move value);}")
        self.reject(self.files(library, call="42"), "E_GENERIC_OWNED")
        for declaration in (IDENTITY, IDENTITY.replace("<Secret>", "<Secret:Copy>")):
            with self.subTest(declaration=declaration):
                files = self.files(declaration, call="42")
                files["main.hepta"] = ("import lib;" + NOMINAL + " fn main()->i32 effects {alloc,block,panic} "
                                       "{let value=lib::answer::<Buffer<u8>>(move buffer(1));drop(move value);return 42;}")
                self.reject(files, "E_GENERIC_COPY")

    def test_unrelated_root_owned_payload_does_not_infect_copy_parameter(self):
        self.execute_c(self.files(nominal="struct Secret{value:Buffer<u8>}"))

    def test_duplicates_reserved_invalid_bounds_unused_and_arity_still_reject(self):
        cases = ((IDENTITY.replace("<Secret>", "<Secret,Secret>"), "42", "E_GENERIC_PARAMETER", "Secret"),
                 (IDENTITY.replace("Secret", "i32"), "42", "E_GENERIC_PARAMETER", "i32"),
                 (IDENTITY.replace("<Secret>", "<Secret:Send>"), "42", "E_GENERIC_BOUND", "Send"),
                 ("pub struct Box<Secret>{value:i32}", "42", "E_GENERIC_UNUSED", None),
                 (IDENTITY, "lib::answer::<i32,i32>(42)", "E_GENERIC_ARITY", None))
        for library, call, code, message in cases:
            with self.subTest(code=code, library=library):
                result = self.reject(self.files(library, call=call), code, message)
                if code == "E_GENERIC_BOUND":
                    diagnostic = next(d for d in result.report["diagnostics"] if d["code"] == code)
                    self.assertEqual(diagnostic["message"], "unsupported constraint Secret: Send; expected Copy or Owned")
                    self.assertEqual(diagnostic["span"]["path"], str(self.root / "lib.hepta"))
                    fn = self.function(result.program)
                    self.assertEqual(fn.type_params, ("Secret",))
                    self.assertEqual(fn.type_bounds, {"Secret": "Send"})

    def test_existing_same_source_shadowing_matrix_is_unchanged(self):
        # Keep this inherited method's identity while explicitly reconciling
        # the imported acceptance that #663 deliberately preserved.
        self.reject({"main.hepta": NOMINAL + IDENTITY + " fn main()->i32 effects {} {return answer::<i32>(42);}"},
                    "E_GENERIC_PARAMETER", "Secret")
        rejected = self.reject(self.files(NOMINAL + IDENTITY, nominal=""), "E_GENERIC_PARAMETER", "Secret")
        self.assertIsNotNone(rejected.checked)
        self.assertEqual([d["code"] for d in rejected.report["diagnostics"]], ["E_GENERIC_PARAMETER"])
        self.assertEqual(rejected.report["diagnostics"][0]["phase"], "check")
        self.reject(self.files(NOMINAL + IDENTITY), "E_GENERIC_PARAMETER", "Secret")
        self.reject(self.files("pub struct Secret<Secret>{value:Secret} pub fn answer()->i32 effects {} "
                               "{let v=Secret::<i32>{value:42};return v.value;}", "lib::answer()", nominal=""),
                    "E_GENERIC_PARAMETER", "Secret")
        self.execute_c(self.files("pub struct Secret<T>{value:T} pub fn answer()->i32 effects {} "
                                  "{let v=Secret::<i32>{value:42};return v.value;}", "lib::answer()", nominal=""))
        self.execute_c({"lib.hepta": "pub " + NOMINAL,
                        "main.hepta": "import lib;" + IDENTITY + " fn main()->i32 effects {} {return answer::<i32>(42);}"})

    def test_repeated_load_preserves_source_spans_names_and_interface_identity(self):
        files = self.files(IDENTITY.replace("value", "Secret"))
        entry = self.project(files)
        first, second = load_project(entry), load_project(entry)
        self.assertEqual(first.program, second.program)
        self.assertEqual(first.identity, second.identity)
        self.assertEqual(first.modules, second.modules)
        self.assertTrue(first.unchanged())
        original = parse(files["lib.hepta"], str(self.root / "lib.hepta")).functions[0]
        fn = self.function(first.program)
        bound = fn.type_params[0]
        self.assertNotEqual(bound, "Secret")
        self.assertEqual(fn.params[0].name, "Secret")
        self.assertEqual(fn.params[0].type.name, bound)
        self.assertEqual(fn.return_type.name, bound)
        self.assertEqual(fn.span, original.span)
        self.assertEqual(fn.body_span, original.body_span)
        self.assertEqual(fn.params[0].span, original.params[0].span)
        self.assertEqual([n.span for n in nodes(fn) if isinstance(n, Expr)],
                         [n.span for n in nodes(original) if isinstance(n, Expr)])
        self.assertEqual([n.value for n in nodes(fn) if isinstance(n, Expr) and n.kind == "name"], ["Secret"])
        one, two = self.frontend(files), self.frontend(files)
        self.assertEqual(one.c, two.c)
        self.assertEqual(interface(one.program), interface(two.program))
        declaration = next(f for f in interface(first.program)["functions"] if f["name"] == fn.name)
        self.assertEqual(declaration["type_params"], [bound])

    def test_lifetime_field_and_qualified_nominal_names_are_not_type_parameters(self):
        # Loader inspection only: lifetime/return-origin strings and nominal
        # expression names must not be rewritten as bound Type identities.
        library = ("import model as m; "
                   "pub fn answer<'Secret,Secret>(Secret:read 'Secret Secret)->read 'Secret Secret "
                   "from Secret effects {} {return read Secret;} "
                   "pub struct Box<Secret>{Secret:Secret, other:m::Secret}")
        files = self.files(library, call="42", **{"model.hepta": "pub struct Secret{value:i32}"})
        entry = self.project(files)
        program = load_project(entry).program
        original = parse(library, str(self.root / "lib.hepta"))
        fn = self.function(program)
        before = original.functions[0]
        self.assertNotEqual(fn.type_params[0], "Secret")
        self.assertEqual(fn.lifetime_params, before.lifetime_params)
        self.assertEqual(fn.return_origin, before.return_origin)
        self.assertEqual(fn.params[0].lifetime, before.params[0].lifetime)
        self.assertEqual(fn.return_lifetime, before.return_lifetime)
        self.assertEqual(fn.return_type.lifetimes, before.return_type.lifetimes)
        self.assertEqual(fn.params[0].name, "Secret")
        box = next(s for s in program.structs if s.name.endswith("_Box"))
        model = next(s for s in program.structs if s.span.path == str(self.root / "model.hepta"))
        self.assertEqual(box.fields[0].name, "Secret")
        self.assertEqual(box.fields[0].type.name, box.type_params[0])
        self.assertEqual(box.fields[1].type.name, model.name)
        self.assertNotEqual(box.fields[1].type.name, box.type_params[0])

    def test_unaffected_parameter_and_same_spelled_value_names_stay_unchanged(self):
        files = self.files(IDENTITY.replace("<Secret>", "<Secret,T>"), call="42")
        fn = self.function(load_project(self.project(files)).program)
        self.assertNotEqual(fn.type_params[0], "Secret")
        self.assertEqual(fn.type_params[1], "T")
        self.assertEqual(fn.params[0].name, "value")
        self.assertNotEqual(fn.type_params[0], fn.type_params[1])

    def test_unrelated_borrowed_root_does_not_infect_generic_capabilities(self):
        # Checker-only on both spellings: borrowed storage is outside the C
        # backend, so a C-backend refusal would not establish this invariant.
        declarations = (
            (IDENTITY.replace("<Secret>", "<Secret:Copy>"), []),
            ("pub fn answer<Secret:Owned>(value:take Secret)->Secret effects {} {return move value;}", []),
            ("pub fn answer<Secret:Owned>(value:take [Secret;2])->Unit effects {alloc,block} {drop(move value);}", ["E_NESTED_LINEAR"]),
            ("pub fn answer<Secret:Owned>(value:read Secret)->Unit effects {alloc,block} {drop(move value);}", ["E_MOVE_BORROW"]),
        )
        for library, required in declarations:
            with self.subTest(library=library):
                observations = []
                for name in ("Secret", "Renamed"):
                    files = self.files(library, call="42", nominal="struct " + name + "<'a>{data:read 'a i32}")
                    checked = check(load_project(self.project(files)).program)
                    codes = [d.code for d in checked.diagnostics]
                    self.assertNotIn("E_GENERIC_PARAMETER", codes)
                    for code in required:
                        self.assertIn(code, codes)
                    if not required:
                        self.assertTrue(checked.ok, [d.to_dict() for d in checked.diagnostics])
                    observations.append((checked.ok, codes))
                self.assertEqual(observations[0], observations[1])

    def test_internal_parameter_freshness_avoids_nominal_and_function_symbols(self):
        library = ("struct T0_Secret{value:i32} fn T1_Secret()->i32 effects {} {return 42;} "
                   + IDENTITY.replace("<Secret>", "<Secret:Copy>"))
        result = self.execute_c(self.files(library))
        fn = self.function(result.program)
        prefix = "M" + hashlib.sha256(b"lib.hepta").hexdigest()[:16] + "_"
        self.assertEqual(fn.type_params, (prefix + "T2_Secret",))
        occupied = {d.name for d in [*result.program.functions, *result.program.structs, *result.program.enums]}
        self.assertNotIn(fn.type_params[0], occupied)
        self.assertEqual(fn.params[0].type.name, fn.type_params[0])
        self.assertEqual(fn.type_bounds, {fn.type_params[0]: "Copy"})

    def test_public_cli_uses_actual_imported_compiler_for_acceptance_and_refusal(self):
        cases = ((self.files(), None),
                 (self.files(IDENTITY.replace("<Secret>", "<Secret,Secret>"), call="42"), "E_GENERIC_PARAMETER"))
        for files, code in cases:
            entry = self.project(files)
            for backend in ("c", "rust"):
                with self.subTest(backend=backend, expected=code):
                    run = subprocess.run([sys.executable, "-m", "hepta", "check", str(entry), "--backend", backend,
                                          "--frontend-only"], cwd=ROOT,
                                         env=dict(os.environ, PYTHONPATH=str(ROOT), PYTHONDONTWRITEBYTECODE="1"),
                                         capture_output=True, text=True, timeout=30)
                    self.assertEqual(run.stderr, "")
                    report = json.loads(run.stdout)
                    self.assertEqual(run.returncode, 0 if code is None else 1, report)
                    self.assertEqual(report["ok"], code is None)
                    if code:
                        self.assertIn(code, [d["code"] for d in report["diagnostics"]])

    def test_real_rust_parity_after_scalar_record_enum_c_controls(self):
        cases = (self.files(), self.record_files(), self.enum_files())
        for files in cases:
            self.execute_c(files)
            self.frontend(files, "rust")
        try:
            rustc = find_rustc(os.environ.get("RUSTC"))
        except HeptaError as error:
            if error.diagnostic.code != "E_TOOLCHAIN":
                raise
            self.skipTest("Three C/Rust frontend controls and six GCC O0/O3+UBSan executions passed; real rustc unavailable")
        for index, files in enumerate(cases):
            result = self.frontend(files, "rust")
            for optimize in (False, True):
                with self.subTest(case=index, optimize=optimize):
                    built = compile_rust(result.rust, rustc=rustc, crate_type="bin", optimize=optimize,
                                         output=self.root / ("rust-" + str(index) + "-" + str(optimize)))
                    self.assertTrue(built["ok"], built)
                    self.run_artifact(built["artifact"])


if __name__ == "__main__":
    unittest.main()
