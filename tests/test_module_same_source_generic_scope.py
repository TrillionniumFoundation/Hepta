"""Same-source generic shadowing must survive module flattening.

Negative cases require returned check-phase Analysis/CheckResult diagnostics,
not loader exceptions. Executed controls are finite scalar/record/enum programs;
owned and borrowed cases are frontend-only. The imported compiler determines
CLI subprocess PYTHONPATH, permitting identical tests against another checkout.
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
from hepta.checker import CheckResult, check
from hepta.modules import load_project
from hepta.parser import parse
from hepta.pipeline import Analysis, analyze_project

ROOT = Path(hepta.__file__).resolve().parents[1]
IDENTITY = "pub fn answer<Secret>(value:Secret)->Secret effects {} {return value;}"
NOMINAL = "struct Secret{value:i32}"
MAIN = "fn main()->i32 effects {} {return 42;}"
NATIVE_EXECUTIONS = []
FRONTEND_OBSERVATIONS = []

# The six originally accepted imported forms, without a foreign root nominal.
SHADOWING = {
    "function_struct": (NOMINAL + " " + IDENTITY, "answer::<i32>(42)"),
    "function_enum": ("enum Secret{Value} " + IDENTITY, "answer::<i32>(42)"),
    "record_struct": (NOMINAL + " pub struct Box<Secret>{value:Secret} "
                      "pub fn answer()->i32 effects {} {let v=Box::<i32>{value:42};return v.value;}", "answer()"),
    "enum_struct": (NOMINAL + " pub enum Box<Secret>{Value(Secret)} "
                    "pub fn answer()->i32 effects {} {let v=Box::<i32>::Value(42);"
                    "match v{Box::Value(n)=>{return n;}}}", "answer()"),
    "self_record": ("pub struct Secret<Secret>{value:Secret} "
                    "pub fn answer()->i32 effects {} {let v=Secret::<i32>{value:42};return v.value;}", "answer()"),
    "self_enum": ("pub enum Secret<Secret>{Value(Secret)} "
                  "pub fn answer()->i32 effects {} {let v=Secret::<i32>::Value(42);"
                  "match v{Secret::Value(n)=>{return n;}}}", "answer()"),
}


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


class ModuleSameSourceGenericScopeTests(unittest.TestCase):
    def setUp(self):
        selected = os.environ.get("HEPTA_TEST_ROOT")
        if selected:
            self.assertEqual(ROOT, Path(selected).resolve(), "Compiler imports must use the selected checkout")
        self.temp = tempfile.TemporaryDirectory(prefix="hepta-same-source-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def files(self, library=IDENTITY, call="answer::<i32>(42)", root_nominal="", **extra):
        return {"lib.hepta": library,
                "main.hepta": "import lib as library; " + root_nominal
                + " fn main()->i32 effects {} {return library::" + call + ";}", **extra}

    def project(self, sources):
        for old in self.root.rglob("*.hepta"):
            old.unlink()
        for name, source in sources.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(source, encoding="utf-8")
        return self.root / "main.hepta"

    def analyze(self, sources, backend="c"):
        result = analyze_project(self.project(sources), backend=backend, native=False, crate_type="bin")
        FRONTEND_OBSERVATIONS.append({"test": self.id(), "backend": backend,
                                      "sources": sources, "report": result.report})
        return result

    def frontend(self, sources, backend="c"):
        result = self.analyze(sources, backend)
        self.assertTrue(result.report["ok"], result.report)
        self.assertEqual(result.report["status"], "frontend_only")
        self.assertTrue(result.checked.ok)
        return result

    def checked_rejection(self, sources, code="E_GENERIC_PARAMETER", backend="c"):
        # Intentionally do not catch HeptaError: a loader refusal is not this contract.
        result = self.analyze(sources, backend)
        self.assertIsInstance(result, Analysis)
        self.assertIsInstance(result.checked, CheckResult)
        self.assertFalse(result.report["ok"], result.report)
        self.assertFalse(result.checked.ok)
        self.assertEqual(result.report["schema"], "hepta.check.v1")
        self.assertEqual(result.report["status"], "rejected")
        self.assertEqual(result.report["checks"]["syntax"], "passed")
        self.assertEqual(result.report["checks"]["types_effects_resources"], "rejected")
        self.assertEqual(result.report["checks"]["rust_borrows_types"], "not_run")
        self.assertEqual(result.report["diagnostics"], [d.to_dict() for d in result.checked.diagnostics])
        matching = [d for d in result.report["diagnostics"] if d["code"] == code]
        self.assertTrue(matching, result.report)
        self.assertTrue(all(d["phase"] == "check" for d in matching))
        self.assertIsNone(result.c)
        self.assertIsNone(result.rust)
        self.assertNotIn("backend", result.report)
        return result

    def declaration(self, program, attr="functions", name="answer"):
        return next(d for d in getattr(program, attr)
                    if d.span.path == str(self.root / "lib.hepta")
                    and (d.name == name or d.name.endswith("_" + name)))

    def execute_c(self, sources):
        self.assertIsNotNone(shutil.which("gcc"), "Actual GCC is required")
        result = self.frontend(sources)
        self.assertIsNotNone(result.c)
        for optimize in (False, True):
            built = compile_c(result.c, cc="gcc", crate_type="bin", optimize=optimize,
                              sanitize=True, output=self.root / ("o3" if optimize else "o0"))
            self.assertTrue(built["ok"], built)
            self.assertFalse(built["check_only"])
            self.assertFalse(built["rustc_used"])
            self.assertIn("-O3" if optimize else "-O0", built["flags"])
            self.assertIn("-fsanitize=undefined", built["flags"])
            self.assertIn("-fno-sanitize-recover=all", built["flags"])
            self.execute(built, sources, "c", optimize)
        return result

    def execute(self, built, sources, backend, optimize):
        run = subprocess.run([built["artifact"]], capture_output=True, text=True, timeout=5)
        NATIVE_EXECUTIONS.append({"test": self.id(), "sources": sources, "backend": backend,
                                  "optimize": optimize, "flags": built["flags"],
                                  "exit": run.returncode, "stdout": run.stdout, "stderr": run.stderr})
        self.assertEqual((run.returncode, run.stdout, run.stderr), (42, "", ""))

    def positive_forms(self):
        return ((IDENTITY, "answer::<i32>(42)"),
                ("pub struct Box<Secret>{value:Secret} pub fn answer()->i32 effects {} "
                 "{let v=Box::<i32>{value:42};return v.value;}", "answer()"),
                ("pub enum Box<Secret>{Value(Secret)} pub fn answer()->i32 effects {} "
                 "{let v=Box::<i32>::Value(42);match v{Box::Value(n)=>{return n;}}}", "answer()"))

    def original_rejection(self, kind):
        library, call = SHADOWING[kind]
        for backend in ("c", "rust"):
            with self.subTest(backend=backend):
                self.checked_rejection(self.files(library, call), backend=backend)

    def test_function_struct_collision_is_checker_rejection(self):
        self.original_rejection("function_struct")

    def test_function_enum_collision_is_checker_rejection(self):
        self.original_rejection("function_enum")

    def test_record_struct_collision_is_checker_rejection(self):
        self.original_rejection("record_struct")

    def test_enum_struct_collision_is_checker_rejection(self):
        self.original_rejection("enum_struct")

    def test_self_record_collision_is_checker_rejection(self):
        self.original_rejection("self_record")

    def test_self_enum_collision_is_checker_rejection(self):
        self.original_rejection("self_enum")

    def test_entry_import_and_foreign_root_do_not_change_shadowing_acceptance(self):
        for kind, (library, call) in SHADOWING.items():
            direct = check(parse(library, "lib.hepta"))
            self.assertIn("E_GENERIC_PARAMETER", [d.code for d in direct.diagnostics])
            modes = {"entry": {"main.hepta": library + " fn main()->i32 effects {} {return " + call + ";}"},
                     "imported": self.files(library, call),
                     "foreign_root": self.files(library, call, root_nominal=NOMINAL)}
            for mode, sources in modes.items():
                for backend in ("c", "rust"):
                    with self.subTest(kind=kind, mode=mode, backend=backend):
                        self.checked_rejection(sources, backend=backend)

    def test_order_and_public_private_declarations_do_not_change_rejection(self):
        for nominal in (NOMINAL, "enum Secret{Value}"):
            for nominal_public in (False, True):
                for generic_public in (False, True):
                    for nominal_first in (False, True):
                        with self.subTest(nominal=nominal, nominal_public=nominal_public,
                                          generic_public=generic_public, nominal_first=nominal_first):
                            one = ("pub " if nominal_public else "") + nominal
                            two = IDENTITY if generic_public else IDENTITY.removeprefix("pub ")
                            source = one + "\n" + two if nominal_first else two + "\n" + one
                            self.checked_rejection({"lib.hepta": source, "main.hepta": "import lib; " + MAIN})

    def test_nested_types_and_explicit_generic_arguments_keep_shadow_identity(self):
        library = (NOMINAL + "\nstruct Box<T>{value:T} enum Choice<T>{Value(T)} "
                   "fn wrap<T>(value:T)->Box<T> effects {} {return Box::<T>{value:value};} "
                   "pub fn answer<Secret:Copy>(value:Secret)->Choice<Box<Secret>> effects {} "
                   "{return Choice::<Box<Secret>>::Value(wrap::<Secret>(value));}")
        sources = {"lib.hepta": library, "main.hepta": "import lib; " + MAIN}
        result = self.checked_rejection(sources)
        fn = self.declaration(result.program)
        nominal = self.declaration(result.program, "structs", "Secret")
        self.assertEqual(fn.type_params, (nominal.name,))
        self.assertEqual(fn.type_bounds, {nominal.name: "Copy"})
        self.assertEqual(fn.return_type.args[0].args, (Type(nominal.name),))
        self.assertTrue(any(isinstance(n, Expr) and n.type_args == (Type(nominal.name),) for n in nodes(fn)))
        mixed = (NOMINAL + " fn helper<T,U>(a:T,b:U)->U effects {} {return b;} "
                 "pub fn answer<Secret:Copy,Foreign:Copy>(local:Secret,other:Foreign)->Foreign effects {} "
                 "{return helper::<Secret,Foreign>(local,other);}")
        result = self.checked_rejection({"lib.hepta": mixed, "main.hepta": "import lib; "
                                         "struct Foreign{value:i32} " + MAIN})
        fn = self.declaration(result.program)
        nominal = self.declaration(result.program, "structs", "Secret")
        own, foreign = fn.type_params
        self.assertEqual(own, nominal.name)
        self.assertNotIn(foreign, {"Secret", "Foreign", own})
        self.assertNotIn(foreign, {d.name for d in [*result.program.structs, *result.program.enums,
                                                   *result.program.functions]})
        self.assertEqual(fn.type_bounds, {own: "Copy", foreign: "Copy"})
        self.assertEqual([p.type for p in fn.params], [Type(own), Type(foreign)])
        self.assertEqual(fn.return_type, Type(foreign))
        self.assertTrue(any(isinstance(n, Expr) and n.type_args == (Type(own), Type(foreign)) for n in nodes(fn)))

    def test_qualified_nominal_remains_distinct_from_colliding_bound(self):
        library = ("import model as m; " + NOMINAL
                   + " pub struct Box<Secret>{bound:Secret, imported:m::Secret}")
        sources = {"lib.hepta": library, "model.hepta": "pub struct Secret{value:i32}",
                   "main.hepta": "import lib; " + MAIN}
        result = self.checked_rejection(sources)
        box = self.declaration(result.program, "structs", "Box")
        own = self.declaration(result.program, "structs", "Secret")
        foreign = next(s for s in result.program.structs if s.span.path == str(self.root / "model.hepta"))
        self.assertEqual(box.type_params, (own.name,))
        self.assertEqual(box.fields[0].type, Type(own.name))
        self.assertEqual(box.fields[1].type, Type(foreign.name))
        self.assertNotEqual(own.name, foreign.name)

    def test_returned_report_source_spans_and_repeated_load_are_preserved(self):
        library = "// declaration source\n" + NOMINAL + "\n" + IDENTITY.replace("value", "Secret")
        sources = self.files(library)
        entry = self.project(sources)
        first, second = load_project(entry), load_project(entry)
        self.assertEqual(first.program, second.program)
        self.assertEqual(first.identity, second.identity)
        self.assertTrue(first.unchanged())
        original = parse(library, str(self.root / "lib.hepta")).functions[0]
        fn = self.declaration(first.program)
        self.assertEqual([n for n in nodes(original) if isinstance(n, Span)],
                         [n for n in nodes(fn) if isinstance(n, Span)])
        self.assertEqual(fn.params[0].name, "Secret")
        self.assertEqual([n.value for n in nodes(fn) if isinstance(n, Expr) and n.kind == "name"], ["Secret"])
        for backend in ("c", "rust"):
            with self.subTest(backend=backend):
                result = self.checked_rejection(sources, backend=backend)
                diagnostic = next(d for d in result.checked.diagnostics if d.code == "E_GENERIC_PARAMETER")
                self.assertEqual(diagnostic.span, original.span)
                self.assertEqual(diagnostic.span.path, str(self.root / "lib.hepta"))
                self.assertEqual(diagnostic.span.line, 3)
                self.assertEqual(diagnostic.span.column, 1)
                self.assertIn("duplicate or shadowing generic parameter", diagnostic.message)

    def test_module_private_and_namespace_diagnostics_keep_loader_precedence(self):
        cases = [(self.files(NOMINAL + " " + IDENTITY.removeprefix("pub ")), "E_MODULE_PRIVATE"),
                 ({"lib.hepta": NOMINAL + " " + IDENTITY,
                   "main.hepta": "import lib; fn main()->i32 effects {} {let x=lib::Secret{value:42};return x.value;}"},
                  "E_MODULE_PRIVATE"),
                 ({"lib.hepta": "import model as m; " + NOMINAL
                   + " fn helper<T>(v:T)->T effects {} {return v;} "
                   "pub fn answer<Secret>(v:Secret)->Secret effects {} {return helper::<m::Hidden>(v);}",
                   "model.hepta": "struct Hidden{value:i32}", "main.hepta": "import lib; " + MAIN}, "E_MODULE_PRIVATE"),
                 ({"lib.hepta": NOMINAL + " pub fn answer<Secret>(v:missing::Secret)->Secret effects {} {return v;}",
                   "main.hepta": "import lib; " + MAIN}, "E_MODULE_NAMESPACE"),
                 ({"lib.hepta": NOMINAL + " pub fn answer<Secret>(v:Hidden)->Secret effects {} {return v;}",
                   "main.hepta": "import lib; struct Hidden{value:i32} " + MAIN}, "E_MODULE_SCOPE")]
        for sources, code in cases:
            with self.subTest(code=code, sources=sources):
                with self.assertRaises(HeptaError) as caught:
                    analyze_project(self.project(sources), backend="c", native=False, crate_type="bin")
                self.assertEqual(caught.exception.diagnostic.code, code)
                self.assertEqual(caught.exception.diagnostic.phase, "module")

    def test_duplicate_reserved_and_unused_parameter_diagnostics_are_protected(self):
        cases = ((IDENTITY.replace("<Secret>", "<Secret,Secret>"), "E_GENERIC_PARAMETER", ("Secret", "Secret")),
                 (IDENTITY.replace("Secret", "i32"), "E_GENERIC_PARAMETER", ("i32",)))
        for declaration, code, params in cases:
            with self.subTest(declaration=declaration):
                result = self.checked_rejection({"lib.hepta": NOMINAL + " " + declaration,
                                                 "main.hepta": "import lib; " + MAIN}, code)
                self.assertEqual(self.declaration(result.program).type_params, params)
                self.assertIn("duplicate or shadowing generic parameter " + params[0],
                              [d.message for d in result.checked.diagnostics])
        self.checked_rejection({"lib.hepta": "pub struct Box<T>{value:i32}",
                                "main.hepta": "import lib; " + MAIN}, "E_GENERIC_UNUSED")

    def test_invalid_bound_preserves_original_parameter_and_diagnostic(self):
        library = NOMINAL + " " + IDENTITY.replace("<Secret>", "<Secret:Send>")
        result = self.checked_rejection({"lib.hepta": library, "main.hepta": "import lib; " + MAIN}, "E_GENERIC_BOUND")
        fn = self.declaration(result.program)
        self.assertEqual(fn.type_params, ("Secret",))
        self.assertEqual(fn.type_bounds, {"Secret": "Send"})
        diag = next(d for d in result.checked.diagnostics if d.code == "E_GENERIC_BOUND")
        self.assertEqual(diag.message, "unsupported constraint Secret: Send; expected Copy or Owned")
        self.assertEqual(diag.span, parse(library, str(self.root / "lib.hepta")).functions[0].span)

    def test_extern_export_and_repr_c_guards_preserve_original_parameters(self):
        cases = (('extern "C" fn answer<Secret>(value:Secret)->Secret effects {};', "functions", "answer", "E_GENERIC_BOUNDARY"),
                 ('pub export "C" fn answer<Secret>(value:Secret)->Secret effects {} {return value;}', "functions", "answer", "E_GENERIC_BOUNDARY"),
                 ('repr(C) struct Box<Secret>{value:Secret}', "structs", "Box", "E_C_ABI"))
        for declaration, attr, name, code in cases:
            with self.subTest(declaration=declaration):
                result = self.checked_rejection({"lib.hepta": NOMINAL + " " + declaration,
                                                 "main.hepta": "import lib; " + MAIN}, code)
                self.assertEqual(self.declaration(result.program, attr, name).type_params, ("Secret",))
                self.assertNotIn("E_GENERIC_PARAMETER", [d.code for d in result.checked.diagnostics])

    def test_same_spelled_function_is_not_a_nominal_and_controls_execute(self):
        for library, call in self.positive_forms():
            with self.subTest(library=library):
                self.execute_c(self.files("fn Secret()->i32 effects {} {return 7;} " + library, call))

    def test_foreign_only_root_and_sibling_nominal_controls_execute(self):
        for library, call in self.positive_forms():
            for root in (True, False):
                with self.subTest(library=library, root=root):
                    sources = self.files(library, call, root_nominal=NOMINAL if root else "import model;",
                                         **({} if root else {"model.hepta": NOMINAL}))
                    self.execute_c(sources)

    def test_renamed_same_source_parameter_controls_execute(self):
        for library, call in self.positive_forms():
            with self.subTest(library=library):
                self.execute_c(self.files(NOMINAL + " " + library.replace("Secret", "T"), call))

    def test_nested_forwarding_and_explicit_public_nominal_control_executes(self):
        library = ("struct Box<T>{value:T} enum Choice<T>{Value(T)} "
                   "fn wrap<Secret:Copy>(value:Secret)->Box<Secret> effects {} {return Box::<Secret>{value:value};} "
                   "fn select<Secret>(value:Secret)->Choice<Secret> effects {} {return Choice::<Secret>::Value(value);} "
                   "pub fn answer<Secret>(value:Secret)->Secret effects {} {let box=wrap::<Secret>(value);"
                   "let choice=select::<Box<Secret>>(box);match choice{Choice::Value(v)=>{return v.value;}}}")
        sources = {"lib.hepta": library, "model.hepta": "pub struct Cell{value:i32}",
                   "main.hepta": "import lib;import model as m;" + NOMINAL + " fn main()->i32 effects {} "
                   "{let v=lib::answer::<m::Cell>(m::Cell{value:42});return v.value;}"}
        self.execute_c(sources)

    def test_lifetime_value_and_field_names_are_not_rewritten_as_bound_types(self):
        library = (NOMINAL + "\npub fn answer<'Secret,Secret>(Secret:read 'Secret Secret)->read 'Secret Secret "
                   "from Secret effects {} {return read Secret;} pub struct Box<Secret>{Secret:Secret}")
        sources = {"lib.hepta": library, "main.hepta": "import lib; " + MAIN}
        program = load_project(self.project(sources)).program
        original = parse(library, str(self.root / "lib.hepta"))
        fn, before = self.declaration(program), original.functions[0]
        self.assertEqual(fn.lifetime_params, before.lifetime_params)
        self.assertEqual(fn.return_origin, before.return_origin)
        self.assertEqual(fn.params[0].name, "Secret")
        self.assertEqual(fn.params[0].lifetime, before.params[0].lifetime)
        self.assertEqual(fn.return_lifetime, before.return_lifetime)
        self.assertEqual(fn.return_type.lifetimes, before.return_type.lifetimes)
        box = self.declaration(program, "structs", "Box")
        self.assertEqual(box.fields[0].name, "Secret")
        self.assertEqual(box.fields[0].type.name, box.type_params[0])
        checked = check(program)
        self.assertIn("E_GENERIC_PARAMETER", [d.code for d in checked.diagnostics])

    def test_owned_and_borrowed_controls_are_frontend_only(self):
        valid = "pub fn answer<Secret:Owned>(value:take Secret)->Secret effects {} {return move value;}"
        cases = ((IDENTITY.replace("<Secret>", "<Secret:Copy>"), None),
                 (valid, None),
                 (valid.replace("return move value", "return value"), "E_MOVE_REQUIRED"),
                 (valid.replace("value:take Secret", "value:Secret"), "E_LINEAR_MODE"),
                 ("pub fn answer<Secret:Owned>(value:read Secret)->Unit effects {alloc,block} {drop(move value);}", "E_MOVE_BORROW"))
        for library, code in cases:
            for nominal in (NOMINAL, "struct Secret<'a>{data:read 'a i32}"):
                with self.subTest(library=library, nominal=nominal):
                    sources = {"lib.hepta": library, "main.hepta": "import lib; " + nominal + " " + MAIN}
                    checked = check(load_project(self.project(sources)).program)
                    codes = [d.code for d in checked.diagnostics]
                    self.assertNotIn("E_GENERIC_PARAMETER", codes)
                    if code is None:
                        self.assertTrue(checked.ok, [d.to_dict() for d in checked.diagnostics])
                    else:
                        self.assertIn(code, codes)
        for nominal in (NOMINAL, "struct Secret<'a>{data:read 'a i32}"):
            program = load_project(self.project({"lib.hepta": nominal + " " + valid,
                                                 "main.hepta": "import lib; " + MAIN})).program
            fn = self.declaration(program)
            own = self.declaration(program, "structs", "Secret")
            self.assertEqual(fn.type_params, (own.name,))
            self.assertEqual(fn.type_bounds, {own.name: "Owned"})
            self.assertEqual(fn.params[0].type, Type(own.name))
            self.assertEqual(fn.return_type, Type(own.name))
            checked = check(program)
            self.assertIn("E_GENERIC_PARAMETER", [d.code for d in checked.diagnostics])

    def test_cli_uses_selected_compiler_for_acceptance_and_check_phase_rejection(self):
        cases = ((self.files(root_nominal=NOMINAL), True),
                 (self.files(NOMINAL + " " + IDENTITY), False))
        for sources, accepted in cases:
            entry = self.project(sources)
            for backend in ("c", "rust"):
                with self.subTest(accepted=accepted, backend=backend):
                    run = subprocess.run([sys.executable, "-m", "hepta", "check", str(entry), "--backend", backend,
                                          "--frontend-only"], cwd=ROOT,
                                         env=dict(os.environ, PYTHONPATH=str(ROOT), PYTHONDONTWRITEBYTECODE="1"),
                                         capture_output=True, text=True, timeout=30)
                    self.assertEqual(run.stderr, "")
                    report = json.loads(run.stdout)
                    self.assertEqual(run.returncode, 0 if accepted else 1, report)
                    self.assertEqual(report["ok"], accepted)
                    if not accepted:
                        self.assertEqual(report["checks"]["types_effects_resources"], "rejected")
                        self.assertTrue(any(d["code"] == "E_GENERIC_PARAMETER" and d["phase"] == "check"
                                            for d in report["diagnostics"]))

    def test_real_rust_parity_after_finite_scalar_record_enum_c_prerequisites(self):
        cases = [self.files(library, call, root_nominal=NOMINAL) for library, call in self.positive_forms()]
        for sources in cases:
            self.execute_c(sources)
            self.frontend(sources, "rust")
        try:
            rustc = find_rustc(os.environ.get("RUSTC"))
        except HeptaError as error:
            if error.diagnostic.code != "E_TOOLCHAIN":
                raise
            self.skipTest("Three C/Rust frontend controls and six GCC O0/O3+UBSan runs passed; actual rustc absent")
        for index, sources in enumerate(cases):
            result = self.frontend(sources, "rust")
            for optimize in (False, True):
                with self.subTest(case=index, optimize=optimize):
                    built = compile_rust(result.rust, rustc=rustc, crate_type="bin", optimize=optimize,
                                         output=self.root / ("rust-" + str(index) + "-" + str(optimize)))
                    self.assertTrue(built["ok"], built)
                    self.assertTrue(built["rustc_used"])
                    self.assertFalse(built["check_only"])
                    self.execute(built, sources, "rust", optimize)


if __name__ == "__main__":
    unittest.main()
