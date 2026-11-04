"""Finite intersections of package-context ownership and cumulative scope fixes.

One standalone case adds only new intersections to the component inventories.
All native programs are finite scalar/record/enum controls. Each native record
binds actual output to input, generated-source, compiler and artifact identities.
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
from hepta.checker import CheckResult
from hepta.modules import load_project
from hepta.packages import load_package, verify_lock, write_lock
from hepta.parser import parse
from hepta.pipeline import Analysis, analyze_project

ROOT = Path(hepta.__file__).resolve().parents[1]
CONFLICT = "E_MODULE_PACKAGE_CONTEXT"
ROOT_DECLARATIONS = ("struct Secret{value:i32}\nstruct Hidden{value:i32}\n"
                     "fn secret()->i32 effects {} {return 91;}\n")
IDENTITY = "pub fn identity<Secret:Copy>(secret:Secret)->Secret effects {} {return secret;}\n"
NESTED = ("pub struct Box<Secret>{value:Secret}\n"
          "pub enum Choice<Secret>{Value(Secret)}\n" + IDENTITY +
          "pub fn pack<Secret:Copy>(secret:Secret)->Choice<Box<Secret>> effects {} "
          "{return Choice::<Box<Secret>>::Value(Box::<Secret>{value:identity::<Secret>(secret)});}\n"
          "pub fn answer()->i32 effects {} {let secret:i32=42;let chosen=pack::<i32>(secret);"
          "match chosen{Choice::Value(v)=>{return v.value;}}}\n")
NATIVE_EXECUTIONS = []


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


def sha256(data):
    return hashlib.sha256(data).hexdigest()


class ModuleScopeContextUnionTests(unittest.TestCase):
    def setUp(self):
        selected = os.environ.get("HEPTA_TEST_ROOT")
        if selected:
            self.assertEqual(ROOT, Path(selected).resolve())
        temporary = tempfile.TemporaryDirectory(prefix="hepta-scope-context-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.serial = 0

    def put(self, relative, source):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(source.encode("utf-8"))
        return path

    def manifest(self, relative, *, name="same", kind="lib", dependencies=None):
        source = f'[package]\nname = "{name}"\nversion = "0.1.0"\nkind = "{kind}"\n'
        if dependencies:
            source += "[dependencies]\n"
            source += "".join(f"{alias} = {{ path = {json.dumps(path)} }}\n"
                              for alias, path in dependencies.items())
        self.put(relative + "/hepta.toml", source)
        return self.root / relative

    def main(self, imports, expression="42"):
        return imports + ROOT_DECLARATIONS + "fn main()->i32 effects {} {return " + expression + ";}\n"

    def reused(self, kind, *, library=NESTED, reverse=False, use_nested=True, call_answer=False):
        base = kind + ("-reverse" if reverse else "")
        app = self.manifest(base + "/app", kind="bin", dependencies={
            "first": "../common", "second": "../common/../common"} if kind == "alias" else {
            "left": "../left", "right": "../right"})
        self.manifest(base + "/common")
        shared = self.put(base + "/common/src/lib.hepta", library)
        if kind == "alias":
            imports = ["import first;", "import second;"]
            body = ("let selected:second::Choice<first::Box<i32>>=first::pack::<i32>(42);"
                    "match selected{second::Choice::Value(v)=>{return second::identity::<i32>(v.value);}}"
                    if use_nested else "return first::answer();" if call_answer else "return 42;")
        else:
            imports = ["import left;", "import right;"]
            for branch in ("left", "right"):
                self.manifest(base + "/" + branch, dependencies={"common": "../common"})
                branch_body = ("let secret:api::Choice<api::Box<i32>>=api::pack::<i32>(42);"
                               "match secret{api::Choice::Value(v)=>{return v.value;}}"
                               if use_nested else "return api::answer();" if call_answer else "return 42;")
                self.put(base + "/" + branch + "/src/lib.hepta", "import common as api;\n"
                         "pub fn answer()->i32 effects {} {" + branch_body + "}\n")
            body = ("if left::answer()==right::answer(){return left::answer();}else{return 1;}"
                    if use_nested or call_answer else "return 42;")
        if reverse:
            imports.reverse()
        entry = self.put(base + "/app/src/main.hepta", "\n".join(imports) + "\n" +
                         ROOT_DECLARATIONS + "fn main()->i32 effects {} {" + body + "}\n")
        write_lock(app)
        return app, entry, shared

    def vendor(self, *, library=None, imports="import dep;\n", expression="dep::answer()"):
        app = self.manifest("vendor-app", kind="bin", dependencies={"dep": "src/vendor"})
        self.manifest("vendor-app/src/vendor")
        if library is None:
            library = ("import helper as secret;\n" + NESTED.replace("let secret:i32=42;",
                                                                  "let secret:i32=secret::value();"))
        shared = self.put("vendor-app/src/vendor/src/lib.hepta", library)
        self.put("vendor-app/src/helper.hepta", "pub fn value()->i32 effects {} {return 7;}\n")
        self.put("vendor-app/src/vendor/src/helper.hepta", "pub fn value()->i32 effects {} {return 42;}\n")
        entry = self.put("vendor-app/src/main.hepta", self.main(imports, expression))
        write_lock(app)
        return app, entry, shared

    def imports(self, reverse=False):
        imports = ["import vendor::src::lib as local;", "import dep;"]
        if reverse:
            imports.reverse()
        return "\n".join(imports) + "\n"

    def analyze(self, app, *, backend="c", locked=True):
        return analyze_project(app, locked=locked, backend=backend, native=False, crate_type="bin")

    def frontend(self, app, *, backend="c", locked=True):
        result = self.analyze(app, backend=backend, locked=locked)
        self.assertTrue(result.report["ok"], result.report)
        self.assertEqual(result.report["status"], "frontend_only")
        self.assertEqual(result.report["diagnostics"], [])
        self.assertTrue(result.checked.ok)
        return result

    def checked_rejection(self, app, code="E_GENERIC_PARAMETER", *, backend="c"):
        # A module exception must not satisfy this checker-stage contract.
        result = self.analyze(app, backend=backend)
        self.assertIsInstance(result, Analysis)
        self.assertIsInstance(result.checked, CheckResult)
        self.assertFalse(result.report["ok"], result.report)
        self.assertFalse(result.checked.ok)
        self.assertEqual(result.report["status"], "rejected")
        self.assertEqual(result.report["checks"]["syntax"], "passed")
        self.assertEqual(result.report["checks"]["types_effects_resources"], "rejected")
        self.assertEqual(result.report["diagnostics"], [d.to_dict() for d in result.checked.diagnostics])
        matches = [d for d in result.checked.diagnostics if d.code == code]
        self.assertTrue(matches, result.report)
        self.assertTrue(all(d.phase == "check" for d in matches))
        self.assertIsNone(result.c)
        self.assertIsNone(result.rust)
        return result

    def declaration(self, result, path, name, attr="functions"):
        return next(d for d in getattr(result.program, attr)
                    if d.span.path == str(path) and (d.name == name or d.name.endswith("_" + name)))

    def assert_nested_identities(self, result, shared):
        nominal_names = {d.name for d in [*result.program.structs, *result.program.enums]}
        functions = {d.name for d in result.program.functions}
        pack = self.declaration(result, shared, "pack")
        identity = self.declaration(result, shared, "identity")
        box = self.declaration(result, shared, "Box", "structs")
        choice = self.declaration(result, shared, "Choice", "enums")
        for declaration in (pack, identity, box, choice):
            bound, = declaration.type_params
            self.assertNotIn(bound, nominal_names | functions | {"Secret"})
        bound, = pack.type_params
        self.assertEqual(pack.type_bounds, {bound: "Copy"})
        self.assertEqual(pack.params[0].type, Type(bound))
        self.assertEqual(pack.return_type, Type(choice.name, (Type(box.name, (Type(bound),)),)))
        self.assertNotEqual(pack.params[0].name, "secret")
        self.assertNotIn(pack.params[0].name, functions)
        self.assertIn(pack.params[0].name, [n.value for n in nodes(pack)
                                          if isinstance(n, Expr) and n.kind == "name"])
        self.assertIn(identity.name, [n.value for n in nodes(pack)
                                     if isinstance(n, Expr) and n.kind == "call"])
        self.assertTrue(any(isinstance(n, Expr) and n.type_args == (Type(bound),) for n in nodes(pack)))
        self.assertEqual(sum(m["path"] == str(shared) for m in result.project.modules), 1)

    def context_diagnostic(self, app, entry, shared, *, reverse=False, source=None):
        source = entry.read_text() if source is None else source
        span = parse(source, str(entry)).imports[1].span
        roots = (app, app / "src/vendor")
        if reverse:
            roots = roots[::-1]
        return {"code": CONFLICT, "phase": "module", "notes": [],
                "message": f"Module {shared} is imported under conflicting package roots: {roots[0]} and {roots[1]}",
                "span": {"path": span.path, "start": span.start, "end": span.end,
                         "line": span.line, "column": span.column}}

    def reject_context(self, action, app, entry, shared, **kwargs):
        with self.assertRaises(HeptaError) as caught:
            action()
        self.assertEqual(caught.exception.diagnostic.to_dict(),
                         self.context_diagnostic(app, entry, shared, **kwargs))

    def execute(self, result, expected=42, *, backend="c", optimize=False, rustc=None, label=None):
        self.serial += 1
        artifact = self.root / f"native-{self.serial}"
        if backend == "c":
            self.assertIsNotNone(shutil.which("gcc"), "Actual GCC is required")
            built = compile_c(result.c, cc="gcc", crate_type="bin", output=artifact,
                              optimize=optimize, sanitize=True)
            self.assertIn("-O3" if optimize else "-O0", built["flags"])
            self.assertIn("-fsanitize=undefined", built["flags"])
            self.assertIn("-fno-sanitize-recover=all", built["flags"])
        else:
            built = compile_rust(result.rust, rustc=rustc, crate_type="bin", output=artifact,
                                 optimize=optimize)
            self.assertIn("opt-level=3" if optimize else "opt-level=0", built["flags"])
        self.assertTrue(built["ok"], built)
        self.assertFalse(built["check_only"])
        generated = result.c if backend == "c" else result.rust
        source_hash = built["source_sha256" if backend == "c" else "rust_sha256"]
        self.assertEqual(source_hash, sha256(generated.encode("utf-8")))
        self.observe_artifact(artifact, result, built, expected, backend, optimize, label)

    def observe_artifact(self, artifact, result, built, expected, backend, optimize, label):
        self.assertTrue(artifact.is_file())
        run = subprocess.run([str(artifact)], capture_output=True, text=True, timeout=10)
        for path, data in result.project.source_bytes.items():
            self.assertEqual(result.project.sources[path], sha256(data))
        observation = {"test": self.id(), "label": label, "backend": backend, "optimize": optimize,
                       "expected": expected, "returncode": run.returncode, "stdout": run.stdout,
                       "stderr": run.stderr, "source_sha256": built.get("source_sha256", built.get("rust_sha256")),
                       "artifact_sha256": sha256(artifact.read_bytes()), "flags": built["flags"],
                       "toolchain": built["toolchain"], "project_sha256": result.project.identity,
                       "input_sources": result.project.sources, "compiler_root": str(ROOT),
                       "modules_py_sha256": sha256((ROOT / "hepta/modules.py").read_bytes())}
        NATIVE_EXECUTIONS.append(observation)
        print("SCOPE_CONTEXT_NATIVE " + json.dumps(observation, sort_keys=True), flush=True)
        self.assertEqual((run.returncode, run.stdout, run.stderr), (expected, "", ""), observation)
        artifact.unlink()

    def cli(self, *arguments):
        return subprocess.run([sys.executable, "-m", "hepta", *map(str, arguments)], cwd=self.root,
                              env=dict(os.environ, PYTHONPATH=str(ROOT), PYTHONDONTWRITEBYTECODE="1"),
                              capture_output=True, text=True, timeout=30)

    def assert_cli_checkout(self):
        process = subprocess.run([sys.executable, "-c", "import hepta.modules; print(hepta.modules.__file__)"],
                                 cwd=self.root, env=dict(os.environ, PYTHONPATH=str(ROOT),
                                                        PYTHONDONTWRITEBYTECODE="1"),
                                 capture_output=True, text=True, timeout=10)
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(Path(process.stdout.strip()).resolve(), ROOT / "hepta/modules.py")

    def test_alias_reuse_preserves_nested_generic_and_local_binding_identities(self):
        for reverse in (False, True):
            app, entry, shared = self.reused("alias", reverse=reverse)
            for backend in ("c", "rust"):
                with self.subTest(reverse=reverse, backend=backend):
                    result = self.frontend(app, backend=backend)
                    self.assert_nested_identities(result, shared)
                    deps = result.project.package.dependencies
                    self.assertIs(deps["first"], deps["second"])
                    self.assertEqual(len(result.project.modules), 2)
                    main = next(m for m in result.project.modules if m["path"] == str(entry))
                    self.assertEqual(main["imports"], {"first": str(shared), "second": str(shared)})
            result = self.frontend(app)
            repeated = self.frontend(app)
            self.assertEqual(result.project.identity, repeated.project.identity)
            self.assertEqual(result.program, repeated.program)
            self.assertEqual(result.project.modules, repeated.project.modules)
            self.assertEqual(result.c, repeated.c)
            self.assertTrue(result.project.unchanged())
            for optimize in (False, True):
                self.execute(result, optimize=optimize, label="alias")

    def test_diamond_reuse_preserves_nested_generic_and_local_binding_identities(self):
        for reverse in (False, True):
            app, _, shared = self.reused("diamond", reverse=reverse)
            for backend in ("c", "rust"):
                with self.subTest(reverse=reverse, backend=backend):
                    result = self.frontend(app, backend=backend)
                    self.assert_nested_identities(result, shared)
                    deps = result.project.package.dependencies
                    self.assertIs(deps["left"].dependencies["common"], deps["right"].dependencies["common"])
                    self.assertEqual(len(result.project.modules), 4)
                    common_names = {f.name for f in result.program.functions if f.span.path == str(shared)}
                    for branch in ("left", "right"):
                        path = app.parent / branch / "src/lib.hepta"
                        wrapper = self.declaration(result, path, "answer")
                        self.assertTrue(any(isinstance(n, Expr) and n.kind == "call" and n.value in common_names
                                            for n in nodes(wrapper)))
            for optimize in (False, True):
                self.execute(self.frontend(app), optimize=optimize, label="diamond")

    def test_same_source_shadow_rejection_survives_alias_and_diamond_reuse(self):
        declarations = ((IDENTITY, "identity", "functions", "return identity::<i32>(42);"),
                        ("pub struct Box<Secret>{value:Secret}\n", "Box", "structs",
                         "let v=Box::<i32>{value:42};return v.value;"),
                        ("pub enum Choice<Secret>{Value(Secret)}\n", "Choice", "enums",
                         "let v=Choice::<i32>::Value(42);match v{Choice::Value(n)=>{return n;}}"))
        for kind in ("alias", "diamond"):
            for generic, name, attr, body in declarations:
                source = ("// same source must still reject\nstruct Secret{value:i32}\n" + generic +
                          "pub fn answer()->i32 effects {} {" + body + "}\n")
                app, _, shared = self.reused(kind, library=source, use_nested=False, call_answer=True)
                original = next(d for d in getattr(parse(source, str(shared)), attr) if d.name == name)
                for backend in ("c", "rust"):
                    with self.subTest(kind=kind, declaration=name, backend=backend):
                        result = self.checked_rejection(app, backend=backend)
                        nominal = self.declaration(result, shared, "Secret", "structs")
                        resolved = self.declaration(result, shared, name, attr)
                        self.assertEqual(resolved.type_params, (nominal.name,))
                        self.assertEqual(resolved.span, original.span)
                        self.assertEqual(sum(m["path"] == str(shared) for m in result.project.modules), 1)
                        diag = next(d for d in result.checked.diagnostics if d.code == "E_GENERIC_PARAMETER")
                        self.assertEqual(diag.span, original.span)
                shared.write_text(source.replace(generic, generic.replace("Secret", "T")), encoding="utf-8")
                write_lock(app)
                for backend in ("c", "rust"):
                    self.frontend(app, backend=backend)
                for optimize in (False, True):
                    self.execute(self.frontend(app), optimize=optimize, label=kind + "-renamed-" + name)

    def test_protected_generic_declarations_keep_checker_refusals_after_reuse(self):
        cases = ((IDENTITY.replace("<Secret:Copy>", "<Secret,Secret>"), "E_GENERIC_PARAMETER", "functions", "identity", ("Secret", "Secret")),
                 (IDENTITY.replace("Secret", "i32"), "E_GENERIC_PARAMETER", "functions", "identity", ("i32",)),
                 (IDENTITY.replace("Secret:Copy", "Secret:Send"), "E_GENERIC_BOUND", "functions", "identity", ("Secret",)),
                 ("pub struct Box<T>{value:i32}", "E_GENERIC_UNUSED", "structs", "Box", ("T",)),
                 ('extern "C" fn boundary<Secret>(value:Secret)->Secret effects {};', "E_GENERIC_BOUNDARY", "functions", "boundary", ("Secret",)),
                 ('pub export "C" fn boundary<Secret>(value:Secret)->Secret effects {} {return value;}', "E_GENERIC_BOUNDARY", "functions", "boundary", ("Secret",)),
                 ('repr(C) struct Box<Secret>{value:Secret}', "E_C_ABI", "structs", "Box", ("Secret",)))
        for declaration, code, attr, name, params in cases:
            app, _, shared = self.reused("alias", library="struct Secret{value:i32}\n" + declaration,
                                         use_nested=False)
            for backend in ("c", "rust"):
                with self.subTest(declaration=declaration, backend=backend):
                    result = self.checked_rejection(app, code, backend=backend)
                    self.assertEqual(self.declaration(result, shared, name, attr).type_params, params)
                    self.assertEqual(sum(m["path"] == str(shared) for m in result.project.modules), 1)

    def test_context_conflict_precedes_later_scope_privacy_namespace_and_checker_errors(self):
        cases = ((IDENTITY + "pub fn answer(secret:i32)->i32 effects {} {return secret();}",
                  "dep::answer(42)", "E_MODULE_SCOPE", "Unqualified symbol is not declared in this module: secret"),
                 ("pub fn answer<Secret>(value:Secret)->Hidden effects {} {return value;}",
                  "42", "E_MODULE_SCOPE", "Unqualified type is not declared in this module: Hidden"),
                 ("fn answer()->i32 effects {} {return 42;}", "dep::answer()",
                  "E_MODULE_PRIVATE", "Imported symbol is private: dep::answer"),
                 ("pub fn answer<Secret>(value:missing::Hidden)->Secret effects {} {return value;}",
                  "42", "E_MODULE_NAMESPACE", "Unknown namespace: missing"),
                 ("struct Secret{value:i32}\n" + IDENTITY, "42", "E_GENERIC_PARAMETER", None))
        for library, expression, code, message in cases:
            app, entry, shared = self.vendor(library=library, expression=expression)
            for reverse in (False, True):
                entry.write_text(self.main(self.imports(reverse), expression), encoding="utf-8")
                write_lock(app)
                for backend in ("c", "rust"):
                    with self.subTest(code=code, message=message, reverse=reverse, backend=backend):
                        self.reject_context(lambda: self.analyze(app, backend=backend), app, entry, shared,
                                            reverse=reverse)
            for route in ("import dep;\n", "import vendor::src::lib as dep;\n"):
                entry.write_text(self.main(route, expression), encoding="utf-8")
                write_lock(app)
                for backend in ("c", "rust"):
                    with self.subTest(single_route=route, code=code, backend=backend):
                        if code == "E_GENERIC_PARAMETER":
                            result = self.checked_rejection(app, backend=backend)
                            original = parse(library, str(shared)).functions[0]
                            self.assertEqual(result.checked.diagnostics[0].span, original.span)
                        else:
                            with self.assertRaises(HeptaError) as caught:
                                self.analyze(app, backend=backend)
                            diagnostic = caught.exception.diagnostic
                            self.assertEqual((diagnostic.code, diagnostic.phase, diagnostic.message),
                                             (code, "module", message))
                            expected_path = entry if code == "E_MODULE_PRIVATE" else shared
                            if code == "E_MODULE_PRIVATE":
                                original = parse(entry.read_text(), str(entry))
                                expected_span = next(n.span for n in nodes(original)
                                                     if isinstance(n, Expr) and n.kind == "call")
                            elif message.endswith(": secret"):
                                original = parse(library, str(shared))
                                expected_span = next(n.span for n in nodes(original)
                                                     if isinstance(n, Expr) and n.kind == "call")
                            else:
                                expected_span = Span(path=str(expected_path))
                            self.assertEqual(diagnostic.span, expected_span)
                            self.assertEqual(diagnostic.notes, [])

    def test_single_routes_choose_correct_helper_with_scope_controls(self):
        for route, expected in (("import dep;\n", 42), ("import vendor::src::lib as dep;\n", 7)):
            app, _, shared = self.vendor(imports=route)
            results = [self.frontend(app, backend=backend) for backend in ("c", "rust")]
            self.assertEqual(results[0].project.identity, results[1].project.identity)
            self.assertEqual(results[0].program, results[1].program)
            self.assert_nested_identities(results[0], shared)
            helper = app / ("src/vendor/src/helper.hepta" if expected == 42 else "src/helper.hepta")
            module = next(m for m in results[0].project.modules if m["path"] == str(shared))
            self.assertEqual(module["imports"], {"secret": str(helper)})
            for optimize in (False, True):
                self.execute(results[0], expected, optimize=optimize, label="dependency" if expected == 42 else "local")

    def test_single_route_local_binding_does_not_grant_foreign_function_access(self):
        for route in ("import dep;\n", "import vendor::src::lib as dep;\n"):
            source = IDENTITY + "pub fn answer(secret:i32)->i32 effects {} {return secret();}\n"
            app, _, shared = self.vendor(library=source, imports=route, expression="dep::answer(42)")
            call = next(n for n in nodes(parse(source, str(shared)))
                        if isinstance(n, Expr) and n.kind == "call")
            for backend in ("c", "rust"):
                with self.subTest(route=route, backend=backend):
                    with self.assertRaises(HeptaError) as caught:
                        self.analyze(app, backend=backend)
                    diagnostic = caught.exception.diagnostic
                    self.assertEqual((diagnostic.code, diagnostic.phase, diagnostic.message, diagnostic.span),
                                     ("E_MODULE_SCOPE", "module", "Unqualified symbol is not declared in this module: secret", call.span))

    def test_source_override_conflict_keeps_disk_and_lock_unchanged(self):
        app, entry, shared = self.vendor()
        original, lock = entry.read_bytes(), (app / "Hepta.lock").read_bytes()
        before = load_project(app, locked=True)
        for reverse in (False, True):
            source = self.main(self.imports(reverse), "dep::answer()")
            for locked in (False, True):
                with self.subTest(reverse=reverse, locked=locked):
                    self.reject_context(lambda: load_project(app, locked=locked, source_overrides={entry: source}),
                                        app, entry, shared, reverse=reverse, source=source)
                    self.assertEqual(entry.read_bytes(), original)
                    self.assertEqual((app / "Hepta.lock").read_bytes(), lock)
                    verify_lock(load_package(app))
        self.assertEqual(before.identity, load_project(app, locked=True).identity)
        self.assertTrue(before.unchanged())
        self.frontend(app)

    def test_physical_cli_distinguishes_context_exception_and_generic_checker_report(self):
        self.assert_cli_checkout()
        library = "struct Secret{value:i32}\n" + IDENTITY
        app, entry, shared = self.vendor(library=library, expression="42")
        for reverse in (False, True):
            entry.write_text(self.main(self.imports(reverse)), encoding="utf-8")
            write_lock(app)
            for backend in ("c", "rust"):
                process = self.cli("check", app, "--locked", "--backend", backend, "--frontend-only")
                self.assertEqual((process.returncode, process.stderr), (1, ""))
                report = json.loads(process.stdout)
                self.assertEqual(report["diagnostics"], [self.context_diagnostic(app, entry, shared, reverse=reverse)])
        entry.write_text(self.main("import dep;\n"), encoding="utf-8")
        write_lock(app)
        for backend in ("c", "rust"):
            expected = self.checked_rejection(app, backend=backend)
            process = self.cli("check", entry, "--locked", "--backend", backend, "--frontend-only")
            self.assertEqual((process.returncode, process.stderr), (1, ""))
            report = json.loads(process.stdout)
            self.assertEqual(report["status"], "rejected")
            self.assertEqual(report["checks"]["syntax"], "passed")
            self.assertEqual(report["diagnostics"], expected.report["diagnostics"])

    def test_physical_cli_executes_combined_single_route_controls(self):
        self.assert_cli_checkout()
        for route, expected in (("import dep;\n", 42), ("import vendor::src::lib as dep;\n", 7)):
            app, entry, _ = self.vendor(imports=route)
            result = self.frontend(app)
            artifact = self.root / "cli-program"
            process = self.cli("build", entry, "--locked", "--backend", "c", "--cc", "gcc", "-o", artifact)
            self.assertEqual((process.returncode, process.stderr), (0, ""), process.stdout + process.stderr)
            report = json.loads(process.stdout)
            self.assertTrue(report["ok"], report)
            self.assertTrue(report["validation"]["project"]["locked"])
            self.assertEqual(report["build"]["source_sha256"], sha256(result.c.encode()))
            self.observe_artifact(artifact, result, report["build"], expected, "cli-c", True, "single-route")

    def test_cached_target_escape_precedes_context_and_scope_checks(self):
        app = self.manifest("escape/app", kind="bin", dependencies={"dep": "vendor"})
        self.manifest("escape/app/vendor")
        shared = self.put("escape/app/vendor/src/lib.hepta", NESTED)
        alias = app / "src/escaped.hepta"
        alias.parent.mkdir(parents=True, exist_ok=True)
        alias.symlink_to(shared)
        entry = self.put("escape/app/src/main.hepta", self.main("import dep;\nimport escaped;\n"))
        # The first route completes and caches the file; the second path escapes
        # app's source root before its otherwise conflicting owner is examined.
        original = parse(entry.read_text(), str(entry)).imports[1].span
        write_lock(app)
        for locked in (False, True):
            for backend in ("c", "rust"):
                with self.subTest(backend=backend, locked=locked):
                    with self.assertRaises(HeptaError) as caught:
                        self.analyze(app, backend=backend, locked=locked)
                    diagnostic = caught.exception.diagnostic
                    self.assertEqual((diagnostic.code, diagnostic.phase, diagnostic.message, diagnostic.span),
                                     ("E_MODULE_ESCAPE", "module", "Module path escapes its declared source_root", original))

    def test_active_context_cycle_precedes_completed_cache_guard(self):
        app, _, shared = self.vendor(library="import dep;\n" + NESTED,
                                     imports="import vendor::src::lib as local;\n", expression="42")
        original = parse(shared.read_text(), str(shared)).imports[0].span
        for backend in ("c", "rust"):
            with self.subTest(backend=backend):
                with self.assertRaises(HeptaError) as caught:
                    self.analyze(app, backend=backend)
                diagnostic = caught.exception.diagnostic
                self.assertEqual((diagnostic.code, diagnostic.phase, diagnostic.span),
                                 ("E_MODULE_CYCLE", "module", original))
                self.assertIn(str(shared) + " -> " + str(shared), diagnostic.message)

    def test_equal_named_packages_keep_distinct_nominal_and_generic_identities(self):
        app = self.manifest("equal/app", kind="bin", dependencies={"left": "../left", "right": "../right"})
        paths = []
        for name, value in (("left", 7), ("right", 42)):
            self.manifest("equal/" + name)
            paths.append(self.put("equal/" + name + "/src/lib.hepta", NESTED.replace("=42;", f"={value};")))
        self.put("equal/app/src/main.hepta", "import left;\nimport right;\n" + ROOT_DECLARATIONS +
                 "fn main()->i32 effects {} {if left::answer()==7{return right::answer();}else{return 1;}}\n")
        write_lock(app)
        for backend in ("c", "rust"):
            result = self.frontend(app, backend=backend)
            left, right = (result.project.package.dependencies[name] for name in ("left", "right"))
            self.assertEqual((left.name, left.version), (right.name, right.version))
            self.assertNotEqual(left.root, right.root)
            self.assertEqual(len(result.project.modules), 3)
            boxes = [self.declaration(result, path, "Box", "structs") for path in paths]
            functions = [self.declaration(result, path, "pack") for path in paths]
            self.assertNotEqual(boxes[0].name, boxes[1].name)
            self.assertNotEqual(boxes[0].type_params, boxes[1].type_params)
            self.assertNotEqual(functions[0].type_params, functions[1].type_params)
            for path in paths:
                self.assert_nested_identities(result, path)
        for optimize in (False, True):
            self.execute(self.frontend(app), optimize=optimize, label="equal-named")

    def test_real_rust_parity_after_all_finite_c_prerequisites(self):
        cases = []
        for kind in ("alias", "diamond"):
            app, _, _ = self.reused(kind)
            cases.append((kind, self.frontend(app), self.frontend(app, backend="rust"), 42))
        for route, expected in (("import dep;\n", 42), ("import vendor::src::lib as dep;\n", 7)):
            app, _, _ = self.vendor(imports=route)
            cases.append(("dependency" if expected == 42 else "local", self.frontend(app),
                          self.frontend(app, backend="rust"), expected))
        for label, c_result, rust_result, expected in cases:
            self.assertEqual(c_result.project.identity, rust_result.project.identity)
            self.assertEqual(c_result.program, rust_result.program)
            for optimize in (False, True):
                self.execute(c_result, expected, optimize=optimize, label=label)
        self.assertEqual(self.serial, 8)
        try:
            rustc = find_rustc()
        except HeptaError as error:
            if error.diagnostic.code != "E_TOOLCHAIN":
                raise
            self.skipTest("Actual Rust unavailable after four frontend pairs and eight GCC O0/O3 UBSan executions: "
                          + error.diagnostic.message)
        for label, _, rust_result, expected in cases:
            for optimize in (False, True):
                with self.subTest(label=label, optimize=optimize):
                    self.execute(rust_result, expected, backend="rust", rustc=rustc, optimize=optimize, label=label)


if __name__ == "__main__":
    unittest.main()
