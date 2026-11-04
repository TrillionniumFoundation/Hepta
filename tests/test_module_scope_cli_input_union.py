"""Focused #667 scope/package-context and #668 CLI input intersections.

These controls qualify stable ordinary captured-input destinations, not output
symlink/hardlink aliases or atomic publication. Native CLI checks can precede an
output refusal; refusal means no final artifact or retained debug publication.
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
from hepta.ast import Diagnostic, Expr, HeptaError, Span, Type
from hepta.backend import find_rustc, toolchain_info
from hepta.checker import CheckResult
from hepta.packages import write_lock
from hepta.parser import parse
from hepta.pipeline import Analysis, analyze_project

ROOT = Path(hepta.__file__).resolve().parents[1]
INPUT_MESSAGE = "Output cannot overwrite an input used to validate the project"
ROOT_DECLARATIONS = "struct Secret{value:i32}\nfn secret()->i32 effects {} {return 91;}\n"
IDENTITY = "pub fn identity<Secret:Copy>(secret:Secret)->Secret effects {} {return secret;}\n"
NESTED = (
    "pub struct Box<Secret>{value:Secret}\n"
    "pub enum Choice<Secret>{Value(Secret)}\n" + IDENTITY +
    "pub fn pack<Secret:Copy>(secret:Secret)->Choice<Box<Secret>> effects {} "
    "{return Choice::<Box<Secret>>::Value(Box::<Secret>{value:identity::<Secret>(secret)});}\n"
    "pub fn answer()->i32 effects {} {let secret:i32=42;let chosen=pack::<i32>(secret);"
    "match chosen{Choice::Value(v)=>{return v.value;}}}\n"
)
NATIVE_EXECUTIONS = []


def digest(data):
    return hashlib.sha256(data).hexdigest()


def nodes(value):
    yield value
    if isinstance(value, dict):
        for child in value.values():
            yield from nodes(child)
    elif isinstance(value, (tuple, list)):
        for child in value:
            yield from nodes(child)
    elif is_dataclass(value) and not isinstance(value, Span):
        for field in fields(value):
            yield from nodes(getattr(value, field.name))


class ModuleScopeCLIInputUnionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cc = shutil.which("gcc")
        if cls.cc is None:
            raise AssertionError("Actual GCC is required; Rust absence cannot hide C prerequisites")
        cls.environment = dict(os.environ, PYTHONPATH=str(ROOT), PYTHONDONTWRITEBYTECODE="1")

    def setUp(self):
        if os.environ.get("HEPTA_TEST_ROOT"):
            self.assertEqual(ROOT, Path(os.environ["HEPTA_TEST_ROOT"]).resolve())
        temporary = tempfile.TemporaryDirectory(prefix="hepta-scope-cli-input-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()

    def put(self, relative, content):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def manifest(self, relative, *, dependencies=None, kind="lib"):
        source = '[package]\nname = "same"\nversion = "0.1.0"\nkind = "' + kind + '"\n'
        if dependencies:
            source += "[dependencies]\n" + "".join(
                f"{alias} = {{ path = {json.dumps(path)} }}\n" for alias, path in dependencies.items())
        self.put(relative + "/hepta.toml", source)
        return self.root / relative

    def main(self, imports, expression="42"):
        return imports + ROOT_DECLARATIONS + "fn main()->i32 effects {} {return " + expression + ";}\n"

    def reused(self, kind="alias", *, library=NESTED):
        app = self.manifest(kind + "/app", kind="bin", dependencies=(
            {"first": "../common", "second": "../common/../common"} if kind == "alias" else
            {"left": "../left", "right": "../right"}))
        common = self.manifest(kind + "/common")
        shared = self.put(kind + "/common/src/lib.hepta", library)
        unused = self.put(kind + "/common/src/unused.hepta", "pub fn unused()->i32 effects {} {return 9;}\n")
        sidecar = self.put(kind + "/common/src/unused.hepta.imports.json", '{"unused":"captured only"}\n')
        if kind == "alias":
            imports = "import first;\nimport second;\n"
            body = ("let selected:second::Choice<first::Box<i32>>=first::pack::<i32>(42);"
                    "match selected{second::Choice::Value(v)=>{return second::identity::<i32>(v.value);}}")
        else:
            imports = "import left;\nimport right;\n"
            for branch in ("left", "right"):
                self.manifest(kind + "/" + branch, dependencies={"common": "../common"})
                self.put(kind + "/" + branch + "/src/lib.hepta", "import common as api;\n"
                         "pub fn answer()->i32 effects {} {let secret:api::Choice<api::Box<i32>>="
                         "api::pack::<i32>(42);match secret{api::Choice::Value(v)=>{return v.value;}}}\n")
            body = "if left::answer()==right::answer(){return left::answer();}else{return 1;}"
        entry = self.put(kind + "/app/src/main.hepta", imports + ROOT_DECLARATIONS +
                         "fn main()->i32 effects {} {" + body + "}\n")
        write_lock(common)
        write_lock(app)
        return app, entry, common, shared, unused, sidecar

    def vendor(self, label="vendor", *, imports="import dep;\n", library=None, expression="dep::answer()"):
        app = self.manifest(label + "/app", kind="bin", dependencies={"dep": "src/vendor"})
        dep = self.manifest(label + "/app/src/vendor")
        if library is None:
            library = ("import helper as secret;\n" +
                       NESTED.replace("let secret:i32=42;", "let secret:i32=secret::value();") +
                       "fn main()->i32 effects {} {return answer();}\n")
        shared = self.put(label + "/app/src/vendor/src/lib.hepta", library)
        self.put(label + "/app/src/helper.hepta", "pub fn value()->i32 effects {} {return 7;}\n")
        self.put(label + "/app/src/vendor/src/helper.hepta", "pub fn value()->i32 effects {} {return 42;}\n")
        entry = self.put(label + "/app/src/main.hepta", self.main(imports, expression))
        write_lock(dep)
        write_lock(app)
        return app, entry, dep, shared

    def snapshot(self):
        paths = list(self.root.rglob("*"))
        return {
            "files": {p.relative_to(self.root).as_posix(): p.read_bytes() for p in paths if p.is_file()},
            "directories": {p.relative_to(self.root).as_posix() for p in paths if p.is_dir()},
            "links": {p.relative_to(self.root).as_posix(): os.readlink(p) for p in paths if p.is_symlink()},
        }

    def cli(self, *arguments, raw=False):
        process = subprocess.run([sys.executable, "-B", "-m", "hepta", *map(str, arguments)],
                                 cwd=self.root, env=self.environment, capture_output=True,
                                 text=True, timeout=120)
        self.assertEqual(process.stderr, "", process.stderr)
        return process, process.stdout if raw else json.loads(process.stdout)

    def command(self, command, entry, destination=None, *, backend="c", locked=True, debug=False, rustc=None):
        arguments = [command, entry, "--backend", backend, "--crate-type", "bin"]
        if backend == "c":
            arguments += ["--cc", self.cc]
        elif rustc is not None:
            arguments += ["--rustc", rustc]
        if locked:
            arguments.append("--locked")
        if debug:
            arguments.append("--debug")
        if destination is not None:
            arguments += ["-o", destination]
        return arguments

    def frontend(self, entry, *, backend="c", locked=True):
        result = analyze_project(entry, backend=backend, locked=locked, native=False, crate_type="bin")
        self.assertIs(result.report["ok"], True, result.report)
        self.assertEqual(result.report["status"], "frontend_only")
        self.assertEqual(result.report["diagnostics"], [])
        self.assertIs(result.checked.ok, True)
        return result

    def frontend_pair(self, entry, *, locked=True):
        c = self.frontend(entry, locked=locked)
        rust = self.frontend(entry, backend="rust", locked=locked)
        self.assertEqual(c.project.identity, rust.project.identity)
        self.assertEqual(c.program, rust.program)
        return c, rust

    def declaration(self, result, path, name, attr="functions"):
        return next(d for d in getattr(result.program, attr)
                    if d.span.path == str(path) and (d.name == name or d.name.endswith("_" + name)))

    def assert_nested(self, result, shared, *, imported=True):
        functions = {d.name for d in result.program.functions}
        nominals = {d.name for d in [*result.program.structs, *result.program.enums]}
        pack = self.declaration(result, shared, "pack")
        identity = self.declaration(result, shared, "identity")
        box = self.declaration(result, shared, "Box", "structs")
        choice = self.declaration(result, shared, "Choice", "enums")
        for declaration in (pack, identity, box, choice):
            parameter, = declaration.type_params
            self.assertNotIn(parameter, nominals | functions)
            if imported:
                self.assertNotEqual(parameter, "Secret")
        parameter, = pack.type_params
        self.assertEqual(pack.type_bounds, {parameter: "Copy"})
        self.assertEqual(pack.params[0].type, Type(parameter))
        self.assertEqual(pack.return_type, Type(choice.name, (Type(box.name, (Type(parameter),)),)))
        self.assertNotIn(pack.params[0].name, functions)
        if imported:
            self.assertNotEqual(pack.params[0].name, "secret")
        self.assertIn(pack.params[0].name, [n.value for n in nodes(pack)
                                         if isinstance(n, Expr) and n.kind == "name"])
        self.assertIn(identity.name, [n.value for n in nodes(pack)
                                     if isinstance(n, Expr) and n.kind == "call"])
        self.assertTrue(any(isinstance(n, Expr) and n.type_args == (Type(parameter),) for n in nodes(pack)))
        self.assertEqual(sum(m["path"] == str(shared) for m in result.project.modules), 1)

    def assert_refused(self, command, entry, destination, *, diagnostic=None, checker=None, **options):
        before = self.snapshot()
        process, report = self.cli(*self.command(command, entry, destination, **options))
        self.assertEqual(self.snapshot(), before, "Refusal changed fixture bytes, files, directories or bindings")
        if checker is not None:
            self.assertEqual(process.returncode, 1, report)
            self.assertEqual(report, checker.report)
            self.assertEqual(report["status"], "rejected")
            self.assertEqual(report["checks"]["syntax"], "passed")
            self.assertEqual(report["checks"]["types_effects_resources"], "rejected")
            self.assertIn("project", report)
        elif diagnostic is not None:
            self.assertEqual(process.returncode, 1, report)
            self.assertEqual(report, {"ok": False, "status": "rejected", "diagnostics": [diagnostic]})
        else:
            self.assertEqual(process.returncode, 2, report)
            self.assertEqual(report, {"ok": False, "status": "error", "diagnostics": [
                {"code": "E_DRIVER", "phase": "driver", "message": INPUT_MESSAGE}]})
        return report

    def expected_exception(self, entry, code, message, span, *, phase="module", locked=True):
        expected = Diagnostic(code, message, span, phase=phase).to_dict()
        for backend in ("c", "rust"):
            with self.assertRaises(HeptaError) as caught:
                analyze_project(entry, backend=backend, locked=locked, native=False, crate_type="bin")
            self.assertEqual(caught.exception.diagnostic.to_dict(), expected)
        return expected

    def observe_native(self, report, analysis, output, before, expected, backend, debug, label):
        built, validation = report["build"], report["validation"]
        self.assertIs(built["ok"], True)
        self.assertIs(built["check_only"], False)
        self.assertEqual(built["status"], "gcc_checked" if backend == "c" else "rustc_checked")
        self.assertEqual(built["diagnostics"], [])
        self.assertEqual(built["artifact"], str(output))
        self.assertEqual(built["artifact_bytes"], output.stat().st_size)
        artifact_hash = digest(output.read_bytes())
        self.assertEqual(built["artifact_sha256"], artifact_hash)
        self.assertEqual(built["validation_artifact_sha256"], artifact_hash)
        generated = analysis.c if backend == "c" else analysis.rust
        generated_hash = digest(generated.encode("utf-8"))
        key = "source_sha256" if backend == "c" else "rust_sha256"
        self.assertEqual(built[key], generated_hash)
        self.assertEqual(validation["c_sha256" if backend == "c" else "rust_sha256"], generated_hash)
        self.assertEqual(validation["project"], analysis.project.report())
        self.assertEqual(validation["compiler_sha256"], analysis.report["compiler_sha256"])
        self.assertEqual(built["toolchain"]["executable_sha256"], digest(Path(built["toolchain"]["path"]).read_bytes()))
        self.assertEqual(validation["backend"]["toolchain"], built["toolchain"])
        self.assertIs(validation["backend"]["check_only"], True)
        if backend == "c":
            self.assertIs(built["rustc_used"], False)
            self.assertIn("-O0" if debug else "-O3", built["flags"])
            self.assertIn("-O3", validation["backend"]["flags"])
            self.assertNotIn("-fsanitize=undefined", built["flags"])
        else:
            self.assertIn("opt-level=0" if debug else "opt-level=3", built["flags"])
            self.assertIn("opt-level=3", validation["backend"]["flags"])
        execution = subprocess.run([str(output)], capture_output=True, text=True, timeout=5)
        self.assertEqual((execution.returncode, execution.stdout, execution.stderr), (expected, "", ""))
        for path, data in analysis.project.source_bytes.items():
            self.assertEqual(analysis.project.sources[path], digest(data))
        receipt = {
            "test": self.id(), "label": label, "backend": backend, "debug": debug,
            "expected_returncode": expected, "returncode": execution.returncode,
            "stdout": execution.stdout, "stderr": execution.stderr,
            "artifact_sha256": artifact_hash, "generated_source_sha256": generated_hash,
            "toolchain": built["toolchain"], "flags": built["flags"],
            "validation_flags": validation["backend"]["flags"],
            "compiler_sha256": validation["compiler_sha256"], "compiler_root": str(ROOT),
            "project_sha256": analysis.project.identity, "input_sources": analysis.project.sources,
            "package_files": analysis.project.package_state["files"] if analysis.project.package_state else {},
            "fixture_files": {path: digest(data) for path, data in sorted(before["files"].items())},
        }
        NATIVE_EXECUTIONS.append(receipt)
        print("SCOPE_CLI_INPUT_NATIVE " + json.dumps(receipt, sort_keys=True), flush=True)

    def assert_output(self, command, entry, output, *, expected=42, default=False, backend="c",
                      locked=True, debug=False, rustc=None, label="allowed"):
        analysis = self.frontend(entry, backend=backend, locked=locked)
        before = self.snapshot()
        output = output.resolve()
        allowed = {output.relative_to(self.root).as_posix()}
        try:
            process, report = self.cli(*self.command(command, entry, None if default else output,
                                                     backend=backend, locked=locked, debug=debug, rustc=rustc))
            self.assertEqual(process.returncode, 0, report)
            self.assertIs(report["ok"], True)
            self.assertIs(report["validation"]["ok"], True)
            self.assertTrue(output.is_file())
            self.assertTrue(output.read_bytes())
            if command == "build":
                self.assertEqual(report["schema"], "hepta.build.v1")
                self.observe_native(report, analysis, output, before, expected, backend, debug, label)
                if debug:
                    metadata = report["build"]["debug_info"]
                    generated, mapping = Path(metadata["source"]), Path(metadata["manifest"])
                    source = analysis.c if backend == "c" else analysis.rust
                    self.assertEqual(generated.read_bytes(), source.encode("utf-8"))
                    self.assertEqual(metadata["source_sha256"], digest(generated.read_bytes()))
                    retained = json.loads(mapping.read_text())
                    self.assertEqual(retained["backend"], backend)
                    self.assertEqual(retained["generated_sha256"], metadata["source_sha256"])
                    self.assertEqual(retained["generated_source"], str(generated))
                    self.assertEqual(generated.parent, output.parent / (output.name + ".hepta-debug") / metadata["source_sha256"])
                    self.assertIs(retained["optimized_variable_visibility_guaranteed"], False)
                    self.assertIn("-g3" if backend == "c" else "debuginfo=2", report["build"]["flags"])
                    allowed |= {generated.relative_to(self.root).as_posix(), mapping.relative_to(self.root).as_posix()}
            else:
                self.assertEqual(report["schema"], "hepta.output.v1")
                self.assertEqual(report["output"], str(output))
                if command == "emit":
                    self.assertEqual(output.read_text(), analysis.c if backend == "c" else analysis.rust)
                else:
                    self.assertIn("#ifndef", output.read_text())
            after = self.snapshot()
            self.assertEqual({p: b for p, b in after["files"].items() if p not in allowed},
                             {p: b for p, b in before["files"].items() if p not in allowed})
            self.assertEqual(after["links"], before["links"])
            expected_directories = set(before["directories"])
            for relative in allowed:
                expected_directories.update(p.as_posix() for p in Path(relative).parents if p != Path("."))
            self.assertEqual(after["directories"], expected_directories)
            return report
        finally:
            after = self.snapshot()
            for relative in after["files"].keys() - before["files"].keys():
                (self.root / relative).unlink()
            for relative in allowed & before["files"].keys():
                (self.root / relative).write_bytes(before["files"][relative])
            for relative in sorted(after["directories"] - before["directories"], key=lambda p: len(Path(p).parts), reverse=True):
                (self.root / relative).rmdir()

    def test_alias_nested_bindings_reach_manifest_unused_source_and_lock_guard(self):
        app, entry, common, shared, unused, _ = self.reused()
        original = entry.read_text()
        for reverse in (False, True):
            entry.write_text(original.replace("import first;\nimport second;\n",
                                              "import second;\nimport first;\n") if reverse else original,
                             encoding="utf-8")
            write_lock(app)
            for result in self.frontend_pair(app):
                self.assert_nested(result, shared)
                self.assertEqual(result.project.package.root, app)
                deps = result.project.package.dependencies
                self.assertIs(deps["first"], deps["second"])
                self.assertEqual(len(result.project.modules), 2)
                module = next(m for m in result.project.modules if m["path"] == str(entry))
                self.assertEqual(module["imports"], {"first": str(shared), "second": str(shared)})
                self.assertNotIn(str(unused), result.project.sources)
                self.assertIn("../common/src/unused.hepta", result.project.package_state["files"])
            for command, target in (("emit", app / "hepta.toml"), ("header", unused), ("build", app / "Hepta.lock")):
                with self.subTest(reverse=reverse, command=command, target=target.name):
                    self.assert_refused(command, app, target)

    def test_diamond_transitive_snapshot_and_loaded_c_header_inventory(self):
        app, _, common, shared, unused, sidecar = self.reused("diamond")
        header = self.put("diamond/common/api.h", "/* Finite empty header; no foreign execution. */\n")
        bindings = common / "src/bindings.hepta"
        process, report = self.cli("import-c", header, "--cc", self.cc, "-o", bindings)
        self.assertEqual(process.returncode, 0, report)
        self.assertIs(report["ok"], True)
        shared.write_text("import bindings;\n" + shared.read_text(), encoding="utf-8")
        write_lock(app)
        for result in self.frontend_pair(app):
            self.assert_nested(result, shared)
            deps = result.project.package.dependencies
            self.assertIs(deps["left"].dependencies["common"], deps["right"].dependencies["common"])
            self.assertEqual(len(result.project.modules), 5)
            captured = {(app / p).resolve() for p in result.project.package_state["files"]}
            self.assertTrue({common / "hepta.toml", unused, sidecar}.issubset(captured))
            self.assertNotIn(header, captured)
            self.assertNotIn(str(unused), result.project.sources)
            self.assertNotIn(str(sidecar), result.project.sources)
            self.assertTrue({str(bindings), str(bindings) + ".imports.json", str(header)}.issubset(result.project.sources))
            self.assertEqual(len(result.project.c_imports), 1)
        targets = (("emit", common / "hepta.toml"), ("header", sidecar), ("build", unused),
                   ("emit", Path(str(bindings) + ".imports.json")), ("build", header))
        for command, target in targets:
            with self.subTest(command=command, target=target.name):
                self.assert_refused(command, app, target)

    def test_single_routes_select_7_42_and_actual_owner_across_entry_forms(self):
        cases = (("local", "import vendor::src::lib as dep;\n", "directory", 7),
                 ("dependency", "import dep;\n", "manifest", 42),
                 ("direct", "import dep;\n", "direct_source", 42))
        for label, imports, form, expected in cases:
            with self.subTest(route=label, entry=form, expected=expected):
                app, _, dep, shared = self.vendor(label, imports=imports)
                entry = app if form == "directory" else app / "hepta.toml" if form == "manifest" else shared
                owner = dep if form == "direct_source" else app
                for result in self.frontend_pair(entry):
                    self.assert_nested(result, shared, imported=form != "direct_source")
                    self.assertEqual(result.project.package.root, owner)
                    self.assertEqual(result.report["project"]["package"]["root"], str(owner))
                    helper = app / ("src/helper.hepta" if expected == 7 else "src/vendor/src/helper.hepta")
                    module = next(m for m in result.project.modules if m["path"] == str(shared))
                    self.assertEqual(module["imports"], {"secret": str(helper)})
                    expected_entry = shared if form == "direct_source" else app / "src/main.hepta"
                    self.assertEqual(result.project.entry, expected_entry)
                self.assert_refused("build", entry, owner / "Hepta.lock")
                self.assert_output("build", entry, self.root / (label + "-program"), expected=expected, label=label)

    def test_context_both_orders_keep_exception_priority_over_output_and_debug(self):
        app, entry, dep, shared = self.vendor()
        for reverse in (False, True):
            imports = ["import vendor::src::lib as local;", "import dep;"]
            if reverse:
                imports.reverse()
            entry.write_text(self.main("\n".join(imports) + "\n", "dep::answer()"), encoding="utf-8")
            write_lock(app)
            roots = (dep, app) if reverse else (app, dep)
            span = parse(entry.read_text(), str(entry)).imports[1].span
            diagnostic = self.expected_exception(app, "E_MODULE_PACKAGE_CONTEXT",
                f"Module {shared} is imported under conflicting package roots: {roots[0]} and {roots[1]}", span)
            for protected, command in ((True, "emit"), (False, "build")):
                with self.subTest(reverse=reverse, protected=protected, command=command):
                    target = app / "hepta.toml" if protected else self.root / "ordinary/nested/program"
                    self.assert_refused(command, app, target, diagnostic=diagnostic, debug=command == "build")

    def test_scope_privacy_and_generic_checker_precede_guard_then_renamed_reaches_it(self):
        cases = (("scope", IDENTITY + "pub fn answer(secret:i32)->i32 effects {} {return secret();}\n", "dep::answer(42)",
                  "E_MODULE_SCOPE", "Unqualified symbol is not declared in this module: secret", "header"),
                 ("private", "fn answer()->i32 effects {} {return 42;}\n", "dep::answer()",
                  "E_MODULE_PRIVATE", "Imported symbol is private: dep::answer", "build"))
        for label, library, expression, code, message, command in cases:
            with self.subTest(kind=label, command=command):
                app, entry, _, shared = self.vendor(label, library=library, expression=expression)
                path = shared if label == "scope" else entry
                span = next(n.span for n in nodes(parse(path.read_text(), str(path)))
                            if isinstance(n, Expr) and n.kind == "call")
                diagnostic = self.expected_exception(app, code, message, span)
                self.assert_refused(command, app, app / "hepta.toml", diagnostic=diagnostic, debug=command == "build")
        source = "struct Secret{value:i32}\n" + IDENTITY
        app, _, _, shared = self.vendor("generic", library=source, expression="dep::identity::<i32>(42)")
        original = parse(source, str(shared)).functions[0]
        for backend in ("c", "rust"):
            with self.subTest(kind="checker", backend=backend):
                result = analyze_project(app, backend=backend, locked=True, native=False, crate_type="bin")
                self.assertIsInstance(result, Analysis)
                self.assertIsInstance(result.checked, CheckResult)
                self.assertIs(result.checked.ok, False)
                self.assertIsNone(result.c)
                self.assertIsNone(result.rust)
                nominal = self.declaration(result, shared, "Secret", "structs")
                identity = self.declaration(result, shared, "identity")
                self.assertEqual(identity.type_params, (nominal.name,))
                expected = Diagnostic("E_GENERIC_PARAMETER", "duplicate or shadowing generic parameter " + nominal.name,
                                      original.span, phase="check").to_dict()
                self.assertIn(expected, result.report["diagnostics"])
                self.assertEqual(result.report["diagnostics"], [d.to_dict() for d in result.checked.diagnostics])
                self.assert_refused("emit", app, app / "Hepta.lock", checker=result, backend=backend)
        shared.write_text("struct Secret{value:i32}\n" + IDENTITY.replace("Secret", "T"), encoding="utf-8")
        write_lock(app)
        self.frontend_pair(app)
        self.assert_refused("build", app, app / "hepta.toml", debug=True)
        self.assert_output("build", app, self.root / "renamed-program", label="renamed-generic")

    def test_stale_lock_escape_cycle_and_c_import_keep_earlier_priority(self):
        app, entry, _, shared = self.vendor("stale")
        entry.write_text(self.main("import vendor::src::lib as local;\nimport dep;\n"), encoding="utf-8")
        diagnostic = self.expected_exception(app, "E_LOCK_STALE", "Manifest, dependency graph, or source bytes differ from Hepta.lock",
                                             Span(path=str(app / "Hepta.lock")), phase="package")
        with self.subTest(priority="stale_lock", command="emit"):
            self.assert_refused("emit", app, app / "hepta.toml", diagnostic=diagnostic)

        app = self.manifest("escape/app", kind="bin", dependencies={"dep": "vendor"})
        self.manifest("escape/app/vendor")
        shared = self.put("escape/app/vendor/src/lib.hepta", NESTED)
        entry = self.put("escape/app/src/main.hepta", self.main("import dep;\nimport escaped;\n"))
        # This is an existing module-loader escape control, not an output alias.
        (app / "src/escaped.hepta").symlink_to(shared)
        write_lock(app)
        diagnostic = self.expected_exception(app, "E_MODULE_ESCAPE", "Module path escapes its declared source_root",
                                             parse(entry.read_text(), str(entry)).imports[1].span)
        with self.subTest(priority="escape", command="header"):
            self.assert_refused("header", app, app / "Hepta.lock", diagnostic=diagnostic)

        app, _, _, shared = self.vendor("cycle", imports="import vendor::src::lib as local;\n",
                                       library="import dep;\n" + NESTED, expression="42")
        span = parse(shared.read_text(), str(shared)).imports[0].span
        entry = app / "src/main.hepta"
        diagnostic = self.expected_exception(app, "E_MODULE_CYCLE", f"Import cycle: {entry} -> {shared} -> {shared}", span)
        with self.subTest(priority="cycle", command="build"):
            self.assert_refused("build", app, app / "hepta.toml", diagnostic=diagnostic, debug=True)

        app, entry, _, shared = self.vendor("c_import", imports="import vendor::src::lib as local;\nimport dep;\n",
                                           library="// hepta:c-import:v1\n" + NESTED, expression="42")
        self.put("c_import/app/src/vendor/src/lib.hepta.imports.json", '{}\n')
        write_lock(app)
        diagnostic = self.expected_exception(app, "E_C_IMPORT_IDENTITY", "C binding source differs from its probe metadata",
                                             parse(entry.read_text(), str(entry)).imports[0].span)
        with self.subTest(priority="c_import", command="emit"):
            self.assert_refused("emit", app, app / "hepta.toml", diagnostic=diagnostic)

    def test_allowed_locks_standalone_sibling_ordinary_default_and_stdout(self):
        app, _, common, _, _, _ = self.reused()
        allowed = (("emit", app / "Hepta.lock", False), ("header", common / "Hepta.lock", True),
                   ("emit", self.root / "ordinary/new.c", True), ("header", self.put("ordinary/existing.h", "old output\n"), True))
        for command, target, locked in allowed:
            with self.subTest(command=command, target=target.relative_to(self.root).as_posix(), locked=locked):
                self.assert_output(command, app, target, locked=locked)
        with self.subTest(command="build", destination="ordinary_default"):
            self.assert_output("build", app, app / "src/build/main", default=True, label="default")
        for command in ("emit", "header"):
            with self.subTest(command=command, destination="stdout"):
                before = self.snapshot()
                process, content = self.cli(*self.command(command, app), raw=True)
                self.assertEqual(process.returncode, 0, content)
                if command == "emit":
                    self.assertEqual(content, self.frontend(app).c)
                else:
                    self.assertIn("#ifndef", content)
                self.assertEqual(self.snapshot(), before)
        entry = self.put("standalone/main.hepta", self.main("import used;\n", "used::answer()"))
        shared = self.put("standalone/used.hepta", NESTED)
        unused = self.put("standalone/unused.hepta", "fn unrelated()->i32 effects {} {return 9;}\n")
        for result in self.frontend_pair(entry, locked=False):
            self.assertIsNone(result.project.package)
            self.assertIsNone(result.project.package_state)
            self.assert_nested(result, shared)
            self.assertNotIn(str(unused), result.project.sources)
        with self.subTest(command="emit", destination="standalone_unused"):
            self.assert_output("emit", entry, unused, locked=False)
        with self.subTest(command="build", destination="standalone_loaded"):
            self.assert_refused("build", entry, shared, locked=False)

    def test_real_c_debug_refusal_and_retained_source_control(self):
        app, _, _, shared, _, _ = self.reused("diamond")
        for result in self.frontend_pair(app):
            self.assert_nested(result, shared)
        with self.subTest(backend="c", debug=True, destination="protected"):
            self.assert_refused("build", app, app / "hepta.toml", debug=True)
        with self.subTest(backend="c", debug=True, destination="ordinary"):
            self.assert_output("build", app, self.root / "debug/program", debug=True, label="diamond-debug")

    def test_z_real_rust_parity_after_actual_c_route_prerequisites(self):
        cases = []
        for label, imports, expected in (("local", "import vendor::src::lib as dep;\n", 7),
                                          ("dependency", "import dep;\n", 42)):
            app, _, _, shared = self.vendor("parity-" + label, imports=imports)
            for result in self.frontend_pair(app):
                self.assert_nested(result, shared)
            with self.subTest(backend="c", route=label, expected=expected):
                self.assert_output("build", app, self.root / ("c-" + label), expected=expected, label=label + "-rust-prerequisite")
            cases.append((label, app, expected))
        try:
            rustc = find_rustc()
        except HeptaError as error:
            if error.diagnostic.code != "E_TOOLCHAIN":
                raise
            self.skipTest("Two C/Rust frontend pairs and actual GCC O3 7/42 executions passed; actual rustc absent: " + error.diagnostic.message)
        identity = toolchain_info(rustc)
        self.assertIn("release: 1.90.0", identity["version"].splitlines())
        for label, app, expected in cases:
            with self.subTest(backend="rust", route=label, expected=expected):
                self.assert_output("build", app, self.root / ("rust-" + label), expected=expected,
                                   backend="rust", rustc=rustc, label=label)
                self.assert_refused("build", app, app / "Hepta.lock", backend="rust", rustc=rustc)
        app, _, _, _, _, sidecar = self.reused()
        self.frontend_pair(app)
        with self.subTest(backend="rust", route="alias", debug=True):
            self.assert_refused("build", app, sidecar, backend="rust", rustc=rustc, debug=True)
            self.assert_output("build", app, self.root / "rust-debug/program", backend="rust", rustc=rustc,
                               debug=True, label="alias-debug")
        with self.subTest(backend="rust", command="emit"):
            self.assert_refused("emit", app, app / "hepta.toml", backend="rust", rustc=rustc)
        with self.subTest(backend="rust", command="header"):
            self.assert_refused("header", app, sidecar, backend="rust", rustc=rustc)


if __name__ == "__main__":
    unittest.main()
