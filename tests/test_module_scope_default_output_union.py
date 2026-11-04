"""Nested module scope/package ownership with resolved default-output aliases.

Only stable ordinary symlinks in self-created trees are exercised. Refusal
means no final artifact/debug publication, not absence of native validation.
There are no hardlink, race, atomic-publication, or native-isolation claims.
"""
from __future__ import annotations

from contextlib import contextmanager
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
from hepta.ast import Diagnostic, Expr, HeptaError, Span
from hepta.backend import find_rustc, toolchain_info
from hepta.checker import CheckResult
from hepta.packages import write_lock
from hepta.parser import parse
from hepta.pipeline import Analysis, analyze_project
from tests import test_cli_default_output_path as default_component
from tests import test_module_scope_cli_input_union as scope_component

ROOT = Path(hepta.__file__).resolve().parents[1]
NATIVE_EXECUTIONS = []
CLI_EXECUTIONS = []


def digest(data):
    return hashlib.sha256(data).hexdigest()


class ModuleScopeDefaultOutputUnionTests(unittest.TestCase):
    # Reuse only alias-independent fixture/frontend helpers, never TestCase
    # inheritance, the dereferencing snapshot, or its resolving output helper.
    put = scope_component.ModuleScopeCLIInputUnionTests.put
    manifest = scope_component.ModuleScopeCLIInputUnionTests.manifest
    main = scope_component.ModuleScopeCLIInputUnionTests.main
    reused = scope_component.ModuleScopeCLIInputUnionTests.reused
    vendor = scope_component.ModuleScopeCLIInputUnionTests.vendor
    command = scope_component.ModuleScopeCLIInputUnionTests.command
    frontend = scope_component.ModuleScopeCLIInputUnionTests.frontend
    frontend_pair = scope_component.ModuleScopeCLIInputUnionTests.frontend_pair
    declaration = scope_component.ModuleScopeCLIInputUnionTests.declaration
    assert_nested = scope_component.ModuleScopeCLIInputUnionTests.assert_nested
    expected_exception = scope_component.ModuleScopeCLIInputUnionTests.expected_exception

    @classmethod
    def setUpClass(cls):
        cls.cc = shutil.which("gcc")
        if cls.cc is None:
            raise AssertionError("Actual GCC is required before optional pinned Rust parity")
        cls.environment = dict(os.environ, PYTHONPATH=str(ROOT), PYTHONDONTWRITEBYTECODE="1")
        # Bind subprocess imports to this physical candidate, not another checkout.
        with tempfile.TemporaryDirectory(prefix="hepta-scope-default-import-") as directory:
            imported = subprocess.run(
                [sys.executable, "-B", "-c", "import hepta.cli; print(hepta.cli.__file__)"],
                cwd=directory, env=cls.environment, capture_output=True, text=True, check=True)
            if imported.stderr or Path(imported.stdout.strip()).resolve() != ROOT / "hepta/cli.py":
                raise AssertionError("CLI import is not the physical candidate: " + repr(imported))

    def setUp(self):
        if os.environ.get("HEPTA_TEST_ROOT"):
            self.assertEqual(ROOT, Path(os.environ["HEPTA_TEST_ROOT"]).resolve())
        temporary = tempfile.TemporaryDirectory(prefix="hepta-scope-default-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()

    def snapshot(self):
        files, directories, links = default_component.snapshot(self.root)
        return {"files": files, "directories": directories, "links": links}

    def cli(self, *arguments, raw=False):
        argv = [sys.executable, "-B", "-m", "hepta", *map(str, arguments)]
        process = subprocess.run(argv, cwd=self.root, env=self.environment,
                                 capture_output=True, text=True, timeout=120)
        record = {"test": self.id(), "argv": argv, "cwd": str(self.root),
                  "returncode": process.returncode, "stdout": process.stdout, "stderr": process.stderr}
        CLI_EXECUTIONS.append(record)
        evidence = os.environ.get("HEPTA_SCOPE_DEFAULT_EVIDENCE_DIR")
        if evidence:
            with (Path(evidence) / "cli-executions.jsonl").open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(record, sort_keys=True) + "\n")
        self.assertEqual(process.stderr, "", process.stderr)
        return process, process.stdout if raw else json.loads(process.stdout)

    def default_alias(self, analysis):
        entry = analysis.project.entry
        self.assertEqual(entry, entry.resolve())
        return entry.parent / "build" / entry.stem

    @contextmanager
    def alias(self, requested, target, *, relative=True, directory=False):
        requested.parent.mkdir(parents=True, exist_ok=True)
        self.assertFalse(requested.exists() or requested.is_symlink())
        text = os.path.relpath(target, requested.parent) if relative else str(target)
        requested.symlink_to(text, target_is_directory=directory)
        try:
            self.assertEqual(os.readlink(requested), text)
            self.assertEqual(requested.resolve(), target.resolve())
            yield requested
        finally:
            if requested.is_symlink():
                requested.unlink()

    def assert_refused(self, entry, alias, *, explicit=False, diagnostic=None, checker=None, **options):
        before = self.snapshot()
        process, report = self.cli(*self.command("build", entry, alias if explicit else None, **options))
        after = self.snapshot()
        self.assertEqual(after["files"], before["files"], "Physical file bytes/inventory changed on refusal")
        self.assertEqual(after["directories"], before["directories"], "Artifact/debug directory published on refusal")
        self.assertEqual(after["links"], before["links"], "Alias text/inventory changed on refusal")
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
            self.assertEqual(report, default_component.INPUT_ERROR)
        return report

    def observe_native(self, report, analysis, requested, target, before, *, expected, backend,
                       debug, explicit, locked, label):
        built, validation = report["build"], report["validation"]
        self.assertIs(built["ok"], True)
        self.assertIs(built["check_only"], False)
        self.assertEqual(built["status"], "gcc_checked" if backend == "c" else "rustc_checked")
        self.assertEqual(built["diagnostics"], [])
        self.assertEqual(built["artifact"], str(target))
        self.assertEqual(built["artifact_bytes"], target.stat().st_size)
        artifact_hash = digest(target.read_bytes())
        self.assertEqual(built["artifact_sha256"], artifact_hash)
        self.assertEqual(built["validation_artifact_sha256"], artifact_hash)
        source = analysis.c if backend == "c" else analysis.rust
        generated_hash = digest(source.encode("utf-8"))
        source_key = "source_sha256" if backend == "c" else "rust_sha256"
        validation_key = "c_sha256" if backend == "c" else "rust_sha256"
        self.assertEqual(built[source_key], generated_hash)
        self.assertEqual(validation[validation_key], generated_hash)
        self.assertEqual(validation["project"], analysis.project.report())
        self.assertEqual(validation["compiler_sha256"], analysis.report["compiler_sha256"])
        compiler = Path(built["toolchain"]["path"])
        self.assertEqual(built["toolchain"]["executable_sha256"], digest(compiler.read_bytes()))
        self.assertEqual(validation["backend"]["toolchain"], built["toolchain"])
        self.assertIs(validation["backend"]["check_only"], True)
        if backend == "c":
            identity = subprocess.run([str(compiler), "--version"], capture_output=True, text=True, timeout=30)
            self.assertEqual(identity.returncode, 0, identity.stderr)
            self.assertEqual(identity.stderr, "")
            self.assertEqual(built["toolchain"]["version"], identity.stdout.strip())
            self.assertEqual(compiler.resolve(), Path(self.cc).resolve())
            self.assertIs(built["rustc_used"], False)
            self.assertIn("-std=c11", built["flags"])
            self.assertIn("-O0" if debug else "-O3", built["flags"])
            self.assertNotIn("-O3" if debug else "-O0", built["flags"])
            self.assertIn("-O3", validation["backend"]["flags"])
            self.assertNotIn("-O0", validation["backend"]["flags"])
            self.assertNotIn("-fsanitize=undefined", built["flags"])
            self.assertNotIn("-fsanitize=undefined", validation["backend"]["flags"])
        else:
            self.assertEqual(built["toolchain"], toolchain_info(str(compiler)))
            self.assertIn("release: 1.90.0", built["toolchain"]["version"].splitlines())
            self.assertIn("opt-level=0" if debug else "opt-level=3", built["flags"])
            self.assertNotIn("opt-level=3" if debug else "opt-level=0", built["flags"])
            self.assertIn("opt-level=3", validation["backend"]["flags"])
        for path, data in analysis.project.source_bytes.items():
            self.assertEqual(analysis.project.sources[path], digest(data))
            self.assertEqual(before["files"][Path(path).relative_to(self.root).as_posix()], data)
        if analysis.project.package_state:
            for path, sha in analysis.project.package_state["files"].items():
                physical = (analysis.project.package.root / path).resolve()
                self.assertEqual(sha, digest(before["files"][physical.relative_to(self.root).as_posix()]))
        execution = subprocess.run([str(target)], capture_output=True, text=True, timeout=5)
        self.assertEqual((execution.returncode, execution.stdout, execution.stderr), (expected, "", ""))
        receipt = {
            "test": self.id(), "label": label, "backend": backend, "debug": debug,
            "explicit": explicit, "locked": locked, "requested_alias": str(requested),
            "output_argument": str(requested) if explicit else None, "resolved_target": str(target),
            "alias_text": before["links"].get(requested.relative_to(self.root).as_posix()),
            "entry": str(analysis.project.entry),
            "owner": str(analysis.project.package.root) if analysis.project.package else None,
            "expected_returncode": expected, "returncode": execution.returncode,
            "stdout": execution.stdout, "stderr": execution.stderr,
            "artifact_sha256": artifact_hash, "artifact_bytes": target.stat().st_size,
            "generated_source_sha256": generated_hash,
            "build_source_sha256": built[source_key], "validation_source_sha256": validation[validation_key],
            "build_artifact_sha256": built["artifact_sha256"],
            "validation_artifact_sha256": built["validation_artifact_sha256"],
            "toolchain": built["toolchain"], "flags": built["flags"],
            "validation_flags": validation["backend"]["flags"],
            "compiler_sha256": validation["compiler_sha256"], "compiler_root": str(ROOT),
            "project_sha256": analysis.project.identity, "input_sources": analysis.project.sources,
            "project": analysis.project.report(),
            "package_files": analysis.project.package_state["files"] if analysis.project.package_state else {},
            "fixture_files": {p: digest(b) for p, b in sorted(before["files"].items())},
            "fixture_directories": sorted(before["directories"]), "fixture_links": before["links"],
        }
        NATIVE_EXECUTIONS.append(receipt)
        print("SCOPE_DEFAULT_NATIVE " + json.dumps(receipt, sort_keys=True), flush=True)

    def assert_output(self, entry, requested, *, expected=42, explicit=False, backend="c", locked=True,
                      debug=False, rustc=None, label="permitted"):
        analysis = self.frontend(entry, backend=backend, locked=locked)
        if not explicit:
            self.assertEqual(requested, self.default_alias(analysis))
        target = requested.resolve()
        self.assertNotEqual(requested, target, "This cross-feature control must really use an alias")
        before = self.snapshot()
        allowed = {target.relative_to(self.root).as_posix()}
        try:
            process, report = self.cli(*self.command("build", entry, requested if explicit else None,
                                                     backend=backend, locked=locked, debug=debug, rustc=rustc))
            self.assertEqual(process.returncode, 0, report)
            self.assertIs(report["ok"], True)
            self.assertEqual(report["schema"], "hepta.build.v1")
            self.assertIs(report["validation"]["ok"], True)
            self.assertTrue(target.is_file())
            self.assertTrue(target.read_bytes())
            self.assertNotEqual(target.read_bytes(), before["files"].get(target.relative_to(self.root).as_posix()))
            self.observe_native(report, analysis, requested, target, before, expected=expected, backend=backend,
                                debug=debug, explicit=explicit, locked=locked, label=label)
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
                self.assertEqual(generated.parent, target.parent / (target.name + ".hepta-debug") / metadata["source_sha256"])
                self.assertEqual(mapping.parent, generated.parent)
                self.assertFalse((requested.parent / (requested.name + ".hepta-debug")).exists())
                self.assertIs(retained["optimized_variable_visibility_guaranteed"], False)
                self.assertIn("-g3" if backend == "c" else "debuginfo=2", report["build"]["flags"])
                self.assertIn("-fno-omit-frame-pointer" if backend == "c" else "force-frame-pointers=yes", report["build"]["flags"])
                allowed |= {generated.relative_to(self.root).as_posix(), mapping.relative_to(self.root).as_posix()}
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
            # Restore only outputs to permit sequential lock-output controls.
            # The comparisons above happen first and never excuse other changes.
            after = self.snapshot()
            for relative in after["files"].keys() - before["files"].keys():
                (self.root / relative).unlink()
            for relative in allowed & before["files"].keys():
                (self.root / relative).write_bytes(before["files"][relative])
            for relative in sorted(after["directories"] - before["directories"],
                                   key=lambda p: len(Path(p).parts), reverse=True):
                (self.root / relative).rmdir()

    def add_c_binding(self, app, common, shared):
        header = self.put(str(common.relative_to(self.root) / "api.h"), "/* Finite empty header. */\n")
        bindings = common / "src/bindings.hepta"
        process, report = self.cli("import-c", header, "--cc", self.cc, "-o", bindings)
        self.assertEqual(process.returncode, 0, report)
        self.assertIs(report["ok"], True)
        shared.write_text("import bindings;\n" + shared.read_text(), encoding="utf-8")
        write_lock(common)
        write_lock(app)
        return header, bindings, Path(str(bindings) + ".imports.json")

    def test_nested_alias_and_diamond_default_input_aliases(self):
        app, entry, common, shared, unused, sidecar = self.reused()
        original = entry.read_text()
        for reverse in (False, True):
            entry.write_text(original.replace("import first;\nimport second;\n", "import second;\nimport first;\n")
                             if reverse else original, encoding="utf-8")
            write_lock(app)
            for result in self.frontend_pair(app):
                self.assert_nested(result, shared)
                self.assertEqual(result.project.package.root, app)
                self.assertEqual(result.project.entry, entry)
                dependencies = result.project.package.dependencies
                self.assertIs(dependencies["first"], dependencies["second"])
                self.assertEqual(len(result.project.modules), 2)
                module = next(m for m in result.project.modules if m["path"] == str(entry))
                self.assertEqual(module["imports"], {"first": str(shared), "second": str(shared)})
                self.assertNotIn(str(unused), result.project.sources)
                self.assertNotIn(str(sidecar), result.project.sources)
                self.assertIn("../common/src/unused.hepta", result.project.package_state["files"])
            alias = self.default_alias(result)
            for index, target in enumerate((shared, unused, sidecar, common / "hepta.toml")):
                explicit, relative = index == 3, index % 2 == 0
                with self.subTest(graph="repeated_alias", reverse=reverse, target=target.name,
                                  explicit=explicit, relative=relative):
                    with self.alias(alias, target, relative=relative):
                        self.assert_refused(app, alias, explicit=explicit)
        app, entry, common, shared, unused, sidecar = self.reused("diamond")
        header, bindings, loaded_sidecar = self.add_c_binding(app, common, shared)
        for result in self.frontend_pair(app):
            self.assert_nested(result, shared)
            dependencies = result.project.package.dependencies
            self.assertIs(dependencies["left"].dependencies["common"], dependencies["right"].dependencies["common"])
            self.assertEqual(len(result.project.modules), 5)
            captured = {(app / p).resolve() for p in result.project.package_state["files"]}
            self.assertTrue({common / "hepta.toml", unused, sidecar}.issubset(captured))
            self.assertNotIn(header, captured)
            self.assertTrue({str(bindings), str(loaded_sidecar), str(header)}.issubset(result.project.sources))
            self.assertNotIn(str(unused), result.project.sources)
            self.assertNotIn(str(sidecar), result.project.sources)
            self.assertEqual(len(result.project.c_imports), 1)
        alias = self.default_alias(result)
        for index, target in enumerate((common / "hepta.toml", unused, loaded_sidecar, header)):
            for explicit in ((False, True) if target == header else (False,)):
                with self.subTest(graph="diamond", target=target.name, explicit=explicit, relative=index % 2 == 0):
                    with self.alias(alias, target, relative=index % 2 == 0):
                        self.assert_refused(app, alias, explicit=explicit, debug=index == 2)

    def test_nested_entry_routes_select_actual_owner(self):
        cases = (("local", "import vendor::src::lib as dep;\n", "directory", 7),
                 ("dependency", "import dep;\n", "manifest", 42),
                 ("direct", "import dep;\n", "direct_source", 42))
        for label, imports, form, expected in cases:
            app, main, dep, shared = self.vendor(label, imports=imports)
            entry = app if form == "directory" else app / "hepta.toml" if form == "manifest" else shared
            owner = dep if form == "direct_source" else app
            for result in self.frontend_pair(entry):
                self.assert_nested(result, shared, imported=form != "direct_source")
                self.assertEqual(result.project.package.root, owner)
                self.assertEqual(result.report["project"]["package"]["root"], str(owner))
                self.assertEqual(result.project.entry, shared if form == "direct_source" else main)
                helper = app / ("src/helper.hepta" if expected == 7 else "src/vendor/src/helper.hepta")
                module = next(m for m in result.project.modules if m["path"] == str(shared))
                self.assertEqual(module["imports"], {"secret": str(helper)})
            alias = self.default_alias(result)
            with self.subTest(route=label, entry=form, destination="verified_owner_lock", expected=expected):
                with self.alias(alias, owner / "Hepta.lock", relative=label != "dependency"):
                    self.assert_refused(entry, alias)
            unread = app / "Hepta.lock" if owner == dep else dep / "Hepta.lock"
            for target, locked, purpose in ((unread, True, "unread_lock"),
                                             (owner / "Hepta.lock", False, "unlocked_owner_lock")):
                with self.subTest(route=label, entry=form, destination=purpose, expected=expected):
                    with self.alias(alias, target, relative=locked):
                        self.assert_output(entry, alias, expected=expected, locked=locked,
                                           label=label + "-" + purpose)

    def test_context_conflict_priority_for_default_aliases(self):
        app, entry, dep, shared = self.vendor()
        for reverse in (False, True):
            imports = ["import vendor::src::lib as local;", "import dep;"]
            if reverse:
                imports.reverse()
            entry.write_text(self.main("\n".join(imports) + "\n", "dep::answer()"), encoding="utf-8")
            write_lock(app)
            roots = (dep, app) if reverse else (app, dep)
            diagnostic = self.expected_exception(app, "E_MODULE_PACKAGE_CONTEXT",
                f"Module {shared} is imported under conflicting package roots: {roots[0]} and {roots[1]}",
                parse(entry.read_text(), str(entry)).imports[1].span)
            alias = entry.parent / "build" / entry.stem
            for protected in (True, False):
                target = app / "hepta.toml" if protected else self.root / "ordinary/nested/program"
                with self.subTest(reverse=reverse, protected=protected, explicit=False, debug=True):
                    with self.alias(alias, target, relative=protected):
                        self.assert_refused(app, alias, diagnostic=diagnostic, debug=True)

    def test_scope_and_generic_priority_for_default_aliases(self):
        cases = (("scope", scope_component.IDENTITY + "pub fn answer(secret:i32)->i32 effects {} {return secret();}\n",
                  "dep::answer(42)", "E_MODULE_SCOPE", "Unqualified symbol is not declared in this module: secret"),
                 ("private", "fn answer()->i32 effects {} {return 42;}\n", "dep::answer()",
                  "E_MODULE_PRIVATE", "Imported symbol is private: dep::answer"))
        for label, library, expression, code, message in cases:
            app, entry, _, shared = self.vendor(label, library=library, expression=expression)
            path = shared if label == "scope" else entry
            span = next(n.span for n in scope_component.nodes(parse(path.read_text(), str(path)))
                        if isinstance(n, Expr) and n.kind == "call")
            diagnostic = self.expected_exception(app, code, message, span)
            alias = entry.parent / "build" / entry.stem
            with self.subTest(error=code, explicit=False):
                with self.alias(alias, app / "hepta.toml", relative=label == "scope"):
                    self.assert_refused(app, alias, diagnostic=diagnostic, debug=True)
        source = "struct Secret{value:i32}\n" + scope_component.IDENTITY
        app, entry, _, shared = self.vendor("generic", library=source, expression="dep::identity::<i32>(42)")
        original = parse(source, str(shared)).functions[0]
        alias = entry.parent / "build" / entry.stem
        for backend in ("c", "rust"):
            with self.subTest(error="E_GENERIC_PARAMETER", backend=backend):
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
                with self.alias(alias, app / "Hepta.lock"):
                    self.assert_refused(app, alias, checker=result, backend=backend, debug=True)
        shared.write_text("struct Secret{value:i32}\n" + scope_component.IDENTITY.replace("Secret", "T"), encoding="utf-8")
        write_lock(app)
        for result in self.frontend_pair(app):
            self.assertEqual(self.default_alias(result), alias)
        with self.subTest(recovery="protected"):
            with self.alias(alias, app / "hepta.toml"):
                self.assert_refused(app, alias, debug=True)
        with self.subTest(recovery="permitted"):
            with self.alias(alias, self.root / "renamed/program", relative=False):
                self.assert_output(app, alias, label="renamed-generic")

    def test_earlier_errors_precede_default_alias_guard(self):
        app, entry, _, _ = self.vendor("stale")
        entry.write_text(self.main("import vendor::src::lib as local;\nimport dep;\n"), encoding="utf-8")
        diagnostic = self.expected_exception(app, "E_LOCK_STALE", "Manifest, dependency graph, or source bytes differ from Hepta.lock",
                                             Span(path=str(app / "Hepta.lock")), phase="package")
        with self.subTest(priority="stale_lock"):
            alias = entry.parent / "build" / entry.stem
            with self.alias(alias, app / "hepta.toml"):
                self.assert_refused(app, alias, diagnostic=diagnostic)
        app = self.manifest("escape/app", kind="bin", dependencies={"dep": "vendor"})
        self.manifest("escape/app/vendor")
        shared = self.put("escape/app/vendor/src/lib.hepta", scope_component.NESTED)
        entry = self.put("escape/app/src/main.hepta", self.main("import dep;\nimport escaped;\n"))
        (app / "src/escaped.hepta").symlink_to(shared)
        write_lock(app)
        diagnostic = self.expected_exception(app, "E_MODULE_ESCAPE", "Module path escapes its declared source_root",
                                             parse(entry.read_text(), str(entry)).imports[1].span)
        with self.subTest(priority="escape"):
            alias = entry.parent / "build" / entry.stem
            with self.alias(alias, app / "Hepta.lock", relative=False):
                self.assert_refused(app, alias, diagnostic=diagnostic)
        app, entry, _, shared = self.vendor("cycle", imports="import vendor::src::lib as local;\n",
                                            library="import dep;\n" + scope_component.NESTED, expression="42")
        diagnostic = self.expected_exception(app, "E_MODULE_CYCLE", f"Import cycle: {entry} -> {shared} -> {shared}",
                                             parse(shared.read_text(), str(shared)).imports[0].span)
        with self.subTest(priority="active_cycle"):
            alias = entry.parent / "build" / entry.stem
            with self.alias(alias, app / "hepta.toml"):
                self.assert_refused(app, alias, diagnostic=diagnostic, debug=True)
        app, entry, _, shared = self.vendor("c_import", imports="import vendor::src::lib as local;\nimport dep;\n",
                                            library="// hepta:c-import:v1\n" + scope_component.NESTED, expression="42")
        self.put("c_import/app/src/vendor/src/lib.hepta.imports.json", '{}\n')
        write_lock(app)
        diagnostic = self.expected_exception(app, "E_C_IMPORT_IDENTITY", "C binding source differs from its probe metadata",
                                             parse(entry.read_text(), str(entry)).imports[0].span)
        with self.subTest(priority="c_import_identity"):
            alias = entry.parent / "build" / entry.stem
            with self.alias(alias, app / "hepta.toml", relative=False):
                self.assert_refused(app, alias, diagnostic=diagnostic, debug=True)

    def test_standalone_directory_alias_and_package_rejection(self):
        entry = self.put("standalone/worker.hepta.hepta", self.main("import values::worker;\n", "worker::answer()"))
        shared = self.put("standalone/values/worker.hepta", scope_component.NESTED)
        for result in self.frontend_pair(entry, locked=False):
            self.assert_nested(result, shared)
            self.assertIsNone(result.project.package)
            self.assertIsNone(result.project.package_state)
            alias = self.default_alias(result)
            self.assertEqual(alias.name, "worker.hepta")
        for relative, explicit in ((True, False), (False, True)):
            with self.subTest(graph="standalone", relative=relative, explicit=explicit):
                with self.alias(alias.parent, shared.parent, relative=relative, directory=True):
                    self.assertEqual(alias.resolve(), shared)
                    self.assert_refused(entry, alias, explicit=explicit, locked=False, debug=True)
        for locked in (True, False):
            app, _, dep, shared = self.vendor("package-" + str(locked))
            result = self.frontend(shared, locked=locked)
            self.assertEqual(result.project.package.root, dep)
            alias = self.default_alias(result)
            ordinary = dep / "src/ordinary"
            ordinary.mkdir()
            with self.subTest(graph="nested_package", locked=locked, explicit=False):
                with self.alias(alias.parent, ordinary, directory=True):
                    diagnostic = self.expected_exception(shared, "E_PACKAGE_SOURCE_LINK",
                        "Source directory symlinks are not supported by package locks; use a real directory",
                        Span(path=str(alias.parent)), phase="package", locked=locked)
                    self.assert_refused(shared, alias, diagnostic=diagnostic,
                                        locked=locked, debug=True)

    def test_permitted_alias_debug_publication(self):
        app, _, _, shared, _, _ = self.reused("diamond")
        for result in self.frontend_pair(app):
            self.assert_nested(result, shared)
        alias = self.default_alias(result)
        cases = (("new", False, True, False), ("existing", True, False, True),
                 ("debug", True, True, False))
        for label, existing, relative, explicit in cases:
            target = self.root / ("ordinary-" + label) / "program"
            if existing:
                self.put(str(target.relative_to(self.root)), "previous ordinary artifact\n")
            with self.subTest(destination=label, existing=existing, relative=relative, explicit=explicit):
                with self.alias(alias, target, relative=relative):
                    self.assert_output(app, alias, explicit=explicit, debug=label == "debug", label="diamond-" + label)
        entry = self.put("standalone/main.hepta", self.main("import used;\n", "used::answer()"))
        shared = self.put("standalone/used.hepta", scope_component.NESTED)
        unused = self.put("standalone/unused.hepta", "fn unrelated()->i32 effects {} {return 9;}\n")
        for result in self.frontend_pair(entry, locked=False):
            self.assert_nested(result, shared)
            self.assertIsNone(result.project.package)
            self.assertNotIn(str(unused), result.project.sources)
        alias = self.default_alias(result)
        with self.subTest(destination="unimported_standalone_sibling"):
            with self.alias(alias, unused):
                self.assert_output(entry, alias, locked=False, label="unimported-standalone-sibling")

    def test_z_pinned_rust_default_alias_parity(self):
        cases = []
        for label, imports, expected in (("local", "import vendor::src::lib as dep;\n", 7),
                                         ("dependency", "import dep;\n", 42),
                                         ("direct", "import dep;\n", 42)):
            app, _, dep, shared = self.vendor("parity-" + label, imports=imports)
            entry = shared if label == "direct" else app
            for result in self.frontend_pair(entry):
                self.assert_nested(result, shared, imported=label != "direct")
            alias = self.default_alias(result)
            with self.subTest(backend="c", route=label, expected=expected, prerequisite=True):
                with self.alias(alias, self.root / ("parity-c-" + label) / "program"):
                    self.assert_output(entry, alias, expected=expected, label=label + "-rust-prerequisite")
            cases.append((label, entry, dep if label == "direct" else app, alias, expected))
        try:
            rustc = find_rustc()
        except HeptaError as error:
            if error.diagnostic.code != "E_TOOLCHAIN":
                raise
            self.skipTest("Three C/Rust frontend pairs and actual GCC O3 local7/dependency42/direct42 executions passed; "
                          "actual rustc absent: " + error.diagnostic.message)
        identity = toolchain_info(rustc)
        self.assertIn("release: 1.90.0", identity["version"].splitlines())
        for label, entry, owner, alias, expected in cases:
            with self.subTest(backend="rust", route=label, expected=expected):
                with self.alias(alias, self.root / ("parity-rust-" + label) / "program", relative=label != "direct"):
                    self.assert_output(entry, alias, backend="rust", rustc=rustc, expected=expected,
                                       debug=label == "local", explicit=label == "dependency", label=label)
            with self.subTest(backend="rust", route=label, protected="actual_owner_lock"):
                with self.alias(alias, owner / "Hepta.lock"):
                    self.assert_refused(entry, alias, backend="rust", rustc=rustc, debug=label == "direct")
        app, _, common, shared, _, _ = self.reused()
        _, _, sidecar = self.add_c_binding(app, common, shared)
        result = self.frontend(app, backend="rust")
        self.assert_nested(result, shared)
        self.assertIn(str(sidecar), result.project.sources)
        alias = self.default_alias(result)
        for target in (common / "hepta.toml", sidecar):
            with self.subTest(backend="rust", protected=target.name, debug=True):
                with self.alias(alias, target, relative=target == sidecar):
                    self.assert_refused(app, alias, backend="rust", rustc=rustc, debug=True)
        with self.subTest(backend="rust", graph="repeated_alias", debug=True):
            with self.alias(alias, self.root / "parity-rust-debug/program"):
                self.assert_output(app, alias, backend="rust", rustc=rustc, debug=True, label="alias-debug")


if __name__ == "__main__":
    unittest.main()
