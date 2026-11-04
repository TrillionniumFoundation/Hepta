"""Finite package-context ownership regressions with real native controls.

A physical source file has one namespace. Importing it through two distinct
canonical package roots must reject instead of retaining the first context.
"""
from __future__ import annotations

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
from hepta.ast import HeptaError
from hepta.backend import compile_rust, find_rustc
from hepta.c_backend import compile_c
from hepta.modules import load_project
from hepta.packages import load_package, verify_lock, write_lock
from hepta.pipeline import analyze_project


ROOT = Path(hepta.__file__).resolve().parents[1]
BODY = "fn main()->i32 effects {} { return dep::answer(); }\n"
CONFLICT = "E_MODULE_PACKAGE_CONTEXT"


class ModulePackageContextTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="hepta-package-context-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.native_serial = 0

    def put(self, relative, source):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(source.encode("utf-8"))
        return path

    def manifest(self, relative, *, name, kind="lib", dependencies=None,
                 source_root=None, entry=None):
        source = (f'[package]\nname = "{name}"\nversion = "0.1.0"\n'
                  f'kind = "{kind}"\n')
        for key, value in (("source_root", source_root), ("entry", entry)):
            if value is not None:
                source += f"{key} = {json.dumps(value)}\n"
        if dependencies:
            source += "[dependencies]\n"
            for alias, path in dependencies.items():
                source += f"{alias} = {{ path = {json.dumps(path)} }}\n"
        self.put(relative + "/hepta.toml", source)
        return self.root / relative

    def imports(self, order):
        local = "import vendor::src::lib as unused;\n"
        dependency = "import dep;\n"
        return local + dependency if order == "local_first" else dependency + local

    def vendor(self, *, source="import dep;\n" + BODY, same_names=False):
        app = self.manifest("app", name="same" if same_names else "app",
                            kind="bin", dependencies={"dep": "src/vendor"})
        self.manifest("app/src/vendor", name="same" if same_names else "vendor")
        entry = self.put("app/src/main.hepta", source)
        self.put("app/src/helper.hepta", "pub fn value()->i32 effects {} { return 7; }\n")
        self.put("app/src/vendor/src/helper.hepta", "pub fn value()->i32 effects {} { return 42; }\n")
        library = self.put("app/src/vendor/src/lib.hepta",
                           "import helper;\npub fn answer()->i32 effects {} { return helper::value(); }\n")
        return app, entry, library

    def aliases(self, *, reverse=False):
        app, entry, library = self.vendor()
        self.manifest("app", name="app", kind="bin", dependencies={
            "first": "src/vendor", "second": "src/vendor/../vendor"})
        imports = (["import second;", "import first;"] if reverse else
                   ["import first;", "import second;"])
        entry.write_bytes(("\n".join(imports) + "\n"
                           "fn main()->i32 effects {} { if first::answer()==second::answer() "
                           "{ return first::answer(); } else { return 1; } }\n").encode())
        return app, entry, library

    def diamond(self, *, reverse=False):
        app = self.manifest("diamond", name="app", kind="bin",
                            dependencies={"left": "../left", "right": "../right"})
        for name in ("left", "right"):
            self.manifest(name, name=name, dependencies={"common": "../common"})
            self.put(name + "/src/lib.hepta", "import common;\n"
                     "pub fn answer()->i32 effects {} { return common::answer(); }\n")
        self.manifest("common", name="common")
        shared = self.put("common/src/lib.hepta", "pub fn answer()->i32 effects {} { return 42; }\n")
        imports = (["import right;", "import left;"] if reverse else
                   ["import left;", "import right;"])
        entry = self.put("diamond/src/main.hepta", "\n".join(imports) + "\n"
                         "fn main()->i32 effects {} { if left::answer()==right::answer() "
                         "{ return left::answer(); } else { return 1; } }\n")
        return app, entry, shared

    def context_roots(self, app, order):
        roots = (app, app / "src/vendor")
        return roots if order == "local_first" else roots[::-1]

    def context_diagnostic(self, entry, module, roots, *, source=None):
        source = entry.read_text() if source is None else source
        lines = source.splitlines(keepends=True)
        start = len(lines[0])
        end = start + len(lines[1].rstrip("\r\n"))
        return {"code": CONFLICT,
                "message": "Module " + str(module) + " is imported under conflicting package roots: "
                           + str(roots[0]) + " and " + str(roots[1]),
                "phase": "module", "notes": [],
                "span": {"path": str(entry), "start": start, "end": end,
                         "line": 2, "column": 1}}

    def reject_context(self, action, entry, module, roots, *, source=None):
        with self.assertRaises(HeptaError) as caught:
            action()
        self.assertEqual(caught.exception.diagnostic.to_dict(),
                         self.context_diagnostic(entry, module, roots, source=source))

    def frontend(self, app, *, locked=True, backend="c"):
        result = analyze_project(app, locked=locked, backend=backend,
                                 native=False, crate_type="bin")
        self.assertTrue(result.report["ok"], result.report)
        self.assertEqual(result.report["diagnostics"], [])
        return result

    def execute(self, result, expected, *, optimize, backend="c", rustc=None):
        self.native_serial += 1
        artifact = self.root / f"native-{self.native_serial}"
        if backend == "c":
            self.assertIsNotNone(shutil.which("gcc"), "Real GCC is required for C controls")
            built = compile_c(result.c, cc="gcc", crate_type="bin", output=artifact,
                              optimize=optimize, sanitize=True)
            self.assertIn("-O3" if optimize else "-O0", built["flags"])
            self.assertIn("-fsanitize=undefined", built["flags"])
            self.assertIn("-fno-sanitize-recover=all", built["flags"])
        else:
            built = compile_rust(result.rust, rustc=rustc, crate_type="bin",
                                 output=artifact, optimize=optimize)
        self.assertTrue(built["ok"], built)
        generated = result.c if backend == "c" else result.rust
        source_hash = built["source_sha256" if backend == "c" else "rust_sha256"]
        self.assertEqual(source_hash, hashlib.sha256(generated.encode("utf-8")).hexdigest())
        self.assertTrue(artifact.is_file())
        executed = subprocess.run([str(artifact)], capture_output=True, timeout=10)
        observation = {"method": self.id(), "backend": backend, "optimize": optimize,
                       "expected": expected, "returncode": executed.returncode,
                       "stdout": executed.stdout.decode("utf-8", errors="replace"),
                       "stderr": executed.stderr.decode("utf-8", errors="replace"),
                       "flags": built["flags"], "source_sha256": source_hash,
                       "artifact_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                       "toolchain": built["toolchain"]}
        print("PACKAGE_CONTEXT_NATIVE " + json.dumps(observation, sort_keys=True), flush=True)
        self.assertEqual(executed.returncode, expected, observation)
        self.assertEqual(executed.stdout, b"", observation)
        self.assertEqual(executed.stderr, b"", observation)

    def cli(self, *arguments):
        environment = dict(os.environ, PYTHONPATH=str(ROOT), PYTHONDONTWRITEBYTECODE="1")
        return subprocess.run([sys.executable, "-m", "hepta", *map(str, arguments)],
                              cwd=self.root, env=environment, capture_output=True,
                              text=True, timeout=30)

    def assert_cli_checkout(self):
        environment = dict(os.environ, PYTHONPATH=str(ROOT), PYTHONDONTWRITEBYTECODE="1")
        process = subprocess.run([sys.executable, "-c",
                                  "import hepta.modules; print(hepta.modules.__file__)"],
                                 cwd=self.root, env=environment, capture_output=True,
                                 text=True, timeout=10)
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(Path(process.stdout.strip()).resolve(), ROOT / "hepta/modules.py")

    def test_mixed_contexts_reject_both_orders_and_entry_forms(self):
        app, entry, library = self.vendor()
        for order in ("local_first", "dependency_first"):
            entry.write_bytes((self.imports(order) + BODY).encode())
            write_lock(app)
            for locked in (False, True):
                for form, argument in (("directory", app), ("manifest", app / "hepta.toml"),
                                       ("entry", entry)):
                    with self.subTest(order=order, locked=locked, form=form):
                        self.reject_context(lambda: load_project(argument, locked=locked), entry,
                                            library, self.context_roots(app, order))

    def test_analysis_rejects_both_context_orders_before_either_backend(self):
        app, entry, library = self.vendor()
        for order in ("local_first", "dependency_first"):
            entry.write_bytes((self.imports(order) + BODY).encode())
            write_lock(app)
            for backend in ("c", "rust"):
                with self.subTest(order=order, backend=backend):
                    self.reject_context(lambda: analyze_project(app, locked=True, backend=backend,
                                                                native=False, crate_type="bin"), entry,
                                        library, self.context_roots(app, order))

    def test_equal_source_roots_do_not_equate_distinct_package_roots(self):
        app = self.manifest("same_source", name="app", kind="bin", source_root="vendor/src",
                            entry="vendor/src/main.hepta", dependencies={"dep": "vendor"})
        self.manifest("same_source/vendor", name="vendor")
        library = self.put("same_source/vendor/src/lib.hepta", "pub fn answer()->i32 effects {} { return 42; }\n")
        entry = self.put("same_source/vendor/src/main.hepta", "")
        for reverse in (False, True):
            imports = ["import lib as local;", "import dep;"]
            if reverse:
                imports.reverse()
            entry.write_bytes(("\n".join(imports) + "\n" + BODY).encode())
            package = load_package(app)
            self.assertEqual(package.source_root, package.dependencies["dep"].source_root)
            self.assertNotEqual(package.root, package.dependencies["dep"].root)
            write_lock(app)
            with self.subTest(reverse=reverse):
                roots = (app, app / "vendor")
                self.reject_context(lambda: load_project(app, locked=True), entry,
                                    library, roots[::-1] if reverse else roots)

    def test_matching_names_and_versions_do_not_equate_package_roots(self):
        app, entry, library = self.vendor(same_names=True)
        package = load_package(app)
        dependency = package.dependencies["dep"]
        self.assertEqual((package.name, package.version), (dependency.name, dependency.version))
        self.assertNotEqual(package.root, dependency.root)
        for order in ("local_first", "dependency_first"):
            entry.write_bytes((self.imports(order) + BODY).encode())
            write_lock(app)
            with self.subTest(order=order):
                self.reject_context(lambda: load_project(app, locked=True), entry,
                                    library, self.context_roots(app, order))

    def test_source_overrides_cannot_introduce_mixed_contexts(self):
        app, entry, library = self.vendor()
        write_lock(app)
        original = entry.read_bytes()
        original_lock = (app / "Hepta.lock").read_bytes()
        for order in ("local_first", "dependency_first"):
            for locked in (False, True):
                with self.subTest(order=order, locked=locked):
                    self.reject_context(lambda: load_project(app, locked=locked,
                                        source_overrides={entry: self.imports(order) + BODY}), entry,
                                        library, self.context_roots(app, order),
                                        source=self.imports(order) + BODY)
                    self.assertEqual(entry.read_bytes(), original)
                    self.assertEqual((app / "Hepta.lock").read_bytes(), original_lock)
                    verify_lock(load_package(app))
        self.assertTrue(load_project(app, locked=True).unchanged())

    def test_same_package_aliases_deduplicate_canonical_roots(self):
        for reverse in (False, True):
            app, entry, library = self.aliases(reverse=reverse)
            write_lock(app)
            for locked in (False, True):
                with self.subTest(reverse=reverse, locked=locked):
                    result = self.frontend(app, locked=locked)
                    package = result.project.package
                    self.assertIs(package.dependencies["first"], package.dependencies["second"])
                    self.assertEqual(len(result.project.modules), 3)
                    self.assertEqual(len(result.program.functions), 3)
                    main = next(m for m in result.project.modules if m["path"] == str(entry))
                    self.assertEqual(main["imports"], {"first": str(library), "second": str(library)})
        for optimize in (False, True):
            self.execute(result, 42, optimize=optimize)

    def test_real_dependency_diamond_preserves_one_shared_module(self):
        for reverse in (False, True):
            app, _, shared = self.diamond(reverse=reverse)
            write_lock(app)
            for locked in (False, True):
                with self.subTest(reverse=reverse, locked=locked):
                    result = self.frontend(app, locked=locked)
                    dependencies = result.project.package.dependencies
                    self.assertIs(dependencies["left"].dependencies["common"],
                                  dependencies["right"].dependencies["common"])
                    self.assertEqual(len(result.project.modules), 4)
                    self.assertEqual(len(result.program.functions), 4)
                    self.assertEqual(sum(m["path"] == str(shared) for m in result.project.modules), 1)
        for optimize in (False, True):
            self.execute(result, 42, optimize=optimize)

    def test_distinct_files_in_equal_named_packages_remain_distinct(self):
        app = self.manifest("named_app", name="app", kind="bin",
                            dependencies={"left": "../named_left", "right": "../named_right"})
        for package, value in (("named_left", 7), ("named_right", 42)):
            self.manifest(package, name="same")
            self.put(package + "/src/lib.hepta", f"pub fn answer()->i32 effects {{}} {{ return {value}; }}\n")
        self.put("named_app/src/main.hepta", "import left;\nimport right;\n"
                 "fn main()->i32 effects {} { if left::answer()==7 { return right::answer(); } else { return 1; } }\n")
        write_lock(app)
        result = self.frontend(app)
        dependencies = result.project.package.dependencies
        self.assertEqual(dependencies["left"].name, dependencies["right"].name)
        self.assertEqual(dependencies["left"].version, dependencies["right"].version)
        self.assertNotEqual(dependencies["left"].root, dependencies["right"].root)
        self.assertEqual(len(result.project.modules), 3)
        self.assertEqual(len({f.name for f in result.program.functions}), 3)
        for optimize in (False, True):
            self.execute(result, 42, optimize=optimize)

    def test_single_route_vendor_and_local_imports_preserve_context(self):
        for label, imports, expected in (("dependency", "import dep;\n", 42),
                                          ("local", "import vendor::src::lib as dep;\n", 7)):
            app, _, library = self.vendor(source=imports + BODY)
            write_lock(app)
            for locked in (False, True):
                with self.subTest(route=label, locked=locked):
                    result = self.frontend(app, locked=locked)
                    rust = self.frontend(app, locked=locked, backend="rust")
                    self.assertEqual(result.project.identity, rust.project.identity)
                    module = next(m for m in result.project.modules if m["path"] == str(library))
                    helper = (app / "src/vendor/src/helper.hepta" if label == "dependency"
                              else app / "src/helper.hepta")
                    self.assertEqual(module["imports"], {"helper": str(helper)})
                    for optimize in (False, True):
                        self.execute(result, expected, optimize=optimize)

    def test_public_cli_rejects_conflicts_using_actual_checkout(self):
        self.assert_cli_checkout()
        app, entry, library = self.vendor()
        for order in ("local_first", "dependency_first"):
            entry.write_bytes((self.imports(order) + BODY).encode())
            write_lock(app)
            for backend in ("c", "rust"):
                with self.subTest(order=order, backend=backend):
                    process = self.cli("check", app, "--locked", "--backend", backend, "--frontend-only")
                    self.assertEqual(process.returncode, 1, process.stdout + process.stderr)
                    self.assertEqual(process.stderr, "")
                    report = json.loads(process.stdout)
                    self.assertFalse(report["ok"])
                    self.assertEqual(report["diagnostics"], [self.context_diagnostic(
                        entry, library, self.context_roots(app, order))])

    def test_public_cli_builds_single_routes_with_real_c(self):
        self.assert_cli_checkout()
        self.assertIsNotNone(shutil.which("gcc"), "Real GCC is required for CLI controls")
        for label, imports, expected in (("dependency", "import dep;\n", 42),
                                          ("local", "import vendor::src::lib as dep;\n", 7)):
            app, entry, _ = self.vendor(source=imports + BODY)
            write_lock(app)
            argument = app if label == "dependency" else entry
            with self.subTest(route=label):
                artifact = self.root / ("cli-" + label)
                process = self.cli("build", argument, "--locked", "--backend", "c",
                                   "--cc", "gcc", "-o", artifact)
                self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
                self.assertEqual(process.stderr, "")
                report = json.loads(process.stdout)
                self.assertTrue(report["ok"], report)
                self.assertTrue(report["validation"]["project"]["locked"])
                executed = subprocess.run([str(artifact)], capture_output=True, timeout=10)
                observation = {"method": self.id(), "backend": "cli-c", "route": label,
                               "expected": expected, "returncode": executed.returncode,
                               "stdout": executed.stdout.decode(), "stderr": executed.stderr.decode(),
                               "build": report["build"]}
                print("PACKAGE_CONTEXT_NATIVE " + json.dumps(observation, sort_keys=True), flush=True)
                self.assertEqual(executed.returncode, expected, observation)
                self.assertEqual(executed.stdout, b"", observation)
                self.assertEqual(executed.stderr, b"", observation)

    def test_active_cross_context_cycle_keeps_cycle_diagnostic(self):
        app, entry, library = self.vendor(source="import vendor::src::lib as local;\n" +
                                          "fn main()->i32 effects {} { return 0; }\n")
        library.write_bytes(b"import dep;\npub fn answer()->i32 effects {} { return 42; }\n")
        with self.assertRaises(HeptaError) as caught:
            load_project(app)
        self.assertEqual(caught.exception.diagnostic.code, "E_MODULE_CYCLE")
        self.assertEqual(caught.exception.diagnostic.span.path, str(library))
        self.assertEqual(caught.exception.diagnostic.span.line, 1)

    def test_rust_parity_after_complete_c_prerequisites(self):
        cases = []
        for label, imports, expected in (("dependency", "import dep;\n", 42),
                                          ("local", "import vendor::src::lib as dep;\n", 7)):
            app, _, _ = self.vendor(source=imports + BODY)
            write_lock(app)
            c_result = self.frontend(app)
            rust_result = self.frontend(app, backend="rust")
            self.assertEqual(c_result.project.identity, rust_result.project.identity)
            cases.append((label, c_result, rust_result, expected))
        app, _, _ = self.diamond()
        write_lock(app)
        cases.append(("diamond", self.frontend(app), self.frontend(app, backend="rust"), 42))
        # All three frontend pairs and six real GCC executions must complete
        # before absence of actual Rust may skip this independent parity gate.
        for label, c_result, _, expected in cases:
            for optimize in (False, True):
                self.execute(c_result, expected, optimize=optimize)
        self.assertEqual(self.native_serial, 6)
        try:
            rustc = find_rustc()
        except HeptaError as error:
            if error.diagnostic.code != "E_TOOLCHAIN":
                raise
            self.skipTest("Actual Rust unavailable after all three frontend pairs and six GCC executions: "
                          + error.diagnostic.message)
        for label, _, rust_result, expected in cases:
            for optimize in (False, True):
                with self.subTest(route=label, optimize=optimize):
                    self.execute(rust_result, expected, optimize=optimize, backend="rust", rustc=rustc)


if __name__ == "__main__":
    unittest.main()
