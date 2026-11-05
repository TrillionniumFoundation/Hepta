"""Version selection and source-context ownership must agree at module reuse.

These are finite acyclic package/module fixtures, not recursion or ABI tests.
The original #665 test module is a byte-identical supplier, used only for helpers
and explicitly selected original methods by the scoped runner.
"""
from __future__ import annotations

import json
import shutil
import unittest

from hepta.ast import HeptaError
from hepta.lock_diff import compare_locks
from hepta.modules import load_project
from hepta.packages import load_package, verify_lock, write_lock
from hepta.pipeline import analyze_project
from tests import test_module_package_context as context

BODY = context.BODY


class VersionedPackageContextTests(unittest.TestCase):
    # Reuse fixture helpers only; do not inherit or expose the original tests.
    setUp = context.ModulePackageContextTests.setUp
    put = context.ModulePackageContextTests.put
    context_diagnostic = context.ModulePackageContextTests.context_diagnostic
    reject_context = context.ModulePackageContextTests.reject_context
    frontend = context.ModulePackageContextTests.frontend
    execute = context.ModulePackageContextTests.execute
    cli = context.ModulePackageContextTests.cli
    assert_cli_checkout = context.ModulePackageContextTests.assert_cli_checkout

    def package(self, relative, name, version="1.0.0", *, kind="lib", dependencies=None):
        path = self.root / relative
        (path / "src").mkdir(parents=True, exist_ok=True)
        text = (f'[package]\nname={json.dumps(name)}\nversion={json.dumps(version)}\n'
                f'kind={json.dumps(kind)}\n[dependencies]\n')
        for alias, spec in sorted((dependencies or {}).items()):
            text += alias + "={" + ", ".join(k + "=" + json.dumps(v)
                                               for k, v in spec.items()) + "}\n"
        (path / "hepta.toml").write_text(text, encoding="utf-8")
        entry = path / "src" / ("main.hepta" if kind == "bin" else "lib.hepta")
        if not entry.exists():
            entry.write_text("pub fn answer()->i32 effects {} { return 0; }\n")
        return path

    def spec(self, requirement=">=1.0.0", *, paths=None):
        return {"package": "vendor", "version": requirement,
                "candidates": paths or ["src/v1", "src/v2"]}

    def versioned(self, requirement=">=1.0.0", *, extra=None):
        app = self.package("app", "app", kind="bin",
                           dependencies={"dep": self.spec(requirement), **(extra or {})})
        for directory, version, answer in (("v1", "1.0.0", 41), ("v2", "2.0.0", 42)):
            self.package("app/src/" + directory, "vendor", version)
            self.put("app/src/" + directory + "/src/lib.hepta",
                     "import helper;\npub fn answer()->i32 effects {} { return helper::value(); }\n")
            self.put("app/src/" + directory + "/src/helper.hepta",
                     f"pub fn value()->i32 effects {{}} {{ return {answer}; }}\n")
        self.put("app/src/helper.hepta", "pub fn value()->i32 effects {} { return 7; }\n")
        entry = self.put("app/src/main.hepta", "import dep;\n" + BODY)
        return app, entry

    def mixed(self, app, entry, version, order):
        local = f"import {version}::src::lib as unused;\n"
        dep = "import dep;\n"
        source = (local + dep if order == "local_first" else dep + local) + BODY
        entry.write_text(source, encoding="utf-8")
        library = app / "src" / version / "src/lib.hepta"
        roots = (app, app / "src" / version)
        return library, roots if order == "local_first" else roots[::-1]

    def rejected(self, action, code):
        with self.assertRaises(HeptaError) as caught:
            action()
        self.assertEqual(caught.exception.diagnostic.code, code)
        return caught.exception.diagnostic

    def test_selected_versions_reject_both_orders_forms_and_lock_modes(self):
        for requirement, version in (("<2.0.0", "v1"), (">=1.0.0", "v2")):
            app, entry = self.versioned(requirement)
            for order in ("local_first", "dependency_first"):
                library, roots = self.mixed(app, entry, version, order)
                write_lock(app)
                for locked in (False, True):
                    for form in (app, app / "hepta.toml", entry):
                        with self.subTest(requirement=requirement, order=order,
                                          locked=locked, form=str(form)):
                            self.reject_context(lambda: load_project(form, locked=locked),
                                                entry, library, roots)

    def test_analysis_refuses_selected_context_before_either_backend(self):
        app, entry = self.versioned()
        for order in ("local_first", "dependency_first"):
            library, roots = self.mixed(app, entry, "v2", order)
            write_lock(app)
            for backend in ("c", "rust"):
                self.reject_context(lambda: analyze_project(app, locked=True,
                                    backend=backend, native=False, crate_type="bin"),
                                    entry, library, roots)

    def test_backtracking_uses_selected_root_for_context_check(self):
        app, entry = self.versioned(extra={"z": {"path": "../bridge"}})
        self.package("bridge", "bridge", dependencies={"v": self.spec("<2.0.0",
                     paths=["../app/src/v1", "../app/src/v2"])})
        selected = load_package(app)
        self.assertEqual(selected.dependencies["dep"].root, app / "src/v1")
        self.assertIs(selected.dependencies["dep"], selected.dependencies["z"].dependencies["v"])
        for order in ("local_first", "dependency_first"):
            library, roots = self.mixed(app, entry, "v1", order)
            write_lock(app)
            self.reject_context(lambda: load_project(app, locked=True), entry, library, roots)

    def test_upgrade_requires_refresh_then_rejects_newly_shared_module(self):
        app, entry = self.versioned("<2.0.0")
        library, roots = self.mixed(app, entry, "v2", "local_first")
        old = write_lock(app)["snapshot"]
        before = self.root / "before.lock"
        before.write_text(json.dumps(old))
        self.assertEqual(old["packages"]["."]["dependencies"], {"dep": "src/v1"})
        result = self.frontend(app)
        for optimize in (False, True):
            self.execute(result, 41, optimize=optimize)
        self.package("app", "app", kind="bin", dependencies={"dep": self.spec()})
        self.rejected(lambda: load_project(app, locked=True), "E_LOCK_STALE")
        after = write_lock(app)["snapshot"]
        self.assertEqual(after["packages"]["."]["dependencies"], {"dep": "src/v2"})
        report = compare_locks(before, app / "Hepta.lock")
        self.assertEqual(report["compatibility"], "not_assessed")
        self.assertEqual(report["dependencies"]["retargeted"],
                         [{"package": ".", "alias": "dep", "before": "src/v1", "after": "src/v2"}])
        self.reject_context(lambda: load_project(app, locked=True), entry, library, roots)
        # Module rejection does not silently choose an older candidate or rewrite the lock.
        self.assertEqual(verify_lock(load_package(app)), after)

    def test_same_selected_root_repeated_names_reuse_one_module(self):
        for requirement, expected, version in (("<2.0.0", 41, "v1"), (">=1.0.0", 42, "v2")):
            app, entry = self.versioned(requirement,
                extra={"other": self.spec(requirement, paths=["src/v2", "src/v1/../v1"])})
            entry.write_text("import dep;\nimport other;\nfn main()->i32 effects {panic} { "
                             "assert(dep::answer()==other::answer()); return dep::answer(); }\n")
            write_lock(app)
            result = self.frontend(app)
            self.assertIs(result.project.package.dependencies["dep"],
                          result.project.package.dependencies["other"])
            self.assertEqual(sum(m["path"] == str(app / "src" / version / "src/lib.hepta")
                                 for m in result.project.modules), 1)
            for optimize in (False, True):
                self.execute(result, expected, optimize=optimize)

    def test_fixed_and_versioned_routes_share_the_same_selected_root(self):
        app, entry = self.versioned(extra={"fixed": {"path": "src/v2"}})
        entry.write_text("import fixed;\nimport dep;\nfn main()->i32 effects {panic} { "
                         "assert(fixed::answer()==dep::answer()); return dep::answer(); }\n")
        write_lock(app)
        result = self.frontend(app)
        self.assertIs(result.project.package.dependencies["fixed"], result.project.package.dependencies["dep"])
        for optimize in (False, True):
            self.execute(result, 42, optimize=optimize)

    def test_versioned_dependency_diamond_preserves_one_selected_context(self):
        app, entry = self.versioned(extra={"z": {"path": "../bridge"}})
        self.package("bridge", "bridge", dependencies={"v": self.spec("<2.0.0",
                     paths=["../app/src/v1", "../app/src/v2"])})
        self.put("bridge/src/lib.hepta", "import v;\npub fn answer()->i32 effects {} { return v::answer(); }\n")
        entry.write_text("import dep;\nimport z;\nfn main()->i32 effects {panic} { "
                         "assert(dep::answer()==z::answer()); return dep::answer(); }\n")
        write_lock(app)
        result = self.frontend(app)
        self.assertIs(result.project.package.dependencies["dep"],
                      result.project.package.dependencies["z"].dependencies["v"])
        self.assertEqual(sum(m["path"] == str(app / "src/v1/src/lib.hepta") for m in result.project.modules), 1)
        for optimize in (False, True):
            self.execute(result, 41, optimize=optimize)

    def test_unselected_distinct_file_stays_local_without_false_context_error(self):
        app, entry = self.versioned()
        entry.write_text("import v1::src::lib as local;\nimport dep;\n"
                         "fn main()->i32 effects {panic} { assert(local::answer()==7); return dep::answer(); }\n")
        write_lock(app)
        result = self.frontend(app)
        self.assertEqual(result.project.package.dependencies["dep"].root, app / "src/v2")
        for optimize in (False, True):
            self.execute(result, 42, optimize=optimize)

    def test_fixed_old_and_selected_new_same_name_remain_distinct(self):
        app, entry = self.versioned(extra={"old": {"path": "src/v1"}})
        entry.write_text("import old;\nimport dep;\nfn main()->i32 effects {panic} { "
                         "assert(old::answer()==41); return dep::answer(); }\n")
        write_lock(app)
        result = self.frontend(app)
        self.assertNotEqual(result.project.package.dependencies["old"].root,
                            result.project.package.dependencies["dep"].root)
        for optimize in (False, True):
            self.execute(result, 42, optimize=optimize)

    def test_overlay_conflict_retains_original_source_lock_and_selection(self):
        app, entry = self.versioned()
        write_lock(app)
        original, lock = entry.read_bytes(), (app / "Hepta.lock").read_bytes()
        for order in ("local_first", "dependency_first"):
            library, roots = self.mixed(app, entry, "v2", order)
            source = entry.read_text()
            entry.write_bytes(original)
            self.reject_context(lambda: load_project(app, locked=True, source_overrides={entry: source}),
                                entry, library, roots, source=source)
            self.assertEqual(entry.read_bytes(), original)
            self.assertEqual((app / "Hepta.lock").read_bytes(), lock)
        self.assertTrue(load_project(app, locked=True).unchanged())

    def test_public_cli_rejects_versioned_conflict_and_executes_recovery(self):
        self.assert_cli_checkout()
        app, entry = self.versioned()
        for order in ("local_first", "dependency_first"):
            library, roots = self.mixed(app, entry, "v2", order)
            write_lock(app)
            for command, extra in (("check", ("--frontend-only", "--backend", "c")),
                                   ("inspect", ())):
                result = self.cli(command, app, "--locked", *extra)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertEqual(result.stderr, "")
                self.assertEqual(json.loads(result.stdout)["diagnostics"],
                                 [self.context_diagnostic(entry, library, roots)])
        entry.write_text("import dep;\n" + BODY)
        write_lock(app)
        result = self.cli("run", app, "--locked", "--backend", "c", "--json")
        self.assertEqual(result.returncode, 42, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual((report["returncode"], report["stdout"], report["stderr"]), (42, "", ""))
        print("VERSIONED_CONTEXT_CLI_NATIVE " + json.dumps(report, sort_keys=True), flush=True)

    def test_relocation_preserves_portable_lock_and_reports_new_context_paths(self):
        app, entry = self.versioned()
        self.mixed(app, entry, "v2", "dependency_first")
        write_lock(app)
        destination = self.root / "relocated/app"
        shutil.copytree(app, destination)
        self.assertEqual(write_lock(destination)["snapshot"], verify_lock(load_package(app)))
        moved_entry = destination / "src/main.hepta"
        self.reject_context(lambda: load_project(destination, locked=True), moved_entry,
                            destination / "src/v2/src/lib.hepta", (destination / "src/v2", destination))
