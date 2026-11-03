from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta.ast import HeptaError
from hepta.backend import compile_rust, find_rustc
from hepta.modules import load_project
from hepta.packages import load_package, package_snapshot, verify_lock, write_lock
from hepta.pipeline import analyze_project, inspect_analysis


class ProjectFixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="hepta-modules-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def put(self, rel, data):
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(data)
        return p

    def reject(self, code, fn):
        with self.assertRaises(HeptaError) as ctx:
            fn()
        self.assertEqual(ctx.exception.diagnostic.code, code)

    def execute(self, source):
        result = analyze_project(source, crate_type="bin")
        self.assertTrue(result.report["ok"], result.report)
        native = compile_rust(result.rust, crate_type="bin", output=self.root / "out")
        self.assertTrue(native["ok"], native)
        p = subprocess.run([native["artifact"]], capture_output=True, timeout=5)
        self.assertEqual(p.returncode, 0, p.stderr)
        return result

class ModuleTests(ProjectFixture):
    def test_aliases_and_private_internal_helpers_execute(self):
        self.put("math.hepta", "module math; fn hidden() -> u64 effects {} { return 7; } pub fn answer() -> u64 effects {} { return hidden(); }")
        entry = self.put("main.hepta", "import math as m; fn main() -> i32 effects {} { if m::answer() == 7 { return 0; } else { return 1; } }")
        result = self.execute(entry)
        self.assertEqual(len(result.report["project"]["sources"]), 2)
        self.assertEqual(result.program.imports, [])
        self.assertEqual({s["path"] for s in inspect_analysis(result)["symbols"]}, {str(entry), str(self.root / "math.hepta")})

    def test_same_local_names_in_multiple_modules_are_distinct(self):
        self.put("a.hepta", "pub fn value() -> u64 effects {} { return 1; }")
        self.put("b.hepta", "pub fn value() -> u64 effects {} { return 2; }")
        entry = self.put("main.hepta", "import a; import b; fn main() -> i32 effects {} { if a::value() == b::value() { return 1; } else { return 0; } }")
        self.execute(entry)

    def test_nested_paths_and_shared_dependency_are_deduplicated(self):
        self.put("common.hepta", "pub fn value() -> u64 effects {} { return 9; }")
        self.put("nested/a.hepta", "import common; pub fn value() -> u64 effects {} { return common::value(); }")
        self.put("b.hepta", "import common; pub fn value() -> u64 effects {} { return common::value(); }")
        entry = self.put("main.hepta", "import nested::a; import b; fn main() -> i32 effects {} { if a::value() == b::value() { return 0; } else { return 1; } }")
        result = self.execute(entry)
        self.assertEqual(len(result.project.modules), 4)

    def test_private_function_rejected(self):
        self.put("a.hepta", "fn hidden() -> u64 effects {} { return 1; }")
        entry = self.put("main.hepta", "import a; fn main() -> i32 effects {} { return a::hidden() as i32; }")
        self.reject("E_MODULE_PRIVATE", lambda: load_project(entry))

    def test_unknown_symbol_rejected(self):
        self.put("a.hepta", "pub fn known() -> u64 effects {} { return 1; }")
        entry = self.put("main.hepta", "import a; fn main() -> i32 effects {} { return a::missing() as i32; }")
        self.reject("E_MODULE_SYMBOL", lambda: load_project(entry))

    def test_cycle_rejected(self):
        self.put("a.hepta", "import b;")
        self.put("b.hepta", "import a;")
        entry = self.put("main.hepta", "import a;")
        self.reject("E_MODULE_CYCLE", lambda: load_project(entry))

    def test_missing_source_rejected(self):
        entry = self.put("main.hepta", "import missing;")
        self.reject("E_MODULE_READ", lambda: load_project(entry))

    def test_alias_collision_rejected(self):
        self.put("a.hepta", "")
        entry = self.put("main.hepta", "import a; fn a() -> Unit effects {} { return; }")
        self.reject("E_MODULE_ALIAS", lambda: load_project(entry))

    def test_source_symlink_escape_rejected(self):
        self.put("outside.hepta", "")
        entry = self.put("src/main.hepta", "import outside;")
        (self.root / "src/outside.hepta").symlink_to(self.root / "outside.hepta")
        self.reject("E_MODULE_ESCAPE", lambda: load_project(entry))

    def test_dependency_change_invalidates_project_identity(self):
        dep = self.put("a.hepta", "pub fn f() -> u64 effects {} { return 1; }")
        entry = self.put("main.hepta", "import a;")
        first = load_project(entry)
        dep.write_text(dep.read_text().replace("return 1", "return 2"))
        second = load_project(entry)
        self.assertNotEqual(first.identity, second.identity)
        self.assertFalse(first.unchanged())

    def test_in_memory_override_preserves_other_source_identities(self):
        self.put("a.hepta", "pub fn f() -> u64 effects {} { return 1; }")
        entry = self.put("main.hepta", "import a; fn main() -> i32 effects {} { return 0; }")
        first = load_project(entry)
        candidate = load_project(entry, source_overrides={entry: entry.read_text().replace("return 0", "return 1")})
        self.assertNotEqual(first.identity, candidate.identity)
        self.assertTrue(candidate.unchanged(except_paths=[entry]))
        self.assertFalse(candidate.unchanged())

    def test_public_struct_crosses_module_and_private_type_rejected(self):
        dep = self.put("model.hepta", "pub struct Item { value: u64 } pub fn value(x: Item) -> u64 effects {} { return x.value; }")
        entry = self.put("main.hepta", "import model; fn main() -> i32 effects {} { let x: model::Item = model::Item { value: 7 }; if model::value(x) == 7 { return 0; } else { return 1; } }")
        self.execute(entry)
        dep.write_text(dep.read_text().replace("pub struct", "struct"))
        self.reject("E_MODULE_PRIVATE", lambda: load_project(entry))


class PackageTests(ProjectFixture):
    def package(self, prefix="app", *, kind="bin", dependencies=""):
        self.put(prefix + "/hepta.toml", f'[package]\nname = "{prefix}"\nversion = "0.1.0"\nkind = "{kind}"\n' + dependencies)
        self.put(prefix + f"/src/{'main' if kind == 'bin' else 'lib'}.hepta", "fn main() -> i32 effects {} { return 0; }" if kind == "bin" else "pub fn answer() -> u64 effects {} { return 7; }")
        return self.root / prefix

    def test_local_library_dependency_executes_locked(self):
        self.package("math", kind="lib")
        app = self.package(dependencies='[dependencies]\nmath = { path = "../math" }\n')
        self.put("app/src/main.hepta", "import math; fn main() -> i32 effects {} { if math::answer() == 7 { return 0; } else { return 1; } }")
        write_lock(app)
        result = analyze_project(app, locked=True)
        self.assertTrue(result.report["ok"], result.report)
        self.assertTrue(result.report["project"]["locked"])
        self.execute(app)

    def test_lock_missing_and_source_changes_fail(self):
        app = self.package()
        self.reject("E_LOCK_MISSING", lambda: analyze_project(app, locked=True))
        write_lock(app)
        self.put("app/src/unused.hepta", "")
        self.reject("E_LOCK_STALE", lambda: analyze_project(app, locked=True))

    def test_dependency_source_changes_fail_lock(self):
        self.package("lib", kind="lib")
        app = self.package(dependencies='[dependencies]\nlib = { path = "../lib" }\n')
        write_lock(app)
        self.put("lib/src/lib.hepta", "pub fn changed() -> Unit effects {} { return; }")
        self.reject("E_LOCK_STALE", lambda: verify_lock(load_package(app)))

    def test_dependency_cycle_fails(self):
        a = self.package("a", kind="lib", dependencies='[dependencies]\nb = { path = "../b" }\n')
        self.package("b", kind="lib", dependencies='[dependencies]\na = { path = "../a" }\n')
        self.reject("E_PACKAGE_CYCLE", lambda: load_package(a))

    def test_remote_dependency_rejected_without_network(self):
        app = self.package(dependencies='[dependencies]\nlib = { git = "https://example.invalid/execute" }\n')
        self.reject("E_PACKAGE_DEPENDENCY", lambda: load_package(app))

    def test_unknown_build_script_key_rejected(self):
        app = self.package()
        f = app / "hepta.toml"
        f.write_text(f.read_text() + 'build = "arbitrary-command"\n')
        self.reject("E_PACKAGE_SCHEMA", lambda: load_package(app))

    def test_source_root_escape_rejected(self):
        app = self.package()
        f = app / "hepta.toml"
        f.write_text(f.read_text() + 'source_root = ".."\n')
        self.reject("E_PACKAGE_ESCAPE", lambda: load_package(app))

    def test_bin_dependency_rejected(self):
        self.package("other")
        app = self.package(dependencies='[dependencies]\nother = { path = "../other" }\n')
        self.reject("E_PACKAGE_DEPENDENCY", lambda: load_package(app))

    def test_invalid_version_rejected(self):
        app = self.package()
        f = app / "hepta.toml"
        f.write_text(f.read_text().replace('"0.1.0"', '"latest"'))
        self.reject("E_PACKAGE_VERSION", lambda: load_package(app))

    def test_source_directory_alias_rejected_before_locking(self):
        app = self.package()
        self.put("app/src/a/value.hepta", "pub fn answer() -> i32 effects {} { return 1; }")
        self.put("app/src/b/value.hepta", "pub fn answer() -> i32 effects {} { return 2; }")
        self.put("app/src/main.hepta", "import alias::value; fn main() -> i32 effects {} { return value::answer(); }")
        alias = app / "src/alias"
        alias.symlink_to("a", target_is_directory=True)
        self.reject("E_PACKAGE_SOURCE_LINK", lambda: write_lock(app))
        self.assertFalse((app / "Hepta.lock").exists())
        self.reject("E_PACKAGE_SOURCE_LINK", lambda: load_project(app, locked=False))
        alias.unlink()
        alias.symlink_to("b", target_is_directory=True)
        self.reject("E_PACKAGE_SOURCE_LINK", lambda: write_lock(app))

    def test_directory_alias_added_after_lock_rejects_locked_load(self):
        app = self.package()
        self.put("app/src/a/value.hepta", "pub fn answer() -> i32 effects {} { return 1; }")
        write_lock(app)
        (app / "src/alias").symlink_to("a", target_is_directory=True)
        self.reject("E_PACKAGE_SOURCE_LINK", lambda: load_project(app, locked=True))

    def test_nested_and_dependency_directory_links_rejected(self):
        lib = self.package("lib", kind="lib")
        app = self.package(dependencies='[dependencies]\nlib = { path = "../lib" }\n')
        self.put("lib/src/nested/real/value.hepta", "")
        (lib / "src/nested/alias").symlink_to("real", target_is_directory=True)
        self.reject("E_PACKAGE_SOURCE_LINK", lambda: write_lock(app))

    def test_directory_link_escape_rejected(self):
        app = self.package()
        self.put("outside/value.hepta", "")
        (app / "src/alias").symlink_to(self.root / "outside", target_is_directory=True)
        self.reject("E_PACKAGE_ESCAPE", lambda: write_lock(app))

    def test_regular_source_file_symlinks_remain_content_locked(self):
        app = self.package()
        source = self.put("app/src/value.hepta", "pub fn answer() -> i32 effects {} { return 1; }")
        (app / "src/alias.hepta").symlink_to("value.hepta")
        write_lock(app)
        verify_lock(load_package(app))
        source.write_text(source.read_text().replace("return 1", "return 2"))
        self.reject("E_LOCK_STALE", lambda: verify_lock(load_package(app)))

    def test_unreadable_source_directory_cannot_issue_partial_lock(self):
        app = self.package()
        self.put("app/src/hidden/value.hepta", "")
        original = os.scandir
        def unreadable(path):
            if Path(path) == app / "src/hidden":
                raise PermissionError("injected unreadable source directory")
            return original(path)
        with patch("os.scandir", side_effect=unreadable):
            self.reject("E_PACKAGE_READ", lambda: write_lock(app))
        self.assertFalse((app / "Hepta.lock").exists())

    def test_unreadable_directory_preserves_existing_lock(self):
        app = self.package()
        self.put("app/src/hidden/value.hepta", "")
        write_lock(app)
        original_lock = (app / "Hepta.lock").read_bytes()
        original = os.scandir
        def unreadable(path):
            if Path(path) == app / "src/hidden":
                raise PermissionError("injected unreadable source directory")
            return original(path)
        with patch("os.scandir", side_effect=unreadable):
            self.reject("E_PACKAGE_READ", lambda: write_lock(app))
            self.reject("E_PACKAGE_READ", lambda: load_project(app, locked=True))
            self.reject("E_PACKAGE_READ", lambda: load_project(app, locked=False))
        self.assertEqual((app / "Hepta.lock").read_bytes(), original_lock)

    def test_inventory_failure_during_recheck_preserves_lock_and_cleans_stage(self):
        app = self.package()
        write_lock(app)
        original_lock = (app / "Hepta.lock").read_bytes()
        original = os.scandir
        calls = 0
        def unreadable_on_recheck(path):
            nonlocal calls
            if Path(path) == app / "src":
                calls += 1
                if calls == 2:
                    raise PermissionError("injected recheck enumeration failure")
            return original(path)
        with patch("os.scandir", side_effect=unreadable_on_recheck):
            self.reject("E_PACKAGE_READ", lambda: write_lock(app))
        self.assertEqual((app / "Hepta.lock").read_bytes(), original_lock)
        self.assertEqual(list(app.glob(".hepta-lock-*")), [])

    def test_unreadable_dependency_directory_rejected(self):
        lib = self.package("lib", kind="lib")
        app = self.package(dependencies='[dependencies]\nlib = { path = "../lib" }\n')
        original = os.scandir
        def unreadable(path):
            if Path(path) == lib / "src":
                raise PermissionError("injected unreadable dependency")
            return original(path)
        with patch("os.scandir", side_effect=unreadable):
            self.reject("E_PACKAGE_READ", lambda: write_lock(app))

    def test_source_root_disappearing_after_load_rejected(self):
        app = self.package()
        package = load_package(app)
        (app / "src/main.hepta").unlink()
        (app / "src").rmdir()
        self.reject("E_PACKAGE_READ", lambda: package_snapshot(package))

    def test_snapshot_is_portable_and_deterministic(self):
        app = self.package()
        first = package_snapshot(load_package(app))
        second = package_snapshot(load_package(app))
        self.assertEqual(first, second)
        self.assertNotIn(str(self.root), json.dumps(first))

    def test_cli_package_check(self):
        app = self.package()
        write_lock(app)
        p = subprocess.run([sys.executable, "-m", "hepta", "check", str(app), "--locked"], capture_output=True, text=True, timeout=20)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertTrue(json.loads(p.stdout)["project"]["locked"])


if __name__ == "__main__":
    unittest.main()
