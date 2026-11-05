"""Actual typed packet/library sources through nested versioned contexts."""
import hashlib
import json
import shutil
import subprocess
import unittest

from hepta.ast import HeptaError
from hepta.c_backend import compile_c
from hepta.lock_diff import compare_locks
from hepta.modules import load_project
from hepta.packages import load_package, verify_lock, write_lock
from hepta.pipeline import analyze_project
from tests import test_module_package_context as context
from tests import test_versioned_typed as original


class TypedPackageContextTests(unittest.TestCase):
    spec = original.VersionedTypedTests.spec
    source = original.VersionedTypedTests.source
    context_diagnostic = context.ModulePackageContextTests.context_diagnostic
    reject_context = context.ModulePackageContextTests.reject_context

    def requirement(self, value="=1.0.0"):
        dependencies = {"typed": {"package": "typed_packet", "version": value,
                                  "candidates": ["src/typed1", "src/typed2"]}}
        dependencies.update({alias: self.spec(name, ">=0.1.0, <0.3.0")
                             for alias, name in original.LIBS.items()})
        original.manifest(self.app, "nested_typed", "1.0.0", dependencies, "bin")

    def setUp(self):
        original.VersionedTypedTests.setUp(self)
        self.native_index = 0
        for version in (1, 2):
            path = self.app / "src" / f"typed{version}"
            shutil.move(self.root / f"typed{version}", path)
            dependencies = {alias: {"package": "hepta_" + name,
                "version": f"=0.{version}.0",
                "candidates": [f"../../../{name}1", f"../../../{name}2"]}
                for alias, name in original.LIBS.items()}
            original.manifest(path, "typed_packet", f"{version}.0.0", dependencies)
            for name in ("lib.hepta", "packet.hepta"):
                self.assertEqual((path / "src" / name).read_bytes(),
                    (original.ROOT / "examples/packages/typed_packet/src" / name).read_bytes())
        packet = (original.ROOT / "examples/packages/typed_packet/src/packet.hepta").read_text()
        needle = "return IndexResult { stage: 0, scalars: count, lower: low.index, upper: high.index };"
        self.assertEqual(packet.count(needle), 1)
        # Only this application-local fixture differs; all suppliers are unchanged.
        (self.app / "src/packet.hepta").write_text(packet.replace(needle,
            "return IndexResult { stage: 5, scalars: count, lower: low.index, upper: high.index };"))

    def mixed(self, version, order):
        entry = self.app / "src/main.hepta"
        text = entry.read_text()
        body = text[text.index("fn main"):]
        local = f"import typed{version}::src::lib as unused;\n"
        dependency = "import typed;\n"
        self.source((local + dependency if order == "local_first" else dependency + local) + body)
        roots = (self.app, self.app / "src" / f"typed{version}")
        return entry, roots[1] / "src/lib.hepta", roots if order == "local_first" else roots[::-1]

    def native(self):
        result = analyze_project(self.app, backend="c", locked=True, crate_type="bin")
        self.assertTrue(result.report["ok"], result.report)
        for optimized in (False, True):
            self.native_index += 1
            output = self.root / f"typed-context-{self.native_index}"
            built = compile_c(result.c, cc="gcc", output=output, optimize=optimized, sanitize=True)
            self.assertTrue(built["ok"], built)
            self.assertIn("-fno-sanitize-recover=all", built["flags"])
            run = subprocess.run([str(output)], capture_output=True, timeout=30)
            self.assertEqual((run.returncode, run.stdout, run.stderr), (0, b"", b""))
            print("TYPED_CONTEXT_NATIVE " + json.dumps({"method": self.id(),
                "optimized": optimized, "returncode": 0, "stdout": "", "stderr": "", "build": built,
                "lock_sha256": hashlib.sha256((self.app / "Hepta.lock").read_bytes()).hexdigest()},
                sort_keys=True), flush=True)

    def test_actual_typed_sources_reject_selected_context_in_both_orders(self):
        for version in (1, 2):
            self.requirement(f"={version}.0.0")
            for order in ("local_first", "dependency_first"):
                entry, library, roots = self.mixed(version, order)
                write_lock(self.app)
                saved = (self.app / "Hepta.lock").read_bytes()
                for locked in (False, True):
                    for form in (self.app, self.app / "hepta.toml", entry):
                        self.reject_context(lambda: load_project(form, locked=locked), entry, library, roots)
                for backend in ("c", "rust"):
                    self.reject_context(lambda: analyze_project(self.app, backend=backend,
                        locked=True, native=False, crate_type="bin"), entry, library, roots)
                self.assertEqual((self.app / "Hepta.lock").read_bytes(), saved)
                self.assertEqual(load_package(self.app).dependencies["typed"].version, f"{version}.0.0")

    def test_native_unicode_and_typed_capacity_error_preserve_full_backing(self):
        self.source(original.vector_source([
            original.raw_case(b"\0\3a\xc3\xa9", 233, scalars=5),
            original.raw_case(b"\0\2aa", scalars=2)]))
        for version in (1, 2):
            self.requirement(f"={version}.0.0")
            write_lock(self.app)
            self.assertEqual(len(load_project(self.app, locked=True).modules), 7)
            self.native()

    def test_upgrade_conflict_preserves_explicit_rollback(self):
        self.requirement("=1.0.0")
        entry, library, roots = self.mixed(2, "local_first")
        old_manifest = (self.app / "hepta.toml").read_bytes()
        write_lock(self.app)
        old_lock = (self.app / "Hepta.lock").read_bytes()
        before = self.root / "before.lock"
        before.write_bytes(old_lock)
        self.native()
        self.requirement("=2.0.0")
        with self.assertRaises(HeptaError) as caught:
            load_project(self.app, locked=True)
        self.assertEqual(caught.exception.diagnostic.code, "E_LOCK_STALE")
        write_lock(self.app)
        delta = compare_locks(before, self.app / "Hepta.lock")
        self.assertEqual(delta["compatibility"], "not_assessed")
        self.assertIn({"package": ".", "alias": "typed", "before": "src/typed1", "after": "src/typed2"},
                      delta["dependencies"]["retargeted"])
        self.reject_context(lambda: load_project(self.app, locked=True), entry, library, roots)
        (self.app / "hepta.toml").write_bytes(old_manifest)
        (self.app / "Hepta.lock").write_bytes(old_lock)
        verify_lock(load_package(self.app))
        self.native()

    def test_typed_overlay_conflict_preserves_disk_and_selected_graph(self):
        self.requirement("=2.0.0")
        write_lock(self.app)
        entry = self.app / "src/main.hepta"
        saved, saved_lock = entry.read_bytes(), (self.app / "Hepta.lock").read_bytes()
        for order in ("local_first", "dependency_first"):
            _, library, roots = self.mixed(2, order)
            source = entry.read_text()
            entry.write_bytes(saved)
            self.reject_context(lambda: load_project(self.app, locked=True,
                source_overrides={entry: source}), entry, library, roots, source=source)
            self.assertEqual(entry.read_bytes(), saved)
            self.assertEqual((self.app / "Hepta.lock").read_bytes(), saved_lock)
            self.assertEqual(load_package(self.app).dependencies["typed"].root, self.app / "src/typed2")
        self.assertTrue(load_project(self.app, locked=True).unchanged())
