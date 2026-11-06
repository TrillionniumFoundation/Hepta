"""Bounded schema/version/context intersections, without native execution."""
from pathlib import Path
import json
import subprocess
import sys
import unittest

from hepta.ast import HeptaError
from hepta.lock_diff import compare_locks
from hepta.modules import load_project
from hepta.packages import load_package, verify_lock, write_lock
from tests import test_versioned_package_context as context


class VersionedPackageKindTests(unittest.TestCase):
    setUp = context.VersionedPackageContextTests.setUp
    put = context.VersionedPackageContextTests.put
    package = context.VersionedPackageContextTests.package
    spec = context.VersionedPackageContextTests.spec
    versioned = context.VersionedPackageContextTests.versioned
    mixed = context.VersionedPackageContextTests.mixed
    context_diagnostic = context.VersionedPackageContextTests.context_diagnostic
    reject_context = context.VersionedPackageContextTests.reject_context

    def invalid_kind(self, candidate, spelling):
        manifest = candidate / "hepta.toml"
        original = manifest.read_bytes()
        self.assertEqual(original.count(b'kind="lib"'), 1)
        manifest.write_bytes(original.replace(b'kind="lib"', b'kind=' + spelling.encode()))
        return manifest, original

    def reject_schema(self, action, manifest):
        with self.assertRaises(HeptaError) as caught:
            action()
        self.assertEqual(caught.exception.diagnostic.to_dict(), {
            "code": "E_PACKAGE_SCHEMA", "message": "Package kind must be bin or lib",
            "span": {"path": str(manifest), "start": 0, "end": 0, "line": 1, "column": 1},
            "notes": [], "phase": "package"})

    def test_invalid_declared_candidates_reject_before_version_selection(self):
        for requirement in ("<2.0.0", ">=2.0.0"):
            for order in (("src/v1", "src/v2"), ("src/v2", "src/v1")):
                for directory in ("v1", "v2"):
                    for spelling in ("[]", "{}"):
                        with self.subTest(requirement=requirement, order=order,
                                          directory=directory, spelling=spelling):
                            app, _ = self.versioned(requirement)
                            self.package("app", "app", kind="bin", dependencies={
                                "dep": self.spec(requirement, paths=list(order))})
                            manifest, original = self.invalid_kind(app / "src" / directory, spelling)
                            self.reject_schema(lambda: load_package(app), manifest)
                            manifest.write_bytes(original)
                            expected = "v1" if requirement == "<2.0.0" else "v2"
                            self.assertEqual(load_package(app).dependencies["dep"].root,
                                             app / "src" / expected)

    def test_schema_diagnostic_precedes_locked_context_conflict(self):
        for order in ("local_first", "dependency_first"):
            app, entry = self.versioned()
            library, roots = self.mixed(app, entry, "v2", order)
            write_lock(app)
            lock = (app / "Hepta.lock").read_bytes()
            for spelling in ("[]", "{}"):
                manifest, original = self.invalid_kind(app / "src/v2", spelling)
                for locked in (False, True):
                    for form in (app, app / "hepta.toml", entry):
                        with self.subTest(order=order, spelling=spelling, locked=locked, form=str(form)):
                            self.reject_schema(lambda: load_project(form, locked=locked), manifest)
                self.assertEqual((app / "Hepta.lock").read_bytes(), lock)
                manifest.write_bytes(original)
                self.reject_context(lambda: load_project(app, locked=True), entry, library, roots)
                self.assertEqual(load_package(app).dependencies["dep"].root, app / "src/v2")

    def test_failed_lock_refresh_preserves_bytes_and_valid_recovery(self):
        app, _ = self.versioned()
        old = write_lock(app)["snapshot"]
        loaded = load_project(app, locked=True)
        lock = app / "Hepta.lock"
        before_bytes = lock.read_bytes()
        before = self.root / "before.lock"
        before.write_bytes(before_bytes)
        for directory in ("v1", "v2"):
            for spelling in ("[]", "{}"):
                manifest, original = self.invalid_kind(app / "src" / directory, spelling)
                self.assertFalse(loaded.unchanged())
                self.reject_schema(lambda: write_lock(app), manifest)
                self.assertEqual(lock.read_bytes(), before_bytes)
                manifest.write_bytes(original)
                self.assertTrue(loaded.unchanged())
                self.assertEqual(verify_lock(load_package(app)), old)
        self.package("app/src/v2", "vendor", "2.1.0")
        with self.assertRaises(HeptaError) as caught:
            load_project(app, locked=True)
        self.assertEqual(caught.exception.diagnostic.code, "E_LOCK_STALE")
        after = write_lock(app)["snapshot"]
        self.assertEqual(after["packages"]["."]["dependencies"], {"dep": "src/v2"})
        self.assertEqual(after["packages"]["src/v2"]["version"], "2.1.0")
        self.assertEqual(verify_lock(load_package(app)), after)
        review = compare_locks(before, lock)
        self.assertTrue(review["changed"])
        self.assertEqual(review["compatibility"], "not_assessed")
        self.assertEqual(review["dependencies"]["retargeted"], [])
        self.assertTrue(load_project(app, locked=True).unchanged())

    def test_public_cli_rejects_unselected_kind_then_frontend_recovers(self):
        app, _ = self.versioned(">=2.0.0")
        write_lock(app)
        lock = (app / "Hepta.lock").read_bytes()
        repository = Path(__file__).resolve().parents[1]
        for spelling in ("[]", "{}"):
            manifest, original = self.invalid_kind(app / "src/v1", spelling)
            for command, flags in (("lock", []), ("check", ["--frontend-only", "--backend", "c", "--json"]),
                                   ("inspect", ["--frontend-only", "--json"])):
                result = subprocess.run([sys.executable, "-B", "-m", "hepta", command, str(app), *flags],
                                        cwd=repository, capture_output=True, text=True, timeout=10)
                self.assertEqual((result.returncode, result.stderr), (1, ""), result.stdout)
                report = json.loads(result.stdout)
                self.assertFalse(report["ok"])
                self.assertEqual(report["status"], "rejected")
                self.assertEqual(len(report["diagnostics"]), 1)
                diagnostic = report["diagnostics"][0]
                self.assertEqual((diagnostic["code"], diagnostic["phase"], diagnostic["span"]["path"]),
                                 ("E_PACKAGE_SCHEMA", "package", str(manifest)))
                self.assertEqual((app / "Hepta.lock").read_bytes(), lock)
            manifest.write_bytes(original)
            result = subprocess.run([sys.executable, "-B", "-m", "hepta", "check", str(app),
                                     "--locked", "--frontend-only", "--backend", "c", "--json"],
                                    cwd=repository, capture_output=True, text=True, timeout=10)
            self.assertEqual((result.returncode, result.stderr), (0, ""), result.stdout)
            self.assertTrue(json.loads(result.stdout)["ok"])
            self.assertEqual((app / "Hepta.lock").read_bytes(), lock)


if __name__ == "__main__":
    unittest.main()
