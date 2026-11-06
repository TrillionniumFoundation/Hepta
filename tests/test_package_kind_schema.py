"""Package-kind schema regressions without native compilation or execution."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from hepta.ast import HeptaError
from hepta.packages import load_package, verify_lock, write_lock


class PackageKindSchemaTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hepta-kind-schema-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.app = self.root / "app"
        self.app.mkdir()
        (self.app / "src").mkdir()
        for filename in ("main.hepta", "lib.hepta"):
            (self.app / "src" / filename).write_text("", encoding="utf-8")
        self.manifest = self.app / "hepta.toml"

    def manifest_text(self, kind=None):
        text = '[package]\nname = "app"\nversion = "0.1.0"\n'
        return text if kind is None else text + f"kind = {kind}\n"

    def put(self, kind=None, *, text=None):
        self.manifest.write_text(self.manifest_text(kind) if text is None else text, encoding="utf-8")

    def assert_rejected(self, root=None, *, code="E_PACKAGE_SCHEMA", message="Package kind must be bin or lib", path=None):
        with self.assertRaises(HeptaError) as caught:
            load_package(self.app if root is None else root)
        diagnostic = caught.exception.diagnostic
        self.assertEqual(diagnostic.code, code)
        self.assertEqual(diagnostic.phase, "package")
        self.assertEqual(diagnostic.message, message)
        self.assertEqual(diagnostic.span.path, str(self.manifest if path is None else path))

    def test_array_kinds_have_package_diagnostics(self):
        for kind in ('[]', '["bin"]', '["lib", "bin"]', '[["bin"]]', '[{name = "bin"}]'):
            with self.subTest(kind=kind):
                self.put(kind)
                self.assert_rejected()

    def test_table_kinds_have_package_diagnostics(self):
        for kind in ('{}', '{name = "bin"}', '{bin = {enabled = true}}'):
            with self.subTest(kind=kind):
                self.put(kind)
                self.assert_rejected()
        for suffix in ('[package.kind]\nname = "bin"\n', '[[package.kind]]\nname = "bin"\n'):
            with self.subTest(suffix=suffix):
                self.put(text=self.manifest_text() + suffix)
                self.assert_rejected()

    def test_non_string_scalar_kinds_keep_the_same_diagnostic(self):
        for kind in ('0', '1', '1.5', 'nan', 'inf', 'true', 'false',
                     '2026-11-05T12:00:00Z', '2026-11-05T12:00:00', '2026-11-05', '12:00:00'):
            with self.subTest(kind=kind):
                self.put(kind)
                self.assert_rejected()

    def test_unsupported_string_kinds_keep_the_same_diagnostic(self):
        for kind in ('""', '"BIN"', '"LIB"', '"bin "', '"binary"', '"shared"'):
            with self.subTest(kind=kind):
                self.put(kind)
                self.assert_rejected()

    def test_default_bin_and_lib_keep_default_entry_selection(self):
        for spelling, expected in ((None, "bin"), ('"bin"', "bin"), ('"lib"', "lib")):
            with self.subTest(kind=spelling):
                self.put(spelling)
                package = load_package(self.app)
                self.assertEqual(package.kind, expected)
                self.assertEqual(package.entry, self.app / "src" / ("main.hepta" if expected == "bin" else "lib.hepta"))
                self.assertEqual(package.manifest_bytes, self.manifest.read_bytes())

    def test_invalid_kind_precedes_missing_entry_and_bad_dependencies(self):
        for kind in ('[]', '{}', 'true', '"bad"'):
            with self.subTest(kind=kind):
                self.put(text=self.manifest_text(kind) + 'entry = "src/missing.hepta"\n[dependencies]\nlib = 1\n')
                self.assert_rejected()

    def test_prior_name_version_and_unknown_key_diagnostics_are_unchanged(self):
        for text, code, message in (
            (self.manifest_text('[]').replace('name = "app"', 'name = []'), "E_PACKAGE_NAME", "Package name must be an ASCII identifier"),
            (self.manifest_text('{}').replace('version = "0.1.0"', 'version = []'), "E_PACKAGE_VERSION", "Package version must be an explicit major.minor.patch"),
            (self.manifest_text('[]') + 'build = "unused"\n', "E_PACKAGE_SCHEMA", "Unsupported package key; build scripts are not supported"),
        ):
            with self.subTest(code=code):
                self.put(text=text)
                self.assert_rejected(code=code, message=message)

    def test_invalid_dependency_kind_reports_the_dependency_manifest(self):
        consumer = self.root / "consumer"
        (consumer / "src").mkdir(parents=True)
        (consumer / "src/main.hepta").write_text("", encoding="utf-8")
        (consumer / "hepta.toml").write_text(
            '[package]\nname = "consumer"\nversion = "0.1.0"\n[dependencies]\napp = {path = "../app"}\n', encoding="utf-8")
        for kind in ('[]', '{}'):
            with self.subTest(kind=kind):
                self.put(kind)
                self.assert_rejected(consumer)
        self.put('"bin"')
        self.assert_rejected(consumer, code="E_PACKAGE_DEPENDENCY", message='Dependencies must declare kind = "lib"', path=self.app)
        self.put('"lib"')
        self.assertEqual(load_package(consumer).dependencies["app"].kind, "lib")

    def test_cli_reports_one_json_diagnostic_instead_of_traceback(self):
        repository = Path(__file__).resolve().parents[1]
        for kind in ('[]', '{}'):
            self.put(kind)
            commands = [["lock", str(self.app)]]
            for command in ("check", "inspect"):
                for target in (self.app, self.manifest, self.app / "src/main.hepta"):
                    commands.append([command, str(target), "--frontend-only", "--json"])
            for command in commands:
                with self.subTest(kind=kind, command=command):
                    result = subprocess.run([sys.executable, "-m", "hepta", *command],
                                            cwd=repository, capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, 1, result.stderr)
                    self.assertEqual(result.stderr, "")
                    report = json.loads(result.stdout)
                    self.assertEqual(report["ok"], False)
                    self.assertEqual(report["status"], "rejected")
                    self.assertEqual(len(report["diagnostics"]), 1)
                    diagnostic = report["diagnostics"][0]
                    self.assertEqual(diagnostic["code"], "E_PACKAGE_SCHEMA")
                    self.assertEqual(diagnostic["phase"], "package")
                    self.assertEqual(diagnostic["message"], "Package kind must be bin or lib")
                    self.assertEqual(diagnostic["span"]["path"], str(self.manifest))
                    self.assertFalse((self.app / "Hepta.lock").exists())

    def test_valid_kinds_roundtrip_content_lock(self):
        for spelling, expected in ((None, "bin"), ('"bin"', "bin"), ('"lib"', "lib")):
            with self.subTest(kind=spelling):
                self.put(spelling)
                report = write_lock(self.app)
                self.assertTrue(report["ok"])
                self.assertEqual(report["snapshot"]["packages"]["."]["kind"], expected)
                self.assertEqual(verify_lock(load_package(self.app)), report["snapshot"])


if __name__ == "__main__":
    unittest.main()
