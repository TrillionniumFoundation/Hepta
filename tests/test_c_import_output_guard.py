"""Real CLI regressions: imported C header must survive every output path."""
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

ROOT = Path(hepta.__file__).resolve().parents[1]


class CImportOutputGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.gcc = shutil.which("gcc")
        if not cls.gcc:
            raise AssertionError("Real GCC is required; no skip/mock qualification permitted")
        cls.env = dict(os.environ, PYTHONPATH=str(ROOT), PYTHONDONTWRITEBYTECODE="1")

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hepta-import-output-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def run_cli(self, header, output):
        proc = subprocess.run(
            [sys.executable, "-B", "-m", "hepta", "import-c",
             str(header), "--cc", self.gcc, "-o", str(output)],
            cwd=self.root, env=self.env, capture_output=True, text=True, timeout=180)
        self.assertEqual(proc.stderr, "", proc.stderr)
        return proc, json.loads(proc.stdout)

    def test_manifest_name_cannot_replace_real_header(self):
        # Path.with_suffix(".imports.json") makes this output's sidecar
        # point to the *original C header*, despite its non-.h filename.
        header = self.root / "bindings.imports.json"
        original = b"int add(int a, int b);\n"
        header.write_bytes(original)
        generated = self.root / "bindings"
        proc, report = self.run_cli(header, generated)
        # Compare bytes BEFORE status: the pre-fix CLI returned success after
        # silently replacing the actual header with the generated manifest.
        self.assertEqual(header.read_bytes(), original, "original C header destroyed")
        self.assertFalse(generated.exists(), "refused import published a partial source")
        self.assertEqual(proc.returncode, 2, report)
        self.assertEqual(report["diagnostics"][0]["code"], "E_DRIVER")

    def test_manifest_symlink_cannot_replace_real_header(self):
        header = self.root / "api.h"
        original = b"int add(int a, int b);\n"
        header.write_bytes(original)
        generated = self.root / "bindings.hepta"
        manifest = self.root / "bindings.hepta.imports.json"
        manifest.symlink_to(header)
        proc, report = self.run_cli(header, generated)
        self.assertEqual(header.read_bytes(), original, "C header overwritten through sidecar symlink")
        self.assertTrue(manifest.is_symlink(), "sidecar alias was replaced")
        self.assertFalse(generated.exists(), "refused import published a partial source")
        self.assertEqual(proc.returncode, 2, report)
        self.assertEqual(report["diagnostics"][0]["code"], "E_DRIVER")

    def test_normal_header_import_remains_native_and_preserves_input(self):
        header = self.root / "api.h"
        original = b"int add(int a, int b);\n"
        header.write_bytes(original)
        generated = self.root / "bindings.hepta"
        proc, report = self.run_cli(header, generated)
        self.assertEqual(proc.returncode, 0, report)
        self.assertIs(report["ok"], True)
        self.assertEqual(header.read_bytes(), original)
        self.assertTrue(generated.read_text().startswith("// hepta:c-import:v1\n"))
        manifest = self.root / "bindings.hepta.imports.json"
        facts = json.loads(manifest.read_text())
        self.assertEqual(facts["header_sha256"], hashlib.sha256(original).hexdigest())
        self.assertEqual(facts["source_sha256"], hashlib.sha256(generated.read_bytes()).hexdigest())


if __name__ == "__main__":
    unittest.main()
