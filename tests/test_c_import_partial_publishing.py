"""Real native import-c output integrity when sidecar publication cannot proceed."""
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
HEADER = b"int add(int a, int b);\n"


class CImportSidecarPreflight(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.gcc = shutil.which("gcc")
        if cls.gcc is None:
            raise AssertionError("Actual GCC required: no mocked/skipped native qualification")
        cls.env = dict(os.environ, PYTHONPATH=str(ROOT), PYTHONDONTWRITEBYTECODE="1")

    def call_import(self, root: Path, generated: Path):
        header = root / "api.h"
        header.write_bytes(HEADER)
        proc = subprocess.run(
            [sys.executable, "-B", "-m", "hepta", "import-c",
             str(header), "--cc", self.gcc, "-o", str(generated)],
            cwd=root, env=self.env, capture_output=True, text=True, timeout=120)
        self.assertEqual(proc.stderr, "", proc.stderr)
        return proc, json.loads(proc.stdout), header

    def test_existing_generated_output_unchanged_when_sidecar_is_directory(self):
        with tempfile.TemporaryDirectory(prefix="hepta-import-preflight-") as td:
            root = Path(td)
            output = root / "bindings.hepta"
            previous = b"ORIGINAL COMMITTED OUTPUT MUST SURVIVE\n"
            output.write_bytes(previous)
            sidecar = root / "bindings.hepta.imports.json"
            sidecar.mkdir()
            proc, report, header = self.call_import(root, output)
            print("PARTIAL_WRITE_EXISTING", json.dumps({
                "exit": proc.returncode, "output_sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
                "original_sha256": hashlib.sha256(previous).hexdigest(),
                "sidecar_is_dir": sidecar.is_dir(), "report": report,
            }, sort_keys=True), flush=True)
            # The previous implementation returns E_DRIVER after overwriting
            # this pre-existing output, creating an invalid partial revision.
            self.assertEqual(output.read_bytes(), previous, "failed sidecar commit destroyed prior output")
            self.assertEqual(header.read_bytes(), HEADER)
            self.assertTrue(sidecar.is_dir())
            self.assertEqual(proc.returncode, 2, report)
            self.assertEqual(report["diagnostics"][0]["code"], "E_DRIVER")

    def test_new_generated_output_not_published_when_sidecar_is_directory(self):
        with tempfile.TemporaryDirectory(prefix="hepta-import-preflight-") as td:
            root = Path(td)
            output = root / "bindings.hepta"
            sidecar = root / "bindings.hepta.imports.json"
            sidecar.mkdir()
            proc, report, header = self.call_import(root, output)
            print("PARTIAL_WRITE_NEW", json.dumps({
                "exit": proc.returncode, "published": output.exists(),
                "sidecar_is_dir": sidecar.is_dir(), "report": report,
            }, sort_keys=True), flush=True)
            self.assertFalse(output.exists(), "failed import published unpaired generated source")
            self.assertEqual(header.read_bytes(), HEADER)
            self.assertEqual(proc.returncode, 2, report)
            self.assertEqual(report["diagnostics"][0]["code"], "E_DRIVER")

    def test_normal_native_import_produces_both_outputs(self):
        with tempfile.TemporaryDirectory(prefix="hepta-import-positive-") as td:
            root = Path(td)
            output = root / "bindings.hepta"
            proc, report, header = self.call_import(root, output)
            self.assertEqual(proc.returncode, 0, report)
            self.assertEqual(header.read_bytes(), HEADER)
            self.assertTrue(output.read_text().startswith("// hepta:c-import:v1\n"))
            sidecar = root / "bindings.hepta.imports.json"
            fact = json.loads(sidecar.read_text())
            self.assertEqual(fact["header_sha256"], hashlib.sha256(HEADER).hexdigest())
            self.assertEqual(fact["source_sha256"], hashlib.sha256(output.read_bytes()).hexdigest())


if __name__ == "__main__":
    unittest.main()
