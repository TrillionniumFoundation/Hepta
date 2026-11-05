"""Native import-c regression: unrelated hardlinked sidecar must not overwrite data."""
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


class CImportUnrelatedSidecarHardlink(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.gcc = shutil.which("gcc")
        if cls.gcc is None:
            raise AssertionError("Real GCC required, no skipped native qualification")
        cls.env = dict(os.environ, PYTHONPATH=str(ROOT), PYTHONDONTWRITEBYTECODE="1")

    def run_import(self, root: Path, dest: Path):
        header = root / "api.h"
        header.write_bytes(HEADER)
        proc = subprocess.run(
            [sys.executable, "-B", "-m", "hepta", "import-c",
             str(header), "--cc", self.gcc, "-o", str(dest)],
            cwd=root, env=self.env, text=True, capture_output=True, timeout=120)
        self.assertEqual(proc.stderr, "", proc.stderr)
        return proc, json.loads(proc.stdout), header

    def test_unrelated_sidecar_hardlink_cannot_truncate_other_user_data(self):
        with tempfile.TemporaryDirectory(prefix="hia-sidecar-hardlink-") as td:
            root = Path(td)
            dest = root / "bindings.hepta"
            victim = root / "human-notes.txt"
            original = b"UNRELATED USER FILE MUST NOT BE OVERWRITTEN\n"
            victim.write_bytes(original)
            sidecar = root / "bindings.hepta.imports.json"
            os.link(victim, sidecar)
            proc, report, header = self.run_import(root, dest)
            observed = victim.read_bytes()
            print("UNRELATED_SIDECAR_HARDLINK", json.dumps({
                "exit": proc.returncode,
                "original_sha256": hashlib.sha256(original).hexdigest(),
                "actual_sha256": hashlib.sha256(observed).hexdigest(),
                "new_source_exists": dest.exists(),
                "sidecar_remains_hardlink": sidecar.samefile(victim),
                "diagnostics": report.get("diagnostics", []),
            }, sort_keys=True), flush=True)
            self.assertEqual(observed, original, "import-c overwrote unrelated existing user file")
            self.assertFalse(dest.exists(), "failed import-c left unpaired generated source")
            self.assertEqual(header.read_bytes(), HEADER)
            self.assertTrue(sidecar.samefile(victim))
            self.assertEqual(proc.returncode, 2, report)
            self.assertEqual(report["diagnostics"][0]["code"], "E_DRIVER")

    def test_normal_import_without_sidecar_hardlink_succeeds(self):
        with tempfile.TemporaryDirectory(prefix="hia-sidecar-positive-") as td:
            root = Path(td)
            dest = root / "bindings.hepta"
            proc, report, header = self.run_import(root, dest)
            self.assertEqual(proc.returncode, 0, report)
            self.assertEqual(header.read_bytes(), HEADER)
            self.assertTrue(dest.read_text().startswith("// hepta:c-import:v1\n"))
            sidecar = root / "bindings.hepta.imports.json"
            self.assertTrue(sidecar.is_file())
            manifest = json.loads(sidecar.read_text())
            self.assertEqual(manifest["header_sha256"], hashlib.sha256(HEADER).hexdigest())
            self.assertEqual(manifest["source_sha256"], hashlib.sha256(dest.read_bytes()).hexdigest())


if __name__ == "__main__":
    unittest.main()
