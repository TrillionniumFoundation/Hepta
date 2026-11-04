"""Actual CLI guard: a distinct hard-link pathname must not destroy a source input."""
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
SCALAR = b"fn main() -> i32 effects {} { return 42; }\n"


class KnownInputHardlinkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.gcc = shutil.which("gcc")
        if cls.gcc is None:
            raise AssertionError("Real GCC required; refusing synthetic or skipped execution")
        cls.env = dict(os.environ, PYTHONPATH=str(ROOT), PYTHONDONTWRITEBYTECODE="1")

    def cli(self, source: Path, output: Path):
        return subprocess.run(
            [sys.executable, "-B", "-m", "hepta", "emit", str(source),
             "--backend", "c", "--cc", self.gcc,
             "--crate-type", "bin", "-o", str(output)],
            cwd=source.parent, env=self.env, capture_output=True, text=True, timeout=120)

    def test_hardlinked_output_must_not_destroy_loaded_source(self):
        with tempfile.TemporaryDirectory(prefix="hepta-input-inode-") as td:
            root = Path(td)
            source, output = root / "main.hepta", root / "generated.c"
            source.write_bytes(SCALAR)
            os.link(source, output)
            self.assertTrue(source.samefile(output))
            before = hashlib.sha256(SCALAR).hexdigest()
            proc = self.cli(source, output)
            after_source = source.read_bytes()
            after_output = output.read_bytes()
            print("HARDLINK_INPUT_EVIDENCE", json.dumps({
                "exit": proc.returncode, "original_sha256": before,
                "source_after_sha256": hashlib.sha256(after_source).hexdigest(),
                "output_after_sha256": hashlib.sha256(after_output).hexdigest(),
                "same_inode_after": source.samefile(output),
                "stdout": proc.stdout, "stderr": proc.stderr,
            }, sort_keys=True), flush=True)
            # Check byte integrity FIRST: the original implementation succeeds
            # while actually overwriting the source through a hardlink.
            self.assertEqual(after_source, SCALAR, "emit destroyed the original Hepta source")
            self.assertEqual(after_output, SCALAR, "refusal mutated an existing hardlink")
            self.assertEqual(proc.stderr, "")
            self.assertEqual(proc.returncode, 2, proc.stdout)
            report = json.loads(proc.stdout)
            self.assertEqual(report["diagnostics"][0]["code"], "E_DRIVER")

    def test_regular_unrelated_output_still_emits_real_c(self):
        with tempfile.TemporaryDirectory(prefix="hepta-input-inode-positive-") as td:
            root = Path(td)
            source, output = root / "main.hepta", root / "generated.c"
            source.write_bytes(SCALAR)
            proc = self.cli(source, output)
            self.assertEqual(proc.stderr, "")
            self.assertEqual(proc.returncode, 0, proc.stdout)
            report = json.loads(proc.stdout)
            self.assertIs(report["ok"], True, report)
            self.assertEqual(source.read_bytes(), SCALAR)
            self.assertTrue(output.exists())
            self.assertGreater(output.stat().st_size, 0)
            self.assertNotEqual(output.read_bytes(), SCALAR)


if __name__ == "__main__":
    unittest.main()
