"""The public compiler command must publish checked migration or fail closed."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class ComposedMigrationCommandTests(unittest.TestCase):
    def test_public_translation_command_and_no_replace_rejection(self):
        clang = shutil.which("clang++")
        self.assertIsNotNone(clang, "the native compiler is required")
        with tempfile.TemporaryDirectory(prefix="hepta-composed-cli-") as temporary:
            output = Path(temporary) / "actual.hepta"
            command = [sys.executable, "-m", "hepta", "migrate-cpp-composed",
                       str(ROOT / "examples/cpp/composed_migration/triple.cpp"),
                       "--output", str(output), "--clang", clang]
            process = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=30)
            self.assertEqual(process.returncode, 0, process.stderr + process.stdout)
            report = json.loads(process.stdout)
            self.assertIs(report["ok"], True)
            self.assertEqual(report["native_execution"], "not_run")
            self.assertEqual(report["output_sha256"], hashlib.sha256(output.read_bytes()).hexdigest())
            before = output.read_bytes()
            refused = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=30)
            self.assertNotEqual(refused.returncode, 0)
            rejected = json.loads(refused.stdout)
            self.assertIs(rejected["ok"], False)
            self.assertEqual(rejected["diagnostics"][0]["code"], "E_CPP_COMPOSED_PATH")
            self.assertEqual(output.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
