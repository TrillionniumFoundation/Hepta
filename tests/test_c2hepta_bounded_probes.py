"""Resource and negative tests for every early Clang metadata probe."""
from __future__ import annotations

import hashlib
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

from tools.c2hepta import migrate


class BoundedClangMetadataProbes(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hepta-clang-probe-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "sample.c"
        self.output = self.root / "sample.hepta"
        self.report = self.root / "sample-report.json"
        self.source.write_text("int f(int x){return x;}\n", encoding="utf-8")

    def fake_clang(self, mode: str) -> str:
        executable = self.root / ("mock-clang-" + mode)
        executable.write_text(f"""#!{sys.executable}
import sys
mode = {mode!r}
if "--version" in sys.argv:
    if mode == "version_overflow":
        sys.stdout.buffer.write(b"v" * 2000000)
    elif mode == "version_failure":
        # Stay below the stderr budget to isolate the nonzero-exit path.
        sys.stderr.buffer.write(b"e" * 300)
        sys.exit(9)
    elif mode == "version_empty":
        pass
    else:
        print("clang version fixture")
elif "-dumpmachine" in sys.argv:
    if mode == "target_overflow":
        sys.stdout.buffer.write(b"t" * 2000000)
    else:
        print("x86_64-unknown-linux-gnu")
elif "-dM" in sys.argv:
    if mode == "defines_overflow":
        sys.stdout.buffer.write(b"d" * 2000000)
    else:
        print("#define __SIZEOF_INT__ 4")
        print("#define __CHAR_BIT__ 8")
else:
    print("{{}}")
""", encoding="utf-8")
        executable.chmod(0o755)
        return str(executable)

    def test_each_metadata_probe_rejects_excess_output_without_publishing(self):
        for mode in ("version_overflow", "target_overflow", "defines_overflow"):
            with self.subTest(mode=mode):
                result = migrate(self.source, self.output, self.report,
                                 clang=self.fake_clang(mode))
                self.assertEqual(result["status"], "rejected", result)
                self.assertIn("Clang probe output exceeds bounded capture limit",
                              result["reason"])
                self.assertFalse(self.output.exists())
                self.assertTrue(self.report.exists())
                self.assertEqual(result["source_sha256"],
                                 hashlib.sha256(self.source.read_bytes()).hexdigest())

    def test_probe_nonzero_does_not_qualify_as_compiler_identity(self):
        result = migrate(self.source, self.output, self.report,
                         clang=self.fake_clang("version_failure"))
        self.assertEqual(result["status"], "rejected")
        self.assertIn("Clang version probe failed", result["reason"])
        self.assertNotIn("e" * 5000, result["reason"])
        self.assertFalse(self.output.exists())

    def test_empty_version_probe_fails_closed(self):
        result = migrate(self.source, self.output, self.report,
                         clang=self.fake_clang("version_empty"))
        self.assertEqual(result["status"], "rejected")
        self.assertIn("Clang version probe returned empty output", result["reason"])
        self.assertFalse(self.output.exists())

    def test_actual_clang_still_converts_scalar_c(self):
        self.assertIsNotNone(shutil.which("clang"), "Clang required for qualification")
        result = migrate(self.source, self.output, self.report)
        self.assertEqual(result["status"], "converted", result)
        self.assertIn("clang", result["clang"].lower())
        self.assertIn("target", result)
        self.assertEqual(result["frontend_validation"], "passed")
        self.assertTrue(self.output.is_file())


if __name__ == "__main__":
    unittest.main()
