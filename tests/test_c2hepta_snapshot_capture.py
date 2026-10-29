"""Captured source identity must bind the bytes actually parsed by Clang."""
from __future__ import annotations

import hashlib
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

from tools import c2hepta


class C2HeptaSnapshotCapture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hepta-c2hepta-snapshot-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "module.c"
        self.output = self.root / "module.hepta"
        self.report = self.root / "report.json"
        self.original = b"int identity(int x) { return x; }\n"
        self.changed = b"int identity(int x) { return x + 1; }\n"
        self.source.write_bytes(self.original)

    def test_real_clang_sees_captured_bytes_during_source_aba(self):
        clang = shutil.which("clang")
        self.assertIsNotNone(clang, "real Clang is required for the source ABA control")
        actual_capture = c2hepta.run_bounded
        observations = []

        def capture(argv, **kwargs):
            if "-ast-dump=json" not in argv:
                return actual_capture(argv, **kwargs)
            self.source.write_bytes(self.changed)
            try:
                observations.append({"path_bytes": self.source.read_bytes(),
                                     "input_bytes": kwargs["input_text"].encode("utf-8"),
                                     "source_operand": argv[-1]})
                return actual_capture(argv, **kwargs)
            finally:
                # A digest-only recheck would miss this temporary change.
                self.source.write_bytes(self.original)

        with patch.object(c2hepta, "run_bounded", side_effect=capture):
            result = c2hepta.migrate(self.source, self.output, self.report, clang=clang)
        self.assertEqual(result["status"], "converted", result)
        self.assertEqual(observations, [{"path_bytes": self.changed,
                                        "input_bytes": self.original,
                                        "source_operand": "-"}])
        self.assertEqual(result["functions"][0]["ir"]["body"][0]["expr"]["kind"], "var")
        self.assertEqual(result["clang_input"], {
            "transport": "captured_source_stdin", "bytes": len(self.original),
            "sha256": hashlib.sha256(self.original).hexdigest()})
        self.assertEqual(self.source.read_bytes(), self.original)
        self.assertIn("return x;", self.output.read_text())
        self.assertNotIn("x +", self.output.read_text())

    def _tool(self, mode):
        tool = self.root / "compiler-probe"
        # A real child writes the oversized stream. The capture helper must
        # reject it without an unbounded communicate() allocation.
        tool.write_text(
            f"#!{sys.executable}\n"
            "import os, sys\n"
            f"mode = {mode!r}\n"
            "args = sys.argv[1:]\n"
            "if '--version' in args:\n"
            "    if mode == 'version': os.write(1, b'v' * 65000)\n"
            "    else: print('test compiler capture probe')\n"
            "elif '-dumpmachine' in args: print('x86_64-unknown-linux-gnu')\n"
            "elif '-dM' in args: print('#define __SIZEOF_INT__ 4\\n#define __CHAR_BIT__ 8')\n"
            "elif mode == 'ast': os.write(1, b' ' * 8000001)\n"
            "elif mode == 'diagnostic': os.write(2, b'e' * 65000)\n"
            "else: sys.exit(1)\n",
            encoding="utf-8")
        tool.chmod(0o700)
        return str(tool)

    def test_all_compiler_output_routes_are_bounded(self):
        for mode in ("version", "ast", "diagnostic"):
            with self.subTest(mode=mode):
                result = c2hepta.migrate(self.source, self.output, self.report,
                                         clang=self._tool(mode))
                self.assertEqual(result["status"], "rejected", result)
                self.assertEqual(result["capture_error"], "E_CAPTURE_OUTPUT_SIZE")
                self.assertFalse(self.output.exists())
                self.assertEqual(self.source.read_bytes(), self.original)

    def test_non_utf8_source_refuses_without_replacement(self):
        clang = shutil.which("clang")
        self.assertIsNotNone(clang, "real Clang required")
        self.source.write_bytes(b"/*\xff*/ " + self.original)
        result = c2hepta.migrate(self.source, self.output, self.report, clang=clang)
        self.assertEqual(result["status"], "rejected", result)
        self.assertIn("utf-8", result["reason"])
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
