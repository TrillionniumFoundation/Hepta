"""Clang stderr must have a rejection budget, not merely bounded retention.

Draining unlimited hostile stderr for 10-20 seconds lets an alternate compiler
consume arbitrarily large CPU/pipe bandwidth before its otherwise normal exit.
"""
from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest

from tools.c2hepta import UnsupportedC, _run_bounded_ast, migrate


class ClangStderrBudget(unittest.TestCase):
    def test_stderr_above_limit_fails_closed_even_when_stdout_is_small(self):
        with self.assertRaisesRegex(UnsupportedC, "stderr exceeds 4 KiB"):
            _run_bounded_ast([
                sys.executable, "-c",
                "import sys; sys.stdout.write('{}'); sys.stderr.write('e' * 32768)",
            ], max_stdout_bytes=4096)

    def test_stderr_exactly_at_limit_remains_allowed(self):
        result = _run_bounded_ast([
            sys.executable, "-c",
            "import sys; sys.stdout.write('ok'); sys.stderr.write('w' * 4096)",
        ], max_stdout_bytes=4096)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"ok")
        self.assertEqual(result.stderr, b"w" * 4096)

    def test_probe_stderr_overflow_is_rejected_without_emitting_hepta(self):
        with tempfile.TemporaryDirectory(prefix="hepta-stderr-") as temp:
            root = Path(temp)
            src, out, report = (root / "in.c", root / "out.hepta", root / "out.json")
            src.write_text("int f(int x) { return x; }\n")
            fake = root / "fake-clang"
            fake.write_text(
                "#!" + sys.executable + "\n"
                "import sys\n"
                "if '--version' in sys.argv:\n"
                "    sys.stderr.write('e' * 32768)\n"
                "    print('clang version fixture')\n"
                "elif '-dumpmachine' in sys.argv:\n"
                "    print('x86_64-unknown-linux-gnu')\n"
                "elif '-dM' in sys.argv:\n"
                "    print('#define __SIZEOF_INT__ 4')\n"
                "    print('#define __CHAR_BIT__ 8')\n"
                "else:\n"
                "    print('{}')\n"
            )
            fake.chmod(0o755)
            result = migrate(src, out, report, clang=str(fake))
            self.assertEqual(result["status"], "rejected", result)
            self.assertIn("stderr exceeds 4 KiB", result["reason"])
            self.assertFalse(out.exists())
            self.assertEqual(json.loads(report.read_text())["status"], "rejected")


if __name__ == "__main__":
    unittest.main()
