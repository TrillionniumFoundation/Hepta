"""Regression: direct C2Hepta library calls may not overwrite input/artifacts.

The CLI already rejects aliases. These checks exercise the Python API itself.
No Clang, native compiler, or network access is required: the non-alias input
deliberately uses a rejected preprocessor directive.
"""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from tools.c2hepta import migrate


class C2HeptaPathAliasing(unittest.TestCase):
    INPUT = b"#define ONE 1\nint f(void) { return ONE; }\n"

    def test_direct_api_rejects_all_aliases_before_writing(self):
        for scenario in ("report_is_source", "output_is_source", "report_is_output",
                         "normalized_report_is_source"):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                src = root / "input.c"
                output = root / "translated.hepta"
                report = root / "evidence.json"
                src.write_bytes(self.INPUT)
                output.write_bytes(b"keep translated artifact")
                report.write_bytes(b"keep evidence")
                if scenario == "report_is_source":
                    report_arg = src
                    output_arg = output
                elif scenario == "output_is_source":
                    report_arg = report
                    output_arg = src
                elif scenario == "report_is_output":
                    report_arg = output
                    output_arg = output
                else:
                    (root / "nested").mkdir()
                    report_arg = root / "nested" / ".." / "input.c"
                    output_arg = output
                with self.assertRaisesRegex(ValueError, "paths must be distinct"):
                    migrate(src, output_arg, report_arg)
                self.assertEqual(src.read_bytes(), self.INPUT)
                self.assertEqual(output.read_bytes(), b"keep translated artifact")
                self.assertEqual(report.read_bytes(), b"keep evidence")

    def test_distinct_paths_still_write_rejection_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "input.c"
            output = root / "translated.hepta"
            report = root / "evidence.json"
            src.write_bytes(self.INPUT)
            result = migrate(src, output, report)
            self.assertEqual(result["status"], "rejected")
            self.assertEqual(src.read_bytes(), self.INPUT)
            self.assertFalse(output.exists())
            self.assertEqual(json.loads(report.read_text())["status"], "rejected")


if __name__ == "__main__":
    unittest.main()
