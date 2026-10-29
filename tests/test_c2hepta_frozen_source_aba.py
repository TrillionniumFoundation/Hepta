"""Clang source-identity ABA regression: compile the admitted immutable bytes.

A pre/post source digest does not detect an input that changes while Clang
reads it and then returns to the original content. The compiler must receive
a frozen snapshot of the admitted source, not the mutable source pathname.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from tools import c2hepta


STABLE = "int stable(int x){return x;}\n"
SWAPPED = "int stable(int x){return x+1;}\n"


class ClangSourceSnapshotABA(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(shutil.which("clang"), "Clang required for source provenance test")
        self.temp = tempfile.TemporaryDirectory(prefix="hepta-clang-aba-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source.c"
        self.output = self.root / "result.hepta"
        self.report = self.root / "report.json"
        self.source.write_text(STABLE, encoding="utf-8")

    def run_with_source_rebind(self, *, restore: bool):
        original_run = c2hepta._run_bounded_ast
        compiler_inputs = []

        def race(args, **kwargs):
            if "-ast-dump=json" not in args:
                return original_run(args, **kwargs)
            compiler_inputs.append(Path(args[-1]))
            self.source.write_text(SWAPPED, encoding="utf-8")
            try:
                return original_run(args, **kwargs)
            finally:
                if restore:
                    self.source.write_text(STABLE, encoding="utf-8")

        with patch.object(c2hepta, "_run_bounded_ast", side_effect=race):
            outcome = c2hepta.migrate(self.source, self.output, self.report, clang="clang")
        self.assertEqual(len(compiler_inputs), 1, "expected one real Clang AST invocation")
        return outcome, compiler_inputs[0]

    def test_source_change_and_restore_cannot_change_emitted_hepta(self):
        baseline = c2hepta.migrate(self.source, self.output, self.report, clang="clang")
        self.assertEqual(baseline["status"], "converted", baseline)
        baseline_hepta = self.output.read_text(encoding="utf-8")

        result, compiler_input = self.run_with_source_rebind(restore=True)
        self.assertEqual(result["status"], "converted", result)
        self.assertEqual(self.source.read_text(encoding="utf-8"), STABLE)
        self.assertEqual(result["source_sha256"], hashlib.sha256(STABLE.encode()).hexdigest())
        self.assertNotEqual(compiler_input, self.source.resolve(),
                            "Clang still reads the mutable original source path")
        self.assertEqual(self.output.read_text(encoding="utf-8"), baseline_hepta,
                         "compiler emitted swapped source despite unchanged source digest")

    def test_persistent_source_change_is_still_rejected_without_output_replacement(self):
        baseline = c2hepta.migrate(self.source, self.output, self.report, clang="clang")
        self.assertEqual(baseline["status"], "converted", baseline)
        baseline_hepta = self.output.read_bytes()

        result, _ = self.run_with_source_rebind(restore=False)
        self.assertEqual(result["status"], "rejected", result)
        self.assertIn("source changed during conversion", result["reason"])
        self.assertEqual(self.output.read_bytes(), baseline_hepta)


if __name__ == "__main__":
    unittest.main()
