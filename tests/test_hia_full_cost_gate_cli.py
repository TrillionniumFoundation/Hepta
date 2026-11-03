"""File admission controls for the observed-cost command, without native tools."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from hepta.hia_full_cost_gate import MAX_INPUT_BYTES
from tests.test_hia_full_cost_gate import fixture, wire

ROOT = Path(__file__).resolve().parents[1]


class HIAFullCostGateCLITests(unittest.TestCase):
    def run_gate(self, source, output, *extra):
        return subprocess.run(
            [sys.executable, str(ROOT / "tools/qualify_hia_full_cost_gate.py"),
             "--input", str(source), "--output", str(output), *extra],
            capture_output=True, text=True, timeout=5, cwd=ROOT)

    def assert_refused(self, source, output):
        result = self.run_gate(source, output)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("E_HIA_FULL_COST_GATE", result.stderr)
        self.assertFalse(output.exists())

    @unittest.skipUnless(hasattr(os, "mkfifo") and hasattr(os, "O_NONBLOCK"),
                         "requires nonblocking FIFO support")
    def test_fifo_without_writer_is_rejected_without_waiting(self):
        with tempfile.TemporaryDirectory() as folder:
            source, output = Path(folder) / "input", Path(folder) / "output.json"
            os.mkfifo(source)
            self.assert_refused(source, output)

    @unittest.skipUnless(hasattr(os, "O_NOFOLLOW"), "requires no-follow support")
    def test_symlink_input_is_not_followed(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "actual.json").write_bytes(wire(fixture()))
            (root / "alias.json").symlink_to(root / "actual.json")
            self.assert_refused(root / "alias.json", root / "output.json")

    def test_directory_missing_and_oversized_inputs_leave_no_verdict(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            oversized = root / "oversized.json"
            oversized.write_bytes(b" " * (MAX_INPUT_BYTES + 1))
            for source in (root, root / "missing", oversized):
                with self.subTest(source=source.name):
                    self.assert_refused(source, root / "output.json")

    def test_regular_evidence_retains_positive_and_negative_exit_semantics(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for positive in (True, False):
                state = fixture()
                if not positive:
                    state["arms"][3]["unknown_costs"] = ["human_work_ns"]
                source = root / "input.json"
                source.write_bytes(wire(state))
                for require_positive in (True, False):
                    with self.subTest(positive=positive, require_positive=require_positive):
                        output = root / f"output-{positive}-{require_positive}.json"
                        extra = ("--require-positive",) if require_positive else ()
                        result = self.run_gate(source, output, *extra)
                        expected = 2 if require_positive and not positive else 0
                        self.assertEqual(result.returncode, expected, result.stderr)
                        verdict = json.loads(output.read_bytes())
                        self.assertIs(verdict["economic_scope_positive"], positive)
                        self.assertEqual(verdict["authority"], "DENY_ALL")
                        self.assertFalse(verdict["production_activation_allowed"])

    def test_existing_output_is_never_replaced(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source, output = root / "input.json", root / "output.json"
            source.write_bytes(wire(fixture()))
            output.write_bytes(b"existing verdict")
            result = self.run_gate(source, output)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(output.read_bytes(), b"existing verdict")


if __name__ == "__main__":
    unittest.main()
