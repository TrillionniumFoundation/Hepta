"""P5 qualification must retain failures and cannot replace another run."""
from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from tools.qualify_c_ring_buffer import main, qualify


class CRingQualificationEvidenceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="hepta-ring-report-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def test_existing_report_never_runs_tools_or_changes_success_failure_or_non_json(self):
        for index, original in enumerate((b'{"ok":true,"prior":1}\n',
                                          b'{"ok":false,"error":"previous failure"}\n',
                                          b"partial prior evidence")):
            path = self.root / f"run-{index}.json"
            path.write_bytes(original)
            with self.subTest(index=index), patch("tools.qualify_c_ring_buffer._qualify", side_effect=AssertionError("paid tools launched")):
                with self.assertRaises(FileExistsError):
                    qualify(clang="must-not-run", rustc="must-not-run", output=path)
            self.assertEqual(path.read_bytes(), original)
            self.assertFalse(path.with_name(path.name + ".generated").exists())

    def test_existing_symlink_and_fifo_are_rejected_before_work(self):
        target = self.root / "target"
        target.write_text("preserve")
        link = self.root / "link"
        link.symlink_to(target)
        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        for path in (link, fifo):
            with self.subTest(path=path), patch("tools.qualify_c_ring_buffer._qualify", side_effect=AssertionError("paid tools launched")):
                with self.assertRaises(FileExistsError):
                    qualify(clang="unused", rustc="unused", output=path)
        self.assertEqual(target.read_text(), "preserve")

    def test_failed_and_interrupted_runs_keep_partial_evidence_and_actual_automatic_cost(self):
        for index, error in enumerate((RuntimeError("actual stage rejected"), KeyboardInterrupt())):
            path = self.root / f"failure-{index}.json"

            def fail(**kwargs):
                kwargs["report"].update(stage="actual_stage", completed_observations=[1, 2, 3])
                raise error

            with patch("tools.qualify_c_ring_buffer._qualify", side_effect=fail), self.assertRaises(type(error)):
                qualify(clang="unused", rustc="unused", output=path)
            report = json.loads(path.read_text())
            self.assertFalse(report["ok"])
            self.assertEqual(report["stage"], "failed")
            self.assertEqual(report["failed_stage"], "actual_stage")
            self.assertEqual(report["completed_observations"], [1, 2, 3])
            self.assertGreaterEqual(report["cost"]["elapsed_seconds"], 0)
            self.assertEqual(report["cost"]["automatic_tool_stages"][0]["stage"], "actual_stage")
            self.assertIsNone(report["cost"]["manual_contract_authoring_hours"])
            self.assertIsNone(report["cost"]["manual_review_hours"])
            self.assertIsNone(report["cost"]["maintenance_hours"])

    def test_previous_generated_artifacts_are_not_reused_or_replaced(self):
        path = self.root / "new-report.json"
        retained = path.with_name(path.name + ".generated")
        retained.mkdir()
        source = retained / "source.hepta"
        source.write_text("previous complete generated source")
        with patch("tools.qualify_c_ring_buffer._qualify", side_effect=AssertionError("paid tools launched")), self.assertRaises(FileExistsError):
            qualify(clang="unused", rustc="unused", output=path)
        self.assertEqual(source.read_text(), "previous complete generated source")
        self.assertFalse(json.loads(path.read_text())["ok"])

    def test_main_error_handler_does_not_overwrite_a_replacement_report(self):
        path = self.root / "run.json"
        replacement = b'{"ok":true,"belongs_to":"another writer"}\n'

        def replace_and_fail(**kwargs):
            path.unlink()
            path.write_bytes(replacement)
            raise RuntimeError("stage failed after pathname replacement")

        with patch("tools.qualify_c_ring_buffer._qualify", side_effect=replace_and_fail), \
                patch("sys.argv", ["qualify_c_ring_buffer.py", "--output", str(path)]), \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(), 1)
        self.assertEqual(path.read_bytes(), replacement)

    def test_actual_process_failure_keeps_raw_streams_and_complete_inventory(self):
        path = self.root / "process-failure.json"

        def observed(**kwargs):
            evidence = kwargs["output"]
            kwargs["report"]["stage"] = "native_process"
            evidence.command([sys.executable, "-c", "print('ready')"], role="test.positive")
            evidence.command([sys.executable, "-c",
                "import sys;sys.stdout.buffer.write(bytes([0,255])+b'partial\\n');"
                "sys.stderr.write('actual failure\\n');sys.exit(17)"], role="test.negative")

        with patch("tools.qualify_c_ring_buffer._qualify", side_effect=observed), self.assertRaises(RuntimeError):
            qualify(clang="unused", rustc="unused", output=path)
        report = json.loads(path.read_text())
        evidence = report["evidence"]
        self.assertEqual(evidence["schema"], "hepta.c-ring-retained-evidence.v2")
        rows = [json.loads(line) for line in (self.root / evidence["processes"]["path"]).read_text().splitlines()]
        self.assertEqual([row["returncode"] for row in rows], [0, 17])
        self.assertEqual((self.root / rows[0]["stdout"]["path"]).read_bytes(), b"ready\n")
        self.assertEqual((self.root / rows[1]["stdout"]["path"]).read_bytes(), b"\x00\xffpartial\n")
        self.assertEqual((self.root / rows[1]["stderr"]["path"]).read_bytes(), b"actual failure\n")
        self.assertEqual(rows[1]["role"], "test.negative")
        self.assertEqual(rows[1]["argv"][0], sys.executable)
        self.assertEqual(evidence["processes"]["rows"], 2)
        self.assertEqual(set(evidence["artifacts"]), {
            p.relative_to(self.root).as_posix() for p in path.with_name(path.name + ".generated").rglob("*") if p.is_file()})

    def test_backend_observer_restores_module_after_actual_process_and_exception(self):
        import hepta.backend as backend
        original_backend, original_run = backend.subprocess, subprocess.run
        path = self.root / "backend-failure.json"

        def observed(**kwargs):
            with kwargs["output"].backend_processes("test.backend"):
                self.assertIs(subprocess.run, original_run)
                process = backend.subprocess.run([sys.executable, "-c", "print('observed once')"],
                                                  capture_output=True, text=True, timeout=5)
                self.assertEqual(process.returncode, 0)
                self.assertEqual(process.stdout, "observed once\n")
                raise RuntimeError("after observed process")

        with patch("tools.qualify_c_ring_buffer._qualify", side_effect=observed), self.assertRaises(RuntimeError):
            qualify(clang="unused", rustc="unused", output=path)
        self.assertIs(backend.subprocess, original_backend)
        self.assertIs(subprocess.run, original_run)
        report = json.loads(path.read_text())
        stream = self.root / report["evidence"]["processes"]["path"]
        rows = [json.loads(line) for line in stream.read_text().splitlines()]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["returncode"], 0)
        self.assertEqual(rows[0]["stdout"]["representation"], "decoded_text_utf8")


if __name__ == "__main__":
    unittest.main()
