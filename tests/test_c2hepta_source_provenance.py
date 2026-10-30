"""Bind strict scalar migration receipts to the admitted source pathname.

These controls call the real Clang capture path. Race hooks only change the
filesystem before a real bounded read; they do not replace compiler output.
They cover selected alias/leaf replacements, not arbitrary ancestor races.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

from tools import c2hepta


@unittest.skipUnless(os.name == "posix" and hasattr(os, "symlink"),
                     "POSIX source-alias controls")
@unittest.skipUnless(shutil.which("clang"), "real Clang is required")
class CSourceProvenance(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="hepta-c-source-provenance-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.original_dir = self.root / "original"
        self.decoy_dir = self.root / "decoy"
        self.original_dir.mkdir()
        self.decoy_dir.mkdir()
        self.source = self.original_dir / "source.c"
        self.decoy = self.decoy_dir / "source.c"
        self.original_bytes = b"int actual(int x) { return x; }\n"
        self.decoy_bytes = b"int unrelated(int x) { return x + 1; }\n"
        self.source.write_bytes(self.original_bytes)
        self.decoy.write_bytes(self.decoy_bytes)
        self.alias = self.root / "selected"
        self.alias.symlink_to(self.original_dir, target_is_directory=True)
        self.requested_source = self.alias / "source.c"
        self.output = self.root / "output.hepta"
        self.report = self.root / "evidence.json"

    def _rebind_parent(self):
        self.alias.unlink()
        self.alias.symlink_to(self.decoy_dir, target_is_directory=True)

    def _capture_ast_input(self, observed):
        real_capture = c2hepta._run_bounded_ast

        def capture(args, **kwargs):
            if kwargs.get("input_text") is not None:
                observed.append(kwargs["input_text"].encode("utf-8"))
            return real_capture(args, **kwargs)

        return capture

    def _assert_original_conversion(self, result, observed):
        self.assertEqual(result["status"], "converted", result)
        self.assertEqual(observed, [self.original_bytes])
        self.assertEqual(result["source"], str(self.source))
        digest = hashlib.sha256(self.original_bytes).hexdigest()
        self.assertEqual(result["source_sha256"], digest)
        self.assertEqual(result["clang_input"], {
            "transport": "captured_source_stdin", "sha256": digest,
            "bytes": len(self.original_bytes),
        })
        self.assertEqual([f["name"] for f in result["functions"]], ["actual"])
        self.assertIn("fn actual(", self.output.read_text(encoding="utf-8"))
        self.assertEqual(json.loads(self.report.read_text(encoding="utf-8")),
                         json.loads(json.dumps(result)))

    def test_regular_source_and_stable_parent_alias_still_convert(self):
        for requested in (self.source, self.requested_source):
            with self.subTest(requested=str(requested)):
                observed = []
                with mock.patch.object(c2hepta, "_run_bounded_ast",
                                       side_effect=self._capture_ast_input(observed)):
                    result = c2hepta.migrate(requested, self.output, self.report)
                self._assert_original_conversion(result, observed)

    def test_parent_rebind_before_first_read_keeps_admitted_source(self):
        real_read = c2hepta._read_bounded_source
        reads = 0
        observed = []

        def rebind_then_read(path):
            nonlocal reads
            reads += 1
            if reads == 1:
                # Admission has already resolved the requested alias to A.
                # Leave the caller alias pointing at B through the recheck.
                self._rebind_parent()
            return real_read(path)

        with (mock.patch.object(c2hepta, "_read_bounded_source",
                                side_effect=rebind_then_read),
              mock.patch.object(c2hepta, "_run_bounded_ast",
                                side_effect=self._capture_ast_input(observed))):
            result = c2hepta.migrate(self.requested_source, self.output, self.report)

        self.assertEqual(reads, 2)
        self.assertEqual(self.requested_source.resolve(), self.decoy)
        self._assert_original_conversion(result, observed)

    def test_parent_rebind_cannot_hide_admitted_source_change_at_recheck(self):
        # B contains the originally admitted bytes. Rebinding to B must not
        # conceal a persistent change to the admitted physical pathname A.
        self.decoy.write_bytes(self.original_bytes)
        self.output.write_text("previous output\n", encoding="utf-8")
        real_read = c2hepta._read_bounded_source
        reads = 0
        observed = []

        def change_then_read(path):
            nonlocal reads
            reads += 1
            if reads == 2:
                self.source.write_bytes(self.decoy_bytes)
                self._rebind_parent()
            return real_read(path)

        with (mock.patch.object(c2hepta, "_read_bounded_source",
                                side_effect=change_then_read),
              mock.patch.object(c2hepta, "_run_bounded_ast",
                                side_effect=self._capture_ast_input(observed))):
            result = c2hepta.migrate(self.requested_source, self.output, self.report)

        self.assertEqual(reads, 2)
        self.assertEqual(observed, [self.original_bytes])
        self.assertEqual(result["status"], "rejected", result)
        self.assertIn("source changed during conversion", result["reason"])
        self.assertEqual(result["source"], str(self.source))
        self.assertEqual(self.output.read_text(encoding="utf-8"), "previous output\n")
        self.assertEqual(json.loads(self.report.read_text(encoding="utf-8")),
                         json.loads(json.dumps(result)))

    def test_direct_source_symlink_is_rejected_before_compiler(self):
        leaf_alias = self.root / "alias.c"
        leaf_alias.symlink_to(self.source)
        self.output.write_text("previous output\n", encoding="utf-8")
        with mock.patch.object(c2hepta, "_run_bounded_ast",
                               wraps=c2hepta._run_bounded_ast) as compiler:
            result = c2hepta.migrate(leaf_alias, self.output, self.report)
        self.assertEqual(result["status"], "rejected", result)
        self.assertIn("symlink", result["reason"])
        self.assertIsNone(result["source_sha256"])
        compiler.assert_not_called()
        self.assertEqual(self.output.read_text(encoding="utf-8"), "previous output\n")
        self.assertEqual(json.loads(self.report.read_text(encoding="utf-8")),
                         json.loads(json.dumps(result)))

    @unittest.skipUnless(hasattr(os, "O_NOFOLLOW"), "terminal symlink open guard")
    def test_leaf_swap_before_initial_open_is_rejected(self):
        real_read = c2hepta._read_bounded_source
        reads = 0
        self.output.write_text("previous output\n", encoding="utf-8")

        def swap_then_read(path):
            nonlocal reads
            reads += 1
            if reads == 1:
                # Swap after the direct-symlink precheck. The actual open
                # must refuse a leaf symlink rather than following it.
                self.source.unlink()
                self.source.symlink_to(self.decoy)
            return real_read(path)

        with (mock.patch.object(c2hepta, "_read_bounded_source",
                                side_effect=swap_then_read),
              mock.patch.object(c2hepta, "_run_bounded_ast",
                                wraps=c2hepta._run_bounded_ast) as compiler):
            result = c2hepta.migrate(self.source, self.output, self.report)

        self.assertEqual(result["status"], "rejected", result)
        self.assertIsNone(result["source_sha256"])
        compiler.assert_not_called()
        self.assertEqual(self.output.read_text(encoding="utf-8"), "previous output\n")
        self.assertEqual(json.loads(self.report.read_text(encoding="utf-8")),
                         json.loads(json.dumps(result)))

    @unittest.skipUnless(hasattr(os, "O_NOFOLLOW"), "terminal symlink open guard")
    def test_leaf_swap_before_recheck_is_rejected_even_for_equal_bytes(self):
        self.decoy.write_bytes(self.original_bytes)
        self.output.write_text("previous output\n", encoding="utf-8")
        real_read = c2hepta._read_bounded_source
        reads = 0
        observed = []

        def swap_then_read(path):
            nonlocal reads
            reads += 1
            if reads == 2:
                self.source.unlink()
                self.source.symlink_to(self.decoy)
            return real_read(path)

        with (mock.patch.object(c2hepta, "_read_bounded_source",
                                side_effect=swap_then_read),
              mock.patch.object(c2hepta, "_run_bounded_ast",
                                side_effect=self._capture_ast_input(observed))):
            result = c2hepta.migrate(self.source, self.output, self.report)

        self.assertEqual(reads, 2)
        self.assertEqual(observed, [self.original_bytes])
        self.assertEqual(result["status"], "rejected", result)
        self.assertEqual(result["source"], str(self.source))
        self.assertEqual(self.output.read_text(encoding="utf-8"), "previous output\n")
        self.assertEqual(json.loads(self.report.read_text(encoding="utf-8")),
                         json.loads(json.dumps(result)))


if __name__ == "__main__":
    unittest.main()
