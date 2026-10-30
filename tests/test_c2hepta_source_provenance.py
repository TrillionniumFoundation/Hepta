"""Adversarial source-provenance checks for the independent strict C oracle.

The observed importer identity must refer to the same physical source path
whose bytes were compiled, even if a parent symlink changes between stages.
These are narrow tests, not filesystem-wide race or native safety proofs.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

from tools import c2hepta


@unittest.skipUnless(os.name == "posix" and hasattr(os, "symlink"),
                     "POSIX directory symlink test")
class CSourceProvenance(unittest.TestCase):
    @unittest.skipUnless(shutil.which("clang"), "Clang is required")
    def test_parent_alias_rebinding_cannot_forge_source_identity(self):
        with tempfile.TemporaryDirectory(prefix="hepta-c-source-provenance-") as temp:
            root = Path(temp)
            original_dir = root / "original"
            decoy_dir = root / "decoy"
            original_dir.mkdir()
            decoy_dir.mkdir()
            original_path = original_dir / "source.c"
            decoy_path = decoy_dir / "source.c"
            original_path.write_text("int actual(int x){return x;}\n", encoding="utf-8")
            decoy_path.write_text("int unrelated(int x){return x + 1;}\n", encoding="utf-8")

            alias = root / "selected"
            alias.symlink_to(original_dir, target_is_directory=True)
            requested_source = alias / "source.c"
            output = root / "output.hepta"
            report = root / "evidence.json"

            original_read = c2hepta._read_source_bounded
            original_ast = c2hepta._run_clang_ast_bounded
            reads = 0

            def read_then_rebind(path):
                nonlocal reads
                value = original_read(path)
                reads += 1
                if reads == 1:
                    # Between first read and receipt assembly, change only
                    # the *caller alias*. The source snapshot stays original.
                    alias.unlink()
                    alias.symlink_to(decoy_dir, target_is_directory=True)
                return value

            def compile_then_restore(command, source):
                # Make the final hash recheck pass even for a vulnerable
                # importer that rereads the mutable caller alias.
                alias.unlink()
                alias.symlink_to(original_dir, target_is_directory=True)
                return original_ast(command, source)

            with (mock.patch.object(c2hepta, "_read_source_bounded",
                                    side_effect=read_then_rebind),
                  mock.patch.object(c2hepta, "_run_clang_ast_bounded",
                                    side_effect=compile_then_restore)):
                result = c2hepta.migrate(requested_source, output, report)

            self.assertEqual(result["status"], "converted", result)
            self.assertEqual([f["name"] for f in result["functions"]], ["actual"])
            self.assertIn("fn actual(", output.read_text(encoding="utf-8"))
            self.assertEqual(
                result["source"], str(original_path.resolve()),
                "receipt attributed original bytes to a rebound decoy path",
            )
            self.assertEqual(
                json.loads(report.read_text(encoding="utf-8"))["source"],
                str(original_path.resolve()),
            )

    @unittest.skipUnless(shutil.which("clang"), "Clang is required")
    def test_direct_source_symlink_remains_rejected(self):
        with tempfile.TemporaryDirectory(prefix="hepta-c-source-symlink-") as temp:
            root = Path(temp)
            actual = root / "real.c"
            actual.write_text("int actual(int x){return x;}\n", encoding="utf-8")
            alias = root / "alias.c"
            alias.symlink_to(actual)
            output = root / "output.hepta"
            report = root / "evidence.json"
            result = c2hepta.migrate(alias, output, report)
            self.assertEqual(result["status"], "rejected", result)
            self.assertFalse(output.exists())
            self.assertEqual(json.loads(report.read_text())["status"], "rejected")


if __name__ == "__main__":
    unittest.main()
