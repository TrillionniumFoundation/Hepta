"""Physical source controls for the hosted Bootstrap observer and its VM."""
from __future__ import annotations

import ast
from hashlib import sha256
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tests import hia_service_bootstrap_support as support


class BootstrapObserverSourceCustodyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hia-bootstrap-source-custody-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "tools").mkdir()
        (self.root / "hepta").mkdir()
        self.runtime = self.root / "hepta/hia_program_runtime.py"
        self.prepared = self.root / "hepta/hia_program_runtime_prepared.py"
        self.runtime.write_bytes(b"VM_VALUE = 1\n")
        self.prepared.write_bytes(b"PREPARED_VALUE = 2\n")
        self.names = ("tools/build_hia_service_bootstrap.py",
                      "hepta/hia_program_runtime.py", "hepta/hia_program_runtime_prepared.py")
        self.builder = self.root / self.names[0]
        self.builder.write_text("INPUTS = " + repr(self.names) + "\n")

    def snapshot(self):
        with patch.object(support, "ROOT", self.root):
            return support.source_snapshot()

    def source_bytes(self, name):
        with patch.object(support, "ROOT", self.root):
            return support._source_bytes(name)

    def test_actual_runtime_and_observed_direct_dependencies_are_declared(self):
        raw = (support.ROOT / "tools/build_hia_service_bootstrap.py").read_bytes()
        tree = ast.parse(raw)
        declaration = next(node for node in tree.body if isinstance(node, ast.Assign)
                           and any(isinstance(target, ast.Name) and target.id == "INPUTS"
                                   for target in node.targets))
        names = ast.literal_eval(declaration.value)
        required = {"hepta/hia_program_runtime.py", "hepta/hia_program_runtime_prepared.py",
                    "hepta/hia_bounded_memory.py", "hepta/hia_bounded_memory_native.py",
                    "hepta/hia_execution_ledger_native.py", "hepta/hia_scalar_reference_native.py",
                    "hepta/hia_opcodes.py", "hepta/hia_json_decode.py",
                    "hepta/hia_default_native.py", "hepta/hia_default_native_pin.py"}
        self.assertTrue(required.issubset(names))
        self.assertEqual(len(names), len(set(names)))
        self.assertIn("tests/test_hia_bootstrap_observer_source_custody.py", names)

    def test_snapshot_preserves_complete_bytes_sha_shape(self):
        expected = {name: {"bytes": len((self.root / name).read_bytes()),
                           "sha256": sha256((self.root / name).read_bytes()).hexdigest()}
                    for name in self.names}
        self.assertEqual(self.snapshot(), expected)
        with patch.object(support, "ROOT", self.root):
            support.assert_snapshot(expected)

    def test_both_runtime_same_length_changes_are_rejected(self):
        before = self.snapshot()
        for path in (self.runtime, self.prepared):
            original = path.read_bytes()
            with self.subTest(path=path.name):
                changed = original[:-2] + b"9\n"
                self.assertEqual(len(changed), len(original))
                path.write_bytes(changed)
                with patch.object(support, "ROOT", self.root):
                    with self.assertRaises(ValueError):
                        support.assert_snapshot(before)
                path.write_bytes(original)
                self.assertEqual(self.snapshot(), before)

    def test_same_bytes_symlink_is_rejected(self):
        target = self.root / "same-bytes.py"
        target.write_bytes(self.runtime.read_bytes())
        self.runtime.unlink()
        self.runtime.symlink_to(target)
        with self.assertRaises(ValueError):
            self.snapshot()

    def test_same_bytes_hardlink_is_rejected(self):
        target = self.root / "same-bytes.py"
        target.write_bytes(self.runtime.read_bytes())
        self.runtime.unlink()
        os.link(target, self.runtime)
        with self.assertRaises(ValueError):
            self.snapshot()

    def test_symlink_directory_is_rejected(self):
        physical = self.root / "physical-hepta"
        (self.root / "hepta").rename(physical)
        (self.root / "hepta").symlink_to(physical, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.snapshot()

    def test_symlink_root_is_rejected(self):
        alias = self.root / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        with patch.object(support, "ROOT", alias):
            with self.assertRaises(ValueError):
                support.source_snapshot()

    def test_same_bytes_file_replacement_during_read_is_rejected(self):
        original_read = os.read
        replacement = self.root / "replacement.py"
        replacement.write_bytes(self.runtime.read_bytes())
        replaced = False
        def read(descriptor, count):
            nonlocal replaced
            value = original_read(descriptor, count)
            if not replaced:
                replaced = True
                os.replace(replacement, self.runtime)
            return value
        with patch.object(support.os, "read", side_effect=read):
            with self.assertRaises(ValueError):
                self.source_bytes("hepta/hia_program_runtime.py")
        self.assertTrue(replaced)

    def test_parent_directory_replacement_during_read_is_rejected(self):
        original_read = os.read
        runtime, prepared = self.runtime.read_bytes(), self.prepared.read_bytes()
        replaced = False
        def read(descriptor, count):
            nonlocal replaced
            value = original_read(descriptor, count)
            if not replaced:
                replaced = True
                (self.root / "hepta").rename(self.root / "old-hepta")
                (self.root / "hepta").mkdir()
                self.runtime.write_bytes(runtime)
                self.prepared.write_bytes(prepared)
            return value
        with patch.object(support.os, "read", side_effect=read):
            with self.assertRaises(ValueError):
                self.source_bytes("hepta/hia_program_runtime.py")
        self.assertTrue(replaced)

    def test_same_length_in_place_change_with_restored_mtime_is_rejected(self):
        original_read = os.read
        before = self.runtime.stat()
        changed = False
        def read(descriptor, count):
            nonlocal changed
            value = original_read(descriptor, count)
            if not changed:
                changed = True
                self.runtime.write_bytes(b"VM_VALUE = 9\n")
                os.utime(self.runtime, ns=(before.st_atime_ns, before.st_mtime_ns))
            return value
        with patch.object(support.os, "read", side_effect=read):
            with self.assertRaises(ValueError):
                self.source_bytes("hepta/hia_program_runtime.py")
        self.assertTrue(changed)

    def test_nonregular_input_is_rejected_without_blocking(self):
        self.runtime.unlink()
        os.mkfifo(self.runtime)
        with self.assertRaises(ValueError):
            self.snapshot()

    def test_absolute_parent_and_normalized_alias_names_are_rejected(self):
        for name in (str(self.runtime), "../outside.py", "hepta/../hepta/hia_program_runtime.py",
                     "hepta//hia_program_runtime.py", "./hepta/hia_program_runtime.py", ""):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    self.source_bytes(name)

    def test_duplicate_source_declaration_is_rejected(self):
        self.builder.write_text("INPUTS = " + repr(self.names + (self.names[1],)) + "\n")
        with self.assertRaises(ValueError):
            self.snapshot()


if __name__ == "__main__":
    unittest.main()
