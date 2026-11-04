"""Workspace inventories must not silently omit failed directory scans."""
from contextlib import contextmanager
import errno
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from hepta import workspace

RUSTC = os.environ.get("RUSTC") or shutil.which("rustc")


@contextmanager
def failed_scan(target, error_type=PermissionError, number=errno.EACCES):
    original = os.scandir
    observed = []

    def scan(path):
        if not isinstance(path, int) and Path(path) == target:
            observed.append(str(path))
            raise error_type(number, "controlled directory scan failure", str(path))
        return original(path)

    with patch.object(workspace.os, "scandir", side_effect=scan):
        yield observed


@contextmanager
def failed_durability_scan():
    original_write, original_scan = workspace._write, os.scandir
    armed = False
    observed = []

    def write(path, data):
        nonlocal armed
        original_write(path, data)
        if path.name == "snapshot.json" and path.parent.name.startswith(".prepare-"):
            armed = True

    def scan(path):
        nonlocal armed
        if armed and not isinstance(path, int) and Path(path).name == "tree":
            armed = False  # Cleanup must retain its ordinary filesystem access.
            observed.append(str(path))
            raise PermissionError(errno.EACCES, "controlled durability scan failure", str(path))
        return original_scan(path)

    with patch.object(workspace, "_write", side_effect=write), \
            patch.object(workspace.os, "scandir", side_effect=scan):
        yield observed


class _WorkspaceFixture:
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hepta-enumeration-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "source"
        self.root.mkdir()
        self.store = Path(self.temp.name) / "store"
        (self.root / "main.hepta").write_text("fn main()->i32 effects {} { return 0; }\n")
        self.nested = self.root / "notes" / "deep"
        self.nested.mkdir(parents=True)
        (self.nested / "important.bin").write_bytes(b"\x00\xffcomplete bundle\r\n")

    def assert_scan_error(self, target, operation, **fault):
        with failed_scan(target, **fault) as observed:
            with self.assertRaises(workspace.WorkspaceError) as caught:
                operation()
        self.assertEqual(caught.exception.code, "E_WORKSPACE_IO")
        self.assertIn(str(target), str(caught.exception))
        self.assertIn("controlled directory scan failure", str(caught.exception))
        self.assertIsInstance(caught.exception.__cause__, OSError)
        self.assertEqual(observed, [str(target)])


class WorkspaceEnumerationTests(_WorkspaceFixture, unittest.TestCase):
    def test_root_scan_failure_is_not_an_empty_inventory(self):
        self.assert_scan_error(self.root, lambda: workspace._files(self.root))

    def test_nested_scan_failure_is_not_a_partial_inventory(self):
        self.assert_scan_error(self.nested, lambda: workspace._files(self.root))

    def test_other_enumeration_errors_are_not_suppressed(self):
        self.assert_scan_error(self.nested, lambda: workspace._files(self.root),
                               error_type=OSError, number=errno.EIO)

    def test_disappeared_root_is_rejected(self):
        missing = self.root / "missing"
        with self.assertRaises(workspace.WorkspaceError) as caught:
            workspace._files(missing)
        self.assertEqual(caught.exception.code, "E_WORKSPACE_IO")
        self.assertIsInstance(caught.exception.__cause__, FileNotFoundError)

    def test_real_os_permission_failure_is_not_suppressed(self):
        self.nested.chmod(0)
        try:
            # Fail the test, rather than silently skip the real OS control, if
            # this host runs with privileges that override the fixture mode.
            with self.assertRaises(PermissionError):
                list(self.nested.iterdir())
            with self.assertRaises(workspace.WorkspaceError) as caught:
                workspace._files(self.root)
            self.assertEqual(caught.exception.code, "E_WORKSPACE_IO")
            self.assertEqual(caught.exception.__cause__.errno, errno.EACCES)
        finally:
            self.nested.chmod(0o700)

    def test_real_unreadable_root_is_rejected(self):
        self.root.chmod(0)
        try:
            with self.assertRaises(PermissionError):
                list(self.root.iterdir())
            with self.assertRaises(workspace.WorkspaceError) as caught:
                workspace._files(self.root)
            self.assertEqual(caught.exception.code, "E_WORKSPACE_IO")
        finally:
            self.root.chmod(0o700)

    def test_initial_capture_failure_precedes_staging_and_publication(self):
        with patch.object(workspace, "_stage", side_effect=AssertionError("staging must not begin")) as stage:
            self.assert_scan_error(self.nested, lambda: workspace.initialize(
                self.store, self.root, "main.hepta"))
        stage.assert_not_called()
        self.assertFalse((self.store / "CURRENT").exists())
        self.assertFalse((self.store / "versions").exists())

    def test_final_capture_scan_failure_precedes_current_publication(self):
        # This is a sequencing control, not native compilation evidence.
        original = os.scandir
        source_reads = 0

        def scan(path):
            nonlocal source_reads
            if not isinstance(path, int) and Path(path) == self.root:
                source_reads += 1
                if source_reads == 2:
                    raise PermissionError(errno.EACCES, "final capture failed", str(path))
            return original(path)

        with patch.object(workspace, "_stage", return_value=("a" * 64, {})), \
                patch.object(workspace.os, "scandir", side_effect=scan):
            with self.assertRaises(workspace.WorkspaceError) as caught:
                workspace.initialize(self.store, self.root, "main.hepta")
        self.assertEqual(caught.exception.code, "E_WORKSPACE_IO")
        self.assertEqual(source_reads, 2)
        self.assertFalse((self.store / "CURRENT").exists())

    def test_ordinary_inventory_bytes_and_order_are_unchanged(self):
        (self.root / "empty").mkdir()
        (self.root / "a.txt").write_bytes(b"a\n")
        expected = {"a.txt": b"a\n", "main.hepta": (self.root / "main.hepta").read_bytes(),
                    "notes/deep/important.bin": b"\x00\xffcomplete bundle\r\n"}
        self.assertEqual(workspace._files(self.root), expected)
        self.assertEqual(list(workspace._files(self.root)), list(expected))

    def test_existing_exclusions_are_pruned_before_directory_scans(self):
        for name in (".git", "__pycache__"):
            directory = self.root / name
            directory.mkdir()
            (directory / "excluded").write_bytes(b"ignored")
            with failed_scan(directory) as observed:
                files = workspace._files(self.root)
            self.assertEqual(observed, [])
            self.assertFalse(any(p.startswith(name + "/") for p in files))

    def test_directory_and_file_symlinks_remain_rejected(self):
        for target in (self.nested, self.nested / "important.bin"):
            alias = self.root / "alias"
            alias.symlink_to(target, target_is_directory=target.is_dir())
            try:
                with self.assertRaises(workspace.WorkspaceError) as caught:
                    workspace._files(self.root)
                self.assertEqual(caught.exception.code, "E_WORKSPACE_SYMLINK")
            finally:
                alias.unlink()

    def test_file_and_byte_limits_remain_enforced(self):
        for limit, value in (("MAX_FILES", 1), ("MAX_BYTES", 1)):
            with self.subTest(limit=limit), patch.object(workspace, limit, value):
                with self.assertRaises(workspace.WorkspaceError) as caught:
                    workspace._files(self.root)
                self.assertEqual(caught.exception.code, "E_WORKSPACE_LIMIT")


@unittest.skipUnless(RUSTC and Path(RUSTC).is_file(), "real pinned Rust required")
class WorkspaceEnumerationNativeTests(_WorkspaceFixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        result = workspace.initialize(self.store, self.root, "main.hepta", rustc=RUSTC)
        self.assertTrue(result["ok"], result)
        self.before = workspace.pin(self.store)

    def request(self):
        view = workspace.inspect_workspace(self.store)
        node = next(n for n in view["nodes"]["main.hepta"] if n["kind"] == "body")
        return {"schema": workspace.PATCH_SCHEMA, "expected_version": self.before["version"],
                "expected_interface_sha256": self.before["manifest"]["interface_sha256"],
                "interface_policy": "preserve", "edits": [{"op": "replace_body", "target": "main.hepta",
                    "node": node["id"], "replacement": "{ return 1; }"}]}

    def test_native_snapshot_retains_complete_regular_bundle(self):
        self.assertEqual(self.before["manifest"]["files"], {
            p: workspace.digest(b) for p, b in sorted(workspace._files(self.root).items())})
        self.assertEqual((Path(self.before["root"]) / "notes/deep/important.bin").read_bytes(),
                         b"\x00\xffcomplete bundle\r\n")

    def test_native_initialization_refuses_unreadable_source_without_current(self):
        destination = self.store.with_name("refused-store")
        self.nested.chmod(0)
        try:
            with self.assertRaises(workspace.WorkspaceError) as caught:
                workspace.initialize(destination, self.root, "main.hepta", rustc=RUSTC)
            self.assertEqual(caught.exception.code, "E_WORKSPACE_IO")
            self.assertFalse((destination / "CURRENT").exists())
        finally:
            self.nested.chmod(0o700)

    def test_native_pin_refuses_unreadable_added_subtree(self):
        directory = Path(self.before["root"]) / "added"
        directory.mkdir()
        (directory / "unrecorded.txt").write_bytes(b"new bytes outside the recorded inventory")
        directory.chmod(0)
        try:
            with self.assertRaises(workspace.WorkspaceError) as caught:
                workspace.pin(self.store)
            self.assertEqual(caught.exception.code, "E_WORKSPACE_IO")
        finally:
            directory.chmod(0o700)

    def test_native_patch_durability_scan_failure_preserves_current_and_cleans_stage(self):
        request = self.request()
        before_current = (self.store / "CURRENT").read_bytes()
        before_versions = sorted(p.name for p in (self.store / "versions").iterdir())
        with failed_durability_scan() as observed:
            report = workspace.apply_workspace_patch(self.store, request, apply=True, rustc=RUSTC)
        self.assertEqual(len(observed), 1)
        self.assertFalse(report["ok"], report)
        self.assertFalse(report["applied"], report)
        self.assertEqual(report["diagnostics"][0]["code"], "E_WORKSPACE_IO")
        self.assertEqual((self.store / "CURRENT").read_bytes(), before_current)
        self.assertEqual(sorted(p.name for p in (self.store / "versions").iterdir()), before_versions)
        self.assertEqual(list(self.store.glob(".prepare-*")), [])
        self.assertEqual(workspace.pin(self.store)["version"], self.before["version"])
        retry = workspace.apply_workspace_patch(self.store, request, apply=True, rustc=RUSTC)
        self.assertTrue(retry["ok"], retry)
        self.assertTrue(retry["applied"], retry)


if __name__ == "__main__":
    unittest.main()
