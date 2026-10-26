"""Real Linux filesystem tests; external compilers are not needed."""
import os
from pathlib import Path
import tempfile
import sys
import unittest
from unittest.mock import patch

from hepta.hia_bundle_atomic import (AtomicBundleRejected, AtomicBundleUncertain,
                                     publish_hia_bundle)


@unittest.skipUnless(sys.platform == "linux", "renameat2 Linux-only qualification")
class AtomicBundleTests(unittest.TestCase):
    def setUp(self):
        self.context = tempfile.TemporaryDirectory(prefix="hia-atomic-test-")
        self.addCleanup(self.context.cleanup)
        self.root = Path(self.context.name)
        self.stage = self.root / ".candidate-staged"
        self.stage.mkdir()
        self.dest = self.root / "bundle"
        self.data = {"candidate.hepta": b"export C - checked source\n",
                     "candidate.so": b"actual staged native bytes\0",
                     "migration-hia.json": b'{"ok":true}\n'}
        for name, value in self.data.items():
            (self.stage / name).write_bytes(value)

    def publish(self, source_guard=lambda: True):
        return publish_hia_bundle(self.stage, self.dest, self.data, source_guard)

    def test_real_atomic_commit_directory_and_exact_bytes(self):
        result = self.publish()
        self.assertEqual(result["method"], "linux_renameat2_noreplace_fsync_v1")
        self.assertTrue(result["parent_directory_fsynced"])
        self.assertFalse(self.stage.exists())
        self.assertEqual({p.name for p in self.dest.iterdir()}, set(self.data))
        self.assertEqual({n:(self.dest/n).read_bytes() for n in self.data},self.data)

    def test_existing_empty_directory_and_symlink_never_replaced(self):
        for form in ("directory", "symlink"):
            with self.subTest(form=form):
                if form == "directory":
                    self.dest.mkdir()
                else:
                    self.dest.symlink_to(self.stage, target_is_directory=True)
                with self.assertRaises(AtomicBundleRejected):
                    self.publish()
                self.assertTrue(self.stage.exists())
                if form == "directory":
                    self.assertEqual(list(self.dest.iterdir()), [])
                    self.dest.rmdir()
                else:
                    self.assertTrue(self.dest.is_symlink())
                    self.dest.unlink()

    def test_source_changes_before_rename_never_publish(self):
        with self.assertRaises(AtomicBundleRejected):
            self.publish(lambda: False)
        self.assertFalse(self.dest.exists())
        self.assertTrue(self.stage.exists())

    def test_tampered_bytes_and_unreviewed_extra_file_never_publish(self):
        (self.stage / "candidate.so").write_bytes(b"bad")
        with self.assertRaises(AtomicBundleRejected):
            self.publish()
        self.assertFalse(self.dest.exists())
        (self.stage / "candidate.so").write_bytes(self.data["candidate.so"])
        (self.stage / "hidden").write_text("unreviewed")
        with self.assertRaises(AtomicBundleRejected):
            self.publish()
        self.assertFalse(self.dest.exists())

    def test_staged_symlink_never_publishes(self):
        (self.stage / "candidate.so").unlink()
        (self.stage / "candidate.so").symlink_to("candidate.hepta")
        with self.assertRaises(AtomicBundleRejected):
            self.publish()
        self.assertFalse(self.dest.exists())

    def test_parent_fsync_failure_preserves_visible_bundle_for_recovery(self):
        real_fsync = os.fsync
        def fault(fd):
            if os.fstat(fd).st_ino == self.root.stat().st_ino:
                raise OSError("injected parent durability failure")
            return real_fsync(fd)
        with patch("hepta.hia_bundle_atomic.os.fsync", side_effect=fault):
            with self.assertRaises(AtomicBundleUncertain):
                self.publish()
        self.assertFalse(self.stage.exists())
        self.assertTrue(self.dest.is_dir())
        self.assertEqual((self.dest / "candidate.so").read_bytes(),self.data["candidate.so"])

    def test_source_changed_after_atomic_rename_is_uncertain_not_false_rejected(self):
        calls = 0
        def guard():
            nonlocal calls
            calls += 1
            return calls == 1
        with self.assertRaises(AtomicBundleUncertain):
            self.publish(guard)
        self.assertTrue(self.dest.is_dir())
        self.assertFalse(self.stage.exists())

    def test_actual_process_death_after_atomic_rename_shows_complete_bundle(self):
        # Real fork/process death at the kernel rename linearization point.
        child = os.fork()
        if child == 0:
            from hepta import hia_bundle_atomic
            original = hia_bundle_atomic._rename_noreplace
            def die_after_rename(fd, old, new):
                original(fd, old, new)
                os._exit(86)
            hia_bundle_atomic._rename_noreplace = die_after_rename
            self.publish()
            os._exit(90)  # unexpected: the hook was not called
        waited, status = os.waitpid(child, 0)
        self.assertEqual(waited, child)
        self.assertTrue(os.WIFEXITED(status))
        self.assertEqual(os.WEXITSTATUS(status), 86)
        self.assertFalse(self.stage.exists())
        self.assertEqual({name: (self.dest/name).read_bytes() for name in self.data}, self.data)

    def test_temporary_stage_cleanup_does_not_remove_published_directory(self):
        with tempfile.TemporaryDirectory(prefix=".hia-l1-", dir=self.root) as directory:
            stage = Path(directory)
            for name, value in self.data.items():
                (stage/name).write_bytes(value)
            published = publish_hia_bundle(stage, self.dest, self.data, lambda: True)
            self.assertTrue(published["atomic_directory_visible"])
        self.assertTrue(self.dest.is_dir())
        self.assertEqual((self.dest/"migration-hia.json").read_bytes(), self.data["migration-hia.json"])

    def test_filesystem_name_race_rejected_with_no_overwrite(self):
        from hepta import hia_bundle_atomic
        original = hia_bundle_atomic._rename_noreplace
        def race(fd, old, new):
            self.dest.mkdir()
            return original(fd,old,new)
        with patch("hepta.hia_bundle_atomic._rename_noreplace", side_effect=race):
            with self.assertRaises(AtomicBundleRejected):
                self.publish()
        self.assertTrue(self.stage.exists())
        self.assertEqual(list(self.dest.iterdir()), [])

if __name__ == "__main__":
    unittest.main()
