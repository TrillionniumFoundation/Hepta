"""Actual Linux filesystem atomic publication and adversarial path tests."""
import errno
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hepta.c_project_publish import PublicationRejected, PublicationRecoveryRequired, publish_no_replace


class AtomicPublishTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.stage = root / "stage"
        self.stage.mkdir()
        for name in ("source.hepta", "bridge.rs", "generated.rs", "migration.json"):
            (self.stage / name).write_text(name)
        self.destination = root / "new"

    def test_atomic_full_tree_and_inodes(self):
        inode = self.stage.stat().st_ino
        publish_no_replace(self.stage, self.destination)
        self.assertFalse(self.stage.exists())
        self.assertEqual(self.destination.stat().st_ino, inode)
        self.assertEqual({p.name for p in self.destination.iterdir()},
                         {"source.hepta", "bridge.rs", "generated.rs", "migration.json"})
        for child in self.destination.iterdir():
            self.assertEqual(child.read_text(), child.name)

    def test_existing_path_and_dangling_symlink_are_never_overwritten(self):
        self.destination.mkdir()
        with self.assertRaises(PublicationRejected):
            publish_no_replace(self.stage, self.destination)
        self.assertTrue(self.stage.is_dir())
        self.destination.rmdir()
        self.destination.symlink_to(self.destination.parent / "does-not-exist", target_is_directory=True)
        with self.assertRaises(PublicationRejected):
            publish_no_replace(self.stage, self.destination)
        self.assertTrue(self.destination.is_symlink())
        self.assertTrue(self.stage.is_dir())

    def test_prepublication_failure_exposes_no_partial_dir(self):
        (self.stage / "migration.json").unlink()
        with self.assertRaises(PublicationRejected):
            publish_no_replace(self.stage, self.destination)
        self.assertFalse(self.destination.exists())
        self.assertTrue(self.stage.exists())

    def test_stage_link_rejects_without_publication(self):
        (self.stage / "evil").symlink_to(self.destination.parent / "absent")
        with self.assertRaises(PublicationRejected):
            publish_no_replace(self.stage, self.destination)
        self.assertFalse(self.destination.exists())
        self.assertTrue(self.stage.is_dir())

    def test_staged_directory_not_a_sibling_rejected(self):
        self.destination = self.stage / "nested"
        with self.assertRaises(PublicationRejected):
            publish_no_replace(self.stage, self.destination)
        self.assertTrue(self.stage.exists())

    def test_planted_directory_at_commit_is_not_overwritten(self):
        import hepta.c_project_publish as pub
        original = pub._rename_noreplace
        def plant_then_attempt(parentfd, src, dst):
            self.destination.mkdir()
            return original(parentfd, src, dst)
        with patch.object(pub, "_rename_noreplace", side_effect=plant_then_attempt):
            with self.assertRaises(PublicationRejected):
                publish_no_replace(self.stage, self.destination)
        self.assertTrue(self.stage.is_dir())
        self.assertEqual(list(self.destination.iterdir()), [])

    def test_swap_target_to_symlink_at_commit_is_not_overwritten(self):
        outside = self.destination.parent / "outside"
        outside.mkdir()
        import hepta.c_project_publish as pub
        original = pub._rename_noreplace
        def plant_then_attempt(parentfd, src, dst):
            self.destination.symlink_to(outside, target_is_directory=True)
            return original(parentfd, src, dst)
        with patch.object(pub, "_rename_noreplace", side_effect=plant_then_attempt):
            with self.assertRaises(PublicationRejected):
                publish_no_replace(self.stage, self.destination)
        self.assertTrue(self.destination.is_symlink())
        self.assertFalse((outside / "source.hepta").exists())
        self.assertTrue(self.stage.is_dir())

    def test_directory_identity_swapped_before_commit_fails_closed(self):
        moved = self.destination.parent / "moved"
        import hepta.c_project_publish as pub
        original = pub._same_inode
        swapped = [False]
        def swap_then_compare(left, right):
            if not swapped[0]:
                swapped[0] = True
                self.stage.rename(moved)
                self.stage.mkdir()
                right = os.stat(self.stage)
            return original(left, right)
        with patch.object(pub, "_same_inode", side_effect=swap_then_compare):
            with self.assertRaises(PublicationRejected):
                publish_no_replace(self.stage, self.destination)
        self.assertFalse(self.destination.exists())
        self.assertTrue(moved.is_dir())

    def test_rename_syscall_unavailable_fails_closed(self):
        import hepta.c_project_publish as pub
        with patch.object(pub, "_rename_noreplace", side_effect=PublicationRejected("unsupported")):
            with self.assertRaises(PublicationRejected):
                publish_no_replace(self.stage, self.destination)
        self.assertFalse(self.destination.exists())
        self.assertTrue(self.stage.is_dir())

    def test_post_commit_fsync_failure_is_recovery_required(self):
        import hepta.c_project_publish as pub
        original = os.fsync
        root_ino = self.destination.parent.stat().st_ino
        def crash_on_parent_fsync(fd):
            if os.fstat(fd).st_ino == root_ino:
                raise OSError(errno.EIO, "simulated parent fsync failure")
            return original(fd)
        with patch.object(pub.os, "fsync", side_effect=crash_on_parent_fsync):
            with self.assertRaises(PublicationRecoveryRequired) as captured:
                publish_no_replace(self.stage, self.destination)
        self.assertTrue(captured.exception.publication_may_have_committed)
        self.assertFalse(self.stage.exists())
        self.assertEqual({p.name for p in self.destination.iterdir()},
                         {"source.hepta", "bridge.rs", "generated.rs", "migration.json"})

    def test_destination_invisible_until_atomic_rename(self):
        import hepta.c_project_publish as pub
        real = pub._rename_noreplace
        observed = []
        def observe_before(parentfd, src, dst):
            observed.append(not self.destination.exists() and self.stage.exists())
            observed.append(len(os.listdir(self.stage)) == 4)
            return real(parentfd, src, dst)
        with patch.object(pub, "_rename_noreplace", side_effect=observe_before):
            publish_no_replace(self.stage, self.destination)
        self.assertEqual(observed, [True, True])
        self.assertEqual(len(os.listdir(self.destination)), 4)

    def test_no_direct_source_binary_modification(self):
        before = {p.name: p.read_bytes() for p in self.stage.iterdir()}
        publish_no_replace(self.stage, self.destination)
        after = {p.name: p.read_bytes() for p in self.destination.iterdir()}
        self.assertEqual(before, after)

if __name__ == "__main__":
    unittest.main()
