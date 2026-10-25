"""Real filesystem redirection and publication negative controls."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hepta.c_project_publish import PublicationRejected, publish_no_replace


class PublishTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.stage = root / "stage"
        self.stage.mkdir()
        (self.stage / "source.hepta").write_text("safe")
        (self.stage / "bridge.rs").write_text("bridge")
        (self.stage / "generated.rs").write_text("generated")
        (self.stage / "migration.json").write_text("manifest")
        self.destination = root / "output"

    def test_normal_content_and_manifest_published(self):
        expected_inode = (self.stage / "source.hepta").stat().st_ino
        publish_no_replace(self.stage, self.destination)
        self.assertEqual((self.destination / "source.hepta").read_text(), "safe")
        self.assertEqual((self.destination / "migration.json").read_text(), "manifest")
        self.assertEqual((self.destination / "source.hepta").stat().st_ino, expected_inode)
        self.assertFalse(self.stage.exists())

    def test_existing_directory_and_dangling_symlink_refused(self):
        self.destination.mkdir()
        with self.assertRaises(PublicationRejected):
            publish_no_replace(self.stage, self.destination)
        self.destination.rmdir()
        self.destination.symlink_to(self.destination.parent / "absent", target_is_directory=True)
        with self.assertRaises(PublicationRejected):
            publish_no_replace(self.stage, self.destination)
        self.assertTrue(self.destination.is_symlink())

    def test_rename_and_symlink_swap_cannot_redirect_a_write(self):
        outside = self.destination.parent / "outside"
        outside.mkdir()
        import hepta.c_project_publish as pub
        original = pub._rename_noreplace
        def plant_symlink_before_commit(parentfd, source, target):
            self.destination.symlink_to(outside, target_is_directory=True)
            return original(parentfd, source, target)
        with patch.object(pub, "_rename_noreplace", side_effect=plant_symlink_before_commit):
            with self.assertRaises(PublicationRejected):
                publish_no_replace(self.stage, self.destination)
        self.assertFalse((outside / "source.hepta").exists())
        self.assertFalse((outside / "migration.json").exists())
        self.assertTrue(self.destination.is_symlink())
        self.assertTrue(self.stage.is_dir())

    def test_missing_stage_manifest_fails_before_publication(self):
        (self.stage / "migration.json").unlink()
        with self.assertRaises(PublicationRejected):
            publish_no_replace(self.stage, self.destination)
        self.assertFalse(self.destination.exists())

    def test_staged_symlink_fails_before_publication(self):
        (self.stage / "bad-link").symlink_to(self.stage / "source.hepta")
        with self.assertRaises(PublicationRejected):
            publish_no_replace(self.stage, self.destination)
        self.assertFalse(self.destination.exists())

if __name__ == "__main__":
    unittest.main()
