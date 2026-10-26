"""Native publication helper races, refusal and exact-byte controls."""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hepta.artifact_publication import PublicationRejected, publish_verified


class ArtifactPublicationTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="hepta-publish-test-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.stage = self.root / "staged"
        self.dest = self.root / "published"
        self.payload = b"\x7fELF verified owned-llvm payload"
        self.stage.write_bytes(self.payload)

    def test_valid_file_exact_digest_and_inode(self):
        from hashlib import sha256
        receipt = publish_verified(self.stage, self.dest, self.payload)
        self.assertEqual(receipt, {"sha256": sha256(self.payload).hexdigest(),
                                   "bytes": len(self.payload)})
        self.assertEqual(self.dest.read_bytes(), self.payload)
        self.assertEqual(self.stage.stat().st_ino, self.dest.stat().st_ino)

    def test_existing_destination_not_replaced(self):
        self.dest.write_bytes(b"unchanged")
        with self.assertRaisesRegex(PublicationRejected, "E_PUBLISH_EXISTS"):
            publish_verified(self.stage, self.dest, self.payload)
        self.assertEqual(self.dest.read_bytes(), b"unchanged")

    def test_dangling_symlink_is_not_a_new_destination(self):
        try:
            self.dest.symlink_to(self.root / "absent")
        except OSError:
            self.skipTest("Symlink creation unavailable")
        with self.assertRaisesRegex(PublicationRejected, "E_PUBLISH_EXISTS"):
            publish_verified(self.stage, self.dest, self.payload)
        self.assertTrue(self.dest.is_symlink())

    def test_mismatched_staged_bytes_reject_before_link(self):
        with self.assertRaisesRegex(PublicationRejected, "E_PUBLISH_BYTES"):
            publish_verified(self.stage, self.dest, b"wrong")
        self.assertFalse(self.dest.exists())

    def test_symlinked_staging_file_rejected(self):
        alias = self.root / "alias"
        try:
            alias.symlink_to(self.stage)
        except OSError:
            self.skipTest("Symlink creation unavailable")
        with self.assertRaisesRegex(PublicationRejected, "E_PUBLISH_IDENTITY"):
            publish_verified(alias, self.dest, self.payload)

    def test_content_modification_after_link_refuses_and_unpublishes_our_inode(self):
        original = os.link
        def mutate(src, dest, *args, **kwargs):
            original(src, dest, *args, **kwargs)
            Path(dest).write_bytes(b"tampered")
        with patch("hepta.artifact_publication.os.link", side_effect=mutate):
            with self.assertRaisesRegex(PublicationRejected, "E_PUBLISH_BYTES"):
                publish_verified(self.stage, self.dest, self.payload)
        self.assertFalse(self.dest.exists())

    def test_path_substitution_preserves_other_writers_file(self):
        original = os.link
        def replace(src, dest, *args, **kwargs):
            original(src, dest, *args, **kwargs)
            Path(dest).unlink()
            Path(dest).write_bytes(b"other writer")
        with patch("hepta.artifact_publication.os.link", side_effect=replace):
            with self.assertRaisesRegex(PublicationRejected, "E_PUBLISH_IDENTITY"):
                publish_verified(self.stage, self.dest, self.payload)
        self.assertEqual(self.dest.read_bytes(), b"other writer")

    @unittest.skipUnless(hasattr(os, "mkfifo"), "POSIX FIFOs required")
    def test_fifo_does_not_block_a_verified_reader(self):
        path = self.root / "fifo"
        os.mkfifo(path)
        with self.assertRaisesRegex(PublicationRejected, "E_PUBLISH_IDENTITY"):
            publish_verified(path, self.dest, self.payload)

    def test_empty_payload_rejected(self):
        with self.assertRaisesRegex(PublicationRejected, "E_PUBLISH_INPUT"):
            publish_verified(self.stage, self.dest, b"")

    def test_same_input_and_output_rejected(self):
        with self.assertRaisesRegex(PublicationRejected, "E_PUBLISH_INPUT"):
            publish_verified(self.stage, self.stage, self.payload)


if __name__ == "__main__":
    unittest.main()
