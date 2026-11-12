"""Native publication helper races, refusal and exact-byte controls."""
from __future__ import annotations

import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from hepta.artifact_publication import (PublicationRejected, publish_verified,
                                       verify_published, withdraw_own_link)


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

    def test_post_publication_exact_inode_replay(self):
        from hashlib import sha256
        before = publish_verified(self.stage, self.dest, self.payload)
        after = verify_published(self.stage, self.dest, self.payload)
        self.assertEqual(before, after)
        self.assertEqual(after["sha256"], sha256(self.payload).hexdigest())

    def test_post_publication_inplace_corruption_is_rejected_and_withdrawn(self):
        publish_verified(self.stage, self.dest, self.payload)
        self.dest.write_bytes(b"tampered after successful publisher return")
        with self.assertRaisesRegex(PublicationRejected, "E_PUBLISH_BYTES"):
            verify_published(self.stage, self.dest, self.payload)
        self.assertTrue(withdraw_own_link(self.stage, self.dest))
        self.assertFalse(self.dest.exists())

    def test_post_publication_competitor_swap_survives_own_link_cleanup(self):
        publish_verified(self.stage, self.dest, self.payload)
        self.dest.unlink()
        self.dest.write_bytes(b"separate other-writer bytes")
        with self.assertRaisesRegex(PublicationRejected, "E_PUBLISH"):
            verify_published(self.stage, self.dest, self.payload)
        self.assertFalse(withdraw_own_link(self.stage, self.dest))
        self.assertEqual(self.dest.read_bytes(), b"separate other-writer bytes")

    def test_post_publication_wrong_size_and_symlink_fail_closed(self):
        publish_verified(self.stage, self.dest, self.payload)
        self.dest.unlink()
        self.dest.symlink_to(self.stage)
        with self.assertRaisesRegex(PublicationRejected, "E_PUBLISH_IDENTITY"):
            verify_published(self.stage, self.dest, self.payload)
        self.assertFalse(withdraw_own_link(self.stage, self.dest))
        self.assertTrue(self.dest.is_symlink())

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

    @unittest.skipUnless(hasattr(os, "mkfifo") and hasattr(os, "O_NONBLOCK"),
                         "POSIX nonblocking FIFO required")
    def test_regular_stage_fifo_swap_is_rejected_before_blocking(self):
        original_open = os.open
        previous = self.root / "previous-stage"
        opened = []
        def swap(path, flags, *args, **kwargs):
            # Check flags FIRST: a regression must fail, not hang this test.
            self.assertTrue(flags & os.O_NOFOLLOW)
            self.assertTrue(flags & os.O_NONBLOCK)
            opened.append(flags)
            self.stage.rename(previous)
            os.mkfifo(self.stage)
            return original_open(path, flags, *args, **kwargs)
        with patch("hepta.artifact_publication.os.open", side_effect=swap):
            with self.assertRaisesRegex(PublicationRejected, "E_PUBLISH_RACE"):
                publish_verified(self.stage, self.dest, self.payload)
        self.assertEqual(len(opened), 1)
        self.assertFalse(self.dest.exists())
        self.assertEqual(previous.read_bytes(), self.payload)

    def test_empty_payload_rejected(self):
        with self.assertRaisesRegex(PublicationRejected, "E_PUBLISH_INPUT"):
            publish_verified(self.stage, self.dest, b"")

    @unittest.skipUnless(platform.system() == "Linux"
                         and platform.machine() in {"x86_64", "amd64"}
                         and shutil.which("clang") and shutil.which("gcc"),
                         "native ELF object execution requires Linux x86-64 Clang and GCC")
    def test_actual_clang_llvm_object_is_published_and_executed_by_gcc(self):
        # This qualifies the publication boundary with a real machine-code
        # artifact, NOT Hepta source-to-LLVM refinement or whole-program ABI.
        source = self.root / "module.ll"
        source.write_text(
            'target triple = "x86_64-unknown-linux-gnu"\n'
            'define i32 @hepta_native_check(i32 %x) {\n'
            'entry:\n  %y = add nsw i32 %x, 1\n  ret i32 %y\n}\n')
        staged = self.root / "module.o"
        published = self.root / "linked.o"
        subprocess.run(["clang", "--target=x86_64-unknown-linux-gnu", "-x", "ir",
                        "-O2", "-c", str(source), "-o", str(staged)],
                       check=True, capture_output=True, timeout=30)
        object_bytes = staged.read_bytes()
        self.assertTrue(object_bytes.startswith(b"\x7fELF"))
        receipt = publish_verified(staged, published, object_bytes)
        self.assertEqual(receipt["bytes"], len(object_bytes))
        self.assertEqual(published.read_bytes(), object_bytes)
        harness = self.root / "driver.c"
        harness.write_text(
            'extern int hepta_native_check(int);\n'
            'int main(void) { return hepta_native_check(41)==42 ? 0 : 13; }\n')
        binary = self.root / "driver"
        subprocess.run(["gcc", str(harness), str(published), "-o", str(binary)],
                       check=True, capture_output=True, timeout=30)
        executed = subprocess.run([str(binary)], capture_output=True, timeout=10)
        self.assertEqual(executed.returncode, 0, executed.stderr)

    def test_same_input_and_output_rejected(self):
        with self.assertRaisesRegex(PublicationRejected, "E_PUBLISH_INPUT"):
            publish_verified(self.stage, self.stage, self.payload)


if __name__ == "__main__":
    unittest.main()
