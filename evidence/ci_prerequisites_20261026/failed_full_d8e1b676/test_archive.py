"""Bounded container and immutable Git-classification data-only regressions."""
import base64
from copy import deepcopy
import io
import json
import lzma
import os
from pathlib import Path
import tarfile
import tempfile
import unittest

import performance_audit as audit
from verify_bundle import MAX_TAR, unpack_archive, read_regular, safe_path, verify_zip_source

ROOT = Path(__file__).resolve().parent

class ContainerBoundaryTests(unittest.TestCase):
    def fixture(self, directory, *, member_name="data", member_type=tarfile.REGTYPE):
        payload = b"retained bytes\n"
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            info = tarfile.TarInfo(member_name)
            info.type = member_type
            info.mode = 0o644
            info.size = len(payload) if member_type == tarfile.REGTYPE else 0
            if member_type == tarfile.SYMTYPE:
                info.linkname = "/outside"
            archive.addfile(info, io.BytesIO(payload) if info.size else None)
        tar = stream.getvalue()
        # Tiny synthetic container only; this does not recompress the full run.
        packed = lzma.compress(tar, preset=0)
        encoded = base64.b64encode(packed) + b"\n"
        name = "fixture.tar.xz.b64"
        (Path(directory) / name).write_bytes(encoded)
        return {"schema": "hepta.ci-candidate.archive.v1", "archive": name,
            "encoding": "base64", "compression": "xz-preset-6-dict-64MiB",
            "parts": [{"path": name, "bytes": len(encoded), "sha256": audit.sha(encoded)}],
            "encoded_bytes": len(encoded), "encoded_sha256": audit.sha(encoded),
            "decoded_bytes": len(packed), "decoded_sha256": audit.sha(packed),
            "tar_bytes": len(tar), "tar_sha256": audit.sha(tar), "member_count": 1,
            "uncompressed_bytes": len(payload) if member_type == tarfile.REGTYPE else 0,
            "members": [{"path": member_name, "bytes": info.size, "sha256": audit.sha(payload if info.size else b""), "mode": 0o644}]}

    def test_real_decoder_checks_content_and_rejects_member_digest_change(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = self.fixture(directory)
            self.assertEqual(unpack_archive(directory, manifest), {"data": b"retained bytes\n"})
            manifest["members"][0]["sha256"] = "0" * 64
            with self.assertRaisesRegex(ValueError, "member digest"):
                unpack_archive(directory, manifest)

    def test_symlink_tar_member_and_traversal_are_rejected_without_extraction(self):
        for name, kind in (("data", tarfile.SYMTYPE), ("../outside", tarfile.REGTYPE), ("/outside", tarfile.REGTYPE)):
            with self.subTest(name=name, kind=kind), tempfile.TemporaryDirectory() as directory:
                manifest = self.fixture(directory, member_name=name, member_type=kind)
                with self.assertRaises(ValueError):
                    unpack_archive(directory, manifest)
                self.assertEqual([p.name for p in Path(directory).iterdir()], ["fixture.tar.xz.b64"])

    def test_part_and_expansion_bounds_are_checked_before_unpack(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = self.fixture(directory)
            manifest["tar_bytes"] = MAX_TAR + 1
            with self.assertRaisesRegex(ValueError, "expansion bound"):
                unpack_archive(directory, manifest)
            manifest = self.fixture(directory)
            manifest["parts"][0]["path"] = "../../outside"
            with self.assertRaisesRegex(ValueError, "part names/order"):
                unpack_archive(directory, manifest)

    def test_nonregular_input_is_rejected_before_opening(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "file").write_bytes(b"x")
            (root / "link").symlink_to(root / "file")
            os.mkfifo(root / "fifo")
            for name in ("link", "fifo"):
                with self.subTest(name=name), self.assertRaises(ValueError):
                    read_regular(root, name)

    def test_duplicate_nonfinite_json_and_path_aliases_are_rejected(self):
        for data in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}'):
            with self.subTest(data=data), self.assertRaises(ValueError):
                audit.parse(data)
        for name in ("a/../b", "a//b", "./data", "", "a\\b"):
            with self.subTest(path=name), self.assertRaises(ValueError):
                safe_path(name)


class ZipSourceProofTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.proof = audit.parse((ROOT / "zip-source-tree-proof.json").read_bytes())
        cls.entries = {row["path"]: row for row in audit.parse((ROOT / "zip-inventory.json").read_bytes())["members"]}

    def test_actual_existing_and_absent_paths_are_bound_to_exact_git_tree(self):
        self.assertEqual(verify_zip_source(self.proof, self.entries), len(self.proof["tree_objects_base64"]))

    def test_arbitrary_deduplicated_source_blob_cannot_be_asserted(self):
        entries = deepcopy(self.entries)
        row = next(row for row in entries.values() if row["classification"] == "unchanged_from_source")
        row["source_git_blob_sha1"] = row["git_blob_sha1"] = "0" * 40
        with self.assertRaisesRegex(ValueError, "exact Git tree"):
            verify_zip_source(self.proof, entries)

    def test_added_file_cannot_be_relabelled_as_an_existing_source_blob(self):
        entries = deepcopy(self.entries)
        row = next(row for row in entries.values() if row["classification"] == "added_by_run")
        row["classification"] = "unchanged_from_source"
        row["source_git_blob_sha1"] = row["git_blob_sha1"]
        with self.assertRaisesRegex(ValueError, "exact Git tree"):
            verify_zip_source(self.proof, entries)


if __name__ == "__main__":
    unittest.main(verbosity=2)
