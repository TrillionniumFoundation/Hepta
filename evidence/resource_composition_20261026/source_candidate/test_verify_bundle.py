"""Small archive attacks and source/report tampering; no native execution."""
import base64
import copy
import io
import json
import lzma
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import verify_bundle as verifier

HERE = Path(__file__).resolve().parent


class BundleNegativeControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def fixture(self, members=None, *, suffix=b"", extra_xz=False, split=False):
        members = members or [("payload.txt", b"payload", tarfile.REGTYPE)]
        raw = io.BytesIO()
        expected = []
        with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for name, data, kind in members:
                row = tarfile.TarInfo(name)
                row.type = kind
                row.size = len(data) if kind == tarfile.REGTYPE else 0
                row.mode = 0o644
                if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                    row.linkname = "/outside"
                archive.addfile(row, io.BytesIO(data) if kind == tarfile.REGTYPE else None)
                expected.append({"path": name, "bytes": row.size, "mode": 0o644, "sha256": verifier.sha(data if row.size else b"")})
        # Synthetic fixture is a few hundred compressed bytes, unrelated to
        # recompression of the real native artifact archive.
        packed = lzma.compress(raw.getvalue() + suffix, preset=0)
        if extra_xz:
            packed += lzma.compress(b"unlisted", preset=0)
        encoded = base64.encodebytes(packed)
        name = "fixture.tar.xz.base64"
        chunks = [encoded] if not split else [encoded[:len(encoded)//2], encoded[len(encoded)//2:]]
        parts = []
        for i, chunk in enumerate(chunks):
            part = name if len(chunks) == 1 else name + ".part%02d" % (i + 1)
            (self.root / part).write_bytes(chunk)
            parts.append({"path": part, "bytes": len(chunk), "sha256": verifier.sha(chunk)})
        return {"schema": "hepta.source-candidate.archive.v1", "encoding": "base64", "compression": "xz-preset-1",
                "archive": name, "encoded_bytes": len(encoded), "encoded_sha256": verifier.sha(encoded),
                "decoded_bytes": len(packed), "decoded_sha256": verifier.sha(packed), "parts": parts,
                "members": expected, "member_count": len(expected), "uncompressed_bytes": sum(r["bytes"] for r in expected)}

    def test_regular_and_split_payloads_verify_without_extraction(self):
        for split in (False, True):
            with self.subTest(split=split):
                data, _ = verifier.unpack_archive(self.root, self.fixture(split=split), lambda _: True)
                self.assertEqual(data, {"payload.txt": b"payload"})
                self.assertFalse((self.root / "payload.txt").exists())

    def test_unsafe_paths_rejected(self):
        for name in ("../escape", "/absolute", "a/../escape", "a//escape", "./escape", "a\\escape"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                verifier.unpack_archive(self.root, self.fixture([(name, b"x", tarfile.REGTYPE)]), lambda _: True)

    def test_symlinks_hardlinks_and_special_files_rejected(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE, tarfile.CHRTYPE):
            with self.subTest(kind=kind), self.assertRaisesRegex(ValueError, "regular"):
                verifier.unpack_archive(self.root, self.fixture([("payload", b"", kind)]), lambda _: True)

    def test_duplicate_tar_member_rejected_even_with_deduplicated_manifest(self):
        manifest = self.fixture([("same", b"x", tarfile.REGTYPE)] * 2)
        manifest["members"] = manifest["members"][:1]
        manifest["member_count"] = 1
        manifest["uncompressed_bytes"] = 1
        with self.assertRaisesRegex(ValueError, "duplicate"):
            verifier.unpack_archive(self.root, manifest, lambda _: True)

    def test_duplicate_manifest_member_rejected(self):
        manifest = self.fixture()
        manifest["members"] *= 2
        manifest["member_count"] = 2
        with self.assertRaisesRegex(ValueError, "duplicate manifest"):
            verifier.unpack_archive(self.root, manifest, lambda _: True)

    def test_unlisted_member_rejected(self):
        manifest = self.fixture()
        manifest["members"][0]["path"] = "different.txt"
        with self.assertRaisesRegex(ValueError, "unlisted"):
            verifier.unpack_archive(self.root, manifest, lambda _: True)

    def test_member_hash_size_and_mode_mismatches_rejected(self):
        for key, value in (("sha256", "0" * 64), ("bytes", 1), ("mode", 0o755)):
            manifest = self.fixture()
            manifest["members"][0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                verifier.unpack_archive(self.root, manifest, lambda _: True)

    def test_part_mutation_and_reordering_rejected(self):
        manifest = self.fixture(split=True)
        manifest["parts"].reverse()
        with self.assertRaisesRegex(ValueError, "part order"):
            verifier.unpack_archive(self.root, manifest, lambda _: True)
        manifest = self.fixture()
        (self.root / manifest["archive"]).write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "part identity"):
            verifier.unpack_archive(self.root, manifest, lambda _: True)

    def test_oversized_manifest_and_concatenated_xz_rejected(self):
        manifest = self.fixture()
        manifest["uncompressed_bytes"] = verifier.MAX_TAR + 1
        with self.assertRaisesRegex(ValueError, "uncompressed size"):
            verifier.unpack_archive(self.root, manifest, lambda _: True)
        with self.assertRaisesRegex(ValueError, "concatenated"):
            verifier.unpack_archive(self.root, self.fixture(extra_xz=True), lambda _: True)

    def test_unlisted_tar_trailing_data_rejected(self):
        with self.assertRaisesRegex(ValueError, "trailing"):
            verifier.unpack_archive(self.root, self.fixture(suffix=b"hidden"), lambda _: True)

    def test_duplicate_json_key_and_nonfinite_value_rejected(self):
        for data in (b'{"name": 1, "name": 2}', b'{"number": NaN}'):
            with self.subTest(data=data), self.assertRaises(ValueError):
                verifier.decode_json(data)

    def test_source_denominator_snapshot_commit_and_tree_tampering_rejected(self):
        snapshot = verifier.decode_json((HERE / "source-snapshot.json").read_bytes())
        proof = verifier.decode_json((HERE / "source-git-identity.json").read_bytes())
        fake_sources = {name: b"not accessed by these early rejection cases" for name in snapshot["files"]}
        with self.assertRaisesRegex(ValueError, "denominator"):
            verifier.verify_source({}, snapshot, proof)
        bad = copy.deepcopy(snapshot)
        bad["files"][next(iter(bad["files"]))] = "0" * 64
        with self.assertRaisesRegex(ValueError, "snapshot identity"):
            verifier.verify_source(fake_sources, bad, proof)
        bad = copy.deepcopy(proof)
        bad["commit_object_base64"] = base64.b64encode(b"changed commit").decode()
        with self.assertRaisesRegex(ValueError, "commit object identity"):
            verifier.verify_source(fake_sources, snapshot, bad)
        bad = copy.deepcopy(proof)
        bad["tree_objects_base64"][next(iter(bad["tree_objects_base64"]))] = base64.b64encode(b"changed tree").decode()
        with self.assertRaisesRegex(ValueError, "tree object identity"):
            verifier.verify_source(fake_sources, snapshot, bad)

    def test_report_gate_denominator_and_source_bindings_rejected(self):
        original = verifier.decode_json((HERE / "release-validation.json").read_bytes())
        snapshot = original["source_snapshot"]
        for mutation in ("denominator", "compiler", "commit", "outcome"):
            report = copy.deepcopy(original)
            if mutation == "denominator":
                report["gates"].pop()
            elif mutation == "compiler":
                report["compiler_sha256"] = "0" * 64
            elif mutation == "commit":
                report["source_git_commit"] = "0" * 40
            else:
                report["status"] = "passed"
            data = json.dumps(report).encode()
            # Even if an attacker rebinds a wrapper hash, the semantic
            # denominator and fixed source identities must still reject.
            with self.subTest(mutation=mutation), patch.object(verifier, "REPORT_SHA256", verifier.sha(data)), self.assertRaises(ValueError):
                verifier.verify_reports(data, {}, {}, {}, snapshot)


if __name__ == "__main__":
    unittest.main()
