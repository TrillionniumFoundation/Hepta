"""Strictly verify full GET wrapper bytes; optionally restore to a new empty root."""
from pathlib import Path, PurePosixPath
import argparse
import base64
import gzip
import hashlib
import io
import json
import os
import stat
import tarfile


def identity(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
            "git_blob": hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()}


def check(raw, row):
    actual = identity(raw)
    assert all(actual[key] == row[key] for key in actual), (actual, row)


def verify(root, destination=None):
    index = json.loads((root / "originals-r2/INDEX.json").read_text())
    compressed_parts, receipts = [], []
    for row in index["chunks"]:
        wrapper = (root / "GIT-CUSTODY/readback" / row["file"]).read_bytes()
        check(wrapper, row)
        raw = base64.b64decode(wrapper, validate=True)
        assert base64.b64encode(raw) == wrapper
        assert len(raw) == row["decoded_bytes"]
        assert hashlib.sha256(raw).hexdigest() == row["decoded_sha256"]
        receipt = json.loads((root / "GIT-CUSTODY" / (row["file"] + ".receipt.json")).read_text())
        assert receipt["full_get_verified"] is True
        assert receipt["full_get_blob"] == row["git_blob"]
        assert receipt["full_get_sha256"] == row["sha256"]
        assert receipt["full_get_bytes"] == row["bytes"]
        receipts.append(receipt)
        compressed_parts.append(raw)
    compressed = b"".join(compressed_parts)
    check(compressed, index["archive"])
    assert compressed == (root / "originals-r2/ORIGINALS.tar.gz").read_bytes()
    tar_raw = gzip.decompress(compressed)
    check(tar_raw, index["tar"])
    if destination is not None:
        destination.mkdir()
        assert not list(destination.iterdir())
    verified_bytes = 0
    with tarfile.open(fileobj=io.BytesIO(tar_raw), mode="r:") as archive:
        members = archive.getmembers()
        assert len(members) == index["logical_members"]
        assert len({item.name for item in members}) == len(members)
        for item in members:
            name = PurePosixPath(item.name)
            assert item.isfile() and not name.is_absolute() and ".." not in name.parts
        manifest_raw = archive.extractfile("ORIGINAL-MANIFEST.json").read()
        check(manifest_raw, index["manifest"])
        manifest = json.loads(manifest_raw)
        rows = {row["path"]: row for row in manifest["files"]}
        assert len(rows) == index["file_count_excluding_manifest"]
        assert set(rows) | {"ORIGINAL-MANIFEST.json"} == {item.name for item in members}
        for item in members:
            raw = archive.extractfile(item).read()
            if item.name == "ORIGINAL-MANIFEST.json":
                assert item.mode == 0o644
            else:
                row = rows[item.name]
                check(raw, row)
                assert item.mode == int(row["mode"], 8)
                original = root / item.name
                st = original.lstat()
                assert stat.S_ISREG(st.st_mode) and stat.S_IMODE(st.st_mode) == item.mode
                assert original.read_bytes() == raw
                verified_bytes += len(raw)
            if destination is not None:
                path = destination / item.name
                path.parent.mkdir(parents=True, exist_ok=True)
                with path.open("xb") as stream:
                    stream.write(raw)
                os.chmod(path, item.mode)
                assert path.read_bytes() == raw
                assert stat.S_IMODE(path.lstat().st_mode) == item.mode
    assert verified_bytes == index["logical_bytes_excluding_manifest"]
    return {"status": "FULL_GET_WRAPPERS_AND_ALL_ARCHIVE_MEMBERS_VERIFIED",
            "scope": "custody only; zero product, generator, test or native execution",
            "archive": index["archive"], "tar": index["tar"], "manifest": index["manifest"],
            "logical_members_verified": len(members), "original_bytes_verified": verified_bytes,
            "all_raw_bytes_modes_git_sha1_and_sha256_equal": True,
            "gzip_crc_and_isize_verified": True, "wrappers": receipts,
            "restored_root": str(destination) if destination is not None else None,
            "source_boundary": index["source_boundary"], "whole_native": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--restore", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    report = verify(args.root, args.restore)
    if args.report is not None:
        with args.report.open("x", encoding="utf-8") as stream:
            json.dump(report, stream, sort_keys=True, indent=2)
            stream.write("\n")
    print(json.dumps({key: value for key, value in report.items() if key != "wrappers"}, indent=2))
