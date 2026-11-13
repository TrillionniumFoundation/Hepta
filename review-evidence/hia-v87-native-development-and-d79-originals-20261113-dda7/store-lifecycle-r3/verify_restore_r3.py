"""Verify immutable UTF-8 Git wrappers and optionally restore all R3 originals.

The caller must obtain INDEX.json and the files named by index.chunks from the
immutable Git blobs recorded in the mount recipe. This tool performs no network
operation, product import, generator invocation, or qualification test.
"""
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


def require(condition, message):
    if not condition:
        raise ValueError(message)


def identity(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
            "git_blob": hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()}


def check(raw, row, label):
    actual = identity(raw)
    require(all(actual[key] == row[key] for key in actual), "identity mismatch: " + label)


def safe_name(text):
    require(type(text) is str and text != "", "empty or nontext archive path")
    name = PurePosixPath(text)
    require(not name.is_absolute() and ".." not in name.parts and name.as_posix() == text,
            "unsafe archive path: " + text)
    require("\\" not in text and "\0" not in text, "unsafe archive path characters")
    return name


def ordinary_bytes(path, mode=None):
    st = path.lstat()
    require(stat.S_ISREG(st.st_mode), "nonordinary file: " + str(path))
    if mode is not None:
        require(stat.S_IMODE(st.st_mode) == mode, "mode mismatch: " + str(path))
    return path.read_bytes()


def verify(root, wrapper_root, receipt_root=None, local_originals=None, destination=None):
    index = json.loads(ordinary_bytes(root / "originals-r3/INDEX.json"))
    require(index["schema"] == "hepta.immutable-base64-archive.v1", "unexpected archive schema")
    compressed_parts, receipts, wrapper_rows = [], [], []
    require(len(index["chunks"]) == 82, "R3 chunk count differs")
    for number, row in enumerate(index["chunks"]):
        require(row["file"] == "originals-r3/chunks/" + str(number).zfill(4) + ".b64",
                "chunk order or path differs")
        safe_name(row["file"])
        wrapper = ordinary_bytes(wrapper_root / row["file"])
        check(wrapper, row, row["file"])
        raw = base64.b64decode(wrapper, validate=True)
        require(base64.b64encode(raw) == wrapper, "noncanonical base64 wrapper")
        require(len(raw) == row["decoded_bytes"] and
                hashlib.sha256(raw).hexdigest() == row["decoded_sha256"], "decoded chunk differs")
        if receipt_root is not None:
            receipt = json.loads(ordinary_bytes(receipt_root / (row["file"] + ".receipt.json")))
            require(receipt["full_get_verified"] is True, "missing actual full GET receipt")
            for field, key in (("full_get_blob", "git_blob"), ("full_get_sha256", "sha256"),
                               ("full_get_bytes", "bytes")):
                require(receipt[field] == row[key], "full GET receipt identity differs")
            receipts.append(receipt)
        compressed_parts.append(raw)
        wrapper_rows.append(row)
    compressed = b"".join(compressed_parts)
    check(compressed, index["archive"], "archive")
    retained_archive_equal = None
    if local_originals is not None:
        retained = ordinary_bytes(local_originals / "originals-r3/ORIGINALS.tar.gz")
        require(compressed == retained, "full GET reconstruction differs from original gzip")
        retained_archive_equal = True
    tar_raw = gzip.decompress(compressed)
    check(tar_raw, index["tar"], "tar")
    if destination is not None:
        destination.mkdir()
        require(not list(destination.iterdir()), "restore target is not empty")
    verified_bytes = compared_members = restored_members = 0
    with tarfile.open(fileobj=io.BytesIO(tar_raw), mode="r:") as archive:
        members = archive.getmembers()
        require(len(members) == index["logical_members"], "member count differs")
        require(len({item.name for item in members}) == len(members), "duplicate archive members")
        for item in members:
            safe_name(item.name)
            require(item.isfile(), "nonordinary archive member")
        manifest_raw = archive.extractfile("ORIGINAL-MANIFEST.json").read()
        check(manifest_raw, index["manifest"], "member manifest")
        manifest = json.loads(manifest_raw)
        rows = {row["path"]: row for row in manifest["files"]}
        require(len(rows) == len(manifest["files"]) == index["file_count_excluding_manifest"],
                "manifest count or unique paths differ")
        require(set(rows) | {"ORIGINAL-MANIFEST.json"} == {item.name for item in members},
                "complete member set differs")
        for item in members:
            raw = archive.extractfile(item).read()
            if item.name == "ORIGINAL-MANIFEST.json":
                require(item.mode == 0o644, "manifest mode differs")
            else:
                row = rows[item.name]
                check(raw, row, item.name)
                require(item.mode == int(row["mode"], 8), "member mode differs: " + item.name)
                if local_originals is not None:
                    # Only the captured compiler was stored under an alias.
                    if "original_path" in row:
                        require(item.name == "inputs/captured-development-B3.image.bin",
                                "unreviewed external original path")
                        original = Path(row["original_path"])
                    else:
                        original = local_originals / item.name
                    require(ordinary_bytes(original, item.mode) == raw,
                            "member differs from original: " + item.name)
                    compared_members += 1
                verified_bytes += len(raw)
            if destination is not None:
                path = destination / item.name
                path.parent.mkdir(parents=True, exist_ok=True)
                with path.open("xb") as stream:
                    stream.write(raw)
                os.chmod(path, item.mode)
                require(ordinary_bytes(path, item.mode) == raw, "restored bytes differ")
                restored_members += 1
    require(verified_bytes == index["logical_bytes_excluding_manifest"], "logical bytes differ")
    return {
        "status": "ALL_WRAPPERS_AND_ARCHIVE_MEMBERS_VERIFIED",
        "scope": "custody only; zero product, generator, test or native execution",
        "archive": index["archive"], "tar": index["tar"], "manifest": index["manifest"],
        "logical_members_verified": len(members), "original_bytes_verified": verified_bytes,
        "original_members_compared": compared_members,
        "retained_original_gzip_equal": retained_archive_equal,
        "all_member_bytes_modes_git_sha1_and_sha256_equal": True,
        "gzip_crc_and_isize_verified": True,
        "full_get_receipts_verified": len(receipts), "wrappers": wrapper_rows, "receipts": receipts,
        "restored_root": str(destination) if destination is not None else None,
        "restored_members_verified": restored_members,
        "source_boundary": index["source_boundary"], "whole_native": False,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--wrapper-root", type=Path)
    parser.add_argument("--receipt-root", type=Path)
    parser.add_argument("--compare-originals", type=Path)
    parser.add_argument("--restore", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    report = verify(args.root, args.wrapper_root or args.root, args.receipt_root,
                    args.compare_originals, args.restore)
    if args.report is not None:
        with args.report.open("x", encoding="utf-8") as stream:
            json.dump(report, stream, sort_keys=True, indent=2)
            stream.write("\n")
    print(json.dumps({key: value for key, value in report.items() if key not in ("wrappers", "receipts")}, indent=2))
