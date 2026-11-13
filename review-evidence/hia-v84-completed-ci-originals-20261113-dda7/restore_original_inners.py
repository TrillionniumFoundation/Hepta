#!/usr/bin/env python3
"""Offline restoration of the five immutable inner ZIPs; never executes project code.

AUTHORED_NOT_EXECUTED in the disconnected author environment. The original
collector and independent V8 readback already verified all 99 wrappers and
whole original ZIP byte identities. This convenience helper repeats that
verification from an audit checkout and checks every ZIP member against the
retained inventory. It never reconstructs or replaces an outer Actions ZIP.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import zipfile
import zlib

PREFIX = "review-evidence/hia-v84-completed-ci-originals-20261113-dda7"
MANIFEST_SHA256 = "2547c6c5ba6dba42467c2b2e80fed55274b91cee1ec6eb0888b6cd353ab423fd"
MANIFEST_GIT_BLOB = "caf91df852216fdcfe2cb35a4f58b44e1b51facf"
MANIFEST_BYTES = 113803


def git_blob(data):
    h = hashlib.sha1()
    h.update(("blob " + str(len(data)) + "\0").encode("ascii"))
    h.update(data)
    return h.hexdigest()


def identity(data, expected):
    actual = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
              "blob": git_blob(data)}
    if actual != {key: expected[key] for key in actual}:
        raise ValueError("content identity mismatch: " + repr(actual))
    return actual


def safe_path(root, value):
    p = PurePosixPath(value)
    if p.is_absolute() or ".." in p.parts or not p.parts or str(p) != value:
        raise ValueError("noncanonical repository path")
    out = root
    for part in p.parts:
        out = out / part
        if out.is_symlink():
            raise ValueError("symlink in audit input: " + value)
    return out


def unwrap(value):
    depth = 0
    while isinstance(value, dict) and value.get("schema") == "hia.lossless-zlib-text-capsule.v1":
        depth += 1
        if depth > 3 or value["encoding"] != "base64(zlib(UTF-8))":
            raise ValueError("unsupported lossless wrapper")
        compressed = base64.b64decode(value["data"], validate=True)
        decoder = zlib.decompressobj()
        raw = decoder.decompress(compressed) + decoder.flush()
        if not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
            raise ValueError("incomplete or trailing zlib stream")
        identity(raw, value)
        value = json.loads(raw.decode("utf-8"))
    return value


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--root", required=True, type=Path,
                   help="read-only audit checkout root containing review-evidence/")
    p.add_argument("--output", required=True, type=Path,
                   help="new output directory; must not already exist")
    args = p.parse_args()
    root = args.root.resolve(strict=True)
    raw = safe_path(root, PREFIX + "/CUSTODY-COMPLETE.json").read_bytes()
    identity(raw, {"bytes": MANIFEST_BYTES, "sha256": MANIFEST_SHA256,
                   "blob": MANIFEST_GIT_BLOB})
    manifest = json.loads(raw.decode("utf-8"))
    if (manifest["status"] != "CUSTODY_COMPLETE" or
            manifest["expected_originals"] != 5 or
            len(manifest["completed_originals"]) != 5 or
            manifest["unpreserved_originals"]):
        raise ValueError("manifest is not complete")
    entries = manifest["entries"]
    names = [row["path"] for row in entries]
    if len(set(names)) != len(names):
        raise ValueError("duplicate audit path")
    by_blob = {}
    for row in entries:
        if row["mode"] != "100644" or row["type"] != "blob":
            raise ValueError("unexpected audit object type")
        path = safe_path(root, row["path"])
        if not stat.S_ISREG(path.stat().st_mode):
            raise ValueError("audit object is not a regular file")
        payload = path.read_bytes()
        if git_blob(payload) != row["sha"]:
            raise ValueError("Git blob mismatch: " + row["path"])
        by_blob.setdefault(row["sha"], path)

    def read_object(meta):
        payload = by_blob[meta["blob"]].read_bytes()
        identity(payload, meta)
        return json.loads(payload.decode("utf-8"))

    args.output.mkdir(parents=False, exist_ok=False)
    restored = []
    for original in manifest["completed_originals"]:
        key = original["key"]
        if not key or "/" in key or "\\" in key or key in (".", ".."):
            raise ValueError("invalid original key")
        index = read_object(original["index"])
        if not all(index[name] is True for name in
                   ("all_published", "all_wrappers_full_readback", "ordered_offsets_complete")):
            raise ValueError("incomplete archive index")
        if index["archive"] != original["archive"]:
            raise ValueError("archive identity disagrees with manifest")
        directory = args.output / key
        directory.mkdir()
        target = directory / "ORIGINAL-INNER.zip"
        expected = index["archive"]
        digest = hashlib.sha256()
        git = hashlib.sha1()
        git.update(("blob " + str(expected["bytes"]) + "\0").encode("ascii"))
        offset = 0
        with target.open("xb") as stream:
            for number, chunk in enumerate(index["chunks"]):
                value = read_object(chunk["wrapper"])
                if (value["schema"] != "hia.lossless-archive-chunk.v1" or
                        value["encoding"] != "base64" or
                        value["archive_name"] != index["archive_name"] or
                        value["archive_bytes"] != expected["bytes"] or
                        value["archive_sha256"] != expected["sha256"] or
                        value["index"] != number or chunk["index"] != number or
                        value["offset"] != offset or chunk["offset"] != offset or
                        value["bytes"] != chunk["bytes"] or
                        value["sha256"] != chunk["sha256"]):
                    raise ValueError("chunk metadata mismatch")
                part = base64.b64decode(value["data"], validate=True)
                if len(part) != chunk["bytes"] or hashlib.sha256(part).hexdigest() != chunk["sha256"]:
                    raise ValueError("raw chunk mismatch")
                stream.write(part)
                digest.update(part)
                git.update(part)
                offset += len(part)
            stream.flush()
            os.fsync(stream.fileno())
        if (offset != expected["bytes"] or digest.hexdigest() != expected["sha256"] or
                git.hexdigest() != expected["blob"]):
            raise ValueError("whole original ZIP mismatch")
        inventory = read_object(original["receipts"]["INNER-MEMBERS.json"])
        with zipfile.ZipFile(target, "r") as archive:
            infos = archive.infolist()
            if len(infos) != len(inventory) or len({i.filename for i in infos}) != len(infos):
                raise ValueError("duplicate or missing original ZIP member")
            if {i.filename for i in infos} != set(inventory):
                raise ValueError("original ZIP member set mismatch")
            for info in infos:
                expected_member = inventory[info.filename]
                sha = hashlib.sha256()
                member_git = hashlib.sha1()
                member_git.update(("blob " + str(info.file_size) + "\0").encode("ascii"))
                size = 0
                crc = 0
                with archive.open(info, "r") as reader:
                    while True:
                        part = reader.read(1024 * 1024)
                        if not part:
                            break
                        size += len(part)
                        sha.update(part)
                        member_git.update(part)
                        crc = zlib.crc32(part, crc)
                actual = {"bytes": size, "sha256": sha.hexdigest(),
                          "blob": member_git.hexdigest(), "crc32": format(crc & 0xffffffff, "08x"),
                          "zip_mode": oct(info.external_attr >> 16),
                          "compressed_bytes": info.compress_size,
                          "compression": info.compress_type, "directory": info.is_dir()}
                if actual != expected_member or (crc & 0xffffffff) != info.CRC:
                    raise ValueError("member identity mismatch: " + info.filename)
        # Decode all retained receipt capsules as another independent check.
        for meta in original["receipts"].values():
            unwrap(read_object(meta))
        restored.append({"key": key, "original_status": original["original_status"],
                         "archive": expected, "chunks": len(index["chunks"]),
                         "members": len(inventory), "path": str(target),
                         "raw_git_binary_object_uploaded": False})
    report = {"schema": "hia.offline-original-inner-restoration.v1",
              "status": "RESTORED_AND_VERIFIED", "originals": restored,
              "product_execution": False, "tests_execution": False,
              "outer_zip_reconstructed": False, "qualification_transferred": False}
    with (args.output / "RESTORE-REPORT.json").open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(json.dumps({"status": report["status"], "originals": len(restored)}))


if __name__ == "__main__":
    main()
