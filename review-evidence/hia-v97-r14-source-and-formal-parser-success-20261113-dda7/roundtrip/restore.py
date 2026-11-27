"""Verify and optionally restore the exact canonical/reparse development capsule.

This is an evidence reader. It imports no product code and runs no product.
Default inputs are mounted UTF-8 base64 parts. --git-responses instead reads
the actual full GET response files produced by this scope's publisher.
"""
import argparse
import base64
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import stat
import tarfile


def pin(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
            "git_blob": hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()}


def check(raw, expected):
    assert pin(raw) == {key: expected[key] for key in ("bytes", "sha256", "git_blob")}


def safe(name):
    p = PurePosixPath(name)
    assert str(p) == name and not p.is_absolute() and p.parts
    assert all(part not in (".", "..", "") for part in p.parts)
    return p


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("index", type=Path)
    parser.add_argument("--git-responses", type=Path)
    parser.add_argument("--original", type=Path)
    parser.add_argument("--destination", type=Path)
    parser.add_argument("--proof", type=Path, required=True)
    args = parser.parse_args()
    index = json.loads(args.index.read_bytes())
    assert index["schema"] == "hia.canonical-roundtrip.complete-archive.v1"
    raw_parts = []
    for i, row in enumerate(index["parts"]):
        assert row["path"] == f"parts/part-{i:03}.b64"
        assert row["offset"] == sum(map(len, raw_parts))
        if args.git_responses:
            stem = row["path"].replace("/", "-").replace(".", "-")
            post = json.loads((args.git_responses / (stem + "-blob.response.json")).read_bytes())
            assert post.get("isError") is not True
            assert post["structuredContent"]["sha"] == row["git_blob"]
            receipt = json.loads((args.git_responses / (stem + "-receipt.json")).read_bytes())
            assert receipt["status"] == "ACK_FULL_GET_MATCH"
            assert {k: receipt[k] for k in row} == row
            response = json.loads((args.git_responses / (stem + "-readback.response.json")).read_bytes())
            assert response.get("isError") is not True
            text = response["structuredContent"]["content"]
            assert type(text) is str
            encoded = text.encode("utf-8", "strict")
        else:
            encoded = (args.index.parent / safe(row["path"])).read_bytes()
        check(encoded, row)
        assert not any(byte in b" \n\r\t" for byte in encoded)
        raw = base64.b64decode(encoded, validate=True)
        assert base64.b64encode(raw) == encoded
        check(raw, row["decoded"])
        raw_parts.append(raw)
    archive = b"".join(raw_parts)
    check(archive, index["archive"])
    decompressed = gzip.decompress(archive)  # verifies gzip CRC and ISIZE
    objects = {}
    with tarfile.open(fileobj=io.BytesIO(decompressed), mode="r:") as stream:
        for item in stream:
            safe(item.name)
            assert item.isfile() and item.mode == 0o644
            assert item.uid == item.gid == item.mtime == 0
            assert item.name not in objects
            content = stream.extractfile(item).read()
            assert len(content) == item.size
            objects[item.name] = content
    manifest_raw = objects.pop("MANIFEST.json")
    manifest = json.loads(manifest_raw)
    assert manifest["schema"] == "hia.complete-logical-cas.v1"
    files, directories = manifest["files"], manifest["directories"]
    assert len(files) == index["logical_files"]
    assert sum(row["bytes"] for row in files.values()) == index["logical_bytes"]
    assert len(directories) == index["original_directories"]
    assert set(objects) == {"objects/" + row["sha256"] for row in files.values()}
    assert len(objects) == index["unique_objects"]
    for name, mode in directories.items():
        safe(name)
        assert type(mode) is int and 0 <= mode <= 0o7777
    if args.destination:
        args.destination.mkdir(exist_ok=False)
        for name in sorted(directories, key=lambda p: (p.count("/"), p)):
            target = args.destination / safe(name)
            target.mkdir(exist_ok=False)
    for name, row in files.items():
        safe(name)
        assert type(row["mode"]) is int and 0 <= row["mode"] <= 0o7777
        content = objects["objects/" + row["sha256"]]
        check(content, row)
        if args.original:
            target = args.original / name
            original_stat = target.lstat()
            assert stat.S_ISREG(original_stat.st_mode)
            assert stat.S_IMODE(original_stat.st_mode) == row["mode"]
            assert target.read_bytes() == content
        if args.destination:
            target = args.destination / name
            with target.open("xb") as out:
                assert out.write(content) == len(content)
            target.chmod(row["mode"])
            assert target.read_bytes() == content
            assert stat.S_IMODE(target.lstat().st_mode) == row["mode"]
    for name, mode in directories.items():
        if args.original:
            s = (args.original / name).lstat()
            assert stat.S_ISDIR(s.st_mode) and stat.S_IMODE(s.st_mode) == mode
        if args.destination:
            (args.destination / name).chmod(mode)
    proof = {"schema": "hia.canonical-roundtrip.full-custody-readback.v1",
             "status": "FULL_BYTE_MODE_GIT_SHA_READBACK_PASS",
             "source": "actual Git full GET responses" if args.git_responses else "mounted UTF8 part files",
             "archive": pin(archive), "manifest": pin(manifest_raw),
             "parts": len(raw_parts), "unique_objects": len(objects),
             "logical_files": len(files), "logical_bytes": sum(row["bytes"] for row in files.values()),
             "original_directories": len(directories),
             "all_original_files_compared": bool(args.original),
             "destination_restored": str(args.destination) if args.destination else None,
             "source_base_required": manifest["source_base_required"],
             "complete_scope": manifest["complete_scope"],
             "raw_binary_git_upload_claim": False, "product_executed": False}
    raw = (json.dumps(proof, sort_keys=True, indent=2) + "\n").encode()
    with args.proof.open("xb") as out:
        out.write(raw)
    print(raw.decode(), end="")


if __name__ == "__main__":
    main()
