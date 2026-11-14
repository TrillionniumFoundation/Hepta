"""Verify the complete immutable R6/R7 archive; optionally restore to a new directory."""
from pathlib import Path, PurePosixPath
import argparse
import base64
import hashlib
import io
import json
import tarfile


def identity(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
            "git_blob": hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("publication", type=Path)
    parser.add_argument("--destination", type=Path)
    args = parser.parse_args()
    root = args.publication
    index = json.loads((root / "INDEX.json").read_bytes())
    assert index["schema"] == "hia.compact-R6-R7.present-raw-publication.v1"
    archive = bytearray()
    for number, row in enumerate(index["parts"]):
        path = PurePosixPath(row["path"])
        assert not path.is_absolute() and ".." not in path.parts and str(path) == row["path"]
        packet = (root / path).read_bytes()
        assert identity(packet) == {k: row[k] for k in ("bytes", "sha256", "git_blob")}
        part = json.loads(packet)
        assert part["schema"] == "hia.complete-raw.archive-part.v1"
        assert part["number"] == number and part["offset"] == row["offset"] == len(archive)
        assert part["encoding"] == "base64"
        raw = base64.b64decode(part["payload"], validate=True)
        assert identity(raw) == part["decoded"] == row["decoded"]
        archive.extend(raw)
    assert identity(archive) == index["archive"]
    manifest_raw = (root / "RAW-MANIFEST.json").read_bytes()
    assert identity(manifest_raw) == index["manifest"]
    manifest = json.loads(manifest_raw)
    assert manifest["schema"] == "hia.compact-R6-R7.present-originals-CAS.v1"
    files = manifest["files"]
    assert len(files) == index["logical_files"] == 272
    assert sum(row["bytes"] for row in files.values()) == index["logical_bytes"] == 100388719
    aliases = {}
    for name, row in files.items():
        path = PurePosixPath(name)
        assert not path.is_absolute() and ".." not in path.parts and str(path) == name
        assert path.parts[0] in ("R6", "R7") and type(row["mode"]) is int
        assert row["mode"] in (0o600, 0o644)
        aliases.setdefault(row["sha256"], []).append(name)
    assert len(aliases) == manifest["unique_objects"] == 165
    assert sum(row["mode"] == 0o600 for row in files.values()) == 54
    assert sum(row["mode"] == 0o644 for row in files.values()) == 218
    if args.destination:
        args.destination.mkdir(parents=False, exist_ok=False)
    seen = set()
    checked_objects = 0
    unique_bytes = 0
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
        for entry in tar:
            assert entry.isreg() and entry.name not in seen
            assert entry.uid == entry.gid == entry.mtime == 0 and entry.mode == 0o644
            seen.add(entry.name)
            stream = tar.extractfile(entry)
            assert stream is not None
            raw = stream.read()
            assert len(raw) == entry.size
            if entry.name == "RAW-MANIFEST.json":
                assert raw == manifest_raw
                continue
            assert entry.name.startswith("objects/")
            digest = entry.name[8:]
            assert digest in aliases and hashlib.sha256(raw).hexdigest() == digest
            actual = identity(raw)
            for name in aliases[digest]:
                row = files[name]
                assert actual == {k: row[k] for k in ("bytes", "sha256", "git_blob")}
                if args.destination:
                    path = args.destination / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    with path.open("xb") as output:
                        output.write(raw)
                    path.chmod(row["mode"])
                    assert path.read_bytes() == raw and path.stat().st_mode & 0o7777 == row["mode"]
            checked_objects += 1
            unique_bytes += len(raw)
    assert seen == {"RAW-MANIFEST.json"} | {"objects/" + key for key in aliases}
    assert checked_objects == 165 and unique_bytes == 53742672
    print(json.dumps({"status": "PASS", "members": len(seen), "unique_objects": checked_objects,
                      "unique_bytes": unique_bytes, "logical_files": len(files),
                      "logical_bytes": index["logical_bytes"], "archive": index["archive"],
                      "materialized": bool(args.destination), "new_product_executions": 0,
                      "prior_missing_R1_originals_remain_missing": True}, sort_keys=True))


if __name__ == "__main__":
    main()
