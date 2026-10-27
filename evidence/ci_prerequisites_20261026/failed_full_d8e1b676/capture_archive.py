#!/usr/bin/env python3
"""Encode all selected provider files once, without running their contents."""
import argparse
import base64
import hashlib
import io
import json
import lzma
from pathlib import Path
import stat
import tarfile


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def capture(raw_directory, output):
    inventory = json.loads((output / "zip-inventory.json").read_bytes())
    selected = sorted((row for row in inventory["members"] if row["classification"] != "unchanged_from_source"),
                      key=lambda row: row["path"])
    found = {path.relative_to(raw_directory).as_posix() for path in raw_directory.rglob("*") if path.is_file()}
    assert found == {row["path"] for row in selected}
    assert not list(output.glob("run-artifacts.tar.xz.b64*")), "archive already exists"
    buffer = io.BytesIO()
    members = []
    with tarfile.open(fileobj=buffer, mode="w:", format=tarfile.USTAR_FORMAT) as archive:
        for row in selected:
            path = raw_directory / row["path"]
            assert not path.is_symlink() and path.is_file()
            raw = path.read_bytes()
            assert len(raw) == row["bytes"] and sha(raw) == row["sha256"]
            mode = stat.S_IMODE(row["zip_external_attr"] >> 16) or 0o644
            assert mode == stat.S_IMODE(path.stat().st_mode) and 0 <= mode <= 0o777
            info = tarfile.TarInfo(row["path"])
            info.type, info.size, info.mode = tarfile.REGTYPE, len(raw), mode
            info.uid = info.gid = info.mtime = 0
            info.uname = info.gname = ""
            archive.addfile(info, io.BytesIO(raw))
            members.append({"path": row["path"], "bytes": len(raw), "sha256": sha(raw), "mode": mode,
                            "zip_classification": row["classification"]})
    tar_bytes = buffer.getvalue()
    assert len(tar_bytes) <= 256 * 1024 * 1024
    packed = lzma.compress(tar_bytes, format=lzma.FORMAT_XZ,
                          filters=[{"id": lzma.FILTER_LZMA2, "preset": 6, "dict_size": 64 * 1024 * 1024}])
    encoded = base64.b64encode(packed) + b"\n"
    chunks = [encoded[index:index + 3_500_000] for index in range(0, len(encoded), 3_500_000)]
    logical = "run-artifacts.tar.xz.b64"
    parts = []
    for index, chunk in enumerate(chunks):
        name = logical if len(chunks) == 1 else logical + ".part%02d" % (index + 1)
        with (output / name).open("xb") as stream:
            stream.write(chunk)
        parts.append({"path": name, "bytes": len(chunk), "sha256": sha(chunk)})
    manifest = {"schema": "hepta.ci-candidate.archive.v1", "source_commit": inventory["source_commit"],
        "archive": logical, "encoding": "base64", "compression": "xz-preset-6-dict-64MiB", "parts": parts,
        "encoded_bytes": len(encoded), "encoded_sha256": sha(encoded), "decoded_bytes": len(packed),
        "decoded_sha256": sha(packed), "tar_bytes": len(tar_bytes), "tar_sha256": sha(tar_bytes),
        "member_count": len(members), "uncompressed_bytes": sum(row["bytes"] for row in members), "members": members,
        "scope": "all added/changed provider ZIP files retained; only byte-identical source Git files are deduplicated; ZIP modes retained, tar timestamps/owners normalized"}
    with (output / "run-artifacts.manifest.json").open("x") as stream:
        stream.write(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return {key: manifest[key] for key in ("source_commit", "member_count", "uncompressed_bytes", "tar_bytes",
            "tar_sha256", "decoded_bytes", "decoded_sha256", "encoded_bytes", "encoded_sha256", "parts")}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-directory", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(capture(args.raw_directory, args.output), indent=2, sort_keys=True))
