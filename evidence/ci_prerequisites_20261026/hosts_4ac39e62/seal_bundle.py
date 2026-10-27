#!/usr/bin/env python3
"""Seal only the new host evidence directory and immutable source/ZIP bytes.

Build the small compressed archive once with --staging. Later invocations update
only sidecar hashes; they preserve the original archive bytes.
"""
import argparse
import base64
import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def seal(root, staging=None):
    relation = json.loads((root / "source-relationship.json").read_bytes())
    identities = json.loads((root / "zip-identities.json").read_bytes())
    manifest_path = root / "MANIFEST.json"
    encoded_path = root / "host-records.tar.gz.base64"
    if staging is not None:
        if encoded_path.exists():
            raise FileExistsError("preserve the existing one-time compressed archive")
        contents = {row["archive_member"]: (staging / "lf" / row["git_path"]).read_bytes()
                    for row in relation["files"]}
        for row in identities:
            data = (staging / f"{row['artifact_id']}.zip").read_bytes()
            assert len(data) == row["bytes"] and sha(data) == row["sha256"]
            contents[f"host-zips/{row['artifact_id']}.zip"] = data
        raw = io.BytesIO()
        members = []
        with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for name, data in sorted(contents.items()):
                member = tarfile.TarInfo(name)
                member.size, member.mode, member.mtime, member.uid, member.gid = len(data), 0o644, 0, 0, 0
                archive.addfile(member, io.BytesIO(data))
                members.append({"path": name, "bytes": len(data), "sha256": sha(data)})
        tar = raw.getvalue()
        packed = gzip.compress(tar, compresslevel=6, mtime=0)
        encoded = base64.encodebytes(packed)
        assert len(encoded) <= 3_500_000
        encoded_path.write_bytes(encoded)
        manifest = {"schema": "hepta.self-contained-host-archive.v2", "source_commit": relation["source_commit"],
                    "source_tree": relation["source_tree"], "member_count": len(members), "members": members,
                    "archive": {"path": encoded_path.name, "compression": "gzip level 6, one operation",
                                "encoded_bytes": len(encoded), "encoded_sha256": sha(encoded),
                                "decoded_bytes": len(packed), "sha256": sha(packed),
                                "tar_bytes": len(tar), "tar_sha256": sha(tar)}}
    else:
        manifest = json.loads(manifest_path.read_bytes())
        assert sha(encoded_path.read_bytes()) == manifest["archive"]["encoded_sha256"]
    excluded = {"MANIFEST.json", "archive-verification.json", encoded_path.name}
    sidecars = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        name = path.relative_to(root).as_posix()
        assert not path.is_symlink() and "__pycache__" not in path.parts and not name.endswith(".pyc")
        if name in excluded:
            continue
        raw = path.read_bytes()
        sidecars.append({"path": name, "bytes": len(raw), "sha256": sha(raw)})
    manifest["sidecar_files"] = sidecars
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"archive": manifest["archive"], "members": manifest["member_count"],
                      "sidecars": len(sidecars)}, sort_keys=True))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--staging", type=Path)
    args = parser.parse_args()
    seal(args.root, args.staging)
