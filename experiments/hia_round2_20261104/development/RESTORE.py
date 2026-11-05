"""Restore the ordered parts after verifying every original byte hash."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import tarfile
import tempfile

def restore(source, target):
    source, target = Path(source).resolve(), Path(target).resolve()
    manifest = json.loads((source / "MANIFEST.json").read_text())
    target.mkdir(parents=True, exist_ok=False)
    archive_hash = hashlib.sha256()
    expected = {row["path"]: row for row in manifest["members"]}
    if len(expected) != len(manifest["members"]):
        raise ValueError("duplicate manifest path")
    seen = set()
    with tempfile.TemporaryFile() as joined:
        for row in manifest["parts"]:
            raw = (source / row["path"]).read_bytes()
            if len(raw) != row["bytes"] or hashlib.sha256(raw).hexdigest() != row["sha256"]:
                raise ValueError("part identity mismatch: " + row["path"])
            joined.write(raw); archive_hash.update(raw)
        if joined.tell() != manifest["archive"]["bytes"] or archive_hash.hexdigest() != manifest["archive"]["sha256"]:
            raise ValueError("archive identity mismatch")
        joined.seek(0)
        with tarfile.open(fileobj=joined, mode="r:xz") as archive:
            for member in archive:
                path = PurePosixPath(member.name)
                if path.is_absolute() or ".." in path.parts or not member.isfile() or member.name in seen:
                    raise ValueError("unsafe or duplicate archive member")
                row = expected.get(member.name)
                if row is None or member.size != row["bytes"]:
                    raise ValueError("unexpected archive member")
                raw = archive.extractfile(member).read()
                if hashlib.sha256(raw).hexdigest() != row["sha256"]:
                    raise ValueError("member byte mismatch: " + member.name)
                destination = target / member.name
                destination.parent.mkdir(parents=True, exist_ok=True)
                with destination.open("xb") as out:
                    out.write(raw)
                destination.chmod(row["mode"])
                if hashlib.sha256(destination.read_bytes()).hexdigest() != row["sha256"]:
                    raise ValueError("restored file mismatch")
                seen.add(member.name)
    if seen != set(expected):
        raise ValueError("archive member set differs")
    return {"passed": True, "files": len(seen), "bytes": sum(x["bytes"] for x in expected.values()),
            "archive_sha256": archive_hash.hexdigest(), "every_file_read_back": True}

if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source", default=str(Path(__file__).resolve().parent))
    p.add_argument("--target", required=True)
    a = p.parse_args()
    print(json.dumps(restore(a.source, a.target), indent=2, sort_keys=True))
