"""Restore the ordered parts after verifying every original byte hash."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import tarfile
import tempfile

def restore_files(source, target):
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


def restore(source, target):
    import os, re, stat
    source, target = Path(source).resolve(), Path(target).resolve()
    manifest_path = source / "MANIFEST.json"
    if manifest_path.is_symlink() or manifest_path.stat().st_nlink != 1:
        raise ValueError("linked manifest")
    manifest = json.loads(manifest_path.read_bytes())
    names = set()
    for index, row in enumerate(manifest["parts"]):
        expected = "evidence.tar.xz.part-" + str(index).zfill(5)
        if row["path"] != expected or row["path"] in names:
            raise ValueError("unsafe or duplicate/nonsequential part name")
        names.add(row["path"])
        p = source / row["path"]
        if p.is_symlink() or not p.is_file() or p.stat().st_nlink != 1:
            raise ValueError("linked or nonregular part")
        if type(row["bytes"]) is not int or not 0 < row["bytes"] <= 750000:
            raise ValueError("part bound")
        if index + 1 < len(manifest["parts"]) and row["bytes"] != 750000:
            raise ValueError("short nonfinal part")
        if re.fullmatch("[0-9a-f]{64}", row["sha256"]) is None:
            raise ValueError("part digest shape")
    if not names:
        raise ValueError("empty part inventory")
    dirs = {}
    for row in manifest["directories"]:
        name = row["path"]; p = PurePosixPath(name)
        if (p.is_absolute() or str(p) != name or ".." in p.parts or name in ("", ".")
                or "\\" in name or "\x00" in name or name in dirs
                or type(row["mode"]) is not int or not 0 <= row["mode"] <= 0o777):
            raise ValueError("invalid directory inventory")
        dirs[name] = row
    expected = {row["path"]: row for row in manifest["members"]}
    if set(dirs) & set(expected):
        raise ValueError("file/directory collision")
    result = restore_files(source, target)
    for name in sorted(dirs, key=lambda n: (len(PurePosixPath(n).parts), n)):
        (target / name).mkdir(parents=True, exist_ok=True)
    for name in sorted(dirs, key=lambda n: (-len(PurePosixPath(n).parts), n)):
        (target / name).chmod(dirs[name]["mode"])
    found_files, found_dirs, inodes = set(), set(), set()
    for path in target.rglob("*"):
        name = str(path.relative_to(target)); s = path.lstat()
        if stat.S_ISDIR(s.st_mode):
            if name not in dirs or stat.S_IMODE(s.st_mode) != dirs[name]["mode"]:
                raise ValueError("restored directory differs")
            found_dirs.add(name)
        else:
            if not stat.S_ISREG(s.st_mode) or s.st_nlink != 1 or name not in expected:
                raise ValueError("nonregular/unexpected restored file")
            row = expected[name]; raw = path.read_bytes()
            if (len(raw) != row["bytes"] or hashlib.sha256(raw).hexdigest() != row["sha256"]
                    or stat.S_IMODE(s.st_mode) != row["mode"]):
                raise ValueError("restored file bytes/mode differ")
            ino = (s.st_dev, s.st_ino)
            if ino in inodes:
                raise ValueError("restored files share inode")
            inodes.add(ino); found_files.add(name)
    if found_files != set(expected) or found_dirs != set(dirs):
        raise ValueError("restored file/directory set differs")
    result.update(directories=len(dirs), independent_file_inodes=len(inodes),
                  target_historical_mtime_restored=False,
                  original_times_retained_in_manifest=True,
                  relative_parts_only=True)
    return result


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source", default=str(Path(__file__).resolve().parent))
    p.add_argument("--target", required=True)
    a = p.parse_args()
    print(json.dumps(restore(a.source, a.target), indent=2, sort_keys=True))
