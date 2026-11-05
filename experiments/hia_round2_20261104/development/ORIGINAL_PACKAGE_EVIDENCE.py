"""Archive selected completed evidence without rerunning or rescoring it.

This is a delivery utility, outside the frozen implementation checkout. It
retains exact bytes, rejects special files, records each original hash, splits
the archive for GitHub's blob API, and restores every member for verification.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import tarfile
import time


RESTORE = r'''"""Restore the ordered parts after verifying every original byte hash."""
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
'''


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def git_blob(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def write(path, value):
    with path.open("x") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def run(base, output, inputs, *, title, prefix, part_bytes=750000):
    started = time.monotonic_ns()
    base, output = Path(base).resolve(), Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    public = output / "public"; public.mkdir()
    files, empty_directories = {}, []
    for item in inputs:
        relative = PurePosixPath(item)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("input must be a safe relative path")
        path = base / item
        if path.is_symlink() or not path.exists():
            raise ValueError("missing/symlink input " + item)
        candidates = [path] if path.is_file() else sorted(path.rglob("*"))
        if path.is_dir() and not candidates:
            empty_directories.append(item)
        for candidate in candidates:
            st = candidate.lstat()
            if stat.S_ISDIR(st.st_mode):
                continue
            if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
                raise ValueError("special or multiply linked input " + str(candidate))
            relative = str(candidate.relative_to(base))
            if candidate.is_relative_to(output):
                raise ValueError("recursive output selection")
            raw = candidate.read_bytes()
            after = candidate.stat()
            if (st.st_size, st.st_mtime_ns, st.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino):
                raise ValueError("input changed while reading")
            files[relative] = {"path": relative, "bytes": len(raw), "sha256": digest(raw),
                               "git_blob_sha": git_blob(raw), "mode": stat.S_IMODE(st.st_mode),
                               "original_mtime_ns": st.st_mtime_ns}
    rows = sorted(files.values(), key=lambda row: row["path"])
    archive_path = output / "evidence.tar.xz"
    compression_started = time.monotonic_ns()
    with tarfile.open(archive_path, mode="x:xz", preset=6) as archive:
        for row in rows:
            raw = (base / row["path"]).read_bytes()
            if digest(raw) != row["sha256"]:
                raise ValueError("input changed during packaging " + row["path"])
            info = tarfile.TarInfo(row["path"])
            info.size, info.mode, info.mtime = len(raw), row["mode"], 0
            info.uid = info.gid = 0; info.uname = info.gname = ""
            archive.addfile(info, io.BytesIO(raw))
    compression_ns = time.monotonic_ns() - compression_started
    archive_raw = archive_path.read_bytes()
    parts = []
    for index, offset in enumerate(range(0, len(archive_raw), part_bytes)):
        raw = archive_raw[offset:offset + part_bytes]
        name = "evidence.tar.xz.part-" + str(index).zfill(5)
        (public / name).write_bytes(raw)
        parts.append({"path": name, "bytes": len(raw), "sha256": digest(raw), "git_blob_sha": git_blob(raw)})
    manifest = {"schema": "hepta.round2.exact-evidence-package.v1", "title": title,
                "original_base": str(base), "selection": inputs, "empty_selected_directories": empty_directories,
                "not_a_new_experiment": True, "no_result_reexecution_or_rescoring": True,
                "archive": {"format": "tar.xz", "bytes": len(archive_raw), "sha256": digest(archive_raw)},
                "members": rows, "parts": parts}
    write(public / "MANIFEST.json", manifest)
    (public / "RESTORE.py").write_text(RESTORE)
    (public / "PARTS.sha256").write_text("".join(row["sha256"] + "  " + row["path"] + "\n" for row in parts))
    restore_started = time.monotonic_ns()
    namespace = {"__name__": "delivery_restore"}
    exec(compile(RESTORE, str(public / "RESTORE.py"), "exec"), namespace)
    verified = namespace["restore"](public, output / "restored")
    verified["restore_wall_ns"] = time.monotonic_ns() - restore_started
    write(public / "RESTORE_VERIFICATION.json", verified)
    (public / "README.md").write_text(
        "# " + title + "\n\n"
        "This package preserves the selected completed source-development evidence, including failures. "
        "It does not rerun, reclassify or combine experimental cohorts. Source commits and scopes remain in the original receipts.\n\n"
        "Download all files in this directory, then run `python3 RESTORE.py --target <new-empty-directory>`. "
        "The restorer checks each part, the complete archive, every member and every restored file.\n\n"
        "Human work, energy and any unobserved historical costs are unknown, never inferred to be zero. "
        "Delivery compression and verification costs are separate from study costs.\n")
    write(public / "DELIVERY_COST.json", {"schema": "hepta.round2.delivery-cost.v1", "compression_wall_ns": compression_ns,
          "restore_wall_ns": verified["restore_wall_ns"], "observed_packaging_wall_ns": time.monotonic_ns() - started,
          "compression_and_restore_nested_in_packaging": True, "not_added_to_benchmark_runtime": True})
    publications = []
    for path in sorted(public.iterdir()):
        raw = path.read_bytes()
        publications.append({"path": prefix.rstrip("/") + "/" + path.name, "local_path": str(path),
                             "bytes": len(raw), "sha256": digest(raw), "git_blob_sha": git_blob(raw),
                             "mode": "100644", "type": "blob"})
    result = {"schema": "hepta.round2.publication-input.v1", "public_files": publications,
              "original_files": len(rows), "original_bytes": sum(x["bytes"] for x in rows),
              "archive": manifest["archive"], "restoration": verified}
    write(output / "PUBLICATION_MANIFEST.json", result)
    print(json.dumps({k: v for k, v in result.items() if k != "public_files"}, sort_keys=True))
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--input-list", required=True)
    parser.add_argument("--title", required=True)
    parser.add_argument("--prefix", required=True)
    args = parser.parse_args()
    run(args.base, args.output, json.loads(Path(args.input_list).read_text()), title=args.title, prefix=args.prefix)
