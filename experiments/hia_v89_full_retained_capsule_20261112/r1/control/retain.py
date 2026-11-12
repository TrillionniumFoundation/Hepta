"""Stream this closed full-retained root into one typed, verified custody tar.

No test/native code is imported or executed. Originals stay in place. Symlinks,
FIFOs, sockets and devices are metadata; none is opened or extracted. The
archive and its readback are new custody, not regenerated producer evidence.
"""
from __future__ import annotations

import argparse
import gzip
from hashlib import sha256
import io
import os
from pathlib import Path
import stat
import tarfile
import traceback

from full_common import closed_guardian, copy_original, create, file_record, identity, parent_fd, read_json, require, wire


MANIFEST = ".FULL-RETAINED-TYPED-MANIFEST.json"


def inventory(root):
    rows = []
    def append(path):
        info = path.lstat()
        row = {"path": path.relative_to(root).as_posix(), "identity": list(identity(info))}
        if stat.S_ISREG(info.st_mode):
            row.update(kind="regular", **{key: value for key, value in file_record(path).items()
                                          if key in ("bytes", "sha256")})
        elif stat.S_ISDIR(info.st_mode):
            row["kind"] = "directory"
        elif stat.S_ISLNK(info.st_mode):
            row.update(kind="symlink", target=os.readlink(path))
        elif stat.S_ISFIFO(info.st_mode):
            row["kind"] = "fifo"
        else:
            row.update(kind="special", rdev=info.st_rdev, no_open_performed=True)
        require(list(identity(path.lstat())) == row["identity"], "member changed while catalogued")
        rows.append(row)
    def walk_error(error):
        raise error
    for directory, dirs, files in os.walk(root, followlinks=False, onerror=walk_error):
        dirs.sort()
        files.sort()
        directory = Path(directory)
        append(directory)
        for name in list(dirs):
            path = directory / name
            if not stat.S_ISDIR(path.lstat().st_mode):
                dirs.remove(name)
                append(path)
        for name in files:
            append(directory / name)
    require(len({row["path"] for row in rows}) == len(rows)
            and all(row["path"] != MANIFEST for row in rows), "duplicate/reserved custody path")
    for row in rows:
        require(list(identity((root / row["path"]).lstat())) == row["identity"],
                "member changed during complete inventory")
    return sorted(rows, key=lambda row: row["path"])


class HashingReader:
    def __init__(self, stream):
        self.stream, self.digest, self.count = stream, sha256(), 0
    def read(self, size=-1):
        raw = self.stream.read(size)
        self.digest.update(raw)
        self.count += len(raw)
        return raw


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--public", type=Path, required=True)
    args = parser.parse_args()
    root, public = args.root, args.public
    require(root.is_absolute() and public.is_absolute() and not public.is_relative_to(root)
            and not root.is_relative_to(public), "custody output must be independent of the owned root")
    setup, _ = read_json(public / "SETUP.json")
    require(setup["root"] == str(root) and setup["public"] == str(public), "custody setup differs")
    request, request_pin = read_json(public / "GUARDIAN-REQUEST.json")
    guardian, guardian_pin = read_json(root / "guard/guardian.json")
    closed_guardian(guardian, request)
    # Keep the actual closed boundary independently of the whole-tree
    # archive, so an unreadable supplied file cannot hide the original
    # owner result. Each fixed original is attempted, never truncated.
    original_directory = public / "qualification-guardian-originals"
    original_directory.mkdir(mode=0o700, exist_ok=False)
    originals = {"schema": "hia.v87.closed-guardian-original-copies.v1", "files": {}, "errors": {}}
    expected = {"guardian.json": guardian_pin, "request.json": request_pin}
    for name in ("guardian.json", "request.json", "child.stdout.log", "child.stderr.log"):
        try:
            row = copy_original(root / "guard" / name, original_directory / name, expected.get(name))
            if name in {"child.stdout.log", "child.stderr.log"}:
                require(row["original"]["sha256"] == guardian["logs"][str(root / "guard" / name)],
                        "original guardian stream differs from its report")
            originals["files"][name] = row
        except BaseException:
            originals["errors"][name] = traceback.format_exc()
    create(original_directory / "COPIES.json", wire(originals))
    rows = inventory(root)
    manifest = wire({"schema": "hia.v87.full-retained-typed-custody.v1", "originals": rows,
                     "closed_original_guardian": guardian_pin, "original_guardian_request": request_pin,
                     "all_regular_bytes_selected": True, "special_nodes_are_metadata": True,
                     "tar_mtime_is_whole_seconds_original_ns_retained_in_manifest": True,
                     "direct_extraction_authorized": False, "product_execution_performed": False})
    catalog_pin = create(public / "ORIGINAL-CATALOG.json", manifest)
    destination = public / "full-retained-originals.tar.gz"
    expected = {row["path"]: row for row in rows if row["path"] != "." and row["kind"] != "special"}
    with parent_fd(destination) as (parent, name, stable):
        descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o600, dir_fd=parent)
        with os.fdopen(descriptor, "wb", buffering=0) as output:
            with gzip.GzipFile(fileobj=output, mode="wb", filename="", mtime=0, compresslevel=1) as compressed:
                with tarfile.open(fileobj=compressed, mode="w|", format=tarfile.PAX_FORMAT) as archive:
                    for relative, row in expected.items():
                        path = root / relative
                        observed = path.lstat()
                        require(list(identity(observed)) == row["identity"], "original changed before archive")
                        item = tarfile.TarInfo(relative)
                        item.mode, item.uid, item.gid = stat.S_IMODE(observed.st_mode), observed.st_uid, observed.st_gid
                        item.uname = item.gname = ""
                        item.mtime = observed.st_mtime_ns // 1000000000
                        if row["kind"] == "regular":
                            item.type, item.size = tarfile.REGTYPE, row["bytes"]
                            with parent_fd(path) as (original_parent, original_name, original_stable):
                                descriptor = os.open(original_name, os.O_RDONLY | os.O_NOFOLLOW
                                    | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=original_parent)
                                with os.fdopen(descriptor, "rb", buffering=0) as original:
                                    require(list(identity(os.fstat(original.fileno()))) == row["identity"],
                                            "original descriptor identity differs")
                                    reader = HashingReader(original)
                                    archive.addfile(item, reader)
                                    require(reader.count == row["bytes"] and reader.digest.hexdigest() == row["sha256"]
                                            and list(identity(os.fstat(original.fileno()))) == row["identity"],
                                            "archived bytes differ from actual inventory")
                                    original_stable()
                        elif row["kind"] == "directory":
                            item.type = tarfile.DIRTYPE
                            archive.addfile(item)
                        elif row["kind"] == "symlink":
                            require(os.readlink(path) == row["target"], "link metadata changed")
                            item.type, item.linkname = tarfile.SYMTYPE, row["target"]
                            archive.addfile(item)
                        else:
                            require(row["kind"] == "fifo", "unknown typed member")
                            item.type = tarfile.FIFOTYPE
                            archive.addfile(item)
                        require(list(identity(path.lstat())) == row["identity"], "original changed after archive")
                    item = tarfile.TarInfo(MANIFEST)
                    item.mode, item.size = 0o400, len(manifest)
                    archive.addfile(item, io.BytesIO(manifest))
            output.flush()
            os.fchmod(output.fileno(), 0o400)
            os.fsync(output.fileno())
            stable()
            os.fsync(parent)

    archive_pin = file_record(destination)
    seen, regular_bytes = set(), 0
    with tarfile.open(destination, mode="r|gz") as archive:
        for item in archive:
            require(item.name not in seen, "duplicate archive member")
            seen.add(item.name)
            if item.name == MANIFEST:
                require(item.isfile() and item.size == len(manifest)
                        and archive.extractfile(item).read() == manifest, "typed manifest bytes differ")
                continue
            require(item.name in expected, "archive contains an unselected path")
            row = expected[item.name]
            original = row["identity"]
            require(item.mode == stat.S_IMODE(original[2]) and item.uid == original[3]
                    and item.gid == original[4] and item.mtime == original[7] // 1000000000,
                    "archived type metadata differs")
            if row["kind"] == "regular":
                require(item.isfile() and item.size == row["bytes"], "regular archive size/type differs")
                stream, digest, count = archive.extractfile(item), sha256(), 0
                for block in iter(lambda: stream.read(1 << 20), b""):
                    digest.update(block)
                    count += len(block)
                require(count == row["bytes"] and digest.hexdigest() == row["sha256"],
                        "complete archived original readback differs")
                regular_bytes += count
            elif row["kind"] == "directory":
                require(item.isdir(), "directory type differs")
            elif row["kind"] == "symlink":
                require(item.issym() and item.linkname == row["target"], "symlink metadata differs")
            else:
                require(item.isfifo(), "FIFO metadata differs")
    require(seen == set(expected) | {MANIFEST}, "complete typed archive population differs")
    require(inventory(root) == rows and file_record(destination) == archive_pin,
            "original namespace/bytes or sealed archive changed during readback")
    report = {"schema": "hia.v87.full-retained-custody-result.v1",
              "status": "COMPLETE_TYPED_ORIGINALS_PENDING_CUSTODY_GUARDIAN",
              "archive": archive_pin, "catalog": catalog_pin, "regular_bytes": regular_bytes,
              "original_members": len(rows), "archive_members": len(seen),
              "special_metadata_only": sum(row["kind"] == "special" for row in rows),
              "all_regular_bytes_read_back": True, "original_namespace_preserved": True,
              "whole_native_delivery_qualified": False, "product_execution_performed": False}
    create(public / "CUSTODY.json", wire(report))


if __name__ == "__main__":
    main()
