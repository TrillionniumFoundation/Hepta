#!/usr/bin/env python3
"""Preserve one frozen experimental tree without moving or hardlinking inputs.

The archive is not a filesystem snapshot: the caller must first freeze all
writers. Hashes, tar's change detection, and a final metadata/path-set comparison
detect accidental writes. No source or restored program is executed.
"""

from __future__ import annotations

import argparse
import decimal
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tarfile
import time
import traceback

CHUNK = 1024 * 1024
SCHEMA = "hepta.hia.linux.full-root-preservation.v1"


def emit(event: str, **fields: object) -> None:
    print(json.dumps({"event": event, "unix": time.time(), **fields}, sort_keys=True), flush=True)


def write_new(path: Path, value: object) -> None:
    data = json.dumps(value, sort_keys=True, indent=2).encode() + b"\n"
    with path.open("xb") as out:
        out.write(data)
        out.flush()
        os.fsync(out.fileno())


def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(CHUNK), b""):
            digest.update(block)
    return digest.hexdigest()


def identity(path: Path) -> dict:
    return {"path": str(path), "bytes": path.stat().st_size, "sha256": sha(path)}


def file_stat(path: Path) -> dict:
    info = path.lstat()
    if stat.S_ISREG(info.st_mode):
        kind = "file"
    elif stat.S_ISDIR(info.st_mode):
        kind = "directory"
    elif stat.S_ISLNK(info.st_mode):
        kind = "symlink"
    else:
        raise RuntimeError(f"unsupported special input: {path}")
    return {
        "kind": kind, "mode": stat.S_IMODE(info.st_mode), "uid": info.st_uid,
        "gid": info.st_gid, "bytes": info.st_size if kind == "file" else 0,
        "mtime_ns": info.st_mtime_ns, "ctime_ns": info.st_ctime_ns,
        "device": info.st_dev, "inode": info.st_ino, "nlink": info.st_nlink,
        "allocated_bytes": info.st_blocks * 512,
        "symlink_target": os.readlink(path) if kind == "symlink" else None,
    }


def paths(root: Path):
    yield root
    stack = [root]
    while stack:
        parent = stack.pop()
        with os.scandir(parent) as entries:
            children = sorted(entries, key=lambda entry: entry.name)
        dirs = []
        for entry in children:
            yield Path(entry.path)
            if entry.is_dir(follow_symlinks=False):
                dirs.append(Path(entry.path))
        stack.extend(reversed(dirs))


def freeze(root: Path, output: Path) -> tuple[dict, dict]:
    inventory = {}
    totals = {"entries": 0, "files": 0, "directories": 0, "symlinks": 0,
              "apparent_bytes": 0, "allocated_regular_bytes": 0}
    count = 0
    started = time.monotonic()
    with (output / "MEMBERS.nul").open("xb") as names:
        with (output / "INVENTORY.jsonl.gz").open("xb") as raw:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw, compresslevel=1, mtime=0) as rows:
                for path in paths(root):
                    record = file_stat(path)
                    name = str(path).lstrip("/")
                    if record["kind"] == "file":
                        record["sha256"] = sha(path)
                        if file_stat(path) != {k: v for k, v in record.items() if k != "sha256"}:
                            raise RuntimeError(f"input changed while hashing: {path}")
                        totals["files"] += 1
                        totals["apparent_bytes"] += record["bytes"]
                        totals["allocated_regular_bytes"] += record["allocated_bytes"]
                    elif record["kind"] == "directory":
                        totals["directories"] += 1
                    else:
                        totals["symlinks"] += 1
                    record["member"] = name
                    inventory[name] = record
                    names.write(os.fsencode(name) + b"\0")
                    rows.write(json.dumps(record, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode() + b"\n")
                    count += 1
                    if count % 10000 == 0:
                        emit("inventory_progress", entries=count, bytes=totals["apparent_bytes"])
                totals["entries"] = count
            raw.flush()
            os.fsync(raw.fileno())
        names.flush()
        os.fsync(names.fileno())
    emit("inventory_frozen", totals=totals, elapsed_seconds=time.monotonic() - started)
    return inventory, totals


def compressor() -> tuple[list[str], list[str], str]:
    if shutil.which("zstd"):
        return [shutil.which("zstd"), "-T1", "-1", "-c"], [shutil.which("zstd"), "-d", "-c"], ".tar.zst"
    if shutil.which("gzip"):
        return [shutil.which("gzip"), "-1", "-n", "-c"], [shutil.which("gzip"), "-d", "-c"], ".tar.gz"
    raise RuntimeError("neither zstd nor gzip is installed")


def archive(output: Path, encode: list[str], suffix: str) -> tuple[Path, dict]:
    partial = output / ("FULL_ROOT" + suffix + ".partial")
    tar_command = [shutil.which("tar"), "--directory=/", "--format=pax", "--numeric-owner",
                   "--hard-dereference", "--pax-option=delete=atime,delete=ctime",
                   "--no-recursion", "--null", "--verbatim-files-from",
                   "--files-from=" + str(output / "MEMBERS.nul"), "-cf", "-"]
    if not tar_command[0]:
        raise RuntimeError("GNU tar unavailable")
    version = subprocess.run([tar_command[0], "--version"], check=True, capture_output=True, text=True).stdout
    if "GNU tar" not in version:
        raise RuntimeError("GNU tar is required")
    emit("archive_start", tar=tar_command, compressor=encode, partial=str(partial))
    started = time.time()
    with (output / "tar.stderr").open("xb") as tar_error, (output / "compressor.stderr").open("xb") as encode_error, partial.open("xb") as target:
        tar_process = subprocess.Popen(tar_command, stdout=subprocess.PIPE, stderr=tar_error)
        try:
            encode_process = subprocess.Popen(encode, stdin=tar_process.stdout, stdout=target, stderr=encode_error)
            tar_process.stdout.close()
            encode_rc = encode_process.wait()
            tar_rc = tar_process.wait()
        except BaseException:
            tar_process.terminate()
            tar_process.wait()
            raise
        target.flush()
        os.fsync(target.fileno())
    receipt = {"tar_argv": tar_command, "compressor_argv": encode, "tar_version": version,
               "tar_returncode": tar_rc, "compressor_returncode": encode_rc,
               "started_unix": started, "completed_unix": time.time(), "partial_bytes": partial.stat().st_size}
    write_new(output / "ARCHIVE_COMMAND.json", receipt)
    if tar_rc != 0 or encode_rc != 0:
        raise RuntimeError(f"archive pipeline failed: tar={tar_rc}, compressor={encode_rc}")
    emit("archive_written", bytes=partial.stat().st_size, elapsed_seconds=time.time() - started)
    return partial, receipt


def verify_stream(partial: Path, decode: list[str], inventory: dict, output: Path) -> dict:
    started = time.time()
    seen = set()
    checked_bytes = 0
    command = decode + [str(partial)]
    with (output / "decompressor.stderr").open("xb") as error:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=error)
        try:
            with tarfile.open(fileobj=process.stdout, mode="r|") as stream:
                for member in stream:
                    name = member.name.rstrip("/")
                    if name not in inventory or name in seen:
                        raise RuntimeError(f"unexpected or duplicate archive member: {name}")
                    expected = inventory[name]
                    kind = "file" if member.isfile() else "directory" if member.isdir() else "symlink" if member.issym() else "unsupported"
                    actual = {"kind": kind, "mode": member.mode, "uid": member.uid, "gid": member.gid,
                              "bytes": member.size if kind == "file" else 0,
                              "symlink_target": member.linkname if kind == "symlink" else None}
                    for key, value in actual.items():
                        if expected[key] != value:
                            raise RuntimeError(f"archive metadata mismatch: {name}: {key}")
                    mtime = member.pax_headers.get("mtime", str(member.mtime))
                    if int(decimal.Decimal(mtime) * 1000000000) != expected["mtime_ns"]:
                        raise RuntimeError(f"archive mtime mismatch: {name}")
                    if kind == "file":
                        digest = hashlib.sha256()
                        data = stream.extractfile(member)
                        if data is None:
                            raise RuntimeError(f"unreadable archive member: {name}")
                        for block in iter(lambda: data.read(CHUNK), b""):
                            digest.update(block)
                            checked_bytes += len(block)
                        if digest.hexdigest() != expected["sha256"]:
                            raise RuntimeError(f"archive content mismatch: {name}")
                    seen.add(name)
                    if len(seen) % 10000 == 0:
                        emit("verify_progress", entries=len(seen), bytes=checked_bytes)
            # Tar end markers can precede compression end: drain so CRC/frame checks run.
            trailing = process.stdout.read()
            if trailing.strip(b"\0"):
                raise RuntimeError("non-zero data after tar end markers")
            rc = process.wait()
            if rc:
                raise RuntimeError(f"decompression failed: {rc}")
        except BaseException:
            process.terminate()
            process.wait()
            raise
        finally:
            process.stdout.close()
    if set(inventory) != seen:
        raise RuntimeError(f"missing archive members: {len(set(inventory) - seen)}")
    result = {"status": "PASS", "independent_reader": "Python tarfile streaming + hashlib.sha256",
              "entries": len(seen), "file_bytes_verified": checked_bytes, "decompressor_argv": command,
              "decompressor_returncode": rc, "started_unix": started, "completed_unix": time.time(),
              "verified_fields": ["exact member set", "type", "mode", "uid", "gid", "size", "mtime_ns", "symlink target", "regular-file sha256"],
              "xattrs_acls_claimed": False, "hardlink_entries": 0}
    write_new(output / "STREAM_VERIFICATION.json", result)
    emit("archive_stream_verified", entries=len(seen), bytes=checked_bytes)
    return result


def recheck(root: Path, inventory: dict) -> None:
    names = set()
    for path in paths(root):
        name = str(path).lstrip("/")
        names.add(name)
        if name not in inventory:
            raise RuntimeError(f"source gained a path: {path}")
        expected = {key: value for key, value in inventory[name].items() if key not in ("member", "sha256")}
        if file_stat(path) != expected:
            raise RuntimeError(f"source metadata changed: {path}")
    if names != set(inventory):
        raise RuntimeError("source lost paths during preservation")


def program_counts(root: Path, inventory: dict) -> dict:
    result = {}
    for name in ("hia-original-r3", "hia-o3-r1", "hia-os-r1"):
        prefix = str(root / name / "hia-programs").lstrip("/") + "/"
        programs = [row for member, row in inventory.items() if member.startswith(prefix) and member.endswith(".hia.json.gz")]
        dependencies = [row for member, row in inventory.items() if member.startswith(prefix) and member.endswith(".d.gz")]
        indices = [row for member, row in inventory.items() if member.startswith(prefix + "index/") and member.endswith(".json")]
        result[name] = {"programs": len(programs), "compressed_program_bytes": sum(row["bytes"] for row in programs),
                        "dependencies": len(dependencies), "indices": len(indices)}
        if len(programs) != 3029 or len(indices) != 3029:
            raise RuntimeError(f"required HIA store count mismatch: {name}: {result[name]}")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--expected-freeze-sha256", required=True)
    parser.add_argument("--freeze-marker", required=True, type=Path)
    parser.add_argument("--dependency-manifest", required=True, type=Path)
    parser.add_argument("--fixture", action="store_true", help="test-only: skip Linux-specific HIA program counts")
    args = parser.parse_args()
    root, output = args.root.absolute(), args.output.absolute()
    if not root.is_dir() or root.is_symlink() or root == Path("/"):
        raise RuntimeError("invalid source root")
    if output == root or root in output.parents or output in root.parents:
        raise RuntimeError("source and output must be disjoint")
    if root.resolve() not in args.freeze_marker.resolve().parents:
        raise RuntimeError("freeze marker must be inside source root")
    if sha(args.freeze_marker) != args.expected_freeze_sha256:
        raise RuntimeError("freeze marker identity mismatch")
    output.mkdir(parents=True, exist_ok=False)
    os.nice(10)
    started = time.time()
    pid = os.getpid()
    boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    owner = {"pid": pid, "start_ticks": Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19],
             "boot_id": boot_id, "source_root": str(root), "output": str(output), "started_unix": started}
    write_new(output / "OWNER.json", owner)
    try:
        inventory, totals = freeze(root, output)
        stores = {} if args.fixture else program_counts(root, inventory)
        git_alternates = []
        for name in inventory:
            if name.endswith("/objects/info/alternates") and inventory[name]["kind"] == "file":
                path = Path("/") / name
                if inventory[name]["bytes"] > 65536:
                    raise RuntimeError(f"unexpectedly large Git alternates file: {path}")
                git_alternates.append({"identity": identity(path), "text": path.read_text()})
        write_new(output / "GIT_ALTERNATES.json", {"schema": SCHEMA, "references": git_alternates,
                  "note": "Source bytes are archived. External Git objects are not implicitly dereferenced or bundled."})
        volume = os.statvfs(output)
        available = volume.f_bavail * volume.f_frsize
        required = totals["apparent_bytes"] + totals["entries"] * 8192 + max(1024**3, totals["apparent_bytes"] // 20)
        if available < required:
            raise RuntimeError(f"insufficient conservative free capacity: {available} < {required}")
        encode, decode, suffix = compressor()
        partial, command = archive(output, encode, suffix)
        verification = verify_stream(partial, decode, inventory, output)
        recheck(root, inventory)
        compressed_sha = sha(partial)
        final = partial.with_name(partial.name.removesuffix(".partial"))
        os.rename(partial, final)
        directory_fd = os.open(output, os.O_DIRECTORY | os.O_RDONLY)
        os.fsync(directory_fd)
        os.close(directory_fd)
        result = {"schema": SCHEMA, "status": "PASS", "source_root": str(root), "output": str(output),
                  "archive": {"path": str(final), "bytes": final.stat().st_size, "sha256": compressed_sha},
                  "inventory": identity(output / "INVENTORY.jsonl.gz"), "member_list": identity(output / "MEMBERS.nul"),
                  "source_totals": totals, "hia_program_stores": stores,
                  "source_unchanged_after_archive": True, "stream_verification": identity(output / "STREAM_VERIFICATION.json"),
                  "archive_command": identity(output / "ARCHIVE_COMMAND.json"),
                  "freeze_marker": identity(args.freeze_marker), "dependency_manifest": identity(args.dependency_manifest),
                  "git_alternates": identity(output / "GIT_ALTERNATES.json"),
                  "preservation_script": identity(Path(__file__).resolve()),
                  "available_bytes_before_archive": available, "required_conservative_free_bytes": required,
                  "source_hardlinks_created": False, "source_files_moved": False, "source_contents_modified": False,
                  "offline_self_contained": False, "started_unix": started, "completed_unix": time.time(), "owner": owner}
        write_new(output / "RESULT.json", result)
        emit("preservation_complete", result=result)
        return 0
    except BaseException as error:
        failure = {"schema": SCHEMA, "status": "FAIL", "source_root": str(root), "output": str(output),
                   "error_type": type(error).__name__, "error": str(error), "traceback": traceback.format_exc(),
                   "started_unix": started, "completed_unix": time.time(), "owner": owner,
                   "partial_preserved": True, "source_contents_modified": False}
        write_new(output / "FAILURE.json", failure)
        emit("preservation_failed", error=str(error))
        raise


if __name__ == "__main__":
    raise SystemExit(main())
