"""Restore the exact archived Core authoring originals; never regenerate source.

This script is a source-custody control. It compiles no HIA or Python authoring
policy and runs no product or qualification suite. Its first execution is a new
observation; prior JavaScript readback is recorded separately.
"""
from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
import tarfile
import time

INDEX_SHA256 = "0920f777a7f4692cf2ef20c9af4258decae6cc9f605ca4d8fe1bc6621b6a817a"
ARCHIVE_SHA256 = "400f59e67817fb9a6fc3ce744b4bb93c64957d932272880af7bb382325a2c450"
ARCHIVE_SIZE = 2218343
TAR_SIZE = 10393600


def digest(data):
    return hashlib.sha256(data).hexdigest()


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field: " + key)
        result[key] = value
    return result


def parsed(raw):
    return json.loads(raw, object_pairs_hook=unique_pairs)


def relative_path(value):
    if type(value) is not str:
        raise ValueError("relative member path must be text")
    path = PurePosixPath(value)
    if (not value or path.is_absolute() or str(path) != value
            or any(part in ("", ".", "..") for part in value.split("/"))):
        raise ValueError("unsafe member path")
    return path


def read_regular(root, relative, expected_size=None, expected_sha=None):
    relative = relative_path(relative)
    current = root
    if not stat.S_ISDIR(current.lstat().st_mode):
        raise ValueError("input root is not a real directory")
    for part in relative.parts[:-1]:
        current = current / part
        if not stat.S_ISDIR(current.lstat().st_mode):
            raise ValueError("input parent is not a real directory")
    path = current / relative.name
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise ValueError("input member is not a regular file")
    raw = path.read_bytes()
    after = path.lstat()
    if ((before.st_dev, before.st_ino, before.st_mode, before.st_size,
         before.st_mtime_ns, before.st_ctime_ns)
            != (after.st_dev, after.st_ino, after.st_mode, after.st_size,
                after.st_mtime_ns, after.st_ctime_ns)):
        raise ValueError("input member changed during reading")
    if expected_size is not None and len(raw) != expected_size:
        raise ValueError("input member size differs: " + str(relative))
    if expected_sha is not None and digest(raw) != expected_sha:
        raise ValueError("input member SHA differs: " + str(relative))
    return raw


def write_new(path, raw, mode):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with path.open("xb") as output:
        os.fchmod(output.fileno(), mode)
        output.write(raw)
        output.flush()
        os.fsync(output.fileno())
    if path.read_bytes() != raw or stat.S_IMODE(path.lstat().st_mode) != mode:
        raise ValueError("new output readback differs: " + str(path))


def restore(received, index_path, destination):
    started = time.monotonic()
    index_path = index_path.absolute()
    index_raw = read_regular(index_path.parent, index_path.name,
                             expected_sha=INDEX_SHA256)
    index = parsed(index_raw)
    if (index["schema"] != "hepta.hia.core-lowering-original-archive-index.v1"
            or index["archive"]["size"] != ARCHIVE_SIZE
            or index["archive"]["sha256"] != ARCHIVE_SHA256
            or index["archive"]["unpacked_tar_bytes"] != TAR_SIZE
            or len(index["chunks"]) != 34 or len(index["members"]) != 58):
        raise ValueError("pinned archive index shape differs")
    received = received.absolute()
    archive = bytearray()
    observations = []
    for ordinal, expected in enumerate(index["chunks"]):
        name = "chunks/" + str(ordinal).zfill(4) + ".sdk.json"
        if (expected["ordinal"] != ordinal or expected["path"] != name
                or expected["offset"] != len(archive)):
            raise ValueError("chunk inventory order differs")
        sdk_raw = read_regular(received, name, expected["sdk_size"],
                               expected["sdk_sha256"])
        git_blob = hashlib.sha1(
            b"blob " + str(len(sdk_raw)).encode("ascii") + b"\0" + sdk_raw
        ).hexdigest()
        if git_blob != expected["sdk_git_blob_sha1"]:
            raise ValueError("SDK Git blob identity differs")
        sdk = parsed(sdk_raw)
        if sdk.get("isError") is not False:
            raise ValueError("SDK original did not report success")
        blocks = sdk["content"]
        if (type(blocks) is not list or len(blocks) != 1
                or blocks[0].get("type") != "text"
                or type(blocks[0].get("text")) is not str):
            raise ValueError("SDK text framing differs")
        chunk = parsed(blocks[0]["text"])
        raw = base64.b64decode(chunk["data_base64"], validate=True)
        size = min(65536, ARCHIVE_SIZE - len(archive))
        if (type(chunk["offset"]) is not int
                or chunk["offset"] != len(archive)
                or chunk["next_offset"] != len(archive) + size
                or chunk["size"] != ARCHIVE_SIZE
                or chunk["path"] != index["archive"]["path"]
                or chunk["version"] != index["archive"]["version"]
                or chunk["eof"] is not (ordinal == 33)
                or len(raw) != size or expected["size"] != size
                or digest(raw) != expected["sha256"]
                or chunk["chunk_sha256"] != expected["sha256"]):
            raise ValueError("original chunk framing or bytes differ")
        observations.append({
            "ordinal": ordinal, "offset": len(archive), "size": size,
            "sha256": digest(raw), "sdk_sha256": digest(sdk_raw),
            "sdk_git_blob_sha1": git_blob,
        })
        archive.extend(raw)
    archive = bytes(archive)
    if len(archive) != ARCHIVE_SIZE or digest(archive) != ARCHIVE_SHA256:
        raise ValueError("whole original archive differs")
    tar_raw = gzip.decompress(archive)
    if len(tar_raw) != TAR_SIZE:
        raise ValueError("original tar extent differs")
    wanted = {entry["path"]: entry for entry in index["members"]}
    if len(wanted) != 58:
        raise ValueError("duplicate original member")
    actual = {}
    with tarfile.open(fileobj=io.BytesIO(tar_raw), mode="r:") as bundle:
        for member in bundle:
            relative_path(member.name)
            if member.name in actual or member.name not in wanted or not member.isreg():
                raise ValueError("unexpected original tar member")
            expected = wanted[member.name]
            if any(getattr(member, key) != expected[key]
                   for key in ("size", "mode", "uid", "gid", "mtime")):
                raise ValueError("original member metadata differs")
            stream = bundle.extractfile(member)
            if stream is None:
                raise ValueError("regular member has no bytes")
            raw = stream.read()
            if len(raw) != expected["size"] or digest(raw) != expected["sha256"]:
                raise ValueError("original member bytes differ")
            actual[member.name] = raw
    if set(actual) != set(wanted):
        raise ValueError("original member denominator differs")
    if sum(map(len, actual.values())) != index["member_bytes"]:
        raise ValueError("original member aggregate differs")
    generated = {
        name.rsplit("/", 1)[1]: raw for name, raw in actual.items()
        if name.startswith(index["generated"]["path_prefix"])
        and name.endswith(".hiaasm")
    }
    expected_names = {"core_lowering_pool.hiaasm"} | {
        "core_lowering_" + str(n).zfill(3) + ".hiaasm" for n in range(31)
    }
    if (set(generated) != expected_names
            or len(generated) != index["generated"]["count"]
            or sum(map(len, generated.values())) != index["generated"]["bytes"]):
        raise ValueError("generated HIA source inventory differs")
    abi = actual[index["generated"]["abi_path"]]
    if digest(abi) != index["generated"]["abi_sha256"]:
        raise ValueError("original ABI identity differs")

    # All archive/member admission above occurs before creating output.
    destination = destination.absolute()
    if destination.name in ("", ".", "..") or not destination.parent.is_dir():
        raise ValueError("new output parent is required")
    destination.mkdir(mode=0o700, parents=False, exist_ok=False)
    write_new(destination / "originals.tar.gz", archive, 0o600)
    for name, raw in actual.items():
        write_new(destination / "originals" / relative_path(name),
                  raw, wanted[name]["mode"])
    for name, raw in generated.items():
        write_new(destination / "generated" / name, raw, 0o644)
    write_new(destination / "generated" / "hia_core_lowering_abi.json",
              abi, 0o644)
    write_new(destination / "ARCHIVE-INDEX.json", index_raw, 0o600)
    report = {
        "schema": "hepta.hia.core-lowering-original-restore.v1",
        "status": "EXACT_ORIGINAL_ARCHIVE_RESTORED",
        "source_checkpoint": index["source_checkpoint"],
        "archive_size": len(archive), "archive_sha256": digest(archive),
        "archive_index_sha256": digest(index_raw),
        "member_count": len(actual), "member_bytes": sum(map(len, actual.values())),
        "member_metadata_matches_original": True,
        "all_restored_bytes_and_modes_read_back": True,
        "original_uid_gid_preserved_in_archive_not_reassigned_on_host": True,
        "generated_count": len(generated),
        "generated_source_sha256": {
            name: digest(raw) for name, raw in sorted(generated.items())
        },
        "generated_abi_sha256": digest(abi),
        "git_resource_copies_mode": "100644",
        "chunks": observations,
        "source_generation_repeated": False,
        "python_authoring_or_hia_compilation_executed": False,
        "native_or_product_tests_executed": False,
        "custody_control_sha256": digest(Path(__file__).read_bytes()),
        "python_executable": sys.executable,
        "python_version": sys.version,
        "python_resolved_sha256": digest(Path(sys.executable).resolve().read_bytes()),
        "destination": str(destination),
        "seconds": time.monotonic() - started,
    }
    wire = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
    write_new(destination / "RESTORE.json", wire, 0o600)
    print(wire.decode("utf-8"), end="")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--received-dir", required=True, type=Path)
    parser.add_argument("--member-index", required=True, type=Path)
    parser.add_argument("--destination", required=True, type=Path)
    args = parser.parse_args()
    restore(args.received_dir, args.member_index, args.destination)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
