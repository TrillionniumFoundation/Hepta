#!/usr/bin/env python3
"""Verify this failed/interrupted HIA evidence bundle without extracting it.

No network, Git checkout, source import, compiler, emulator, native executable,
or benchmark is used. Only this reviewer's standard-library data code runs.
"""
import argparse
import base64
import io
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import stat
import tarfile

from audit import (COMMIT, COMPILER, SNAPSHOT, QUALIFICATION_SHA, PERFORMANCE_SHA,
                   PROTOCOL_SHA, parse, require, review, same, sha, wire)

MAX_ENCODED = 32 * 1024 * 1024
MAX_TAR = 64 * 1024 * 1024
MAX_MEMBER = 16 * 1024 * 1024


def safe_path(value):
    require(type(value) is str and value and "\\" not in value and "\0" not in value, "unsafe path text")
    path = PurePosixPath(value)
    require(not path.is_absolute() and ".." not in path.parts and str(path) == value
            and value != ".", "unsafe relative path")
    return path


def read_regular(directory, name, maximum=MAX_ENCODED):
    path = Path(directory)
    for part in safe_path(name).parts:
        path = path / part
        require(not path.is_symlink(), "symlink in retained file path")
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= maximum, "nonregular or oversized retained file")
    identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        opened = os.fstat(stream.fileno())
        require(stat.S_ISREG(opened.st_mode) and identity(opened) == identity(before), "file changed before read")
        data = stream.read(maximum + 1)
        require(identity(os.fstat(stream.fileno())) == identity(before), "file changed during read")
    require(identity(path.lstat()) == identity(before) and len(data) == before.st_size, "file changed after read")
    return data


def unpack_archive(directory, manifest):
    require(manifest["schema"] == "hepta.hia-candidate.archive.v1"
            and manifest["encoding"] == "base64" and manifest["compression"] == "xz-preset-6-dict-64MiB",
            "archive schema or encoding differs")
    require(type(manifest["encoded_bytes"]) is int and 0 < manifest["encoded_bytes"] <= MAX_ENCODED
            and type(manifest["decoded_bytes"]) is int and 0 < manifest["decoded_bytes"] <= MAX_ENCODED,
            "archive encoded bound")
    require(type(manifest["tar_bytes"]) is int and 0 < manifest["tar_bytes"] <= MAX_TAR
            and type(manifest["uncompressed_bytes"]) is int and 0 <= manifest["uncompressed_bytes"] <= MAX_TAR,
            "archive expansion bound")
    require(type(manifest["member_count"]) is int and 0 < manifest["member_count"] <= 1000, "archive member bound")
    logical = str(safe_path(manifest["archive"]))
    parts = manifest["parts"]
    require(type(parts) is list and 1 <= len(parts) <= 16, "archive part count")
    names = [logical] if len(parts) == 1 else [logical + ".part%02d" % (index + 1) for index in range(len(parts))]
    require([part["path"] for part in parts] == names, "archive part names/order")
    encoded = bytearray()
    for part in parts:
        data = read_regular(directory, part["path"], 3_500_000)
        require(len(data) == part["bytes"] and sha(data) == part["sha256"], "archive part identity")
        encoded.extend(data)
        require(len(encoded) <= MAX_ENCODED, "combined archive bound")
    require(len(encoded) == manifest["encoded_bytes"] and sha(encoded) == manifest["encoded_sha256"], "encoded archive identity")
    packed = base64.b64decode(b"".join(encoded.split()), validate=True)
    require(len(packed) == manifest["decoded_bytes"] and sha(packed) == manifest["decoded_sha256"], "compressed archive identity")
    decoder = lzma.LZMADecompressor(memlimit=96 * 1024 * 1024)
    tar_bytes = decoder.decompress(packed, max_length=MAX_TAR + 1)
    require(len(tar_bytes) <= MAX_TAR and decoder.eof and not decoder.unused_data,
            "truncated, oversized, or concatenated xz stream")
    require(len(tar_bytes) == manifest["tar_bytes"] and sha(tar_bytes) == manifest["tar_sha256"], "tar container identity")
    expected = {}
    for row in manifest["members"]:
        name = str(safe_path(row["path"]))
        require(name not in expected, "duplicate manifest member")
        require(type(row["bytes"]) is int and 0 <= row["bytes"] <= MAX_MEMBER, "archive member size bound")
        require(type(row["mode"]) is int and 0 <= row["mode"] <= 0o777, "archive mode bound")
        expected[name] = row
    require(len(expected) == manifest["member_count"], "manifest member denominator")
    found, total, next_offset = {}, 0, 0
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:") as archive:
        for member in archive:
            name = str(safe_path(member.name))
            require(member.type == tarfile.REGTYPE and not member.pax_headers and not archive.pax_headers,
                    "archive member must be an ordinary USTAR file")
            require(member.offset == next_offset and tar_bytes[member.offset + 257:member.offset + 265] == b"ustar\00000",
                    "extended or hidden tar header")
            require(member.uid == member.gid == member.mtime == 0 and member.uname == member.gname == "",
                    "archive normalized metadata differs")
            require(name in expected and name not in found, "unexpected or duplicate tar member")
            wanted = expected[name]
            require(member.size == wanted["bytes"] and member.mode == wanted["mode"], "member metadata differs")
            with archive.extractfile(member) as stream:
                data = stream.read(member.size + 1)
            require(len(data) == member.size and sha(data) == wanted["sha256"], "archive member digest differs")
            total += len(data)
            require(total <= MAX_TAR, "member total exceeds bound")
            found[name] = data
            next_offset = member.offset_data + (member.size + 511) // 512 * 512
    require(set(found) == set(expected) and total == manifest["uncompressed_bytes"], "archive inventory denominator")
    require(len(tar_bytes) >= next_offset + 1024 and not any(tar_bytes[next_offset:]), "unexpected trailing tar bytes")
    return found


def verify(directory):
    bundle = parse(read_regular(directory, "MANIFEST.json"))
    require(bundle["schema"] == "hepta.hia-candidate.bundle.v1" and bundle["tested_source_commit"] == COMMIT
            and bundle["source_snapshot_sha256"] == SNAPSHOT and bundle["compiler_sha256"] == COMPILER,
            "bundle source identity differs")
    require(bundle["qualification_sha256"] == QUALIFICATION_SHA and bundle["performance_sha256"] == PERFORMANCE_SHA,
            "bundle original report pins differ")
    actual_names = {path.relative_to(directory).as_posix() for path in Path(directory).rglob("*") if not path.is_dir()}
    parts = bundle["archive_parts"]
    require(actual_names == set(bundle["files"]) | set(parts) | {"MANIFEST.json"}, "bundle file denominator differs")
    for name, identity in bundle["files"].items():
        data = read_regular(directory, name)
        require(len(data) == identity["bytes"] and sha(data) == identity["sha256"], "bundle auxiliary file identity")
    manifest = parse(read_regular(directory, "run-artifacts.manifest.json"))
    require([part["path"] for part in manifest["parts"]] == parts, "bundle/archive part inventory")
    members = unpack_archive(directory, manifest)
    require(len(members) == 729 and sum(name.startswith("attempt1/") for name in members) == 2
            and sum(name.startswith("attempt2/") for name in members) == 721
            and sum(name.startswith("runner/") for name in members) == 6, "frozen complete archive denominator")
    scope = parse(read_regular(directory, "archive-scope.json"))
    require(scope["tested_source_commit"] == COMMIT and scope["source_snapshot_sha256"] == SNAPSHOT
            and scope["archive_members"] == len(members) and scope["all_present_regular_files_captured"] is True
            and scope["unchanged_during_capture"] is True, "capture scope differs")
    for label in ("attempt1", "attempt2"):
        names = sorted(name[len(label) + 1:] for name in members if name.startswith(label + "/"))
        selected = scope["directories"][label]
        require(len(names) == selected["files"] and sha(wire(names)) == selected["relative_paths_sha256"]
                and sum(len(members[label + "/" + name]) for name in names) == selected["bytes"], "capture inventory identity")
    copies = {"qualification.json": "attempt2/qualification.json", "performance.json": "attempt2/performance.json",
              "attempt1-interruption-observation.json": "attempt1/interruption-observation.json"}
    copies.update({name: "runner/" + name for name in ("attempt1-driver.log", "attempt2-driver.log",
                   "attempt2-job.json", "attempt2-spec.json", "attempt2-supervisor.log")})
    require(all(read_regular(directory, name) == members[member] for name, member in copies.items()),
            "convenience copy differs from original archive member")
    observed = review(members)
    require(same(observed, parse(read_regular(directory, "review.json"))), "independent derived review differs")
    protocol = parse(read_regular(directory, "protocol-review.json"))
    snapshot = parse(members["attempt2/qualification.json"])["source_snapshot_before"]
    require(protocol["candidate_commit"] == COMMIT and protocol["expanded_protocol_equal"] is True
            and protocol["expanded_protocol_sha256"] == PROTOCOL_SHA, "protocol comparison identity")
    for name, row in protocol["comparisons"]["files"].items():
        require(row["candidate_sha256"] == row["baseline_sha256"] == snapshot["files"][name]
                and row["exact_bytes_equal"] is True, "recorded unchanged protocol file differs")
    for row in protocol["comparisons"]["definitions"].values():
        require(row["candidate_sha256"] == row["baseline_sha256"] and row["exact_bytes_equal"] is True,
                "recorded unchanged protocol definition differs")
    return {"schema": "hepta.hia-candidate.bundle-verification.v1", "status": "retained_failed_attempts_verified",
        "ok": True, "qualification_passed": False, "tested_source_commit": COMMIT,
        "source_snapshot_sha256": SNAPSHOT, "compiler_sha256": COMPILER,
        "qualification_sha256": QUALIFICATION_SHA, "performance_sha256": PERFORMANCE_SHA,
        "archive_members": 729, "archive_parts": len(parts), "archive_compressed_bytes": manifest["decoded_bytes"],
        "archive_member_bytes": manifest["uncompressed_bytes"], "source_files_before": 920, "source_files_after": 920,
        "attempt1_status": "interrupted_unqualified", "attempt1_exit_code": None,
        "attempt1_unit_count": None, "attempt1_performance_samples": 0,
        "attempt2_completed_gates": 15, "attempt2_passed_gates": 14, "attempt2_exit_code": 1,
        "unit_tests": 2093, "unit_skipped": 0, "performance_samples": 63,
        "performance_status": "measurement_inconclusive", "measurement_quality_failures": 4,
        "performance_threshold_failures": 0, "retained_native_performance_files": 16,
        "native_correctness_receipts": 588, "native_execution_repeated": False,
        "performance_remeasured": False, "archive_extracted": False, "network_used": False,
        "scope": "artifact integrity, linked recorded receipts, and independent formulas/statistics; execution authenticity and full source Git binding remain separate"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path, nargs="?", default=Path(__file__).resolve().parent)
    args = parser.parse_args()
    print(json.dumps(verify(args.directory.resolve()), indent=2, sort_keys=True, allow_nan=False))
