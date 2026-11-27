#!/usr/bin/env python3
"""Read-only d79 CI custody. No product imports or execution.

The original outer ZIP files remain untouched. The CAS preserves every
member's exact uncompressed bytes; the manifest preserves original modes,
ZIP metadata and all paths, including duplicate paths if any existed.
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import time
import zipfile
import zlib

ROOT = Path(__file__).resolve().parent
INPUT = ROOT.parent / "v87-core-d79-failure-r1"
OUT = ROOT / "collected"
EXPECTED = {
    "native.zip": (535678599, "ee438c75c427c2195f76d1c5228504b16373ef3a066d9c4c3c2456f9774e03da"),
    "wire.zip": (64558, "1ea06334c05de0cff2b6f061b2472841d1f2df20ba2bdb9f70dfa094bdae5e57"),
}
BLOCK = 1 << 20


def dump(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def sha_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(BLOCK):
            digest.update(block)
    return digest.hexdigest()


def identity(path):
    st = path.stat()
    return dict(device=st.st_dev, inode=st.st_ino, bytes=st.st_size,
                mode=stat.S_IMODE(st.st_mode), mtime_ns=st.st_mtime_ns)


def same_bytes(a, b):
    if a.stat().st_size != b.stat().st_size:
        return False
    with a.open("rb") as first, b.open("rb") as second:
        while True:
            left, right = first.read(BLOCK), second.read(BLOCK)
            if left != right:
                return False
            if not left:
                return True


def main():
    OUT.mkdir(exist_ok=False)
    pool = OUT / "pool"
    pool.mkdir()
    objects = {}
    started = time.monotonic()
    events = (OUT / "EVENTS.jsonl").open("x", buffering=1)

    def event(**value):
        value["elapsed_seconds"] = time.monotonic() - started
        events.write(json.dumps(value, sort_keys=True) + "\n")
        print(json.dumps(value, sort_keys=True), flush=True)

    def capture(stream, expected_size=None, expected_crc=None):
        temporary = OUT / "in-progress-object"
        digest = hashlib.sha256()
        total = crc = 0
        with temporary.open("xb") as target:
            while block := stream.read(BLOCK):
                target.write(block)
                digest.update(block)
                crc = zlib.crc32(block, crc)
                total += len(block)
        hexdigest = digest.hexdigest()
        if expected_size is not None and total != expected_size:
            raise ValueError(("member length differs", total, expected_size))
        if expected_crc is not None and crc != expected_crc:
            raise ValueError(("member CRC differs", crc, expected_crc))
        target = pool / hexdigest
        if target.exists():
            if not same_bytes(target, temporary):
                raise ValueError("same digest did not have the same full bytes")
            temporary.unlink()
            objects[hexdigest]["references"] += 1
        else:
            temporary.chmod(0o400)
            temporary.replace(target)
            objects[hexdigest] = dict(bytes=total, sha256=hexdigest, references=1)
        return dict(bytes=total, sha256=hexdigest, crc32=f"{crc:08x}", pool=hexdigest)

    def zip_row(info, number):
        return dict(ordinal=number, path=info.filename, original_filename=info.orig_filename,
                    bytes=info.file_size, compressed_bytes=info.compress_size,
                    crc32=f"{info.CRC:08x}", unix_mode=(info.external_attr >> 16) & 0xffff,
                    permission_mode=stat.S_IMODE(info.external_attr >> 16),
                    external_attr=info.external_attr, internal_attr=info.internal_attr,
                    create_system=info.create_system, create_version=info.create_version,
                    extract_version=info.extract_version, flag_bits=info.flag_bits,
                    compression=info.compress_type, header_offset=info.header_offset,
                    date_time=list(info.date_time), is_directory=info.is_dir(),
                    extra_base64=base64.b64encode(info.extra).decode("ascii"),
                    comment_base64=base64.b64encode(info.comment).decode("ascii"))

    archives = []
    nested_queue = []
    originals = []
    try:
        for name, (size, expected_sha) in EXPECTED.items():
            path = INPUT / name
            before = identity(path)
            actual_sha = sha_file(path)
            if before["bytes"] != size or actual_sha != expected_sha:
                raise ValueError(("outer ZIP identity differs", name, before, actual_sha))
            event(phase="outer_verified", archive=name, bytes=size, sha256=actual_sha)
            members = []
            with zipfile.ZipFile(path) as archive:
                entries = archive.infolist()
                for ordinal, info in enumerate(entries):
                    row = zip_row(info, ordinal)
                    with archive.open(info) as stream:
                        row.update(capture(stream, info.file_size, info.CRC))
                    members.append(row)
                    if info.filename.endswith((".zip", ".whl")):
                        nested_queue.append((name + "!/" + info.filename, row["sha256"]))
                    if (ordinal + 1) % 2000 == 0:
                        event(phase="members", archive=name, complete=ordinal + 1,
                              total=len(entries), unique=len(objects),
                              unique_bytes=sum(x["bytes"] for x in objects.values()))
                comment = base64.b64encode(archive.comment).decode("ascii")
            after = identity(path)
            if after != before or sha_file(path) != expected_sha:
                raise ValueError(("original outer ZIP changed", name))
            record = dict(name=name, path=str(path), bytes=size, sha256=actual_sha,
                          comment_base64=comment, before=before, after=after,
                          crc_all_pass=True, members=members)
            archives.append(record)
            dump(OUT / (name + ".MEMBERS.json"), record)
            event(phase="archive_complete", archive=name, members=len(members),
                  raw_bytes=sum(x["bytes"] for x in members))

        for name in ("ORIGINAL-METADATA.json", "source.log", "native.log"):
            path = INPUT / name
            before = identity(path)
            with path.open("rb") as stream:
                row = capture(stream, before["bytes"])
            if identity(path) != before or sha_file(path) != row["sha256"]:
                raise ValueError(("original sidecar changed", name))
            originals.append(dict(name=name, path=str(path), original_identity=before, **row))

        nested = {}
        references = []
        while nested_queue:
            path, digest = nested_queue.pop(0)
            references.append(dict(path=path, sha256=digest))
            if digest in nested:
                continue
            rows = []
            with zipfile.ZipFile(pool / digest) as archive:
                for ordinal, info in enumerate(archive.infolist()):
                    row = zip_row(info, ordinal)
                    with archive.open(info) as stream:
                        row.update(capture(stream, info.file_size, info.CRC))
                    rows.append(row)
                    if info.filename.endswith((".zip", ".whl")):
                        nested_queue.append((path + "!/" + info.filename, row["sha256"]))
                comment = base64.b64encode(archive.comment).decode("ascii")
            nested[digest] = dict(sha256=digest, members=rows, comment_base64=comment,
                                  crc_all_pass=True)
            event(phase="nested_complete", sha256=digest, members=len(rows),
                  complete=len(nested), queue=len(nested_queue))

        manifest = dict(schema="hepta.original-ci-member-custody.v1",
                        scope="ORIGINAL_D79_CI_OBSERVATIONS_ONLY_NO_PRODUCT_EXECUTION",
                        run=43402528459, commit="d79eb096ddcce6c317b2c316a4773ce76a37bab9",
                        tree="279c5459c9cc7746d5e347d90285eebfe21986d2",
                        archives=archives, originals=originals,
                        nested_zip_objects=nested, nested_zip_references=references,
                        pool=objects,
                        qualification_transferred=False,
                        outer_zip_git_custody=False,
                        outer_zip_custody="Original full ZIPs retained locally and in original Actions artifacts; CAS fully preserves original member bytes and ZIP metadata, not the outer compressed byte stream.")
        dump(OUT / "MANIFEST.json", manifest)
        summary = dict(status="ALL_ORIGINAL_AND_NESTED_ZIP_MEMBERS_VERIFIED",
                       scope=manifest["scope"], run=manifest["run"], commit=manifest["commit"],
                       outer_members=sum(len(x["members"]) for x in archives),
                       outer_member_bytes=sum(y["bytes"] for x in archives for y in x["members"]),
                       nested_zip_objects=len(nested), nested_zip_references=len(references),
                       nested_members=sum(len(x["members"]) for x in nested.values()),
                       nested_member_bytes=sum(y["bytes"] for x in nested.values() for y in x["members"]),
                       unique_objects=len(objects), unique_bytes=sum(x["bytes"] for x in objects.values()),
                       manifest_bytes=(OUT / "MANIFEST.json").stat().st_size,
                       manifest_sha256=sha_file(OUT / "MANIFEST.json"),
                       original_outer_files_unchanged=True,
                       product_tests_executed=0, qualification_transferred=False,
                       elapsed_seconds=time.monotonic() - started)
        dump(OUT / "SUMMARY.json", summary)
        event(phase="complete", **summary)
    except BaseException as error:
        import traceback
        dump(OUT / "FAILURE.json", dict(type=type(error).__name__, message=str(error),
                                       traceback=traceback.format_exc(),
                                       product_tests_executed=0))
        raise
    finally:
        events.close()


if __name__ == "__main__":
    main()
