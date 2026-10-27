#!/usr/bin/env python3
"""Independently verify a Hepta evidence package without extracting its files.

Run only after qualification/performance and archive generation have finished:
  python verify_hepta_archive.py --package NEW_PACKAGE_DIRECTORY

The ordered parts are the verification input; a standalone tar.xz is optional
and is also checked when present. No producer code is imported, no original
absolute dependency path is opened, and no test/compiler/process is launched.
The only output is a new archive-validation.json (or --output); existing files
are never replaced. Integrity here does not authenticate qualification claims.
"""
from __future__ import annotations

import argparse
from collections import Counter
from contextlib import contextmanager
import datetime
import hashlib
import io
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tarfile

CHUNK = 1024 * 1024
PART_BYTES = 4 * CHUNK
MAX_METADATA_BYTES = 32 * CHUNK
MAX_ROWS = 100_000
MAX_EXPANDED_BYTES = 16 * 1024 * CHUNK
PREFIX = "hepta-evidence/"
METADATA_NAMES = {"path-mapping.json", "dependencies.json", "PACKAGE_README.md", "inventory.json"}
HEX = re.compile(r"[0-9a-f]{64}")


class InvalidArchive(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise InvalidArchive(message)


def integer(value, minimum=0):
    return type(value) is int and value >= minimum


def version(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def relative_name(name):
    require(isinstance(name, str) and 0 < len(name) <= 4096
            and "\\" not in name and "\x00" not in name,
            "invalid archive-relative name")
    require(not name.startswith("/") and all(part not in {"", ".", ".."} for part in name.split("/"))
            and PurePosixPath(name).as_posix() == name,
            "noncanonical archive-relative name: " + name)
    return name


def basename(name):
    relative_name(name)
    require("/" not in name, "package inputs must be local basenames: " + name)
    return name


def identity(row, path_key):
    require(isinstance(row, dict), "identity row must be an object")
    relative_name(row.get(path_key))
    require(integer(row.get("bytes")) and isinstance(row.get("sha256"), str)
            and HEX.fullmatch(row["sha256"]) is not None, "invalid byte count or SHA-256")
    return row


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key: " + key)
        result[key] = value
    return result


def reject_constant(value):
    raise InvalidArchive("nonfinite JSON number: " + value)


def parse_json(data, expected_schema):
    document = json.loads(data.decode("utf-8"), object_pairs_hook=unique_object,
                          parse_constant=reject_constant)
    require(isinstance(document, dict) and document.get("schema") == expected_schema,
            "unexpected JSON schema; expected " + expected_schema)
    return document


class StrictTarInfo(tarfile.TarInfo):
    """Do not let tarfile treat a malformed nonzero header as normal EOF."""

    @classmethod
    def frombuf(cls, buffer, encoding, errors):
        if buffer == b"\x00" * tarfile.BLOCKSIZE:
            return super().frombuf(buffer, encoding, errors)
        try:
            return super().frombuf(buffer, encoding, errors)
        except tarfile.HeaderError as error:
            raise InvalidArchive("malformed or missing tar header: " + str(error)) from error


class Inputs:
    """Pin every package file to the bytes/version observed during this run."""

    def __init__(self):
        self.versions = {}

    @contextmanager
    def open(self, path):
        before = path.lstat()
        require(stat.S_ISREG(before.st_mode), "package input is not regular: " + str(path))
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        try:
            opened = os.fstat(fd)
            require(stat.S_ISREG(opened.st_mode) and version(opened) == version(before),
                    "package input changed before opening: " + str(path))
            stream = os.fdopen(fd, "rb")
        except BaseException:
            os.close(fd)
            raise
        with stream:
            previous = self.versions.setdefault(path, version(before))
            require(previous == version(before), "package input version differs: " + str(path))
            yield stream, before
            require(version(os.fstat(stream.fileno())) == version(before)
                    and version(path.lstat()) == version(before),
                    "package input changed while reading: " + str(path))

    def small(self, path):
        with self.open(path) as (stream, before):
            require(before.st_size <= MAX_METADATA_BYTES, "metadata exceeds 32 MiB: " + str(path))
            raw = stream.read(before.st_size + 1)
            require(len(raw) == before.st_size, "metadata length changed: " + str(path))
        return raw

    def unchanged(self):
        for path, observed in self.versions.items():
            require(version(path.lstat()) == observed, "package input changed after verification: " + str(path))


class ChunksReader(io.RawIOBase):
    """Expose a bounded chunk generator as a streaming binary reader."""

    def __init__(self, chunks):
        super().__init__()
        self.chunks = iter(chunks)
        self.pending = b""

    def readable(self):
        return True

    def readinto(self, buffer):
        if not buffer:
            return 0
        while not self.pending:
            try:
                self.pending = next(self.chunks)
            except StopIteration:
                return 0
        count = min(len(buffer), len(self.pending))
        buffer[:count] = self.pending[:count]
        self.pending = self.pending[count:]
        return count

    def close(self):
        if not self.closed:
            close = getattr(self.chunks, "close", None)
            if close:
                close()
        super().close()


def part_chunks(package, parts, expected_archive, inputs, observed):
    whole, total = hashlib.sha256(), 0
    for row in parts:
        digest, count = hashlib.sha256(), 0
        with inputs.open(package / row["path"]) as (stream, before):
            require(before.st_size == row["bytes"], "part size differs: " + row["path"])
            while data := stream.read(CHUNK):
                digest.update(data)
                whole.update(data)
                count += len(data)
                total += len(data)
                yield data
            require(count == row["bytes"] and digest.hexdigest() == row["sha256"],
                    "part content differs: " + row["path"])
        observed["parts_verified"] = observed.get("parts_verified", 0) + 1
    require(total == expected_archive["bytes"] and whole.hexdigest() == expected_archive["sha256"],
            "ordered parts do not reproduce the declared archive size/hash")
    observed.update(archive_bytes=total, archive_sha256=whole.hexdigest(), ordered_parts_verified=True)


def xz_chunks(compressed, expanded_limit, observed):
    # One XZ stream, as produced by the packager. Reject concatenated streams
    # and trailing compressed junk instead of accepting an ignored suffix.
    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=256 * CHUNK)
    expanded = 0
    while not decoder.eof:
        if decoder.needs_input:
            data = compressed.read(CHUNK)
            require(bool(data), "truncated XZ stream")
        else:
            data = b""
        output = decoder.decompress(data, max_length=CHUNK)
        expanded += len(output)
        require(expanded <= expanded_limit, "expanded tar exceeds the declared inventory budget")
        if output:
            yield output
    require(not decoder.unused_data and compressed.read(1) == b"",
            "trailing bytes or another stream after the XZ archive")
    observed.update(xz_eof_verified=True, expanded_bytes=expanded)


def prepare(package, inputs):
    manifest_raw = inputs.small(package / "archive-manifest.json")
    manifest = parse_json(manifest_raw, "hepta.archive-package.v1")
    archive = identity(manifest.get("archive"), "path")
    require(basename(archive["path"]) == "hepta-evidence.tar.xz" and archive["bytes"] > 0,
            "unexpected standalone archive name/size")
    require(type(manifest.get("part_bytes")) is int and manifest["part_bytes"] == PART_BYTES,
            "parts must use the declared 4 MiB profile")
    parts = manifest.get("parts")
    require(isinstance(parts, list) and 1 <= len(parts) <= 10000, "invalid part inventory")
    for index, row in enumerate(parts):
        identity(row, "path")
        require(type(row.get("index")) is int and row["index"] == index
                and basename(row["path"]) == archive["path"] + f".part{index:04d}",
                "parts must be unique and in exact contiguous index/name order")
        require(0 < row["bytes"] <= PART_BYTES and (index == len(parts) - 1 or row["bytes"] == PART_BYTES),
                "invalid part length")
    require(sum(row["bytes"] for row in parts) == archive["bytes"], "declared part/archive lengths differ")

    rows = manifest.get("metadata")
    require(isinstance(rows, list) and len(rows) == len(METADATA_NAMES), "four metadata identities required")
    metadata, raw_metadata = {}, {}
    for row in rows:
        identity(row, "archive_path")
        name = basename(row["archive_path"])
        require(name in METADATA_NAMES and name not in metadata
                and row.get("role") == "generated_archival_metadata", "unexpected/duplicate metadata identity")
        raw = inputs.small(package / name)
        require(len(raw) == row["bytes"] and hashlib.sha256(raw).hexdigest() == row["sha256"],
                "external metadata content differs: " + name)
        metadata[name], raw_metadata[name] = row, raw

    inventory = parse_json(raw_metadata["inventory.json"], "hepta.archive-inventory.v1")
    require(inventory.get("self_digest_in_outer_archive_manifest") is True, "inventory self-digest location differs")
    files = inventory.get("files")
    require(isinstance(files, list) and len(files) <= MAX_ROWS, "invalid file inventory")
    expected = {}
    for row in files:
        identity(row, "archive_path")
        name = row["archive_path"]
        require(name not in expected and name != "inventory.json", "duplicate/self-referential inventory member: " + name)
        require(isinstance(row.get("role"), str) and bool(row["role"]), "file role missing")
        expected[name] = row
    for name, row in metadata.items():
        if name != "inventory.json":
            require(expected.get(name) == row, "outer metadata differs from inventory: " + name)
    expected["inventory.json"] = metadata["inventory.json"]
    require(integer(manifest.get("archived_regular_files"))
            and manifest["archived_regular_files"] + len(METADATA_NAMES) == len(expected),
            "raw/generated member count differs")
    require(sum(row.get("role") == "generated_archival_metadata" for row in expected.values()) == len(METADATA_NAMES),
            "unexpected extra generated metadata member")
    expanded_limit = sum(((row["bytes"] + 511) // 512) * 512 + 8192 for row in expected.values()) + CHUNK
    require(expanded_limit <= MAX_EXPANDED_BYTES, "inventory exceeds the verifier's 16 GiB expanded profile")
    return manifest_raw, manifest, expected, raw_metadata, expanded_limit


def verify_members(package, inputs, manifest, expected, raw_metadata, expanded_limit, observed):
    seen, member_bytes = set(), 0
    compressed_chunks = part_chunks(package, manifest["parts"], manifest["archive"], inputs, observed)
    with io.BufferedReader(ChunksReader(compressed_chunks), buffer_size=CHUNK) as compressed:
        with io.BufferedReader(ChunksReader(xz_chunks(compressed, expanded_limit, observed)), buffer_size=CHUNK) as expanded:
            with tarfile.open(fileobj=expanded, mode="r|", bufsize=CHUNK,
                              encoding="utf-8", errors="strict", errorlevel=2,
                              tarinfo=StrictTarInfo) as archive:
                for member in archive:
                    require(member.type in (tarfile.REGTYPE, tarfile.AREGTYPE)
                            and member.sparse is None, "nonregular/sparse tar member: " + member.name)
                    require(member.name.startswith(PREFIX), "tar member outside evidence namespace")
                    name = relative_name(member.name[len(PREFIX):])
                    require(name in expected, "undeclared extra tar member: " + name)
                    require(name not in seen, "duplicate tar member: " + name)
                    seen.add(name)
                    row = expected[name]
                    require(member.size == row["bytes"], "tar member size differs: " + name)
                    digest, count = hashlib.sha256(), 0
                    stream = archive.extractfile(member)
                    require(stream is not None, "regular member has no data stream")
                    with stream:
                        while data := stream.read(CHUNK):
                            digest.update(data)
                            if name in raw_metadata:
                                require(data == raw_metadata[name][count:count + len(data)],
                                        "embedded/external metadata bytes differ: " + name)
                            count += len(data)
                    require(count == row["bytes"] and digest.hexdigest() == row["sha256"],
                            "tar member content differs: " + name)
                    member_bytes += count
                # Drain tar's own buffered reader: draining only `expanded`
                # would miss bytes already prefetched after its first EOF block.
                trailer = 0
                while data := archive.fileobj.read(CHUNK):
                    require(not data.strip(b"\x00"), "nonzero data or hidden members after tar EOF")
                    trailer += len(data)
                    require(trailer <= CHUNK, "excessive tar padding")
                require(trailer >= 512, "tar must include the second zero EOF block")
    require(seen == set(expected), "missing declared tar members: " + ", ".join(sorted(set(expected) - seen)[:12]))
    require(observed.get("xz_eof_verified") is True and observed.get("ordered_parts_verified") is True,
            "compressed source was not completely consumed and checked")
    observed.update(tar_members_verified=len(seen), regular_member_bytes=member_bytes,
                    embedded_metadata_identical=sorted(METADATA_NAMES), tar_padding_bytes=trailer)


def verify_dependencies(raw, expected):
    document = parse_json(raw, "hepta.archive-dependencies.v1")
    require(document.get("identity_shape") == ["path", "sha256", "bytes"], "unexpected dependency identity shape")
    rows = document.get("identities")
    require(isinstance(rows, list) and len(rows) <= MAX_ROWS, "invalid dependency observations")
    counts = Counter()
    for row in rows:
        require(isinstance(row, dict) and row.get("report") in expected
                and isinstance(row.get("status"), str), "dependency report/status is not inventoried")
        status = row["status"]
        require(status != "pending_archived_identity_check", "unfinished dependency identity check")
        counts[status] += 1
        if status in {"already_archived_identity_matches", "already_archived_identity_mismatch", "supplemented_verified_native_artifact"}:
            target = expected.get(row.get("archive_path"))
            require(target is not None, "dependency points to an undeclared archive member")
            declared_hash = row.get("declared_sha256")
            require(isinstance(declared_hash, str) and HEX.fullmatch(declared_hash.lower()) is not None
                    and integer(row.get("declared_bytes")), "invalid archived dependency identity")
            matches = target["sha256"] == declared_hash.lower() and target["bytes"] == row["declared_bytes"]
            require(matches == (status != "already_archived_identity_mismatch"), "dependency disposition disagrees with archived bytes")
    return {"records": len(rows), "statuses": dict(sorted(counts.items())),
            "original_absolute_paths_opened": False,
            "missing_or_mismatched_references_are_qualification_failures": False}


def verify_standalone(package, inputs, row):
    path = package / row["path"]
    try:
        path.lstat()
    except FileNotFoundError:
        return {"present": False, "required": False, "canonical_archive_verified_from_parts": True}
    digest, count = hashlib.sha256(), 0
    with inputs.open(path) as (stream, before):
        require(before.st_size == row["bytes"], "standalone archive size differs")
        while data := stream.read(CHUNK):
            digest.update(data)
            count += len(data)
    require(count == row["bytes"] and digest.hexdigest() == row["sha256"], "standalone archive differs from the ordered parts")
    return {"present": True, "size_and_sha256_verified": True}


def verify(package):
    inputs, observed = Inputs(), {}
    manifest_raw, manifest, expected, raw_metadata, limit = prepare(package, inputs)
    verify_members(package, inputs, manifest, expected, raw_metadata, limit, observed)
    dependencies = verify_dependencies(raw_metadata["dependencies.json"], expected)
    standalone = verify_standalone(package, inputs, manifest["archive"])
    inputs.unchanged()
    return {"schema": "hepta.archive-validation.v1", "status": "passed", "ok": True,
            "package": str(package), "manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(),
            "archive": manifest["archive"], "checks": observed, "standalone_archive": standalone,
            "dependencies": dependencies, "input_files_version_checked": len(inputs.versions),
            "scope": "Package byte integrity and declared-member consistency only; no qualification reexecution or authenticity proof.",
            "original_reports_modified": False, "original_dependency_paths_opened": False,
            "qualification_claims_upgraded": False, "archive_extracted_to_filesystem": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    package = args.package.resolve(strict=True)
    require(package.is_dir(), "package must be an existing directory")
    output = args.output or package / "archive-validation.json"
    output = output.absolute()
    require(not os.path.lexists(output), "validation output already exists; choose a new --output")
    require(output.parent.is_dir(), "validation output parent must already exist")
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    try:
        report = verify(package)
    except (OSError, ValueError, TypeError, KeyError, OverflowError, RecursionError, EOFError,
            lzma.LZMAError, tarfile.TarError) as error:
        report = {"schema": "hepta.archive-validation.v1", "status": "failed", "ok": False,
                  "package": str(package), "error_type": type(error).__name__, "error": str(error)[:4000],
                  "qualification_claims_upgraded": False, "archive_extracted_to_filesystem": False}
    report["started_utc"] = started
    report["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    payload = (json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")
    with output.open("xb") as stream:
        stream.write(payload)
    print(json.dumps({"status": report["status"], "output": str(output), "error": report.get("error")}))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
