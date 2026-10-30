#!/usr/bin/env python3
"""Assemble the explicitly frozen round-seven public evidence selection.

The only executable verification step is the standalone RESTORE.py reader
copied from this directory. No selected project or archived program is run.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import lzma
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import zipfile

BASE = Path(os.path.abspath(__file__)).parent
ROOT = BASE.parent
REPO = ROOT / "hepta-round6-integration"
ROOTS = {
    "evidence": ROOT / "round7-evidence",
    "guarded-development": ROOT / "round7-guarded-development",
    "resource-review": ROOT / "round7-resource-review",
}
spec = importlib.util.spec_from_file_location("round7_evidence_reader", BASE / "RESTORE.py")
reader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reader)


def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n").encode()


def write_bytes(root, name, data):
    with reader.new_file(root, name) as target:
        target.write(data)
    return {"path": name, **reader.identity(data)}


def write_json(root, name, value):
    return write_bytes(root, name, json_bytes(value))


def git(*args):
    result = subprocess.run(["git", "-C", str(REPO), *args], capture_output=True, check=True)
    return result.stdout


def source_state(expected_source):
    head = git("rev-parse", "HEAD").decode("ascii").strip()
    tree = git("rev-parse", "HEAD^{tree}").decode("ascii").strip()
    status = git("status", "--porcelain=v1", "--untracked-files=all").decode("utf-8")
    listing = git("ls-tree", "-r", "-z", "--full-tree", expected_source)
    reader.require(git("rev-parse", "HEAD").decode("ascii").strip() == head,
                   "source changed during identity snapshot")
    return {"head": head, "tree": tree, "status": status,
            "tracked_tree_listing_sha256": hashlib.sha256(listing).hexdigest(),
            "scope": "Git HEAD, tree, status and raw tree listing; this packaging step does not rerun project qualification."}


class CountingWriter:
    def __init__(self, target):
        self.target, self.bytes = target, 0

    def write(self, data):
        size = self.target.write(data)
        reader.require(size == len(data), "incomplete compressed stream write")
        self.bytes += size
        return size

    def flush(self):
        return self.target.flush()


class HashingReader:
    def __init__(self, source):
        self.source, self.bytes, self.digest = source, 0, hashlib.sha256()

    def read(self, size=-1):
        data = self.source.read(size)
        self.bytes += len(data)
        self.digest.update(data)
        return data


def local_child(path, label):
    path = Path(os.path.abspath(path))
    reader.require(path.is_relative_to(BASE) and path != BASE, label + " must be within round7-publication")
    # directory_fd/new_file enforce nonsymlink actual parents when opened.
    return path


def build(args):
    selection_path = local_child(args.selection, "selection")
    output_path = local_child(args.output, "output")
    work_path = local_child(args.workdir, "work directory")
    reader.require(not output_path.is_relative_to(work_path) and not work_path.is_relative_to(output_path),
                   "output and work directory must be disjoint")
    reader.require(isinstance(args.selection_sha256, str) and reader.SHA.fullmatch(args.selection_sha256),
                   "a full lowercase frozen selection SHA-256 is required")
    selection_raw = reader.read_regular(selection_path.parent, selection_path.name)
    reader.require(hashlib.sha256(selection_raw).hexdigest() == args.selection_sha256,
                   "frozen INPUT_SELECTION bytes differ")
    selection = reader.json_value(selection_raw)
    index_rows, zipmap = reader.validate_selection(selection)
    source_commit, source_tree = selection["source_commit"], selection["source_tree"]
    source_before = source_state(source_commit)
    reader.require(source_before["head"] == source_commit and source_before["tree"] == source_tree
                   and not source_before["status"], "source must be clean at the exact published round-seven commit")
    reader_raw = reader.read_regular(BASE, "RESTORE.py")
    packager_raw = reader.read_regular(BASE, Path(__file__).name)
    output = reader.new_directory(output_path)
    work = reader.new_directory(work_path)
    try:
        selection_identity = write_bytes(output, "INPUT_SELECTION.json", selection_raw)
        reader_identity = write_bytes(output, "RESTORE.py", reader_raw)
        packager_identity = write_bytes(output, "PACKAGER.py", packager_raw)
        expansions = []
        with tempfile.TemporaryDirectory(prefix="round7-input-stage-", dir=work) as temporary:
            staged = Path(temporary)
            selection_rows = {row["archive_path"]: row for row in selection["files"]}
            for expected in index_rows:
                name = expected["path"]
                row = selection_rows[name]
                root = ROOTS[row["component"]]
                with reader.new_file(staged, name) as target:
                    size, sha = reader.stable_copy(root, row["relative"], (target,), limit=row["bytes"])
                    reader.verify_identity(size, sha, expected, name)
                with reader.regular_file(staged, name) as stream:
                    is_zip = zipfile.is_zipfile(stream)
                    reader.require(is_zip == (name in zipmap),
                                   "unapproved or malformed original ZIP: " + name)
                    if is_zip:
                        stream.seek(0)
                        descriptor = zipmap[name]
                        inventory = reader.inspect_zip(stream)
                        expansions.append({
                            "archive": name,
                            "destination": "expanded-ci/artifact-" + str(descriptor["artifact_id"]),
                            **{key: descriptor[key] for key in
                               ("artifact_id", "run_id", "run_attempt", "workflow_profile", "workflow_path",
                                "source_commit", "source_tree")},
                            **inventory,
                        })
            expansions.sort(key=lambda row: row["archive"])
            reader.require(sum(row["bytes"] for row in expansions) <= reader.MAX_ALL_ZIP_BYTES,
                           "all original ZIP members exceed total bound")
            index = {
                "schema": "hepta.hia-round7.raw-index.v1",
                "source_commit": source_commit, "source_tree": source_tree,
                "root_identity_scope": "final qualification source; historical inputs retain their declared group identities",
                "evidence_inputs": selection["evidence_inputs"],
                "file_count": len(index_rows), "bytes": selection["bytes"],
                "selection": selection_identity, "files": index_rows,
                "zip_expansions": expansions, "source_snapshot_before": source_before,
                "scope": "Explicit public round-seven execution, development, review, source-publication and CI evidence.",
                "original_file_bytes_modified": False,
                "private_original_verified_zip_included": False,
                "project_code_executed": False,
            }
            index_identity = write_json(output, "RAW-INDEX.json", index)
            reader.require(index_identity["bytes"] <= reader.MAX_JSON, "RAW-INDEX exceeds reader JSON bound")
            with reader.new_file(work, "raw-evidence.tar.xz") as raw:
                with lzma.LZMAFile(raw, "wb", format=lzma.FORMAT_XZ,
                                   check=lzma.CHECK_CRC64, preset=6) as compressed:
                    counted = CountingWriter(compressed)
                    with tarfile.open(fileobj=counted, mode="w|", format=tarfile.PAX_FORMAT) as archive:
                        for row in index_rows:
                            member = tarfile.TarInfo(row["path"])
                            member.size, member.mode, member.mtime = row["bytes"], 0o644, 0
                            member.uid = member.gid = 0
                            member.uname = member.gname = ""
                            with reader.regular_file(staged, row["path"]) as source:
                                before = reader.stat_identity(source)
                                checked = HashingReader(source)
                                archive.addfile(member, checked)
                                reader.verify_identity(checked.bytes, checked.digest.hexdigest(), row, row["path"])
                                reader.require(not source.read(1) and reader.stat_identity(source) == before,
                                               "staged bytes changed while archived")
                    tar_bytes = counted.bytes
        parts, joined, joined_size = [], hashlib.sha256(), 0
        with reader.regular_file(work, "raw-evidence.tar.xz") as stream:
            number = 0
            while True:
                data = stream.read(reader.PART_SIZE)
                if not data:
                    break
                number += 1
                reader.require(number <= 1000, "part count exceeds reader bound")
                name = "parts/raw-evidence.tar.xz.part" + str(number).zfill(3)
                parts.append(write_bytes(output, name, data))
                joined.update(data)
                joined_size += len(data)
        archive_record = {
            "schema": "hepta.hia-round7.archive.v1",
            "source_commit": source_commit, "source_tree": source_tree,
            "root_identity_scope": "final qualification source; historical inputs retain their declared group identities",
            "archive_format": "tar.xz", "part_size_limit": reader.PART_SIZE,
            "parts": parts, "bytes": joined_size, "sha256": joined.hexdigest(),
            "uncompressed_tar_bytes": tar_bytes,
            "file_count": index["file_count"], "uncompressed_file_bytes": index["bytes"],
            "index": index_identity, "selection": selection_identity,
            "reader": reader_identity, "packager": packager_identity,
            "original_public_ci_zip_count": len(expansions),
            "original_public_ci_member_count": sum(row["member_count"] for row in expansions),
            "private_original_verified_zip_included": False,
            "project_tests_or_archived_programs_executed": False,
        }
        reader.validate_index(archive_record, index, selection, index_rows, zipmap)
        archive_identity = write_json(output, "ARCHIVE.json", archive_record)
        command = [sys.executable, str(output / "RESTORE.py"), "--verify-only"]
        result = subprocess.run(command, capture_output=True)
        write_bytes(work, "VERIFY_ONLY.stdout.log", result.stdout)
        write_bytes(work, "VERIFY_ONLY.stderr.log", result.stderr)
        reader.require(result.returncode == 0, "standalone RESTORE verification failed; logs retained")
        verified = reader.json_value(result.stdout)
        reader.require(verified.get("all_passed") is True
                       and verified.get("source_commit") == source_commit
                       and verified.get("source_tree") == source_tree
                       and verified.get("archive_sha256") == archive_record["sha256"]
                       and verified.get("raw_files") == len(index_rows)
                       and verified.get("ci_zip_members_verified") == archive_record["original_public_ci_member_count"],
                       "standalone verification did not bind this complete archive")
        write_bytes(output, "VERIFY_ONLY.json", result.stdout)
        source_after = source_state(source_commit)
        reader.require(source_after == source_before, "source identity changed during assembly")
        reader.require(reader.read_regular(BASE, "RESTORE.py") == reader_raw
                       and reader.read_regular(BASE, Path(__file__).name) == packager_raw,
                       "packaging/reader tooling changed during assembly")
        assembly = {
            "schema": "hepta.hia-round7.assembly-verification.v1",
            "created_at_utc": datetime.now(timezone.utc).isoformat(),
            "source_before": source_before, "source_after": source_after, "source_unchanged": True,
            "selection_sha256": args.selection_sha256,
            "archive_manifest": archive_identity, "archive_sha256": archive_record["sha256"],
            "reader": reader_identity, "packager": packager_identity,
            "verify_command": command, "verify_returncode": result.returncode,
            "verify_stdout": reader.identity(result.stdout), "verify_stderr": reader.identity(result.stderr),
            "same_verified_staged_bytes_used": True,
            "all_original_public_zip_members_read_during_packaging_and_verification": True,
            "project_tests_or_archived_programs_executed": False, "remote_writes": False,
        }
        write_json(output, "ASSEMBLY-VERIFICATION.json", assembly)
        print(json.dumps({
            "output": str(output), "source_commit": source_commit,
            "source_tree": source_tree, "source_unchanged": True,
            "selection_sha256": args.selection_sha256,
            "raw_files": len(index_rows), "raw_bytes": index["bytes"],
            "archive_bytes": joined_size, "archive_sha256": joined.hexdigest(), "parts": len(parts),
            "original_public_ci_zips": len(expansions),
            "original_public_ci_members": archive_record["original_public_ci_member_count"],
            "standalone_verify_only_passed": True,
        }, indent=2, sort_keys=True))
    except BaseException as error:
        try:
            write_json(work, "PACKAGING-FAILURE.json", {
                "schema": "hepta.hia-round7.packaging-failure.v1",
                "source_commit": source_commit, "source_tree": source_tree,
                "selection_sha256": args.selection_sha256,
                "error_type": type(error).__name__, "error": str(error),
                "partial_output_retained": str(output), "qualified_publication": False,
            })
        except Exception:
            pass
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selection", type=Path, default=BASE / "INPUT_SELECTION.json")
    parser.add_argument("--selection-sha256", required=True)
    parser.add_argument("--output", type=Path, default=BASE / "bundle")
    parser.add_argument("--workdir", type=Path, default=BASE / "work")
    args = parser.parse_args()
    reader.require_posix()
    build(args)


if __name__ == "__main__":
    main()

