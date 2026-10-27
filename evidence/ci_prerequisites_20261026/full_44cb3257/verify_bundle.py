#!/usr/bin/env python3
"""Bounded offline verification of the exact 44cb CI originals; no extraction or native execution."""
import argparse
import base64
from collections import Counter
import io
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import stat
import tarfile
import zipfile
from hashlib import sha1
from performance_audit import CANDIDATE, COMPILER, parse, require, sha, wire, same
from report_audit import TREE, review_reports
from supplemental_audit import review_supplemental
MAX_ENCODED = 64 * 1024 * 1024
MAX_TAR = 256 * 1024 * 1024
MAX_MEMBER = 32 * 1024 * 1024


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


def verify_zip_source(proof, entries):
    require(proof["schema"] == "hepta.ci-zip-source-tree-proof.v1"
            and proof["source_commit"] == CANDIDATE and proof["root_tree"] == TREE, "ZIP source tree identity")
    commit = base64.b64decode(proof["commit_object_base64"], validate=True)
    require(sha1(b"commit " + str(len(commit)).encode() + b"\0" + commit).hexdigest() == CANDIDATE
            and commit.splitlines()[0] == ("tree " + TREE).encode(), "ZIP source commit object")
    trees = {}
    for oid, encoded in proof["tree_objects_base64"].items():
        raw = base64.b64decode(encoded, validate=True)
        require(sha1(b"tree " + str(len(raw)).encode() + b"\0" + raw).hexdigest() == oid, "ZIP source tree object")
        children, offset = {}, 0
        while offset < len(raw):
            zero = raw.index(b"\0", offset)
            mode, name = raw[offset:zero].split(b" ", 1)
            name = name.decode()
            require(zero + 21 <= len(raw) and name not in children and name not in {".", ".."}
                    and "/" not in name, "ZIP source tree entry")
            children[name] = mode.decode(), raw[zero + 1:zero + 21].hex()
            offset = zero + 21
        trees[oid] = children
    used = {TREE}
    pending = []
    for name in ("artifacts", "evidence"):
        mode, oid = trees[TREE][name]
        require(mode == "40000", "ZIP source subtree root")
        pending.append(oid)
    while pending:
        oid = pending.pop()
        if oid in used:
            continue
        used.add(oid)
        for mode, child in trees[oid].values():
            require(mode in {"40000", "100644", "100755"}, "ZIP source subtree mode")
            if mode == "40000":
                pending.append(child)
    require(used == set(trees), "ZIP source subtree proof denominator")
    for name, row in entries.items():
        parts = safe_path(name).parts
        require(parts[0] in {"artifacts", "evidence"}, "ZIP source path root")
        oid, actual = TREE, None
        for index, part in enumerate(parts):
            child = trees[oid].get(part)
            if child is None:
                break
            mode, child_oid = child
            if index == len(parts) - 1:
                require(mode in {"100644", "100755"}, "ZIP file replaces a tracked directory")
                actual = child_oid
            elif mode == "40000":
                oid = child_oid
            else:
                break
        require(actual == row["source_git_blob_sha1"], "ZIP classification differs from exact Git tree")
    return len(trees)

def unpack_archive(directory, manifest):
    require(manifest["schema"] == "hepta.ci-candidate.archive.v1"
            and manifest["encoding"] == "base64" and manifest["compression"] == "xz-preset-6-dict-64MiB",
            "archive schema or encoding differs")
    require(type(manifest["encoded_bytes"]) is int and 0 < manifest["encoded_bytes"] <= MAX_ENCODED
            and type(manifest["decoded_bytes"]) is int and 0 < manifest["decoded_bytes"] <= MAX_ENCODED,
            "archive encoded bound")
    require(type(manifest["tar_bytes"]) is int and 0 < manifest["tar_bytes"] <= MAX_TAR
            and type(manifest["uncompressed_bytes"]) is int and 0 <= manifest["uncompressed_bytes"] <= MAX_TAR,
            "archive expansion bound")
    require(type(manifest["member_count"]) is int and 0 < manifest["member_count"] <= 3000, "archive member bound")
    logical = str(safe_path(manifest["archive"]))
    parts = manifest["parts"]
    require(type(parts) is list and 1 <= len(parts) <= 32, "archive part count")
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


def verify(directory, original_zip=None):
    bundle = parse(read_regular(directory, "MANIFEST.json"))
    require(bundle["schema"] == "hepta.ci-candidate.bundle.v1" and bundle["source_commit"] == CANDIDATE,
            "bundle source identity")
    files = bundle["files"]
    archive_parts = bundle["archive_parts"]
    actual = {path.relative_to(directory).as_posix() for path in Path(directory).rglob("*") if not path.is_dir()}
    require(actual == set(files) | set(archive_parts) | {"MANIFEST.json"}, "bundle sidecar denominator")
    sidecars = {}
    for name, identity in files.items():
        raw = read_regular(directory, name)
        require(len(raw) == identity["bytes"] and sha(raw) == identity["sha256"], "sidecar identity: " + name)
        sidecars[name] = raw
    manifest = parse(sidecars["run-artifacts.manifest.json"])
    require(manifest["source_commit"] == CANDIDATE
            and [part["path"] for part in manifest["parts"]] == archive_parts, "bundle/part inventory")
    members = unpack_archive(directory, manifest)
    provider = parse(sidecars["provider-observation.json"])
    original = parse(sidecars["zip-identity.json"])
    artifact, = provider["artifact_metadata"]["artifacts"]
    job, = provider["job_metadata"]["jobs"]
    require(provider["source_commit"] == artifact["workflow_run"]["head_sha"] == CANDIDATE
            and job["id"] == 121976747689 and job["run_id"] == artifact["workflow_run"]["id"] == 40439677114
            and job["status"] == "completed", "provider terminal job/source identity")
    require(artifact["id"] == original["artifact_id"] and original["source_commit"] == CANDIDATE
            and artifact["size_in_bytes"] == original["bytes"]
            and artifact["digest"] == original["provider_digest"] == "sha256:" + original["sha256"]
            and original["digest_matches"] is True, "original provider ZIP identity")
    require(original == bundle["original_zip"], "ZIP/bundle pins differ")
    inventory = parse(sidecars["zip-inventory.json"])
    require(inventory["source_commit"] == CANDIDATE, "ZIP inventory source")
    entries = {}
    for row in inventory["members"]:
        name = str(safe_path(row["path"]))
        require(name not in entries and row["kind"] in {"artifacts", "evidence"}
                and row["classification"] in {"added_by_run", "changed_by_run", "unchanged_from_source"},
                "ZIP member/classification inventory")
        entries[name] = row
    zip_source_trees = verify_zip_source(parse(sidecars["zip-source-tree-proof.json"]), entries)
    selected = {name for name, row in entries.items() if row["classification"] != "unchanged_from_source"}
    require(selected == set(members), "all added/changed artifact and evidence files must be retained")
    for name, raw in members.items():
        row = entries[name]
        require(len(raw) == row["bytes"] and sha(raw) == row["sha256"], "ZIP/archive member identity")
        require(sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() == row["git_blob_sha1"],
                "ZIP/archive Git blob identity")
    for row in entries.values():
        if row["classification"] == "unchanged_from_source":
            require(row["git_blob_sha1"] == row["source_git_blob_sha1"], "deduplicated file differs from captured Git identity")
        elif row["classification"] == "changed_by_run":
            require(row["source_git_blob_sha1"] is not None and row["git_blob_sha1"] != row["source_git_blob_sha1"],
                    "changed tracked file classification")
        else:
            require(row["source_git_blob_sha1"] is None, "added file classification")
    if original_zip is not None:
        raw_zip = read_regular(Path(original_zip).parent, Path(original_zip).name, 512 * 1024 * 1024)
        require(len(raw_zip) == original["bytes"] and sha(raw_zip) == original["sha256"], "original provider ZIP digest")
        with zipfile.ZipFile(io.BytesIO(raw_zip)) as archive:
            records = [record for record in archive.infolist() if not record.is_dir()]
            require(len(records) == len(entries) and {record.filename for record in records} == set(entries),
                    "complete original ZIP denominator")
            for record in records:
                row = entries[record.filename]
                require(record.file_size == row["bytes"] and record.external_attr == row["zip_external_attr"],
                        "original ZIP file metadata")
                require(0 <= record.file_size <= 128 * 1024 * 1024, "original ZIP per-member bound")
                raw = archive.read(record)
                require(sha(raw) == row["sha256"] and len(raw) == row["bytes"]
                        and sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() == row["git_blob_sha1"],
                        "original ZIP member hash/Git identity")
                if record.filename in members:
                    require(raw == members[record.filename], "original ZIP/new archive exact bytes")
    copies = parse(sidecars["original-copies.json"])
    for row in copies:
        require(sidecars[row["path"]] == members[row["archive_member"]]
                and len(sidecars[row["path"]]) == row["bytes"] and sha(sidecars[row["path"]]) == row["sha256"],
                "convenience original copy differs")
    result = review_reports(members, sidecars, inventory["members"])
    require(same(result, parse(sidecars["review.json"])), "derived independent report review differs")
    supplemental = review_supplemental(members, sidecars)
    require(same(supplemental, parse(sidecars["supplemental-review.json"])), "supplemental independent review differs")
    pins = parse(sidecars["original-identities.json"])
    require(pins["source_commit"] == CANDIDATE and pins["run_id"] == 40439677114 and pins["job_id"] == 121976747689,
            "original identity header")
    require(set(pins["files"]) == set(members), "original identity denominator")
    for name, identity in pins["files"].items():
        raw = members[name]
        require(len(raw) == identity["bytes"] and sha(raw) == identity["sha256"], "pinned original report identity")
    log_name = "job-121976747689.log"
    log = sidecars[log_name]
    require(sha(log) == pins["job_log"]["sha256"] and len(log) == pins["job_log"]["bytes"]
            and len(log.decode().splitlines()) == pins["job_log"]["lines"], "complete provider-decoded job log identity")
    steps = {step["name"]: step for step in job["steps"]}
    require(steps["Run all current native and experiment qualification gates"]["conclusion"]
            == ("success" if result["full_source"]["status"] == "passed" else "failure"), "provider/full result linkage")
    require(steps["Qualify the standalone HIA interpreter and direct native paths"]["conclusion"]
            == ("success" if result["hia"]["status"] == "all_scoped_gates_passed" else "failure"), "provider/HIA result linkage")
    native = {name: raw for name, raw in members.items() if raw.startswith(b"\x7fELF")}
    classifications = Counter(row["kind"] + "/" + row["classification"] for row in entries.values())
    summary = {"schema": "hepta.ci-candidate.bundle-verification.v1", "verified": True, "source_commit": CANDIDATE,
        "provider_run_id": 40439677114, "provider_job_id": 121976747689, "provider_conclusion": job["conclusion"],
        "original_zip_rechecked": original_zip is not None, "provider_zip_files": len(entries),
        "zip_classifications": dict(classifications), "retained_members": len(members),
        "zip_deduplication_source_tree_objects": zip_source_trees,
        "retained_member_bytes": sum(map(len, members.values())), "elf_files": len(native), "elf_bytes": sum(map(len, native.values())),
        "source_snapshot_files": result["source_identity"]["files_checked_at_capture"],
        "full_source_passed": result["full_source"]["passed_gates"], "full_source_completed": result["full_source"]["completed_gates"],
        "source_unit": {key: result["full_source"]["unit"][key] for key in ("tests_run", "skipped", "failures", "errors")},
        "hia_passed": result["hia"]["passed_gates"], "hia_completed": result["hia"]["completed_gates"],
        "hia_unit": {key: result["hia"]["unit"][key] for key in ("tests_run", "skipped", "failures", "errors")},
        "namespace_check_counts": supplemental["namespace"]["counts"],
        "known_qualification_limitations": [row["id"] for row in supplemental["known_qualification_limitations"]],
        "implicit_C_declaration_diagnostics": supplemental["implicit_C_declaration_diagnostics"]["by_severity_and_symbol"],
        "performance": {kind: {key: row.get(key) for key in ("report_present", "phase", "status", "observed_raw_samples")}
                        for kind, row in result["performance"].items()},
        "native_execution_repeated": False, "performance_remeasured": False,
        "archive_extracted": False, "network_used": False, "whole_project_blockers_closed": False,
        "scope": "retained provider originals, source identities and independent data replay; a verified archive is not an overall passing qualification"}
    for name, with_zip in (("verification.json", False), ("verification-original-zip.json", True)):
        if name in sidecars:
            require(same(parse(sidecars[name]), {**summary, "original_zip_rechecked": with_zip}),
                    "retained verification summary differs")
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--original-zip", type=Path)
    parser.add_argument("--directory", type=Path, default=Path(__file__).resolve().parent)
    args = parser.parse_args()
    print(json.dumps(verify(args.directory.resolve(), args.original_zip), indent=2, sort_keys=True))
