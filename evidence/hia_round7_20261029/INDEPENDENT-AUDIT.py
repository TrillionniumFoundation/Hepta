#!/usr/bin/env python3
"""Independently audit the frozen round-seven bundle after explicit authorization.

The only child commands are the hash-pinned standalone reader's verify-only and
restore modes. This file imports no project, packager, reader, or restored module.
Every raw file is compared byte-for-byte with its original allowed-root file;
every expanded file is compared with a freshly decompressed original ZIP member.
Results are archive-tooling evidence, not additional project/native tests.
"""
from __future__ import annotations

import argparse
import base64
import contextlib
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import time
import traceback
import unicodedata
import zipfile

sys.dont_write_bytecode = True
WORKSPACE = Path("/workspace/scratch/bf7d454bbc83")
PUBLICATION = WORKSPACE / "round7-publication"
ALLOWED_ROOTS = {
    "evidence": WORKSPACE / "round7-evidence",
    "guarded-development": WORKSPACE / "round7-guarded-development",
    "resource-review": WORKSPACE / "round7-resource-review",
}
FINAL = ("e57f440c32b54ffc8da795370fc288652f3c3319",
         "c5f098feb0cd1d9e465a364088b49f2568ceea31")
HISTORICAL = ("e6b10e9b74c6585f9dba18a78a31cf8f36c071c5",
              "18d5689f68baa2b1e0c496b1ee097adffe43ae39")
REVIEWED_READER = "e75a5134c187354549055754d3305421fafc0d0b6b23bf88cfea0d504da06cde"
REVIEWED_PACKAGER = "24b478e19407dc7396ca71264bfbe28da6fc5b117157f3f8fcbd7ba1fff73362"
PUBLIC_WORKFLOWS = {
    "native-hosts": ".github/workflows/hepta-native-hosts.yml",
    "cpp-upstream-hosts": ".github/workflows/hepta-cpp-upstream-hosts.yml",
    "six-outcome": ".github/workflows/hepta-six-outcomes.yml",
    "integrated": ".github/workflows/hepta-qualification.yml",
}
CHUNK = 1024 * 1024
MAX_JSON, MAX_FILE, MAX_MEMBER = 64 * CHUNK, 512 * CHUNK, 128 * CHUNK
SHA = re.compile(r"[0-9a-f]{64}")
FORBIDDEN = ("round7-ci-private", "private-quarantine", "private-transfer",
             "round7-transfer-private")


def require(value, message):
    if not value:
        raise ValueError(message)


def utc():
    return datetime.now(timezone.utc).isoformat()


def identity(data):
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False,
                       allow_nan=False) + "\n").encode("utf-8")


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key: " + key)
        result[key] = value
    return result


def parse_json(data):
    require(len(data) <= MAX_JSON, "JSON exceeds audit bound")
    return json.loads(data.decode("utf-8"), object_pairs_hook=unique_pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(
                          ValueError("nonfinite JSON value: " + value)))


def safe_relative(value):
    require(isinstance(value, str) and value, "missing relative path")
    path = PurePosixPath(value)
    require(bool(path.parts) and not path.is_absolute() and path.as_posix() == value
            and "\\" not in value and ":" not in value,
            "noncanonical relative path: " + value)
    require(unicodedata.normalize("NFC", value) == value
            and len(value.encode("utf-8")) <= 1024
            and not any(unicodedata.category(c) in {"Cc", "Cf"} for c in value),
            "unsafe Unicode path: " + value)
    reserved = {"con", "prn", "aux", "nul",
                *("com" + str(i) for i in range(1, 10)),
                *("lpt" + str(i) for i in range(1, 10))}
    for part in path.parts:
        lowered = part.casefold()
        require(part not in {"", ".", ".."} and not part.endswith((" ", "."))
                and len(part.encode("utf-8")) <= 255 and lowered != ".git"
                and not any(token in lowered for token in FORBIDDEN)
                and lowered.split(".", 1)[0] not in reserved,
                "forbidden path component: " + value)
    return path


class Names:
    def __init__(self):
        self.paths = {}
        self.explicit = set()

    def add(self, value, kind):
        parts = safe_relative(value).parts
        require(value not in self.explicit, "duplicate path: " + value)
        for i in range(len(parts)):
            path = "/".join(parts[:i + 1])
            wanted = kind if i == len(parts) - 1 else "directory"
            key = path.casefold()
            require(key not in self.paths or self.paths[key] == (path, wanted),
                    "path alias or prefix collision: " + path)
            self.paths[key] = (path, wanted)
        self.explicit.add(value)


@contextlib.contextmanager
def directory_fd(path):
    require(os.name == "posix" and all(hasattr(os, name) for name in
            ("O_NOFOLLOW", "O_DIRECTORY", "O_NONBLOCK")), "POSIX no-follow opens required")
    absolute = Path(os.path.abspath(path))
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in absolute.parts[1:]:
            next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                              dir_fd=fd)
            os.close(fd)
            fd = next_fd
        yield fd
    finally:
        os.close(fd)


@contextlib.contextmanager
def open_regular(root, relative):
    parts = safe_relative(relative).parts
    with directory_fd(root) as root_fd:
        parent = os.dup(root_fd)
    fd = None
    try:
        for part in parts[:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                              dir_fd=parent)
            os.close(parent)
            parent = next_fd
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                     dir_fd=parent)
        value = os.fstat(fd)
        require(stat.S_ISREG(value.st_mode) and value.st_nlink == 1,
                "not an independent regular file: " + relative)
        with os.fdopen(fd, "rb") as stream:
            fd = None
            yield stream
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


def stat_identity(stream):
    value = os.fstat(stream.fileno())
    return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
            value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def read_regular(root, relative, limit=MAX_JSON):
    with open_regular(root, relative) as stream:
        before = stat_identity(stream)
        require(before[4] <= limit, "file exceeds read bound: " + relative)
        data = stream.read(limit + 1)
        require(len(data) <= limit and stat_identity(stream) == before,
                "file changed while read: " + relative)
    return data


def compare_streams(original, restored, limit):
    original_hash, restored_hash = hashlib.sha256(), hashlib.sha256()
    original_size = restored_size = 0
    equal, first_unequal_chunk = True, None
    while True:
        left = original.read(min(CHUNK, limit - original_size + 1))
        right = restored.read(min(CHUNK, limit - restored_size + 1))
        if left != right:
            equal = False
            if first_unequal_chunk is None:
                first_unequal_chunk = min(original_size, restored_size)
        original_size += len(left)
        restored_size += len(right)
        require(original_size <= limit and restored_size <= limit,
                "comparison exceeds declared payload size")
        original_hash.update(left)
        restored_hash.update(right)
        if not left and not right:
            break
    return {"byte_for_byte_equal": equal, "original_bytes": original_size,
            "restored_bytes": restored_size, "original_sha256": original_hash.hexdigest(),
            "restored_sha256": restored_hash.hexdigest(),
            "first_unequal_chunk_offset": first_unequal_chunk}


def validate_identity(row, limit, label):
    require(isinstance(row, dict) and type(row.get("bytes")) is int
            and 0 <= row["bytes"] <= limit and isinstance(row.get("sha256"), str)
            and SHA.fullmatch(row["sha256"]), "invalid byte identity: " + label)


def require_match(actual, expected, label):
    require(actual == {"bytes": expected["bytes"], "sha256": expected["sha256"]},
            "byte identity differs: " + label)


def require_comparison(actual, expected, label):
    require(actual["byte_for_byte_equal"] is True
            and actual["original_bytes"] == actual["restored_bytes"] == expected["bytes"]
            and actual["original_sha256"] == actual["restored_sha256"] == expected["sha256"],
            "original, restored, or indexed bytes differ: " + label)


def local_path(path):
    path = Path(os.path.abspath(path))
    require(path.is_relative_to(PUBLICATION) and path != PUBLICATION,
            "audit paths must stay within round7-publication")
    safe_relative(path.relative_to(PUBLICATION).as_posix())
    return path


def require_absent(path):
    with directory_fd(path.parent) as parent:
        try:
            os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return
    raise ValueError("output must be a new path: " + str(path))


def new_directory(path):
    with directory_fd(path.parent) as parent:
        os.mkdir(path.name, 0o700, dir_fd=parent)


def write_new(root, name, data):
    require(len(safe_relative(name).parts) == 1, "receipt files must be direct children")
    with directory_fd(root) as parent:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=parent)
    with os.fdopen(fd, "wb") as target:
        target.write(data)
        target.flush()
        os.fchmod(target.fileno(), 0o644)
    return {"path": name, **identity(data)}


def metadata_inputs(args):
    archive_raw = read_regular(args.bundle, "ARCHIVE.json")
    require(identity(archive_raw)["sha256"] == args.archive_manifest_sha256,
            "owner-pinned ARCHIVE.json SHA differs")
    archive = parse_json(archive_raw)
    require(archive.get("schema") == "hepta.hia-round7.archive.v1", "wrong archive schema")
    pinned = {"ARCHIVE.json": identity(archive_raw)}
    loaded = {}
    for key, name in (("selection", "INPUT_SELECTION.json"), ("index", "RAW-INDEX.json"),
                      ("reader", "RESTORE.py"), ("packager", "PACKAGER.py")):
        descriptor = archive.get(key)
        validate_identity(descriptor, MAX_JSON, name)
        require(descriptor.get("path") == name, "unexpected metadata filename")
        raw = read_regular(args.bundle, name)
        require_match(identity(raw), descriptor, name)
        pinned[name] = identity(raw)
        loaded[key] = raw
    require(pinned["RESTORE.py"]["sha256"] == REVIEWED_READER
            and pinned["PACKAGER.py"]["sha256"] == REVIEWED_PACKAGER,
            "bundled reader or packager differs from independently reviewed bytes")
    frozen = read_regular(args.selection.parent, args.selection.name)
    require(identity(frozen)["sha256"] == args.selection_sha256
            and frozen == loaded["selection"], "external frozen selection differs from bundle")
    selection, index = parse_json(frozen), parse_json(loaded["index"])
    require(selection.get("schema") == "hepta.hia-round7.input-selection.v1"
            and index.get("schema") == "hepta.hia-round7.raw-index.v1", "wrong input schema")
    for value in (archive, selection, index):
        require((value.get("source_commit"), value.get("source_tree")) == FINAL,
                "root final-source identity differs")
    require(selection.get("public_evidence_only") is True
            and archive.get("private_original_verified_zip_included") is False
            and index.get("private_original_verified_zip_included") is False,
            "public-only declarations differ")
    groups = selection.get("evidence_inputs")
    require(isinstance(groups, list) and index.get("evidence_inputs") == groups,
            "historical/mixed provenance groups differ")
    group_map = {}
    for group in groups:
        name = group.get("id")
        require(isinstance(name, str) and name not in group_map, "duplicate/missing input group")
        source = (group.get("source_commit"), group.get("source_tree"))
        if group.get("kind") == "final-source-execution":
            require(source == FINAL and name.startswith("e57-"), "wrong final execution group")
        elif group.get("kind") == "historical-execution":
            require(source == HISTORICAL and name.startswith("e6-"), "wrong historical group")
        else:
            require(source == (None, None) and bool(group.get("description")),
                    "mixed/development/review group must retain explicit null source")
        group_map[name] = group
    rows, namespace, raw_map = [], Names(), {}
    require(isinstance(selection.get("files"), list) and 0 < len(selection["files"]) <= 100000,
            "invalid selected file list")
    for row in selection["files"]:
        component = row.get("component")
        require(component in ALLOWED_ROOTS, "file outside the three allowed roots")
        relative = safe_relative(row.get("relative")).as_posix()
        name = component + "/" + relative
        require(row.get("archive_path") == name and row.get("evidence_input") in group_map,
                "selection mapping or evidence group differs")
        namespace.add(name, "file")
        validate_identity(row, MAX_FILE, name)
        rows.append({"path": name, "bytes": row["bytes"], "sha256": row["sha256"],
                     "mode": 0o644, "evidence_input": row["evidence_input"]})
        raw_map[name] = row
    rows.sort(key=lambda row: row["path"])
    total = sum(row["bytes"] for row in rows)
    require(index.get("files") == rows and selection.get("file_count") == index.get("file_count")
            == archive.get("file_count") == len(rows)
            and selection.get("bytes") == index.get("bytes")
            == archive.get("uncompressed_file_bytes") == total,
            "raw inventory or aggregate byte counts differ")
    require(index.get("selection") == archive["selection"], "index selection binding differs")
    descriptors, artifact_ids, cohort_counts = {}, set(), {}
    require(isinstance(selection.get("public_ci_zips"), list)
            and len(selection["public_ci_zips"]) == 32, "expected exactly 32 original public CI ZIPs")
    for row in selection["public_ci_zips"]:
        name = safe_relative(row.get("archive_path")).as_posix()
        require(name in raw_map and name.endswith(".zip") and "verified" not in name.casefold()
                and name not in descriptors, "unexpected original CI ZIP")
        group = group_map[raw_map[name]["evidence_input"]]
        require((row.get("source_commit"), row.get("source_tree")) ==
                (group["source_commit"], group["source_tree"]) in (FINAL, HISTORICAL),
                "ZIP/source group identity differs")
        profile = row.get("workflow_profile")
        require(profile in PUBLIC_WORKFLOWS and row.get("workflow_path") == PUBLIC_WORKFLOWS[profile],
                "private or unexpected workflow ZIP")
        for key in ("run_id", "artifact_id", "run_attempt"):
            require(type(row.get(key)) is int and 0 < row[key] < 2**63, "invalid CI identifier")
        require(row["artifact_id"] not in artifact_ids, "duplicate artifact identity")
        artifact_ids.add(row["artifact_id"])
        descriptors[name] = row
        cohort_key = (row["source_commit"], profile)
        cohort_counts[cohort_key] = cohort_counts.get(cohort_key, 0) + 1
    for commit, unused_tree in (FINAL, HISTORICAL):
        for profile, count in (("native-hosts", 7), ("cpp-upstream-hosts", 7),
                               ("six-outcome", 1), ("integrated", 1)):
            require(cohort_counts.get((commit, profile)) == count, "public ZIP cohort is incomplete")
    require({name for name in raw_map if name.lower().endswith(".zip")} == set(descriptors),
            "unapproved loose ZIP in raw selection")
    expansions = index.get("zip_expansions")
    require(isinstance(expansions, list) and len(expansions) == 32, "ZIP expansion inventory incomplete")
    expansion_map = {}
    for expansion in expansions:
        name = expansion.get("archive")
        require(name in descriptors and name not in expansion_map, "duplicate/unexpected ZIP index")
        descriptor = descriptors[name]
        for key in ("artifact_id", "run_id", "run_attempt", "workflow_profile", "workflow_path",
                    "source_commit", "source_tree"):
            require(expansion.get(key) == descriptor[key], "ZIP provenance differs: " + key)
        require(expansion.get("destination") == "expanded-ci/artifact-" + str(descriptor["artifact_id"]),
                "expanded artifact destination differs")
        require(isinstance(expansion.get("members"), list), "ZIP members missing")
        inner = Names()
        for member in expansion["members"]:
            require(member.get("kind") in {"file", "directory"}, "invalid ZIP member kind")
            inner.add(member.get("path"), member["kind"])
            validate_identity(member, 0 if member["kind"] == "directory" else MAX_MEMBER,
                              member["path"])
            require(type(member.get("mode")) is int and 0 <= member["mode"] <= 0o777
                    and type(member.get("compression")) is int, "invalid ZIP indexed metadata")
        require(expansion.get("member_count") == len(expansion["members"])
                and expansion.get("file_count") == sum(m["kind"] == "file" for m in expansion["members"])
                and expansion.get("bytes") == sum(m["bytes"] for m in expansion["members"]),
                "ZIP indexed aggregate counts differ")
        expansion_map[name] = expansion
    require(archive.get("original_public_ci_zip_count") == 32
            and archive.get("original_public_ci_member_count") == sum(
                value["member_count"] for value in expansions), "archive ZIP counts differ")
    parts, joined, joined_size = archive.get("parts"), hashlib.sha256(), 0
    require(isinstance(parts, list) and 0 < len(parts) <= 1000, "archive parts missing")
    for number, row in enumerate(parts, 1):
        name = "parts/raw-evidence.tar.xz.part" + str(number).zfill(3)
        validate_identity(row, 6 * CHUNK, name)
        require(row.get("path") == name and row["bytes"] > 0
                and (number == len(parts) or row["bytes"] == 6 * CHUNK), "archive part mapping differs")
        data = read_regular(args.bundle, name, 6 * CHUNK)
        require_match(identity(data), row, name)
        pinned[name] = identity(data)
        joined.update(data)
        joined_size += len(data)
    require(joined_size == archive.get("bytes") and joined.hexdigest() == archive.get("sha256"),
            "independently joined archive identity differs")
    return archive, selection, index, raw_map, expansion_map, pinned


def command_record(args, label, command):
    started_at, start = utc(), time.monotonic()
    try:
        result = subprocess.run(command, cwd=PUBLICATION, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=900, check=False)
        output, error, returncode, timed_out = result.stdout, result.stderr, result.returncode, False
    except subprocess.TimeoutExpired as exc:
        output, error, returncode, timed_out = exc.stdout or b"", exc.stderr or b"", None, True
    record = {"label": label, "argv": command, "cwd": str(PUBLICATION),
              "started_at_utc": started_at, "ended_at_utc": utc(),
              "elapsed_seconds": time.monotonic() - start,
              "returncode": returncode, "timed_out": timed_out}
    for key, data in (("stdout", output), ("stderr", error)):
        record[key] = write_new(args.receipts, label + "." + key + ".log", data)
        record[key]["content_base64"] = base64.b64encode(data).decode("ascii")
        try:
            record[key]["content_utf8"] = data.decode("utf-8")
        except UnicodeDecodeError:
            pass
    try:
        record["parsed_result"] = parse_json(output)
    except (ValueError, UnicodeError):
        record["parsed_result"] = None
    return record


def validate_reader_result(record, args, archive, index, restore):
    value = record.get("parsed_result")
    require(record["returncode"] == 0 and record["timed_out"] is False
            and isinstance(value, dict), "standalone reader command failed: " + record["label"])
    expected = {
        "schema": "hepta.hia-round7.restore-verification.v1", "all_passed": True,
        "source_commit": FINAL[0], "source_tree": FINAL[1],
        "evidence_input_groups": len(index["evidence_inputs"]),
        "archive_manifest_sha256": args.archive_manifest_sha256,
        "archive_sha256": archive["sha256"], "parts": len(archive["parts"]),
        "raw_files": index["file_count"], "raw_file_bytes": index["bytes"],
        "original_public_ci_zips_verified": 32,
        "ci_zip_members_verified": archive["original_public_ci_member_count"],
        "ci_expanded_files": sum(row["file_count"] for row in index["zip_expansions"]) if restore else 0,
        "ci_expanded_bytes": sum(row["bytes"] for row in index["zip_expansions"]) if restore else 0,
        "project_code_executed": False, "restored_regular_file_mode": "0644",
        "output": str(args.restore_output) if restore else None,
    }
    for key, wanted in expected.items():
        require(value.get(key) == wanted, "reader output binding differs: " + key)
    record["result_binding_passed"] = True


def verify_pins(args, pinned):
    for name, expected in pinned.items():
        require_match(identity(read_regular(args.bundle, name)), expected, name)
    require(identity(read_regular(args.selection.parent, args.selection.name))["sha256"]
            == args.selection_sha256, "external frozen selection changed")


def restored_namespace(root):
    observed, names = {}, Names()
    with directory_fd(root) as fd:
        require(stat.S_IMODE(os.fstat(fd).st_mode) == 0o700, "restore root mode differs")
    def walk(parent, prefix):
        with directory_fd(parent) as fd:
            with os.scandir(fd) as iterator:
                entries = sorted(iterator, key=lambda entry: entry.name)
            for entry in entries:
                name = prefix + entry.name
                value = entry.stat(follow_symlinks=False)
                if stat.S_ISDIR(value.st_mode):
                    kind = "directory"
                else:
                    require(stat.S_ISREG(value.st_mode) and value.st_nlink == 1
                            and stat.S_IMODE(value.st_mode) == 0o644,
                            "restored symlink/special/hardlinked/executable file: " + name)
                    kind = "file"
                names.add(name, kind)
                observed[name] = {"kind": kind, "stat": [value.st_dev, value.st_ino, value.st_mode,
                                  value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns]}
                if kind == "directory":
                    walk(parent / entry.name, name + "/")
    walk(root, "")
    return observed


def compare_all(args, raw_map, expansions, comparison):
    expected_names = Names()
    for name in sorted(raw_map):
        expected_names.add(name, "file")
    for name, expansion in sorted(expansions.items()):
        for member in expansion["members"]:
            expected_names.add(expansion["destination"] + "/" + member["path"], member["kind"])
    expected = {name: kind for name, kind in expected_names.paths.values()}
    before = restored_namespace(args.restore_output)
    require({name: row["kind"] for name, row in before.items()} == expected,
            "restored paths differ (missing, extra, or wrong kind)")
    comparison["restored_namespace"] = {"expected_files": sum(k == "file" for k in expected.values()),
        "expected_directories": sum(k == "directory" for k in expected.values()),
        "exact_path_and_kind_match": True, "all_regular_file_modes_0644": True,
        "symlinks_special_files_or_hardlinks": 0, "before_after_unchanged": False}
    original_stats = {}
    for name, row in sorted(raw_map.items()):
        root = ALLOWED_ROOTS[row["component"]]
        with open_regular(root, row["relative"]) as original, open_regular(args.restore_output, name) as restored:
            original_before, restored_before = stat_identity(original), stat_identity(restored)
            result = compare_streams(original, restored, row["bytes"])
            require(stat_identity(original) == original_before and stat_identity(restored) == restored_before,
                    "raw file changed while compared: " + name)
        receipt = {"path": name, "component": row["component"], "relative": row["relative"],
                   "evidence_input": row["evidence_input"], **result,
                   "selection_and_raw_index_match": False, "stable_during_read": True}
        comparison["raw_files"].append(receipt)
        require_comparison(result, row, name)
        receipt["selection_and_raw_index_match"] = True
        original_stats[name] = original_before
    comparison["raw_files_compared"] = len(comparison["raw_files"])
    comparison["raw_bytes_compared"] = sum(row["original_bytes"] for row in comparison["raw_files"])
    for name, expansion in sorted(expansions.items()):
        row = raw_map[name]
        record = {key: expansion[key] for key in ("archive", "destination", "artifact_id", "run_id",
                  "run_attempt", "workflow_profile", "workflow_path", "source_commit", "source_tree")}
        record.update({"original_zip_bytes_bound_by_raw_comparison": True,
                       "original_zip_sha256": row["sha256"], "members": [], "all_passed": False})
        comparison["expanded_ci"].append(record)
        member_map = {member["path"]: member for member in expansion["members"]}
        names, seen, zip_total = Names(), set(), 0
        with open_regular(ALLOWED_ROOTS[row["component"]], row["relative"]) as raw:
            original_before = stat_identity(raw)
            require(original_before == original_stats[name], "original ZIP changed after raw comparison")
            with zipfile.ZipFile(raw) as archive:
                require(len(archive.infolist()) == expansion["member_count"], "original ZIP member count differs")
                for info in archive.infolist():
                    require(info.orig_filename == info.filename and not (info.flag_bits & 1),
                            "truncated or encrypted original ZIP member")
                    kind = "directory" if info.is_dir() else "file"
                    member_name = info.filename[:-1] if info.is_dir() else info.filename
                    names.add(member_name, kind)
                    require(member_name in member_map, "unindexed original ZIP member")
                    seen.add(member_name)
                    expected_member = member_map[member_name]
                    mode = info.external_attr >> 16
                    allowed_type = stat.S_IFDIR if kind == "directory" else stat.S_IFREG
                    require(stat.S_IFMT(mode) in {0, allowed_type} and not (mode & 0o7000)
                            and (kind == "directory" or not (info.external_attr & 0x10)),
                            "special or ambiguous original ZIP member")
                    require(expected_member["kind"] == kind and expected_member["bytes"] == info.file_size
                            and expected_member["mode"] == stat.S_IMODE(mode)
                            and expected_member["compression"] == info.compress_type,
                            "original ZIP/member index metadata differs")
                    destination = expansion["destination"] + "/" + member_name
                    with archive.open(info) as source:
                        if kind == "file":
                            with open_regular(args.restore_output, destination) as restored:
                                restored_before = stat_identity(restored)
                                result = compare_streams(source, restored, expected_member["bytes"])
                                require(stat_identity(restored) == restored_before,
                                        "expanded member changed while read")
                            require_comparison(result, expected_member, destination)
                            member_result = {"path": member_name, "kind": kind, **result,
                                             "raw_index_match": True, "stable_during_read": True}
                        else:
                            data = source.read(1)
                            require(data == b"", "nonempty ZIP directory member")
                            require_match(identity(data), expected_member, destination)
                            member_result = {"path": member_name, "kind": kind,
                                "bytes": 0, "sha256": identity(data)["sha256"],
                                "raw_index_match": True, "restored_directory_exists": True,
                                "file_byte_comparison_applicable": False}
                    record["members"].append(member_result)
                    zip_total += info.file_size
            require(stat_identity(raw) == original_before, "original ZIP changed during member comparison")
        require(seen == set(member_map) and zip_total == expansion["bytes"], "ZIP member coverage incomplete")
        record["members"].sort(key=lambda member: member["path"])
        record.update({"member_count": len(seen), "file_count": expansion["file_count"],
                       "bytes": zip_total, "all_passed": True})
    after = restored_namespace(args.restore_output)
    require(after == before, "restored namespace or file metadata changed during comparison")
    comparison["restored_namespace"]["before_after_unchanged"] = True
    comparison["original_public_ci_zips_compared"] = len(comparison["expanded_ci"])
    comparison["expanded_members_compared"] = sum(row["member_count"] for row in comparison["expanded_ci"])
    comparison["expanded_files_compared"] = sum(row["file_count"] for row in comparison["expanded_ci"])
    comparison["expanded_bytes_compared"] = sum(row["bytes"] for row in comparison["expanded_ci"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true", required=True,
                        help="Only use after the owner explicitly authorizes the completed bundle audit.")
    parser.add_argument("--bundle", type=Path, default=PUBLICATION / "bundle-e57")
    parser.add_argument("--selection", type=Path, default=PUBLICATION / "INPUT_SELECTION.json")
    parser.add_argument("--receipts", type=Path, default=PUBLICATION / "independent-e57")
    parser.add_argument("--restore-output", type=Path, default=PUBLICATION / "restored-e57-independent")
    parser.add_argument("--selection-sha256", required=True)
    parser.add_argument("--archive-manifest-sha256", required=True)
    args = parser.parse_args()
    for key in ("bundle", "selection", "receipts", "restore_output"):
        setattr(args, key, local_path(getattr(args, key)))
    require(SHA.fullmatch(args.selection_sha256) and SHA.fullmatch(args.archive_manifest_sha256),
            "full lowercase owner-approved selection and archive manifest SHA-256 values are required")
    dirs = (args.bundle, args.receipts, args.restore_output)
    require(all(not a.is_relative_to(b) and not b.is_relative_to(a)
                for i, a in enumerate(dirs) for b in dirs[i + 1:]), "audit directories must be disjoint")
    require(not any(args.selection.is_relative_to(path) for path in dirs),
            "external frozen selection must be outside bundle/output directories")
    require_absent(args.receipts)
    require_absent(args.restore_output)
    new_directory(args.receipts)
    script_path = Path(os.path.abspath(__file__))
    script = {"path": str(script_path), **identity(read_regular(script_path.parent, script_path.name))}
    common = {"created_at_utc": utc(), "source_commit": FINAL[0], "source_tree": FINAL[1],
              "source_identity_scope": "Final root identity; historical and mixed input groups retain their own identities.",
              "bundle": str(args.bundle), "external_frozen_selection": str(args.selection),
              "selection_sha256": args.selection_sha256,
              "archive_manifest_sha256": args.archive_manifest_sha256,
              "audit_script": script, "restore_output": str(args.restore_output),
              "archive_tooling_audit_only": True, "project_tests_or_native_benchmarks_run": False,
              "restored_or_archived_code_executed": False, "private_original_verified_zip_read": False,
              "writes_to_frozen_evidence_roots": False, "remote_writes": False}
    restore = {**common, "schema": "hepta.hia-round7.independent-restore.v1", "all_passed": False,
               "python_executable": sys.executable, "python_version": sys.version, "commands": [],
               "logs_embedded_as_base64_and_utf8_when_valid": True,
               "only_child_program": "Hash-pinned standalone RESTORE.py in the bundle, run with isolated Python.",
               "reviewed_reader_sha256": REVIEWED_READER, "reviewed_packager_sha256": REVIEWED_PACKAGER}
    comparison = {**common, "schema": "hepta.hia-round7.independent-compare.v1", "all_passed": False,
                  "independence": "No imports or helper calls from RESTORE.py, PACKAGER.py, or build_selection.py; stdlib file/ZIP traversal and direct byte comparison.",
                  "allowed_original_roots": {key: str(value) for key, value in ALLOWED_ROOTS.items()},
                  "raw_files": [], "expanded_ci": []}
    phase = "metadata_and_original_selection_binding"
    try:
        archive, selection, index, raw_map, expansions, pinned = metadata_inputs(args)
        for receipt in (restore, comparison):
            receipt["bundle_inputs"] = pinned
            receipt["archive_sha256"] = archive["sha256"]
            receipt["evidence_inputs"] = selection["evidence_inputs"]
        phase = "standalone_verify_only"
        command = [sys.executable, "-I", "-B", str(args.bundle / "RESTORE.py"), "--verify-only"]
        record = command_record(args, "VERIFY_ONLY", command)
        restore["commands"].append(record)
        validate_reader_result(record, args, archive, index, False)
        verify_pins(args, pinned)
        phase = "standalone_full_restore_and_expand_ci"
        command = [sys.executable, "-I", "-B", str(args.bundle / "RESTORE.py"), "--output",
                   str(args.restore_output), "--expand-ci"]
        record = command_record(args, "RESTORE_EXPAND_CI", command)
        restore["commands"].append(record)
        validate_reader_result(record, args, archive, index, True)
        verify_pins(args, pinned)
        restore["all_passed"] = True
        restore["bundle_inputs_unchanged_through_reader_commands"] = True
        phase = "independent_original_raw_and_zip_member_comparison"
        compare_all(args, raw_map, expansions, comparison)
        verify_pins(args, pinned)
        require(identity(read_regular(script_path.parent, script_path.name))["sha256"] == script["sha256"],
                "independent audit script changed during execution")
        comparison["bundle_inputs_unchanged_through_independent_comparison"] = True
        comparison["all_passed"] = True
    except Exception as error:
        failure = {"phase": phase, "type": type(error).__name__, "message": str(error),
                   "traceback": traceback.format_exc()}
        if not restore["all_passed"]:
            restore["failure"] = failure
        comparison["failure"] = failure
    restore["finished_at_utc"] = utc()
    restore_identity = write_new(args.receipts, "INDEPENDENT-RESTORE.json", json_bytes(restore))
    comparison["independent_restore_receipt"] = restore_identity
    comparison["finished_at_utc"] = utc()
    comparison_identity = write_new(args.receipts, "INDEPENDENT-COMPARE.json", json_bytes(comparison))
    print(json.dumps({"archive_tooling_audit_only": True,
                      "restore_passed": restore["all_passed"], "compare_passed": comparison["all_passed"],
                      "receipts_directory": str(args.receipts), "restore_receipt": restore_identity,
                      "compare_receipt": comparison_identity,
                      "raw_files_compared": comparison.get("raw_files_compared", 0),
                      "public_ci_zips_compared": comparison.get("original_public_ci_zips_compared", 0),
                      "expanded_members_compared": comparison.get("expanded_members_compared", 0)},
                     indent=2, sort_keys=True))
    return 0 if restore["all_passed"] and comparison["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
