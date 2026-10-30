#!/usr/bin/env python3
"""Verify or restore the explicitly frozen round-seven public evidence.

Standalone Python standard-library reader for POSIX hosts. Archived programs
are never executed; restored regular files are data (mode 0644).
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
import tempfile
import unicodedata
import zipfile

COMPONENTS = {"evidence", "guarded-development", "resource-review"}
PUBLIC_WORKFLOWS = {
    "native-hosts": ".github/workflows/hepta-native-hosts.yml",
    "cpp-upstream-hosts": ".github/workflows/hepta-cpp-upstream-hosts.yml",
    "migration": ".github/workflows/hepta-migration.yml",
    "integrated": ".github/workflows/hepta-qualification.yml",
    "six-outcome": ".github/workflows/hepta-six-outcomes.yml",
}
INPUT_KINDS = {"final-source-execution", "historical-execution", "development", "review",
               "publication-metadata", "toolchain-receipt", "mixed-provenance"}
QUALIFICATION_STATUSES = {"passed", "failed", "incomplete", "mixed", "not-qualification"}
PART_SIZE = 6 * 1024 * 1024
CHUNK = 1024 * 1024
MAX_JSON = 64 * CHUNK
MAX_FILES = 100_000
MAX_FILE = 512 * CHUNK
MAX_RAW = 4 * 1024 * CHUNK
MAX_ZIP_MEMBERS = 100_000
MAX_ZIP_MEMBER = 128 * CHUNK
MAX_ZIP_BYTES = 4 * 1024 * CHUNK
MAX_ALL_ZIP_BYTES = 8 * 1024 * CHUNK
SHA = re.compile(r"[0-9a-f]{64}")
GIT_SHA = re.compile(r"[0-9a-f]{40}")
INPUT_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,79}")
FORBIDDEN = {"private-quarantine", "private-transfer", "round7-transfer-private",
             "round7-ci-private"}
DOS_RESERVED = {"con", "prn", "aux", "nul",
                *("com" + str(i) for i in range(1, 10)),
                *("lpt" + str(i) for i in range(1, 10))}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def integer(value, minimum, maximum, label):
    require(type(value) is int and minimum <= value <= maximum, "invalid " + label)
    return value


def safe_name(name):
    require(isinstance(name, str) and bool(name), "relative path must be nonempty text")
    require(len(name.encode("utf-8")) <= 1024 and unicodedata.normalize("NFC", name) == name,
            "noncanonical or oversized path")
    require(not any(unicodedata.category(c) in {"Cc", "Cf"} for c in name), "control character in path")
    require("\\" not in name and ":" not in name, "foreign path separator or drive syntax")
    p = PurePosixPath(name)
    require(not p.is_absolute() and p.as_posix() == name, "noncanonical relative path")
    for part in p.parts:
        lowered = part.casefold()
        require(part not in {"", ".", ".."} and not part.endswith((" ", ".")),
                "unsafe path component")
        require(len(part.encode("utf-8")) <= 255, "oversized path component")
        require(lowered != ".git" and not any(token in lowered for token in FORBIDDEN),
                "private or Git-control path is forbidden")
        require(lowered.split(".", 1)[0] not in DOS_RESERVED, "reserved device path")
    return p


class Namespace:
    """Reject duplicate paths, case aliases, and file/directory prefix conflicts."""
    def __init__(self):
        self.nodes = {}

    def add(self, name, kind="file"):
        parts = safe_name(name).parts
        for i in range(len(parts)):
            path = "/".join(parts[:i + 1])
            final = i == len(parts) - 1
            wanted = kind if final else "directory"
            key = path.casefold()
            old = self.nodes.get(key)
            if old is None:
                self.nodes[key] = [path, wanted, final]
            else:
                require(old[0] == path and old[1] == wanted, "path alias/prefix collision: " + path)
                require(not (final and old[2]), "duplicate path: " + path)
                if final:
                    old[2] = True


def _pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, "duplicate JSON object key")
        result[key] = value
    return result


def json_value(data):
    require(len(data) <= MAX_JSON, "JSON exceeds size limit")
    return json.loads(data.decode("utf-8"), object_pairs_hook=_pairs,
                      parse_constant=lambda x: (_ for _ in ()).throw(ValueError("nonfinite JSON")))


def identity(data):
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def identity_row(row, maximum, label):
    require(isinstance(row, dict), "invalid identity row: " + label)
    integer(row.get("bytes"), 0, maximum, label + " byte count")
    require(isinstance(row.get("sha256"), str) and SHA.fullmatch(row["sha256"]),
            "invalid SHA-256: " + label)


def verify_identity(size, sha, row, label):
    require(size == row["bytes"] and sha == row["sha256"], "identity mismatch: " + label)


def require_posix():
    require(os.name == "posix" and hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_DIRECTORY")
            and hasattr(os, "O_NONBLOCK"),
            "this reader requires POSIX no-follow directory operations")


@contextlib.contextmanager
def directory_fd(path):
    require_posix()
    path = Path(os.path.abspath(path))
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in path.parts[1:]:
            new_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = new_fd
        yield fd
    finally:
        os.close(fd)


@contextlib.contextmanager
def parent_fd(root, name, create=False):
    parts = safe_name(name).parts
    with directory_fd(root) as first:
        fd = os.dup(first)
    try:
        for part in parts[:-1]:
            if create:
                try:
                    os.mkdir(part, 0o755, dir_fd=fd)
                except FileExistsError:
                    pass
            new_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = new_fd
        yield fd, parts[-1]
    finally:
        os.close(fd)


@contextlib.contextmanager
def regular_file(root, name):
    with parent_fd(root, name) as (parent, leaf):
        # Opening a FIFO must not block before fstat can reject its type.
        # O_NONBLOCK does not change ordinary regular-file reads.
        fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    try:
        st = os.fstat(fd)
        require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1,
                "input must be a regular file without hard links: " + name)
        with os.fdopen(fd, "rb") as stream:
            fd = None
            yield stream
    finally:
        if fd is not None:
            os.close(fd)


def stat_identity(stream):
    st = os.fstat(stream.fileno())
    return (st.st_dev, st.st_ino, st.st_mode, st.st_nlink,
            st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def hashed_copy(source, targets=(), *, limit):
    h, size = hashlib.sha256(), 0
    while True:
        data = source.read(min(CHUNK, limit - size + 1))
        if not data:
            break
        size += len(data)
        require(size <= limit, "payload exceeds declared byte limit")
        h.update(data)
        for target in targets:
            target.write(data)
    return size, h.hexdigest()


def stable_copy(root, name, targets=(), *, limit):
    with regular_file(root, name) as stream:
        before = stat_identity(stream)
        require(before[4] <= limit, "input exceeds byte limit: " + name)
        result = hashed_copy(stream, targets, limit=limit)
        require(stat_identity(stream) == before, "input changed while read: " + name)
        return result


def read_regular(root, name, maximum=MAX_JSON):
    import io
    target = io.BytesIO()
    stable_copy(root, name, (target,), limit=maximum)
    return target.getvalue()


def new_directory(path):
    """The parent must already exist. Refuse every symlink parent and an existing leaf."""
    path = Path(os.path.abspath(path))
    require(path.name not in {"", ".", ".."}, "invalid new directory")
    with directory_fd(path.parent) as parent:
        os.mkdir(path.name, 0o700, dir_fd=parent)
    return path


@contextlib.contextmanager
def new_file(root, name):
    with parent_fd(root, name, create=True) as (parent, leaf):
        fd = os.open(leaf, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            fd = None
            yield stream
            stream.flush()
            os.fchmod(stream.fileno(), 0o644)
    finally:
        if fd is not None:
            os.close(fd)


def ensure_directory(root, name):
    with parent_fd(root, name, create=True) as (parent, leaf):
        try:
            os.mkdir(leaf, 0o755, dir_fd=parent)
        except FileExistsError:
            pass
        fd = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        os.close(fd)


def validate_selection(selection):
    require(isinstance(selection, dict) and selection.get("schema") == "hepta.hia-round7.input-selection.v1",
            "wrong selection schema")
    require(all(isinstance(selection.get(key), str) and GIT_SHA.fullmatch(selection[key])
                for key in ("source_commit", "source_tree")), "invalid final qualification source identity")
    require(selection.get("public_evidence_only") is True, "public-only assertion is required")
    inputs = selection.get("evidence_inputs")
    require(isinstance(inputs, list) and 1 <= len(inputs) <= MAX_FILES, "evidence input groups are required")
    groups = {}
    for group in inputs:
        require(isinstance(group, dict) and isinstance(group.get("id"), str)
                and INPUT_ID.fullmatch(group["id"]) and group["id"] not in groups,
                "invalid or duplicate evidence input ID")
        require(group.get("kind") in INPUT_KINDS
                and group.get("qualification_status") in QUALIFICATION_STATUSES,
                "invalid input kind or qualification status")
        require(isinstance(group.get("description"), str) and bool(group["description"].strip()),
                "each input group needs an explicit provenance description")
        require("source_commit" in group and "source_tree" in group,
                "input source identity keys must be explicit, including null when applicable")
        commit, tree = group.get("source_commit"), group.get("source_tree")
        if commit is None or tree is None:
            require(commit is None and tree is None
                    and group["kind"] not in {"final-source-execution", "historical-execution"},
                    "execution input groups require their own exact source identity")
        else:
            require(isinstance(commit, str) and GIT_SHA.fullmatch(commit)
                    and isinstance(tree, str) and GIT_SHA.fullmatch(tree), "invalid input source identity")
        if group["kind"] == "final-source-execution":
            require(commit == selection["source_commit"] and tree == selection["source_tree"],
                    "final-source group differs from the root qualification source")
        groups[group["id"]] = group
    rows = selection.get("files")
    require(isinstance(rows, list), "selection files must be a list")
    integer(len(rows), 1, MAX_FILES, "selected file count")
    integer(selection.get("file_count"), 1, MAX_FILES, "selection file total")
    require(selection.get("file_count") == len(rows), "selection file total differs")
    names, normalized = Namespace(), []
    for row in rows:
        require(isinstance(row, dict) and row.get("component") in COMPONENTS, "unapproved component")
        relative = safe_name(row.get("relative")).as_posix()
        path = row["component"] + "/" + relative
        require(row.get("archive_path") == path, "component/archive path mapping differs")
        require(row.get("evidence_input") in groups, "selected file lacks a declared evidence input group")
        names.add(path)
        identity_row(row, MAX_FILE, path)
        normalized.append({"path": path, "bytes": row["bytes"], "sha256": row["sha256"],
                           "mode": 0o644, "evidence_input": row["evidence_input"]})
    total = sum(row["bytes"] for row in normalized)
    integer(total, 0, MAX_RAW, "selected raw bytes")
    integer(selection.get("bytes"), 0, MAX_RAW, "selection byte total")
    require(selection.get("bytes") == total, "selection byte total differs")
    zips = selection.get("public_ci_zips")
    require(isinstance(zips, list), "explicit public_ci_zips list is required")
    zipmap, artifact_ids = {}, set()
    selected_names = {row["path"] for row in normalized}
    selected_groups = {row["path"]: groups[row["evidence_input"]] for row in normalized}
    for row in zips:
        require(isinstance(row, dict), "invalid public ZIP descriptor")
        path = safe_name(row.get("archive_path")).as_posix()
        require(path in selected_names and path.lower().endswith(".zip"), "ZIP is not a selected .zip file")
        require("verified" not in path.casefold(), "original verified-integration ZIP is forbidden")
        require(path not in zipmap, "duplicate original ZIP descriptor")
        profile = row.get("workflow_profile")
        require(profile in PUBLIC_WORKFLOWS and row.get("workflow_path") == PUBLIC_WORKFLOWS[profile],
                "ZIP is not from an explicitly approved public workflow profile")
        group = selected_groups[path]
        require(group["source_commit"] is not None
                and row.get("source_commit") == group["source_commit"]
                and row.get("source_tree") == group["source_tree"], "ZIP/input group source identity differs")
        integer(row.get("run_id"), 1, 2**63 - 1, "run ID")
        integer(row.get("artifact_id"), 1, 2**63 - 1, "artifact ID")
        integer(row.get("run_attempt"), 1, 1000, "run attempt")
        require(row["artifact_id"] not in artifact_ids, "duplicate artifact ID")
        artifact_ids.add(row["artifact_id"])
        zipmap[path] = row
    require({name for name in selected_names if name.lower().endswith(".zip")} == set(zipmap),
            "every original .zip must be explicitly approved")
    return sorted(normalized, key=lambda x: x["path"]), zipmap


def inspect_zip(stream, expected=None, output=None, destination=None):
    """Always decompress/hash every member; optional extraction adds no execution."""
    observed, names = [], Namespace()
    total = 0
    with zipfile.ZipFile(stream) as archive:
        members = archive.infolist()
        integer(len(members), 0, MAX_ZIP_MEMBERS, "ZIP member count")
        for info in members:
            require(info.orig_filename == info.filename, "truncated ZIP member name")
            require(not (info.flag_bits & 1), "encrypted ZIP member")
            is_dir = info.is_dir()
            name = info.filename[:-1] if is_dir else info.filename
            safe_name(name)
            kind = "directory" if is_dir else "file"
            names.add(name, kind)
            mode = info.external_attr >> 16
            allowed_type = stat.S_IFDIR if is_dir else stat.S_IFREG
            require(stat.S_IFMT(mode) in {0, allowed_type} and not (mode & 0o7000),
                    "ZIP symlink/special member or privileged permissions")
            require(is_dir or not (info.external_attr & 0x10), "ambiguous DOS directory member")
            integer(info.file_size, 0, 0 if is_dir else MAX_ZIP_MEMBER, "ZIP member size")
            total += info.file_size
            require(total <= MAX_ZIP_BYTES, "ZIP expanded size exceeds bound")
            if output is not None and is_dir:
                ensure_directory(output, destination + "/" + name)
            with archive.open(info) as source:
                if output is not None and not is_dir:
                    with new_file(output, destination + "/" + name) as target:
                        size, sha = hashed_copy(source, (target,), limit=info.file_size)
                else:
                    size, sha = hashed_copy(source, limit=info.file_size)
            require(size == info.file_size, "ZIP member size differs")
            observed.append({"path": name, "kind": kind, "bytes": size, "sha256": sha,
                             "mode": stat.S_IMODE(mode), "compression": info.compress_type})
    observed.sort(key=lambda x: x["path"])
    result = {"member_count": len(observed),
              "file_count": sum(row["kind"] == "file" for row in observed),
              "bytes": total, "members": observed}
    if expected is not None:
        for key in result:
            require(expected.get(key) == result[key], "ZIP member inventory differs: " + key)
    return result


def validate_index(archive, index, selection, expected_files, zipmap):
    require(archive.get("schema") == "hepta.hia-round7.archive.v1"
            and index.get("schema") == "hepta.hia-round7.raw-index.v1", "wrong evidence schema")
    for value in (archive, index):
        require(value.get("source_commit") == selection["source_commit"]
                and value.get("source_tree") == selection["source_tree"],
                "source identity differs")
    require(index.get("evidence_inputs") == selection["evidence_inputs"], "input provenance groups differ")
    require(index.get("files") == expected_files, "raw index differs from frozen selection")
    for key, expected in (("file_count", len(expected_files)), ("bytes", selection["bytes"])):
        require(index.get(key) == expected, "raw index total differs")
    require(archive.get("file_count") == index["file_count"]
            and archive.get("uncompressed_file_bytes") == index["bytes"], "archive/index totals differ")
    expansions = index.get("zip_expansions")
    require(isinstance(expansions, list), "ZIP expansion index is missing")
    result, namespace, expanded_total = {}, Namespace(), 0
    for row in expected_files:
        namespace.add(row["path"])
    for row in expansions:
        name = row.get("archive")
        require(name in zipmap and name not in result, "unexpected/duplicate indexed ZIP")
        frozen = zipmap[name]
        destination = "expanded-ci/artifact-" + str(frozen["artifact_id"])
        require(row.get("destination") == destination, "ZIP expansion mapping differs")
        for key in ("artifact_id", "run_id", "run_attempt", "workflow_profile", "workflow_path",
                    "source_commit", "source_tree"):
            require(row.get(key) == frozen[key], "ZIP provenance differs: " + key)
        namespace.add(destination, "directory")
        members = row.get("members")
        require(isinstance(members, list), "ZIP member inventory missing")
        integer(len(members), 0, MAX_ZIP_MEMBERS, "ZIP member count")
        inner = Namespace()
        for member in members:
            require(member.get("kind") in {"file", "directory"}, "unknown ZIP member kind")
            inner.add(member.get("path"), member["kind"])
            identity_row(member, 0 if member["kind"] == "directory" else MAX_ZIP_MEMBER, "ZIP member")
            integer(member.get("mode"), 0, 0o777, "ZIP mode")
            integer(member.get("compression"), 0, 65535, "ZIP compression")
        require(row.get("member_count") == len(members)
                and row.get("file_count") == sum(x["kind"] == "file" for x in members)
                and row.get("bytes") == sum(x["bytes"] for x in members), "ZIP index totals differ")
        integer(row["bytes"], 0, MAX_ZIP_BYTES, "ZIP expanded bytes")
        expanded_total += row["bytes"]
        result[name] = row
    require(set(result) == set(zipmap), "ZIP index is incomplete")
    require(expanded_total <= MAX_ALL_ZIP_BYTES, "all ZIP members exceed total bound")
    require(archive.get("original_public_ci_zip_count") == len(result)
            and archive.get("original_public_ci_member_count") ==
            sum(row["member_count"] for row in result.values()), "archive ZIP totals differ")
    integer(archive.get("uncompressed_tar_bytes"), index["bytes"] + 1024,
            index["bytes"] + len(expected_files) * 8192 + 10240, "TAR stream bytes")
    return result


def decompress_exact(source, target, expected_bytes):
    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=256 * CHUNK)
    total = 0
    while not decoder.eof:
        data = source.read(CHUNK) if decoder.needs_input else b""
        require(data or not decoder.needs_input, "incomplete XZ stream")
        decoded = decoder.decompress(data, max_length=min(CHUNK, expected_bytes - total + 1))
        total += len(decoded)
        require(total <= expected_bytes, "XZ output exceeds declared TAR size")
        target.write(decoded)
    require(decoder.check == lzma.CHECK_CRC64, "unexpected XZ integrity check")
    require(not decoder.unused_data and not source.read(1), "trailing or concatenated XZ data")
    require(total == expected_bytes, "decompressed TAR byte count differs")
    target.seek(0)


def run():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--verify-only", action="store_true")
    modes.add_argument("--output", type=Path, help="New directory under an existing nonsymlink parent.")
    parser.add_argument("--expand-ci", action="store_true",
                        help="Also write every already-verified original public CI ZIP member.")
    args = parser.parse_args()
    if args.expand_ci and args.output is None:
        parser.error("--expand-ci requires --output")
    require_posix()
    base = Path(os.path.abspath(__file__)).parent
    archive_raw = read_regular(base, "ARCHIVE.json")
    archive = json_value(archive_raw)
    identity_row(archive, MAX_RAW + MAX_FILES * 8192 + 64 * CHUNK, "joined XZ archive")
    require(archive.get("archive_format") == "tar.xz"
            and archive.get("part_size_limit") == PART_SIZE, "wrong archive format/part limit")
    loaded = {}
    for key, name in (("index", "RAW-INDEX.json"), ("selection", "INPUT_SELECTION.json"),
                      ("reader", "RESTORE.py"), ("packager", "PACKAGER.py")):
        row = archive.get(key)
        identity_row(row, MAX_JSON, name)
        require(row.get("path") == name, "metadata filename differs")
        data = read_regular(base, name)
        verify_identity(len(data), hashlib.sha256(data).hexdigest(), row, name)
        loaded[key] = data
    index, selection = json_value(loaded["index"]), json_value(loaded["selection"])
    expected_files, zipmap = validate_selection(selection)
    require(index.get("selection") == archive["selection"], "selection identity differs")
    expansions = validate_index(archive, index, selection, expected_files, zipmap)
    parts = archive.get("parts")
    require(isinstance(parts, list) and 1 <= len(parts) <= 1000, "invalid part inventory")
    output = None
    observed, observed_set = [], set()
    zip_members_checked, zip_files_written, zip_bytes_written = 0, 0, 0
    with tempfile.TemporaryFile() as combined, tempfile.TemporaryFile() as plain:
        joined, total = hashlib.sha256(), 0
        for number, row in enumerate(parts, 1):
            identity_row(row, PART_SIZE, "archive part")
            name = "parts/raw-evidence.tar.xz.part" + str(number).zfill(3)
            require(row.get("path") == name and row["bytes"] > 0, "part order/name differs")
            require(number == len(parts) or row["bytes"] == PART_SIZE, "nonfinal part size differs")
            data = read_regular(base, name, PART_SIZE)
            verify_identity(len(data), hashlib.sha256(data).hexdigest(), row, name)
            combined.write(data)
            joined.update(data)
            total += len(data)
        verify_identity(total, joined.hexdigest(), archive, "joined archive")
        combined.seek(0)
        decompress_exact(combined, plain, archive["uncompressed_tar_bytes"])
        if args.output is not None:
            output = new_directory(args.output)
        expected = {row["path"]: row for row in expected_files}
        last_end = 0
        with tarfile.open(fileobj=plain, mode="r:", errorlevel=2) as tar:
            for member in tar:
                name = safe_name(member.name).as_posix()
                require(name in expected and name not in observed_set, "unexpected/duplicate TAR member")
                row = expected[name]
                require(member.type == tarfile.REGTYPE and not member.issparse() and not member.linkname,
                        "TAR link/sparse/special member")
                require(member.size == row["bytes"] and member.mode == 0o644
                        and member.mtime == 0 and member.uid == 0 and member.gid == 0
                        and member.uname == "" and member.gname == "", "TAR member metadata differs")
                require(set(member.pax_headers) <= {"path"}
                        and ("path" not in member.pax_headers or member.pax_headers["path"] == name),
                        "unexpected PAX metadata")
                source = tar.extractfile(member)
                require(source is not None, "missing TAR member payload")
                with source, tempfile.SpooledTemporaryFile(max_size=16 * CHUNK) as staged:
                    if output is None:
                        size, sha = hashed_copy(source, (staged,), limit=row["bytes"])
                    else:
                        with new_file(output, name) as target:
                            size, sha = hashed_copy(source, (staged, target), limit=row["bytes"])
                    verify_identity(size, sha, row, name)
                    staged.seek(0)
                    is_zip = zipfile.is_zipfile(staged)
                    require(is_zip == (name in expansions), "unapproved or malformed original ZIP")
                    if is_zip:
                        staged.seek(0)
                        expansion = expansions[name]
                        actual = inspect_zip(staged, expected=expansion,
                                             output=output if args.expand_ci else None,
                                             destination=expansion["destination"])
                        zip_members_checked += actual["member_count"]
                        if args.expand_ci:
                            zip_files_written += actual["file_count"]
                            zip_bytes_written += actual["bytes"]
                observed.append(name)
                observed_set.add(name)
                payload_end = member.offset_data + member.size
                alignment_bytes = (-member.size) % 512
                plain.seek(payload_end)
                alignment = plain.read(alignment_bytes)
                require(len(alignment) == alignment_bytes and not any(alignment),
                        "nonzero or incomplete TAR member padding: " + name)
                last_end = payload_end + alignment_bytes
        require(observed == [row["path"] for row in expected_files], "TAR inventory/order differs")
        plain.seek(last_end)
        padding = 0
        while True:
            data = plain.read(CHUNK)
            if not data:
                break
            require(not any(data), "hidden data after the final TAR member")
            padding += len(data)
        require(padding >= 1024 and archive["uncompressed_tar_bytes"] % 10240 == 0,
                "incomplete or noncanonical TAR padding")
    print(json.dumps({
        "schema": "hepta.hia-round7.restore-verification.v1",
        "source_commit": selection["source_commit"], "source_tree": selection["source_tree"],
        "root_identity_scope": "final qualification source; historical inputs retain their declared group identities",
        "evidence_input_groups": len(selection["evidence_inputs"]), "all_passed": True,
        "archive_manifest_sha256": hashlib.sha256(archive_raw).hexdigest(),
        "archive_sha256": archive["sha256"], "parts": len(parts),
        "raw_files": len(observed), "raw_file_bytes": index["bytes"],
        "original_public_ci_zips_verified": len(expansions),
        "ci_zip_members_verified": zip_members_checked,
        "ci_expanded_files": zip_files_written, "ci_expanded_bytes": zip_bytes_written,
        "project_code_executed": False, "restored_regular_file_mode": "0644",
        "output": str(output) if output else None,
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    run()

