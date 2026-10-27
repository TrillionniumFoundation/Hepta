#!/usr/bin/env python3
"""Package a completed Hepta qualification run without changing its source.

Do not run while qualification/performance measurement is in progress.
Example (after run/qualification.json has been written):
  python package_hepta_evidence.py --run RUN --support SUPPORT --repo REPO --dest NEW_DEST

The default wrapper log is RUN's sibling named RUN.name + '.log'. Override it
with --wrapper-log, restricted to that same parent directory. No build, test,
network request, tool invocation, or source modification is performed.
For multiple qualification attempts, invoke once per run with a distinct new
destination. Failed and successful runs retain separate original identities.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shlex
import stat
import tarfile

CHUNK = 1024 * 1024
PART_BYTES = 4 * 1024 * 1024
MAX_JSON_BYTES = 32 * 1024 * 1024
MAX_EXTERNAL_FILE_BYTES = 64 * 1024 * 1024
MAX_EXTERNAL_TOTAL_BYTES = 256 * 1024 * 1024
CARGO_DIRECTORY = "rust-shadow-target"
RUST_BINARIES = ("debug/hia-core-shadow", "debug/hia-core-shadow.exe")


def within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def wire(value) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def fingerprint(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def open_regular(path):
    """Final-component symlinks and nonregular files are never opened."""
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise ValueError("not a regular file: " + str(path))
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                 | getattr(os, "O_NONBLOCK", 0))
    stream = os.fdopen(fd, "rb")
    opened = os.fstat(stream.fileno())
    if not stat.S_ISREG(opened.st_mode) or fingerprint(opened) != fingerprint(before):
        stream.close()
        raise ValueError("file changed before opening: " + str(path))
    return stream, before


def unchanged(path, stream, before):
    if (fingerprint(os.fstat(stream.fileno())) != fingerprint(before)
            or fingerprint(path.lstat()) != fingerprint(before)):
        raise ValueError("file changed during archival: " + str(path))


def file_hash(path):
    stream, before = open_regular(path)
    with stream:
        digest = hashlib.sha256()
        while data := stream.read(CHUNK):
            digest.update(data)
        unchanged(path, stream, before)
    return digest.hexdigest(), before.st_size


def native_magic(path):
    stream, before = open_regular(path)
    with stream:
        header = stream.read(64)
        unchanged(path, stream, before)
    if header.startswith((b"\x7fELF", b"!<arch>\n", b"!<thin>\n", b"MZ",
                          b"BC\xc0\xde", b"\xde\xc0\x17\x0b", b"\x00asm")):
        return True
    if header[:4] in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
                      b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
                      b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
                      b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca"):
        return True
    # Common little-endian COFF objects. This is a retention heuristic, not
    # an object-format validator or authorization to execute the file.
    return (len(header) >= 20 and header[:2] in (b"\x64\x86", b"\x64\xaa", b"\x4c\x01")
            and 0 < int.from_bytes(header[2:4], "little") <= 96)


class HashReader:
    def __init__(self, stream):
        self.stream, self.digest, self.bytes = stream, hashlib.sha256(), 0

    def read(self, amount=-1):
        data = self.stream.read(amount)
        self.digest.update(data)
        self.bytes += len(data)
        return data


class Package:
    def __init__(self, run, support, repo):
        self.run, self.support, self.repo = run, support, repo
        self.entries, self.by_source = [], {}
        self.input_versions = {}
        self.omissions, self.dependencies, self.scan_notes, self.retention_flags = [], [], [], []
        self.external_bytes = 0

    def add(self, source, archived, role, expected=None):
        key = str(source)
        if key in self.by_source:
            return self.by_source[key]
        info = source.lstat()
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("nonregular archive input: " + key)
        entry = {"original_path": key, "archive_path": archived, "role": role,
                 "expected_external_identity": expected}
        self.entries.append(entry)
        self.by_source[key] = entry
        self.input_versions[key] = fingerprint(info)
        return entry

    def tree(self, root, prefix, *, exclude_cargo=False):
        def fail_on_walk_error(error):
            raise error

        for current, dirs, names in os.walk(root, followlinks=False, onerror=fail_on_walk_error):
            current = Path(current)
            dirs.sort()
            names.sort()
            for name in list(dirs):
                path = current / name
                if exclude_cargo and current == root and name == CARGO_DIRECTORY:
                    dirs.remove(name)
                    self.omissions.append({"path": str(path), "reason": "cargo_build_cache_excluded",
                                           "exception": list(RUST_BINARIES)})
                elif path.is_symlink():
                    dirs.remove(name)
                    self.omissions.append({"path": str(path), "reason": "symlink_directory_not_followed",
                                           "target": os.readlink(path)})
            for name in names:
                path = current / name
                info = path.lstat()
                if not stat.S_ISREG(info.st_mode):
                    self.omissions.append({"path": str(path), "reason": "nonregular_file_not_read",
                                           "symlink_target": os.readlink(path) if path.is_symlink() else None})
                    continue
                self.add(path, prefix + "/" + path.relative_to(root).as_posix(), prefix)
        if exclude_cargo:
            for name in RUST_BINARIES:
                path = root / CARGO_DIRECTORY / name
                if path.is_file() and not path.is_symlink():
                    if path.resolve(strict=True) != path:
                        self.omissions.append({"path": str(path),
                                               "reason": "rust_binary_symlink_ancestor_not_followed"})
                    else:
                        self.add(path, prefix + "/" + path.relative_to(root).as_posix(),
                                 "preserved_rust_shadow_executable")

    def allowed_external(self, path):
        return (within(path, self.run) or within(path, self.repo / "artifacts")
                or (len(path.parts) >= 3 and path.parts[:2] == ("/", "tmp")
                    and path.parts[2].startswith("hepta")))

    def dependency(self, report, pointer, node):
        record = {"report": report["archive_path"], "json_pointer": pointer,
                  "declared_path": node.get("path"), "declared_sha256": node.get("sha256"),
                  "declared_bytes": node.get("bytes")}
        # Avoid duplicating arbitrary malformed subtrees in generated metadata.
        if (type(node["path"]) is not str or len(node["path"]) > 4096
                or type(node["sha256"]) is not str
                or not re.fullmatch(r"[0-9a-fA-F]{64}", node["sha256"])
                or type(node["bytes"]) is not int or node["bytes"] < 0):
            self.dependencies.append({"report": report["archive_path"], "json_pointer": pointer,
                                      "status": "invalid_identity_fields_not_followed"})
            return
        self.dependencies.append(record)
        path = Path(node["path"])
        if not path.is_absolute():
            # Only these two documented resolutions; no filesystem search.
            parent = self.repo if path.parts and path.parts[0] == "artifacts" else Path(report["original_path"]).parent
            path = parent / path
            record["relative_path_resolution"] = str(parent)
            record["relative_path_resolution_is_archival_convention"] = True
        try:
            path = path.resolve(strict=False)
            record["resolved_path"] = str(path)
            if str(path) in self.by_source:
                record["status"] = "pending_archived_identity_check"
                return
            if within(path, self.run / CARGO_DIRECTORY):
                record["status"] = "cargo_cache_reference_not_reintroduced"
                return
            if not self.allowed_external(path):
                record["status"] = ("repository_source_dependency_not_copied" if within(path, self.repo)
                                    else "external_toolchain_or_other_dependency_not_copied")
                record["availability"] = "not_probed_outside_allowlist"
                return
            # Resolve first, then inspect only allowed destinations. A link to
            # a system/toolchain location does not expand the allowlist.
            if not path.exists():
                record["status"] = "missing_allowed_temporary_or_artifact_file"
                return
            if not stat.S_ISREG(path.lstat().st_mode):
                record["status"] = "nonregular_dependency_not_read"
                return
            lowered = pointer.lower().split("/")
            if any(part in {"toolchain", "compiler", "c_compiler", "rustc", "clang", "linker", "lean"}
                   for part in lowered):
                record["status"] = "toolchain_identity_not_copied"
                return
            size = path.stat().st_size
            if size != node["bytes"]:
                record.update(status="declared_size_mismatch_not_copied", observed_bytes=size)
                return
            if size > MAX_EXTERNAL_FILE_BYTES or self.external_bytes + size > MAX_EXTERNAL_TOTAL_BYTES:
                record["status"] = "external_supplement_size_limit_not_copied"
                return
            if not native_magic(path):
                record["status"] = "source_or_other_non_native_dependency_not_copied"
                return
            observed, _ = file_hash(path)
            if observed != node["sha256"].lower():
                record.update(status="declared_hash_mismatch_not_copied", observed_sha256=observed)
                return
            basename = re.sub(r"[^A-Za-z0-9._-]", "_", path.name)[:128] or "artifact"
            archived = "external-native/" + observed + "/" + basename
            # Different original paths may have the same bytes and basename.
            existing = next((item for item in self.entries if item["archive_path"] == archived), None)
            if existing is None:
                self.add(path, archived, "supplemental_existing_native_artifact",
                         {"sha256": observed, "bytes": size})
                self.external_bytes += size
            else:
                self.by_source[str(path)] = existing
            record.update(status="supplemented_verified_native_artifact", archive_path=archived)
        except (OSError, ValueError, RuntimeError) as exc:
            record.update(status="dependency_unavailable_or_changed", detail=str(exc))

    def scan(self):
        # Scan only original JSON inputs, never binaries or newly supplemented files.
        for report in list(self.entries):
            path = Path(report["original_path"])
            if path.suffix != ".json":
                continue
            try:
                stream, before = open_regular(path)
                with stream:
                    if fingerprint(before) != self.input_versions[str(path)]:
                        raise ValueError("input changed after enumeration: " + str(path))
                    if before.st_size > MAX_JSON_BYTES:
                        self.scan_notes.append({"report": report["archive_path"], "status": "json_scan_size_limit_raw_file_retained"})
                        continue
                    document = json.load(stream)
                    unchanged(path, stream, before)
                pending = [(document, "")]
                while pending:
                    value, pointer = pending.pop()
                    if isinstance(value, dict):
                        if {"path", "sha256", "bytes"}.issubset(value):
                            self.dependency(report, pointer, value)
                        for key, child in value.items():
                            escaped = key.replace("~", "~0").replace("/", "~1")
                            location = pointer + "/" + escaped
                            if key in {"native_binaries_retained", "native_artifacts_retained"}:
                                self.retention_flags.append({"report": report["archive_path"],
                                                             "json_pointer": location, "value": child})
                            pending.append((child, location))
                    elif isinstance(value, list):
                        pending.extend((child, pointer + "/" + str(index)) for index, child in enumerate(value))
            except (OSError, ValueError, RecursionError) as exc:
                self.scan_notes.append({"report": report["archive_path"], "status": "json_scan_failed_raw_file_retained", "detail": str(exc)})

    def archive_regular(self, archive, entry):
        path = Path(entry["original_path"])
        stream, before = open_regular(path)
        with stream:
            if fingerprint(before) != self.input_versions[str(path)]:
                raise ValueError("input changed after enumeration/scanning: " + str(path))
            info = tarfile.TarInfo("hepta-evidence/" + entry["archive_path"])
            info.size, info.mode, info.mtime = before.st_size, stat.S_IMODE(before.st_mode), int(before.st_mtime)
            reader = HashReader(stream)
            archive.addfile(info, reader)
            unchanged(path, stream, before)
        entry.update(bytes=reader.bytes, sha256=reader.digest.hexdigest())
        if reader.bytes != before.st_size:
            raise ValueError("incomplete file in archive: " + str(path))
        expected = entry["expected_external_identity"]
        if expected and any(entry[key] != expected[key] for key in ("bytes", "sha256")):
            raise ValueError("supplement changed after identity verification: " + str(path))

    def finish_dependencies(self):
        for item in self.dependencies:
            if item["status"] != "pending_archived_identity_check":
                continue
            entry = self.by_source[item["resolved_path"]]
            item["archive_path"] = entry["archive_path"]
            item["status"] = ("already_archived_identity_matches"
                              if entry["sha256"] == item["declared_sha256"].lower() and entry["bytes"] == item["declared_bytes"]
                              else "already_archived_identity_mismatch")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("run", "support", "repo", "dest"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--wrapper-log", type=Path)
    args = parser.parse_args()
    run, support, repo = (getattr(args, name).resolve(strict=True) for name in ("run", "support", "repo"))
    if any(not path.is_dir() for path in (run, support, repo)):
        parser.error("run, support and repo must be existing directories")
    if not (run / "qualification.json").is_file():
        parser.error("wait for the completed collector's qualification.json before packaging")
    destination = args.dest.resolve(strict=False)
    if any(within(destination, root) for root in (run, support, repo)):
        parser.error("destination must be outside run, support and the source repository")
    wrapper = args.wrapper_log or run.parent / (run.name + ".log")
    if wrapper.is_symlink() or wrapper.parent.resolve() != run.parent or wrapper.suffix != ".log":
        parser.error("wrapper must be a regular .log beside the run directory")
    wrapper = wrapper.resolve(strict=True)
    if not stat.S_ISREG(wrapper.stat().st_mode):
        parser.error("wrapper log must be regular")
    destination.mkdir(parents=True, exist_ok=False)
    package = Package(run, support, repo)
    package.tree(run, "run", exclude_cargo=True)
    package.tree(support, "support")
    package.add(wrapper, "wrapper.log", "external_wrapper_log")
    package.scan()
    archive_path = destination / "hepta-evidence.tar.xz"
    partial = destination / "hepta-evidence.tar.xz.partial"
    generated = []

    def add_metadata(archive, name, data):
        (destination / name).write_bytes(data)
        info = tarfile.TarInfo("hepta-evidence/" + name)
        info.size, info.mode = len(data), 0o644
        archive.addfile(info, io.BytesIO(data))
        row = {"archive_path": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
               "role": "generated_archival_metadata"}
        generated.append(row)
        return row

    with tarfile.open(partial, "w:xz", preset=3, format=tarfile.PAX_FORMAT) as archive:
        for entry in package.entries:
            package.archive_regular(archive, entry)
        package.finish_dependencies()
        add_metadata(archive, "path-mapping.json", wire({"schema": "hepta.archive-path-map.v1",
            "raw_reports_rewritten": False, "files": package.entries, "omissions": package.omissions}))
        add_metadata(archive, "dependencies.json", wire({"schema": "hepta.archive-dependencies.v1",
            "identity_shape": ["path", "sha256", "bytes"], "identities": package.dependencies,
            "scan_notes": package.scan_notes, "producer_retention_flags": package.retention_flags,
            "limits": {"json_scan_bytes": MAX_JSON_BYTES, "external_file_bytes": MAX_EXTERNAL_FILE_BYTES,
                       "external_total_bytes": MAX_EXTERNAL_TOTAL_BYTES},
            "scope": "References can include intentional negative controls. Missing/mismatched references are archival observations, not new qualification judgments."}))
        readme = """# Retained Hepta qualification evidence

This archive contains the reports, logs and artifacts the producers left on
disk at packaging time. It does not claim to contain every binary that was
executed. Some producers explicitly report native_binaries_retained=false;
their reports are preserved unchanged. Missing temporary artifacts and
external source/toolchain dependencies are recorded in dependencies.json.
Each package contains one original run; packaging a failed attempt never
relabels it as a passing run or transfers its evidence to another source SHA.

Original JSON bytes and absolute paths are not rewritten. path-mapping.json
maps original files to archive-relative names. Cargo build cache is excluded,
except the existing debug/hia-core-shadow executable (or .exe), when present.
No symlink is followed while walking run/support; omitted links/special files
are recorded. The identity scan follows only path+sha256+bytes objects, and
may encounter negative controls or other identity schemas it does not follow.

Existing external native artifacts are supplemented only from the task's run,
repo/artifacts, or /tmp/hepta* paths, with matching size/hash and native-file
magic. Toolchains, arbitrary system files, source dependencies and installation
caches are not copied through this mechanism. Raw run/support regular files
are retained regardless of whether they are native artifacts.
Supplementing an archive file does not recursively preserve its thin-archive
members, shared libraries, or other dependencies unless separately identified.

inventory.json records SHA-256 for every archive file except itself; its own
digest is in the outer archive-manifest.json. This packaging does not change
the producers' qualification scope or infer missing execution evidence.
"""
        add_metadata(archive, "PACKAGE_README.md", readme.encode())
        inventory = [{key: entry[key] for key in ("archive_path", "bytes", "sha256", "role")}
                     for entry in package.entries] + list(generated)
        add_metadata(archive, "inventory.json", wire({"schema": "hepta.archive-inventory.v1",
            "files": sorted(inventory, key=lambda item: item["archive_path"]),
            "self_digest_in_outer_archive_manifest": True}))
    partial.rename(archive_path)
    parts, whole, total = [], hashlib.sha256(), 0
    with archive_path.open("rb") as stream:
        while data := stream.read(PART_BYTES):
            number = len(parts)
            if number >= 10000:
                raise ValueError("archive exceeds four-digit part inventory")
            name = archive_path.name + ".part" + str(number).zfill(4)
            with (destination / name).open("xb") as output:
                output.write(data)
            whole.update(data)
            total += len(data)
            parts.append({"path": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(), "index": number})
    if not parts or total != archive_path.stat().st_size:
        raise ValueError("incomplete archive split")
    archive_hash = whole.hexdigest()
    instructions = ("Verify the part digests in archive-manifest.json before joining.\n"
        "From this directory, join every part in the exact listed order:\n\ncat "
        + " ".join(shlex.quote(part["path"]) for part in parts)
        + " > hepta-evidence.reassembled.tar.xz\n\n"
        + "printf '%s  %s\\n' '" + archive_hash + "' 'hepta-evidence.reassembled.tar.xz' | sha256sum -c -\n"
        + "tar -xJf hepta-evidence.reassembled.tar.xz\n\n"
        + "Each part is 4 MiB (4194304 bytes), except the final remainder.\n"
        + "The full tar.xz and the ordered parts encode the same bytes.\n")
    (destination / "REASSEMBLE.txt").write_text(instructions)
    manifest = {"schema": "hepta.archive-package.v1",
        "created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "inputs": {"run": str(run), "support": str(support), "repo": str(repo), "wrapper_log": str(wrapper)},
        "archive": {"path": archive_path.name, "bytes": total, "sha256": archive_hash},
        "part_bytes": PART_BYTES, "parts": parts, "metadata": generated,
        "archived_regular_files": len(package.entries), "all_executed_binaries_preserved": False,
        "original_report_bytes_rewritten": False, "source_repository_modified": False,
        "tests_or_performance_runs_started": False,
        "reassemble_sha256": hashlib.sha256(instructions.encode()).hexdigest()}
    manifest_bytes = wire(manifest)
    (destination / "archive-manifest.json").write_bytes(manifest_bytes)
    sums = [(archive_hash, archive_path.name)] + [(part["sha256"], part["path"]) for part in parts]
    sums += [(entry["sha256"], entry["archive_path"]) for entry in generated]
    sums += [(hashlib.sha256(manifest_bytes).hexdigest(), "archive-manifest.json"),
             (hashlib.sha256(instructions.encode()).hexdigest(), "REASSEMBLE.txt")]
    (destination / "SHA256SUMS").write_text("".join(digest + "  " + name + "\n" for digest, name in sums))
    print(json.dumps({"destination": str(destination), "archive_bytes": total,
                      "archive_sha256": archive_hash, "parts": len(parts),
                      "archived_regular_files": len(package.entries),
                      "dependency_records": len(package.dependencies)}))


if __name__ == "__main__":
    main()
