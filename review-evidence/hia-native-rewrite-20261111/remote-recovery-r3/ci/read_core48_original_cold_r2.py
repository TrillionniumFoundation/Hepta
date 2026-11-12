"""Read the immutable FOLLOW48 Core artifact; never run its project code.

All original ZIP entries are streamed and hashed. Every embedded ZIP is replayed
and every declared HIA lossless archive is checked against its full manifest.
Source exports are bound to the exact original Git tree. The original cold FAIL
is data: a PASS here means readback only. No cold/native/compiler is rerun.
"""
from __future__ import annotations
import argparse
import ast
import base64
from hashlib import sha1, sha256
import json
import os
from pathlib import Path, PurePosixPath
import platform
import resource
import signal
import stat
import subprocess
import sys
import time
import traceback
import zipfile

PIN = {
    "repository": "TrillionniumFoundation/Hepta",
    "commit": "e035dfd0e2603adcf2bfcb28958afaddffe9fb62",
    "tree": "a80210cfcba140ebe413914767a86815b6f152f5",
    "run_id": 43210143623, "job_id": 131155352486,
    "artifact_id": 13940703193,
    "artifact_name": "hia-core-native-e035dfd0e2603adcf2bfcb28958afaddffe9fb62-1",
    "zip_bytes": 54245802,
    "zip_sha256": "4eec8d75658d48abe01c9518efa4362ba97b9b534576cc1d5b9deacde4a514cc",
    "producer_upload_file_count": 3928,
}
SOURCE_PINS = {
    "tools/replay_hia_selfhost_cold.py": "0d53ccbd2e56240280938ab829fe9c9798f02075",
    "tools/qualify_hia_selfhost.py": "edc251e0759ded53e20a616c27f1a42fe39780ef",
    "tools/hia_selfhost_process_owner.py": "6f600ab75894859b9840c0311cc8891a67b6c53a",
    "tools/hia_evidence_archive.py": "0a0c26a3a5fe989de1f614ef59f8535aa3cd17c8",
}
ROOT = "hia-cold.cold/"
EVIDENCE = ROOT + "qualification.evidence/"
REQUIRED = ("hia-cold.json", ROOT + "request.json",
            ROOT + "stdout.log", ROOT + "stderr.log")
MANIFEST = "HIA_ARCHIVE_MANIFEST.json"
CONSOLE_LIMIT = 512 * 1024
TEXT_SUFFIXES = (".json", ".jsonl", ".log", ".txt", ".stdout", ".stderr",
                 ".stdout.bin", ".stderr.bin")


def require(ok, detail):
    if not ok:
        raise AssertionError(detail)


def digest_file(path):
    value = sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            value.update(chunk)
    return value.hexdigest()


def file_identity(path):
    path = Path(path)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and not path.is_symlink(),
            ("ordinary input required", str(path)))
    return {"bytes": info.st_size, "sha256": digest_file(path),
            "mode": stat.S_IMODE(info.st_mode)}


def save_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n",
                    encoding="utf-8")


def safe_name(name, is_directory=False):
    require(type(name) is str and name and "\0" not in name and "\\" not in name,
            ("ZIP member spelling", repr(name)))
    plain = name[:-1] if is_directory and name.endswith("/") else name
    value = PurePosixPath(plain)
    require(plain and not value.is_absolute() and ".." not in value.parts
            and "." not in value.parts and value.as_posix() == plain,
            ("noncanonical ZIP member", repr(name)))
    return plain


def git_environment():
    result = dict(os.environ)
    count = int(result.get("GIT_CONFIG_COUNT", "0"))
    require(count >= 0, "invalid inherited Git config count")
    for key, value in (("core.packedGitWindowSize", "16m"),
                       ("core.packedGitLimit", "64m")):
        result["GIT_CONFIG_KEY_" + str(count)] = key
        result["GIT_CONFIG_VALUE_" + str(count)] = value
        count += 1
    result["GIT_CONFIG_COUNT"] = str(count)
    result["GIT_OPTIONAL_LOCKS"] = "0"
    return result


def exact_tree(repo):
    def command(arguments):
        result = subprocess.run(
            ["git", "-C", str(repo), *arguments],
            stdin=subprocess.DEVNULL, capture_output=True, timeout=30,
            env=git_environment(), check=False)
        require(result.returncode == 0,
                ("read-only git failed", arguments, result.returncode,
                 result.stderr.decode("utf-8", "replace")))
        return result.stdout
    tree = command(["rev-parse", PIN["commit"] + "^{tree}"]).decode().strip()
    require(tree == PIN["tree"], ("original tree", tree))
    raw = command(["ls-tree", "-rz", "--full-tree", PIN["commit"]])
    rows = {}
    for line in raw.split(b"\0"):
        if not line:
            continue
        header, name = line.split(b"\t", 1)
        mode, kind, object_id = header.decode("ascii").split(" ")
        path = name.decode("utf-8")
        safe_name(path)
        require(path not in rows, ("duplicate Git path", path))
        rows[path] = {"mode": mode, "kind": kind, "gitsha": object_id}
    require(rows, "empty original Git tree")
    for path, object_id in SOURCE_PINS.items():
        require(rows.get(path, {}).get("gitsha") == object_id,
                ("original writer Git pin", path))
    return rows, {"tree": tree, "entries": len(rows),
                  "ls_tree_bytes": len(raw), "ls_tree_sha256": sha256(raw).hexdigest()}


class Reader:
    def __init__(self, out):
        self.out = out
        self.outer = []
        self.inner = []
        self.archives = []
        self.retained = {}
        self.materialized = {}
        self.pending_writes = set()
        self.console_bytes = 0
        self.console_omitted = []

    def register(self, path, expected):
        require(file_identity(path) == expected,
                ("materialized readback", str(path)))
        self.materialized[str(path)] = expected

    def keep(self, key, path, row):
        expected = {"bytes": row["bytes"], "sha256": row["sha256"],
                    "mode": row["mode"]}
        self.register(path, expected)
        require(key not in self.retained, ("duplicate retained key", key))
        self.retained[key] = {"path": str(path.relative_to(self.out)), **expected}

    def stream_member(self, packed, info, key, target=None):
        mode = info.external_attr >> 16
        require(not stat.S_ISLNK(mode), ("ZIP symbolic link", key))
        require(stat.S_IFMT(mode) in (0, stat.S_IFREG, stat.S_IFDIR),
                ("unsupported original ZIP type", key, mode))
        if info.is_dir():
            require(stat.S_IFMT(mode) in (0, stat.S_IFDIR) and info.file_size == 0,
                    ("ZIP directory metadata", key))
            return {"path": info.filename, "kind": "directory",
                    "bytes": 0, "mode": stat.S_IMODE(mode),
                    "external_attr": info.external_attr}
        require(stat.S_IFMT(mode) in (0, stat.S_IFREG),
                ("ZIP file type mismatch", key, mode))
        permissions = stat.S_IMODE(mode)
        result = sha256()
        git = sha1(b"blob " + str(info.file_size).encode() + b"\0")
        count = 0
        output = None
        if target is not None:
            target.parent.mkdir(parents=True, exist_ok=True)
            self.pending_writes.add(str(target))
            output = target.open("xb")
        try:
            with packed.open(info) as stream:
                for chunk in iter(lambda: stream.read(1 << 20), b""):
                    result.update(chunk)
                    git.update(chunk)
                    count += len(chunk)
                    if output is not None:
                        output.write(chunk)
        finally:
            if output is not None:
                output.close()
        require(count == info.file_size, ("ZIP extent", key, count, info.file_size))
        row = {"path": info.filename, "kind": "file", "bytes": count,
               "sha256": result.hexdigest(), "gitsha": git.hexdigest(),
               "mode": permissions, "external_attr": info.external_attr,
               "compressed_bytes": info.compress_size, "crc32": info.CRC,
               "compression_type": info.compress_type}
        if target is not None:
            target.chmod(permissions)
            self.keep(key, target, row)
            self.pending_writes.remove(str(target))
        return row

    def scan_outer(self, path):
        seen = set()
        with zipfile.ZipFile(path) as packed:
            for info in packed.infolist():
                normalized = safe_name(info.filename, info.is_dir())
                require(normalized not in seen, ("duplicate outer member", normalized))
                seen.add(normalized)
                keep = (not info.is_dir() and (
                    info.filename.startswith(ROOT + "source/")
                    or info.filename.endswith(TEXT_SUFFIXES)
                    or info.filename.endswith(".zip")))
                target = self.out / "originals" / "outer" / normalized if keep else None
                self.outer.append(self.stream_member(packed, info, info.filename, target))
        files = [row for row in self.outer if row["kind"] == "file"]
        require(len(files) == PIN["producer_upload_file_count"],
                ("original upload file count", len(files)))
        require(all(name in self.retained for name in REQUIRED),
                ("missing required cold originals",
                 [name for name in REQUIRED if name not in self.retained]))
        return files

    def raw(self, key):
        row = self.retained[key]
        path = self.out / row["path"]
        raw = path.read_bytes()
        require(len(raw) == row["bytes"] and sha256(raw).hexdigest() == row["sha256"]
                and stat.S_IMODE(path.lstat().st_mode) == row["mode"],
                ("retained original identity", key))
        return raw

    def value(self, key):
        return json.loads(self.raw(key))

    def scan_inner(self, outer_row):
        outer_name = outer_row["path"]
        archive_path = self.out / self.retained[outer_name]["path"]
        rows = []
        with zipfile.ZipFile(archive_path) as packed:
            seen = set()
            for info in packed.infolist():
                normalized = safe_name(info.filename, info.is_dir())
                require(normalized not in seen,
                        ("duplicate inner member", outer_name, normalized))
                seen.add(normalized)
                key = outer_name + "!/" + info.filename
                keep = not info.is_dir() and info.filename.endswith(TEXT_SUFFIXES)
                target = (self.out / "originals" / "nested" / outer_name / normalized
                          if keep else None)
                row = self.stream_member(packed, info, key, target)
                rows.append(row)
                self.inner.append({"archive": outer_name, **row})
        result = {"path": outer_name, "bytes": outer_row["bytes"],
                  "sha256": outer_row["sha256"], "members": len(rows),
                  "files": sum(row["kind"] == "file" for row in rows),
                  "raw_file_bytes": sum(row["bytes"] for row in rows),
                  "all_member_CRC_bytes_hash_modes_read": True,
                  "HIA_manifest_present": MANIFEST in seen}
        if MANIFEST in seen:
            manifest_key = outer_name + "!/" + MANIFEST
            manifest = self.value(manifest_key)
            require(manifest["schema"] == "hepta.hia.lossless-evidence-archive.v1"
                    and manifest["native_or_correctness_authority"] is False,
                    ("inner manifest schema", outer_name))
            files = manifest["files"]
            require(type(files) is dict and len(files) <= 100000
                    and seen == set(files) | {MANIFEST},
                    ("inner exact manifest inventory", outer_name))
            total = 0
            for row in rows:
                if row["path"] == MANIFEST:
                    continue
                expected = files[row["path"]]
                require(row["kind"] == "file"
                        and 0 <= row["bytes"] <= 16 * 1024 * 1024
                        and {key: row[key] for key in ("bytes", "sha256", "mode")} == expected,
                        ("inner full member identity", outer_name, row["path"]))
                total += row["bytes"]
            require(total == manifest["unpacked_bytes"] and total <= 512 * 1024 * 1024,
                    ("inner total", outer_name, total))
            canonical = json.dumps(manifest, sort_keys=True,
                                   separators=(",", ":")).encode()
            result.update(HIA_manifest_verified=True, HIA_file_count=len(files),
                          HIA_unpacked_bytes=total,
                          HIA_manifest_sha256=sha256(canonical).hexdigest(),
                          original_source_directory=manifest["source_directory"])
            receipt_key = outer_name[:-4] + "/ARCHIVED.json"
            result["publication_receipt_member"] = receipt_key
            result["publication_receipt_present"] = receipt_key in self.retained
            if receipt_key in self.retained:
                receipt = self.value(receipt_key)
                require(receipt["schema"] == "hepta.hia.archived-stage.v1"
                        and receipt["archive_sha256"] == outer_row["sha256"]
                        and receipt["packed_bytes"] == outer_row["bytes"]
                        and receipt["files"] == len(files)
                        and receipt["unpacked_bytes"] == total
                        and receipt["manifest_sha256"] == result["HIA_manifest_sha256"]
                        and receipt["archive"] == manifest["source_directory"] + ".zip"
                        and receipt["raw_paths_available"] is False
                        and receipt["every_original_byte_verified_before_retirement"] is True
                        and receipt["qualification_or_production_authority"] is False,
                        ("inner publication receipt", outer_name))
                result["publication_receipt_verified"] = True
        self.archives.append(result)

    def emit(self, key):
        row = self.retained[key]
        # Bound console work before reading/encoding any large original.
        upper = ((row["bytes"] + 2) // 3) * 4 + ((row["bytes"] + 11999) // 12000 + 1) * 1024
        if self.console_bytes + upper > CONSOLE_LIMIT:
            self.console_omitted.append({"member": key, **row})
            return False
        raw = self.raw(key)
        frames = []
        if not raw:
            frames.append({"event": "CORE48_ORIGINAL_EMPTY", "member": key,
                           "bytes": 0, "sha256": row["sha256"],
                           "artifact_path": row["path"]})
        for offset in range(0, len(raw), 12000):
            frames.append({"event": "CORE48_ORIGINAL_BASE64", "member": key,
                           "offset": offset, "total_bytes": len(raw),
                           "sha256": row["sha256"],
                           "base64": base64.b64encode(raw[offset:offset + 12000]).decode("ascii")})
        encoded = [json.dumps(frame, sort_keys=True) for frame in frames]
        count = sum(len(line.encode()) + 1 for line in encoded)
        if self.console_bytes + count > CONSOLE_LIMIT:
            self.console_omitted.append({"member": key, **row})
            return False
        for line in encoded:
            print(line, flush=True)
        self.console_bytes += count
        return True


def original_sources(reader, tree, cold, request):
    expected = cold["source_manifest"]
    require(type(expected) is dict and expected and request["source_manifest"] == expected,
            "cold/request source manifest equality")
    actual = {row["path"][len(ROOT + "source/"):]: row for row in reader.outer
              if row["kind"] == "file" and row["path"].startswith(ROOT + "source/")}
    verified = []
    for path, wanted in sorted(expected.items()):
        safe_name(path)
        row = actual[path]
        original = tree[path]
        require(row["sha256"] == wanted and row["gitsha"] == original["gitsha"]
                and original["kind"] == "blob" and original["mode"] in ("100644", "100755"),
                ("source export / exact original head", path))
        verified.append({"path": path, "bytes": row["bytes"], "sha256": row["sha256"],
                         "gitsha": row["gitsha"], "Git_mode": original["mode"],
                         "original_ZIP_mode": row["mode"]})
    for path, object_id in SOURCE_PINS.items():
        require(actual[path]["gitsha"] == object_id and path in expected,
                ("actual original writer source", path))
    contract_path = "docs/HIA_SELFHOST_CORE_SUPPORT.json"
    contract = reader.value(ROOT + "source/" + contract_path)
    combined = dict(contract["source_identity"]["files"])
    combined[contract_path] = actual[contract_path]["sha256"]
    require(combined == expected, "actual support contract / cold source manifest")
    save_json(reader.out / "source-export-verified.json", verified)
    extras = sorted(set(actual) - set(expected))
    save_json(reader.out / "source-export-extra-files.json",
              [actual[path] for path in extras])
    return {"expected_files": len(expected), "verified_exact_head_files": len(verified),
            "extra_files": extras, "original_tree": PIN["tree"],
            "mode_observation": "ZIP mode retained separately; Git tracks executable bit, cold writer chmods export 0400"}


def owner_facts(reader, cold):
    key = ROOT + "process-owner.json"
    returned = cold["process_owner"]
    require(type(returned) is dict, "returned owner object")
    result = {"disk_receipt_present": key in reader.retained,
              "returned_owner": returned, "new_inference": False}
    if key not in reader.retained:
        require(returned.get("status") in ("OWNER_UNCONFIRMED_HOLD", "OWNER_RECEIPT_MISSING_HOLD"),
                ("missing owner receipt disagrees with returned owner", returned))
        return result
    raw = reader.raw(key)
    try:
        disk = json.loads(raw)
    except (ValueError, UnicodeError):
        disk = None
    result["disk_receipt_parses_as_object"] = type(disk) is dict
    if type(disk) is not dict:
        require(returned.get("status") == "OWNER_RECEIPT_INVALID_HOLD"
                and returned.get("receipt_bytes") == len(raw)
                and returned.get("receipt_sha256") == sha256(raw).hexdigest(),
                "invalid owner disk receipt / returned original")
        return result
    result["original_disk_owner"] = disk
    differences = []
    for field in sorted(set(disk) | set(returned)):
        if field not in disk or field not in returned or disk[field] != returned[field]:
            differences.append({"field": field, "disk_present": field in disk,
                                "returned_present": field in returned,
                                "disk_value": disk.get(field), "returned_value": returned.get(field)})
    result["disk_vs_returned_differences"] = differences
    save_json(reader.out / "complete-owner-original-differences.json", result)
    # A still-unconfirmed supervisor may produce a disk receipt after the
    # original caller returned HOLD. Preserve both; no augmentation was used.
    if returned.get("status") == "OWNER_UNCONFIRMED_HOLD":
        result["run_owned_augmentation_used"] = False
        result["late_disk_receipt_does_not_upgrade_original_HOLD"] = True
        return result
    require(type(returned.get("supervisor_returncode")) is int,
            "actual supervisor return code")
    expected = dict(disk)
    expected.update(supervisor_returncode=returned["supervisor_returncode"],
                    receipt_sha256=sha256(raw).hexdigest())
    if returned["supervisor_returncode"] != 0 and disk["status"] == "OWNED_PROCESS_COMPLETED":
        expected["status"] = "OWNER_EXIT_MISMATCH_HOLD"
    require(returned == expected, ("actual run_owned augmentation", differences))
    request_key = key + ".request.json"
    require(request_key in reader.retained, "original owner request missing")
    owner_request_raw = reader.raw(request_key)
    owner_request = json.loads(owner_request_raw)
    writer_key = ROOT + "source/tools/hia_selfhost_process_owner.py"
    writer_sha = reader.retained[writer_key]["sha256"]
    require(disk["request_sha256"] == sha256(owner_request_raw).hexdigest()
            and disk["implementation_sha256"] == writer_sha
            and owner_request["implementation_sha256"] == writer_sha,
            "actual owner request / implementation SHA")
    require(owner_request["qualification_seconds"] == 180
            and owner_request["cleanup_seconds"] == 3
            and owner_request["deadline_ns"] - owner_request["started_ns"] == 180_000_000_000,
            "unchanged original owner 180/3 budgets")
    result["actual_disk_request_and_writer_verified"] = True
    return result


def phase_facts(reader, cold):
    key = EVIDENCE + "phase-index.json"
    if key not in reader.retained:
        return {"index_present": False, "absence_is_original": True}, []
    index = reader.value(key)
    require(index["schema"] == "hepta.hia.selfhost-phase-index.v1",
            "original phase index schema")
    source = reader.raw(ROOT + "source/tools/qualify_hia_selfhost.py").decode("utf-8")
    assignments = [node for node in ast.parse(source).body
                   if isinstance(node, ast.Assign)
                   and any(isinstance(target, ast.Name) and target.id == "QUALIFICATION_FAMILIES"
                           for target in node.targets)]
    require(len(assignments) == 1, "unique literal phase family declaration")
    families = ast.literal_eval(assignments[0].value)
    expected = {(family, label) for family in families for label in ("original", "modified")}
    entries = index["phases"]
    require(type(entries) is list and len(entries) == len(expected)
            and {(entry["family"], entry["compiler_label"]) for entry in entries} == expected,
            "complete original phase inventory")
    require(all(entry["state"] in ("pending", "completed", "exception") for entry in entries)
            and index["completed"] == sum(entry["state"] != "pending" for entry in entries)
            and index["exceptions"] == sum(entry["state"] == "exception" for entry in entries),
            "original phase index state counts")
    rows = []
    selected = []
    manifest_sha = sha256(json.dumps(cold["source_manifest"], sort_keys=True,
                                    separators=(",", ":")).encode()).hexdigest()
    for entry in entries:
        family, label = entry["family"], entry["compiler_label"]
        stem = EVIDENCE + "phase-" + family + "-" + label
        keys = {part: stem + suffix for part, suffix in (
            ("request", ".request.json"), ("report", ".json"),
            ("process", ".process.json"), ("stdout", ".stdout.log"), ("stderr", ".stderr.log"))}
        row = {"family": family, "compiler_label": label, "original_index_entry": entry,
               "members": {part: ({"member": path, **reader.retained[path]}
                                   if path in reader.retained else None)
                           for part, path in keys.items()}}
        parsed = {}
        parse_errors = []
        for part in ("request", "process"):
            path = keys[part]
            if path not in reader.retained:
                parsed[part] = None
                continue
            try:
                value = reader.value(path)
                require(type(value) is dict, ("original process/request is not object", path))
                parsed[part] = value
            except (ValueError, UnicodeError, AssertionError) as exc:
                parsed[part] = None
                parse_errors.append({"member": path, "error_class": type(exc).__name__,
                                     "error": str(exc), "original_bytes_preserved": True})
        row["original_partial_JSON_observations"] = parse_errors
        request = parsed["request"]
        if request is not None:
            require(request["schema"] == "hepta.hia.selfhost-phase-request.v1"
                    and request["family"] == family and request["compiler_label"] == label
                    and request["source_manifest_sha256"] == manifest_sha,
                    ("phase original request source binding", family, label))
        process = parsed["process"]
        if process is not None:
            require(process["schema"] == "hepta.hia.selfhost-phase-process.v1"
                    and process["family"] == family and process["compiler_label"] == label,
                    ("original phase process", family, label))
            report_sha = process.get("report_sha256")
            if report_sha is not None:
                require(keys["report"] in reader.retained
                        and reader.retained[keys["report"]]["sha256"] == report_sha,
                        ("phase actual report hash", family, label))
            row["actual_process"] = process
            if "raw_artifacts" in process:
                stage_receipt = EVIDENCE + "phase-runs/" + family + "-" + label + "/ARCHIVED.json"
                require(stage_receipt in reader.retained
                        and reader.value(stage_receipt) == process["raw_artifacts"],
                        ("phase receipt / sealed original archive", family, label))
        focus = (entry["state"] != "completed" or bool(parse_errors)
                 or process is not None and process.get("returncode") != 0)
        row["selected_for_full_original_failure_or_pending_export"] = focus
        if focus:
            selected.extend(path for path in keys.values() if path in reader.retained)
            stage = EVIDENCE + "phase-runs/" + family + "-" + label
            stage_members = [item for item in reader.outer if item["path"].startswith(stage + "/")]
            nested_members = [item for item in reader.inner if item["archive"] == stage + ".zip"]
            row["stage_files"] = len(stage_members) + len(nested_members)
            save_json(reader.out / "focused-stages" / (family + "-" + label + ".json"),
                      {"index_entry": entry, "outer_members": stage_members,
                       "inner_members": nested_members})
            observations = []
            for retained_key in sorted(reader.retained):
                if not (retained_key.startswith(stage + "/")
                        or retained_key.startswith(stage + ".zip!/")):
                    continue
                if retained_key.endswith(".stderr.log") and reader.retained[retained_key]["bytes"]:
                    selected.append(retained_key)
                if not retained_key.endswith((".receipt.json", ".process.json")):
                    continue
                raw = reader.raw(retained_key)
                try:
                    value = json.loads(raw)
                except (ValueError, UnicodeError) as exc:
                    observations.append({"member": retained_key,
                                         "original_JSON_error": type(exc).__name__,
                                         **reader.retained[retained_key]})
                    continue
                observations.append({"member": retained_key, "original_value": value,
                                     **reader.retained[retained_key]})
                if type(value) is dict and (
                        value.get("status") not in (None, "returned")
                        or value.get("timed_out") is True
                        or value.get("returncode") not in (None, 0)):
                    selected.append(retained_key)
            save_json(reader.out / "focused-stages" / (family + "-" + label + "-process-originals.json"),
                      observations)
            row["actual_child_receipt_observations"] = len(observations)
            row["nonreturned_receipts_are_not_assumed_unexpected"] = True
        rows.append(row)
    save_json(reader.out / "complete-phase-frontier.json", rows)
    return {"index_present": True, "phase_count": len(entries),
            "completed": index["completed"], "exceptions": index["exceptions"],
            "states": {state: sum(entry["state"] == state for entry in entries)
                       for state in ("completed", "pending", "exception")},
            "focused": [{"family": row["family"], "compiler_label": row["compiler_label"],
                         "state": row["original_index_entry"]["state"],
                         "process_present": "actual_process" in row,
                         "process_returncode": row.get("actual_process", {}).get("returncode"),
                         "process_wall_elapsed_ns": row.get("actual_process", {}).get("wall_elapsed_ns")}
                        for row in rows if row["selected_for_full_original_failure_or_pending_export"]]}, selected


def timeout(signum, frame):
    raise TimeoutError("readonly original-artifact reader exceeded 180 wall seconds")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--zip", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    start = time.monotonic_ns()
    resource.setrlimit(resource.RLIMIT_CPU, (90, 90))
    resource.setrlimit(resource.RLIMIT_AS, (1 << 30, 1 << 30))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    signal.signal(signal.SIGALRM, timeout)
    signal.setitimer(signal.ITIMER_REAL, 180)
    args.out.mkdir(parents=True, exist_ok=False)
    reader = Reader(args.out)
    original_inputs = {}
    status, primary = "FAIL", None
    facts, source_result, phase_result, owner_result = {}, {}, {}, {}
    tree_result = {}
    validation_errors = []
    retained_zip = args.out / "core48-original-artifact.zip"
    try:
        require(sys.version_info[:3] == (3, 12, 14),
                ("reader interpreter, not original producer", sys.version))
        require(platform.system() == "Linux" and platform.machine().lower() in ("x86_64", "amd64"),
                "readonly reader Linux x86_64")
        for path in (Path(__file__).resolve(), args.zip.resolve()):
            original_inputs[str(path)] = file_identity(path)
        zip_identity = original_inputs[str(args.zip.resolve())]
        require(zip_identity["bytes"] == PIN["zip_bytes"]
                and zip_identity["sha256"] == PIN["zip_sha256"], "exact original artifact ZIP")
        reader.pending_writes.add(str(retained_zip))
        with args.zip.open("rb") as incoming, retained_zip.open("xb") as outgoing:
            for chunk in iter(lambda: incoming.read(1 << 20), b""):
                outgoing.write(chunk)
        retained_zip.chmod(zip_identity["mode"])
        reader.register(retained_zip, zip_identity)
        reader.pending_writes.remove(str(retained_zip))
        tree, tree_result = exact_tree(args.repo)
        files = reader.scan_outer(retained_zip)
        # Print primary originals before interpretation, so a later reader
        # assertion cannot hide the producer's actual records from its own log.
        for key in REQUIRED + (
                ROOT + "process-owner.json", ROOT + "process-owner.json.request.json",
                ROOT + "process-owner.json.stdout.log", ROOT + "process-owner.json.stderr.log",
                EVIDENCE + "phase-index.json"):
            if key in reader.retained:
                reader.emit(key)
        for row in files:
            if not row["path"].endswith(".zip"):
                continue
            try:
                reader.scan_inner(row)
            except BaseException as exc:
                if isinstance(exc, (KeyboardInterrupt, SystemExit, TimeoutError)):
                    raise
                validation_errors.append({"scope": "embedded-ZIP", "member": row["path"],
                                          "error_class": type(exc).__name__, "error": str(exc),
                                          "traceback": traceback.format_exc()})
        cold = reader.value("hia-cold.json")
        request = reader.value(ROOT + "request.json")
        require(cold["schema"] == "hepta.hia.selfhost-cold-replay.v1"
                and request["schema"] == "hepta.hia.selfhost-cold-request.v1",
                "original cold/request schemas")
        require(cold["qualification_wall_limit_seconds"] == 180
                and cold["cleanup_wall_limit_seconds"] == 3,
                "unchanged original cold budgets")
        require(type(cold["checks"]) is dict
                and all(type(value) is bool for value in cold["checks"].values()),
                "original cold checks")
        facts = {key: cold.get(key) for key in (
            "schema", "status", "profile", "checks", "returncode", "process_owner",
            "qualification_wall_limit_seconds", "cleanup_wall_limit_seconds", "wall_elapsed_ns",
            "nested_report", "nested_report_sha256", "seed_sha256",
            "generation_sha256", "modified_generation_sha256")}
        nested_key = ROOT + "qualification.json"
        facts["nested_report_original_member_present"] = nested_key in reader.retained
        if cold.get("nested_report_sha256") is not None:
            require(nested_key in reader.retained
                    and reader.retained[nested_key]["sha256"] == cold["nested_report_sha256"],
                    "actual nested qualification SHA")
        save_json(args.out / "complete-cold-producer-facts.json", facts)
        source_result = original_sources(reader, tree, cold, request)
        owner_result = owner_facts(reader, cold)
        save_json(args.out / "complete-owner-original-differences.json", owner_result)
        phase_result, selected = phase_facts(reader, cold)
        generation = []
        for key in sorted(reader.retained):
            name = PurePosixPath(key).name
            if name in tuple(prefix + ".receipt.json" for prefix in
                             ("B0", "B1", "B2", "B3", "M1", "M2", "M3")):
                generation.append({"member": key, **reader.retained[key]})
                selected.append(key)
        save_json(args.out / "generation-original-receipts.json", generation)
        if nested_key in reader.retained:
            selected.insert(0, nested_key)
        seen = set()
        for key in selected:
            if key not in seen:
                reader.emit(key)
                seen.add(key)
        require(not validation_errors, ("embedded original validation errors", validation_errors))
        status = "PASS"
    except BaseException as exc:
        primary = {"error_class": type(exc).__name__, "error": str(exc),
                   "traceback": traceback.format_exc()}
        traceback.print_exc()
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        # The original ZIP and all successfully materialized original bytes,
        # including complete source exports, are checked even on reader failure.
        after_errors = []
        complete_retained_zip_after_checked = False
        for scope, items in (("reader-self-or-input-ZIP", original_inputs),
                             ("materialized-original", reader.materialized)):
            for path, expected in items.items():
                try:
                    require(file_identity(path) == expected,
                            ("unconditional original after-check", path))
                    if scope == "materialized-original" and path == str(retained_zip):
                        complete_retained_zip_after_checked = True
                except BaseException as exc:
                    after_errors.append({"scope": scope, "path": path, "expected": expected,
                                         "error_class": type(exc).__name__, "error": str(exc)})
        if reader.pending_writes:
            after_errors.append({"scope": "incomplete-original-materialization",
                                 "paths": sorted(reader.pending_writes)})
        ledgers = {
            "outer-ZIP-members.json": reader.outer,
            "embedded-ZIP-members.json": reader.inner,
            "embedded-archives.json": reader.archives,
            "retained-originals.json": reader.retained,
            "input-identities.json": original_inputs,
            "embedded-validation-errors.json": validation_errors,
            "console-omitted-full-originals.json": reader.console_omitted,
        }
        ledger_identity = {}
        for name, value in ledgers.items():
            try:
                target = args.out / name
                save_json(target, value)
                ledger_identity[name] = file_identity(target)
            except BaseException as exc:
                after_errors.append({"scope": "persist-full-readback-ledger", "path": name,
                                     "error_class": type(exc).__name__, "error": str(exc)})
        usage = resource.getrusage(resource.RUSAGE_SELF)
        children = resource.getrusage(resource.RUSAGE_CHILDREN)
        cpu = usage.ru_utime + usage.ru_stime + children.ru_utime + children.ru_stime
        elapsed = time.monotonic_ns() - start
        if cpu >= 90:
            after_errors.append({"scope": "aggregate-parent-children-CPU", "actual_seconds": cpu,
                                 "required_less_than": 90})
        if elapsed >= 180_000_000_000:
            after_errors.append({"scope": "complete-reader-wall", "actual_ns": elapsed,
                                 "required_less_than_ns": 180_000_000_000})
        if after_errors or primary or validation_errors:
            status = "FAIL"
        returned_owner = facts.get("process_owner")
        owner_summary = returned_owner if type(returned_owner) is dict else {}
        summary = {
            "schema": "hia-core48-original-readback-r2", "status": status,
            "scope": "READ_ONLY_EXACT_CORE48_ARTIFACT_AND_SOURCE_CUSTODY",
            "pin": PIN, "reader_interpreter": sys.version, "original_tree": tree_result,
            "original_cold_status": facts.get("status"),
            "original_cold_returncode": facts.get("returncode"),
            "original_owner_status": owner_summary.get("status"),
            "original_owner_timed_out": owner_summary.get("timed_out"),
            "original_owner_cleanup": owner_summary.get("cleanup"),
            "original_checks_passed": sum(facts.get("checks", {}).values()),
            "original_checks_total": len(facts.get("checks", {})),
            "original_wall_elapsed_ns": facts.get("wall_elapsed_ns"),
            "original_generation_sha256": facts.get("generation_sha256"),
            "empty_generation_list_is_not_interpreted_as_no_native_execution": True,
            "source_export": source_result, "phase_frontier": phase_result,
            "outer_members": len(reader.outer),
            "outer_files": sum(row["kind"] == "file" for row in reader.outer),
            "outer_raw_bytes": sum(row["bytes"] for row in reader.outer),
            "embedded_archives": len(reader.archives), "embedded_members": len(reader.inner),
            "embedded_raw_bytes": sum(row["bytes"] for row in reader.inner),
            "original_outputs_preserved": len(reader.retained),
            "materialized_originals_after_checked": len(reader.materialized),
            "input_and_self_after_checked": len(original_inputs),
            "unconditional_after_checks": True,
            "ledgers": ledger_identity, "primary_error": primary, "after_errors": after_errors,
            "embedded_validation_error_count": len(validation_errors),
            "console_original_bytes": reader.console_bytes,
            "console_omitted_original_count": len(reader.console_omitted),
            "complete_originals_are_in_artifact": complete_retained_zip_after_checked,
            "original_ZIP_copy_complete_after_checked": complete_retained_zip_after_checked,
            "incomplete_original_materialization_paths": sorted(reader.pending_writes),
            "elapsed_ns_including_after_checks_and_ledgers": elapsed,
            "aggregate_CPU_seconds_including_readonly_git_children": cpu,
            "limits": {"CPU_seconds": 90, "wall_seconds": 180, "address_bytes": 1 << 30},
            "native_entries": 0, "B3_entries": 0, "project_imports": 0,
            "original_tests_reexecuted": 0, "new_cold_qualification": False,
            "original_failure_not_superseded": True,
            "environment_causality_not_inferred": True,
        }
        save_json(args.out / "summary.json", summary)
        print("HIA_CORE48_READBACK " + json.dumps(summary, sort_keys=True), flush=True)
    if status != "PASS":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
