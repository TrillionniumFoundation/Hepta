"""Read original 970 CI bytes only; never import or execute Hepta or its artifacts.

Input is the reconstructed, externally sealed original artifact 13911977275.
The original DIRECTORY/SELECTED and the earlier independent semantic report are
separately pinned. This adds physical byte checks; it does not rerun qualification.

Revision 2 distinguishes known report annotations from the original receipt.
It also inventories, without accepting as complete history, the 46 real earlier
names compilation records whose companion paths were later reused by execution.
The original revision-1 HOLD and the all-38 difference observation are preserved.
"""
from __future__ import annotations

import argparse
import binascii
from contextlib import contextmanager
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import struct
import sys
import time
import traceback
import zipfile


ARTIFACT = {
    "id": 13911977275, "run_id": 43140734709, "run_attempt": 1,
    "bytes": 599427251,
    "sha256": "40e81308484173d36153f6a3014293a78705aa28e8f8f7718dcdd3d87c03f580",
    "checkout_commit": "9704596acc4470bd0042838586602e26bac7b3d1",
    "checkout_tree": "c3ca94c57f9bd75f22f2c694e32bca2dfc6b329b",
}
PINS = {
    "DIRECTORY.json": (13678084, "9aeb1fb0ce400ef7e1d0e7a58bba55f7b5c3a80cdccbfb63ebbde3e814221e66"),
    "SELECTED.json": (317307, "b0760d77746721d441067b63c8442dafbf0ad3e2bc6f9c79f26770b448965fff"),
    "SEMANTIC-READBACK.json": (461370, "591b896a21ab0be224240c91d0df518ea1cfe8faff65e65c8336ce55a5ae02cb"),
    "PHASE-DIFFERENCE.json": (742957, "c5fd048e58dad9d6190ce9a254bca303474098bea1323e52616138d60bfaf2e2"),
}
TEMP = "/home/runner/work/_temp/"
ORIGINAL_SOURCE = "/home/runner/work/Hepta/Hepta/"
EVIDENCE = "hia-cold.cold/qualification.evidence/"
COLD_SOURCE = "hia-cold.cold/source/"
DIRECTORY_COUNT = 19100
DIRECTORY_BYTES = 1649066402
PHASE_COUNT = 38
PHASE_FILES = 42623
PHASE_UNPACKED_BYTES = 2397882660
PHASE_PACKED_BYTES = 66295061
PHASE_MANIFEST = "HIA_ARCHIVE_MANIFEST.json"
CHUNK = 1024 * 1024
OWNER_SHA = "36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2"
CHILD_SHA = "1d298396e97b6d362bcd51121eff1d2f411305133fadb1c974477b2dd9052c29"
SOURCE_MAP_SHA = "7d7c89008c59cbd7bd30e2311c5246d134fb8df7d80f8432bea46de8cf049190"
NAMES_SOURCE_SHA = "3fb7d15d3b25ddd86950665534aff2c15d40d625c9684e4a21287be70b193d1a"
ANNOTATION_KEYS = {
    "capacity": {("object_inspection",)},
    "resource": {("object_inspection",)},
    "tail": {("object_inspection",)},
    "select": {("object_inspection",), ("condition", "expected", "type"), ("expected",)},
    "multi": {("inspection",)}, "keyword": {("inspection",)},
    "signed": {("inspection",)}, "scalar-casts": {("inspection",)},
    "explicit-traps": {("inspection",)}, "cli": {("inspection",)},
    "names": {("inspection",)},
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def wire(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key: " + key)
        result[key] = value
    return result


def document(data):
    # Python integers retain the exact original nanoseconds and inode values.
    return json.loads(data, object_pairs_hook=no_duplicate_keys,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))


def identity(s):
    return [s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_nlink,
            s.st_size, s.st_mtime_ns, s.st_ctime_ns]


@contextmanager
def ordinary(path, maximum):
    """Hold every input parent; reject symlinks, special files, and substitutions."""
    path = Path(path).absolute()
    if ".." in path.parts:
        raise ValueError("input path is not canonical")
    directory_fds = [os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)]
    links = []
    fd = None
    try:
        for part in path.parts[1:-1]:
            parent = directory_fds[-1]
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=parent)
            links.append((parent, part, child, os.fstat(child)))
            directory_fds.append(child)
        parent = directory_fds[-1]
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=parent)
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_uid != os.getuid() or not 0 <= before.st_size <= maximum
                or identity(before) != identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False))):
            raise ValueError("input is not a stable owned single-link ordinary file")
        with os.fdopen(os.dup(fd), "rb") as stream:
            yield stream, before
        if (identity(before) != identity(os.fstat(fd))
                or identity(before) != identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False))):
            raise ValueError("input changed during read")
        for parent, name, child, original in reversed(links):
            actual = os.fstat(child)
            named = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if ((original.st_dev, original.st_ino, original.st_mode)
                    != (actual.st_dev, actual.st_ino, actual.st_mode)
                    or (actual.st_dev, actual.st_ino, actual.st_mode)
                    != (named.st_dev, named.st_ino, named.st_mode)):
                raise ValueError("input parent changed during read")
    finally:
        if fd is not None:
            os.close(fd)
        for opened in reversed(directory_fds):
            os.close(opened)


def hash_stream(stream, size):
    h = hashlib.sha256()
    count = 0
    stream.seek(0)
    while count < size:
        chunk = stream.read(min(CHUNK, size - count))
        if not chunk:
            raise ValueError("short original file")
        h.update(chunk)
        count += len(chunk)
    if stream.read(1):
        raise ValueError("original file has trailing bytes")
    return {"bytes": count, "sha256": h.hexdigest()}


def pinned_local(path, expected):
    size, sha = expected
    with ordinary(path, size) as (stream, before):
        data = stream.read(size + 1)
    if len(data) != size or digest(data) != sha:
        raise ValueError("local immutable input seal differs: " + str(path))
    return data


def safe_name(name, directory=False):
    if (type(name) is not str or not name or len(name) > 4096 or name.startswith("/")
            or "\\" in name or any(ord(c) < 32 or ord(c) == 127 for c in name)):
        raise ValueError("unsafe ZIP name")
    key = name[:-1] if directory else name
    if any(not p or p in (".", "..") or ":" in p for p in key.split("/")):
        raise ValueError("noncanonical ZIP name")
    return key


def catalog(z, packed_bytes, count_limit, unpacked_limit):
    infos = z.infolist()
    if len(infos) > count_limit:
        raise ValueError("ZIP member count exceeded")
    names = set()
    kinds = {}
    rows = []
    total = 0
    for index, info in enumerate(infos):
        name = info.filename
        directory = info.is_dir()
        key = safe_name(name, directory)
        mode = info.external_attr >> 16
        if (info.orig_filename != name or name in names or key in kinds
                or info.flag_bits & 1 or info.compress_type not in (0, 8)
                or stat.S_IMODE(mode) & 0o7000
                or stat.S_IFMT(mode) not in ((0, stat.S_IFDIR) if directory else (0, stat.S_IFREG))
                or info.file_size < 0 or info.compress_size < 0
                or not 0 <= info.header_offset < packed_bytes
                or directory and info.file_size):
            raise ValueError("ZIP type, name, compression, or extent differs")
        total += info.file_size
        if total > unpacked_limit:
            raise ValueError("ZIP declared expansion exceeded")
        names.add(name)
        kinds[key] = "directory" if directory else "regular"
        rows.append({"index": index, "name": name, "kind": kinds[key],
                     "uncompressed_bytes": info.file_size, "compressed_bytes": info.compress_size,
                     "crc32_from_directory": info.CRC, "compression": info.compress_type,
                     "flags": info.flag_bits, "external_attr": info.external_attr,
                     "internal_attr": info.internal_attr, "create_system": info.create_system,
                     "create_version": info.create_version, "extract_version": info.extract_version,
                     "header_offset": info.header_offset, "date_time": list(info.date_time),
                     "extra_hex": info.extra.hex(), "comment_hex": info.comment.hex()})
    for key in kinds:
        parents = key.split("/")[:-1]
        if any(kinds.get("/".join(parents[:at]), "directory") != "directory"
               for at in range(1, len(parents) + 1)):
            raise ValueError("ZIP regular file is an ancestor")
    return rows, {i.filename: i for i in infos}, total


def read_member(z, info, maximum=None, capture=False):
    if maximum is not None and info.file_size > maximum:
        raise ValueError("original member exceeds explicitly requested read extent")
    h = hashlib.sha256()
    crc = 0
    count = 0
    chunks = [] if capture else None
    with z.open(info, "r") as source:
        while True:
            chunk = source.read(CHUNK)
            if not chunk:
                break
            count += len(chunk)
            if count > info.file_size:
                raise ValueError("member exceeds declared extent")
            h.update(chunk)
            crc = binascii.crc32(chunk, crc)
            if chunks is not None:
                chunks.append(chunk)
    if count != info.file_size or crc & 0xffffffff != info.CRC:
        raise ValueError("complete member size or CRC differs")
    return {"bytes": count, "sha256": h.hexdigest(), "crc32": crc & 0xffffffff,
            "mode": info.external_attr >> 16}, (b"".join(chunks) if chunks is not None else None)


def put(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    with ordinary(path, len(data)) as (stream, before):
        if stream.read() != data:
            raise ValueError("new report readback differs")
    return {"path": str(path), "bytes": len(data), "sha256": digest(data)}


class Audit:
    def __init__(self, output, expected_history_gaps):
        self.output = output
        self.check_count = 0
        self.outer_records = {}
        self.source_copy_matches = []
        self.receipt_joins = []
        self.retained_stage_joins = []
        self.expected_history_gaps = expected_history_gaps
        self.history_gaps = []
        self.annotation_joins = []

    def check(self, ok, message):
        self.check_count += 1
        if not ok:
            raise ValueError(message)

    def equal_record(self, actual, size, sha, label):
        self.check(actual["bytes"] == size and actual["sha256"] == sha,
                   "physical bytes differ: " + label)

    def absolute_record(self, path, phase_records=None, phase_source=None):
        if phase_records is not None and path.startswith(phase_source + "/"):
            relative = path[len(phase_source) + 1:]
            if relative in phase_records:
                return phase_records[relative]
        if path.startswith(TEMP):
            name = path[len(TEMP):]
            if name in self.outer_records:
                return self.outer_records[name]
        if path.startswith(ORIGINAL_SOURCE):
            name = COLD_SOURCE + path[len(ORIGINAL_SOURCE):]
            if name in self.outer_records:
                return self.outer_records[name]
        raise ValueError("referenced byte path is not in admitted original inventory: " + path)

    def invocation(self, receipt_name, receipt, request, get_bytes, phase_records=None,
                   phase_source=None):
        """Only inspect the existing request/input/output/receipt; never call a runner."""
        self.check(type(receipt.get("case")) is str and receipt.get("format") == request.get("format"),
                   "invocation format or case differs")
        image = self.absolute_record(request["image"], phase_records, phase_source)
        source = self.absolute_record(request["source"], phase_records, phase_source)
        self.check(image["sha256"] == request["image_sha256"] == receipt["artifact_sha256"],
                   "invocation physical image differs: " + receipt_name)
        self.check(source["sha256"] == request["source_sha256"] == receipt["input_sha256"]
                   and source["bytes"] == receipt["input_bytes"],
                   "invocation physical input differs: " + receipt_name)
        if "source_sha256" in receipt:
            self.check(source["sha256"] == receipt["source_sha256"], "receipt source differs")
        if "image_sha256" in receipt:
            self.check(image["sha256"] == receipt["image_sha256"], "receipt image differs")
        native = "transport" in request
        if native:
            self.check(request["transport"] in (
                "HIA-emitted-static-ELF-observer-v2", "HIA-policy-dynamic-ELF-linked-observer-v1"),
                "unknown original observer transport")
            observer = EVIDENCE + ("native-observer.elf" if request["format"] == "flat-x86-64"
                                   else "linked-observer.elf")
            self.check(self.outer_records[observer]["sha256"] == request["observer_sha256"]
                       == receipt["runner_sha256"], "actual observer bytes differ")
            image_bytes = get_bytes(request["image"])
            source_bytes = get_bytes(request["source"])
            descriptor = request["shared_output_fd"]
            frame = hashlib.sha256(b"HIAOBS02" + struct.pack("<6Q", len(image_bytes), len(source_bytes),
                request["capacity"], request["workspace_size"], request["workspace_fill"],
                (1 << 64) - 1 if descriptor is None else descriptor))
            frame.update(image_bytes)
            frame.update(source_bytes)
            self.check(frame.hexdigest() == request["frame_sha256"], "actual observer frame differs")
        else:
            self.check(receipt["runner_sha256"] == CHILD_SHA
                       == self.outer_records[COLD_SOURCE + "tools/hia_selfhost_child.py"]["sha256"],
                       "actual retained child implementation differs")
        output = None
        if "output_sha256" in receipt:
            output = self.absolute_record(request["output"], phase_records, phase_source)
            self.equal_record(output, request["capacity"], receipt["output_sha256"], receipt_name + " output")
        shared = receipt.get("shared_output_observation")
        if shared is not None:
            actual = self.absolute_record(request["output"], phase_records, phase_source)
            self.equal_record(actual, shared["observed_bytes"], shared["observed_sha256"], "shared output")
        if "produced_image" in receipt:
            produced = self.absolute_record(receipt["produced_image"], phase_records, phase_source)
            self.equal_record(produced, receipt["produced_bytes"], receipt["produced_sha256"], "produced image")
            self.check(receipt["status"] == "returned" and receipt["abi_status"] == 0
                       and receipt["core_u32"] == receipt["produced_bytes"], "compile result differs")
            whole_output = get_bytes(request["output"])
            actual_image = get_bytes(receipt["produced_image"])
            self.check(whole_output[:receipt["produced_bytes"]] == actual_image,
                       "produced image is not exact actual full-output prefix")
        stdout_path = request["source"][:-len(".input.bin")] + ".stdout.log"
        if native or receipt.get("status") == "returned":
            stdout = document(get_bytes(stdout_path))
            additions = {"produced_image", "produced_bytes", "produced_sha256"}
            if not native:
                additions |= {"case", "input_sha256", "input_bytes", "artifact_sha256", "format",
                              "runner_sha256", "wall_elapsed_ns"}
            self.check(stdout == {k: v for k, v in receipt.items() if k not in additions},
                       "original stdout/receipt complete dictionary differs: " + receipt_name)
        self.receipt_joins.append({"receipt": receipt_name, "case": receipt["case"],
            "status": receipt["status"], "transport": request.get("transport", "original Python child"),
            "image_sha256": image["sha256"], "input_sha256": source["sha256"],
            "output_sha256": None if output is None else output["sha256"],
            "produced_sha256": receipt.get("produced_sha256")})


def nested_receipts(value):
    if isinstance(value, dict):
        if (type(value.get("case")) is str and "input_sha256" in value
                and "artifact_sha256" in value and "wall_elapsed_ns" in value):
            yield value
        for child in value.values():
            yield from nested_receipts(child)
    elif isinstance(value, list):
        for child in value:
            yield from nested_receipts(child)


def semantic_digest(value):
    return digest(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def join_phase_observations(audit, phase, report_name, raw_report, physical, records, source):
    """Join every surviving receipt; preserve true overwritten histories as gaps."""
    embedded = list(nested_receipts(document(raw_report)))
    full = {semantic_digest(row["receipt"]): row for row in physical}
    by_case = {}
    for row in physical:
        by_case.setdefault(row["receipt"]["case"], []).append(row)
    counts = {"embedded_total": len(embedded), "exact_receipt_joins": 0,
              "annotated_receipt_joins": 0, "unpreserved_earlier_invocations": 0}
    for observed in embedded:
        if semantic_digest(observed) in full:
            counts["exact_receipt_joins"] += 1
            continue
        candidates = by_case.get(observed["case"], [])
        matched = []
        differences = []
        for row in candidates:
            receipt = row["receipt"]
            extras = tuple(sorted(set(observed) - set(receipt)))
            difference = {
                "receipt": row["name"],
                "extra_report_keys": list(extras),
                "missing_report_keys": sorted(set(receipt) - set(observed)),
                "changed_shared_keys": sorted(k for k in set(receipt) & set(observed)
                    if semantic_digest(receipt[k]) != semantic_digest(observed[k])),
                "extra_report_values": {k: observed[k] for k in extras},
            }
            differences.append(difference)
            projected = {k: v for k, v in observed.items() if k not in extras}
            if (extras in ANNOTATION_KEYS.get(phase["family"], set())
                    and semantic_digest(projected) == semantic_digest(receipt)):
                matched.append((row, difference))
        if matched:
            audit.check(len(matched) == 1, "annotation matches multiple physical receipts")
            row, difference = matched[0]
            audit.annotation_joins.append({
                "family": phase["family"], "compiler_label": phase["compiler_label"],
                "case": observed["case"], "report": report_name,
                "report_sha256": digest(raw_report), "receipt": row["name"],
                "actual_receipt_bytes": records[row["name"]],
                "all_original_receipt_fields_unchanged": True,
                "annotation_keys": difference["extra_report_keys"],
                "annotation_values": difference["extra_report_values"],
                "annotation_algorithm_independently_reexecuted": False,
            })
            counts["annotated_receipt_joins"] += 1
            continue
        key = (phase["family"], phase["compiler_label"], observed["case"])
        expected = audit.expected_history_gaps.get(key)
        audit.check(expected is not None and phase["family"] == "names"
                    and semantic_digest(differences) == semantic_digest(expected["candidate_receipts"]),
                    "unexpected unmatched historical invocation: " + repr(key))
        audit.check(len(candidates) == 1, "known history gap has ambiguous archived final receipt")
        replacement = candidates[0]
        stem = observed["case"]
        audit.check(replacement["name"] == stem + ".receipt.json"
                    and set(observed) - set(replacement["receipt"]) ==
                        {"produced_image", "produced_bytes", "produced_sha256"}
                    and observed["status"] == "returned" and observed["abi_status"] == 0
                    and observed["core_u32"] == observed["produced_bytes"],
                    "known earlier compilation observation changed shape")
        produced = audit.absolute_record(observed["produced_image"], records, source)
        audit.equal_record(produced, observed["produced_bytes"], observed["produced_sha256"],
                           "surviving produced image of overwritten earlier compilation")
        audit.check(replacement["request"]["image"] == observed["produced_image"]
                    and replacement["receipt"]["artifact_sha256"] == observed["produced_sha256"],
                    "known replacement is not execution of the surviving compilation image")
        companions = {}
        for suffix in (".receipt.json", ".request.json", ".input.bin", ".output.bin",
                       ".stdout.log", ".stderr.log"):
            name = stem + suffix
            audit.check(name in records, "known reused companion path absent")
            companions[name] = records[name]
        audit.check(companions[stem + ".input.bin"]["sha256"] != observed["input_sha256"]
                    and companions[stem + ".output.bin"]["sha256"] != observed["output_sha256"],
                    "expected different historical compile input/output not observed")
        audit.history_gaps.append({
            "family": phase["family"], "compiler_label": phase["compiler_label"], "case": stem,
            "finding": "EARLIER_COMPILE_COMPANION_PATHS_REUSED_BY_LATER_RUNTIME_INVOCATION",
            "report": report_name, "report_sha256": digest(raw_report),
            "earlier_compile_observation_survives_in_report": observed,
            "archived_later_runtime_receipt": replacement["receipt"],
            "archived_later_runtime_request": replacement["request"],
            "actual_final_companion_records": companions,
            "earlier_produced_image_actual_record": produced,
            "different_earlier_input_and_output_bytes_not_in_their_paths": True,
            "earlier_standalone_receipt_request_and_stdout_originals_recovered": False,
            "earlier_stderr_historical_file_identity_preserved": False,
            "historical_custody_complete": False, "product_result_reclassified": False,
            "source_path": "tools/hia_selfhost_names.py", "source_sha256": NAMES_SOURCE_SHA,
        })
        counts["unpreserved_earlier_invocations"] += 1
    audit.check(sum(counts[k] for k in ("exact_receipt_joins", "annotated_receipt_joins",
                                     "unpreserved_earlier_invocations")) == len(embedded),
                "embedded observation accounting does not partition the full denominator")
    counts["complete_historical_invocation_custody"] = not counts["unpreserved_earlier_invocations"]
    return counts


def audit_phase(audit, outer, infos, phase, jsonl):
    desc = phase["archive"]
    archive_name = desc["archive"][len(TEMP):]
    source = desc["archive"][:-4]
    audit.check(desc["schema"] == "hepta.hia.archived-stage.v1"
                and desc["archive"].startswith(TEMP) and desc["archive"].endswith(".zip")
                and desc["qualification_or_production_authority"] is False,
                "phase receipt format or scope differs")
    original, packed = read_member(outer, infos[archive_name], 576 * CHUNK, capture=True)
    audit.equal_record(original, desc["packed_bytes"], desc["archive_sha256"], archive_name)
    receipt_path = source[len(TEMP):] + "/ARCHIVED.json"
    _, archived_raw = read_member(outer, infos[receipt_path], 65536, capture=True)
    audit.check(document(archived_raw) == desc, "original ARCHIVED.json differs from process receipt")
    with zipfile.ZipFile(io.BytesIO(packed)) as z:
        _, stage_infos, total = catalog(z, len(packed), 100001, 544 * CHUNK)
        audit.check(PHASE_MANIFEST in stage_infos, "phase manifest absent")
        _, manifest_raw = read_member(z, stage_infos[PHASE_MANIFEST], 32 * CHUNK, capture=True)
        manifest = document(manifest_raw)
        audit.check(digest(manifest_raw) == desc["manifest_sha256"], "actual phase manifest SHA differs")
        audit.check(manifest_raw == json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode(),
                    "original phase manifest canonical bytes differ")
        audit.check(manifest["schema"] == "hepta.hia.lossless-evidence-archive.v1"
                    and manifest["source_directory"] == source
                    and manifest["native_or_correctness_authority"] is False,
                    "phase manifest source or scope differs")
        files = manifest["files"]
        audit.check(set(stage_infos) == set(files) | {PHASE_MANIFEST}
                    and len(files) == desc["files"] and len(files) <= 100000
                    and manifest["unpacked_bytes"] == desc["unpacked_bytes"] <= 512 * CHUNK,
                    "complete phase manifest inventory differs")
        records = {}
        for name in sorted(files):
            info = stage_infos[name]
            row = files[name]
            record, unused = read_member(z, info, 16 * CHUNK)
            audit.equal_record(record, row["bytes"], row["sha256"], archive_name + "!" + name)
            audit.check(stat.S_IMODE(record["mode"]) == row["mode"], "phase original mode differs")
            records[name] = record
            jsonl.write(json.dumps({"archive": archive_name, "name": name, **record}, sort_keys=True) + "\n")
        audit.check(sum(v["bytes"] for v in records.values()) == manifest["unpacked_bytes"],
                    "phase full uncompressed total differs")
        def original_bytes(path):
            if path.startswith(source + "/"):
                name = path[len(source) + 1:]
                if name in stage_infos:
                    return read_member(z, stage_infos[name], 16 * CHUNK, capture=True)[1]
            if path.startswith(TEMP) and path[len(TEMP):] in infos:
                return read_member(outer, infos[path[len(TEMP):]], 16 * CHUNK, capture=True)[1]
            if path.startswith(ORIGINAL_SOURCE):
                name = COLD_SOURCE + path[len(ORIGINAL_SOURCE):]
                return read_member(outer, infos[name], 16 * CHUNK, capture=True)[1]
            raise ValueError("unknown fixed original path")
        physical = []
        receipts = 0
        for name in sorted(files):
            if not name.endswith(".receipt.json"):
                continue
            receipt = document(original_bytes(source + "/" + name))
            if "case" not in receipt or "input_sha256" not in receipt:
                continue
            request_name = name[:-len(".receipt.json")] + ".request.json"
            audit.check(request_name in records, "phase invocation request absent")
            request = document(original_bytes(source + "/" + request_name))
            audit.invocation(archive_name + "!" + name, receipt, request, original_bytes, records, source)
            physical.append({"name": name, "receipt": receipt, "request": request})
            receipts += 1
        report_name = phase["report"]["name"]
        _, raw_report = read_member(outer, infos[report_name], 64 * CHUNK, capture=True)
        observations = join_phase_observations(audit, phase, report_name, raw_report,
                                               physical, records, source)
        put(audit.output / ("phase-" + phase["family"] + "-" + phase["compiler_label"] + ".manifest.original.json"),
            manifest_raw)
        return {"family": phase["family"], "compiler_label": phase["compiler_label"],
                "archive": archive_name, "archive_sha256": original["sha256"],
                "packed_bytes": original["bytes"], "manifest_sha256": digest(manifest_raw),
                "manifest_original_bytes": len(manifest_raw), "files": len(files),
                "unpacked_bytes": manifest["unpacked_bytes"], "physical_invocation_receipts": receipts,
                "embedded_invocation_observation_accounting": observations,
                "every_member_full_CRC_SHA256_size_mode_read": True,
                "original_files_executed": False}


def boundary_gzip(audit, outer, infos):
    prefix = "hia-machine-elf-component-evidence/fixture/MachineElfBoundaryTests/"
    names = [name for name in infos if name.startswith(prefix) and "/" not in name[len(prefix):]
             and name.endswith(".json")]
    audit.check(len(names) == 11, "original eleven ELF boundary reports differ")
    observed = []
    for name in sorted(names):
        raw = read_member(outer, infos[name], CHUNK, capture=True)[1]
        doc = document(raw)
        original, selected = doc["original"], doc["native"]
        audit.check(doc["equal"] is True and original["kind"] == selected["kind"], "ELF boundary result differs")
        row = {"case": doc["case"], "report": name, "kind": original["kind"]}
        if original["kind"] == "bytes":
            gzip_names = []
            for item in (original, selected):
                path = item["archive"]
                actual_name = path[len(TEMP):] if path.startswith(TEMP) else prefix + path
                audit.check(actual_name in infos, "ELF compressed original absent")
                audit.check(audit.outer_records[actual_name]["sha256"] == item["archive_sha256"],
                            "ELF original gzip SHA differs")
                gzip_names.append(actual_name)
            h = hashlib.sha256()
            total = 0
            with outer.open(infos[gzip_names[0]]) as first, outer.open(infos[gzip_names[1]]) as second:
                with gzip.GzipFile(fileobj=first) as left, gzip.GzipFile(fileobj=second) as right:
                    while True:
                        a, b = left.read(CHUNK), right.read(CHUNK)
                        audit.check(a == b, "complete original/native ELF decompressed bytes differ")
                        if not a:
                            break
                        total += len(a)
                        audit.check(total <= original["bytes"] <= 64 * CHUNK, "ELF declared byte bound differs")
                        h.update(a)
            audit.check(total == original["bytes"] == selected["bytes"]
                        and h.hexdigest() == original["sha256"] == selected["sha256"],
                        "ELF decompressed size/SHA differs")
            row.update(bytes=total, sha256=h.hexdigest(), original_gzip=gzip_names[0], native_gzip=gzip_names[1],
                       full_original_native_bytes_equal=True)
        else:
            audit.check(original == selected, "ELF original/native error differs")
            row["original_error"] = original
        observed.append(row)
    audit.check(sum(r["kind"] == "bytes" for r in observed) == 6,
                "original six successful ELF gzip pairs differ")
    return observed


def run(args):
    reader_before = digest(Path(__file__).read_bytes())
    raw_dir = Path(args.selected_root).absolute()
    directory_raw = pinned_local(raw_dir / "DIRECTORY.json", PINS["DIRECTORY.json"])
    selected_raw = pinned_local(raw_dir / "SELECTED.json", PINS["SELECTED.json"])
    semantic_raw = pinned_local(args.semantic_report, PINS["SEMANTIC-READBACK.json"])
    differences_raw = pinned_local(args.difference_report, PINS["PHASE-DIFFERENCE.json"])
    directory, selected, semantic = map(document, (directory_raw, selected_raw, semantic_raw))
    differences = document(differences_raw)
    expected_history_gaps = {}
    for phase in differences["phases"]:
        for observed in phase["unmatched"]:
            if any(row["changed_shared_keys"] or row["missing_report_keys"]
                   for row in observed["candidate_receipts"]):
                key = (phase["family"], phase["label"], observed["case"])
                if key in expected_history_gaps:
                    raise ValueError("duplicate pinned historical difference")
                expected_history_gaps[key] = observed
    if (len(differences["phases"]) != 38 or len(expected_history_gaps) != 46
            or {k[0] for k in expected_history_gaps} != {"names"}
            or any(sum(k[1] == label for k in expected_history_gaps) != 23
                   for label in ("original", "modified"))):
        raise ValueError("pinned 46 historical differences do not have the observed fixed denominator")
    output = Path(args.output).absolute()
    if any(p.is_symlink() for p in (output.parent, *output.parent.parents)):
        raise ValueError("output parent symlink")
    output.mkdir(mode=0o700, exist_ok=False)
    audit = Audit(output, expected_history_gaps)
    started = time.monotonic_ns()
    report = {"schema": "hia.970-original-full-physical-readback.v2", "status": "HOLD",
              "original_artifact": ARTIFACT, "output": str(output), "errors": [],
              "prior_difference_observation": {"bytes": len(differences_raw),
                  "sha256": digest(differences_raw), "expected_history_gaps": 46,
                  "prior_revision_1_HOLD_reclassified": False},
              "scope": {"product_reexecuted": False, "project_imported": False,
                        "historical_HOLD_or_cancelled_reclassified": False,
                        "full_5400_retained_suite_executed": False,
                        "historical_worktree_inodes_preserved": False}}
    try:
        audit.check(directory["entry_count"] == DIRECTORY_COUNT and len(directory["entries"]) == DIRECTORY_COUNT
                    and directory["declared_uncompressed_bytes"] == DIRECTORY_BYTES,
                    "original complete directory denominator differs")
        audit.check(all(directory["artifact"][k] == v for k, v in ARTIFACT.items()),
                    "external original artifact/run/source pins differ")
        audit.check(selected["schema"] == "hia.ci-selected-original-members.v1"
                    and len(selected["selected_members"]) == 354, "selected denominator differs")
        audit.check(semantic["status"] == "ORIGINAL_COLD_AND_FIVE_COMPILER_GATES_JOINED"
                    and semantic["performed_check_count"] == 2799, "prior independent semantic scope differs")
        expected_selected = {r["original_name"]: r for r in selected["selected_members"]}
        with ordinary(args.archive, ARTIFACT["bytes"]) as (source, before):
            original_before = hash_stream(source, before.st_size)
            audit.equal_record(original_before, ARTIFACT["bytes"], ARTIFACT["sha256"], "full ZIP before")
            report["original_before"] = {**original_before, "path": str(Path(args.archive).absolute()),
                                         "identity": identity(before)}
            with zipfile.ZipFile(source) as outer:
                actual_rows, infos, total = catalog(outer, before.st_size, DIRECTORY_COUNT, DIRECTORY_BYTES)
                audit.check(len(infos) == DIRECTORY_COUNT and total == DIRECTORY_BYTES,
                            "full original ZIP inventory differs")
                audit.check(outer.comment.hex() == directory["archive_comment_hex"], "ZIP archive comment differs")
                expected_rows = [{k: v for k, v in r.items() if k != "uncompressed_payload_independently_read"}
                                 for r in directory["entries"]]
                audit.check(actual_rows == expected_rows, "full original central metadata differs from original DIRECTORY")
                inventory_path = output / "outer-member-readback.jsonl"
                with inventory_path.open("x", encoding="utf-8") as inventory:
                    for index, row in enumerate(actual_rows):
                        name = row["name"]
                        rec, unused = read_member(outer, infos[name])
                        audit.outer_records[name] = rec
                        if name in expected_selected:
                            wanted = expected_selected[name]
                            audit.equal_record(rec, wanted["bytes"], wanted["sha256"], "selected raw " + name)
                            audit.check(rec["crc32"] == wanted["crc32"], "selected original CRC differs")
                        inventory.write(json.dumps({"name": name, **rec}, sort_keys=True) + "\n")
                        if index % 2000 == 0:
                            print(json.dumps({"stage": "outer-full-read", "completed": index + 1,
                                              "expected": DIRECTORY_COUNT}), flush=True)
                    inventory.flush()
                    os.fsync(inventory.fileno())
                report["outer"] = {"members": len(infos), "uncompressed_bytes": total,
                                   "all_complete_CRC_SHA256_read": True, "prior_354_selected_joined": True}
                def outer_bytes(path):
                    if path.startswith(TEMP):
                        name = path[len(TEMP):]
                    elif path.startswith(ORIGINAL_SOURCE):
                        name = COLD_SOURCE + path[len(ORIGINAL_SOURCE):]
                    else:
                        raise ValueError("unknown original absolute path")
                    return read_member(outer, infos[name], 64 * CHUNK, capture=True)[1]
                cold = document(outer_bytes(TEMP + "hia-cold.json"))
                source_map = cold["source_manifest"]
                audit.check(len(source_map) == 787 and semantic_digest(source_map) == SOURCE_MAP_SHA,
                            "exact 787 original source map differs")
                audit.check(source_map["tools/hia_selfhost_names.py"] == NAMES_SOURCE_SHA,
                            "original names source cause identity differs")
                for relative, sha in source_map.items():
                    name = COLD_SOURCE + relative
                    audit.check(name in audit.outer_records and audit.outer_records[name]["sha256"] == sha,
                                "complete copied cold source bytes differ: " + relative)
                report["cold_copied_source"] = {"files": len(source_map), "mapping_sha256": SOURCE_MAP_SHA,
                    "all_actual_copied_source_bytes_read": True,
                    "original_worktree_inode_observation_recreated": False}
                gaps = semantic["unselected_physical_file_references"]
                audit.check(len(gaps) == 1025, "prior physical gap denominator differs")
                gap_joins = []
                for path, expected in gaps.items():
                    rec = audit.absolute_record(path)
                    audit.equal_record(rec, expected["bytes"], expected["sha256"], path)
                    copied = path.startswith(ORIGINAL_SOURCE)
                    gap_joins.append({"original_report_path": path,
                                      "archive_member": COLD_SOURCE + path[len(ORIGINAL_SOURCE):] if copied else path[len(TEMP):],
                                      "identity_scope": "same-content retained cold source copy" if copied else "retained original bytes at original relative path",
                                      **rec})
                audit.check(sum(x["identity_scope"].startswith("same-content") for x in gap_joins) == 1,
                            "unexpected original-worktree path substitution")
                report["prior_physical_references"] = {"count": len(gap_joins), "direct_member_count": 1024,
                    "same_content_cold_source_copy_count": 1, "all_declared_byte_hashes_joined": True,
                    "original_worktree_inode_not_preserved": ORIGINAL_SOURCE + "tools/hia_selfhost_process_owner.py"}
                put(output / "physical-reference-joins.json", wire(gap_joins))
                b0 = document(outer_bytes(TEMP + EVIDENCE + "B0.receipt.json"))
                audit.equal_record(audit.absolute_record(b0["output"]), b0["artifact_bytes"], b0["artifact_sha256"], "B0.so")
                audit.check(b0["seed_only"] is True and b0["schema"] == "hepta.hia.program.direct-native.v1",
                            "original B0 boundary differs")
                direct_receipts = [n for n in infos if n.startswith(EVIDENCE)
                                   and "/" not in n[len(EVIDENCE):] and n.endswith(".receipt.json")]
                audit.check(len(direct_receipts) == 87, "fixed original root receipt inventory differs")
                for name in sorted(direct_receipts):
                    if name.endswith("/B0.receipt.json"):
                        continue
                    receipt = document(outer_bytes(TEMP + name))
                    request = document(outer_bytes(TEMP + name[:-len(".receipt.json")] + ".request.json"))
                    audit.invocation(name, receipt, request, outer_bytes)
                report["root_receipts"] = {"B0_actual_bytes": audit.absolute_record(b0["output"]),
                                           "original_invocation_count": len(direct_receipts) - 1}
                for observer in ("native", "linked"):
                    build = document(outer_bytes(TEMP + EVIDENCE + observer + "-observer-build.json"))
                    executable = audit.outer_records[EVIDENCE + observer + "-observer.elf"]
                    audit.check(executable["sha256"] == build["executable_sha256"], "actual observer ELF differs")
                    emission = build["native_emission"]
                    emitted = outer_bytes(TEMP + EVIDENCE + observer + "-observer-emit.output.bin")
                    actual = outer_bytes(TEMP + EVIDENCE + observer + "-observer.elf")
                    audit.check(emitted[:len(actual)] == actual and emission["core_u32"] == len(actual),
                                "observer ELF differs from actual emitted full-output prefix")
                phases = semantic["cold"]["phases"]
                audit.check(len(phases) == PHASE_COUNT and sum(p["archive"]["files"] for p in phases) == PHASE_FILES
                            and sum(p["archive"]["unpacked_bytes"] for p in phases) == PHASE_UNPACKED_BYTES
                            and sum(p["archive"]["packed_bytes"] for p in phases) == PHASE_PACKED_BYTES,
                            "fixed original 38 archive totals differ")
                phase_results = []
                phase_inventory_path = output / "phase-member-readback.jsonl"
                with phase_inventory_path.open("x", encoding="utf-8") as inventory:
                    for phase in phases:
                        result = audit_phase(audit, outer, infos, phase, inventory)
                        phase_results.append(result)
                        print(json.dumps({"stage": "phase-physical-read", "family": result["family"],
                                          "label": result["compiler_label"], "completed": len(phase_results),
                                          "files": result["files"]}), flush=True)
                    inventory.flush()
                    os.fsync(inventory.fileno())
                report["phases"] = {"count": len(phase_results), "member_files": PHASE_FILES,
                    "unpacked_bytes": PHASE_UNPACKED_BYTES, "packed_bytes": PHASE_PACKED_BYTES,
                    "all_complete_CRC_SHA256_mode_and_manifest_verified": True, "results": phase_results}
                audit.check(len(audit.annotation_joins) == 688 and len(audit.history_gaps) == 46
                            and {(r["family"], r["compiler_label"], r["case"])
                                 for r in audit.history_gaps} == set(expected_history_gaps),
                            "known annotation or historical gap accounting differs")
                audit.check(sum(r["embedded_invocation_observation_accounting"]["embedded_total"]
                                for r in phase_results) == 6270,
                            "fixed embedded invocation denominator differs")
                report["historical_invocation_custody"] = {
                    "complete": False, "embedded_observations": 6270,
                    "fully_equal_archived_receipts": 5536,
                    "all_receipt_fields_equal_with_declared_annotations": 688,
                    "earlier_compile_companion_path_overwrites": 46,
                    "families_with_overwrites": {"names-original": 23, "names-modified": 23},
                    "earlier_produced_images_still_physically_verified": 46,
                    "earlier_compile_input_output_request_standalone_originals_recovered": False,
                    "original_product_or_CI_outcomes_reclassified": False,
                }
                report["elf_boundary_original_bytes"] = boundary_gzip(audit, outer, infos)
                put(output / "original-invocation-byte-joins.json", wire(audit.receipt_joins))
                put(output / "annotation-receipt-joins.json", wire(audit.annotation_joins))
                put(output / "historical-overwritten-compilation-observations.json", wire(audit.history_gaps))
                report["original_invocation_byte_join_count"] = len(audit.receipt_joins)
            original_after = hash_stream(source, before.st_size)
            audit.check(original_after == original_before, "full original ZIP changed after all physical reads")
            report["original_after"] = original_after
        audit.check(pinned_local(raw_dir / "DIRECTORY.json", PINS["DIRECTORY.json"]) == directory_raw
                    and pinned_local(raw_dir / "SELECTED.json", PINS["SELECTED.json"]) == selected_raw
                    and pinned_local(args.semantic_report, PINS["SEMANTIC-READBACK.json"]) == semantic_raw
                    and pinned_local(args.difference_report, PINS["PHASE-DIFFERENCE.json"]) == differences_raw,
                    "admitted metadata inputs changed after the physical audit")
        audit.check(digest(Path(__file__).read_bytes()) == reader_before, "independent reader source changed")
        report["status"] = "ALL_RETAINED_PHYSICAL_BYTES_VERIFIED_WITH_46_HISTORICAL_INVOCATION_CUSTODY_GAPS"
    except BaseException as error:
        report["status"] = "PHYSICAL_READBACK_HOLD"
        report["errors"].append({"type": type(error).__name__, "message": str(error),
                                 "traceback": traceback.format_exc()})
    report["performed_check_count"] = audit.check_count
    report["reader_elapsed_ns"] = time.monotonic_ns() - started
    report["reader_sha256"] = digest(Path(__file__).read_bytes())
    report["reader_sha256_before"] = reader_before
    report["reader_python"] = sys.version
    report["command"] = sys.argv
    receipt = put(output / "PHYSICAL-READBACK.json", wire(report))
    print(json.dumps({"status": report["status"], "checks": audit.check_count, "report": receipt}), flush=True)
    return 0 if not report["errors"] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True)
    parser.add_argument("--selected-root", required=True)
    parser.add_argument("--semantic-report", required=True)
    parser.add_argument("--difference-report", required=True)
    parser.add_argument("--output", required=True)
    return run(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
