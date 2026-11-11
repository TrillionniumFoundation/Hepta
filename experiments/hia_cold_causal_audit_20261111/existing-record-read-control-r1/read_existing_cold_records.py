"""Read existing exact608 cold records only; never execute project code or write files."""
import base64
import hashlib
import json
import os
from pathlib import Path
import resource
import stat
import sys
import time

REVISION = "hia.existing-cold-records-read.v1"
ORIGIN = Path("/home/qian-qi/he26v67r2/q")
EVIDENCE = ORIGIN / "cold.cold" / "qualification.evidence"
COLD_SHA256 = "c64d3b4a7f46233e593e8bd5b6f87c18ebffb4b9ca9e02e0f3cd1070a5339628"
PYTHON_SHA256 = "b2d6bc2ad950753c5ea407a30788165d8f59c110ca4e90fbad14c8c75376a493"
B3_SHA256 = "0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8"
FAMILIES = ["exports","names","cli","explicit-traps","resource","bulk","loan","cfg","capacity","tail","select","effects","multi","keyword","signed","scalar-casts","core"]
CASES = ["original-bytesum","original-sample-0","original-sample-1","original-sample-2","modified-bytesum","modified-sample-0","modified-sample-1","modified-sample-2","reject-unknown-opcode","reject-missing-end","reject-overflow-u64","reject-overflow-u32","reject-duplicate-ssa","reject-out-of-scope","reject-absent-block","reject-edge-type","reject-call-type","reject-recursive-call-signature","reject-mutable-alias","reject-readonly-jump-alias","reject-readonly-branch-alias","reject-readonly-write","reject-unreachable-block","reject-duplicate-function","reject-quoted-declaration","reject-unquoted-call","reject-leading-zero","reject-invalid-byte","reject-empty-source","reject-function-adjacency","reject-block-adjacency","reject-effects-adjacency","reject-entry-adjacency","reject-entry-open-adjacency","reject-entry-close-adjacency","reject-arrow-adjacency","reject-return-adjacency","reject-edge-adjacency","reject-branch-separation","reject-opcode-adjacency","reject-constant-attribute-separation","reject-call-attribute-separation","reject-cast-attribute-separation","reject-effects-separation","reject-entry-separation","readonly-call-code","readonly-call","original-backward-bytesum","original-backward-sample-0","original-backward-sample-1","original-backward-sample-2","original-full-call-depth","original-full-call-depth-run","original-reject-backward-signature","original-reject-missing-in-range-callee","original-reject-out-of-range-callee","original-reject-overflow-callee","original-reject-non-tail-direct-recursion","original-reject-mutual-recursion","original-reject-unreachable-cycle","modified-backward-bytesum","modified-backward-sample-0","modified-backward-sample-1","modified-backward-sample-2","modified-full-call-depth","modified-full-call-depth-run","modified-reject-backward-signature","modified-reject-missing-in-range-callee","modified-reject-out-of-range-callee","modified-reject-overflow-callee","modified-reject-non-tail-direct-recursion","modified-reject-mutual-recursion","modified-reject-unreachable-cycle","short-output","short-workspace"]
FILE_LIMIT = 64 << 20
TOTAL_LIMIT = 512 << 20
RAW_CAPTURE_LIMIT = 1 << 20
RAW_CAPTURE_TOTAL_LIMIT = 4 << 20
IDENTITY_FIELDS = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
records = {}
total_bytes = 0
captured_bytes = 0

def identity(info):
    return {name: getattr(info, name) for name in IDENTITY_FIELDS}

def read_fixed(path, *, capture=False, expected=None, maximum=FILE_LIMIT):
    global total_bytes, captured_bytes
    path = Path(path)
    if path.resolve(strict=True) != path:
        raise ValueError("symlink in declared input path: " + str(path))
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError("input must be an ordinary single-link file: " + str(path))
        if not 0 <= before.st_size <= maximum or total_bytes + before.st_size > TOTAL_LIMIT:
            raise ValueError("declared read budget exceeded")
        chunks = []
        digest = hashlib.sha256()
        count = 0
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            count += len(chunk)
            if count > before.st_size:
                raise ValueError("input grew while reading")
            digest.update(chunk)
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if count != before.st_size or identity(before) != identity(after):
            raise ValueError("input identity changed while reading")
        if identity(os.stat(path, follow_symlinks=False)) != identity(before):
            raise ValueError("input path changed while reading")
    finally:
        os.close(descriptor)
    total_bytes += count
    raw = b"".join(chunks)
    value = digest.hexdigest()
    if expected is not None and value != expected:
        raise ValueError("fixed original SHA differs: " + str(path))
    row = {"path": str(path), "bytes": count, "sha256": value, "identity": identity(before)}
    if capture:
        if count <= RAW_CAPTURE_LIMIT and captured_bytes + count <= RAW_CAPTURE_TOTAL_LIMIT:
            row["raw_base64"] = base64.b64encode(raw).decode("ascii")
            captured_bytes += count
        else:
            row["raw_capture_omitted_due_to_declared_limit"] = True
    records[str(path)] = row
    return raw, row

def verify_again(row):
    path = Path(row["path"])
    if path.resolve(strict=True) != path:
        raise ValueError("input path became a symlink")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = identity(os.fstat(descriptor))
        digest = hashlib.sha256()
        count = 0
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            count += len(chunk)
            if count > row["bytes"]:
                raise ValueError("input grew during final readback")
            digest.update(chunk)
        after = identity(os.fstat(descriptor))
        path_after = identity(os.stat(path, follow_symlinks=False))
    finally:
        os.close(descriptor)
    if before != row["identity"] or after != before or path_after != before or count != row["bytes"] or digest.hexdigest() != row["sha256"]:
        raise ValueError("original input changed across collection: " + str(path))

def document(name, *, capture=False):
    raw, row = read_fixed(EVIDENCE / name, capture=capture)
    value = json.loads(raw)
    if type(value) is not dict:
        raise ValueError("original JSON report is not an object: " + name)
    return value, row

def main():
    began = time.monotonic_ns()
    report = {"schema": REVISION, "status": "HOLD", "source_commit": "608157e52b0b94e0d294f6b99c4e809869f183aa",
              "original_cold_status_unchanged": True, "qualification_executed": False,
              "project_modules_imported": False, "child_processes_requested": 0,
              "files_or_directories_written_by_collector": 0,
              "reference_reports": [], "prefix_reports": [], "other_reports": [],
              "current_hashes_of_existing_reports_are_not_previous_snapshot_hashes": True,
              "raw_reference_payloads_republished": False, "source_generation_elapsed_reconstructed": False}
    try:
        resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
        resource.setrlimit(resource.RLIMIT_AS, (512 << 20, 512 << 20))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        python = Path(sys.executable).resolve(strict=True)
        # The interpreter can be multiply linked; only its actual immutable bytes are pinned.
        digest = hashlib.sha256()
        with python.open("rb") as stream:
            while True:
                chunk = stream.read(65536)
                if not chunk:
                    break
                digest.update(chunk)
        if digest.hexdigest() != PYTHON_SHA256:
            raise ValueError("formal interpreter bytes differ")
        report["python"] = {"path": str(python), "sha256": digest.hexdigest(), "version": sys.version,
                            "isolated": bool(sys.flags.isolated), "no_site": bool(sys.flags.no_site),
                            "dont_write_bytecode": bool(sys.flags.dont_write_bytecode)}
        if not all(report["python"][name] for name in ("isolated", "no_site", "dont_write_bytecode")):
            raise ValueError("interpreter isolation differs")
        raw, anchor = read_fixed(ORIGIN / "cold.json", expected=COLD_SHA256, maximum=1 << 20)
        cold = json.loads(raw)
        if cold.get("status") != "FAIL" or cold.get("qualification_wall_limit_seconds") != 180 or len(cold.get("source_manifest", {})) != 682:
            raise ValueError("fixed original cold scope differs")
        expected_source = hashlib.sha256(json.dumps(cold["source_manifest"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        report["cold_anchor"] = anchor
        report["expected_reference_source_manifest_sha256"] = expected_source
        _, image = read_fixed(EVIDENCE / "B3.image.bin", expected=B3_SHA256, maximum=668608)
        if image["bytes"] != 668608:
            raise ValueError("original B3 size differs")
        report["compiler"] = image
        for family in FAMILIES:
            value, record = document("reference-" + family + ".worker.json")
            if (value.get("schema") != "hepta.hia.selfhost-independent-reference-process.v1"
                    or value.get("family") != family or value.get("before_B0") is not True
                    or value.get("source_manifest_sha256") != expected_source
                    or type(value.get("wall_elapsed_ns")) is not int or value["wall_elapsed_ns"] < 0
                    or type(value.get("worker_pid")) is not int or value["worker_pid"] <= 0
                    or type(value.get("reference")) is not dict):
                raise ValueError("original reference envelope differs: " + family)
            actual_reference = hashlib.sha256(json.dumps(value["reference"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            if actual_reference != value.get("reference_sha256"):
                raise ValueError("original reference payload hash differs: " + family)
            report["reference_reports"].append({"family": family, "record": record, "worker_pid": value["worker_pid"],
                "wall_elapsed_ns": value["wall_elapsed_ns"], "reference_sha256": actual_reference,
                "reference_keys": sorted(value["reference"]), "before_B0": True,
                "timing_scope": "Original producer starts its timer after first source admission and snapshot."})
        for name in ("B0.receipt.json", "native-observer-build.json", "linked-observer-build.json",
                     "independent-native-observer-reference.json", "independent-linked-observer-reference.json"):
            value, record = document(name, capture=True)
            report["other_reports"].append({"name": name, "record": record, "keys": sorted(value),
                "timing_scope": "Retain actual receipt bytes; missing outer elapsed fields remain unknown."})
        for name in CASES:
            value, record = document(name + ".receipt.json", capture=True)
            if value.get("case") != name or type(value.get("wall_elapsed_ns")) is not int or value["wall_elapsed_ns"] < 0:
                raise ValueError("original prefix receipt differs: " + name)
            report["prefix_reports"].append({"case": name, "record": record, "status": value.get("status"),
                "format": value.get("format"), "wall_elapsed_ns": value["wall_elapsed_ns"],
                "native_elapsed_ns": value.get("native_elapsed_ns"), "runner_sha256": value.get("runner_sha256"),
                "image_sha256": value.get("image_sha256"), "input_sha256": value.get("input_sha256"),
                "output_sha256": value.get("output_sha256")})
        if len(report["reference_reports"]) != 17 or len(report["prefix_reports"]) != 75:
            raise ValueError("fixed observation denominator differs")
        for record in records.values():
            verify_again(record)
        report["all_read_files_sha256_and_identity_unchanged"] = True
        report["status"] = "EXISTING_ORIGINAL_RECORDS_OBSERVED_NOT_QUALIFICATION"
    except BaseException as error:
        report["error"] = {"type": type(error).__module__ + "." + type(error).__qualname__, "message": str(error)}
    finally:
        report["read_file_count"] = len(records)
        report["first_pass_read_bytes"] = total_bytes
        report["captured_original_bytes"] = captured_bytes
        report["elapsed_ns"] = time.monotonic_ns() - began
        # No output path, caches, source imports, subprocess or network is used.
        sys.stdout.write(json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n")
        sys.stdout.flush()
    return 0 if report["status"] == "EXISTING_ORIGINAL_RECORDS_OBSERVED_NOT_QUALIFICATION" else 1

if __name__ == "__main__":
    raise SystemExit(main())
