"""Unexecuted bounded-read native-development control support.

This module does not select a product implementation. It binds the complete
source plan and the unchanged owned-process implementation used by the driver.
"""
from __future__ import annotations
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import re
import sys
import traceback

from source_common import create, pin, read, require, snapshot, wire

OWNER_SHA = "36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2"
COMPILER_SHA = "0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8"
COMPILER_BYTES = 668608
SOURCE_MANIFEST_SHA = "cc7fd4c40506bde614b615e3d6c86691e5c14a0f114d5ce47b8f87944a3f11b3"
SOURCE_MANIFEST_BYTES = 821801
BASE = "9704596acc4470bd0042838586602e26bac7b3d1"
BASE_TREE = "c3ca94c57f9bd75f22f2c694e32bca2dfc6b329b"
CANDIDATE = "0e36619bc65ada7072c1e8a1f1454728036fee4e"
CANDIDATE_TREE = "1d95802c453a006f077eb8735a6939b1957d500b"
GENERATED = "examples/hia_bootstrap/bounded_read.hiaasm"
OVERLAYS = ("hepta/hia_program_tools.py", "hepta/hia_bounded_read_native.py",
            "tools/generate_hia_bounded_read.py")
SELECTOR = "HEPTA_HIA_BOUNDED_READ_MANIFEST"
LIMITS = {
    "source_bytes": 1048576, "source_lines": 16384, "functions": 128,
    "blocks": 1536, "max_blocks_per_function": 256, "operations": 8192,
    "max_unique_ssa_names_per_function": 2048,
    "max_function_parameters": 16, "max_block_parameters": 16,
    "max_edge_arguments": 16, "max_operation_arguments": 16,
    "max_return_arguments": 16,
}
NATIVE_LIMITS = {
    "cpu_seconds": 10, "address_bytes": 256 << 20, "core_dumpable": False,
    "stack_bytes": 8 << 20, "output_capacity": 1 << 20, "workspace_bytes": 1 << 20,
}

def source_manifest(path):
    raw, record = read(path, SOURCE_MANIFEST_BYTES)
    require(record["bytes"] == SOURCE_MANIFEST_BYTES and record["sha256"] == SOURCE_MANIFEST_SHA,
            "complete fixed source manifest differs")
    value = json.loads(raw)
    require(value["schema"] == "hepta.hia.bounded-read-native-development-source-manifest.v1"
            and value["canonical_base_commit"] == BASE
            and value["canonical_base_tree"] == BASE_TREE
            and value["canonical_candidate_commit"] == CANDIDATE
            and value["canonical_candidate_tree"] == CANDIDATE_TREE
            and value["base_members"] == 4023 and value["candidate_members"] == 4025
            and value["overlay_paths"] == list(OVERLAYS)
            and value["generated_resource"] == GENERATED
            and value["generated_resource_in_candidate"] is False,
            "fixed source manifest header differs")
    rows = value["files"]
    require(type(rows) is list and len(rows) == 4025
            and len({row["path"] for row in rows}) == 4025
            and GENERATED not in {row["path"] for row in rows}, "source member denominator differs")
    for row in rows:
        name = row["path"]
        require(type(name) is str and not name.startswith("/") and "\0" not in name
                and "\\" not in name and all(x not in ("", ".", "..") for x in name.split("/"))
                and name.split("/")[0] != ".git" and row["mode"] in ("100644", "100755")
                and type(row["size"]) is int and row["size"] >= 0
                and re.fullmatch(r"[0-9a-f]{40}", row["git_blob_sha1"]) is not None,
                "unsafe fixed source member")
    return rows, raw, record

def generated_rows(rows, assembly):
    return [*rows, {"path": GENERATED, "mode": "100644",
                   "size": len(assembly), "git_blob_sha1": pin(assembly)["git_blob_sha1"],
                   "sha256": sha256(assembly).hexdigest()}]

def load_fixed_module(name, path, expected):
    raw, record = read(path, 1 << 20)
    require(record["sha256"] == expected, "fixed module SHA differs")
    spec = importlib.util.spec_from_file_location(name, path)
    require(spec is not None and spec.loader is not None, "fixed module loader absent")
    module = importlib.util.module_from_spec(spec)
    previous = sys.modules.get(name)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        if previous is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = previous
    require(read(path, 1 << 20)[1] == record, "fixed module changed while loaded")
    return module, record

def natural_process(raw_receipt, returned, request, command, cwd, environment, seconds):
    require(returned["supervisor_returncode"] == 0, "process owner did not exit zero")
    require(request["command"] == command and request["cwd"] == str(cwd)
            and request["env"] == environment and request["qualification_seconds"] == seconds
            and request["cleanup_seconds"] == 3 and request["implementation_sha256"] == OWNER_SHA,
            "actual owned request differs")
    cleanup = raw_receipt["cleanup"]
    require(raw_receipt["status"] == "OWNED_PROCESS_COMPLETED"
            and type(raw_receipt["returncode"]) is int and raw_receipt["returncode"] == 0
            and raw_receipt["qualification_seconds"] == seconds and raw_receipt["cleanup_seconds"] == 3
            and raw_receipt["qualification_started"] is True
            and raw_receipt["exit_observed_before_deadline"] is True
            and raw_receipt["timed_out"] is False and raw_receipt["event_overflow"] is False
            and raw_receipt["subreaper_enabled"] is True and raw_receipt["interrupted_signals"] == []
            and raw_receipt.get("owner_error") is None
            and cleanup["complete"] is True and cleanup["observed_echild"] is True
            and cleanup["leader_reaped"] is True and cleanup["deadline_exceeded"] is False
            and cleanup["remaining_direct_children"] == [] and cleanup["errors"] == []
            and raw_receipt["events"]
            and {"qualification_started", "qualification_exit_observed", "owned_child_reaped"}
                <= {event["kind"] for event in raw_receipt["events"]}
            and all(event["kind"] in {
                "qualification_started", "owned_child_observed",
                "qualification_exit_observed", "owned_child_reaped"}
                for event in raw_receipt["events"]), "owned child did not finish naturally")

def owned_step(owner, root, report, label, command, cwd, environment, seconds):
    out = root / (label + ".stdout.log")
    err = root / (label + ".stderr.log")
    receipt = root / (label + ".process-owner.json")
    step = {"label": label, "command": command, "cwd": str(cwd),
            "qualification_seconds": seconds, "cleanup_seconds": 3, "status": "HOLD",
            "original_files": []}
    report["processes"].append(step)
    returned = None
    try:
        returned = owner.run_owned(command, cwd=cwd, env=environment,
            stdout_path=out, stderr_path=err, receipt_path=receipt,
            qualification_seconds=seconds, cleanup_seconds=3)
        step["owner_returned"] = returned
    finally:
        cleanup = returned.get("cleanup", {}) if type(returned) is dict else {}
        step["cleanup_closed_before_original_read"] = (
            cleanup.get("complete") is True and cleanup.get("observed_echild") is True
            and cleanup.get("leader_reaped") is True and cleanup.get("deadline_exceeded") is False
            and cleanup.get("errors") == [] and cleanup.get("remaining_direct_children") == [])
        paths = (out, err, receipt, Path(str(receipt) + ".request.json"),
                 Path(str(receipt) + ".stdout.log"), Path(str(receipt) + ".stderr.log"))
        if step["cleanup_closed_before_original_read"]:
            for path in paths:
                try:
                    raw, observed = read(path, 4 << 20 if path.name.endswith(".json") else 16 << 20)
                    step["original_files"].append(observed)
                except BaseException as error:
                    step.setdefault("custody_errors", []).append({
                        "path": str(path), "type": type(error).__name__,
                        "traceback": traceback.format_exc()})
        else:
            step["custody_deferred_until_outer_cleanup"] = [str(path) for path in paths]
    require(returned is not None and step["cleanup_closed_before_original_read"]
            and not step.get("custody_errors"), "owned original output incomplete or still live")
    receipt_raw, receipt_record = read(receipt, 4 << 20)
    request_raw, request_record = read(Path(str(receipt) + ".request.json"), 1 << 20)
    actual, request = json.loads(receipt_raw), json.loads(request_raw)
    require(actual["schema"] == request["schema"] == owner.SCHEMA
            and actual["request_sha256"] == sha256(request_raw).hexdigest()
            and actual["implementation_sha256"] == OWNER_SHA
            and request["stdout_path"] == str(out) and request["stderr_path"] == str(err)
            and request["receipt_path"] == str(receipt), "owner receipt/request binding differs")
    augmented = dict(actual, supervisor_returncode=0, receipt_sha256=sha256(receipt_raw).hexdigest())
    require(returned == augmented, "returned owner metadata differs from actual raw receipt")
    natural_process(actual, returned, request, command, cwd, environment, seconds)
    out_raw, out_record = read(out, 16 << 20)
    _, err_record = read(err, 16 << 20)
    step.update(status="OWNED_STEP_PASS", receipt=receipt_record, request=request_record,
                stdout=out_record, stderr=err_record)
    create(root / (label + ".step.json"), wire(step))
    return out_raw
