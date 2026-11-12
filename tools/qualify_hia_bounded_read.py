"""Run the fixed bounded-read finite component and original public callers.

Six owned steps (build, four finite groups, original callers) run inside one
180-second owner with the original three-second cleanup allowance. The exact
55 + 8 method populations and seven CLI children are mandatory. This finite
gate is not a cold qualification or proof of arbitrary foreign objects.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import sys
import traceback

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from tools.build_hia_bounded_read import (
    ABI, CHECK_ROOT, OWNED_SOURCE_FILES, SCHEMA, SOURCE, current_sources,
)
from tools.hia_bounded_read_checks.source_common import create, read, require, wire
from tools import hia_selfhost_process_owner as process_owner

OWNER_SHA = "36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2"
SELECTOR = "HEPTA_HIA_BOUNDED_READ_MANIFEST"
GROUP_NAMES = ("reject", "lifetime", "permission", "filesystem", "original-eight")
GROUP_COUNTS = (12, 24, 10, 9, 8)
GROUP_SECONDS = (30, 30, 30, 30, 180)
ANOMALIES = {"failures", "errors", "skips", "expected_failures", "unexpected_successes"}

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


def population():
    value = json.loads((ROOT / CHECK_ROOT / "populations.json").read_bytes())
    groups = value["groups"]
    require(value["finite_component_cases"] == 55 and value["original_methods"] == 8
            and value["original_CLI_children"] == 7
            and value["original_CLI_child_timeout_seconds"] == 20
            and [row["name"] for row in groups] == list(GROUP_NAMES)
            and [row["method_count"] for row in groups] == list(GROUP_COUNTS)
            and [row["qualification_seconds"] for row in groups] == list(GROUP_SECONDS)
            and all(len(row["expected_ids"]) == row["method_count"]
                    and len(set(row["expected_ids"])) == row["method_count"]
                    for row in groups), "fixed bounded-read populations differ")
    return groups


def environment():
    return {"PATH": os.environ.get("PATH", ""), "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1"}


def image_bundle(manifest_path):
    raw, manifest_record = read(manifest_path, 16384)
    manifest = json.loads(raw)
    require(type(manifest) is dict and set(manifest) == {
        "schema", "source_sha256", "image_path", "image_sha256", "compiler_sha256"}
        and manifest["schema"] == SCHEMA
        and manifest["source_sha256"] == sha256((ROOT / SOURCE).read_bytes()).hexdigest(),
        "bounded-read selected manifest differs")
    image_path = manifest_path.parent / manifest["image_path"]
    require(image_path == manifest_path.parent / "bounded-read.image.bin",
            "bounded-read build image path differs")
    image, image_record = read(image_path, 1 << 20)
    require(0 < len(image) <= 1 << 20
            and sha256(image).hexdigest() == manifest["image_sha256"],
            "bounded-read selected image bytes differ")
    return {"manifest": manifest_record, "image": image_record, "value": manifest}


def group_result(folder, group):
    raw, report_record = read(folder / "report.json", 16 << 20)
    result = json.loads(raw)
    require(result["schema"] == group["schema"] and result["status"] == group["status"]
            and result["expected_ids"] == result["loaded_ids"] == result["executed_ids"]
            == group["expected_ids"] and not result.get("errors")
            and set(result["anomalies"]) == ANOMALIES
            and all(not rows for rows in result["anomalies"].values()),
            "complete finite group result differs: " + group["name"])
    originals = []
    if group["name"] != "original-eight":
        require([row["id"] for row in result["cases"]] == group["expected_ids"]
                and all(row["status"] == "PASS" for row in result["cases"]),
                "finite case result population differs")
        for row in result["cases"]:
            record = row.get("record", row.get("original"))
            expected = folder / (row["id"] + ".json")
            require(type(record) is dict and record["path"] == str(expected),
                    "finite case original path differs")
            detail_raw, observed = read(expected, 4 << 20)
            require(observed["bytes"] == record["bytes"]
                    and observed["sha256"] == record["sha256"],
                    "finite case original bytes differ")
            detail = json.loads(detail_raw)
            require(detail["id"] == row["id"] and detail["status"] == "PASS",
                    "finite case original result differs")
            if group["name"] in ("reject", "lifetime"):
                require(detail.get("real_native_entry_required") is True,
                        "differential case did not require actual native entry")
            elif group["name"] == "permission":
                require(type(detail.get("actual_native_entry_returns")) is int
                        and detail["actual_native_entry_returns"] > 0
                        and detail.get("terminal_permission_sealed") is True,
                        "permission case lacks actual entry and terminal seal")
            else:
                require(detail.get("actual_native_call_delta") == 1
                        and type(detail.get("actual_native_transition_delta")) is int
                        and detail["actual_native_transition_delta"] > 0
                        and detail.get("retained_policy_calls") == [],
                        "filesystem case lacks actual native call")
            originals.append(observed)
    else:
        require(result["testsRun"] == 8 and not result["loader_errors"]
                and len(result["children"]) == 7
                and result["original_CLI_timeout_seconds"] == 20
                and result["actual_native_read_attempts"] == 12
                and result["actual_native_read_returns"] == 11
                and result["parent"]["retained_owner_calls"] == []
                and all(row["result"]["retained_owner_calls"] == []
                        for row in result["children"]),
                "original eight/seven CLI actual results differ")
        for row in result["children"]:
            for key in ("record", "start"):
                record = row[key]
                path = Path(record["path"])
                require(path.parent == folder / "children", "unexpected original CLI file")
                child_raw, observed = read(path, 4 << 20)
                require(observed == record, "original CLI custody record differs")
                if key == "record":
                    require(json.loads(child_raw) == row["result"],
                            "original CLI body differs from report")
                originals.append(observed)
    return {"name": group["name"], "report": report_record, "originals": originals,
            "result": result}


def worker(args):
    output = args.output
    output.mkdir(mode=0o700)
    report = {
        "schema": "hepta.hia.bounded-read-finite-validation.v1", "status": "HOLD",
        "processes": [], "groups": [], "errors": [],
        "outer_seconds": 180, "cleanup_seconds": 3,
        "finite_component_cases": 55, "original_methods": 8,
        "original_CLI_children": 7, "original_CLI_child_timeout_seconds": 20,
        "production_activated": False, "all_input_equivalence_proved": False,
        "cold_qualification": False, "whole_native_delivery_qualified": False,
        "filesystem_and_context_operations_remain_hosted": True,
        "python": {"implementation": platform.python_implementation(),
                   "version": platform.python_version(), "executable": sys.executable},
    }
    before = None
    bundle_before = None
    try:
        before = current_sources()
        require(all(name in before for name in OWNED_SOURCE_FILES),
                "finite validation source closure is incomplete")
        require(sha256((ROOT / "tools/hia_selfhost_process_owner.py").read_bytes()).hexdigest()
                == OWNER_SHA, "original process owner differs")
        report["source_before"] = before
        compiler_raw = args.compiler.read_bytes()
        report["compiler_before"] = {"bytes": len(compiler_raw),
                                      "sha256": sha256(compiler_raw).hexdigest()}
        build_root = output / "build"
        command = [sys.executable, "-B", str(ROOT / "tools/build_hia_bounded_read.py"),
                   "--compiler", str(args.compiler), "--output", str(build_root)]
        command += (["--development"] if args.development else
                    ["--cold-report", str(args.cold_report)])
        owned_step(process_owner, output, report, "build", command, ROOT, environment(), 60)
        manifest_path = build_root / "manifest.json"
        bundle_before = image_bundle(manifest_path)
        report["bundle_before"] = bundle_before
        build_raw, build_record = read(build_root / "build.json", 8 << 20)
        build = json.loads(build_raw)
        expected_scope = ("DEVELOPMENT_ONLY_NOT_MATCHING_SOURCE_COLD" if args.development
                          else "MATCHING_SOURCE_COLD_BUILD")
        require(build["status"] == "NATIVE_CANDIDATE_BUILT"
                and build["scope"] == expected_scope and build["source_manifest"] == before
                and build["compiler_sha256"] == report["compiler_before"]["sha256"]
                and build["manifest"] == bundle_before["value"]
                and build["build_inputs_stable"] is True, "component build binding differs")
        report["build"] = {"record": build_record, "scope": expected_scope}
        selected = dict(environment(), **{SELECTOR: str(manifest_path)})
        oracle = ROOT / "tests/fixtures/hia_program_tools_acffa.py.txt"
        for group in population():
            folder = output / group["name"]
            command = [sys.executable, "-B", str(ROOT / CHECK_ROOT / group["script"]),
                       "--source-root", str(ROOT), "--manifest", str(manifest_path),
                       "--output", str(folder)]
            if group["oracle"]:
                command += ["--oracle", str(oracle)]
            owned_step(process_owner, output, report, group["name"], command,
                       ROOT, selected, group["qualification_seconds"])
            report["groups"].append(group_result(folder, group))
        report["bundle_after"] = image_bundle(manifest_path)
        report["compiler_after"] = {"bytes": args.compiler.stat().st_size,
            "sha256": sha256(args.compiler.read_bytes()).hexdigest()}
        require(report["bundle_after"] == bundle_before
                and report["compiler_before"] == report["compiler_after"]
                and len(report["processes"]) == 6 and len(report["groups"]) == 5,
                "final component originals differ")
        report["status"] = "FINITE_BOUNDED_READ_VALIDATION_PASS"
    except BaseException as error:
        report["status"] = "HOLD"
        report["errors"].append({"type": type(error).__name__, "text": str(error),
                                 "traceback": traceback.format_exc()})
    finally:
        try:
            report["source_after"] = current_sources()
            report["source_preserved"] = before == report["source_after"]
            if not report["source_preserved"]:
                report["status"] = "HOLD"
        except BaseException as error:
            report["status"] = "HOLD"
            report["source_preserved"] = False
            report["errors"].append({"phase": "final_source", "type": type(error).__name__,
                                     "text": str(error)})
        create(output / "report.json", wire(report))
    return 0 if report["status"] == "FINITE_BOUNDED_READ_VALIDATION_PASS" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--compiler", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--cold-report", type=Path)
    mode.add_argument("--development", action="store_true")
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    args.output = args.output.resolve()
    args.compiler = args.compiler.resolve(strict=True)
    if args.cold_report is not None:
        args.cold_report = args.cold_report.resolve(strict=True)
    require(args.output != ROOT and ROOT not in args.output.parents,
            "finite validation evidence must be outside source")
    if args.worker:
        return worker(args)
    args.output.mkdir(mode=0o700)
    final = {"schema": "hepta.hia.bounded-read-finite-acceptance.v1", "status": "HOLD",
             "processes": [], "errors": [], "product_full_qualification": False,
             "outer_seconds": 180, "cleanup_seconds": 3}
    command = [sys.executable, "-B", str(Path(__file__).resolve()), "--worker",
               "--output", str(args.output / "work"), "--compiler", str(args.compiler)]
    command += (["--development"] if args.development else
                ["--cold-report", str(args.cold_report)])
    try:
        owned_step(process_owner, args.output, final, "validation", command,
                   ROOT, environment(), 180)
        raw, record = read(args.output / "work/report.json", 32 << 20)
        value = json.loads(raw)
        require(value["status"] == "FINITE_BOUNDED_READ_VALIDATION_PASS"
                and value["source_preserved"] is True and not value["errors"]
                and len(value["groups"]) == 5 and len(value["processes"]) == 6
                and [row["name"] for row in value["groups"]] == list(GROUP_NAMES),
                "bounded-read worker finite conjunction differs")
        final.update(status="FINITE_BOUNDED_READ_VALIDATION_PASS", report=record,
                     scope="FINITE_55_PLUS_ORIGINAL_8_AND_7_CLI_NOT_FULL_QUALIFICATION")
    except BaseException as error:
        final["errors"].append({"type": type(error).__name__, "text": str(error),
                                "traceback": traceback.format_exc()})
    create(args.output / "acceptance.json", wire(final))
    print(json.dumps({"status": final["status"], "report": str(args.output / "acceptance.json")}))
    return 0 if final["status"] == "FINITE_BOUNDED_READ_VALIDATION_PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
