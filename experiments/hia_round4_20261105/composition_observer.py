"""One-attempt outer observer for a separately frozen composition launch plan.

This file never edits source, selects samples, reruns a lane, or repairs results.
The plan is external to the source tree and must be supplied with its exact hash.
"""
import time
_OBSERVER_ENTERED_NS = time.monotonic_ns()
_OBSERVER_ENTERED_UNIX_NS = time.time_ns()

from pathlib import Path
import hashlib
import json
import os
import platform
import subprocess
import sys


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def save_new(path, value):
    raw = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return {"path": str(path), "bytes": len(raw), "sha256": digest(raw)}


def file_record(path):
    path = Path(path)
    raw = path.read_bytes()
    return {"path": str(path), "bytes": len(raw), "sha256": digest(raw)}


def git(root, *args):
    return subprocess.check_output(["git", *args], cwd=root, text=True).strip()


def source_record(root, footprint=False):
    result = {
        "commit": git(root, "rev-parse", "HEAD"),
        "tree": git(root, "rev-parse", "HEAD^{tree}"),
        "status": git(root, "status", "--porcelain=v1", "--untracked-files=all"),
    }
    if footprint:
        result["materialized_tracked_paths"] = subprocess.check_output(
            ["git", "ls-files", "-t"], cwd=root, text=True).splitlines()
    return result


def small_error(exc):
    return {"type": type(exc).__name__, "message": str(exc)}



def validate_composition_receipts(prefix, plan):
    """Read terminal evidence independently; exit zero alone grants no gate."""
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate composition receipt key")
            result[key] = value
        return result
    def reject_constant(value):
        raise ValueError("non-finite composition receipt number: " + value)
    def read(path):
        raw = path.read_bytes()
        return json.loads(raw, object_pairs_hook=unique_object, parse_constant=reject_constant), {"path": str(path), "bytes": len(raw), "sha256": digest(raw)}
    report, report_record = read(prefix / "RESULT.json")
    registration, registration_record = read(prefix / "PLAN.json")
    expected_names = plan["expected_command_names"]
    expected_flags = plan["expected_qualification_names"]
    if len(expected_names) != 36 or len(set(expected_names)) != 36 or len(expected_flags) != 34 or len(set(expected_flags)) != 34:
        raise ValueError("fixed command or qualification inventory differs")
    if report.get("schema") != "hepta.hia.source-composition.v4" or report.get("status") != "completed":
        raise ValueError("composition terminal receipt missing or unsuccessful")
    for key in ("qualification_commands_passed", "source_and_tools_unchanged", "p0_same_combination_build_execute_reject_cancel_recover"):
        if report.get(key) is not True:
            raise ValueError("composition gate not true: " + key)
    flags = report.get("qualifications")
    if type(flags) is not dict or set(flags) != set(expected_flags) or any(value is not True for value in flags.values()):
        raise ValueError("complete exact qualification flags required")
    if report.get("authority") != "DENY_ALL" or report.get("safety_certificate") is not False or report.get("all_seven_research_targets_closed") is not False:
        raise ValueError("bounded research authority differs")
    for obj in (report, registration):
        identity = obj.get("source", {})
        if identity.get("commit") != plan["source"]["commit"] or identity.get("tree") != plan["source"]["tree"]:
            raise ValueError("registered source identity differs")
    if registration.get("schema") != "hepta.hia.source-composition.v4" or registration.get("process_affinity") != plan["affinity"]:
        raise ValueError("registered composition schema or affinity differs")
    if report.get("frozen_artifacts_sha256", {}).get(str(prefix / "PLAN.json")) != registration_record["sha256"]:
        raise ValueError("registered PLAN commitment differs")
    rows = report.get("commands")
    if type(rows) is not list or [row.get("name") for row in rows] != expected_names:
        raise ValueError("all fixed command receipts in execution order required")
    actual_paths = sorted((prefix / "commands").glob("*.command.json"))
    if {path.name for path in actual_paths} != {name + ".command.json" for name in expected_names}:
        raise ValueError("disk command receipt inventory differs")
    receipts = []
    for name, recorded in zip(expected_names, rows):
        actual, identity = read(prefix / "commands" / (name + ".command.json"))
        if actual != recorded or actual.get("name") != name:
            raise ValueError("disk and terminal command receipts differ")
        if type(actual.get("returncode")) is not int or actual["returncode"] != 0 or actual.get("timed_out") is not False or actual.get("launch_error") is not None:
            raise ValueError("a registered command failed or timed out")
        if type(actual.get("wall_ns")) is not int or actual["wall_ns"] <= 0:
            raise ValueError("positive observed command wall required")
        receipts.append(identity)
    return {
        "valid": True, "result": report_record, "registration": registration_record,
        "command_count": len(rows), "qualification_count": len(flags),
        "last_command": expected_names[-1], "receipts": receipts,
        "scope": "Complete configured qualification and source/tool stability only; positive runtime, resource-cost, or universal research conclusions are read separately.",
    }


def main():
    if len(sys.argv) != 3:
        raise ValueError("usage: observer.py ABSOLUTE_PLAN EXPECTED_PLAN_SHA256")
    plan_path = Path(sys.argv[1])
    raw = plan_path.read_bytes()
    if not plan_path.is_absolute() or digest(raw) != sys.argv[2]:
        raise ValueError("frozen launch-plan identity mismatch")
    plan = json.loads(raw)
    if plan["schema"] != "hepta.hia.composition-v4-launch-plan.v1":
        raise ValueError("unexpected launch-plan schema")
    root, prefix = Path(plan["cwd"]), Path(plan["output_prefix"])
    if not root.is_absolute() or not prefix.is_absolute() or prefix.is_relative_to(root):
        raise ValueError("output must be a separate absolute evidence path")
    if not prefix.parent.is_dir():
        raise ValueError("evidence parent must already exist")
    names = ("invocation.json", "stdout", "stderr", "outer.json")
    paths = {name: Path(str(prefix) + "." + name) for name in names}
    if prefix.exists() or any(os.path.lexists(path) for path in paths.values()):
        raise ValueError("fresh one-attempt output and sibling receipts required")
    expected = plan["source"]
    chosen = plan["affinity"]
    invocation = {
        "schema": "hepta.hia.composition-v4-outer-invocation.v1",
        "plan": {"path": str(plan_path), "bytes": len(raw), "sha256": digest(raw)},
        "driver": file_record(__file__),
        "source_expected": expected,
        "argv": plan["argv"], "cwd": str(root),
        "explicit_environment": plan["explicit_environment"],
        "original_affinity": sorted(os.sched_getaffinity(0)),
        "selected_affinity": chosen,
        "platform": platform.platform(), "machine": platform.machine(),
        "exclusive_host": False,
        "concurrent_work_scope": plan["concurrent_work_scope"],
        "loadavg_before": list(os.getloadavg()),
        "observer_entered_monotonic_ns": _OBSERVER_ENTERED_NS,
        "observer_entered_unix_ns": _OBSERVER_ENTERED_UNIX_NS,
        "release": plan["release"],
        "historical_preparation": plan["historical_preparation"],
        "one_attempt": True,
        "performance_protocol_or_threshold_changes_by_observer": False,
    }
    result = {
        "schema": "hepta.hia.composition-v4-outer-result.v1",
        "returncode": None, "exception": None, "child_started": False,
        "child_pid": None, "child_command_wall_ns": None,
        "source_after": None, "source_after_error": None,
        "stream_errors": {}, "receipt_errors": {},
        "composition_receipt_check": None, "composition_receipt_error": None,
        "exclusive_host": False,
        "wall_scope": "Python first clock through terminal receipt preparation; interpreter startup and final receipt fsync are outside this clock; authoritative Runtime job receipts retained separately",
        "cost_accounting": "child_command_wall_ns is nested in wall_ns; never add the two; prior preparation and later packaging reported separately",
    }
    original_affinity = set(os.sched_getaffinity(0))
    invocation_written = False
    try:
        if plan.get("observer_path") != str(Path(__file__).absolute()) or plan.get("observer_sha256") != invocation["driver"]["sha256"]:
            raise ValueError("launch plan must bind this exact observer")
        release = plan["release"]
        if release.get("authorized") is not True or release["source_commit"] != expected["commit"] or release["source_tree"] != expected["tree"]:
            raise ValueError("same-source proof release not bound to this source")
        invocation["release_files"] = []
        for wanted in release["files"]:
            observed = file_record(wanted["path"])
            invocation["release_files"].append(observed)
            if observed["sha256"] != wanted["sha256"] or observed["bytes"] != wanted["bytes"]:
                raise ValueError("proof release receipt drift")
        if not release["files"]:
            raise ValueError("proof release evidence required")
        invocation["source_before"] = source_record(root, footprint=True)
        before = invocation["source_before"]
        if before["commit"] != expected["commit"] or before["tree"] != expected["tree"] or before["status"]:
            raise ValueError("frozen source identity mismatch")
        script_record = file_record(root / "tools/qualify_hia_composition.py")
        invocation["composition_entry"] = script_record
        if script_record["sha256"] != plan["composition_entry_sha256"]:
            raise ValueError("composition entry drift")
        if chosen != [0, 1, 2, 3] or not set(chosen) <= original_affinity:
            raise ValueError("fixed CPU affinity unavailable")
        os.sched_setaffinity(0, set(chosen))
        invocation["actual_affinity"] = sorted(os.sched_getaffinity(0))
        if invocation["actual_affinity"] != chosen:
            raise ValueError("actual CPU affinity differs")
        if plan["argv"][0] != plan["python"] or plan["argv"][1:3] != ["-B", "tools/qualify_hia_composition.py"]:
            raise ValueError("unexpected frozen composition command")
        invocation["prelaunch_check_wall_ns"] = time.monotonic_ns() - _OBSERVER_ENTERED_NS
        save_new(paths["invocation.json"], invocation)
        invocation_written = True
        command_started = time.monotonic_ns()
        try:
            with paths["stdout"].open("xb") as out, paths["stderr"].open("xb") as err:
                process = subprocess.Popen(
                    plan["argv"], cwd=root,
                    env={**os.environ, **plan["explicit_environment"]},
                    stdout=out, stderr=err)
                result["child_started"] = True
                result["child_pid"] = process.pid
                result["child_start_unix_ns"] = time.time_ns()
                result["returncode"] = process.wait()
        finally:
            result["child_command_wall_ns"] = time.monotonic_ns() - command_started
    except Exception as exc:
        result["exception"] = small_error(exc)
    finally:
        if not invocation_written:
            invocation["prelaunch_error"] = result["exception"]
            try:
                save_new(paths["invocation.json"], invocation)
            except Exception as exc:
                result["receipt_errors"]["invocation"] = small_error(exc)
        try:
            result["source_after"] = source_record(root)
        except Exception as exc:
            result["source_after_error"] = small_error(exc)
        after = result["source_after"]
        result["source_unchanged"] = bool(
            after is not None and after["commit"] == expected["commit"]
            and after["tree"] == expected["tree"] and not after["status"])
        try:
            result["composition_receipt_check"] = validate_composition_receipts(prefix, plan)
        except Exception as exc:
            result["composition_receipt_error"] = small_error(exc)
        result["streams"] = {}
        for name in ("stdout", "stderr"):
            try:
                result["streams"][name] = file_record(paths[name]) if paths[name].exists() else None
            except Exception as exc:
                result["stream_errors"][name] = small_error(exc)
        try:
            result["loadavg_after"] = list(os.getloadavg())
            result["final_affinity"] = sorted(os.sched_getaffinity(0))
            os.sched_setaffinity(0, original_affinity)
            result["restored_affinity"] = sorted(os.sched_getaffinity(0))
        except Exception as exc:
            result["affinity_cleanup_error"] = small_error(exc)
        result["terminal_unix_ns"] = time.time_ns()
        result["wall_ns"] = time.monotonic_ns() - _OBSERVER_ENTERED_NS
        result["successful_process_and_source_identity"] = bool(
            result["returncode"] == 0 and result["exception"] is None
            and result["source_unchanged"] and not result["receipt_errors"]
            and not result["stream_errors"] and "affinity_cleanup_error" not in result
            and result["composition_receipt_check"] is not None
            and result["composition_receipt_check"]["valid"] is True
            and result["composition_receipt_error"] is None)
        save_new(paths["outer.json"], result)
    print(json.dumps(result, sort_keys=True), flush=True)
    return 0 if result["successful_process_and_source_identity"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
