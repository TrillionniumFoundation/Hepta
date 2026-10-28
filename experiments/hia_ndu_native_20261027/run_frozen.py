#!/usr/bin/env python3
"""Execute exactly the committed three-search protocol and preserve all results."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
PROTOCOL = Path(__file__).with_name("protocol.json")


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def save(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n")
    temporary.replace(path)


def git(*arguments):
    return subprocess.check_output(["git", *arguments], cwd=ROOT)


def snapshot():
    files = []
    for raw in sorted(set(git("ls-files", "-z").split(b"\0")) - {b""}):
        name = os.fsdecode(raw)
        path = ROOT / name
        if path.is_symlink():
            target = os.fsencode(os.readlink(path))
            files.append({"path": name, "kind": "symlink", "bytes": len(target),
                          "sha256": hashlib.sha256(target).hexdigest()})
        else:
            files.append({"path": name, "kind": "regular", "bytes": path.stat().st_size,
                          "sha256": digest(path)})
    status = git("status", "--porcelain=v1", "--untracked-files=all").decode()
    difference = subprocess.run(["git", "diff", "--exit-code", "--no-ext-diff", "HEAD"],
                                cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    return {"git_head": git("rev-parse", "HEAD").decode().strip(), "status": status,
            "tracked_files": files, "tracked_files_sha256": hashlib.sha256(encoded(files)).hexdigest(),
            "tracked_files_match_commit": difference.returncode == 0,
            "worktree_clean": status == "", "scope": "all Git-tracked files; ignored build caches excluded"}


def tool(path):
    selected = Path(path).absolute()
    resolved = selected.resolve(strict=True)
    return {"selected": str(selected), "resolved": str(resolved),
            "sha256": digest(resolved), "bytes": resolved.stat().st_size}


def _protocol_expectations(protocol, spec, cases):
    """Derive the fixed budget from the actual corpus, before paying for a run."""
    if type(protocol) is not dict or type(spec) is not dict:
        raise ValueError("protocol and run specification must be objects")
    if protocol.get("schema") != "hepta.hia.ndu-frozen-protocol.v1":
        raise ValueError("unsupported frozen protocol schema")
    if any(type(spec.get(key)) is not str or not spec[key] for key in ("id", "entry", "pass_id")):
        raise ValueError("run identity, entry and pass must be explicit")
    if (type(cases) is not list or not 1 <= len(cases) <= 64
            or any(type(row) is not list or len(row) != 4
                   or any(type(value) is not int or not 0 <= value < 1 << 64 for value in row)
                   for row in cases)):
        raise ValueError("actual corpus must contain 1..64 four-usize case rows")
    if type(spec.get("case_count")) is not int or spec["case_count"] != len(cases):
        raise ValueError("frozen case count differs from the actual corpus")
    thresholds = protocol["thresholds"]
    objective = {key: thresholds[key] for key in (
        "maximum_live_bytes", "maximum_artifact_bytes", "maximum_search_ns",
        "minimum_gain_ppm", "maximum_mad_ppm")}
    objective["horizon_calls"] = protocol["horizon_calls"]
    reserve = thresholds["decision_reserve_ns"]
    samples, iterations = protocol["samples"], protocol["iterations"]
    if (any(type(value) is not int or value < 0 for value in objective.values())
            or type(reserve) is not int or reserve < 0
            or type(samples) is not int or not 15 <= samples <= 63 or samples % 2 != 1
            or type(iterations) is not int or iterations <= 0):
        raise ValueError("protocol budgets must be exact integers within the measurement profile")
    counts = {"cases": len(cases), "paired_samples": samples,
              "calls_per_sample": iterations * len(cases),
              "timed_calls_total": 2 * samples * iterations * len(cases),
              "untimed_correctness_calls": 2 * len(cases)}
    declared_calls = protocol["native_timed_calls"][spec["timed_calls_budget"]]
    if type(declared_calls) is not int or declared_calls != counts["timed_calls_total"]:
        raise ValueError("frozen native call budget differs from actual corpus, samples and iterations")
    if thresholds.get("require_different_native_artifacts") is not True:
        raise ValueError("the frozen protocol must retain native artifact identity policy")
    deadline = protocol["cooperative_deadline"]
    if (type(deadline) is not dict or type(deadline.get("seconds")) is not int
            or deadline["seconds"] != 120
            or deadline.get("enforcement") != "tool_poll_and_phase_boundary"
            or deadline.get("asynchronous_signal") is not False
            or deadline.get("hard_kill_deadline") is not False):
        raise ValueError("the protocol requires the fixed 120-second cooperative deadline")
    return {"objective": objective, "decision_reserve_ns": reserve,
            "measurement_protocol": {"samples": samples, "iterations": iterations,
                                     "sample_trimming": False, "adaptive_repetition": False},
            "counts": counts, "cooperative_deadline": dict(deadline),
            "case_inventory_sha256": hashlib.sha256(encoded(cases)).hexdigest()}


def check_report(report, protocol, spec, *, cases, returncode):
    """Check one actual CLI report against its frozen inputs without executing it.

    ``complete`` means a consistent terminal attempt, including an ordinary
    failed-closed attempt. ``measurement_complete`` separately requires a
    successful full paired measurement. Missing, interrupted, expired or
    inconsistent reports stop the protocol; they never become a completed run.
    """
    checked = {"schema": "hepta.hia.ndu-frozen-report-check.v1", "consistent": False,
               "complete": False, "measurement_complete": False, "stop_protocol": True,
               "outcome": "incomplete", "errors": []}
    errors = checked["errors"]
    try:
        expected = _protocol_expectations(protocol, spec, cases)
        checked["expected"] = expected
    except (KeyError, TypeError, ValueError) as error:
        errors.append({"code": "invalid_frozen_protocol", "message": str(error)})
        return checked
    if type(report) is not dict:
        errors.append({"code": "missing_or_invalid_report"})
        return checked

    def field(*path):
        value = report
        for key in path:
            if type(value) is not dict or key not in value:
                return None
            value = value[key]
        return value

    def equal(path, value):
        observed = field(*path)
        if type(observed) is not type(value) or observed != value:
            errors.append({"code": "report_protocol_mismatch", "field": ".".join(path),
                           "expected": value, "observed": observed})

    equal(("schema",), "hepta.hia.ndu-qualification.v1")
    equal(("activated",), False)
    equal(("plan", "entry"), spec["entry"])
    equal(("plan", "pass_id"), spec["pass_id"])
    actual_objective = field("plan", "objective")
    if type(actual_objective) is not dict or set(actual_objective) != set(expected["objective"]):
        errors.append({"code": "missing_or_changed_objective_fields"})
    for key, value in expected["objective"].items():
        equal(("plan", "objective", key), value)
    equal(("budget_enforcement", "decision_reserve_ns"), expected["decision_reserve_ns"])
    for key, value in expected["cooperative_deadline"].items():
        equal(("cooperative_deadline", key), value)
    equal(("cooperative_deadline", "expired"), False)
    if field("cooperative_deadline", "expired") is True:
        errors.append({"code": "cooperative_deadline_expired"})

    status = field("status")
    successful = status in ("completed_no_change", "completed_candidate_advised")
    failed_closed = status == "failed_closed_no_change"
    if not successful and not failed_closed:
        errors.append({"code": "nonterminal_or_interrupted_report", "status": status})
    else:
        equal(("ok",), successful)
        equal(("decision",), "candidate_advised" if status == "completed_candidate_advised" else "no_change")
        expected_returncode = 0 if successful else 1
        if type(returncode) is not int or returncode != expected_returncode:
            errors.append({"code": "terminal_exit_code_mismatch", "expected": expected_returncode,
                           "observed": returncode})
    paid = field("costs", "total_paid_wall_ns")
    if type(paid) is not int or paid < 0:
        errors.append({"code": "missing_final_paid_cost"})
    diagnostics = field("diagnostics")
    if type(diagnostics) is not list or (failed_closed and not diagnostics):
        errors.append({"code": "missing_final_diagnostics"})

    measurement = field("measurement")
    if measurement is not None:
        if type(measurement) is not dict:
            errors.append({"code": "invalid_measurement"})
        else:
            for key, value in expected["measurement_protocol"].items():
                equal(("measurement", "protocol", key), value)
            for key, value in expected["counts"].items():
                equal(("measurement", "counts", key), value)
            equal(("measurement", "input", "entry"), spec["entry"])
            try:
                same_cases = encoded(field("measurement", "input", "cases")) == encoded(cases)
            except (TypeError, ValueError):
                same_cases = False
            if not same_cases:
                errors.append({"code": "measurement_case_inventory_mismatch"})
            measured = field("measurement", "ok")
            if type(measured) is not bool or (successful and measured is not True):
                errors.append({"code": "measurement_completion_mismatch"})
            if measured is True:
                equal(("measurement", "status"), "finite_pair_measured_no_selection_authority")
                raw = field("measurement", "raw_samples")
                if (type(raw) is not list or len(raw) != protocol["samples"]
                        or any(type(row) is not dict or type(row.get("pair")) is not int
                               or row["pair"] != index
                               or any(type(row.get(role + "_ns")) is not int or row[role + "_ns"] <= 0
                                      for role in ("baseline", "candidate"))
                               for index, row in enumerate(raw))):
                    errors.append({"code": "incomplete_paired_samples"})
                else:
                    checked["measurement_complete"] = True
            else:
                equal(("measurement", "status"), "measurement_failed")
    elif successful:
        errors.append({"code": "missing_completed_measurement"})

    assessment = field("assessment")
    if assessment is not None:
        equal(("assessment", "schema"), "hepta.hia.ndu-measurement-policy.v2")
        equal(("assessment", "decision_reserve_ns"), expected["decision_reserve_ns"])
        equal(("assessment", "samples"), protocol["samples"])
        equal(("assessment", "calls_per_sample"), expected["counts"]["calls_per_sample"])
        equal(("assessment", "native_artifact_identity_checked"), True)
        identities = [field("measurement", "native", role, "artifact_sha256")
                      for role in ("baseline", "candidate")]
        if any(type(value) is not str or len(value) != 64
               or any(char not in "0123456789abcdef" for char in value) for value in identities):
            errors.append({"code": "missing_native_artifact_identity"})
        else:
            different = identities[0] != identities[1]
            equal(("assessment", "native_artifact_changed"), different)
            if not different:
                equal(("assessment", "eligible"), False)
                reasons = field("assessment", "reasons")
                if type(reasons) is not list or "identical_native_artifacts" not in reasons:
                    errors.append({"code": "missing_artifact_equality_refusal"})
        if status == "completed_candidate_advised":
            equal(("assessment", "eligible"), True)
    elif successful:
        errors.append({"code": "missing_completed_assessment"})
    checked["consistent"] = not errors
    checked["measurement_complete"] = checked["measurement_complete"] and not errors
    checked["complete"] = not errors and (successful or failed_closed)
    checked["stop_protocol"] = not checked["complete"]
    if checked["complete"]:
        checked["outcome"] = "completed_qualification" if successful else "completed_failed_closed_attempt"
    elif successful or failed_closed:
        checked["outcome"] = "incomplete_or_protocol_mismatch"
    return checked


def run(row, output, *, protocol, spec, cases):
    started = time.perf_counter_ns()
    cpu_before = resource.getrusage(resource.RUSAGE_CHILDREN)
    result = {**row, "started_utc": datetime.now(timezone.utc).isoformat(), "returncode": None}
    with (output / (row["id"] + ".stdout.log")).open("xb") as stdout, \
            (output / (row["id"] + ".stderr.log")).open("xb") as stderr:
        process = subprocess.Popen(row["argv"], cwd=ROOT, stdout=stdout, stderr=stderr,
                                   stdin=subprocess.DEVNULL, start_new_session=True)
        try:
            # The CLI checks its cooperative deadline at tool polls and phase
            # boundaries and owns every child's bounded capture/cleanup.
            # Force-killing that capture owner first would orphan its children,
            # which intentionally use new sessions.
            result["returncode"] = process.wait()
        except BaseException:
            if process.poll() is None:
                process.send_signal(signal.SIGINT)
                process.wait()
            raise
        finally:
            result["total_cli_wall_ns"] = time.perf_counter_ns() - started
            cpu_after = resource.getrusage(resource.RUSAGE_CHILDREN)
            result["child_cpu_user_seconds"] = cpu_after.ru_utime - cpu_before.ru_utime
            result["child_cpu_system_seconds"] = cpu_after.ru_stime - cpu_before.ru_stime
            result["finished_utc"] = datetime.now(timezone.utc).isoformat()
            save(output / (row["id"] + ".process.json"), result)
    report, report_path = None, Path(row["report"])
    if report_path.is_file():
        try:
            report = json.loads(report_path.read_text())
            result["qualification_report_sha256"] = digest(report_path)
            if type(report) is dict:
                deadline = report.get("cooperative_deadline")
                result.update(qualification_status=report.get("status"),
                              decision=report.get("decision"), qualification_ok=report.get("ok"),
                              cooperative_deadline_expired=deadline.get("expired") if type(deadline) is dict else None)
        except (OSError, UnicodeError, ValueError, RecursionError) as error:
            report = None
            result["report_parse_error"] = str(error)
    else:
        result["qualification_report_missing"] = True
    result["protocol_check"] = check_report(report, protocol, spec, cases=cases,
                                            returncode=result["returncode"])
    save(output / (row["id"] + ".process.json"), result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--clang", type=Path, required=True)
    parser.add_argument("--bridge", type=Path, required=True)
    parser.add_argument("--bridge-sha256", required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    args = parser.parse_args()
    before = snapshot()
    if not before["worktree_clean"] or not before["tracked_files_match_commit"]:
        parser.error("commit the complete worktree before running the frozen protocol")
    output = args.output_directory.resolve()
    if output == ROOT or ROOT in output.parents:
        parser.error("output must be outside the tested repository")
    output.mkdir(parents=True, exist_ok=False)
    selected = {"python": sys.executable, "clang": args.clang, "bridge": args.bridge}
    tools_before = {name: tool(path) for name, path in selected.items()}
    if tools_before["bridge"]["sha256"] != args.bridge_sha256:
        parser.error("bridge bytes do not match the declared pinned executable")
    protocol = json.loads(PROTOCOL.read_text())
    for item in protocol["input_files"]:
        if digest(ROOT / item["path"]) != item["sha256"]:
            parser.error("protocol input hash mismatch: " + item["path"])
    save(output / "source-before.json", before)
    save(output / "tools-before.json", tools_before)
    save(output / "protocol.json", protocol)
    plan, frozen_cases = [], {}
    for spec in protocol["runs"]:
        cases = json.loads((ROOT / spec["cases"]).read_text())
        try:
            expected = _protocol_expectations(protocol, spec, cases)
        except (KeyError, TypeError, ValueError) as error:
            parser.error("invalid frozen run " + spec["id"] + ": " + str(error))
        frozen_cases[spec["id"]] = cases
        report = output / (spec["id"] + ".json")
        argv = [sys.executable, "tools/qualify_hia_ndu.py", "--program", spec["program"],
                "--cases", spec["cases"], "--entry", spec["entry"], "--pass-id", spec["pass_id"],
                "--bridge", str(args.bridge.resolve()), "--bridge-sha256", args.bridge_sha256,
                "--clang", str(args.clang.resolve()), "--samples", str(protocol["samples"]),
                "--iterations", str(protocol["iterations"]), "--horizon-calls",
                str(protocol["horizon_calls"]), "--output", str(report)]
        argv += ["--deadline-seconds", str(expected["cooperative_deadline"]["seconds"])]
        if spec.get("negative_cases"):
            argv += ["--negative-cases", spec["negative_cases"]]
        plan.append({"id": spec["id"], "argv": argv, "report": str(report),
                     "case_count": len(cases), "expected_counts": expected["counts"],
                     "cooperative_deadline": expected["cooperative_deadline"],
                     "outer_force_kill_deadline": False})
    save(output / "command-plan.json", plan)
    summary = {"schema": "hepta.hia.ndu-frozen-protocol-run.v1", "status": "running", "ok": False,
               "git_head": before["git_head"], "source_was_committed": True,
               "host": {"system": platform.system(), "machine": platform.machine(),
                        "release": platform.release(), "exclusive_host": False,
                        "dot_physical_host_identity_established": False},
               "protocol_sha256": digest(PROTOCOL), "commands": plan, "results": [],
               "claims": {"p4_closed": False, "p7_closed": False, "production_gain_proved": False,
                          "all_input_equivalence_proved": False, "code_activated": False,
                          "full_35_gate_qualification_executed": False}}
    save(output / "summary.json", summary)
    try:
        for spec, command in zip(protocol["runs"], plan):
            print(json.dumps({"started": command["id"]}), flush=True)
            result = run(command, output, protocol=protocol, spec=spec,
                         cases=frozen_cases[spec["id"]])
            summary["results"].append(result)
            save(output / "summary.json", summary)
            print(json.dumps({"finished": command["id"], "decision": result.get("decision"),
                              "seconds": result["total_cli_wall_ns"] / 1e9}), flush=True)
            if result["protocol_check"]["stop_protocol"]:
                summary["status"] = "incomplete_report_or_protocol"
                summary["stopped_after"] = command["id"]
                break
        else:
            summary["status"] = "completed"
    except BaseException as error:
        summary["status"] = "incomplete_interrupted_protocol"
        summary["interruption"] = {"type": type(error).__name__, "message": str(error)}
        raise
    finally:
        after = snapshot()
        tools_after = {name: tool(path) for name, path in selected.items()}
        save(output / "source-after.json", after)
        save(output / "tools-after.json", tools_after)
        summary.update(source_unchanged=before == after, tools_unchanged=tools_before == tools_after,
                       finished_utc=datetime.now(timezone.utc).isoformat())
        summary["ok"] = (summary["status"] == "completed" and summary["source_unchanged"]
                         and summary["tools_unchanged"] and len(summary["results"]) == len(plan)
                         and all(row.get("qualification_ok") is True and row["returncode"] == 0
                                 and row["protocol_check"]["complete"]
                                 and row["protocol_check"]["measurement_complete"]
                                 for row in summary["results"]))
        save(output / "summary.json", summary)
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
