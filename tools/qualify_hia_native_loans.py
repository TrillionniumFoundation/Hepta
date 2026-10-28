#!/usr/bin/env python3
"""Retain actual, source-bound diagnostic native-loan lifecycle observations.

Seven fixed native child calls exercise switching and partial failure. This is
an additional finite qualification, not a performance benchmark or general P6
completion. Uncommitted or changing source can never produce `ok=true`.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import errno
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
from time import perf_counter_ns

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from hepta.hia_native_differential import HIADifferentialRejected
from hepta.hia_native_version_dispatch import NativeVersionDispatcher
from hepta.hia_ndu import make_plan, prepare_candidate
from hepta.hia_program import verify_program
from hepta.hia_program_runtime import execute_program
from hepta.hia_program_tools import read_bounded
from tools.release_check import snapshot

SITE = ("swap_candidate", "entry", "loan")
FIXTURE = ROOT / "examples/hia_native_lifecycle/swap.json"


def _json(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n")
    temporary.replace(path)


def _git(*args):
    process = subprocess.run(["git", "-C", str(ROOT), *args], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10, check=False)
    if process.returncode:
        raise ValueError("source identity unavailable")
    return process.stdout.decode("utf-8", "strict").strip()


def _need(condition, reason):
    if condition is not True:
        raise ValueError("E_NATIVE_LOAN_QUALIFICATION: " + reason)


def qualify(output, *, clang):
    output = Path(output).absolute()
    if output == ROOT or ROOT in output.parents:
        raise ValueError("use an evidence directory outside the source checkout")
    if output.exists() or output.is_symlink():
        raise ValueError("evidence output directory must be new")
    output.mkdir(parents=True, exist_ok=False)
    report_path = output / "report.json"
    started = perf_counter_ns()
    report = {"schema": "hepta.hia.native-loan-qualification.v1", "ok": False,
              "status": "running", "execution_passed": False,
              "started_utc": datetime.now(timezone.utc).isoformat(),
              "scope": "one local byte loan; diagnostic sealed native images; seven fixed child calls",
              "planned_child_calls": 7, "attempts": [], "images": [], "transitions": [],
              "claims": {"diagnostic_instrumentation": True, "production_p6_qualified": False,
                         "full_resource_ledger_observed": False, "all_bytes_observed": False,
                         "native_trap_reason_proved": False, "external_state_migrated": False,
                         "performance_gain_qualified": False, "p0_p7_fully_closed": False}}
    host = None
    handles = []

    def checkpoint():
        _json(report_path, report)

    def retain_image(name, identity):
        version = host._versions[identity]
        raw = os.pread(version.descriptor, version.artifact_bytes + 1, 0)
        _need(len(raw) == version.artifact_bytes and sha256(raw).hexdigest() == version.artifact_sha256,
              "sealed image differs from its actual build receipt")
        artifact = output / (name + ".so")
        with artifact.open("xb") as stream:
            stream.write(raw)
        receipt = version.receipt()
        _json(output / (name + ".build.json"), receipt)
        with (output / (name + ".ll")).open("x") as stream:
            stream.write(receipt["llvm_ir"])
        report["images"].append({"name": name, "core_sha256": identity,
            "artifact": artifact.name, "sha256": version.artifact_sha256, "bytes": len(raw),
            "build_receipt": name + ".build.json", "llvm_ir": name + ".ll",
            "loan_probe_site": receipt["loan_probe_site"]})
        checkpoint()

    def begin(name, arguments, *, timeout=8.0, hold=True):
        row = {"name": name, "entry": "native_swap", "arguments": arguments, "timeout_seconds": timeout}
        report["attempts"].append(row)
        checkpoint()
        handle = host.start_loan_probe("native_swap", arguments, timeout=timeout)
        handles.append((row, handle))
        if hold:
            row["held"] = handle.wait_active(timeout=min(5.0, timeout))
            _need(row["held"]["held"] and len(row["held"]["events"]) == 1,
                  "native loan did not reach its acknowledgement barrier")
            row["dispatch_while_held"] = host.snapshot()
            checkpoint()
        return row, handle

    def finish(row, handle, *, expected=55):
        handle.resume()
        row["result"] = handle.wait()
        _need(row["result"]["status"] == "returned" and row["result"]["value"] == expected,
              "actual native result differs")
        events = row["result"]["observation"]["events"]
        _need(len(events) == 2 and [event["event"] for event in events] == ["loan_started", "loan_ended"],
              "normal native loan interval incomplete")
        _need(events[0]["bytes"] == events[1]["bytes"] == 5
              and (events[0]["first_byte"], events[0]["last_byte"]) == (0, 0)
              and (events[1]["first_byte"], events[1]["last_byte"]) == (55, 11),
              "actual borrowed storage endpoints differ")
        checkpoint()

    checkpoint()
    try:
        report["source_snapshot_before"] = snapshot()
        report["git_commit"] = _git("rev-parse", "HEAD")
        report["git_status_before"] = _git("status", "--porcelain=v1", "--untracked-files=all")
        report["source_was_committed"] = not report["git_status_before"]
        baseline = verify_program(read_bounded(FIXTURE))
        prepared = prepare_candidate(baseline, make_plan(baseline, entry="native_swap"))
        candidate = prepared.candidate
        _need(prepared.replacements == 1 and candidate.sha256 != baseline.sha256,
              "fixed swap fixture did not produce exactly one registered rewrite")
        for name, core in (("baseline", baseline), ("candidate", candidate)):
            (output / (name + ".json")).write_bytes(core.canonical_bytes + b"\n")
        report["input"] = {"path": str(FIXTURE.relative_to(ROOT)), "sha256": sha256(FIXTURE.read_bytes()).hexdigest(),
                           "baseline_sha256": baseline.sha256, "candidate_sha256": candidate.sha256,
                           "registered_plan": prepared.plan, "plan_sha256": prepared.plan_sha256,
                           "site": list(SITE)}
        report["interpreter_control"] = execute_program(baseline, "native_swap", [5, 0, 4, 0])
        _need(report["interpreter_control"]["result"] == 55, "fixed interpreter control differs")
        checkpoint()
        host = NativeVersionDispatcher(baseline.canonical_bytes, clang=clang,
            diagnostic_loan_site=SITE, max_in_flight=2)
        retain_image("baseline", baseline.sha256)
        queued = host.stage_candidate_async(candidate.canonical_bytes)
        report["first_build"] = host.wait_candidate(queued["job_id"], timeout=30)
        _need(report["first_build"]["status"] == "staged", "candidate native build failed")
        retain_image("candidate-first", candidate.sha256)

        old_row, old = begin("baseline-held-across-activation", [5, 0, 4, 0])
        report["transitions"].append(host.activate(candidate.sha256, expected_generation=0))
        current_row, current = begin("new-entry-on-candidate", [5, 0, 4, 0])
        _need(current_row["held"]["program_sha256"] == candidate.sha256
              and current_row["held"]["generation"] == 1, "new call did not use activated candidate")
        _need(host.snapshot()["in_flight"] == 2, "two actual held calls were not counted")
        finish(current_row, current)
        finish(old_row, old)
        _need(old_row["result"]["program_sha256"] == baseline.sha256
              and old_row["result"]["generation"] == 0, "old call lost its original image/generation")

        row, handle = begin("candidate-held-across-rollback", [5, 0, 4, 0])
        old_fd = host._versions[candidate.sha256].descriptor
        report["transitions"].append(host.rollback(expected_generation=1))
        row["dispatch_after_rollback"] = host.snapshot()
        row["old_image_open_before_ack"] = os.fstat(old_fd).st_size > 0
        _need(row["old_image_open_before_ack"], "rollback released an active loan image")
        finish(row, handle)
        try:
            os.fstat(old_fd)
        except OSError as error:
            row["old_image_closed_after_drain"] = error.errno == errno.EBADF
        else:
            row["old_image_closed_after_drain"] = False
        _need(row["old_image_closed_after_drain"], "inactive candidate did not retire after drain")

        row, handle = begin("trap-inside-active-loan", [5, 5, 0, 0])
        handle.resume()
        row["result"] = handle.wait()
        _need(row["result"]["status"] == "trapped"
              and len(row["result"]["observation"]["events"]) == 1, "trap invented a loan-end event")
        checkpoint()

        row, handle = begin("allocation-refusal-before-loan", [2**32 - 1, 0, 4, 0], hold=False)
        row["result"] = handle.wait()
        _need(row["result"]["status"] == "trapped"
              and row["result"]["observation"]["events"] == [], "pre-loan trap invented loan activity")
        checkpoint()

        row, handle = begin("withheld-acknowledgement-timeout", [5, 0, 4, 0], timeout=1.0)
        try:
            handle.wait(timeout=4)
        except HIADifferentialRejected as error:
            row["expected_rejection"] = {"type": type(error).__name__, "message": str(error)}
            _need("timed out" in str(error), "timeout control failed for a different reason")
        else:
            raise ValueError("withheld native acknowledgement unexpectedly returned")
        row["partial_observation"] = handle.snapshot()
        _need(row["partial_observation"]["done"] and not row["partial_observation"]["ack_sent"]
              and len(row["partial_observation"]["events"]) == 1, "timeout observation was not retained")
        _need(host.snapshot()["in_flight"] == 0, "timeout leaked a dispatch reference")

        queued = host.stage_candidate_async(candidate.canonical_bytes)
        report["second_build"] = host.wait_candidate(queued["job_id"], timeout=30)
        _need(report["second_build"]["status"] == "staged", "second real candidate build failed")
        retain_image("candidate-second", candidate.sha256)
        report["transitions"].append(host.activate(candidate.sha256, expected_generation=2))
        row, handle = begin("candidate-held-across-close", [5, 0, 4, 0])
        row["close_while_held"] = host.close(wait=False)
        _need(row["close_while_held"]["status"] == "closing" and not row["close_while_held"]["drained"],
              "close discarded an active loan call")
        finish(row, handle)
        report["final_dispatch"] = host.snapshot()
        _need(report["final_dispatch"]["drained"] and report["final_dispatch"]["released_artifacts"] == 3,
              "owned images did not drain")
        _need(len(report["attempts"]) == report["planned_child_calls"], "fixed native denominator incomplete")
        report["execution_passed"] = True
        report["status"] = "executed"
    except BaseException as error:
        report["status"] = "failed"
        report["error"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        # A failed assertion cannot discard held calls. Their finite native
        # timeout remains in effect; close waits for their process cleanup.
        try:
            if host is not None:
                report["close"] = host.close(wait=True, timeout=12)
                report["final_dispatch"] = host.snapshot()
            for row, handle in handles:
                row["final_observation"] = handle.snapshot()
        except BaseException as error:
            report["cleanup_error"] = {"type": type(error).__name__, "message": str(error)}
        report["source_unchanged"] = False
        report["git_status_after"] = None
        try:
            report["source_snapshot_after"] = snapshot()
            report["source_unchanged"] = report.get("source_snapshot_before") == report["source_snapshot_after"]
            report["git_status_after"] = _git("status", "--porcelain=v1", "--untracked-files=all")
        except BaseException as error:
            report["post_snapshot_error"] = {"type": type(error).__name__, "message": str(error)}
        report["ok"] = (report["execution_passed"] and report.get("source_was_committed") is True
                        and report["source_unchanged"] and report["git_status_after"] == ""
                        and report.get("close", {}).get("drained") is True
                        and "cleanup_error" not in report and "post_snapshot_error" not in report)
        if report["execution_passed"]:
            report["status"] = "passed" if report["ok"] else "execution_only_source_not_frozen"
        report["wall_ns"] = perf_counter_ns() - started
        report["finished_utc"] = datetime.now(timezone.utc).isoformat()
        checkpoint()
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-directory", required=True)
    parser.add_argument("--clang", default="clang")
    arguments = parser.parse_args()
    report = qualify(arguments.output_directory, clang=arguments.clang)
    print(json.dumps({"ok": report["ok"], "status": report["status"],
                      "execution_passed": report["execution_passed"], "actual_child_calls": len(report["attempts"])}))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
