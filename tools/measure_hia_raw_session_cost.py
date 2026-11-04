#!/usr/bin/env python3
"""Fixed four-arm raw Rust planner service-cost study; freeze before run.

This measures one-shot/session x exact_dp/ndu on one recorded release image.
It does not run Python DP, execute selected programs, or rebuild the adapter.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import gzip
from hashlib import sha256
from itertools import combinations
import json
from pathlib import Path
import shutil
import statistics
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from hepta.hia_ndu import _read_json
from hepta.hia_ndu_raw_model import UPSTREAM, invoke
from hepta.hia_ndu_raw_session import RawModelSession
from tools.measure_hia_raw_model_cost import (
    ROUNDS, _git, _quantile, _sha, _write, build_cost_observation, cases,
    source_inventory as one_shot_source_inventory,
)

SCHEMA = "hepta.hia.ndu.raw-model.four-arm-service-cost.v1"
ARMS = ("one_shot_exact_dp", "one_shot_ndu", "session_exact_dp", "session_ndu")
SESSION_ARMS = ARMS[2:]
MODES = dict(zip(ARMS, ("exact_dp", "ndu", "exact_dp", "ndu")))
CALLS_PER_ARM = 744
SESSION_LIMIT = 256
DECISION_FIELDS = ("bundle", "pareto_candidate_ids", "selected_first_action")


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def schedule(case_rows):
    counts = dict.fromkeys(ARMS, 0)
    rows = []
    for round_id in range(ROUNDS):
        for case_index, case in enumerate(case_rows):
            order = ARMS if (round_id + case_index) % 2 == 0 else ARMS[::-1]
            for arm in order:
                index = counts[arm]
                rows.append({"slot": len(rows), "round": round_id, "case_id": case["id"],
                    "arm": arm, "mode": MODES[arm], "arm_call_index": index,
                    "segment": index // SESSION_LIMIT if arm in SESSION_ARMS else None,
                    "sequence": index % SESSION_LIMIT + 1 if arm in SESSION_ARMS else None})
                counts[arm] += 1
    return rows


def definition():
    return {"rounds": ROUNDS, "case_count": 24, "calls_per_arm": CALLS_PER_ARM,
        "total_calls": 2976, "arms": list(ARMS), "session_limit": SESSION_LIMIT,
        "session_segment_requests": [256, 256, 232], "timeout_seconds": 10,
        "image_check_profile": "sealed", "warmup_calls": 0, "extra_identity_probes": 0,
        "order": "fixed cases; forward arms iff (round + case_index) is even, otherwise reverse",
        "primary": "standalone service = sum(outer startup + complete API call + outer close)",
        "call_clock": "monotonic_ns immediately around invoke/evaluate, including returned receipt construction",
        "one_shot_startup_close": "already inside invoke; separate startup/close terms are zero, not missing",
        "session_clock": "constructor and close measured separately, including their return; no request replay",
        "build_rule": "same observed build B charged once to each standalone arm; per-call B/744; unknown stays null",
        "decision_equality": "all six arm pairs, every bundle/winner-list/selected-first-action field, type-sensitive JSON",
        "failure_rule": "stop on first failure, close all acquired sessions, retain attempts/errors/unattempted slots",
        "outlier_removal": False, "rerun_failed_slots": False, "performance_early_stopping": False,
        "analysis": "fixed descriptive totals and ratios only; no confidence or independent-host inference",
        "excludes": "imports, caller logging/audit, acquisition outside recorded build, optimized application execution",
        "machine_cold_claim": False, "full_application_lifecycle_advantage_established": False,
        "production_activation_allowed": False, "safety_certificate": False}


def source_inventory():
    inventory = one_shot_source_inventory()
    for name in ("tools/measure_hia_raw_session_cost.py", "hepta/hia_ndu_session.py",
                 "hepta/hia_ndu_raw_session.py", "docs/HIA_RAW_MODEL_SESSION_COST_V1.md",
                 "tests/test_hia_raw_session_cost.py"):
        inventory[name] = _sha(ROOT / name)
    return dict(sorted(inventory.items()))


def _build_observation(binary, build):
    manifest = _read_json(build.read_bytes())
    adapter = ROOT / "rust/hia-ndu-raw-model"
    expected = {str(p.relative_to(adapter)): _sha(p) for p in adapter.rglob("*") if p.is_file()}
    if (manifest.get("schema") != "hepta.hia.ndu-build.v1"
            or manifest.get("upstream", {}).get("commit") != UPSTREAM
            or manifest.get("original_rust_sources_unchanged") is not True
            or manifest.get("all_original_non_manifest_inputs_unchanged") is not True
            or manifest.get("binary_sha256") != _sha(binary)
            or _canonical(manifest.get("adapter_files")) != _canonical(expected)
            or type(manifest.get("build_command")) is not list
            or any(type(arg) is not str for arg in manifest["build_command"])
            or "--release" not in manifest["build_command"]):
        raise ValueError("release binary, original source or adapter binding differs")
    # Includes original compiler stdout/stderr identities. A malformed present
    # cost is an error; an inherited unmeasured build remains unknown.
    return build_cost_observation(manifest, build)


def validate_definition(protocol):
    fixed_cases = cases()
    if (protocol.get("schema") != SCHEMA
            or _canonical(protocol.get("fixed")) != _canonical(definition())
            or _canonical(protocol.get("cases")) != _canonical(fixed_cases)
            or _canonical(protocol.get("schedule")) != _canonical(schedule(fixed_cases))):
        raise ValueError("registration differs from the fixed four-arm protocol")


def _validate_inputs(protocol, registration, registration_sha256):
    validate_definition(protocol)
    if (protocol["source_head"] != _git("rev-parse", "HEAD")
            or protocol["source_tree"] != _git("rev-parse", "HEAD^{tree}")
            or _canonical(protocol["source_files"]) != _canonical(source_inventory())
            or _git("status", "--porcelain=v1", "--untracked-files=no")):
        raise ValueError("source changed after registration")
    binary, build = Path(protocol["binary"]), Path(protocol["build_receipt"])
    if (_sha(binary) != protocol["binary_sha256"]
            or _sha(build) != protocol["build_receipt_sha256"]
            or _sha(registration) != registration_sha256):
        raise ValueError("registration or native build changed")
    observed = _build_observation(binary, build)
    if _canonical(observed) != _canonical(protocol["build_cost"]):
        raise ValueError("recorded build cost changed")


def freeze(args):
    if _git("status", "--porcelain=v1", "--untracked-files=no"):
        raise ValueError("freeze requires unchanged committed source")
    files = source_inventory()
    if set(files) - set(_git("ls-files").splitlines()):
        raise ValueError("all measurement sources must be committed before registration")
    binary, build = args.binary.resolve(strict=True), args.build.resolve(strict=True)
    observed = _build_observation(binary, build)
    case_rows = cases()
    protocol = {"schema": SCHEMA, "frozen_at_utc": datetime.now(timezone.utc).isoformat(),
        "source_head": _git("rev-parse", "HEAD"), "source_tree": _git("rev-parse", "HEAD^{tree}"),
        "source_files": files, "binary": str(binary), "binary_sha256": _sha(binary),
        "build_receipt": str(build), "build_receipt_sha256": _sha(build), "build_cost": observed,
        "fixed": definition(), "cases": case_rows, "schedule": schedule(case_rows)}
    validate_definition(protocol)
    args.output.mkdir(parents=True, exist_ok=False)
    registration = args.output / "REGISTRATION.json"
    _write(registration, protocol)
    print(json.dumps({"registration": str(registration), "sha256": _sha(registration),
        "planned_calls": 2976, "calls_per_arm": CALLS_PER_ARM,
        "build_wall_ns": observed["wall_ns"]}, indent=2))


def compare_decisions(responses):
    """Compare values, not just selected scores or Python's bool/int equality."""
    if set(responses) != set(ARMS):
        raise ValueError("a decision quartet requires every arm exactly once")
    values = {arm: {key: _canonical(responses[arm][key]) for key in DECISION_FIELDS} for arm in ARMS}
    pairs = [{"arms": [left, right], "fields_equal": {
        key: values[left][key] == values[right][key] for key in DECISION_FIELDS}}
        for left, right in combinations(ARMS, 2)]
    return {"all_equal": all(all(row["fields_equal"].values()) for row in pairs), "pairs": pairs,
        "field_sha256": {arm: {key: sha256(value.encode()).hexdigest() for key, value in fields.items()}
                          for arm, fields in values.items()}}


def _error(error):
    result = {"type": type(error).__name__, "message": str(error),
              "traceback": "".join(traceback.format_exception(type(error), error, error.__traceback__))}
    for name in ("stdout", "stderr", "output"):
        value = getattr(error, name, None)
        if value is not None:
            result[name] = ({"encoding": "base64", "data": base64.b64encode(value).decode()}
                            if isinstance(value, bytes) else {"encoding": "text", "data": str(value)})
    return result


def _session_observation(session):
    report = session.snapshot()
    process = session._process
    report["process_returncode"] = process.returncode if process is not None else None
    report["sealed_fd_released"] = session._fd is None
    report["pipes_closed"] = process is None or all(
        pipe is None or pipe.closed for pipe in (process.stdin, process.stdout, process.stderr))
    return report


def _run_schedule(protocol, record):
    """Internal fixed-schedule executor; CLI validates registration first."""
    calls, operations, quartets, errors = [], [], [], []
    active, pending = {}, {}
    models = {row["id"]: row["model"] for row in protocol["cases"]}
    binary, build = Path(protocol["binary"]), Path(protocol["build_receipt"])
    timeout = protocol["fixed"]["timeout_seconds"]
    write_record, log_ok = record, True

    def record(row):
        nonlocal log_ok
        if log_ok:
            try:
                write_record(row)
            except BaseException as error:
                log_ok = False
                errors.append({"event": "error", "phase": "original-record-write", "error": _error(error)})

    def failure(phase, error, **where):
        row = {"event": "error", "phase": phase, **where, "error": _error(error)}
        errors.append(row)
        record(row)

    def close(arm, reason):
        session, segment = active.pop(arm)
        record({"event": "close-start", "arm": arm, "segment": segment, "reason": reason})
        before = time.monotonic_ns()
        error = None
        try:
            session.close()
        except BaseException as caught:
            error = caught
        elapsed = time.monotonic_ns() - before
        row = {"event": "close-finish", "arm": arm, "segment": segment, "reason": reason,
               "outer_observed_ns": elapsed, "status": "success" if error is None else "failure"}
        try:
            row["session"] = _session_observation(session)
            observed = row["session"]
            if (observed["closed"] is not True or observed["process_returncode"] != 0
                    or observed["sealed_fd_released"] is not True or observed["pipes_closed"] is not True
                    or observed["cleanup_errors"]):
                raise ValueError("session did not close cleanly with a reaped successful child and released descriptors")
        except BaseException as caught:
            row["status"] = "failure"
            failure("close-observation", caught, arm=arm, segment=segment)
        operations.append(row)
        record(row)
        if error is not None:
            failure("close", error, arm=arm, segment=segment)
        return row["status"] == "success" and log_ok

    phase, current = "schedule", None
    try:
        for current in protocol["schedule"]:
            arm = current["arm"]
            if arm in SESSION_ARMS and arm not in active:
                phase = "startup"
                record({"event": "startup-start", "arm": arm, "segment": current["segment"]})
                if not log_ok:
                    break
                before = time.monotonic_ns()
                try:
                    session = RawModelSession(binary, build, timeout=timeout,
                                              image_check=protocol["fixed"]["image_check_profile"])
                except BaseException:
                    row = {"event": "startup-finish", "arm": arm, "segment": current["segment"],
                           "outer_observed_ns": time.monotonic_ns() - before, "status": "failure",
                           "raw_stream_status": "constructor did not return a session; runtime owns failure cleanup"}
                    operations.append(row)
                    record(row)
                    raise
                elapsed = time.monotonic_ns() - before
                active[arm] = session, current["segment"]
                row = {"event": "startup-finish", "arm": arm, "segment": current["segment"],
                       "outer_observed_ns": elapsed, "status": "success"}
                operations.append(row)
                row["session"] = _session_observation(session)
                row["hello_frame_base64"] = base64.b64encode(session._last_received_frame).decode()
                record(row)
                if not log_ok:
                    break
                if (row["session"]["binary_sha256"] != protocol["binary_sha256"]
                        or row["session"]["closed"] is not False or row["session"]["requests"] != 0):
                    raise ValueError("new session identity or initial state differs")
            phase = "call"
            record({"event": "call-start", **current})
            if not log_ok:
                break
            before = time.monotonic_ns()
            try:
                if arm in SESSION_ARMS:
                    response, receipt = active[arm][0].evaluate(models[current["case_id"]], mode=current["mode"])
                else:
                    response, receipt = invoke(binary, build, models[current["case_id"]],
                                               mode=current["mode"], timeout=timeout)
            except BaseException:
                row = {"event": "call-finish", **current, "status": "failure",
                       "outer_observed_ns": time.monotonic_ns() - before,
                       "raw_stream_status": "only returned exception/session data available; no fabricated native streams"}
                calls.append(row)
                record(row)
                raise
            elapsed = time.monotonic_ns() - before
            row = {"event": "call-finish", **current, "status": "success", "outer_observed_ns": elapsed,
                   "api_reported_ns": receipt.get("outer_wall_ns"), "native_measured": response.get("measured")}
            calls.append(row)
            record({**row, "original": receipt})
            if not log_ok:
                break
            phase = "call-receipt-admission"
            if (receipt.get("binary_sha256") != protocol["binary_sha256"]
                    or receipt.get("mode") != current["mode"]
                    or (arm in SESSION_ARMS and (type(receipt.get("sequence")) is not int
                                                or receipt["sequence"] != current["sequence"]))):
                raise ValueError("returned call receipt identity/sequence differs")
            key = current["round"], current["case_id"]
            group = pending.setdefault(key, {})
            if arm in group:
                raise ValueError("duplicate arm in a decision quartet")
            group[arm] = response
            if len(group) == len(ARMS):
                phase = "decision-equality"
                comparison = {"event": "decision-quartet", "round": key[0], "case_id": key[1],
                              **compare_decisions(group)}
                quartets.append(comparison)
                record(comparison)
                del pending[key]
                if not log_ok:
                    break
                if not comparison["all_equal"]:
                    raise ValueError("bundle, winners or selected first action differs across arms")
            if arm in SESSION_ARMS and (current["sequence"] == SESSION_LIMIT
                                        or current["arm_call_index"] + 1 == CALLS_PER_ARM):
                phase = "close"
                if not close(arm, "registered segment complete"):
                    break
    except BaseException as error:
        failure(phase, error, slot=current)
        if current is not None and current["arm"] in active:
            session = active[current["arm"]][0]
            # Preserve the last received frame even when the public API rejects
            # it. It may be the prior frame; never label it as this call's reply.
            frame = getattr(session, "_last_received_frame", None)
            if frame is not None:
                record({"event": "last-observed-session-frame", "arm": current["arm"],
                        "attribution": "last observed; not necessarily the failing request",
                        "base64": base64.b64encode(frame).decode()})
    finally:
        for arm in list(active):
            close(arm, "campaign finalization after stop or schedule end")
    return {"calls": calls, "operations": operations, "quartets": quartets, "errors": errors}


def _summary(values):
    return {"count": len(values), "sum_ns": sum(values),
        "mean_ns": statistics.mean(values) if values else None,
        "median_ns": statistics.median(values) if values else None,
        "p95_ns": _quantile(values, .95) if values else None,
        "p99_ns": _quantile(values, .99) if values else None,
        "maximum_ns": max(values) if values else None}


def analyze(protocol, observations, inputs_unchanged):
    calls, operations, quartets = (observations[key] for key in ("calls", "operations", "quartets"))
    expected = protocol["schedule"]
    exact_schedule = (len(calls) == len(expected) and all(
        _canonical({key: row.get(key) for key in slot}) == _canonical(slot)
        for row, slot in zip(calls, expected)))
    equal = (len(quartets) == CALLS_PER_ARM and all(row["all_equal"] for row in quartets))
    complete = (inputs_unchanged and exact_schedule and equal and not observations["errors"]
                and all(row["status"] == "success" for row in calls + operations))
    for arm in SESSION_ARMS:
        for event in ("startup-finish", "close-finish"):
            segments = [row["segment"] for row in operations if row["arm"] == arm and row["event"] == event]
            complete = complete and segments == [0, 1, 2]
    totals = {}
    for arm in ARMS:
        selected = [row for row in calls if row["arm"] == arm]
        startup = [row["outer_observed_ns"] for row in operations
                   if row["arm"] == arm and row["event"] == "startup-finish"]
        closing = [row["outer_observed_ns"] for row in operations
                   if row["arm"] == arm and row["event"] == "close-finish"]
        call = _summary([row["outer_observed_ns"] for row in selected])
        observed = sum(startup) + call["sum_ns"] + sum(closing)
        totals[arm] = {"call": call, "startup": _summary(startup), "close": _summary(closing),
            "successful_calls": sum(row["status"] == "success" for row in selected),
            "unattempted_calls": CALLS_PER_ARM - len(selected), "observed_partial_service_ns": observed,
            "standalone_service_ns": observed if complete else None,
            "amortized_service_per_call_ns": observed / CALLS_PER_ARM if complete else None,
            "startup_close_already_in_call": arm not in SESSION_ARMS}
    build = protocol["build_cost"]["wall_ns"]
    amortization = {"common_build_wall_ns": build,
        "rule": "each standalone arm charged the same entire B once, not B/4; per-call B/744",
        "standalone_build_plus_service_ns": {}, "amortized_build_plus_service_per_call_ns": {}}
    for arm in ARMS:
        value = build + totals[arm]["standalone_service_ns"] if build is not None and complete else None
        amortization["standalone_build_plus_service_ns"][arm] = value
        amortization["amortized_build_plus_service_per_call_ns"][arm] = value / CALLS_PER_ARM if value is not None else None
    ratios = []
    for numerator, denominator in (("session_exact_dp", "one_shot_exact_dp"),
            ("session_ndu", "one_shot_ndu"), ("one_shot_ndu", "one_shot_exact_dp"),
            ("session_ndu", "session_exact_dp")):
        ratio = None
        if complete and totals[denominator]["standalone_service_ns"] > 0:
            ratio = totals[numerator]["standalone_service_ns"] / totals[denominator]["standalone_service_ns"]
        ratios.append({"numerator": numerator, "denominator": denominator, "service_cost_ratio": ratio})
    return {"measurement_complete": bool(complete), "inputs_unchanged": inputs_unchanged,
        "planned_calls": 2976, "attempted_calls": len(calls), "unattempted_calls": 2976 - len(calls),
        "successful_calls": sum(row["status"] == "success" for row in calls),
        "failed_calls": sum(row["status"] != "success" for row in calls), "error_count": len(observations["errors"]),
        "completed_quartets": len(quartets), "all_decisions_and_witnesses_equal": equal,
        "additional_ndu_decision_quality_observed": False if complete else None,
        "arms": totals, "amortization": amortization, "descriptive_comparisons": ratios,
        "full_application_lifecycle_advantage_established": False, "machine_cold_claim": False,
        "statistical_scope": "one fixed 31-round service campaign; descriptive only, no population or independent-host claim"}


def execute(args):
    started = time.monotonic_ns()
    registration = args.output / "REGISTRATION.json"
    original = args.output / "ORIGINAL.jsonl"
    records = 0
    observations = {"calls": [], "operations": [], "quartets": [], "errors": []}
    protocol, registration_hash, unchanged, admitted = None, None, False, False
    for name in ("ORIGINAL.jsonl", "ORIGINAL.jsonl.gz", "ERRORS.json", "RESULT.json"):
        if (args.output / name).exists():
            raise ValueError("measurement outputs already exist; a registered campaign cannot be replayed")
    with original.open("x", encoding="utf-8") as log:
        def record(row):
            nonlocal records
            log.write(_canonical(row) + "\n")
            log.flush()
            records += 1

        try:
            raw_registration = registration.read_bytes()
            registration_hash = sha256(raw_registration).hexdigest()
            protocol = _read_json(raw_registration)
            record({"event": "campaign-start", "registration_sha256": registration_hash})
            _validate_inputs(protocol, registration, registration_hash)
            admitted = True
            observations = _run_schedule(protocol, record)
            _validate_inputs(protocol, registration, registration_hash)
            unchanged = True
        except BaseException as error:
            row = {"event": "error", "phase": "campaign-input-admission-or-final-check", "error": _error(error)}
            observations["errors"].append(row)
            record(row)
        record({"event": "campaign-finish", "inputs_unchanged": unchanged,
                "attempted_calls": len(observations["calls"]), "error_count": len(observations["errors"])})
    result = {"measurement_complete": False, "planned_calls": 2976, "attempted_calls": 0,
              "unattempted_calls": 2976,
              "error_count": len(observations["errors"]), "inputs_unchanged": False}
    if admitted:
        result = analyze(protocol, observations, unchanged)
    _write(args.output / "ERRORS.json", observations["errors"])
    archive = args.output / "ORIGINAL.jsonl.gz"
    with original.open("rb") as source, archive.open("xb") as destination:
        with gzip.GzipFile(filename="", mode="wb", fileobj=destination, mtime=0) as compressed:
            shutil.copyfileobj(source, compressed)
    result.update({"schema": SCHEMA, "registration_sha256": registration_hash,
        "source_head": protocol.get("source_head") if protocol else None,
        "binary_sha256": protocol.get("binary_sha256") if protocol else None,
        "build_cost": protocol.get("build_cost") if protocol else None,
        "original_records": {"file": original.name, "bytes": original.stat().st_size,
            "sha256": _sha(original), "gzip_file": archive.name, "gzip_sha256": _sha(archive), "record_count": records},
        "campaign_wall_before_final_report_ns": time.monotonic_ns() - started,
        "campaign_scope": "admission, measured service operations, caller audit/logging, analysis and compression; excludes imports/build/final report write",
        "full_application_lifecycle_advantage_established": False, "machine_cold_claim": False,
        "authority": "DENY_ALL", "safety_certificate": False, "production_activation_allowed": False})
    _write(args.output / "RESULT.json", result)
    print(json.dumps({key: result[key] for key in ("measurement_complete", "attempted_calls", "error_count")}, indent=2))
    if not result["measurement_complete"]:
        raise SystemExit(1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    registration = sub.add_parser("freeze")
    registration.add_argument("--binary", type=Path, required=True)
    registration.add_argument("--build", type=Path, required=True)
    registration.add_argument("--output", type=Path, required=True)
    run = sub.add_parser("run")
    run.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    freeze(args) if args.command == "freeze" else execute(args)


if __name__ == "__main__":
    main()
