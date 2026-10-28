"""Strict local replay of the fixed native lifecycle evidence protocol.

This checks retained observations, never substitutes a pass flag for them.
It is not an attestation of a malicious evaluator, OS or compiler.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import re
import stat

from hepta.hia_program import verify_program
from hepta.hia_program_tools import read_bounded
from hepta.hia_ndu import make_plan, prepare_candidate


def need(condition, message):
    if condition is not True:
        raise ValueError("E_NATIVE_RUNTIME_SOAK_EVIDENCE: " + message)


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def same(left, right):
    return wire(left) == wire(right)


def hashed(raw):
    return sha256(raw).hexdigest()


def integer(value, minimum=0, maximum=2**63 - 1):
    return type(value) is int and minimum <= value <= maximum


def number(value):
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def identity(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def strict_json(raw):
    def pairs(values):
        result = {}
        for key, value in values:
            need(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    def constant(value):
        raise ValueError("E_NATIVE_RUNTIME_SOAK_EVIDENCE: nonfinite JSON constant " + value)
    result = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    # Also reject overflowing numeric literals such as 1e999.
    wire(result)
    return result


def validate_registration(value):
    from tools import soak_hia_native_runtime as protocol
    need(type(value) is dict and set(value) == {"schema", "created_utc", "profile", "profile_sha256",
         "source", "tools", "fixture_sha256", "host", "claims"}, "registration shape differs")
    need(value["schema"] == "hepta.hia.native-runtime-soak-registration.v1", "registration schema differs")
    selected = value["profile"]
    need(type(selected) is dict and same(selected, protocol.profile(selected.get("profile_id"))),
         "registered budget/protocol differs from the fixed profile")
    need(value["profile_sha256"] == hashed(wire(selected)) and same(value["claims"], protocol.CLAIMS),
         "profile identity or evidence scope differs")
    need(type(value["created_utc"]) is str and datetime.fromisoformat(value["created_utc"]).utcoffset() is not None,
         "registration timestamp requires a timezone")
    source = value["source"]
    need(type(source) is dict and set(source) == {"git_commit", "git_status", "snapshot"}
         and type(source["git_commit"]) is str and re.fullmatch(r"[0-9a-f]{40}", source["git_commit"]) is not None
         and type(source["git_status"]) is str, "source binding missing")
    snapshot = source["snapshot"]
    need(type(snapshot) is dict and set(snapshot) == {"files", "sha256"}
         and type(snapshot["files"]) is dict and 0 < len(snapshot["files"]) <= 65536,
         "source snapshot shape differs")
    for path, digest in snapshot["files"].items():
        need(type(path) is str and path and not Path(path).is_absolute() and ".." not in Path(path).parts
             and identity(digest), "source snapshot entry differs")
    need(snapshot["sha256"] == hashed(wire(snapshot["files"]))
         and snapshot["files"].get("examples/hia_native_lifecycle/swap.json") == value["fixture_sha256"],
         "snapshot or fixture identity differs")
    need(not selected["formal_qualification"] or source["git_status"] == "", "formal registration source was dirty")
    tools = value["tools"]
    need(type(tools) is dict and set(tools) == {"clang", "python", "rustc_used"}
         and tools["rustc_used"] is False, "tool identity shape differs")
    for name in ("clang", "python"):
        tool = tools[name]
        need(type(tool) is dict and set(tool) == ({"path", "sha256", "version", "target"} if name == "clang" else
             {"path", "sha256", "version"}) and type(tool["path"]) is str and Path(tool["path"]).is_absolute()
             and identity(tool["sha256"]) and type(tool["version"]) is str and 0 < len(tool["version"]) <= 4096,
             "tool identity incomplete")
    need("clang version 20." in tools["clang"]["version"] and tools["clang"]["target"] in
         {"x86_64-unknown-linux-gnu", "x86_64-pc-linux-gnu"}, "unsupported registered compiler")
    host = value["host"]
    need(type(host) is dict and set(host) == {"system", "machine", "kernel", "cpu_count"}
         and host["system"] == "Linux" and type(host["machine"]) is str and host["machine"].lower() in {"x86_64", "amd64"}
         and type(host["kernel"]) is str and bool(host["kernel"])
         and (host["cpu_count"] is None or integer(host["cpu_count"], 1)), "registered host differs")
    return selected


def epoch_plan(epoch, selected):
    calls = []
    events = []
    def event(kind, key=None):
        events.append((kind, key))
    def call(name, args, outcome, version, generation):
        offset = len(calls)
        spec = {"case": name, "arguments": args, "expected": outcome,
                "version_role": version, "generation": generation,
                "attempt_id": epoch * selected["calls_per_epoch"] + offset + 1}
        calls.append(spec)
        event("attempt", offset)
        if outcome != "trap_before_loan":
            event("loan_held", offset)
        return offset
    def pair(prefix, length, version="candidate", generation=1):
        event("pacing")
        return [call(prefix + "-" + str(i), [length, 0, 4, 0], "return", version, generation) for i in range(2)]
    for operation, result in (("baseline_build", "baseline_build"), ("candidate_cancellation", "cancel_attempt"),
                              ("candidate_stage", "candidate_build")):
        event("build_attempt", operation)
        event(result)
    event("staged_image")
    event("pacing")
    old = call("baseline-across-activation", [5, 0, 4, 0], "return", "baseline", 0)
    event("activation")
    current = call("candidate-after-activation", [5, 0, 4, 0], "return", "candidate", 1)
    event("terminal_observation", current)
    event("terminal_observation", old)
    for number_ in range(selected["middle_pairs_per_epoch"]):
        length = selected["buffer_sizes"][(epoch + number_) % len(selected["buffer_sizes"])]
        for offset in pair("steady-" + str(number_), length):
            event("terminal_observation", offset)
    offsets = pair("candidate-across-rollback", 5)
    event("rollback")
    for offset in offsets:
        event("terminal_observation", offset)
    for name, args, outcome in (("trap-in-loan", [5, 5, 0, 0], "trap_in_loan"),
            ("trap-before-loan", [2**32 - 1, 0, 4, 0], "trap_before_loan"),
            ("withheld-ack", [5, 0, 4, 0], "timeout")):
        event("terminal_observation", call(name, args, outcome, "baseline", 2))
    offsets = pair("baseline-across-close", 5, "baseline", 2)
    event("close_while_held")
    for offset in offsets:
        event("terminal_observation", offset)
    event("epoch_cleanup")
    for offset in range(len(calls)):
        event("sample", offset)
    event("drained_resources")
    need(len(calls) == selected["calls_per_epoch"], "internal fixed epoch denominator differs")
    return calls, events


def resource_sample(value, pid=None, *, required=False):
    need(type(value) is dict and type(value.get("available")) is bool and integer(value.get("pid"), 1),
         "resource sample shape differs")
    need(pid is None or value["pid"] == pid, "resource sample PID differs from its child")
    if value["available"]:
        need(set(value) == {"available", "pid", "starttime_ticks", "fd_count", "rss_kib", "vm_hwm_kib", "threads"}
             and all(integer(value[key], 1 if key in {"pid", "starttime_ticks", "threads"} else 0)
                     for key in ("pid", "starttime_ticks", "fd_count", "rss_kib", "vm_hwm_kib", "threads")),
             "resource sample numeric fields differ")
    else:
        need(not required and set(value) == {"available", "pid", "reason", "message"}
             and type(value["reason"]) is str and type(value["message"]) is str, "required resource sample unavailable")


def observation(value, spec, images, *, held=False):
    need(type(value) is dict and value.get("schema") == "hepta.hia.native-loan-observation.v2", "loan schema differs")
    need(value["program_sha256"] == images[spec["version_role"]][0]
         and value["artifact_sha256"] == images[spec["version_role"]][1]
         and integer(value["generation"]) and value["generation"] == spec["generation"], "captured native version differs")
    outcome = spec["expected"]
    length = spec["arguments"][0]
    events = [] if outcome == "trap_before_loan" else [{"event": "loan_started", "bytes": length,
        "first_byte": 0, "last_byte": 0, "selected_loan_active": True}]
    if not held and outcome == "return":
        events.append({"event": "loan_ended", "bytes": length, "first_byte": 55,
                       "last_byte": 11 if length == 5 else 0, "selected_loan_active": False})
    need(same(value["events"], events), "actual loan events/endpoints differ from the fixed case")
    need(value["done"] is (not held) and value["held"] is held and value["quarantined"] is False
         and value["ack_sent"] is (not held and outcome in {"return", "trap_in_loan"}), "loan terminal/ACK state differs")
    process = value["child_process"]
    entered = outcome != "trap_before_loan"
    need(type(process) is dict and integer(process.get("pid"), 1) and process["creation_attempted"] is True
         and process["spawn_observed"] is True and type(process["known_child_processes_started"]) is int
         and process["known_child_processes_started"] == 1 and process["child_start_count_complete"] is True
         and process["native_entry_observed"] is entered and process["native_entry_outcome_available"] is entered,
         "child start/entry observation differs")
    cleanup = process["cleanup"]
    need(type(cleanup) is dict and cleanup.get("schema") == "hepta.hia.native-child-cleanup.v1"
         and integer(cleanup.get("pid"), 1) and cleanup["pid"] == process["pid"]
         and cleanup["cleanup_confirmed"] is (not held) and cleanup["quarantined"] is False
         and cleanup["status"] == ("active" if held else "reaped")
         and integer(cleanup["reap_attempts"]) and (cleanup["reap_attempts"] == 0 if held else cleanup["reap_attempts"] >= 1)
         and cleanup["claims"]["direct_child_reaped"] is (not held)
         and cleanup["claims"]["uninterruptible_kernel_wait_preempted"] is False,
         "child cleanup identity/confirmation differs")
    expected_rc = None if held else 0 if outcome == "return" else -9 if outcome == "timeout" else -6
    need(same(cleanup["returncode"], expected_rc) and cleanup["last_error"] is None and cleanup["secondary_errors"] == []
         and cleanup["group_signal_attempted"] is (not held)
         and type(cleanup["group_signal_delivered"]) is bool, "child cleanup result differs")
    if held or outcome != "timeout":
        need(value["error"] is None, "unexpected native observation error")
    else:
        need(type(value["error"]) is dict and value["error"].get("type") == "HIADifferentialRejected"
             and "timed out" in value["error"].get("message", ""), "timeout observation is unavailable")
    return process["pid"]


def validate(output, *, require_hosted=True):
    from tools import soak_hia_native_runtime as protocol
    output = Path(output)
    report_raw = read_bounded(output / "report.json", protocol._COMMON["report_reserve_bytes"] // 2)
    report = strict_json(report_raw)
    need(type(report) is dict and set(report) == {"schema", "status", "ok", "execution_passed", "claims", "profile",
         "registration_sha256", "started_utc", "source_git_commit", "source_was_committed", "host", "completed_epochs",
         "stop_reason", "failure", "drained", "counts", "resources", "timing", "registration_object", "fixture_object",
         "programs", "progress_wall_ns", "case_counts", "cancelled_build_publications", "journal", "source_unchanged",
         "tools_unchanged", "total_wall_ns", "finished_utc"}, "complete report shape differs")
    need(report.get("schema") == "hepta.hia.native-runtime-soak.v2", "run anchors require the v2 receipt")
    selected = protocol.profile(report["profile"]["profile_id"])
    need(same(report["profile"], selected) and same(report["claims"], protocol.CLAIMS), "profile or claims differ")
    checked = {}
    object_total = 0
    def object_(reference, suffix):
        nonlocal object_total
        need(type(reference) is dict and set(reference) == {"path", "sha256", "bytes"}
             and identity(reference["sha256"]) and integer(reference["bytes"], 1, 8 * 1024 * 1024)
             and reference["path"] == "objects/" + reference["sha256"] + suffix, "object reference differs")
        if reference["path"] not in checked:
            raw = read_bounded(output / reference["path"], 8 * 1024 * 1024)
            need(len(raw) == reference["bytes"] and hashed(raw) == reference["sha256"], "retained artifact/object identity differs")
            object_total += len(raw)
            need(object_total <= selected["max_evidence_bytes"] - selected["report_reserve_bytes"], "unique object budget exceeded")
            checked[reference["path"]] = raw
        raw = checked[reference["path"]]
        need(len(raw) == reference["bytes"], "object extent differs")
        return raw
    registration_raw = object_(report["registration_object"], ".registration.json")
    registered = strict_json(registration_raw)
    need(registration_raw == wire(registered) and hashed(registration_raw) == report["registration_sha256"]
         and same(validate_registration(registered), selected), "registration identity differs")
    need(report["source_git_commit"] == registered["source"]["git_commit"]
         and report["source_was_committed"] is (registered["source"]["git_status"] == "")
         and same(report["host"], registered["host"]), "report source/host binding differs")
    need(report["execution_passed"] is True and report["drained"] is True and report["source_unchanged"] is True
         and report["tools_unchanged"] is True and report["failure"] is None and "evidence_write_error" not in report,
         "run did not complete its controls")
    need(report["ok"] is selected["formal_qualification"] and report["status"] ==
         ("passed" if selected["formal_qualification"] else "development_complete"), "qualification status differs")
    need(not require_hosted or report["ok"] is True and report["source_was_committed"] is True,
         "development evidence cannot qualify the hosted profile")
    fixture = object_(report["fixture_object"], ".fixture.json")
    need(hashed(fixture) == registered["fixture_sha256"], "registered fixture bytes differ")
    baseline = verify_program(fixture)
    prepared = prepare_candidate(baseline, make_plan(baseline, entry="native_swap"))
    need(set(report["programs"]) == {"baseline", "candidate"} and prepared.replacements == 1,
         "program roles or exact rewrite differ")
    cores = {}
    for role, expected in (("baseline", baseline), ("candidate", prepared.candidate)):
        raw = object_(report["programs"][role], ".core.json")
        core = verify_program(raw)
        need(raw == core.canonical_bytes == expected.canonical_bytes, "Core is not the verified fixture or exact candidate")
        cores[role] = core.sha256
    need(integer(report["completed_epochs"], 1, selected["max_epochs"]), "completed epoch denominator differs")
    epochs = report["completed_epochs"]
    expected_events = [("run_start", None, None)]
    specifications = {}
    for epoch in range(epochs):
        calls, events = epoch_plan(epoch, selected)
        specifications[epoch] = calls
        expected_events.extend((kind, epoch, key) for kind, key in events)
    expected_events.append(("run_end", None, None))
    need(len(expected_events) <= 100000, "event inventory exceeds bounded replay")
    chain, sequence, journal_bytes, last_clock = "0" * 64, 0, 0, -1
    counts, cases = Counter({key: 0 for key in protocol.COUNT_KEYS}), Counter()
    times, pacing, builds, cancelled = [], 0, 0, 0
    images, attempts, held, terminal = {}, {}, {}, {}
    drained, children = [], []
    start = end = None
    build_start = last_drained_clock = None
    live_pids = {}
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    with os.fdopen(os.open(output / "events.jsonl", flags), "rb") as stream:
        info = os.fstat(stream.fileno())
        need(stat.S_ISREG(info.st_mode) and info.st_size <= selected["max_evidence_bytes"], "journal is not bounded regular data")
        while True:
            raw = stream.readline(1024 * 1024 + 1)
            if not raw:
                break
            journal_bytes += len(raw)
            need(len(raw) <= 1024 * 1024 and object_total + journal_bytes <=
                 selected["max_evidence_bytes"] - selected["report_reserve_bytes"], "aggregate evidence budget exceeded")
            row = strict_json(raw)
            need(type(row) is dict and set(row) == {"sequence", "previous_sha256", "kind", "value"}
                 and raw == wire(row) + b"\n" and integer(row["sequence"]) and row["sequence"] == sequence
                 and row["previous_sha256"] == chain and sequence < len(expected_events), "journal sequence/extent differs")
            kind, epoch, key = expected_events[sequence]
            need(row["kind"] == kind, "fixed epoch schedule differs")
            value = row["value"]
            need(type(value) is dict and integer(value.get("elapsed_ns")) and value["elapsed_ns"] >= last_clock
                 and integer(value.get("epoch")) and (epoch is None or value["epoch"] == epoch), "journal clock/epoch differs")
            previous_clock = last_clock
            last_clock, chain, sequence = value["elapsed_ns"], hashed(raw), sequence + 1
            if kind in {"run_start", "run_end"}:
                resource_sample(value["parent"], required=True)
                need(number(value["cpu_user_seconds"]) and number(value["cpu_system_seconds"]), "CPU anchor differs")
                if kind == "run_start":
                    start = value
                else:
                    end = value
                continue
            if kind == "build_attempt":
                build_start = value["elapsed_ns"]
                need(value["operation"] == key and value["program_sha256"] == cores["baseline" if key == "baseline_build" else "candidate"],
                     "build attempt identity differs")
                if key == "baseline_build":
                    need(value["elapsed_ns"] < selected["new_epoch_deadline_seconds"] * 1e9, "epoch admitted after deadline")
                    images = {}
            if kind in {"baseline_build", "staged_image"}:
                role = "baseline" if kind == "baseline_build" else "candidate"
                image = value["image"]
                artifact = object_(image["artifact"], ".so")
                receipt = strict_json(object_(image["build_receipt"], ".build.json"))
                need(image["program_sha256"] == receipt["core_sha256"] == cores[role]
                     and receipt["artifact_sha256"] == hashed(artifact) and receipt["artifact_bytes"] == len(artifact)
                     and receipt["toolchain"]["sha256"] == registered["tools"]["clang"]["sha256"]
                     and receipt["llvm_ir_sha256"] == hashed(receipt["llvm_ir"].encode())
                     and receipt["ok"] is True, "actual image/build binding differs")
                images[role] = (cores[role], hashed(artifact))
            if kind in {"baseline_build", "candidate_build", "cancel_attempt"}:
                duration = value["build_control_wall_ns"] if kind == "cancel_attempt" else value["build_wall_ns"]
                need(integer(duration) and build_start is not None
                     and duration <= value["elapsed_ns"] - build_start, "build interval exceeds its actual event window")
                builds += duration
            if kind in {"cancel_attempt", "candidate_build"}:
                done = value["finished"]
                need(done["baseline_sha256"] == cores["baseline"] and done["candidate_sha256"] == cores["candidate"]
                     and done["plan_sha256"] == prepared.plan_sha256 and done["pass_id"] == prepared.plan["pass_id"],
                     "build transformation relationship differs")
                if "native_receipt_object" in done:
                    receipt = strict_json(object_(done["native_receipt_object"], ".build.json"))
                    need(receipt["core_sha256"] == cores["candidate"] and receipt["artifact_sha256"] == done["artifact_sha256"],
                         "cancelled/staged build receipt differs")
                if kind == "candidate_build":
                    need(done["status"] == "staged" and done["published"] is True, "candidate was not staged")
                else:
                    cancel = value["cancel"]
                    need(cancel["job_id"] == done["job_id"] == value["submitted"]["job_id"], "cancel job identity differs")
                    need(done["status"] in {"cancelled", "staged"}, "cancel attempt never reached a terminal state")
                    if done["status"] == "cancelled":
                        need(done["published"] is False and cancel["cancel_requested"] is True, "cancelled build was published")
                        cancelled += 1
                    else:
                        need(cancel["changed"] is False, "accepted cancellation published its candidate")
                    need(value["dispatch"]["active_sha256"] == cores["baseline"] and value["dispatch"]["in_flight"] == 0,
                         "cancellation changed active work")
            if kind == "pacing":
                need(integer(value["wait_ns"]) and value["wait_ns"] <= value["elapsed_ns"] - previous_clock
                     and value["kind"] == "offered_load_spacing_not_native_work", "pacing measurement differs")
                pacing += value["wait_ns"]
            if kind in {"activation", "rollback"}:
                new, old, generation = ("candidate", "baseline", 1) if kind == "activation" else ("baseline", "candidate", 2)
                need(value["active_sha256"] == cores[new] and value["previous_sha256"] == cores[old]
                     and integer(value["generation"]) and value["generation"] == generation
                     and value["changed"] is True and value["future_calls_only"] is True
                     and value["external_state_migrated"] is False and value["in_process_native_hot_patch"] is False,
                     "version transition differs")
            if kind == "close_while_held":
                need(value["drained"] is False and value["status"] == "closing" and value["new_admission_disabled"] is True,
                     "close discarded held work")
            if kind == "epoch_cleanup":
                close, dispatch = value["close"], value["dispatch"]
                need(close["drained"] is True and close["status"] == "closed" and dispatch["drained"] is True
                     and integer(dispatch["in_flight"]) and integer(dispatch["unconfirmed_child_reaps"])
                     and dispatch["in_flight"] == dispatch["unconfirmed_child_reaps"] == 0
                     and dispatch["versions"] == dispatch["quarantined_calls"] == []
                     and dispatch["background_build_active"] is False, "epoch did not actually drain")
            if kind == "drained_resources":
                resource_sample(value["parent"], start["parent"]["pid"], required=True)
                parent = value["parent"]
                need(parent["starttime_ticks"] == start["parent"]["starttime_ticks"]
                     and parent["rss_kib"] <= selected["max_parent_rss_kib"]
                     and parent["fd_count"] - start["parent"]["fd_count"] <= selected["max_drained_parent_fd_growth"],
                     "parent resource threshold or identity differs")
                drained.append(parent)
                last_drained_clock = value["elapsed_ns"]
            if kind not in {"attempt", "loan_held", "terminal_observation", "sample"}:
                continue
            spec = specifications[epoch][key]
            aid = spec["attempt_id"]
            need(integer(value.get("attempt_id"), 1) and value["attempt_id"] == aid, "fixed call identity differs")
            if kind in {"attempt", "sample"}:
                need(value["entry"] == "native_swap" and same(value["arguments"], spec["arguments"])
                     and value["case"] == spec["case"] and value["expected"] == spec["expected"]
                     and value["admission_version"] == cores[spec["version_role"]]
                     and integer(value["start_ns"]) and value["start_ns"] <= value["elapsed_ns"], "fixed call input/role differs")
            if kind == "attempt":
                need(value["dispatcher_admission_attempted"] is False and aid not in attempts, "attempt order differs")
                attempts[aid] = value
            elif kind == "loan_held":
                pid = observation(value["observation"], spec, images, held=True)
                need(pid != start["parent"]["pid"] and pid not in live_pids,
                     "simultaneously held calls must own distinct child PIDs")
                live_pids[pid] = aid
                held[aid] = value
            elif kind == "terminal_observation":
                need(value["control_passed"] is True and value["error"] is None, "terminal control failed")
                if aid in held:
                    pid = held[aid]["observation"]["child_process"]["pid"]
                    need(live_pids.pop(pid, None) == aid, "live child PID ownership differs")
                terminal[aid] = value
            else:
                need(value["control_passed"] is True and value["dispatcher_admission_attempted"] is True
                     and value["start_ns"] == attempts[aid]["start_ns"]
                     and integer(value["observed_ns"]) and integer(value["finalized_ns"])
                     and value["start_ns"] <= value["observed_ns"] <= terminal[aid]["elapsed_ns"] <= value["finalized_ns"] <= value["elapsed_ns"]
                     and integer(value["admission_to_observation_ns"])
                     and value["admission_to_observation_ns"] == value["observed_ns"] - value["start_ns"], "sample time/control association differs")
                final = value["final_observation"]
                pid = observation(final, spec, images)
                need(pid != start["parent"]["pid"], "native child cannot be its parent process")
                outcome = spec["expected"]
                if outcome != "trap_before_loan":
                    need(pid == held[aid]["observation"]["child_process"]["pid"]
                         and value["held_program_sha256"] == final["program_sha256"]
                         and value["held_artifact_sha256"] == final["artifact_sha256"]
                         and integer(value["loan_observed_ns"]) and value["start_ns"] <= value["loan_observed_ns"] <= held[aid]["elapsed_ns"],
                         "held/final native child or image differs")
                    resource_sample(value["child_resource_sample"], pid)
                    children.append(value["child_resource_sample"])
                else:
                    need("child_resource_sample" not in value and aid not in held, "pre-loan trap invented an observation")
                    children.append(None)
                if outcome in {"return", "trap_in_loan"}:
                    need(integer(value["resumed_ns"]) and value["loan_observed_ns"] <= value["resumed_ns"] <= value["observed_ns"], "ACK timestamp differs")
                else:
                    need("resumed_ns" not in value, "unexpected ACK")
                if outcome == "timeout":
                    rejection = value["expected_rejection"]
                    detail = {"type": rejection["type"], "message": rejection["message"]}
                    need(same(detail, final["error"]) and rejection["identity"] == hashed(wire(detail))
                         and "result" not in value, "timeout evidence differs")
                else:
                    result = value["result"]
                    need(result["schema"] == "hepta.hia.native-loan-execution.v2"
                         and result["program_sha256"] == final["program_sha256"] and result["artifact_sha256"] == final["artifact_sha256"]
                         and same(result["generation"], spec["generation"])
                         and result["status"] == ("returned" if outcome == "return" else "trapped")
                         and result["native_observation"] == ("value" if outcome == "return" else "trap")
                         and same(result["value"], 55 if outcome == "return" else None), "actual native result differs from fixed case")
                observed = protocol._execution_counts([value])
                counts.update({name: observed[name] for name in protocol.COUNT_KEYS})
                cases[outcome] += 1
                times.append(value["admission_to_observation_ns"])
    need(set(report["journal"]) == {"path", "records", "last_sha256", "retained_bytes_excluding_report"}
         and integer(report["journal"]["records"]) and sequence == len(expected_events) and end is not None
         and sequence == report["journal"]["records"]
         and chain == report["journal"]["last_sha256"], "retained journal/sample extent differs")
    need(report["journal"]["path"] == "events.jsonl" and integer(report["journal"]["retained_bytes_excluding_report"])
         and report["journal"]["retained_bytes_excluding_report"] == object_total + journal_bytes,
         "retained byte summary differs from actual unique objects and journal")
    # Refuse unreferenced or special objects; account all producer-owned files.
    inventory = set()
    disk_bytes = 0
    for path in output.rglob("*"):
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            need(path == output / "objects", "unexpected evidence directory")
            continue
        need(stat.S_ISREG(info.st_mode), "special evidence file refused")
        inventory.add(str(path.relative_to(output)))
        disk_bytes += info.st_size
    need(inventory == set(checked) | {"report.json", "events.jsonl"}
         and disk_bytes == object_total + journal_bytes + len(report_raw)
         and disk_bytes + len(report_raw) <= selected["max_evidence_bytes"], "aggregate retained evidence budget/inventory differs")
    expected_counts = dict(counts)
    expected_counts.update(child_process_start_count_complete=counts["unavailable_child_start_outcomes"] == 0,
        native_entry_invocations=None if counts["unavailable_native_entry_outcomes"] else counts["native_entries_observed"])
    need(same(report["counts"], expected_counts), "report counters/derived unknown outcomes differ from retained samples")
    need(same(report["case_counts"], dict(cases)) and same(dict(cases), {"return": 30 * epochs,
         "trap_in_loan": epochs, "trap_before_loan": epochs, "timeout": epochs})
         and integer(report["cancelled_build_publications"], 1) and report["cancelled_build_publications"] == cancelled,
         "case or cancellation denominator differs")
    need(integer(end["completed_epochs"]) and end["completed_epochs"] == epochs
         and start["epoch"] == 0 and end["epoch"] == epochs - 1 and end["stop_reason"] == report["stop_reason"]
         and end["source_unchanged"] is True and end["tools_unchanged"] is True, "final run anchor differs")
    elapsed = end["observation_wall_ns"]
    need(not live_pids and last_drained_clock is not None and integer(report["progress_wall_ns"])
         and last_drained_clock <= report["progress_wall_ns"] and integer(elapsed, 1)
         and elapsed <= end["elapsed_ns"] and elapsed >= report["progress_wall_ns"]
         and integer(report["total_wall_ns"]) and report["total_wall_ns"] == end["elapsed_ns"]
         and report["total_wall_ns"] <= selected["max_wall_seconds"] * 1e9, "observation/total clock anchor differs")
    need(report["stop_reason"] in {"max_epochs", "new_epoch_deadline"}
         and (epochs == selected["max_epochs"] if report["stop_reason"] == "max_epochs" else
              elapsed >= selected["new_epoch_deadline_seconds"] * 1e9), "stop reason differs from actual budget state")
    cpu = (end["cpu_user_seconds"] + end["cpu_system_seconds"]) - (start["cpu_user_seconds"] + start["cpu_system_seconds"])
    need(number(cpu) and end["parent"]["pid"] == start["parent"]["pid"]
         and end["parent"]["starttime_ticks"] == start["parent"]["starttime_ticks"], "parent CPU/process identity differs")
    expected_timing = {"observation_wall_ns": elapsed, "explicit_pacing_wait_ns": pacing,
        "nonpacing_controller_wall_ns": elapsed - pacing, "parent_cpu_seconds": cpu,
        "actual_call_observation_wall_sum_ns": sum(times), "observed_build_control_wall_sum_ns": builds,
        "admission_to_host_observation": protocol.latencies(times),
        "completed_observations_per_wall_second": counts["completed_observations"] / (elapsed / 1e9),
        "call_intervals_overlap": True, "includes_process_startup_diagnostic_wait_and_cleanup": True,
        "network_or_service_latency": False, "outer_process_wall_including_recovery_requires_supervisor_record": True}
    need(same(report["timing"], expected_timing), "timing summaries differ from retained anchors/intervals")
    available = [child for child in children if child is not None and child["available"]]
    expected_resources = {"parent_before": start["parent"], "parent_after": end["parent"],
        "last_drained_parent": drained[-1], "available_child_samples": len(available),
        "unavailable_or_unrequested_child_samples": len(children) - len(available),
        "largest_observed_drained_parent_rss_kib": max(parent["rss_kib"] for parent in drained),
        "largest_observed_drained_parent_fd_count": max(parent["fd_count"] for parent in drained)}
    if available:
        expected_resources.update(largest_observed_child_rss_kib=max(child["rss_kib"] for child in available),
            largest_observed_child_fd_count=max(child["fd_count"] for child in available))
    else:
        expected_resources.pop("available_child_samples")
    need(same(report["resources"], expected_resources), "resource summaries differ from retained samples")
    need(protocol.workload_complete(selected, counts, epochs, elapsed, pacing), "actual duration/work/pacing below fixed minimum")
    return {"validated": True, "profile_id": selected["profile_id"], "samples": len(times),
            "hosted_qualification": selected["formal_qualification"], "journal_last_sha256": chain,
            "actual_retained_bytes": disk_bytes}
