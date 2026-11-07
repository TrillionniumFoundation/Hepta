#!/usr/bin/env python3
"""Auditable contract-only first-use task broker and independent native judge.

This broker exposes the real local domain service. It is explicitly not MCP and
it cannot attest that a model was fresh, unseen, or correctly billed. A separate
fresh Agent must receive only public/ plus the invoke command. Original model
interaction and provider usage must be attached by their owner; missing data
stays unknown and cannot close P1.
"""
from __future__ import annotations

import argparse
from contextlib import closing, contextmanager
import fcntl
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
sys.dont_write_bytecode = True

from hepta.hia_agent_service import HIAAgentService, installation_manifest
from hepta.hia_agent_store import decode_data, wire
from hepta.hia_program import verify_program
from hepta.hia_agent_runner import run_native_batch
from tools.qualify_hia_macro_campaign import _read_regular, _new_file

SCHEMA = "hepta.hia.agent.first-use.v1"
MAX_BYTES = 8 * 1024 * 1024
ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
EXPECTED_TOOLS = frozenset("hia_describe hia_artifact hia_read hia_context hia_inspect hia_candidate hia_verify hia_emit hia_evaluate hia_adopt hia_rollback".split())


class TrialRejected(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise TrialRejected(message)


def put(path, value):
    raw = value if type(value) is bytes else wire(value)
    _new_file(path, raw)
    return sha256(raw).hexdigest()


def read(path):
    return decode_data(_read_regular(path, MAX_BYTES))


def source_identity():
    return {"installation": installation_manifest(),
            "broker_sha256": sha256(_read_regular(Path(__file__), MAX_BYTES)).hexdigest(),
            "evidence_io_sha256": sha256(_read_regular(ROOT / "tools/qualify_hia_macro_campaign.py", MAX_BYTES)).hexdigest(),
            "native_observer_sha256": sha256(_read_regular(ROOT / "hepta/hia_agent_runner.py", MAX_BYTES)).hexdigest()}


def prepare(output, campaign_id, task, *, max_calls=128, wall_seconds=900):
    require(ID.fullmatch(campaign_id) is not None, "a unique literal campaign id is required")
    require(type(max_calls) is int and 1 <= max_calls <= 256, "call allowance must be in 1..256")
    require(type(wall_seconds) is int and 1 <= wall_seconds <= 3600, "wall allowance must be in 1..3600")
    require(type(task) is dict and set(task) == {"id", "instruction", "source", "workload", "provenance"},
            "task requires exactly id, instruction, source, workload, provenance")
    require(ID.fullmatch(task["id"]) is not None and type(task["instruction"]) is str and task["instruction"], "invalid task identity")
    require(type(task["provenance"]) is dict, "explicit task provenance is required")
    program = verify_program(task["source"])
    require(type(task["workload"]) is dict and task["workload"].get("cases"), "nonempty registered workload required")
    output = Path(output).absolute()
    require(not output.is_relative_to(ROOT), "trial output must be outside the source tree")
    output.mkdir(parents=True, exist_ok=False)
    (output / "public").mkdir()
    (output / "events").mkdir()
    (output / "objects").mkdir()
    with closing(HIAAgentService(output / "state")) as service:
        catalog = service.catalog
    require({tool["name"] for tool in catalog["tools"]} == EXPECTED_TOOLS, "eleven-tool domain contract changed")
    catalog_sha = put(output / "public/catalog.json", catalog)
    public_task = {"schema": SCHEMA, **task, "campaign_id": campaign_id, "target_slot": campaign_id,
        "source_sha256": program.sha256, "budget": {"max_calls": max_calls, "wall_seconds": wall_seconds},
        "objective": {"schema": "hepta.hia.agent.objective.v1", "metric": "artifact_bytes",
            "required_claims": ["core_admission", "behavior_equivalence", "encoding_check"],
            "allow_unchanged": False, "min_improvement_ratio": 0.0},
        "transport": "local_domain_service", "formal_mcp_discovery": False,
        "request_keys": "Each mutating request_key must start with campaign_id + '/'.",
        "entry": "Read catalog.json; use invoke with JSON {method:'tools/list'} or {method:'tools/call',params:{name,arguments}}.",
        "learning_scope": "Read only public/ and tool replies. Do not inspect broker, tests, private state or previous trial solutions.",
        "completion": "Use the domain tools to verify, emit, evaluate and adopt a strictly smaller compatible artifact into target_slot. Then stop; coordinator runs judge."}
    task_sha = put(output / "public/task.json", public_task)
    registration = {"schema": SCHEMA, "campaign_id": campaign_id, "task_sha256": task_sha,
        "public_catalog_sha256": catalog_sha, "sources": source_identity(), "prepared_unix_ns": time.time_ns(),
        "provider_usage": None, "fresh_agent_session_attested": False,
        "prior_task_exposure_attested": False, "original_model_interaction_complete": False,
        "formal_mcp_discovery": False, "p1_acceptance": "HOLD"}
    put(output / "registration.json", registration)
    put(output / "lock", b"")
    return registration


@contextmanager
def locked(root):
    fd = os.open(root / "lock", os.O_RDWR | os.O_NOFOLLOW)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def check_registration(root):
    registration = read(root / "registration.json")
    require(registration["schema"] == SCHEMA, "wrong trial schema")
    require(registration["sources"] == source_identity(), "source identity changed since registration")
    for path, field in (("public/task.json", "task_sha256"), ("public/catalog.json", "public_catalog_sha256")):
        require(sha256(_read_regular(root / path, MAX_BYTES)).hexdigest() == registration[field], "registered public input changed")
    return registration, read(root / "public/task.json")


def capture(service, root, value):
    queue, seen = [value], set()
    while queue:
        item = queue.pop()
        if type(item) is dict:
            if set(item) == {"id", "sha256", "uri"} and type(item["uri"]) is str and item["uri"].startswith("hia://artifacts/"):
                if item["sha256"] in seen:
                    continue
                data, _metadata = service.store.get(item)
                require(len(data) <= MAX_BYTES, "artifact capture limit exceeded")
                target = root / "objects" / item["sha256"]
                if target.exists():
                    require(_read_regular(target, MAX_BYTES) == data, "captured artifact changed")
                else:
                    put(target, data)
                seen.add(item["sha256"])
                if data.startswith((b"{", b"[")):
                    try:
                        queue.append(decode_data(data))
                    except (ValueError, UnicodeError):
                        pass
            else:
                queue.extend(item.values())
        elif type(item) is list:
            queue.extend(item)
        require(len(seen) <= 4096 and len(queue) <= 65536, "artifact graph bound exceeded")
    return sorted(seen)


def recorded_events(root):
    paths = sorted((root / "events").iterdir())
    require(all(re.fullmatch(r"[0-9]{4}\.(intent|outcome)\.json", path.name) for path in paths), "unexpected journal file")
    outcomes = []
    registration_sha = sha256(_read_regular(root / "registration.json", MAX_BYTES)).hexdigest()
    for index in range((len(paths) + 1) // 2):
        prefix = f"{index:04d}"
        intent_path, outcome_path = (root / "events" / (prefix + "." + suffix + ".json") for suffix in ("intent", "outcome"))
        require(intent_path.exists(), "journal gap")
        intent = read(intent_path)
        require(outcome_path.exists(), "uncertain prior invocation; inspect its retained intent, never dispatch another call")
        outcome = read(outcome_path)
        require(outcome["intent_sha256"] == sha256(_read_regular(intent_path, MAX_BYTES)).hexdigest(), "intent binding changed")
        require(outcome["index"] == intent["index"] == index, "journal identity mismatch")
        require(intent["registration_sha256"] == registration_sha, "journal registration drift")
        raw_request = _read_regular(root / "objects" / intent["request_wire_sha256"], MAX_BYTES)
        require(sha256(raw_request).hexdigest() == intent["request_wire_sha256"], "original request bytes changed")
        if intent["request"] is not None:
            require(decode_data(raw_request) == intent["request"], "request parse differs from original bytes")
        require(type(intent["started_monotonic_ns"]) is int and type(outcome["ended_monotonic_ns"]) is int
                and outcome["ended_monotonic_ns"] - intent["started_monotonic_ns"] == outcome["operation_wall_ns"], "journal interval mismatch")
        if outcomes:
            require(intent["started_monotonic_ns"] >= outcomes[-1][1]["ended_monotonic_ns"], "overlapping or reordered invocations")
        require(type(outcome["operation_wall_ns"]) is int and outcome["operation_wall_ns"] >= 0, "invalid operation time")
        for digest in outcome["artifact_sha256"]:
            require(re.fullmatch(r"[0-9a-f]{64}", digest) is not None, "bad artifact identity")
            require(sha256(_read_regular(root / "objects" / digest, MAX_BYTES)).hexdigest() == digest, "artifact bytes changed")
        outcomes.append((intent, outcome))
    return outcomes


def invoke(root, request=None, *, raw_request=None):
    root = Path(root).absolute()
    with locked(root):
        registration, task = check_registration(root)
        previous = recorded_events(root)
        require(not (root / "JUDGEMENT.json").exists(), "trial already closed")
        require(len(previous) < task["budget"]["max_calls"], "original call allowance exhausted")
        start = time.monotonic_ns()
        origin = previous[0][0]["started_monotonic_ns"] if previous else start
        require(0 <= start - origin < task["budget"]["wall_seconds"] * 1_000_000_000, "original task wall allowance exhausted or clock changed")
        index = len(previous)
        raw = wire(request) if raw_request is None else raw_request
        require(type(raw) is bytes and len(raw) <= MAX_BYTES, "bounded request bytes required")
        parse_error = None
        try:
            request = decode_data(raw)
        except (ValueError, UnicodeError) as error:
            request, parse_error = None, str(error)
        raw_sha = sha256(raw).hexdigest()
        raw_path = root / "objects" / raw_sha
        if raw_path.exists():
            require(_read_regular(raw_path, MAX_BYTES) == raw, "request object changed")
        else:
            put(raw_path, raw)
        intent = {"index": index, "schema": SCHEMA, "request": request,
            "request_wire_sha256": raw_sha,
            "request_origin": "stdin_original" if raw_request is not None else "python_object_canonicalized",
            "started_monotonic_ns": start, "started_unix_ns": time.time_ns(),
            "registration_sha256": sha256(_read_regular(root / "registration.json", MAX_BYTES)).hexdigest()}
        intent_sha = put(root / "events" / f"{index:04d}.intent.json", intent)
        outcome = {"index": index, "intent_sha256": intent_sha, "status": "failed", "response": None,
                   "failure": None, "artifact_sha256": [], "provider_usage": None, "model_tokens": None}
        try:
            require(parse_error is None, "malformed request JSON: " + str(parse_error))
            require(type(request) is dict and set(request) <= {"method", "params"}, "request requires method and optional params")
            with closing(HIAAgentService(root / "state")) as service:
                if request.get("method") == "tools/list":
                    require(request.get("params", {}) == {}, "tools/list takes no arguments")
                    response = {"tools": service.catalog["tools"], "transport": "local_domain_service", "formal_mcp_discovery": False}
                else:
                    require(request.get("method") == "tools/call", "only tools/list and tools/call are supported")
                    params = request.get("params")
                    require(type(params) is dict and set(params) == {"name", "arguments"} and params["name"] in EXPECTED_TOOLS, "exact domain tool and arguments required")
                    arguments = params["arguments"]
                    require(type(arguments) is dict, "tool arguments must be an object")
                    if "request_key" in arguments:
                        require(type(arguments["request_key"]) is str and arguments["request_key"].startswith(task["campaign_id"] + "/"), "request_key is outside the registered campaign")
                    if params["name"] in {"hia_adopt", "hia_rollback"}:
                        require(arguments.get("target_slot") == task["target_slot"], "target_slot is outside the registered campaign")
                    response = service.call(params["name"], arguments)
                outcome.update(status="returned", response=response,
                               artifact_sha256=capture(service, root, response))
        except Exception as error:
            outcome["failure"] = {"type": type(error).__name__, "message": str(error)[:2048]}
        outcome["ended_monotonic_ns"] = time.monotonic_ns()
        outcome["operation_wall_ns"] = outcome["ended_monotonic_ns"] - start
        outcome["ended_unix_ns"] = time.time_ns()
        put(root / "events" / f"{index:04d}.outcome.json", outcome)
        return outcome


def judge(root):
    root = Path(root).absolute()
    with locked(root):
        registration, task = check_registration(root)
        events = recorded_events(root)
        require(not (root / "JUDGEMENT.json").exists(), "judgement already exists; read it instead of rerunning")
        start = time.monotonic_ns()
        report = {"schema": SCHEMA, "task_id": task["id"], "campaign_id": task["campaign_id"],
            "task_success": False, "p1_acceptance": "HOLD", "formal_mcp_discovery": False,
            "original_model_interaction_complete": False, "fresh_agent_session_attested": False,
            "prior_task_exposure_attested": False, "provider_usage": None, "model_tokens": None,
            "monetary_cost": None, "full_cost_complete": False, "events": len(events),
            "failed_invocations": sum(outcome["status"] != "returned" for _, outcome in events),
            "domain_rejections": sum((outcome["response"] or {}).get("status") == "rejected" for _, outcome in events),
            "tool_execution_wall_ns": sum(outcome["operation_wall_ns"] for _, outcome in events),
            "task_elapsed_wall_ns": (events[-1][0]["started_monotonic_ns"] + events[-1][1]["operation_wall_ns"] - events[0][0]["started_monotonic_ns"]) if events else 0,
            "model_and_tool_intervals_added_twice": False,
            "task_elapsed_scope": "first broker invocation through last response; initial model startup and reading before that point are unknown",
            "failure": None}
        try:
            discovered = [outcome for intent, outcome in events if (intent["request"] or {}).get("method") == "tools/list" and outcome["status"] == "returned"]
            require(discovered and {tool["name"] for tool in discovered[0]["response"]["tools"]} == EXPECTED_TOOLS, "no actual domain tool catalog observation")
            adoptions = [outcome["response"]["result"] for intent, outcome in events
                if (intent["request"] or {}).get("method") == "tools/call" and (intent["request"] or {}).get("params", {}).get("name") == "hia_adopt"
                and (outcome["response"] or {}).get("status") == "completed"]
            require(adoptions, "no completed learner adoption")
            adoption = adoptions[-1]
            with closing(HIAAgentService(root / "state")) as service:
                snapshot = service._slot_snapshot(task["target_slot"])
                require(snapshot["active_artifact"] == adoption["active_artifact"] and snapshot["current"] == adoption["current"], "adopted generation is no longer current")
                adopted, _ = service.store.get_json(adoption["adoption_receipt"], kind="adoption-receipt")
                evaluation, _ = service.store.get_json(adopted["evaluation_receipt"], kind="evaluation-receipt")
                context = service._context(evaluation["context"])
                workload, _ = service.store.get_json(context["workload"])
                objective, _ = service.store.get_json(context["objective"])
                require(workload == task["workload"] and objective == task["objective"], "learner changed registered workload or acceptance objective")
                require(evaluation["baseline_core_sha256"] == task["source_sha256"], "learner substituted another baseline")
                require(evaluation["report_complete"] and evaluation["planned_workload_complete"] and evaluation["termination_confirmed"] and evaluation["outcome"] == "improved", "evaluation is not complete and improved")
                image, metadata, program = service._native(adoption["active_artifact"])
                baseline_image, _ = service.store.get(evaluation["baseline_artifact"], kind="native")
                require(len(image) < len(baseline_image), "actual adopted image is not strictly smaller")
                observed = run_native_batch(image, metadata["signatures"], task["workload"]["cases"], timeout_ms=10000, memory_bytes=536870912)
                put(root / "independent-native.json", observed)
                require(observed["status"] == "returned" and observed["termination_confirmed"], "independent native judge did not return with confirmed cleanup")
                native_report = observed["report"]
                require(native_report["completed_cases"] == len(task["workload"]["cases"]) and len(native_report["observations"]) == len(task["workload"]["cases"]), "independent native case inventory incomplete")
                for actual, case in zip(native_report["observations"], task["workload"]["cases"]):
                    require(not actual["mismatch"] and {"status": actual["status"], "values": actual["values"]} == case["expected"], "independent native behavior mismatch")
                require(report["task_elapsed_wall_ns"] <= task["budget"]["wall_seconds"] * 1_000_000_000, "original task wall allowance exceeded")
                report.update(task_success=True, baseline_artifact_bytes=len(baseline_image), candidate_artifact_bytes=len(image),
                    independent_native_cases=len(task["workload"]["cases"]), candidate_sha256=program.sha256,
                    adopted_image_sha256=sha256(image).hexdigest(), adoption=adoption)
                put(root / "candidate.core.json", program.canonical_bytes)
                put(root / "candidate.so", image)
                capture(service, root, report)
        except Exception as error:
            report["failure"] = {"type": type(error).__name__, "message": str(error)[:2048]}
        report["independent_judge_wall_ns"] = time.monotonic_ns() - start
        report["limitations"] = ["Domain service tools only; no MCP transport or formal endpoint discovery.",
            "Tool requests are original bytes but model interaction, freshness and token usage require separate original owner receipts.",
            "Task/native correctness and artifact reduction cannot establish net benefit or broad first-use generalization."]
        report["original_file_inventory"] = {str(path.relative_to(root)): sha256(_read_regular(path, MAX_BYTES)).hexdigest()
            for path in sorted([root / "registration.json", root / "public/task.json", root / "public/catalog.json",
                                *(root / "events").iterdir(), *(root / "objects").iterdir()])}
        for name in ("independent-native.json", "candidate.core.json", "candidate.so"):
            if (root / name).exists():
                report["original_file_inventory"][name] = sha256(_read_regular(root / name, MAX_BYTES)).hexdigest()
        put(root / "JUDGEMENT.json", report)
        return report


def verify(root):
    root = Path(root).absolute()
    with locked(root):
        check_registration(root)
        events = recorded_events(root)
        if (root / "JUDGEMENT.json").exists():
            judgement = read(root / "JUDGEMENT.json")
            expected_paths = {"registration.json", "public/task.json", "public/catalog.json"}
            expected_paths.update(str(path.relative_to(root)) for path in (root / "events").iterdir())
            expected_paths.update(str(path.relative_to(root)) for path in (root / "objects").iterdir())
            expected_paths.update(name for name in ("independent-native.json", "candidate.core.json", "candidate.so") if (root / name).exists())
            require(set(judgement["original_file_inventory"]) == expected_paths, "final original inventory differs")
            for name, expected in judgement["original_file_inventory"].items():
                require(sha256(_read_regular(root / name, MAX_BYTES)).hexdigest() == expected, "final original bytes changed")
            require(judgement["p1_acceptance"] == "HOLD" and judgement["provider_usage"] is None
                    and judgement["model_tokens"] is None and judgement["formal_mcp_discovery"] is False,
                    "domain trial cannot invent provider or MCP acceptance")
    return {"schema": SCHEMA, "original_tool_evidence_valid": True, "events": len(events),
            "p1_acceptance": "HOLD", "provider_usage": None, "formal_mcp_discovery": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "invoke", "judge", "verify"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--campaign-id")
    parser.add_argument("--task", type=Path)
    parser.add_argument("--max-calls", type=int, default=128)
    parser.add_argument("--wall-seconds", type=int, default=900)
    args = parser.parse_args(argv)
    try:
        if args.mode == "prepare":
            require(args.task is not None and args.campaign_id is not None, "prepare needs --task and --campaign-id")
            result = prepare(args.output, args.campaign_id, read(args.task), max_calls=args.max_calls, wall_seconds=args.wall_seconds)
        elif args.mode == "invoke":
            raw = sys.stdin.buffer.read(MAX_BYTES + 1)
            require(len(raw) <= MAX_BYTES, "request byte limit exceeded")
            result = invoke(args.output, raw_request=raw)
        elif args.mode == "judge":
            result = judge(args.output)
        else:
            result = verify(args.output)
        print(wire(result).decode())
        return 0
    except (ValueError, OSError, KeyError, TypeError) as error:
        print(wire({"status": "rejected", "error": {"type": type(error).__name__, "message": str(error)}}).decode())
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
