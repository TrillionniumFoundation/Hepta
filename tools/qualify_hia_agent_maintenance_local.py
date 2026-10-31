#!/usr/bin/env python3
"""Distinct local maintenance arm; author controls never count as model work."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools import qualify_hia_agent_maintenance as maintenance
from tools import hia_agent_llama_transport as local
from tools.hia_agent_codex_transport import canonical, identity, save, strict_json

HERE = ROOT / "benchmarks/hia_agent_maintenance_local"


def protocol():
    cfg = strict_json((HERE / "PROTOCOL.json").read_bytes())
    inherited = maintenance.protocol()
    current_prompts = {key: value["request_text_sha256"] for key, value in prompt_bindings().items()}
    capacity = cfg.get("capacity_preflight", {})
    historical_prompts = capacity.get("historical", {}).get("public_request_text_sha256", {})
    same = ("arms", "cleanup_reserve_seconds", "hidden_policy", "max_cell_wall_seconds",
            "max_charged_tokens_per_cell", "max_experiment_wall_seconds", "max_public_checks_per_cell",
            "max_reported_input_tokens_per_request", "max_request_wall_seconds", "max_requests_per_cell",
            "public_rpc", "resource_task_admission", "tasks", "transport")
    if (cfg.get("schema") != "hepta.hia.agent-maintenance-local.v1"
            or cfg.get("models") != ["local-qwen3.5-4b-q4_k_m"]
            or any(cfg.get(key) != inherited[key] for key in same)
            or cfg.get("context_tokens") != 8192 or cfg.get("output_reserve_tokens") != 1536
            or cfg.get("max_charged_output_tokens_per_request") != 1536 or cfg.get("threads") != 4
            or cfg.get("decoder") != {"mode": "unconstrained", "temperature": 0, "seed": 0, "cache_prompt": False}
            or capacity.get("public_request_text_sha256") != current_prompts
            or set(historical_prompts) != set(current_prompts)
            or capacity.get("newly_required_prefixes") != [key for key in current_prompts if current_prompts[key] != historical_prompts[key]]
            or capacity.get("historical_exact_matches") != [key for key in current_prompts if current_prompts[key] == historical_prompts[key]]
            or cfg.get("inherited_task_file_sha256") != identity(maintenance.HERE / "tasks.py")["sha256"]):
        raise ValueError("E_LOCAL_PROTOCOL_DRIFT")
    cfg["protocol_sha256"] = identity(HERE / "PROTOCOL.json")["sha256"]
    return cfg


def bindings():
    paths = [*ROOT.joinpath("hepta").glob("*.py"), Path(__file__),
             ROOT / "tools/qualify_hia_agent_maintenance.py", ROOT / "tools/hia_agent_codex_transport.py",
             ROOT / "tools/hia_agent_llama_transport.py",
             ROOT / "tools/provider_adapter/llama_cpp_engine.py",
             ROOT / "tools/provider_adapter/hia_maintenance_llama_worker.py",
             ROOT / "tools/fixtures/hia_agent_maintenance_resource.rs",
             ROOT / "tests/test_hia_agent_maintenance_local.py",
             maintenance.HERE / "tasks.py", maintenance.HERE / "PROTOCOL.json",
             ROOT / "benchmarks/hia_agent_public_tools/PROTOCOL.json", HERE / "PROTOCOL.json"]
    return {str(p.relative_to(ROOT)): identity(p)["sha256"] for p in sorted(paths)}


def tool_bindings():
    cfg = protocol()
    rows = {key: {"invocation_path": cfg[key], "file": identity(cfg[key])}
            for key in ("python", "clang", "rustc")}
    runtime = cfg["runtime"]
    actual = [identity(item["path"]) for item in runtime["runtime_files"]]
    if actual != runtime["runtime_files"]:
        raise ValueError("E_LOCAL_RUNTIME_TOOL_DRIFT")
    model = identity(runtime["model"])
    if model["sha256"] != runtime["model_sha256"]:
        raise ValueError("E_LOCAL_MODEL_TOOL_DRIFT")
    rows.update(model=model, runtime_files=actual)
    return rows


def public_prefix_texts():
    rows = {}
    for task in maintenance.TASKS:
        for language in ("hia", "rust"):
            messages = [{"role": "user", "content": maintenance.public_prompt(task, language)}]
            for stage in ("initial", "after_catalog"):
                if stage == "after_catalog":
                    messages.extend([{"role": "assistant", "content": '{"action":"catalog"}'},
                                     {"role": "user", "content": maintenance.catalog(language)}])
                text = maintenance.request_text(messages)
                rows[stage + "-" + task["id"] + "-" + language] = text
    return rows


def prompt_bindings():
    return {key: {"request_text_sha256": hashlib.sha256(text.encode()).hexdigest(),
                  "request_text_bytes": len(text.encode())} for key, text in public_prefix_texts().items()}


def evaluate(task, language, folder, *, candidate=None, build=None, timeout=70, deadline=None):
    hidden = build is not None
    phase = "hidden" if hidden else "public"
    maintenance.admitted_wall_seconds(phase, timeout, deadline)
    cfg = protocol()
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=False)
    argv = [cfg["python"], str(Path(__file__).resolve()), "_evaluate", "--task", task["id"],
            "--language", language, "--mode", "hidden" if hidden else "public",
            "--output", str(folder / "evaluation")]
    if hidden:
        save(folder / "BUILD.json", build)
        argv.extend(["--build", str(folder / "BUILD.json")])
    else:
        save(folder / "CANDIDATE.json", candidate)
        argv.extend(["--candidate", str(folder / "CANDIDATE.json")])
    try:
        process = maintenance.checked_owned(phase, argv, ROOT, folder / "transport",
                                             wall_seconds=timeout, deadline=deadline)
    except maintenance.CleanupUncertain as error:
        error.observation = {"accepted": False, "correct": False, "hidden_evaluated": hidden,
                             "status": "evaluation_cleanup_uncertain", "process": error.record["process"],
                             "cleanup_uncertainty": error.record}
        raise
    receipt = folder / "evaluation/RESULT.json"
    if process["status"] != "exited" or not receipt.is_file():
        return {"accepted": False, "correct": False, "hidden_evaluated": hidden,
                "status": "evaluation_runtime_failure", "process": process}
    result = strict_json(receipt.read_bytes())
    result["process"] = process
    return result


def native_controls(output):
    """The original six author control groups with explicit new compiler bindings."""
    started = time.monotonic_ns()
    folder = Path(output).resolve()
    folder.mkdir(parents=True, exist_ok=False)
    result = {"schema": "hepta.hia.local-maintenance-native-controls.v1", "bindings": bindings(),
              "tools": tool_bindings(), "model_generations": 0, "reference_controls_are_model_successes": False,
              "rows": [], "passed": False}
    save(folder / "RESULT.json", result)
    for task in maintenance.TASKS:
        for language in ("hia", "rust"):
            cell = folder / (task["id"] + "-" + language)
            cell.mkdir()
            good = evaluate(task, language, cell / "good", candidate=maintenance.TASK_MODULE.reference(task["id"], language))
            hidden = evaluate(task, language, cell / "hidden", build=good) if good["accepted"] else None
            bad = (maintenance.TASK_MODULE.program([maintenance.TASK_MODULE.block("entry", ["x", "y"],
                   [maintenance.TASK_MODULE.const("z", 0)], maintenance.TASK_MODULE.ret("z"))])
                   if language == "hia" else "fn target(x:u32,y:u32)->u32 { 0 }")
            wrong = evaluate(task, language, cell / "bad", candidate=bad)
            unchanged = evaluate(task, language, cell / "unchanged-initial", candidate=maintenance.TASK_MODULE.initial(task["id"], language))
            signature = maintenance.TASK_MODULE.reference(task["id"], language)
            if language == "rust":
                body = signature[signature.index("{") + 1:signature.rindex("}")]
                signature = "fn target(x:u32,y:u32)->u64 { let value:u32={" + body + "};value as u64 }"
            else:
                signature["functions"][0]["returns"] = ["u64"]
            signature_result = evaluate(task, language, cell / "bad-signature", candidate=signature)
            lifecycle = None
            if task["id"] == "buffer_resize":
                candidate = maintenance.TASK_MODULE.reference(task["id"], language)
                if language == "rust":
                    candidate = candidate.replace("drop(data);", "")
                else:
                    block = candidate["functions"][0]["blocks"][0]
                    block["ops"] = [op for op in block["ops"] if op["op"] != "owner.drop"]
                lifecycle = evaluate(task, language, cell / "bad-lifecycle", candidate=candidate)
            row = {"task": task["id"], "language": language, "reference_public": good["accepted"],
                   "reference_hidden": bool(hidden and hidden["correct"]),
                   "wrong_control_rejected": not wrong["accepted"],
                   "wrong_signature_rejected": not signature_result["accepted"],
                   "unmaintained_initial_rejected": not unchanged["accepted"],
                   "missing_explicit_release_rejected": lifecycle is None or not lifecycle["accepted"]}
            result["rows"].append(row)
            save(folder / "RESULT.json", result)
            print(json.dumps(row), flush=True)
    fields = ("reference_public", "reference_hidden", "wrong_control_rejected", "wrong_signature_rejected",
              "unmaintained_initial_rejected", "missing_explicit_release_rejected")
    result.update(passed=len(result["rows"]) == 6 and all(all(row[k] for k in fields) for row in result["rows"]),
                  unchanged=result["bindings"] == bindings() and result["tools"] == tool_bindings(),
                  wall_ns=time.monotonic_ns() - started)
    result["passed"] &= result["unchanged"]
    save(folder / "RESULT.json", result)
    return 0 if result["passed"] else 1


def runtime_control(output):
    """Measure exactly the three changed current catalog prefixes, no completion."""
    folder = Path(output).resolve()
    folder.mkdir(parents=True, exist_ok=False)
    started = time.monotonic_ns()
    cfg = protocol()
    texts = public_prefix_texts()
    required = cfg["capacity_preflight"]["newly_required_prefixes"]
    expected_required = ["after_catalog-" + task["id"] + "-hia" for task in maintenance.TASKS]
    if required != expected_required or len(cfg["capacity_preflight"]["historical_exact_matches"]) != 9:
        raise ValueError("E_LOCAL_CAPACITY_CONTROL_SCOPE")
    record = {"schema": "hepta.hia.local-maintenance-runtime-control.v1", "bindings": bindings(),
              "tools": tool_bindings(), "model_generations": None, "passed": False,
              "historical_exact_matches": cfg["capacity_preflight"]["historical_exact_matches"],
              "historical_capacity_evidence": cfg["capacity_preflight"]["historical"],
              "current_prompts": prompt_bindings(), "results": [], "all_current_prefixes_fit": False}
    save(folder / "PLAN.json", record)
    save(folder / "CONTROL_INPUTS.json", [{"id": key, "request_text": texts[key],
         "request_text_sha256": hashlib.sha256(texts[key].encode()).hexdigest()} for key in required])
    try:
        for index, key in enumerate(required):
            result = local.invoke(texts[key], folder / ("request-" + str(index)), cfg,
                                  deadline=time.monotonic() + cfg["max_request_wall_seconds"], mode="capacity_probe")
            record["results"].append({"id": key, "result": result})
            save(folder / "RESULT.json", record)
            if not result["qualified"]:
                break
        record["all_current_prefixes_fit"] = (len(record["results"]) == 3
                                              and all(row["result"]["qualified"] for row in record["results"]))
    except Exception as error:
        record["error"] = {"type": type(error).__name__, "message": str(error)}
        if isinstance(error, maintenance.CleanupUncertain):
            record["cleanup_uncertainty"] = error.record
    finally:
        workers = [row["result"]["worker"] for row in record["results"]]
        record.update(unchanged=record["bindings"] == bindings() and record["tools"] == tool_bindings(),
                      model_generations=sum(row["generation_count"] for row in workers)
                        if len(workers) == 3 and all(row is not None and type(row.get("generation_count")) is int for row in workers) else None,
                      wall_ns=time.monotonic_ns() - started)
        record["passed"] = record["all_current_prefixes_fit"] and record["unchanged"] and record["model_generations"] == 0
        save(folder / "RESULT.json", record)
    return 0 if record["passed"] else 1


def prepare(native_path, runtime_path, pure_path, output):
    native = strict_json(Path(native_path).read_bytes())
    runtime = strict_json(Path(runtime_path).read_bytes())
    pure = strict_json(Path(pure_path).read_bytes())
    current, tools = bindings(), tool_bindings()
    if (native.get("passed") is not True or runtime.get("passed") is not True
            or runtime.get("all_current_prefixes_fit") is not True
            or pure.get("passed") is not True or pure.get("actual_model_generations") != 0
            or native.get("model_generations") != 0 or runtime.get("model_generations") != 0
            or native.get("bindings") != current or runtime.get("bindings") != current
            or native.get("tools") != tools or runtime.get("tools") != tools
            or pure.get("bindings") != current):
        raise ValueError("E_LOCAL_PREPARATION_REQUIRES_CURRENT_ZERO_GENERATION_CONTROLS")
    value = {"schema": "hepta.hia.local-maintenance-preparation.v1", "protocol": identity(HERE / "PROTOCOL.json"),
             "source": current, "tools": tools, "prompts": prompt_bindings(),
             "controls": {"native": identity(native_path), "runtime": identity(runtime_path), "pure": identity(pure_path)},
             "model_generations": 0, "ready_for_independent_freeze_review": True,
             "generation_authorized": False, "previous_negative_results_replaced": False}
    path = Path(output)
    if path.exists():
        raise ValueError("E_LOCAL_PREPARATION_EXISTS")
    save(path, value)
    return value


def freeze(preparation_path):
    value = strict_json(Path(preparation_path).read_bytes())
    if (value.get("schema") != "hepta.hia.local-maintenance-preparation.v1"
            or value.get("source") != bindings() or value.get("tools") != tool_bindings()
            or value.get("prompts") != prompt_bindings() or value.get("generation_authorized") is not False):
        raise ValueError("E_LOCAL_PREPARATION_DRIFT")
    for item in value["controls"].values():
        if identity(item["path"]) != item:
            raise ValueError("E_LOCAL_CONTROL_IDENTITY")
    path = HERE / "FREEZE.json"
    if path.exists():
        raise ValueError("E_LOCAL_FREEZE_EXISTS")
    save(path, {"schema": "hepta.hia.local-maintenance-freeze.v1", "preparation": identity(preparation_path),
                "source": bindings(), "tools": tool_bindings(), "prompts": prompt_bindings(),
                "controls": value["controls"], "generation_authorized": False})


def verify_freeze():
    value = strict_json((HERE / "FREEZE.json").read_bytes())
    if (value.get("schema") != "hepta.hia.local-maintenance-freeze.v1"
            or value.get("source") != bindings() or value.get("tools") != tool_bindings()
            or value.get("prompts") != prompt_bindings()):
        raise ValueError("E_LOCAL_FREEZE_SOURCE_TOOL_PROMPT_DRIFT")
    for item in value["controls"].values():
        if identity(item["path"]) != item:
            raise ValueError("E_LOCAL_FREEZE_CONTROL_DRIFT")
    return value


def recover_prefix(request_folder):
    request_path = Path(request_folder) / "model/REQUEST.json"
    if not request_path.is_file():
        return None
    request = local._bounded_json(request_path, 1024**2)
    return local.observed_prefix(Path(request_folder) / "model", request)


def retain_observation(receipt, prefix):
    if prefix is None:
        return
    receipt["observed_prefix"] = prefix
    receipt.setdefault("observation_history", []).append({key: value for key, value in prefix.items() if key != "worker"})
    for key, value in [("observed_usage", prefix["usage"]),
                       *((key, prefix[key]) for key in ("generation_endpoint_attempted", "completion_received",
                                                       "generation_count", "response_count"))]:
        # A later unreadable/in-progress record cannot erase already bound
        # usage or endpoint knowledge. Conflicting observations remain explicit.
        if value is None:
            continue
        if receipt.get(key) is None:
            receipt[key] = value
        elif receipt[key] != value:
            receipt.setdefault("observation_conflicts", []).append({"field": key, "retained": receipt[key], "later": value})


def run_cell(task, language, folder, experiment_deadline, cfg, *, verify=verify_freeze):
    started = time.monotonic_ns()
    deadline = min(experiment_deadline, time.monotonic() + cfg["max_cell_wall_seconds"]) - cfg["cleanup_reserve_seconds"]
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=False)
    row = {"task": task["id"], "language": language, "model": cfg["models"][0], "correct": False,
           "hidden_evaluated": False, "requests": [], "tool_calls": [], "charged_tokens": 0,
           "status": "starting", "experiment_poisoned": False, "human_answer_repairs": 0}
    save(folder / "CELL.json", row)
    # This per-cell identity work is included in the recorded cell wall.
    verify()
    messages = [{"role": "user", "content": maintenance.public_prompt(task, language)}]
    approved, public_checks = {}, 0
    for index in range(cfg["max_requests_per_cell"]):
        if deadline <= time.monotonic():
            row["status"] = "wall_budget"
            break
        request_folder = folder / ("request-" + str(index))
        request_folder.mkdir()
        receipt = {"index": index, "usage": None, "observed_usage": None, "unknown_usage": True,
                   "generation_endpoint_attempted": None, "completion_received": None,
                   "generation_count": None, "response_count": None}
        row["requests"].append(receipt)
        text = maintenance.request_text(messages)
        save(request_folder / "REQUEST.json", {"messages": messages, "text_sha256": hashlib.sha256(text.encode()).hexdigest()})
        save(folder / "CELL.json", row)
        try:
            answer = local.invoke(text, request_folder / "model", cfg, deadline=deadline)
            receipt.update(process=answer["process"], worker=answer["worker"], observed_usage=answer["usage"])
            retain_observation(receipt, answer.get("observed_prefix"))
            if "validation_error" in answer:
                receipt["validation_error"] = answer["validation_error"]
            if answer["usage"] is not None:
                receipt["charged_tokens"] = answer["usage"]["total_tokens"]
            row["charged_tokens"] = sum(r.get("charged_tokens", 0) for r in row["requests"])
            if not answer["qualified"]:
                raise local.LocalTransportFailure("E_LOCAL_MODEL_TRANSPORT_OR_USAGE_INCOMPLETE")
            receipt.update(usage=answer["usage"], unknown_usage=False)
            if row["charged_tokens"] > cfg["max_charged_tokens_per_cell"]:
                raise local.LocalTransportFailure("E_LOCAL_CELL_TOKEN_BUDGET")
            text = answer["worker"]["text"]
            save(request_folder / "ANSWER.json", {"text": text, "usage": answer["usage"]})
            messages.append({"role": "assistant", "content": text})
            try:
                action = maintenance.parse_action(text)
            except (ValueError, RecursionError) as error:
                feedback = {"status": "rpc_rejected", "error": str(error)}
                row["tool_calls"].append({"name": "invalid", "feedback": feedback})
                messages.append({"role": "user", "content": feedback})
                continue
            name = action["action"]
            entered = time.monotonic_ns()
            call = {"name": name}
            row["tool_calls"].append(call)
            if name == "catalog":
                feedback = maintenance.catalog(language)
            elif name == "check" or "candidate" in action:
                if name == "check" and public_checks >= cfg["max_public_checks_per_cell"]:
                    feedback = {"status": "public_check_budget_exhausted", "error": "final an already accepted digest or submit a final candidate"}
                else:
                    public_checks += int(name == "check")
                    digest = hashlib.sha256(canonical(action["candidate"])).hexdigest()
                    try:
                        observed = evaluate(task, language, request_folder / "public", candidate=action["candidate"],
                                            timeout=70, deadline=deadline)
                    except maintenance.CleanupUncertain as error:
                        call["public"] = error.observation
                        raise
                    finally:
                        call["wall_ns"] = time.monotonic_ns() - entered
                    call["public"] = observed
                    feedback = maintenance.public_feedback(observed, digest)
                    if observed["accepted"]:
                        approved[digest] = observed
                    if name == "final":
                        action = {"action": "final", "candidate_digest": digest}
            else:
                feedback = {"status": "final_received"}
            call["wall_ns"] = time.monotonic_ns() - entered
            if name == "final":
                build = approved.get(action.get("candidate_digest"))
                if build is None:
                    row["status"] = "final_not_publicly_accepted"
                    break
                entered = time.monotonic_ns()
                try:
                    hidden = evaluate(task, language, request_folder / "hidden", build=build, timeout=30, deadline=deadline)
                except maintenance.CleanupUncertain as error:
                    row.update(hidden_evaluated=True, experiment_poisoned=True, cleanup_uncertainty=error.record)
                    save(request_folder / "HIDDEN.json", error.observation)
                    raise
                finally:
                    row["hidden_wall_ns"] = time.monotonic_ns() - entered
                row.update(hidden_evaluated=True, correct=hidden["correct"], status="correct" if hidden["correct"] else "hidden_failed")
                save(request_folder / "HIDDEN.json", hidden)
                break
            call["feedback_sha256"] = hashlib.sha256(canonical(feedback)).hexdigest()
            save(request_folder / "PUBLIC_FEEDBACK.json", feedback)
            messages.append({"role": "user", "content": feedback})
        except Exception as error:
            receipt["error"] = {"type": type(error).__name__, "message": str(error)}
            if isinstance(error, maintenance.CleanupUncertain):
                row.update(experiment_poisoned=True, cleanup_uncertainty=error.record)
                if error.record["phase"] == "model":
                    receipt["process"] = error.record["process"]
            if isinstance(error, maintenance.WallBudgetExhausted):
                row["wall_budget_refusal"] = error.record
                receipt["model_launch_refused"] = error.record["phase"] == "model"
                if receipt["model_launch_refused"]:
                    receipt.update(generation_endpoint_attempted=False, completion_received=False,
                                   generation_count=0, response_count=0)
            if isinstance(error, local.LocalAdmissionRefused):
                receipt.update(model_launch_refused=True, admission_refusal=error.record,
                               generation_endpoint_attempted=False, completion_received=False,
                               generation_count=0, response_count=0)
            row["status"] = ("terminal_cleanup_uncertain" if row["experiment_poisoned"] else
                             "wall_budget" if isinstance(error, maintenance.WallBudgetExhausted) else
                             "terminal_runtime_or_protocol_failure")
            if not receipt.get("model_launch_refused"):
                try:
                    retain_observation(receipt, recover_prefix(request_folder))
                except Exception as recovery:
                    receipt["usage_recovery_error"] = {"type": type(recovery).__name__, "message": str(recovery)}
            if receipt.get("observed_usage") is not None:
                receipt["charged_tokens"] = receipt["observed_usage"]["total_tokens"]
            row["charged_tokens"] = sum(r.get("charged_tokens", 0) for r in row["requests"])
            break
        finally:
            save(request_folder / "RECEIPT.json", receipt)
            save(folder / "CELL.json", row)
    if row["status"] == "starting":
        row["status"] = "request_budget_exhausted"
    row.update(public_failed_checks=sum("public" in c and not c["public"]["accepted"] for c in row["tool_calls"]),
               complete_usage=bool(row["requests"]) and all(not r["unknown_usage"] for r in row["requests"]),
               wall_ns=time.monotonic_ns() - started)
    save(folder / "CELL.json", row)
    return row


def summary(rows):
    groups = {}
    for language in ("hia", "rust"):
        selected = [r for r in rows if r["language"] == language]
        groups[language] = {"attempted": len(selected), "correct": sum(r["correct"] for r in selected),
                            "complete_usage": len(selected) == 3 and all(r["complete_usage"] for r in selected),
                            "charged_tokens": sum(r["charged_tokens"] for r in selected),
                            "wall_ns": sum(r["wall_ns"] for r in selected),
                            "failed_public_checks": sum(r["public_failed_checks"] for r in selected)}
    h, r = groups["hia"], groups["rust"]
    gate = (h["complete_usage"] and r["complete_usage"] and h["correct"] >= r["correct"] and h["correct"] > 0
            and h["charged_tokens"] < r["charged_tokens"] and h["wall_ns"] < r["wall_ns"]
            and h["failed_public_checks"] <= r["failed_public_checks"])
    return {"groups": groups, "descriptive_hia_advantage_gate": gate, "general_productivity_proved": False,
            "human_review_time_ns": None, "human_cost_advantage_proved": False, "full_cost_advantage_proved": False,
            "cross_model_pooling_used": False, "population_task_representativeness": False,
            "os_file_cache_or_scheduler_controlled": False}


def run(output, review_path, registration_commit):
    started = time.monotonic_ns()
    cfg, frozen = protocol(), verify_freeze()
    review = strict_json(Path(review_path).read_bytes())
    if (review.get("decision") != "allow_generation" or review.get("freeze_sha256") != identity(HERE / "FREEZE.json")["sha256"]
            or review.get("controls") != frozen["controls"] or review.get("model_requests_by_reviewer") != 0):
        raise ValueError("E_LOCAL_INDEPENDENT_EXACT_FREEZE_REVIEW_REQUIRED")
    registered = subprocess.check_output(["git", "show", registration_commit + ":benchmarks/hia_agent_maintenance_local/FREEZE.json"], cwd=ROOT)
    if registered != (HERE / "FREEZE.json").read_bytes():
        raise ValueError("E_LOCAL_REGISTRATION_COMMIT")
    subprocess.run(["git", "merge-base", "--is-ancestor", registration_commit, "HEAD"], cwd=ROOT, check=True)
    folder = Path(output).resolve()
    folder.mkdir(parents=True, exist_ok=False)
    result = {"schema": "hepta.hia.local-maintenance-result.v1", "freeze": identity(HERE / "FREEZE.json"),
              "registration_commit": registration_commit, "review": identity(review_path), "status": "started",
              "cells": [], "experiment_poisoned": False, "previous_negative_results_replaced": False,
              "human_answer_repairs": 0, "preflight_wall_ns": time.monotonic_ns() - started}
    save(folder / "PLAN.json", {**result, "protocol": cfg, "model_requests_before_plan": 0})
    deadline = started / 1_000_000_000 + cfg["max_experiment_wall_seconds"]
    try:
        for index, task in enumerate(maintenance.TASKS):
            for language in (("hia", "rust") if index % 2 == 0 else ("rust", "hia")):
                if time.monotonic() + cfg["cleanup_reserve_seconds"] >= deadline:
                    raise TimeoutError("E_LOCAL_EXPERIMENT_WALL_BUDGET")
                row = run_cell(task, language, folder / (task["id"] + "-" + language), deadline, cfg)
                result["cells"].append(row)
                if row["experiment_poisoned"]:
                    result.update(experiment_poisoned=True, cleanup_uncertainty=row["cleanup_uncertainty"])
                result["summary"] = summary(result["cells"])
                save(folder / "RESULT.json", result)
                if result["experiment_poisoned"]:
                    raise RuntimeError("E_LOCAL_UNCERTAIN_CLEANUP_STOP_ALL_CELLS")
                if row["status"] == "terminal_runtime_or_protocol_failure":
                    last = row["requests"][-1] if row["requests"] else {}
                    if not last.get("model_launch_refused") and not maintenance.cleanup_confirmed(last.get("process")):
                        raise RuntimeError("E_LOCAL_MISSING_CLEANUP_RECEIPT_STOP_ALL_CELLS")
        result["status"] = "all_cells_attempted"
    except Exception as error:
        result.update(status="incomplete", error={"type": type(error).__name__, "message": str(error)})
    finally:
        final_started = time.monotonic_ns()
        try:
            verify_freeze()
            result["identities_unchanged"] = True
        except Exception as error:
            result.update(identities_unchanged=False, identity_error=str(error))
        result.update(final_revalidation_wall_ns=time.monotonic_ns() - final_started,
                      wall_ns=time.monotonic_ns() - started, summary=summary(result["cells"]))
        result["summary"]["descriptive_hia_advantage_gate"] &= (result["status"] == "all_cells_attempted" and result["identities_unchanged"])
        save(folder / "RESULT.json", result)
    return 0 if result["status"] == "all_cells_attempted" and result["identities_unchanged"] else 1


def main(argv=None):
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("native-controls", "runtime-control"):
        item = sub.add_parser(name); item.add_argument("--output", required=True)
    item = sub.add_parser("prepare")
    for name in ("native-controls", "runtime-control", "pure-controls", "output"):
        item.add_argument("--" + name, required=True)
    item = sub.add_parser("freeze"); item.add_argument("--preparation", required=True)
    item = sub.add_parser("run")
    for name in ("output", "review", "registration-commit"):
        item.add_argument("--" + name, required=True)
    item = sub.add_parser("_evaluate")
    for name in ("task", "language", "mode", "output"):
        item.add_argument("--" + name, required=True)
    item.add_argument("--candidate"); item.add_argument("--build")
    args = parser.parse_args(argv)
    if args.command == "native-controls": return native_controls(args.output)
    if args.command == "runtime-control": return runtime_control(args.output)
    if args.command == "prepare":
        prepare(args.native_controls, args.runtime_control, args.pure_controls, args.output); return 0
    if args.command == "freeze": freeze(args.preparation); return 0
    if args.command == "run": return run(args.output, args.review, args.registration_commit)
    return maintenance.evaluate_worker(args, tool_config=protocol())


if __name__ == "__main__":
    raise SystemExit(main())
