#!/usr/bin/env python3
"""Prospective bounded-repair study; v4 results and task gates remain immutable."""
from __future__ import annotations

import argparse
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from experiments.hia_agent_factorial_v4_20261028 import calibration, evaluator, fixtures
from experiments.hia_agent_factorial_v5_20261028.engine import StreamingEnvelopeEngine as EnvelopeEngine
from experiments.hia_agent_factorial_v5_20261028.prompts import prompt, strip_check
from tools.provider_adapter.llama_cpp_engine import canonical, file_identity

HERE = ROOT / "experiments/hia_agent_factorial_v5_20261028"


def runtime_preflight():
    """Check the actual seal API before any model request or candidate run."""
    required = ("F_ADD_SEALS", "F_GET_SEALS", "F_SEAL_WRITE", "F_SEAL_SHRINK", "F_SEAL_GROW", "F_SEAL_SEAL")
    if any(type(getattr(fcntl, name, None)) is not int for name in required):
        raise RuntimeError("E_REPAIR_PYTHON_SEAL_API: interpreter lacks required Linux fcntl constants; use a supported Python build")
    descriptor = os.memfd_create("hepta-agent-preflight", os.MFD_ALLOW_SEALING)
    try:
        os.write(descriptor, b"preflight")
        seals = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SEAL
        fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, seals)
        if fcntl.fcntl(descriptor, fcntl.F_GET_SEALS) & seals != seals:
            raise RuntimeError("E_REPAIR_KERNEL_SEALS")
        try:
            os.write(descriptor, b"forbidden")
        except PermissionError:
            pass
        else:
            raise RuntimeError("E_REPAIR_SEALED_WRITE_SUCCEEDED")
    finally:
        os.close(descriptor)
    module_file = getattr(fcntl, "__file__", sys.executable)
    return {"python": file_identity(sys.executable), "python_version": sys.version,
            "fcntl": file_identity(module_file),
            "fcntl_origin": "extension" if hasattr(fcntl, "__file__") else "built_into_interpreter",
            "kernel_seal_check": True}


def protocol():
    value = json.loads((HERE / "PROTOCOL.json").read_text())
    inherited = json.loads((fixtures.HERE / "PROTOCOL.json").read_text())
    for field in ("hidden_seed", "hidden_random_cases_per_task"):
        if value[field] != inherited[field]:
            raise ValueError("E_REPAIR_FIXTURE_PROTOCOL_DRIFT: " + field)
    return value


def bindings():
    paths = sorted([*ROOT.joinpath("hepta").rglob("*.py"), *HERE.glob("*.py"), *fixtures.HERE.glob("*.py"), HERE / "PROTOCOL.json", fixtures.HERE / "PROTOCOL.json",
                    Path(__file__).resolve(), ROOT / "tools/provider_adapter/llama_cpp_engine.py"])
    return {str(p.relative_to(ROOT)): file_identity(p)["sha256"] for p in paths}


def prompt_bindings():
    tasks = fixtures.make_fixtures()
    return {"main": {t["id"]: {arm: hashlib.sha256(prompt(t, arm).encode()).hexdigest() for arm in protocol()["arms"]} for t in tasks},
            "calibration": {t["id"]: hashlib.sha256(prompt(t, "calibration").encode()).hexdigest() for t in calibration.problems()}}


def controls(output, clang, rustc):
    root = Path(output); root.mkdir(parents=True, exist_ok=False)
    rows = []
    for task in fixtures.make_fixtures():
        for language in ("hia", "rust"):
            for mask in range(4):
                files = copy.deepcopy(task["original_" + language])
                for index, name in enumerate(fixtures.EDITABLE[language]):
                    if mask & (1 << index):
                        files[name] = copy.deepcopy(task["correct_" + language][name])
                identity = task["id"] + "_" + language + "_mask" + str(mask)
                built = evaluator.build(task, language, canonical({"files": files}).decode(), root / identity, clang, rustc,
                                        enforce_contract=mask != 0)
                observed = evaluator.execute(built, task, task["public_cases"] + task["hidden_cases"], task["public_expected"] + task["hidden_expected"]) if built["native_built"] else None
                if observed:
                    evaluator.save(root / identity / "EXECUTION.json", observed)
                expected_ok = mask == 3
                passed = (observed is not None and observed["status"] == "correct") if expected_ok else (observed is not None and observed["status"] != "correct" or built["status"] in {"response_rejected", "compile_rejected"})
                if mask == 0:
                    passed = passed and observed is not None and observed["native_executed"]
                rows.append({"id": identity, "mask": mask, "passed": passed, "model_answer": False, "build": built, "execution": observed})
    for task in calibration.problems():
        built = evaluator.build(task, "rust", canonical({"files": task["correct_rust"]}).decode(), root / task["id"], clang, rustc)
        observed = evaluator.execute(built, task, task["cases"], task["expected"]) if built["native_built"] else None
        rows.append({"id": task["id"], "passed": bool(observed and observed["status"] == "correct"), "model_answer": False, "build": built, "execution": observed})
    result = {"schema": "hepta.agent.factorial.controls.v4", "count": len(rows), "passed": sum(r["passed"] for r in rows), "rows": rows, "model_requests": 0}
    evaluator.save(root / "CONTROLS.json", result)
    return result


def _sources_snapshot(root, source_bindings):
    for name, expected in source_bindings.items():
        data = (ROOT / name).read_bytes()
        if hashlib.sha256(data).hexdigest() != expected:
            raise RuntimeError("source drift during snapshot")
        destination = root / "source_snapshot" / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)


def validate_calibration(record):
    tasks = [t["id"] for t in calibration.problems()]
    cells = record.get("cells", [])
    if (record.get("protocol_sha256") != file_identity(HERE / "PROTOCOL.json")["sha256"]
            or record.get("source_bindings") != bindings()
            or [c.get("task") for c in cells] != tasks
            or any(c.get("arm") != "rust_calibration" for c in cells)
            or not all(record.get(k) is True for k in ("source_unchanged", "model_unchanged", "tools_unchanged"))):
        raise ValueError("E_REPAIR_CALIBRATION_BINDING")
    derived = all(c.get("correct") is True and c.get("hidden_evaluated") is True
                  and c.get("status") == "correct" and 1 <= len(c.get("attempts", [])) <= protocol()["generation"]["attempts_per_cell"]
                  and all(a.get("usage") is not None for a in c["attempts"]) for c in cells)
    if record.get("calibration_eligible") is not derived:
        raise ValueError("E_REPAIR_CALIBRATION_DERIVED_GATE")
    pinned = next((m for m in protocol()["models"] if m["id"] == record.get("model", {}).get("id")), None)
    if pinned is None or any(record["model"].get(k) != v for k,v in pinned.items()):
        raise ValueError("E_REPAIR_CALIBRATION_MODEL")


def _selection(model_id, calibration_paths):
    order = protocol()["model_selection"]["order"]
    records = [json.loads(Path(p).read_text()) for p in calibration_paths]
    if [r.get("model", {}).get("id") for r in records] != order[:len(records)] or not records:
        raise ValueError("E_FACTORIAL_SELECTION_ORDER")
    for record in records:
        validate_calibration(record)
        if record.get("stage") != "calibration" or record.get("prompt_bindings") != prompt_bindings() or not record.get("valid_observation"):
            raise ValueError("E_FACTORIAL_SELECTION_EVIDENCE")
    chosen = next((r for r in records if r["calibration_eligible"]), records[-1])
    if chosen["model"]["id"] != model_id or (not chosen["calibration_eligible"] and len(records) != len(order)):
        raise ValueError("E_FACTORIAL_SELECTION_POLICY")
    if any(r["calibration_eligible"] for r in records[:-1]):
        raise ValueError("E_FACTORIAL_UNAUTHORIZED_MODEL_ESCALATION")
    if not chosen["calibration_eligible"]:
        raise ValueError("E_FACTORIAL_BASELINE_CAPABILITY_UNQUALIFIED: main comparison requires all three original task gates within the preregistered repair budget")
    return {"chosen_model": model_id, "eligible": chosen["calibration_eligible"], "calibrations": records,
            "records": [file_identity(path) for path in calibration_paths], "unbiased_model_sample": False}


def _check_model(model_id, model):
    entry = next((m for m in protocol()["models"] if m["id"] == model_id), None)
    if entry is None:
        raise ValueError("unregistered model")
    actual = file_identity(model)
    if (actual["bytes"], actual["sha256"]) != (entry["bytes"], entry["sha256"]):
        raise ValueError("model bytes differ from pinned publisher identity")
    return {**entry, "file": actual}


def summarize(cells, selection):
    groups = {}
    for arm in protocol()["arms"]:
        rows = [r for r in cells if r["arm"] == arm]
        attempts = [a for r in rows for a in r["attempts"]]
        known = [a for a in attempts if a.get("usage")]
        partials = [a["partial_usage"] for a in attempts if a.get("partial_usage")]
        complete = len(rows) == 4 and len(known) == len(attempts)
        input_count = sum(a["usage"]["input_tokens"] for a in known) + sum(a["input_tokens"] for a in partials)
        output_count = sum(a["usage"]["output_tokens"] for a in known)
        groups[arm] = {"planned_cells": 4, "attempted_cells": len(rows), "correct": sum(r["correct"] for r in rows),
                       "attempts": len(attempts), "automatic_repairs": sum(max(0, len(r["attempts"])-1) for r in rows),
                       "complete_usage": complete, "known_input_tokens": input_count, "known_output_tokens": output_count,
                       "partial_output_token_lower_bound": sum(a["observed_output_token_lower_bound"] for a in partials),
                       "total_tokens": input_count + output_count if complete else None,
                       "request_wall_ns": sum(a["request_wall_ns"] for a in attempts),
                       "validation_wall_ns": sum(a.get("validation_wall_ns", 0) for a in attempts) + sum(r.get("hidden_wall_ns", 0) for r in rows),
                       "tokens_per_correct_cell": (input_count+output_count)/sum(r["correct"] for r in rows) if complete and any(r["correct"] for r in rows) else None}
    hq, rq, hf = (groups[a] for a in ("hia_query", "rust_query", "hia_full"))
    complete = len(cells) == 16 and all(g["complete_usage"] for g in groups.values())
    gate = bool(selection and selection["eligible"] and complete and hq["correct"] == 4 and hq["correct"] >= rq["correct"] and hq["correct"] >= hf["correct"]
                and hq["total_tokens"] <= rq["total_tokens"] and hq["total_tokens"] < hf["total_tokens"])
    return {"groups": groups, "complete_costed_coverage": complete, "descriptive_advantage_gate": gate,
            "general_agent_productivity_proved": False, "adaptive_model_selection": True}


def run(*, stage, output, model_id, model, binary, clang, rustc, calibration_results=()):
    started = time.monotonic_ns()
    runtime = runtime_preflight()
    if stage not in {"calibration", "main"} or os.environ.get("LLAMA_ARG_REPACK") != "0":
        raise ValueError("stage and LLAMA_ARG_REPACK=0 are required")
    cfg = protocol(); chosen = _check_model(model_id, model)
    selection = _selection(model_id, calibration_results) if stage == "main" else None
    if stage == "calibration" and model_id == cfg["models"][1]["id"]:
        if len(calibration_results) != 1:
            raise ValueError("7B calibration requires the unsuccessful 1.5B result")
        previous = json.loads(Path(calibration_results[0]).read_text())
        validate_calibration(previous)
        if previous.get("model", {}).get("id") != cfg["models"][0]["id"] or previous.get("calibration_eligible") or not previous.get("valid_observation") or previous.get("prompt_bindings") != prompt_bindings():
            raise ValueError("7B escalation differs from the frozen calibration rule")
    root = Path(output).absolute(); root.mkdir(parents=True, exist_ok=False)
    source = bindings()
    tracked = set(subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.splitlines())
    if not set(source).issubset(tracked):
        raise ValueError("all bound implementation files must be tracked before inference")
    status = subprocess.run(["git", "status", "--porcelain", "--untracked-files=no"], cwd=ROOT, capture_output=True, text=True, check=True).stdout
    if status.strip():
        raise ValueError("tracked source must be committed before inference")
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip()
    tools = {name: file_identity(path) for name, path in (("binary", binary), ("clang", clang), ("rustc", rustc), ("python", sys.executable), ("fcntl", runtime["fcntl"]["path"]))}
    plan = {"schema": cfg["schema"], "stage": stage, "protocol": cfg, "model": chosen, "source_commit": head,
            "source_bindings": source, "prompt_bindings": prompt_bindings(), "tools": tools, "selection": selection, "runtime_preflight": runtime,
            "started_unix_ns": time.time_ns(), "model_requests_before_plan": 0,
            "performance_timing_qualified": False, "execution_location": "current shared development host; LOCAL_RUNTIME_NOT_OBSERVABLE for dot", "human_repairs": 0}
    _sources_snapshot(root, source); evaluator.save(root / "PLAN.json", plan)
    tasks = calibration.problems() if stage == "calibration" else fixtures.make_fixtures()
    cells = [{"id": t["id"], "task": t["id"], "arm": "rust_calibration"} for t in tasks] if stage == "calibration" else [
        {"id": t["id"]+"_"+a, "task": t["id"], "arm": a}
        for i,t in enumerate(tasks) for a in cfg["arms"][i%4:]+cfg["arms"][:i%4]]
    by_id = {t["id"]: t for t in tasks}
    result = {"schema": cfg["schema"], "stage": stage, "model": chosen, "plan_sha256": file_identity(root / "PLAN.json")["sha256"],
              "prompt_bindings": plan["prompt_bindings"], "source_bindings": source, "source_commit": head,
              "protocol_sha256": file_identity(HERE / "PROTOCOL.json")["sha256"], "cells": [], "engines": [], "selection": selection,
              "valid_observation": False, "human_repairs": 0, "status": "incomplete"}
    engine = None
    def close_engine():
        nonlocal engine
        if engine is None:
            return
        record = {"path": str(engine.output), "requests": engine.generation_count, "responses": engine.response_count}
        try:
            record["identity"] = engine.verify_final_identity()
        finally:
            before = time.monotonic_ns(); engine.close(); record["shutdown_ns"] = time.monotonic_ns()-before
            record["exited"] = engine.process.poll() is not None
            result["engines"].append(record); engine = None
        if not record["exited"] or not all(record["identity"][key] for key in ("model_unchanged", "runtime_unchanged")):
            raise RuntimeError("model/runtime identity or owned shutdown failed")
    try:
        for cell in cells:
            if bindings() != source:
                raise RuntimeError("source changed during model cohort")
            task = by_id[cell["task"]]
            language = cell["arm"].split("_")[0]
            folder = root / cell["id"]; folder.mkdir()
            row = {**cell, "attempts": [], "correct": False, "hidden_evaluated": False, "status": "not_started"}
            result["cells"].append(row)
            if engine is None:
                before = time.monotonic_ns()
                engine = EnvelopeEngine(binary=binary, model=model, model_sha256=chosen["sha256"], output_dir=root/("engine-"+str(len(result["engines"])).zfill(2)), threads=cfg["generation"]["threads"], context=8192)
                entries = Path("/proc/"+str(engine.process.pid)+"/environ").read_bytes().split(b"\0")
                if b"LLAMA_ARG_REPACK=0" not in entries:
                    raise RuntimeError("owned runtime repack environment differs")
                evaluator.save(engine.output / "STARTUP.json", {"wall_ns": time.monotonic_ns()-before, "LLAMA_ARG_REPACK": "0"})
            initial_prompt = prompt(task, "calibration" if stage == "calibration" else cell["arm"])
            messages = [{"role": "user", "content": initial_prompt}]
            rounds = cfg["generation"]["attempts_per_cell"]
            for index in range(rounds):
                attempt = {"index": index, "usage": None, "status": "request_started"}; row["attempts"].append(attempt)
                evaluator.save(folder / f"attempt-{index}.request.json", {"messages": messages})
                before = time.monotonic_ns()
                try:
                    response = engine.generate(messages, language=language, limit=cfg["generation"]["max_output_tokens"], wall_seconds=cfg["generation"]["wall_seconds"])
                    attempt.update(usage=response["usage"], request_wall_ns=time.monotonic_ns()-before)
                    evaluator.save(folder / f"attempt-{index}.response.json", response)
                except Exception as error:
                    attempt.update(request_wall_ns=time.monotonic_ns()-before, error={"type": type(error).__name__, "message": str(error)}, status="timeout" if isinstance(error, TimeoutError) else "inference_failure")
                    attempt["partial_usage"] = engine.last_usage_receipt
                    row["status"] = attempt["status"]; evaluator.save(folder / f"attempt-{index}.evaluation.json", attempt)
                    close_engine()
                    if row["status"] != "timeout":
                        raise
                    break
                before = time.monotonic_ns()
                built = evaluator.build(task, language, strip_check(response["text"]), folder / f"candidate-{index}", clang, rustc)
                observed = evaluator.execute(built, task, task["public_cases"], task["public_expected"]) if built["native_built"] else None
                attempt.update(build=built, public=observed, validation_wall_ns=time.monotonic_ns()-before,
                               status=observed["status"] if observed else built["status"])
                evaluator.save(folder / f"attempt-{index}.evaluation.json", attempt)
                row["status"] = attempt["status"]
                if built["status"] == "infrastructure_failure" or observed is not None and not observed["artifact_unchanged"]:
                    raise RuntimeError("candidate infrastructure or artifact identity failure")
                if observed and observed["status"] == "correct":
                    before = time.monotonic_ns()
                    hidden = evaluator.execute(built, task, task["hidden_cases"], task["hidden_expected"])
                    evaluator.save(folder / "HIDDEN.json", hidden)
                    row.update(hidden_evaluated=True, hidden_wall_ns=time.monotonic_ns()-before,
                               correct=hidden["status"] == "correct" and hidden["artifact_unchanged"],
                               status="correct" if hidden["status"] == "correct" else "hidden_failed")
                    break
                if index + 1 < rounds:
                    messages = [{"role": "user", "content": initial_prompt},
                                {"role": "assistant", "content": response["text"]}, {"role": "user", "content":
                        "Public validation rejected that submission. There are " + str(rounds-index-1) + " submissions remaining. Recheck the entire stated task, all widths and resource rules. Return the same check/files envelope with both complete files. Only public validation has run.\n" + canonical(evaluator.feedback(built, observed)).decode()}]
            evaluator.save(folder / "CELL.json", row)
            boundary = {"source_unchanged": bindings() == source, "model_unchanged": file_identity(model) == chosen["file"],
                        "tools_unchanged": all(file_identity(value["path"]) == value for value in tools.values())}
            evaluator.save(folder / "BOUNDARY.json", boundary)
            if not all(boundary.values()):
                raise RuntimeError("identity drift at cell boundary")
            print(json.dumps({"stage": stage, "model": model_id, "cell": row["id"], "status": row["status"], "attempts": len(row["attempts"])}), flush=True)
        result["status"] = "all_cells_attempted"
    except Exception as error:
        result["error"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        try:
            close_engine()
        except Exception as error:
            result.update(status="incomplete", shutdown_error=str(error))
        result["source_unchanged"] = bindings() == source
        result["tools_unchanged"] = all(file_identity(value["path"]) == value for value in tools.values())
        result["model_unchanged"] = file_identity(model) == chosen["file"]
        result["valid_observation"] = result["status"] == "all_cells_attempted" and len(result["cells"]) == len(cells) and all(result[k] for k in ("source_unchanged", "tools_unchanged", "model_unchanged"))
        result["calibration_eligible"] = bool(stage == "calibration" and result["valid_observation"] and all(c["correct"] for c in result["cells"]))
        result["first_submission_correct"] = sum(c["correct"] and len(c["attempts"]) == 1 for c in result["cells"])
        result["requests"] = sum(e["requests"] for e in result["engines"])
        result["responses"] = sum(e["responses"] for e in result["engines"])
        result["unknown_usage_requests"] = result["requests"]-result["responses"]
        known = [a["usage"] for c in result["cells"] for a in c["attempts"] if a.get("usage")]
        partials = [a["partial_usage"] for c in result["cells"] for a in c["attempts"] if a.get("partial_usage")]
        result["known_input_tokens"] = sum(u["input_tokens"] for u in known) + sum(u["input_tokens"] for u in partials)
        result["known_output_tokens"] = sum(u["output_tokens"] for u in known)
        result["partial_output_token_lower_bound"] = sum(u["observed_output_token_lower_bound"] for u in partials)
        result["total_tokens"] = result["known_input_tokens"]+result["known_output_tokens"] if not result["unknown_usage_requests"] else None
        if stage == "main":
            result["summary"] = summarize(result["cells"], selection)
            result["summary"]["descriptive_advantage_gate"] &= result["valid_observation"]
        result["experiment_wall_ns"] = time.monotonic_ns()-started
        evaluator.save(root / "RESULT.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage", choices=["controls", "calibration", "main"])
    parser.add_argument("--output", required=True)
    parser.add_argument("--clang", required=True); parser.add_argument("--rustc", required=True)
    for name in ("model-id", "model", "binary"):
        parser.add_argument("--"+name)
    parser.add_argument("--calibration-results", nargs="*", default=[])
    args = vars(parser.parse_args())
    if args["stage"] == "controls":
        result = controls(args["output"], args["clang"], args["rustc"])
        print(json.dumps({"controls": result["count"], "passed": result["passed"]}))
        return 0 if result["count"] == result["passed"] else 1
    result = run(**args)
    print(json.dumps({key: result.get(key) for key in ("stage", "status", "calibration_eligible", "requests", "responses", "total_tokens")}))
    return 0 if result["valid_observation"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
