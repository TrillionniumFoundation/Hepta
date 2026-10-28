#!/usr/bin/env python3
"""One-model matched maintenance pilot with withheld native test inputs.

This is a new, explicitly single-model protocol. It does not satisfy or weaken
the historical two-model study's qualification gate. Four existing two-helper
contracts are retained; deterministic additional test inputs are withheld from
all model prompts. All four language/interface arms use the same model, JSON
syntax constraint, token budget and one-attempt policy.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools import qualify_hia_batch_study as batch
from tools.qualify_hia_edit_study import ARMS, _run_model, scheduled_cells
from tools.provider_adapter.llama_cpp_engine import canonical, file_identity

PROTOCOL = "hepta.hia.single-model-withheld-inputs.v1"
LIMIT = 512
HIDDEN_PAIRS = 64
HIDDEN_SEED = 0x48504132


def bindings(extra_source_paths=()):
    result = batch.bindings()
    result[str(Path(__file__).relative_to(ROOT))] = file_identity(__file__)["sha256"]
    for name in extra_source_paths:
        path = (ROOT / name).resolve(strict=True)
        result[str(path.relative_to(ROOT))] = file_identity(path)["sha256"]
    return result


def tasks(seed=HIDDEN_SEED):
    if type(seed) is not int or not 0 <= seed < 2**32:
        raise ValueError("E_HOLDOUT_SEED")
    result = copy.deepcopy(batch.fixtures())
    state = seed
    pairs = []
    for _ in range(HIDDEN_PAIRS):
        state = (1664525 * state + 1013904223) % 2**32
        x = state
        state = (1664525 * state + 1013904223) % 2**32
        pairs.append([x, state])
    for task in result:
        # Preserve the original boundary/trap inventory and append withheld
        # inputs. The independent formula does not read either implementation.
        task["cases"] += pairs
        first, second = [part["id"] for part in task["parts"]]
        task["expected"] = [(31 * batch.formula(first, x, y) + batch.formula(second, x, y)) % 2**32
                            for x, y in task["cases"]]
    return result


def write(path, value):
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(canonical(value) + b"\n")


def run(*, output_dir, binary, model, model_sha256, clang="/usr/bin/clang-20",
        rustc="/tmp/hepta-ai-rust-1.90.0/bin/rustc", threads=4, controls_only=False,
        model_metadata=None, model_index=0, withheld_seed=HIDDEN_SEED,
        protocol_id=PROTOCOL, extra_source_paths=()):
    experiment_started = time.monotonic_ns()
    out = Path(output_dir).absolute(); out.mkdir(parents=True, exist_ok=False)
    binding_fn = lambda: bindings(extra_source_paths)
    fixtures, initial = tasks(withheld_seed), binding_fn()
    model_info = {"id": "locked_local_model", "family": "single local model; no cross-model generalization",
                  "path": str(Path(model).absolute()), "sha256": model_sha256,
                  "provenance": "caller-supplied local GGUF identified by exact bytes"}
    if model_metadata is not None:
        required = {"id", "family", "repository", "revision", "sha256", "bytes", "provenance"}
        if (type(model_metadata) is not dict or not required.issubset(model_metadata)
                or type(model_metadata["id"]) is not str
                or re.fullmatch(r"[a-z][a-z0-9_]{0,63}", model_metadata["id"]) is None
                or model_metadata["sha256"] != model_sha256):
            raise ValueError("E_HOLDOUT_MODEL_METADATA")
        model_info.update(copy.deepcopy(model_metadata), path=str(Path(model).absolute()))
    if type(model_index) is not int or not 0 <= model_index <= 16:
        raise ValueError("E_HOLDOUT_MODEL_INDEX")
    require_model = file_identity(model)
    if (require_model["sha256"] != model_sha256 or
            (model_metadata is not None and require_model["bytes"] != model_metadata["bytes"])):
        raise ValueError("E_HOLDOUT_MODEL_HASH")
    plan = {"schema": protocol_id, "source_bindings": initial, "tasks": fixtures, "arms": list(ARMS),
            "model": model_info, "runtime": file_identity(binary), "clang": file_identity(clang), "rustc": file_identity(rustc),
            "max_new_tokens": LIMIT, "attempts_per_cell": 1, "threads": threads, "greedy": True, "seed": 0,
            "json_constraint": "object syntax only; no task-specific answer grammar", "scheduled_cells": scheduled_cells(fixtures, model_index),
            "test_inputs_in_prompts": False, "additional_withheld_pairs_per_task": HIDDEN_PAIRS,
            "withheld_lcg_seed": withheld_seed, "model_index": model_index,
            "task_origin": "existing four two-helper arithmetic maintenance compositions; new withheld input cases, not new task families",
            "success_rule": "both helpers repaired, unchanged caller, actual native output matches every independent case",
            "primary_comparison": "HIA query vs Rust query under same model/budget; successful tasks and all request token/time costs",
            "secondary_comparison": "within-language full context vs query to expose interface/context effects",
            "cost_exclusions": ["human review and tool construction", "model training", "upstream integration", "model download"],
            "claims": {"general_productivity_advantage": False, "two_model_gate_satisfied": False, "total_economic_cost_measured": False}}
    plan["sha256"] = hashlib.sha256(canonical(plan)).hexdigest()
    for name, expected_hash in initial.items():
        payload = (ROOT / name).read_bytes()
        if hashlib.sha256(payload).hexdigest() != expected_hash:
            raise ValueError("E_HOLDOUT_SOURCE_CHANGED_DURING_FREEZE")
        destination = out / "source_snapshot" / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)
    write(out / "plan.json", plan)
    controls = []
    started = time.monotonic_ns()
    for task in fixtures:
        for language in ("hia", "rust"):
            for mask in range(4):
                name = task["id"] + "_" + language + "_mask" + str(mask)
                candidate = batch.parse_response(task, language + "_edit_query", canonical(batch.response_for(task, language, mask)).decode())
                result = batch.native(task, candidate, language, out / "controls" / name, clang, rustc)
                passed = (result.get("native_executed") is True and
                          (result["status"] == "correct" if mask == 3 else result["status"] in {"observable_wrong", "expected_overflow_trap"}))
                controls.append({"id": name, "fixed_mask": mask, "passed": passed, "result": result})
    controls_ns = time.monotonic_ns() - started
    write(out / "controls.json", controls)
    controls_ok = all(item["passed"] for item in controls)
    model_report = None
    model_execution_wall_ns = None
    if controls_ok and not controls_only:
        formats = [(language, canonical({"edits": [
            {"site": i, "changes": {"op" if language == "hia" else "replacement": "const" if language == "hia" else "0"}}
            for i in range(2)]}).decode()) for language in ("hia", "rust")]
        model_started = time.monotonic_ns()
        model_report = _run_model(model_info, model_index, fixtures, out, binary, clang, rustc, threads, initial,
                                  json_object=True, prompt_fn=batch.prompt, parse_fn=batch.parse_response,
                                  native_fn=batch.native, bindings_fn=binding_fn, response_limit=LIMIT, preflight_formats=formats)
        model_execution_wall_ns = time.monotonic_ns() - model_started
    tools_stable = all(file_identity(path) == plan[name] for name, path in (("runtime", binary), ("clang", clang), ("rustc", rustc)))
    source_stable = binding_fn() == initial
    complete = bool(model_report and model_report["status"] == "completed" and source_stable and tools_stable and
                    len(model_report["completed_cells"]) == 16 and not model_report["unresolved_requests"])
    report = {"schema": protocol_id, "status": "completed" if complete else "development_controls_only" if controls_only and controls_ok else "incomplete",
              "plan_sha256": plan["sha256"], "native_controls": len(controls), "native_controls_passed": sum(c["passed"] for c in controls),
              "native_controls_wall_ns": controls_ns, "source_unchanged": source_stable, "tools_unchanged": tools_stable,
              "model_execution_wall_ns": model_execution_wall_ns,
              "model_execution_cost_scope": "startup, model/runtime hashing, probes, all task attempts, native evaluations and shutdown",
              "model_report": model_report, "claims": plan["claims"], "limitations": [plan["task_origin"], *plan["cost_exclusions"],
                  "one fixed quantized model per invocation and one attempt per cell", "tests are withheld from prompts, not a secret dataset",
                  "four paired tasks cannot establish a population productivity effect"]}
    if model_report:
        report["single_model_descriptive_criteria"] = batch.criteria(model_report["summary"], complete)
        report["all_actual_request_usage"] = {"requests_started": model_report["requests_started"],
            "responses_received": model_report["responses_received"], "unresolved_requests": model_report["unresolved_requests"],
            "probe_input_tokens": sum(p.get("usage", {}).get("input_tokens", 0) for p in model_report["preflight"]),
            "probe_output_tokens": sum(p.get("usage", {}).get("output_tokens", 0) for p in model_report["preflight"])}
        report["tokens_per_successful_task"] = {
            arm: ((row["input_tokens"] + row["output_tokens"]) / row["successes"]
                  if row["successes"] and row["usage_complete"] else None)
            for arm, row in model_report["summary"].items()}
    report["experiment_wall_ns"] = time.monotonic_ns() - experiment_started
    write(out / "report.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("output-dir", "binary", "model", "model-sha256"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--clang", default="/usr/bin/clang-20")
    parser.add_argument("--rustc", default="/tmp/hepta-ai-rust-1.90.0/bin/rustc")
    parser.add_argument("--threads", type=int, default=4)
    parser.add_argument("--controls-only", action="store_true")
    report = run(**vars(parser.parse_args()))
    print(json.dumps({key: report.get(key) for key in ("status", "native_controls", "native_controls_passed", "single_model_descriptive_criteria")}))
    return 0 if report["status"] in {"completed", "development_controls_only"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
