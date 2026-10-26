#!/usr/bin/env python3
"""Run the frozen 2x2 HIA/Rust single-site repair pilot with real owned inference.

The factorial arms distinguish language from edit-interface effects. Four tasks
do not establish general productivity, maintenance effort, or economic benefit.
All attempts and actual candidate binaries are retained, including failures.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from hepta.hia_program import verify_program
from tools.provider_adapter.llama_cpp_engine import LlamaCppEngine, canonical, file_identity
from tools.qualify_hia_agent_pilot import (ARMS, BINDINGS, clean_response, native_oracle, native_control_passed,
    parse_candidate, prompt, reference_response, repaired_hia, task_fixtures, write_new)
from tools.provider_adapter.local_model_common import digest


EXTRA_BINDINGS = ("tools/qualify_hia_agent_gguf.py", "tools/provider_adapter/llama_cpp_engine.py")


def bindings():
    files = set((*BINDINGS, *EXTRA_BINDINGS,
                 "tools/provider_adapter/local_model_common.py"))
    files.update(str(path.relative_to(ROOT)) for path in (ROOT / "hepta").rglob("*.py"))
    return {name: file_identity(ROOT / name)["sha256"] for name in sorted(files)}


def summarize(outcomes):
    result = {}
    for arm in ARMS:
        rows = [row for row in outcomes if row["arm"] == arm]
        attempts = [attempt for row in rows for attempt in row["attempts"]]
        known = [item for item in attempts if item["usage"] is not None]
        result[arm] = {"tasks": len(rows), "successes": sum(row["success"] for row in rows),
                       "planned_tasks": 4, "completed_tasks": sum(row.get("completed", False) for row in rows),
                       "first_attempt_successes": sum(bool(row["attempts"]) and row["attempts"][0]["ok"] for row in rows),
                       "attempts": len(attempts),
                       "rejected_candidates": sum(not item["accepted"] for item in known),
                       "accepted_but_wrong": sum(item["accepted"] and not item["ok"] for item in attempts),
                       "input_tokens": sum(item["usage"]["input_tokens"] for item in known),
                       "output_tokens": sum(item["usage"]["output_tokens"] for item in known),
                       "unknown_usage_attempts": len(attempts) - len(known),
                       "token_cost_complete": len(attempts) == len(known),
                       "inference_nanoseconds": sum(item["wall_nanoseconds"] for item in attempts),
                       "evaluation_nanoseconds": sum(item["evaluation_nanoseconds"] for item in attempts)}
    return result


def run(*, binary, model, model_sha256, output_dir, clang, rustc, threads):
    out = Path(output_dir).absolute()
    out.mkdir(parents=True, exist_ok=False)
    initial = bindings()
    tasks = task_fixtures()
    tool_identity = {"clang": file_identity(clang), "rustc": file_identity(rustc)}
    outcomes, controls, preflight, generations = [], [], [], []
    frozen = None
    with LlamaCppEngine(binary=binary, model=model, model_sha256=model_sha256,
                        output_dir=out / "engine", threads=threads) as engine:
        capacity = {t["id"]: {a: len(engine.tokenize(reference_response(t, a))) for a in ARMS} for t in tasks}
        largest = max(count for by_arm in capacity.values() for count in by_arm.values())
        limit = next((n for n in (512, 1024, 2048) if largest + 8 <= n), None)
        if limit is None:
            raise ValueError("E_PILOT_CAPACITY")
        frozen = {"schema": "hepta.hia.gguf-pilot-plan.v1", "tasks": tasks,
                  "arms": list(ARMS), "attempts_per_task_arm": 2,
                  "reference_output_token_counts": capacity, "max_new_tokens": limit,
                  "generation": {"greedy": True, "seed": 0, "cache_prompt": False,
                                 "threads": threads, "wall_seconds_per_attempt": 180},
                  "runtime_identity": engine.identity, "tool_identity": tool_identity,
                  "compiler_bindings": initial, "arm_order": "rotate by task index",
                  "native_oracle": "frozen independent arithmetic cases; exact context-preserving repairs",
                  "eligibility": "both unchanged JSON and Rust exact-format probes must pass",
                  "failure_policy": "all outputs retained; no retry beyond two planned attempts",
                  "comparison_policy": "2x2 language/interface; no causal population claim from four tasks",
                  "total_development_cost_measured": False}
        frozen["plan_sha256"] = digest(canonical(frozen))
        write_new(out / "plan.json", frozen)
        print(json.dumps({"event": "plan_frozen", "sha256": frozen["plan_sha256"],
                          "largest_reference_tokens": largest, "max_new_tokens": limit}), flush=True)

        def finish(status, **extra):
            final = engine.verify_final_identity()
            final_bindings = bindings()
            final_tools = {"clang": file_identity(clang), "rustc": file_identity(rustc)}
            stable = (final_bindings == initial and final_tools == tool_identity
                      and all(final[k] for k in ("model_unchanged", "runtime_unchanged")))
            result = {"schema": "hepta.hia.gguf-agent-pilot.v1", "status": status if stable else "identity_drift",
                      "plan_sha256": frozen["plan_sha256"], "source_unchanged": final_bindings == initial,
                      "final_bindings": final_bindings, "model_runtime_identity": final,
                      "actual_model_runs": len(generations), "generations": generations,
                      "completion_requests_started": engine.generation_count,
                      "completion_responses_received": engine.response_count,
                      "unresolved_completion_requests": engine.generation_count - engine.response_count,
                      "validated_generations": len(generations),
                      "tools_unchanged": final_tools == tool_identity,
                      "preflight": preflight, "outcomes": outcomes, "summary": summarize(outcomes),
                      "comparative_task_attempts": sum(len(x["attempts"]) for x in outcomes),
                      "effect_established": False, "general_coding_advantage_established": False,
                      "maintenance_cost_measured": False, "total_development_cost_measured": False,
                      "limitations": ["one locked local quantized model", "four disclosed single-site repairs",
                                      "not independent real-world task families or a population estimate",
                                      "token and elapsed costs exclude language/tool development and human labor"],
                      **extra}
            write_new(out / "report.json", result)
            return result

        for task in tasks:
            for language in ("hia", "rust"):
                for correct in (False, True):
                    candidate = (verify_program(repaired_hia(task) if correct else task["hia"])
                                 if language == "hia" else task["rust_template"].replace(
                                     "@SLOT@", task["rust_good"] if correct else task["rust_bad"]))
                    identity = task["id"] + "_" + language + "_" + str(correct).lower()
                    try:
                        result = native_oracle(task, candidate, language, clang=clang, rustc=rustc,
                                              artifact_directory=out / "controls" / identity)
                    except Exception as error:
                        result = {"ok": False, "native_executed": False,
                                  "error": {"type": type(error).__name__, "message": str(error)}}
                    controls.append({"id": identity, "control_passed": native_control_passed(result, correct),
                                     "oracle": result})
        write_new(out / "controls.json", controls)
        if not all(c["control_passed"] for c in controls):
            return finish("native_controls_failed")

        def generate(messages, identity):
            if bindings() != initial:
                raise RuntimeError("E_PILOT_SOURCE_DRIFT")
            write_new(out / (identity + ".request.json"), {"messages": messages, "limit": limit})
            value = engine.generate(messages, limit=limit, wall_seconds=180)
            write_new(out / (identity + ".response.json"), value)
            generations.append(identity)
            print(json.dumps({"event": "generation", "id": identity,
                              "output_tokens": value["usage"]["output_tokens"]}), flush=True)
            return value

        try:
            probes = [("json", 'Return exactly this JSON object and no explanation: {"ok":true}', '{"ok":true}'),
                      ("rust", "Return exactly this Rust function and no explanation: fn probe(x:u32)->u32{x}",
                       "fn probe(x:u32)->u32{x}")]
            for name, message, wanted in probes:
                response = generate([{"role": "user", "content": message}], "preflight_" + name)
                actual = clean_response(response["text"])
                preflight.append({"id": name, "ok": re.sub(r"\s+", "", actual) == re.sub(r"\s+", "", wanted)})
            write_new(out / "preflight.json", preflight)
            if not all(item["ok"] for item in preflight):
                return finish("model_capability_preflight_failed")
            for tindex, task in enumerate(tasks):
                for arm in ARMS[tindex % 4:] + ARMS[:tindex % 4]:
                    messages = [{"role": "user", "content": prompt(task, arm)}]
                    attempts = []
                    outcome = {"task": task["id"], "arm": arm, "attempts": attempts,
                               "success": False, "completed": False}
                    outcomes.append(outcome)
                    for attempt in (1, 2):
                        identity = task["id"] + "_" + arm + "_" + str(attempt)
                        item = {"attempt": attempt, "response": identity + ".response.json",
                                "accepted": False, "ok": False, "usage": None,
                                "wall_nanoseconds": 0, "evaluation_nanoseconds": 0,
                                "generation_completed": False}
                        attempts.append(item)
                        generation_started = time.monotonic_ns()
                        try:
                            response = generate(messages, identity)
                        except Exception as error:
                            item["wall_nanoseconds"] = time.monotonic_ns() - generation_started
                            item["response"] = None
                            item["generation_error"] = {"type": type(error).__name__, "message": str(error)}
                            write_new(out / (identity + ".evaluation.json"), item)
                            write_new(out / (task["id"] + "_" + arm + ".outcome.json"), outcome)
                            raise
                        item.update(usage=response["usage"], generation_completed=True,
                                    wall_nanoseconds=time.monotonic_ns() - generation_started)
                        started = time.monotonic_ns()
                        try:
                            candidate = parse_candidate(task, arm, response["text"])
                            item["accepted"] = True
                            item["native_oracle"] = native_oracle(task, candidate,
                                "hia" if arm.startswith("hia") else "rust", clang=clang, rustc=rustc,
                                artifact_directory=out / "candidates" / identity)
                            item["ok"] = item["native_oracle"]["ok"]
                            feedback = "Independent native oracle failed. Correct the same repair site and preserve all other code."
                        except Exception as error:
                            item["error"] = {"type": type(error).__name__, "message": str(error)}
                            feedback = "Candidate rejected: " + str(error)[:500] + ". Return only the requested artifact."
                        item["evaluation_nanoseconds"] = time.monotonic_ns() - started
                        if bindings() != initial:
                            raise RuntimeError("E_PILOT_SOURCE_DRIFT")
                        outcome["success"] = outcome["success"] or item["ok"]
                        write_new(out / (identity + ".evaluation.json"), item)
                        if item["ok"]:
                            break
                        messages += [{"role": "assistant", "content": response["text"]},
                                     {"role": "user", "content": feedback}]
                    outcome["completed"] = True
                    write_new(out / (task["id"] + "_" + arm + ".outcome.json"), outcome)
        except Exception as error:
            return finish("execution_incomplete", error={"type": type(error).__name__, "message": str(error)})
        return finish("completed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--model-sha256", required=True)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--clang", default="/usr/lib/llvm-20/bin/clang")
    parser.add_argument("--rustc", default="/tmp/hepta-ai-rust-1.90.0/bin/rustc")
    parser.add_argument("--threads", type=int, default=4)
    result = run(**vars(parser.parse_args()))
    print(json.dumps({key: result[key] for key in ("status", "actual_model_runs", "summary")}))
    return 0 if result["status"] == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
