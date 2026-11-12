#!/usr/bin/env python3
"""No-generation native/reference and exact model-tokenizer capacity controls."""
from __future__ import annotations

import argparse
import ast
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

from experiments.hia_agent_factorial_v4_20261028 import evaluator
from experiments.hia_agent_toolstudy_v8_20261029 import budget, prompts, references, support, validation
from experiments.hia_agent_toolstudy_v8_20261029.engine import ToolStudyEngine
from tools.provider_adapter.llama_cpp_engine import canonical, file_identity
from tools.qualify_hia_agent_primitive_repair import runtime_preflight


def run(*, output, binary, tokenizer, model, clang, rustc):
    started = time.monotonic_ns()
    if os.environ.get("LLAMA_ARG_REPACK") != "0":
        raise ValueError("LLAMA_ARG_REPACK=0 required")
    head, source = support.clean_committed_source()
    cfg = support.protocol(); generation = cfg["generation"]
    chosen = support.check_model(model)
    tools = support.tool_identities(binary, tokenizer, clang, rustc)
    root = Path(output).absolute(); root.mkdir(parents=True, exist_ok=False)
    plan = {"schema": "hepta.agent.tool-capacity.v8", "source_commit": head, "source_bindings": source,
            "prompt_bindings": support.prompt_bindings(), "protocol_sha256": file_identity(support.HERE / "PROTOCOL.json")["sha256"],
            "model": chosen, "tools": tools, "runtime_preflight": runtime_preflight(),
            "model_requests": 0, "references_are_agent_successes": False}
    support.snapshot(root, source); evaluator.save(root / "PLAN.json", plan)
    engine = None
    rows = []
    result = {**plan, "rows": rows, "complete": False}
    try:
        engine = ToolStudyEngine(binary=binary, model=model, model_sha256=chosen["sha256"],
                                 output_dir=root / "tokenizer-runtime", threads=generation["threads"],
                                 context=generation["context_tokens"])
        for stage in ("calibration", "main"):
            for task, arm in support.cells(stage):
                before = time.monotonic_ns()
                language, interface = support.language_interface(arm)
                key = stage + "/" + task["id"] + "/" + arm
                folder = root / stage / task["id"] / arm
                folder.mkdir(parents=True)
                session = support.session_for(task, arm, clang, rustc)
                query = session.query()
                initial = prompts.prompt(task, arm, query)
                evaluator.save(folder / "QUERY.json", query)
                noop = (references.identity_response(query) if interface == "node"
                        else {"files": task["original_" + language]})
                noop_text = canonical(noop).decode()
                noop_result = validation.evaluate(task, language, interface, session, query, noop_text, folder / "public_noop", clang, rustc)
                if noop_result["accepted"] or noop_result["status"] == "infrastructure_failure" or session.revision != query["source_revision"]:
                    raise RuntimeError("E_TOOLSTUDY_NOOP_CONTROL")
                answer = (references.reference(session, query, task) if interface == "node"
                          else {"files": task["correct_" + language]})
                answer_text = canonical(answer).decode()
                evaluator.save(folder / "REFERENCE.json", {"model_answer": False, "response": answer})
                admitted = validation.evaluate(task, language, interface, session, query, answer_text, folder / "reference", clang, rustc)
                hidden = (evaluator.execute(admitted["build"], task, task["hidden_cases"], task["hidden_expected"])
                          if admitted["accepted"] else None)
                if hidden is not None:
                    evaluator.save(folder / "REFERENCE_HIDDEN.json", hidden)
                reference_passed = bool(admitted["accepted"] and hidden and hidden["status"] == "correct" and hidden["artifact_unchanged"])

                def count_request(items, name):
                    rendered = engine.request("/apply-template", {"messages": items})["prompt"]
                    if rendered != prompts.plain_qwen_template(items):
                        raise RuntimeError("E_TOOLSTUDY_TEMPLATE_MISMATCH")
                    ids = engine.tokenize(rendered, special=True)
                    evaluator.save(folder / (name + ".json"), {"messages": items, "rendered_prompt": rendered,
                                   "input_token_ids": ids, "reserved_output_tokens": generation["max_output_tokens"]})
                    return len(ids)

                initial_tokens = count_request(prompts.messages(initial), "INITIAL")
                answer_ids = engine.tokenize(answer_text)
                # Check the independent pinned tokenizer against the owned
                # server on EVERY complete reference response, not estimates.
                argv = [tokenizer, "--model", model, "--stdin", "--ids", "--offline", "--no-bos"]
                proc = subprocess.run(argv, input=answer_text.encode(), capture_output=True, timeout=30, check=True)
                cli_ids = ast.literal_eval(proc.stdout.decode())
                evaluator.save(folder / "REFERENCE_TOKENS.json", {"argv": argv, "server_token_ids": answer_ids,
                               "cli_token_ids": cli_ids, "stderr": proc.stderr.decode(), "model_generation_requests": 0})
                if cli_ids != answer_ids:
                    raise RuntimeError("E_TOOLSTUDY_TOKENIZER_MISMATCH")
                repair, repair_receipt = budget.repair_messages(initial, noop_text, noop_result["feedback"],
                                                                engine.tokenize, cfg["history"])
                evaluator.save(folder / "REPAIR_BUDGET.json", repair_receipt)
                repair_tokens = [count_request(repair, "REPAIR_" + str(index)) for index in (2, 3)]
                # Correct-answer histories are capacity controls only. They
                # are never used in qualification/main generation messages.
                reference_history, reference_receipt = budget.repair_messages(initial, answer_text, noop_result["feedback"],
                                                                               engine.tokenize, cfg["history"])
                evaluator.save(folder / "REFERENCE_HISTORY_BUDGET.json", reference_receipt)
                reference_history_tokens = count_request(reference_history, "REFERENCE_HISTORY")
                framing = engine.tokenize(prompts.REPAIR)
                reserved = generation["max_output_tokens"]
                hard_bound = (initial_tokens + cfg["history"]["previous_response_tokens"] + cfg["history"]["feedback_tokens"]
                              + cfg["history"]["framing_reserve_tokens"] + reserved)
                fits = (len(answer_ids) <= reserved and len(framing) + 32 <= cfg["history"]["framing_reserve_tokens"]
                        and max(initial_tokens, *repair_tokens, reference_history_tokens) + reserved <= generation["context_tokens"]
                        and hard_bound <= generation["context_tokens"])
                row = {"id": key, "stage": stage, "task": task["id"], "arm": arm,
                       "reference_passed_all_gates": reference_passed, "reference_is_model_answer": False,
                       "reference_response_sha256": hashlib.sha256(answer_text.encode()).hexdigest(),
                       "initial_input_tokens": initial_tokens, "complete_reference_output_tokens": len(answer_ids),
                       "repair_input_tokens": repair_tokens, "reference_history_input_tokens": reference_history_tokens,
                       "initial_plus_output_reserve": initial_tokens + reserved,
                       "max_observed_repair_plus_output_reserve": max(*repair_tokens, reference_history_tokens) + reserved,
                       "allocated_worst_repair_plus_output_reserve": hard_bound,
                       "actual_complete_requests_always_rechecked": True, "capacity_passed": fits,
                       "tokenizer_ids_match": cli_ids == answer_ids, "template_exact_match": True,
                       "passed": reference_passed and fits, "wall_ns": time.monotonic_ns() - before}
                rows.append(row)
                print(json.dumps(row), flush=True)
        result["complete"] = len(rows) == 19 and all(row["passed"] for row in rows)
    except Exception as exc:
        result["error"] = {"type": type(exc).__name__, "message": str(exc)}
    finally:
        if engine is not None:
            try:
                result["engine_identity_after"] = engine.verify_final_identity()
            finally:
                engine.close()
            result["engine_exited"] = engine.process.poll() is not None
            result["model_requests"] = engine.generation_count
            evaluator.save(root / "TOKENIZER_SERVICE_CALLS.json", engine.service_calls)
        result["source_unchanged"] = support.bindings() == source
        result["tools_unchanged"] = all(file_identity(value["path"]) == value for value in tools.values())
        result["model_unchanged"] = file_identity(model) == chosen["file"]
        result["experiment_wall_ns"] = time.monotonic_ns() - started
        result["complete"] = bool(result["complete"] and result.get("engine_exited") and result["model_requests"] == 0
                                  and all(result[key] for key in ("source_unchanged", "tools_unchanged", "model_unchanged")))
        evaluator.save(root / "CAPACITY.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("output", "binary", "tokenizer", "model", "clang", "rustc"):
        parser.add_argument("--" + name, required=True)
    result = run(**vars(parser.parse_args()))
    print(json.dumps({"complete": result["complete"], "rows": len(result["rows"]), "model_requests": result["model_requests"], "error": result.get("error")}))
    return 0 if result["complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
