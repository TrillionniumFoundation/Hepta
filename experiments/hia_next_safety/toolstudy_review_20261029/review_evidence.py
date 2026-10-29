#!/usr/bin/env python3
"""Read-only integrity audit of the real-node study's registered controls.

This independent receipt audit imports only the standard library. It does not
run the study, production editors, tests, a tokenizer, compiler, VM, or model.
Recorded tokenizer/native results remain producer observations. Their hashes,
source attribution, counts, and internal consistency are checked here.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import time


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def identity(path):
    path = Path(path)
    data = path.read_bytes()
    return {"path": str(path), "bytes": len(data), "sha256": sha(data)}


def read(path):
    return json.loads(Path(path).read_bytes())


def require(condition, label):
    if not condition:
        raise ValueError("E_INDEPENDENT_TOOLSTUDY_REVIEW: " + label)


def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args])


def qwen_template(messages):
    return ("<|im_start|>system\nYou are Qwen, created by Alibaba Cloud. You are a helpful assistant.<|im_end|>\n"
            + "".join("<|im_start|>" + item["role"] + "\n" + item["content"] + "<|im_end|>\n"
                      for item in messages)
            + "<|im_start|>assistant\n")


def run(args):
    started = time.monotonic_ns()
    root, capacity_path, tests_path = Path(args.source), Path(args.capacity), Path(args.tests)
    directory = capacity_path.parent
    capacity, tests = read(capacity_path), read(tests_path)
    expected_commit = args.commit
    require(git(root, "rev-parse", "HEAD").decode().strip() == expected_commit, "current frozen commit")
    require(not git(root, "status", "--porcelain", "--untracked-files=no").strip(), "clean tracked source")
    require(capacity["source_commit"] == tests["source_commit"] == expected_commit, "producer source attribution")
    require(capacity["source_bindings"] == tests["source_bindings"], "same tests/capacity dependency identities")
    require(capacity["source_unchanged"] is True and tests["source_unchanged"] is True, "producer stable source")
    dependencies = capacity["source_bindings"]
    for name, digest in dependencies.items():
        require(sha(git(root, "show", expected_commit + ":" + name)) == digest, "Git blob " + name)
        require(sha((root / name).read_bytes()) == digest, "working source " + name)
        require(sha((directory / "source_snapshot" / name).read_bytes()) == digest, "retained source " + name)
    log = identity(args.log)
    require(log["sha256"] == tests["log_sha256"] and log["bytes"] == tests["log_bytes"], "static test log")
    log_text = Path(args.log).read_text()
    match = re.search(r"Ran (\d+) tests in [^\n]+\n\nOK\s*$", log_text)
    require(match is not None and int(match[1]) == 34, "34 tests and final OK")
    require(tests["returncode"] == 0 and tests["model_requests"] == 0, "static producer result")
    study = "experiments/hia_agent_toolstudy_v8_20261029/"
    cfg = read(root / study / "PROTOCOL.json")
    require(sha((root / study / "PROTOCOL.json").read_bytes()) == capacity["protocol_sha256"], "protocol hash")
    require(capacity["schema"] == "hepta.agent.tool-capacity.v8", "capacity schema")
    require(all(capacity[key] is True for key in ("complete", "tools_unchanged", "model_unchanged", "engine_exited")), "producer completion gates")
    require(capacity["model_requests"] == 0, "no capacity generation")
    require(not list((directory / "tokenizer-runtime").glob("transport-*.request.json")), "no retained generation request")
    require(all(capacity["engine_identity_after"][key] is True for key in ("model_unchanged", "runtime_unchanged")), "owned runtime final producer identity")
    companions = {name: value for name, value in capacity["tools"].items() if name.startswith("runtime_companion:")}
    require(bool(companions), "companion runtime libraries bound")
    require(capacity["model"]["sha256"] == cfg["model"]["sha256"], "registered model digest")

    qualification = ["json_scalar_reasoning", "two_file_signature_repair", "owner_flow_repair"]
    main = ["saturating_score", "wide_span_upgrade", "owned_byte_return", "owner_pair_replace"]
    arms = ["hia_full", "hia_node", "rust_full", "rust_node"]
    require(cfg["qualification"]["tasks"] == qualification and cfg["tasks"] == main and cfg["arms"] == arms, "registered cells")
    expected_ids = ["calibration/" + task + "/calibration" for task in qualification]
    for index, task in enumerate(main):
        expected_ids.extend("main/" + task + "/" + arm for arm in arms[index:] + arms[:index])
    require([row["id"] for row in capacity["rows"]] == expected_ids, "complete fixed ordered 19 controls")
    require(set(capacity["prompt_bindings"]) == set(expected_ids), "all prompt identities")
    context, reserve = cfg["generation"]["context_tokens"], cfg["generation"]["max_output_tokens"]
    require((context, reserve, cfg["generation"]["attempts_per_cell"]) == (8192, 1536, 3), "fixed shared budgets")
    artifacts, files, rows = [], {}, []
    for row in capacity["rows"]:
        key = row["id"]
        folder = directory / key
        require(all(row[name] is True for name in ("passed", "reference_passed_all_gates", "capacity_passed", "template_exact_match", "tokenizer_ids_match")), key + " control gates")
        require(row["reference_is_model_answer"] is False, key + " reference attribution")
        source_query = read(folder / "QUERY.json")
        query_unsigned = {k: v for k, v in source_query.items() if k != "query_sha256"}
        require(sha(canonical(query_unsigned)) == source_query["query_sha256"], key + " query digest")
        binding = capacity["prompt_bindings"][key]
        require(source_query["query_sha256"] == binding["query_sha256"] and source_query["source_revision"] == binding["source_revision"], key + " query/source binding")
        reference = read(folder / "REFERENCE.json")
        answer = canonical(reference["response"]).decode()
        require(reference["model_answer"] is False and sha(answer.encode()) == row["reference_response_sha256"], key + " exact complete reference")
        tokens = read(folder / "REFERENCE_TOKENS.json")
        require(tokens["server_token_ids"] == tokens["cli_token_ids"], key + " independent tokenizer recorded ID agreement")
        require(all(type(token) is int and 0 <= token < 2**31 for token in tokens["server_token_ids"]), key + " valid reference IDs")
        require(len(tokens["server_token_ids"]) == row["complete_reference_output_tokens"] <= reserve, key + " complete reference token count")
        require(tokens["model_generation_requests"] == 0, key + " tokenizer only")
        counts = {}
        for name in ("INITIAL", "REPAIR_2", "REPAIR_3", "REFERENCE_HISTORY"):
            record = read(folder / (name + ".json"))
            require(record["rendered_prompt"] == qwen_template(record["messages"]), key + " template " + name)
            ids = record["input_token_ids"]
            require(all(type(token) is int and 0 <= token < 2**31 for token in ids), key + " valid prompt IDs")
            require(record["reserved_output_tokens"] == reserve and len(ids) + reserve <= context, key + " actual recorded request capacity")
            require(sha(record["messages"][0]["content"].encode()) == binding["prompt_sha256"], key + " initial prompt binding")
            if name == "REFERENCE_HISTORY":
                require(record["messages"][1]["content"] == answer, key + " complete reference history")
            counts[name] = len(ids)
            files[str(folder / (name + ".json"))] = identity(folder / (name + ".json"))
        require(counts["INITIAL"] == row["initial_input_tokens"], key + " initial count")
        require([counts["REPAIR_2"], counts["REPAIR_3"]] == row["repair_input_tokens"], key + " repair counts")
        require(counts["REFERENCE_HISTORY"] == row["reference_history_input_tokens"], key + " reference history count")
        actual_max = max(counts[name] for name in ("REPAIR_2", "REPAIR_3", "REFERENCE_HISTORY")) + reserve
        allocation = counts["INITIAL"] + sum(cfg["history"][name] for name in ("previous_response_tokens", "feedback_tokens", "framing_reserve_tokens")) + reserve
        require(actual_max == row["max_observed_repair_plus_output_reserve"], key + " observed capacity calculation")
        require(allocation == row["allocated_worst_repair_plus_output_reserve"] <= context, key + " registered allocation calculation")
        noop = read(folder / "public_noop" / "STUDY_EVALUATION.json")
        admitted = read(folder / "reference" / "STUDY_EVALUATION.json")
        hidden = read(folder / "REFERENCE_HIDDEN.json")
        require(noop["accepted"] is False and noop["before_revision"] == noop["after_revision"] == binding["source_revision"], key + " rejected no-op did not change source")
        require(admitted["accepted"] is True and admitted["hidden_evaluated"] is False, key + " public admission only")
        require(admitted["build"]["status"] == "compiled" and admitted["build"]["native_built"] is True, key + " actual reference compilation")
        for observation in (admitted["public"], hidden):
            require(observation["status"] == "correct" and all(observation[name] is True for name in ("native_executed", "artifact_unchanged", "resource_contract_passed", "vm_contract_passed")), key + " public and separate terminal hidden observation")
        artifact = admitted["build"]["artifact"]
        actual_artifact = identity(artifact["path"])
        require(actual_artifact == artifact, key + " retained actual native artifact")
        artifacts.append(actual_artifact)
        for relative in ("QUERY.json", "REFERENCE.json", "REFERENCE_TOKENS.json", "REPAIR_BUDGET.json", "REFERENCE_HISTORY_BUDGET.json", "public_noop/STUDY_EVALUATION.json", "reference/STUDY_EVALUATION.json", "REFERENCE_HIDDEN.json"):
            files[str(folder / relative)] = identity(folder / relative)
        rows.append({"id": key, "initial_tokens": counts["INITIAL"], "reference_output_tokens": len(tokens["server_token_ids"]), "observed_repair_plus_reserve": actual_max, "allocated_repair_plus_reserve": allocation, "reference_gate_observations": "producer public/native/resource and separate terminal hidden all passed"})

    preserved_prefixes = ("experiments/hia_agent_factorial_v4_", "experiments/hia_agent_factorial_v5_", "experiments/hia_agent_factorial_v6_", "experiments/hia_agent_structured_v7_")
    preserved = [name for name in dependencies if name.startswith(preserved_prefixes)]
    for name in preserved:
        require(git(root, "show", "677a15928c1dd3b236c7bee8cf4b3e6041177f6c:" + name) == git(root, "show", expected_commit + ":" + name), "immutable historical implementation " + name)
    result = {"schema": "hepta.agent.toolstudy.independent-method-review.v1", "source_commit": expected_commit,
              "source_tree": git(root, "rev-parse", expected_commit + "^{tree}").decode().strip(),
              "source_dependencies_checked": len(dependencies), "historical_files_preserved": preserved,
              "static_tests": {"producer_count": 34, "producer_receipt": identity(tests_path), "producer_log": log, "reviewer_reran_tests": False},
              "capacity": {"producer_receipt": identity(capacity_path), "rows": rows, "generation_requests": 0,
                           "maximum_initial_tokens": max(row["initial_tokens"] for row in rows),
                           "maximum_reference_output_tokens": max(row["reference_output_tokens"] for row in rows),
                           "maximum_observed_repair_plus_reserve": max(row["observed_repair_plus_reserve"] for row in rows),
                           "maximum_allocated_repair_plus_reserve": max(row["allocated_repair_plus_reserve"] for row in rows)},
              "companion_runtime_identities": companions, "native_artifacts_hashed": artifacts,
              "retained_evidence": files, "reviewer_model_requests": 0, "reviewer_native_or_vm_executions": 0,
              "reviewer_tokenizer_invocations": 0, "qualification_or_main_success_asserted": False,
              "limitations": ["Producer observations are checked for attribution and consistency, not independently rerun.",
                              "Token allocation is not a theorem for arbitrary generated text. Exact runtime checks can end a cell as a recorded budget failure.",
                              "Three submissions is a maximum, not a guarantee under timeout or history/context overflow.",
                              "Tracked runtime companion bytes are not an attestation of all system libraries, process state, hardware, or user dot.",
                              "No productivity, general language safety, or long-term maintenance advantage is established by these controls."],
              "audit_wall_ns": time.monotonic_ns() - started}
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=False)
    (output / "REVIEW.json").write_bytes(canonical(result) + b"\n")
    for source, name in ((capacity_path, "PRODUCER_CAPACITY.json"), (tests_path, "PRODUCER_STATIC_TESTS.json"), (Path(args.log), "PRODUCER_STATIC_TESTS.log")):
        (output / name).write_bytes(source.read_bytes())
    print(json.dumps({"source": expected_commit, "dependencies": len(dependencies), "capacity_rows": len(rows), "static_tests": 34, "maximum_reference_tokens": result["capacity"]["maximum_reference_output_tokens"], "maximum_observed_repair_plus_reserve": result["capacity"]["maximum_observed_repair_plus_reserve"], "reviewer_generation_requests": 0}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "commit", "capacity", "tests", "log", "output"):
        parser.add_argument("--" + name, required=True)
    run(parser.parse_args())
