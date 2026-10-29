"""Read-only review of retained V10 capacity; imports no experiment modules."""
from pathlib import Path
from hashlib import sha256
from collections import Counter
from datetime import datetime, timezone
import ast
import json
import subprocess
import sys

FROZEN = "11d6f78c6c01f66978af7fcf4d40eea7dae5d5f0"
FROZEN_TREE = "66ff2c9ff5292be55791b9f1a184a7f64bc3942f"
MODEL_SHA = "3605803b982cb64aead44f6c1b2ae36e3acdb41d8e46c8a94c6533bc4c67e597"
TEMPLATE_SHA = "a62ff0a2472a0fa1b8eaabcb57c59b58afa42a22831dc141400b6e0cf2b65ce3"
SOURCE = Path("/tmp/hepta-next-agent-toolstudy-v10-20261029")
OLD_CAPACITY = Path("/tmp/hepta-next-agent-v9-capacity-01")
PROFILE = "experiments/hia_agent_toolstudy_v10_20261029"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(data):
    return sha256(data).hexdigest()


def file_identity(path):
    path = Path(path).resolve(strict=True)
    before = path.stat()
    h = sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    after = path.stat()
    assert (before.st_size, before.st_mtime_ns) == (after.st_size, after.st_mtime_ns), str(path)
    return {"path": str(path), "bytes": before.st_size, "sha256": h.hexdigest()}


def git(*args):
    return subprocess.check_output(["git", *args], cwd=SOURCE)


def main():
    caproot, output = (Path(arg).resolve() for arg in sys.argv[1:])
    output.mkdir(parents=True, exist_ok=False)
    read_files = {}
    identities = {}
    result = {
        "schema": "hepta.agent.v10.independent-capacity-review.v1",
        "reviewed_at": datetime.now(timezone.utc).isoformat(),
        "source_commit": FROZEN, "source_tree": FROZEN_TREE,
        "capacity_directory": str(caproot),
        "reviewer_script_sha256": file_identity(__file__)["sha256"],
        "decision": "HOLD qualification and main pending successful complete independent review",
        "model_requests": 0, "tokenizer_invocations": 0,
        "native_executions": 0, "tests_rerun": 0, "production_module_imports": 0,
        "review_complete": False,
    }

    def read_json(path):
        path = Path(path)
        data = path.read_bytes()
        read_files[str(path)] = {"bytes": len(data), "sha256": digest(data)}
        return json.loads(data)

    def checked_identity(record):
        key = record["path"]
        if key not in identities:
            identities[key] = file_identity(key)
        assert identities[key] == record, key

    def check_native(value):
        assert value["status"] == "correct"
        assert all(value[k] is True for k in ("artifact_unchanged", "native_executed", "resource_contract_passed", "vm_contract_passed"))
        assert value["execution"]["returncode"] == 0 and value["execution"]["timeout"] is False
        parsed = [[int(part) for part in line.split()] for line in value["execution"]["stdout"].splitlines()]
        assert parsed == value["observations"]
        assert len(parsed) == len(value["expected"])
        assert [row[:2] for row in parsed] == value["expected"]
        return len(parsed)

    def check_cli(path, text, expected_ids, special):
        record = read_json(path)
        assert record["input_sha256"] == digest(text.encode())
        assert record["input_utf8_bytes"] == len(text.encode())
        assert record["returncode"] == 0 and record["matched"] is True
        assert record["server_add_special"] is special and record["server_parse_special"] is True
        assert record["model_generation_requests"] == 0
        ids = ast.literal_eval(record["stdout"])
        assert type(ids) is list and all(type(item) is int and item >= 0 for item in ids)
        assert ids == record["cli_token_ids"] == record["server_token_ids"] == expected_ids
        argv = record["argv"]
        assert Path(argv[0]).resolve() == Path(cap["tools"]["tokenizer"]["path"])
        assert argv[1:] == ["--model", cap["model"]["file"]["path"], "--stdin", "--ids", "--offline", "--no-escape"] + ([] if special else ["--no-bos"])
        assert type(record["wall_ns"]) is int and record["wall_ns"] >= 0
        return record

    try:
        assert git("rev-parse", "HEAD").decode().strip() == FROZEN
        assert git("rev-parse", "HEAD^{tree}").decode().strip() == FROZEN_TREE
        assert not git("status", "--porcelain", "--untracked-files=no").strip()
        cap = read_json(caproot / "CAPACITY.json")
        plan = read_json(caproot / "PLAN.json")
        cfg = read_json(SOURCE / PROFILE / "PROTOCOL.json")
        result["capacity_sha256"] = read_files[str(caproot / "CAPACITY.json")]["sha256"]
        assert cap["schema"] == "hepta.agent.tool-capacity.v10"
        assert cap["source_commit"] == FROZEN
        assert cap["complete"] and all(cap[k] is True for k in ("source_unchanged", "model_unchanged", "tools_unchanged", "engine_exited"))
        assert cap["model_requests"] == 0 and cap["references_are_agent_successes"] is False
        assert cap["protocol_sha256"] == digest((SOURCE / PROFILE / "PROTOCOL.json").read_bytes())
        for key in plan:
            assert plan[key] == cap[key], key
        source_checks = []
        for name, expected in sorted(cap["source_bindings"].items()):
            assert digest((SOURCE / name).read_bytes()) == expected
            assert digest(git("show", FROZEN + ":" + name)) == expected
            assert digest((caproot / "source_snapshot" / name).read_bytes()) == expected
            source_checks.append({"path": name, "sha256": expected})
        assert len(source_checks) == 185
        result["sources_checked_against_current_git_and_snapshot"] = source_checks
        for value in cap["tools"].values():
            checked_identity(value)
        checked_identity(cap["model"]["file"])
        assert cap["model"]["file"]["sha256"] == MODEL_SHA
        assert cap["model"]["file"]["bytes"] == 2497281120
        assert all(cap["model"][key] == value for key, value in cfg["model"].items())
        engine = read_json(caproot / "tokenizer-runtime/identity.json")
        after = read_json(caproot / "tokenizer-runtime/identity-after.json")
        assert after == cap["engine_identity_after"]
        assert after["model_unchanged"] and after["runtime_unchanged"]
        assert engine["model"] == after["model"] == cap["model"]["file"]
        assert engine["runtime_files"] == after["runtime_files"]
        for value in after["runtime_files"]:
            checked_identity(value)
        assert engine["threads"] == cfg["generation"]["threads"] == 4
        assert engine["context"] == cfg["generation"]["context_tokens"] == 8192
        template_cfg_path = SOURCE / PROFILE / "provenance/Qwen__Qwen3-4B-Instruct-2507__tokenizer_config.json"
        assert file_identity(template_cfg_path)["sha256"] == TEMPLATE_SHA
        template_cfg = read_json(template_cfg_path)
        result["official_template_sha256"] = digest(template_cfg["chat_template"].encode())
        result["embedded_server_template_sha256"] = digest(engine["properties"]["chat_template"].encode())
        assert engine["official_plain_template"]["config_sha256"] == TEMPLATE_SHA
        assert engine["official_plain_template"]["chat_template_sha256"] == result["official_template_sha256"]
        pid_path = Path("/proc") / str(engine["pid"])
        alive = pid_path.exists()
        same_owned_process = alive and cap["model"]["file"]["path"].encode() in (pid_path / "cmdline").read_bytes().split(b"\0")
        assert not same_owned_process
        result["owned_model_process_observed_alive_at_review"] = bool(same_owned_process)
        result["producer_pid_present_at_review"] = alive
        assert not list((caproot / "tokenizer-runtime").glob("transport-*"))
        calls = read_json(caproot / "TOKENIZER_SERVICE_CALLS.json")
        counts = Counter(call["endpoint"] for call in calls)
        assert set(counts) <= {"/health", "/props", "/apply-template", "/tokenize"}
        assert counts["/apply-template"] == 76
        assert all(call["success"] is True for call in calls if call["endpoint"] != "/health")
        result["recorded_service_call_counts"] = dict(counts)
        result["recorded_startup_health_not_ready"] = sum(call["success"] is False for call in calls if call["endpoint"] == "/health")
        expected_ids = ["calibration/" + task + "/calibration" for task in cfg["qualification"]["tasks"]]
        for index, task in enumerate(cfg["tasks"]):
            arms = cfg["arms"]
            expected_ids.extend("main/" + task + "/" + arm for arm in arms[index % 4:] + arms[:index % 4])
        assert [row["id"] for row in cap["rows"]] == expected_ids
        assert len(set(expected_ids)) == 19
        repair_ast = ast.parse((SOURCE / "experiments/hia_agent_toolstudy_v8_20261029/prompts.py").read_text())
        repair_text = next(ast.literal_eval(node.value) for node in repair_ast.body if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "REPAIR" for target in node.targets))
        reviewed_rows = []
        cli_total_ns = public_cases = hidden_cases = object_count = core_count = 0
        template_index = 0
        cli_paths = []
        for row in cap["rows"]:
            folder = caproot / row["id"]
            old_folder = OLD_CAPACITY / row["id"]
            query = read_json(folder / "QUERY.json")
            assert query == read_json(old_folder / "QUERY.json")
            reference = read_json(folder / "REFERENCE.json")
            assert reference == read_json(old_folder / "REFERENCE.json")
            assert reference["model_answer"] is False
            answer = canonical(reference["response"]).decode()
            assert digest(answer.encode()) == row["reference_response_sha256"]
            original_noop_text = read_json(old_folder / "REPAIR_2.json")["messages"][1]["content"]
            noop = read_json(folder / "public_noop/STUDY_EVALUATION.json")
            assert noop["accepted"] is False and noop["status"] != "infrastructure_failure"
            assert noop["before_revision"] == noop["after_revision"] == query["source_revision"]
            evaluated = read_json(folder / "reference/STUDY_EVALUATION.json")
            assert evaluated["accepted"] is True and evaluated["status"] == "correct"
            assert evaluated["before_revision"] == query["source_revision"]
            built = evaluated["build"]
            assert built["native_built"] is True and built["status"] == "compiled"
            checked_identity(built["artifact"])
            assert Path(built["artifact"]["path"]).is_relative_to(caproot)
            assert Path(built["artifact"]["path"]).read_bytes()[:4] == b"\x7fELF"
            public_cases += check_native(evaluated["public"])
            hidden_cases += check_native(read_json(folder / "REFERENCE_HIDDEN.json"))
            if built["language"] == "hia":
                obj = built["native_compile"]
                assert obj["ok"] is True and obj["core_sha256"] == built["core_sha256"]
                assert obj["input_sha256"] == built["core_sha256"]
                assert file_identity(obj["output"])["sha256"] == obj["artifact_sha256"]
                assert Path(obj["output"]).stat().st_size == obj["artifact_bytes"]
                assert file_identity(built["core_path"])["sha256"] == built["core_sha256"]
                object_count += 1
                core_count += 1
            initial = read_json(folder / "INITIAL.json")
            assert initial["messages"] == read_json(old_folder / "INITIAL.json")["messages"]
            assert len(initial["messages"]) == 1 and initial["messages"][0]["role"] == "user"
            initial_text = initial["messages"][0]["content"]
            assert digest(initial_text.encode()) == cap["prompt_bindings"][row["id"]]["prompt_sha256"]
            assert query["query_sha256"] == cap["prompt_bindings"][row["id"]]["query_sha256"]
            answer_cli = read_json(folder / "REFERENCE_TOKENS.json")
            answer_ids = answer_cli["server_token_ids"]
            receipt = check_cli(folder / "REFERENCE_TOKENS.json", answer, answer_ids, False)
            cli_total_ns += receipt["wall_ns"]
            cli_paths.append(folder / "REFERENCE_TOKENS.json")
            assert len(answer_ids) == row["complete_reference_output_tokens"] <= 1536
            lengths = []
            for name in ("INITIAL", "REPAIR_2", "REPAIR_3", "REFERENCE_HISTORY"):
                rendered = read_json(folder / (name + ".json"))
                items = rendered["messages"]
                assert all(set(item) == {"role", "content"} and item["role"] in ("user", "assistant") and type(item["content"]) is str for item in items)
                expected_render = "".join("<|im_start|>" + item["role"] + "\n" + item["content"] + "<|im_end|>\n" for item in items) + "<|im_start|>assistant\n"
                assert rendered["rendered_prompt"] == expected_render
                assert rendered["reserved_output_tokens"] == 1536
                if name != "INITIAL":
                    budget_name = "REFERENCE_HISTORY_BUDGET" if name == "REFERENCE_HISTORY" else "REPAIR_BUDGET"
                    budget = read_json(folder / (budget_name + ".json"))
                    assert budget["previous_code_truncated"] is False and budget["public_cases_removed"] is False
                    assert budget["previous_response_tokens"] <= cfg["history"]["previous_response_tokens"]
                    assert budget["feedback_tokens"] <= cfg["history"]["feedback_tokens"]
                    assert items[0] == initial["messages"][0]
                    assert items[1]["role"] == "assistant" and items[2]["role"] == "user" and len(items) == 3
                    assert items[1]["content"] == (answer if name == "REFERENCE_HISTORY" else original_noop_text)
                    if name == "REFERENCE_HISTORY":
                        assert budget["previous_response_tokens"] == len(answer_ids)
                    bounded = budget["feedback"]
                    for key, value in noop["feedback"].items():
                        if key != "diagnostic":
                            assert bounded[key] == value
                    diagnostic = noop["feedback"].get("diagnostic", "")
                    diagnostic_text = diagnostic if type(diagnostic) is str else canonical(diagnostic).decode()
                    assert bounded["diagnostic_original_sha256"] == digest(diagnostic_text.encode())
                    assert bounded["diagnostic_original_characters"] == len(diagnostic_text)
                    if bounded["diagnostic_clipped"] is False:
                        assert bounded["diagnostic"] == diagnostic_text
                    else:
                        prefixes = []
                        while diagnostic_text:
                            diagnostic_text = diagnostic_text[:len(diagnostic_text) // 2]
                            prefixes.append(diagnostic_text)
                        assert bounded["diagnostic"] in prefixes
                    assert items[2]["content"] == repair_text + canonical(budget["feedback"]).decode()
                ids = rendered["input_token_ids"]
                assert len(ids) + 1536 <= 8192
                receipt = check_cli(folder / (name + ".cli.json"), expected_render, ids, True)
                cli_total_ns += receipt["wall_ns"]
                cli_paths.append(folder / (name + ".cli.json"))
                lengths.append(len(ids))
                template_index += 1
                check = read_json(caproot / "tokenizer-runtime" / ("template-" + str(template_index).zfill(3) + ".json"))
                assert check["matched"] is True and check["request"] == {"messages": items}
                assert check["observed_response"]["prompt"] == check["expected_prompt"] == expected_render
                assert check["messages_or_answers_rewritten"] is False and check["model_generation_requested_by_this_check"] is False
                assert check["official_template"] == {"config_sha256": TEMPLATE_SHA, "config_bytes": 9377}
            assert read_json(folder / "REPAIR_2.json")["messages"] == read_json(folder / "REPAIR_3.json")["messages"]
            assert lengths[0] == row["initial_input_tokens"]
            assert lengths[1:3] == row["repair_input_tokens"]
            assert lengths[3] == row["reference_history_input_tokens"]
            assert lengths[0] + 1536 == row["initial_plus_output_reserve"]
            assert max(lengths[1:]) + 1536 == row["max_observed_repair_plus_output_reserve"]
            envelope = lengths[0] + 1664 + 1024 + 256 + 1536
            assert envelope == row["allocated_worst_repair_plus_output_reserve"] <= 8192
            assert all(row[key] is True for key in ("reference_passed_all_gates", "capacity_passed", "tokenizer_ids_match", "template_exact_match", "all_rendered_request_cli_ids_match", "actual_complete_requests_always_rechecked", "passed"))
            assert row["reference_is_model_answer"] is False and row["rendered_request_cli_checks"] == 4
            reviewed_rows.append({"id": row["id"], "query_unchanged_from_v9": True, "initial_messages_unchanged_from_v9": True, "reference_unchanged_from_v9": True, "actual_cli_checks": 5, "native_artifact_sha256": built["artifact"]["sha256"], "max_observed_request_plus_output": max(lengths) + 1536})
        assert len(cli_paths) == len(set(cli_paths)) == 95
        assert len(list((caproot / "tokenizer-runtime").glob("template-*.json"))) == template_index == 76
        independent = cap["independent_cli_tokenizer"]
        assert independent["calls"] == 95 and independent["all_matched"] is True and independent["model_generation_requests"] == 0
        assert cli_total_ns == independent["wall_ns"]
        actual_cli = sorted((file_identity(path) for path in cli_paths), key=lambda record: record["path"])
        assert actual_cli == independent["receipts"]
        assert len(reviewed_rows) == 19 and object_count == core_count == 8
        assert public_cases == 54 and hidden_cases == 472
        result.update(review_complete=True,
            decision="ALLOW fresh V10 qualification only on the reviewed unchanged frozen source/model/tools; main still requires its fresh 3/3 result and separate gate",
            reviewed_rows=reviewed_rows, reference_controls=19, actual_cli_controls=95,
            exact_template_controls=76, public_case_observations=public_cases,
            terminal_hidden_case_observations=hidden_cases, native_artifacts=19,
            hia_objects=object_count, hia_cores=core_count,
            capacity_wall_ns=cap["experiment_wall_ns"], independent_cli_wall_ns=cli_total_ns,
            max_initial_prompt_tokens=max(row["initial_input_tokens"] for row in cap["rows"]),
            max_complete_reference_output_tokens=max(row["complete_reference_output_tokens"] for row in cap["rows"]),
            max_observed_repair_plus_output_reserve=max(row["max_observed_repair_plus_output_reserve"] for row in cap["rows"]),
            max_registered_allocation_plus_output=max(row["allocated_worst_repair_plus_output_reserve"] for row in cap["rows"]),
            boundary="Retained original producer observations plus independent byte/identity/accounting review; no new native execution, tokenizer or model result, physical host attestation, general safety theorem or efficiency claim.")
    except Exception as exc:
        result["error"] = {"type": type(exc).__name__, "message": str(exc)}
        raise
    finally:
        result["read_json_files"] = read_files
        result["independently_rehashed_file_identities"] = list(identities.values())
        (output / "REVIEW.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps({key: result[key] for key in ("review_complete", "decision", "model_requests", "tokenizer_invocations", "native_executions")}))


if __name__ == "__main__":
    main()
