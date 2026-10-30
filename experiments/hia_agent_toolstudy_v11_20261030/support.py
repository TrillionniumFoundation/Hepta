"""Registered source, task and tool identities; no reference-answer import."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys

from experiments.hia_agent_factorial_v4_20261028 import calibration, fixtures
from experiments.hia_agent_structured_v7_20261029.session import ValidatedTaskSession
from experiments.hia_agent_toolstudy_v11_20261030 import prompts
from tools.provider_adapter.llama_cpp_engine import canonical, file_identity

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent

PINNED_MODEL = {"bytes":2740937888,"filename":"Qwen3.5-4B-Q4_K_M.gguf","id":"qwen35_4b_unsloth_q4_k_m","repository":"unsloth/Qwen3.5-4B-GGUF","revision":"e87f176479d0855a907a41277aca2f8ee7a09523","sha256":"00fe7986ff5f6b463e62455821146049db6f9313603938a70800d1fb69ef11a4"}
PINNED_TEMPLATE = {"repository":"Qwen/Qwen3.5-4B","revision":"851bf6e806efd8d0a36b00ddf55e13ccb7b8cd0a","file":"tokenizer_config.json","bytes":16710,"sha256":"316230d6a809701f4db5ea8f8fc862bc3a6f3229c937c174e674ff3ca0a64ac8","local_file":"provenance/Qwen__Qwen3.5-4B__tokenizer_config.json"}


def protocol():
    value = json.loads((HERE / "PROTOCOL.json").read_text())
    old = json.loads((ROOT / "experiments/hia_agent_toolstudy_v9_20261029/PROTOCOL.json").read_text())
    # This revision changes only one pinned model and its template, not the task/tool experiment.
    for key in ("runtime", "arms", "tasks", "generation", "history", "budget",
                "rust_conversion_profile", "hidden_seed", "hidden_random_cases_per_task", "decoder", "cell_order",
                "advantage_gate", "capacity_gate", "public_feedback", "rollback", "tool_scope", "timeout"):
        if value[key] != old[key]:
            raise ValueError("E_TOOLSTUDY_V11_UNAUTHORIZED_CONDITION_CHANGE: " + key)
    for key in ("arm", "tasks", "main_forbidden_without_qualification", "reference_controls_are_qualification_successes"):
        if value["qualification"][key] != old["qualification"][key]:
            raise ValueError("E_TOOLSTUDY_V11_QUALIFICATION_CHANGE: " + key)
    if value["model"] != PINNED_MODEL or value["official_template"] != PINNED_TEMPLATE:
        raise ValueError("E_TOOLSTUDY_V11_MODEL_OR_TEMPLATE_CHANGE")
    if (value["model_template_options"]["chat_template_kwargs"] != {"enable_thinking": False}
            or any(value["model_template_options"][key] is not False
                   for key in ("system_message_added", "task_messages_changed", "answer_repair"))):
        raise ValueError("E_TOOLSTUDY_V11_TEMPLATE_OPTIONS")
    for name, expected in value["model_provenance"]["files"].items():
        if file_identity(HERE / name)["sha256"] != expected:
            raise ValueError("E_TOOLSTUDY_V11_PROVENANCE_BYTES")
    prompts.official_template_binding()
    inherited = json.loads((fixtures.HERE / "PROTOCOL.json").read_text())
    for key in ("hidden_seed", "hidden_random_cases_per_task"):
        if value[key] != inherited[key]:
            raise ValueError("E_TOOLSTUDY_FIXTURE_PROTOCOL")
    return value


def policy(task):
    return "migrate" if task["id"] in {"two_file_signature_repair", "wide_span_upgrade"} else "preserve"


def language_interface(arm):
    return ("rust", "node") if arm == "calibration" else tuple(arm.split("_"))


def session_for(task, arm, clang="unused", rustc="unused"):
    language, _ = language_interface(arm)
    return ValidatedTaskSession(task, language, clang=clang, rustc=rustc, interface_policy=policy(task))


def cells(stage):
    if stage == "calibration":
        return [(task, "calibration") for task in calibration.problems()]
    if stage != "main":
        raise ValueError("registered stage required")
    arms = protocol()["arms"]
    return [(task, arm) for index, task in enumerate(fixtures.make_fixtures())
            for arm in arms[index % 4:] + arms[:index % 4]]


def bindings():
    paths = [*ROOT.joinpath("hepta").rglob("*.py"), *HERE.glob("*.py"), HERE / "PROTOCOL.json",
             ROOT / "tools/qualify_hia_agent_toolstudy_v11.py", ROOT / "tools/qualify_hia_agent_tool_capacity_v11.py",
             ROOT / "tools/qualify_hia_agent_toolstudy_v9.py", ROOT / "tools/qualify_hia_agent_tool_capacity_v9.py",
             ROOT / "tools/qualify_hia_agent_toolstudy.py", ROOT / "tools/qualify_hia_agent_tool_capacity.py",
             ROOT / "tools/qualify_hia_agent_primitive_repair.py", ROOT / "tools/provider_adapter/llama_cpp_engine.py",
             ROOT / "tests/test_hia_agent_toolstudy.py", ROOT / "tests/test_hia_agent_toolstudy_v9.py",
             ROOT / "tests/test_hia_agent_toolstudy_v11.py", *(p for p in HERE.joinpath("provenance").rglob("*") if p.is_file())]
    for directory in ("hia_agent_toolstudy_v9_20261029", "hia_agent_toolstudy_v8_20261029", "hia_agent_structured_v7_20261029", "hia_agent_factorial_v4_20261028",
                      "hia_agent_factorial_v5_20261028", "hia_agent_factorial_v6_20261028"):
        folder = ROOT / "experiments" / directory
        paths += [*folder.glob("*.py"), folder / "PROTOCOL.json"]
    return {str(path.relative_to(ROOT)): file_identity(path)["sha256"] for path in sorted(set(paths))}


def clean_committed_source():
    source = bindings()
    tracked = set(subprocess.check_output(["git", "ls-files"], cwd=ROOT, text=True).splitlines())
    if not set(source).issubset(tracked):
        raise ValueError("E_TOOLSTUDY_UNTRACKED_SOURCE")
    if subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=no"], cwd=ROOT, text=True).strip():
        raise ValueError("E_TOOLSTUDY_DIRTY_SOURCE")
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    return head, source


def snapshot(output, source):
    for name, expected in source.items():
        data = (ROOT / name).read_bytes()
        if hashlib.sha256(data).hexdigest() != expected:
            raise RuntimeError("E_TOOLSTUDY_SNAPSHOT_DRIFT")
        path = Path(output) / "source_snapshot" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)


def prompt_bindings():
    result = {}
    for stage in ("calibration", "main"):
        for task, arm in cells(stage):
            query = session_for(task, arm).query()
            text = prompts.prompt(task, arm, query)
            key = stage + "/" + task["id"] + "/" + arm
            result[key] = {"prompt_sha256": hashlib.sha256(text.encode()).hexdigest(),
                           "query_sha256": query["query_sha256"], "source_revision": query["source_revision"]}
    return result


def check_model(model):
    pinned = protocol()["model"]
    identity = file_identity(model)
    if any(identity[key] != pinned[key] for key in ("bytes", "sha256")):
        raise ValueError("E_TOOLSTUDY_MODEL_BYTES")
    return {**pinned, "file": identity}


def tool_identities(binary, tokenizer, clang, rustc):
    identities = {name: file_identity(path) for name, path in (("binary", binary), ("tokenizer", tokenizer),
                  ("clang", clang), ("rustc", rustc), ("python", sys.executable))}
    # Match the owned engine's actual runtime companion inventory, and include
    # the tokenizer's directory too. A new process may not silently establish
    # a different library baseline between capacity, qualification and main.
    companions = set()
    for name in ("binary", "tokenizer"):
        directory = Path(identities[name]["path"]).parent
        companions.update(directory.glob("*.so*"))
        companions.update(directory.glob("*.dll"))
    for path in sorted(companions):
        identities["runtime_companion:" + str(path)] = file_identity(path)
    return identities


def validate_capacity(record, *, tools, model):
    expected = set(prompt_bindings())
    if (record.get("schema") != "hepta.agent.tool-capacity.v11"
            or record.get("source_bindings") != bindings()
            or record.get("prompt_bindings") != prompt_bindings()
            or record.get("protocol_sha256") != file_identity(HERE / "PROTOCOL.json")["sha256"]
            or record.get("model") != model
            or record.get("tools") != tools
            or set(row.get("id") for row in record.get("rows", [])) != expected
            or len(record.get("rows", [])) != 19
            or not all(record.get(key) is True for key in ("complete", "source_unchanged", "tools_unchanged", "model_unchanged"))
            or record.get("independent_cli_tokenizer", {}).get("calls") != protocol()["tokenizer_controls"]["independent_cli_calls"]
            or record.get("independent_cli_tokenizer", {}).get("all_matched") is not True
            or record.get("model_requests") != 0
            or record.get("engine_exited") is not True
            or not all(row.get("passed") is True and row.get("reference_passed_all_gates") is True
                       and row.get("capacity_passed") is True and row.get("template_exact_match") is True
                       and row.get("tokenizer_ids_match") is True
                       and row.get("rendered_request_cli_checks") == 4
                       and row.get("all_rendered_request_cli_ids_match") is True
                       and 0 < row.get("complete_reference_output_tokens", 10**9) <= protocol()["generation"]["max_output_tokens"]
                       and row.get("allocated_worst_repair_plus_output_reserve", 10**9) <= protocol()["generation"]["context_tokens"]
                       for row in record.get("rows", []))):
        raise ValueError("E_TOOLSTUDY_CAPACITY_BINDING")


def validate_qualification(record, *, tools, model, capacity_sha256):
    expected = [(task["id"], "rust_node") for task, _ in cells("calibration")]
    actual = [(cell.get("task"), cell.get("arm")) for cell in record.get("cells", [])]
    if (record.get("schema") != protocol()["schema"] or record.get("stage") != "calibration"
            or record.get("protocol_sha256") != file_identity(HERE / "PROTOCOL.json")["sha256"]
            or record.get("source_bindings") != bindings() or record.get("prompt_bindings") != prompt_bindings()
            or record.get("model") != model or record.get("tools") != tools
            or record.get("capacity_sha256") != capacity_sha256 or actual != expected
            or not all(record.get(key) is True for key in ("valid_observation", "source_unchanged", "model_unchanged", "tools_unchanged"))):
        raise ValueError("E_TOOLSTUDY_QUALIFICATION_BINDING")
    derived = all(cell.get("correct") is True and cell.get("hidden_evaluated") is True and cell.get("status") == "correct"
                  and 1 <= len(cell.get("attempts", [])) <= protocol()["generation"]["attempts_per_cell"]
                  and all(attempt.get("usage") is not None for attempt in cell["attempts"])
                  for cell in record["cells"])
    attempts = [attempt for cell in record["cells"] for attempt in cell.get("attempts", [])]
    # Successful reference controls or stale summary booleans cannot turn an
    # unknown generation cost into a complete, eligible model observation.
    if derived:
        valid_usage = all(type(attempt["usage"]) is dict
                          and all(type(attempt["usage"].get(key)) is int and attempt["usage"][key] > 0
                                  for key in ("input_tokens", "output_tokens", "total_tokens"))
                          and attempt["usage"]["total_tokens"] == attempt["usage"]["input_tokens"] + attempt["usage"]["output_tokens"]
                          and attempt.get("actual_generation_requested") is True
                          for attempt in attempts)
        inputs = sum(attempt["usage"].get("input_tokens", 0) for attempt in attempts) if valid_usage else None
        outputs = sum(attempt["usage"].get("output_tokens", 0) for attempt in attempts) if valid_usage else None
        if (not valid_usage or record.get("unknown_usage_requests") != 0
                or record.get("requests") != len(attempts) or record.get("responses") != len(attempts)
                or record.get("known_input_tokens") != inputs or record.get("known_output_tokens") != outputs
                or record.get("total_tokens") != inputs + outputs):
            raise ValueError("E_TOOLSTUDY_V11_INCOMPLETE_USAGE")
    if record.get("calibration_eligible") is not derived:
        raise ValueError("E_TOOLSTUDY_QUALIFICATION_DERIVED_GATE")
    if not derived:
        raise ValueError("E_TOOLSTUDY_NO_QUALIFIED_MODEL: fresh Rust node qualification did not pass 3/3")
    return {"eligible": True, "fresh_v11": True, "calibration_correct": 3, "calibration_tasks": 3}
