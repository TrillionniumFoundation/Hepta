"""Registered source, task and tool identities; no reference-answer import."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys

from experiments.hia_agent_factorial_v4_20261028 import calibration, fixtures
from experiments.hia_agent_structured_v7_20261029.session import ValidatedTaskSession
from experiments.hia_agent_toolstudy_v10_20261029 import prompts
from tools.provider_adapter.llama_cpp_engine import canonical, file_identity

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent

PINNED_MODEL = {'bytes': 2497281120, 'filename': 'Qwen3-4B-Instruct-2507-Q4_K_M.gguf', 'id': 'qwen3_4b_instruct_2507', 'repository': 'unsloth/Qwen3-4B-Instruct-2507-GGUF', 'revision': 'a06e946bb6b655725eafa393f4a9745d460374c9', 'sha256': '3605803b982cb64aead44f6c1b2ae36e3acdb41d8e46c8a94c6533bc4c67e597'}
PINNED_TEMPLATE = {'repository': 'Qwen/Qwen3-4B-Instruct-2507', 'revision': 'cdbee75f17c01a7cc42f958dc650907174af0554', 'file': 'tokenizer_config.json', 'bytes': 9377, 'sha256': 'a62ff0a2472a0fa1b8eaabcb57c59b58afa42a22831dc141400b6e0cf2b65ce3', 'local_file': 'provenance/Qwen__Qwen3-4B-Instruct-2507__tokenizer_config.json'}


def protocol():
    value = json.loads((HERE / "PROTOCOL.json").read_text())
    old = json.loads((ROOT / "experiments/hia_agent_toolstudy_v9_20261029/PROTOCOL.json").read_text())
    # This revision changes only one pinned model and its template, not the task/tool experiment.
    for key in ("runtime", "arms", "tasks", "generation", "history", "budget",
                "rust_conversion_profile", "hidden_seed", "hidden_random_cases_per_task", "decoder", "cell_order",
                "advantage_gate", "capacity_gate", "public_feedback", "rollback", "tool_scope", "timeout"):
        if value[key] != old[key]:
            raise ValueError("E_TOOLSTUDY_V10_UNAUTHORIZED_CONDITION_CHANGE: " + key)
    for key in ("arm", "tasks", "main_forbidden_without_qualification", "reference_controls_are_qualification_successes"):
        if value["qualification"][key] != old["qualification"][key]:
            raise ValueError("E_TOOLSTUDY_V10_QUALIFICATION_CHANGE: " + key)
    if value["model"] != PINNED_MODEL or value["official_template"] != PINNED_TEMPLATE:
        raise ValueError("E_TOOLSTUDY_V10_MODEL_OR_TEMPLATE_CHANGE")
    for name, expected in value["model_provenance"]["files"].items():
        if file_identity(HERE / name)["sha256"] != expected:
            raise ValueError("E_TOOLSTUDY_V10_PROVENANCE_BYTES")
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
             ROOT / "tools/qualify_hia_agent_toolstudy_v10.py", ROOT / "tools/qualify_hia_agent_tool_capacity_v10.py",
             ROOT / "tools/qualify_hia_agent_toolstudy_v9.py", ROOT / "tools/qualify_hia_agent_tool_capacity_v9.py",
             ROOT / "tools/qualify_hia_agent_toolstudy.py", ROOT / "tools/qualify_hia_agent_tool_capacity.py",
             ROOT / "tools/qualify_hia_agent_primitive_repair.py", ROOT / "tools/provider_adapter/llama_cpp_engine.py",
             ROOT / "tests/test_hia_agent_toolstudy.py", ROOT / "tests/test_hia_agent_toolstudy_v9.py",
             ROOT / "tests/test_hia_agent_toolstudy_v10.py", *HERE.joinpath("provenance").glob("*.json")]
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
    if (record.get("schema") != "hepta.agent.tool-capacity.v10"
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
    if record.get("calibration_eligible") is not derived:
        raise ValueError("E_TOOLSTUDY_QUALIFICATION_DERIVED_GATE")
    if not derived:
        raise ValueError("E_TOOLSTUDY_NO_QUALIFIED_MODEL: fresh Rust node qualification did not pass 3/3")
    return {"eligible": True, "fresh_v10": True, "calibration_correct": 3, "calibration_tasks": 3}

