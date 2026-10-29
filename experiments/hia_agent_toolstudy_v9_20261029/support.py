"""Registered source, task and tool identities; no reference-answer import."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys

from experiments.hia_agent_factorial_v4_20261028 import calibration, fixtures
from experiments.hia_agent_structured_v7_20261029.session import ValidatedTaskSession
from experiments.hia_agent_toolstudy_v9_20261029 import prompts
from tools.provider_adapter.llama_cpp_engine import canonical, file_identity

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent


def protocol():
    value = json.loads((HERE / "PROTOCOL.json").read_text())
    old = json.loads((ROOT / "experiments/hia_agent_toolstudy_v8_20261029/PROTOCOL.json").read_text())
    # This revision may disclose existing API rules, not relax the experiment.
    for key in ("model", "runtime", "arms", "tasks", "generation", "history", "budget",
                "rust_conversion_profile", "hidden_seed", "hidden_random_cases_per_task"):
        if value[key] != old[key]:
            raise ValueError("E_TOOLSTUDY_V9_UNAUTHORIZED_CONDITION_CHANGE: " + key)
    for key in ("arm", "tasks", "main_forbidden_without_qualification", "reference_controls_are_qualification_successes"):
        if value["qualification"][key] != old["qualification"][key]:
            raise ValueError("E_TOOLSTUDY_V9_QUALIFICATION_CHANGE: " + key)
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
             ROOT / "tools/qualify_hia_agent_toolstudy_v9.py", ROOT / "tools/qualify_hia_agent_tool_capacity_v9.py",
             ROOT / "tools/qualify_hia_agent_toolstudy.py", ROOT / "tools/qualify_hia_agent_tool_capacity.py",
             ROOT / "tools/qualify_hia_agent_primitive_repair.py", ROOT / "tools/provider_adapter/llama_cpp_engine.py",
             ROOT / "tests/test_hia_agent_toolstudy.py", ROOT / "tests/test_hia_agent_toolstudy_v9.py"]
    for directory in ("hia_agent_toolstudy_v8_20261029", "hia_agent_structured_v7_20261029", "hia_agent_factorial_v4_20261028",
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
    if (record.get("schema") != "hepta.agent.tool-capacity.v9"
            or record.get("source_bindings") != bindings()
            or record.get("prompt_bindings") != prompt_bindings()
            or record.get("protocol_sha256") != file_identity(HERE / "PROTOCOL.json")["sha256"]
            or record.get("model") != model
            or record.get("tools") != tools
            or set(row.get("id") for row in record.get("rows", [])) != expected
            or len(record.get("rows", [])) != 19
            or not all(record.get(key) is True for key in ("complete", "source_unchanged", "tools_unchanged", "model_unchanged"))
            or record.get("model_requests") != 0
            or record.get("engine_exited") is not True
            or not all(row.get("passed") is True and row.get("reference_passed_all_gates") is True
                       and row.get("capacity_passed") is True and row.get("template_exact_match") is True
                       and row.get("tokenizer_ids_match") is True
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
    return {"eligible": True, "fresh_v9": True, "calibration_correct": 3, "calibration_tasks": 3}

