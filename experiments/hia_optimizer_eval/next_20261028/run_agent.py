#!/usr/bin/env python3
"""Register and execute the fixed two-family maintenance/upgrade follow-up.

Every model runs once in registered order. Reference answers create controls;
scored answers come only from retained owned-runtime responses. Registration
freezes fixtures/prompts first; the suite plan also freezes compiler sources.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from tools import qualify_hia_agent_holdout as holdout
from tools import qualify_hia_batch_study as batch
from tools.qualify_hia_edit_study import ARMS
from tools.provider_adapter.llama_cpp_engine import canonical, file_identity
from experiments.hia_optimizer_eval.next_20261028 import upgrade_pilot as upgrade

HERE = Path(__file__).resolve().parent


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def read(path):
    return json.loads(Path(path).read_bytes())


def inventory():
    protocol = read(HERE / "PROTOCOL.json")
    return {"primary": holdout.tasks(protocol["agent"]["withheld_lcg_seed"]),
            "upgrade": upgrade.fixtures()}


def prompt_inventory(fixtures):
    return {"primary": {task["id"] + "_" + arm: hashlib.sha256(batch.prompt(task, arm).encode()).hexdigest()
                        for task in fixtures["primary"] for arm in ARMS},
            "upgrade": {task["id"] + "_" + language: hashlib.sha256(upgrade.prompt(task, language).encode()).hexdigest()
                        for task in fixtures["upgrade"] for language in ("hia", "rust")}}


def evaluator_bindings():
    # Compiler sources are frozen at execution after compiler development.
    result = {name: value for name, value in holdout.bindings().items() if not name.startswith("hepta/")}
    result.update({str(path.relative_to(ROOT)): file_identity(path)["sha256"] for path in sorted(HERE.glob("*.py"))})
    return result


def register():
    protocol, values = read(HERE / "PROTOCOL.json"), inventory()
    for label, key in (("primary", "agent"), ("upgrade", "upgrade")):
        if [task["id"] for task in values[label]] != protocol[key]["task_ids"]:
            raise ValueError("registered task inventory differs")
    for task in values["upgrade"]:
        if len(task["hidden_cases"]) != protocol["upgrade"]["hidden_counts"][task["id"]]:
            raise ValueError("hidden upgrade inventory differs")
    upgrade.save(HERE / "FIXTURES.json", values)
    result = {"schema": "hepta.hia.agent-next-registration.v1", "registered_unix_ns": time.time_ns(),
              "before_any_model_inference": True,
              "protocol_sha256": file_identity(HERE / "PROTOCOL.json")["sha256"],
              "fixtures_sha256": file_identity(HERE / "FIXTURES.json")["sha256"],
              "fixtures_canonical_sha256": digest(values), "prompt_sha256": prompt_inventory(values),
              "evaluation_sources": evaluator_bindings(),
              "compiler_freeze": "all current compiler/evaluator files byte-bound in the first family suite plan",
              "model_requests_performed_during_registration": 0}
    upgrade.save(HERE / "REGISTRATION.json", result)
    return result


def validate_registration():
    result, values = read(HERE / "REGISTRATION.json"), inventory()
    if (file_identity(HERE / "PROTOCOL.json")["sha256"] != result["protocol_sha256"]
            or file_identity(HERE / "FIXTURES.json")["sha256"] != result["fixtures_sha256"]
            or digest(values) != result["fixtures_canonical_sha256"]
            or digest(read(HERE / "FIXTURES.json")) != result["fixtures_canonical_sha256"]
            or prompt_inventory(values) != result["prompt_sha256"]
            or evaluator_bindings() != result["evaluation_sources"]):
        raise ValueError("registered fixtures, prompts, protocol or evaluator source changed")
    return result


def runtime_identity(binary):
    path = Path(binary).resolve(strict=True)
    return [file_identity(p) for p in sorted({path, *path.parent.glob("*.so*"), *path.parent.glob("*.dll")})]


def tool_identity(binary, clang, rustc):
    return {"runtime": runtime_identity(binary), "clang": file_identity(clang), "rustc": file_identity(rustc)}


def run_one(*, output_dir, model_id, model_path, binary, clang, rustc):
    registration = validate_registration()
    protocol = read(HERE / "PROTOCOL.json")
    models = protocol["agent"]["models"]
    ids = [model["id"] for model in models]
    if ids != protocol["agent"]["model_execution_order"] or model_id not in ids:
        raise ValueError("unregistered model/order")
    index = ids.index(model_id)
    model = {**models[index], "path": str(Path(model_path).absolute())}
    actual = file_identity(model_path)
    if (actual["bytes"], actual["sha256"]) != (model["bytes"], model["sha256"]):
        raise ValueError("model bytes differ from the locked official revision")
    root, sources = Path(output_dir).absolute(), upgrade.bindings()
    tools = tool_identity(binary, clang, rustc)
    if not root.exists():
        if index != 0:
            raise ValueError("registered first family must execute first")
        root.mkdir(parents=True)
        upgrade.save(root / "SUITE_PLAN.json", {"schema": protocol["agent"]["id"], "protocol": protocol,
            "registration_sha256": file_identity(HERE / "REGISTRATION.json")["sha256"],
            "source_bindings": sources, "tool_identities": tools, "models": models,
            "prompt_sha256": registration["prompt_sha256"], "manual_time_ns": None,
            "all_raw_requests_and_failures_retained": True})
    plan = read(root / "SUITE_PLAN.json")
    if (plan["source_bindings"] != sources or plan["tool_identities"] != tools
            or plan["registration_sha256"] != file_identity(HERE / "REGISTRATION.json")["sha256"]):
        raise ValueError("sources, runtime, tools or registration changed between families")
    for earlier in ids[:index]:
        if not (root / earlier / "MODEL_RESULT.json").is_file():
            raise ValueError("earlier family has not finished its registered attempt")
    folder = root / model_id
    folder.mkdir(exist_ok=False)
    result = {"schema": protocol["agent"]["id"] + ".model", "model": model, "model_index": index,
              "status": "incomplete", "manual_time_ns": None, "phases": {}}
    upgrade.save(folder / "MODEL_STARTED.json", {**result, "registered_model_identity": actual})
    started = time.monotonic_ns()
    try:
        extras = tuple(name for name in sources if name not in holdout.bindings())
        primary = holdout.run(output_dir=folder / "primary", binary=binary, model=model_path,
            model_sha256=model["sha256"], model_metadata=models[index], model_index=index,
            clang=clang, rustc=rustc, threads=protocol["agent"]["threads"],
            withheld_seed=protocol["agent"]["withheld_lcg_seed"], protocol_id=protocol["agent"]["id"],
            extra_source_paths=extras)
        result["phases"]["primary"] = {"status": primary["status"],
            "report_sha256": file_identity(folder / "primary/report.json")["sha256"],
            "criteria": primary.get("single_model_descriptive_criteria"),
            "summary": primary["model_report"]["summary"] if primary.get("model_report") else None}
        if upgrade.bindings() != sources:
            raise RuntimeError("source changed between primary and upgrade phases")
        secondary = upgrade.run_model(folder / "upgrade", model=model, binary=binary, clang=clang,
                                      rustc=rustc, model_index=index)
        result["phases"]["upgrade"] = {"status": secondary["status"], "complete": secondary["complete"],
            "report_sha256": file_identity(folder / "upgrade/RESULT.json")["sha256"], "summary": secondary["summary"]}
        result["status"] = "completed" if primary["status"] == "completed" and secondary["complete"] else "incomplete"
    except Exception as error:
        result["diagnostic"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        result["source_unchanged"] = upgrade.bindings() == sources
        result["tools_unchanged"] = tool_identity(binary, clang, rustc) == tools
        result["model_unchanged"] = file_identity(model_path) == actual
        result["experiment_wall_ns"] = time.monotonic_ns() - started
        if not all(result[key] for key in ("source_unchanged", "tools_unchanged", "model_unchanged")):
            result["status"] = "incomplete"
        upgrade.save(folder / "MODEL_RESULT.json", result)
    return result


def summarize(output_dir):
    root = Path(output_dir)
    plan = read(root / "SUITE_PLAN.json")
    reports = []
    for model in plan["models"]:
        path = root / model["id"] / "MODEL_RESULT.json"
        reports.append(read(path) if path.is_file() else {"model": model, "status": "not_run"})
    complete = all(report["status"] == "completed" for report in reports)
    criteria = [report.get("phases", {}).get("primary", {}).get("criteria", {}) or {} for report in reports]
    result = {"schema": plan["schema"] + ".summary", "complete": complete, "models": reports,
              "primary_cross_family_gate": bool(complete and all(row.get("primary") for row in criteria)),
              "secondary_context_gate": bool(complete and all(row.get("secondary") for row in criteria)),
              "manual_time_ns": None, "claims": {"general_productivity_advantage": False,
                  "human_labor_measured": False, "all_model_attempts_retained": True,
                  "upgrade_results_added_to_primary_task_successes": False}}
    upgrade.save(root / "SUITE_RESULT.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("register")
    sub.add_parser("validate")
    command = sub.add_parser("run")
    for name in ("output-dir", "model-id", "model-path", "binary", "clang", "rustc"):
        command.add_argument("--" + name, required=True)
    command = sub.add_parser("summarize")
    command.add_argument("--output-dir", required=True)
    args = vars(parser.parse_args())
    action = args.pop("action")
    result = {"register": register, "validate": validate_registration, "run": run_one,
              "summarize": summarize}[action](**args)
    print(json.dumps(result if action in {"run", "summarize"} else
                     {"status": "registered" if action == "register" else "valid",
                      "prompt_sha256": result["prompt_sha256"]}), flush=True)
    return 1 if result.get("status") == "incomplete" else 0


if __name__ == "__main__":
    raise SystemExit(main())
