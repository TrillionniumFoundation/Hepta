#!/usr/bin/env python3
"""Run the 19 existing real-node study references against the current Core.

This CI entry point does not start inference, load a model, call a tokenizer, or
establish capacity/model qualification. It reuses the registered references,
actual edit validation, and original public/terminal-hidden resource evaluator.
No frozen experiment implementation or protocol is changed by this wrapper.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from experiments.hia_agent_factorial_v4_20261028 import evaluator
from experiments.hia_agent_toolstudy_v8_20261029 import references, support, validation

SCHEMA = "hepta.agent.real-node.native-references.v1"
EXPECTED_COUNT = 19
EXTRA_SOURCE = (
    "tools/qualify_hia_agent_tool_references.py",
    "tests/test_hia_agent_tool_references.py",
)
SCOPE = ("Actual native reference controls on the recorded current source; "
         "not tokenizer capacity, model qualification, Agent success, "
         "language soundness, or a performance result.")


def digest(value):
    return hashlib.sha256(evaluator.canonical(value)).hexdigest()


def select_study(study_version):
    if study_version == "v8":
        return support
    if study_version == "v9":
        from experiments.hia_agent_toolstudy_v9_20261029 import support as next_support
        return next_support
    raise ValueError("E_TOOL_REFERENCES_STUDY_VERSION")


def source_bindings(*, study_support=support):
    source = study_support.bindings()
    for name in EXTRA_SOURCE:
        source[name] = evaluator.file_identity(ROOT / name)["sha256"]
    return source


def clean_source(*, study_support=support):
    head, _ = study_support.clean_committed_source()
    source = source_bindings(study_support=study_support)
    tracked = set(subprocess.check_output(["git", "ls-files"], cwd=ROOT, text=True).splitlines())
    if not set(source).issubset(tracked):
        raise ValueError("E_TOOL_REFERENCES_UNTRACKED_SOURCE")
    return head, source


def tool_identities(clang, rustc):
    # No server, tokenizer, model, inference runtime, or download is required.
    module = getattr(fcntl, "__file__", sys.executable)
    return {name: evaluator.file_identity(path) for name, path in (
        ("clang", clang), ("rustc", rustc), ("python", sys.executable), ("fcntl", module))}


def registered_cells(*, study_support=support):
    cfg = study_support.protocol()
    actual = [(stage, task, arm) for stage in ("calibration", "main")
              for task, arm in study_support.cells(stage)]
    expected = ["calibration/" + task + "/calibration" for task in cfg["qualification"]["tasks"]]
    arms = cfg["arms"]
    for index, task in enumerate(cfg["tasks"]):
        expected.extend("main/" + task + "/" + arm for arm in arms[index % 4:] + arms[:index % 4])
    identities = [stage + "/" + task["id"] + "/" + arm for stage, task, arm in actual]
    if (len(actual) != EXPECTED_COUNT or len(set(identities)) != EXPECTED_COUNT
            or identities != expected):
        raise ValueError("E_TOOL_REFERENCES_CELL_REGISTRY")
    return actual


def native_observation_passed(value):
    return (type(value) is dict and value.get("status") == "correct"
            and all(value.get(key) is True for key in (
                "native_executed", "artifact_unchanged", "resource_contract_passed", "vm_contract_passed")))


def boundary(source, tools, clang, rustc, *, study_support=support):
    # A failed identity read is a failed boundary, but cannot erase an actual
    # row that has already executed. Preserve that row and stop further work.
    observed = {"source_unchanged": False, "tools_unchanged": False}
    errors = []
    for name, expected, read in (
        ("source_unchanged", source, lambda: source_bindings(study_support=study_support)),
        ("tools_unchanged", tools, lambda: tool_identities(clang, rustc)),
    ):
        try:
            observed[name] = read() == expected
        except Exception as exc:
            errors.append({"boundary": name, "type": type(exc).__name__, "message": str(exc)})
    if errors:
        observed["identity_errors"] = errors
    return observed


def evaluate_reference(task, arm, output, clang, rustc, *, study_support=support):
    """One unchanged human reference; no generated answer repair or evaluator."""
    folder = Path(output)
    folder.mkdir(parents=True, exist_ok=False)
    language, interface = study_support.language_interface(arm)
    session = study_support.session_for(task, arm, clang, rustc)
    query = session.query()
    answer = (references.reference(session, query, task) if interface == "node"
              else {"files": task["correct_" + language]})
    text = evaluator.canonical(answer).decode()
    inputs = {"task_sha256": digest(task), "query": query, "reference_response": answer,
              "reference_response_sha256": hashlib.sha256(text.encode()).hexdigest(),
              "public_cases_sha256": digest([task["public_cases"], task["public_expected"]]),
              "terminal_hidden_cases_sha256": digest([task["hidden_cases"], task["hidden_expected"]]),
              "reference_is_model_answer": False, "model_requests": 0}
    evaluator.save(folder / "INPUT.json", inputs)
    public = validation.evaluate(task, language, interface, session, query, text,
                                 folder / "reference", clang, rustc)
    # The same actual evaluator is reused, but a forged/failed compiled status
    # must never authorize even a terminal reference execution.
    built = public.get("build", {})
    admitted = (public.get("accepted") is True and public.get("status") == "correct"
                and built.get("status") == "compiled" and built.get("native_built") is True
                and native_observation_passed(public.get("public")))
    hidden = None
    if admitted:
        hidden = evaluator.execute(built, task, task["hidden_cases"], task["hidden_expected"])
        evaluator.save(folder / "TERMINAL_HIDDEN.json", hidden)
    return {"language": language, "interface": interface, "input_sha256": digest(inputs),
            "reference_response_sha256": inputs["reference_response_sha256"],
            "query_sha256": query["query_sha256"], "source_revision": query["source_revision"],
            "public": public, "terminal_hidden": hidden,
            "passed": admitted and native_observation_passed(hidden),
            "model_answer": False, "model_requests": 0}


def run(*, output, clang, rustc, study_version="v8"):
    started = time.monotonic_ns()
    study_support = select_study(study_version)
    destination = Path(output).resolve()
    if destination.is_relative_to(ROOT.resolve()):
        raise ValueError("E_TOOL_REFERENCES_OUTPUT: retain artifacts outside the checkout")
    head, source = clean_source(study_support=study_support)
    tools = tool_identities(clang, rustc)
    cells = registered_cells(study_support=study_support)
    expected_ids = [stage + "/" + task["id"] + "/" + arm for stage, task, arm in cells]
    destination.mkdir(parents=True, exist_ok=False)
    plan = {"schema": SCHEMA, "scope": SCOPE, "source_commit": head,
            "study_version": study_version, "study_protocol_schema": study_support.protocol()["schema"],
            "source_bindings": source, "tools": tools,
            "protocol_sha256": evaluator.file_identity(study_support.HERE / "PROTOCOL.json")["sha256"],
            "expected_count": EXPECTED_COUNT, "expected_ids": expected_ids,
            "task_inputs": {ident: digest(task) for ident, (_, task, _) in zip(expected_ids, cells)},
            "model_requests": 0, "tokenizer_invocations": 0, "capacity_qualified": False,
            "model_qualified": False, "agent_successes": 0}
    study_support.snapshot(destination, source)
    evaluator.save(destination / "PLAN.json", plan)
    result = {**plan, "rows": [], "complete": False, "passed": 0, "status": "incomplete"}
    try:
        for ident, (stage, task, arm) in zip(expected_ids, cells):
            before_identity = boundary(source, tools, clang, rustc, study_support=study_support)
            if not before_identity["source_unchanged"] or not before_identity["tools_unchanged"]:
                result["stopped_before_row"] = {"id": ident, **before_identity}
                raise RuntimeError("E_TOOL_REFERENCES_IDENTITY_DRIFT_BEFORE_ROW")
            before = time.monotonic_ns()
            row = {"id": ident, "fixture_stage": stage, "task": task["id"], "arm": arm,
                   "passed": False, "model_answer": False, "model_requests": 0}
            try:
                row.update(evaluate_reference(task, arm, destination / ident, clang, rustc,
                                              study_support=study_support))
            except Exception as exc:
                row["error"] = {"type": type(exc).__name__, "message": str(exc)}
            row["wall_ns"] = time.monotonic_ns() - before
            row.update(boundary(source, tools, clang, rustc, study_support=study_support))
            row["passed"] = bool(row["passed"] and row["source_unchanged"] and row["tools_unchanged"])
            result["rows"].append(row)
            evaluator.save(destination / ident / "ROW.json", row)
            print(json.dumps({key: row[key] for key in ("id", "passed", "source_unchanged", "tools_unchanged")}), flush=True)
            if not row["source_unchanged"] or not row["tools_unchanged"]:
                raise RuntimeError("E_TOOL_REFERENCES_IDENTITY_DRIFT_AFTER_ROW")
        result["status"] = "all_references_attempted"
    except Exception as exc:
        result["error"] = {"type": type(exc).__name__, "message": str(exc)}
    finally:
        result.update(boundary(source, tools, clang, rustc, study_support=study_support))
        ids = [row["id"] for row in result["rows"]]
        result["attempted_count"] = len(ids)
        result["missing_ids"] = [ident for ident in expected_ids if ident not in ids]
        result["passed"] = sum(row["passed"] is True for row in result["rows"])
        result["complete"] = bool(result["status"] == "all_references_attempted"
                                  and ids == expected_ids and len(ids) == EXPECTED_COUNT
                                  and result["passed"] == EXPECTED_COUNT
                                  and result["source_unchanged"] and result["tools_unchanged"])
        result["experiment_wall_ns"] = time.monotonic_ns() - started
        evaluator.save(destination / "REFERENCES.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("output", "clang", "rustc"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--study-version", choices=("v8", "v9"), default="v8")
    result = run(**vars(parser.parse_args()))
    print(json.dumps({key: result[key] for key in ("complete", "attempted_count", "passed", "model_requests", "capacity_qualified", "model_qualified")}))
    return 0 if result["complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
