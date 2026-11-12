#!/usr/bin/env python3
"""Prospective language x edit-interface study with actual local inference.

This is a prospective pilot of two real historical upstream fixes adapted into
HIA and Rust. Two functions from one library are not an independent population.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.dont_write_bytecode = True

from experiments.hia_agent_assembly_v4_20261030 import run_study as prior
from benchmarks.hia_upstream_factorial import evaluator, tasks as fixtures
from hepta.hia_program_tools import decode_json
from tools.provider_adapter.llama_cpp_engine import LlamaCppEngine, canonical, file_identity

PROTOCOL = ROOT / "benchmarks/hia_upstream_factorial/PROTOCOL.json"
ARMS = (("assembly", "full"), ("rust", "full"), ("assembly", "patch"), ("rust", "patch"))


def digest(value):
    return sha256(canonical(value)).hexdigest()


def save(path, value):
    path = Path(path)
    with path.open("xb") as stream:
        stream.write(canonical(value) + b"\n")
        stream.flush()
        os.fsync(stream.fileno())


def protocol():
    value = decode_json(PROTOCOL.read_bytes())
    if (value["schema"] != "hepta.agent.upstream-fixes-factorial.v1"
            or value["expected_cells"] != len(value["models"]) * len(value["tasks"]) * len(ARMS)
            or value["languages"] != ["assembly", "rust"]
            or value["interfaces"] != ["full", "patch"]):
        raise ValueError("factorial protocol inventory mismatch")
    return value


def source_bindings():
    result = prior.source_bindings()
    for path in [*ROOT.glob("hepta/*.py"), Path(__file__), PROTOCOL,
                 *PROTOCOL.parent.glob("*.py"), *PROTOCOL.parent.glob("*.hepta"),
                 PROTOCOL.parent / "UPSTREAM_TASKS.json", PROTOCOL.parent / "UPSTREAM_FIX.json",
                 ROOT / "tools/capture_hia_upstream_tasks.py", ROOT / "tools/qualify_hia_upstream_ports.py",
                 ROOT / "tests/test_hia_upstream_factorial.py",
                 ROOT / "tools/provider_adapter/llama_cpp_engine.py",
                 ROOT / "tests/fixtures/c_migration/stb_divide/stb_divide.h",
                 ROOT / "tests/fixtures/c_migration/stb_divide/UPSTREAM.json",
                 ROOT / "tests/fixtures/c_migration/stb_divide_v0_93/stb_divide.h",
                 ROOT / "tests/fixtures/c_migration/stb_divide_v0_93/UPSTREAM.json"]:
        if not path.is_file():
            raise FileNotFoundError("required study source binding is missing: " + str(path))
        result[str(path.relative_to(ROOT))] = file_identity(path)["sha256"]
    return dict(sorted(result.items()))


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def require_committed(bindings):
    for name, wanted in bindings.items():
        raw = subprocess.check_output(["git", "show", "HEAD:" + name], cwd=ROOT)
        if sha256(raw).hexdigest() != wanted:
            raise ValueError("uncommitted study input: " + name)


def prompt(task, language, interface):
    if (language, interface) not in ARMS:
        raise ValueError("unregistered language/interface")
    original = task["original_" + language]
    contract = ('Return {"expected_sha256": HASH, "files": {FILENAME: COMPLETE_SOURCE, ...}} with every listed file.'
                if interface == "full" else
                'Return {"expected_sha256": HASH, "patches": [{"path": FILENAME, "old": EXACT_OLD_TEXT, "new": REPLACEMENT}, ...]}. '
                'Use 1..16 edits in order. Every old text is nonempty and must occur exactly once at its step. '
                'Edits start from the shown original files on every submission. No fuzzy matching or implicit repair.')
    # Only the inherited response-format instruction changes. The complete
    # public problem, language admission, examples and files stay identical.
    public = fixtures.prompt(task, language).split("\n", 1)[1]
    return ("Repair this upstream-derived function. Return only one JSON object. "
            "The decoder enforces only generic JSON-object syntax for every arm. "
            + contract + "\nHASH = " + digest(original) + "\n" + public)


def materialize(task, language, interface, text):
    if (language, interface) not in ARMS or type(text) is not str or len(text.encode()) > 65536:
        raise ValueError("E_FACTORIAL_RESPONSE_BOUND")
    value = decode_json(text)
    key = "files" if interface == "full" else "patches"
    if type(value) is not dict or set(value) != {"expected_sha256", key}:
        raise ValueError("E_FACTORIAL_ENVELOPE")
    original = task["original_" + language]
    if value["expected_sha256"] != digest(original):
        raise ValueError("E_FACTORIAL_STALE_SOURCE")
    if interface == "full":
        files = value["files"]
        if (type(files) is not dict or set(files) != set(original)
                or any(type(v) is not str or len(v.encode()) > 65536 for v in files.values())):
            raise ValueError("E_FACTORIAL_FILE_INVENTORY")
    else:
        edits = value["patches"]
        if type(edits) is not list or not 1 <= len(edits) <= 16:
            raise ValueError("E_FACTORIAL_PATCH_BUDGET")
        files = dict(original)
        for edit in edits:
            if type(edit) is not dict or set(edit) != {"path", "old", "new"}:
                raise ValueError("E_FACTORIAL_EDIT_FIELDS")
            if (type(edit["path"]) is not str or edit["path"] not in files
                    or any(type(edit[k]) is not str for k in ("old", "new"))
                    or not edit["old"] or files[edit["path"]].count(edit["old"]) != 1):
                raise ValueError("E_FACTORIAL_EXACT_EDIT")
            files[edit["path"]] = files[edit["path"]].replace(edit["old"], edit["new"], 1)
            if len(files[edit["path"]].encode()) > 65536:
                raise ValueError("E_FACTORIAL_FILE_BUDGET")
    return canonical({"files": files}).decode()


def edit_contract_feedback(task, language, interface, text, error):
    """Explain a rejected edit using only the already disclosed source contract.

    Admission stays in materialize, unchanged. Never consult the correct source,
    oracle, public executions or hidden cases while formatting these details.
    """
    feedback = {"edit_rejected": str(error)}
    if ((language, interface) not in ARMS or type(text) is not str
            or not str(error).startswith("E_FACTORIAL_")):
        return feedback
    try:
        if len(text.encode()) > 65536:
            return feedback
        value = decode_json(text)
    except ValueError:
        return feedback
    original = task["original_" + language]
    key = "files" if interface == "full" else "patches"
    details = {"schema": "hepta.agent.public-edit-feedback.v1",
               "expected_files": sorted(original), "base_sha256": digest(original),
               "expected_fields": ["expected_sha256", key],
               "received_type": type(value).__name__}
    feedback["details"] = details
    if type(value) is not dict:
        return feedback
    details["received_fields"] = [name[:120] for name in sorted(value)[:8]]
    details["received_field_count"] = len(value)
    if interface == "full":
        files = value.get("files")
        details["received_files_type"] = type(files).__name__
        if type(files) is dict:
            details["received_file_count"] = len(files)
            details["received_files"] = [name[:120] for name in sorted(files)[:8]]
            details["received_value_types"] = [
                {"path": name[:120], "type": type(files[name]).__name__}
                for name in sorted(files)[:8]]
        return feedback
    edits = value.get("patches")
    details["received_patches_type"] = type(edits).__name__
    if type(edits) is not list:
        return feedback
    details["patch_count"] = len(edits)
    if not 1 <= len(edits) <= 16:
        return feedback
    files = dict(original)
    for index, edit in enumerate(edits):
        if type(edit) is not dict or set(edit) != {"path", "old", "new"}:
            details.update(patch_index=index, expected_edit_fields=["path", "old", "new"])
            break
        path, old, new = (edit[k] for k in ("path", "old", "new"))
        known_path = type(path) is str and path in files
        count = files[path].count(old) if known_path and type(old) is str and old else None
        if not known_path or type(new) is not str or count != 1:
            details.update(patch_index=index, path=path[:120] if type(path) is str else None,
                           path_type=type(path).__name__, old_type=type(old).__name__,
                           new_type=type(new).__name__, old_occurrences=count)
            break
        files[path] = files[path].replace(old, new, 1)
        if len(files[path].encode()) > 65536:
            details.update(patch_index=index, path=path[:120],
                           resulting_file_bytes=len(files[path].encode()))
            break
    return feedback


def answer(task, language, interface, label="correct"):
    original, target = task["original_" + language], task[label + "_" + language]
    if interface == "full":
        return canonical({"expected_sha256": digest(original), "files": target}).decode()
    return canonical({"expected_sha256": digest(original), "patches": [
        {"path": name, "old": original[name], "new": target[name]} for name in sorted(original)]}).decode()


def schedule(configuration):
    rows = []
    for model_index, model in enumerate(configuration["models"]):
        for task_index, task in enumerate(configuration["tasks"]):
            start = (model_index + task_index) % len(ARMS)
            for language, interface in ARMS[start:] + ARMS[:start]:
                rows.append({"id": model["id"] + "/" + task + "/" + language + "-" + interface,
                             "model_id": model["id"], "task": task, "language": language,
                             "interface": interface})
    return rows



def runtime_inventory(binary):
    """Freeze the engine's complete explicit runtime-file inventory."""
    binary = Path(binary).resolve(strict=True)
    paths = sorted({binary, *binary.parent.glob("*.so*"), *binary.parent.glob("*.dll")})
    return [file_identity(path) for path in paths]


def validate_runtime(registration):
    if runtime_inventory(registration["tools"]["binary"]["path"]) != registration["runtime_files"]:
        raise RuntimeError("frozen factorial runtime file inventory drift")


def check_engine_registration(engine, registration, model_id):
    if (engine.runtime_identity != registration["runtime_files"]
            or engine.model_identity != registration["models"][model_id]):
        raise RuntimeError("engine session differs from frozen model/runtime files")
    properties = engine.identity.get("properties", {})
    actual_context = properties.get("default_generation_settings", {}).get("n_ctx")
    if (type(actual_context) is not int or actual_context != registration["context_tokens"]
            or engine.context != registration["context_tokens"]
            or engine.identity.get("threads") != registration["threads"]
            or type(properties.get("total_slots")) is not int or properties["total_slots"] != 1):
        raise RuntimeError("actual owned server context/thread/slot configuration differs from registration")


def check_cell_environment(engine, registration, model_id):
    if not prior.check_bindings(registration["source_bindings"]):
        raise RuntimeError("source drift during factorial cell")
    validate_runtime(registration)
    check_engine_registration(engine, registration, model_id)


def error_record(stage, error):
    return {"stage": stage, "type": type(error).__name__, "message": str(error)}


def checked_usage(value):
    if (type(value) is not dict
            or any(type(value.get(k)) is not int or value[k] < 0
                   for k in ("input_tokens", "output_tokens", "total_tokens"))
            or value["total_tokens"] != value["input_tokens"] + value["output_tokens"]):
        raise RuntimeError("invalid observed engine token usage")
    return value


def retain_engine_receipt(engine, before, attempt):
    """Bind this call's receipt, including known tokens from a late response.

    A failed request may have known input tokens, known complete usage, or no
    observed usage. These cases remain distinct. No earlier receipt is reused.
    """
    after = getattr(engine, "attempt_count", 0)
    if after == before:
        attempt["engine_attempt"] = None
        return
    if type(after) is not int or after != before + 1:
        raise RuntimeError("engine attempt sequence changed")
    path = engine.output / ("attempt-" + str(after).zfill(3) + ".json")
    raw = path.read_bytes()
    identity = file_identity(path)
    receipt = decode_json(raw)
    if (sha256(raw).hexdigest() != identity["sha256"]
            or receipt.get("schema") != "hepta.gguf-attempt-observation.v1"
            or receipt.get("attempt") != after):
        raise RuntimeError("engine attempt receipt identity changed")
    attempt["engine_attempt"] = {"file": identity, "receipt": receipt}
    known_input = receipt.get("input_tokens")
    if known_input is not None:
        if type(known_input) is not int or known_input < 0:
            raise RuntimeError("invalid observed input-token count")
        attempt["input_tokens"] = known_input
    usage = receipt.get("usage")
    if usage is not None:
        usage = checked_usage(usage)
        if ((known_input is not None and usage["input_tokens"] != known_input)
                or (attempt["usage"] is not None and attempt["usage"] != usage)):
            raise RuntimeError("engine receipt and response usage disagree")
        attempt["usage"] = usage
        attempt["input_tokens"], attempt["output_tokens"] = usage["input_tokens"], usage["output_tokens"]


def close_engine(engine, registration):
    """Best-effort owned shutdown; all cleanup/identity errors are data."""
    entered = time.monotonic_ns()
    record = {"errors": [], "close_attempts": 0, "reaped": False}
    for number in range(2):
        record["close_attempts"] += 1
        try:
            engine.close()
        except BaseException as error:
            record["errors"].append(error_record("close", error))
        try:
            process = getattr(engine, "process", None)
            code = process.poll() if process is not None else None
            record["reaped"] = process is None or type(code) is int
            record["returncode"] = code if type(code) is int else None
        except BaseException as error:
            record["errors"].append(error_record("process_observation", error))
        if record["reaped"]:
            break
    if not record["reaped"]:
        record["errors"].append(error_record("close", RuntimeError("owned model process not observed reaped")))
    try:
        state = engine.verify_final_identity()
        record["identity"] = state
        if not state["model_unchanged"] or not state["runtime_unchanged"]:
            raise RuntimeError("model/runtime drift at shutdown")
    except BaseException as error:
        record["errors"].append(error_record("final_identity", error))
    try:
        validate_runtime(registration)
    except BaseException as error:
        record["errors"].append(error_record("registered_runtime", error))
    record["wall_ns"] = time.monotonic_ns() - entered
    return record


def validate(output):
    output = Path(output)
    registration = decode_json((output / "REGISTRATION.json").read_bytes())
    if (registration["source_commit"] != git("rev-parse", "HEAD")
            or registration["source_tree"] != git("rev-parse", "HEAD^{tree}")
            or registration["protocol_sha256"] != file_identity(PROTOCOL)["sha256"]
            or not prior.check_bindings(registration["source_bindings"])
            or digest(fixtures.make_fixtures()) != registration["fixtures_sha256"]
            or registration["schedule"] != schedule(protocol())
            or registration["context_tokens"] != protocol()["context_tokens"]
            or registration["threads"] != protocol()["threads"]):
        raise ValueError("frozen factorial source/protocol/fixture identity drift")
    for item in registration["tools"].values():
        if file_identity(item["path"]) != item:
            raise ValueError("frozen factorial tool identity drift")
    validate_runtime(registration)
    return registration


def reference_controls(tasks, output, clang, rustc):
    """Use the same real native positive/historical controls for every transport."""
    controls = []
    control_root = Path(output)
    control_root.mkdir(parents=True, exist_ok=False)
    for task in tasks:
        for language in ("assembly", "rust"):
            full = materialize(task, language, "full", answer(task, language, "full"))
            patched = materialize(task, language, "patch", answer(task, language, "patch"))
            if full != patched:
                raise ValueError("interfaces do not reach identical reference sources")
            built = evaluator.build(task, language, full, control_root / (task["id"] + "-" + language),
                                    clang, rustc)
            observed = (evaluator.execute(built, task, task["hidden_cases"], task["hidden_expected"])
                        if built["native_built"] else None)
            correct = observed is not None and observed["status"] == "correct" and observed["artifact_unchanged"]
            controls.append({"task": task["id"], "language": language, "interfaces": ["full", "patch"],
                             "same_native_source": True, "passed": correct, "build": built, "observed": observed})
            if not correct:
                raise ValueError("actual reference control failed")
            unchanged = canonical({"files": task["original_" + language]}).decode()
            old_build = evaluator.build(task, language, unchanged,
                control_root / (task["id"] + "-" + language + "-historical"), clang, rustc)
            old_observed = (evaluator.execute(old_build, task, task["public_cases"], task["public_expected"])
                            if old_build["native_built"] else None)
            old_fails = (old_observed is not None and old_observed["status"] == "observable_wrong"
                         and old_observed["artifact_unchanged"])
            controls.append({"task": task["id"], "language": language, "kind": "historical_defect",
                             "passed": old_fails, "build": old_build, "observed": old_observed})
            if not old_fails:
                raise ValueError("historical defect not observed in an actual native port")
    report = {"model_answers": False, "rows": controls,
              "count": len(controls), "passed": sum(row["passed"] for row in controls)}
    save(control_root / "CONTROLS.json", report)
    return report


def prepare(output, *, binary, assets, clang, rustc):
    output = Path(output).resolve()
    if output.is_relative_to(ROOT):
        raise ValueError("evidence must be outside the source checkout")
    output.mkdir(parents=True, exist_ok=False)
    entered = time.monotonic_ns()
    configuration = protocol()
    tasks = fixtures.make_fixtures()
    if [t["id"] for t in tasks] != configuration["tasks"]:
        raise ValueError("fixture order differs from protocol")
    controls = reference_controls(tasks, output / "controls", clang, rustc)
    save(output / "CONTROLS.json", controls)
    tools = {k: file_identity(v) for k, v in {"binary": binary, "clang": clang, "rustc": rustc}.items()}
    frozen_runtime = runtime_inventory(binary)
    models, capacities = {}, []
    runtime_registration = {"tools": tools, "models": models, "runtime_files": frozen_runtime,
                            "context_tokens": configuration["context_tokens"], "threads": configuration["threads"]}
    if os.environ.get("LLAMA_ARG_REPACK") != "0":
        raise ValueError("registered runtime requires LLAMA_ARG_REPACK=0")
    for model in configuration["models"]:
        path = Path(assets) / model["filename"]
        identity = file_identity(path)
        if identity["sha256"] != model["sha256"] or identity["bytes"] != model["bytes"]:
            raise ValueError("model differs from registered bytes")
        models[model["id"]] = identity
        validate_runtime(runtime_registration)
        with LlamaCppEngine(binary=binary, model=path, model_sha256=model["sha256"],
                            output_dir=output / ("capacity-" + model["id"]),
                            threads=configuration["threads"], context=configuration["context_tokens"], json_object=True) as engine:
            check_engine_registration(engine, runtime_registration, model["id"])
            for task in tasks:
                for language, interface in ARMS:
                    messages = [{"role": "user", "content": prompt(task, language, interface)}]
                    rendered = engine.request("/apply-template", {"messages": messages})["prompt"]
                    tokens = engine.tokenize(rendered, special=True)
                    reference_tokens = len(engine.tokenize(answer(task, language, interface), special=False))
                    fits = len(tokens) + configuration["max_output_tokens"] <= configuration["context_tokens"]
                    capacities.append({"model_id": model["id"], "task": task["id"], "language": language,
                                       "interface": interface, "input_tokens": len(tokens), "fits": fits,
                                       "reference_output_tokens": reference_tokens,
                                       "reference_fits": reference_tokens <= configuration["max_output_tokens"]})
                    if not fits or reference_tokens > configuration["max_output_tokens"]:
                        save(output / "CAPACITY_REFUSAL.json", {"model_requests": 0, "rows": capacities})
                        raise ValueError("initial prompt or canonical reference exceeds the common budget")
            if engine.generation_count != 0:
                raise ValueError("preparation unexpectedly generated a model answer")
        state = engine.verify_final_identity()
        if not state["model_unchanged"] or not state["runtime_unchanged"]:
            raise RuntimeError("capacity session model/runtime drift")
        validate_runtime(runtime_registration)
    frozen = source_bindings()
    require_committed(frozen)
    registration = {"schema": configuration["schema"] + ".registration", "source_commit": git("rev-parse", "HEAD"),
                    "source_tree": git("rev-parse", "HEAD^{tree}"), "source_bindings": frozen,
                    "protocol_sha256": file_identity(PROTOCOL)["sha256"], "fixtures_sha256": digest(tasks),
                    "tools": tools, "runtime_files": frozen_runtime, "models": models, "capacities": capacities,
                    "context_tokens": configuration["context_tokens"], "threads": configuration["threads"],
                    "schedule": schedule(configuration), "registered_unix_ns": time.time_ns(),
                    "before_any_model_requests": True, "model_requests": 0,
                    "observed_preparation_wall_ns": time.monotonic_ns() - entered,
                    "human_labor_ns": None, "historical_model_download_ns": None}
    save(output / "REGISTRATION.json", registration)
    validate(output)
    return registration


def cell(task, descriptor, output, engine, registration, configuration):
    output.mkdir(parents=True, exist_ok=False)
    entered = time.monotonic_ns()
    row = {**descriptor, "status": "not_started", "correct": False, "attempts": [],
           "human_repairs": 0, "fatal_error": None}
    usable = True
    try:
        messages = [{"role": "user", "content": prompt(task, descriptor["language"], descriptor["interface"])}]
        for index in range(configuration["attempts_per_cell"]):
            check_cell_environment(engine, registration, descriptor["model_id"])
            attempt = {"index": index, "usage": None, "input_tokens": None,
                       "output_tokens": None, "status": "started"}
            row["attempts"].append(attempt)
            try:
                save(output / f"request-{index}.json", {"messages": messages, "max_output_tokens": configuration["max_output_tokens"]})
                started = time.monotonic_ns()
                before = getattr(engine, "attempt_count", 0)
                try:
                    response = engine.generate(messages, limit=configuration["max_output_tokens"],
                                               wall_seconds=configuration["request_wall_seconds"])
                    usage = checked_usage(response["usage"])
                    attempt.update(usage=usage, input_tokens=usage["input_tokens"],
                                   output_tokens=usage["output_tokens"])
                except Exception as error:
                    attempt.update(status="budget_timeout" if isinstance(error, TimeoutError) else "generation_error",
                                   error=error_record("generation", error))
                    row["status"] = attempt["status"]
                    usable = False
                    break
                finally:
                    attempt["request_wall_ns"] = time.monotonic_ns() - started
                    retain_engine_receipt(engine, before, attempt)
                save(output / f"response-{index}.json", response)
                built = observed = None
                try:
                    text = materialize(task, descriptor["language"], descriptor["interface"], response["text"])
                except ValueError as error:
                    feedback = edit_contract_feedback(task, descriptor["language"], descriptor["interface"],
                                                      response["text"], error)
                    attempt["edit_error"] = str(error)
                    attempt["edit_feedback"] = feedback
                else:
                    built = evaluator.build(task, descriptor["language"], text, output / f"candidate-{index}",
                                            registration["tools"]["clang"]["path"], registration["tools"]["rustc"]["path"])
                    attempt["build"] = built
                    if built["status"] == "infrastructure_failure":
                        raise RuntimeError("native infrastructure failure: " + str(built.get("error")))
                    observed = (evaluator.execute(built, task, task["public_cases"], task["public_expected"])
                                if built["native_built"] else None)
                    attempt["public"] = observed
                    if observed is not None and not observed["artifact_unchanged"]:
                        raise RuntimeError("native artifact changed")
                    feedback = evaluator.feedback(built, observed)
                check_cell_environment(engine, registration, descriptor["model_id"])
                if observed is not None and observed["status"] == "correct":
                    hidden = evaluator.execute(built, task, task["hidden_cases"], task["hidden_expected"])
                    row["hidden"] = hidden
                    if not hidden["artifact_unchanged"]:
                        raise RuntimeError("native artifact changed during hidden validation")
                    row["correct"] = hidden["status"] == "correct"
                    row["status"] = "correct" if row["correct"] else "hidden_validation_failed"
                    attempt["status"] = "public_passed"
                    break
                row["status"] = attempt["status"] = "public_validation_failed"
                if index + 1 < configuration["attempts_per_cell"]:
                    messages.extend([{"role": "assistant", "content": response["text"]},
                                     {"role": "user", "content": "The edit or public validation failed. This is the final submission. "
                                      "Use the same response interface and original source HASH. Edits still start from the original files. "
                                      "Hidden tests have not run.\n" + canonical(feedback).decode()}])
            except BaseException as error:
                attempt.update(status="infrastructure_failure", infrastructure_error=error_record("cell", error))
                raise
            finally:
                save(output / f"attempt-{index}.json", attempt)
    except BaseException as error:
        row.update(status="infrastructure_failure", correct=False, fatal_error=error_record("cell", error))
        usable = False
    finally:
        try:
            check_cell_environment(engine, registration, descriptor["model_id"])
        except BaseException as error:
            row["environment_error"] = error_record("cell_final_identity", error)
            row.update(status="infrastructure_failure", correct=False,
                       fatal_error=row["fatal_error"] or row["environment_error"])
            usable = False
        row["input_tokens_complete"] = all(a["input_tokens"] is not None for a in row["attempts"])
        row["output_tokens_complete"] = all(a["output_tokens"] is not None for a in row["attempts"])
        row["usage_complete"] = row["input_tokens_complete"] and row["output_tokens_complete"]
        row["known_input_tokens"] = sum(a["input_tokens"] for a in row["attempts"] if a["input_tokens"] is not None)
        row["known_output_tokens"] = sum(a["output_tokens"] for a in row["attempts"] if a["output_tokens"] is not None)
        row["total_input_tokens"] = row["known_input_tokens"] if row["input_tokens_complete"] else None
        row["total_output_tokens"] = row["known_output_tokens"] if row["output_tokens_complete"] else None
        row["cell_wall_ns"] = time.monotonic_ns() - entered
        save(output / "CELL.json", row)
    return row, usable


def summarize(registration, rows, wall_ns, completed, error=None):
    shared = wall_ns - sum(row["cell_wall_ns"] for row in rows)
    if shared < 0:
        raise ValueError("cohort and nonoverlapping cell cost clocks disagree")
    arms = []
    for language, interface in ARMS:
        selected = [r for r in rows if r["language"] == language and r["interface"] == interface]
        expected_arm = [r for r in registration["schedule"] if r["language"] == language and r["interface"] == interface]
        complete = len(selected) == len(expected_arm) and {r["id"] for r in selected} == {r["id"] for r in expected_arm}
        input_complete = complete and all(r["input_tokens_complete"] for r in selected)
        output_complete = complete and all(r["output_tokens_complete"] for r in selected)
        known_input = sum(r["known_input_tokens"] for r in selected)
        known_output = sum(r["known_output_tokens"] for r in selected)
        correct = sum(r["correct"] for r in selected)
        cost = (sum(r["cell_wall_ns"] for r in selected) + shared
                + registration["observed_preparation_wall_ns"])
        arms.append({"language": language, "interface": interface, "cells": len(selected),
                     "expected_cells": len(expected_arm), "correct": correct,
                     "requests": sum(len(r["attempts"]) for r in selected),
                     "known_input_tokens": known_input, "known_output_tokens": known_output,
                     "total_input_tokens": known_input if input_complete else None,
                     "total_output_tokens": known_output if output_complete else None,
                     "input_tokens_complete": input_complete, "output_tokens_complete": output_complete,
                     "usage_complete": input_complete and output_complete,
                     "observed_shared_cost_solo_allocation_ns": cost,
                     "cost_per_correct_ns": cost / correct if correct else None})
    expected = registration["schedule"]
    identity_complete = [r["id"] for r in rows] == [r["id"] for r in expected]
    return {"schema": "hepta.agent.upstream-fixes-factorial.result.v1", "completed": completed and identity_complete,
            "expected_cells": len(expected), "observed_cells": len(rows),
            "missing_cells": [r["id"] for r in expected if r["id"] not in {x["id"] for x in rows}],
            "arms": arms, "cells": rows, "error": error, "cohort_wall_ns": wall_ns,
            "common_observed_runner_and_model_overhead_ns": shared,
            "cost_allocation": "Each descriptive solo arm pays all common preparation and runtime overhead once; not independently executed solo campaigns.",
            "historical_model_download_ns": None, "human_labor_ns": None, "hardware_energy_joules": None,
            "stable_productivity_advantage": False, "real_external_maintenance_corpus": False,
            "real_historical_fixes_adapted": True, "independent_upstream_projects": 1,
            "scope": "Two real fixes from one pinned upstream header, with reviewed language ports. Descriptive factorial pilot; not a representative corpus or stable economic superiority proof."}


def run(output):
    entered = time.monotonic_ns()
    output = Path(output).resolve()
    registration = validate(output)
    registration_identity = file_identity(output / "REGISTRATION.json")
    configuration = protocol()
    if os.environ.get("LLAMA_ARG_REPACK") != "0":
        raise ValueError("runtime environment differs from registration")
    if (output / "RUN_STARTED.json").exists():
        raise ValueError("cohort already attempted; no retry or rescore")
    save(output / "RUN_STARTED.json", {"unix_ns": time.time_ns(), "registration_sha256": registration_identity["sha256"]})
    rows, engine, current_model, errors, cleanups = [], None, None, [], []
    session = 0

    def close_current():
        nonlocal engine
        owned, engine = engine, None
        try:
            record = close_engine(owned, registration)
        except BaseException as error:
            record = {"errors": [error_record("cleanup_observer", error)], "reaped": False}
        record.update(session=session, model_id=current_model)
        cleanups.append(record)
        if record["errors"]:
            errors.append({"stage": "cleanup", "type": "CleanupError", "message": "owned session cleanup/identity failed",
                           "session": session, "details": record["errors"]})
            return False
        return True

    try:
        tasks = {t["id"]: t for t in fixtures.make_fixtures()}
        for descriptor in registration["schedule"]:
            validate(output)
            if file_identity(output / "REGISTRATION.json") != registration_identity:
                raise RuntimeError("factorial registration changed after run started")
            model = next(m for m in configuration["models"] if m["id"] == descriptor["model_id"])
            if engine is None or current_model != model["id"]:
                if engine is not None and not close_current():
                    break
                session += 1
                engine = LlamaCppEngine(binary=registration["tools"]["binary"]["path"],
                    model=registration["models"][model["id"]]["path"], model_sha256=model["sha256"],
                    output_dir=output / ("model-session-" + str(session)),
                    threads=configuration["threads"], context=configuration["context_tokens"], json_object=True)
                current_model = model["id"]
                check_engine_registration(engine, registration, current_model)
                validate_runtime(registration)
            row, usable = cell(tasks[descriptor["task"]], descriptor, output / "cells" / descriptor["id"],
                               engine, registration, configuration)
            rows.append(row)
            print(canonical({"id": row["id"], "status": row["status"], "attempts": len(row["attempts"])}).decode(), flush=True)
            if row.get("fatal_error"):
                errors.append(row["fatal_error"])
                break
            if not usable and not close_current():
                break
    except BaseException as error:
        errors.append(error_record("cohort", error))
    finally:
        if engine is not None:
            close_current()
    source_unchanged = runtime_unchanged = registration_unchanged = False
    try:
        source_unchanged = prior.check_bindings(registration["source_bindings"])
        if not source_unchanged:
            raise RuntimeError("source drift after factorial cohort")
        validate(output)
    except BaseException as error:
        errors.append(error_record("final_frozen_inputs", error))
    try:
        validate_runtime(registration)
        runtime_unchanged = True
    except BaseException as error:
        errors.append(error_record("final_registered_runtime", error))
    try:
        registration_unchanged = file_identity(output / "REGISTRATION.json") == registration_identity
        if not registration_unchanged:
            raise RuntimeError("factorial registration changed")
    except BaseException as error:
        errors.append(error_record("final_registration", error))
    result = summarize(registration, rows, time.monotonic_ns() - entered, not errors, errors[0] if errors else None)
    result.update(errors=errors, session_cleanup=cleanups, source_unchanged=source_unchanged,
                  runtime_unchanged=runtime_unchanged, registration_unchanged=registration_unchanged)
    result["completed"] = result["completed"] and source_unchanged and runtime_unchanged and registration_unchanged
    result["registration_sha256"] = registration_identity["sha256"]
    result["source_commit"] = registration["source_commit"]
    result["source_tree"] = registration["source_tree"]
    save(output / "RESULT.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    p = commands.add_parser("prepare")
    for name in ("output", "binary", "assets", "clang", "rustc"):
        p.add_argument("--" + name, required=True)
    p = commands.add_parser("run")
    p.add_argument("--output", required=True)
    args = vars(parser.parse_args())
    action = args.pop("action")
    result = {"prepare": prepare, "run": run}[action](**args)
    print(canonical({k: result.get(k) for k in ("schema", "completed", "observed_cells", "arms", "error")}).decode())
    return 0 if action == "prepare" or result["completed"] and result["source_unchanged"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
