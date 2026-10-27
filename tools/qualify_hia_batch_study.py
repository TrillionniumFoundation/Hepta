#!/usr/bin/env python3
"""Frozen multi-site maintenance study with two independently published families.

Four paired contracts require changing two called helpers atomically. The eight
helper specifications come from the retained single-site study; they are not
new independent task sources.  Native bad/partially fixed/fully fixed controls
are required before any inference. No retry or response repair is permitted.
"""
from __future__ import annotations

import argparse
import copy
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta.hia_edit_batch import apply_batch, prepare_batch, render_batch_context
from hepta.hia_program import verify_program
from hepta.hia_program_llvm import build_program_native
from hepta.hia_program_tools import decode_json
from tools.provider_adapter.llama_cpp_engine import canonical, file_identity
from tools.qualify_hia_edit_study import (ARMS, SCORED_STATES, _run_model, bindings as old_bindings,
                                        fixtures as single_fixtures, instruction, scheduled_cells,
                                        sha, summarize, write)

PROTOCOL = "hepta.hia.atomic-maintenance-study.v1"
LIMIT = 512
PAIRS = (("capacity_roundup", "capacity", "ceil_half"),
         ("tagged_octet", "low_byte", "xor_tag"),
         ("epoch_delta", "distance", "next_epoch"),
         ("weighted_minimum", "triple", "minimum"))
CASES = ((0, 0), (0, 1), (1, 0), (1, 1), (17, 29), (29, 17),
         (255, 256), (256, 255), (1431655766, 19), (2147483648, 1),
         (4294967294, 4294967295), (4294967295, 1), (4294967295, 4294967295))


def formula(name, x, y):
    # Independent arithmetic specification; no HIA/Rust instruction is read.
    value = {"capacity": lambda: int(x < y), "ceil_half": lambda: (x + 1) // 2,
             "low_byte": lambda: x % 256, "xor_tag": lambda: x ^ y,
             "distance": lambda: x - y, "next_epoch": lambda: x + 1,
             "triple": lambda: 3 * x, "minimum": lambda: min(x, y)}[name]()
    return value % 2**32


def fixtures():
    singles = {task["id"]: task for task in single_fixtures()}
    tasks = []
    for name, first, second in PAIRS:
        parts = [copy.deepcopy(singles[first]), copy.deepcopy(singles[second])]
        functions, selections = [], []
        for index, part in enumerate(parts):
            label = "part_" + str(index)
            fn = copy.deepcopy(part["hia"]["functions"][0])
            fn["name"] = label
            functions.append(fn)
            selections.append({"function": label, "block": "entry", "output": part["output"],
                               "fields": [part["field"]]})
        params = [{"name": n, "type": "u32"} for n in ("x", "y")]
        ops = [instruction("call", ["x", "y"][:len(part["names"])], "a" if index == 0 else "b",
                           function="part_" + str(index)) for index, part in enumerate(parts)]
        ops.extend([instruction("const", [], "weight", value=31),
                    instruction("int.mul.wrap", ["a", "weight"], "weighted"),
                    instruction("int.add.wrap", ["weighted", "b"], "result")])
        functions.append({"name": "entrypoint", "params": params, "returns": ["u32"], "effects": ["trap"],
                          "entry": "entry", "blocks": [{"id": "entry", "params": params, "ops": ops,
                                                          "term": {"op": "ret", "values": ["result"]}}]})
        program = {"schema": "hepta.hia.program.v6", "module": name,
                   "exports": ["entrypoint"], "functions": functions}
        tasks.append({"id": name, "parts": parts, "hia": program, "selections": selections,
                      "cases": [list(c) for c in CASES],
                      "expected": [(31 * formula(first, x, y) + formula(second, x, y)) % 2**32
                                   for x, y in CASES]})
        verify_program(program)
    return tasks


def query_for(task):
    return prepare_batch(task["hia"], task["selections"])


def response_for(task, language, fixed_mask):
    edits = []
    for index, part in enumerate(task["parts"]):
        if language == "hia":
            field = part["field"]
            original = query_for(task)["sites"][index]["query"]["context"]["operation"][field]
            changes = {field: part["good"] if fixed_mask & (1 << index) else original}
        else:
            changes = {"replacement": part["rust_good"] if fixed_mask & (1 << index) else part["rust_bad"]}
        edits.append({"site": index, "changes": changes})
    return {"edits": edits}


def rust_sources(task, replacements):
    sources = {}
    for index, (part, replacement) in enumerate(zip(task["parts"], replacements)):
        name = "part_" + str(index)
        sources[name + ".rs"] = part["rust_template"].replace("pub fn kernel(", "pub fn " + name + "(").replace("@SLOT@", replacement)
    calls = ["part_" + str(i) + "::part_" + str(i) + "(" + ",".join(["x", "y"][:len(p["names"])]) + ")"
             for i, p in enumerate(task["parts"])]
    sources["caller.rs"] = ("mod part_0; mod part_1;\nfn entrypoint(x:u32,y:u32)->u32{"
                             + calls[0] + ".wrapping_mul(31).wrapping_add(" + calls[1] + ")}")
    return sources


def prompt(task, arm):
    hia = arm.startswith("hia")
    language = "hia" if hia else "rust"
    contracts = []
    for index, part in enumerate(task["parts"]):
        contracts.append("part_" + str(index) + "(" + ",".join(part["names"]) + "): " + part["description"])
    if hia:
        context = canonical(task["hia"]).decode() if arm == "hia_full_context" else render_batch_context(query_for(task))
        rules = "HIA .wrap is modulo word width; .checked traps on overflow; bit.and/or/xor are bitwise; compare.lt/le/gt/ge/eq/ne are unsigned comparisons."
    else:
        rules = "Rust arguments/results are u32; wrapping methods are modulo 2^32; checked arithmetic may terminate."
        if arm == "rust_full_context":
            context = "\n".join(name + ":\n" + source for name, source in rust_sources(
                task, [p["rust_bad"] for p in task["parts"]]).items())
        else:
            context = "\n".join("@" + str(index) + " " + part["rust_signature"].replace("kernel", "part_" + str(index))
                                  + "\nExpression: " + part["rust_body"] + "\nCurrent @SLOT@: " + part["rust_bad"]
                                  for index, part in enumerate(task["parts"]))
    return ("Repair both helper sites in one atomic response. Return ONLY JSON, without fences or explanation.\n"
            + "Contracts:\n" + "\n".join(contracts)
            + "\nThe unchanged caller passes x,y (only x to unary helpers) and returns part_0 * 31 + part_1 modulo 2^32.\n"
            + rules + "\nContext:\n" + context
            + "\nChange only the marked fields. Correct both entries in this response object:\n"
            + canonical(response_for(task, language, 0)).decode())


def parse_response(task, arm, text):
    if type(text) is not str or len(text.encode()) > 64 * 1024:
        raise ValueError("E_BATCH_STUDY_RESPONSE")
    value = decode_json(text)
    if type(value) is not dict or set(value) != {"edits"} or type(value["edits"]) is not list or len(value["edits"]) != 2:
        raise ValueError("E_BATCH_STUDY_FIELDS")
    hia, replacements, seen = arm.startswith("hia"), {}, set()
    for edit in value["edits"]:
        if type(edit) is not dict or set(edit) != {"site", "changes"} or type(edit["site"]) is not int or edit["site"] not in (0, 1) or edit["site"] in seen:
            raise ValueError("E_BATCH_STUDY_SITE")
        index = edit["site"]; seen.add(index)
        part = task["parts"][index]; field = part["field"] if hia else "replacement"
        changes = edit["changes"]
        if type(changes) is not dict or set(changes) != {field}:
            raise ValueError("E_BATCH_STUDY_FIELD")
        allowed = part["allowed"] if hia else part["rust_allowed"]
        if not any(canonical(changes[field]) == canonical(option) for option in allowed):
            raise ValueError("E_BATCH_STUDY_ALTERNATIVE")
        replacements[index] = changes[field]
    return (apply_batch(task["hia"], query_for(task), value)[0] if hia else
            rust_sources(task, [replacements[0], replacements[1]]))


def expected_trap(task, candidate, language):
    if not any(p["id"] == "next_epoch" for p in task["parts"]):
        return None
    checked = (any(op["op"] == "int.add.checked" for fn in candidate.as_dict()["functions"]
                   for block in fn["blocks"] for op in block["ops"]) if language == "hia" else
               any('checked_add(1).expect("overflow")' in value for value in candidate.values()))
    return next((i for i, case in enumerate(task["cases"]) if case[0] == 2**32 - 1), None) if checked else None


def classify(task, language, code, stdout, stderr, trap_case):
    base = {"ok": False, "native_executed": False, "status": "infrastructure_error",
            "returncode": code, "stdout": stdout, "stderr": stderr, "expected": task["expected"]}
    lines, actual = stdout.splitlines(), []
    if not lines or lines[0] != "STUDY_READY":
        return base
    count = len(task["cases"]) if code == 0 else trap_case
    if count is None:
        return base
    expected_length = 2 + 2 * count
    if len(lines) != expected_length:
        return base
    for i in range(count):
        if lines[1 + 2 * i] != "STUDY_CALL " + str(i):
            return base
        match = re.fullmatch(r"STUDY_VALUE " + str(i) + r" ([0-9]+)", lines[2 + 2 * i])
        if match is None or not 0 <= int(match[1]) < 2**32:
            return base
        actual.append(int(match[1]))
    if code == 0 and lines[-1] == "STUDY_DONE":
        ok = actual == task["expected"]
        return {**base, "ok": ok, "native_executed": True, "status": "correct" if ok else "observable_wrong", "actual": actual}
    trapped = ((code == -signal.SIGABRT and not stderr.strip()) if language == "hia" else
               code == 101 and "panicked at" in stderr and "overflow" in stderr)
    if trapped and lines[-1] == "STUDY_CALL " + str(trap_case):
        return {**base, "native_executed": True, "status": "expected_overflow_trap",
                "completed_values": actual, "trapping_case": trap_case}
    return base


def native(task, candidate, language, directory, clang, rustc):
    folder = Path(directory); folder.mkdir(parents=True, exist_ok=False)
    record = {"ok": False, "native_executed": False, "status": "infrastructure_error"}
    try:
        compiler = clang if language == "hia" else rustc
        before = file_identity(compiler)
        binary = folder / "candidate"
        if language == "hia":
            (folder / "program.json").write_bytes(candidate.canonical_bytes)
            record["native_compile"] = build_program_native(candidate, folder / "program.o", clang=clang, kind="object")
            calls = []
            for index, (x, y) in enumerate(task["cases"]):
                calls.append('puts("STUDY_CALL ' + str(index) + '");printf("STUDY_VALUE ' + str(index)
                             + ' %u\\n",entrypoint(' + str(x) + 'u,' + str(y) + 'u));')
            driver = folder / "driver.c"
            driver.write_text('#include <stdio.h>\n#include <stdint.h>\nextern uint32_t entrypoint(uint32_t,uint32_t);\n'
                              + 'int main(void){setbuf(stdout,0);puts("STUDY_READY");' + ''.join(calls)
                              + 'puts("STUDY_DONE");return 0;}\n')
            command = [clang, "-O2", str(driver), str(folder / "program.o"), "-o", str(binary)]
        else:
            for name, source in candidate.items():
                (folder / name).write_text(source)
            calls = []
            for index, (x, y) in enumerate(task["cases"]):
                calls.append('println!("STUDY_CALL ' + str(index) + '");std::io::stdout().flush().unwrap();'
                             + 'let v=entrypoint(' + str(x) + 'u32,' + str(y) + 'u32);println!("STUDY_VALUE '
                             + str(index) + ' {}",v);')
            main = folder / "main.rs"
            main.write_text('#![forbid(unsafe_code)]\nuse std::io::Write;\n' + candidate["caller.rs"]
                            + '\nfn main(){println!("STUDY_READY");' + ''.join(calls) + 'println!("STUDY_DONE");}\n')
            command = [rustc, "--edition=2021", "-C", "opt-level=2", "-C", "overflow-checks=on", str(main), "-o", str(binary)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=45)
        record["compile"] = {"argv": command, "returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr}
        if result.returncode:
            return record
        artifact = file_identity(binary)
        run = subprocess.run([str(binary)], capture_output=True, text=True, timeout=15)
        record.update(classify(task, language, run.returncode, run.stdout, run.stderr, expected_trap(task, candidate, language)))
        record["artifact"] = file_identity(binary)
        if record["artifact"] != artifact or file_identity(compiler) != before:
            record.update(ok=False, native_executed=False, status="infrastructure_error", error="artifact or compiler identity drift")
    except Exception as exc:
        record.update(ok=False, native_executed=False, status="infrastructure_error", error={"type": type(exc).__name__, "message": str(exc)})
        if isinstance(exc, subprocess.TimeoutExpired):
            record["partial_stdout"] = repr(exc.stdout); record["partial_stderr"] = repr(exc.stderr)
    return record


def bindings():
    result = old_bindings()
    result[str(Path(__file__).resolve().relative_to(ROOT))] = file_identity(__file__)["sha256"]
    return result


def criteria(summary, complete):
    hia, rust, full = (summary[arm] for arm in ("hia_edit_query", "rust_edit_query", "hia_full_context"))
    qualified = complete and all(row["usage_complete"] for row in (hia, rust, full)) and hia["successes"] == 4
    tokens = lambda row: row["input_tokens"] + row["output_tokens"]
    return {"primary": bool(qualified and hia["successes"] >= rust["successes"] and tokens(hia) <= tokens(rust)),
            "secondary": bool(qualified and hia["successes"] >= full["successes"] and tokens(hia) < tokens(full))}


def run_study(output, models, binary, clang, rustc, threads=4, *, controls_only=False):
    if (type(models) is not list or len(models) != 2
            or any(type(m) is not dict or not {"id", "family", "path", "sha256", "repository", "revision"}.issubset(m) for m in models)
            or len({m["family"] for m in models}) != 2 or len({m["sha256"] for m in models}) != 2
            or any(type(m["id"]) is not str or re.fullmatch(r"[a-z][a-z0-9_]{0,63}", m["id"]) is None for m in models)
            or len({m["id"] for m in models}) != 2):
        raise ValueError("E_BATCH_STUDY_MODELS: two distinct identified model families required")
    status = subprocess.run(["git", "status", "--porcelain", "--untracked-files=all"], cwd=ROOT,
                            check=True, capture_output=True, text=True).stdout
    commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, check=True,
                            capture_output=True, text=True).stdout.strip()
    if status and not controls_only:
        raise ValueError("commit the complete implementation before inference")
    out = Path(output).absolute(); out.mkdir(parents=True, exist_ok=False)
    tasks, initial = fixtures(), bindings()
    plan = {"schema": PROTOCOL, "tasks": tasks, "arms": list(ARMS), "models": models,
            "source_bindings": initial, "git_commit": commit, "source_was_committed": not bool(status),
            "mode": "development_controls_only" if controls_only else "frozen_complete_study",
            "runtime": file_identity(binary), "clang": file_identity(clang), "rustc": file_identity(rustc),
            "max_new_tokens": LIMIT, "threads": threads, "greedy": True, "seed": 0, "attempts_per_cell": 1,
            "scheduled_task_requests": 32, "scheduled_preflights": 4,
            "native_controls": "per task/language: neither, only site 0, only site 1, both repaired; 32 actual executions",
            "decoder": {"json_schema": {"type": "object"}, "answer_fields_constrained": False},
            "minimum_hia_query_successes": 4,
            "primary_rule": "per model: all 4 HIA query tasks correct, success >= Rust query, task input+output tokens <= Rust query",
            "secondary_rule": "per model: all 4 HIA query tasks correct, success >= HIA full, task input+output tokens < HIA full",
            "maintenance_structure": "two edited helper functions plus unchanged caller; one HIA module versus three Rust source files",
            "task_origin": "four new compositions of the previous eight disclosed arithmetic contracts; not independent source tasks",
            "response_policy": "strict complete batch JSON; one attempt; no retries, fence extraction, correction or rescoring",
            "cost_scope": "all actual completion requests retained, including probes; inference and native evaluation time separately measured",
            "unmeasured_costs": ["human labor", "model training", "integration", "model load/setup", "real upstream upgrades"],
            "limits": ["finite disclosed arithmetic maintenance", "one attempt and one quantization per model", "not HIA multi-module linking",
                       "representation and context change together", "no general productivity or total economic cost claim"]}
    plan_hash = sha(canonical(plan)); write(out / "plan.json", {**plan, "plan_sha256": plan_hash})
    controls = []
    for task in tasks:
        for language in ("hia", "rust"):
            for mask in range(4):
                name = task["id"] + "_" + language + "_mask" + str(mask)
                candidate = parse_response(task, language + "_edit_query", canonical(response_for(task, language, mask)).decode())
                result = native(task, candidate, language, out / "controls" / name, clang, rustc)
                passed = (result.get("native_executed") is True and
                          (result["status"] == "correct" if mask == 3 else result["status"] in {"observable_wrong", "expected_overflow_trap"}))
                controls.append({"id": name, "passed": passed, "fixed_mask": mask, "result": result})
    write(out / "controls.json", controls)
    controls_ok = all(row["passed"] for row in controls)
    reports = []
    if controls_ok and not controls_only:
        formats = [(language, canonical({"edits": [
            {"site": i, "changes": {"op" if language == "hia" else "replacement": "const" if language == "hia" else "0"}}
            for i in range(2)]}).decode()) for language in ("hia", "rust")]
        for index, model in enumerate(models):
            reports.append(_run_model(model, index, tasks, out, binary, clang, rustc, threads, initial,
                                      json_object=True, prompt_fn=prompt, parse_fn=parse_response, native_fn=native,
                                      bindings_fn=bindings, response_limit=LIMIT, preflight_formats=formats))
    else:
        for index, model in enumerate(models):
            cells = scheduled_cells(tasks, index)
            report = {"model": model, "status": "not_started_development_controls" if controls_only else "not_started_native_controls_failed",
                      "planned_cells": cells, "completed_cells": [], "unfinished_cells": cells, "unstarted_cells": cells,
                      "rows": [], "preflight": [], "summary": summarize([], planned_tasks=len(tasks)),
                      "requests_started": 0, "responses_received": 0, "unresolved_requests": 0,
                      "identity": {"model_unchanged": False, "runtime_unchanged": False, "available": False}}
            write(out / model["id"] / "report.json", report); reports.append(report)
    source_stable = bindings() == initial
    tools_after = {name: file_identity(path) for name, path in (("runtime", binary), ("clang", clang), ("rustc", rustc))}
    toolchain_stable = all(tools_after[name] == plan[name] for name in tools_after)
    complete = (not controls_only and controls_ok and source_stable and toolchain_stable and len(reports) == 2
                and all(report["status"] == "completed" and len(report["completed_cells"]) == 16
                        and not report["unfinished_cells"] and not report["unresolved_requests"]
                        and report["identity"]["model_unchanged"] and report["identity"]["runtime_unchanged"] for report in reports))
    comparisons = [criteria(report["summary"], complete) for report in reports]
    result = {"schema": PROTOCOL, "status": "completed" if complete else "development_controls_only" if controls_only else "incomplete",
              "plan_sha256": plan_hash, "git_commit": commit, "source_unchanged": source_stable,
              "toolchain_unchanged": toolchain_stable, "final_tool_identities": tools_after,
              "native_controls": len(controls), "native_controls_passed": sum(row["passed"] for row in controls),
              "models": reports, "primary_criteria_per_model": [c["primary"] for c in comparisons],
              "secondary_criteria_per_model": [c["secondary"] for c in comparisons],
              "actual_requests": sum(r["requests_started"] for r in reports),
              "actual_responses": sum(r["responses_received"] for r in reports),
              "general_productivity_advantage_established": False, "total_development_cost_measured": False,
              "limitations": plan["limits"] + plan["unmeasured_costs"]}
    write(out / "report.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("output", "models-lock", "binary", "clang", "rustc"):
        parser.add_argument("--" + flag, required=True)
    parser.add_argument("--threads", type=int, default=4)
    parser.add_argument("--controls-only", action="store_true")
    args = vars(parser.parse_args()); lock = json.loads(Path(args.pop("models_lock")).read_text())
    result = run_study(models=lock["models"], **args)
    print(json.dumps({key: result[key] for key in ("status", "native_controls", "native_controls_passed", "actual_requests",
                                                   "primary_criteria_per_model", "secondary_criteria_per_model")}))
    return 0 if result["status"] == "completed" or args["controls_only"] and result["native_controls_passed"] == 32 else 1


if __name__ == "__main__":
    raise SystemExit(main())
