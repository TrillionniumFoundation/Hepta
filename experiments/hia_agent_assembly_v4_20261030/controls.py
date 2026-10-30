#!/usr/bin/env python3
"""Native controls for all three representations; never scored model answers."""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from experiments.hia_agent_assembly_v4_20261030 import fixtures, evaluator
from experiments.hia_agent_matched_v3_20261028.controls import rename_block
from experiments.hia_optimizer_eval.next_20261028.upgrade_pilot import op
from tools.provider_adapter.llama_cpp_engine import canonical


def inline_average(consumer):
    result = copy.deepcopy(consumer)
    operations = result["blocks"][0]["ops"]
    operations[1:1] = [op("int.cast", ["a"], "inline_a", "u64"),
        op("int.cast", ["b"], "inline_b", "u64"),
        op("int.add.wrap", ["inline_a", "inline_b"], "inline_sum", "u64"),
        op("const", [], "inline_two", "u64", value=2),
        op("int.div.checked", ["inline_sum", "inline_two"], "inline_average", "u64")]
    operations[6]["args"] = ["inline_average"]
    return result


def hostile_candidates():
    task = fixtures.make_fixtures()[0]
    rows = []
    for language in ("hia", "rust"):
        files = copy.deepcopy(task["correct_" + language])
        if language == "hia":
            files["client.hia.json"]["blocks"][0]["ops"][0]["args"] = ["b", "a"]
        else:
            files["client.rs"] = files["client.rs"].replace("api::average(a,b)", "api::average(b,a)")
        rows.append(("wrong_arguments", language, files))
        files = copy.deepcopy(task["correct_" + language])
        if language == "hia":
            files["api.hia.json"]["blocks"][0]["ops"] = [op("const", [], "answer", "u64", value=0)]
            files["client.hia.json"] = inline_average(files["client.hia.json"])
        else:
            files["api.rs"] = "pub fn average(a:u32,b:u32)->u64 { let _=a; let _=b; 0 }"
            files["client.rs"] = "use crate::api; pub fn entrypoint(a:u32,b:u32,c:u32)->u64 { let _=api::average(a,b); (((a as u64)+(b as u64))/2) ^ (((c & 255) as u64)<<40) }"
        rows.append(("wrong_provider_bypassed", language, files))
        files = copy.deepcopy(task["correct_" + language])
        if language == "hia":
            original = files["client.hia.json"]
            called = copy.deepcopy(original["blocks"][0]); called["id"] = "called"
            bypassed = inline_average(original)["blocks"][0]
            bypassed["id"] = "bypassed"; bypassed["ops"].pop(0)
            rename_block(called, "called_"); rename_block(bypassed, "bypassed_")
            original["blocks"] = [{"id": "entry", "params": copy.deepcopy(original["params"]),
                "ops": [op("const", [], "never", "bool", value=False)],
                "term": {"op": "branch", "cond": "never",
                         "then": {"target": "called", "args": ["a", "b", "c"]},
                         "else": {"target": "bypassed", "args": ["a", "b", "c"]}}}, called, bypassed]
        else:
            files["client.rs"] = "use crate::api; pub fn entrypoint(a:u32,b:u32,c:u32)->u64 { if false { let _=api::average(a,b); } let answer=(((a as u64)+(b as u64))/2) ^ (((c & 255) as u64)<<40); answer }"
        rows.append(("provider_not_executed", language, files))
    rows += [(kind, "assembly", fixtures.assembly_files(task, files))
             for kind, language, files in tuple(rows) if language == "hia"]
    return task, rows


def run(output, clang, rustc):
    folder = Path(output); folder.mkdir(parents=True, exist_ok=False)
    task, candidates = hostile_candidates()
    rows = []
    for name, language, files in candidates:
        built = evaluator.build(task, language, canonical({"files": files}).decode(),
                                folder / (name + "_" + language), clang, rustc)
        observed = evaluator.execute(built, task, task["public_cases"], task["public_expected"]) if built["native_built"] else None
        passed = bool(built["native_built"] and observed["actual"] == task["public_expected"]
                      and observed["status"] == "observable_wrong")
        rows.append({"name": name, "language": language, "build": built, "execution": observed, "passed": passed})
    result = {"count": len(rows), "passed": sum(row["passed"] for row in rows),
              "rows": rows, "model_answers": False}
    evaluator.save(folder / "CONTROLS.json", result)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("output", "clang", "rustc"):
        parser.add_argument("--" + name, required=True)
    result = run(**vars(parser.parse_args()))
    print(json.dumps({"count": result["count"], "passed": result["passed"]}), flush=True)
    raise SystemExit(result["count"] != result["passed"])
