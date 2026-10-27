#!/usr/bin/env python3
"""Retain and replay source-bound concurrent protocol graphs with native runs."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from hepta.concurrent_ir import CLAIMS, read_graph, verify_concurrent_ir
from hepta.pipeline import analyze, compiler_hash, concurrent_ir_analysis
from tools.validate_groups import run_scenario

SCENARIOS = ("bounded_pipeline", "admission_budgets", "cancellation", "worker_failure")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def mutations(original):
    result = {}
    def ops(doc, worker=False):
        return doc["functions"][0 if worker else -1]["blocks"][0]["operations"]
    def change(name, action):
        doc = copy.deepcopy(original)
        action(doc)
        result[name] = doc
    change("cancel_does_not_join", lambda d: ops(d).__setitem__(-1, {"op": "group", "src": ops(d)[-1]["src"], "mode": "group_cancel"}))
    change("worker_buffer_leak", lambda d: ops(d, True).pop())
    change("wrong_worker_signature", lambda d: next(o for o in ops(d) if o["op"] == "spawn").update(worker="main"))
    change("forged_sender", lambda d: ops(d, True)[0].update(src="invented"))
    change("double_join", lambda d: ops(d).append(copy.deepcopy(ops(d)[-1])))
    change("use_after_join", lambda d: ops(d).append({"op": "group", "src": ops(d)[-1]["src"], "mode": "group_snapshot"}))
    change("unknown_operation", lambda d: ops(d).append({"op": "ignore"}))
    change("owned_cancellation", lambda d: d["functions"][0]["params"][1].update(mode="take"))
    change("invented_task", lambda d: next(o for o in ops(d) if o["op"] == "create").update(type="Task<u64>"))
    change("false_refinement_claim", lambda d: d["claims"].update(source_to_ir_refinement_proved=True))
    change("numeric_proof_claim", lambda d: d["claims"].update(worker_input_transfer_verified=1))
    change("capability_owner_slot", lambda d: d["functions"][0]["slots"].update(v1="Cancellation"))
    change("duplicate_function", lambda d: d["functions"].append(copy.deepcopy(d["functions"][0])))
    change("unreachable_unknown_operation", lambda d: d["functions"][-1]["blocks"].append({"id": "unreachable", "operations": [{"op": "unknown"}], "terminator": {"op": "return", "owner": None}}))
    change("dangling_edge", lambda d: d["functions"][-1]["blocks"][0].update(terminator={"op": "jump", "targets": ["missing"]}))
    return result


def lower(path):
    analysis = analyze(path.read_text(), str(path), native=True, crate_type="bin")
    exported = concurrent_ir_analysis(analysis)
    if exported["ok"] is not True:
        raise RuntimeError(json.dumps(exported))
    return exported


def qualify(output):
    before = compiler_hash()
    directory = output.with_suffix(".graphs")
    directory.mkdir(parents=True, exist_ok=False)
    projects = []
    names = (*SCENARIOS, "select_pipeline", "shared_budget", "protocol")
    for name in names:
        path = ROOT / "examples/groups" / (name + ".hepta")
        exported = lower(path)
        graph = exported["concurrent_ir"]
        target = directory / (name + ".json")
        data = (json.dumps(graph, sort_keys=True, indent=2) + "\n").encode()
        target.write_bytes(data)
        independent = subprocess.run([sys.executable, "-m", "hepta.concurrent_ir", str(target)],
                                     cwd=ROOT, text=True, capture_output=True, timeout=30)
        replay = json.loads(independent.stdout)
        if independent.returncode or replay.get("ok") is not True or replay.get("source_binding_verified") is not False:
            raise RuntimeError("Independent concurrent graph process rejected: " + independent.stdout + independent.stderr)
        native = run_scenario(name, repeats=3) if name in SCENARIOS else None
        if native is None:
            # New runtime examples carry their own exact assertions. The full
            # fault/race denominator is qualified separately by shared_runtime.
            native = {"runs": []}
            for trial in range(3):
                executed = subprocess.run([sys.executable, "-m", "hepta", "run", str(path), "--json"],
                                          cwd=ROOT, text=True, capture_output=True, timeout=45)
                report = json.loads(executed.stdout)
                if executed.returncode or report.get("ok") is not True or report.get("returncode") != 0:
                    raise RuntimeError("Concurrent source did not execute: " + executed.stdout + executed.stderr)
                native["runs"].append({"trial": trial, **report})
        projects.append({"name": name, "source": str(path.relative_to(ROOT)),
                         "source_sha256": digest(path.read_bytes()), "validation": exported["validation"],
                         "graph": {"path": str(target.resolve()), "sha256": digest(data), "bytes": len(data)},
                         "verification": exported["verifier"], "standalone_replay": replay,
                         "native": native})
    base = read_graph(directory / "protocol.json")
    controls = []
    for name, document in mutations(base).items():
        result = verify_concurrent_ir(document)
        if result["ok"]:
            raise ValueError("Invalid concurrent protocol accepted: " + name)
        controls.append({"name": name, "graph_sha256": digest(json.dumps(document, sort_keys=True, separators=(",", ":")).encode()),
                         "verification": result})
    if compiler_hash() != before:
        raise ValueError("Compiler changed during concurrent protocol qualification")
    return {"schema": "hepta.concurrent-qualification.v1", "status": "passed", "compiler_sha256": before,
            "projects": projects, "negative_controls": controls, "claims": dict(CLAIMS)}


def validate_report(report):
    names = {*SCENARIOS, "select_pipeline", "shared_budget", "protocol"}
    projects = report.get("projects", [])
    if (report.get("schema") != "hepta.concurrent-qualification.v1" or report.get("status") != "passed"
            or report.get("compiler_sha256") != compiler_hash() or report.get("claims") != CLAIMS
            or len(projects) != len(names) or {p.get("name") for p in projects} != names):
        raise ValueError("Concurrent qualification identity, claims, or project denominator differs")
    graphs = {}
    for project in projects:
        name = project["name"]
        source = ROOT / "examples/groups" / (name + ".hepta")
        metadata = project.get("graph", {})
        path = Path(metadata["path"])
        graph = read_graph(path)
        graphs[name] = graph
        actual = verify_concurrent_ir(graph)
        validation = project.get("validation", {})
        if (metadata.get("sha256") != digest(path.read_bytes()) or metadata.get("bytes") != path.stat().st_size
                or project.get("source") != str(source.relative_to(ROOT))
                or project.get("source_sha256") != digest(source.read_bytes())
                or graph["source_sha256"] != project["source_sha256"]
                or validation.get("ok") is not True or validation.get("compiler_sha256") != compiler_hash()
                or validation.get("source_sha256") != graph["source_sha256"]
                or validation.get("checks", {}).get("rust_borrows_types") != "rustc_checked"
                or actual.get("ok") is not True or actual != project.get("verification")
                or project.get("standalone_replay") != {**actual, "source_binding_verified": False}):
            raise ValueError("Retained concurrent graph is not source/native bound and independently revalidated")
        native = project.get("native", {})
        if len(native.get("runs", [])) != 3:
            raise ValueError("Every concurrent source must execute three times")
        for run in native["runs"]:
            if type(run.get("returncode")) is not int or run["returncode"] != 0:
                raise ValueError("Concurrent native execution failed")
            if name not in SCENARIOS:
                build = run.get("build", {})
                if (run.get("ok") is not True or build.get("ok") is not True or build.get("check_only") is not False
                        or type(build.get("artifact_bytes")) is not int or build["artifact_bytes"] < 1
                        or build.get("artifact_sha256") != build.get("validation_artifact_sha256")):
                    raise ValueError("Concurrent source did not retain an actual executable build")
        if name in SCENARIOS and (native.get("status") != "passed" or native.get("source_sha256") != project["source_sha256"]
                                  or native.get("compiler_sha256") != compiler_hash()):
            raise ValueError("Concurrent native scenario differs from source/compiler")
    expected = mutations(graphs["protocol"])
    negative = report.get("negative_controls", [])
    if len(negative) != len(expected) or {x.get("name") for x in negative} != set(expected):
        raise ValueError("Concurrent graph mutation denominator differs")
    for entry in negative:
        graph = expected[entry["name"]]
        actual = verify_concurrent_ir(graph)
        if (actual["ok"] or entry.get("verification") != actual or entry.get("graph_sha256")
                != digest(json.dumps(graph, sort_keys=True, separators=(",", ":")).encode())):
            raise ValueError("Invalid concurrent protocol did not reject independently")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/concurrent-ir.json")
    args = parser.parse_args()
    report = qualify(args.output.resolve())
    validate_report(report)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"status": report["status"], "projects": len(report["projects"]),
                      "negative_controls": len(report["negative_controls"]), "output": str(args.output)}))


if __name__ == "__main__":
    main()
