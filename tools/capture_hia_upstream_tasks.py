"""Capture real stb overflow-fix tasks with explicit reference provenance.

C-to-Core correctness is a separate trust boundary. Inlining and alpha naming
are checked by the existing per-program, all-input scalar-call validator.
The new floor reference is a separately authored mathematical implementation:
an unknown inlining result never authorizes execution of the proposed rewrite.
"""
from __future__ import annotations

import argparse
import copy
from hashlib import sha256
import json
from pathlib import Path
import shutil
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta.c_migrate import migrate_c_project
from hepta.hia_program_source import lower_source
from hepta.hia_program import verify_program
from hepta.hia_agent_assembly import render_assembly, assemble_program
from hepta.hia_scalar_call_validation import inline_scalar_calls, validate_scalar_calls
from tools.qualify_c_stb_divide import capture_fixture

FUNCTIONS = ("c_stb_div_floor", "c_stb_mod_eucl")


def write(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def compact(function):
    result = copy.deepcopy(function)
    names = {p["name"]: p["name"] for p in result["params"]}
    for block in result["blocks"]:
        for value in [*block["params"], *[v for op in block["ops"] for v in op["out"]]]:
            if value["name"] not in names:
                names[value["name"]] = "v" + str(len(names) + 100)
    blocks = {b["id"]: "b" + str(i) for i, b in enumerate(result["blocks"])}
    result["entry"] = blocks[result["entry"]]
    for block in result["blocks"]:
        block["id"] = blocks[block["id"]]
        for value in [*block["params"], *[v for op in block["ops"] for v in op["out"]]]:
            value["name"] = names[value["name"]]
        for op in block["ops"]:
            op["args"] = [names[a] for a in op["args"]]
        term = block["term"]
        if term["op"] == "ret":
            term["values"] = [names[a] for a in term["values"]]
        edges = ([term] if term["op"] == "jump" else [term["then"], term["else"]] if term["op"] == "branch" else [])
        if term["op"] == "branch":
            term["cond"] = names[term["cond"]]
        for edge in edges:
            edge["target"] = blocks[edge["target"]]
            edge["args"] = [names[a] for a in edge["args"]]
    return result


def run(output, fixtures, clang, *, solver_timeout_ms=10000):
    if type(solver_timeout_ms) is not int or not 1 <= solver_timeout_ms <= 10000:
        raise ValueError("task-construction solver budget must be in 1..10000 ms")
    output, fixtures = Path(output).resolve(), Path(fixtures).resolve()
    output.mkdir(parents=True, exist_ok=False); fixtures.mkdir(parents=True, exist_ok=True)
    started = time.monotonic_ns()
    report = {"schema": "hepta.hia.upstream-agent-task-capture.v1", "ok": False,
              "versions": {}, "model_requests": 0, "formal_C_refinement_proved": False,
              "origin": "two real overflow fixes from the same pinned stb_divide header",
              "human_labor_ns": None, "task_construction_solver_timeout_ms": solver_timeout_ms,
              "independent_of_fixed_Lean_acceptance_budget": True}
    try:
        for label, profile in (("before", "stb_divide_v0_93"), ("after", "stb_divide")):
            directory = output / label; directory.mkdir()
            metadata = json.loads((ROOT / "tests/fixtures/c_migration" / profile / "UPSTREAM.json").read_text())
            header = ROOT / "tests/fixtures/c_migration" / profile / "stb_divide.h"
            expected = next(row["sha256"] for row in metadata["files"] if row["local_path"] == "stb_divide.h")
            if sha256(header.read_bytes()).hexdigest() != expected:
                raise ValueError("upstream source identity drift")
            database = capture_fixture(directory / "upstream", [])
            shutil.copyfile(header, directory / "upstream/stb_divide.h")
            migration = migrate_c_project(database, directory / "translated", clang=clang)
            write(directory / "MIGRATION.json", migration)
            if not migration["ok"]:
                raise ValueError("complete upstream migration rejected")
            core = lower_source((directory / "translated/source.hepta").read_text())
            (directory / "captured.core.json").write_bytes(core.canonical_bytes)
            row = {"metadata": metadata, "header_sha256": expected, "coverage": migration["coverage"],
                   "captured_core_sha256": core.sha256, "selected": {}}
            report["versions"][label] = row
            for name in FUNCTIONS:
                inlined = inline_scalar_calls(core, function=name)
                proof = validate_scalar_calls(core.as_dict(), inlined, function=name, timeout_ms=solver_timeout_ms)
                write(directory / (name + ".inlining.json"), proof)
                manual_floor = label == "after" and name == "c_stb_div_floor"
                if proof["status"] != "proved" and not manual_floor:
                    raise ValueError("call-graph inlining not proved: " + name)
                if manual_floor:
                    # This is a new authored repair, not an optimizer rewrite.
                    # Select it unconditionally, independently of SMT outcome.
                    # The unproved inlined new C graph is never executed.
                    source = (fixtures / "floor_reference.hiaasm").read_text()
                    primitive = assemble_program(source)
                    function = primitive.as_dict()["functions"][0]
                    if render_assembly(primitive) != source:
                        raise ValueError("manual floor reference is not canonical")
                    row["selected"][name] = {
                        "path": "floor_reference.hiaasm", "bytes": len(source.encode()),
                        "sha256": sha256(source.encode()).hexdigest(),
                        "core_sha256": primitive.sha256,
                        "blocks": len(function["blocks"]),
                        "operations": sum(len(b["ops"]) for b in function["blocks"]),
                        "inlining_status": proof["status"],
                        "representation_status": "not_applicable_to_authored_repair",
                        "reference_origin": "separately authored widened quotient/remainder mathematical implementation",
                        "captured_after_inlining_authorized": False,
                        "all_input_C_or_captured_Core_refinement_proved": False,
                        "required_validation": "native upstream C, HIA, Rust, canonical VM and independent finite mathematical oracle"}
                    continue
                function = copy.deepcopy(next(f for f in verify_program(inlined).as_dict()["functions"] if f["name"] == name))
                if any(op["op"] == "call" for b in function["blocks"] for op in b["ops"]):
                    raise ValueError("selected function still has a callee")
                function["name"] = "target"
                # Legacy scalar instructions are rechecked under the canonical
                # explicit primitive grammar; no operation/effect is repaired.
                original = verify_program({"schema": core.as_dict()["schema"], "module": name,
                                           "exports": ["target"], "functions": [function]})
                primitive = verify_program({"schema": "hepta.hia.program.v6", "module": name,
                                            "exports": ["target"], "functions": [compact(function)]})
                bridge = validate_scalar_calls(original.as_dict(), primitive.as_dict(), function="target", timeout_ms=solver_timeout_ms)
                write(directory / (name + ".representation.json"), bridge)
                if bridge["status"] != "proved":
                    raise ValueError("primitive/alpha representation not proved: " + name)
                assembly = render_assembly(primitive)
                if assemble_program(assembly).canonical_bytes != primitive.canonical_bytes:
                    raise ValueError("assembly roundtrip changed Core")
                path = fixtures / (name + "-" + label + ".hiaasm")
                if path.exists():
                    if path.read_text() != assembly:
                        raise ValueError("existing task source differs; do not overwrite")
                else:
                    with path.open("x") as stream:
                        stream.write(assembly)
                row["selected"][name] = {"path": path.name, "bytes": path.stat().st_size,
                    "sha256": sha256(path.read_bytes()).hexdigest(), "core_sha256": primitive.sha256,
                    "blocks": len(function["blocks"]), "operations": sum(len(b["ops"]) for b in function["blocks"]),
                    "inlining_status": proof["status"], "representation_status": bridge["status"],
                    "reference_origin": "captured selected function; inlining and alpha representation proved in bounded scalar profile"}
        report["ok"] = True
        write(fixtures / "UPSTREAM_TASKS.json", report)
    except BaseException as error:
        report["error"] = {"type": type(error).__name__, "message": str(error)}
    report["wall_ns"] = time.monotonic_ns() - started
    write(output / "CAPTURE.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True); parser.add_argument("--fixtures", required=True)
    parser.add_argument("--clang", required=True); args = parser.parse_args()
    result = run(args.output, args.fixtures, args.clang)
    print(json.dumps({"ok": result["ok"], "error": result.get("error"), "wall_ns": result["wall_ns"],
                      "selected": {k: v["selected"] for k, v in result["versions"].items()}}))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
