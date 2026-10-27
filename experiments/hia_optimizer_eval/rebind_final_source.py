#!/usr/bin/env python3
"""Rebind frozen measurements to final source without collecting new samples.

Rebuild only the original HIA library and regenerate the original model request
messages. Never execute a benchmark driver or start an inference server. Earlier
plans, reports, archives and measured costs remain immutable historical records.
"""
from __future__ import annotations

import argparse
import difflib
import hashlib
import json
from pathlib import Path
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from hepta.hia_program import verify_program
from hepta.hia_program_llvm import compile_program_llvm, emit_program_llvm
from hepta.hia_program_source import lower_source
from tools import qualify_hia_agent_holdout as agent
from tools import qualify_hia_optimizer_bench as bench
from tools.provider_adapter.llama_cpp_engine import canonical


def sha(data):
    return hashlib.sha256(data).hexdigest()


def save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(canonical(value) + b"\n")


def run(output_dir, report_path):
    out = Path(output_dir).absolute()
    out.mkdir(parents=True, exist_ok=False)
    report_path = Path(report_path).absolute()
    if report_path.exists():
        raise ValueError("rebind report already exists")
    evidence = ROOT / "experiments/hia_optimizer_eval/evidence"
    preserved = {str(p.relative_to(ROOT)): sha(p.read_bytes())
                 for label in ("bench_final", "agent_final")
                 for p in (evidence / label).iterdir() if p.is_file()}
    current = {"bench_final": bench.source_bindings(), "agent_final": agent.bindings()}
    plans = {label: json.loads((evidence / label / "plan.json").read_bytes()) for label in current}
    changes = {}
    for label, manifest in current.items():
        prior = plans[label]["source_bindings"]
        changes[label] = {"added": sorted(set(manifest) - set(prior)),
                          "removed": sorted(set(prior) - set(manifest)),
                          "changed": [{"path": name, "measured_sha256": prior[name],
                                       "final_sha256": manifest[name]}
                                      for name in sorted(set(prior) & set(manifest))
                                      if prior[name] != manifest[name]],
                          "unchanged_count": sum(prior.get(name) == value for name, value in manifest.items())}
        if changes[label]["added"] or changes[label]["removed"]:
            raise ValueError("source inventory changed; this narrowly scoped rebind cannot be used")
        if [row["path"] for row in changes[label]["changed"]] != ["hepta/hia_optimization.py"]:
            raise ValueError("unexpected source changes; review before reusing measurements")
    save(out / "source_manifests.json", {"measured": {k: v["source_bindings"] for k, v in plans.items()},
                                         "final": current, "differences": changes})
    changed_name = "hepta/hia_optimization.py"
    changed_bytes = (ROOT / changed_name).read_bytes()
    destination = out / "changed_source" / changed_name
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(changed_bytes)
    with tarfile.open(evidence / "bench_final/raw-attempt.tar.xz", "r:xz") as archive:
        before = archive.extractfile("source_snapshot/" + changed_name).read()
        measured_library = archive.extractfile("hia.so").read()
        measured_core = archive.extractfile("program.hia").read()
        measured_ir = archive.extractfile("program.ll").read()
    (out / "source_changes.diff").write_text("".join(difflib.unified_diff(
        before.decode().splitlines(keepends=True), changed_bytes.decode().splitlines(keepends=True),
        fromfile="measured/" + changed_name, tofile="final/" + changed_name)))

    fixtures = agent.tasks()
    if canonical(fixtures) != canonical(plans["agent_final"]["tasks"]):
        raise ValueError("agent fixture or withheld oracle changed")
    if agent.scheduled_cells(fixtures, 0) != plans["agent_final"]["scheduled_cells"]:
        raise ValueError("agent schedule changed")
    prompt_rows = []
    with tarfile.open(evidence / "agent_final/raw-attempt.tar.xz", "r:xz") as archive:
        for task in fixtures:
            for arm in agent.ARMS:
                cell = task["id"] + "_" + arm
                name = "locked_local_model/" + cell + ".request.json"
                previous = archive.extractfile(name).read()
                request = {"messages": [{"role": "user", "content": agent.batch.prompt(task, arm)}],
                           "limit": agent.LIMIT}
                regenerated = canonical(request) + b"\n"
                target = out / "regenerated_requests" / (cell + ".request.json")
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(regenerated)
                prompt_rows.append({"id": cell, "archived_member": name,
                    "measured_request_sha256": sha(previous), "regenerated_request_sha256": sha(regenerated),
                    "request_bytes_identical": previous == regenerated,
                    "prompt_sha256": sha(request["messages"][0]["content"].encode())})
        probe_rows = []
        for index, language in enumerate(("hia", "rust"), 1):
            wanted = canonical({"edits": [
                {"site": i, "changes": {"op" if language == "hia" else "replacement":
                                         "const" if language == "hia" else "0"}}
                for i in range(2)]}).decode()
            messages = [{"role": "user", "content": "Return exactly this JSON object and nothing else: " + wanted}]
            name = f"locked_local_model/engine/transport-{index:03d}.request.json"
            previous = json.loads(archive.extractfile(name).read())
            save(out / "regenerated_requests" / ("preflight_" + language + ".json"), {"messages": messages})
            probe_rows.append({"language": language, "archived_member": name,
                               "messages_identical": messages == previous["messages"],
                               "measured_messages_sha256": sha(canonical(previous["messages"])),
                               "regenerated_messages_sha256": sha(canonical(messages))})
    if not all(row["request_bytes_identical"] for row in prompt_rows) or not all(row["messages_identical"] for row in probe_rows):
        raise ValueError("a prompt changed; previous model results cannot be rebound")

    original = json.loads((evidence / "bench_final/report.json").read_bytes())
    source = (ROOT / "experiments/hia_optimizer_eval/kernels.hepta").read_text()
    # Preserve the original diagnostic source label. Read bytes from the final
    # current fixture, whose hash was checked against the measured snapshot.
    diagnostic_label = str(Path(original["artifacts_before"]["hia"]["path"]).parent / "kernels.hepta")
    core = verify_program(lower_source(source, path=diagnostic_label, module="optimizer_bench"))
    ir = emit_program_llvm(core)
    (out / "program.hia").write_bytes(core.canonical_bytes)
    (out / "program.ll").write_text(ir.text)
    clang = original["builds"]["hia"]["receipt"]["toolchain"]["path"]
    receipt = compile_program_llvm(ir, program=core, output=out / "hia.so", clang=clang)
    save(out / "native_receipt.json", receipt)
    library = (out / "hia.so").read_bytes()
    native = {"compile_invocations": 1, "benchmark_executions": 0,
              "core_bytes_identical": core.canonical_bytes == measured_core,
              "llvm_ir_bytes_identical": ir.text.encode() == measured_ir,
              "artifact_bytes_identical": library == measured_library,
              "measured_artifact_sha256": sha(measured_library),
              "rebuilt_artifact_sha256": sha(library), "artifact_bytes": len(library),
              "flags_identical": receipt["flags"] == original["builds"]["hia"]["receipt"]["flags"],
              "toolchain_identical": receipt["toolchain"] == original["builds"]["hia"]["receipt"]["toolchain"],
              "diagnostic_source_label": diagnostic_label}
    source_stable = current == {"bench_final": bench.source_bindings(), "agent_final": agent.bindings()}
    preserved_unchanged = all(sha((ROOT / name).read_bytes()) == value for name, value in preserved.items())
    result = {"schema": "hepta.hia.final-source-rebinding.v1",
              "scope": "source identity, native-byte rebuild and regenerated request messages only",
              "differences": changes, "native": native, "agent_task_requests": prompt_rows,
              "agent_preflight_messages": probe_rows, "agent_fixtures_and_withheld_oracle_identical": True,
              "agent_native_evaluator_and_request_tools_unchanged": True,
              "changed_optimizer_module_loaded_by_rebinding_pipeline": changed_name[:-3].replace("/", ".") in sys.modules,
              "change_review": ["independent Z3 Context per verifier request with context-bound ASTs and solver",
                                "checker identity additionally binds hia_program_runtime.py and hia_bounded_memory.py"],
              "source_unchanged_during_rebinding": source_stable,
              "original_evidence_file_hashes": preserved, "original_evidence_unchanged": preserved_unchanged,
              "model_inference_requests": 0, "new_performance_samples": 0,
              "original_compile_and_verification_costs_remeasured": False,
              "entire_final_source_benchmarked": False, "model_run_repeated": False,
              "procedure_sha256": sha(Path(__file__).read_bytes()),
              "files": {str(p.relative_to(ROOT)): sha(p.read_bytes()) for p in sorted(out.rglob("*")) if p.is_file()}}
    result["ok"] = bool(source_stable and preserved_unchanged and
        all(native[k] for k in ("core_bytes_identical", "llvm_ir_bytes_identical", "artifact_bytes_identical",
                                "flags_identical", "toolchain_identical")) and
        not result["changed_optimizer_module_loaded_by_rebinding_pipeline"])
    save(report_path, result)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--report-path", required=True)
    args = parser.parse_args()
    result = run(**vars(args))
    print(json.dumps({"ok": result["ok"], "native": result["native"],
                      "task_requests": len(result["agent_task_requests"]),
                      "preflight_messages": len(result["agent_preflight_messages"]),
                      "source_unchanged": result["source_unchanged_during_rebinding"],
                      "original_evidence_unchanged": result["original_evidence_unchanged"]}, indent=2))
    raise SystemExit(0 if result["ok"] else 1)
