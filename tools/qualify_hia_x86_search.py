#!/usr/bin/env python3
"""Exhaust a closed instruction grammar, then measure its actual native output.

The selected candidate minimizes encoded bytes, before any timings are seen.
The LLVM baseline and every model-equivalent recipe receive the same seven
native trials. Failed samples and unfavorable results are retained. This is a
bounded mechanism qualification, not a claim of general runtime superiority.
"""
from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import shutil
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from hepta.clang_capture import run_bounded
from hepta.hia_program_llvm import TARGET, build_program_native
from hepta.hia_x86_search import (
    GRAMMAR, affine_program, build_candidate, exported_code,
    inspect_candidate_artifact, search_affine_candidates,
)
from tools.qualify_hia_ndu_search import DRIVER, _schedule, _summary, expected_checksum, native_sample

SCHEMA = "hepta.hia.x86-finite-search-qualification.v1"
PROTOCOL = {
    "schema": "hepta.hia.x86-finite-search-protocol.v1", "grammar": GRAMMAR,
    "workload": "calculate(x:u64) = x+12 modulo 2^64", "offset": 12,
    "complete_recipe_count": 146, "selection_metric": "encoded function body bytes including ret",
    "native_eligible_set": "all recipes proved equivalent by the complete SMT enumeration",
    "selection_order": "minimum encoded bytes, then stable candidate ID; before native measurements",
    "trials_per_artifact": 7, "iterations": 200000, "warmup_iterations": 20000,
    "seed": 20261027, "target": TARGET, "solver_timeout_ms_per_recipe": 2000,
    "measurement_order": "rotate by trial, reverse on odd trials; no retries or sample dropping",
    "uncertainty": "maximum absolute sample deviation from the median, rounded up per call; not a confidence interval",
    "edge_inputs": [0, 1, 11, 12, (1 << 63) - 1, 1 << 63, (1 << 64) - 13, (1 << 64) - 1],
    "timing_decides_admission": False, "global_optimality_established": False,
}
INPUTS = (
    "hepta/hia_x86_search.py", "hepta/hia_translation_validation.py", "hepta/hia_program.py", "hepta/hia_opcodes.py",
    "hepta/hia_program_runtime.py", "hepta/hia_program_llvm.py", "hepta/elf_shared_abi.py",
    "hepta/artifact_publication.py", "hepta/clang_capture.py", "hepta/native_tool_identity.py",
    "tools/qualify_hia_ndu_search.py", "tools/qualify_hia_x86_search.py",
)
# These explicit boundary probes supplement, and never replace, all-input SMT.
EDGE_CHILD = r'''import ctypes, json, sys
inputs = json.loads(sys.argv[2])
lib = ctypes.CDLL(sys.argv[1])
fn = lib.calculate
fn.argtypes = [ctypes.c_uint64]
fn.restype = ctypes.c_uint64
rows = [{"input": x, "actual": fn(x), "expected": (x+12) & ((1<<64)-1)} for x in inputs]
print(json.dumps(rows, separators=(",", ":")))
raise SystemExit(0 if all(row["actual"] == row["expected"] for row in rows) else 91)
'''


def _wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _digest(path):
    return sha256(Path(path).read_bytes()).hexdigest()


def _require(condition, message):
    if not condition:
        raise RuntimeError("E_HIA_X86_QUALIFY: " + message)


def _edge_sample(path, artifact_hash, inputs):
    row = {"status": "failed", "artifact_sha256": artifact_hash}
    start = time.perf_counter_ns()
    try:
        _require(_digest(path) == artifact_hash, "artifact changed before edge probes")
        result = run_bounded([sys.executable, "-c", EDGE_CHILD, str(path), json.dumps(inputs)],
                             timeout=10, stdout_limit=16384, stderr_limit=16384)
        row.update(returncode=result.returncode, stdout=result.stdout, stderr=result.stderr)
        _require(result.returncode == 0, "native edge probe failed")
        outputs = json.loads(result.stdout)
        _require(type(outputs) is list and len(outputs) == len(inputs), "missing edge probe observations")
        for expected_input, observed in zip(inputs, outputs):
            _require(type(observed) is dict and observed == {
                "input": expected_input, "actual": (expected_input + 12) & ((1 << 64) - 1),
                "expected": (expected_input + 12) & ((1 << 64) - 1)}, "native boundary output differs")
        _require(_digest(path) == artifact_hash, "artifact changed during edge probes")
        row.update(status="observed", outputs=outputs)
    except Exception as exc:
        row["error"] = f"{type(exc).__name__}: {exc}"
    row["wall_ns"] = time.perf_counter_ns() - start
    return row


def _run(clang, directory, report):
    protocol = report["protocol"]
    (directory / "frozen-protocol.json").write_bytes(_wire(protocol) + b"\n")
    report["protocol_sha256"] = sha256(_wire(protocol)).hexdigest()
    search = search_affine_candidates(protocol["offset"], timeout_ms=protocol["solver_timeout_ms_per_recipe"])
    report["search"] = search
    (directory / "complete-search.json").write_bytes(_wire(search) + b"\n")
    _require(search["finite_minimum_encoded_bytes_proved"], "finite search incomplete or unresolved")
    _require(search["candidate_count"] == protocol["complete_recipe_count"], "frozen grammar count changed")
    candidates = [row["candidate"] for row in search["candidates"] if row["proof"]["status"] == "proved"]
    baseline = affine_program(protocol["offset"])
    labels = ["llvm_o3"] + [c["id"] for c in candidates]
    builds = report["native_builds"] = {}
    artifact_inspections = report["native_body_inspections"] = {}
    build_wall = report["build_wall_ns"] = {}
    begin = time.perf_counter_ns()
    builds["llvm_o3"] = build_program_native(baseline, directory / "llvm_o3.so", clang=clang)
    build_wall["llvm_o3"] = time.perf_counter_ns() - begin
    artifact_inspections["llvm_o3"] = exported_code((directory / "llvm_o3.so").read_bytes())
    for candidate in candidates:
        ident = candidate["id"]
        begin = time.perf_counter_ns()
        artifact = directory / f"{ident}.so"
        builds[ident] = build_candidate(baseline, candidate, artifact, clang=clang,
                                       timeout_ms=protocol["solver_timeout_ms_per_recipe"])
        build_wall[ident] = time.perf_counter_ns() - begin
        # Independently inspect exact published bytes again before the child.
        artifact_inspections[ident] = inspect_candidate_artifact(artifact.read_bytes(), candidate)
        _require(artifact_inspections[ident]["artifact_sha256"] == builds[ident]["artifact_sha256"],
                 "published artifact changed after its byte gate")
    edges = report["edge_samples"] = []
    for ident in labels:
        edges.append({"candidate_id": ident, **_edge_sample(directory / f"{ident}.so",
                     builds[ident]["artifact_sha256"], protocol["edge_inputs"])})
    _require(all(row["status"] == "observed" for row in edges), "at least one native edge sample failed")
    source, driver = directory / "driver.c", directory / "driver"
    source.write_text(DRIVER, encoding="ascii")
    compiler = shutil.which(clang)
    _require(compiler is not None, "Clang unavailable for native driver")
    begin = time.perf_counter_ns()
    result = run_bounded([compiler, "-O3", "-std=c11", str(source), "-ldl", "-o", str(driver)],
                         timeout=30, stdout_limit=65536, stderr_limit=65536)
    _require(result.returncode == 0, "native C-loop driver failed: " + result.stderr[:2000])
    report["driver"] = {"source_sha256": _digest(source), "binary_sha256": _digest(driver),
                        "path": str(driver), "build_ns": time.perf_counter_ns() - begin}
    expected = {trial: expected_checksum(protocol["iterations"], protocol["seed"] + trial)
                for trial in range(protocol["trials_per_artifact"])}
    rows = report["native_samples"] = []
    for trial, ident in _schedule(labels, protocol["trials_per_artifact"]):
        row = native_sample(driver, directory / f"{ident}.so", iterations=protocol["iterations"],
                            warmup=protocol["warmup_iterations"], seed=protocol["seed"] + trial,
                            expected=expected[trial], artifact_sha256=builds[ident]["artifact_sha256"],
                            driver_sha256=report["driver"]["binary_sha256"])
        rows.append({"trial": trial, "candidate_id": ident, **row})
    summaries = {ident: _summary([r for r in rows if r["candidate_id"] == ident], protocol["iterations"])
                 for ident in labels}
    report["native_summaries"] = summaries
    comparisons = report["comparisons_to_llvm_o3"] = []
    base = summaries["llvm_o3"]
    for candidate in candidates:
        ident = candidate["id"]
        summary = summaries[ident]
        base_lower = max(0, base["runtime_ns"] - base["uncertainty_ns"])
        base_upper = base["runtime_ns"] + base["uncertainty_ns"]
        lower = max(0, summary["runtime_ns"] - summary["uncertainty_ns"])
        upper = summary["runtime_ns"] + summary["uncertainty_ns"]
        relation = "faster_in_this_empirical_envelope" if upper < base_lower else (
            "slower_in_this_empirical_envelope" if lower > base_upper else "envelopes_overlap")
        comparisons.append({"candidate_id": ident, "encoded_bytes": candidate["encoded_bytes"],
            "median_batch_delta_ns": summary["median_batch_ns"] - base["median_batch_ns"],
            "empirical_relation": relation,
            "identical_machine_body_to_llvm": artifact_inspections[ident]["code_hex"] == artifact_inspections["llvm_o3"]["code_hex"]})
    selected = search["selected_candidate"]["id"]
    report.update(selected_id=selected, finite_minimum_encoded_bytes_proved=True,
                  minimum_encoded_bytes=search["minimum_encoded_bytes"],
                  llvm_baseline_encoded_bytes=artifact_inspections["llvm_o3"]["encoded_bytes"],
                  selected_native_body_identical_to_llvm=(artifact_inspections[selected]["code_hex"] == artifact_inspections["llvm_o3"]["code_hex"]),
                  all_native_equivalent_candidates_checked=True,
                  timed_native_call_count=len(rows) * protocol["iterations"],
                  edge_native_call_count=len(edges) * len(protocol["edge_inputs"]),
                  search_and_all_build_wall_ns=search["wall_ns"] + sum(build_wall.values()) + report["driver"]["build_ns"],
                  ok=True)


def qualify(clang="clang", *, artifacts=None):
    """Run the frozen complete grammar and real native comparison campaign."""
    started = time.perf_counter_ns()
    report = {"schema": SCHEMA, "ok": False, "timestamp_utc": datetime.now(timezone.utc).isoformat(),
              "host": {"system": platform.system(), "machine": platform.machine(), "platform": platform.platform()},
              "protocol": copy.deepcopy(PROTOCOL), "source_sha256": {name: _digest(ROOT / name) for name in INPUTS},
              "finite_minimum_encoded_bytes_proved": False, "global_optimality_established": False,
              "native_backend_refinement_proved": False, "runtime_improvement_established": False,
              "arbitrary_program_or_isa_supported": False,
              "limits": [
                  "The minimum concerns only the complete 146-recipe grammar and encoded bytes, under its trusted ISA-to-HIA model.",
                  "Model equivalence uses actual all-input Z3 proofs; finite native probes do not prove assembler/ISA/loader refinement.",
                  "Exact allowed encoder bytes and ABI entry mapping are checked after local trusted assembly; arbitrary machine code is rejected.",
                  "Flags are caller-clobbered; DF and callee-saved registers stay unchanged. The fixed ret uses the ABI caller stack.",
                  "Native timings include C-loop/indirect-call overhead and local host noise. Empirical envelopes are not statistical confidence bounds.",
                  "Search/build costs are recorded; no runtime or whole-program global optimum or production hot-code admission is claimed.",
                  "Artifacts are locally generated under a trusted host; the ELF checks do not sandbox malicious loaders or same-user filesystem writers.",
              ]}
    try:
        if artifacts is not None:
            directory = Path(artifacts).absolute()
            directory.mkdir(mode=0o700)
            report["artifact_directory"] = str(directory)
            _run(clang, directory, report)
        else:
            with tempfile.TemporaryDirectory(prefix="hia-x86-search-") as temporary:
                _run(clang, Path(temporary), report)
    except Exception as exc:
        report["error"] = f"{type(exc).__name__}: {exc}"
        report["ok"] = False
    report["wall_ns"] = time.perf_counter_ns() - started
    final_sources = {name: _digest(ROOT / name) for name in INPUTS}
    report["source_inputs_unchanged"] = final_sources == report["source_sha256"]
    if not report["source_inputs_unchanged"]:
        report.update(ok=False, finite_minimum_encoded_bytes_proved=False,
                      error="source inputs changed during the frozen campaign", final_source_sha256=final_sources)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--clang", default=os.environ.get("HEPTA_CLANG", "clang"))
    parser.add_argument("--artifacts", type=Path, help="new directory retaining exact native artifacts")
    parser.add_argument("--output", type=Path, help="new JSON evidence file; prior evidence is not overwritten")
    args = parser.parse_args(argv)
    result = qualify(args.clang, artifacts=args.artifacts)
    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        with args.output.open("x", encoding="utf-8") as stream:
            stream.write(encoded)
        print(json.dumps({"output": str(args.output), "ok": result["ok"], "error": result.get("error")}))
    else:
        print(encoded, end="")
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
