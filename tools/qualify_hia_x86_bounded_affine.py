#!/usr/bin/env python3
"""Qualify ten bounded affine targets against the unchanged x86 grammar.

Every target's complete SMT search and byte-minimum selection are retained
before any native observation. LLVM O3 is an external comparison, including
when it emits shorter code outside the grammar. No timing changes selection.
The existing x+12 campaign and its frozen protocol are not modified.
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
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from hepta.clang_capture import run_bounded
from hepta.hia_program_llvm import TARGET, build_program_native
from hepta.hia_x86_search import (
    GRAMMAR, bounded_affine_program, build_candidate, enumerate_candidates,
    exported_code, inspect_candidate_artifact, search_bounded_affine_candidates,
)
from hepta.native_tool_identity import digest_executable
from tools.qualify_hia_ndu_search import DRIVER, _schedule, _summary, native_sample

SCHEMA = "hepta.hia.x86-bounded-affine-qualification.v1"
CASES = tuple((a, b) for a in (-1, 0, 2, 3, 4) for b in (-12, 12))
PROTOCOL = {
    "schema": "hepta.hia.x86-bounded-affine-protocol.v1",
    "targets": [{"multiplier": a, "offset": b} for a, b in CASES],
    "formula": "(multiplier*x+offset) modulo 2^64; x is every u64 value",
    "grammar": GRAMMAR, "complete_recipe_count_per_target": 146,
    "selection_metric": "exact encoded function body bytes including ret",
    "selection_order": "minimum encoded bytes, then stable candidate ID",
    "native_eligible_set": "all model-equivalent recipes, after every recipe has a decided proof",
    "selection_timing": "freeze every target selection before the first native build or observation",
    "solver_timeout_ms_per_recipe": 2000, "trials_per_artifact": 7,
    "iterations": 200000, "warmup_iterations": 20000, "seed": 20261030,
    "measurement_order": "rotate by trial, reverse on odd trials; no retries or dropped samples",
    "edge_inputs": [0, 1, 11, 12, (1 << 63) - 1, 1 << 63, (1 << 64) - 13, (1 << 64) - 1],
    "uncertainty": "max absolute observed deviation from median, rounded up per call; not a confidence interval",
    "target": TARGET, "llvm_comparison": "O3, same target and workload; not restricted to the grammar",
    "timing_decides_admission": False, "previous_protocols_or_results_replaced": False,
    "global_optimality_established": False, "runtime_improvement_established": False,
}
EDGE_CHILD = r'''import ctypes, json, sys
inputs, a, b = json.loads(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
lib = ctypes.CDLL(sys.argv[1])
fn = lib.calculate
fn.argtypes, fn.restype = [ctypes.c_uint64], ctypes.c_uint64
rows = [{"input": x, "actual": fn(x), "expected": (a*x+b) & ((1<<64)-1)} for x in inputs]
print(json.dumps(rows, separators=(",", ":")))
raise SystemExit(0 if all(r["actual"] == r["expected"] for r in rows) else 91)
'''


def _wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _digest(path):
    return sha256(Path(path).read_bytes()).hexdigest()


def _save(path, value):
    with Path(path).open("xb") as stream:
        stream.write(_wire(value) + b"\n")


def _require(condition, message):
    if not condition:
        raise RuntimeError("E_HIA_BOUNDED_AFFINE_QUALIFY: " + message)


def expected_checksum(iterations, seed, multiplier, offset):
    """Independent formula oracle for the unchanged compiled C-loop driver."""
    mask, x, result = (1 << 64) - 1, seed, 0
    for _ in range(iterations):
        x = (x * 6364136223846793005 + 1442695040888963407) & mask
        result = (result + multiplier * x + offset) & mask
    return result


def edge_sample(path, artifact_hash, inputs, multiplier, offset):
    row = {"status": "failed", "artifact_sha256": artifact_hash}
    started = time.perf_counter_ns()
    try:
        _require(_digest(path) == artifact_hash, "artifact changed before edge probe")
        run = run_bounded([sys.executable, "-c", EDGE_CHILD, str(path), json.dumps(inputs),
                           str(multiplier), str(offset)],
                          timeout=10, stdout_limit=16384, stderr_limit=16384)
        row.update(returncode=run.returncode, stdout=run.stdout, stderr=run.stderr)
        _require(run.returncode == 0, "native edge probe failed")
        outputs = json.loads(run.stdout)
        expected = [{"input": x, "actual": (multiplier * x + offset) & ((1 << 64) - 1),
                     "expected": (multiplier * x + offset) & ((1 << 64) - 1)} for x in inputs]
        _require(_wire(outputs) == _wire(expected), "native edge output or exact type differs")
        _require(_digest(path) == artifact_hash, "artifact changed during edge probe")
        row.update(status="observed", outputs=outputs)
    except Exception as error:
        row["error"] = f"{type(error).__name__}: {error}"
    row["wall_ns"] = time.perf_counter_ns() - started
    return row


def freeze_selections(directory, protocol):
    """Persist all search outcomes, including unknown/empty, before native work."""
    _require(protocol["targets"], "qualification requires at least one target")
    records, selections = [], []
    for index, target in enumerate(protocol["targets"]):
        folder = directory / f"case-{index:02d}"
        folder.mkdir()
        result = search_bounded_affine_candidates(target["multiplier"], target["offset"],
            timeout_ms=protocol["solver_timeout_ms_per_recipe"])
        _save(folder / "complete-search.json", result)
        selected = result["selected_candidate"]
        complete = (result["candidate_count"] == protocol["complete_recipe_count_per_target"]
                    and result["decided_count"] == result["candidate_count"]
                    and result["finite_minimum_encoded_bytes_proved"] is True and selected is not None)
        selections.append({"case": index, **target, "complete": complete,
            "baseline_sha256": result["baseline_sha256"], "grammar_sha256": result["grammar_sha256"],
            "selected_id": selected["id"] if complete else None,
            "minimum_encoded_bytes": result["minimum_encoded_bytes"] if complete else None,
            "search_sha256": _digest(folder / "complete-search.json")})
        records.append({"case": index, **target, "search": result, "folder": str(folder)})
    receipt = {"schema": "hepta.hia.x86-bounded-affine-selections.v1", "selections": selections,
               "native_observations_consumed": 0, "selection_metric": protocol["selection_metric"]}
    _save(directory / "SELECTIONS.json", receipt)
    _require(all(row["complete"] for row in selections),
             "unknown, incomplete or empty search cannot authorize native qualification")
    return records, _digest(directory / "SELECTIONS.json")


def _native_case(record, protocol, clang, driver, driver_sha):
    folder, search = Path(record["folder"]), record["search"]
    a, b = record["multiplier"], record["offset"]
    row = {"case": record["case"], "multiplier": a, "offset": b, "ok": False,
           "selected_id": search["selected_candidate"]["id"],
           "minimum_encoded_bytes": search["minimum_encoded_bytes"],
           "builds": {}, "body_inspections": {}, "build_wall_ns": {}, "edge_samples": [], "samples": []}
    started = time.perf_counter_ns()
    try:
        baseline = bounded_affine_program(a, b)
        candidates = [r["candidate"] for r in search["candidates"] if r["proof"]["status"] == "proved"]
        labels = ["llvm_o3"] + [c["id"] for c in candidates]
        for ident, candidate in [("llvm_o3", None)] + [(c["id"], c) for c in candidates]:
            artifact = folder / (ident + ".so")
            begin = time.perf_counter_ns()
            build = (build_program_native(baseline, artifact, clang=clang) if candidate is None else
                     build_candidate(baseline, candidate, artifact, clang=clang,
                                     timeout_ms=protocol["solver_timeout_ms_per_recipe"]))
            row["build_wall_ns"][ident] = time.perf_counter_ns() - begin
            row["builds"][ident] = build
            data = artifact.read_bytes()
            _require(sha256(data).hexdigest() == build["artifact_sha256"], "built artifact identity changed")
            row["body_inspections"][ident] = (exported_code(data) if candidate is None else
                                               inspect_candidate_artifact(data, candidate))
            row["edge_samples"].append({"candidate_id": ident,
                **edge_sample(artifact, build["artifact_sha256"], protocol["edge_inputs"], a, b)})
        _require(all(r["status"] == "observed" for r in row["edge_samples"]), "native edge comparison failed")
        expected = {trial: expected_checksum(protocol["iterations"], protocol["seed"] + trial, a, b)
                    for trial in range(protocol["trials_per_artifact"])}
        for trial, ident in _schedule(labels, protocol["trials_per_artifact"]):
            sample = native_sample(driver, folder / (ident + ".so"),
                iterations=protocol["iterations"], warmup=protocol["warmup_iterations"],
                seed=protocol["seed"] + trial, expected=expected[trial],
                artifact_sha256=row["builds"][ident]["artifact_sha256"], driver_sha256=driver_sha)
            row["samples"].append({"trial": trial, "candidate_id": ident, **sample})
        summaries = {ident: _summary([r for r in row["samples"] if r["candidate_id"] == ident],
                                     protocol["iterations"]) for ident in labels}
        row["summaries"] = summaries
        llvm, chosen = row["body_inspections"]["llvm_o3"], row["body_inspections"][row["selected_id"]]
        row.update(llvm_encoded_bytes=llvm["encoded_bytes"], selected_encoded_bytes=chosen["encoded_bytes"],
            llvm_body_in_declared_grammar=llvm["code_hex"] in {c["expected_code_hex"] for c in enumerate_candidates()},
            llvm_shorter_than_grammar_minimum=llvm["encoded_bytes"] < search["minimum_encoded_bytes"],
            selected_body_identical_to_llvm=chosen["code_hex"] == llvm["code_hex"],
            selected_minus_llvm_median_batch_ns=(summaries[row["selected_id"]]["median_batch_ns"]
                                                 - summaries["llvm_o3"]["median_batch_ns"]),
            all_native_equivalent_candidates_checked=True, ok=True)
    except Exception as error:
        row["error"] = f"{type(error).__name__}: {error}"
    row["wall_ns"] = time.perf_counter_ns() - started
    _save(folder / "NATIVE.json", row)
    return row


def qualify(clang, artifacts):
    """Freeze one clean source commit and execute the separate ten-target study."""
    started = time.perf_counter_ns()
    directory = Path(artifacts).resolve()
    _require(not directory.is_relative_to(ROOT), "artifacts must be external to the source checkout")
    _require(not subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT),
             "qualification requires clean committed source")
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    inputs = sorted((ROOT / "hepta").glob("*.py")) + [Path(__file__), ROOT / "tools/qualify_hia_ndu_search.py"]
    sources = {str(path.relative_to(ROOT)): _digest(path) for path in inputs}
    for path in inputs:
        name = str(path.relative_to(ROOT))
        _require(subprocess.check_output(["git", "cat-file", "blob", commit + ":" + name], cwd=ROOT)
                 == path.read_bytes(), "source differs from named commit: " + name)
    compiler = shutil.which(clang)
    _require(compiler is not None, "actual Clang 20+ is required")
    compiler = str(Path(compiler).resolve())
    compiler_sha = digest_executable(compiler)
    directory.mkdir(parents=True, exist_ok=False)
    report = {"schema": SCHEMA, "source_commit": commit, "ok": False, "protocol": copy.deepcopy(PROTOCOL),
        "protocol_sha256": sha256(_wire(PROTOCOL)).hexdigest(),
        "registered_utc": datetime.now(timezone.utc).isoformat(), "source_sha256": sources,
        "host": {"platform": platform.platform(), "exclusive": False, "physical_dot_verified": False},
        "clang": {"path": compiler, "sha256": compiler_sha}, "native_cases": [],
        "global_optimality_established": False, "native_backend_refinement_proved": False,
        "runtime_improvement_established": False, "previous_protocols_or_results_replaced": False}
    _save(directory / "REGISTRATION.json", report)
    registration_digest = _digest(directory / "REGISTRATION.json")
    try:
        records, selection_digest = freeze_selections(directory, report["protocol"])
        report.update(selection_receipt_sha256=selection_digest,
                      every_selection_frozen_before_native=True,
                      all_finite_minima_proved=True,
                      decided_candidate_count=sum(r["search"]["decided_count"] for r in records),
                      search_wall_ns=sum(r["search"]["wall_ns"] for r in records))
        source, driver = directory / "driver.c", directory / "driver"
        source.write_text(DRIVER, encoding="ascii")
        begin = time.perf_counter_ns()
        command = [compiler, "-O3", "-std=c11", str(source), "-ldl", "-o", str(driver)]
        build = run_bounded(command, timeout=30, stdout_limit=65536, stderr_limit=65536)
        report["driver_build"] = {"command": command, "returncode": build.returncode,
            "stdout": build.stdout, "stderr": build.stderr, "wall_ns": time.perf_counter_ns() - begin,
            "source_sha256": _digest(source)}
        _require(build.returncode == 0, "actual native measurement driver build failed")
        driver_sha = _digest(driver)
        report["driver_build"]["binary_sha256"] = driver_sha
        for record in records:
            row = _native_case(record, report["protocol"], compiler, driver, driver_sha)
            report["native_cases"].append(row)
        report["ok"] = len(report["native_cases"]) == len(CASES) and all(r["ok"] for r in report["native_cases"])
        report["selection_receipt_unchanged"] = _digest(directory / "SELECTIONS.json") == selection_digest
        selections = json.loads((directory / "SELECTIONS.json").read_bytes())["selections"]
        report["complete_search_files_unchanged"] = all(
            _digest(directory / f"case-{row['case']:02d}" / "complete-search.json") == row["search_sha256"]
            for row in selections)
        report["driver_unchanged"] = _digest(driver) == driver_sha
        report["ok"] = (report["ok"] and report["selection_receipt_unchanged"]
                        and report["complete_search_files_unchanged"] and report["driver_unchanged"])
    except Exception as error:
        report["error"] = f"{type(error).__name__}: {error}"
        report["ok"] = False
    report.update(source_inputs_unchanged=False, compiler_unchanged=False, registration_unchanged=False,
                  registration_sha256=registration_digest)
    try:
        report["source_inputs_unchanged"] = (all(_digest(ROOT / name) == value for name, value in sources.items())
            and subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip() == commit
            and not subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT))
        report["compiler_unchanged"] = digest_executable(compiler) == compiler_sha
        report["registration_unchanged"] = _digest(directory / "REGISTRATION.json") == registration_digest
    except Exception as error:
        report["final_integrity_error"] = f"{type(error).__name__}: {error}"
    report["ok"] = (report["ok"] and report["source_inputs_unchanged"]
                    and report["compiler_unchanged"] and report["registration_unchanged"])
    report["wall_ns_before_final_encoding"] = time.perf_counter_ns() - started
    _save(directory / "RESULT.json", report)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--clang", default=os.environ.get("HEPTA_CLANG", "clang-20"))
    parser.add_argument("--artifacts", type=Path, required=True, help="new external directory; retain every outcome")
    args = parser.parse_args(argv)
    report = qualify(args.clang, args.artifacts)
    print(json.dumps({"source_commit": report["source_commit"], "ok": report["ok"],
        "decided_candidate_count": report.get("decided_candidate_count"),
        "cases": [{key: row.get(key) for key in ("multiplier", "offset", "ok", "minimum_encoded_bytes",
            "llvm_encoded_bytes", "llvm_shorter_than_grammar_minimum", "selected_minus_llvm_median_batch_ns")}
            for row in report["native_cases"]], "error": report.get("error")}, indent=2))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
