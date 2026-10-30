#!/usr/bin/env python3
"""Finite, equal-information native comparison of HIA proposal selectors.

The workload, recipe order, seeds and budgets are frozen before compilation.
Every selector sees the same native observation table. This is paired replay,
not evidence for online learning or sequential-search superiority. Raw samples,
failures and uncertainty are retained, including results showing no gain.
"""
from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import platform
import random
import shutil
import statistics
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from hepta.clang_capture import run_bounded
from hepta.hia_finite_actions import propose_candidates
from hepta.hia_program import SCHEMA, verify_program
from hepta.hia_program_llvm import TARGET, build_program_native
from hepta.hia_translation_validation import validate_translation

PROTOCOL = {
    "schema": "hepta.hia.ndu-finite-search-protocol.v2",
    "workload": "u64_wrapping_x_plus_12_with_redundant_total_operations",
    "function": "calculate", "seed": 20261027, "candidate_limit": 8,
    "training_trials": 7, "holdout_trials": 7, "iterations": 200000,
    "warmup_iterations": 20000, "expected_calls": 1000000,
    "resource_cap_ns": 60000000000, "target": TARGET,
    "measurement_profile": "native-c-loop-u64-v1",
    "policies": ["fixed_recipe", "seeded_random", "exhaustive_observed", "ndu"],
    "measurement_order": "rotate by trial, reverse on odd trials; no sample dropping or retries",
    "uncertainty": "ceil maximum absolute deviation from median per call, minimum one nanosecond; not a confidence guarantee",
    "comparison": "one shared equal-budget observation table, paired holdout evaluation",
    "sequential_learning_claimed": False,
}
INPUTS = (
    "hepta/hia_finite_actions.py", "hepta/hia_translation_validation.py",
    "hepta/hia_program.py", "hepta/hia_opcodes.py", "hepta/hia_program_runtime.py", "hepta/hia_program_llvm.py",
    "hepta/hia_ndu_optimizer.py", "tools/qualify_hia_ndu_search.py",
)

DRIVER = r'''#define _POSIX_C_SOURCE 200809L
#include <dlfcn.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <time.h>
typedef uint64_t (*kernel_t)(uint64_t);
static uint64_t now(clockid_t kind) {
    struct timespec t;
    if (clock_gettime(kind, &t)) exit(81);
    return (uint64_t)t.tv_sec * UINT64_C(1000000000) + (uint64_t)t.tv_nsec;
}
static uint64_t step(uint64_t x) {
    return x * UINT64_C(6364136223846793005) + UINT64_C(1442695040888963407);
}
int main(int argc, char **argv) {
    if (argc != 5) return 82;
    uint64_t iterations = strtoull(argv[2], NULL, 10);
    uint64_t warmup = strtoull(argv[3], NULL, 10);
    uint64_t seed = strtoull(argv[4], NULL, 10);
    if (!iterations || iterations > UINT64_C(10000000) || warmup > UINT64_C(1000000)) return 83;
    void *library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!library) { fprintf(stderr, "%s\n", dlerror()); return 84; }
    kernel_t kernel = (kernel_t)dlsym(library, "calculate");
    if (!kernel) return 85;
    volatile uint64_t warm_checksum = 0;
    uint64_t x = seed;
    for (uint64_t i = 0; i < warmup; ++i) { x = step(x); warm_checksum ^= kernel(x); }
    (void)warm_checksum;
    struct rusage before, after;
    if (getrusage(RUSAGE_SELF, &before)) return 86;
    x = seed;
    uint64_t checksum = 0;
    uint64_t cpu_start = now(CLOCK_PROCESS_CPUTIME_ID), start = now(CLOCK_MONOTONIC);
    for (uint64_t i = 0; i < iterations; ++i) { x = step(x); checksum += kernel(x); }
    uint64_t end = now(CLOCK_MONOTONIC), cpu_end = now(CLOCK_PROCESS_CPUTIME_ID);
    if (getrusage(RUSAGE_SELF, &after)) return 87;
    printf("{\"elapsed_ns\":%" PRIu64 ",\"process_cpu_ns\":%" PRIu64
           ",\"iterations\":%" PRIu64 ",\"seed\":%" PRIu64 ",\"checksum\":%" PRIu64
           ",\"voluntary_context_switches\":%ld,\"involuntary_context_switches\":%ld"
           ",\"minor_page_faults\":%ld,\"major_page_faults\":%ld}\n",
           end-start, cpu_end-cpu_start, iterations, seed, checksum,
           after.ru_nvcsw-before.ru_nvcsw, after.ru_nivcsw-before.ru_nivcsw,
           after.ru_minflt-before.ru_minflt, after.ru_majflt-before.ru_majflt);
    if (dlclose(library)) return 88;
    return 0;
}
'''


def _wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _digest(path):
    return sha256(Path(path).read_bytes()).hexdigest()


def _require(condition, message):
    if not condition:
        raise RuntimeError("E_HIA_NDU_SEARCH: " + message)


def workload():
    def literal(name, value):
        return {"op": "const", "args": [], "out": [{"name": name, "type": "u64"}], "attrs": {"value": value}}
    def operation(op, left, right, out):
        return {"op": op, "args": [left, right], "out": [{"name": out, "type": "u64"}], "attrs": {}}
    parameter = {"name": "x", "type": "u64"}
    return {"schema": SCHEMA, "module": "ndu_finite_search", "functions": [{
        "name": "calculate", "params": [parameter], "returns": ["u64"], "effects": [],
        "entry": "entry", "blocks": [{"id": "entry", "params": [parameter], "ops": [
            literal("zero", 0), literal("one", 1), literal("five", 5), literal("seven", 7),
            operation("int.add.wrap", "x", "zero", "identity"),
            operation("int.add.wrap", "five", "seven", "folded"),
            operation("int.add.wrap", "identity", "five", "mid"),
            operation("int.add.wrap", "mid", "seven", "value"),
            operation("int.mul.wrap", "value", "one", "out"),
            operation("bit.xor", "x", "folded", "dead"),
        ], "term": {"op": "ret", "values": ["out"]}}],
    }]}


def expected_checksum(iterations, seed):
    """Frozen x+12 specification; independent of candidate generation/codegen."""
    mask, x, result = (1 << 64) - 1, seed, 0
    for _ in range(iterations):
        x = (x * 6364136223846793005 + 1442695040888963407) & mask
        result = (result + x + 12) & mask
    return result


def _schedule(labels, rounds):
    for trial in range(rounds):
        offset = trial % len(labels)
        order = labels[offset:] + labels[:offset]
        if trial % 2:
            order = order[::-1]
        for label in order:
            yield trial, label


def native_sample(driver, artifact, *, iterations, warmup, seed, expected, artifact_sha256, driver_sha256):
    """Measure the actual shared library in a bounded compiled C-loop child."""
    row = {"status": "failed", "artifact_sha256": artifact_sha256,
           "driver_sha256": driver_sha256, "expected_checksum": expected}
    started = time.perf_counter_ns()
    try:
        _require(_digest(artifact) == artifact_sha256 and _digest(driver) == driver_sha256,
                 "measured artifact or driver changed before launch")
        run = run_bounded([str(driver), str(artifact), str(iterations), str(warmup), str(seed)],
                          timeout=10, stdout_limit=16384, stderr_limit=16384)
        row.update(returncode=run.returncode, stdout=run.stdout, stderr=run.stderr)
        _require(run.returncode == 0, "native measurement child failed")
        observed = json.loads(run.stdout)
        _require(type(observed) is dict and observed.get("iterations") == iterations
                 and observed.get("seed") == seed and type(observed.get("checksum")) is int
                 and observed["checksum"] == expected, "native output differs from frozen formula oracle")
        _require(all(type(observed.get(k)) is int and observed[k] > 0 for k in ("elapsed_ns", "process_cpu_ns")),
                 "native timing is missing or malformed")
        _require(_digest(artifact) == artifact_sha256 and _digest(driver) == driver_sha256,
                 "measured artifact or driver changed during execution")
        row.update(observed)
        row["status"] = "observed"
    except Exception as exc:
        row["error"] = f"{type(exc).__name__}: {exc}"
    row["measurement_wall_ns"] = time.perf_counter_ns() - started
    return row


def _summary(rows, iterations):
    _require(rows and all(row["status"] == "observed" for row in rows),
             "all frozen samples must complete; failed samples cannot be trimmed")
    raw = [row["elapsed_ns"] for row in rows]
    median = statistics.median(raw)
    return {"runtime_ns": max(1, math.ceil(median / iterations)),
            "uncertainty_ns": max(1, math.ceil(max(abs(value - median) for value in raw) / iterations)),
            "median_batch_ns": median, "min_batch_ns": min(raw), "max_batch_ns": max(raw),
            "sample_count": len(raw)}


def _guard(proposed, observations, expected_calls, search_ns, policy_ns, resource_cap_ns):
    base = observations["abstain"]
    lower = max(0, base["runtime_ns"] - base["uncertainty_ns"]) * expected_calls
    candidate = observations[proposed]
    upper = (candidate["runtime_ns"] + candidate["uncertainty_ns"]) * expected_calls + search_ns + policy_ns
    within_cap = search_ns + policy_ns <= resource_cap_ns
    return {"proposed_id": proposed, "selected_id": proposed if upper < lower and within_cap else "abstain",
            "baseline_lower_cost_ns": lower, "candidate_upper_cost_ns": upper,
            "search_cost_ns": search_ns, "policy_cost_ns": policy_ns,
            "resource_cap_ns": resource_cap_ns, "within_resource_cap": within_cap,
            "guard": "same conservative compile-inclusive no-regression rule"}


def _run(clang, bridge, directory, report):
    # Write the exact protocol before any build or native observation.
    protocol = report["protocol"]
    (directory / "frozen-protocol.json").write_bytes(_wire(protocol) + b"\n")
    report["protocol_sha256"] = sha256(_wire(protocol)).hexdigest()
    begin = time.perf_counter_ns()
    baseline = workload()
    candidates = propose_candidates(baseline, function="calculate", max_candidates=protocol["candidate_limit"])
    proposal_ns = time.perf_counter_ns() - begin
    _require(candidates, "frozen workload produced no candidates")
    programs = {"abstain": baseline, **{c["id"]: c["program"] for c in candidates}}
    labels = list(programs)
    report["candidates"] = candidates
    report["baseline"] = baseline
    report["proposal_wall_ns"] = proposal_ns
    receipts, proof_ns, build_ns, artifacts = {}, {}, {}, {}
    report["translation_receipts"] = receipts
    report["native_builds"] = artifacts
    for label, program in programs.items():
        (directory / f"{label}.hia.json").write_bytes(_wire(program) + b"\n")
        if label != "abstain":
            start = time.perf_counter_ns()
            receipts[label] = validate_translation(baseline, program, function="calculate")
            proof_ns[label] = time.perf_counter_ns() - start
            _require(receipts[label]["status"] == "proved", "candidate failed independent all-input validation")
        start = time.perf_counter_ns()
        artifact = directory / f"{label}.so"
        artifacts[label] = build_program_native(program, artifact, clang=clang)
        build_ns[label] = time.perf_counter_ns() - start
    source, driver = directory / "driver.c", directory / "driver"
    source.write_text(DRIVER, encoding="ascii")
    start = time.perf_counter_ns()
    compiler = shutil.which(clang)
    _require(compiler is not None, "native C-loop compiler unavailable")
    built = run_bounded([compiler, "-O3", "-std=c11", str(source), "-ldl", "-o", str(driver)],
                        timeout=30, stdout_limit=65536, stderr_limit=65536)
    _require(built.returncode == 0, "native C-loop driver failed to compile: " + built.stderr[:2000])
    driver_build_ns = time.perf_counter_ns() - start
    driver_hash = _digest(driver)
    report["driver"] = {"source_sha256": _digest(source), "binary_sha256": driver_hash,
                        "build_ns": driver_build_ns, "path": str(driver)}
    rows = report["training_samples"] = []
    expected = {trial: expected_checksum(protocol["iterations"], protocol["seed"] + trial)
                for trial in range(protocol["training_trials"])}
    for trial, label in _schedule(labels, protocol["training_trials"]):
        row = native_sample(driver, directory / f"{label}.so", iterations=protocol["iterations"],
                            warmup=protocol["warmup_iterations"], seed=protocol["seed"] + trial,
                            expected=expected[trial], artifact_sha256=artifacts[label]["artifact_sha256"],
                            driver_sha256=driver_hash)
        rows.append({"trial": trial, "candidate_id": label, **row})
    summaries = {label: _summary([r for r in rows if r["candidate_id"] == label], protocol["iterations"])
                 for label in labels}
    report["training_summaries"] = summaries
    # All selectors receive and are charged the same frozen candidate corpus.
    # Baseline probing/driver/generation are common optimization overhead.
    common = proposal_ns + driver_build_ns + build_ns["abstain"] + sum(
        row["measurement_wall_ns"] for row in rows if row["candidate_id"] == "abstain")
    per_candidate_common = math.ceil(common / len(candidates))
    observations = {"abstain": {k: summaries["abstain"][k] for k in ("runtime_ns", "uncertainty_ns")}}
    observations["abstain"]["search_ns"] = 0
    observations["abstain"]["program_sha256"] = verify_program(baseline).sha256
    for candidate in candidates:
        label = candidate["id"]
        observations[label] = {k: summaries[label][k] for k in ("runtime_ns", "uncertainty_ns")}
        observations[label]["program_sha256"] = verify_program(candidate["program"]).sha256
        observations[label]["search_ns"] = (per_candidate_common + proof_ns[label] + build_ns[label]
            + sum(r["measurement_wall_ns"] for r in rows if r["candidate_id"] == label))
    report["observations"] = observations
    objective = {key: protocol[key] for key in ("expected_calls", "resource_cap_ns", "target", "measurement_profile")}
    report["objective"] = objective
    search_ns = sum(row["search_ns"] for key, row in observations.items() if key != "abstain")
    _require(search_ns <= protocol["resource_cap_ns"], "frozen search budget exceeded")
    ids = [c["id"] for c in candidates]
    decisions = {}
    for name in protocol["policies"][:-1]:
        start = time.perf_counter_ns()
        if name == "fixed_recipe":
            proposed = ids[0]
        elif name == "seeded_random":
            proposed = random.Random(protocol["seed"]).choice(ids)
        else:
            proposed = min(ids, key=lambda ident: (observations[ident]["runtime_ns"]
                           + observations[ident]["uncertainty_ns"], observations[ident]["runtime_ns"], ident))
        cost = time.perf_counter_ns() - start
        decisions[name] = _guard(proposed, observations, protocol["expected_calls"], search_ns, cost,
                                 protocol["resource_cap_ns"])
    from hepta.hia_ndu_optimizer import rank_candidates
    start = time.perf_counter_ns()
    ndu = rank_candidates(baseline, candidates, observations, function="calculate", bridge=bridge,
                          objective=objective, generation=1)
    ndu_wall = time.perf_counter_ns() - start
    _require(type(ndu) is dict and ndu.get("selected_id") in programs,
             "NDU adapter did not return a known candidate or abstain")
    selected = ndu["selected_id"]
    _require(verify_program(ndu["selected_program"]).sha256 == verify_program(programs[selected]).sha256,
             "NDU selected program does not bind its selected candidate identity")
    decisions["ndu"] = {"selected_id": selected, "policy_cost_ns": ndu_wall, "report": ndu}
    report["policy_decisions"] = decisions
    report["equal_budget"] = {
        "candidate_count": len(candidates), "training_trials_per_candidate": protocol["training_trials"],
        "same_observation_table_sha256": sha256(_wire(observations)).hexdigest(),
        "shared_search_cost_ns": search_ns, "resource_cap_ns": protocol["resource_cap_ns"],
        "all_policies_received_same_candidates_samples_and_budget": True,
        "actual_policy_overheads_retained": True, "paired_replay_not_sequential_learning": True,
    }
    evaluation = report["holdout_samples"] = []
    eval_labels = ["reference"] + protocol["policies"]
    expected = {trial: expected_checksum(protocol["iterations"], protocol["seed"] + 10000 + trial)
                for trial in range(protocol["holdout_trials"])}
    for trial, policy in _schedule(eval_labels, protocol["holdout_trials"]):
        label = "abstain" if policy == "reference" else decisions[policy]["selected_id"]
        row = native_sample(driver, directory / f"{label}.so", iterations=protocol["iterations"],
                            warmup=protocol["warmup_iterations"], seed=protocol["seed"] + 10000 + trial,
                            expected=expected[trial], artifact_sha256=artifacts[label]["artifact_sha256"],
                            driver_sha256=driver_hash)
        evaluation.append({"trial": trial, "policy": policy, "candidate_id": label, **row})
    report["holdout_summaries"] = {name: _summary([r for r in evaluation if r["policy"] == name], protocol["iterations"])
                                    for name in eval_labels}
    grouped = {}
    for label, artifact in artifacts.items():
        grouped.setdefault(artifact["artifact_sha256"], []).append(label)
    report["identical_artifact_groups"] = [group for group in grouped.values() if len(group) > 1]
    report["qualified_for_finite_paired_replay"] = True
    report["claims"] = {
        "actual_native_c_loop_samples": True,
        "every_measured_candidate_independently_translation_proved": True,
        "equal_information_and_frozen_budget_comparison_executed": True,
        "runtime_improvement_established": False,
        "unique_ndu_gain_established": False,
        "sequential_learning_evaluated": False,
        "backend_refinement_proved": False,
        "global_optimality_proved": False,
    }
    report["interpretation"] = (
        "This fixed workload is a negative/control experiment: LLVM -O3 can erase the source-level "
        "rewrites. Raw time differences include scheduling and measurement noise. Selection is "
        "compile-cost-inclusive and uncertainty-aware; abstention and no measured gain are retained. "
        "A single shared-table replay does not establish sequential learning or general NDU benefit."
    )


def qualify(clang, bridge, *, artifacts=None):
    started = time.perf_counter_ns()
    report = {"schema": "hepta.hia.ndu-search-qualification.v1", "protocol": copy.deepcopy(PROTOCOL),
              "qualified_for_finite_paired_replay": False, "observed_utc": datetime.now(timezone.utc).isoformat(),
              "host": {"system": platform.system(), "machine": platform.machine(), "python": sys.version.split()[0]},
              "artifacts_retained": artifacts is not None,
              "source_sha256": {name: _digest(ROOT / name) for name in INPUTS}}
    try:
        if artifacts is not None:
            directory = Path(artifacts).absolute()
            directory.mkdir(mode=0o700)
            report["artifact_directory"] = str(directory)
            _run(clang, bridge, directory, report)
        else:
            with tempfile.TemporaryDirectory(prefix="hia-ndu-search-") as temporary:
                _run(clang, bridge, Path(temporary), report)
    except Exception as exc:
        report["error"] = f"{type(exc).__name__}: {exc}"
    report["wall_ns"] = time.perf_counter_ns() - started
    final_sources = {name: _digest(ROOT / name) for name in INPUTS}
    report["source_inputs_unchanged"] = final_sources == report["source_sha256"]
    if not report["source_inputs_unchanged"]:
        report["qualified_for_finite_paired_replay"] = False
        report["error"] = "source inputs changed during the frozen campaign"
        report["final_source_sha256"] = final_sources
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--clang", default=os.environ.get("HEPTA_CLANG", "clang"))
    parser.add_argument("--bridge", required=True, type=Path)
    parser.add_argument("--bridge-build-receipt", required=True, type=Path)
    parser.add_argument("--artifacts", type=Path, help="new directory retaining exact measured native artifacts")
    parser.add_argument("--output", type=Path, help="new JSON evidence file; existing evidence is not overwritten")
    args = parser.parse_args(argv)
    result = qualify(args.clang, {"binary": args.bridge, "build_receipt": args.bridge_build_receipt}, artifacts=args.artifacts)
    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        with args.output.open("x", encoding="utf-8") as stream:
            stream.write(encoded)
        print(json.dumps({"output": str(args.output), "qualified": result["qualified_for_finite_paired_replay"],
                          "error": result.get("error")}))
    else:
        print(encoded, end="")
    return 0 if result["qualified_for_finite_paired_replay"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
