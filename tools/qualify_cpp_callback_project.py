"""Qualify the captured callback implementation, resource traces and net cost.

The oracle below is an independently written value/event model. Native original
C++ and standalone HIA are built separately; only the latter's own object and
a C observation harness are linked into the migrated target.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import math
from pathlib import Path
import random
import shutil
import statistics
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from hepta.cpp_callback_project import lower_callback_matrix
from hepta.hia_program_llvm import build_program_native
from hepta.hia_program_source import lower_source
from hepta.pipeline import compiler_hash
from tools.evidence_checks import require, strict_equal
from tools.qualify_cpp_unique_project import _qualify, command, HARNESS, WRAP_FLAGS
from tools.validate_cpp_owned import CPP_FLAGS

EXAMPLE = ROOT / "examples/cpp/callback_project_migration"


def oracle(raw, variant):
    """Closed scalar result and exact allocation/free/refusal trace.

    Constructor members initialize left-to-right. Every complete or partial
    owner unwinds right-to-left. Neither moving an owner nor lending it to the
    synchronous read callback allocates, frees, or changes its bytes.
    """
    left, right, value, index, reject, early, refuse_at = raw
    weight, mask = {"three_weight": (3, 37), "five_weight": (5, 11)}[variant]
    owners, events = [], []
    attempts = allocated = refusals = 0
    result = family = None
    for field, size in enumerate((left, right), 1):
        if size:
            attempts += 1
            if attempts == refuse_at:
                refusals += 1
                events.append((3, attempts, size))
                result, family = 1001, "allocation_refusal_" + str(field)
                break
            allocated += 1
            owners.append((allocated, size))
            events.append((1, allocated, size))
        if reject == field:
            result, family = 1002, "leaf_constructor_rejection_" + str(field)
            break
    if result is None:
        if reject == 3:
            result, family = 1003, "composite_constructor_rejection"
        elif early == 1:
            result, family = 2001, "cancel_before_owner_transfer"
        elif early == 2:
            result, family = 2002, "cancel_after_owner_transfer"
        elif index >= min(left, right):
            result, family = 2003, "range_error_before_callback"
        elif early == 3:
            result, family = 4001, "callback_error_then_owner_cleanup"
        else:
            selected = value ^ 91 if index == 0 else value
            result = (selected * weight + (value ^ mask) + left + right) % (1 << 64)
            family = "callback_read_then_owner_cleanup"
    events.extend((2, identity, size) for identity, size in reversed(owners))
    trace = 14695981039346656037
    for event in events:
        for word in event:
            for shift in range(0, 64, 8):
                trace = ((trace ^ ((word >> shift) & 255)) * 1099511628211) % (1 << 64)
    return dict(zip(("left", "right", "value", "index", "reject", "early", "refuse_at"), raw),
                expected=result, allocated=allocated, refusals=refusals, trace=trace,
                family=family, events=[list(event) for event in events])


def cases(variant):
    # First case has two unequal allocations so reversing cleanup is visible.
    inputs = [(3, 5, 7, 0, 0, 0, 0)]
    for left, right in ((0, 0), (0, 3), (3, 0), (1, 1), (3, 5), (257, 513)):
        for value in (0, 255):
            for index in sorted({0, max(min(left, right) - 1, 0), min(left, right)}):
                for reject in range(4):
                    for early in range(4):
                        for refusal in range(3):
                            inputs.append((left, right, value, index, reject, early, refusal))
    randomizer = random.Random(0xC411BAC)
    for _ in range(128):
        left, right = randomizer.randrange(1025), randomizer.randrange(1025)
        inputs.append((left, right, randomizer.randrange(256), randomizer.randrange(min(left, right) + 2),
                       randomizer.randrange(4), randomizer.randrange(4), randomizer.randrange(3)))
    return [oracle(row, variant) for row in inputs]


def source_bindings():
    paths = [Path(__file__), ROOT / "tools/qualify_cpp_unique_project.py",
             ROOT / "tools/validate_cpp_composed.py", ROOT / "tools/validate_cpp_owned.py",
             ROOT / "tools/evidence_checks.py", HARNESS / "harness.c",
             *[ROOT / "hepta" / name for name in (
                 "cpp_callback_project.py", "cpp_unique_project.py", "cpp_unique_capture.py",
                 "cpp_composed_project.py", "cpp_composed_migrate.py", "cpp_owned_migrate.py")],
             *EXAMPLE.iterdir()]
    return {str(path.relative_to(ROOT)): sha256(path.read_bytes()).hexdigest()
            for path in paths if path.is_file()}


def semantic_controls(*, name, target, source, clang, cc):
    changes = {
        "wrong_owner_cleanup_order": (
            "    HeptaLeaf_drop(move owner.resource1);\n    HeptaLeaf_drop(move owner.resource0);",
            "    HeptaLeaf_drop(move owner.resource0);\n    HeptaLeaf_drop(move owner.resource1);", 3, "lifecycle"),
        "wrong_callback_error": ("(4001 as i32)", "(4002 as i32)", 2, "value"),
        "wrong_cancellation_result": ("(2002 as i32)", "(2004 as i32)", 2, "value"),
    }
    controls = {}
    for label, (before, after, code, failure) in changes.items():
        require(source.count(before) == 1, "Missing unique source mutation site: " + label)
        changed = source.replace(before, after)
        path = target / (label + ".hepta")
        path.write_text(changed)
        program = lower_source(changed, path=str(path))
        obj, binary = target / (label + ".o"), target / label
        row = {"scope": "deliberately_mutated_qualification_fixture", "commands": [],
               "resource_check_passed": True, "detected": False,
               "source_sha256": sha256(changed.encode()).hexdigest()}
        row["build"] = build_program_native(program.as_dict(), obj, clang=clang, kind="object")
        command(row["commands"], None, [cc, "-std=c11", "-O2", "-fno-lto", *WRAP_FLAGS,
                                        "-I" + str(target), str(HARNESS / "harness.c"), str(obj), "-o", str(binary)])
        observation = command(row, "execution", [str(binary)], expected_code=code)
        result = json.loads(observation["stdout"])
        require(result.get("ok") is False and result.get("failure") == failure,
                "Independent oracle failed to detect: " + label)
        row.update(detected=True, artifact_sha256=sha256(binary.read_bytes()).hexdigest())
        controls[name + "_" + label] = row
    return controls


BENCHMARK = r'''#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <inttypes.h>
extern uint64_t composed_case(size_t, size_t, uint8_t, size_t, uint32_t, uint32_t);
static uint64_t tick(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) abort();
    return (uint64_t)t.tv_sec * UINT64_C(1000000000) + (uint64_t)t.tv_nsec;
}
int main(int argc, char** argv) {
    if (argc != 3) return 10;
    size_t iterations = (size_t)strtoull(argv[1], NULL, 10);
    unsigned family = (unsigned)strtoul(argv[2], NULL, 10);
    uint64_t digest = UINT64_C(14695981039346656037);
    uint64_t started = tick();
    for (size_t i = 0; i < iterations; ++i) {
        size_t left = 3 + i % 255, right = 5 + i % 511;
        size_t limit = left < right ? left : right;
        uint32_t reject = family ? (uint32_t)(i % 17 == 0 ? 1 + i % 3 : 0) : 0;
        uint32_t early = family ? (uint32_t)(i % 4) : 0;
        uint64_t actual = composed_case(left, right, (uint8_t)i, i % limit, reject, early);
        digest = (digest ^ actual) * UINT64_C(1099511628211);
    }
    uint64_t elapsed = tick() - started;
    printf("{\"iterations\":%zu,\"family\":%u,\"elapsed_ns\":%" PRIu64 ",\"digest\":\"%016" PRIx64 "\"}\n",
           iterations, family, elapsed, digest);
    return 0;
}
'''


def benchmark(work, report, *, clangxx, clang, cc, iterations=200000, repeats=5):
    require(type(iterations) is int and 100 <= iterations <= 10000000, "Invalid benchmark iteration budget")
    require(type(repeats) is int and 3 <= repeats <= 11, "Benchmark needs 3..11 repetitions")
    costs = {"schema": "hepta.cpp-callback-cost.v1", "ok": False, "variants": [],
             "scope": "two_declared_variants_two_generated_workloads_this_host",
             "includes_runtime_allocation_callback_cleanup": True,
             "compile_cost_amortized_into_execution": False,
             "human_engineering_seconds": None,
             "universal_performance_superiority_claimed": False}
    begin = time.perf_counter_ns()
    project = work / "project"
    timer = shutil.which("/usr/bin/time")
    for number, qualified in enumerate(report["variants"], 1):
        target = work / qualified["name"]
        row = {"name": qualified["name"], "commands": [], "workloads": []}
        costs["variants"].append(row)
        source = target / "benchmark.c"
        source.write_text(BENCHMARK)
        caller = target / "benchmark-caller.o"
        build_begin = time.perf_counter_ns()
        command(row["commands"], None, [cc, "-std=c11", "-O3", "-fno-lto", "-c", str(source), "-o", str(caller)])
        originals = []
        for cpp in (project / "entry.cpp", project / "consume.cpp", target / "reference.cpp"):
            obj = target / (cpp.stem + ".perf.o")
            command(row["commands"], None, [clangxx, "-std=c++20", "-O3", "-fno-lto",
                                            "-DPROJECT_VARIANT=" + str(number), "-I" + str(project),
                                            "-c", str(cpp), "-o", str(obj)])
            originals.append(obj)
        baseline, candidate = target / "benchmark-cpp", target / "benchmark-hia"
        command(row["commands"], None, ["g++", "-O3", "-fno-lto", *map(str, originals), str(caller), "-o", str(baseline)])
        row["cpp_benchmark_build_wall_ns"] = time.perf_counter_ns() - build_begin
        lto_begin = time.perf_counter_ns()
        lto_objects = []
        for cpp in (project / "entry.cpp", project / "consume.cpp", target / "reference.cpp"):
            obj = target / (cpp.stem + ".lto.o")
            command(row["commands"], None, [clangxx, "-std=c++20", "-O3", "-flto",
                                            "-DPROJECT_VARIANT=" + str(number), "-I" + str(project),
                                            "-c", str(cpp), "-o", str(obj)])
            lto_objects.append(obj)
        strong_baseline = target / "benchmark-cpp-lto"
        command(row["commands"], None, [clangxx, "-O3", "-flto", "-fuse-ld=lld",
                                        *map(str, lto_objects), str(caller), "-o", str(strong_baseline)])
        row["cpp_lto_benchmark_build_wall_ns"] = time.perf_counter_ns() - lto_begin
        native_begin = time.perf_counter_ns()
        native_object = target / "benchmark-hia.o"
        native_document = json.loads((target / "standalone.core.json").read_text())
        row["hia_object_build"] = build_program_native(native_document, native_object, clang=clang, kind="object")
        row["hia_benchmark_build_wall_ns"] = time.perf_counter_ns() - native_begin
        link_begin = time.perf_counter_ns()
        command(row["commands"], None, [cc, "-O3", "-fno-lto", str(native_object), str(caller), "-o", str(candidate)])
        row["hia_benchmark_link_wall_ns"] = time.perf_counter_ns() - link_begin
        targets = (("cpp", baseline), ("cpp_lto", strong_baseline), ("hia", candidate))
        row["binary_bytes"] = {label: path.stat().st_size for label, path in targets}
        row["binary_sha256"] = {label: sha256(path.read_bytes()).hexdigest() for label, path in targets}
        row["optimization"] = {"cpp": "clang20_O3_separate_units_no_lto",
                               "cpp_lto": "clang20_O3_full_lto_lld",
                               "hia": "clang20_O3_single_generated_llvm_module"}
        for family in (0, 1):
            sample = {"name": "success" if family == 0 else "errors_and_cancellation",
                      "iterations": iterations, "repeats": repeats, "samples": {label: [] for label, _ in targets}}
            row["workloads"].append(sample)
            for repetition in range(repeats):
                offset = repetition % len(targets)
                order = targets[offset:] + targets[:offset]
                for label, binary in order:
                    argv = [str(binary), str(iterations), str(family)]
                    if timer:
                        argv = [timer, "-f", "peak_rss_kib=%M", *argv]
                    observed = command(row["commands"], None, argv)
                    result = json.loads(observed["stdout"])
                    require(result["iterations"] == iterations and result["family"] == family and result["elapsed_ns"] > 0,
                            "Malformed benchmark observation")
                    result["peak_rss_kib"] = None
                    if timer:
                        prefix, value = observed["stderr"].strip().rsplit("=", 1)
                        require(prefix.endswith("peak_rss_kib") and value.isdigit(), "Missing peak memory observation")
                        result["peak_rss_kib"] = int(value)
                    sample["samples"][label].append(result)
            digests = {v["digest"] for group in sample["samples"].values() for v in group}
            require(len(digests) == 1, "Benchmark C++ and migrated implementation disagree")
            sample["median_elapsed_ns"] = {label: statistics.median(v["elapsed_ns"] for v in observations)
                                           for label, observations in sample["samples"].items()}
            sample["cpp_over_hia_time_ratio"] = sample["median_elapsed_ns"]["cpp"] / sample["median_elapsed_ns"]["hia"]
            sample["cpp_lto_over_hia_time_ratio"] = sample["median_elapsed_ns"]["cpp_lto"] / sample["median_elapsed_ns"]["hia"]
            sample["median_ns_per_call"] = {label: elapsed / iterations for label, elapsed in sample["median_elapsed_ns"].items()}
            saved = sample["median_ns_per_call"]["cpp_lto"] - sample["median_ns_per_call"]["hia"]
            # Deliberately charge the entire two-variant capture to each
            # scenario. This avoids inventing a split of a shared measured
            # cost; the report states the allocation convention explicitly.
            upfront = (report["costs"]["migration_wall_ns"] + row["hia_benchmark_build_wall_ns"]
                       + row["hia_benchmark_link_wall_ns"])
            sample["amortization"] = {
                "baseline": "already_built_cpp_lto",
                "charge": "entire_measured_two_variant_migration_plus_this_hia_build_and_link",
                "upfront_wall_ns": upfront,
                "runtime_savings_per_call_ns": saved,
                "estimated_calls_to_amortize": math.ceil(upfront / saved) if saved > 0 else None,
                "measured_candidate_calls": iterations * repeats,
                "estimated_net_savings_at_measured_call_count_ns": saved * iterations * repeats - upfront,
                "human_contract_work_included": False,
                "unknown_future_reuse_guaranteed": False,
            }
    costs["wall_ns"] = time.perf_counter_ns() - begin
    costs["ok"] = True
    return costs


def allocation_high_water(work, report, *, clangxx, cc):
    """Observe bytes/owners with allocator hooks, independently of Core types."""
    results = []
    harness = EXAMPLE / "metrics_harness.c"
    for qualified in report["variants"]:
        target = work / qualified["name"]
        vectors = cases(qualified["name"])
        peak_bytes = peak_owners = 0
        for case in vectors:
            live_bytes = live_owners = 0
            for event, _, size in case["events"]:
                if event == 1:
                    live_bytes += size
                    live_owners += 1
                elif event == 2:
                    live_bytes -= size
                    live_owners -= 1
                peak_bytes = max(peak_bytes, live_bytes)
                peak_owners = max(peak_owners, live_owners)
            require(live_bytes == 0 and live_owners == 0, "Independent high-water oracle leaked an owner")
        expected = {**qualified["expected"], "max_live_bytes": peak_bytes, "max_live_owners": peak_owners}
        row = {"name": qualified["name"], "expected": expected, "commands": []}
        results.append(row)
        harness_object = target / "metrics-harness.cpp.o"
        command(row["commands"], None, [clangxx, *CPP_FLAGS, "-x", "c++", "-I" + str(target),
                                        "-c", str(harness), "-o", str(harness_object)])
        reference = target / "metrics-cpp"
        originals = [target / (name + ".cpp.o") for name in ("entry", "consume", "reference")]
        command(row["commands"], None, ["g++", *CPP_FLAGS, *map(str, originals), str(harness_object), "-o", str(reference)])
        candidate = target / "metrics-hia"
        command(row["commands"], None, [cc, "-std=c11", "-O2", "-fno-lto", *WRAP_FLAGS,
                                        "-I" + str(target), str(harness), str(target / "standalone.o"), "-o", str(candidate)])
        for label, binary in (("cpp", reference), ("hia", candidate)):
            observation = command(row, label, [str(binary)])
            require(strict_equal(json.loads(observation["stdout"]), expected),
                    "Native high-water resource observation differs for " + label)
        row["ok"] = True
    return {"ok": True, "scope": "actual_allocator_hooks_all_declared_cases", "variants": results}


def qualify(directory, *, clangxx="clang++", clang="clang", cc="gcc", iterations=200000, repeats=5):
    begin = time.perf_counter_ns()
    report = _qualify(directory, clangxx=clangxx, clang=clang, cc=cc, example=EXAMPLE,
        translate_matrix=lower_callback_matrix, vectors_for_variant=cases, bindings_for_run=source_bindings,
        schema="hepta.cpp-callback-project-native-qualification.v1",
        extra_claims={"closed_synchronous_callback_implementation_migrated": True,
                      "arbitrary_callback_or_pointer_escape_supported": False,
                      "callback_body_and_failure_paths_translated": True},
        extra_native_controls=semantic_controls)
    if report["ok"]:
        try:
            report["allocation_high_water"] = allocation_high_water(Path(directory).absolute(), report,
                                                                    clangxx=clangxx, cc=cc)
            report["performance"] = benchmark(Path(directory).absolute(), report, clangxx=clangxx, clang=clang, cc=cc,
                                               iterations=iterations, repeats=repeats)
            require(compiler_hash() == report["compiler_sha256"], "Compiler changed during benchmark")
            require(source_bindings() == report["source_bindings"], "Sources changed during benchmark")
            report["costs"]["performance_comparison_performed"] = True
            report["claims"]["performance_qualified"] = True
            report["claims"]["performance_scope"] = "generated_success_error_and_cancellation_workloads_only"
        except Exception as error:
            report["ok"] = False
            report["error"] = {"kind": type(error).__name__, "message": str(error)}
    report["costs"]["qualification_wall_ns"] = time.perf_counter_ns() - begin
    report["migration_coverage"] = {
        "captured_project_free_function_definitions": 3,
        "implemented_free_function_definitions": 3 if report["variants"] else 0,
        "original_cpp_bridge_functions_in_target": 0,
        "borrowed_callback_definitions": 1,
        "external_cxx_standard_library_bodies_migrated": 0,
        "general_cpp_source_coverage_percentage": None,
        "manual_profile_implementation_required": True,
        "human_engineering_seconds": None,
        "human_time_not_inferred_from_wall_clock": True,
    }
    (Path(directory) / "qualification.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workdir", required=True)
    parser.add_argument("--clang", default="clang")
    parser.add_argument("--clangxx", default="clang++")
    parser.add_argument("--cc", default="gcc")
    parser.add_argument("--iterations", type=int, default=200000)
    parser.add_argument("--repeats", type=int, default=5)
    args = parser.parse_args()
    report = qualify(args.workdir, clang=args.clang, clangxx=args.clangxx, cc=args.cc,
                     iterations=args.iterations, repeats=args.repeats)
    print(json.dumps({"ok": report["ok"], "error": report.get("error"),
                      "cases": [v["case_count"] for v in report["variants"]],
                      "costs": report["costs"]}))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
