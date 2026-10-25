#!/usr/bin/env python3
"""Frozen host-only Rust/LLVM scalar32 correctness and performance qualification.

There are no CLI overrides for the workload, repetitions, sample count, or
acceptance thresholds. Change the protocol ID before changing those constants.
The same checked Hepta source builds both actual native implementations.
"""
from __future__ import annotations

import argparse
import ctypes
import datetime
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import platform
import shutil
import statistics
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from hepta.backend import RUST_VERSION, compile_rust
from hepta.cfg import lower_hsir_cfg
from hepta.clang_capture import run_bounded
from hepta.hsir import lower_checked_program
from hepta.llvm_ssa_backend import emit_scalar_ssa_llvm, compile_scalar_ssa_llvm
from hepta.llvm_ssa_target import compile_ssa_target_object
from hepta.pipeline import analyze, compiler_hash
from hepta.ssa import lower_cfg_scalar_ssa
from tools.evidence_checks import is_sha, native_build, normalized_errors, require, strict_equal, text


PROTOCOL = {
    "id": "hepta.llvm-native-scalar32-perf.v2",
    "supersedes_protocol_sha256": "b6d02dd1423590766589945531fe7489c22347ee35737917de3215de6e1b9a6e",
    "revision_reason": "v1 samples were shorter than 50 ms; uniformly repeat its 64-call input sequence 16 times",
    "paired_groups": 7,
    "kernel_iterations": 1_048_576,
    "native_calls_per_sample": 1024,
    "warmup_calls_per_process": 8,
    "minimum_sample_seconds": 0.05,
    "maximum_relative_mad": 0.05,
    "maximum_geometric_mean_paired_time_ratio": 1.10,
    "maximum_kernel_paired_time_ratio": 1.20,
    "relative_mad_definition": "median(abs(sample - median(samples))) / median(samples)",
    "ratio_definition": "median over paired groups of LLVM elapsed / Rust elapsed",
    "ordering": "rotate kernel order by group; alternate Rust/LLVM order by group+kernel",
    "cpu_affinity": "lowest permitted logical CPU; enforced for qualifier and descendants",
    "outlier_policy": "retain every sample; no clipping, retries, or best-run selection",
    "overflow_semantics": "checked i32/u32 add/sub/mul and abort on overflow on both paths",
}
KERNELS = ("signed_walk", "unsigned_walk", "branch_accumulate")
SOURCE = """module qualify_llvm_native;
export "C" fn signed_walk(n: i32, seed: i32) -> i32 effects {panic} {
    let mut i: i32 = 0;
    let mut state: i32 = seed;
    while i < n {
        if state < 0 { state = state + 31; }
        else { state = state - 19; }
        i = i + 1;
    }
    return state;
}
export "C" fn unsigned_walk(n: u32, seed: u32) -> u32 effects {panic} {
    let mut i: u32 = 0;
    let mut state: u32 = seed;
    while i < n {
        if state < 65536 { state = state * 3 + 1; }
        else { state = state - 65535; }
        i = i + 1;
    }
    return state;
}
export "C" fn branch_accumulate(n: i32, seed: i32) -> i32 effects {panic} {
    let mut i: i32 = 0;
    let mut state: i32 = seed;
    let mut total: i32 = 0;
    while i < n {
        if state < 7 { total = total + state; state = state + 1; }
        else { total = total - 3; state = 0; }
        i = i + 1;
    }
    return total;
}
"""
DRIVER = r"""#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <time.h>
#include <sys/resource.h>
typedef int32_t (*Signed)(int32_t, int32_t);
typedef uint32_t (*Unsigned)(uint32_t, uint32_t);
static uint64_t nanos(struct timespec t) {
    return (uint64_t)t.tv_sec * UINT64_C(1000000000) + (uint64_t)t.tv_nsec;
}
int main(int argc, char **argv) {
    if (argc != 6) return 11;
    int is_unsigned = strcmp(argv[2], "unsigned_walk") == 0;
    if (!is_unsigned && strcmp(argv[2], "signed_walk") && strcmp(argv[2], "branch_accumulate")) return 12;
    uint32_t n = (uint32_t)strtoul(argv[3], NULL, 10);
    unsigned reps = (unsigned)strtoul(argv[4], NULL, 10);
    unsigned warmup = (unsigned)strtoul(argv[5], NULL, 10);
    if (n != 1048576 || reps != 1024 || warmup != 8) return 13;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) { fprintf(stderr, "%s\n", dlerror()); return 14; }
    dlerror();
    void *symbol = dlsym(handle, argv[2]);
    if (dlerror() || !symbol) return 15;
    Signed signed_fn = NULL;
    Unsigned unsigned_fn = NULL;
    _Static_assert(sizeof(symbol) == sizeof(signed_fn), "POSIX function pointer size");
    _Static_assert(sizeof(symbol) == sizeof(unsigned_fn), "POSIX function pointer size");
    memcpy(&signed_fn, &symbol, sizeof(symbol));
    memcpy(&unsigned_fn, &symbol, sizeof(symbol));
    volatile uint64_t warm_sink = 0;
    for (unsigned r = 0; r < warmup; ++r) {
        uint32_t seed = ((r % 64) * 17 + 13) % 97 + 1;
        warm_sink ^= is_unsigned ? unsigned_fn(n, seed) : (uint32_t)signed_fn((int32_t)n, (int32_t)seed);
    }
    struct timespec begin, end, resolution;
    if (clock_getres(CLOCK_MONOTONIC_RAW, &resolution)) return 16;
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &begin)) return 17;
    uint64_t checksum = UINT64_C(1469598103934665603);
    for (unsigned r = 0; r < reps; ++r) {
        uint32_t seed = ((r % 64) * 17 + 13) % 97 + 1;
        uint32_t result = is_unsigned ? unsigned_fn(n, seed) : (uint32_t)signed_fn((int32_t)n, (int32_t)seed);
        checksum = (checksum ^ result) * UINT64_C(1099511628211);
    }
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &end)) return 18;
    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage)) return 19;
    if (nanos(end) <= nanos(begin)) return 20;
    printf("{\"elapsed_ns\":%" PRIu64 ",\"checksum\":%" PRIu64
           ",\"clock_resolution_ns\":%" PRIu64 ",\"process_peak_rss_kib\":%ld}\n",
           nanos(end) - nanos(begin), checksum, nanos(resolution), usage.ru_maxrss);
    dlclose(handle);
    (void)warm_sink;
    return 0;
}
"""


def sha(data):
    return hashlib.sha256(data).hexdigest()


def digest(path):
    return sha(Path(path).read_bytes())


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def run(argv, *, timeout=120):
    result = run_bounded(list(map(str, argv)), timeout=timeout, stdin_limit=0,
                         stdout_limit=128_000, stderr_limit=256_000)
    if result.returncode:
        raise RuntimeError(f"E_NATIVE_QUALIFY_COMMAND: {argv[0]} exited {result.returncode}: {result.stderr[:2000]}")
    return result.stdout


def oracle(kernel, n, seed):
    state, total = seed, 0
    for _ in range(max(0, n)):
        if kernel == "signed_walk":
            state = state + 31 if state < 0 else state - 19
        elif kernel == "unsigned_walk":
            state = state * 3 + 1 if state < 65536 else state - 65535
        elif state < 7:
            total, state = total + state, state + 1
        else:
            total, state = total - 3, 0
    return total if kernel == "branch_accumulate" else state


def correctness_cases():
    """The complete finite oracle domain, independent of native loading."""
    cases = []
    for kernel in KERNELS:
        unsigned = kernel == "unsigned_walk"
        counts = (0, 1, 2, 7, 31, 127, 257, 1024) + (() if unsigned else (-7, -1))
        seeds = ((0, 1, 97, 65535, 65536, 196606, 2**32 - 1) if unsigned else
                 (-2**31, -1, 0, 1, 97, 2**31 - 1) if kernel == "signed_walk" else
                 (-7, -1, 0, 1, 6, 7, 97))
        for n in counts:
            for seed in seeds:
                cases.append({"kernel": kernel, "iterations": n, "seed": seed,
                              "expected": oracle(kernel, n, seed)})
    return cases


def check_correctness(libraries):
    if set(libraries) != {"rust", "llvm"}:
        raise ValueError("E_NATIVE_QUALIFY_CORRECTNESS: both native backends required")
    loaded = {name: ctypes.CDLL(str(libraries[name])) for name in ("rust", "llvm")}
    cases = correctness_cases()
    for case in cases:
        kernel, n, seed, expected = (case[key] for key in ("kernel", "iterations", "seed", "expected"))
        typ = ctypes.c_uint32 if kernel == "unsigned_walk" else ctypes.c_int32
        functions = [getattr(lib, kernel) for lib in loaded.values()]
        for fn in functions:
            fn.argtypes, fn.restype = [typ, typ], typ
        observed = [int(fn(n, seed)) for fn in functions]
        if observed != [expected, expected]:
            raise RuntimeError(f"E_NATIVE_QUALIFY_CORRECTNESS: {kernel}/{n}/{seed}: {observed} != {expected}")
    return {"status": "passed_finite_domain", "cases": cases, "case_count": len(cases),
            "native_calls": len(cases) * 2, "oracle": "independent Python integer recurrence"}


def evaluate_samples(rows):
    """Apply the frozen gates to all samples; malformed/incomplete data reject."""
    expected = {(kernel, group, backend) for kernel in KERNELS
                for group in range(PROTOCOL["paired_groups"]) for backend in ("rust", "llvm")}
    seen, summary, quality_failures, performance_failures = set(), {}, [], []
    for row in rows:
        key = (row.get("kernel"), row.get("group"), row.get("backend"))
        elapsed = row.get("elapsed_ns")
        if key not in expected or key in seen or type(elapsed) is not int or elapsed <= 0:
            raise ValueError("E_NATIVE_QUALIFY_SAMPLES: malformed, duplicate or nonpositive sample")
        seen.add(key)
    if seen != expected:
        raise ValueError("E_NATIVE_QUALIFY_SAMPLES: missing paired samples")
    for kernel in KERNELS:
        stats = {}
        for backend in ("rust", "llvm"):
            values = [r["elapsed_ns"] for r in rows if r["kernel"] == kernel and r["backend"] == backend]
            middle = statistics.median(values)
            relative_mad = statistics.median(abs(x - middle) for x in values) / middle
            stats[backend] = {"samples_ns": values, "median_ns": middle, "minimum_ns": min(values),
                              "maximum_ns": max(values), "relative_mad": relative_mad,
                              "median_ns_per_kernel_iteration": middle / (
                                  PROTOCOL["native_calls_per_sample"] * PROTOCOL["kernel_iterations"])}
            if min(values) < PROTOCOL["minimum_sample_seconds"] * 1e9:
                quality_failures.append(f"{kernel}/{backend}: sample shorter than fixed minimum")
            if relative_mad > PROTOCOL["maximum_relative_mad"]:
                quality_failures.append(f"{kernel}/{backend}: relative MAD above fixed maximum")
        pairs = []
        for group in range(PROTOCOL["paired_groups"]):
            pair = {r["backend"]: r for r in rows if r["kernel"] == kernel and r["group"] == group}
            if (type(pair["rust"].get("checksum")) is not int or
                    pair["rust"].get("checksum") != pair["llvm"].get("checksum")):
                raise ValueError("E_NATIVE_QUALIFY_CORRECTNESS: timed native checksums differ")
            pairs.append(pair["llvm"]["elapsed_ns"] / pair["rust"]["elapsed_ns"])
        ratio = statistics.median(pairs)
        summary[kernel] = {"implementations": stats, "paired_time_ratios": pairs, "median_paired_time_ratio": ratio}
        if ratio > PROTOCOL["maximum_kernel_paired_time_ratio"]:
            performance_failures.append(f"{kernel}: median paired LLVM/Rust ratio exceeds fixed maximum")
    geometric = math.exp(statistics.mean(math.log(v["median_paired_time_ratio"]) for v in summary.values()))
    if geometric > PROTOCOL["maximum_geometric_mean_paired_time_ratio"]:
        performance_failures.append("geometric mean LLVM/Rust ratio exceeds fixed maximum")
    status = ("measurement_inconclusive" if quality_failures else
              "performance_failed" if performance_failures else "passed")
    return {"status": status, "ok": status == "passed", "summary": summary,
            "geometric_mean_paired_time_ratio": geometric,
            "measurement_quality_failures": quality_failures,
            "performance_threshold_failures": performance_failures}


@normalized_errors
def validate_report(report, *, expected_git_commit=None):
    """Accept only a complete, successful current-source v2 qualification.

    This replays the frontend/SSA/LLVM and finite oracle without invoking any
    native compiler or collecting timings. It checks retained observations and
    their relationships; JSON alone cannot authenticate arbitrary third-party
    execution. The release caller can additionally bind its candidate commit.
    """
    require(isinstance(report, dict) and report.get("schema") == "hepta.llvm-native-qualification.v1"
            and report.get("status") == "passed" and report.get("ok") is True
            and report.get("phase") == "complete" and "diagnostic" not in report,
            "native performance qualification did not complete successfully")
    require(strict_equal(report.get("protocol"), PROTOCOL)
            and report.get("protocol_sha256") == sha(wire(PROTOCOL).encode())
            and report.get("source_sha256") == sha(SOURCE.encode())
            and report.get("driver_source_sha256") == sha(DRIVER.encode())
            and report.get("qualifier_sha256") == digest(__file__)
            and report.get("compiler_tree_sha256") == compiler_hash(),
            "native performance protocol, source, driver or current implementation identity differs")
    commit = report.get("git_commit")
    require(isinstance(commit, str) and len(commit) == 40
            and all(c in "0123456789abcdef" for c in commit)
            and (expected_git_commit is None or commit == expected_git_commit),
            "native performance candidate commit differs")
    require(strict_equal(report.get("claims"), {
        "finite_correctness_checked": True, "host_scalar32_performance_gate_passed": True,
        "whole_language_performance_qualified": False, "owned_or_borrowed_lowering_qualified": False,
        "backend_refinement_proved": False, "universal_rust_superiority_proved": False,
        "heap_allocation_cost_qualified": False, "cross_target_execution_qualified": False}),
        "native performance scope or claims differ")

    frontend = report.get("reference_validation", {})
    source_path = frontend.get("path")
    require(text(source_path) and PurePosixPath(source_path).is_absolute()
            and PurePosixPath(source_path).name == "kernels.hepta",
            "native source path missing or mismatched")
    directory = PurePosixPath(source_path).parent
    generated = analyze(SOURCE, source_path, native=False, crate_type="cdylib")
    require(generated.report["ok"] is True, "frozen native source no longer checks")
    expected_frontend = dict(generated.report)
    expected_frontend["status"] = "checked"
    expected_frontend["checks"] = dict(expected_frontend["checks"], rust_borrows_types="rustc_checked")
    require(strict_equal({key: value for key, value in frontend.items() if key != "backend"},
                         expected_frontend), "native reference frontend, effects, resources or assumptions differ")
    rust_sha = sha(generated.rust.encode())
    require(report.get("generated_rust_sha256") == rust_sha, "generated Rust source identity differs")
    reference = frontend.get("backend")
    native_build(reference, "rust", check_only=True, crate_type="cdylib", source_sha256=rust_sha)
    receipts = report.get("native_receipts", {})
    require(set(receipts) == {"rust_library", "rust_object", "llvm_library", "llvm_object"},
            "both native libraries and separately emitted objects are required")
    for name, native, check_only, crate_type in (
        ("reference", reference, True, "cdylib"),
        ("rust_library", receipts["rust_library"], False, "cdylib"),
        ("rust_object", receipts["rust_object"], False, "obj"),
    ):
        native_build(native, "rust", check_only=check_only, crate_type=crate_type, source_sha256=rust_sha)
        chain = native["toolchain"]
        version_fields = dict(line.split(": ", 1) for line in chain["version"].splitlines() if ": " in line)
        require(chain["version"].startswith("rustc ") and version_fields.get("binary") == "rustc"
                and version_fields.get("release") == RUST_VERSION
                and version_fields.get("host") == "x86_64-unknown-linux-gnu"
                and text(version_fields.get("commit-hash"))
                and native["target"] == chain.get("host") == "x86_64-unknown-linux-gnu"
                and strict_equal(chain, reference["toolchain"]),
                "pinned Rust native host toolchain identity differs")
        sysroot, linker = native.get("sysroot"), native.get("linker")
        require(sysroot == chain.get("sysroot") and (sysroot is None or text(sysroot))
                and (linker is None or (name == "rust_library" and text(linker))),
                "native Rust sysroot or linker identity differs")
        flags = ["edition=2021", "opt-level=3", "overflow-checks=yes", "panic=abort", "codegen-units=1"]
        if sysroot:
            flags.append("sysroot=" + sysroot)
        if linker:
            flags.append("linker=" + linker)
        require(strict_equal(native["flags"], flags) and strict_equal(native.get("link_args"), [])
                and native.get("rustc_crate_type") == ("cdylib" if name == "rust_library" else "lib"),
                "native Rust checked-overflow optimization profile differs")
        if not check_only:
            extension = ".so" if name == "rust_library" else ".o"
            require(native["artifact"] == str(directory / ("rust" + extension)),
                    "native Rust artifact path differs")

    cfg = lower_hsir_cfg(lower_checked_program(generated.program, generated.checked))
    ssa = lower_cfg_scalar_ssa(cfg)
    ir = emit_scalar_ssa_llvm(ssa, cfg)
    require(report.get("llvm_ir_sha256") == ir.sha256 and report.get("ssa_sha256") == ssa.sha256
            and report.get("ssa_verification_sha256") == ir.verification_sha256,
            "native LLVM source differs from freshly checked SSA/CFG")
    clang = report.get("clang", {})
    require(text(clang.get("path")) and PurePosixPath(clang["path"]).is_absolute()
            and text(clang.get("version")) and is_sha(clang.get("sha256")),
            "native Clang identity missing")
    library, object_report = receipts["llvm_library"], receipts["llvm_object"]
    require(library.get("schema") == "hepta.llvm-ssa-host.v0"
            and library.get("status") == "native_host_compiled_unqualified"
            and library.get("output") == str(directory / "llvm.so")
            and library.get("ssa_verification_sha256") == ir.verification_sha256
            and strict_equal(library.get("toolchain"),
                             {"version": clang["version"], "compiler_sha256": clang["sha256"]})
            and strict_equal(library.get("claims"), {
                "backend_refinement_proven": False, "cross_target_abi_qualified": False,
                "runtime_execution_qualified": False, "whole_p6_gate_closed": False,
                "ssa_cfg_origin_rechecked": True}), "LLVM native library identity or origin differs")
    require(object_report.get("schema") == "hepta.llvm-ssa-object.v0"
            and object_report.get("status") == "cross_object_only_not_executed"
            and object_report.get("target") == "x86_64-unknown-linux-gnu"
            and object_report.get("object_format") == "ELF64" and type(object_report.get("machine")) is int
            and object_report["machine"] == 62
            and strict_equal(object_report.get("functions"), list(ir.functions))
            and object_report.get("structural_ssa_verification_sha256") == ir.verification_sha256
            and strict_equal(object_report.get("compiler"),
                             {"version": clang["version"], "sha256": clang["sha256"]})
            and strict_equal(object_report.get("claims"), {
                "target_object_compiled": True, "target_program_executed": False,
                "foreign_c_abi_qualified": False, "physical_hardware_tested": False,
                "native_backend_semantics_proved": False, "full_language_profile_qualified": False,
                "ssa_cfg_origin_rechecked": True}), "LLVM object identity or origin differs")
    for native in (library, object_report):
        require(native.get("llvm_ir_sha256") == ir.sha256 and native.get("ssa_sha256") == ssa.sha256
                and native.get("llvm_source_profile") == ir.profile, "LLVM build source identity differs")
    artifacts = report.get("artifacts", {})
    require(set(artifacts) == set(receipts) | {"driver_object", "driver_binary"},
            "complete native artifact inventory required")
    for name, artifact in artifacts.items():
        require(isinstance(artifact, dict) and set(artifact) == {"sha256", "bytes"}
                and is_sha(artifact["sha256"]) and type(artifact["bytes"]) is int and artifact["bytes"] > 0,
                "native artifact identity missing or empty")
        if name in receipts:
            require(artifact["sha256"] == receipts[name].get("artifact_sha256")
                    and type(receipts[name].get("artifact_bytes")) is int
                    and artifact["bytes"] == receipts[name]["artifact_bytes"],
                    "native build and measured artifact identity differ")
    require(strict_equal(report.get("driver_commands"), [
        [clang["path"], "-std=c11", "-O3", "-Wall", "-Wextra", "-Werror",
         "-c", str(directory / "driver.c"), "-o", str(directory / "driver.o")],
        [clang["path"], str(directory / "driver.o"), "-ldl", "-o", str(directory / "driver")]]),
        "native driver compile/link profile differs")
    require(report.get("object_relationship") == "Rust/LLVM objects are separate emissions of identical sources, not the link inputs of the measured shared libraries",
            "object emission must not be conflated with the measured library link")

    cases = correctness_cases()
    require(strict_equal(report.get("correctness"), {
        "status": "passed_finite_domain", "cases": cases, "case_count": len(cases),
        "native_calls": len(cases) * 2, "oracle": "independent Python integer recurrence"}),
        "complete native correctness domain and independent oracle results required")
    expected_order = []
    for group in range(PROTOCOL["paired_groups"]):
        rotation = group % len(KERNELS)
        for kernel_index, kernel in enumerate(KERNELS[rotation:] + KERNELS[:rotation]):
            backends = ("rust", "llvm") if (group + kernel_index) % 2 == 0 else ("llvm", "rust")
            expected_order.extend((group, kernel, backend) for backend in backends)
    rows = report.get("raw_samples")
    require(isinstance(rows, list) and len(rows) == len(expected_order), "all 42 timed native samples required")
    checksums = {}
    for index, (row, (group, kernel, backend)) in enumerate(zip(rows, expected_order)):
        require(isinstance(row, dict) and set(row) == {
            "group", "kernel", "backend", "sample_index", "elapsed_ns", "checksum",
            "clock_resolution_ns", "process_peak_rss_kib"}
            and strict_equal([row.get("group"), row.get("kernel"), row.get("backend"), row.get("sample_index")],
                             [group, kernel, backend, index]), "native sample inventory or frozen execution order differs")
        require(all(type(row[key]) is int and row[key] > 0 for key in
                    ("elapsed_ns", "clock_resolution_ns", "process_peak_rss_kib"))
                and row["clock_resolution_ns"] <= row["elapsed_ns"]
                and type(row["checksum"]) is int and 0 <= row["checksum"] < 2**64,
                "native sample timing, clock, memory or checksum malformed")
        require(row["checksum"] == checksums.setdefault(kernel, row["checksum"]),
                "identical timed input sequence produced different native checksums")
    evaluation = evaluate_samples(rows)
    require(strict_equal(report.get("evaluation"), evaluation), "native sample evaluation was altered")
    require(evaluation["ok"] is True and evaluation["status"] == "passed",
            "raw native samples fail frozen performance or measurement-quality gates")

    environment = report.get("environment", {})
    allowed = environment.get("allowed_cpus_before")
    require(environment.get("system") == "Linux" and environment.get("machine") in {"x86_64", "amd64"}
            and text(environment.get("kernel")) and text(environment.get("python"))
            and isinstance(allowed, list) and allowed
            and all(type(cpu) is int and cpu >= 0 for cpu in allowed)
            and allowed == sorted(set(allowed)) and type(environment.get("selected_cpu")) is int
            and environment["selected_cpu"] == allowed[0]
            and environment.get("scope") == "shared host; affinity reduces migration but does not provide exclusive CPU access",
            "native host or fixed affinity evidence differs")
    for key in ("loadavg_before", "loadavg_after"):
        values = environment.get(key)
        require(isinstance(values, list) and len(values) == 3
                and all(type(value) in {int, float} and math.isfinite(value) and value >= 0 for value in values),
                "native host load observations missing or malformed")
    timings = report.get("compile_wall_seconds", {})
    require(set(timings) == set(receipts) | {
        "checked_frontend_and_native_rust_metadata", "native_driver_object_and_link"}
        and all(type(value) in {int, float} and math.isfinite(value) and value >= 0 for value in timings.values())
        and report.get("compile_time_scope") == "wall time of checked build operation, including tool identity and temporary I/O",
        "native compilation timings missing, nonfinite or mislabeled")
    dates = [datetime.datetime.strptime(report[key], "%Y-%m-%dT%H:%M:%SZ")
             for key in ("started_utc", "finished_utc")]
    require(dates[0] <= dates[1], "native qualification timestamps are reversed")


def optional_read(path):
    try:
        return Path(path).read_text().strip()
    except OSError:
        return None


def qualify(*, clang="clang", rustc=None):
    report = {"schema": "hepta.llvm-native-qualification.v1", "status": "blocked", "ok": False,
              "protocol": dict(PROTOCOL), "protocol_sha256": sha(wire(PROTOCOL).encode()),
              "source_sha256": sha(SOURCE.encode()), "driver_source_sha256": sha(DRIVER.encode()),
              "qualifier_sha256": digest(__file__), "compiler_tree_sha256": compiler_hash(),
              "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "raw_samples": [], "compile_wall_seconds": {},
              "claims": {"finite_correctness_checked": False, "host_scalar32_performance_gate_passed": False,
                         "whole_language_performance_qualified": False, "owned_or_borrowed_lowering_qualified": False,
                         "backend_refinement_proved": False, "universal_rust_superiority_proved": False,
                         "heap_allocation_cost_qualified": False, "cross_target_execution_qualified": False}}
    affinity = None
    try:
        if platform.system() != "Linux" or platform.machine() not in {"x86_64", "amd64"}:
            raise ValueError("E_NATIVE_QUALIFY_HOST: this frozen protocol requires Linux x86_64")
        if not hasattr(os, "sched_getaffinity") or not hasattr(os, "sched_setaffinity"):
            raise ValueError("E_NATIVE_QUALIFY_AFFINITY: CPU affinity controls required")
        affinity = os.sched_getaffinity(0)
        selected_cpu = min(affinity)
        os.sched_setaffinity(0, {selected_cpu})
        report["environment"] = {
            "system": platform.system(), "machine": platform.machine(), "kernel": platform.release(),
            "python": platform.python_version(), "libc": platform.libc_ver(),
            "allowed_cpus_before": sorted(affinity), "selected_cpu": selected_cpu,
            "cpu_model": next((line.split(":", 1)[1].strip() for line in
                               (optional_read("/proc/cpuinfo") or "").splitlines()
                               if line.startswith("model name")), None),
            "scaling_governor": optional_read(f"/sys/devices/system/cpu/cpu{selected_cpu}/cpufreq/scaling_governor"),
            "cgroup_cpu_max": optional_read("/sys/fs/cgroup/cpu.max"),
            "loadavg_before": list(os.getloadavg()),
            "scope": "shared host; affinity reduces migration but does not provide exclusive CPU access",
        }
        report["git_commit"] = run(["git", "-C", ROOT, "rev-parse", "HEAD"]).strip()
        dirty = run(["git", "-C", ROOT, "status", "--porcelain", "--untracked-files=no"]).strip()
        if dirty:
            raise ValueError("E_NATIVE_QUALIFY_DIRTY: commit tracked implementation before measurement")
        found = shutil.which(clang)
        if not found:
            raise ValueError("E_NATIVE_QUALIFY_CLANG: native Clang required")
        compiler = Path(found).resolve()
        report["clang"] = {"path": str(compiler), "sha256": digest(compiler),
                           "version": run([compiler, "--version"]).splitlines()[0]}
        report["phase"] = "build"
        with tempfile.TemporaryDirectory(prefix="hepta-llvm-native-qualify-") as directory:
            temp = Path(directory)
            source_path, driver_source = temp / "kernels.hepta", temp / "driver.c"
            source_path.write_text(SOURCE)
            driver_source.write_text(DRIVER)
            start = time.perf_counter()
            analysis = analyze(SOURCE, str(source_path), native=True, rustc=rustc, crate_type="cdylib")
            report["compile_wall_seconds"]["checked_frontend_and_native_rust_metadata"] = time.perf_counter() - start
            report["reference_validation"] = analysis.report
            if not analysis.report["ok"] or analysis.report["checks"]["rust_borrows_types"] != "rustc_checked":
                raise ValueError("E_NATIVE_QUALIFY_RUST: pinned native Rust reference gate rejected")
            report["generated_rust_sha256"] = sha(analysis.rust.encode())
            cfg = lower_hsir_cfg(lower_checked_program(analysis.program, analysis.checked))
            ssa = lower_cfg_scalar_ssa(cfg)
            ir = emit_scalar_ssa_llvm(ssa, cfg)
            report["llvm_ir_sha256"] = ir.sha256
            report["ssa_sha256"] = ssa.sha256
            report["ssa_verification_sha256"] = ir.verification_sha256
            libraries = {name: temp / (name + ".so") for name in ("rust", "llvm")}
            objects = {name: temp / (name + ".o") for name in ("rust", "llvm")}
            receipts = {}
            builds = (
                ("rust_library", lambda: compile_rust(analysis.rust, rustc=rustc, crate_type="cdylib", output=libraries["rust"])),
                ("llvm_library", lambda: compile_scalar_ssa_llvm(ir, clang=str(compiler), output=libraries["llvm"], ssa=ssa, cfg=cfg)),
                ("rust_object", lambda: compile_rust(analysis.rust, rustc=rustc, crate_type="obj", output=objects["rust"])),
                ("llvm_object", lambda: compile_ssa_target_object(ir, clang=str(compiler), target="x86_64-unknown-linux-gnu",
                                                                 output=objects["llvm"], ssa=ssa, cfg=cfg)),
            )
            for name, build in builds:
                start = time.perf_counter()
                receipts[name] = build()
                report["compile_wall_seconds"][name] = time.perf_counter() - start
                if name.startswith("rust") and receipts[name]["ok"] is not True:
                    raise ValueError(f"E_NATIVE_QUALIFY_BUILD: {name} failed")
            report["native_receipts"] = receipts
            driver_object, driver = temp / "driver.o", temp / "driver"
            start = time.perf_counter()
            compile_command = [str(compiler), "-std=c11", "-O3", "-Wall", "-Wextra", "-Werror",
                               "-c", str(driver_source), "-o", str(driver_object)]
            link_command = [str(compiler), str(driver_object), "-ldl", "-o", str(driver)]
            run(compile_command)
            run(link_command)
            report["driver_commands"] = [compile_command, link_command]
            report["compile_wall_seconds"]["native_driver_object_and_link"] = time.perf_counter() - start
            report["compile_time_scope"] = "wall time of checked build operation, including tool identity and temporary I/O"
            artifacts = {**{f"{key}_library": path for key, path in libraries.items()},
                         **{f"{key}_object": path for key, path in objects.items()},
                         "driver_object": driver_object, "driver_binary": driver}
            report["artifacts"] = {name: {"sha256": digest(path), "bytes": path.stat().st_size}
                                   for name, path in artifacts.items()}
            report["object_relationship"] = "Rust/LLVM objects are separate emissions of identical sources, not the link inputs of the measured shared libraries"
            report["phase"] = "correctness"
            report["correctness"] = check_correctness(libraries)
            report["claims"]["finite_correctness_checked"] = True
            report["phase"] = "measurement"
            for group in range(PROTOCOL["paired_groups"]):
                rotation = group % len(KERNELS)
                order = KERNELS[rotation:] + KERNELS[:rotation]
                for kernel_index, kernel in enumerate(order):
                    backends = ("rust", "llvm") if (group + kernel_index) % 2 == 0 else ("llvm", "rust")
                    for backend in backends:
                        argv = [driver, libraries[backend], kernel, str(PROTOCOL["kernel_iterations"]),
                                str(PROTOCOL["native_calls_per_sample"]), str(PROTOCOL["warmup_calls_per_process"])]
                        measured = json.loads(run(argv, timeout=120))
                        report["raw_samples"].append({"group": group, "kernel": kernel, "backend": backend,
                                                      "sample_index": len(report["raw_samples"]), **measured})
            report["evaluation"] = evaluate_samples(report["raw_samples"])
            if any(digest(path) != report["artifacts"][name]["sha256"] for name, path in artifacts.items()):
                raise ValueError("E_NATIVE_QUALIFY_IDENTITY: compiled artifact changed during measurement")
            if compiler_hash() != report["compiler_tree_sha256"]:
                raise ValueError("E_NATIVE_QUALIFY_IDENTITY: compiler source changed during qualification")
            report["status"] = report["evaluation"]["status"]
            report["ok"] = report["evaluation"]["ok"]
            report["claims"]["host_scalar32_performance_gate_passed"] = report["ok"]
            report["phase"] = "complete"
    except (OSError, RuntimeError, ValueError, TypeError, KeyError) as exc:
        report["diagnostic"] = {"code": str(exc).split(":", 1)[0], "message": str(exc)}
        report["status"] = "correctness_failed" if report.get("phase") == "correctness" else "blocked"
        report["ok"] = False
    finally:
        if affinity is not None:
            os.sched_setaffinity(0, affinity)
        report["finished_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        if "environment" in report:
            report["environment"]["loadavg_after"] = list(os.getloadavg())
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--clang", default="clang")
    parser.add_argument("--rustc", default=os.environ.get("RUSTC"))
    parser.add_argument("--describe-protocol", action="store_true")
    args = parser.parse_args(argv)
    if args.describe_protocol:
        print(json.dumps({"protocol": PROTOCOL, "protocol_sha256": sha(wire(PROTOCOL).encode()),
                          "source_sha256": sha(SOURCE.encode()), "driver_source_sha256": sha(DRIVER.encode())},
                         indent=2, sort_keys=True))
        return 0
    if args.output is None:
        parser.error("--output is required for an actual qualification run")
    if args.output.exists() or args.output.is_symlink() or not args.output.parent.is_dir():
        parser.error("--output must be a new file in an existing directory")
    report = qualify(clang=args.clang, rustc=args.rustc)
    with args.output.open("x", encoding="utf-8") as destination:
        json.dump(report, destination, indent=2, sort_keys=True, allow_nan=False)
        destination.write("\n")
    evaluation = report.get("evaluation", {})
    print(json.dumps({"ok": report["ok"], "status": report["status"], "output": str(args.output),
                      "geometric_mean_paired_time_ratio": evaluation.get("geometric_mean_paired_time_ratio"),
                      "measurement_quality_failures": evaluation.get("measurement_quality_failures", []),
                      "performance_threshold_failures": evaluation.get("performance_threshold_failures", []),
                      "diagnostic": report.get("diagnostic")}, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
