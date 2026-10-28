#!/usr/bin/env python3
"""Frozen, finite-host HIA / Rust / C / C++ byte-owner comparison.

No retries, trimming, adaptive repetition counts, threshold overrides, or
holdout-based compiler selection. Real C/C++ instrumentation PGO uses a disjoint
training inventory. All commands, failed samples and native artifacts remain in
the new output directory. This measures two kernels, not a language ranking.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import shutil
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta.hia_program import verify_program
from hepta.hia_program_llvm import compile_program_llvm, emit_program_llvm
from hepta.hia_program_source import lower_source

FIXTURES = ROOT / "experiments/hia_optimizer_eval"
KERNELS = ("full_lifecycle", "packet_xor")
BACKENDS = ("hia", "rust_o3_lto", "c_o3_lto", "cpp_o3_lto", "c_pgo_lto", "cpp_pgo_lto")
NEXT_PROTOCOL_PATH = "experiments/hia_optimizer_eval/next_20261028/PROTOCOL.json"
PROTOCOL = {
    "id": "hepta.hia.optimizer-bench.v1", "scope": "Linux x86-64; two byte-owner kernels; finite successful-allocation inputs",
    "groups": 7, "batches": 31, "calls_per_batch": 128, "warmup_calls": 32,
    "training_sizes": [16, 64, 256, 1024, 4096, 16384, 65536],
    "training_seeds": [1, 13, 37, 97],
    "holdout_sizes": [0, 1, 63, 255, 1021, 4093, 16381, 65519],
    "holdout_seeds": [7, 19, 83, 251, 2147483649, 4294967293, 4294967295],
    "ordering": "rotate kernels by group; rotate backends by group plus original kernel index; reverse odd groups",
    "sampling_randomization": "none; fully deterministic registered order and explicit input seeds",
    "minimum_sample_ns": 1_000_000, "maximum_sample_ns": 120_000_000_000,
    "maximum_relative_mad": 0.25, "maximum_paired_geomean_ratio_upper95": 1.05,
    "maximum_empirical_p95_batch_ratio": 1.10, "maximum_peak_rss_ratio": 1.25,
    "paired_log_t_upper95_critical_df6": 1.9431802805153022,
    "tail_scope": "empirical nearest-rank batch quantiles; not service p99 or population-tail confidence bounds",
    "rss_scope": "Linux /proc/self/status VmHWM of post-exec driver; ru_maxrss retained separately because launcher high-water marks can survive exec",
    "inference_scope": "seven paired groups; log-ratio t bound assumes independent approximately normal group log ratios",
    "failure_policy": "retain every scheduled attempt; failed or missing samples fail quality; no trimming or reruns",
    "search": "none; fixed compiler configurations, zero optimizer search calls",
    "pgo": "Clang instrumentation; both kernels on training inventory only, then llvm-profdata merge and profile-use",
    "allocation_scope": "same source-level allocation/lifetime algorithms; each compiler may optimize according to its semantics",
    "limitations": ["two synthetic buffer workloads, not real-world application coverage", "single shared Linux x86-64 host",
                    "C/C++ internals are not established memory-safe", "finite correctness checks are not semantic equivalence proofs",
                    "PGO holdout is disclosed and only excludes profile training; it is not an unseen benchmark population"],
}


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def sha(value):
    return hashlib.sha256(value).hexdigest()


def identity(path):
    path = Path(path).resolve(strict=True)
    with path.open("rb") as stream:
        return {"path": str(path), "bytes": path.stat().st_size,
                "sha256": hashlib.file_digest(stream, "sha256").hexdigest()}


def source_bindings(extra_paths=()):
    paths = [Path(__file__), *FIXTURES.glob("kernels.*"), FIXTURES / "driver.c"]
    paths.extend((ROOT / "hepta").rglob("*.py"))
    paths.extend(ROOT / name for name in extra_paths)
    return {str(path.relative_to(ROOT)): identity(path)["sha256"] for path in sorted(paths)}


def write_new(path, value):
    with Path(path).open("xb") as stream:
        stream.write(wire(value) + b"\n")


def execute(argv, *, timeout=120, env=None):
    start = time.perf_counter_ns()
    record = {"argv": [str(x) for x in argv], "status": "started"}
    try:
        process = subprocess.run(record["argv"], capture_output=True, text=True, timeout=timeout, env=env)
        record.update(returncode=process.returncode, stdout=process.stdout, stderr=process.stderr,
                      status="completed" if process.returncode == 0 else "failed")
    except subprocess.TimeoutExpired as error:
        def text(value):
            return value.decode(errors="replace") if isinstance(value, bytes) else value or ""
        record.update(status="timeout", returncode=None, stdout=text(error.stdout), stderr=text(error.stderr))
    except OSError as error:
        record.update(status="launch_failed", returncode=None, stdout="", stderr=str(error))
    record["wall_ns"] = time.perf_counter_ns() - start
    return record


def require(condition, message):
    if not condition:
        raise ValueError("E_OPTIMIZER_BENCH: " + message)


def successful(record):
    require(record["status"] == "completed" and record["returncode"] == 0,
            "native command failed: " + record["status"])
    return record["stdout"]


def sample_order(protocol=PROTOCOL, backends=BACKENDS):
    backends = tuple(backends)
    result = []
    for group in range(protocol["groups"]):
        rotation = group % len(KERNELS)
        for kernel in KERNELS[rotation:] + KERNELS[:rotation]:
            offset = (group + KERNELS.index(kernel)) % len(backends)
            names = backends[offset:] + backends[:offset]
            if group % 2:
                names = names[::-1]
            result.extend((group, kernel, name) for name in names)
    return result


def oracle(kernel, size, seed):
    """Independent modular arithmetic oracle, not interpreted benchmark code."""
    require(kernel in KERNELS and type(size) is int and 0 <= size <= 65536 and
            type(seed) is int and 0 <= seed < 2**32, "oracle input outside frozen domain")
    def byte(index):
        if kernel == "full_lifecycle":
            return (index + seed) % 256
        return ((13 * index + seed) % 256) ^ ((index + (seed ^ 90)) % 256)
    period = [byte(i) for i in range(256)]
    return (size // 256) * sum(period) + sum(period[:size % 256])


def timed_checksum(kernel, split="holdout", protocol=PROTOCOL):
    require(split in {"train", "holdout"}, "unknown workload split")
    prefix = "training" if split == "train" else "holdout"
    sizes, seeds = protocol[prefix + "_sizes"], protocol[prefix + "_seeds"]
    value = 1469598103934665603
    cache = {(n, seed): oracle(kernel, n, seed) for n in sizes for seed in seeds}
    for index in range(protocol["batches"] * protocol["calls_per_batch"]):
        result = cache[sizes[index % len(sizes)], seeds[(index * 5 + 1) % len(seeds)]]
        value = ((value ^ result) * 1099511628211) % 2**64
    return value


def workload_header(protocol=PROTOCOL):
    lines = []
    for label, prefix in (("TRAIN", "training"), ("HOLDOUT", "holdout")):
        for name, typ in (("sizes", "size_t"), ("seeds", "uint32_t")):
            values = protocol[prefix + "_" + name]
            lines.append("static const " + typ + " " + label + "_" + name.upper() + "[] = {" +
                         ",".join(str(v) + "U" for v in values) + "};")
            lines.append("#define " + label + "_" + name[:-1].upper() + "_COUNT " + str(len(values)))
    for label, key in (("BATCHES", "batches"), ("CALLS_PER_BATCH", "calls_per_batch"), ("WARMUP_CALLS", "warmup_calls")):
        lines.append("#define " + label + " " + str(protocol[key]))
    return "\n".join(lines) + "\n"


def quantile(values, p):
    require(values and 0 < p <= 1, "quantile domain")
    return sorted(values)[max(0, math.ceil(p * len(values)) - 1)]


def evaluate_samples(rows, protocol=PROTOCOL, backends=BACKENDS, candidate="hia"):
    expected = sample_order(protocol, backends)
    quality = []
    if len(rows) != len(expected):
        quality.append("sample_inventory_incomplete")
    valid = {}
    for index, (group, kernel, backend) in enumerate(expected):
        if index >= len(rows):
            continue
        row = rows[index]
        if (row.get("group"), row.get("kernel"), row.get("backend"), row.get("sample_index")) != (group, kernel, backend, index):
            quality.append("sample_identity_" + str(index)); continue
        if row.get("status") != "measured":
            quality.append("sample_failed_" + str(index)); continue
        integers = ("elapsed_ns", "process_cpu_ns", "process_peak_rss_kib", "outer_wall_ns")
        if any(type(row.get(k)) is not int or row[k] <= 0 for k in integers):
            quality.append("sample_metrics_" + str(index)); continue
        batches = row.get("batch_ns")
        if (type(batches) is not list or len(batches) != protocol["batches"] or
                any(type(v) is not int or v <= 0 for v in batches) or sum(batches) > row["elapsed_ns"]):
            quality.append("batch_metrics_" + str(index)); continue
        if row.get("checksum") != timed_checksum(kernel, protocol=protocol):
            quality.append("checksum_" + str(index)); continue
        if not protocol["minimum_sample_ns"] <= row["elapsed_ns"] <= protocol["maximum_sample_ns"]:
            quality.append("sample_duration_" + str(index))
        valid[group, kernel, backend] = row
    summary = {}
    for kernel in KERNELS:
        summary[kernel] = {}
        for backend in backends:
            samples = [valid[g, kernel, backend] for g in range(protocol["groups"]) if (g, kernel, backend) in valid]
            if len(samples) != protocol["groups"]:
                continue
            values = [row["elapsed_ns"] for row in samples]
            median = statistics.median(values)
            relative_mad = statistics.median(abs(v - median) for v in values) / median
            if relative_mad > protocol["maximum_relative_mad"]:
                quality.append("unstable_" + kernel + "_" + backend)
            batches = [value for row in samples for value in row["batch_ns"]]
            summary[kernel][backend] = {
                "samples": len(samples), "median_elapsed_ns": median, "relative_mad": relative_mad,
                "median_outer_wall_ns": statistics.median(row["outer_wall_ns"] for row in samples),
                "batch_count": len(batches), "batch_p50_ns": quantile(batches, .50),
                "batch_p95_ns": quantile(batches, .95), "batch_p99_ns": quantile(batches, .99),
                "maximum_process_peak_rss_kib": max(row["process_peak_rss_kib"] for row in samples),
                "median_cpu_to_wall_ratio": statistics.median(row["process_cpu_ns"] / row["elapsed_ns"] for row in samples),
            }
    comparisons = []
    for kernel in KERNELS:
        for baseline in (name for name in backends if name != candidate):
            if candidate not in summary[kernel] or baseline not in summary[kernel]:
                continue
            log_ratios = [math.log(valid[g, kernel, candidate]["elapsed_ns"] / valid[g, kernel, baseline]["elapsed_ns"])
                          for g in range(protocol["groups"])]
            mean = statistics.mean(log_ratios)
            upper = math.exp(mean + protocol["paired_log_t_upper95_critical_df6"] * statistics.stdev(log_ratios) / math.sqrt(len(log_ratios)))
            hia, other = summary[kernel][candidate], summary[kernel][baseline]
            p95 = hia["batch_p95_ns"] / other["batch_p95_ns"]
            rss = hia["maximum_process_peak_rss_kib"] / other["maximum_process_peak_rss_kib"]
            comparisons.append({"kernel": kernel, "baseline": baseline, "paired_time_geomean_ratio": math.exp(mean),
                                "paired_time_ratio_upper95": upper, "empirical_p95_batch_ratio": p95,
                                "empirical_p99_batch_ratio": hia["batch_p99_ns"] / other["batch_p99_ns"],
                                "peak_rss_ratio": rss, "noninferiority_thresholds_passed":
                                upper <= protocol["maximum_paired_geomean_ratio_upper95"] and
                                p95 <= protocol["maximum_empirical_p95_batch_ratio"] and rss <= protocol["maximum_peak_rss_ratio"]})
    complete_comparisons = len(comparisons) == len(KERNELS) * (len(backends) - 1)
    passed = not quality and complete_comparisons and all(c["noninferiority_thresholds_passed"] for c in comparisons)
    return {"quality_passed": not quality, "quality_failures": quality, "summary": summary, "comparisons": comparisons,
            "noninferiority_passed": passed, "samples_excluded": 0, "thresholds_adjusted": False}


CORRECTNESS_CHILD = r'''
import ctypes, json, sys
library = ctypes.CDLL(sys.argv[1])
for case in json.loads(sys.argv[2]):
    fn = getattr(library, case["kernel"])
    fn.argtypes, fn.restype = [ctypes.c_size_t, ctypes.c_uint32], ctypes.c_uint64
    print(json.dumps({**case, "actual": int(fn(case["size"], case["seed"]))}), flush=True)
'''


def correctness_cases(protocol=PROTOCOL):
    sizes = sorted({0, 1, 2, 7, 255, 256, 257, *protocol["holdout_sizes"]})
    seeds = (0, 1, 255, 256, 2147483648, 4294967295)
    return [{"kernel": k, "size": n, "seed": s, "expected": oracle(k, n, s)} for k in KERNELS for n in sizes for s in seeds]


def next_protocol():
    profile = json.loads((ROOT / NEXT_PROTOCOL_PATH).read_bytes())["benchmark"]
    require(profile["id"] == "hepta.hia.optimizer-bench.next-20261028.v1", "unknown next protocol")
    for key in ("groups", "batches", "calls_per_batch", "warmup_calls", "minimum_sample_ns", "maximum_sample_ns",
                "maximum_relative_mad", "maximum_paired_geomean_ratio_upper95", "maximum_empirical_p95_batch_ratio",
                "maximum_peak_rss_ratio", "paired_log_t_upper95_critical_df6"):
        require(profile[key] == PROTOCOL[key], "next protocol may not relax the existing sampling or gates")
    require(profile["backends"] == ["hia_original", "hia_verified", *BACKENDS[1:]], "strong baseline inventory changed")
    return {**PROTOCOL, **profile,
            "search": "one frozen deterministic guarded-reduction proposal; actual proposal/check/build costs retained"}


def run(*, output_dir, clang="/usr/bin/clang-20", clangxx="/usr/bin/clang++-20",
        rustc="/tmp/hepta-ai-rust-1.90.0/bin/rustc", profdata="/usr/bin/llvm-profdata-20",
        linker="/usr/bin/ld.lld-20", candidate_core=None, profile_runtime=None, guarded_next=False):
    require(not (guarded_next and candidate_core), "next guarded experiment must start from the frozen original source")
    protocol = next_protocol() if guarded_next else PROTOCOL
    backends = tuple(protocol["backends"]) if guarded_next else BACKENDS
    measured_candidate = "hia_verified" if guarded_next else "hia"
    original_backend = "hia_original" if guarded_next else "hia"
    extra_paths = (NEXT_PROTOCOL_PATH,) if guarded_next else ()
    bindings = lambda: source_bindings(extra_paths)
    order = sample_order(protocol, backends)
    out = Path(output_dir).absolute(); out.mkdir(parents=True, exist_ok=False)
    report = {"schema": protocol["id"], "status": "running", "ok": False, "protocol": protocol,
              "protocol_sha256": sha(wire(protocol)), "source_bindings": bindings(),
              "kernels": list(KERNELS), "backends": list(backends), "candidate_backend": measured_candidate,
              "scheduled_samples": [{"sample_index": i, "group": g, "kernel": k, "backend": b}
                                    for i, (g, k, b) in enumerate(order)],
              "commands": [], "builds": {}, "training": [], "correctness": {}, "raw_samples": [],
              "search_cost": {"search_performed": False, "search_calls": 0, "wall_ns": 0},
              "claims": {"universal_rust_superiority": False, "resource_soundness_proved": False,
                         "global_optimality_proved": False, "physical_device_qualified": False}}
    affinity = None
    def command(argv, phase, **kwargs):
        result = execute(argv, **kwargs); result["phase"] = phase
        report["commands"].append(result)
        return result
    try:
        require(platform.system() == "Linux" and platform.machine() == "x86_64", "Linux x86-64 required")
        require(not set(protocol["training_sizes"]) & set(protocol["holdout_sizes"]) and
                not set(protocol["training_seeds"]) & set(protocol["holdout_seeds"]), "PGO splits overlap")
        report["git_commit"] = successful(command(["git", "-C", ROOT, "rev-parse", "HEAD"], "identity")).strip()
        report["git_status_at_start"] = successful(command(["git", "-C", ROOT, "status", "--porcelain"], "identity"))
        report["source_was_committed"] = not bool(report["git_status_at_start"])
        tool_paths = {"clang": clang, "clangxx": clangxx, "rustc": rustc, "profdata": profdata, "linker": linker}
        report["tools"] = {name: {**identity(path), "version": command([path, "--version"], "identity")} for name, path in tool_paths.items()}
        report["profile_runtime"] = identity(profile_runtime) if profile_runtime else None
        affinity = os.sched_getaffinity(0); os.sched_setaffinity(0, {min(affinity)})
        report["environment"] = {"platform": platform.platform(), "selected_cpu": min(affinity),
                                 "allowed_cpus": sorted(affinity), "exclusive_cpu": False, "load_before": os.getloadavg()}
        for name, expected_hash in report["source_bindings"].items():
            payload = (ROOT / name).read_bytes()
            require(sha(payload) == expected_hash, "source changed while freezing exact experiment inputs")
            destination = out / "source_snapshot" / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(payload)
        write_new(out / "plan.json", {k: report[k] for k in ("schema", "protocol", "protocol_sha256", "kernels", "backends", "scheduled_samples", "source_bindings", "tools", "profile_runtime", "git_commit", "git_status_at_start", "environment")})
        for name in ("kernels.hepta", "kernels.c", "kernels.cpp", "kernels.rs", "driver.c"):
            shutil.copyfile(FIXTURES / name, out / name)
        (out / "workload.h").write_text(workload_header(protocol))
        successful(command([clang, "-std=c11", "-O3", out / "driver.c", "-ldl", "-o", out / "driver"], "driver_build"))
        libraries = {name: out / (name + ".so") for name in backends}
        start = time.perf_counter_ns()
        core = (verify_program(Path(candidate_core).read_bytes()) if candidate_core else
                lower_source((out / "kernels.hepta").read_text(), path=str(out / "kernels.hepta"), module="optimizer_bench"))
        report["front_end_wall_ns"] = time.perf_counter_ns() - start
        start = time.perf_counter_ns(); core = verify_program(core)
        report["explicit_core_verification_wall_ns"] = time.perf_counter_ns() - start
        (out / "program.hia").write_bytes(core.canonical_bytes)
        report["core_sha256"] = core.sha256
        report["candidate_core_supplied"] = candidate_core is not None
        start = time.perf_counter_ns(); ir = emit_program_llvm(core)
        report["verified_llvm_emission_wall_ns"] = time.perf_counter_ns() - start
        (out / "program.ll").write_text(ir.text)
        start = time.perf_counter_ns()
        try:
            receipt = compile_program_llvm(ir, program=core, output=libraries[original_backend], clang=clang)
            report["builds"][original_backend] = {"status": "compiled", "receipt": receipt}
        except Exception as error:
            report["builds"][original_backend] = {"status": "failed", "error": str(error)}
        report["builds"][original_backend]["wall_ns"] = time.perf_counter_ns() - start
        if guarded_next:
            start = time.perf_counter_ns()
            try:
                from hepta.hia_guarded_optimization import (propose_guarded_reduction, verify_guarded_optimization,
                                                            guarded_program, build_guarded_native)
                proposal_started = time.perf_counter_ns()
                proposal = propose_guarded_reduction(core)
                report["search_cost"] = {"search_performed": True, "search_calls": 1,
                    "mode": "one registered deterministic proposal, no learned search or holdout-based selection",
                    "wall_ns": time.perf_counter_ns() - proposal_started, "model_calls": 0}
                write_new(out / "guarded-proposal.json", proposal)
                verification_started = time.perf_counter_ns()
                proof = verify_guarded_optimization(core, proposal)
                report["guarded_verification_wall_ns"] = time.perf_counter_ns() - verification_started
                write_new(out / "guarded-verification.json", proof)
                require(proof["status"] == "verified", "guarded candidate has no independent proof")
                guarded = verify_program(guarded_program(core, proposal))
                (out / "guarded-program.hia").write_bytes(guarded.canonical_bytes)
                (out / "guarded-program.ll").write_text(emit_program_llvm(guarded).text)
                receipt = build_guarded_native(core, proposal, libraries["hia_verified"], clang=clang)
                require(receipt["verification"]["status"] == "verified", "native guarded build lacks verified receipt")
                require(identity(libraries["hia_verified"])["sha256"] == receipt["native"]["artifact_sha256"],
                        "guarded native artifact differs from its independent receipt")
                write_new(out / "guarded-native.json", receipt)
                report["builds"]["hia_verified"] = {"status": "compiled", "receipt": receipt}
            except Exception as error:
                report["builds"]["hia_verified"] = {"status": "failed", "error": str(error)}
            report["builds"]["hia_verified"]["wall_ns"] = time.perf_counter_ns() - start
        flags = ["-O3", "-flto=full", "-fuse-ld=" + linker, "-march=x86-64", "-mtune=generic", "-fPIC", "-shared"]
        for backend, compiler, source, standard in (("c_o3_lto", clang, "kernels.c", "c11"),
                                                     ("cpp_o3_lto", clangxx, "kernels.cpp", "c++17")):
            result = command([compiler, "-std=" + standard, *flags, out / source, "-o", libraries[backend]], "baseline_build")
            report["builds"][backend] = {"status": "compiled" if result["status"] == "completed" else "failed", "wall_ns": result["wall_ns"], "command_index": len(report["commands"]) - 1}
        result = command([rustc, "--edition=2021", "--crate-type=cdylib", "-Copt-level=3", "-Clto=fat", "-Ccodegen-units=1",
                          "-Cpanic=abort", "-Ctarget-cpu=x86-64", out / "kernels.rs", "-o", libraries["rust_o3_lto"]], "baseline_build")
        report["builds"]["rust_o3_lto"] = {"status": "compiled" if result["status"] == "completed" else "failed", "wall_ns": result["wall_ns"], "command_index": len(report["commands"]) - 1}
        for label, compiler, source, standard in (("c", clang, "kernels.c", "c11"), ("cpp", clangxx, "kernels.cpp", "c++17")):
            start = time.perf_counter_ns()
            directory = out / (label + "_profiles"); directory.mkdir()
            instrumented = out / (label + "_instrumented.so")
            backend = label + "_pgo_lto"
            try:
                if profile_runtime:
                    # Some minimal Clang installations omit compiler-rt. An
                    # explicitly identified official archive can be linked
                    # after the ordinary instrumented-object compilation.
                    obj = out / (label + "_instrumented.o")
                    compile_flags = [flag for flag in flags if flag != "-shared" and not flag.startswith("-fuse-ld=")]
                    successful(command([compiler, "-std=" + standard, *compile_flags, "-fprofile-instr-generate", "-c", out / source, "-o", obj], "pgo_instrumentation_build"))
                    successful(command([compiler, *flags, obj, "-Wl,-u,__llvm_profile_runtime", profile_runtime, "-o", instrumented], "pgo_instrumentation_link"))
                else:
                    successful(command([compiler, "-std=" + standard, *flags, "-fprofile-instr-generate", out / source, "-o", instrumented], "pgo_instrumentation_build"))
                for kernel in KERNELS:
                    environment = dict(os.environ, LLVM_PROFILE_FILE=str(directory / (kernel + "-%p.profraw")))
                    result = command([out / "driver", instrumented, kernel, "train"], "pgo_training", env=environment)
                    item = {"backend": backend, "kernel": kernel, "split": "train", "command_index": len(report["commands"]) - 1}
                    report["training"].append(item)
                    measured = json.loads(successful(result)); item["measurement"] = measured
                    require(measured["checksum"] == timed_checksum(kernel, "train", protocol), "PGO training checksum")
                profiles = sorted(directory.glob("*.profraw"))
                require(len(profiles) == len(KERNELS) and all(p.stat().st_size > 0 for p in profiles), "actual training profiles absent")
                merged = directory / "training.profdata"
                successful(command([profdata, "merge", "-o", merged, *profiles], "pgo_profile_merge"))
                result = command([compiler, "-std=" + standard, *flags, "-fprofile-instr-use=" + str(merged),
                                  "-Werror=profile-instr-out-of-date", "-Werror=profile-instr-unprofiled", out / source, "-o", libraries[backend]], "pgo_use_build")
                successful(result)
                report["builds"][backend] = {"status": "compiled", "training_profile": identity(merged), "profile_inputs": [identity(p) for p in profiles],
                                             "native_compile_wall_ns": result["wall_ns"]}
            except Exception as error:
                report["builds"][backend] = {"status": "failed", "error": str(error)}
            report["builds"][backend]["wall_ns"] = time.perf_counter_ns() - start
        cases = correctness_cases(protocol)
        for backend in backends:
            start = time.perf_counter_ns()
            if report["builds"][backend]["status"] != "compiled":
                report["correctness"][backend] = {"ok": False, "status": "not_built"}; continue
            result = command([sys.executable, "-c", CORRECTNESS_CHILD, libraries[backend], json.dumps(cases)], "finite_correctness")
            try:
                observations = [json.loads(line) for line in successful(result).splitlines()]
                ok = observations == [{**case, "actual": case["expected"]} for case in cases]
                report["correctness"][backend] = {"ok": ok, "observations": observations}
            except Exception as error:
                report["correctness"][backend] = {"ok": False, "error": str(error)}
            report["correctness"][backend]["wall_ns"] = time.perf_counter_ns() - start
        report["artifacts_before"] = {name: identity(path) for name, path in libraries.items()
                                      if report["builds"][name]["status"] == "compiled" and path.exists()}
        report["driver_identity"] = identity(out / "driver")
        for index, (group, kernel, backend) in enumerate(order):
            row = {"group": group, "kernel": kernel, "backend": backend, "sample_index": index, "status": "not_built"}
            report["raw_samples"].append(row)
            if backend in report["artifacts_before"]:
                result = command([out / "driver", libraries[backend], kernel, "holdout"], "measurement")
                row.update(execution=result, outer_wall_ns=result["wall_ns"], library_sha256=report["artifacts_before"][backend]["sha256"])
                try:
                    row.update(json.loads(successful(result))); row["status"] = "measured"
                except Exception as error:
                    row.update(status="failed", error=str(error))
            write_new(out / ("sample-" + str(index).zfill(3) + ".json"), row)
            print(json.dumps({"sample": index + 1, "total": len(order), "backend": backend, "kernel": kernel, "status": row["status"]}), flush=True)
        report["evaluation"] = evaluate_samples(report["raw_samples"], protocol, backends, measured_candidate)
        report["source_unchanged"] = bindings() == report["source_bindings"]
        report["artifacts_unchanged"] = all(identity(libraries[name]) == item for name, item in report["artifacts_before"].items()) and identity(out / "driver") == report["driver_identity"]
        report["tools_unchanged"] = all(identity(path)["sha256"] == report["tools"][name]["sha256"] for name, path in tool_paths.items())
        if profile_runtime:
            report["tools_unchanged"] = report["tools_unchanged"] and identity(profile_runtime) == report["profile_runtime"]
        correctness_ok = all(row["ok"] for row in report["correctness"].values()) and len(report["correctness"]) == len(backends)
        stable = report["source_unchanged"] and report["artifacts_unchanged"] and report["tools_unchanged"]
        report["quality_passed"] = correctness_ok and stable and report["evaluation"]["quality_passed"]
        report["ok"] = report["quality_passed"] and report["evaluation"]["noninferiority_passed"]
        report["status"] = ("qualified_finite_host" if report["ok"] else "completed_noninferiority_failed" if report["quality_passed"] else "completed_quality_failed")
        report["costs"] = {"all_command_wall_ns": sum(c["wall_ns"] for c in report["commands"]),
                           "explicit_core_verification_wall_ns": report["explicit_core_verification_wall_ns"],
                           "verification_in_native_build_included": True,
                           "finite_correctness_wall_ns": sum(c.get("wall_ns", 0) for c in report["correctness"].values()),
                           "optimizer_search_wall_ns": report["search_cost"]["wall_ns"],
                           "guarded_proposal_verification_build_charged_to_candidate": guarded_next,
                           "pgo_training_and_compile_charged_to_pgo_builds": True}
    except Exception as error:
        report.update(status="blocked", diagnostic={"type": type(error).__name__, "message": str(error)})
    finally:
        if affinity is not None:
            os.sched_setaffinity(0, affinity)
        if "environment" in report:
            report["environment"]["load_after"] = os.getloadavg()
        write_new(out / "report.json", report)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--clang", default="/usr/bin/clang-20")
    parser.add_argument("--clangxx", default="/usr/bin/clang++-20")
    parser.add_argument("--rustc", default="/tmp/hepta-ai-rust-1.90.0/bin/rustc")
    parser.add_argument("--profdata", default="/usr/bin/llvm-profdata-20")
    parser.add_argument("--linker", default="/usr/bin/ld.lld-20")
    parser.add_argument("--profile-runtime", type=Path, help="optional explicit Clang compiler-rt profiling archive; bytes are hash-bound")
    parser.add_argument("--candidate-core", type=Path, help="optional independently verified candidate; finite oracle remains the frozen baseline")
    parser.add_argument("--guarded-next", action="store_true", help="registered 2026-10-28 guarded-candidate vs original HIA and five strong baselines; unchanged acceptance thresholds")
    result = run(**vars(parser.parse_args(argv)))
    print(json.dumps({key: result.get(key) for key in ("status", "ok", "quality_passed", "diagnostic")}))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
