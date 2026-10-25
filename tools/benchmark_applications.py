"""Measure two owned-buffer applications through a common native C driver.

Three compiled implementations: one Hepta source through the independent Rust
and C backends, and separately handwritten Rust. The native oracle, allocator
instrumentation, request schedule and timer are shared, never the app bodies.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta.backend import compile_rust, find_rustc, toolchain_info
from hepta.c_backend import compile_c
from hepta.pipeline import analyze, compiler_hash

IMPLEMENTATIONS = ("rust", "hepta_rust", "hepta_c")
APPLICATIONS = ("packet", "transform")
UNITS = (1, 32, 1024)
CORRECTNESS_UNITS = (0, 1, 2, 17, 4097)
SEED = 20261024
MASK = (1 << 64) - 1
INITIAL_HASH = 14695981039346656037
RESULT_FIELDS = ("status", "reserved", "bytes", "records", "checksum")
ALLOCATION_FIELDS = ("attempts", "allocations", "frees", "failures", "malloc_calls", "calloc_calls",
                     "realloc_calls", "attempted_bytes", "allocated_bytes", "freed_bytes", "peak_live_bytes", "live_bytes")
SUMMARY_FIELDS = ("summary", "requests", "warmups", "warmup_checksum", "timer_pair_min_ns",
                  "rss_start_kib", "rss_peak_kib", "rss_vm_hwm_start_kib", "rss_vm_hwm_peak_kib", "abi_size")
SOURCE_FILES = [f"benchmarks/{name}" for name in (
    "applications.hepta", "applications.rs", "applications.h", "applications_allocator.rs",
    "applications_driver.c", "applications_meter.c", "applications_wrong.c")]
SOURCE_FILES.append("tools/benchmark_applications.py")
CLAIMS = {"universal_performance_superiority": False, "multiple_machines_measured": False,
          "whole_process_memory_bounded": False, "uninstrumented_production_latency_measured": False,
          "asynchronous_service_tail_latency_measured": False, "model_productivity_measured": False}
WRAP_FLAGS = ["-Wl,--wrap=" + name for name in ("malloc", "calloc", "realloc", "free")]
TIMING_CONTRACT = {
    "includes": ["common_C_ABI_call", "input_generation", "application_allocation", "validation_and_processing", "cleanup", "allocation_instrumentation"],
    "excludes": ["native_build", "process_startup", "warmup", "independent_oracle", "transcript_output", "RSS_query"],
    "quantile": "nearest_rank_on_all_retained_request_samples",
    "throughput": "request_count_divided_by_sum_of_timed_service_intervals_not_wall_clock_service_RPS",
    "allocation_bytes": "requested_successful_allocation_sizes_not_allocator_overhead_or_RSS",
    "rss": "Linux_getrusage_ru_maxrss_and_current_address_space_proc_VmHWM_in_KiB_including_startup_oracle_and_driver",
    "comparison": "same_Hepta_source_two_backends_separately_written_Rust_same_algorithms_inputs_and_common_driver",
    "optimization": "Rust_O3_overflow_checks_yes_panic_abort_C_default_O3_no_LTO_no_fast_math",
}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def identities() -> dict:
    return {name: digest((ROOT / name).read_bytes()) for name in SOURCE_FILES}


def _step(state):
    return (state * 6364136223846793005 + 1442695040888963407) & MASK


def _feed(hash_, byte):
    return ((hash_ ^ byte) * 1099511628211) & MASK


def allocation_profile(application, units, request, fault=0):
    sizes = [] if not 0 < units <= 4096 else (
        [units * 64, 256] if application == "packet" else
        [units * 256 + 4] if request % 8 == 1 else [units * 256 + 4, 256, units * 256])
    failed = int(0 < fault <= len(sizes))
    attempted = sizes[:fault] if failed else sizes
    allocated = attempted[:-1] if failed else attempted
    return {"attempts": len(attempted), "allocations": len(allocated), "frees": len(allocated), "failures": failed,
            "realloc_calls": 0, "attempted_bytes": sum(attempted), "allocated_bytes": sum(allocated),
            "freed_bytes": sum(allocated), "peak_live_bytes": sum(allocated), "live_bytes": 0}


def result_shape(application, units, request, fault=0):
    result = {"status": 0, "reserved": 0, "bytes": 0, "records": 0}
    if not 0 < units <= 4096:
        result.update(status=1, checksum=0)
    elif allocation_profile(application, units, request, fault)["failures"]:
        result.update(status=10, checksum=0)
    elif application == "packet":
        if request % 8 in (1, 2, 3):
            result.update(status={1: 2, 2: 3, 3: 4}[request % 8], bytes=(units // 2) * 64, records=units // 2)
        else:
            result.update(bytes=units * 64, records=units)
    elif request % 8 == 1:
        result.update(status=2, checksum=0)
    else:
        result.update(bytes=units * 256, records=units)
    return result


def reference_result(application, units, request, fault=0):
    """Independent Python oracle for every correctness and failure input."""
    result = result_shape(application, units, request, fault)
    if "checksum" in result:
        return result
    if application == "packet":
        wire = bytearray(units * 64)
        state = request ^ 11400714819323198485
        for frame in range(units):
            offset = frame * 64
            state = _step(state)
            wire[offset:offset + 3] = bytes((60, 0, state & 7))
            for index in range(4, 64):
                state = _step(state)
                wire[offset + index] = (state >> 32) & 255
            wire[offset + 3] = sum(wire[offset + 4:offset + 64]) & 255
        middle = (units // 2) * 64
        if request % 8 == 1:
            wire[middle] = 61
        elif request % 8 == 2:
            wire[middle + 4] ^= 1
        elif request % 8 == 3:
            wire[middle + 2] = 8
        histogram = [0] * 256
        offset = records = 0
        hash_ = INITIAL_HASH
        status = 0
        while offset < len(wire):
            length = int.from_bytes(wire[offset:offset + 2], "little")
            if length != 60 or length > len(wire) - offset - 4:
                status = 2
                break
            kind = wire[offset + 2]
            if kind >= 8:
                status = 4
                break
            payload = wire[offset + 4:offset + 4 + length]
            for byte in payload:
                hash_ = _feed(hash_, byte)
            if sum(payload) & 255 != wire[offset + 3]:
                status = 3
                break
            histogram[kind] = (histogram[kind] + 1) & 255
            offset += 4 + length
            records += 1
        if status == 0:
            for byte in histogram:
                hash_ = _feed(hash_, byte)
        return {"status": status, "reserved": 0, "bytes": offset, "records": records, "checksum": hash_}
    state = request ^ 15111065706836454659
    previous = request & 255
    output = bytearray(units * 256)
    for chunk in range(units):
        transformed = []
        for _ in range(256):
            state = _step(state)
            byte = (state >> 32) & 255
            previous = (((byte << 3) | (byte >> 5)) & 255) ^ previous
            transformed.append(previous)
        for index, byte in enumerate(reversed(transformed)):
            output[chunk * 256 + index] = byte ^ index
    hash_ = INITIAL_HASH
    for byte in output:
        hash_ = _feed(hash_, byte)
    return dict(result, checksum=hash_)


def native_transcript(rows, summary):
    lines = []
    for row in rows:
        ordered = {key: row[key] for key in ("request_id", "fault_nth", "elapsed_ns", "oracle_checked")}
        ordered["result"] = {key: row["result"][key] for key in RESULT_FIELDS}
        ordered["allocation"] = {key: row["allocation"][key] for key in ALLOCATION_FIELDS}
        lines.append(json.dumps(ordered, separators=(",", ":")))
    lines.append(json.dumps({key: summary[key] for key in SUMMARY_FIELDS}, separators=(",", ":")))
    return "\n".join(lines) + "\n"


class Commands:
    def __init__(self):
        self.records = []

    def run(self, args, *, expected=0, timeout=90):
        args = list(map(str, args))
        start = time.monotonic_ns()
        try:
            proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired as error:
            stdout = error.stdout or b""
            stderr = error.stderr or b""
            if isinstance(stdout, str):
                stdout = stdout.encode()
            if isinstance(stderr, str):
                stderr = stderr.encode()
            self.records.append({"argv": args, "status": "timeout", "returncode": None,
                                 "elapsed_ns": time.monotonic_ns() - start, "timeout_seconds": timeout,
                                 "stdout_sha256": digest(stdout), "stderr_sha256": digest(stderr),
                                 "partial_stdout_base64": base64.b64encode(stdout).decode(),
                                 "partial_stderr_base64": base64.b64encode(stderr).decode()})
            raise RuntimeError(f"command timed out after {timeout}s; partial output retained: {args!r}") from error
        elapsed = time.monotonic_ns() - start
        self.records.append({"argv": args, "status": "completed", "returncode": proc.returncode, "elapsed_ns": elapsed,
                             "stdout_sha256": digest(proc.stdout.encode()), "stderr_sha256": digest(proc.stderr.encode()),
                             **({"stderr": proc.stderr, "stdout": proc.stdout} if proc.returncode != expected else {})})
        if proc.returncode != expected:
            raise RuntimeError(f"command failed ({proc.returncode}): {args!r}: {proc.stderr}")
        return proc, elapsed


def _object(commands, cc, source, output):
    flags = ["-std=c11", "-O3", "-Wall", "-Wextra", "-Werror"]
    proc, _ = commands.run([cc, *flags, "-c", source, "-o", output])
    if not output.is_file() or output.stat().st_size == 0:
        raise RuntimeError("native C object is absent or empty")
    return {"source": str(source.relative_to(ROOT)), "source_sha256": digest(source.read_bytes()),
            "compiler_sha256": digest(Path(cc).read_bytes()),
            "flags": flags, "object_sha256": digest(output.read_bytes()), "object_bytes": output.stat().st_size,
            "returncode": proc.returncode}


def build_applications(commands, directory, rustc, cc):
    builds = {"common": {}}
    objects = {}
    for component in ("driver", "meter"):
        source = ROOT / f"benchmarks/applications_{component}.c"
        objects[component] = directory / f"{component}.o"
        builds["common"][component] = _object(commands, cc, source, objects[component])
    source = ROOT / "benchmarks/applications.hepta"
    allocator = (ROOT / "benchmarks/applications_allocator.rs").read_text()
    executables = {}
    for name in IMPLEMENTATIONS:
        build = {}
        if name == "rust":
            lowered = (ROOT / "benchmarks/applications.rs").read_text()
            build["source_sha256"] = digest(lowered.encode())
        else:
            analysis = analyze(source.read_text(), str(source), backend="c" if name == "hepta_c" else "rust",
                               rustc=rustc, native=True, crate_type="obj" if name == "hepta_c" else "staticlib")
            build["analysis"] = analysis.report
            if not analysis.report["ok"]:
                raise RuntimeError(json.dumps(analysis.report))
            lowered = analysis.c if name == "hepta_c" else analysis.rust
        library = directory / (name + (".o" if name == "hepta_c" else ".a"))
        if name == "hepta_c":
            native = compile_c(lowered, cc=cc, crate_type="obj", output=library)
        else:
            lowered += "\n" + allocator
            native = compile_rust(lowered, rustc=rustc, crate_type="staticlib", output=library)
        build["compiled_source_sha256"] = digest(lowered.encode())
        build["allocator_sha256"] = digest(allocator.encode()) if name != "hepta_c" else None
        build["native"] = native
        if not native["ok"] or not library.is_file() or not library.stat().st_size:
            raise RuntimeError(json.dumps(native))
        build["library_bytes"] = library.stat().st_size
        build["library_sha256"] = digest(library.read_bytes())
        executable = directory / name
        command = [cc, objects["driver"], objects["meter"], library, *WRAP_FLAGS, "-lpthread", "-ldl", "-lm", "-o", executable]
        proc, _ = commands.run(command)
        build["link"] = {"returncode": proc.returncode, "flags": WRAP_FLAGS + ["-lpthread", "-ldl", "-lm"],
                         "compiler_sha256": digest(Path(cc).read_bytes()),
                         "inputs": {"driver": builds["common"]["driver"]["object_sha256"],
                                    "meter": builds["common"]["meter"]["object_sha256"], "application": build["library_sha256"]},
                         "executable_sha256": digest(executable.read_bytes()), "executable_bytes": executable.stat().st_size}
        builds[name] = build
        executables[name] = executable
    wrong = directory / "wrong.o"
    builds["wrong"] = _object(commands, cc, ROOT / "benchmarks/applications_wrong.c", wrong)
    executable = directory / "wrong"
    proc, _ = commands.run([cc, objects["driver"], objects["meter"], wrong, *WRAP_FLAGS, "-o", executable])
    builds["wrong"].update(executable_sha256=digest(executable.read_bytes()), executable_bytes=executable.stat().st_size,
                           link_returncode=proc.returncode,
                           link_inputs={"driver": builds["common"]["driver"]["object_sha256"],
                                        "meter": builds["common"]["meter"]["object_sha256"],
                                        "application": builds["wrong"]["object_sha256"]})
    executables["wrong"] = executable
    return executables, builds


def run_batch(commands, executable, implementation, application, units, first, count, fault, warmups, prefix):
    proc, elapsed = commands.run([*prefix, executable, application, units, first, count, fault, warmups], timeout=60)
    try:
        records = [json.loads(line) for line in proc.stdout.splitlines()]
        if len(records) != count + 1 or not isinstance(records[-1], dict) or records[-1].get("summary") is not True or proc.stderr:
            raise RuntimeError("native request transcript is incomplete")
    except (ValueError, RuntimeError):
        commands.records[-1].update(stdout=proc.stdout, stderr=proc.stderr)
        raise
    return {"implementation": implementation, "application": application, "units": units,
            "first_request": first, "count": count, "fault_nth": fault, "warmups": warmups,
            "returncode": proc.returncode, "process_elapsed_ns": elapsed,
            "executable_sha256": digest(executable.read_bytes()), "stdout_sha256": digest(proc.stdout.encode()),
            "stderr_sha256": digest(proc.stderr.encode()), "samples": records[:-1], "process": records[-1]}


def _latencies(values):
    ordered = sorted(values)
    count = len(ordered)
    return {"requests": count, "min_ns": ordered[0], "p50_ns": ordered[math.ceil(count * .50) - 1],
            "p95_ns": ordered[math.ceil(count * .95) - 1], "p99_ns": ordered[math.ceil(count * .99) - 1],
            "max_ns": ordered[-1], "mean_ns": sum(ordered) / count,
            "service_requests_per_second": count * 1_000_000_000 / sum(ordered)}


def summarize(measurements):
    summaries = []
    for application in APPLICATIONS:
        for units in UNITS:
            implementations = {}
            for implementation in IMPLEMENTATIONS:
                batches = [value for value in measurements if (value["application"], value["units"], value["implementation"])
                           == (application, units, implementation)]
                samples = [sample for batch in batches for sample in batch["samples"]]
                latencies = [sample["elapsed_ns"] for sample in samples]
                statuses = sorted({sample["result"]["status"] for sample in samples})
                allocations = [sample["allocation"] for sample in samples]
                implementations[implementation] = {
                    "latency": _latencies(latencies),
                    "latency_by_status": {str(status): _latencies([sample["elapsed_ns"] for sample in samples if sample["result"]["status"] == status])
                                          for status in statuses},
                    "allocation_totals": {key: sum(row[key] for row in allocations) for key in ALLOCATION_FIELDS
                                          if key not in {"peak_live_bytes", "live_bytes"}},
                    "peak_tracked_live_bytes": max(row["peak_live_bytes"] for row in allocations),
                    "every_request_clean": all(row["live_bytes"] == 0 for row in allocations),
                    "rss_ru_maxrss_kib": [batch["process"]["rss_peak_kib"] for batch in batches],
                    "rss_address_space_hwm_kib": [batch["process"]["rss_vm_hwm_peak_kib"] for batch in batches],
                    "driver_wall_ns": sum(batch["process_elapsed_ns"] for batch in batches),
                }
            baseline = implementations["rust"]["latency"]
            ratios = {name: {metric: implementations[name]["latency"][metric] / baseline[metric]
                             for metric in ("p50_ns", "p95_ns", "p99_ns", "max_ns", "mean_ns")}
                      for name in IMPLEMENTATIONS if name != "rust"}
            summaries.append({"application": application, "units": units,
                              "payload_bytes": units * (64 if application == "packet" else 256),
                              "implementations": implementations, "time_relative_to_independent_rust": ratios})
    regressions = [{"application": row["application"], "units": row["units"], "implementation": implementation,
                    "metric": metric, "observed_time_ratio": ratio}
                   for row in summaries for implementation, values in row["time_relative_to_independent_rust"].items()
                   for metric, ratio in values.items() if ratio > 1]
    return summaries, regressions


def run_qualification(*, rustc=None, cc=None, trials=3, requests=96, warmups=16):
    if type(trials) is not int or not 1 <= trials <= 9 or type(requests) is not int or not 8 <= requests <= 4096 or requests % 8:
        raise ValueError("trials must be 1..9; requests must be 8..4096 and divisible by eight")
    if type(warmups) is not int or not 0 <= warmups <= 64:
        raise ValueError("warmups must be 0..64")
    commands = Commands()
    report = {"schema": "hepta.application-benchmarks.v1", "status": "running",
              "created_utc": datetime.now(timezone.utc).isoformat(), "compiler_sha256": compiler_hash(),
              "sources": identities(), "host": {"system": platform.system(), "machine": platform.machine(), "release": platform.release()},
              "profile": "full" if trials >= 3 and requests >= 96 and warmups >= 16 else "development",
              "trials": trials, "requests_per_trial": requests, "warmups": warmups, "request_seed": SEED,
              "claims": dict(CLAIMS), "correctness": [], "fault_recovery": [], "measurements": [], "execution_order": [],
              "timing_contract": dict(TIMING_CONTRACT)}
    try:
        if platform.system() != "Linux":
            raise RuntimeError("this native allocator/RSS qualification requires Linux")
        rustc = find_rustc(rustc)
        cc = shutil.which(cc or "gcc")
        if not cc:
            raise RuntimeError("native GCC is required")
        report["rust_toolchain"] = toolchain_info(rustc)
        report["c_toolchain"] = {"path": str(Path(cc).resolve()), "executable_sha256": digest(Path(cc).read_bytes()),
                                 "version": subprocess.check_output([cc, "--version"], text=True)}
        affinity = min(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") and shutil.which("taskset") else None
        prefix = ["taskset", "-c", str(affinity)] if affinity is not None else []
        report["cpu_affinity"] = affinity
        with tempfile.TemporaryDirectory(prefix="hepta-applications-") as temporary:
            directory = Path(temporary)
            executables, report["builds"] = build_applications(commands, directory, rustc, cc)
            for implementation in IMPLEMENTATIONS:
                for application in APPLICATIONS:
                    for units in CORRECTNESS_UNITS:
                        batch = run_batch(commands, executables[implementation], implementation, application, units, 1040, 8, 0, 0, prefix)
                        report["correctness"].append(batch)
                        for sample in batch["samples"]:
                            if sample["result"] != reference_result(application, units, sample["request_id"]):
                                raise RuntimeError("independent Python oracle rejected native result")
                    for fault in range(1, 3 if application == "packet" else 4):
                        batch = run_batch(commands, executables[implementation], implementation, application, 17, 1040, 2, fault, 0, prefix)
                        report["fault_recovery"].append(batch)
                        for sample in batch["samples"]:
                            if sample["result"] != reference_result(application, 17, sample["request_id"], sample["fault_nth"]):
                                raise RuntimeError("independent Python oracle rejected failure/recovery")
            wrong, _ = commands.run([*prefix, executables["wrong"], "packet", 17, 1040, 1, 0, 0], expected=41)
            report["negative_control"] = {"status": "rejected", "returncode": wrong.returncode,
                                          "executable_sha256": digest(executables["wrong"].read_bytes()),
                                          "stdout": wrong.stdout, "stderr": wrong.stderr,
                                          "stdout_sha256": digest(wrong.stdout.encode()), "stderr_sha256": digest(wrong.stderr.encode())}
            for app_index, application in enumerate(APPLICATIONS):
                for size_index, units in enumerate(UNITS):
                    for trial in range(trials):
                        shift = (app_index + size_index + trial) % len(IMPLEMENTATIONS)
                        order = list(IMPLEMENTATIONS[shift:] + IMPLEMENTATIONS[:shift])
                        report["execution_order"].append({"application": application, "units": units, "trial": trial, "implementations": order})
                        for implementation in order:
                            batch = run_batch(commands, executables[implementation], implementation, application, units,
                                              SEED + trial * requests, requests, 0, warmups, prefix)
                            batch["trial"] = trial
                            report["measurements"].append(batch)
            report["summary"], report["all_observed_slowdowns"] = summarize(report["measurements"])
        report["status"] = "passed"
        validate_application_report(report, minimum_trials=trials, minimum_requests=requests, minimum_warmups=warmups)
    except Exception as error:
        report["status"] = "failed"
        report["error"] = f"{type(error).__name__}: {error}"
    report["commands"] = commands.records
    if identities() != report["sources"] or compiler_hash() != report["compiler_sha256"]:
        report["status"] = "failed"
        report["error"] = "source changed during qualification"
    return report


def validate_application_report(report, *, minimum_trials=3, minimum_requests=96, minimum_warmups=16):
    # The implementation below checks raw requests and rebuilds all statistics.
    # Source-bound records are evidence, not a signature/proof of arbitrary JSON.
    def require(value, message):
        if not value:
            raise ValueError(message)

    def hash_(value):
        return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)

    def same(left, right):
        return json.dumps(left, sort_keys=True, allow_nan=False) == json.dumps(right, sort_keys=True, allow_nan=False)

    require(isinstance(report, dict) and report.get("schema") == "hepta.application-benchmarks.v1"
            and report.get("status") == "passed", "not a passing application qualification")
    require(report.get("compiler_sha256") == compiler_hash() and report.get("sources") == identities(), "source identity mismatch")
    require(report.get("claims") == CLAIMS and all(value is False for value in report["claims"].values()), "unsupported qualification claim")
    require(same(report.get("timing_contract"), TIMING_CONTRACT), "timing scope/accounting claim changed")
    require(isinstance(report.get("host"), dict) and report["host"].get("system") == "Linux", "native qualification host missing")
    require(isinstance(report.get("rust_toolchain"), dict) and hash_(report["rust_toolchain"].get("executable_sha256"))
            and isinstance(report["rust_toolchain"].get("host"), str), "native Rust identity missing")
    require(isinstance(report.get("c_toolchain"), dict) and hash_(report["c_toolchain"].get("executable_sha256")), "native GCC identity missing")
    require(report.get("cpu_affinity") is None or type(report["cpu_affinity"]) is int and report["cpu_affinity"] >= 0,
            "invalid process affinity record")
    trials, requests, warmups = report.get("trials"), report.get("requests_per_trial"), report.get("warmups")
    require(type(trials) is int and minimum_trials <= trials <= 9, "trial denominator")
    require(type(requests) is int and minimum_requests <= requests <= 4096 and requests % 8 == 0, "request denominator")
    require(type(warmups) is int and minimum_warmups <= warmups <= 64, "warmup denominator")
    require(report.get("request_seed") == SEED and type(report["request_seed"]) is int, "request seed changed")
    require(report.get("profile") == ("full" if trials >= 3 and requests >= 96 and warmups >= 16 else "development"), "qualification profile mismatch")
    builds = report.get("builds")
    require(isinstance(builds, dict) and set(builds) == {"common", "wrong", *IMPLEMENTATIONS}, "build denominator")
    common = builds.get("common")
    require(isinstance(common, dict) and set(common) == {"driver", "meter"}, "common native driver or allocator missing")
    for name, value in common.items():
        require(isinstance(value, dict) and value.get("source_sha256") == report["sources"][f"benchmarks/applications_{name}.c"]
                and value.get("compiler_sha256") == report["c_toolchain"]["executable_sha256"]
                and value.get("flags") == ["-std=c11", "-O3", "-Wall", "-Wextra", "-Werror"]
                and hash_(value.get("object_sha256")) and type(value.get("object_bytes")) is int and value["object_bytes"] > 0
                and type(value.get("returncode")) is int and value["returncode"] == 0, "missing native common object")
    for name in IMPLEMENTATIONS:
        value = builds[name]
        require(isinstance(value, dict), "invalid implementation build")
        native, link = value.get("native"), value.get("link")
        require(isinstance(native, dict) and native.get("ok") is True and native.get("check_only") is False,
                "native artifact was not built")
        source_key = "source_sha256" if name == "hepta_c" else "rust_sha256"
        require(hash_(value.get("compiled_source_sha256")) and native.get(source_key) == value["compiled_source_sha256"], "native source identity mismatch")
        require(hash_(value.get("library_sha256")) and native.get("artifact_sha256") == value["library_sha256"]
                and native.get("validation_artifact_sha256") == value["library_sha256"]
                and type(value.get("library_bytes")) is int and value["library_bytes"] > 0, "library identity mismatch")
        if name == "hepta_c":
            require(native.get("status") == "gcc_checked" and native.get("rustc_used") is False
                    and native.get("crate_type") == "obj" and native.get("optimization_profile") == "default", "C backend fallback/profile changed")
            require(isinstance(native.get("toolchain"), dict) and native["toolchain"].get("executable_sha256") == report["c_toolchain"]["executable_sha256"]
                    and isinstance(native.get("flags"), list) and all(flag in native["flags"] for flag in
                    ("-std=c11", "-O3", "-ffp-contract=off", "-fno-strict-aliasing")), "C compiler/flags changed")
            require(value.get("allocator_sha256") is None, "C backend cannot install Rust allocator source")
        else:
            require(native.get("status") == "rustc_checked" and native.get("crate_type") == "staticlib"
                    and native.get("toolchain") == report.get("rust_toolchain")
                    and isinstance(native.get("flags"), list)
                    and all(flag in native.get("flags", []) for flag in ("opt-level=3", "overflow-checks=yes", "panic=abort")),
                    "Rust reference flags or toolchain changed")
        if name == "rust":
            require(value.get("source_sha256") == report["sources"]["benchmarks/applications.rs"], "independent Rust source changed")
            expected_source = (ROOT / "benchmarks/applications.rs").read_text() + "\n" + (ROOT / "benchmarks/applications_allocator.rs").read_text()
        else:
            analysis = value.get("analysis")
            require(isinstance(analysis, dict) and analysis.get("ok") is True and analysis.get("compiler_sha256") == report["compiler_sha256"]
                    and analysis.get("source_sha256") == report["sources"]["benchmarks/applications.hepta"], "Hepta source checking missing")
            checks = analysis.get("checks", {})
            require(isinstance(checks, dict), "invalid source check record")
            require(checks.get("syntax") == "passed" and checks.get("types_effects_resources") == "passed_in_supported_subset", "Hepta frontend incomplete")
            require(checks.get("c_types_codegen") == "gcc_checked" and checks.get("rust_borrows_types") == "not_run"
                    if name == "hepta_c" else checks.get("rust_borrows_types") == "rustc_checked", "Hepta native gate incomplete")
            reference_check = analysis.get("backend")
            require(isinstance(reference_check, dict) and reference_check.get("ok") is True and reference_check.get("check_only") is True
                    and hash_(reference_check.get("validation_artifact_sha256")), "native reference metadata check missing")
            recorded_path = analysis.get("path")
            require(isinstance(recorded_path, str) and 0 < len(recorded_path) <= 4096, "source path identity missing")
            recreated = analyze((ROOT / "benchmarks/applications.hepta").read_text(), recorded_path,
                                backend="c" if name == "hepta_c" else "rust", native=False,
                                crate_type="obj" if name == "hepta_c" else "staticlib")
            require(recreated.report["ok"], "checked source no longer lowers")
            if name == "hepta_c":
                expected_source = recreated.c
                require(analysis.get("c_sha256") == digest(expected_source.encode()), "C lowering identity changed")
            else:
                require(analysis.get("rust_sha256") == digest(recreated.rust.encode()), "Rust lowering identity changed")
                expected_source = recreated.rust + "\n" + (ROOT / "benchmarks/applications_allocator.rs").read_text()
            require(reference_check.get(source_key) == analysis.get("c_sha256" if name == "hepta_c" else "rust_sha256"),
                    "reference metadata checked a different source")
        require(value["compiled_source_sha256"] == digest(expected_source.encode()), "native body differs from fresh source lowering")
        if name != "hepta_c":
            require(value.get("allocator_sha256") == report["sources"]["benchmarks/applications_allocator.rs"], "allocator instrumentation source changed")
        require(isinstance(link, dict) and type(link.get("returncode")) is int and link["returncode"] == 0
                and link.get("compiler_sha256") == report["c_toolchain"]["executable_sha256"]
                and link.get("inputs") == {"driver": common["driver"]["object_sha256"], "meter": common["meter"]["object_sha256"],
                                           "application": value["library_sha256"]}
                and hash_(link.get("executable_sha256")) and type(link.get("executable_bytes")) is int and link["executable_bytes"] > 0
                and link.get("flags") == WRAP_FLAGS + ["-lpthread", "-ldl", "-lm"], "linked executable identity mismatch")

    def batch(value, implementation, application, units, first, count, fault, warming, *, full_oracle):
        require(isinstance(value, dict), "invalid native batch")
        require((value.get("implementation"), value.get("application"), value.get("units"), value.get("first_request"),
                 value.get("count"), value.get("fault_nth"), value.get("warmups")) ==
                (implementation, application, units, first, count, fault, warming), "batch identity/order mismatch")
        require(all(type(value.get(key)) is int for key in ("units", "first_request", "count", "fault_nth", "warmups")), "noninteger batch identity")
        require(value.get("executable_sha256") == builds[implementation]["link"]["executable_sha256"], "wrong implementation executable")
        require(type(value.get("returncode")) is int and value["returncode"] == 0
                and type(value.get("process_elapsed_ns")) is int and value["process_elapsed_ns"] > 0, "native execution missing")
        samples, process = value.get("samples"), value.get("process")
        require(isinstance(samples, list) and len(samples) == count and isinstance(process, dict), "raw request denominator")
        for index, sample in enumerate(samples):
            require(isinstance(sample, dict) and set(sample) == {"request_id", "fault_nth", "elapsed_ns", "oracle_checked", "result", "allocation"}, "request schema")
            request = first + index * (8 if fault else 1)
            failure = fault if index == 0 else 0
            require(type(sample["request_id"]) is int and sample["request_id"] == request and type(sample["fault_nth"]) is int
                    and sample["fault_nth"] == failure and sample["oracle_checked"] is True, "request identity/failure/oracle mismatch")
            require(type(sample["elapsed_ns"]) is int and sample["elapsed_ns"] > 0, "missing raw native latency")
            result, allocation = sample["result"], sample["allocation"]
            require(isinstance(result, dict) and set(result) == set(RESULT_FIELDS)
                    and all(type(number) is int and 0 <= number <= MASK for number in result.values()), "invalid application result")
            expected = reference_result(application, units, request, failure) if full_oracle else result_shape(application, units, request, failure)
            require(all(result[key] == number for key, number in expected.items()), "oracle/result mismatch")
            expected_allocation = allocation_profile(application, units, request, failure)
            require(isinstance(allocation, dict) and set(allocation) == set(ALLOCATION_FIELDS)
                    and all(type(number) is int and number >= 0 for number in allocation.values())
                    and all(allocation[key] == number for key, number in expected_allocation.items())
                    and allocation["malloc_calls"] + allocation["calloc_calls"] + allocation["realloc_calls"] == allocation["attempts"],
                    "allocation/failure/cleanup accounting mismatch")
        require(set(process) == set(SUMMARY_FIELDS) and process["summary"] is True and process["requests"] == count
                and process["warmups"] == warming and process["abi_size"] == 32, "native process summary mismatch")
        require(all(type(process[key]) is int for key in SUMMARY_FIELDS if key != "summary")
                and 0 <= process["warmup_checksum"] <= MASK and process["timer_pair_min_ns"] >= 0
                and process["rss_peak_kib"] >= process["rss_start_kib"] >= 0, "invalid process measurements")
        require(warming != 0 or process["warmup_checksum"] == INITIAL_HASH, "zero-warmup checksum changed")
        require(process["rss_vm_hwm_start_kib"] == process["rss_vm_hwm_peak_kib"] == -1 or
                0 < process["rss_vm_hwm_start_kib"] <= process["rss_vm_hwm_peak_kib"], "invalid address-space RSS high water")
        require(value.get("stdout_sha256") == digest(native_transcript(samples, process).encode())
                and value.get("stderr_sha256") == digest(b""), "native transcript identity mismatch")

    expected_correctness = [(name, app, units) for name in IMPLEMENTATIONS for app in APPLICATIONS for units in CORRECTNESS_UNITS]
    correctness = report.get("correctness")
    require(isinstance(correctness, list) and len(correctness) == len(expected_correctness), "correctness denominator")
    for value, (name, app, units) in zip(correctness, expected_correctness):
        batch(value, name, app, units, 1040, 8, 0, 0, full_oracle=True)
    expected_faults = [(name, app, fault) for name in IMPLEMENTATIONS for app in APPLICATIONS
                       for fault in range(1, 3 if app == "packet" else 4)]
    faults = report.get("fault_recovery")
    require(isinstance(faults, list) and len(faults) == len(expected_faults), "failure/recovery denominator")
    for value, (name, app, fault) in zip(faults, expected_faults):
        batch(value, name, app, 17, 1040, 2, fault, 0, full_oracle=True)
    expected_order = []
    for app_index, app in enumerate(APPLICATIONS):
        for size_index, units in enumerate(UNITS):
            for trial in range(trials):
                shift = (app_index + size_index + trial) % 3
                expected_order.append({"application": app, "units": units, "trial": trial,
                                       "implementations": list(IMPLEMENTATIONS[shift:] + IMPLEMENTATIONS[:shift])})
    require(same(report.get("execution_order"), expected_order), "implementation rotation changed")
    measurements = report.get("measurements")
    require(isinstance(measurements, list) and len(measurements) == len(expected_order) * 3, "timing batch denominator")
    position = 0
    for schedule in expected_order:
        paired = []
        paired_warmups = []
        for name in schedule["implementations"]:
            value = measurements[position]
            require(isinstance(value, dict) and value.get("trial") == schedule["trial"] and type(value.get("trial")) is int, "trial identity mismatch")
            batch(value, name, schedule["application"], schedule["units"], SEED + schedule["trial"] * requests,
                  requests, 0, warmups, full_oracle=False)
            paired.append([sample["result"] for sample in value["samples"]])
            paired_warmups.append(value["process"]["warmup_checksum"])
            position += 1
        require(paired[0] == paired[1] == paired[2], "paired native implementations disagree")
        require(paired_warmups[0] == paired_warmups[1] == paired_warmups[2], "paired warmup inputs/results disagree")
    wrong, negative = builds.get("wrong"), report.get("negative_control")
    require(isinstance(wrong, dict) and wrong.get("source_sha256") == report["sources"]["benchmarks/applications_wrong.c"]
            and hash_(wrong.get("object_sha256")) and type(wrong.get("object_bytes")) is int and wrong["object_bytes"] > 0
            and wrong.get("compiler_sha256") == report["c_toolchain"]["executable_sha256"]
            and type(wrong.get("returncode")) is int and wrong["returncode"] == 0
            and type(wrong.get("link_returncode")) is int and wrong["link_returncode"] == 0
            and hash_(wrong.get("executable_sha256")) and type(wrong.get("executable_bytes")) is int and wrong["executable_bytes"] > 0
            and wrong.get("link_inputs") == {"driver": common["driver"]["object_sha256"], "meter": common["meter"]["object_sha256"],
                                             "application": wrong["object_sha256"]}, "wrong native implementation was not built")
    require(isinstance(negative, dict) and negative.get("status") == "rejected" and type(negative.get("returncode")) is int
            and negative["returncode"] == 41 and negative.get("executable_sha256") == wrong.get("executable_sha256")
            and hash_(negative.get("executable_sha256")) and negative.get("stdout") == ""
            and negative.get("stderr") == "request oracle rejected result: 0\n"
            and negative.get("stdout_sha256") == digest(b"") and negative.get("stderr_sha256") == digest(negative["stderr"].encode()),
            "wrong implementation was not rejected by the actual oracle")
    expected_summary, expected_regressions = summarize(measurements)
    require(same(report.get("summary"), expected_summary), "summary does not recompute from raw measurements")
    require(same(report.get("all_observed_slowdowns"), expected_regressions), "observed slowdown omitted or altered")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--rustc", default=os.environ.get("RUSTC"))
    parser.add_argument("--cc")
    parser.add_argument("--trials", type=int, default=3)
    parser.add_argument("--requests", type=int, default=96)
    parser.add_argument("--warmups", type=int, default=16)
    args = parser.parse_args(argv)
    if args.output.exists():
        parser.error("refusing to overwrite an earlier qualification attempt; choose a fresh output path")
    report = run_qualification(rustc=args.rustc, cc=args.cc, trials=args.trials, requests=args.requests, warmups=args.warmups)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"status": report["status"], "profile": report["profile"], "output": str(args.output),
                      "timed_requests": sum(len(value["samples"]) for value in report["measurements"]), "error": report.get("error")}))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
