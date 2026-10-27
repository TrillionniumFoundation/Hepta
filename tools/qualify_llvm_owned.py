#!/usr/bin/env python3
"""Frozen native owned-byte qualification; no workload or threshold overrides.

LLVM and generated Rust/C consume the same checked Hepta source. Handwritten
Rust is an additional baseline, not a claim about all possible optimized Rust.
Native loops, real allocator refusal and a compiled leak mutant are mandatory.
"""
from __future__ import annotations

import argparse
import base64
import ctypes
from dataclasses import replace
import datetime
from functools import lru_cache
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
from hepta.c_backend import compile_c
from hepta.clang_capture import CaptureRejected, run_bounded
from hepta.llvm_owned_backend import PROFILE, TARGET, compile_owned_llvm, emit_owned_llvm
from hepta.pipeline import analyze, compiler_hash
from tools.evidence_checks import is_sha, native_build, normalized_errors, require, strict_equal, text

EXAMPLE = ROOT / "examples/llvm_owned"
SOURCE = (EXAMPLE / "owned.hepta").read_text() + "\n" + (EXAMPLE / "qualification.hepta").read_text()
RUST_REFERENCE = (EXAMPLE / "reference.rs").read_text()
DRIVER = (EXAMPLE / "driver.c").read_text()
OBSERVER = (EXAMPLE / "observe.c").read_text()
INPUTS = ("tools/qualify_llvm_owned.py", "tools/evidence_checks.py",
          *("examples/llvm_owned/" + name for name in
            ("owned.hepta", "qualification.hepta", "reference.rs", "driver.c", "observe.c")))
SCHEMA = "hepta.llvm-owned-qualification.v1"
KERNELS = ("full_lifecycle", "constructor_error", "two_stage")
BACKENDS = ("rust", "llvm", "handwritten_rust")
CORRECTNESS_BACKENDS = (*BACKENDS, "c")
SIZES = {"full_lifecycle": 4093, "constructor_error": 4093, "two_stage": 4093}
CALLS = {"full_lifecycle": 1_048_576, "constructor_error": 8_388_608, "two_stage": 1_048_576}
PROTOCOL = {
    "id": "hepta.llvm-owned-bytes-perf.v1",
    "profile": PROFILE,
    "paired_groups": 7,
    "native_calls_per_sample": CALLS,
    "warmup_calls_per_process": 8192,
    "kernel_buffer_sizes": SIZES,
    "seed_sequence": "((call_index % 64) * 17 + 13) % 97 + 1",
    "minimum_sample_seconds": 0.05,
    "maximum_sample_seconds": 30.0,
    "maximum_relative_mad": 0.05,
    "maximum_geometric_mean_paired_time_ratio": 1.10,
    "maximum_kernel_paired_time_ratio": 1.20,
    "baselines": ["same-source Hepta to Rust", "independent handwritten safe Vec/slice Rust"],
    "ratio_definition": "median paired LLVM/baseline time; both baselines must pass independently",
    "relative_mad_definition": "median(abs(sample - median(samples))) / median(samples)",
    "ordering": "rotate kernels by group; rotate backends by group+kernel-position; reverse on odd groups",
    "outlier_policy": "retain every sample; no clipping, retries, calibration or best-run selection",
    "cpu_affinity": "lowest permitted logical CPU; qualifier and children pinned",
    "semantics": "checked integer arithmetic; fallible zeroed allocation; explicit moves and drop; abort on panic",
    "measurement_scope": "native loop includes allocation, initialization, borrowed access, cleanup and dispatch",
    "c_backend_scope": "independent checked C with UBSan for correctness only; not a timed baseline",
}
LIMITS = {
    "whole_language_performance_qualified": False, "universal_rust_superiority_proved": False,
    "optimal_rust_baseline_proved": False, "backend_refinement_proved": False,
    "whole_language_memory_safety_proved": False, "cross_target_execution_qualified": False,
    "stored_lifetime_record_lowering_qualified": False, "fallback_used": False,
}
WRAP_FLAGS = ["-fno-builtin-calloc", "-fno-builtin-malloc", "-fno-builtin-free",
              "-Wl,--wrap=calloc", "-Wl,--wrap=malloc", "-Wl,--wrap=free"]
OBJECT_RELATIONSHIP = "Objects are separate emissions of the measured sources; only llvm_object links the untimed resource observer."
COMPILE_SCOPE = "wall time of checked build operations, including tool identity and temporary I/O"
ENV_SCOPE = "shared host; fixed affinity does not provide exclusive CPU access"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(path):
    return sha(Path(path).read_bytes())


def inputs():
    return {name: digest(ROOT / name) for name in INPUTS}


def identity(path):
    path = Path(path)
    return {"path": str(path), "sha256": digest(path), "bytes": path.stat().st_size}


def execute(argv, *, timeout=120):
    argv = list(map(str, argv))
    try:
        result = run_bounded(argv, timeout=timeout, stdin_limit=0,
                             stdout_limit=128_000, stderr_limit=256_000)
    except CaptureRejected as error:
        return failed_capture(error, argv)
    return {"command": argv, "returncode": result.returncode,
            "stdout": result.stdout, "stderr": result.stderr,
            "stdout_sha256": sha(result.stdout.encode()), "stderr_sha256": sha(result.stderr.encode())}


def failed_capture(error, argv=None):
    capture = error.capture
    record = {"command": list(capture.command) if capture else list(argv or []),
              "returncode": capture.returncode if capture else None,
              "capture_error": {"code": error.code, "message": str(error)},
              "capture_available": capture is not None}
    if error.capture_error is not None:
        record["capture_read_error"] = error.capture_error
    for channel in ("stdout", "stderr"):
        data = getattr(capture, channel) if capture else b""
        total = getattr(capture, channel + "_total_bytes") if capture else None
        record[channel] = data.decode("utf-8", errors="replace").replace("\r\n", "\n").replace("\r", "\n")
        record[channel + "_sha256"] = sha(record[channel].encode())
        record[channel + "_raw"] = {"prefix_base64": base64.b64encode(data).decode("ascii"),
            "prefix_sha256": sha(data), "retained_bytes": len(data), "total_bytes": total,
            "truncated": len(data) < total if total is not None else None}
    return record


class NativeCommandFailed(ValueError):
    def __init__(self, record):
        self.record = record
        reason = record.get("capture_error", {}).get("code", "native_exit")
        super().__init__(f"E_OWNED_QUALIFY_COMMAND: {reason}; exit={record.get('returncode')}; "
                         "complete bounded process evidence retained in failed_command")


def successful(record):
    if type(record.get("returncode")) is not int or record["returncode"] != 0 or "capture_error" in record:
        raise NativeCommandFailed(record)
    return record["stdout"]


def process(record, command, *, code=0):
    require(strict_equal(record.get("command"), list(map(str, command)))
            and type(record.get("returncode")) is int and record["returncode"] == code
            and "capture_error" not in record,
            "executed command or exit status differs")
    for channel in ("stdout", "stderr"):
        require(isinstance(record.get(channel), str)
                and record.get(channel + "_sha256") == sha(record[channel].encode()),
                "native stdout/stderr identity differs")


def oracle(kernel, size, seed):
    if kernel == "two_alloc":
        return 1 if size > 2**63 - 1 else 2 if seed else size + 19
    if size > 2**63 - 1:
        return 1001 + (seed if kernel == "constructor_error" else 0)
    if kernel == "constructor_error":
        return 1002 + seed
    if kernel == "two_stage":
        return size * ((seed & 255) ^ 90)
    require(kernel == "full_lifecycle", "unknown frozen kernel")
    cycles, remaining = divmod(size, 256)
    return cycles * 32640 + sum((index + seed) & 255 for index in range(remaining))


def correctness_cases():
    rows = [{"kernel": kernel, "size": size, "seed": seed, "expected": oracle(kernel, size, seed)}
            for kernel in KERNELS for size in (0, 1, 2, 7, 255, 256, 257, 4093, 65519)
            for seed in (0, 1, 90, 255, 256, 2**32 - 1)]
    rows += [{"kernel": kernel, "size": size, "seed": seed, "expected": oracle(kernel, size, seed)}
             for kernel in (*KERNELS, "two_alloc") for size in (2**63, 2**64 - 1)
             for seed in (0, 2**32 - 1)]
    rows += [{"kernel": "two_alloc", "size": size, "seed": seed, "expected": oracle("two_alloc", size, seed)}
             for size in (0, 1, 3, 5, 17, 4093) for seed in (0, 1, 2**32 - 1)]
    return rows


def correctness_record():
    cases = correctness_cases()
    observations = [{**row, "actual": row["expected"]} for row in cases]
    return {"status": "passed_finite_domain", "case_count": len(cases),
            "native_calls": len(cases) * len(CORRECTNESS_BACKENDS), "cases": cases,
            "observations_sha256": {name: sha(wire(observations)) for name in CORRECTNESS_BACKENDS},
            "oracle": "independent Python integer/byte formula, including rejected allocation sizes"}


def check_correctness(libraries):
    require(set(libraries) == set(CORRECTNESS_BACKENDS), "all four correctness implementations required")
    loaded = {name: ctypes.CDLL(str(path)) for name, path in libraries.items()}
    for name, library in loaded.items():
        for row in correctness_cases():
            function = getattr(library, row["kernel"])
            function.argtypes, function.restype = [ctypes.c_size_t, ctypes.c_uint32], ctypes.c_uint64
            actual = int(function(row["size"], row["seed"]))
            require(actual == row["expected"], f"E_OWNED_QUALIFY_ORACLE: {name}/{row}: {actual}")
    return correctness_record()


@lru_cache(maxsize=3)
def timed_checksum(kernel):
    sequence = [oracle(kernel, SIZES[kernel], ((index % 64) * 17 + 13) % 97 + 1) for index in range(64)]
    value = 1469598103934665603
    for index in range(CALLS[kernel]):
        value = ((value ^ sequence[index % 64]) * 1099511628211) & (2**64 - 1)
    return value


def sample_order():
    result = []
    for group in range(PROTOCOL["paired_groups"]):
        rotation = group % len(KERNELS)
        for position, kernel in enumerate(KERNELS[rotation:] + KERNELS[:rotation]):
            offset = (group + position) % len(BACKENDS)
            backends = BACKENDS[offset:] + BACKENDS[:offset]
            if group % 2:
                backends = backends[::-1]
            result += [(group, kernel, backend) for backend in backends]
    return result


def evaluate_samples(rows, *, expected_order=None):
    """Evaluate against a caller's fixed schedule, never an order inferred from rows.

    The historical schedule remains the default. A trusted caller may fix a
    different backend order while preserving the complete grouped workload.
    """
    order = sample_order() if expected_order is None else expected_order
    require(isinstance(order, (list, tuple)) and len(order) == len(sample_order()),
            "expected schedule must contain all 63 native samples")
    for index, entry in enumerate(order):
        require(isinstance(entry, (list, tuple)) and len(entry) == 3,
                "malformed expected sample identity")
        group, kernel, backend = entry
        require(type(group) is int and group == index // (len(KERNELS) * len(BACKENDS))
                and kernel == KERNELS[(group + (index % (len(KERNELS) * len(BACKENDS))) // len(BACKENDS)) % len(KERNELS)]
                and backend in BACKENDS, "expected schedule changes fixed groups or kernel inventory")
    require(len({tuple(entry) for entry in order}) == len(order), "duplicate expected sample identity")
    require(isinstance(rows, list) and len(rows) == len(order), "complete 63 native samples required")
    for index, (row, expected) in enumerate(zip(rows, order)):
        require(isinstance(row, dict), "malformed sample record")
        require(strict_equal([row.get("group"), row.get("kernel"), row.get("backend"), row.get("sample_index")],
                             [*expected, index]), "sample order/identity differs")
        require(type(row.get("elapsed_ns")) is int and row["elapsed_ns"] > 0
                and type(row.get("checksum")) is int and row["checksum"] == timed_checksum(row["kernel"]),
                "invalid native timing or oracle checksum")
    summary, quality_failures, performance_failures = {}, [], []
    for kernel in KERNELS:
        implementations = {}
        for backend in BACKENDS:
            values = [row["elapsed_ns"] for row in rows if row["kernel"] == kernel and row["backend"] == backend]
            middle = statistics.median(values)
            mad = statistics.median(abs(value - middle) for value in values) / middle
            implementations[backend] = {"samples_ns": values, "median_ns": middle,
                "minimum_ns": min(values), "maximum_ns": max(values), "relative_mad": mad,
                "median_ns_per_native_call": middle / CALLS[kernel]}
            if min(values) < PROTOCOL["minimum_sample_seconds"] * 1e9:
                quality_failures.append(kernel + "/" + backend + ": sample shorter than fixed minimum")
            if max(values) > PROTOCOL["maximum_sample_seconds"] * 1e9:
                quality_failures.append(kernel + "/" + backend + ": sample longer than fixed maximum")
            if mad > PROTOCOL["maximum_relative_mad"]:
                quality_failures.append(kernel + "/" + backend + ": relative MAD above fixed maximum")
        comparisons = {}
        for baseline in ("rust", "handwritten_rust"):
            ratios = []
            for group in range(PROTOCOL["paired_groups"]):
                pair = {row["backend"]: row["elapsed_ns"] for row in rows
                        if row["kernel"] == kernel and row["group"] == group}
                ratios.append(pair["llvm"] / pair[baseline])
            ratio = statistics.median(ratios)
            comparisons[baseline] = {"paired_time_ratios": ratios, "median_paired_time_ratio": ratio}
            if ratio > PROTOCOL["maximum_kernel_paired_time_ratio"]:
                performance_failures.append(kernel + "/" + baseline + ": paired ratio exceeds fixed maximum")
        summary[kernel] = {"implementations": implementations, "comparisons": comparisons}
    geometric = {baseline: math.exp(statistics.mean(
        math.log(summary[kernel]["comparisons"][baseline]["median_paired_time_ratio"]) for kernel in KERNELS))
        for baseline in ("rust", "handwritten_rust")}
    for baseline, ratio in geometric.items():
        if ratio > PROTOCOL["maximum_geometric_mean_paired_time_ratio"]:
            performance_failures.append(baseline + ": geometric mean exceeds fixed maximum")
    status = "measurement_inconclusive" if quality_failures else "performance_failed" if performance_failures else "passed"
    return {"ok": status == "passed", "status": status, "summary": summary,
            "geometric_mean_paired_time_ratios": geometric,
            "measurement_quality_failures": quality_failures, "performance_threshold_failures": performance_failures}


def llvm_identity(ir):
    return {name: getattr(ir, name) for name in ("sha256", "semantic_sha256", "resource_ir_sha256",
            "resource_verification_sha256", "compiler_sha256", "profile")} | {
            "functions": list(ir.functions), "specializations": list(ir.specializations)}


def leak_source(ir):
    changed = ir.text.replace("call void @free(ptr %data)", "; intentionally removed free")
    require(changed != ir.text, "E_OWNED_QUALIFY_MUTATION: no actual drop call changed")
    return changed


def driver_commands(clang, directory):
    return [[clang, "-std=c11", "-O3", "-Wall", "-Wextra", "-Werror",
             "-c", str(directory / "driver.c"), "-o", str(directory / "driver.o")],
            [clang, str(directory / "driver.o"), "-ldl", "-o", str(directory / "driver")]]


def observer_commands(clang, cc, directory):
    return [[cc, "-std=c11", "-O3", str(directory / "observe.c"), str(directory / "llvm.o"),
             *WRAP_FLAGS, "-o", str(directory / "observe")],
            [clang, "--target=" + TARGET, "-x", "ir", "-O3", "-fPIC", "-c",
             str(directory / "leak.ll"), "-o", str(directory / "leak.o")],
            [cc, "-std=c11", "-O3", str(directory / "observe.c"), str(directory / "leak.o"),
             *WRAP_FLAGS, "-o", str(directory / "observe_leak")]]


def observe_resources(ir, analyzed, temp, clang, cc, *, observation=None):
    row = observation if observation is not None else {}
    row.update(status="running", commands=[])
    changed = leak_source(ir)
    candidate = replace(ir, text=changed, sha256=sha(changed.encode()))
    denied_path = temp / "forbidden.so"
    try:
        compile_owned_llvm(candidate, program=analyzed.program, checked=analyzed.checked,
                           output=denied_path, clang=clang)
    except ValueError as error:
        require(str(error).startswith("E_LLVM_OWNED_ORIGIN:"), "mutant rejected for unrelated reason")
    else:
        raise ValueError("E_OWNED_QUALIFY_MUTATION: public compiler accepted altered LLVM")
    require(not denied_path.exists(), "mutant compiler unexpectedly published output")
    row["origin_mutation_rejected_before_native_build"] = True
    row["mutated_llvm_sha256"] = sha(changed.encode())
    (temp / "observe.c").write_text(OBSERVER)
    (temp / "leak.ll").write_text(changed)
    for command in observer_commands(clang, cc, temp):
        record = execute(command)
        row["commands"].append(record)
        successful(record)
    positive = execute([temp / "observe"])
    row["positive"] = positive
    successful(positive)
    require(strict_equal(json.loads(positive["stdout"]), {"allocations": 7, "frees": 7, "live": 0, "refusals": 1}),
            "E_OWNED_QUALIFY_RESOURCE: real allocation/failure cleanup differs")
    negative = execute([temp / "observe_leak"])
    row["negative"] = negative
    leaked = json.loads(negative["stdout"])
    require(negative["returncode"] == 1 and type(leaked.get("allocations")) is int and leaked["allocations"] > 0
            and leaked == {"allocations": leaked["allocations"], "frees": 0,
                           "live": leaked["allocations"], "refusals": 1},
            "E_OWNED_QUALIFY_NEGATIVE: actual leak mutant escaped the resource oracle")
    row["artifacts"] = {name: identity(temp / name) for name in ("observe", "leak.o", "observe_leak")}
    row["status"] = "passed"
    return row


@normalized_errors
def validate_report(report, *, expected_git_commit=None, require_pass=True):
    """Replay source, oracles and frozen metrics without executing native code.

    A successful report is accepted by default. require_pass=False permits
    auditing a complete failed/inconclusive attempt without converting it into
    a release pass. JSON checks do not authenticate arbitrary third-party runs.
    """
    require(type(require_pass) is bool and isinstance(report, dict) and report.get("schema") == SCHEMA
            and report.get("phase") == "complete"
            and all(key not in report for key in ("diagnostic", "failed_command", "failed_sample")),
            "complete owned native qualification required")
    require(strict_equal(report.get("protocol"), PROTOCOL)
            and report.get("protocol_sha256") == sha(wire(PROTOCOL))
            and strict_equal(report.get("inputs"), inputs())
            and report.get("compiler_tree_sha256") == compiler_hash()
            and report.get("source_sha256") == sha(SOURCE.encode())
            and report.get("handwritten_rust_sha256") == sha(RUST_REFERENCE.encode())
            and report.get("driver_source_sha256") == sha(DRIVER.encode())
            and report.get("observer_source_sha256") == sha(OBSERVER.encode()),
            "frozen protocol/source/compiler/input identity differs")
    commit = report.get("git_commit")
    require(isinstance(commit, str) and len(commit) == 40 and all(ch in "0123456789abcdef" for ch in commit)
            and (expected_git_commit is None or commit == expected_git_commit), "candidate commit differs")
    frontend = report["reference_validation"]
    path = frontend.get("path")
    require(text(path) and PurePosixPath(path).is_absolute() and PurePosixPath(path).name == "kernels.hepta",
            "source entry path differs")
    directory = PurePosixPath(path).parent
    generated = analyze(SOURCE, path, native=False, crate_type="cdylib")
    require(generated.report["ok"] is True, "frozen Hepta source no longer checks")
    expected_frontend = dict(generated.report, status="checked")
    expected_frontend["checks"] = dict(generated.report["checks"], rust_borrows_types="rustc_checked")
    require(strict_equal({key: value for key, value in frontend.items() if key != "backend"}, expected_frontend),
            "pinned reference source/effect/resource checks differ")
    c = analyze(SOURCE, path, backend="c", native=False, crate_type="cdylib")
    require(c.report["ok"] is True and strict_equal(report["c_validation"], c.report),
            "independent C frontend differs")
    rust_sha, c_sha = sha(generated.rust.encode()), sha(c.c.encode())
    require(report.get("generated_rust_sha256") == rust_sha and report.get("generated_c_sha256") == c_sha,
            "generated reference source identity differs")
    ir = emit_owned_llvm(generated.program, generated.checked)
    require(strict_equal(report.get("llvm"), llvm_identity(ir)) and report.get("llvm_ir") == ir.text,
            "exact source-derived LLVM/resource/generic specialization identity differs")
    native_build(frontend["backend"], "rust", check_only=True, crate_type="cdylib", source_sha256=rust_sha)
    receipts = report["native_receipts"]
    expected_names = {"rust_library", "rust_object", "handwritten_rust_library", "handwritten_rust_object",
                      "llvm_library", "llvm_object", "c_library"}
    require(set(receipts) == expected_names, "complete native build inventory required")
    rust_chain = frontend["backend"]["toolchain"]
    for name in ("rust_library", "rust_object", "handwritten_rust_library", "handwritten_rust_object"):
        native = receipts[name]
        handwritten = name.startswith("handwritten")
        object_kind = name.endswith("_object")
        native_build(native, "rust", check_only=False, crate_type="obj" if object_kind else "cdylib",
                     source_sha256=sha(RUST_REFERENCE.encode()) if handwritten else rust_sha)
        require(strict_equal(native["toolchain"], rust_chain) and native["target"] == TARGET,
                "native Rust baseline toolchains/host differ")
        flags = ["edition=2021", "opt-level=3", "overflow-checks=yes", "panic=abort", "codegen-units=1"]
        if native.get("sysroot"):
            flags += ["sysroot=" + native["sysroot"]]
        if native.get("linker"):
            flags += ["linker=" + native["linker"]]
        require(strict_equal(native["flags"], flags) and strict_equal(native["link_args"], [])
                and native.get("sysroot") == rust_chain.get("sysroot")
                and native.get("rustc_crate_type") == ("lib" if object_kind else "cdylib"),
                "native Rust checked arithmetic/optimization profile differs")
    versions = dict(line.split(": ", 1) for line in rust_chain["version"].splitlines() if ": " in line)
    require(versions.get("release") == RUST_VERSION and versions.get("host") == TARGET,
            "pinned native Rust version/target differs")
    native_build(receipts["c_library"], "c", check_only=False, crate_type="cdylib", source_sha256=c_sha)
    require("-O3" in receipts["c_library"]["flags"] and "-fsanitize=undefined" in receipts["c_library"]["flags"]
            and "-fno-sanitize-recover=all" in receipts["c_library"]["flags"]
            and receipts["c_library"]["link_args"] == [], "independent C UBSan flags differ")
    clang = report["clang"]
    require(text(clang["path"]) and PurePosixPath(clang["path"]).is_absolute() and is_sha(clang["sha256"])
            and text(clang["version"]), "native Clang identity missing")
    for name, kind in (("llvm_library", "shared"), ("llvm_object", "object")):
        native = receipts[name]
        require(native["schema"] == "hepta.llvm-owned-native.v1" and native["ok"] is True
                and native["status"] == "native_compiled_not_executed" and native["profile"] == PROFILE
                and native["kind"] == kind and native["target"] == TARGET
                and strict_equal(native["toolchain"], clang), "actual source-bound LLVM build differs")
        for field, attr in (("llvm_ir_sha256", "sha256"), ("semantic_sha256", "semantic_sha256"),
                            ("resource_ir_sha256", "resource_ir_sha256"),
                            ("resource_verification_sha256", "resource_verification_sha256"),
                            ("compiler_sha256", "compiler_sha256")):
            require(native.get(field) == getattr(ir, attr), "LLVM build identity differs from exact source replay")
        require(strict_equal(native["flags"], ["--target=" + TARGET, "-x", "ir", "-O3", "-fPIC",
                                               "-shared" if kind == "shared" else "-c"])
                and strict_equal(native["claims"], {
                    "checked_ast_resource_origin_replayed": True, "rust_codegen_used": False,
                    "c_codegen_used": False, "fallback_used": False, "native_execution_qualified": False,
                    "backend_refinement_proved": False, "whole_language_memory_safety_proved": False,
                    "cross_target_execution_qualified": False}), "LLVM optimization/origin/claims differ")
    artifacts = report["artifacts"]
    require(set(artifacts) == expected_names | {"driver_object", "driver_binary"}, "native artifact inventory incomplete")
    for name, artifact in artifacts.items():
        require(set(artifact) == {"path", "sha256", "bytes"} and is_sha(artifact["sha256"])
                and type(artifact["bytes"]) is int and artifact["bytes"] > 0, "native artifact identity malformed")
        if name in receipts:
            native = receipts[name]
            base, kind = name.rsplit("_", 1)
            require(artifact["path"] == str(directory / (base + (".o" if kind == "object" else ".so")))
                    and native.get("artifact", native.get("output")) == artifact["path"]
                    and native.get("artifact_sha256") == artifact["sha256"]
                    and type(native.get("artifact_bytes")) is int and native["artifact_bytes"] == artifact["bytes"],
                    "build-to-execution artifact identities differ")
    require(artifacts["driver_binary"]["path"] == str(directory / "driver")
            and artifacts["driver_object"]["path"] == str(directory / "driver.o")
            and report["object_relationship"] == OBJECT_RELATIONSHIP, "native object/link relationship differs")
    for record, command in zip(report["driver_commands"], driver_commands(clang["path"], directory), strict=True):
        process(record, command)
    require(strict_equal(report["correctness"], correctness_record()), "finite oracle denominator/results differ")
    resource = report["resource_observation"]
    require(resource.get("status") == "passed" and resource.get("origin_mutation_rejected_before_native_build") is True
            and resource.get("mutated_llvm_sha256") == sha(leak_source(ir).encode()),
            "actual leak control or origin rejection differs")
    commands = observer_commands(clang["path"], report["cc"]["path"], directory)
    require(report["cc"]["sha256"] == receipts["c_library"]["toolchain"]["executable_sha256"],
            "resource observer C toolchain identity differs")
    for record, command in zip(resource["commands"], commands, strict=True):
        process(record, command)
    process(resource["positive"], [directory / "observe"])
    process(resource["negative"], [directory / "observe_leak"], code=1)
    require(strict_equal(json.loads(resource["positive"]["stdout"]),
                         {"allocations": 7, "frees": 7, "live": 0, "refusals": 1}),
            "actual resource cleanup or allocator-refusal count differs")
    negative = json.loads(resource["negative"]["stdout"])
    require(type(negative.get("allocations")) is int and negative["allocations"] > 0
            and strict_equal(negative, {"allocations": negative["allocations"], "frees": 0,
                                       "live": negative["allocations"], "refusals": 1}), "compiled leak was not detected")
    require(set(resource["artifacts"]) == {"observe", "leak.o", "observe_leak"}, "observer artifact inventory differs")
    for name, artifact in resource["artifacts"].items():
        require(artifact["path"] == str(directory / name) and is_sha(artifact["sha256"])
                and type(artifact["bytes"]) is int and artifact["bytes"] > 0, "observer artifact identity missing")
    rows = report["raw_samples"]
    evaluation = evaluate_samples(rows)
    for row in rows:
        require(all(type(row.get(key)) is int and row[key] > 0 for key in
                    ("elapsed_ns", "clock_resolution_ns", "process_peak_rss_kib"))
                and row["clock_resolution_ns"] <= row["elapsed_ns"], "native timing/memory observations malformed")
        process(row["execution"], [directory / "driver", directory / (row["backend"] + ".so"), row["kernel"]])
        require(strict_equal(json.loads(row["execution"]["stdout"]),
                             {key: row[key] for key in ("elapsed_ns", "checksum", "clock_resolution_ns", "process_peak_rss_kib")})
                and row["library_sha256"] == artifacts[row["backend"] + "_library"]["sha256"]
                and row["driver_sha256"] == artifacts["driver_binary"]["sha256"],
                "timed native outputs/artifacts were altered")
    require(strict_equal(report["evaluation"], evaluation) and report["status"] == evaluation["status"]
            and report["ok"] is evaluation["ok"], "outer status masks fixed sample evaluation")
    require(not require_pass or evaluation["ok"] is True, "fixed native performance/quality gates did not pass")
    require(strict_equal(report["claims"], {**LIMITS, "finite_correctness_checked": True,
            "actual_owned_cleanup_checked": True, "handwritten_rust_baseline_checked": True,
            "host_owned_performance_gate_passed": evaluation["ok"]}), "native qualification claims exceed evidence")
    environment = report["environment"]
    allowed = environment["allowed_cpus_before"]
    require(environment["system"] == "Linux" and environment["machine"] in {"x86_64", "amd64"}
            and isinstance(allowed, list) and allowed and allowed == sorted(set(allowed))
            and all(type(cpu) is int and cpu >= 0 for cpu in allowed)
            and type(environment["selected_cpu"]) is int and environment["selected_cpu"] == allowed[0]
            and environment["scope"] == ENV_SCOPE, "fixed host/affinity evidence differs")
    for key in ("loadavg_before", "loadavg_after"):
        require(isinstance(environment[key], list) and len(environment[key]) == 3
                and all(type(value) in {int, float} and math.isfinite(value) and value >= 0
                        for value in environment[key]), "host load observations missing/nonfinite")
    timings = report["compile_wall_seconds"]
    require(set(timings) == expected_names | {"native_reference_and_frontends", "driver", "resource_observer"}
            and all(type(value) in {int, float} and math.isfinite(value) and value >= 0 for value in timings.values())
            and report["compile_time_scope"] == COMPILE_SCOPE, "compilation time scope/observations differ")
    dates = [datetime.datetime.strptime(report[key], "%Y-%m-%dT%H:%M:%SZ")
             for key in ("started_utc", "finished_utc")]
    require(dates[0] <= dates[1], "qualification timestamps reversed")


def optional_read(path):
    try:
        return Path(path).read_text().strip()
    except OSError:
        return None


def qualify(*, clang="clang", rustc=None, cc="gcc"):
    report = {"schema": SCHEMA, "status": "blocked", "ok": False, "phase": "initialize",
        "protocol": dict(PROTOCOL), "protocol_sha256": sha(wire(PROTOCOL)), "inputs": inputs(),
        "compiler_tree_sha256": compiler_hash(), "source_sha256": sha(SOURCE.encode()),
        "handwritten_rust_sha256": sha(RUST_REFERENCE.encode()), "driver_source_sha256": sha(DRIVER.encode()),
        "observer_source_sha256": sha(OBSERVER.encode()),
        "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "raw_samples": [], "compile_wall_seconds": {}, "native_receipts": {},
        "claims": {**LIMITS, "finite_correctness_checked": False, "actual_owned_cleanup_checked": False,
                   "handwritten_rust_baseline_checked": False, "host_owned_performance_gate_passed": False}}
    affinity = None
    def timed(name, action):
        start = time.perf_counter()
        try:
            return action()
        finally:
            report["compile_wall_seconds"][name] = time.perf_counter() - start
    try:
        require(platform.system() == "Linux" and platform.machine() in {"x86_64", "amd64"},
                "E_OWNED_QUALIFY_HOST: frozen Linux x86_64 native host required")
        affinity = os.sched_getaffinity(0)
        selected = min(affinity)
        os.sched_setaffinity(0, {selected})
        report["environment"] = {
            "system": platform.system(), "machine": platform.machine(), "kernel": platform.release(),
            "python": platform.python_version(), "libc": platform.libc_ver(),
            "allowed_cpus_before": sorted(affinity), "selected_cpu": selected,
            "cpu_model": next((line.split(":", 1)[1].strip() for line in
                              (optional_read("/proc/cpuinfo") or "").splitlines()
                              if line.startswith("model name")), None),
            "scaling_governor": optional_read(f"/sys/devices/system/cpu/cpu{selected}/cpufreq/scaling_governor"),
            "cgroup_cpu_max": optional_read("/sys/fs/cgroup/cpu.max"),
            "loadavg_before": list(os.getloadavg()), "scope": ENV_SCOPE}
        report["git_commit"] = successful(execute(["git", "-C", ROOT, "rev-parse", "HEAD"])).strip()
        require(not successful(execute(["git", "-C", ROOT, "status", "--porcelain", "--untracked-files=no"])).strip(),
                "E_OWNED_QUALIFY_DIRTY: commit all tracked implementation before native measurement")
        found_clang, found_cc = shutil.which(clang), shutil.which(cc)
        require(found_clang and found_cc, "E_OWNED_QUALIFY_TOOLS: real Clang and GCC required")
        clang, cc = str(Path(found_clang).resolve()), str(Path(found_cc).resolve())
        report["clang"] = {"path": clang, "sha256": digest(clang),
            "version": successful(execute([clang, "--version"])).splitlines()[0],
            "default_target": successful(execute([clang, "-dumpmachine"])).strip()}
        report["cc"] = {"path": cc, "sha256": digest(cc),
                        "version": successful(execute([cc, "--version"])).splitlines()[0]}
        report["phase"] = "build"
        with tempfile.TemporaryDirectory(prefix="hepta-llvm-owned-qualify-") as directory:
            temp = Path(directory)
            path = temp / "kernels.hepta"
            path.write_text(SOURCE)
            (temp / "driver.c").write_text(DRIVER)
            start = time.perf_counter()
            analyzed = analyze(SOURCE, str(path), native=True, rustc=rustc, crate_type="cdylib")
            report["reference_validation"] = analyzed.report
            require(analyzed.report["ok"] is True and analyzed.report["checks"]["rust_borrows_types"] == "rustc_checked",
                    "E_OWNED_QUALIFY_REFERENCE: pinned Rust source/reference check failed: " + wire(analyzed.report).decode()[:3000])
            c = analyze(SOURCE, str(path), native=False, backend="c", crate_type="cdylib")
            report["c_validation"] = c.report
            require(c.report["ok"] is True, "E_OWNED_QUALIFY_C: independent C frontend failed")
            report["compile_wall_seconds"]["native_reference_and_frontends"] = time.perf_counter() - start
            report["generated_rust_sha256"], report["generated_c_sha256"] = sha(analyzed.rust.encode()), sha(c.c.encode())
            ir = emit_owned_llvm(analyzed.program, analyzed.checked)
            report["llvm"], report["llvm_ir"] = llvm_identity(ir), ir.text
            libraries = {name: temp / (name + ".so") for name in CORRECTNESS_BACKENDS}
            objects = {name: temp / (name + ".o") for name in BACKENDS}
            actions = {
                "rust_library": lambda: compile_rust(analyzed.rust, rustc=rustc, crate_type="cdylib", output=libraries["rust"]),
                "rust_object": lambda: compile_rust(analyzed.rust, rustc=rustc, crate_type="obj", output=objects["rust"]),
                "handwritten_rust_library": lambda: compile_rust(RUST_REFERENCE, rustc=rustc, crate_type="cdylib", output=libraries["handwritten_rust"]),
                "handwritten_rust_object": lambda: compile_rust(RUST_REFERENCE, rustc=rustc, crate_type="obj", output=objects["handwritten_rust"]),
                "llvm_library": lambda: compile_owned_llvm(ir, program=analyzed.program, checked=analyzed.checked,
                                                          clang=clang, output=libraries["llvm"], kind="shared"),
                "llvm_object": lambda: compile_owned_llvm(ir, program=analyzed.program, checked=analyzed.checked,
                                                         clang=clang, output=objects["llvm"], kind="object"),
                "c_library": lambda: compile_c(c.c, cc=cc, crate_type="cdylib", output=libraries["c"], sanitize=True)}
            for name, action in actions.items():
                receipt = timed(name, action)
                report["native_receipts"][name] = receipt
                require(receipt["ok"] is True, "E_OWNED_QUALIFY_NATIVE: build failed: " + wire(receipt).decode()[:3000])
            report["driver_commands"] = timed("driver", lambda: [execute(command) for command in driver_commands(clang, temp)])
            for record in report["driver_commands"]:
                successful(record)
            artifact_paths = {**{name + "_library": value for name, value in libraries.items()},
                              **{name + "_object": value for name, value in objects.items()},
                              "driver_object": temp / "driver.o", "driver_binary": temp / "driver"}
            report["artifacts"] = {name: identity(value) for name, value in artifact_paths.items()}
            report["object_relationship"], report["compile_time_scope"] = OBJECT_RELATIONSHIP, COMPILE_SCOPE
            report["phase"] = "correctness"
            report["correctness"] = check_correctness(libraries)
            report["claims"].update(finite_correctness_checked=True, handwritten_rust_baseline_checked=True)
            report["resource_observation"] = {}
            timed("resource_observer", lambda: observe_resources(ir, analyzed, temp, clang, cc,
                  observation=report["resource_observation"]))
            report["claims"]["actual_owned_cleanup_checked"] = True
            for kernel in KERNELS:
                timed_checksum(kernel)  # Python oracle computation occurs outside native timing.
            report["phase"] = "measurement"
            for group, kernel, backend in sample_order():
                execution = execute([temp / "driver", libraries[backend], kernel])
                report["failed_sample"] = {"group": group, "kernel": kernel, "backend": backend,
                    "sample_index": len(report["raw_samples"]), "execution": execution,
                    "library_sha256": report["artifacts"][backend + "_library"]["sha256"],
                    "driver_sha256": report["artifacts"]["driver_binary"]["sha256"]}
                measured = json.loads(successful(execution))
                report["raw_samples"].append({"group": group, "kernel": kernel, "backend": backend,
                    "sample_index": len(report["raw_samples"]), **measured, "execution": execution,
                    "library_sha256": report["artifacts"][backend + "_library"]["sha256"],
                    "driver_sha256": report["artifacts"]["driver_binary"]["sha256"]})
                del report["failed_sample"]
            report["evaluation"] = evaluate_samples(report["raw_samples"])
            require(all(identity(value) == report["artifacts"][name] for name, value in artifact_paths.items())
                    and compiler_hash() == report["compiler_tree_sha256"] and inputs() == report["inputs"]
                    and path.read_text() == SOURCE, "E_OWNED_QUALIFY_STALE: source or native artifacts changed")
            report["ok"], report["status"] = report["evaluation"]["ok"], report["evaluation"]["status"]
            report["claims"]["host_owned_performance_gate_passed"] = report["ok"]
            report["phase"] = "complete"
    except (OSError, RuntimeError, ValueError, TypeError, KeyError) as error:
        if isinstance(error, NativeCommandFailed):
            report["failed_command"] = error.record
        elif isinstance(error, CaptureRejected):
            report["failed_command"] = failed_capture(error)
        report["diagnostic"] = {"message": str(error), "code": str(error).split(":", 1)[0]}
        report["ok"] = False
        report["status"] = "correctness_failed" if report["phase"] == "correctness" else "blocked"
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
    parser.add_argument("--cc", default="gcc")
    parser.add_argument("--describe-protocol", action="store_true")
    args = parser.parse_args(argv)
    if args.describe_protocol:
        print(json.dumps({"protocol": PROTOCOL, "protocol_sha256": sha(wire(PROTOCOL)),
                          "source_sha256": sha(SOURCE.encode()), "inputs": inputs()}, indent=2, sort_keys=True))
        return 0
    if args.output is None or args.output.exists() or args.output.is_symlink() or not args.output.parent.is_dir():
        parser.error("--output must name a new file in an existing directory")
    report = qualify(clang=args.clang, rustc=args.rustc, cc=args.cc)
    with args.output.open("x", encoding="utf-8") as destination:
        json.dump(report, destination, indent=2, sort_keys=True, allow_nan=False)
        destination.write("\n")
    print(json.dumps({"ok": report["ok"], "status": report["status"], "output": str(args.output),
                      "evaluation": report.get("evaluation"), "diagnostic": report.get("diagnostic")}, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
