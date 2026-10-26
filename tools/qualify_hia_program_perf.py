#!/usr/bin/env python3
"""Fixed same-safety Rust comparisons for the new standalone HIA backend.

Preserves the frozen native workload, formula oracle, 63-sample ordering and
quality/performance limits while building the source-free core. The standalone
driver additionally observes CPU time and scheduling outside the timed loop.
No result trimming, retries, calibration or threshold overrides are supported.
The raw JSON retains failed samples. Passing is a finite host qualification,
not universal Rust superiority or a physical-device result.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import statistics
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from hepta.backend import compile_rust
from hepta.hia_program_source import lower_source
from hepta.hia_program_llvm import HIAProgramLLVMRejected, emit_program_llvm, compile_program_llvm
from hepta.pipeline import analyze, compiler_hash
from tools.qualify_llvm_owned import (PROTOCOL as ORIGINAL_PROTOCOL, RUST_REFERENCE,
    OBSERVER, WRAP_FLAGS, correctness_cases, driver_commands, sample_order,
    evaluate_samples, timed_checksum, KERNELS, BACKENDS, execute, successful,
    identity, sha, wire, NativeCommandFailed)

SOURCE_PATH = ROOT / "examples/hia_program/benchmarks.hepta"
SOURCE = SOURCE_PATH.read_text()
DRIVER = (ROOT / "examples/hia_program/perf_driver.c").read_text()
PROTOCOL = {**ORIGINAL_PROTOCOL, "id": "hepta.hia.program.perf.v1",
            "profile": "closed-ssa-integer-byte-resources-64-v1",
            "implementation_mapping": {"llvm": "standalone HIA direct LLVM",
                "rust": "same Hepta input to checked Rust",
                "handwritten_rust": "independent safe Vec/slice Rust"},
            "observer": "actual allocator/NULL interception plus compiled missing-free negative control",
            "resource_observation_scope": "untimed standalone LLVM two_alloc object; Rust allocator traces are not compared",
            "c_backend_scope": "no C correctness or performance backend is executed by this qualification",
            "allocation_optimization_scope": "HIA preserves allocator effects; Rust baselines use their standard allocator optimization rules",
            "interference_observation": "CPU time, context switches and page faults are retained per sample; informational only, no sample exclusion or acceptance adjustment",
            "scope": "Linux x86-64; finite integer/byte-owner kernels; source-free HIA execution"}
INPUTS = ("tools/qualify_hia_program_perf.py", "tools/qualify_llvm_owned.py",
          "tools/evidence_checks.py", "examples/hia_program/benchmarks.hepta",
          "examples/llvm_owned/reference.rs", "examples/llvm_owned/driver.c",
          "examples/llvm_owned/observe.c", "examples/hia_program/perf_driver.c")


def input_hashes():
    return {name: sha((ROOT / name).read_bytes()) for name in INPUTS}


def require(condition, message):
    if not condition:
        raise ValueError("E_HIA_PERF: " + message)


def interference_summary(samples):
    """Describe scheduling visibility without repairing or censoring a sample."""
    fields = ("voluntary_context_switches", "involuntary_context_switches",
              "minor_page_faults", "major_page_faults")
    for row in samples:
        require(type(row.get("process_cpu_ns")) is int and row["process_cpu_ns"] > 0,
                "missing or malformed native CPU-time observation")
        require(type(row.get("elapsed_ns")) is int and row["elapsed_ns"] > 0,
                "missing or malformed native wall-time observation")
        require(all(type(row.get(field)) is int and row[field] >= 0 for field in fields),
                "missing or malformed native scheduling observation")
    require(samples, "scheduling summary requires actual samples")
    fractions = [row["process_cpu_ns"] / row["elapsed_ns"] for row in samples]
    return {"sample_count": len(samples),
            "cpu_to_wall_ratio": {"minimum": min(fractions), "median": statistics.median(fractions),
                                  "maximum": max(fractions)},
            "totals": {field: sum(row[field] for row in samples) for field in fields},
            "scope": "CPU interval brackets the wall interval; overhead and host interference are not isolated",
            "samples_excluded": 0, "acceptance_thresholds_adjusted": False}


def scheduler_environment():
    result = {"policy": os.sched_getscheduler(0), "priority": os.sched_getparam(0).sched_priority,
              "exclusive_cpu_ownership": False}
    for label, path in (("cgroup_cpu_max", "/sys/fs/cgroup/cpu.max"),
                        ("cgroup_cpuset_cpus_effective", "/sys/fs/cgroup/cpuset.cpus.effective")):
        try:
            with open(path) as stream:
                result[label] = stream.read(4096).strip()
        except OSError as error:
            result[label] = {"available": False, "error": type(error).__name__}
    return result


@contextmanager
def artifact_workspace(directory, report):
    """Keep the exact measured files when explicitly requested, even on failure.

    A new directory is mandatory. Retention does not alter sample collection,
    acceptance, or artifact identity checks and never substitutes a rebuild for
    the binary which produced a sample.
    """
    if directory is None:
        with tempfile.TemporaryDirectory(prefix="hepta-hia-perf-") as temporary:
            report["artifact_retention"] = {"retained": False}
            yield Path(temporary)
        return
    destination = Path(os.path.abspath(directory))
    require(destination.parent.is_dir() and not destination.exists() and not destination.is_symlink(),
            "artifact directory must be new and have an existing parent")
    destination.mkdir(mode=0o700)
    report["artifact_retention"] = {"retained": True, "directory": str(destination)}
    try:
        yield destination
    finally:
        inventory = {}
        for item in sorted(destination.rglob("*")):
            metadata = item.lstat()
            if stat.S_ISDIR(metadata.st_mode):
                continue
            require(stat.S_ISREG(metadata.st_mode), "retained artifact is not an ordinary file")
            inventory[item.relative_to(destination).as_posix()] = {
                "bytes": metadata.st_size, "sha256": sha(item.read_bytes())}
        manifest = {"schema": "hepta.hia.program-perf-artifacts.v1", "files": inventory,
                    "scope": "exact files retained from this attempt, including failed attempts; no rebuilds"}
        encoded = wire(manifest)
        with (destination / "artifact-retention.json").open("xb") as stream:
            stream.write(encoded + b"\n")
        report["artifact_retention"].update(manifest_sha256=sha(encoded + b"\n"), files=inventory)


_CORRECTNESS_CHILD = r"""
import ctypes, json, sys
libraries, cases = json.loads(sys.argv[1]), json.loads(sys.argv[2])
for name, path in libraries:
    library = ctypes.CDLL(path)
    for case in cases:
        fn = getattr(library, case["kernel"])
        fn.argtypes, fn.restype = [ctypes.c_size_t, ctypes.c_uint32], ctypes.c_uint64
        actual = int(fn(case["size"], case["seed"]))
        print(json.dumps({"backend": name, **case, "actual": actual}, separators=(",", ":")), flush=True)
        if actual != case["expected"]:
            sys.exit(90)
"""


def check_correctness(libraries, *, observation=None):
    """Run real ABI calls in a bounded child so aborts retain failure evidence."""
    require(set(libraries) == set(BACKENDS), "exactly the three measured implementations are required")
    row = observation if observation is not None else {}
    row.update(status="running", observations=[])
    cases = correctness_cases()
    process = execute([sys.executable, "-c", _CORRECTNESS_CHILD,
                       json.dumps([(name, str(libraries[name])) for name in BACKENDS]), json.dumps(cases)])
    row["process"] = process
    for line in process["stdout"].splitlines():
        row["observations"].append(json.loads(line))
    successful(process)
    expected = [{"backend": name, **case, "actual": case["expected"]} for name in BACKENDS for case in cases]
    require(row["observations"] == expected, "native output differs from the independent formula or fixed call inventory")
    row.update(status="passed_finite_domain", native_calls=len(expected),
               observations_sha256=sha(wire(row["observations"])))
    return row


def observe(ir, core, temp, clang, *, observation=None):
    row = observation if observation is not None else {}
    row.update(status="running", commands=[])
    obj = temp / "owned.o"
    receipt = compile_program_llvm(ir, program=core, output=obj, clang=clang, kind="object")
    require(receipt["ok"], "resource object did not compile")
    row["object"] = receipt
    observer = temp / "observer.c"
    observer.write_text(OBSERVER)
    mutant = re.sub(r"(?m)^\s*call void @free\(ptr [^\n]*\) nobuiltin\s*$",
                    "  ; intentionally removed actual free", ir.text)
    require(mutant != ir.text, "missing real free instruction for negative control")
    rejected = False
    try:
        compile_program_llvm(replace(ir, text=mutant, sha256=sha(mutant.encode())),
                            program=core, output=temp / "forbidden.o", clang=clang, kind="object")
    except HIAProgramLLVMRejected as error:
        require(str(error).startswith("E_HIA_PROGRAM_ORIGIN:"), "mutant rejected for an unrelated reason")
        rejected = True
    require(rejected and not (temp / "forbidden.o").exists(), "public compiler admitted changed LLVM")
    row.update(rehashed_llvm_rejected=True, mutant_sha256=sha(mutant.encode()))
    (temp / "leak.ll").write_text(mutant)
    commands = [[clang, "-x", "ir", "-O3", "-c", str(temp / "leak.ll"), "-o", str(temp / "leak.o")]]
    for label, source in (("positive", obj), ("negative", temp / "leak.o")):
        commands.append([clang, "-std=c11", "-O3", str(observer), str(source),
                         *WRAP_FLAGS, "-o", str(temp / label)])
    for command in commands:
        record = execute(command)
        row["commands"].append(record)
        successful(record)
    positive = execute([temp / "positive"])
    row["positive"] = positive
    require(json.loads(successful(positive)) == {"allocations": 7, "frees": 7, "live": 0, "refusals": 1},
            "positive allocator events differ")
    negative = execute([temp / "negative"])
    row["negative"] = negative
    require(type(negative.get("returncode")) is int and negative["returncode"] == 1
            and "capture_error" not in negative and json.loads(negative["stdout"]) ==
            {"allocations": 7, "frees": 0, "live": 7, "refusals": 1},
            "compiled missing-free mutant escaped the observer")
    row["artifacts"] = {name: identity(temp / name) for name in ("owned.o", "positive", "leak.o", "negative")}
    row["status"] = "passed"
    return row


def qualify(*, clang="clang", rustc=None, artifact_directory=None):
    report = {"schema": "hepta.hia.program-perf-qualification.v1", "ok": False,
        "status": "blocked", "phase": "preflight", "protocol": PROTOCOL,
        "protocol_sha256": sha(wire(PROTOCOL)), "inputs": input_hashes(),
        "compiler_tree_sha256": compiler_hash(), "source_sha256": sha(SOURCE.encode()),
        "raw_samples": [], "native_receipts": {}, "compile_wall_seconds": {},
        "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "claims": {"source_free_core_executed": False, "finite_correctness_checked": False,
            "actual_owned_cleanup_checked": False, "host_performance_gate_passed": False,
            "whole_language_performance_qualified": False, "universal_rust_superiority_proved": False,
            "physical_device_qualified": False, "backend_refinement_proved": False}}
    affinity = None
    try:
        require(platform.system() == "Linux" and platform.machine() == "x86_64", "Linux x86-64 required")
        report["git_commit"] = successful(execute(["git", "-C", ROOT, "rev-parse", "HEAD"])).strip()
        require(not successful(execute(["git", "-C", ROOT, "status", "--porcelain", "--untracked-files=no"])).strip(),
                "commit tracked implementation before measurement")
        affinity = os.sched_getaffinity(0)
        os.sched_setaffinity(0, {min(affinity)})
        report["environment"] = {"system": platform.system(), "machine": platform.machine(),
            "kernel": platform.release(), "python": platform.python_version(),
            "selected_cpu": min(affinity), "allowed_cpus_before": sorted(affinity),
            "scope": "shared host; affinity is not exclusive CPU ownership",
            "scheduler": scheduler_environment(),
            "loadavg_before": list(os.getloadavg())}
        report["phase"] = "build"
        with artifact_workspace(artifact_directory, report) as temp:
            start = time.perf_counter()
            core = lower_source(SOURCE, path=str(SOURCE_PATH), module="hia_benchmarks")
            report["core_sha256"] = core.sha256
            ir = emit_program_llvm(core)
            report["llvm_sha256"] = ir.sha256
            (temp / "program.hia").write_bytes(core.canonical_bytes)
            (temp / "program.ll").write_text(ir.text)
            report["compile_wall_seconds"]["source_to_verified_hia_and_llvm"] = time.perf_counter() - start
            # Rust verifies its own reference independently; it does not admit HIA.
            analysis = analyze(SOURCE, str(SOURCE_PATH), native=False, crate_type="cdylib")
            require(analysis.report["ok"], "same-source Rust reference failed frontend")
            report["generated_rust_sha256"] = sha(analysis.rust.encode())
            (temp / "generated.rs").write_text(analysis.rust)
            (temp / "handwritten.rs").write_text(RUST_REFERENCE)
            libraries = {name: temp / (name + ".so") for name in BACKENDS}
            actions = {
                "llvm": lambda: compile_program_llvm(ir, program=core, output=libraries["llvm"], clang=clang),
                "rust": lambda: compile_rust(analysis.rust, rustc=rustc, crate_type="cdylib", output=libraries["rust"]),
                "handwritten_rust": lambda: compile_rust(RUST_REFERENCE, rustc=rustc, crate_type="cdylib", output=libraries["handwritten_rust"])}
            for name, action in actions.items():
                start = time.perf_counter()
                receipt = action()
                report["compile_wall_seconds"][name] = time.perf_counter() - start
                report["native_receipts"][name] = receipt
                require(receipt["ok"], name + " native build failed")
            report["phase"] = "correctness"
            report["correctness"] = {}
            check_correctness(libraries, observation=report["correctness"])
            report["claims"]["finite_correctness_checked"] = True
            report["claims"]["source_free_core_executed"] = True
            report["resource_observation"] = {}
            observe(ir, core, temp, clang, observation=report["resource_observation"])
            report["claims"]["actual_owned_cleanup_checked"] = True
            (temp / "driver.c").write_text(DRIVER)
            report["driver_build"] = [execute(command) for command in driver_commands(clang, temp)]
            for record in report["driver_build"]:
                successful(record)
            paths = {**libraries, "driver": temp / "driver"}
            report["artifacts"] = {name: identity(path) for name, path in paths.items()}
            for kernel in KERNELS:
                timed_checksum(kernel)
            report["phase"] = "measurement"
            for group, kernel, backend in sample_order():
                execution = execute([temp / "driver", libraries[backend], kernel])
                report["failed_sample"] = {"group": group, "kernel": kernel, "backend": backend,
                    "sample_index": len(report["raw_samples"]), "execution": execution}
                measured = json.loads(successful(execution))
                report["raw_samples"].append({**report["failed_sample"], **measured,
                    "library_sha256": report["artifacts"][backend]["sha256"],
                    "driver_sha256": report["artifacts"]["driver"]["sha256"]})
                del report["failed_sample"]
                print(json.dumps({"progress": len(report["raw_samples"]), "total": 63,
                                  "kernel": kernel, "backend": backend}), file=sys.stderr, flush=True)
            report["evaluation"] = evaluate_samples(report["raw_samples"])
            report["interference_observations"] = interference_summary(report["raw_samples"])
            require(all(identity(path) == report["artifacts"][name] for name, path in paths.items()),
                    "native artifacts changed during measurement")
            require(compiler_hash() == report["compiler_tree_sha256"] and input_hashes() == report["inputs"],
                    "compiler or experiment inputs changed during measurement")
            report["ok"], report["status"] = report["evaluation"]["ok"], report["evaluation"]["status"]
            report["claims"]["host_performance_gate_passed"] = report["ok"]
            report["phase"] = "complete"
    except (ValueError, OSError, RuntimeError, KeyError, TypeError) as error:
        report["diagnostic"] = {"message": str(error)}
        if isinstance(error, NativeCommandFailed):
            report["failed_command"] = error.record
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
    parser.add_argument("--rustc")
    parser.add_argument("--artifact-directory", type=Path,
                        help="retain exact build inputs and measured native artifacts in a new directory")
    parser.add_argument("--describe-protocol", action="store_true")
    args = parser.parse_args(argv)
    if args.describe_protocol:
        result = {"protocol": PROTOCOL, "protocol_sha256": sha(wire(PROTOCOL)), "inputs": input_hashes()}
    else:
        result = qualify(clang=args.clang, rustc=args.rustc, artifact_directory=args.artifact_directory)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x") as stream:
            json.dump(result, stream, sort_keys=True, indent=2)
            stream.write("\n")
    else:
        print(json.dumps(result, sort_keys=True, indent=2))
    return 0 if args.describe_protocol or result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
