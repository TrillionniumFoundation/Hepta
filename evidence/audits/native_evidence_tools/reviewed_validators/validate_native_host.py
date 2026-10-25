#!/usr/bin/env python3
"""Execute a bidirectional C ABI matrix on the actual host compiler/linker.

The same generated matrix runs on Linux, Windows/MSVC clang, and macOS. This
command never substitutes cross compilation or QEMU for host execution. A
workflow declaration alone is not qualification evidence for another host.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from hepta.backend import compile_rust, emit_header
from hepta.pipeline import analyze, compiler_hash
from tools.abi_fuzz import Matrix

SEED, SHAPES, VALUES = 20261025, 36, 3


def sha(data):
    return hashlib.sha256(data).hexdigest()


def run_host(*, cc=None, rustc=None, expected_system=None, expected_machine=None):
    system, machine = platform.system(), platform.machine().lower()
    normalized = {"amd64": "x86_64", "arm64": "aarch64"}.get(machine, machine)
    if expected_system is not None and system != expected_system:
        raise ValueError("Requested actual host system does not match")
    if expected_machine is not None and normalized != expected_machine:
        raise ValueError("Requested actual host architecture does not match")
    compiler = shutil.which(cc or ("clang" if system in {"Windows", "Darwin"} else "gcc"))
    if not compiler:
        raise ValueError("An actual host C compiler is required")
    commands = []
    def run(argv, *, positive=True):
        argv = list(map(str, argv))
        start = time.monotonic()
        process = subprocess.run(argv, text=True, capture_output=True, timeout=120)
        entry = {"argv": argv, "returncode": process.returncode,
                 "seconds": time.monotonic() - start,
                 "stdout": process.stdout, "stderr": process.stderr}
        commands.append(entry)
        if positive and process.returncode:
            raise RuntimeError("Host command failed: " + json.dumps(entry))
        return process
    version = run([compiler, "--version"]).stdout.strip()
    target = run([compiler, "-dumpmachine"]).stdout.strip()
    source, harness, probes, denominator = Matrix(SEED, SHAPES, VALUES).generate()
    before = compiler_hash()
    analysis = analyze(source, "<native-host-matrix>", rustc=rustc, native=True, no_std=True, crate_type="obj")
    if not analysis.report["ok"]:
        raise RuntimeError(json.dumps(analysis.report))
    with tempfile.TemporaryDirectory(prefix="hepta-native-host-") as td:
        directory = Path(td)
        header = emit_header(analysis.program)
        (directory / "matrix.h").write_text(header)
        cfile = directory / "matrix.c"
        cfile.write_text(harness)
        object_file = directory / ("matrix.obj" if system == "Windows" else "matrix.o")
        native = compile_rust(analysis.rust + "\n" + probes, rustc=rustc, crate_type="obj", output=object_file)
        if not native["ok"]:
            raise RuntimeError(json.dumps(native))
        executions = []
        executable_hashes = []
        for optimization in ("-O0", "-O2"):
            executable = directory / ("host-matrix" + optimization + (".exe" if system == "Windows" else ""))
            run([compiler, "-std=c11", optimization, "-Wall", "-Wextra", "-Werror", "-pedantic-errors",
                 "-DABI_LAYOUT", cfile, object_file, "-o", executable])
            executed = run([executable])
            observed = json.loads(executed.stdout)
            if observed != {"status": "passed", "foreign_calls": denominator["expected_foreign_calls_per_run"]}:
                raise ValueError("Actual host ABI denominator differs")
            executions.append({"optimization": optimization, "layout_checked": True,
                               "returncode": executed.returncode, "observed": observed})
            executable_hashes.append(sha(executable.read_bytes()))
        # The same full driver must reject a genuinely compiled wrong echo.
        needle = "ExpectedType0 abi_c_scalar0(ExpectedType0 value) { ++abi_calls; return value; }"
        if harness.count(needle) != 1:
            raise ValueError("Expected exactly one independent C negative-control site")
        wrong = harness.replace(needle, needle.replace("return value;", "return (ExpectedType0)(value ^ 1);"))
        cfile.write_text(wrong)
        bad_executable = directory / ("wrong" + (".exe" if system == "Windows" else ""))
        run([compiler, "-std=c11", "-O2", "-DABI_LAYOUT", cfile, object_file, "-o", bad_executable])
        wrong_run = run([bad_executable], positive=False)
        if wrong_run.returncode == 0:
            raise ValueError("The actual host oracle accepted the wrong C implementation")
        negative = {"name": "compiled_wrong_c_echo", "source_sha256": sha(wrong.encode()),
                    "artifact_sha256": sha(bad_executable.read_bytes()), "returncode": wrong_run.returncode,
                    "status": "rejected_as_expected"}
    if compiler_hash() != before:
        raise ValueError("Compiler changed while qualifying the host")
    return {"schema": "hepta.native-host.v1", "status": "passed",
            "created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "host": {"system": system, "machine": normalized, "kernel_release": platform.release(),
                     "python": platform.python_version(), "execution": "native_host_process"},
            "compiler_sha256": before, "c_compiler": {"path": compiler, "version": version,
                "target": target, "binary_sha256": sha(Path(compiler).read_bytes())},
            "matrix": denominator, "source_sha256": sha(source.encode()),
            "harness_sha256": sha(harness.encode()), "header_sha256": sha(header.encode()),
            "layout_probes_sha256": sha(probes.encode()), "frontend": analysis.report,
            "native_object": native, "executions": executions, "executable_sha256s": executable_hashes,
            "negative_control": negative, "commands": commands,
            "claims": {"actual_reported_host_executed": True, "cross_host_results_inferred": False,
                       "physical_board_executed": False, "gpu_device_executed": False,
                       "all_abi_features_qualified": False},
            "limits": ["Finite scalar/ordinary-record/nested-array/pointer and register-spill ABI matrix only.",
                       "Every host needs its own successful command and retained report.",
                       "A container/VM native process is not physical-board or MMIO/DMA/IRQ/GPU qualification.",
                       "Packed records, bitfields, varargs and foreign lifetime safety remain outside this matrix."]}


def validate_report(report):
    source, harness, probes, denominator = Matrix(SEED, SHAPES, VALUES).generate()
    claims = {"actual_reported_host_executed": True, "cross_host_results_inferred": False,
              "physical_board_executed": False, "gpu_device_executed": False, "all_abi_features_qualified": False}
    if (report.get("schema") != "hepta.native-host.v1" or report.get("status") != "passed"
            or report.get("compiler_sha256") != compiler_hash() or report.get("matrix") != denominator
            or report.get("source_sha256") != sha(source.encode()) or report.get("harness_sha256") != sha(harness.encode())
            or report.get("layout_probes_sha256") != sha(probes.encode()) or report.get("claims") != claims):
        raise ValueError("Host qualification identity or scope differs")
    executions = report.get("executions", [])
    if len(executions) != 2 or {e.get("optimization") for e in executions} != {"-O0", "-O2"}:
        raise ValueError("Both native host optimization profiles must execute")
    for result in executions:
        if (type(result.get("returncode")) is not int or result["returncode"] != 0 or result.get("layout_checked") is not True
                or result.get("observed") != {"status": "passed", "foreign_calls": denominator["expected_foreign_calls_per_run"]}):
            raise ValueError("Native host ABI execution did not complete")
    negative = report.get("negative_control", {})
    if (negative.get("name") != "compiled_wrong_c_echo" or negative.get("status") != "rejected_as_expected"
            or type(negative.get("returncode")) is not int or negative["returncode"] == 0):
        raise ValueError("The compiled wrong host implementation was not rejected")
    native = report.get("native_object", {})
    if (native.get("ok") is not True or native.get("status") != "rustc_checked" or native.get("check_only") is not False
            or type(native.get("artifact_bytes")) is not int or native["artifact_bytes"] < 1
            or native.get("artifact_sha256") != native.get("validation_artifact_sha256")
            or report.get("frontend", {}).get("ok") is not True):
        raise ValueError("A host object must actually compile and retain artifact identity")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cc")
    parser.add_argument("--rustc", default=os.environ.get("RUSTC"))
    parser.add_argument("--expected-system", choices=["Linux", "Windows", "Darwin"])
    parser.add_argument("--expected-machine", choices=["x86_64", "aarch64"])
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/native-host.json")
    args = parser.parse_args()
    try:
        report = run_host(cc=args.cc, rustc=args.rustc, expected_system=args.expected_system, expected_machine=args.expected_machine)
        validate_report(report)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        report = {"schema": "hepta.native-host.v1", "status": "failed", "error": str(exc),
                  "host": {"system": platform.system(), "machine": platform.machine()},
                  "claims": {"cross_host_results_inferred": False}}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"status": report["status"], "output": str(args.output), "error": report.get("error")}))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
