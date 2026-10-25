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
from pathlib import Path, PurePosixPath, PureWindowsPath
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
from tools.evidence_checks import command as check_command, is_sha, native_build, normalized_errors, require, strict_equal, text

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


def target_shape(target):
    require(text(target), "native target triple missing")
    arch = {"amd64":"x86_64", "arm64":"aarch64"}.get(target.split("-")[0], target.split("-")[0])
    system = ("Windows" if any(token in target for token in ("windows", "mingw", "win32")) else
              "Darwin" if "darwin" in target else "Linux" if "linux" in target else None)
    require(arch in {"x86_64", "aarch64"} and system is not None, "unqualified host target triple")
    return system, arch


@normalized_errors
def validate_report(report):
    source, harness, probes, denominator = Matrix(SEED, SHAPES, VALUES).generate()
    claims = {"actual_reported_host_executed": True, "cross_host_results_inferred": False,
              "physical_board_executed": False, "gpu_device_executed": False, "all_abi_features_qualified": False}
    if (report.get("schema") != "hepta.native-host.v1" or report.get("status") != "passed"
            or report.get("compiler_sha256") != compiler_hash() or not strict_equal(report.get("matrix"), denominator)
            or report.get("source_sha256") != sha(source.encode()) or report.get("harness_sha256") != sha(harness.encode())
            or report.get("layout_probes_sha256") != sha(probes.encode()) or not strict_equal(report.get("claims"), claims)):
        raise ValueError("Host qualification identity or scope differs")
    generated = analyze(source, "<native-host-matrix>", native=False, no_std=True, crate_type="obj")
    require(generated.report["ok"] is True, "frozen host source no longer checks")
    require(report.get("header_sha256") == sha(emit_header(generated.program).encode()), "generated ABI header differs")
    host = report.get("host", {})
    require(host.get("system") in {"Linux", "Windows", "Darwin"} and host.get("machine") in {"x86_64", "aarch64"}
            and host.get("execution") == "native_host_process" and text(host.get("kernel_release")) and text(host.get("python")),
            "actual host identity incomplete")
    cc = report.get("c_compiler", {})
    require(text(cc.get("path")) and text(cc.get("version")) and is_sha(cc.get("binary_sha256")), "C compiler identity incomplete")
    expected_host = (host["system"], host["machine"])
    require(target_shape(cc.get("target")) == expected_host, "C compiler target differs from reported host")
    frontend = report.get("frontend", {})
    require(frontend.get("ok") is True and frontend.get("compiler_sha256") == report["compiler_sha256"]
            and frontend.get("source_sha256") == sha(source.encode())
            and frontend.get("interface_sha256") == generated.report["interface_sha256"]
            and strict_equal(frontend.get("profile"), generated.report["profile"])
            and strict_equal(frontend.get("claims"), generated.report["claims"])
            and strict_equal(frontend.get("assumptions"), generated.report["assumptions"]), "host frontend identity or assumptions differ")
    require(frontend.get("checks") == {"syntax":"passed", "types_effects_resources":"passed_in_supported_subset", "rust_borrows_types":"rustc_checked"},
            "host source did not receive native reference checks")
    native_build(frontend.get("backend"), "rust", check_only=True, crate_type="obj", source_sha256=sha(generated.rust.encode()))
    native = report.get("native_object", {})
    native_build(native, "rust", check_only=False, crate_type="obj", source_sha256=sha((generated.rust + "\n" + probes).encode()))
    require(target_shape(native["target"]) == expected_host and native["target"] == native["toolchain"].get("host")
            and strict_equal(native["toolchain"], frontend["backend"]["toolchain"])
            and native["target"] == frontend["backend"]["target"], "Rust object target/toolchain differs from actual host checks")
    require({"opt-level=3", "overflow-checks=yes", "panic=abort", "codegen-units=1"}.issubset(native["flags"]), "host object compilation flags differ")
    executions = report.get("executions", [])
    if len(executions) != 2 or [e.get("optimization") for e in executions] != ["-O0", "-O2"]:
        raise ValueError("Both native host optimization profiles must execute")
    for result in executions:
        if (type(result.get("returncode")) is not int or result["returncode"] != 0 or result.get("layout_checked") is not True
                or not strict_equal(result.get("observed"), {"status": "passed", "foreign_calls": denominator["expected_foreign_calls_per_run"]})):
            raise ValueError("Native host ABI execution did not complete")
    hashes = report.get("executable_sha256s", [])
    require(isinstance(hashes, list) and len(hashes) == 2 and all(is_sha(x) for x in hashes), "native driver artifact identities missing")
    negative = report.get("negative_control", {})
    if (negative.get("name") != "compiled_wrong_c_echo" or negative.get("status") != "rejected_as_expected"
            or type(negative.get("returncode")) is not int or negative["returncode"] == 0):
        raise ValueError("The compiled wrong host implementation was not rejected")
    needle = "ExpectedType0 abi_c_scalar0(ExpectedType0 value) { ++abi_calls; return value; }"
    wrong = harness.replace(needle, needle.replace("return value;", "return (ExpectedType0)(value ^ 1);"))
    require(negative.get("source_sha256") == sha(wrong.encode()) and is_sha(negative.get("artifact_sha256"))
            and negative["artifact_sha256"] not in hashes, "wrong-implementation source/artifact identity differs")
    commands = report.get("commands", [])
    require(isinstance(commands, list) and len(commands) == 8, "complete host compilation/execution trace required")
    for entry in commands:
        check_command(entry)
    require(commands[0]["argv"] == [cc["path"],"--version"] and commands[0]["returncode"] == 0 and commands[0]["stdout"].strip() == cc["version"], "C compiler version command differs")
    require(commands[1]["argv"] == [cc["path"],"-dumpmachine"] and commands[1]["returncode"] == 0 and commands[1]["stdout"].strip() == cc["target"], "C target command differs")
    path_type = PureWindowsPath if host["system"] == "Windows" else PurePosixPath
    directory = path_type(native["artifact"]).parent
    require(path_type(native["artifact"]).name == ("matrix.obj" if host["system"] == "Windows" else "matrix.o"), "host object path differs")
    cfile = str(directory / "matrix.c")
    extension = ".exe" if host["system"] == "Windows" else ""
    for index, optimization in enumerate(("-O0", "-O2")):
        executable = str(directory / ("host-matrix" + optimization + extension))
        expected = [cc["path"], "-std=c11", optimization, "-Wall", "-Wextra", "-Werror", "-pedantic-errors", "-DABI_LAYOUT", cfile, native["artifact"], "-o", executable]
        built, executed = commands[2 + index*2:4 + index*2]
        if (built["argv"] != expected or built["returncode"] != 0
                or executed["argv"] != [executable] or executed["returncode"] != 0):
            # Keep exact bytes in the diagnostic. Case, separators and OS-specific
            # path identities must not be normalized without an ABI-specific
            # justification: a relaxed equality could certify the wrong binary.
            mismatch = {"profile": optimization,
                        "expected_compile": expected, "actual_compile": built["argv"],
                        "expected_execute": [executable], "actual_execute": executed["argv"],
                        "compile_returncode": built["returncode"],
                        "execute_returncode": executed["returncode"]}
            raise ValueError("host compile/link/run trace differs: "
                             + json.dumps(mismatch, sort_keys=True)[:4000])
        require(strict_equal(json.loads(executed["stdout"]), executions[index]["observed"]), "raw host execution observation differs")
    bad_executable = str(directory / ("wrong" + extension))
    require(commands[6]["argv"] == [cc["path"], "-std=c11", "-O2", "-DABI_LAYOUT", cfile, native["artifact"], "-o", bad_executable]
            and commands[6]["returncode"] == 0 and commands[7]["argv"] == [bad_executable]
            and commands[7]["returncode"] == negative["returncode"] and "v_scalar0_0" in commands[7]["stderr"],
            "wrong echo must fail its actual native assertion, not fail to launch")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cc")
    parser.add_argument("--rustc", default=os.environ.get("RUSTC"))
    parser.add_argument("--expected-system", choices=["Linux", "Windows", "Darwin"])
    parser.add_argument("--expected-machine", choices=["x86_64", "aarch64"])
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/native-host.json")
    args = parser.parse_args()
    observed = None
    try:
        report = run_host(cc=args.cc, rustc=args.rustc, expected_system=args.expected_system, expected_machine=args.expected_machine)
        observed = report
        validate_report(report)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        report = {"schema": "hepta.native-host.v1", "status": "failed", "error": str(exc),
                  "host": {"system": platform.system(), "machine": platform.machine()},
                  "claims": {"cross_host_results_inferred": False}}
        if observed is not None:
            # A completed but rejected run is NOT evidence of qualification.
            # Retain the unqualified raw command transcript so Windows/macOS
            # mismatches can be diagnosed without changing verification rules.
            report["unqualified_observations"] = {
                "commands": observed.get("commands", []),
                "c_compiler": observed.get("c_compiler"),
                "native_object_artifact": observed.get("native_object", {}).get("artifact"),
                "executions": observed.get("executions"),
                "negative_control": observed.get("negative_control"),
                "source_sha256": observed.get("source_sha256"),
            }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"status": report["status"], "output": str(args.output), "error": report.get("error")}))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
