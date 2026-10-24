#!/usr/bin/env python3
"""Reproducible native, C ABI, freestanding, and optional microbenchmark checks.

The benchmark Rust source is handwritten, not Hepta's emitted Rust. A successful
run qualifies only the recorded host/targets and fixtures, not a language-wide
performance, safety, hardware, or agent-productivity claim.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import shutil
import statistics
import subprocess
import sys
import tempfile
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
RUST_FLAGS = ["--edition=2021", "-C", "opt-level=3", "-C", "overflow-checks=yes",
              "-C", "panic=abort", "-C", "codegen-units=1"]
LAYOUT_FIELDS = {
    "AbiRecord": ("tag", "count", "score"),
    "AbiPair": ("low", "high"),
    "AbiFloatPair": ("x", "y"),
}


def rustc_path() -> str | None:
    configured = os.environ.get("RUSTC")
    if configured:
        return shutil.which(configured) or (configured if Path(configured).is_file() else None)
    found = shutil.which("rustc")
    if found:
        return found
    local = ROOT.parent / "toolchains/rust-1.90.0/bin/rustc"
    return str(local) if local.is_file() else None


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def compiler_identity() -> dict[str, str]:
    return {str(path.relative_to(ROOT)): digest(path)
            for path in sorted((ROOT / "hepta").glob("*.py"))}


class Runner:
    def __init__(self, rustc: str):
        self.rustc = rustc
        self.env = dict(os.environ, RUSTC=rustc)
        self.commands: list[dict[str, Any]] = []

    def run(self, args: list[str | Path], timeout: int = 120) -> subprocess.CompletedProcess[str]:
        command = [str(arg) for arg in args]
        result = subprocess.run(command, cwd=ROOT, env=self.env, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=timeout)
        self.commands.append({"argv": command, "exit_code": result.returncode,
                              "stdout": result.stdout, "stderr": result.stderr})
        if result.returncode:
            raise RuntimeError(f"Command failed ({result.returncode}): {command!r}\n"
                               f"{result.stdout}\n{result.stderr}")
        return result

    def hepta(self, *args: str | Path) -> subprocess.CompletedProcess[str]:
        return self.run([sys.executable, "-m", "hepta", *args])


def native_abi(runner: Runner, directory: Path) -> dict[str, Any]:
    """Exercise the actual CLI-built staticlib, then independently probe layout."""
    source = ROOT / "examples/ffi/abi.hepta"
    header = directory / "abi.h"
    emitted = directory / "abi.rs"
    library = directory / "libhepta_abi.a"
    cc = shutil.which("gcc") or shutil.which("cc")
    if not cc:
        raise RuntimeError("A C compiler is required for native ABI validation")
    runner.hepta("header", source, "--output", header)
    runner.hepta("emit", source, "--output", emitted)
    runner.hepta("build", source, "--crate-type", "staticlib", "--output", library)
    harness = ROOT / "examples/ffi/harness.c"
    system_libs = ["-ldl", "-lpthread", "-lm", "-lrt", "-lutil"]
    binary = directory / "abi-native"
    runner.run([cc, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-I", directory,
                harness, library, *system_libs, "-o", binary])
    actual = json.loads(runner.run([binary]).stdout)

    # These functions observe the exact generated Rust types. They are a test
    # supplement, never a language escape hatch, and never modify the source.
    probes: list[str] = []
    for struct, fields in LAYOUT_FIELDS.items():
        for label, expression in [("size", f"core::mem::size_of::<H_{struct}>()"),
                                  ("align", f"core::mem::align_of::<H_{struct}>()")]:
            probes.append(f'#[unsafe(no_mangle)] pub extern "C" fn '
                          f'hepta_layout_{struct}_{label}() -> usize {{ {expression} }}')
        for field in fields:
            probes.append(f'#[unsafe(no_mangle)] pub extern "C" fn '
                          f'hepta_layout_{struct}_{field}() -> usize '
                          f'{{ core::mem::offset_of!(H_{struct}, h_{field}) }}')
    supplemented = directory / "abi_layout.rs"
    supplemented.write_text(emitted.read_text() + "\n" + "\n".join(probes) + "\n")
    layout_library = directory / "libhepta_layout.a"
    runner.run([runner.rustc, supplemented, *RUST_FLAGS, "--crate-type", "staticlib",
                "-o", layout_library])
    layout_binary = directory / "abi-layout"
    runner.run([cc, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-I", directory,
                "-DHEPTA_LAYOUT_PROBE", harness, layout_library, *system_libs,
                "-o", layout_binary])
    layout = json.loads(runner.run([layout_binary]).stdout)
    return {"status": "passed", "native_staticlib": actual, "layout": layout,
            "structs": list(LAYOUT_FIELDS), "source_sha256": digest(source),
            "emitted_rust_sha256": digest(emitted), "generated_header_sha256": digest(header),
            "scope": "Current host; ordinary aggregates, by-value calls and returns; not varargs, packed or bitfields"}


def no_std_objects(runner: Runner, directory: Path) -> dict[str, Any]:
    source = ROOT / "benchmarks/kernels.hepta"
    targets: dict[str, Any] = {}
    for target in (None, "aarch64-unknown-linux-gnu", "thumbv7em-none-eabi", "x86_64-pc-windows-msvc"):
        label = target or "host"
        if target:
            libdir = Path(runner.run([runner.rustc, "--print", "target-libdir", "--target", target]).stdout.strip())
            if not libdir.is_dir() or not list(libdir.glob("libcore-*.rlib")):
                targets[label] = {"status": "not_run", "reason": "Rust core component is not installed"}
                continue
        obj = directory / f"kernels-{label}.o"
        command: list[str | Path] = ["build", source, "--crate-type", "obj", "--no-std", "--output", obj]
        if target:
            command += ["--target", target]
        runner.hepta(*command)
        symbols = runner.run(["nm", "--undefined-only", obj]).stdout
        forbidden = ("__rust_alloc", "__rust_realloc", "__rust_dealloc", "__rg_alloc",
                     "malloc", "calloc", "realloc", "pthread_create", "tokio")
        if any(name in symbols for name in forbidden):
            raise RuntimeError(f"Unexpected allocator/scheduler dependency in {label}: {symbols}")
        identity = runner.run(["file", obj]).stdout.strip() if shutil.which("file") else None
        targets[label] = {"status": "passed", "qualification": "object compilation only",
                          "sha256": digest(obj), "undefined_symbols": symbols.splitlines(),
                          "object_identity": identity, "executed_on_target": False}
    return {"status": "passed", "targets": targets,
            "scope": "No allocator/scheduler symbol dependencies in these two kernels; no board, IRQ or DMA validation"}


def compile_benchmarks(runner: Runner, directory: Path) -> dict[str, Path]:
    cc = shutil.which("gcc") or shutil.which("cc")
    if not cc:
        raise RuntimeError("A C compiler is required for benchmarks")
    hepta = directory / "bench-hepta.o"
    rust = directory / "bench-rust.o"
    c = directory / "bench-c.o"
    runner.hepta("build", ROOT / "benchmarks/kernels.hepta", "--crate-type", "obj",
                  "--no-std", "--output", hepta)
    runner.run([runner.rustc, ROOT / "benchmarks/baseline.rs", *RUST_FLAGS,
                "--emit=obj", "--crate-type", "lib", "-o", rust])
    runner.run([cc, "-std=c11", "-O3", "-c", ROOT / "benchmarks/baseline.c", "-o", c])
    driver = directory / "driver.o"
    runner.run([cc, "-std=c11", "-O3", "-Wall", "-Wextra", "-Werror", "-c",
                ROOT / "benchmarks/driver.c", "-o", driver])
    binaries = {}
    for name, obj in (("hepta", hepta), ("rust", rust), ("c", c)):
        binary = directory / f"bench-{name}"
        runner.run([cc, driver, obj, "-o", binary])
        binaries[name] = binary
    return binaries


def kernel_correctness(runner: Runner, binaries: dict[str, Path]) -> dict[str, Any]:
    counts = [1, 3, 31, 32, 33, 127, 1025, 8193]
    for count in counts:
        checksums = []
        for binary in binaries.values():
            # The driver validates both kernels and zero-length calls before timing.
            checksums.append(json.loads(runner.run([binary, "sum", str(count), "1"]).stdout)["checksum"])
        if len(set(checksums)) != 1:
            raise RuntimeError(f"Independent kernel results disagree at count {count}")
    return {"status": "passed", "counts": counts, "zero_length_also_checked": True,
            "compared": list(binaries), "semantics": "u64 sum modulo 2^64; non-overlapping copy"}


def safe_borrowed(runner: Runner, directory: Path) -> dict[str, Any]:
    """Run safe-slice kernels through real borrow checking and native execution."""
    hepta_binary = directory / "borrowed-hepta"
    rust_binary = directory / "borrowed-rust"
    runner.hepta("build", ROOT / "benchmarks/borrowed.hepta", "--output", hepta_binary)
    runner.run([runner.rustc, ROOT / "benchmarks/borrowed.rs", *RUST_FLAGS, "-o", rust_binary])
    runner.run([hepta_binary])
    runner.run([rust_binary])
    return {"status": "passed", "native_execution": True,
            "features": ["immutable slice borrow", "mutable slice borrow", "array-to-slice coercion",
                         "bounds-checked indexing", "wrapping sum", "stack arrays", "no allocation resource clauses"],
            "scope": "Correctness and native borrow checking of this fixture; not a timed safe-slice benchmark"}


def kernel_codegen(runner: Runner, directory: Path) -> dict[str, Any]:
    """Compare function bytes, excluding crate metadata and the panic handler."""
    if not shutil.which("objcopy"):
        return {"status": "not_run", "reason": "objcopy is unavailable"}
    functions = {}
    for function in ("hepta_sum", "hepta_copy"):
        versions = {}
        for implementation in ("hepta", "rust"):
            output = directory / f"{implementation}-{function}.text"
            obj = directory / f"bench-{implementation}.o"
            runner.run(["objcopy", "--dump-section", f".text.{function}={output}", obj])
            versions[implementation] = {"bytes": output.stat().st_size, "sha256": digest(output)}
        functions[function] = {"implementations": versions,
                               "identical_function_bytes": versions["hepta"] == versions["rust"]}
    return {"status": "completed", "functions": functions,
            "scope": "These two host function text sections only, with the recorded compiler and flags; entire objects may differ."}


def benchmarks(runner: Runner, binaries: dict[str, Path], trials: int) -> dict[str, Any]:
    seed = 20261024
    rng = random.Random(seed)
    prefix: list[str] = []
    affinity = None
    if hasattr(os, "sched_getaffinity") and shutil.which("taskset"):
        affinity = min(os.sched_getaffinity(0))
        prefix = ["taskset", "-c", str(affinity)]
    raw: list[dict[str, Any]] = []
    summaries = []
    for count in [8192, 1048576]:
        iterations = 134217728 // count
        for kernel in ["sum", "copy"]:
            grouped: dict[str, list[float]] = {name: [] for name in binaries}
            for trial in range(trials):
                order = list(binaries)
                rng.shuffle(order)
                for name in order:
                    result = json.loads(runner.run([*prefix, binaries[name], kernel,
                                                   str(count), str(iterations)]).stdout)
                    result.update({"implementation": name, "trial": trial})
                    raw.append(result)
                    grouped[name].append(result["ns_per_element"])
            stats = {name: {"median_ns_per_element": statistics.median(values),
                            "min_ns_per_element": min(values), "max_ns_per_element": max(values)}
                     for name, values in grouped.items()}
            summaries.append({"kernel": kernel, "elements": count, "implementations": stats,
                              "hepta_over_rust_median_time": stats["hepta"]["median_ns_per_element"] /
                                                             stats["rust"]["median_ns_per_element"]})
    return {"status": "completed", "trials": trials, "randomization_seed": seed,
            "cpu_affinity": affinity, "rust_flags": RUST_FLAGS, "c_flags": ["-O3"],
            "lto": False, "samples": raw, "summary": summaries,
            "interpretation": "Host microbenchmarks only; ratios below 1 mean faster observed Hepta time. Shared-host noise is not controlled and no universal speed advantage is established."}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/native-validation.json")
    parser.add_argument("--bench", action="store_true", help="run timed independent C/Rust/Hepta comparisons")
    parser.add_argument("--trials", type=int, default=7)
    args = parser.parse_args(argv)
    if args.trials < 3:
        parser.error("--trials must be at least 3")
    rustc = rustc_path()
    if not rustc:
        parser.error("No rustc found; install Rust or set RUSTC to its executable")
    runner = Runner(rustc)
    report: dict[str, Any] = {"schema": "hepta.native-validation.v1",
                              "created_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
                              "host": platform.platform(), "machine": platform.machine(),
                              "compiler_sources": compiler_identity(),
                              "status": "running", "results": {}}
    exit_code = 0
    try:
        report["rustc"] = runner.run([rustc, "--version", "--verbose"]).stdout
        provenance = ROOT.parent / "toolchains/rust-1.90.0-provenance.json"
        if provenance.is_file() and Path(rustc).resolve().is_relative_to(ROOT.parent / "toolchains"):
            report["toolchain_component_provenance"] = json.loads(provenance.read_text())
        report["c_compiler"] = runner.run([shutil.which("gcc") or "cc", "--version"]).stdout
        with tempfile.TemporaryDirectory(prefix="hepta-native-") as temporary:
            directory = Path(temporary)
            report["results"]["c_abi"] = native_abi(runner, directory)
            report["results"]["no_std"] = no_std_objects(runner, directory)
            binaries = compile_benchmarks(runner, directory)
            report["results"]["kernel_correctness"] = kernel_correctness(runner, binaries)
            report["results"]["safe_borrowed"] = safe_borrowed(runner, directory)
            report["results"]["kernel_codegen"] = kernel_codegen(runner, directory)
            report["results"]["benchmarks"] = benchmarks(runner, binaries, args.trials) if args.bench else {
                "status": "not_run", "reason": "Pass --bench to collect timing evidence"}
        report["status"] = "passed"
    except (RuntimeError, OSError, subprocess.TimeoutExpired) as error:
        report["status"] = "failed"
        report["error"] = str(error)
        exit_code = 1
    report["sources"] = {str(path.relative_to(ROOT)): digest(path)
                         for folder in (ROOT / "benchmarks", ROOT / "examples/ffi")
                         for path in sorted(folder.glob("*")) if path.is_file()}
    report["commands"] = runner.commands
    if compiler_identity() != report["compiler_sources"]:
        report["status"] = "failed"
        report["error"] = "Compiler sources changed during validation; rerun against a stable source snapshot."
        exit_code = 1
    report["limitations"] = ["Native execution covers the recorded host only.",
                              "AArch64/Cortex-M/Windows results are compilation evidence, not target execution.",
                              "No GPU, MMIO, DMA, interrupts, packed layouts, bitfields, varargs or long-lived callbacks were qualified.",
                              "FFI pointer preconditions remain caller obligations.",
                              "No general Rust performance superiority or AI-agent productivity claim follows from these fixtures."]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"status": report["status"], "report": str(args.output.resolve()),
                      "error": report.get("error")}, indent=2))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
