#!/usr/bin/env python3
"""Representative native kernels, with all timings and regressions retained."""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import platform
import random
import shutil
import statistics
import sys
import tempfile

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from hepta.c_backend import compile_c, emit_c
from hepta.checker import check
from hepta.parser import parse
from tools.validate import ROOT, RUST_FLAGS, Runner, compiler_identity, digest, rustc_path

KERNELS = ("fnv1a", "histogram", "dot", "binary_search")


def build_suite(runner, directory):
    source = ROOT / "benchmarks/representative.hepta"
    objects = {name: directory / (name + ".o") for name in ("hepta_rust", "rust", "hepta_c")}
    hepta_build = json.loads(runner.hepta("build", source, "--crate-type", "obj", "--no-std",
                                         "--output", objects["hepta_rust"]).stdout)
    runner.run([runner.rustc, ROOT / "benchmarks/representative.rs", *RUST_FLAGS,
                "--emit=obj", "--crate-type", "lib", "-o", objects["rust"]])
    program = parse(source.read_text(), str(source))
    checked = check(program)
    if not checked.ok:
        raise RuntimeError(str([d.to_dict() for d in checked.diagnostics]))
    c_source = emit_c(program, checked, crate_type="obj")
    c_build = compile_c(c_source, crate_type="obj", output=objects["hepta_c"])
    if not c_build["ok"]:
        raise RuntimeError(str(c_build["diagnostics"]))
    driver = directory / "driver.o"
    runner.run(["gcc", "-std=c11", "-O3", "-Wall", "-Wextra", "-Werror", "-c",
                ROOT / "benchmarks/representative_driver.c", "-o", driver])
    binaries = {}
    for name, obj in objects.items():
        binary = directory / ("run-" + name)
        runner.run(["gcc", driver, obj, "-lm", "-o", binary])
        binaries[name] = binary
    return binaries, {"hepta_rust": hepta_build, "hepta_c": c_build,
                      "independent_rust_flags": RUST_FLAGS,
                      "undefined_symbols": {name: runner.run(["nm", "--undefined-only", obj]).stdout.splitlines()
                                            for name, obj in objects.items()}}


def correctness(runner, binaries):
    counts = [1, 3, 31, 255, 257, 4099]
    for kernel in KERNELS:
        for count in counts:
            values = []
            for executable in binaries.values():
                values.append(json.loads(runner.run([executable, kernel, str(count), "1"]).stdout)["reference_checksum"])
            if len(set(values)) != 1:
                raise RuntimeError(f"Differential correctness failed for {kernel}/{count}")
    return {"status": "passed", "kernels": KERNELS, "counts": counts,
            "zero_length_also_checked": True, "implementations": list(binaries),
            "search_oracle": "sorted-query linear merge over a table with duplicates and gaps"}


def function_bytes(runner, directory):
    if not shutil.which("objcopy"):
        return {"status": "not_run", "reason": "objcopy unavailable"}
    result = {}
    for kernel in KERNELS:
        shapes = {}
        for name in ("hepta_rust", "rust"):
            data = directory / f"{name}-{kernel}.text"
            runner.run(["objcopy", "--dump-section", f".text.hepta_{kernel}={data}", directory / (name + ".o")])
            shapes[name] = {"bytes": data.stat().st_size, "sha256": digest(data)}
        result[kernel] = {"implementations": shapes, "identical_function_bytes": shapes["hepta_rust"] == shapes["rust"]}
    return {"status": "completed", "functions": result, "scope": "Function text sections only, not complete object or relocation equivalence"}


def measure(runner, binaries, trials):
    rng = random.Random(20261024)
    affinity = min(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") and shutil.which("taskset") else None
    prefix = ["taskset", "-c", str(affinity)] if affinity is not None else []
    samples, summary, regressions = [], [], []
    for count in (4096, 262144):
        for kernel in KERNELS:
            iterations = 512 if kernel == "binary_search" else max(1, (1 << 26) // count)
            grouped = {name: [] for name in binaries}
            for trial in range(trials):
                order = list(binaries)
                rng.shuffle(order)
                for name in order:
                    result = json.loads(runner.run([*prefix, binaries[name], kernel, str(count), str(iterations)]).stdout)
                    result.update(implementation=name, trial=trial)
                    samples.append(result)
                    grouped[name].append(result["ns_per_operation"])
            stats = {name: {"median_ns_per_operation": statistics.median(values),
                            "min_ns_per_operation": min(values), "max_ns_per_operation": max(values)}
                     for name, values in grouped.items()}
            ratios = {name: stats[name]["median_ns_per_operation"] / stats["rust"]["median_ns_per_operation"]
                      for name in ("hepta_rust", "hepta_c")}
            row = {"kernel": kernel, "elements": count, "operation": "query" if kernel == "binary_search" else "element",
                   "implementations": stats, "time_relative_to_independent_rust": ratios}
            summary.append(row)
            for name, ratio in ratios.items():
                if ratio > 1:
                    regressions.append({"kernel": kernel, "elements": count, "implementation": name,
                                        "observed_median_time_ratio": ratio})
    return {"status": "completed", "trials": trials, "seed": 20261024, "cpu_affinity": affinity,
            "samples": samples, "summary": summary, "all_observed_slowdowns": regressions,
            "interpretation": "Ratios above 1 are slower observed times. All samples and slowdowns are retained; shared-host noise and compiler differences preclude universal superiority claims."}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/representative-benchmarks.json")
    parser.add_argument("--trials", type=int, default=7)
    parser.add_argument("--correctness-only", action="store_true")
    args = parser.parse_args(argv)
    if args.trials < 3:
        parser.error("At least 3 trials are required")
    rustc = rustc_path()
    if not rustc:
        parser.error("Set RUSTC to the pinned native Rust compiler")
    runner = Runner(rustc)
    report = {"schema": "hepta.representative-benchmarks.v1", "created_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
              "host": platform.platform(), "compiler_sources": compiler_identity(), "status": "running",
              "contract": {"allocation": "All driver allocation is outside timed regions; kernels allocate nothing",
                           "pointer_safety": "All implementations use the same raw-pointer caller obligations",
                           "rust_comparison": "Independent handwritten Rust, same rustc/flags/target; no LTO",
                           "c_comparison": "Hepta C11 backend uses GCC, a different optimizer; not an LLVM-independent claim"}}
    try:
        report["rustc"] = runner.run([rustc, "--version", "--verbose"]).stdout
        report["gcc"] = runner.run(["gcc", "--version"]).stdout
        with tempfile.TemporaryDirectory(prefix="hepta-representative-") as td:
            directory = Path(td)
            binaries, report["builds"] = build_suite(runner, directory)
            report["correctness"] = correctness(runner, binaries)
            report["function_bytes"] = function_bytes(runner, directory)
            report["measurements"] = {"status": "not_run"} if args.correctness_only else measure(runner, binaries, args.trials)
        report["status"] = "passed"
    except Exception as error:
        report["status"] = "failed"
        report["error"] = str(error)
    if compiler_identity() != report["compiler_sources"]:
        report["status"] = "failed"
        report["error"] = "Compiler source changed during measurement; rerun a stable snapshot"
    report["sources"] = {str(p.relative_to(ROOT)): digest(p) for p in [ROOT / "benchmarks/representative.hepta", ROOT / "benchmarks/representative.rs", ROOT / "benchmarks/representative_driver.c"]}
    report["commands"] = runner.commands
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"status": report["status"], "report": str(args.output.resolve()), "error": report.get("error")}, indent=2))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
