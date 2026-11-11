"""Execute and measure selected C++ RAII scopes through actual Hepta exports.

This qualifier exercises foreign std::vector and authored lifecycle probes.
It does not translate those implementations or prove arbitrary foreign safety.
"""
from __future__ import annotations

import argparse
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import statistics
import tempfile

from .backend import compile_rust, emit_header
from .cpp_contracts import _command, bridge_cpp_contracts
from .pipeline import analyze_project

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "cpp" / "scoped"
TIMING_CASES = {"native_cpp_lifecycle", "scoped_cpp_lifecycle", "hepta_scoped_lifecycle", "handle_cpp_lifecycle"}


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _process(process) -> dict:
    return {"returncode": process.returncode,
            "stdout_sha256": hashlib.sha256(process.stdout.encode()).hexdigest(),
            "stderr_sha256": hashlib.sha256(process.stderr.encode()).hexdigest()}


def qualify_scoped_cpp(directory: str | Path, *, cxx: str = "g++", rustc: str | None = None,
                       benchmark: bool = True, iterations: int = 100000) -> dict:
    if type(iterations) is not int or not 1 <= iterations <= 1000000:
        raise ValueError("iterations must be an integer in 1..1000000")
    root = Path(directory)
    root.mkdir(parents=True, exist_ok=True)
    inputs = {str(path.relative_to(ROOT)): _digest(path) for path in sorted(EXAMPLE.iterdir()) if path.is_file()}
    result = {"schema": "hepta.cpp-scoped-qualification.v1", "ok": False,
              "generated_at_utc": datetime.now(timezone.utc).isoformat(),
              "native_link_qualified": False, "foreign_cpp_library_rewritten": False,
              "whole_library_memory_safety_proved": False, "arbitrary_hepta_raii_supported": False,
              "scope": "selected_cpp_automatic_objects_with_scalar_or_POD_results",
              "inputs": inputs, "performance": {"status": "not_run"}}
    generated = root / "bridge"
    bridge = bridge_cpp_contracts(EXAMPLE / "foreign.hpp", EXAMPLE / "contract.json", generated,
                                  cxx=cxx, rustc=rustc)
    result["bridge_generation"] = bridge
    if not bridge["ok"]:
        return result
    shutil.copyfile(EXAMPLE / "consumer.hepta", generated / "consumer.hepta")
    checked = analyze_project(generated / "consumer.hepta", rustc=rustc, crate_type="staticlib")
    result["hepta_consumer"] = checked.report
    if not checked.report["ok"]:
        return result
    exports = replace(checked.program, functions=[f for f in checked.program.functions if f.export_c])
    (generated / "hepta.h").write_text(emit_header(exports), encoding="utf-8")
    library = root / "consumer.a"
    native = compile_rust(checked.rust, rustc=rustc, crate_type="staticlib", output=library)
    result["hepta_native_library"] = native
    if not native["ok"]:
        return result
    # Preserve argv[0]: resolving clang++ to clang changes the driver mode at
    # link time even though the executable bytes have the same identity.
    compiler = shutil.which(cxx) or cxx
    flags = ["-std=c++20", "-O2", "-fPIC", "-pthread", "-Werror", "-I" + str(generated), "-I" + str(EXAMPLE)]
    objects = []
    for source in (generated / "bridge.cpp", EXAMPLE / "foreign.cpp", EXAMPLE / "harness.cpp"):
        obj = root / (source.stem + ".o")
        _command([compiler, *flags, "-c", str(source), "-o", str(obj)])
        objects.append(obj)
    executable = root / "cpp-scoped-native"
    _command([compiler, *(str(p) for p in objects), str(library), "-pthread", "-ldl", "-lm", "-o", str(executable)])
    run = _command([str(executable)], timeout=30)
    result.update({"execution": json.loads(run.stdout), "execution_process": _process(run),
                   "native_link_qualified": True, "executable_sha256": _digest(executable),
                   "object_sha256": {p.name: _digest(p) for p in objects}, "build_flags": flags,
                   "hepta_library_sha256": _digest(library)})
    macros = _command([compiler, "-std=c++20", "-dM", "-E", "-x", "c++", "-include", "vector", "/dev/null"]).stdout
    result["standard_library_macros"] = [line for line in macros.splitlines()
                                         if line.startswith(("#define _GLIBCXX_RELEASE ", "#define __GLIBCXX__ ", "#define _LIBCPP_VERSION "))]
    if benchmark:
        timing = root / "cpp-scoped-benchmark"
        _command([compiler, *flags, str(EXAMPLE / "benchmark.cpp"), str(root / "bridge.o"),
                  str(root / "foreign.o"), str(library), "-ldl", "-lm", "-o", str(timing)])
        measured = _command([str(timing), str(iterations)], timeout=60)
        rows = [json.loads(line) for line in measured.stdout.splitlines()]
        if (len(rows) != 4 or {row["case"] for row in rows} != TIMING_CASES
                or any(row["iterations"] != iterations or len(row["samples_ns"]) != 7 for row in rows)
                or len({row["checksum"] for row in rows}) != 1):
            raise ValueError("Native lifecycle timing output is incomplete or disagrees")
        expected_checksum = (iterations // 32) * sum(range(32)) + sum(range(iterations % 32))
        for row in rows:
            if (row["checksum"] != expected_checksum
                    or any(type(n) is not int or n <= 0 for n in row["samples_ns"])):
                raise ValueError("Native lifecycle timing samples or checksum invalid")
            row["median_ns_per_lifecycle"] = statistics.median(row["samples_ns"]) / iterations
        by_name = {row["case"]: row for row in rows}
        baseline = by_name["native_cpp_lifecycle"]["median_ns_per_lifecycle"]
        result["performance"] = {"status": "measured", "benchmark_sha256": _digest(timing),
                                 "process": _process(measured), "measurements": rows,
                                 "observed_median_ratios_to_native": {
                                     name: row["median_ns_per_lifecycle"] / baseline for name, row in by_name.items()},
                                 "scope": "construct_append_at_and_destroy_entire_lifecycle",
                                 "limitations": ["One host and selected C++/Rust compilers; seven sequential samples; no LTO.",
                                                 "Timings include foreign vector allocations; C++ new counts are measured separately.",
                                                 "No universal speedup, tail-latency, total-stack-bound or arbitrary library claim."]}
    after = {str(path.relative_to(ROOT)): _digest(path) for path in sorted(EXAMPLE.iterdir()) if path.is_file()}
    if inputs != after or _digest(Path(compiler)) != bridge["compiler"]["executable_sha256"]:
        raise ValueError("Example or C++ compiler changed during native qualification")
    result["source_snapshot_unchanged"] = True
    result["ok"] = True
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cxx", default="g++")
    parser.add_argument("--rustc")
    parser.add_argument("--iterations", type=int, default=100000)
    parser.add_argument("--no-benchmark", action="store_true")
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink():
        parser.error("Refusing to overwrite a previous qualification")
    with tempfile.TemporaryDirectory(prefix="hepta-cpp-scoped-") as directory:
        try:
            result = qualify_scoped_cpp(directory, cxx=args.cxx, rustc=args.rustc,
                                        benchmark=not args.no_benchmark, iterations=args.iterations)
        except (OSError, RuntimeError, ValueError) as exc:
            result = {"schema": "hepta.cpp-scoped-qualification.v1", "ok": False, "error": str(exc)}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as file:
        json.dump(result, file, indent=2, sort_keys=True)
        file.write("\n")
    print(json.dumps({"ok": result["ok"], "output": str(args.output)}))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
