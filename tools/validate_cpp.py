"""Execute the C++/Hepta standard-library example and optional bridge timings.

The sample uses the installed C++ standard library, not a claim of having
migrated that library into Hepta. Every timing is an observed local sample.
"""
from __future__ import annotations

import argparse
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import shutil
import statistics
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from hepta.backend import compile_rust, emit_header
from hepta.cpp_contracts import bridge_cpp_contracts
from hepta.pipeline import analyze_project


EXAMPLE = ROOT / "examples" / "cpp" / "stdlib"


def _run(argv: list[str], timeout: int = 120) -> subprocess.CompletedProcess:
    process = subprocess.run(argv, text=True, capture_output=True, timeout=timeout)
    if process.returncode:
        raise RuntimeError(f"Native command failed ({process.returncode}): {argv}\n{process.stdout}\n{process.stderr}")
    return process


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def qualify_cpp(directory: str | Path, *, cxx: str = "g++", rustc: str | None = None,
                benchmark: bool = True, iterations: int = 500000) -> dict:
    root = Path(directory)
    root.mkdir(parents=True, exist_ok=True)
    result = {"schema": "hepta.cpp-native-qualification.v1", "ok": False,
              "generated_at_utc": datetime.now(timezone.utc).isoformat(),
              "foreign_cpp_library_rewritten": False, "whole_library_memory_safety_proved": False,
              "universal_performance_advantage_proved": False,
              "scope": "host_std_library_explicit_instantiations_and_small_fixture"}
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
    # The consumer header declares only Hepta's exported entrypoints. Foreign
    # declarations already come from bridge.h and use its ABI mirror types.
    exports = replace(checked.program, functions=[f for f in checked.program.functions if f.export_c])
    (generated / "hepta.h").write_text(emit_header(exports), encoding="utf-8")
    library = root / "consumer.a"
    native = compile_rust(checked.rust, rustc=rustc, crate_type="staticlib", output=library)
    result["hepta_native_library"] = native
    if not native["ok"]:
        return result
    compiler = shutil.which(cxx) or cxx
    flags = ["-std=c++20", "-O2", "-fPIC", "-pthread", "-Werror", "-I" + str(generated), "-I" + str(EXAMPLE)]
    objects = []
    for source in (generated / "bridge.cpp", EXAMPLE / "foreign.cpp", EXAMPLE / "harness.cpp"):
        obj = root / (source.stem + ".o")
        _run([compiler, *flags, "-c", str(source), "-o", str(obj)])
        objects.append(obj)
    executable = root / "cpp-native-check"
    _run([compiler, *(str(p) for p in objects), str(library), "-pthread", "-ldl", "-lm", "-o", str(executable)])
    run = _run([str(executable)], timeout=30)
    result["execution"] = json.loads(run.stdout)
    result["native_link_qualified"] = True
    result["executable_sha256"] = _digest(executable)
    result["inputs"] = {str(path.relative_to(ROOT)): _digest(path) for path in sorted(EXAMPLE.iterdir()) if path.is_file()}
    result["build_flags"] = flags
    result["platform"] = {"system": platform.system(), "machine": platform.machine(), "release": platform.release()}
    macros = _run([compiler, "-std=c++20", "-dM", "-E", "-x", "c++", "-include", "string", "/dev/null"]).stdout
    result["standard_library_macros"] = [line for line in macros.splitlines() if line.startswith(("#define _GLIBCXX_RELEASE ", "#define __GLIBCXX__ ", "#define _LIBCPP_VERSION "))]
    result["performance"] = {"status": "not_run"}
    if benchmark:
        if not 0 < iterations <= 10000000:
            raise ValueError("iterations must be in 1..10000000")
        timing = root / "cpp-bridge-benchmark"
        _run([compiler, *flags, str(EXAMPLE / "benchmark.cpp"), str(root / "bridge.o"), str(root / "foreign.o"), "-o", str(timing)])
        rows = [json.loads(line) for line in _run([str(timing), str(iterations)], timeout=60).stdout.splitlines()]
        if len(rows) != 6 or any(len(row["samples_ns"]) != 7 or row["iterations"] != iterations for row in rows):
            raise RuntimeError("Native timing output is incomplete")
        by_name = {row["case"]: row for row in rows}
        if len(by_name) != 6:
            raise RuntimeError("Native timing output has duplicate cases")
        pairs = [("native_scalar", "direct_scalar"), ("native_borrow", "checked_borrow"), ("native_vector_size", "handle_vector_size")]
        for baseline, route in pairs:
            if by_name[baseline]["checksum"] != by_name[route]["checksum"]:
                raise RuntimeError("Timing paths disagree on observed result checksum")
        for row in rows:
            row["median_ns_per_call"] = statistics.median(row["samples_ns"]) / iterations
        result["performance"] = {"status": "measured", "benchmark_sha256": _digest(timing), "measurements": rows,
                                 "comparison": [{"baseline": base, "route": route,
                                                 "observed_median_ratio": by_name[route]["median_ns_per_call"] / by_name[base]["median_ns_per_call"]} for base, route in pairs],
                                 "limitations": ["One host, one compiler and standard library, sequential benchmark order, no LTO.",
                                                 "Process startup, registry/object creation and destruction are outside the timed loops.",
                                                 "No statement about unmeasured targets, Rust superiority, tail latency or whole C++ libraries.",
                                                 "Operation counts in the bridge report are static accounting; timings are separate observed evidence."]}
    result["ok"] = True
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cxx", default="g++")
    parser.add_argument("--rustc")
    parser.add_argument("--no-benchmark", action="store_true")
    parser.add_argument("--iterations", type=int, default=500000)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("Refusing to overwrite a previous qualification")
    with tempfile.TemporaryDirectory(prefix="hepta-cpp-native-") as td:
        try:
            result = qualify_cpp(td, cxx=args.cxx, rustc=args.rustc,
                                 benchmark=not args.no_benchmark, iterations=args.iterations)
        except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as exc:
            result = {"schema": "hepta.cpp-native-qualification.v1", "ok": False, "error": str(exc)}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as file:
        json.dump(result, file, indent=2, sort_keys=True)
        file.write("\n")
    print(json.dumps({"ok": result["ok"], "output": str(args.output)}))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
