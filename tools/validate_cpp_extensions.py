"""Execute bounded C++ loop migration and sized-template bridge qualification.

The migrated class is linked through independent Rust and C implementations,
without the original C++ object. The bridge exercise deliberately retains its
foreign implementation, and reports that separate trust boundary. Native
artifacts are removed by default after identity and execution are recorded.
"""
from __future__ import annotations

import argparse
import ctypes
from dataclasses import replace
import difflib
import hashlib
import json
import os
from pathlib import Path
import random
import shutil
import subprocess
import time

from hepta.backend import compile_rust, emit_header
from hepta.c_backend import compile_c
from hepta.cpp_class_migrate import migrate_cpp_class
from hepta.cpp_contracts import bridge_cpp_contracts
from hepta.pipeline import analyze_project

ROOT = Path(__file__).resolve().parents[1]
LOOPS = ROOT / "examples/cpp/class_loops"
SIZES = ROOT / "examples/cpp/template_sizes"
SCHEMA = "hepta.cpp-extensions-qualification.v1"
SEED = 0xC10A55


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _identity(path: Path) -> dict:
    data = path.read_bytes()
    return {"path": str(path.resolve()), "bytes": len(data), "sha256": _sha(data)}


def _removed(identity: dict, native: dict | None = None) -> None:
    """Keep execution identity without advertising an already removed file."""
    identity["path_during_execution"] = identity.pop("path")
    identity["retained"] = False
    if native is not None:
        native["artifact_path_during_execution"] = native.pop("artifact")
        native["artifact_retained"] = False


def _tool_identity(command: str, *, rust: bool = False) -> dict:
    resolved = shutil.which(command)
    if resolved is None:
        raise RuntimeError("Qualification tool unavailable: " + command)
    path = Path(resolved).resolve()
    identity = _identity(path)
    identity["version_process"] = _run([str(path), "--version", "--verbose"] if rust else [str(path), "--version"])
    return identity


def _run(argv: list[str]) -> dict:
    process = subprocess.run([str(x) for x in argv], capture_output=True, text=True, timeout=120)
    record = {"command": [str(x) for x in argv], "returncode": process.returncode,
              "stdout": process.stdout, "stderr": process.stderr,
              "stdout_sha256": _sha(process.stdout.encode()), "stderr_sha256": _sha(process.stderr.encode())}
    if process.returncode != 0:
        raise RuntimeError("Native validation failed: " + json.dumps(record))
    return record


def _require(report: dict, context: str) -> dict:
    if not report.get("ok"):
        raise RuntimeError(context + ": " + json.dumps(report))
    return report


def _build_class(consumer: Path, directory: Path, backend: str, *, rustc: str, cc: str) -> dict:
    checked = analyze_project(consumer, backend=backend, rustc=rustc, cc=cc, crate_type="cdylib")
    _require(checked.report, "Migrated frontend")
    if checked.report["assumptions"]:
        raise RuntimeError("Migrated implementation introduced foreign assumptions")
    generated = checked.rust if backend == "rust" else checked.c
    source = directory / ("generated.rs" if backend == "rust" else "generated.c")
    source.write_text(generated)
    library = directory / ("mixer_" + backend + ".so")
    link_map = directory / ("link_" + backend + ".map")
    link_args = ["-Wl,-Map," + str(link_map)]
    native = (compile_rust(generated, rustc=rustc, crate_type="cdylib", output=library,
                           link_args=link_args) if backend == "rust" else
              compile_c(generated, cc=cc, crate_type="cdylib", output=library, sanitize=True,
                        link_args=link_args))
    _require(native, "Migrated native build")
    mapping = link_map.read_text()
    if any(name in mapping for name in (str(LOOPS), "reference.so", "original_cpp_mixer_marker")):
        raise RuntimeError("Original C++ implementation appeared in migrated linker map")
    return {"frontend": checked.report, "native": native, "generated_source": _identity(source),
            "library": _identity(library), "foreign_cpp_link_inputs": [],
            "linker_map": _identity(link_map), "original_cpp_reference_inputs_in_linker_map": False}


def _advance(value: int, count: int) -> int:
    for _ in range(count):
        value = (value * 1664525 + 1013904223) & 0xffffffff
    return value


def _expected(seed: int, first_count: int, second_count: int) -> int:
    first = _advance(seed, first_count)
    checksum = first
    for n in range(second_count, 0, -1):
        checksum ^= n
    drained = (first + second_count * (second_count + 1) // 2) & 0xffffffff
    second = _advance(drained, second_count)
    snapshot = seed
    for i in range(first_count):
        snapshot ^= i
    snapshot = (snapshot + first_count * (first_count - 1) // 2) & 0xffffffff
    return first ^ checksum ^ drained ^ second ^ snapshot


def _probe_class(libraries: dict[str, Path], observations_path: Path) -> dict:
    opened = {name: ctypes.CDLL(str(path.resolve())) for name, path in libraries.items()}
    for library in opened.values():
        library.mixer_trace.argtypes = [ctypes.c_uint32] * 3
        library.mixer_trace.restype = ctypes.c_uint32
        library.mixer_read_guard.argtypes = [ctypes.c_uint32] * 2
        library.mixer_read_guard.restype = ctypes.c_uint32
    vectors = [(seed, first, second) for seed in (0, 1, 2, 2**31-1, 2**31, 2**32-2, 2**32-1)
               for first in (0, 1, 2, 3, 16, 127) for second in (0, 1, 7, 32)]
    rng = random.Random(SEED)
    vectors += [(rng.randrange(2**32), rng.randrange(256), rng.randrange(256)) for _ in range(128)]
    observations = {name: [] for name in opened}
    for args in vectors:
        expected = _expected(*args)
        for name, library in opened.items():
            actual = library.mixer_trace(*args)
            guard = library.mixer_read_guard(args[0], args[1] + args[2])
            if actual != expected or guard != args[0]:
                raise RuntimeError(f"Mixer mismatch: {name}, {args}, {actual}, {expected}, {guard}")
            observations[name].append([list(args), actual, guard])
    digests = {name: _sha(json.dumps(values, separators=(",", ":")).encode())
               for name, values in observations.items()}
    observations_path.write_text(json.dumps({"vectors": vectors, "observations": observations,
                                            "oracle_trace": [_expected(*args) for args in vectors]},
                                           indent=2, sort_keys=True) + "\n")
    return {"ok": True, "seed": SEED, "trace_cases": len(vectors), "read_preservation_cases": len(vectors),
            "cases_per_backend": 2 * len(vectors), "independent_python_integer_oracle": True,
            "input_vectors_sha256": _sha(json.dumps(vectors, separators=(",", ":")).encode()),
            "observations_sha256": digests, "raw_results": _identity(observations_path)}


def qualify_class_loops(output: Path, *, clangxx: str, rustc: str, cc: str,
                        keep_native: bool = False) -> dict:
    output.mkdir(parents=True, exist_ok=False)
    translated = output / "mixer.hepta"
    migration = _require(migrate_cpp_class(LOOPS / "mixer.cpp", translated, clangxx=clangxx), "Class migration")
    consumer = output / "consumer.hepta"
    shutil.copyfile(LOOPS / "consumer.hepta", consumer)
    reference = output / "reference.so"
    reference_build = _run([clangxx, "-std=c++20", "-O2", "-shared", "-fPIC", "-Werror",
                            str(LOOPS / "reference.cpp"), "-o", str(reference)])
    identities = {"cpp": _identity(reference)}
    built = {backend: _build_class(consumer, output, backend, rustc=rustc, cc=cc) for backend in ("rust", "c")}
    paths = {"cpp": reference, **{name: Path(data["library"]["path"]) for name, data in built.items()}}
    identities.update({name: data["library"] for name, data in built.items()})
    observations = _probe_class(paths, output / "observations.json")
    symbols = {name: _run(["nm", "-D", "--defined-only", str(path)]) for name, path in paths.items()}
    marker = "original_cpp_mixer_marker"
    if marker not in symbols["cpp"]["stdout"] or any(marker in symbols[name]["stdout"] for name in ("rust", "c")):
        raise RuntimeError("Reference-only native marker did not distinguish migrated libraries")
    # A real wrong compiled implementation must be caught by the oracle. This
    # control only changes a generated unsigned multiplier, preserving typing.
    mutation_dir = output / "mutation"
    mutation_dir.mkdir()
    original = translated.read_text()
    if original.count("1664525") != 1:
        raise RuntimeError("Mutation target is not uniquely bound")
    (mutation_dir / "mixer.hepta").write_text(original.replace("1664525", "1664527"))
    shutil.copyfile(consumer, mutation_dir / "consumer.hepta")
    mutation = _build_class(mutation_dir / "consumer.hepta", mutation_dir, "c", rustc=rustc, cc=cc)
    negative = ctypes.CDLL(mutation["library"]["path"])
    negative.mixer_trace.argtypes, negative.mixer_trace.restype = [ctypes.c_uint32] * 3, ctypes.c_uint32
    mutation_args = (7, 5, 3)
    actual, expected = negative.mixer_trace(*mutation_args), _expected(*mutation_args)
    if actual == expected:
        raise RuntimeError("Wrong compiled implementation escaped differential control")
    for name, path in paths.items():
        if _identity(path) != identities[name]:
            raise RuntimeError("Class artifact changed during execution: " + name)
    artifacts = [*paths.values(), Path(mutation["library"]["path"])]
    if not keep_native:
        for path in artifacts:
            path.unlink()
        _removed(identities["cpp"])
        for data in built.values():
            _removed(data["library"], data["native"])
        _removed(mutation["library"], mutation["native"])
    return {"ok": True, "migration": migration, "builds": built, "reference_build": reference_build,
            "reference_library": identities["cpp"], "execution": observations,
            "negative_control": {"detected": True, "arguments": mutation_args, "expected": expected,
                                 "observed": actual, "artifact": mutation["library"]},
            "native_symbol_evidence": symbols,
            "reference_only_marker_present_only_in_reference_library": True,
            "original_cpp_implementation_linked_into_migrated_libraries": False,
            "source_equivalence_proved": False, "native_binaries_retained": keep_native}


def qualify_template_sizes(output: Path, *, cxx: str, rustc: str, keep_native: bool = False) -> dict:
    output.mkdir(parents=True, exist_ok=False)
    base = json.loads((SIZES / "contract.json").read_text())
    variants = []
    for extent in (4, 8):
        contract = json.loads(json.dumps(base))
        for item in contract["functions"] + contract["handles"]:
            for argument in item["template_args"]:
                if isinstance(argument, dict):
                    argument["value"] = extent
        directory = output / ("extent_" + str(extent))
        start = time.perf_counter_ns()
        generation = _require(bridge_cpp_contracts(SIZES / "foreign.hpp", contract, directory, cxx=cxx, rustc=rustc),
                              "Sized template generation")
        generation_ns = time.perf_counter_ns() - start
        consumer = directory / "consumer.hepta"
        shutil.copyfile(SIZES / "consumer.hepta", consumer)
        checked = analyze_project(consumer, crate_type="staticlib", rustc=rustc)
        _require(checked.report, "Sized Hepta frontend")
        exports = replace(checked.program, functions=[fn for fn in checked.program.functions if fn.export_c])
        (directory / "hepta.h").write_text(emit_header(exports))
        library = directory / "consumer.a"
        compiled = _require(compile_rust(checked.rust, crate_type="staticlib", output=library, rustc=rustc),
                            "Sized Hepta native library")
        executable = directory / "native"
        link = _run([cxx, "-std=c++20", "-O2", "-pthread", "-Werror", "-DHEPTA_TEST_EXTENT=" + str(extent),
                     "-I" + str(directory), "-I" + str(SIZES), str(directory / "bridge.cpp"),
                     str(SIZES / "verify.cpp"), str(library), "-ldl", "-lm", "-o", str(executable)])
        identity = _identity(executable)
        execution = _run([str(executable)])
        observed = json.loads(execution["stdout"])
        if not observed.get("ok") or observed.get("extent") != extent or observed.get("live_members") != 0:
            raise RuntimeError("Invalid template native observations")
        if _identity(executable) != identity:
            raise RuntimeError("Template native executable changed during execution")
        variants.append({"extent": extent, "ok": True, "generation": generation,
                         "native_build": compiled, "native_link": link, "native_binary": identity,
                         "execution_process": execution, "execution": observed,
                         "generation_and_native_check_ns": generation_ns,
                         "native_binaries_retained": keep_native})
        if not keep_native:
            library.unlink()
            executable.unlink()
            _removed(identity)
            compiled["artifact_path_during_execution"] = compiled.pop("artifact")
            compiled["artifact_retained"] = False
    headers = [(output / ("extent_" + str(n)) / "bridge.h").read_bytes() for n in (4, 8)]
    cpp = [(output / ("extent_" + str(n)) / "bridge.cpp").read_text().splitlines(keepends=True) for n in (4, 8)]
    delta = list(difflib.unified_diff(cpp[0], cpp[1], fromfile="extent_4/bridge.cpp", tofile="extent_8/bridge.cpp"))
    diff_path = output / "specialization-change.diff"
    diff_path.write_text("".join(delta))
    return {"ok": True, "variants": variants, "native_link_qualified": True,
            "foreign_cpp_implementation_retained": True, "foreign_nonretention_proved": False,
            "whole_library_memory_safety_proved": False,
            "upgrade_experiment": {"from_extent": 4, "to_extent": 8, "contract_size_values_changed": 3,
                                   "generated_c_header_identical": headers[0] == headers[1],
                                   "consumer_source_edits": 0, "native_variants_executed": 2,
                                   "generated_cpp_lines_added": sum(line.startswith("+") and not line.startswith("+++") for line in delta),
                                   "generated_cpp_lines_removed": sum(line.startswith("-") and not line.startswith("---") for line in delta),
                                   "generated_cpp_bytes": [sum(len(line.encode()) for line in source) for source in cpp],
                                   "generation_and_native_check_ns": [v["generation_and_native_check_ns"] for v in variants],
                                   "native_cpp_object_bytes": [v["generation"]["object_bytes"] for v in variants],
                                   "source_diff": _identity(diff_path),
                                   "human_maintenance_minutes": None,
                                   "covers_library_version_upgrade": False}}


def qualify_cpp_extensions(output: str | Path, *, clangxx: str | None = None, rustc: str | None = None,
                           cc: str = "gcc", cxx: str = "g++", keep_native: bool = False) -> dict:
    destination = Path(output).resolve()
    destination.mkdir(parents=True, exist_ok=False)
    inputs = [ROOT / path for path in ("hepta/cpp_class_migrate.py", "hepta/cpp_contracts.py", "hepta/c_migrate.py",
              "hepta/backend.py", "hepta/c_backend.py", "hepta/pipeline.py", "hepta/parser.py", "hepta/checker.py")]
    inputs += [Path(__file__),
              *(p for p in LOOPS.iterdir() if p.is_file()), *(p for p in SIZES.iterdir() if p.is_file())]
    before = {str(p.relative_to(ROOT)): _sha(p.read_bytes()) for p in inputs}
    selected_rustc = rustc or os.environ.get("RUSTC", "rustc")
    selected_clangxx = clangxx or os.environ.get("CLANGXX", "clang++")
    toolchains = {"clangxx": _tool_identity(selected_clangxx), "rustc": _tool_identity(selected_rustc, rust=True),
                  "cc": _tool_identity(cc), "cxx": _tool_identity(cxx), "nm": _tool_identity("nm")}
    classes = qualify_class_loops(destination / "class", clangxx=selected_clangxx,
                                  rustc=selected_rustc, cc=cc, keep_native=keep_native)
    templates = qualify_template_sizes(destination / "templates", cxx=cxx, rustc=selected_rustc,
                                        keep_native=keep_native)
    if before != {str(p.relative_to(ROOT)): _sha(p.read_bytes()) for p in inputs}:
        raise RuntimeError("Qualification input changed during native execution")
    for identity in toolchains.values():
        if _sha(Path(identity["path"]).read_bytes()) != identity["sha256"]:
            raise RuntimeError("Qualification executable changed during native execution")
    report = {"schema": SCHEMA, "ok": True, "inputs_sha256": before,
              "toolchains": toolchains,
              "class_implementation_migration": classes, "sized_template_bridging": templates,
              "all_cpp_supported": False, "all_template_instantiations_qualified": False,
              "performance_parity_with_rust_proved": False}
    (destination / "qualification.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--clangxx", default=os.environ.get("CLANGXX", "clang++"))
    parser.add_argument("--rustc", default=os.environ.get("RUSTC", "rustc"))
    parser.add_argument("--cc", default="gcc")
    parser.add_argument("--cxx", default="g++")
    parser.add_argument("--keep-native", action="store_true")
    args = parser.parse_args()
    report = qualify_cpp_extensions(args.output, clangxx=args.clangxx, rustc=args.rustc,
                                    cc=args.cc, cxx=args.cxx, keep_native=args.keep_native)
    print(json.dumps({"ok": report["ok"], "report": str(args.output / "qualification.json")}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
