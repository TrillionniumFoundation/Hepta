"""Run real C++/Hepta-Rust/Hepta-C differential checks for a migrated value class.

The original C++ library is a reference only. Neither Hepta library links it.
This qualifies one complete fixture in the bounded class migration profile;
it is not an equivalence proof or a resource-owning RAII rewrite.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import itertools
import json
import os
from pathlib import Path
import random
import re
import shutil
import subprocess
import sys

from hepta.backend import compile_rust
from hepta.ast import HeptaError
from hepta.c_backend import compile_c
from hepta.cpp_class_migrate import PROFILE, migrate_cpp_class
from hepta.pipeline import analyze_project, compiler_hash
from tools.evidence_checks import native_build, strict_equal

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples/cpp/class_migration"
SCHEMA = "hepta.cpp-class-qualification.v1"
SEED = 0xC1A55
RANDOM_CASES = 256
INPUTS = ("hepta/cpp_class_migrate.py", "tools/validate_cpp_class.py", "tools/evidence_checks.py",
          "examples/cpp/class_migration/scalar_state.cpp", "examples/cpp/class_migration/reference.cpp",
          "examples/cpp/class_migration/consumer.hepta")
LIMITS = {"source_equivalence_proved": False, "cpp_class_abi_preserved": False,
          "resource_owning_raii_translated": False, "whole_language_memory_safety_proved": False,
          "all_programs_faster_than_rust": False, "foreign_cpp_implementation_retained": False}


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _json_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _identity(path):
    path = Path(path).resolve()
    data = path.read_bytes()
    return {"path": str(path), "bytes": len(data), "sha256": _sha(data)}


def _inputs():
    return {name: _sha((ROOT / name).read_bytes()) for name in INPUTS}


def _run(command, *, expected=0):
    process = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=120)
    record = {"command": [str(arg) for arg in command], "returncode": process.returncode,
              "stdout": process.stdout, "stderr": process.stderr,
              "stdout_sha256": _sha(process.stdout.encode()), "stderr_sha256": _sha(process.stderr.encode())}
    if process.returncode != expected:
        raise RuntimeError("Native process failed: " + json.dumps(record))
    return record


def _cases():
    u32 = [0, 1, 2, 2**31 - 1, 2**31, 2**32 - 2, 2**32 - 1]
    u64 = [0, 1, 2, 2**63 - 1, 2**63, 2**64 - 2, 2**64 - 1]
    i32 = [-2**31, -2**31 + 1, -1, 0, 1, 2**31 - 2, 2**31 - 1]
    i64 = [-2**63, -2**63 + 1, -1, 0, 1, 2**63 - 2, 2**63 - 1]
    cases = {
        "word_trace": [(a, b, u32[i % 7], u32[(i + 3) % 7])
                       for i, (a, b) in enumerate(itertools.product(u32, repeat=2))],
        "wide_trace": [(a, b, u64[(i + 1) % 7])
                       for i, (a, b) in enumerate(itertools.product(u64, repeat=2))],
        "balance_trace": list(itertools.product(i32, repeat=3)),
        "position_trace": list(itertools.product(i64, repeat=2)),
        "state_guard": [(u32[i], u64[i], i32[i], i64[i], u32[(i + 1) % 7], u64[(i + 4) % 7],
                         i32[(i + 5) % 7], i32[(i + 2) % 7], i64[(i + 3) % 7]) for i in range(7)],
    }
    rng = random.Random(SEED)
    for _ in range(RANDOM_CASES):
        cases["word_trace"].append(tuple(rng.randrange(2**32) for _ in range(4)))
        cases["wide_trace"].append(tuple(rng.randrange(2**64) for _ in range(3)))
        cases["balance_trace"].append(tuple(rng.randrange(-2**31, 2**31) for _ in range(3)))
        cases["position_trace"].append(tuple(rng.randrange(-2**63, 2**63) for _ in range(2)))
        cases["state_guard"].append((rng.randrange(2**32), rng.randrange(2**64),
            rng.randrange(-2**31, 2**31), rng.randrange(-2**63, 2**63), rng.randrange(2**32),
            rng.randrange(2**64), rng.randrange(-2**31, 2**31), rng.randrange(-2**31, 2**31),
            rng.randrange(-2**63, 2**63)))
    return cases


def _expected(name, args):
    if name == "word_trace":
        initial, step, reset, last = args
        return ((initial + step) % 2**32) ^ ((reset + last) % 2**32) ^ initial
    if name == "wide_trace":
        initial, first, second = args
        a = ((initial ^ first) + 1) % 2**64
        b = ((a ^ second) + 1) % 2**64
        return a ^ b ^ initial
    if name == "balance_trace":
        initial, lower, upper = args
        return lower if initial < lower else upper if initial > upper else initial
    if name == "position_trace":
        return args[1]
    return 0


def _probe(paths):
    u32, u64, i32, i64 = ctypes.c_uint32, ctypes.c_uint64, ctypes.c_int32, ctypes.c_int64
    signatures = {"word_trace": ([u32] * 4, u32), "wide_trace": ([u64] * 3, u64),
                  "balance_trace": ([i32] * 3, i32), "position_trace": ([i64] * 2, i64),
                  "state_guard": ([u32, u64, i32, i64, u32, u64, i32, i32, i64], i32)}
    identities = {name: _identity(path) for name, path in zip(("cpp", "rust", "c"), paths)}
    libraries = {name: ctypes.CDLL(record["path"]) for name, record in identities.items()}
    for library in libraries.values():
        for name, (args, returns) in signatures.items():
            function = getattr(library, name)
            function.argtypes, function.restype = args, returns
    cases, observations = _cases(), {name: [] for name in libraries}
    for name, inputs in cases.items():
        for index, args in enumerate(inputs):
            expected = _expected(name, args)
            reference = getattr(libraries["cpp"], name)(*args)
            if reference != expected:
                return {"ok": False, "status": "reference_oracle_mismatch", "family": name, "index": index,
                        "arguments": args, "reference": reference, "expected": expected}
            observations["cpp"].append([name, args, reference])
            for backend in ("rust", "c"):
                observed = getattr(libraries[backend], name)(*args)
                if observed != reference:
                    return {"ok": False, "status": "differential_mismatch", "backend": backend,
                            "family": name, "index": index, "arguments": args,
                            "reference": reference, "expected": expected, "observed": observed}
                observations[backend].append([name, args, observed])
    for name, identity in identities.items():
        if _identity(identity["path"]) != identity:
            raise RuntimeError("Native library changed during differential execution: " + name)
    return {"ok": True, "status": "differential_passed", "seed": SEED,
            "cases_by_family": {name: len(values) for name, values in cases.items()},
            "cases_per_backend": sum(map(len, cases.values())), "input_vectors_sha256": _sha(_json_bytes(cases)),
            "observations_sha256": {name: _sha(_json_bytes(values)) for name, values in observations.items()},
            "libraries": identities, "python_integer_oracle_checked": True}


def _build(entry, directory, backend, *, rustc=None, cc=None):
    checked = analyze_project(entry, backend=backend, rustc=rustc, cc=cc, crate_type="cdylib")
    if not checked.report["ok"] or checked.report["assumptions"]:
        raise RuntimeError("Migrated class frontend/native check rejected: " + json.dumps(checked.report))
    source = checked.rust if backend == "rust" else checked.c
    generated = directory / ("generated." + ("rs" if backend == "rust" else "c"))
    generated.write_text(source)
    library = directory / ("migrated-" + backend + ".so")
    native = (compile_rust(source, rustc=rustc, crate_type="cdylib", output=library) if backend == "rust" else
              compile_c(source, cc=cc, crate_type="cdylib", output=library, sanitize=True))
    if not native["ok"]:
        raise RuntimeError("Migrated class actual build rejected: " + json.dumps(native))
    return {"frontend": checked.report, "generated_source": _identity(generated), "native": native,
            "library": _identity(library), "foreign_cpp_link_inputs": []}


def _process(record, code):
    if not isinstance(record, dict) or type(record.get("returncode")) is not int or record["returncode"] != code:
        raise ValueError("Exact native process exit status required")
    if (not isinstance(record.get("command"), list) or not record["command"]
            or any(not isinstance(part, str) or not part for part in record["command"])):
        raise ValueError("Actual native command identity required")
    for channel in ("stdout", "stderr"):
        if not isinstance(record.get(channel), str) or record.get(channel + "_sha256") != _sha(record[channel].encode()):
            raise ValueError("Native process output identity missing or inconsistent")


def _is_sha(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _native_row(row, backend, *, consumer_hash, migrated_hash, compiler):
    native, frontend = row["native"], row["frontend"]
    key, source_key = ("rust_sha256", "rust_sha256") if backend == "rust" else ("source_sha256", "c_sha256")
    status = "rustc_checked" if backend == "rust" else "gcc_checked"
    checked = frontend["backend"]
    native_build(checked, backend, check_only=True, crate_type="cdylib", source_sha256=frontend[source_key])
    native_build(native, backend, check_only=False, crate_type="cdylib", source_sha256=frontend[source_key])
    valid = (frontend["ok"] is True and frontend["status"] == "checked" and frontend["diagnostics"] == []
        and frontend["assumptions"] == [] and frontend["compiler_sha256"] == compiler
        and frontend["source_sha256"] == consumer_hash
        and len(frontend["project"]["sources"]) == 2
        and set(frontend["project"]["sources"].values()) == {consumer_hash, migrated_hash}
        and frontend["checks"]["syntax"] == "passed"
        and frontend["checks"]["types_effects_resources"] == "passed_in_supported_subset"
        and frontend["checks"]["rust_borrows_types" if backend == "rust" else "c_types_codegen"] == status
        and _is_sha(frontend[source_key]) and frontend[source_key] == row["generated_source"]["sha256"]
        and checked["ok"] is True and checked["status"] == status and checked["check_only"] is True
        and checked["crate_type"] == "cdylib" and checked[key] == frontend[source_key]
        and checked["diagnostics"] == [] and _is_sha(checked["validation_artifact_sha256"])
        and native["ok"] is True and native["status"] == status and native["check_only"] is False
        and native["crate_type"] == "cdylib" and native["diagnostics"] == [] and native["link_args"] == []
        and native[key] == frontend[source_key] and native["toolchain"] == checked["toolchain"]
        and native["target"] == checked["target"] and row["foreign_cpp_link_inputs"] == []
        and native["artifact"] == row["library"]["path"]
        and _is_sha(native["artifact_sha256"]) and native["artifact_sha256"] == row["library"]["sha256"]
        and native["validation_artifact_sha256"] == native["artifact_sha256"]
        and type(native["artifact_bytes"]) is int and native["artifact_bytes"] > 0
        and type(row["library"]["bytes"]) is int and native["artifact_bytes"] == row["library"]["bytes"])
    if backend == "rust":
        valid = valid and native["rustc_crate_type"] == "cdylib" and checked["rustc_crate_type"] == "lib"
    else:
        valid = (valid and native["backend"] == "c11-gcc" and native["rustc_used"] is False
                 and checked["rustc_used"] is False and "-fsanitize=undefined" in native["flags"])
    if not valid:
        raise ValueError("Independent backend frontend/build/artifact identity required")


def validate_cpp_class_qualification(report, *, current_inputs=True):
    def require(condition, message):
        if not condition:
            raise ValueError(message)
    try:
        require(isinstance(report, dict) and report.get("schema") == SCHEMA and report.get("ok") is True,
                "Successful class qualification required")
        require(report.get("profile") == PROFILE and all(report.get(key) is value for key, value in LIMITS.items()),
                "Bounded class qualification claim limits changed")
        require(set(report["inputs"]) == set(INPUTS) and (not current_inputs or report["inputs"] == _inputs()),
                "Current input identities required")
        require(all(_is_sha(value) for value in report["inputs"].values())
                and _is_sha(report["hepta_compiler_sha256"])
                and (not current_inputs or report["hepta_compiler_sha256"] == compiler_hash()),
                "Current compiler identity required")
        migration = report["migration"]
        require(migration["ok"] is True and migration["native_trivial_lifecycle_checked"] is True
                and migration["status"] == "class_implementation_translated_frontend_checked"
                and migration["tier"] == "L1" and migration["profile"] == PROFILE
                and migration["cpp_abi_preserved"] is False and migration["source_equivalence_proved"] is False
                and migration["whole_language_memory_safety_proved"] is False
                and migration["foreign_cpp_implementation_retained"] is False
                and type(migration["foreign_calls_introduced"]) is int and migration["foreign_calls_introduced"] == 0
                and migration["resource_owning_raii_translated"] is False
                and migration["translated_class"]["unconverted_members"] == []
                and migration["source_sha256"] == report["inputs"]["examples/cpp/class_migration/scalar_state.cpp"]
                and migration["output_sha256"] == report["migrated_source"]["sha256"]
                and migration["output_sha256"] == _sha(report["migrated_source_text"].encode())
                and migration["output_sha256"] == migration["hepta_frontend"]["source_sha256"]
                and migration["hepta_frontend"]["compiler_sha256"] == report["hepta_compiler_sha256"]
                and migration["target_model"]["compiler_sha256"] == report["cpp_compiler"]["sha256"],
                "Complete implementation migration required")
        _process(report["reference_build"], 0)
        _process(report["execution_process"], 0)
        execution = report["execution"]
        require(strict_equal(json.loads(report["execution_process"]["stdout"]), execution), "Execution payload is not native stdout")
        cases = _cases()
        require(execution["ok"] is True and execution["status"] == "differential_passed"
                and strict_equal(execution["cases_by_family"], {name: len(values) for name, values in cases.items()})
                and type(execution["cases_per_backend"]) is int
                and execution["cases_per_backend"] == sum(map(len, cases.values()))
                and type(execution["seed"]) is int and execution["seed"] == SEED
                and execution["input_vectors_sha256"] == _sha(_json_bytes(cases))
                and execution["python_integer_oracle_checked"] is True, "Complete differential/oracle execution required")
        oracle = _sha(_json_bytes([[name, args, _expected(name, args)] for name, values in cases.items() for args in values]))
        require(execution["observations_sha256"]["cpp"] == execution["observations_sha256"]["rust"]
                == execution["observations_sha256"]["c"]
                == oracle, "Backend observations differ from the complete integer oracle")
        require(execution["libraries"]["cpp"] == report["reference_library"], "Reference artifact identity mismatch")
        for backend in ("rust", "c"):
            row = report["backends"][backend]
            _native_row(row, backend, consumer_hash=report["inputs"]["examples/cpp/class_migration/consumer.hepta"],
                        migrated_hash=migration["output_sha256"], compiler=report["hepta_compiler_sha256"])
            require(execution["libraries"][backend] == row["library"], "Executed artifact identity mismatch")
        libraries = [execution["libraries"][name]["path"] for name in ("cpp", "rust", "c")]
        require(report["execution_process"]["command"][-3:] == libraries, "Executed library command mismatch")
        control = report["negative_control"]
        _process(control["execution_process"], 2)
        mismatch = json.loads(control["execution_process"]["stdout"])
        changed = report["migrated_source_text"].replace("return receiver.word;", "return wrapping_add(receiver.word, 1);", 1)
        require(mismatch["ok"] is False and mismatch["status"] == "differential_mismatch"
                and mismatch["backend"] == "c"
                and type(mismatch["observed"]) is int and type(mismatch["reference"]) is int
                and mismatch["observed"] != mismatch["reference"]
                and mismatch["family"] in cases and type(mismatch["index"]) is int
                and 0 <= mismatch["index"] < len(cases[mismatch["family"]])
                and strict_equal(mismatch["arguments"], cases[mismatch["family"]][mismatch["index"]])
                and mismatch["reference"] == mismatch["expected"] == _expected(mismatch["family"], mismatch["arguments"])
                and control["source_sha256"] == _sha(changed.encode())
                and control["source_sha256"] != migration["output_sha256"]
                and control["build"]["native"]["ok"] is True,
                "Executed arithmetic mutation must be detected")
        _native_row(control["build"], "c", consumer_hash=report["inputs"]["examples/cpp/class_migration/consumer.hepta"],
                    migrated_hash=control["source_sha256"], compiler=report["hepta_compiler_sha256"])
        require(control["execution_process"]["command"][-3:] == [*libraries[:2], control["build"]["library"]["path"]],
                "Mutated artifact was not the executed negative control")
        require(report["inputs_unchanged"] is True and report["performance"]["status"] == "not_run",
                "Input stability and explicit unmeasured performance required")
        return True
    except (KeyError, TypeError, AttributeError) as error:
        raise ValueError("Malformed class qualification evidence") from error


def qualify_cpp_class(directory, *, clangxx="clang++", rustc=None, cc=None):
    report = {"schema": SCHEMA, "profile": PROFILE, "ok": False, "status": "not_run", **LIMITS,
              "inputs": _inputs(), "hepta_compiler_sha256": compiler_hash(),
              "performance": {"status": "not_run"}, "diagnostics": []}
    try:
        work = Path(directory).resolve() / "cpp-class"
        work.mkdir(parents=True)
        migrated = work / "scalar_state.hepta"
        report["migration"] = migrate_cpp_class(EXAMPLE / "scalar_state.cpp", migrated, clangxx=clangxx)
        if report["migration"]["ok"] is not True:
            raise RuntimeError("Class migration rejected: " + json.dumps(report["migration"]))
        report["migrated_source"] = _identity(migrated)
        report["migrated_source_text"] = migrated.read_text()
        entry = work / "consumer.hepta"
        entry.write_bytes((EXAMPLE / "consumer.hepta").read_bytes())
        compiler = shutil.which(clangxx)
        if compiler is None:
            raise RuntimeError("Clang C++ driver unavailable")
        report["cpp_compiler"] = _identity(compiler)
        original = work / "reference-cpp.so"
        report["reference_build"] = _run([compiler, "-std=c++20", "-O3", "-fPIC", "-shared", "-Werror",
            "-fsanitize=undefined", "-fno-sanitize-recover=all", str(EXAMPLE / "reference.cpp"), "-o", str(original)])
        report["reference_library"] = _identity(original)
        report["backends"] = {}
        for backend in ("rust", "c"):
            target = work / backend
            target.mkdir()
            report["backends"][backend] = _build(entry, target, backend, rustc=rustc, cc=cc)
        libraries = [str(original), report["backends"]["rust"]["library"]["path"], report["backends"]["c"]["library"]["path"]]
        report["execution_process"] = _run([sys.executable, "-m", "tools.validate_cpp_class", "--probe", *libraries])
        report["execution"] = json.loads(report["execution_process"]["stdout"])
        wrong = work / "mutated"
        wrong.mkdir()
        (wrong / "consumer.hepta").write_bytes(entry.read_bytes())
        original_text = migrated.read_text()
        changed = original_text.replace("return receiver.word;", "return wrapping_add(receiver.word, 1);", 1)
        if changed == original_text:
            raise RuntimeError("Arithmetic mutation did not modify the migrated method")
        (wrong / "scalar_state.hepta").write_text(changed)
        changed_build = _build(wrong / "consumer.hepta", wrong, "c", cc=cc)
        report["negative_control"] = {"kind": "compiled_migrated_method_arithmetic_changed",
            "source_sha256": _sha(changed.encode()), "build": changed_build,
            "execution_process": _run([sys.executable, "-m", "tools.validate_cpp_class", "--probe",
                                       *libraries[:2], changed_build["library"]["path"]], expected=2)}
        report["inputs_unchanged"] = (report["inputs"] == _inputs()
            and report["hepta_compiler_sha256"] == compiler_hash()
            and report["cpp_compiler"] == _identity(compiler))
        report.update(ok=True, status="native_class_implementation_differential_qualified")
        validate_cpp_class_qualification(report)
    except (HeptaError, OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        report.update(ok=False, status="failed")
        report["diagnostics"].append({"message": str(error)})
    return report


# Common release-gate entrypoint; the longer name remains useful to callers.
validate_report = validate_cpp_class_qualification


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", nargs=3, metavar=("CPP", "RUST", "C"))
    parser.add_argument("--workdir", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--clangxx", default="clang++")
    parser.add_argument("--rustc", default=os.environ.get("RUSTC"))
    parser.add_argument("--cc", default=os.environ.get("CC", "gcc"))
    args = parser.parse_args()
    if args.probe:
        result = _probe(args.probe)
    else:
        if args.workdir is None or args.out is None:
            parser.error("qualification requires --workdir and --out")
        result = qualify_cpp_class(args.workdir, clangxx=args.clangxx, rustc=args.rustc, cc=args.cc)
        with args.out.open("x") as destination:
            json.dump(result, destination, indent=2, sort_keys=True)
            destination.write("\n")
    print(json.dumps(result, sort_keys=True))
    return 0 if result["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
