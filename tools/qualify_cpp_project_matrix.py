"""Execute two complete, explicitly partitioned C++ configurations via HIA.

The original compile database contains the same two source units twice. Each
macro configuration is translated, linked and observed separately. Target link
inputs are reconstructed independently and cannot contain original C++ objects.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import random
import shutil
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta.c_migrate import MigrationRejected
from hepta.c_project_matrix import capture_project_matrix, verify_project_matrix
from hepta.cpp_project_migrate import lower_cpp_project_matrix
from hepta.hia_program import execute_program, verify_program
from hepta.hia_program_llvm import build_program_native, emit_program_llvm
from hepta.native_tool_identity import digest_executable
from tools.qualify_cpp_project_hia import RUNNER, _process

SIGNATURES = {"matrix_word": (["u32", "u32"], "u32"),
              "matrix_wide": (["u64", "u64"], "u64"),
              "matrix_cross": (["u32", "u64"], "u64")}
VARIANTS = {"small": (1, 2, 3), "large": (2, 4, 17)}


def _hash(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _write(path, data):
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(data, stream, sort_keys=True, indent=2, allow_nan=False)
        stream.write("\n")


def cases():
    rng = random.Random(0x4849414D41545249)
    rows = []
    for index in range(68):
        word = [0, 1, 1 << 31, (1 << 32) - 1][index] if index < 4 else rng.getrandbits(32)
        wide = [0, 1, 1 << 63, (1 << 64) - 1][index] if index < 4 else rng.getrandbits(64)
        rows.extend([{"function": "matrix_word", "arguments": [word, rng.getrandbits(32)]},
                     {"function": "matrix_wide", "arguments": [wide, rng.getrandbits(64)]},
                     {"function": "matrix_cross", "arguments": [word, wide]}])
    return rows


def expected(variant, case):
    _, rounds, bias = VARIANTS[variant]
    def mix(value, salt, bits):
        for index in range(rounds):
            value = (value * 33 + salt + index) % (1 << bits)
        return (value + bias) % (1 << bits)
    name, (left, right) = case["function"], case["arguments"]
    if name == "matrix_word":
        return mix(left, right, 32)
    if name == "matrix_wide":
        return mix(left, right, 64)
    if name == "matrix_cross":
        return mix(left, 7, 32) ^ mix(right, 11, 64)
    raise ValueError("Unknown matrix oracle function")


def make_inputs(directory):
    source = directory / "source"
    source.mkdir()
    for name in ("model.hpp", "word.cpp", "wide.cpp"):
        (source / name).write_bytes((ROOT / "examples/cpp/project_variants" / name).read_bytes())
    commands, variants = [], []
    for name, (number, _, _) in VARIANTS.items():
        indices = []
        for unit in ("word.cpp", "wide.cpp"):
            indices.append(len(commands))
            commands.append({"directory": str(source), "file": unit,
                             "arguments": ["clang++", "-std=c++20", f"-DPROJECT_VARIANT={number}",
                                           "-O2", "-fPIC", "-c", unit, "-o", f"{name}-{unit}.o"]})
        variants.append({"name": name, "command_indices": indices})
    _write(directory / "compile_commands.json", commands)
    manifest = {"schema": "hepta.build-matrix.v1", "language": "c++",
                "database": "compile_commands.json", "variants": variants}
    path = directory / "matrix.json"
    _write(path, manifest)
    return path


def negative_partition_controls(directory, manifest, clangxx):
    """Retain actual rejected inputs, including a mutually edited receipt."""
    original = json.loads(manifest.read_text())
    rows = []
    changes = (
        ("omitted_command", lambda doc: doc["variants"][1].update(command_indices=[2])),
        ("overlapping_command", lambda doc: doc["variants"][1].update(command_indices=[1, 2, 3])),
        ("duplicate_index", lambda doc: doc["variants"][0].update(command_indices=[0, 0, 1])),
        ("repeated_source", lambda doc: doc["variants"][0].update(command_indices=[0, 2])),
    )
    for name, change in changes:
        document = deepcopy(original)
        change(document)
        path = directory / ("rejected-" + name + ".json")
        _write(path, document)
        try:
            capture_project_matrix(path, clang=clangxx)
        except MigrationRejected as exc:
            rows.append({"name": name, "input": str(path), "rejected": True,
                         "diagnostic": {"code": exc.code, "message": str(exc)}})
        else:
            raise ValueError("Invalid partition was accepted: " + name)
    bad_database = json.loads((directory / "compile_commands.json").read_text())
    bad_database[2]["arguments"][0] = "g++"
    _write(directory / "rejected-driver-database.json", bad_database)
    document = deepcopy(original)
    document["database"] = "rejected-driver-database.json"
    path = directory / "rejected-driver-matrix.json"
    _write(path, document)
    try:
        capture_project_matrix(path, clang=clangxx)
    except MigrationRejected as exc:
        rows.append({"name": "inconsistent_driver", "input": str(path), "rejected": True,
                     "diagnostic": {"code": exc.code, "message": str(exc)}})
    else:
        raise ValueError("Inconsistent matrix compiler drivers were accepted")
    return rows


def validate_matrix_receipt(report):
    if (report.get("schema") != "hepta.cpp-project-matrix-qualification.v1"
            or report.get("cases") != cases()
            or [row["name"] for row in report["variants"]] != list(VARIANTS)):
        raise ValueError("Matrix qualification scope/denominator differs")
    verify_project_matrix(report["matrix_capture"])
    directory = Path(report["workdir"])
    clang = report["tools"]["clang"]["path"]
    for tool in report["tools"].values():
        if digest_executable(tool["path"]) != tool["sha256"]:
            raise ValueError("Matrix tool identity changed")
    distinct = set()
    for row in report["variants"]:
        work = directory / row["name"]
        oracle = [expected(row["name"], case) for case in cases()]
        if (row["expected"] != oracle or row["observed"] != {"original_cpp": oracle, "standalone_hia": oracle}
                or row["interpreter_results"] != oracle):
            raise ValueError("Matrix behavior differs from fixed per-variant oracle")
        program = verify_program((work / "program.hia.json").read_bytes())
        distinct.add(program.sha256)
        if (program.sha256 != row["program_sha256"]
                or _hash(work / "program.ll") != emit_program_llvm(program).sha256
                or row["native_build"]["core_sha256"] != program.sha256
                or row["native_build"]["artifact_sha256"] != _hash(work / "program.o")
                or not set(row["native_build"]["binary_inventory"]["undefined"]) <= {"abort"}):
            raise ValueError("Matrix target differs from verified standalone HIA")
        required = [clang, "-shared", "-fPIC", str(work / "program.o"), "-o", str(work / "target.so")]
        process = row["processes"][row["target_link_process"]]
        if row["target_link_argv"] != required or process["argv"] != required or process["returncode"] != 0:
            raise ValueError("Matrix target must link only directly generated HIA object")
        for role in ("original_cpp", "standalone_hia"):
            process = row["processes"][row["observation_processes"][role]]
            library = "original.so" if role == "original_cpp" else "target.so"
            payload = {"library": str(work / library), "cases": cases(), "signatures": SIGNATURES}
            if (process["argv"] != [sys.executable, "-I", "-c", RUNNER]
                    or process["returncode"] != 0
                    or json.loads(Path(process["stdin"]).read_text()) != json.loads(json.dumps(payload))
                    or json.loads(Path(process["stdout"]).read_text()) != oracle):
                raise ValueError("Retained native matrix execution differs")
        for process in row["processes"]:
            for field in ("stdin", "stdout", "stderr"):
                if field in process and _hash(process[field]) != process[field + "_sha256"]:
                    raise ValueError("Retained matrix process bytes changed")
        if any(item["status"].endswith("pending") for item in row["declarations"]):
            raise ValueError("Unresolved matrix declaration")
    if len(distinct) != len(VARIANTS):
        raise ValueError("Different macro configurations were merged or dropped")
    for item in report["retained_files"]:
        if _hash(item["path"]) != item["sha256"]:
            raise ValueError("Retained matrix artifact changed")
    if report["claims"] != {"two_complete_macro_configurations_executed": True,
                             "all_four_compilation_commands_accounted_for": True,
                             "separate_variant_semantics_observed": True,
                             "original_cpp_implementation_in_target": False,
                             "unlisted_configurations_qualified": False,
                             "arbitrary_cpp_or_lifecycle_qualified": False,
                             "source_equivalence_proved": False}:
        raise ValueError("Unqualified matrix claim")
    controls = report.get("negative_controls", [])
    if ({row.get("name") for row in controls} != {"omitted_command", "overlapping_command", "duplicate_index",
                                                "repeated_source", "inconsistent_driver"}
            or len(controls) != 5 or any(row.get("rejected") is not True for row in controls)):
        raise ValueError("Matrix rejected-control denominator differs")


def qualify_cpp_matrix(workdir, *, clang="clang", clangxx="clang++"):
    directory = Path(workdir).absolute()
    directory.mkdir(parents=True, exist_ok=False)
    report = {"schema": "hepta.cpp-project-matrix-qualification.v1", "ok": False,
              "workdir": str(directory), "variants": [], "cases": cases()}
    start = time.perf_counter()
    try:
        report["tools"] = {}
        for name, selected in (("clang", clang), ("clangxx", clangxx)):
            found = shutil.which(selected)
            if not found:
                raise ValueError("Actual Clang tool unavailable: " + name)
            path = Path(found).resolve(strict=True)
            report["tools"][name] = {"path": str(path), "sha256": digest_executable(path)}
        manifest = make_inputs(directory)
        migration = lower_cpp_project_matrix(manifest, clangxx=report["tools"]["clangxx"]["path"])
        report["matrix_capture"] = migration["matrix_capture"]
        for variant in migration["variants"]:
            name = variant["name"]
            work = directory / name
            work.mkdir()
            program = variant.pop("program")
            (work / "program.hia.json").write_bytes(program.canonical_bytes)
            (work / "program.hepta").write_text(variant["source"])
            (work / "program.ll").write_text(emit_program_llvm(program).text)
            _write(work / "migration.json", variant)
            row = {"name": name, "processes": [], "observed": {}, "observation_processes": {},
                   "command_indices": variant["command_indices"], "program_sha256": program.sha256,
                   "declarations": variant["declarations"], "active_project_declarations": variant["active_project_declarations"]}
            report["variants"].append(row)
            row["native_build"] = build_program_native(program, work / "program.o",
                                                        clang=report["tools"]["clang"]["path"], kind="object")
            if not row["native_build"]["ok"]:
                raise ValueError("Matrix native HIA build rejected")
            argv = [report["tools"]["clang"]["path"], "-shared", "-fPIC", str(work / "program.o"), "-o", str(work / "target.so")]
            row["target_link_argv"], row["target_link_process"] = argv, len(row["processes"])
            _process(argv, row, work)
            objects = []
            for config in variant["capture"]["configurations"]:
                obj = work / f"original-{config['index']}.o"
                objects.append(obj)
                _process([report["tools"]["clangxx"]["path"], *config["frontend_arguments"],
                          "-c", config["source"], "-o", obj], row, work)
            _process([report["tools"]["clangxx"]["path"], "-shared", *objects, "-o", work / "original.so"], row, work)
            row["expected"] = [expected(name, case) for case in cases()]
            row["interpreter_results"] = [execute_program(program, case["function"], case["arguments"])["result"] for case in cases()]
            for role, library in (("original_cpp", "original.so"), ("standalone_hia", "target.so")):
                row["observation_processes"][role] = len(row["processes"])
                payload = {"library": str(work / library), "cases": cases(), "signatures": SIGNATURES}
                raw = _process([sys.executable, "-I", "-c", RUNNER], row, work, stdin=json.dumps(payload))
                row["observed"][role] = json.loads(raw)
        report["claims"] = {"two_complete_macro_configurations_executed": True,
                             "all_four_compilation_commands_accounted_for": True,
                             "separate_variant_semantics_observed": True,
                             "original_cpp_implementation_in_target": False,
                             "unlisted_configurations_qualified": False,
                             "arbitrary_cpp_or_lifecycle_qualified": False,
                             "source_equivalence_proved": False}
        report["negative_controls"] = negative_partition_controls(directory, manifest,
                                                                    report["tools"]["clangxx"]["path"])
        report["retained_files"] = [{"path": str(path), "sha256": _hash(path)}
                                     for path in sorted(directory.rglob("*")) if path.is_file()]
        validate_matrix_receipt(report)
        report.update(ok=True, status="finite_cpp_build_matrix_native_qualified",
                      cases_per_variant=len(cases()), interpreter_results=2 * len(cases()),
                      native_result_executions=4 * len(cases()))
    except Exception as exc:
        report.update(ok=False, status="qualification_failed",
                      diagnostic={"code": getattr(exc, "code", type(exc).__name__), "message": str(exc)})
    report["wall_seconds"] = time.perf_counter() - start
    _write(directory / "qualification.json", report)
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--workdir", required=True)
    parser.add_argument("--clang", default="clang")
    parser.add_argument("--clangxx", default="clang++")
    args = parser.parse_args()
    result = qualify_cpp_matrix(args.workdir, clang=args.clang, clangxx=args.clangxx)
    print(json.dumps({key: result.get(key) for key in ("ok", "status", "diagnostic", "cases_per_variant",
                                                     "native_result_executions", "wall_seconds")}, indent=2))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
