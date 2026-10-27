"""Real C17 two-configuration, two-unit scalar implementation qualification.

Source compilation, scalar HIA lowering, independent arithmetic oracles and
native observations are retained separately from the C++ matrix denominator.
This does not qualify pointer/resource contracts or unrestricted C migration.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta.c_project_matrix import verify_project_matrix
from hepta.c_scalar_matrix import lower_c_project_matrix
from hepta.hia_program import execute_program, verify_program
from hepta.hia_program_llvm import build_program_native, emit_program_llvm
from hepta.native_tool_identity import digest_executable
from hepta.object_symbols import inspect_object_symbols
from tools.qualify_cpp_project_hia import RUNNER, _process
from tools.qualify_cpp_project_matrix import (SIGNATURES, VARIANTS, _hash, _write,
                                             cases, expected, negative_partition_controls)

CLAIMS = {"two_complete_c_macro_configurations_executed": True,
          "all_four_c_compilation_commands_accounted_for": True,
          "scalar_c_export_names_preserved_and_executed": True,
          "original_c_defined_symbols_match_hia": True,
          "original_c_implementation_in_target": False,
          "resource_contracts_qualified": False,
          "unlisted_configurations_qualified": False,
          "arbitrary_c_supported": False, "source_equivalence_proved": False}


def make_c_inputs(directory):
    source = directory / "source"
    source.mkdir()
    for name in ("model.h", "word.c", "wide.c"):
        (source / name).write_bytes((ROOT / "examples/c/project_variants" / name).read_bytes())
    commands, variants = [], []
    for name, (number, _, _) in VARIANTS.items():
        indices = []
        for unit in ("word.c", "wide.c"):
            indices.append(len(commands))
            commands.append({"directory": str(source), "file": unit,
                             "arguments": ["clang", "-std=c17", f"-DPROJECT_VARIANT={number}",
                                           "-O2", "-fPIC", "-c", unit, "-o", f"{name}-{unit}.o"]})
        variants.append({"name": name, "command_indices": indices})
    _write(directory / "compile_commands.json", commands)
    path = directory / "matrix.json"
    _write(path, {"schema": "hepta.build-matrix.v1", "language": "c",
                  "database": "compile_commands.json", "variants": variants})
    return path


def validate_c_matrix_receipt(report):
    if (report.get("schema") != "hepta.c-project-matrix-qualification.v1"
            or report.get("cases") != cases() or report.get("claims") != CLAIMS
            or [row["name"] for row in report["variants"]] != list(VARIANTS)
            or report["matrix_capture"]["language"] != "c"):
        raise ValueError("C matrix qualification scope or claims differ")
    verify_project_matrix(report["matrix_capture"])
    clang = report["tool"]["path"]
    if digest_executable(clang) != report["tool"]["sha256"]:
        raise ValueError("C matrix compiler identity changed")
    directory = Path(report["workdir"])
    hashes = set()
    for row in report["variants"]:
        work = directory / row["name"]
        oracle = [expected(row["name"], case) for case in cases()]
        if (row["expected"] != oracle or row["interpreter_results"] != oracle
                or row["observed"] != {"original_c": oracle, "standalone_hia": oracle}):
            raise ValueError("C matrix behavior differs from fixed independent oracle")
        program = verify_program((work / "program.hia.json").read_bytes())
        hashes.add(program.sha256)
        if (program.sha256 != row["program_sha256"]
                or _hash(work / "program.ll") != emit_program_llvm(program).sha256
                or not row["native_build"]["ok"]
                or row["native_build"]["core_sha256"] != program.sha256
                or row["native_build"]["artifact_sha256"] != _hash(work / "program.o")
                or not set(row["native_build"]["binary_inventory"]["undefined"]) <= {"abort"}):
            raise ValueError("C native target does not match verified standalone HIA")
        capture = next(variant["capture"] for variant in report["matrix_capture"]["variants"]
                       if variant["name"] == row["name"])
        object_symbols, original_defined = [], set()
        for config in capture["configurations"]:
            obj = work / f"original-{config['index']}.o"
            inventory = inspect_object_symbols(obj.read_bytes(), "ELF64", 62)
            original_defined.update(inventory["defined"])
            object_symbols.append({"command_index": config["index"], "object": str(obj),
                                   **{key: sorted(value) for key, value in inventory.items()}})
        target_symbols = inspect_object_symbols((work / "program.o").read_bytes(), "ELF64", 62)
        if (row.get("original_object_symbols") != object_symbols
                or row.get("original_defined_symbols") != sorted(original_defined)
                or target_symbols["defined"] != original_defined
                or target_symbols["defined"] != program.scalar_entrypoints
                or sorted(target_symbols["defined"]) != row["native_build"]["exports"]):
            raise ValueError("Original C defined symbols differ from standalone HIA exports")
        required = [clang, "-shared", "-fPIC", str(work / "program.o"), "-o", str(work / "target.so")]
        process = row["processes"][row["target_link_process"]]
        if row["target_link_argv"] != required or process["argv"] != required or process["returncode"] != 0:
            raise ValueError("C target must link only directly generated HIA object")
        for role in ("original_c", "standalone_hia"):
            process = row["processes"][row["observation_processes"][role]]
            library = "original.so" if role == "original_c" else "target.so"
            payload = {"library": str(work / library), "cases": cases(), "signatures": SIGNATURES}
            if (process["argv"] != [sys.executable, "-I", "-c", RUNNER]
                    or process["returncode"] != 0
                    or json.loads(Path(process["stdin"]).read_text()) != json.loads(json.dumps(payload))
                    or json.loads(Path(process["stdout"]).read_text()) != oracle):
                raise ValueError("Retained C native execution differs")
        active = [item for item in row["declarations"] if item["status"] != "system_or_compiler_declaration"]
        if row["active_project_declarations"] != len(active) or any(item["status"].endswith("pending") for item in active):
            raise ValueError("C matrix declaration inventory has unresolved entries")
        for process in row["processes"]:
            for field in ("stdin", "stdout", "stderr"):
                if field in process and _hash(process[field]) != process[field + "_sha256"]:
                    raise ValueError("Retained C matrix process bytes changed")
    if len(hashes) != len(VARIANTS):
        raise ValueError("C macro configuration implementations were merged or dropped")
    for item in report["retained_files"]:
        if _hash(item["path"]) != item["sha256"]:
            raise ValueError("Retained C matrix artifact changed")
    if (len(report.get("negative_controls", [])) != 5
            or any(row.get("rejected") is not True for row in report["negative_controls"])):
        raise ValueError("C matrix negative controls incomplete")


def qualify_c_matrix(workdir, *, clang="clang"):
    directory = Path(workdir).absolute()
    directory.mkdir(parents=True, exist_ok=False)
    report = {"schema": "hepta.c-project-matrix-qualification.v1", "ok": False,
              "workdir": str(directory), "cases": cases(), "variants": []}
    started = time.perf_counter()
    try:
        found = shutil.which(clang)
        if found is None:
            raise ValueError("Actual C compiler unavailable")
        compiler = str(Path(found).resolve(strict=True))
        report["tool"] = {"path": compiler, "sha256": digest_executable(compiler)}
        manifest = make_c_inputs(directory)
        migration = lower_c_project_matrix(manifest, clang=compiler)
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
            row = {"name": name, "command_indices": variant["command_indices"],
                   "program_sha256": program.sha256, "processes": [], "observed": {}, "observation_processes": {},
                   "declarations": variant["declarations"], "active_project_declarations": variant["active_project_declarations"]}
            report["variants"].append(row)
            row["native_build"] = build_program_native(program, work / "program.o", clang=compiler, kind="object")
            if not row["native_build"]["ok"]:
                raise ValueError("C matrix HIA native build rejected")
            row["target_link_argv"] = [compiler, "-shared", "-fPIC", str(work / "program.o"), "-o", str(work / "target.so")]
            row["target_link_process"] = len(row["processes"])
            _process(row["target_link_argv"], row, work)
            originals = []
            row["original_object_symbols"] = []
            original_defined = set()
            for config in variant["capture"]["configurations"]:
                obj = work / f"original-{config['index']}.o"
                originals.append(obj)
                _process([compiler, *config["frontend_arguments"], "-O2", "-fPIC", "-c", config["source"], "-o", obj], row, work)
                symbols = inspect_object_symbols(obj.read_bytes(), "ELF64", 62)
                original_defined.update(symbols["defined"])
                row["original_object_symbols"].append({
                    "command_index": config["index"], "object": str(obj),
                    **{key: sorted(value) for key, value in symbols.items()},
                })
            row["original_defined_symbols"] = sorted(original_defined)
            if original_defined != program.scalar_entrypoints:
                raise ValueError("Original C defined symbols differ from standalone HIA exports")
            _process([compiler, "-shared", *originals, "-o", work / "original.so"], row, work)
            row["expected"] = [expected(name, case) for case in cases()]
            row["interpreter_results"] = [execute_program(program, case["function"], case["arguments"])["result"] for case in cases()]
            for role, library in (("original_c", "original.so"), ("standalone_hia", "target.so")):
                row["observation_processes"][role] = len(row["processes"])
                payload = {"library": str(work / library), "cases": cases(), "signatures": SIGNATURES}
                row["observed"][role] = json.loads(_process([sys.executable, "-I", "-c", RUNNER], row, work, stdin=json.dumps(payload)))
        report["claims"] = dict(CLAIMS)
        report["negative_controls"] = negative_partition_controls(directory, manifest, compiler)
        report["retained_files"] = [{"path": str(path), "sha256": _hash(path)}
                                     for path in sorted(directory.rglob("*")) if path.is_file()]
        validate_c_matrix_receipt(report)
        report.update(ok=True, status="finite_c_scalar_build_matrix_native_qualified", cases_per_variant=len(cases()),
                      interpreter_results=2 * len(cases()), native_result_executions=4 * len(cases()))
    except Exception as exc:
        report.update(ok=False, status="qualification_failed",
                      diagnostic={"code": getattr(exc, "code", type(exc).__name__), "message": str(exc)})
    report["wall_seconds"] = time.perf_counter() - started
    _write(directory / "qualification.json", report)
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--workdir", required=True)
    parser.add_argument("--clang", default="clang")
    args = parser.parse_args()
    report = qualify_c_matrix(args.workdir, clang=args.clang)
    print(json.dumps({key: report.get(key) for key in ("ok", "status", "diagnostic", "cases_per_variant",
                                                     "native_result_executions", "wall_seconds")}, indent=2))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
