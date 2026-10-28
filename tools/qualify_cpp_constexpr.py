"""Retained, finite C++ if-constexpr instantiations -> HIA -> native comparison.

The original and translated libraries are linked separately. Unsigned boundary
inputs are defined in C++; discarded object/throwing branches never execute.
This is a finite qualification, not arbitrary template or object migration.
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

from hepta.c_project import captured_source_argument, verify_capture
from hepta.cpp_project_migrate import lower_cpp_project
from hepta.hia_program import execute_program, verify_program
from hepta.hia_program_llvm import build_program_native, emit_program_llvm
from hepta.native_tool_identity import digest_executable
from tools.qualify_cpp_project_hia import RUNNER, _process, _write, digest


FIXTURE = ROOT / "examples/cpp/project_constexpr"
FIXTURE_NAMES = ("branches.hpp", "word.cpp", "wide.cpp")
SIGNATURES = {name: (["u64" if name.startswith("wide") else "u32"],
                     "u64" if name.startswith("wide") else "u32")
              for name in ("narrow0", "narrow1", "wide0", "wide1", "scope0", "scope1",
                           "discard_object", "repeated_narrow", "runtime_step", "repeated_step")}


def cases():
    rows = []
    for name, (_, typ) in SIGNATURES.items():
        bits = 64 if typ == "u64" else 32
        for value in (0, 1, 7, 31, (1 << (bits - 1)) - 1, 1 << (bits - 1),
                      (1 << bits) - 30, (1 << bits) - 20, (1 << bits) - 2, (1 << bits) - 1):
            rows.append({"function": name, "arguments": [value]})
    return rows


def expected(case):
    name, value = case["function"], case["arguments"][0]
    bits = 64 if name.startswith("wide") else 32
    if name in {"runtime_step", "repeated_step"}:
        return (3 * value + 1) % (1 << bits)
    increment = {"narrow0": 3, "narrow1": 7, "wide0": 11, "wide1": 13,
                 "scope0": 7, "scope1": 11, "discard_object": 19, "repeated_narrow": 3}[name]
    return ((2 * value if name.startswith("scope") else value) + increment) % (1 << bits)


def validate_cpp_constexpr_receipt(report):
    """Recheck the finite input, native link and retained observation bindings."""
    if report.get("schema") != "hepta.cpp-constexpr-hia-qualification.v2":
        raise ValueError("Wrong constexpr qualification schema")
    directory = Path(report["workdir"])
    actual_cases = cases()
    reference = [expected(row) for row in actual_cases]
    if report.get("cases") != actual_cases or report.get("expected") != reference:
        raise ValueError("Constexpr corpus or oracle differs")
    if (report.get("case_count") != len(actual_cases)
            or report.get("native_result_executions") != 2 * len(actual_cases)
            or report.get("observed") != {"original_cpp": reference, "standalone_hia": reference}):
        raise ValueError("Constexpr native observations or denominator differ")
    for selected in report["tools"].values():
        if digest_executable(Path(selected["path"])) != selected["sha256"]:
            raise ValueError("Selected compiler changed")
    for name in FIXTURE_NAMES:
        if ((directory / "source" / name).read_bytes() != (FIXTURE / name).read_bytes()
                or digest(FIXTURE / name) != report["fixture_sha256"][name]):
            raise ValueError("Frozen constexpr source fixture changed")
    for name, library in (("original_cpp", "original.so"), ("standalone_hia", "target.so")):
        process = report["processes"][report["observation_processes"][name]]
        payload = {"library": str(directory / library), "cases": actual_cases, "signatures": SIGNATURES}
        if (process["returncode"] != 0
                or process["argv"] != [sys.executable, "-I", "-c", RUNNER]
                or json.loads(Path(process["stdout"]).read_text()) != reference
                or json.loads(Path(process["stdin"]).read_text()) != json.loads(json.dumps(payload))):
            raise ValueError("Retained constexpr execution differs")
    expected_link = [report["tools"]["clang"]["path"], "-shared", "-fPIC",
                     str(directory / "program.o"), "-o", str(directory / "target.so")]
    link = report["processes"][report["target_link_process"]]
    if (link["argv"] != expected_link or link["returncode"] != 0
            or report["original_cpp_link_inputs_in_target"] != []):
        raise ValueError("Target must link only the directly generated HIA object")
    program = verify_program((directory / "program.hia.json").read_bytes())
    llvm = emit_program_llvm(program)
    native = report["native_build"]
    if (program.sha256 != report["program_sha256"]
            or llvm.sha256 != report["llvm_ir_sha256"]
            or digest(directory / "program.ll") != llvm.sha256
            or native["core_sha256"] != program.sha256
            or native["artifact_sha256"] != digest(directory / "program.o")
            or not native["ok"] or not set(native["binary_inventory"]["undefined"]) <= {"abort"}):
        raise ValueError("Constexpr native object is not the retained standalone Core lowering")
    selections = report["constexpr_selections"]
    migration = json.loads((directory / "migration.json").read_text())
    bodies = report["constexpr_runtime_bodies"]
    if (bodies != [row for row in migration["declarations"] if row.get("constexpr_runtime_body")]
            or not any(row["name"] == "scalar_step" for row in bodies)
            or not any(row["name"] == "scalar_step"
                       and row["status"] == "identical_inline_or_template_definition_resolved"
                       for row in bodies)
            or migration["constexpr_selections"] != selections):
        raise ValueError("Missing captured constexpr runtime bodies or complete definition coalescing")
    if (not selections or not any(row["selected_branch"] == "none" for row in selections)
            or not any(row["condition_value"] is True for row in selections)
            or not any(row["condition_value"] is False for row in selections)
            or any(type(row["condition_value"]) is not bool
                   or row["selected_branch"] not in {"then", "else", "none"}
                   or not row["template_pattern_odr_sha256"] for row in selections)):
        raise ValueError("Missing constexpr branch dispositions")
    if report["claims"] != {
        "finite_captured_constexpr_instances_qualified": True,
        "original_cpp_implementation_in_target": False,
        "discarded_object_lifecycle_executed": False,
        "arbitrary_templates_or_selected_object_lifecycles_qualified": False,
        "source_equivalence_proved": False,
    }:
        raise ValueError("Unqualified constexpr claim added")
    for item in report["retained_files"]:
        if digest(item["path"]) != item["sha256"]:
            raise ValueError("Retained constexpr file changed")
    for process in report["processes"]:
        for name in ("stdout", "stderr", "stdin"):
            if name in process and digest(process[name]) != process[name + "_sha256"]:
                raise ValueError("Retained constexpr process evidence changed")
    verify_capture(report["capture"])


def qualify_cpp_constexpr(workdir, *, clang="clang", clangxx="clang++"):
    directory = Path(workdir).absolute()
    directory.mkdir(parents=True, exist_ok=False)
    report = {"schema": "hepta.cpp-constexpr-hia-qualification.v2", "ok": False,
              "workdir": str(directory), "processes": [], "observation_processes": {}, "observed": {}}
    started = time.perf_counter()
    try:
        report["tools"] = {}
        for name, selected in (("clang", clang), ("clangxx", clangxx)):
            found = shutil.which(selected)
            if found is None:
                raise ValueError("Required compiler unavailable: " + name)
            path = Path(found).resolve(strict=True)
            report["tools"][name] = {"path": str(path), "sha256": digest_executable(path)}
        report["fixture_sha256"] = {name: digest(FIXTURE / name) for name in FIXTURE_NAMES}
        actual_cases = cases()
        reference = [expected(row) for row in actual_cases]
        _write(directory / "plan.json", {
            "schema": "hepta.cpp-constexpr-hia-plan.v2", "tools": report["tools"],
            "fixture_sha256": report["fixture_sha256"], "cases": actual_cases, "expected": reference,
            "native_process_timeout_seconds": 90,
            "target_link_inputs": [str(directory / "program.o")],
            "scope": "Finite unsigned C++20 template instances; no original undefined executions.",
        })
        source = directory / "source"; source.mkdir()
        for name in FIXTURE_NAMES:
            (source / name).write_bytes((FIXTURE / name).read_bytes())
        database = directory / "compile_commands.json"
        _write(database, [{"directory": str(source), "file": name,
                           "arguments": ["clang++", "-std=c++20", "-O2", "-fPIC", "-c", name, "-o", name + ".o"]}
                          for name in ("word.cpp", "wide.cpp")])
        migration = lower_cpp_project(database, clangxx=report["tools"]["clangxx"]["path"])
        program = migration.pop("program")
        _write(directory / "migration.json", migration)
        (directory / "program.hepta").write_text(migration["source"])
        (directory / "program.hia.json").write_bytes(program.canonical_bytes)
        report.update(capture=migration["capture"], constexpr_selections=migration["constexpr_selections"],
                      constexpr_runtime_bodies=[row for row in migration["declarations"]
                                                if row.get("constexpr_runtime_body")],
                      template_instances=migration["template_instances"], program_sha256=program.sha256,
                      active_project_declarations=migration["active_project_declarations"])
        llvm = emit_program_llvm(program)
        (directory / "program.ll").write_text(llvm.text)
        report["llvm_ir_sha256"] = llvm.sha256
        report["native_build"] = build_program_native(program, directory / "program.o",
            clang=report["tools"]["clang"]["path"], kind="object")
        report["target_link_process"] = len(report["processes"])
        _process([report["tools"]["clang"]["path"], "-shared", "-fPIC", directory / "program.o",
                  "-o", directory / "target.so"], report, directory)
        report["original_cpp_link_inputs_in_target"] = []
        originals = []
        for config in migration["capture"]["configurations"]:
            obj = directory / f"original-{config['index']}.o"; originals.append(obj)
            _process([report["tools"]["clangxx"]["path"], *config["frontend_arguments"], "-c",
                      captured_source_argument(config, language="c++"), "-o", obj],
                     report, directory, cwd=Path(config["directory"]))
        _process([report["tools"]["clangxx"]["path"], "-shared", *originals, "-o", directory / "original.so"],
                 report, directory)
        interpreted = [execute_program(program, row["function"], row["arguments"]) for row in actual_cases]
        if (any(row["status"] != "returned" for row in interpreted)
                or [row["result"] for row in interpreted] != reference):
            raise ValueError("Constexpr interpreter differs from the frozen arithmetic oracle")
        report.update(cases=actual_cases, expected=reference, interpreter_results=interpreted)
        for name, library in (("original_cpp", "original.so"), ("standalone_hia", "target.so")):
            payload = {"library": str(directory / library), "cases": actual_cases, "signatures": SIGNATURES}
            report["observation_processes"][name] = len(report["processes"])
            observed = _process([sys.executable, "-I", "-c", RUNNER], report, directory, stdin=json.dumps(payload))
            report["observed"][name] = json.loads(observed)
            if report["observed"][name] != reference:
                raise ValueError("Constexpr native behavior differs: " + name)
        report.update(case_count=len(actual_cases), native_result_executions=2 * len(actual_cases),
                      claims={"finite_captured_constexpr_instances_qualified": True,
                              "original_cpp_implementation_in_target": False,
                              "discarded_object_lifecycle_executed": False,
                              "arbitrary_templates_or_selected_object_lifecycles_qualified": False,
                              "source_equivalence_proved": False})
        report["retained_files"] = [{"path": str(path), "bytes": path.stat().st_size,
                                     "sha256": digest(path)} for path in sorted(directory.rglob("*")) if path.is_file()]
        validate_cpp_constexpr_receipt(report)
        report.update(ok=True, status="finite_constexpr_instances_native_qualified")
    except Exception as exc:
        report.update(status="failed", diagnostic={"type": type(exc).__name__, "message": str(exc)})
    report["seconds"] = time.perf_counter() - started
    _write(directory / "report.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-directory", required=True)
    parser.add_argument("--clang", default="clang")
    parser.add_argument("--clangxx", default="clang++")
    args = parser.parse_args()
    report = qualify_cpp_constexpr(args.output_directory, clang=args.clang, clangxx=args.clangxx)
    print(json.dumps({key: report.get(key) for key in ("ok", "status", "case_count", "native_result_executions", "diagnostic")}, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
