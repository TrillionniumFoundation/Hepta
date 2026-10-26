"""Real captured C++ template/overload bodies -> standalone HIA -> native.

The finite corpus includes two translation units, a macro-dependent header,
four concrete template instances, overloaded functions, cross-unit calls,
signed/unsigned scalar ABI boundaries and a real checked-overflow abort.
Original C++ objects are only linked into the reference shared library.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import random
import shutil
import signal
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta.c_project import verify_capture
from hepta.clang_capture import run_bounded
from hepta.cpp_project_migrate import lower_cpp_project
from hepta.hia_program import execute_program, verify_program
from hepta.hia_program_runtime import HIAProgramTrap
from hepta.hia_program_llvm import build_program_native, emit_program_llvm
from hepta.native_tool_identity import digest_executable


SIGNATURES = {"word": (["u32", "u32"], "u32"), "wide": (["u64", "u64"], "u64"),
              "signed_clamp": (["i32"] * 3, "i32"), "wide_clamp": (["i64"] * 3, "i64"),
              "cross_unit": (["u32", "u64"], "u64"), "signed_step": (["i32"], "i32"),
              "positive": (["u32"], "bool")}
RUNNER = r'''
import ctypes, json, resource, sys
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
data=json.load(sys.stdin)
types={'u32':ctypes.c_uint32,'u64':ctypes.c_uint64,'i32':ctypes.c_int32,
       'i64':ctypes.c_int64,'bool':ctypes.c_bool}
library=ctypes.CDLL(data['library'])
answers=[]
for case in data['cases']:
    arguments,returns=data['signatures'][case['function']]
    fn=getattr(library,case['function'])
    fn.argtypes=[types[x] for x in arguments];fn.restype=types[returns]
    answers.append(fn(*case['arguments']))
print(json.dumps(answers,separators=(',',':')))
'''


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _write(path, value):
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True, indent=2, allow_nan=False)
        stream.write("\n")


def _process(argv, report, directory, *, stdin=None, expected=0):
    start = time.perf_counter()
    result = run_bounded(list(map(str, argv)), input_text=stdin, timeout=90,
                         stdout_limit=2_000_000, stderr_limit=1_000_000)
    ordinal = len(report["processes"])
    out, err = directory / f"process-{ordinal:02d}.stdout", directory / f"process-{ordinal:02d}.stderr"
    out.write_text(result.stdout); err.write_text(result.stderr)
    row = {"argv": list(map(str, argv)), "returncode": result.returncode,
           "seconds": time.perf_counter() - start,
           "stdout": str(out), "stdout_sha256": digest(out),
           "stderr": str(err), "stderr_sha256": digest(err)}
    if stdin is not None:
        inp = directory / f"process-{ordinal:02d}.stdin"
        inp.write_text(stdin)
        row.update(stdin=str(inp), stdin_sha256=digest(inp))
    report["processes"].append(row)
    if result.returncode != expected:
        raise ValueError("Unexpected native process exit: " + repr(row) + "\n" + result.stderr[-2000:])
    return result.stdout


def cases():
    rng = random.Random(0x484941435050)
    word = [0, 1, (1 << 31) - 1, 1 << 31, (1 << 32) - 1]
    wide = [0, 1, (1 << 63) - 1, 1 << 63, (1 << 64) - 1]
    values = []
    for i in range(37):
        x = word[i] if i < len(word) else rng.getrandbits(32)
        y = wide[i] if i < len(wide) else rng.getrandbits(64)
        values.extend([{"function": "word", "arguments": [x, rng.getrandbits(32)]},
                       {"function": "wide", "arguments": [y, rng.getrandbits(64)]},
                       {"function": "cross_unit", "arguments": [x, y]},
                       {"function": "positive", "arguments": [x]}])
    for bits, function in [(32, "signed_clamp"), (64, "wide_clamp")]:
        values.extend({"function": function, "arguments": [x, -17, 42]}
                      for x in [-(1 << (bits - 1)), -18, -17, 0, 42, 43, (1 << (bits - 1)) - 1])
        values.extend({"function": function, "arguments": [rng.randint(-(1 << (bits - 1)), (1 << (bits - 1)) - 1),
                                                               rng.randint(-100000, 0), rng.randint(0, 100000)]}
                      for _ in range(30))
    values.extend({"function": "signed_step", "arguments": [x]}
                  for x in [-(1 << 31), -1, 0, 1, (1 << 31) - 2])
    return values


def expected(case):
    name, args = case["function"], case["arguments"]
    if name in {"word", "wide"}:
        bits, count = (32, 3) if name == "word" else (64, 5)
        value, salt = args
        for index in range(count):
            value = (value * 33 + salt + index) % (1 << bits)
        return (value + 19) % (1 << bits)
    if name in {"signed_clamp", "wide_clamp"}:
        value, low, high = args
        return low if value < low else high if value > high else value
    if name == "cross_unit":
        return expected({"function": "word", "arguments": [args[0], 7]}) ^ expected({"function": "wide", "arguments": [args[1], 11]})
    if name == "signed_step":
        return args[0] + 1
    if name == "positive":
        return args[0] != 0
    raise ValueError("Unknown frozen corpus function")


def validate_cpp_project_receipt(report):
    """Check retained input/core/link/observation consistency, not a proof.

    In particular the allowed target link inputs are reconstructed here rather
    than accepted from mutually editable receipt arrays.
    """
    if report.get("schema") != "hepta.cpp-project-hia-qualification.v1":
        raise ValueError("Wrong qualification schema")
    directory = Path(report["workdir"])
    clang = report["tools"]["clang"]["path"]
    if digest_executable(Path(clang)) != report["tools"]["clang"]["sha256"]:
        raise ValueError("Native compiler identity changed")
    actual_cases = cases()
    reference = [expected(row) for row in actual_cases]
    if report["cases"] != actual_cases or report["expected"] != reference:
        raise ValueError("Finite corpus denominator or oracle differs")
    if report["observed"] != {"original_cpp": reference, "standalone_hia": reference}:
        raise ValueError("Native behavior differs from the frozen oracle")
    for name, role in [("original_cpp", "original"), ("standalone_hia", "target")]:
        observed = report["observation_processes"][name]
        process = report["processes"][observed]
        if process["returncode"] != 0 or json.loads(Path(process["stdout"]).read_text()) != reference:
            raise ValueError("Retained native execution differs from observations")
        payload = {"library": str(directory / (role + ".so")), "cases": actual_cases, "signatures": SIGNATURES}
        if json.loads(Path(process["stdin"]).read_text()) != json.loads(json.dumps(payload)):
            raise ValueError("Native observation input differs from frozen cases")
        if process["argv"] != [sys.executable, "-I", "-c", RUNNER]:
            raise ValueError("Native observation runner differs")
    required = [clang, "-shared", "-fPIC", str(directory / "program.o"), "-o", str(directory / "target.so")]
    process = report["processes"][report["target_link_process"]]
    if (report["target_link_argv"] != required or process["argv"] != required or process["returncode"] != 0
            or report.get("original_cpp_link_inputs_in_target") != []):
        raise ValueError("Target must link only the directly generated HIA object")
    program = verify_program((directory / "program.hia.json").read_bytes())
    if program.sha256 != report["program_sha256"]:
        raise ValueError("Retained standalone core identity differs")
    if emit_program_llvm(program).sha256 != report["llvm_ir_sha256"] or digest(directory / "program.ll") != report["llvm_ir_sha256"]:
        raise ValueError("LLVM is not the direct lowering of the retained core")
    native = report["native_build"]
    if native["core_sha256"] != program.sha256 or native["artifact_sha256"] != digest(directory / "program.o"):
        raise ValueError("Native object identity differs from the retained core build")
    if not native["ok"] or not set(native["binary_inventory"]["undefined"]) <= {"abort"}:
        raise ValueError("Scalar native object unexpectedly imports foreign implementations")
    if report["claims"] != {"finite_template_body_migration_qualified": True,
                             "scalar_c_abi_executed": True,
                             "original_cpp_implementation_in_target": False,
                             "arbitrary_templates_stl_raii_qualified": False,
                             "cpp_class_or_mangled_abi_preserved": False,
                             "source_equivalence_proved": False,
                             "independent_total_development_cost_improvement_proved": False}:
        raise ValueError("Unqualified claim added to template migration receipt")
    for item in report["retained_files"]:
        if digest(item["path"]) != item["sha256"]:
            raise ValueError("Retained file changed")
    for process in report["processes"]:
        for field in ("stdout", "stderr", "stdin"):
            if field in process and digest(process[field]) != process[field + "_sha256"]:
                raise ValueError("Retained process evidence changed")
    control = report["overflow_control"]
    invalid = {"function": "signed_step", "arguments": [(1 << 31) - 1]}
    trap_process = report["processes"][control["native_process"]]
    trap_payload = {"library": str(directory / "target.so"), "cases": [invalid], "signatures": SIGNATURES}
    if (control["native_returncode"] != -signal.SIGABRT or trap_process["returncode"] != -signal.SIGABRT
            or control["case"] != invalid or control["original_cpp_executed_outside_defined_domain"] is not False
            or trap_process["argv"] != [sys.executable, "-I", "-c", RUNNER]
            or json.loads(Path(trap_process["stdin"]).read_text()) != json.loads(json.dumps(trap_payload))):
        raise ValueError("Checked overflow was not observed as an actual abort")
    verify_capture(report["capture"])


def qualify_cpp_templates_to_hia(workdir, *, clang="clang", clangxx="clang++"):
    directory = Path(workdir).absolute()
    directory.mkdir(parents=True, exist_ok=False)
    report = {"schema": "hepta.cpp-project-hia-qualification.v1", "ok": False,
              "workdir": str(directory), "processes": [], "observed": {}, "observation_processes": {}}
    started = time.perf_counter()
    try:
        tools = {}
        for name, selected in [("clang", clang), ("clangxx", clangxx)]:
            found = shutil.which(selected)
            if found is None:
                raise ValueError("Required native tool unavailable: " + name)
            actual = Path(found).resolve(strict=True)
            tools[name] = {"path": str(actual), "sha256": digest_executable(actual)}
        report["tools"] = tools
        fixtures = directory / "source"; fixtures.mkdir()
        for name in ("generic.hpp", "word.cpp", "wide.cpp"):
            (fixtures / name).write_bytes((ROOT / "examples/cpp/project_templates" / name).read_bytes())
        db = directory / "compile_commands.json"
        _write(db, [{"directory": str(fixtures), "file": name,
                    "arguments": ["clang++", "-std=c++20", "-DPROJECT_BIAS=19", "-O2", "-fPIC", "-c", name, "-o", name + ".o"]}
                   for name in ("word.cpp", "wide.cpp")])
        compile_start = time.perf_counter()
        migration = lower_cpp_project(db, clangxx=tools["clangxx"]["path"])
        report["translation_seconds"] = time.perf_counter() - compile_start
        program = migration.pop("program")
        (directory / "program.hia.json").write_bytes(program.canonical_bytes)
        (directory / "program.hepta").write_text(migration["source"])
        _write(directory / "migration.json", migration)
        report.update(capture=migration["capture"], declarations=migration["declarations"],
                      template_instances=migration["template_instances"],
                      active_project_declarations=migration["active_project_declarations"],
                      program_sha256=program.sha256)
        llvm = emit_program_llvm(program)
        (directory / "program.ll").write_text(llvm.text)
        report["llvm_ir_sha256"] = llvm.sha256
        report["native_build"] = build_program_native(program, directory / "program.o", clang=tools["clang"]["path"], kind="object")
        report["target_link_argv"] = [tools["clang"]["path"], "-shared", "-fPIC", str(directory / "program.o"), "-o", str(directory / "target.so")]
        report["target_link_process"] = len(report["processes"])
        _process(report["target_link_argv"], report, directory)
        report["original_cpp_link_inputs_in_target"] = []
        originals = []
        for config in migration["capture"]["configurations"]:
            obj = directory / f"original-{config['index']}.o"; originals.append(obj)
            _process([tools["clangxx"]["path"], *config["frontend_arguments"], "-O2", "-fPIC", "-c", config["source"], "-o", obj], report, directory)
        _process([tools["clangxx"]["path"], "-shared", *originals, "-o", directory / "original.so"], report, directory)
        actual_cases = cases()
        reference = [expected(row) for row in actual_cases]
        interpreted = [execute_program(program, row["function"], row["arguments"]) for row in actual_cases]
        if any(row["status"] != "returned" for row in interpreted) or [row["result"] for row in interpreted] != reference:
            raise ValueError("Standalone interpreter differs from scalar corpus oracle")
        report.update(cases=actual_cases, expected=reference, interpreter_results=interpreted)
        for name, library in [("original_cpp", "original.so"), ("standalone_hia", "target.so")]:
            payload = {"library": str(directory / library), "cases": actual_cases, "signatures": SIGNATURES}
            report["observation_processes"][name] = len(report["processes"])
            result = _process([sys.executable, "-I", "-c", RUNNER], report, directory, stdin=json.dumps(payload))
            report["observed"][name] = json.loads(result)
            if report["observed"][name] != reference:
                raise ValueError("Native template migration differs from expected corpus: " + name)
        invalid = {"function": "signed_step", "arguments": [(1 << 31) - 1]}
        try:
            execute_program(program, invalid["function"], invalid["arguments"])
        except HIAProgramTrap as exc:
            trap = exc.report
        else:
            raise ValueError("Interpreter did not check signed overflow")
        trap_index = len(report["processes"])
        payload = {"library": str(directory / "target.so"), "cases": [invalid], "signatures": SIGNATURES}
        _process([sys.executable, "-I", "-c", RUNNER], report, directory,
                 stdin=json.dumps(payload), expected=-signal.SIGABRT)
        report["overflow_control"] = {"case": invalid, "interpreter": trap,
                                      "native_process": trap_index, "native_returncode": -signal.SIGABRT,
                                      "original_cpp_executed_outside_defined_domain": False}
        altered = deepcopy(program.as_dict())
        target = next(fn for fn in altered["functions"] if fn["name"] == "word")
        target["returns"] = ["bool"]
        try:
            verify_program(altered)
        except ValueError as exc:
            report["negative_controls"] = [{"kind": "forged_return_type", "rejected": True,
                                             "diagnostic": str(exc)}]
        else:
            raise ValueError("Forged standalone return type was accepted")
        report["claims"] = {"finite_template_body_migration_qualified": True,
                             "scalar_c_abi_executed": True,
                             "original_cpp_implementation_in_target": False,
                             "arbitrary_templates_stl_raii_qualified": False,
                             "cpp_class_or_mangled_abi_preserved": False,
                             "source_equivalence_proved": False,
                             "independent_total_development_cost_improvement_proved": False}
        report["cost_observations"] = {"translation_wall_seconds": report["translation_seconds"],
                                       "original_project_bytes": sum((fixtures / n).stat().st_size for n in ("generic.hpp", "word.cpp", "wide.cpp")),
                                       "generated_hepta_bytes": (directory / "program.hepta").stat().st_size,
                                       "generated_hia_bytes": (directory / "program.hia.json").stat().st_size,
                                       "human_review_or_maintenance_cost_measured": False}
        report["retained_files"] = [{"path": str(path), "sha256": digest(path)}
                                     for path in sorted(directory.rglob("*")) if path.is_file()]
        validate_cpp_project_receipt(report)
        report.update(ok=True, status="finite_cpp_template_native_qualification_passed",
                      case_count=len(actual_cases), native_result_executions=2 * len(actual_cases),
                      concrete_template_instance_count=sum(len(x["instances"]) for x in migration["template_instances"]),
                      total_seconds=time.perf_counter() - started)
    except Exception as exc:
        report.update(ok=False, status="rejected", diagnostic={"type": type(exc).__name__, "message": str(exc)},
                      total_seconds=time.perf_counter() - started)
    _write(directory / "qualification.json", report)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workdir", type=Path, required=True)
    parser.add_argument("--clang", default=os.environ.get("CLANG", "clang"))
    parser.add_argument("--clangxx", default=os.environ.get("CLANGXX", "clang++"))
    args = parser.parse_args(argv)
    report = qualify_cpp_templates_to_hia(args.workdir, clang=args.clang, clangxx=args.clangxx)
    print(json.dumps({k: report.get(k) for k in ("ok", "status", "case_count", "concrete_template_instance_count", "diagnostic")}, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
