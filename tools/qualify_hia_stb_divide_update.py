#!/usr/bin/env python3
"""Requalify the real stb_divide overflow fix through existing Core and LLVM.

Old C undefined behavior is retained as a failing UBSan observation, never
used as a positive equivalence oracle. This is one finite historical update,
not a new source language, ownership system, performance or agent experiment.
"""
from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import re
import shutil
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta.c_migrate import migrate_c_project
from hepta.c_project import captured_source_argument, verify_capture
from hepta.clang_capture import run_bounded
from hepta.hia_program import execute_program, verify_program
from hepta.hia_program_llvm import build_program_native, emit_program_llvm
from hepta.hia_program_runtime import HIAProgramTrap
from hepta.hia_program_source import lower_source
from tools.qualify_c_stb_divide import FUNCTIONS, HARNESS, MIN, MAX, replay_rows, verify_upstream as verify_successor
from tools.qualify_hia_musl_strncmp import configured_frontend_libraries

BASELINE = ROOT / "tests/fixtures/c_migration/stb_divide_v0_93"
SUCCESSOR = ROOT / "tests/fixtures/c_migration/stb_divide"
PINS = {
    "0.93": {"commit": "dcb1116f1351bc8edad059d9ca432e8f322ba922", "bytes": 14279,
             "git_blob": "f8b1f3e36d4cc20936c312c34efda86d1badf2ec",
             "sha256": "160e8c23d1c21aa2845062e357af06ca1c833ffa514d4ca7504fe11af77a6866"},
    "0.94": {"commit": "003501f6d7a8668ce8b6d875e34dd97ad0d5d5b5", "bytes": 14507,
             "git_blob": "6a51e3f2e3b328df25bf9c9a866268782889d08c",
             "sha256": "46358dedcc0f49324a602f796b13f24e00fa0e512046354ee69511997401af6c"},
}
FLAGS = ["-std=c11", "-O2", "-DC_INTEGER_DIVISION_TRUNCATES"]
SANITIZER_FLAGS = ["-fsanitize=undefined", "-fno-sanitize-recover=undefined"]
PROTOCOL = {
    "schema": "hepta.hia.stb-divide-changed-body-update-protocol.v1",
    "versions": ["0.93", "0.94"], "functions": list(FUNCTIONS),
    "upstream_fix": "c38ec91d229cbe56167f8af865c05b3d92db705f",
    "flags": FLAGS, "original_c_sanitizer_flags": SANITIZER_FLAGS,
    "active_changed_functions": ["stb_div_floor", "stb_mod_eucl"],
    "common_grid": [-3, -2, -1, 0, 1, 2, 3], "seed": 20261030, "seeded_pairs": 64,
    "native_route": "captured C project to existing Hepta source to Core to direct LLVM",
    "old_undefined_inputs_are_equivalence_successes": False,
    "other_macro_configurations_qualified": False, "new_holdout": False,
    "model_experiment": False, "performance_advantage_measured": False,
}
WITNESSES = [
    {"case": "floor_positive_negative_intermediate", "function": "stb_div_floor", "arguments": [MAX, -2]},
    {"case": "floor_negative_positive_intermediate", "function": "stb_div_floor", "arguments": [MIN + 1, 2]},
    {"case": "negative_absolute_minimum", "function": "stb_mod_eucl", "arguments": [-7, MIN]},
    {"case": "negative_absolute_minimum_edge", "function": "stb_mod_eucl", "arguments": [-1, MIN]},
]
CLAIMS = {
    "changed_active_bodies_recaptured_and_retranslated": True,
    "manual_migrated_body_edits": 0, "original_c_linked_into_hia_target": False,
    "rust_codegen_used": False, "fallback_used": False,
    "all_input_source_or_backend_refinement_proved": False,
    "arbitrary_c_cpp_maintenance_qualified": False, "foreign_noexcept_recovery_qualified": False,
    "native_allocator_counters_measured": False, "human_effort_measured": False,
    "complete_environment_attested": False, "performance_advantage_measured": False,
}
ORIGINAL_PROBE = r'''#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <sys/resource.h>
#define STB_DIVIDE_IMPLEMENTATION
#include "stb_divide.h"
_Static_assert(sizeof(int)==4 && INT_MIN==(-2147483647-1), "int32 required");
typedef int (*function_t)(int,int);
static function_t functions[6] = {stb_div_trunc,stb_div_floor,stb_div_eucl,
                                 stb_mod_trunc,stb_mod_floor,stb_mod_eucl};
static int number(const char *s, int *out) {
    char *end; long value; errno=0; value=strtol(s,&end,10);
    if(errno || end==s || *end || value<INT_MIN || value>INT_MAX)return 0;
    *out=(int)value; return 1;
}
int main(int argc,char **argv) {
    int index,a,b,value; struct rlimit limit={0,0};
    if(setrlimit(RLIMIT_CORE,&limit) || argc!=4 || !number(argv[1],&index)
       || index<0 || index>=6 || !number(argv[2],&a) || !number(argv[3],&b))return 2;
    puts("ENTERED_ORIGINAL_C"); fflush(stdout);
    value=functions[index](a,b);
    printf("{\"value\":%d}\n",value); return 0;
}
'''


def require(condition, message):
    if not condition:
        raise ValueError("E_HIA_STB_UPDATE: " + message)


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def write(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n")


def identity(path):
    path = Path(path)
    data = path.read_bytes()
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def verify_inputs():
    verify_successor()
    for version, fixture in (("0.93", BASELINE), ("0.94", SUCCESSOR)):
        data = (fixture / "stb_divide.h").read_bytes()
        pin = PINS[version]
        metadata = json.loads((fixture / "UPSTREAM.json").read_text())
        require(metadata["commit"] == pin["commit"] and metadata["source_modifications"] == [], "upstream provenance changed")
        require(identity(fixture / "stb_divide.h") == {k: pin[k] for k in ("bytes", "sha256")}, "original header changed")
        require(hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest() == pin["git_blob"], "upstream Git blob differs")
        require(b"ALTERNATIVE A - MIT License" in data and b"ALTERNATIVE B - Public Domain" in data, "complete embedded licenses missing")
    require(PINS["0.93"]["sha256"] != PINS["0.94"]["sha256"], "changed original bodies required")
    return json.loads(wire(PINS))


def oracle(a, b):
    require(type(a) is int and type(b) is int and MIN <= a <= MAX and MIN <= b <= MAX
            and b and (a, b) != (MIN, -1), "outside mathematical int32 division domain")
    magnitude = abs(a) // abs(b)
    trunc = -magnitude if (a < 0) != (b < 0) else magnitude
    remainder = a % abs(b)
    return [trunc, a // b, (a - remainder) // b, a - trunc * b, a % b, remainder]


def common_defined(a, b):
    """Conservative common domain for all six functions in the fixed build.

    v0.93 floor computes -a+b or a-b before adding one. Its Euclidean
    remainder computes -INT_MIN when the truncating remainder is negative.
    These arithmetic predicates are derived before any execution result.
    """
    if not (type(a) is int and type(b) is int and MIN <= a <= MAX and MIN <= b <= MAX
            and b and (a, b) != (MIN, -1)):
        return False
    if a >= 0 and b < 0 and -a + b < MIN:
        return False
    if MIN < a < 0 and b > 0 and a - b < MIN:
        return False
    if b == MIN and MIN < a < 0:
        return False
    return True


def cases():
    pairs = [(a, b) for a in PROTOCOL["common_grid"] for b in PROTOCOL["common_grid"] if b]
    pairs += [(MIN, 1), (MIN, 2), (MIN, 7), (MIN, -2), (MIN, -7), (MIN, MIN),
              (MAX, 1), (MAX, 2), (MAX, 7), (MAX, -1), (MIN + 1, 1), (MIN + 1, -1), (0, MIN)]
    rng = random.Random(PROTOCOL["seed"])
    for _ in range(PROTOCOL["seeded_pairs"]):
        a, b = rng.randint(-1_000_000, 1_000_000), rng.randint(-1_000_000, 1_000_000)
        pairs.append((a, b or 1))
    require(len(pairs) == len(set(pairs)) and all(common_defined(a, b) for a, b in pairs), "fixed common-domain matrix changed")
    return [{"case": index, "a": a, "b": b, "expected": oracle(a, b)} for index, (a, b) in enumerate(pairs)]


def source_state():
    def git(*args):
        return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()
    paths = [Path(__file__), ROOT / "tools/qualify_c_stb_divide.py", ROOT / "tools/qualify_hia_musl_strncmp.py",
             ROOT / "tests/test_hia_stb_divide_update.py", *sorted((ROOT / "hepta").glob("*.py")),
             *sorted(BASELINE.rglob("*")), *sorted(SUCCESSOR.rglob("*"))]
    return {"head": git("rev-parse", "HEAD"), "tree": git("rev-parse", "HEAD^{tree}"),
            "status": git("status", "--porcelain", "--untracked-files=all"),
            "files": {str(p.relative_to(ROOT)): identity(p) for p in paths if p.is_file()}}


def tools_state(clang, gcc):
    return {"clang": {"path": clang, **identity(clang)}, "gcc": {"path": gcc, **identity(gcc)},
            "python": {"path": str(Path(sys.executable).resolve()), "version": sys.version,
                       **identity(Path(sys.executable).resolve())},
            "frontend_libraries": configured_frontend_libraries()}


def _run(argv, output, report, stage, *, expected=0, stdout_limit=256_000, cwd=None):
    started = time.monotonic_ns()
    row = {"index": len(report["processes"]), "stage": stage, "argv": list(map(str, argv)),
           "cwd": str(output if cwd is None else cwd), "returncode": None, "stdout": "", "stderr": "", "status": "started"}
    report["processes"].append(row)
    try:
        observed = run_bounded(row["argv"], cwd=row["cwd"], timeout=60, stdin_limit=0,
                               stdout_limit=stdout_limit, stderr_limit=256_000)
        row.update(returncode=observed.returncode, stdout=observed.stdout, stderr=observed.stderr, status="completed")
        if expected is not None:
            require(observed.returncode == expected, stage + " process exit differs")
        return row
    except BaseException as error:
        row["error"] = {"type": type(error).__name__, "message": str(error), "code": getattr(error, "code", None)}
        capture = getattr(error, "capture", None)
        if capture is not None:
            row.update(returncode=capture.returncode, stdout=capture.stdout.decode("utf-8", "replace"),
                       stderr=capture.stderr.decode("utf-8", "replace"), status="bounded-capture-failed")
        raise
    finally:
        row["wall_ns"] = time.monotonic_ns() - started
        for field in ("stdout", "stderr"):
            name = f"process-{row['index']:03d}.{field}.txt"
            (output / name).write_text(row[field])
            row[field + "_file"] = name
            row[field + "_identity"] = identity(output / name)


def active_bodies(ast):
    ignored = {"id", "loc", "range", "previousDecl", "typeAliasDeclId", "isUsed", "isReferenced"}
    def semantic(value):
        if type(value) is dict:
            return {k: semantic(v) for k, v in value.items() if k not in ignored}
        return [semantic(v) for v in value] if type(value) is list else value
    result = {}
    for node in ast["inner"]:
        bodies = [child for child in node.get("inner", []) if child.get("kind") == "CompoundStmt"]
        if node.get("kind") == "FunctionDecl" and bodies:
            require(node["name"] in FUNCTIONS and len(bodies) == 1 and node["name"] not in result, "active body inventory differs")
            result[node["name"]] = hashlib.sha256(wire(semantic(bodies[0])).encode()).hexdigest()
    require(set(result) == set(FUNCTIONS), "all six active bodies required")
    return result


def _inputs(path, rows):
    path.write_text("".join(" ".join(map(str, [row["a"], row["b"], *row["expected"]])) + "\n" for row in rows))


def _vm(program, function, args):
    started = time.monotonic_ns()
    try:
        observed = execute_program(program, function, args, max_heap_bytes=0)
        row = {"status": "returned", "observation": observed}
    except HIAProgramTrap as error:
        row = {"status": "trapped", "code": error.code, "observation": error.report}
    row["wall_ns"] = time.monotonic_ns() - started
    require(not any(row["observation"]["resources"].values()), "scalar component used resources")
    return row


def _prepare_version(version, output, report, clang, gcc):
    fixture = BASELINE if version == "0.93" else SUCCESSOR
    work = output / version
    work.mkdir()
    (work / "stb_divide.h").write_bytes((fixture / "stb_divide.h").read_bytes())
    (work / "implementation.c").write_bytes((SUCCESSOR / "implementation.c").read_bytes())
    database = work / "compile_commands.json"
    write(database, [{"directory": str(work), "file": "implementation.c",
                      "arguments": [clang, *FLAGS, "-c", "implementation.c", "-o", "implementation.o"]}])
    row = {"version": version, "status": "preparing", "witnesses": [], "invalid_target_inputs": []}
    report["versions"].append(row)
    started = time.monotonic_ns()
    migration = migrate_c_project(database, work / "translated", clang=clang, verify_native=False)
    write(work / "migration.json", migration)
    require(migration["ok"] and migration["declaration_inventory_complete"]
            and migration["coverage"]["active_project_declarations"] == 12
            and migration["coverage"]["status_counts"] == {"function_converted": 6, "prototype_resolved": 6}
            and {fn["name"] for fn in migration["functions"]} == set(FUNCTIONS), "complete C component migration failed")
    row["migration_wall_ns"] = time.monotonic_ns() - started
    row["active_declarations"] = 12
    config = migration["build"]["configurations"][0]
    ast = _run([clang, *config["frontend_arguments"], "-Werror", "-fsyntax-only", "-Xclang", "-ast-dump=json",
                captured_source_argument(config)], output, report, version + "-ast", stdout_limit=4_000_000, cwd=work)
    (work / "raw-clang-ast.json").write_text(ast["stdout"])
    row["active_body_sha256"] = active_bodies(json.loads(ast["stdout"]))
    source = (work / "translated/source.hepta").read_text() + "\n" + "\n".join(
        f'export "C" fn {fn}(a:i32,b:i32)->i32 effects {{panic,write}} {{return c_{fn}(a,b);}}' for fn in FUNCTIONS)
    (work / "program.hepta").write_text(source + "\n")
    started = time.monotonic_ns()
    program = lower_source(source)
    (work / "program.hia.json").write_bytes(program.canonical_bytes)
    row["core_sha256"] = program.sha256
    row["lowering_wall_ns"] = time.monotonic_ns() - started
    llvm = emit_program_llvm(program)
    (work / "program.ll").write_text(llvm.text)
    started = time.monotonic_ns()
    build = build_program_native(program, work / "hia.so", clang=clang)
    row["native_build_wall_ns"] = time.monotonic_ns() - started
    write(work / "native-build.json", build)
    require(build["ok"] and build["core_sha256"] == program.sha256
            and all(build["claims"][key] is False for key in ("rust_codegen_used", "c_codegen_used", "fallback_used")),
            "direct LLVM target required")
    row["hia_artifact"] = identity(work / "hia.so")
    (work / "harness.c").write_text(HARNESS)
    (work / "original-probe.c").write_text(ORIGINAL_PROBE)
    for name in ("harness", "original-probe"):
        _run([gcc, *FLAGS, *SANITIZER_FLAGS, work / (name + ".c"), "-ldl", "-o", work / name],
             output, report, version + "-build-" + name)
    verify_capture(migration["build"])
    row["status"] = "prepared"
    return work, row, program, migration


def _positive(work, rows, label, output, report):
    inputs = work / (label + "-inputs.txt")
    observations = work / (label + "-native.tsv")
    _inputs(inputs, rows)
    process = _run([work / "harness", work / "hia.so", inputs, observations], output, report,
                   work.name + "-" + label + "-native")
    expected = {"cases": len(rows), "native_function_observations": len(rows) * 12,
                "allocation_probe": False, "resource_before": None, "resource_after": None}
    require(json.loads(process["stdout"]) == expected and process["stderr"] == ""
            and replay_rows(observations, rows) == len(rows), "native matrix differs from independent oracle")
    return {"process": process["index"], "summary": expected,
            "observations": str(observations.relative_to(output)), "inputs": str(inputs.relative_to(output))}


def _common_vm(program, rows, path):
    count = 0
    with path.open("x") as stream:
        for case in rows:
            for function, expected in zip(FUNCTIONS, case["expected"]):
                observed = _vm(program, function, [case["a"], case["b"]])
                require(observed["status"] == "returned" and observed["observation"]["result"] == expected, "VM common-domain result differs")
                stream.write(wire({"case": case["case"], "function": function, "arguments": [case["a"], case["b"]],
                                   "expected": expected, **observed}) + "\n")
                count += 1
    return count


def qualify(output, *, clang, gcc, source_sha=None):
    """A missing source_sha is explicitly a development run, not final qualification."""
    output = Path(output).absolute()
    output.mkdir(parents=True, exist_ok=False)
    started = time.monotonic_ns()
    report = {"schema": "hepta.hia.stb-divide-changed-body-update.v1", "protocol": json.loads(wire(PROTOCOL)),
              "status": "incomplete", "ok": False, "processes": [], "versions": [],
              "output_directory": str(output),
              "expected_source_head": source_sha, "qualified_implementation_commit": False,
              "development_only": source_sha is None, "claims": json.loads(wire(CLAIMS)),
              "human_effort": None, "agent_tokens": None, "historical_results_relabelled": False}
    resolved = None
    try:
        report["source_before"] = source_state()
        require(platform.system() == "Linux" and platform.machine().lower() in {"x86_64", "amd64"}, "actual Linux x86-64 required")
        if source_sha is not None:
            require(re.fullmatch(r"[0-9a-f]{40}", source_sha) and report["source_before"]["head"] == source_sha
                    and report["source_before"]["status"] == "", "exact clean implementation commit required")
        report["upstream_pins"] = verify_inputs()
        clang, gcc = (str(Path(shutil.which(value) or value).resolve(strict=True)) for value in (clang, gcc))
        resolved = (clang, gcc)
        report["tools_before"] = tools_state(clang, gcc)
        _run([clang, "--version"], output, report, "clang-version")
        gcc_version = _run([gcc, "--version"], output, report, "gcc-version")
        require("gcc" in gcc_version["stdout"].lower(), "actual GCC UBSan reference required")
        common = cases()
        write(output / "common-cases.json", common)
        write(output / "witnesses.json", WITNESSES)
        write(output / "protocol.json", PROTOCOL)
        (output / "original-header.diff").write_text("".join(difflib.unified_diff(
            (BASELINE / "stb_divide.h").read_text().splitlines(True),
            (SUCCESSOR / "stb_divide.h").read_text().splitlines(True), fromfile="stb_divide-0.93.h", tofile="stb_divide-0.94.h")))
        prepared = {}
        for version in PROTOCOL["versions"]:
            work, row, program, migration = _prepare_version(version, output, report, clang, gcc)
            prepared[version] = (work, program, migration)
            row["common_native"] = _positive(work, common, "common", output, report)
            row["common_vm_function_observations"] = _common_vm(program, common, work / "common-vm.jsonl")
            for witness in WITNESSES:
                index = FUNCTIONS.index(witness["function"])
                arguments = witness["arguments"]
                expected = oracle(*arguments)[index]
                require(not common_defined(*arguments), "UB witness leaked into common-domain claim")
                observed = _vm(program, witness["function"], arguments)
                process = _run([work / "original-probe", index, *arguments], output, report,
                               version + "-" + witness["case"] + "-original-ubsan", expected=None)
                item = {**witness, "expected_successor_value": expected, "vm": observed, "original_c_process": process["index"],
                        "common_domain_equivalence_claimed": False}
                row["witnesses"].append(item)
                if version == "0.93":
                    require(process["returncode"] != 0 and process["stdout"] == "ENTERED_ORIGINAL_C\n"
                            and "runtime error:" in process["stderr"] and "cannot be represented" in process["stderr"]
                            and "stb_divide.h" in process["stderr"], "old signed UB was not actually observed")
                    require(observed["status"] == "trapped" and observed["code"] == "overflow", "old HIA must retain its checked overflow trap")
                    trapped = _run([work / "harness", work / "hia.so", "--trap", index, *arguments], output,
                                   report, version + "-" + witness["case"] + "-hia-trap", expected=-signal.SIGABRT)
                    require(trapped["stdout"] == "ENTERED_SAFE_TARGET\n", "old HIA trap did not enter target")
                    item.update(status="original_c_undefined_hia_trapped", hia_native_process=trapped["index"])
                else:
                    require(process["returncode"] == 0 and process["stderr"] == ""
                            and process["stdout"] == "ENTERED_ORIGINAL_C\n" + wire({"value": expected}) + "\n"
                            and observed["status"] == "returned" and observed["observation"]["result"] == expected,
                            "successor fix did not return the independent result")
                    item["status"] = "successor_defined_return"
            if version == "0.94":
                added = [{"case": i, "a": w["arguments"][0], "b": w["arguments"][1], "expected": oracle(*w["arguments"])}
                         for i, w in enumerate(WITNESSES)]
                row["successor_only_native"] = _positive(work, added, "successor-only", output, report)
                row["successor_only_vm_function_observations"] = _common_vm(program, added, work / "successor-only-vm.jsonl")
            for index, function in enumerate(FUNCTIONS):
                for args, code in (([7, 0], "division_by_zero"), ([MIN, -1], "overflow")):
                    observed = _vm(program, function, args)
                    require(observed["status"] == "trapped" and observed["code"] == code, "invalid HIA input did not preserve trap")
                    process = _run([work / "harness", work / "hia.so", "--trap", index, *args], output, report,
                                   version + "-invalid-hia-" + function, expected=-signal.SIGABRT)
                    require(process["stdout"] == "ENTERED_SAFE_TARGET\n", "invalid input did not enter HIA-only route")
                    row["invalid_target_inputs"].append({"function": function, "arguments": args,
                        "vm": observed, "process": process["index"], "original_c_called": False})
            verify_capture(migration["build"])
            row["status"] = "completed"
        old, new = report["versions"]
        report["changed_active_functions"] = sorted(name for name in FUNCTIONS if old["active_body_sha256"][name] != new["active_body_sha256"][name])
        require(report["changed_active_functions"] == PROTOCOL["active_changed_functions"]
                and old["core_sha256"] != new["core_sha256"] and old["hia_artifact"] != new["hia_artifact"], "a distinct changed-body/Core/native update is required")
        work = prepared["0.94"][0]
        stale = _run([work / "harness", prepared["0.93"][0] / "hia.so", work / "successor-only-inputs.txt", output / "stale-target.tsv"],
                     output, report, "stale-baseline-target", expected=-signal.SIGABRT)
        wrong = lower_source("\n".join(f'export "C" fn {fn}(a:i32,b:i32)->i32 effects {{}} {{return 0;}}' for fn in FUNCTIONS))
        (output / "wrong.hia.json").write_bytes(wrong.canonical_bytes)
        write(output / "wrong-native-build.json", build_program_native(wrong, output / "wrong.so", clang=clang))
        wrong_run = _run([work / "harness", output / "wrong.so", work / "common-inputs.txt", output / "wrong-target.tsv"],
                         output, report, "wrong-but-resource-legal-target", expected=2)
        require("functional mismatch" in wrong_run["stderr"], "wrong code was not rejected by the actual oracle")
        report["negative_controls"] = {"stale_target_process": stale["index"], "wrong_target_process": wrong_run["index"],
                                       "old_undefined_behavior_reclassified_as_success": False}
        report["counts"] = {"common_inputs": len(common), "functions_per_version": 6,
            "common_native_function_observations": len(common) * 12 * 2,
            "common_vm_function_observations": len(common) * 6 * 2,
            "old_ubsan_failure_processes": len(WITNESSES), "old_hia_overflow_processes": len(WITNESSES),
            "successor_only_native_function_observations": len(WITNESSES) * 12,
            "successor_probe_return_processes": len(WITNESSES),
            "successor_only_vm_function_observations": len(WITNESSES) * 6,
            "witness_vm_observations": len(WITNESSES) * 2, "hia_invalid_target_processes": 24,
            "hia_invalid_vm_observations": 24, "failed_native_negative_controls": 2}
        report.update(ok=True, status="passed_finite_changed_body_update")
    except BaseException as error:
        report.update(ok=False, status="failed", error={"type": type(error).__name__, "message": str(error), "code": getattr(error, "code", None)})
    finally:
        try:
            report["source_after"] = source_state()
            require(report.get("source_before") == report["source_after"], "source changed during qualification")
            if resolved:
                report["tools_after"] = tools_state(*resolved)
                require(report.get("tools_before") == report["tools_after"], "observed tools/loader inputs changed")
            for _work, _program, capture in locals().get("prepared", {}).values():
                verify_capture(capture["build"])
        except BaseException as error:
            report.update(ok=False, status="failed_postflight", postflight_error={"type": type(error).__name__, "message": str(error)})
        report["qualified_implementation_commit"] = bool(report["ok"] and source_sha is not None)
        report["retained_files"] = {str(p.relative_to(output)): identity(p) for p in sorted(output.rglob("*")) if p.is_file()}
        if report["ok"]:
            try:
                report["readback"] = validate_qualification(output, report)
            except BaseException as error:
                report.update(ok=False, status="failed_readback", qualified_implementation_commit=False,
                              readback_error={"type": type(error).__name__, "message": str(error)})
        report["collected_work_wall_ns"] = time.monotonic_ns() - started
        report["cost_scope"] = "all attempted qualification work including failed children, postflight and readback; final report serialization excluded; not initial development/human cost"
        write(output / "qualification.json", report)
    return report


def validate_qualification(output, report=None):
    """Read retained data and recompute finite consistency; execute no native artifact."""
    output = Path(output)
    report = json.loads((output / "qualification.json").read_text()) if report is None else report
    require(report.get("schema") == "hepta.hia.stb-divide-changed-body-update.v1" and report.get("ok") is True
            and report.get("status") == "passed_finite_changed_body_update", "completed update required")
    require(wire(report["protocol"]) == wire(PROTOCOL) and wire(report["claims"]) == wire(CLAIMS)
            and report["upstream_pins"] == verify_inputs(), "protocol, source pins or claim scope differs")
    require(report["source_before"] == report["source_after"] and report["tools_before"] == report["tools_after"], "source/tool snapshot changed")
    require(report["qualified_implementation_commit"] is (report["expected_source_head"] is not None)
            and report["development_only"] is (report["expected_source_head"] is None), "development run promoted")
    if report["qualified_implementation_commit"]:
        require(report["source_before"]["head"] == report["expected_source_head"] and report["source_before"]["status"] == "", "clean source binding differs")
    retained = report["retained_files"]
    require(not any(p.is_symlink() for p in output.rglob("*")), "symlink is not retained evidence")
    require(type(retained) is dict and set(retained) == {str(p.relative_to(output)) for p in output.rglob("*")
            if p.is_file() and p != output / "qualification.json"}, "retained file inventory differs")
    for name, expected in retained.items():
        require(type(name) is str and not Path(name).is_absolute() and ".." not in Path(name).parts
                and not (output / name).is_symlink() and identity(output / name) == expected, "retained file bytes differ")
    common = cases()
    require(json.loads((output / "common-cases.json").read_text()) == common
            and json.loads((output / "witnesses.json").read_text()) == WITNESSES
            and json.loads((output / "protocol.json").read_text()) == PROTOCOL, "fixed input matrix differs")
    processes = report["processes"]
    original_root = Path(report["output_directory"])
    require(original_root.is_absolute(), "absolute original execution directory required")
    for index, process in enumerate(processes):
        require(process["index"] == index and type(process["wall_ns"]) is int and process["wall_ns"] > 0
                and process["status"] == "completed" and "error" not in process, "unfinished process or omitted cost")
        for stream in ("stdout", "stderr"):
            require(process[stream + "_file"] == f"process-{index:03d}.{stream}.txt"
                    and process[stream + "_file"] in retained, "raw stream path differs")
            require((output / process[stream + "_file"]).read_text() == process[stream]
                    and identity(output / process[stream + "_file"]) == process[stream + "_identity"], "raw process stream differs")
    def native_matrix(row, version, label, planned):
        expected_summary = {"cases": len(planned), "native_function_observations": len(planned) * 12,
                            "allocation_probe": False, "resource_before": None, "resource_after": None}
        process = processes[row["process"]]
        prefix = original_root / version
        require(wire(row["summary"]) == wire(expected_summary)
                and row["inputs"] == version + "/" + label + "-inputs.txt"
                and row["observations"] == version + "/" + label + "-native.tsv"
                and process["argv"] == list(map(str, [prefix / "harness", prefix / "hia.so",
                    prefix / (label + "-inputs.txt"), prefix / (label + "-native.tsv")]))
                and process["returncode"] == 0 and process["stderr"] == ""
                and wire(json.loads(process["stdout"])) == wire(expected_summary), "native process/matrix binding differs")
        require((output / row["inputs"]).read_text() == "".join(
            " ".join(map(str, [case["a"], case["b"], *case["expected"]])) + "\n" for case in planned)
            and replay_rows(output / row["observations"], planned) == len(planned), "native input or observation rows differ")

    def vm_matrix(path, planned, count):
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        expected_vm = [(case, function, value) for case in planned for function, value in zip(FUNCTIONS, case["expected"])]
        require(type(count) is int and len(rows) == count == len(expected_vm), "VM matrix denominator differs")
        for observed, (case, function, value) in zip(rows, expected_vm):
            require(observed["case"] == case["case"] and observed["function"] == function
                    and observed["arguments"] == [case["a"], case["b"]] and observed["expected"] == value
                    and observed["status"] == "returned" and observed["observation"]["result"] == value
                    and not any(observed["observation"]["resources"].values()), "retained VM observation differs")

    require([row["version"] for row in report["versions"]] == PROTOCOL["versions"], "version inventory differs")
    for row in report["versions"]:
        version, work = row["version"], output / row["version"]
        require(row["status"] == "completed" and row["active_declarations"] == 12
                and identity(work / "stb_divide.h") == {k: PINS[version][k] for k in ("bytes", "sha256")}, "version source/coverage differs")
        require(active_bodies(json.loads((work / "raw-clang-ast.json").read_text())) == row["active_body_sha256"], "captured active bodies differ")
        program = verify_program((work / "program.hia.json").read_bytes())
        require(program.sha256 == row["core_sha256"] and identity(work / "hia.so") == row["hia_artifact"], "Core/native identity differs")
        build = json.loads((work / "native-build.json").read_text())
        migration = json.loads((work / "migration.json").read_text())
        require(build["ok"] is True and build["core_sha256"] == program.sha256
                and build["artifact_sha256"] == row["hia_artifact"]["sha256"]
                and all(build["claims"][key] is False for key in ("rust_codegen_used", "c_codegen_used", "fallback_used")),
                "retained direct LLVM build differs")
        require(migration["ok"] is True and migration["declaration_inventory_complete"] is True
                and migration["coverage"]["active_project_declarations"] == 12
                and migration["coverage"]["status_counts"] == {"function_converted": 6, "prototype_resolved": 6}
                and {fn["name"] for fn in migration["functions"]} == set(FUNCTIONS), "retained component migration differs")
        native_matrix(row["common_native"], version, "common", common)
        vm_matrix(work / "common-vm.jsonl", common, row["common_vm_function_observations"])
        if version == "0.94":
            added = [{"case": i, "a": w["arguments"][0], "b": w["arguments"][1], "expected": oracle(*w["arguments"])}
                     for i, w in enumerate(WITNESSES)]
            native_matrix(row["successor_only_native"], version, "successor-only", added)
            vm_matrix(work / "successor-only-vm.jsonl", added, row["successor_only_vm_function_observations"])
        require(len(row["witnesses"]) == len(WITNESSES) and len(row["invalid_target_inputs"]) == 12, "failure denominator differs")
        for observed, planned in zip(row["witnesses"], WITNESSES):
            require({k: observed[k] for k in planned} == planned and observed["common_domain_equivalence_claimed"] is False, "old undefined input promoted")
            process = processes[observed["original_c_process"]]
            require(process["argv"] == list(map(str, [original_root / version / "original-probe",
                FUNCTIONS.index(planned["function"]), *planned["arguments"]])), "original probe command differs")
            expected = oracle(*planned["arguments"])[FUNCTIONS.index(planned["function"])]
            require(observed["expected_successor_value"] == expected
                    and not any(observed["vm"]["observation"]["resources"].values()), "successor oracle/resource observation differs")
            if version == "0.93":
                trapped = processes[observed["hia_native_process"]]
                require(observed["status"] == "original_c_undefined_hia_trapped" and process["returncode"] != 0
                        and process["stdout"] == "ENTERED_ORIGINAL_C\n"
                        and "runtime error:" in process["stderr"] and "cannot be represented" in process["stderr"]
                        and "stb_divide.h" in process["stderr"]
                        and observed["vm"]["status"] == "trapped" and observed["vm"]["code"] == "overflow"
                        and trapped["argv"] == list(map(str, [original_root / version / "harness", original_root / version / "hia.so",
                            "--trap", FUNCTIONS.index(planned["function"]), *planned["arguments"]]))
                        and trapped["returncode"] == -signal.SIGABRT and trapped["stdout"] == "ENTERED_SAFE_TARGET\n", "old UB/trap failure erased")
            else:
                require(observed["status"] == "successor_defined_return" and process["returncode"] == 0
                        and process["stderr"] == "" and process["stdout"] == "ENTERED_ORIGINAL_C\n" + wire({"value": expected}) + "\n"
                        and observed["vm"]["status"] == "returned" and observed["vm"]["observation"]["result"] == expected, "successor witness differs")
        invalid = [(index, function, args, code) for index, function in enumerate(FUNCTIONS)
                   for args, code in (([7, 0], "division_by_zero"), ([MIN, -1], "overflow"))]
        for observed, (index, function, args, code) in zip(row["invalid_target_inputs"], invalid):
            process = processes[observed["process"]]
            require(observed["function"] == function and observed["arguments"] == args
                    and observed["original_c_called"] is False and observed["vm"]["status"] == "trapped"
                    and observed["vm"]["code"] == code and not any(observed["vm"]["observation"]["resources"].values())
                    and process["argv"] == list(map(str, [original_root / version / "harness", original_root / version / "hia.so", "--trap", index, *args]))
                    and process["returncode"] == -signal.SIGABRT and process["stdout"] == "ENTERED_SAFE_TARGET\n",
                    "invalid original C exposure or missing target trap")
    old, new = report["versions"]
    require(report["changed_active_functions"] == PROTOCOL["active_changed_functions"]
            == sorted(fn for fn in FUNCTIONS if old["active_body_sha256"][fn] != new["active_body_sha256"][fn])
            and old["core_sha256"] != new["core_sha256"] and old["hia_artifact"] != new["hia_artifact"], "unchanged body relabelled as maintenance")
    controls = report["negative_controls"]
    stale, wrong = (processes[controls[key]] for key in ("stale_target_process", "wrong_target_process"))
    require(controls["old_undefined_behavior_reclassified_as_success"] is False
            and stale["argv"] == list(map(str, [original_root / "0.94/harness", original_root / "0.93/hia.so",
                original_root / "0.94/successor-only-inputs.txt", original_root / "stale-target.tsv"]))
            and wrong["argv"] == list(map(str, [original_root / "0.94/harness", original_root / "wrong.so",
                original_root / "0.94/common-inputs.txt", original_root / "wrong-target.tsv"]))
            and stale["returncode"] == -signal.SIGABRT and wrong["returncode"] == 2
            and "functional mismatch" in wrong["stderr"], "negative native control missing")
    expected_counts = {"common_inputs": len(common), "functions_per_version": 6,
        "common_native_function_observations": len(common) * 24, "common_vm_function_observations": len(common) * 12,
        "old_ubsan_failure_processes": 4, "old_hia_overflow_processes": 4,
        "successor_only_native_function_observations": 48, "successor_probe_return_processes": 4,
        "successor_only_vm_function_observations": 24, "witness_vm_observations": 8,
        "hia_invalid_target_processes": 24, "hia_invalid_vm_observations": 24, "failed_native_negative_controls": 2}
    require(wire(report["counts"]) == wire(expected_counts), "denominator or outcome category changed")
    return {"verified": True, "scope": "retained finite observation consistency; no archived native execution or source equivalence theorem",
            "files_rehashed": len(retained), "counts": expected_counts}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--clang", required=True)
    parser.add_argument("--gcc", default="gcc")
    parser.add_argument("--source-sha", required=True)
    options = parser.parse_args()
    report = qualify(options.output, clang=options.clang, gcc=options.gcc, source_sha=options.source_sha)
    if report["ok"]:
        print(json.dumps(validate_qualification(options.output), sort_keys=True))
    else:
        print(json.dumps({key: report.get(key) for key in ("ok", "status", "error", "postflight_error", "readback_error", "collected_work_wall_ns")}, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
