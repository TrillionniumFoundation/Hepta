"""Execute captured C/C++ migration through standalone HIA and direct LLVM.

The original implementations are separate oracles.  The HIA targets link only
their directly generated objects and the observation harness/runtime libraries.
The retained report includes full declaration inventory, build provenance,
deterministic allocator refusals and actual cleanup counts.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta.c_project import verify_capture
from hepta.cpp_class_migrate import migrate_cpp_class
from hepta.cpp_owned_migrate import migrate_cpp_owned
from hepta.hia_program import execute_program
from hepta.hia_program_llvm import build_program_native, emit_program_llvm
from hepta.hia_program_source import lower_c_multi_owner, lower_program
from hepta.modules import load_project


ALLOCATOR_HARNESS = r'''
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
void *__real_calloc(size_t,size_t);
void *__real_malloc(size_t);
void __real_free(void *);
static volatile size_t attempts=0, allocations=0, frees=0, live=0, fail_at=0;
void *__wrap_calloc(size_t n,size_t size) {
    ++attempts;
    if (fail_at && attempts==fail_at) return NULL;
    void *p=__real_calloc(n,size);
    if(p){++allocations;++live;}
    return p;
}
void *__wrap_malloc(size_t n) {
    ++attempts;
    if (fail_at && attempts==fail_at) return NULL;
    void *p=__real_malloc(n);
    if(p){++allocations;++live;}
    return p;
}
void __wrap_free(void *p) {
    if(p){++frees;--live;}
    __real_free(p);
}
extern uint64_t ENTRY(size_t,size_t,unsigned char,unsigned int);
int main(int argc,char **argv) {
    if(argc!=6)return 80;
    size_t left=(size_t)strtoull(argv[1],NULL,10),right=(size_t)strtoull(argv[2],NULL,10);
    unsigned char seed=(unsigned char)strtoul(argv[3],NULL,10);
    unsigned int early=(unsigned int)strtoul(argv[4],NULL,10);
    fail_at=(size_t)strtoull(argv[5],NULL,10);
    uint64_t result=ENTRY(left,right,seed,early);
    printf("%" PRIu64 " %zu %zu %zu %zu\n",result,attempts,allocations,frees,live);
    return live ? 81 : 0;
}
'''


CLASS_RUNNER = r'''
import ctypes,json,sys
data=json.load(sys.stdin)
types={'u32':ctypes.c_uint32,'u64':ctypes.c_uint64,'i32':ctypes.c_int32,'i64':ctypes.c_int64}
signatures={'word_trace':(['u32']*4,'u32'),'wide_trace':(['u64']*3,'u64'),
            'balance_trace':(['i32']*3,'i32'),'position_trace':(['i64']*2,'i64'),
            'state_guard':(['u32','u64','i32','i64','u32','u64','i32','i32','i64'],'i32')}
out={}
for name,path in data['libraries'].items():
    lib=ctypes.CDLL(path)
    answers=[]
    for case in data['cases']:
        params,ret=signatures[case['function']]
        fn=getattr(lib,case['function']);fn.argtypes=[types[x] for x in params];fn.restype=types[ret]
        answers.append(fn(*case['arguments']))
    out[name]=answers
print(json.dumps(out,sort_keys=True))
'''


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _write_json(path, value):
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")


def _run(command, report, directory, *, input_text=None, timeout=60):
    started = time.perf_counter()
    result = subprocess.run(list(map(str, command)), input=input_text, text=True,
                            capture_output=True, timeout=timeout)
    index = len(report["processes"])
    stdout, stderr = directory / f"process-{index:03d}.stdout", directory / f"process-{index:03d}.stderr"
    stdout.write_text(result.stdout); stderr.write_text(result.stderr)
    row = {"argv": list(map(str, command)), "returncode": result.returncode,
           "seconds": time.perf_counter() - started,
           "stdout": str(stdout), "stdout_sha256": digest(stdout),
           "stderr": str(stderr), "stderr_sha256": digest(stderr)}
    if input_text is not None:
        row["stdin_sha256"] = hashlib.sha256(input_text.encode()).hexdigest()
    report["processes"].append(row)
    if result.returncode:
        raise ValueError("Native process failed: " + repr(row) + "\n" + result.stderr[-3000:])
    return result.stdout


def _cases():
    pairs = [(0, 0), (0, 9), (7, 0), (1, 1), (3, 5), (17, 31), (64, 65), (127, 128)]
    cases = [{"arguments": [a, b, seed, early], "allocation_fail_at": None}
             for a, b in pairs for seed in (0, 249, 255) for early in (0, 1)]
    cases += [{"arguments": [17, 31, seed, early], "allocation_fail_at": failure}
              for seed in (0, 255) for early in (0, 1) for failure in (1, 2)]
    return cases


def _expected(case):
    left, right, seed, early = case["arguments"]
    if not left or not right:
        return 0
    if case["allocation_fail_at"] is not None:
        return 1000 + case["allocation_fail_at"]
    if early:
        return 2000
    return sum((i + seed) % 251 for i in range(left)) + sum(((i + seed) % 251) ^ 90 for i in range(right))


def _identity(path):
    path = Path(path).absolute()
    return {"path": str(path), "sha256": digest(path), "bytes": path.stat().st_size}


def validate_cpp_owned_hia_receipt(report):
    """Recheck retained source, core, native observations and link provenance."""
    from tools.evidence_checks import require, strict_equal
    from tools.validate_cpp_owned import EXAMPLE, cases, _observation_oracle, WRAP_FLAGS
    from hepta.hia_program import verify_program
    require(report.get("ok") is True and report.get("status") == "bounded_cpp_owner_to_standalone_hia_passed",
            "Completed actual C++ owner/HIA qualification required")
    migration = json.loads(Path(report["migration_receipt"]["path"]).read_text())
    require(report["migration_receipt"] == _identity(report["migration_receipt"]["path"]), "Migration receipt changed")
    require(migration["ok"] is True and migration["protocol_verified"] is True
            and migration["source_sha256"] == digest(EXAMPLE / "owned_bytes.cpp")
            and migration["output_sha256"] == report["migrated_source"]["sha256"]
            and migration["source_declarations"] == migration["converted_source_declarations"] == 2
            and len(migration["declaration_inventory"]) == 15 and migration["unconverted_members"] == []
            and migration["complete_ast_sha256"] == migration["protocol_ast_sha256"]
            and migration["foreign_cpp_implementation_retained"] is False
            and type(migration["foreign_cpp_calls"]) is int and migration["foreign_cpp_calls"] == 0,
            "Complete bounded C++ implementation inventory/source binding required")
    require(report["source_declarations"] == migration["source_declarations"]
            and report["converted_source_declarations"] == migration["converted_source_declarations"]
            and report["source_sha256"] == migration["source_sha256"]
            and strict_equal(report["declaration_inventory"], migration["declaration_inventory"]),
            "Displayed owned declaration accounting differs from the actual translator receipt")
    for key in ("migrated_source", "consumer", "core", "object", "case_manifest", "case_header", "prototype", "target", "original"):
        require(report[key] == _identity(report[key]["path"]), "Retained owned artifact changed: " + key)
    core = verify_program(Path(report["core"]["path"]).read_bytes())
    project = load_project(report["consumer"]["path"])
    require(lower_program(project.program).canonical_bytes == core.canonical_bytes
            and project.identity == report["project_sha256"], "Fresh migrated source differs from the compiled HIA")
    require(report["native_build"]["ok"] is True and report["native_build"]["core_sha256"] == core.sha256
            and report["native_build"]["artifact_sha256"] == report["object"]["sha256"], "Native object/core binding changed")
    vectors, expected = cases(), _observation_oracle(cases())
    require(strict_equal(json.loads(Path(report["case_manifest"]["path"]).read_text()), vectors)
            and report["case_count"] == len(vectors)
            and strict_equal(report["case_families"], dict(Counter(row["family"] for row in vectors))), "Complete owner vector inventory changed")
    require(report["foreign_cpp_link_inputs"] == [] and report["cpp_class_abi_preserved"] is False
            and report["general_cpp_raii_supported"] is False
            and report["source_equivalence_proved"] is False
            and report["migration_strategy"] == "complete_normalized_ast_protocol", "Unsupported C++ migration or ABI claim")
    recorded_link = report["target_link_argv"]
    require(type(recorded_link) is list and recorded_link
            and all(type(part) is str and part for part in recorded_link), "Recorded target link command required")
    directory = Path(report["case_header"]["path"]).parent
    expected_link = [recorded_link[0], "-std=c11", "-O2", "-fno-lto", "-Werror=implicit-function-declaration",
        *WRAP_FLAGS, "-I" + str(directory), "-include", report["prototype"]["path"],
        str(EXAMPLE / "harness.c"), report["object"]["path"], "-o", report["target"]["path"]]
    # These two receipt arrays are not independent evidence. Reconstruct the
    # closed input vector and bind the actual recorded link process to it too;
    # coordinated additions of an original .o/.a must also reject.
    require(recorded_link == expected_link and report["expected_target_link_argv"] == expected_link
            and report["processes"][0]["argv"] == expected_link,
            "Target must link the standalone HIA object with the correctly declared C harness only")
    for name in ("original_cpp", "standalone_hia"):
        process = report["processes"][report["execution_process_indices"][name]]
        require(process["returncode"] == 0 and digest(process["stdout"]) == process["stdout_sha256"]
                and strict_equal(json.loads(Path(process["stdout"]).read_text()), expected)
                and strict_equal(report["observed"][name], expected), "Actual owner values/allocator/refusal/cleanup observations differ")
    require(report["native_result_executions"] == 2 * len(vectors)
            and report["actual_fault_executions"] == 2 * expected["refusals"], "Native case/refusal accounting changed")


def qualify_cpp_owned_to_hia(workdir, *, clang="clang", clangxx="clang++", cc="cc", cxx="c++"):
    """Fresh real owner migration; original C++ is a separate native oracle."""
    from tools.validate_cpp_owned import EXAMPLE, cases, _case_sources, _observation_oracle, WRAP_FLAGS, CPP_FLAGS
    from tools.evidence_checks import strict_equal
    directory = Path(workdir).absolute()
    if directory.exists() or directory.is_symlink():
        raise ValueError("C++ owned qualification requires a new directory")
    directory.mkdir(parents=True)
    report = {"schema": "hepta.hia-cpp-owned-qualification.v1", "ok": False, "status": "in_progress",
              "processes": [], "foreign_cpp_link_inputs": [], "cpp_class_abi_preserved": False,
              "general_cpp_raii_supported": False, "source_equivalence_proved": False,
              "migration_strategy": "complete_normalized_ast_protocol"}
    try:
        migrated, consumer = directory / "migrated.hepta", directory / "consumer.hepta"
        migration = migrate_cpp_owned(EXAMPLE / "owned_bytes.cpp", migrated, clangxx=clangxx)
        _write_json(directory / "migration.json", migration)
        if migration["ok"] is not True:
            raise ValueError("Actual C++ owned implementation migration rejected: " + repr(migration["diagnostics"]))
        report["translator_invocation"] = {"callable": "hepta.cpp_owned_migrate.migrate_cpp_owned",
            "source": str(EXAMPLE / "owned_bytes.cpp"), "output": str(migrated), "clangxx": clangxx,
            "implementation_sha256": digest(ROOT / "hepta/cpp_owned_migrate.py")}
        report["migration_receipt"] = _identity(directory / "migration.json")
        report["source_declarations"] = migration["source_declarations"]
        report["converted_source_declarations"] = migration["converted_source_declarations"]
        report["declaration_inventory"] = migration["declaration_inventory"]
        report["source_sha256"] = migration["source_sha256"]
        report["exception_mapping"] = migration["exception_mapping"]
        report["limitations"] = migration["limitations"]
        consumer.write_bytes((EXAMPLE / "consumer.hepta").read_bytes())
        report["migrated_source"], report["consumer"] = _identity(migrated), _identity(consumer)
        project = load_project(consumer)
        core = lower_program(project.program)
        (directory / "owned.hia.json").write_bytes(core.canonical_bytes)
        (directory / "owned.ll").write_text(emit_program_llvm(core).text)
        report["core"], report["project_sha256"] = _identity(directory / "owned.hia.json"), project.identity
        obj = directory / "owned.o"
        report["native_build"] = build_program_native(core, obj, clang=clang, kind="object")
        report["object"] = _identity(obj)
        vectors = cases()
        _write_json(directory / "cases.json", vectors)
        header, _ = _case_sources(vectors)
        (directory / "cases.h").write_text(header)
        prototype = directory / "owned_case.h"
        prototype.write_text('#include <stddef.h>\n#include <stdint.h>\n'
            'extern uint64_t owned_case(size_t, uint8_t, size_t, uint32_t, uint32_t);\n')
        report["case_manifest"], report["case_header"], report["prototype"] = (
            _identity(directory / "cases.json"), _identity(directory / "cases.h"), _identity(prototype))
        target, original = directory / "standalone_hia", directory / "original_cpp"
        target_link = [cc, "-std=c11", "-O2", "-fno-lto", "-Werror=implicit-function-declaration",
            *WRAP_FLAGS, "-I" + str(directory), "-include", str(prototype), str(EXAMPLE / "harness.c"), str(obj), "-o", str(target)]
        report["expected_target_link_argv"] = list(target_link)
        _run(target_link, report, directory)
        report["target_link_argv"] = report["processes"][-1]["argv"]
        _run([cxx, *CPP_FLAGS, "-I" + str(directory), "-x", "c++", EXAMPLE / "harness.c",
              EXAMPLE / "reference.cpp", "-o", original], report, directory)
        report["target"], report["original"] = _identity(target), _identity(original)
        symbols = _run(["nm", "-u", obj], report, directory)
        report["target_undefined_symbols"] = symbols.splitlines()
        if any(line.split()[-1] not in {"abort", "calloc", "malloc", "free", "memset", "memcpy", "memmove"}
               for line in symbols.splitlines() if line.split()):
            raise ValueError("Owned HIA object imports an unmodeled or original implementation symbol")
        report["observed"], report["execution_process_indices"] = {}, {}
        for name, binary in (("original_cpp", original), ("standalone_hia", target)):
            report["execution_process_indices"][name] = len(report["processes"])
            report["observed"][name] = json.loads(_run([binary], report, directory))
            if not strict_equal(report["observed"][name], _observation_oracle(vectors)):
                raise ValueError("Actual C++ owner/HIA native lifecycle differential failed")
        # The complete 475-vector corpus runs natively on both implementations.
        # Interpret all small extents too; large-buffer interpreter throughput
        # is not needed to establish that this is the same standalone core.
        report["interpreter_cases"] = []
        for index, case in enumerate(vectors):
            if case["size"] > 17:
                continue
            args = [case[key] for key in ("size", "value", "index", "reject", "early")]
            observed = execute_program(core, "owned_case", args, allocation_fail_at=1 if case["refuse"] else None)
            resources = observed["resources"]
            if (observed["result"] != case["expected"] or resources["allocations"] != case["allocated"]
                    or resources["frees"] != case["allocated"] or resources["live_owners"] != 0
                    or resources["allocation_attempts"] != case["allocated"] + case["refusals"]):
                raise ValueError("Actual migrated source interpreter lifecycle differential failed")
            report["interpreter_cases"].append({"case_index": index, "execution": observed})
        if not project.unchanged() or digest(EXAMPLE / "owned_bytes.cpp") != migration["source_sha256"]:
            raise ValueError("C++ owner source or actual migrated module changed during execution")
        report.update(ok=True, status="bounded_cpp_owner_to_standalone_hia_passed",
                      case_count=len(vectors), case_families=dict(Counter(row["family"] for row in vectors)),
                      native_result_executions=2 * len(vectors),
                      actual_fault_executions=2 * sum(row["refusals"] for row in vectors))
        validate_cpp_owned_hia_receipt(report)
    except Exception as exc:
        report.update(ok=False, status="rejected", diagnostic={"type": type(exc).__name__, "message": str(exc)})
    _write_json(directory / "qualification.json", report)
    return report


def qualify(workdir, *, clang="clang", clangxx="clang++", cc="cc", cxx="c++"):
    directory = Path(workdir).absolute()
    if directory.exists() or directory.is_symlink():
        raise ValueError("Qualification workdir must be a new path")
    directory.mkdir(parents=True)
    report = {"schema": "hepta.hia-migration-qualification.v1", "ok": False,
              "status": "in_progress", "processes": [], "multi_owner_cases": [],
              "cpp_class_cases": [], "claims": {
                  "standalone_core_consumed": True, "source_required_for_hia_execution": False,
                  "original_implementations_linked_into_targets": False,
                  "c_multi_owner_whole_program_ast_template": False,
                  "cpp_owned_complete_protocol_ast_match": True, "all_c_cpp_supported": False,
                  "source_equivalence_proved": False, "backend_refinement_proved": False,
                  "rust_performance_parity_proved": False, "human_labor_reduction_measured": False}}
    implementation = [ROOT / "hepta" / name for name in
                      ("hia_program.py", "hia_program_runtime.py", "hia_program_source.py", "hia_program_llvm.py",
                       "ast.py", "parser.py", "checker.py", "modules.py", "c_project.py", "c_translation.py",
                       "cpp_class_migrate.py", "cpp_owned_migrate.py")]
    implementation.append(Path(__file__).resolve())
    implementation.extend(ROOT / name for name in ("tools/validate_cpp_owned.py", "tools/evidence_checks.py"))
    before = {str(path.relative_to(ROOT)): digest(path) for path in implementation}
    report["implementation_sha256"] = before
    fixture_inputs = [ROOT / relative for relative in (
        "examples/hia_migration/paired_bytes.c", "examples/hia_migration/paired_bytes.h",
        "examples/cpp/class_migration/scalar_state.cpp", "examples/cpp/class_migration/consumer.hepta",
        "examples/cpp/class_migration/reference.cpp", "examples/cpp/owned_migration/owned_bytes.cpp",
        "examples/cpp/owned_migration/consumer.hepta", "examples/cpp/owned_migration/reference.cpp",
        "examples/cpp/owned_migration/harness.c")]
    input_before = {str(path.relative_to(ROOT)): digest(path) for path in fixture_inputs}
    report["source_inputs_sha256"] = input_before
    try:
        fixture = ROOT / "examples/hia_migration"
        database = directory / "compile_commands.json"
        _write_json(database, [{"directory": str(fixture), "file": "paired_bytes.c",
            "arguments": [clang, "-std=c11", "-I.", "-c", "paired_bytes.c", "-o", "paired_bytes.o"]}])
        started = time.perf_counter()
        migrated = lower_c_multi_owner(database, clang=clang)
        core = migrated.pop("program")
        (directory / "paired_bytes.hepta").write_text(migrated["source"])
        (directory / "paired_bytes.hia.json").write_bytes(core.canonical_bytes)
        (directory / "paired_bytes.ll").write_text(emit_program_llvm(core).text)
        migrated["program_sha256"] = core.sha256
        migrated["translation_seconds"] = time.perf_counter() - started
        _write_json(directory / "migration.json", migrated)
        report["migration"] = {"receipt": str(directory / "migration.json"),
                               "receipt_sha256": digest(directory / "migration.json"),
                               "declaration_inventory_complete": migrated["declaration_inventory_complete"],
                               "active_project_declarations": migrated["active_project_declarations"],
                               "owners_lowered": migrated["owners_lowered"], "program_sha256": core.sha256}
        target_object = directory / "paired_hia.o"
        report["hia_native_build"] = build_program_native(core, target_object, clang=clang, kind="object")
        source_object = directory / "paired_original.o"
        _run([cc, "-std=c11", "-O2", "-c", fixture / "paired_bytes.c", "-o", source_object], report, directory)
        harness = directory / "allocator_harness.c"
        harness.write_text(ALLOCATOR_HARNESS)
        original, target = directory / "original_c", directory / "standalone_hia"
        suffix = ["-Wl,--wrap=malloc", "-Wl,--wrap=calloc", "-Wl,--wrap=free"]
        original_link = [cc, "-std=c11", "-O2", "-DENTRY=hia_paired_bytes", harness, source_object, *suffix, "-o", original]
        target_link = [cc, "-std=c11", "-O2", "-DENTRY=c_hia_paired_bytes", harness, target_object, *suffix, "-o", target]
        _run(original_link, report, directory); _run(target_link, report, directory)
        report["target_link_provenance"] = {"argv": list(map(str, target_link)),
            "object_sha256": {str(target_object): digest(target_object)},
            "harness_sha256": digest(harness), "executable_sha256": digest(target),
            "original_source_object": str(source_object), "original_source_object_in_target_link": False}
        symbols = _run(["nm", "-u", target_object], report, directory)
        report["target_undefined_symbols"] = symbols.splitlines()
        if any(line.split()[-1] in {"hia_paired_bytes", "hia_seed_byte"} for line in symbols.splitlines() if line.split()):
            raise ValueError("Generated target still imports an original implementation")
        for case in _cases():
            expected = _expected(case)
            reference = execute_program(core, "c_hia_paired_bytes", case["arguments"],
                                        allocation_fail_at=case["allocation_fail_at"])
            arguments = [*case["arguments"], case["allocation_fail_at"] or 0]
            observations = {}
            for name, binary in (("original_c", original), ("standalone_hia", target)):
                raw = _run([binary, *map(str, arguments)], report, directory)
                values = [int(item) for item in raw.split()]
                if len(values) != 5:
                    raise ValueError("Malformed native allocation observation")
                observations[name] = dict(zip(("result", "attempts", "allocations", "frees", "live"), values))
            resource = reference["resources"]
            expected_observation = {"result": expected, "attempts": resource["allocation_attempts"],
                                    "allocations": resource["allocations"], "frees": resource["frees"], "live": 0}
            if (reference["result"] != expected or resource["live_owners"] != 0
                    or any(row != expected_observation for row in observations.values())):
                raise ValueError("C/HIA allocation/resource differential failed: " + repr((case, observations, reference)))
            report["multi_owner_cases"].append({**case, "expected": expected,
                                                "reference": reference, "native": observations})
        verify_capture(migrated["capture"])

        # Real existing C++ class migration, then the actual module resolver and
        # the same AST->HIA compiler pass.  No scalar-class fixture substitution.
        class_directory = directory / "cpp_class"; class_directory.mkdir()
        cpp_fixture = ROOT / "examples/cpp/class_migration"
        migration = migrate_cpp_class(cpp_fixture / "scalar_state.cpp", class_directory / "scalar_state.hepta", clangxx=clangxx)
        if not migration["ok"]:
            raise ValueError("C++ class migration failed: " + repr(migration))
        _write_json(class_directory / "migration.json", migration)
        (class_directory / "consumer.hepta").write_bytes((cpp_fixture / "consumer.hepta").read_bytes())
        project = load_project(class_directory / "consumer.hepta")
        class_core = lower_program(project.program)
        (class_directory / "class.hia.json").write_bytes(class_core.canonical_bytes)
        target_library, original_library = class_directory / "hia.so", class_directory / "original.so"
        report["cpp_hia_native_build"] = build_program_native(class_core, target_library, clang=clang)
        _run([cxx, "-std=c++20", "-O2", "-fPIC", "-shared", cpp_fixture / "reference.cpp", "-o", original_library], report, directory)
        cases = []
        for value in (0, 1, 17, (1 << 32) - 1):
            cases += [{"function": "word_trace", "arguments": [value, 19, 42, 33]},
                      {"function": "wide_trace", "arguments": [value, 37, (1 << 63) + 11]}]
        cases += [{"function": "balance_trace", "arguments": [n, -10, 10]} for n in (-(1 << 31), -11, 0, 11, (1 << 31) - 1)]
        cases += [{"function": "position_trace", "arguments": [17, n]} for n in (-(1 << 63), -5, 0, (1 << 63) - 1)]
        cases += [{"function": "state_guard", "arguments": [w, 2, b, 4, 5, 6, -10, 10, -7]}
                  for w, b in ((0, -13), (17, 9), ((1 << 32) - 1, 19))]
        references = [execute_program(class_core, row["function"], row["arguments"])["result"] for row in cases]
        payload = {"libraries": {"original_cpp": str(original_library), "standalone_hia": str(target_library)}, "cases": cases}
        observed = json.loads(_run([sys.executable, "-I", "-c", CLASS_RUNNER], report, directory, input_text=json.dumps(payload)))
        if set(observed) != {"original_cpp", "standalone_hia"} or any(values != references for values in observed.values()):
            raise ValueError("C++ class/HIA scalarized-state differential failed")
        report["cpp_class_cases"] = [{**case, "reference": references[i],
                                      "native": {name: values[i] for name, values in observed.items()}}
                                     for i, case in enumerate(cases)]
        report["cpp_class"] = {"migration_sha256": digest(class_directory / "migration.json"),
                               "program_sha256": class_core.sha256, "module_identity": project.identity,
                               "class_source_sha256": digest(cpp_fixture / "scalar_state.cpp"),
                               "original_library_sha256": digest(original_library),
                               "hia_library_sha256": digest(target_library),
                               "foreign_cpp_implementation_retained": False,
                               "class_cpp_abi_preserved": False,
                               "public_scalar_consumer_abi_executed": True}
        if not project.unchanged():
            raise ValueError("Resolved class migration project changed during qualification")
        report["cpp_owned"] = qualify_cpp_owned_to_hia(directory / "cpp_owned", clang=clang,
                                                       clangxx=clangxx, cc=cc, cxx=cxx)
        if report["cpp_owned"]["ok"] is not True:
            raise ValueError("Actual C++ owner to standalone HIA qualification failed: " + repr(report["cpp_owned"].get("diagnostic")))
        after = {str(path.relative_to(ROOT)): digest(path) for path in implementation}
        report["implementation_after_sha256"] = after
        if before != after:
            raise ValueError("HIA implementation changed during qualification; rerun on frozen source")
        input_after = {str(path.relative_to(ROOT)): digest(path) for path in fixture_inputs}
        report["source_inputs_after_sha256"] = input_after
        if input_before != input_after:
            raise ValueError("Migration input source changed during qualification; rerun on frozen source")
        report.update(ok=True, status="finite_source_to_hia_native_qualification_passed",
                      multi_owner_case_count=len(report["multi_owner_cases"]),
                      cpp_class_case_count=len(report["cpp_class_cases"]),
                      cpp_owned_case_count=report["cpp_owned"]["case_count"],
                      native_result_executions=2 * (len(report["multi_owner_cases"]) + len(report["cpp_class_cases"])) + report["cpp_owned"]["native_result_executions"],
                      actual_fault_executions=2 * sum(c["allocation_fail_at"] is not None for c in report["multi_owner_cases"]) + report["cpp_owned"]["actual_fault_executions"])
    except Exception as exc:
        report.update(ok=False, status="rejected", diagnostic={"type": type(exc).__name__, "message": str(exc)})
    _write_json(directory / "qualification.json", report)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workdir", type=Path, required=True)
    parser.add_argument("--clang", default=os.environ.get("CLANG", "clang"))
    parser.add_argument("--clangxx", default=os.environ.get("CLANGXX", "clang++"))
    parser.add_argument("--cc", default=os.environ.get("CC", "cc"))
    parser.add_argument("--cxx", default=os.environ.get("CXX", "c++"))
    args = parser.parse_args(argv)
    report = qualify(args.workdir, clang=args.clang, clangxx=args.clangxx, cc=args.cc, cxx=args.cxx)
    print(json.dumps({key: report[key] for key in ("ok", "status", "multi_owner_case_count", "cpp_class_case_count", "cpp_owned_case_count", "native_result_executions", "actual_fault_executions", "diagnostic") if key in report}, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
