"""Qualify nominal two-owner HIA with v2-v6 memory operations on x86-64/ARM64.

The two backends execute the same independently submitted composite Core and
its normalized v6 form. A separate byte-array oracle, real allocation refusal,
wrong-value Core, removed-free machine code and three native bounds traps are
retained. The ARM64 runtime is a fixed eight-slot Linux userspace QEMU harness;
it is neither physical-device evidence nor a general allocator qualification.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta.clang_capture import run_bounded
from hepta.hia_program import HIAProgramRejected, execute_program, verify_program
from hepta.hia_program_runtime import HIAProgramTrap
from hepta.hia_program_llvm import TARGET, TARGET_AARCH64, compile_program_llvm, emit_program_llvm
from hepta.hia_program_aarch64 import (COMPOSITE_BULK_CASES, COMPOSITE_BULK_TRAPS,
    QEMU_SHA256, REVIEWED_MULTI_RUNTIME_SHA256, _runtime_source)
from hepta.native_tool_identity import digest_executable
from hepta.object_symbols import inspect_object_symbols
from hepta.owned_aarch64_link import inspect_synthetic_aarch64_elf
from tools.qualify_hia_program import block, branch, function, operation, ret


def _unique_block_values(fn):
    """Give the authored block-local notation globally unique SSA spellings."""
    for current in fn["blocks"]:
        names = {}
        prefix = current["id"] + "_"
        for param in current["params"]:
            original = param["name"]
            names[original] = prefix + original
            param["name"] = names[original]
        for instruction in current["ops"]:
            instruction["args"] = [names[name] for name in instruction["args"]]
            for output in instruction["out"]:
                original = output["name"]
                if original in names:
                    raise ValueError("Fixture repeated an SSA definition")
                names[original] = prefix + original
                output["name"] = names[original]
        term = current["term"]
        if term["op"] == "ret":
            term["values"] = [names[name] for name in term["values"]]
        elif term["op"] == "branch":
            term["cond"] = names[term["cond"]]
            for edge in (term["then"], term["else"]):
                edge["args"] = [names[name] for name in edge["args"]]
        else:
            raise ValueError("Unexpected fixture terminator")
    fn["params"] = deepcopy(fn["blocks"][0]["params"])
    return fn


def composite_bulk_program():
    pair = {"name": "OwnerPair", "args": ["buffer"]}
    types = [
        {"name": "OwnerPair", "params": ["T"], "kind": "record",
         "fields": [{"name": "source", "type": "T"}, {"name": "destination", "type": "T"}]},
        {"name": "LiveViews", "params": [], "kind": "record", "fields": [
            {"name": "source_owner", "type": "buffer"}, {"name": "source_loan", "type": "readbuf"},
            {"name": "destination_owner", "type": "buffer"}, {"name": "destination_loan", "type": "mutbuf"}]},
    ]
    tail = [("offset", "usize"), ("count", "usize"), ("value", "u8"), ("probe", "usize")]
    args = [name for name, _ in tail]
    owned = [("source", "buffer"), ("destination", "buffer")]
    process = function("process_pair", [("pair", pair), *tail], ["u8"],
                       ["alloc", "read", "write", "trap"], [
        block("entry", [("pair", pair), *tail], [
            operation("record.unpack", ["pair"], owned),
            operation("buffer.len", ["source"], [("size", "usize")]),
            operation("const", out=[("zero", "usize")], value=0),
            operation("compare.eq", ["size", "zero"], [("empty", "bool")]),
        ], branch("empty", "empty", ["source", "destination"],
                  "work", ["source", "destination", "size", *args])),
        block("empty", owned, [
            operation("owner.drop", ["source"]), operation("owner.drop", ["destination"]),
            operation("const", out=[("answer", "u8")], value=0),
        ], ret("answer")),
        block("work", [*owned, ("size", "usize"), *tail], [
            operation("const", out=[("zero", "usize")], value=0),
            operation("const", out=[("one", "usize")], value=1),
            operation("const", out=[("eleven", "u8")], value=11),
            operation("borrow.mut", ["source"], [("writer", "mutbuf")]),
            operation("buffer.fill", ["writer", "eleven"]),
            operation("buffer.fill_range", ["writer", "offset", "count", "value"]),
            operation("buffer.swap", ["writer", "zero", "probe"]),
            operation("buffer.move_within", ["writer", "one", "zero", "count"]),
            operation("loan.end", ["writer"]),
            operation("borrow.read", ["source"], [("reader", "readbuf")]),
            operation("borrow.mut", ["destination"], [("destination_writer", "mutbuf")]),
            operation("record.make", ["source", "reader", "destination", "destination_writer"],
                      [("views", "LiveViews")]),
            operation("record.unpack", ["views"], [("source_owner", "buffer"), ("source_view", "readbuf"),
                      ("destination_owner", "buffer"), ("destination_view", "mutbuf")]),
            operation("buffer.copy", ["destination_view", "source_view", "size"]),
            operation("buffer.copy_range", ["destination_view", "source_view", "zero", "one", "count"]),
            operation("buffer.load", ["destination_view", "probe"], [("answer", "u8")]),
            operation("loan.end", ["source_view"]), operation("loan.end", ["destination_view"]),
            operation("owner.drop", ["source_owner"]), operation("owner.drop", ["destination_owner"]),
        ], ret("answer")),
    ])
    main = function("aggregate_bulk", [("size", "usize"), *tail], ["u8"],
                    ["alloc", "read", "write", "trap"], [
        block("entry", [("size", "usize"), *tail], [
            operation("buffer.try_new", ["size"], [("source", "buffer"), ("first_ok", "bool")]),
        ], branch("first_ok", "second", ["source", "size", *args], "first_failure", ["source"])),
        block("first_failure", [("source", "buffer")], [
            operation("owner.drop", ["source"]), operation("const", out=[("answer", "u8")], value=251),
        ], ret("answer")),
        block("second", [("source", "buffer"), ("size", "usize"), *tail], [
            operation("buffer.try_new", ["size"], [("destination", "buffer"), ("second_ok", "bool")]),
        ], branch("second_ok", "pack", ["source", "destination", *args],
                  "second_failure", ["source", "destination"])),
        block("second_failure", owned, [
            operation("owner.drop", ["source"]), operation("owner.drop", ["destination"]),
            operation("const", out=[("answer", "u8")], value=252),
        ], ret("answer")),
        block("pack", [*owned, *tail], [
            operation("record.make", ["source", "destination"], [("pair", pair)]),
            operation("call", ["pair", *args], [("answer", "u8")], function="process_pair"),
        ], ret("answer")),
    ])
    return {"schema": "hepta.hia.composite.v1", "module": "composite_bulk", "types": types,
            "functions": [_unique_block_values(process), _unique_block_values(main)]}


def byte_oracle(arguments, failure=None):
    size, offset, count, value, probe = arguments
    if failure in (1, 2):
        return 250 + failure
    if not size:
        return 0
    if offset > size or count > size - offset or probe >= size or count > size - 1:
        raise IndexError("outside the frozen byte-operation domain")
    source = bytearray([11]) * size
    source[offset:offset + count] = bytes([value]) * count
    source[0], source[probe] = source[probe], source[0]
    source[1:1 + count] = source[:count]
    destination = source.copy()
    destination[:count] = source[1:1 + count]
    return destination[probe]


def wrong_result_program():
    document = composite_bulk_program()
    work = document["functions"][0]["blocks"][2]
    answer = work["term"]["values"][0]
    work["ops"] += [operation("const", out=[("wrong_mask", "u8")], value=1),
                    operation("bit.xor", [answer, "wrong_mask"], [("wrong", "u8")])]
    work["term"] = ret("wrong")
    return document


HOST_PREFIX = r'''
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
typedef size_t hepta_size; typedef uint8_t hepta_u8; typedef uint32_t hepta_u32;
typedef uint64_t hepta_u64;
void *__real_malloc(size_t); void *__real_calloc(size_t,size_t); void __real_free(void *);
static void *addresses[64];
static hepta_u32 successful_allocations,releases,outstanding,denied_allocations;
static hepta_u32 failure_countdown,peak_outstanding;
static bool refuse(void) {
    if(failure_countdown && --failure_countdown == 0){denied_allocations++;return true;}return false;
}
static void *remember(void *p) {
    if(!p)return NULL;
    for(size_t i=0;i<64;i++)if(!addresses[i]) {
        addresses[i]=p;successful_allocations++;outstanding++;
        if(outstanding>peak_outstanding)peak_outstanding=outstanding;
        return p;
    }
    exit(89);
}
void *__wrap_malloc(size_t n) {if(refuse())return NULL;return remember(__real_malloc(n));}
void *__wrap_calloc(size_t n,size_t w) {if(refuse())return NULL;return remember(__real_calloc(n,w));}
void __wrap_free(void *p) {
    if(p){size_t i;for(i=0;i<64 && addresses[i]!=p;i++){}if(i==64)exit(90);
        addresses[i]=NULL;outstanding--;releases++;}
    __real_free(p);
}
static void write_case(hepta_u32 index,hepta_u32 value){printf("HIA_BULK case %u %u\n",index,value);}
static void write_counters(void){printf("HIA_AARCH64 resources %u %u %u %u\n",
    successful_allocations,releases,outstanding,denied_allocations);}
'''


def host_source(document, mode):
    target, _ = _runtime_source(document, mode)
    marker = "extern hepta_u8 aggregate_bulk("
    body = target[target.index(marker):]
    body = body[:body.index('__attribute__((noreturn)) void _start(void)')]
    # The host observer uses the real libc memory primitives. The separate
    # freestanding target implementation self-check remains in the ARM64 path.
    body = body.replace("    if (!memory_primitives_ok()) return 39;\n", "")
    return HOST_PREFIX + body + "\nint main(void){struct rlimit c={0,0};if(setrlimit(RLIMIT_CORE,&c))return 88;return smoke();}\n"


def _sha(path):
    return sha256(Path(path).read_bytes()).hexdigest()


def _write(path, value):
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True, indent=2, allow_nan=False)
        stream.write("\n")


def _run(command, report, directory):
    started = time.monotonic()
    result = run_bounded(list(map(str, command)), timeout=60, stdout_limit=1048576, stderr_limit=1048576)
    index = len(report["processes"])
    stdout, stderr = directory / f"process-{index:03d}.stdout", directory / f"process-{index:03d}.stderr"
    stdout.write_text(result.stdout); stderr.write_text(result.stderr)
    report["processes"].append({"argv": list(map(str, command)), "returncode": result.returncode,
        "seconds": time.monotonic() - started, "stdout": str(stdout), "stdout_sha256": _sha(stdout),
        "stderr": str(stderr), "stderr_sha256": _sha(stderr)})
    return index, result


def _must_run(command, report, directory):
    index, result = _run(command, report, directory)
    if result.returncode:
        raise ValueError("Native build failed: " + result.stderr[-2000:])
    return index


def _build_run(core, name, mode, target, report, directory, tools, *, remove_free=False):
    folder = directory / name
    folder.mkdir()
    _write(folder / "core.json", core.as_dict())
    ir = emit_program_llvm(core, target=target)
    (folder / "program.ll").write_text(ir.text)
    obj = folder / "program.o"
    if remove_free:
        changed = "\n".join(line for line in ir.text.splitlines() if "call void @free(" not in line) + "\n"
        if changed == ir.text:
            raise ValueError("Missing-free control made no change")
        (folder / "removed-free.ll").write_text(changed)
        _must_run([tools["clang"], "--target=" + target, "-x", "ir", "-O3", "-fPIC", "-c",
                   folder / "removed-free.ll", "-o", obj], report, directory)
        build = {"qualified_hia_artifact": False, "reason": "deliberately removed actual free calls",
                 "artifact_sha256": _sha(obj), "unqualified_ir_sha256": _sha(folder / "removed-free.ll")}
    else:
        build = compile_program_llvm(ir, program=core, output=obj, clang=tools["clang"], kind="object")
        if build["exports"] != ["aggregate_bulk"]:
            raise ValueError("Nominal helper leaked into external C ABI")
    runtime = folder / "driver.c"
    runtime.write_text(host_source(core.as_dict(), mode) if target == TARGET
                       else _runtime_source(core.as_dict(), mode)[0])
    executable = folder / "program"
    if target == TARGET:
        command = [tools["clang"], "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", runtime, obj,
                   "-Wl,--wrap=malloc", "-Wl,--wrap=calloc", "-Wl,--wrap=free", "-o", executable]
        _must_run(command, report, directory)
        inventory = None
    else:
        runtime_obj = folder / "driver.o"
        _must_run([tools["clang"], "--target=" + TARGET_AARCH64, "-x", "c", "-std=c11",
            "-ffreestanding", "-nostdinc", "-fno-builtin", "-fno-stack-protector", "-O2",
            "-Wall", "-Wextra", "-Werror", "-c", runtime, "-o", runtime_obj], report, directory)
        symbols = inspect_object_symbols(runtime_obj.read_bytes(), "ELF64", 183)
        if symbols["undefined"] != frozenset({"aggregate_bulk"}):
            raise ValueError("Target driver did not call the exact public scalar ABI")
        _must_run([tools["linker"], "-flavor", "gnu", "-m", "aarch64linux", "-static", "-z", "noexecstack",
                   "-e", "_start", obj, runtime_obj, "-o", executable], report, directory)
        inventory = inspect_synthetic_aarch64_elf(executable.read_bytes(), ("aggregate_bulk", "calloc"))
    payload = executable.read_bytes()
    process, actual = _run([executable] if target == TARGET else [tools["qemu"], executable], report, directory)
    if executable.read_bytes() != payload or emit_program_llvm(core, target=target) != ir:
        raise ValueError("Source or executable changed during actual execution")
    return {"target": target, "mode": mode, "input_sha256": core.input_sha256, "core_sha256": core.sha256,
            "llvm_ir_sha256": ir.sha256, "build": build, "driver_sha256": _sha(runtime),
            "executable_sha256": sha256(payload).hexdigest(), "binary_inventory": inventory,
            "run_process": process, "execution": {"returncode": actual.returncode,
                "stdout": actual.stdout, "stderr": actual.stderr}}


def _source_bindings():
    selected = [*sorted((ROOT / "hepta").glob("*.py")), Path(__file__).resolve(),
                ROOT / "examples/hia_program/finite_aarch64_multi_runtime.c"]
    return {str(path.relative_to(ROOT)): _sha(path) for path in selected}


def expected_counts():
    return {"cases_per_native_binary": len(COMPOSITE_BULK_CASES), "positive_native_binaries": 4,
            "actual_scalar_abi_calls": len(COMPOSITE_BULK_CASES) * 4,
            "allocations_per_positive_binary": 31, "frees_per_positive_binary": 31,
            "refusals_per_positive_binary": 2, "peak_live_per_positive_binary": 2,
            "live_after_each_positive_call": 0, "actual_wrong_result_controls": 2,
            "actual_removed_free_controls": 2, "actual_native_bounds_traps": 6}


def validate_qualification(report, *, require_success=True):
    """Replay source/artifact/observer identities, never just trust an ok flag."""
    if report.get("schema") != "hepta.hia.composite-bulk-qualification.v1":
        raise ValueError("Wrong composite bulk report schema")
    if require_success and (report.get("ok") is not True or
            report.get("status") != "finite_two_owner_composite_bulk_x86_64_and_qemu_passed"):
        raise ValueError("Composite bulk report did not pass")
    if report.get("counts") != expected_counts() or report.get("source_bindings") != _source_bindings():
        raise ValueError("Frozen case count or source identity differs")
    if len(report.get("negative_controls", [])) != 2 * (2 + len(COMPOSITE_BULK_TRAPS)):
        raise ValueError("Native negative-control denominator differs")
    directory = Path(report["workdir"])
    if not directory.is_absolute() or not directory.is_dir():
        raise ValueError("Retained work directory unavailable")
    for tool in report["tools"].values():
        if digest_executable(Path(tool["path"])) != tool["sha256"]:
            raise ValueError("Native tool identity differs")
    if report["tools"]["qemu"]["sha256"] != QEMU_SHA256:
        raise ValueError("QEMU executable differs")
    expected_source = composite_bulk_program()
    if json.loads((directory / "input.json").read_bytes()) != expected_source:
        raise ValueError("Retained original composite input differs")
    core = verify_program(expected_source)
    normalized = verify_program((directory / "normalized.json").read_bytes())
    if core.canonical_bytes != normalized.canonical_bytes or core.scalar_entrypoints != frozenset({"aggregate_bulk"}):
        raise ValueError("Normalized Core or external ABI differs")
    if len(report["reference"]) != len(COMPOSITE_BULK_CASES):
        raise ValueError("Reference case denominator differs")
    for row, (arguments, failure, expected) in zip(report["reference"], COMPOSITE_BULK_CASES):
        if row["arguments"] != list(arguments) or row["failure_at"] != failure or row["expected"] != expected:
            raise ValueError("Reference case or expected result changed")
        if byte_oracle(arguments, failure) != expected:
            raise ValueError("Independent byte oracle differs")
        current = [execute_program(p, "aggregate_bulk", list(arguments), allocation_fail_at=failure)
                   for p in (core, normalized)]
        if row["receipts"] != current:
            raise ValueError("Reference trace differs from fresh execution")
    for index, process in enumerate(report["processes"]):
        for stream in ("stdout", "stderr"):
            path = directory / f"process-{index:03d}.{stream}"
            if process[stream] != str(path) or process[stream + "_sha256"] != _sha(path):
                raise ValueError("Native execution log path/digest differs")
    expected_stdout = "".join("HIA_BULK case " + str(index) + " " + str(row[2]) + "\n"
                              for index, row in enumerate(COMPOSITE_BULK_CASES)) + "HIA_AARCH64 resources 31 31 0 2\n"

    def inspect(row, name, candidate, target, mode, expected_exit, stdout, *, removed=False):
        folder = directory / name
        ir = emit_program_llvm(candidate, target=target)
        if (json.loads((folder / "core.json").read_bytes()) != candidate.as_dict()
                or row["target"] != target or row["mode"] != mode
                or row["input_sha256"] != candidate.input_sha256 or row["core_sha256"] != candidate.sha256
                or row["llvm_ir_sha256"] != ir.sha256 or (folder / "program.ll").read_text() != ir.text):
            raise ValueError("Core/native source identities differ")
        driver = (host_source(candidate.as_dict(), mode) if target == TARGET
                  else _runtime_source(candidate.as_dict(), mode)[0])
        if (folder / "driver.c").read_text() != driver or row["driver_sha256"] != _sha(folder / "driver.c"):
            raise ValueError("Independent native observer changed")
        obj = folder / "program.o"
        if row["build"]["artifact_sha256"] != _sha(obj):
            raise ValueError("Actual Core object changed")
        symbols = inspect_object_symbols(obj.read_bytes(), "ELF64", 62 if target == TARGET else 183)
        if symbols["defined"] != frozenset({"aggregate_bulk"}):
            raise ValueError("Nominal helper became a public native symbol")
        if removed:
            changed = "\n".join(line for line in ir.text.splitlines() if "call void @free(" not in line) + "\n"
            if (row["build"]["qualified_hia_artifact"] is not False
                    or (folder / "removed-free.ll").read_text() != changed
                    or row["build"]["unqualified_ir_sha256"] != _sha(folder / "removed-free.ll")):
                raise ValueError("Missing-free negative control changed or claimed qualification")
        elif (row["build"]["input_sha256"] != candidate.input_sha256
                or row["build"]["core_sha256"] != candidate.sha256 or row["build"]["exports"] != ["aggregate_bulk"]
                or row["build"]["implementation_sha256"] != ir.implementation_sha256
                or row["build"]["output"] != str(obj)):
            raise ValueError("Qualified native origin receipt changed")
        executable = folder / "program"
        if row["executable_sha256"] != _sha(executable):
            raise ValueError("Executed native binary changed")
        if target == TARGET_AARCH64:
            shape = inspect_synthetic_aarch64_elf(executable.read_bytes(), ("aggregate_bulk", "calloc"))
            if row["binary_inventory"] != shape:
                raise ValueError("Target executable ABI inventory differs")
        process = report["processes"][row["run_process"]]
        command = [str(executable)] if target == TARGET else [report["tools"]["qemu"]["path"], str(executable)]
        observed = {"returncode": process["returncode"], "stdout": Path(process["stdout"]).read_text(),
                    "stderr": Path(process["stderr"]).read_text()}
        if process["argv"] != command or row["execution"] != observed or observed != {
                "returncode": expected_exit, "stdout": stdout, "stderr": ""}:
            raise ValueError("Actual execution differs from required observer result")

    controls = iter(report["negative_controls"])
    for target, label in ((TARGET, "x86_64"), (TARGET_AARCH64, "aarch64")):
        for kind, candidate in (("composite", core), ("normalized", normalized)):
            inspect(report["native"][label][kind], label + "-" + kind, candidate, target,
                    "composite_bulk", 0, expected_stdout)
        for control, candidate, suffix, code, output, removed in (
            ("wrong_result_core", verify_program(wrong_result_program()), "wrong-value", 41, "HIA_BULK case 0 10\n", False),
            ("unqualified_removed_free", core, "removed-free", 91, "HIA_BULK case 0 11\nHIA_AARCH64 resources 2 0 2 0\n", True)):
            row = next(controls)
            if row["kind"] != control:
                raise ValueError("Negative control order or kind differs")
            inspect(row["observed"], label + "-" + suffix, candidate, target, "composite_bulk", code, output, removed=removed)
        for mode in COMPOSITE_BULK_TRAPS:
            row = next(controls)
            if row["kind"] != mode:
                raise ValueError("Bounds trap denominator differs")
            inspect(row["observed"], label + "-" + mode, core, target, mode, -6 if target == TARGET else 134, "")
    if next(controls, None) is not None:
        raise ValueError("Unexpected additional negative controls")
    digest_payload = dict(report)
    previous = digest_payload.pop("record_sha256", None)
    if previous is not None and previous != sha256(json.dumps(digest_payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest():
        raise ValueError("Report record digest differs")
    return {"ok": True, "status": "current_source_artifact_and_observer_replayed", "counts": expected_counts()}


def qualify(*, directory, clang, linker, qemu):
    directory = Path(directory).resolve()
    directory.mkdir()
    tools = {"clang": str(Path(clang).resolve()), "linker": str(Path(linker).resolve()),
             "qemu": str(Path(qemu).resolve())}
    report = {"schema": "hepta.hia.composite-bulk-qualification.v1", "ok": False, "status": "rejected",
              "workdir": str(directory), "processes": [], "reference": [], "native": {}, "negative_controls": [],
              "limits": ["fixed eighteen-case scalar C ABI corpus; nominal aggregates remain internal",
                         "ARM64 uses Linux userspace QEMU with eight independent 4096-byte test slots",
                         "only cleanup on normal/error returns; traps abort without cleanup",
                         "finite evidence does not prove compiler refinement or general allocator soundness"],
              "claims": {"physical_target_executed": False, "general_allocator_qualified": False,
                         "whole_language_soundness_proved": False, "backend_refinement_proved": False}}
    try:
        before = _source_bindings()
        report["source_bindings"] = before
        report["tools"] = {name: {"path": path, "sha256": digest_executable(Path(path))}
                           for name, path in tools.items()}
        if report["tools"]["qemu"]["sha256"] != QEMU_SHA256:
            raise ValueError("QEMU differs from the repository's reviewed executable")
        report["reviewed_runtime_sha256"] = REVIEWED_MULTI_RUNTIME_SHA256
        document = composite_bulk_program()
        core = verify_program(document)
        normalized = verify_program(core.canonical_bytes)
        if core.scalar_entrypoints != frozenset({"aggregate_bulk"}) or core.canonical_bytes != normalized.canonical_bytes:
            raise ValueError("Nominal/core/export identity differs")
        _write(directory / "input.json", document)
        _write(directory / "normalized.json", normalized.as_dict())
        for arguments, failure, expected in COMPOSITE_BULK_CASES:
            if byte_oracle(arguments, failure) != expected:
                raise ValueError("Independent byte-array oracle differs from frozen result")
            refs = []
            for candidate in (core, normalized):
                observed = execute_program(candidate, "aggregate_bulk", list(arguments), allocation_fail_at=failure)
                if observed["result"] != expected or observed["resources"]["live_owners"] or observed["resources"]["live_local_loans"]:
                    raise ValueError("Reference semantic/resource result differs")
                refs.append(observed)
            report["reference"].append({"arguments": list(arguments), "failure_at": failure,
                                       "expected": expected, "receipts": refs})
        expected_stdout = "".join("HIA_BULK case " + str(index) + " " + str(row[2]) + "\n"
                                  for index, row in enumerate(COMPOSITE_BULK_CASES)) + "HIA_AARCH64 resources 31 31 0 2\n"
        for target, label in ((TARGET, "x86_64"), (TARGET_AARCH64, "aarch64")):
            report["native"][label] = {}
            for kind, candidate in (("composite", core), ("normalized", normalized)):
                row = _build_run(candidate, label + "-" + kind, "composite_bulk", target, report, directory, tools)
                report["native"][label][kind] = row
                if row["execution"] != {"returncode": 0, "stdout": expected_stdout, "stderr": ""}:
                    raise ValueError("Native composite values/resources differ: " + label + "/" + kind)
            wrong = _build_run(verify_program(wrong_result_program()), label + "-wrong-value", "composite_bulk",
                               target, report, directory, tools)
            report["negative_controls"].append({"kind": "wrong_result_core", "observed": wrong})
            if wrong["execution"]["returncode"] != 41 or wrong["execution"]["stdout"] != "HIA_BULK case 0 10\n":
                raise ValueError("Actual wrong-result control failed to reject")
            leaked = _build_run(core, label + "-removed-free", "composite_bulk", target, report, directory, tools, remove_free=True)
            report["negative_controls"].append({"kind": "unqualified_removed_free", "observed": leaked})
            if leaked["execution"]["returncode"] != 91 or leaked["execution"]["stdout"] != "HIA_BULK case 0 11\nHIA_AARCH64 resources 2 0 2 0\n":
                raise ValueError("Actual missing-free control failed to observe leak")
            for mode, arguments in COMPOSITE_BULK_TRAPS.items():
                try:
                    execute_program(core, "aggregate_bulk", list(arguments))
                except HIAProgramTrap as error:
                    if error.code != "bounds":
                        raise
                else:
                    raise ValueError("Reference trap missing")
                row = _build_run(core, label + "-" + mode, mode, target, report, directory, tools)
                report["negative_controls"].append({"kind": mode, "observed": row})
                if row["execution"]["returncode"] != (-6 if target == TARGET else 134):
                    raise ValueError("Actual bounds trap missing")
        if _source_bindings() != before or any(digest_executable(Path(path)) != report["tools"][name]["sha256"]
                                               for name, path in tools.items()):
            raise ValueError("Compiler source or tools changed during qualification")
        report.update(ok=True, status="finite_two_owner_composite_bulk_x86_64_and_qemu_passed", counts=expected_counts())
        validate_qualification(report)
    except Exception as error:
        report.update(ok=False, status="rejected")
        report["error"] = {"type": type(error).__name__, "message": str(error), "traceback": traceback.format_exc()[-6000:]}
    report["record_sha256"] = sha256(json.dumps(report, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    _write(directory / "qualification.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-directory", required=True)
    parser.add_argument("--clang", default="/usr/lib/llvm-20/bin/clang")
    parser.add_argument("--linker", default="/tmp/hepta-ai-rust-1.90.0/lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld")
    parser.add_argument("--qemu-aarch64", default="/usr/bin/qemu-aarch64-static")
    args = parser.parse_args()
    directory = Path(args.output_directory)
    if directory.exists() or directory.is_symlink() or not directory.parent.is_dir():
        parser.error("a new output directory in an existing directory is required")
    report = qualify(directory=directory, clang=args.clang, linker=args.linker, qemu=args.qemu_aarch64)
    print(json.dumps({key: report.get(key) for key in ("ok", "status", "counts", "error", "record_sha256")}, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
