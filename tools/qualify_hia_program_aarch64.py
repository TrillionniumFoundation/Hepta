"""Fail-closed standalone HIA -> LLVM -> AArch64 -> actual QEMU qualification."""
from __future__ import annotations

import argparse
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import traceback

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from hepta.hia_program import execute_program, verify_program
from hepta.hia_program_runtime import HIAProgramTrap
from hepta.hia_program_aarch64 import CASES, run_finite_program_aarch64
from tools.qualify_hia_program import block, constant, function, operation, qualification_program, ret


def aarch64_program():
    """A standalone Core fixture; no high-level source replay is available."""
    selected = {"fill_sum", "read_one", "scalar_mix", "tuple_call", "pair", "no_result", "bool_gate",
                "int_add_wrap_u32", "int_div_checked_i64", "int_shr_checked_i64", "cast_i8_u64", "bounds_trap"}
    document = qualification_program()
    document["module"] = "standalone_aarch64_qualification"
    document["functions"] = [fn for fn in document["functions"] if fn["name"] in selected]
    document["functions"].append(function("try_capacity", [("n", "usize")], ["u64"], ["alloc"], [
        block("entry", [("n", "usize")], [
            operation("buffer.try_new", ["n"], [("owner", "buffer"), ("ok", "bool")]),
            operation("buffer.len", ["owner"], [("length", "usize")]),
            operation("owner.drop", ["owner"]),
            operation("int.cast", ["length"], [("wide", "u64")], mode="wrap"),
            constant("error", "u64", 99),
            operation("select", ["ok", "wide", "error"], [("answer", "u64")]),
        ], ret("answer")),
    ]))
    return document


def _wrong_sum(document):
    changed = deepcopy(document)
    fn = next(fn for fn in changed["functions"] if fn["name"] == "fill_sum")
    done = next(block for block in fn["blocks"] if block["id"] == "done")
    done["ops"] += [constant("wrong_one", "u64", 1),
                    operation("int.add.wrap", ["total", "wrong_one"], [("wrong_total", "u64")])]
    done["term"] = ret("wrong_total")
    return changed


def _wrong_failure(document):
    changed = deepcopy(document)
    fn = next(fn for fn in changed["functions"] if fn["name"] == "try_capacity")
    next(op for op in fn["blocks"][0]["ops"] if op["op"] == "const")["attrs"]["value"] = 98
    return changed


def qualify(*, clang, linker, qemu_aarch64):
    report = {"schema": "hepta.hia.program.aarch64-qualification.v1", "ok": False,
              "status": "rejected", "reference_cases": [], "negative_controls": [],
              "claims": {"finite_corpus_qemu_execution_passed": False,
                         "physical_target_executed": False, "general_allocator_qualified": False,
                         "whole_language_soundness_proved": False, "backend_refinement_proved": False,
                         "automatic_cpp_migration_qualified": False, "faster_than_rust_demonstrated": False}}
    try:
        document = aarch64_program()
        program = verify_program(document)
        report["program"] = program.as_dict()
        report["core_sha256"] = program.sha256
        for name, arguments, expected, failure in CASES:
            reference = execute_program(program, name, list(arguments), allocation_fail_at=failure)
            if reference["result"] != expected or reference["resources"]["live_owners"]:
                raise ValueError("independent reference failed for " + name)
            report["reference_cases"].append({"function": name, "arguments": list(arguments),
                                               "expected": expected, "reference": reference,
                                               "allocation_fail_at": failure})
        positive = run_finite_program_aarch64(program, clang=clang, linker=linker,
                                             qemu_aarch64=qemu_aarch64)
        report["positive"] = positive
        if positive["execution"] != {"returncode": 0, "stdout": "HIA_AARCH64 resources 4 4 0 1\n", "stderr": ""}:
            raise ValueError("actual AArch64 value/resource matrix failed")
        for name, mutate, expected in [("wrong_sum", _wrong_sum, 11), ("wrong_allocation_error", _wrong_failure, 16)]:
            wrong = verify_program(mutate(document))
            observed = run_finite_program_aarch64(wrong, clang=clang, linker=linker, qemu_aarch64=qemu_aarch64)
            report["negative_controls"].append({"name": name, "program": wrong.as_dict(),
                                                  "expected_exit": expected, "observed": observed})
            if observed["execution"]["returncode"] != expected:
                raise ValueError("actual wrong-program control did not fail as expected: " + name)
        try:
            execute_program(program, "bounds_trap", [1])
        except HIAProgramTrap as trap:
            if trap.code != "bounds":
                raise
            report["reference_trap"] = {"code": trap.code, "report": trap.report}
        else:
            raise ValueError("reference bounds trap missing")
        trap = run_finite_program_aarch64(program, clang=clang, linker=linker,
                                         qemu_aarch64=qemu_aarch64, mode="bounds_trap")
        report["native_trap"] = trap
        if trap["execution"]["returncode"] != 134:
            raise ValueError("finite runtime abort did not exit with 134 under QEMU")
        report.update(ok=True, status="finite_standalone_aarch64_qemu_corpus_passed",
                      counts={"reference_and_native_return_cases": len(CASES), "actual_wrong_core_controls": 2,
                              "actual_bounds_abort_exit": 1, "successful_allocations": 4, "frees": 4,
                              "outstanding_allocations": 0, "actual_null_refusals": 1})
        report["claims"]["finite_corpus_qemu_execution_passed"] = True
        report["limits"] = ["QEMU user-mode Linux emulation, not a physical AArch64 board",
                            "17 fixed scalar ABI calls; finite 4096-byte single-live-allocation runtime",
                            "NULL caused by the target arena bound is compared with explicit interpreter allocation failure",
                            "bounds abort uses the reviewed runtime exit(134), not host SIGABRT",
                            "resource cleanup is checked on normal and error returns; traps terminate without cleanup",
                            "LLVM lld is bundled in the existing Rust toolchain; rustc and Rust source are never invoked"]
    except Exception as error:
        report["error"] = {"type": type(error).__name__, "message": str(error), "traceback": traceback.format_exc()[-6000:]}
    report["record_sha256"] = sha256(json.dumps(report, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--clang", default="/usr/lib/llvm-20/bin/clang")
    parser.add_argument("--linker", default="/tmp/hepta-ai-rust-1.90.0/lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld")
    parser.add_argument("--qemu-aarch64", default="/tmp/hepta-ai-verification/qemu-8.2.2/qemu-aarch64-static")
    args = parser.parse_args()
    output = Path(args.output)
    if output.exists() or output.is_symlink() or not output.parent.is_dir():
        parser.error("--output must be a new path in an existing directory")
    report = qualify(clang=args.clang, linker=args.linker, qemu_aarch64=args.qemu_aarch64)
    with os.fdopen(os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w", encoding="utf-8") as stream:
        json.dump(report, stream, sort_keys=True, indent=2)
        stream.write("\n")
    print(json.dumps({key: report.get(key) for key in ("ok", "status", "counts", "error", "record_sha256")}, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
