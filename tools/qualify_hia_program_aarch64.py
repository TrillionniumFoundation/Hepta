"""Standalone HIA -> LLVM -> AArch64; explicit QEMU or native-host qualification."""
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
from hepta.hia_program_aarch64 import CASES, _execution_host, _read, run_finite_program_aarch64
from hepta.hia_program_llvm import _run_logged
from hepta.pipeline import compiler_hash
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


def _native_source_snapshot(command_log):
    root = Path(__file__).resolve().parents[1]
    observed = []
    for args in (("rev-parse", "HEAD", "HEAD^{tree}"),
                 ("status", "--porcelain", "--untracked-files=all")):
        result = _run_logged(["git", "--no-replace-objects", *args], cwd=root,
                             command_log=command_log, timeout=10,
                             stdout_limit=65536, stderr_limit=65536)
        if result.returncode:
            raise ValueError("native qualification requires actual Git source identity")
        observed.append(result.stdout)
    identities = observed[0].splitlines()
    if (len(identities) != 2 or any(len(value) != 40 or
            any(ch not in "0123456789abcdef" for ch in value) for value in identities)
            or observed[1]):
        raise ValueError("native qualification requires an exact clean source checkout")
    return {"head": identities[0], "tree": identities[1], "status": "",
            "compiler_sha256": compiler_hash(),
            "qualifier_sha256": sha256(_read(Path(__file__), 65536)).hexdigest(),
            "fixture_producer_sha256": sha256(_read(root / "tools/qualify_hia_program.py", 65536)).hexdigest()}


def qualify(*, clang, linker, qemu_aarch64=None, execution="qemu"):
    native = execution == "native"
    report = {"schema": ("hepta.hia.program.aarch64-native-host-qualification.v1" if native
                         else "hepta.hia.program.aarch64-qualification.v1"), "ok": False,
              "status": "rejected", "reference_cases": [], "negative_controls": [],
              "claims": {"finite_corpus_qemu_execution_passed": False,
                         "physical_target_executed": False, "general_allocator_qualified": False,
                         "whole_language_soundness_proved": False, "backend_refinement_proved": False,
                         "automatic_cpp_migration_qualified": False, "faster_than_rust_demonstrated": False}}
    if native:
        report.update(execution_mode="native", commands=[])
        report["claims"].update(finite_corpus_native_host_execution_passed=False,
                                 physical_board_executed=False, hardware_attestation_proved=False)
    try:
        host = _execution_host(execution, qemu_aarch64)
        if native:
            report["native_host_before"] = host
            report["source_before"] = _native_source_snapshot(report["commands"])
        run_options = {"clang": clang, "linker": linker, "qemu_aarch64": qemu_aarch64}
        if native:
            run_options.update(execution="native", command_log=report["commands"])
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
        positive = run_finite_program_aarch64(program, **run_options)
        report["positive"] = positive
        if positive["execution"] != {"returncode": 0, "stdout": "HIA_AARCH64 resources 4 4 0 1\n", "stderr": ""}:
            raise ValueError("actual AArch64 value/resource matrix failed")
        for name, mutate, expected in [("wrong_sum", _wrong_sum, 11), ("wrong_allocation_error", _wrong_failure, 16)]:
            wrong = verify_program(mutate(document))
            observed = run_finite_program_aarch64(wrong, **run_options)
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
        trap = run_finite_program_aarch64(program, mode="bounds_trap", **run_options)
        report["native_trap"] = trap
        if trap["execution"]["returncode"] != 134:
            raise ValueError("finite runtime abort did not exit with 134 under " + ("native Linux" if native else "QEMU"))
        if native:
            report["source_after"] = _native_source_snapshot(report["commands"])
            report["native_host_after"] = _execution_host(execution, qemu_aarch64)
            if (report["source_after"] != report["source_before"]
                    or report["native_host_after"] != report["native_host_before"]):
                raise ValueError("native qualification source or host identity changed")
            if not report["commands"] or any(row.get("status") != "completed"
                    or row.get("stdout_complete") is not True or row.get("stderr_complete") is not True
                    for row in report["commands"]):
                raise ValueError("native qualification lacks complete real command streams")
        report.update(ok=True, status=("finite_standalone_aarch64_native_host_corpus_passed" if native
                                      else "finite_standalone_aarch64_qemu_corpus_passed"),
                      counts={"reference_and_native_return_cases": len(CASES), "actual_wrong_core_controls": 2,
                              "actual_bounds_abort_exit": 1, "successful_allocations": 4, "frees": 4,
                              "outstanding_allocations": 0, "actual_null_refusals": 1})
        report["claims"]["finite_corpus_native_host_execution_passed" if native else "finite_corpus_qemu_execution_passed"] = True
        report["limits"] = [("Direct Linux AArch64 ELF execution, not physical-board or hardware-attestation qualification" if native
                             else "QEMU user-mode Linux emulation, not a physical AArch64 board"),
                            "17 fixed scalar ABI calls; finite 4096-byte single-live-allocation runtime",
                            "NULL caused by the target arena bound is compared with explicit interpreter allocation failure",
                            "bounds abort uses the reviewed runtime exit(134), not host SIGABRT",
                            "resource cleanup is checked on normal and error returns; traps terminate without cleanup",
                            ("The selected LLVM linker is invoked directly; rustc and Rust source are never invoked" if native
                             else "LLVM lld is bundled in the existing Rust toolchain; rustc and Rust source are never invoked")]
    except Exception as error:
        report["error"] = {"type": type(error).__name__, "message": str(error), "traceback": traceback.format_exc()[-6000:]}
    report["record_sha256"] = sha256(json.dumps(report, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--clang", default="/usr/lib/llvm-20/bin/clang")
    parser.add_argument("--linker", default="/tmp/hepta-ai-rust-1.90.0/lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld")
    parser.add_argument("--qemu-aarch64", default=None)
    parser.add_argument("--execution", choices=("qemu", "native"), default="qemu")
    args = parser.parse_args()
    output = Path(args.output)
    if args.execution == "native" and (not output.is_absolute() or
            output.resolve().is_relative_to(Path(__file__).resolve().parents[1])):
        parser.error("native --output must be absolute and outside the source checkout")
    if output.exists() or output.is_symlink() or not output.parent.is_dir():
        parser.error("--output must be a new path in an existing directory")
    if args.execution == "native" and args.qemu_aarch64 is not None:
        parser.error("--execution native cannot accept --qemu-aarch64")
    qemu = (args.qemu_aarch64 if args.qemu_aarch64 is not None else
            "/tmp/hepta-ai-verification/qemu-8.2.2/qemu-aarch64-static") if args.execution == "qemu" else None
    report = qualify(clang=args.clang, linker=args.linker, qemu_aarch64=qemu, execution=args.execution)
    with os.fdopen(os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w", encoding="utf-8") as stream:
        json.dump(report, stream, sort_keys=True, indent=2)
        stream.write("\n")
    print(json.dumps({key: report.get(key) for key in ("ok", "status", "counts", "error", "record_sha256")}, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
