#!/usr/bin/env python3
"""Execute finite recursive-owner examples against an independent byte ledger.

This qualifies a runtime-sized Nil | Node(buffer, chain) profile. It does not
prove general recursive ADTs, arbitrary foreign resources, or backend refinement.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import signal
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from hepta.clang_capture import run_bounded
from hepta.hia_program import verify_program
from hepta.hia_program_llvm import build_program_native, emit_program_llvm
from hepta.hia_program_runtime import execute_program, HIAProgramTrap
from hepta.native_tool_identity import digest_executable
from hepta.pipeline import compiler_hash


EXAMPLES = ROOT / "examples" / "hia_recursive_chain"


def load_examples():
    return {name: verify_program((EXAMPLES / (name + ".json")).read_bytes())
            for name in ("core_v7", "composite_v2")}


def sum_bytes(n):
    cycles, rest = divmod(n, 256)
    return cycles * 32640 + rest * (rest - 1) // 2


def independent_spec(function, n, mode=0, fail=0):
    """Closed arithmetic specification, independent of Core/VM/native helpers."""
    failed = 0 < fail <= 2 * n
    nodes = (fail - 1) // 2 if failed else n
    payloads = nodes + int(failed and fail % 2 == 0)
    attempts = fail if failed else 2 * n
    peak = nodes * 25 + int(failed and fail % 2 == 0)
    total = sum_bytes(nodes)
    if function == "chain_checksum":
        answer = total + (1000000 if failed else 0)
    elif function == "chain_cancel":
        answer = int(not failed)
    elif function in {"chain_head_update", "chain_stored_loan"}:
        byte = 255 if function == "chain_head_update" else 99
        answer = total - ((nodes - 1) % 256) + byte if nodes else 0
    elif function == "chain_task":
        answer = (1000000 if failed else 3000000 if mode == 0
                  else 2000000 if mode == 1 and nodes else total)
    elif function == "chain_empty_payloads":
        failed = 0 < fail <= n
        nodes = fail - 1 if failed else n
        payloads, attempts, peak = 0, fail if failed else n, nodes * 24
        answer = int(not failed)
    elif function == "chain_empty_pop":
        nodes = payloads = attempts = peak = answer = 0
    elif function == "chain_recover":
        if fail not in {0, 2 * n + 2}:
            raise ValueError("recovery oracle admits only the targeted final-node refusal")
        nodes, payloads, attempts = n + int(fail == 0), n + 1, 2 * n + 2
        peak = 25 * n + 1 + (24 if fail == 0 else 0)
        answer = sum_bytes(n) + 73 + (1000000 if fail else 0)
    else:
        raise ValueError("unknown fixture function")
    return {"result": answer, "attempts": attempts,
            "allocations": nodes + payloads, "frees": nodes + payloads,
            "node_allocations": nodes, "payload_allocations": payloads,
            "node_frees": nodes, "payload_frees": payloads,
            "live_bytes": 0, "peak_bytes": peak,
            "null_frees": 0, "bad_frees": 0, "unknown_sizes": 0}


def case_plan():
    result = []
    for n in (0, 1, 2, 17, 257, 4097):
        for function in ("chain_checksum", "chain_cancel", "chain_head_update", "chain_stored_loan"):
            result.append((function, n, 0, 0))
        result.extend(("chain_task", n, mode, 0) for mode in range(3))
        result.append(("chain_empty_payloads", n, 0, 0))
        result.extend(("chain_recover", n, 0, failure) for failure in (0, 2 * n + 2))
    # Sweep every actual payload and header allocation failure in a 17-node
    # construction, plus the first non-occurring refusal (normal completion).
    for fail in range(1, 36):
        result.extend((function, 17, 0, fail) for function in
                      ("chain_checksum", "chain_cancel", "chain_head_update", "chain_stored_loan"))
        result.extend(("chain_task", 17, mode, fail) for mode in range(3))
    result.extend(("chain_empty_payloads", 17, 0, fail) for fail in range(1, 19))
    result.append(("chain_empty_pop", 0, 0, 0))
    return result


def vm_ledger(report):
    data = report["resources"]
    return {"result": int(report["result"]), "attempts": data["allocation_attempts"],
            "allocations": data["allocations"], "frees": data["frees"],
            "node_allocations": data["chain_nodes_created"],
            "payload_allocations": data["allocations"] - data["chain_nodes_created"],
            "node_frees": data["chain_nodes_dropped"],
            "payload_frees": data["frees"] - data["chain_nodes_dropped"],
            "live_bytes": data["live_bytes"], "peak_bytes": data["peak_bytes"],
            "null_frees": 0, "bad_frees": 0, "unknown_sizes": 0}


def source_snapshot():
    paths = [Path(__file__).resolve(), EXAMPLES / "core_v7.json",
             EXAMPLES / "composite_v2.json", EXAMPLES / "allocator_driver.c"]
    return {"compiler_sha256": compiler_hash(),
            "files": {str(path.relative_to(ROOT)): sha256(path.read_bytes()).hexdigest()
                      for path in paths}}


def qualify(output, clang):
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    programs = load_examples()
    before_snapshot = source_snapshot()
    before = before_snapshot["compiler_sha256"]
    clang_path = Path(clang).resolve() if Path(clang).is_file() else Path(shutil.which(clang) or clang).resolve()
    clang = str(clang_path)
    clang_before = digest_executable(clang_path)
    git = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    dirty = bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True).strip())
    plan = case_plan()
    (output / "plan.json").write_text(json.dumps({
        "schema": "hepta.hia.recursive-chain-plan.v1", "cases": plan,
        "negative_controls": ["removed_header_free", "removed_payload_free", "empty_head_trap"],
        "source_commit": git, "compiler_sha256": before,
        "source_snapshot": before_snapshot, "clang_sha256": clang_before,
        "scope": "finite Linux x86-64 scalar ABI, runtime-sized recursive buffer owners"}, indent=2) + "\n")
    commands, builds, results, negatives = [], {}, [], []

    def run(argv, label):
        completed = run_bounded([str(x) for x in argv], timeout=30,
                                stdout_limit=1048576, stderr_limit=1048576)
        out, err = output / (label + ".stdout.log"), output / (label + ".stderr.log")
        out.write_text(completed.stdout)
        err.write_text(completed.stderr)
        commands.append({"argv": [str(x) for x in argv], "returncode": completed.returncode,
                         "stdout": out.name, "stderr": err.name})
        return completed

    try:
        for name, program in programs.items():
            (output / (name + ".source.json")).write_bytes(program.structured_bytes or program.canonical_bytes)
            (output / (name + ".core.json")).write_bytes(program.canonical_bytes)
            (output / (name + ".ll")).write_text(emit_program_llvm(program).text)
            builds[name] = build_program_native(program, output / (name + ".o"), clang=clang, kind="object")
        driver = output / "allocator_driver.c"
        driver.write_bytes((EXAMPLES / "allocator_driver.c").read_bytes())
        flags = ["-O2", "-Wl,--wrap=malloc", "-Wl,--wrap=calloc", "-Wl,--wrap=free"]
        executable = output / "chain_native"
        link = run([clang, *flags, driver, output / "core_v7.o", output / "composite_v2.o", "-o", executable], "link")
        if link.returncode:
            raise RuntimeError("native driver link failed")
        for index, (function, n, mode, fail) in enumerate(plan):
            expected = independent_spec(function, n, mode, fail)
            program = programs["composite_v2" if function in {"chain_task", "chain_stored_loan"} else "core_v7"]
            args = [] if function == "chain_empty_pop" else [n, mode] if function == "chain_task" else [n]
            vm = execute_program(program, function, args, allocation_fail_at=fail or None)
            native = run([executable, function, n, mode, fail], "case_" + str(index))
            actual = json.loads(native.stdout) if native.returncode == 0 else None
            clean = all(vm["resources"][field] == 0 for field in
                        ("live_owners", "live_chains", "live_chain_nodes", "live_local_loans", "live_bytes"))
            results.append({"function": function, "n": n, "mode": mode, "fail_at": fail,
                            "expected": expected, "vm": vm, "native": actual,
                            "passed": native.returncode == 0 and actual == expected
                                      and vm_ledger(vm) == expected and clean})
        source = (output / "core_v7.ll").read_text()
        for label, needle in [("removed_header_free", "  call void @free(ptr %head) nobuiltin"),
                              ("removed_payload_free", "  call void @free(ptr %payload_ptr) nobuiltin")]:
            # These are deliberately corrupted real emitted runtimes, not an
            # invented receipt. Both variants are compiled and executed.
            if needle not in source:
                raise RuntimeError("negative mutation no longer matches emitted runtime")
            mutated = output / (label + ".ll")
            mutated.write_text(source.replace(needle, "  ; deliberately removed free"))
            binary = output / label
            compiled = run([clang, *flags, driver, mutated, output / "composite_v2.o", "-o", binary], label + "_link")
            if compiled.returncode:
                raise RuntimeError("negative-control binary did not compile")
            observed = run([binary, "chain_cancel", 17, 0, 0], label)
            actual = json.loads(observed.stdout) if observed.returncode == 0 else None
            negatives.append({"name": label, "actual": actual,
                              "detected": actual is not None and actual != independent_spec("chain_cancel", 17)
                                          and actual["live_bytes"] > 0})
        vm_trap = None
        try:
            execute_program(programs["core_v7"], "chain_empty_head", [])
        except HIAProgramTrap as exc:
            vm_trap = exc.report
        native_trap = run([executable, "chain_empty_head", 0, 0, 0], "empty_head_trap")
        negatives.append({"name": "empty_head_trap", "vm": vm_trap,
                          "returncode": native_trap.returncode,
                          "detected": vm_trap is not None and vm_trap["error"]["code"] == "bounds"
                                      and native_trap.returncode == -signal.SIGABRT})
        error = None
    except Exception as exc:
        error = {"type": type(exc).__name__, "message": str(exc)}
    after_snapshot = source_snapshot()
    after = after_snapshot["compiler_sha256"]
    clang_after = digest_executable(clang_path)
    artifacts = {path.name: {"bytes": path.stat().st_size,
                            "sha256": sha256(path.read_bytes()).hexdigest()}
                 for path in sorted(output.iterdir()) if path.is_file()}
    report = {"schema": "hepta.hia.recursive-chain-qualification.v1", "git_commit": git,
              "git_worktree_dirty": dirty, "compiler_sha256_before": before,
              "compiler_sha256_after": after, "source_unchanged": before_snapshot == after_snapshot,
              "source_snapshot_before": before_snapshot, "source_snapshot_after": after_snapshot,
              "clang_sha256_before": clang_before, "clang_sha256_after": clang_after,
              "toolchain_unchanged": clang_before == clang_after, "artifacts": artifacts,
              "planned_cases": len(plan), "executed_cases": len(results),
              "cases_passed": sum(x["passed"] for x in results),
              "builds": builds, "commands": commands, "cases": results,
              "negative_controls": negatives, "error": error,
              "claims": {"actual_native_execution": len(results) > 0,
                         "recursive_dynamic_length": True,
                         "maximum_successful_tested_nodes": max((x["expected"]["node_allocations"]
                             for x in results if x["passed"]), default=0),
                         "node_and_payload_frees_observed_separately": any(x["passed"] for x in results),
                         "generic_records_error_enums_stored_loans_tasks_executed": all(
                             any(x["function"] == name and x["n"] == 17 and x["passed"] for x in results)
                             for name in ("chain_task", "chain_stored_loan")),
                         "all_recursive_adts_supported": False,
                         "whole_language_soundness_proved": False,
                         "backend_refinement_proved": False,
                         "physical_device_evidence": False}}
    report["ok"] = (error is None and before_snapshot == after_snapshot and clang_before == clang_after and len(results) == len(plan)
                    and all(x["passed"] for x in results) and len(negatives) == 3
                    and all(x["detected"] for x in negatives))
    (output / "qualification.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-directory", required=True)
    parser.add_argument("--clang", default="clang")
    args = parser.parse_args()
    report = qualify(args.output_directory, args.clang)
    print(json.dumps({key: report[key] for key in ("ok", "planned_cases", "executed_cases", "cases_passed", "error")}))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
