#!/usr/bin/env python3
"""Fresh captured-C, proof, LLVM and finite-native CRC proposal qualification.

This command runs correctness controls only. Its retained native timers are
costs/observations, never a performance comparison. A later economic study must
freeze its own complete protocol and regenerate/reprove/recompile all images.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta.clang_capture import run_bounded
from hepta.hia_crc_kernel import POLYNOMIALS, kernel, step
from hepta.hia_crc_linear import LABELS, candidates
from hepta.hia_finite_context import TIMED_XOR_FOLD_PROFILE, build_bank
from hepta.hia_program import verify_program
from tools.qualify_hia_crc_context import _capture_and_compare
from tools.qualify_hia_integrated import _digest_file
from tools.qualify_hia_ndu_loop import EpisodeBudget, measured
from tools.qualify_hia_stb_ndu import frontend_libraries, solver_identity

BUDGET_NS = 300_000_000_000
SCHEMA = "hepta.hia.crc-linear-qualification.v1"


def require(condition, message):
    if not condition:
        raise ValueError("E_HIA_CRC_LINEAR: " + message)


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def save(path, value):
    Path(path).write_bytes(wire(value) + b"\n")


def source_state(expected_head):
    """Bind raw Git modes/blobs, including new proposals and the actual C inputs."""
    git = lambda *args: subprocess.check_output(["git", "--no-replace-objects", *args], cwd=ROOT)
    head = git("rev-parse", "HEAD").decode().strip()
    require(re.fullmatch(r"[0-9a-f]{40}", expected_head) and head == expected_head,
            "exact committed source required")
    require(not git("status", "--porcelain", "--untracked-files=all"), "clean source required")
    scope = ["hepta", "tools", "examples/hia_filecheck", "tests/test_hia_crc_linear.py",
             "tests/test_hia_crc_linear_qualification.py", "docs/HIA_CRC_LINEAR_PROPOSALS.md", "docs/HIA_FINITE_NATIVE_CONTEXT.md",
             "tests/test_hia_crc_linear_economics.py", "experiments/hia_crc_linear_20261030",
             "tests/test_hia_finite_context_timed_fold.py", "tests/fixtures/hia_crc_linear",
             "experiments/hia_crc_context"]
    files = {}
    for row in git("ls-tree", "-r", "--full-tree", "-z", head, "--", *scope).split(b"\0")[:-1]:
        metadata, name = row.split(b"\t", 1)
        mode, kind, blob = metadata.decode().split()
        name = name.decode()
        require(kind == "blob" and mode in {"100644", "100755"}
                and all(p not in {"", ".", "..", ".git"} for p in name.split("/")),
                "unsafe source member")
        parent = ROOT
        for part in name.split("/")[:-1]:
            parent /= part
            require(stat.S_ISDIR(parent.lstat().st_mode), "source parent is not an actual directory")
        files[name] = _digest_file(ROOT / name, expected_mode=mode, expected_blob=blob)
    require("hepta/hia_crc_linear.py" in files and str(Path(__file__).relative_to(ROOT)) in files,
            "proposal/runner absent from immutable tree")
    require(git("rev-parse", "HEAD").decode().strip() == head, "source moved during identity read")
    return {"head": head, "tree": git("rev-parse", head + "^{tree}").decode().strip(),
            "scope": scope, "files": files}


def tool_state(clang, cc, objdump):
    result = {}
    for name, value in (("python", sys.executable), ("clang", clang), ("cc", cc), ("objdump", objdump)):
        path = Path(shutil.which(value) or value).resolve(strict=True)
        result[name] = {"path": str(path), "bytes": path.stat().st_size, "sha256": _digest_file(path)}
    result["solver"] = solver_identity()
    result["frontend_libraries"] = frontend_libraries()
    result["all_system_loader_dependencies_attested"] = False
    return result


def edge_cases():
    states = (0, 1, 0x7F, 0x80, 0xFF, 0x100, 0x80000000, 0xFFFFFFFF)
    polys = (*POLYNOMIALS, 0, 1, 0xFFFFFFFF, 0x80000000, 0x12345678, 0xEDB88321)
    return [[state, polynomial] for state in states for polynomial in polys]


def finite_plan(*, timed=False):
    """Each image really executes both target polynomials and a generic fallback."""
    return [{"id": index * 3 + p, "candidate": label, "mode": "timed_xor_fold" if timed else "xor_fold",
             "parameter": polynomial, "seed": 0xFFFFFFFF, "values": list(b"123456789")}
            for index, label in enumerate(LABELS)
            for p, polynomial in enumerate((*POLYNOMIALS, 0x12345678))]


def disassembly(bank_report, directory, objdump):
    rows = {}
    for label in LABELS:
        path = directory / (label + ".so")
        command = [objdump, "-d", "-M", "intel", "--disassemble=calculate", str(path)]
        result = run_bounded(command, timeout=10, stdout_limit=65536, stderr_limit=65536)
        row = {"argv": command, "returncode": result.returncode,
               "stdout": result.stdout, "stderr": result.stderr,
               "artifact_sha256": _digest_file(path), "code": bank_report["candidates"][label]["code"]}
        save(directory / (label + ".disassembly.json"), row)
        require(result.returncode == 0 and result.stderr == "", "actual disassembly failed")
        require(row["artifact_sha256"] == bank_report["candidates"][label]["compilation"]["artifact_sha256"],
                "disassembly source differs from freshly compiled image")
        rows[label] = {"code_sha256": row["code"]["sha256"], "code_bytes": row["code"]["bytes"],
                       "disassembly_sha256": _digest_file(directory / (label + ".disassembly.json"))}
    legacy = {rows[label]["code_sha256"] for label in LABELS[:3]}
    return {"candidates": rows,
        "new_export_bytes_differ_from_every_legacy": {
            label: rows[label]["code_sha256"] not in legacy for label in LABELS[3:]},
        "code_difference_proves_performance": False, "machine_code_refinement_proved": False}


def qualify(*, output, expected_head, clang, cc, objdump, timed=False):
    started = time.monotonic_ns()
    directory = Path(output).resolve()
    require(directory != ROOT and ROOT not in directory.parents, "external new output directory required")
    directory.mkdir(parents=True, exist_ok=False)
    ledger = []
    report = {"schema": SCHEMA, "qualified": False, "status": "failed", "ledger": ledger,
        "expected_head": expected_head, "started_utc": datetime.now(timezone.utc).isoformat(),
        "budget_ns": BUDGET_NS, "labels": list(LABELS), "errors": [],
        "host": {"platform": platform.platform(), "python": sys.version, "pid": os.getpid()},
        "claims": {"economic_study_executed": False, "performance_qualified": False,
            "positive_net_benefit": False, "NDU_incremental_value": False,
            "source_C_refinement_proved": False, "whole_language_safety_proved": False,
            "final_machine_code_refinement_proved": False, "production_workload": False,
            "third_party_source_library": False, "deployment_authority": False}}
    bank = None
    require(type(timed) is bool, "exact timing profile opt-in required")
    report["timed_xor_fold"] = timed
    budget = EpisodeBudget(started, BUDGET_NS)

    def run(label, action):
        return budget.stage(label, ledger, action)

    def fail(label, error):
        report["qualified"] = False
        report["errors"].append({"stage": label, "type": type(error).__name__, "message": str(error)})

    try:
        report["source_before"] = run("source.before", lambda: source_state(expected_head))
        report["tools_before"] = run("tools.before", lambda: tool_state(clang, cc, objdump))
        run("source.capture-and-bridge", lambda: _capture_and_compare(directory, clang, cc, report))
        pool = run("proposal.generate", candidates)
        report["candidate_core_sha256"] = {name: verify_program(document).sha256 for name, document in pool.items()}
        for name, document in pool.items():
            save(directory / (name + ".hia.json"), document)
        require(report["source_bridge"]["kernel_sha256"] == report["candidate_core_sha256"]["baseline"],
                "captured-source bridge is not tied to the actual baseline")
        images = directory / "bank"
        images.mkdir()
        report["bank"] = {}
        bank = run("bank.prepare", lambda: build_bank(kernel(), pool, images, clang=clang,
            cases=edge_cases(), oracle=step, report=report["bank"], reuse_oracle=True,
            allow_timed_xor_fold=timed))
        report["code_inspection"] = run("code.inspect", lambda: disassembly(report["bank"], images, objdump))
        plan = finite_plan(timed=timed)
        trace = run("trace.prepare", lambda: bank.prepare_trace(plan))
        save(directory / "PLAN.json", {"requests": plan, "trace_sha256": trace.sha256, "expected": trace.expected})
        native = report["native"] = {}
        try:
            run("trace.execute", lambda: bank.run(trace, report=native))
        finally:
            save(directory / "NATIVE.json", native)
        require(native["status"] == "completed" and native["prefix"]["complete"], "finite native trace incomplete")
        observed = native["prefix"]["completed_requests"]
        if timed:
            require(native["profile"] == TIMED_XOR_FOLD_PROFILE
                    and all(row["mode"] == 3 and type(row.get("kernel_ns")) is int
                            and row["kernel_ns"] > 0 for row in observed), "actual timed fold event missing/invalid")
        require(len(observed) == 18 and sum(row["calls"] for row in observed) == 162,
                "actual qualification request/call denominator differs")
        require(sum(row["native_differential"]["cases_executed"]
                    for row in report["bank"]["candidates"].values()) == 384,
                "preparation native differential denominator differs")
        report["actual_counts"] = {"original_C_reference_cases": 48,
            "native_preparation_differential_cases": 384, "finite_requests": 18, "finite_kernel_calls": 162,
            "economic_observations": 0, "ndu_decisions": 0}
        report["qualified"] = True
    except BaseException as error:
        fail("qualification", error)
    finally:
        if bank is not None:
            try:
                report["release"] = measured("bank.close", ledger, bank.close)
                require(report["release"]["complete"] is True, "bank release incomplete; no retry")
            except BaseException as error:
                fail("bank.close", error)
        for name, action in (("source", lambda: source_state(expected_head)),
                             ("tools", lambda: tool_state(clang, cc, objdump))):
            try:
                report[name + "_after"] = measured(name + ".after", ledger, action)
                require(report.get(name + "_before") == report[name + "_after"], name + " identity changed")
            except BaseException as error:
                fail(name + ".after", error)
        report["wall_ns"] = time.monotonic_ns() - started
        if report["wall_ns"] > BUDGET_NS:
            fail("deadline", RuntimeError("complete qualification including cleanup/identity exceeded budget"))
        report["status"] = "completed" if report["qualified"] else "failed"
        save(directory / "RESULT.json", report)
        report["wall_through_first_result_write_ns"] = time.monotonic_ns() - started
        if report["wall_through_first_result_write_ns"] > BUDGET_NS:
            fail("result.deadline", RuntimeError("first result serialization/write exceeded budget"))
            report["status"] = "failed"
        save(directory / "RESULT.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--clang", default="clang")
    parser.add_argument("--cc", default="gcc")
    parser.add_argument("--objdump", default="objdump")
    parser.add_argument("--timed-fold", action="store_true")
    options = parser.parse_args()
    result = qualify(output=options.output_directory, expected_head=options.expected_head,
                     clang=options.clang, cc=options.cc, objdump=options.objdump, timed=options.timed_fold)
    print(json.dumps({"qualified": result["qualified"], "status": result["status"],
                      "wall_ns": result["wall_ns"], "economic_study_executed": False}, sort_keys=True))
    return 0 if result["qualified"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
