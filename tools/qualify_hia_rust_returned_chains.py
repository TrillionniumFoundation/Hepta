#!/usr/bin/env python3
"""Retain independent chain/v8 execution and refusal evidence on a frozen tree."""
from __future__ import annotations

import argparse
from collections import Counter
from contextlib import redirect_stdout
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tests.test_hia_rust_returned_chains import RustReturnedChainsParity, PROFILE


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inventory():
    paths = set((ROOT / "hepta").glob("*.py"))
    paths.update((ROOT / "rust/hia-core-shadow").rglob("*.rs"))
    paths.update(ROOT / name for name in (
        "rust/hia-core-shadow/Cargo.toml", "rust/hia-core-shadow/Cargo.lock",
        "tests/test_hia_program.py", "tests/test_hia_returned_loans.py",
        "tests/test_hia_rust_calls_shadow.py", "tests/test_hia_rust_owned_cfg.py",
        "tests/test_hia_rust_bulk_vm.py", "tests/test_hia_rust_owned_memory.py",
        "tests/test_hia_rust_returned_loans.py", "tests/test_hia_rust_returned_chains.py",
        "tests/test_hia_bulk_memory.py", "tests/test_hia_overlap_move.py",
        "tests/test_hia_swap_v4.py", "tests/test_hia_offset_copy_v5.py",
        "tests/test_hia_range_fill_v6.py", "tests/test_hia_zero_length_bulk_native.py",
        "tests/test_hia_program_composite.py", "tests/test_hia_composite_v6_resources.py",
        "tests/test_hia_recursive_chain.py", "tools/qualify_hia_returned_loans_cross.py",
        "tools/qualify_hia_riscv64.py", "tools/qualify_hia_rust_returned_chains.py",
        "examples/hia_program/returned_loans_cross_target_v8.hia",
        "examples/hia_recursive_chain/core_v7.json", "examples/hia_recursive_chain/composite_v2.json"))
    return {str(path.relative_to(ROOT)): digest(path) for path in sorted(paths)}


def command(argv):
    try:
        result = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True, timeout=30)
        return {"argv": argv, "returncode": result.returncode,
                "stdout": result.stdout, "stderr": result.stderr}
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"argv": argv, "returncode": None, "error": str(error)}


def qualify(*, expected_head=None):
    started = datetime.now(timezone.utc).isoformat()
    before = inventory()
    head_before = command(["git", "rev-parse", "HEAD"])
    status_before = command(["git", "status", "--porcelain"])
    captured = io.StringIO()
    with redirect_stdout(captured):
        result = unittest.TextTestRunner(stream=captured, verbosity=2).run(
            unittest.defaultTestLoader.loadTestsFromTestCase(RustReturnedChainsParity))
    after = inventory()
    head_after = command(["git", "rev-parse", "HEAD"])
    status_after = command(["git", "status", "--porcelain"])
    clean_frozen = (head_before.get("returncode") == head_after.get("returncode") == 0
        and head_before.get("stdout") == head_after.get("stdout")
        and status_before.get("returncode") == status_after.get("returncode") == 0
        and status_before.get("stdout") == status_after.get("stdout") == ""
        and (expected_head is None or head_after["stdout"].strip() == expected_head))
    observations = getattr(RustReturnedChainsParity, "observations", [])
    refusals = getattr(RustReturnedChainsParity, "rejections", [])
    tests_ok = result.wasSuccessful() and not result.skipped and result.testsRun > 0
    matched = bool(observations) and all(row.get("matched") is True for row in observations)
    refused = bool(refusals) and all(row.get("rejected") is True and row["rust_shadow"]["returncode"] != 0
        and row["rust_execution"]["returncode"] != 0 and not row["rust_shadow"]["stdout"]
        and not row["rust_execution"]["stdout"] for row in refusals)
    observed = tests_ok and matched and refused and before == after
    qualified = observed and clean_frozen
    executable = getattr(RustReturnedChainsParity, "executable", None)
    return {
        "schema": "hepta.hia.rust-returned-chain-qualification.v1", "profile": PROFILE,
        "started_utc": started, "finished_utc": datetime.now(timezone.utc).isoformat(),
        "ok": qualified,
        "status": ("finite_returned_chain_parity_passed" if qualified
                   else "finite_returned_chain_not_qualified"),
        "observations_matched": observed, "clean_frozen_commit": clean_frozen,
        "tests": {"run": result.testsRun, "failures": len(result.failures),
                  "errors": len(result.errors), "skipped": len(result.skipped)},
        "test_log": captured.getvalue(),
        "source_before": before, "source_after": after, "source_unchanged": before == after,
        "git_head_before": head_before, "git_head": head_after,
        "git_worktree_status_before": status_before, "git_worktree_status": status_after,
        "expected_head": expected_head,
        "toolchains": {"rustc": command(["rustc", "-vV"]), "cargo": command(["cargo", "-V"]),
                       "python": sys.version},
        "build_process": getattr(RustReturnedChainsParity, "build", None),
        "rust_executable": ({"path": executable, "sha256": digest(Path(executable)),
                             "bytes": Path(executable).stat().st_size} if executable else None),
        "parity_observations": len(observations), "independent_rejections": len(refusals),
        "statuses": dict(Counter(row.get("rust", {}).get("status", "process_failure") for row in observations)),
        "programs_by_sha256": getattr(RustReturnedChainsParity, "sources", {}),
        "observations": observations, "rejection_observations": refusals,
        "claims": {
            "actual_rust_binary_executed": qualified,
            "canonical_python_admission_before_positive_execution": qualified,
            "independent_rust_admission_without_python_receipts": qualified,
            "full_stopped_resource_ledgers_compared": qualified,
            "chain_and_v8_returned_loan_composition_executed": qualified,
            "logical_storage_and_formal_identity_controls_executed": qualified,
            "same_core_as_cross_target_corpus_compared": qualified,
            "native_controls_executed_by_this_runner": False,
            "rust_production_admission_authorized": False,
            "whole_language_soundness_proved": False,
            "native_backend_refinement_proved": False,
            "general_resource_execution": False,
            "rust_performance_advantage_proved": False,
            "full_P2_closed": False,
        },
        "limits": [
            "One Rust execution Machine; nonchain byte v3 and returned-loan v4 contracts remain separate.",
            "Public scalar entry/results only; finite primitive chain operations and original-parameter direct-child returns.",
            "Native execution belongs to separately retained same-Core controls, not this Rust/Python runner.",
            "32 root-inclusive call frames, at most 1M steps and 16MiB payload/node bytes; VM metadata is outside that ledger.",
            "Call-formal scope witnesses do not count as source loans. Trap/budget stops retain actual counted live resources.",
            "General lifetime parameters, recursive heap ADTs, foreign callbacks and asynchronous unwind cancellation remain unqualified.",
        ],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--expected-head")
    args = parser.parse_args(argv)
    report = qualify(expected_head=args.expected_head)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    args.output.with_suffix(".log").write_text(report["test_log"])
    print(json.dumps({"ok": report["ok"], "status": report["status"], "tests": report["tests"],
                      "observations": report["parity_observations"], "refusals": report["independent_rejections"],
                      "report": str(args.output)}, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
