#!/usr/bin/env python3
"""Retain Rust byte-owner CFG/bulk or opt-in v8 returned-loan differential evidence."""
from __future__ import annotations

import argparse
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

from tests.test_hia_rust_owned_cfg import RustByteOwnerCfgParity
from tests.test_hia_rust_bulk_vm import RustByteOwnerBulkParity
from tests.test_hia_rust_returned_loans import RustReturnedLoansParity


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inventory():
    files = set((ROOT / "hepta").glob("*.py"))
    files.update((ROOT / "rust/hia-core-shadow/src").rglob("*.rs"))
    files.update(ROOT / path for path in (
        "rust/hia-core-shadow/Cargo.toml", "rust/hia-core-shadow/Cargo.lock",
        "tests/test_hia_program.py", "tests/test_hia_rust_calls_shadow.py",
        "tests/test_hia_rust_owned_cfg.py", "tests/test_hia_rust_bulk_vm.py",
        "tests/test_hia_rust_returned_loans.py", "tests/test_hia_returned_loans.py",
        "tests/test_hia_bulk_memory.py", "tests/test_hia_overlap_move.py",
        "tests/test_hia_swap_v4.py", "tests/test_hia_offset_copy_v5.py",
        "tests/test_hia_range_fill_v6.py", "tools/qualify_hia_rust_owned_cfg.py"))
    return {str(path.relative_to(ROOT)): digest(path) for path in sorted(files)}


def command(argv):
    try:
        result = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"argv": argv, "returncode": None, "error": str(error)}
    return {"argv": argv, "returncode": result.returncode,
            "stdout": result.stdout, "stderr": result.stderr}


def qualify(*, returned_loans=False):
    started = datetime.now(timezone.utc).isoformat()
    before = inventory()
    head_before = command(["git", "rev-parse", "HEAD"])
    status_before = command(["git", "status", "--porcelain"])
    captured = io.StringIO()
    corpora = ((RustReturnedLoansParity,) if returned_loans else
               (RustByteOwnerCfgParity, RustByteOwnerBulkParity))
    suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(cls) for cls in corpora)
    with redirect_stdout(captured):
        result = unittest.TextTestRunner(stream=captured, verbosity=2).run(suite)
    after = inventory()
    observations = [dict(row, corpus=cls.__name__) for cls in corpora for row in getattr(cls, "observations", [])]
    sources = {digest: document for cls in corpora for digest, document in getattr(cls, "sources", {}).items()}
    rejections = [row for cls in corpora for row in getattr(cls, "rejections", [])]
    head_after = command(["git", "rev-parse", "HEAD"])
    status_after = command(["git", "status", "--porcelain"])
    clean_frozen = (head_before.get("returncode") == head_after.get("returncode") == 0
                    and head_before.get("stdout") == head_after.get("stdout")
                    and status_before.get("returncode") == status_after.get("returncode") == 0
                    and status_before.get("stdout") == status_after.get("stdout") == "")
    passed = (result.wasSuccessful() and not result.skipped and result.testsRun > 0
              and len(observations) > 0 and before == after)
    if returned_loans:
        passed = passed and clean_frozen and bool(rejections)
    executable = getattr(corpora[0], "executable", None)
    report = {
        "schema": ("hepta.hia.rust-returned-loan-qualification.v1" if returned_loans
                   else "hepta.hia.rust-byte-owner-cfg-qualification.v1"),
        "profile": ("bounded-cfg-byte-owner-loan-returns-v4" if returned_loans
                    else "bounded-cfg-byte-owner-bulk-v3"),
        "started_utc": started,
        "finished_utc": datetime.now(timezone.utc).isoformat(),
        "ok": passed,
        "status": "finite_cfg_parity_passed" if passed else "finite_cfg_parity_not_qualified",
        "tests": {"run": result.testsRun, "failures": len(result.failures),
                  "errors": len(result.errors), "skipped": len(result.skipped)},
        "test_log": captured.getvalue(),
        "build_process": getattr(corpora[0], "build", None),
        "source_before": before, "source_after": after, "source_unchanged": before == after,
        "git_head": head_after, "git_worktree_status": status_after,
        "git_head_before": head_before, "git_worktree_status_before": status_before,
        "clean_frozen_commit": clean_frozen,
        "toolchains": {"rustc": command(["rustc", "-vV"]),
                       "cargo": command(["cargo", "-V"]), "python": sys.version},
        "rust_executable": ({"path": executable, "sha256": digest(Path(executable))}
                            if executable and Path(executable).is_file() else None),
        "parity_observations": len(observations),
        "observations_per_corpus": {cls.__name__: len(getattr(cls, "observations", [])) for cls in corpora},
        "programs_by_sha256": sources,
        "observations": observations,
        "claims": {
            "actual_rust_binary_executed": passed,
            "canonical_python_admission_before_positive_execution": passed,
            "full_resource_ledgers_compared": passed,
            "values_traps_step_heap_and_call_stops_compared": passed,
            "versioned_bulk_operations_executed": passed and not returned_loans,
            "bulk_offsets_overlap_zero_length_and_bounds_compared": passed and not returned_loans,
            "whole_language_soundness_proved": False,
            "general_resource_execution": False,
            "rust_production_admission_authorized": False,
            "native_backend_refinement_proved": False,
            "full_P2_closed": False,
        },
        "limits": [
            "Finite byte-owner CFG/call and v2-v7 bulk corpora; no chain, v8 or nominal execution.",
            "Cross-owner copies use fixed 4096-byte host stack scratch; this does not bound whole-process memory.",
            "Public scalar signatures only; 32 call frames, at most 1M steps and 16MiB live bytes.",
            "Trap and evaluator budget stops retain actual live-resource ledgers; no unwind cleanup claim.",
            "Python Core remains production authority; this is neither a native backend nor a soundness proof.",
        ],
    }
    if returned_loans:
        report["status"] = ("finite_returned_loan_parity_passed" if passed
                            else "finite_returned_loan_parity_not_qualified")
        report["rejection_observations"] = rejections
        report["independent_rejections"] = len(rejections)
        report["claims"]["parameter_bound_returned_loans_executed"] = passed
        report["claims"]["independent_invalid_program_refusals_retained"] = passed
        report["limits"][0] = "Finite primitive v8 byte-owner returned-loan corpus; no chain or direct nominal execution."
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--returned-loans", action="store_true",
                        help="qualify the separate v8 profile on a clean frozen commit")
    args = parser.parse_args(argv)
    report = qualify(returned_loans=args.returned_loans)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n")
    print(json.dumps({"ok": report["ok"], "status": report["status"],
                      "tests": report["tests"], "observations": report["parity_observations"],
                      "report": str(args.output)}, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
