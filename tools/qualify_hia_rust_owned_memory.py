#!/usr/bin/env python3
"""Run actual Rust resource execution and retain raw input/process/ledger evidence."""
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

from tests.test_hia_rust_owned_memory import RustOwnedMemoryParity


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inventory():
    files = set((ROOT / "hepta").glob("*.py"))
    files.update((ROOT / "rust/hia-core-shadow/src").rglob("*.rs"))
    files.update((ROOT / "rust/hia-core-shadow/tests").rglob("*.rs"))
    files.update(ROOT / name for name in (
        "rust/hia-core-shadow/Cargo.toml", "rust/hia-core-shadow/Cargo.lock",
        "tests/test_hia_program.py", "tests/test_hia_bulk_memory.py",
        "tests/test_hia_offset_copy_v5.py", "tests/test_hia_overlap_move.py",
        "tests/test_hia_range_fill_v6.py", "tests/test_hia_swap_v4.py",
        "tests/test_hia_zero_length_bulk_native.py", "tests/test_hia_program_composite.py",
        "tests/test_hia_composite_v6_resources.py", "tests/test_hia_recursive_chain.py",
        "tests/test_hia_rust_owned_memory.py", "tools/qualify_hia_rust_owned_memory.py",
        "tools/qualify_hia_recursive_chain.py",
        "examples/hia_recursive_chain/core_v7.json", "examples/hia_recursive_chain/composite_v2.json",
        "examples/hia_migration/generic_owners.hepta", "examples/cpp/owned_migration/expected.hepta",
        "examples/hia_resource_core/borrowed_projection.hepta"))
    return {str(path.relative_to(ROOT)): digest(path) for path in sorted(files)}


def command(argv):
    try:
        result = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"argv": argv, "returncode": None, "error": str(error)}
    return {"argv": argv, "returncode": result.returncode,
            "stdout": result.stdout, "stderr": result.stderr}


def qualify():
    started = datetime.now(timezone.utc).isoformat()
    before = inventory()
    captured = io.StringIO()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(RustOwnedMemoryParity)
    with redirect_stdout(captured):
        result = unittest.TextTestRunner(stream=captured, verbosity=2).run(suite)
    after = inventory()
    observations = RustOwnedMemoryParity.observations
    admissions = RustOwnedMemoryParity.admissions
    passed = (result.wasSuccessful() and not result.skipped and result.testsRun > 0
              and bool(observations) and all(item.get("matched") for item in observations)
              and bool(admissions) and all(item.get("rejected") for item in admissions)
              and before == after)
    executable = getattr(RustOwnedMemoryParity, "executable", None)
    return {
        "schema": "hepta.hia.rust-owned-memory-qualification.v2",
        "profile": "bounded-cfg-owned-memory-v5",
        "started_utc": started, "finished_utc": datetime.now(timezone.utc).isoformat(),
        "ok": passed,
        "status": "finite_owned_memory_parity_passed" if passed else "finite_owned_memory_not_qualified",
        "tests": {"run": result.testsRun, "failures": len(result.failures),
                  "errors": len(result.errors), "skipped": len(result.skipped)},
        "test_log": captured.getvalue(),
        "source_before": before, "source_after": after, "source_unchanged": before == after,
        "git_head": command(["git", "rev-parse", "HEAD"]),
        "git_worktree_status": command(["git", "status", "--porcelain"]),
        "toolchains": {"rustc": command(["rustc", "-vV"]),
                       "cargo": command(["cargo", "-V"]), "python": sys.version},
        "build_process": getattr(RustOwnedMemoryParity, "build", None),
        "rust_executable": ({"path": executable, "sha256": digest(Path(executable))}
                            if executable and Path(executable).is_file() else None),
        "parity_observations": len(observations), "negative_admissions": len(admissions),
        "observed_statuses": dict(Counter(item.get("rust", {}).get("status", "process_failure")
                                           for item in observations)),
        "observed_profiles": dict(Counter(item.get("rust", {}).get("profile", "process_failure")
                                           for item in observations)),
        "inputs_by_sha256": RustOwnedMemoryParity.inputs,
        "programs_by_sha256": RustOwnedMemoryParity.programs,
        "observations": observations, "admissions": admissions,
        "claims": {
            "actual_rust_binary_executed": passed,
            "canonical_python_admission_before_positive_execution": passed,
            "original_source_nominal_and_core_inputs_retained": passed,
            "full_resource_ledgers_compared": passed,
            "values_traps_step_heap_call_and_allocation_stops_compared": passed,
            "source_projection_borrow_lifecycles_compared": passed,
            "primitive_cross_call_loan_returns_supported": False,
            "whole_language_soundness_proved": False,
            "general_resource_execution": False,
            "rust_production_admission_authorized": False,
            "native_backend_refinement_proved": False,
            "rust_performance_advantage_proved": False,
            "full_P2_closed": False,
        },
        "limits": [
            "Finite primitive v1-v7 CFG/call corpus; canonical Python remains production admission authority.",
            "Source borrowed-return helpers are existing checked projection inlining; no primitive cross-call Loan return or stored returned source borrow.",
            "Nominal records/enums/cooperative tasks require existing canonical lowering; raw nominal Rust input remains rejected.",
            "Cancellation is the explicit cooperative task protocol, not concurrent/asynchronous cancellation or unwinding on traps.",
            "Trap/step/heap/call stops preserve the actual live ledger; interrupted node destruction does not claim cleanup.",
            "Public scalar entry/results only; at most 32 call frames, 1M steps and 16MiB live payload/node bytes. VM metadata is outside that byte ledger.",
            "No native backend, compiler soundness, source refinement or performance claim is established by this finite differential.",
        ],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    report = qualify()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n")
    log = args.output.with_suffix(".log")
    log.write_text(report["test_log"])
    print(json.dumps({"ok": report["ok"], "status": report["status"], "tests": report["tests"],
                      "observations": report["parity_observations"],
                      "negative_admissions": report["negative_admissions"],
                      "report": str(args.output), "log": str(log)}, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
