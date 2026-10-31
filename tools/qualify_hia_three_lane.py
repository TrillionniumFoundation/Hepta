#!/usr/bin/env python3
"""Source-bound HIA cross-lane test gate: zero errors, failures AND skips.

Scoped proof/test evidence, never a production authorization. It refuses
unknown scopes, zero-test successes, missing Git source identity, and writes
an immutable per-run receipt with explicit negative outcomes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys
import unittest

# Direct script execution sets sys.path[0] to tools/, not to repository root.
# Agent/CI invocations and python -m must resolve the exact same tests package.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


SUITES = {
    "gate": ("tests.test_hia_three_lane_gate",),
    "core": (
        "tests.test_hia_bounded_mutable_snapshot",
        "tests.test_hia_bounded_input_utf8",
        "tests.test_hia_bounded_research_wire",
        "tests.test_hia_evidence_json_structure",
        "tests.test_hia_program",
        "tests.test_hia_json_preflight",
        "tests.test_hia_program_composite",
        "tests.test_hia_execution_contract",
        "tests.test_hia_exit_accounting",
        "tests.test_hia_opcode_catalog",
        "tests.test_hia_full_cost_gate",
        "tests.test_hia_paired_holdout",
    ),
    "native": (
        "tests.test_hia_native_process_observer",
        "tests.test_hia_native_paired_replay",
    ),
    "rust": (
        "tests.test_hia_rust_byte_dag",
    ),
    "legacy": (
        "tests.test_hsir_wire_audit",
        "tests.test_hsir_bridge",
        "tests.test_cfg_analysis",
        "tests.test_ssa_scalar",
        "tests.test_ssa_verify",
        "tests.test_hia_schema_unification",
        "tests.test_hia_agent_assembly",
        "tests.test_hia_routes",
    ),
    "llvm": (
        "tests.test_hia_agent_public_tools",
        "tests.test_hia_program_llvm",
        "tests.test_hia_composite_abi",
        "tests.test_hia_native_differential",
    ),
    "migration": (
        "tests.test_cpp_gsl_branching_callback",
        "tests.test_hia_c_project_views",
        "tests.test_hia_c_loop_migration_qualification",
        "tests.test_c_fixed_slice_shift",
        "tests.test_hia_native_ndu",
    ),
}


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], text=True, timeout=10).strip()


def _planned_test_ids(suite) -> tuple[str, ...]:
    """Freeze the exact discovered tests before unittest may consume the suite."""
    ids = []
    stack = [suite]
    while stack:
        current = stack.pop()
        if isinstance(current, unittest.TestSuite):
            stack.extend(reversed(list(current)))
        else:
            if not callable(getattr(current, "id", None)):
                raise ValueError("non-TestCase discovery entry")
            ids.append(current.id())
    return tuple(ids)


def _outcome_admissible(result, planned_ids, *, immutable: bool) -> bool:
    """Strict pure gate; expectedFailures and missing/duplicated tests refuse."""
    return bool(
        immutable and planned_ids
        and len(set(planned_ids)) == len(planned_ids)
        and result.testsRun == len(planned_ids)
        and result.wasSuccessful()
        and not result.errors and not result.failures and not result.skipped
        and not result.expectedFailures and not result.unexpectedSuccesses
    )


def check(scope: str, output: Path) -> dict:
    if scope not in SUITES:
        raise ValueError("unknown exact cross-lane suite")
    # Reject both tracked modifications and untracked material inside the
    # repository: test discovery must not silently import an extra local file.
    if git("status", "--porcelain", "--untracked-files=all"):
        raise ValueError("source checkout dirty before cross-lane gate")
    head = git("rev-parse", "HEAD")
    tree = git("rev-parse", "HEAD^{tree}")
    suite = unittest.defaultTestLoader.loadTestsFromNames(SUITES[scope])
    planned_ids = _planned_test_ids(suite)
    result = unittest.TextTestRunner(stream=sys.stderr, verbosity=2).run(suite)
    status_after = git("status", "--porcelain", "--untracked-files=all")
    head_after = git("rev-parse", "HEAD")
    tree_after = git("rev-parse", "HEAD^{tree}")
    dirty_after = bool(status_after)
    identity_drift = (head_after != head or tree_after != tree)
    passed = _outcome_admissible(
        result, planned_ids, immutable=(not dirty_after and not identity_drift))
    receipt = {
        "schema": "hepta.hia.three-lane-test-receipt.v1",
        "source_commit": head,
        "source_tree": tree,
        "scope": scope,
        "test_modules": list(SUITES[scope]),
        "tests_executed": result.testsRun,
        "tests_planned": len(planned_ids),
        "planned_test_ids_sha256": hashlib.sha256(json.dumps(
            planned_ids, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest(),
        "duplicate_test_identity": len(planned_ids) != len(set(planned_ids)),
        "expected_failures": [test.id() for test, _ in result.expectedFailures],
        "errors": [test.id() for test, _ in result.errors],
        "failures": [test.id() for test, _ in result.failures],
        "skipped": [{"test": test.id(), "reason": reason}
                    for test, reason in result.skipped],
        "unexpected_successes": [test.id() for test in result.unexpectedSuccesses],
        "source_identity_drift": identity_drift,
        "worktree_dirty_after": dirty_after,
        "tracked_source_mutated": dirty_after,
        "python_version": platform.python_version(),
        "passed": passed,
        "authority": "DENY_ALL",
        "production_activation_allowed": False,
        "claims": {
            "whole_language_soundness_proved": False,
            "source_to_native_refinement_proved": False,
            "p0_through_p7_production_closed": False,
            "ndu_real_full_cost_gain_established": False,
        },
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    # Do not overwrite a prior positive or negative artifact. Retain failures.
    with output.open("x", encoding="utf-8") as target:
        target.write(json.dumps(receipt, ensure_ascii=False, sort_keys=True, indent=2) + "\n")
    print(json.dumps({k: receipt[k] for k in ("scope", "source_commit",
          "source_tree", "tests_planned", "tests_executed", "errors", "failures",
          "skipped", "expected_failures", "duplicate_test_identity",
          "source_identity_drift", "worktree_dirty_after", "passed", "authority")}, sort_keys=True))
    return receipt


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--suite", choices=sorted(SUITES), required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    if not check(args.suite, Path(args.output))["passed"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
