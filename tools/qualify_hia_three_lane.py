#!/usr/bin/env python3
"""Source-bound HIA cross-lane test gate: zero errors, failures AND skips.

Scoped proof/test evidence, never a production authorization. It refuses
unknown scopes, zero-test successes, missing Git source identity, and writes
an immutable per-run receipt with explicit negative outcomes.
"""
from __future__ import annotations

import argparse
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
    "core": (
        "tests.test_hia_bounded_mutable_snapshot",
        "tests.test_hia_bounded_input_utf8",
        "tests.test_hia_bounded_research_wire",
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
}


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], text=True, timeout=10).strip()


def check(scope: str, output: Path) -> dict:
    if scope not in SUITES:
        raise ValueError("unknown exact cross-lane suite")
    # Reuse only frozen code under one Git commit. A dirty tracked worktree is
    # not a qualified source. Tests additionally recheck this after execution.
    if git("status", "--porcelain", "--untracked-files=no"):
        raise ValueError("tracked source tree modified before cross-lane gate")
    head = git("rev-parse", "HEAD")
    tree = git("rev-parse", "HEAD^{tree}")
    suite = unittest.defaultTestLoader.loadTestsFromNames(SUITES[scope])
    result = unittest.TextTestRunner(stream=sys.stderr, verbosity=2).run(suite)
    dirty_after = bool(git("status", "--porcelain", "--untracked-files=no"))
    passed = bool(result.testsRun > 0 and result.wasSuccessful()
                  and not result.skipped and not dirty_after)
    receipt = {
        "schema": "hepta.hia.three-lane-test-receipt.v1",
        "source_commit": head,
        "source_tree": tree,
        "scope": scope,
        "test_modules": list(SUITES[scope]),
        "tests_executed": result.testsRun,
        "errors": [test.id() for test, _ in result.errors],
        "failures": [test.id() for test, _ in result.failures],
        "skipped": [{"test": test.id(), "reason": reason}
                    for test, reason in result.skipped],
        "unexpected_successes": [test.id() for test in result.unexpectedSuccesses],
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
          "source_tree", "tests_executed", "errors", "failures", "skipped",
          "tracked_source_mutated", "passed", "authority")}, sort_keys=True))
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
