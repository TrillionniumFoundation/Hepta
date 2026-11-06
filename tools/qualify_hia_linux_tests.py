#!/usr/bin/env python3
"""Run the exact Linux campaign regression inventory with no skipped native tests.

This receipt concerns tests and real native leaf objects. It is not a Linux
boot, a whole-kernel rewrite, a workload benchmark or an NDU comparison.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from tools.qualify_hia_three_lane import (
    _IdentityRecordingResult, _outcome_admissible, _planned_test_ids,
    _verified_receipt_destination, _write_immutable_receipt,
)

MODULES = (
    "tests.test_hia_linux_baseline", "tests.test_hia_linux_translation",
    "tests.test_hia_linux_component", "tests.test_hia_linux_system",
    "tests.test_hia_linux_kernel_contract",
)


def git(*args):
    environment = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    return subprocess.check_output(["git", "--no-replace-objects", "-C", str(ROOT), *args],
                                   text=True, env=environment).strip()


def run(output):
    output = _verified_receipt_destination(Path(output))
    if git("status", "--porcelain", "--untracked-files=all"):
        raise ValueError("regression qualification requires a clean committed checkout")
    before = {"commit": git("rev-parse", "HEAD"), "tree": git("rev-parse", "HEAD^{tree}")}
    suite = unittest.defaultTestLoader.loadTestsFromNames(MODULES)
    planned = _planned_test_ids(suite)
    result = unittest.TextTestRunner(stream=sys.stderr, verbosity=2,
                                     resultclass=_IdentityRecordingResult).run(suite)
    after = {"commit": git("rev-parse", "HEAD"), "tree": git("rev-parse", "HEAD^{tree}")}
    dirty = git("status", "--porcelain", "--untracked-files=all")
    passed = _outcome_admissible(result, planned, immutable=before == after and not dirty)
    record = {
        "schema": "hepta.hia.linux-regression-tests.v1",
        "status": "PASS" if passed else "FAIL", "source_before": before, "source_after": after,
        "source_status_after": dirty, "python_version": platform.python_version(),
        "modules": list(MODULES), "tests_planned": len(planned), "tests_executed": result.testsRun,
        "planned_ids": list(planned), "started_ids": result.started_ids, "finished_ids": result.finished_ids,
        "planned_ids_sha256": hashlib.sha256(json.dumps(planned, separators=(",", ":")).encode()).hexdigest(),
        "errors": [test.id() for test, _ in result.errors],
        "failures": [test.id() for test, _ in result.failures],
        "skipped": [{"test": test.id(), "reason": reason} for test, reason in result.skipped],
        "expected_failures": [test.id() for test, _ in result.expectedFailures],
        "unexpected_successes": [test.id() for test in result.unexpectedSuccesses],
        "scope": "source_contract_and_real_native_leaf_regressions_not_kernel_guest_campaign",
        "claims": {"kernel_booted": False, "whole_kernel_rewritten": False,
                   "global_comparison_completed": False, "ndu_gain_established": False},
    }
    _write_immutable_receipt(output, record)
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = run(args.output)
    print(json.dumps({k: report[k] for k in ("status", "tests_planned", "tests_executed", "skipped")}))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
