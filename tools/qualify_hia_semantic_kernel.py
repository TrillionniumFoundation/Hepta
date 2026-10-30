#!/usr/bin/env python3
"""Qualify production semantic consumers; absent native execution stays pending."""
from __future__ import annotations
import argparse
from hashlib import sha256
import io
import json
from pathlib import Path
import platform
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


class RecordedResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.passed_ids = []

    def addSuccess(self, test):
        super().addSuccess(test)
        self.passed_ids.append(test.id())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--require-native", action="store_true")
    args = parser.parse_args()
    paths = list((ROOT / "hepta").glob("*.py")) + [Path(__file__),
        ROOT / "tests/test_hia_semantic_kernel.py", ROOT / "tests/test_hia_program.py",
        ROOT / "tools/qualify_hia_program_resources.py"]
    def inventory():
        return {str(p.relative_to(ROOT)): sha256(p.read_bytes()).hexdigest() for p in sorted(paths)}
    before = inventory()
    log = io.StringIO()
    started = time.monotonic_ns()
    suite = unittest.defaultTestLoader.loadTestsFromName("tests.test_hia_semantic_kernel")
    native_name = "tests.test_hia_semantic_kernel.SemanticKernelNativeTests"
    native_planned = unittest.defaultTestLoader.loadTestsFromName(native_name).countTestCases()
    planned = suite.countTestCases()
    result = unittest.TextTestRunner(stream=log, verbosity=2, resultclass=RecordedResult).run(suite)
    stable = inventory() == before
    native_passed = [name for name in result.passed_ids if name.startswith(native_name + ".")]
    native = (result.wasSuccessful() and not result.skipped and stable and planned == result.testsRun
              and native_planned > 0 and len(native_passed) == native_planned)
    ok = result.wasSuccessful() and stable and (native or not args.require_native)
    from hepta.hia_semantic_kernel import contract
    report = {"schema": "hepta.hia.semantic-kernel-qualification.v1",
        "status": "native_and_VM_qualified" if native else "VM_pass_native_pending" if ok else "failed",
        "ok": ok, "require_native": args.require_native,
        "source_sha256": before, "sources_stable_during_tests": stable,
        "environment": {"python": sys.version, "platform": platform.platform()},
        "tests_planned": planned, "tests_run": result.testsRun,
        "tests_passed": len(result.passed_ids), "passed_ids": result.passed_ids,
        "native_tests_planned": native_planned, "native_passed_ids": native_passed,
        "skipped": [{"test": t.id(), "reason": reason} for t, reason in result.skipped],
        "errors": [{"test": t.id(), "traceback": trace} for t, trace in result.errors],
        "failures": [{"test": t.id(), "traceback": trace} for t, trace in result.failures],
        "wall_ns": time.monotonic_ns() - started, "semantic_contract": contract(),
        "native_observations": {"cases": 30 if native else 0,
            "fields": ["C_ABI_result", "allocator_attempts", "live_payload_bytes", "peak_payload_bytes"],
            "scope": "24 pipeline cases plus 6 owner-loop cases; independently executed child processes"},
        "claims": {"native_execution_qualified": native, "finite_regression_only": True,
            "backend_refinement_proved": False, "whole_language_soundness_proved": False,
            "native_VM_budget_equivalence": False}, "test_log": log.getvalue()}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({k: report[k] for k in ("status", "ok", "tests_run", "tests_passed", "skipped")}))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
