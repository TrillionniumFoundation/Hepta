"""Run the fixed quota application inventory and retain exact execution evidence."""
from __future__ import annotations

import argparse
from hashlib import sha256
import importlib
import io
import json
import os
from pathlib import Path
import platform
import shutil
import sys
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SOURCES = (
    "hepta/apps/__init__.py", "hepta/apps/quota.py", "hepta/apps/quota_v1.hiaasm",
    "hepta/apps/quota_v2.hiaasm", "tests/test_hia_quota_application.py",
    "tools/qualify_hia_quota_application.py",
)


def identities():
    return {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in SOURCES}


class ObservedResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.observations = []

    def startTest(self, test):
        self.started = time.perf_counter_ns()
        super().startTest(test)

    def record(self, test, outcome, detail=None):
        self.observations.append({"test": test.id(), "outcome": outcome,
                                  "wall_ns": time.perf_counter_ns() - self.started, "detail": detail})

    def addSuccess(self, test):
        super().addSuccess(test)
        self.record(test, "passed")

    def addError(self, test, err):
        super().addError(test, err)
        self.record(test, "error", self._exc_info_to_string(err, test))

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.record(test, "failed", self._exc_info_to_string(err, test))

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self.record(test, "skipped", reason)

    def addExpectedFailure(self, test, err):
        super().addExpectedFailure(test, err)
        self.record(test, "expected_failure", self._exc_info_to_string(err, test))

    def addUnexpectedSuccess(self, test):
        super().addUnexpectedSuccess(test)
        self.record(test, "unexpected_success")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--clang", default=os.environ.get("CLANG", "/usr/lib/llvm-20/bin/clang"))
    parser.add_argument("--vm-only", action="store_true", help="explicitly exclude native qualification")
    args = parser.parse_args(argv)
    if args.output.exists():
        parser.error("output must be new; preserve earlier attempts")
    os.environ["CLANG"] = args.clang
    if not args.vm_only and not shutil.which(args.clang):
        parser.error("actual Clang 20+ is required; use --vm-only for an explicitly narrower result")
    before = identities()
    from hepta.hia_program_llvm import build_program_native
    from hepta.apps.quota import HIAEngine
    module = importlib.import_module("tests.test_hia_quota_application")
    names = ["tests.test_hia_quota_application.QuotaApplicationTests"]
    if not args.vm_only:
        names.append("tests.test_hia_quota_application.QuotaNativeTests")
    suite = unittest.defaultTestLoader.loadTestsFromNames(names)
    inventory = suite.countTestCases()
    log, builds = io.StringIO(), []

    def captured_build(*call_args, **call_kwargs):
        receipt = build_program_native(*call_args, **call_kwargs)
        builds.append(receipt)
        return receipt

    start = time.perf_counter_ns()
    with patch("hepta.hia_program_llvm.build_program_native", side_effect=captured_build):
        result = unittest.TextTestRunner(stream=log, verbosity=2, resultclass=ObservedResult).run(suite)
    elapsed = time.perf_counter_ns() - start
    after = identities()
    with HIAEngine() as engine:
        program_ids = {version: engine.identity(version) for version in ("v1", "v2")}
        budgets = engine.budgets
    passed = (inventory > 0 and result.wasSuccessful() and not result.skipped
              and not result.expectedFailures and not result.unexpectedSuccesses
              and result.testsRun == inventory and len(result.observations) == inventory
              and before == after and (args.vm_only or len(builds) == 2))
    report = {"schema": "hepta.hia.quota-qualification.v1", "qualified": passed,
        "scope": "bounded single-account local POSIX journal and HIA balance transition",
        "source_sha256": before, "source_unchanged": before == after,
        "program_sha256": program_ids, "static_budgets": budgets,
        "python": sys.version, "platform": platform.platform(),
        "inventory": inventory, "tests_run": result.testsRun, "failures": len(result.failures),
        "errors": len(result.errors), "skips": len(result.skipped),
        "expected_failures": len(result.expectedFailures), "unexpected_successes": len(result.unexpectedSuccesses),
        "wall_ns": elapsed,
        "native_status": "not_requested" if args.vm_only else "executed" if builds else "failed_before_build",
        "native_build_receipts": builds, "observations": result.observations,
        "oracle_cases_per_version_per_backend": len(list(module.cases())),
        "claims": {"hia_business_transition": True, "process_restart_tested": passed,
            "native_execution_tested": passed and not args.vm_only,
            "hardware_power_loss_tested": False, "external_effect_exactly_once": False,
            "production_authorization": False, "hia_language_speedup": False},
        "full_test_log": log.getvalue()}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(json.dumps({key: report[key] for key in ("qualified", "inventory", "tests_run", "failures", "errors", "skips", "native_status", "wall_ns")}))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
