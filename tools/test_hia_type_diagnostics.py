#!/usr/bin/env python3
"""Exact-identity, no-skip tests for diagnostics and existing non-native Core.

No models, native toolchains, registered campaigns, or hidden oracles run here.
Native/backend qualification remains in the existing hosted workflows.
"""
from pathlib import Path
import json
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.dont_write_bytecode = True

from tools.qualify_hia_three_lane import (
    _IdentityRecordingResult, _outcome_admissible, _planned_test_ids,
)

SUITES = (
    "tests.test_hia_type_diagnostics",
    "tests.test_hia_opcode_catalog",
    "tests.test_hia_program",
    "tests.test_hia_agent_assembly",
    "tests.test_hia_incremental",
    "tests.test_hia_incremental_v8",
    "tests.test_hia_program_tools",
    "tests.test_hia_schema_unification",
    "tests.test_hia_returned_loans.ReturnedLoans",
    "tests.test_hia_returned_loans.ReturnedLoanSemantics",
    "tests.test_hia_three_lane_gate",
)


def main():
    suite = unittest.defaultTestLoader.loadTestsFromNames(SUITES)
    planned = _planned_test_ids(suite)
    result = unittest.TextTestRunner(verbosity=2, resultclass=_IdentityRecordingResult).run(suite)
    # This local test runner qualifies test outcomes only. Exact commit/tree and
    # clean before/after state are checked separately by the hosted workflow.
    passed = _outcome_admissible(result, planned, immutable=True)
    print(json.dumps({"passed": passed, "suites": SUITES, "planned": planned,
        "started": result.started_ids, "finished": result.finished_ids,
        "tests_run": result.testsRun, "failures": len(result.failures), "errors": len(result.errors),
        "skips": len(result.skipped), "expected_failures": len(result.expectedFailures),
        "unexpected_successes": len(result.unexpectedSuccesses)}, sort_keys=True))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
