"""Run the complete fixed Source selection and preserve exact unittest outcomes."""
import argparse
from collections import Counter
import json
from pathlib import Path
import sys
import time
import unittest

def ids(suite):
    result = []
    for test in suite:
        if isinstance(test, unittest.TestSuite):
            result.extend(ids(test))
        else:
            result.append(test.id())
    return result

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--registration", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    plan = json.loads(args.registration.read_text(encoding="utf-8"))
    sys.path.insert(0, str(args.source.resolve()))
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromNames(plan["selectors"])
    selected_ids = ids(suite)
    selected_errors = list(loader.errors)
    main_loader = unittest.TestLoader()
    main_suite = main_loader.loadTestsFromNames(plan["main_selectors"])
    main_ids = ids(main_suite)
    a733_loader = unittest.TestLoader()
    mapped = [plan["selector_renames"].get(name, name) for name in plan["a733_selectors"]]
    a733_suite = a733_loader.loadTestsFromNames(mapped)
    a733_ids = ids(a733_suite)
    counts = Counter(selected_ids)
    duplicates = {name: count for name, count in counts.items() if count != 1}
    missing_main = list((Counter(main_ids) - counts).elements())
    missing_a733 = list((Counter(a733_ids) - counts).elements())
    expected = suite.countTestCases()
    started = time.monotonic()
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    complete = result.testsRun == expected and expected > 0
    clean = not (result.errors or result.failures or result.skipped or
                 result.expectedFailures or result.unexpectedSuccesses)
    projections = not (duplicates or missing_main or missing_a733 or selected_errors
                       or main_loader.errors or a733_loader.errors)
    passed = complete and clean and result.wasSuccessful() and projections
    report = {
        "schema": "hepta.fixed-combined-source-tests.v1",
        "status": "PASS" if passed else "FAIL",
        "selectors": plan["selectors"], "ordered_ids": selected_ids,
        "expected": expected, "tests_run": result.testsRun, "complete": complete,
        "wall_seconds": time.monotonic() - started,
        "errors": [{"id": test.id(), "traceback": trace} for test, trace in result.errors],
        "failures": [{"id": test.id(), "traceback": trace} for test, trace in result.failures],
        "skipped": [{"id": test.id(), "reason": reason} for test, reason in result.skipped],
        "expected_failures": [{"id": test.id(), "traceback": trace} for test, trace in result.expectedFailures],
        "unexpected_successes": [test.id() for test in result.unexpectedSuccesses],
        "duplicate_ids": duplicates, "missing_main_ids": missing_main,
        "missing_a733_ids": missing_a733,
        "loader_errors": {"selected": selected_errors, "main": list(main_loader.errors),
                          "a733": list(a733_loader.errors)},
        "main_projection_ids": main_ids, "mapped_a733_projection_ids": a733_ids,
        "native_qualification": False, "whole_native": False,
    }
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(json.dumps({"status": report["status"], "expected": expected,
                      "tests_run": result.testsRun, "errors": len(result.errors),
                      "failures": len(result.failures), "skipped": len(result.skipped),
                      "wall_seconds": report["wall_seconds"]}, sort_keys=True))
    return 0 if passed else 1

if __name__ == "__main__":
    raise SystemExit(main())
