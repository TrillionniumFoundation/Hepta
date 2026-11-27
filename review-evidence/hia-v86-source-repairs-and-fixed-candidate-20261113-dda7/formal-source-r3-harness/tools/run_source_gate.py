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
    parser.add_argument("--original-ids", type=Path, required=True)
    args = parser.parse_args()
    plan = json.loads(args.registration.read_text(encoding="utf-8"))
    helper_dir = Path(__file__).resolve().parent
    sys.path[:] = [entry for entry in sys.path if entry and Path(entry).resolve() != helper_dir]
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
    frozen = json.loads(args.original_ids.read_text(encoding="utf-8"))
    if (frozen["main"]["commit"] != "016f00bbbafddec8112ef6762eb799e83c8e5d00"
            or frozen["a733"]["commit"] != "a733926a2786a3d4a37304bd2d18ebb2eac57ac9"):
        raise ValueError("original Source result heads differ")
    exact_main_ids = frozen["main"]["ids"]
    exact_a733_ids = frozen["a733"]["ids"]
    if len(exact_main_ids) != 530 or len(set(exact_main_ids)) != 530 or len(exact_a733_ids) != 973 or len(set(exact_a733_ids)) != 973:
        raise ValueError("original executed Source method inventory differs")
    def mapped_id(name):
        matches = [prefix for prefix in plan["selector_renames"] if name == prefix or name.startswith(prefix+".")]
        if not matches:
            return name
        prefix = max(matches,key=len)
        return plan["selector_renames"][prefix]+name[len(prefix):]
    projected_a733_original = [mapped_id(name) for name in exact_a733_ids]
    counts = Counter(selected_ids)
    duplicates = {name: count for name, count in counts.items() if count != 1}
    missing_main = list((Counter(main_ids) - counts).elements())
    missing_a733 = list((Counter(a733_ids) - counts).elements())
    missing_frozen_main = list((Counter(exact_main_ids) - counts).elements())
    missing_frozen_a733 = list((Counter(projected_a733_original) - counts).elements())
    expected = suite.countTestCases()
    events_path = args.output.with_suffix(".events.jsonl")
    events = events_path.open("x", encoding="utf-8")
    class ObservedResult(unittest.TextTestResult):
        def __init__(self, *arguments, **options):
            super().__init__(*arguments, **options)
            self.started_ids = []
            self.stopped_ids = []
        def startTest(self, test):
            name = test.id()
            self.started_ids.append(name)
            events.write(json.dumps({"event":"start","id":name},sort_keys=True)+"\n")
            events.flush()
            super().startTest(test)
        def stopTest(self, test):
            name = test.id()
            self.stopped_ids.append(name)
            events.write(json.dumps({"event":"stop","id":name},sort_keys=True)+"\n")
            events.flush()
            super().stopTest(test)
    started = time.monotonic()
    try:
        result = unittest.TextTestRunner(verbosity=2, resultclass=ObservedResult).run(suite)
    finally:
        events.close()
    complete = (result.testsRun == expected and expected > 0
                and result.started_ids == selected_ids and result.stopped_ids == selected_ids)
    clean = not (result.errors or result.failures or result.skipped or
                 result.expectedFailures or result.unexpectedSuccesses)
    projections = not (duplicates or missing_main or missing_a733 or selected_errors
                       or main_loader.errors or a733_loader.errors
                       or missing_frozen_main or missing_frozen_a733)
    passed = complete and clean and result.wasSuccessful() and projections
    report = {
        "schema": "hepta.fixed-combined-source-tests.v1",
        "status": "PASS" if passed else "FAIL",
        "selectors": plan["selectors"], "ordered_ids": selected_ids,
        "expected": expected, "tests_run": result.testsRun, "complete": complete,
        "actual_started_ids": result.started_ids, "actual_stopped_ids": result.stopped_ids,
        "execution_events": str(events_path),
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
        "frozen_original_result_pins": {head:{key:value for key,value in row.items() if key != "ids"} for head,row in frozen.items()},
        "frozen_original_main_ids": exact_main_ids, "frozen_original_a733_projected_ids": projected_a733_original,
        "missing_frozen_main_ids": missing_frozen_main, "missing_frozen_a733_ids": missing_frozen_a733,
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
