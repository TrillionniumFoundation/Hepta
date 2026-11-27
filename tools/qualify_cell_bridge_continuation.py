"""Retain complete component-native unittest terminals on one fixed source."""
from __future__ import annotations
import argparse
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCES = (
    "examples/hia_cell_bridge/continuation.hepta",
    "tools/generate_cell_bridge_continuation.py",
    "tools/cell_bridge_native.py",
    "tools/qualify_cell_bridge_continuation.py",
    "tests/test_hia_cell_bridge.py",
)


def identities():
    return {name: {"bytes": len(data), "sha256": sha256(data).hexdigest()}
            for name in SOURCES for data in [(ROOT / name).read_bytes()]}


def test_ids(suite):
    for test in suite:
        if isinstance(test, unittest.TestSuite):
            yield from test_ids(test)
        else:
            yield test.id()


class Result(unittest.TextTestResult):
    def __init__(self, *args):
        super().__init__(*args)
        self.terminals = []
        self.starts = {}
        self.subtests = 0

    def startTest(self, test):
        self.starts[test.id()] = time.perf_counter_ns()
        super().startTest(test)

    def stopTest(self, test):
        failed = any(item is test for item, _ in self.failures + self.errors)
        self.terminals.append({"id": test.id(), "wall_ns": time.perf_counter_ns() - self.starts[test.id()],
                               "method_completed": True, "status": "failed" if failed else "completed"})
        super().stopTest(test)

    def addSubTest(self, test, subtest, err):
        self.subtests += 1
        super().addSubTest(test, subtest, err)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    before = identities()
    os.environ["HIA_CELL_BRIDGE_TEST_OUTPUT"] = str(args.output / "build")
    suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"), pattern="test_hia_cell_bridge.py")
    loaded = list(test_ids(suite))
    transcript = io.StringIO()
    start = time.perf_counter_ns()
    result = unittest.TextTestRunner(stream=transcript, verbosity=2, resultclass=Result).run(suite)
    elapsed = time.perf_counter_ns() - start
    after = identities()
    complete = result.testsRun == len(loaded) and len(result.terminals) == len(loaded)
    passed = result.wasSuccessful() and complete and not result.skipped and before == after
    report = {
        "schema": "hepta.cell-hia-continuation-native-controls.v1",
        "status": "PASS" if passed else "HOLD", "loaded_test_ids": loaded,
        "tests_run": result.testsRun, "subtests_observed": result.subtests,
        "terminals": result.terminals, "source_stable": before == after,
        "source_before": before, "source_after": after,
        "wall_ns": elapsed, "failures": len(result.failures), "errors": len(result.errors),
        "skips": len(result.skipped), "complete_original_population": complete,
        "scope": "component native continuation, not actual Cell integration or model learning",
        "claims": {"component_native_controls_passed": passed, "cell_execution_qualified": False,
                   "learning_benefit_qualified": False, "whole_stack_qualified": False,
                   "production_activated": False},
    }
    log = transcript.getvalue().encode()
    (args.output / "unittest.log").write_bytes(log)
    report["unittest_log_sha256"] = sha256(log).hexdigest()
    (args.output / "RESULT.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(transcript.getvalue(), end="")
    print(json.dumps({"status": report["status"], "tests_run": result.testsRun,
                      "subtests_observed": result.subtests, "result": str(args.output / "RESULT.json")}))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
