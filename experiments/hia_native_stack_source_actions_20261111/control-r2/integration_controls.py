"""Execute all original resource, release and workflow source controls; no native run."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys
import time
import traceback
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from author_common import (BASE_COMMIT, atomic_report, digest, git, load_policy,
                           read_regular, require)

def flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        else:
            yield item

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    source = args.source.resolve(strict=True)
    output = args.output.resolve()
    require(output != source and not output.is_relative_to(source), "control evidence is inside source")
    output.mkdir(mode=0o700)
    policy = load_policy(Path(__file__).resolve().parent)
    report = {
        "schema": "hia.native-stack.integration-source-controls.v1",
        "scope": "ORIGINAL_SOURCE_WORKFLOW_RESOURCE_AND_RELEASE_CONTROLS_ONLY", "status": "HOLD",
        "product_execution": False, "cold_qualification": False,
        "compiler_or_native_image_executed": False,
        "loaded_ids": [], "executed_ids": [], "loader_errors": [],
        "tests_run": 0, "source_stable": False,
    }
    started = time.monotonic()
    before = None
    def source_pins():
        from tools.hia_selfhost_contract import file_digests, CONTRACT_PATH
        return {**file_digests(source),
                CONTRACT_PATH: digest(read_regular(source / CONTRACT_PATH)[0])}
    try:
        sys.path.insert(0, str(source))
        require(git(source, "rev-parse", "HEAD").decode().strip() == BASE_COMMIT,
                "source control checkout is not the frozen base")
        before = source_pins()
        report["source_before"] = before
        loader = unittest.TestLoader()
        suite = loader.loadTestsFromNames(policy["integration_control_classes"])
        loaded = [test.id() for test in flatten(suite)]
        report["loaded_ids"] = loaded
        report["loader_errors"] = list(loader.errors)
        require(not loader.errors and loaded == policy["integration_control_test_ids"]
                and len(set(loaded)) == len(loaded) and loaded,
                "complete integration control IDs changed")
        executed = report["executed_ids"]
        class Result(unittest.TextTestResult):
            def startTest(self, test):
                executed.append(test.id())
                super().startTest(test)
        with (output / "unittest.log").open("x", encoding="utf-8") as stream:
            result = unittest.TextTestRunner(stream=stream, verbosity=2, resultclass=Result).run(suite)
        report["tests_run"] = result.testsRun
        for name in ("errors", "failures", "skipped", "expectedFailures"):
            report[name] = [[test.id(), detail] for test, detail in getattr(result, name)]
        report["unexpectedSuccesses"] = [test.id() for test in result.unexpectedSuccesses]
        require(loaded == executed and result.testsRun == len(loaded)
                and all(report[name] == [] for name in
                    ("errors", "failures", "skipped", "expectedFailures", "unexpectedSuccesses")),
                "a complete integration source control failed or was not executed")
        report["status"] = "CONTROL_ONLY_PASS"
    except BaseException:
        report["status"] = "HOLD"
        report["exception"] = traceback.format_exc()
    finally:
        try:
            after = source_pins()
            report["source_after"] = after
            report["source_stable"] = before is not None and before == after
            require(report["source_stable"], "source changed during integration controls")
            require(load_policy(Path(__file__).resolve().parent) == policy, "control policy changed")
        except BaseException:
            report["status"] = "HOLD"
            report["final_identity_error"] = traceback.format_exc()
        report["seconds"] = time.monotonic() - started
        atomic_report(output / "report.json", report)
        print(json.dumps({k: report.get(k) for k in ("schema", "status", "scope", "tests_run",
            "seconds", "source_stable", "exception")}, sort_keys=True), flush=True)
    return 0 if report["status"] == "CONTROL_ONLY_PASS" else 1

if __name__ == "__main__":
    raise SystemExit(main())
