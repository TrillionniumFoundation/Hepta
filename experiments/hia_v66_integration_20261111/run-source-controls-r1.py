"""Run the actual integrated source/workflow controls; no cold/native pass claim."""
from pathlib import Path
import json
import subprocess
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tools.hia_selfhost_contract import file_digests

NAMES = (
    'tests.test_hia_integrated_workflow',
    'tests.test_hia_json_wire_native.WireSourceTests',
    'tests.test_hia_worker_report_native.WorkerReportSourceTests',
    'tests.test_hia_machine_plan_native.MachinePlanSourceTests',
    'tests.test_hia_selfhost_linked_observer.LinkedObserverSourceTests',
)


def flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        else:
            yield item


def main():
    before = file_digests(ROOT)
    suite = unittest.defaultTestLoader.loadTestsFromNames(NAMES)
    loaded = [test.id() for test in flatten(suite)]
    executed = []

    class Result(unittest.TextTestResult):
        def startTest(self, test):
            executed.append(test.id())
            super().startTest(test)

    start = time.monotonic_ns()
    result = unittest.TextTestRunner(verbosity=2, resultclass=Result).run(suite)
    elapsed = time.monotonic_ns() - start
    after = file_digests(ROOT)
    anomalies = {name: [str(item) for item in getattr(result, name)] for name in (
        'errors', 'failures', 'skipped', 'expectedFailures', 'unexpectedSuccesses')}
    passed = (bool(loaded) and loaded == executed and len(loaded) == result.testsRun
              and result.wasSuccessful() and not any(anomalies.values())
              and before == after)
    report = {
        'schema': 'hepta.hia.v66-source-controls.v1',
        'scope': 'SOURCE_AND_WORKFLOW_CONTROLS_NOT_COLD_OR_FULL_QUALIFICATION',
        'status': 'PASS' if passed else 'FAIL_OR_INCOMPLETE',
        'source_head': subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True).strip(),
        'source_worktree_diff': subprocess.check_output(['git', '-C', str(ROOT), 'diff', '--name-only'], text=True).splitlines(),
        'source_pins_before': before,
        'source_pins_after': after,
        'source_pins_preserved': before == after,
        'loaded_test_ids': loaded,
        'executed_test_ids': executed,
        'tests_run': result.testsRun,
        'anomalies': anomalies,
        'elapsed_ns': elapsed,
        'python_version': sys.version,
        'whole_native_delivery_qualified': False,
    }
    Path(__file__).with_name('source-controls-r1.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    raise SystemExit(0 if passed else 1)


if __name__ == '__main__':
    main()
