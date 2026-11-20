"""Owned complete test-list observer for the new lease gates."""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from tests.hia_slot_operations_qualification_support import read_json, write_json, pin, product_snapshot


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--selection', choices=('source', 'component'), required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--source-freeze', type=Path, required=True)
    parser.add_argument('--source-freeze-sha256', required=True)
    args = parser.parse_args()
    if pin(args.source_freeze)['sha256'] != args.source_freeze_sha256:
        raise ValueError('outer lease source freeze differs')
    before = read_json(args.source_freeze)['files']
    if product_snapshot(ROOT, before) != before:
        raise ValueError('source changed before complete test loading')
    plan = read_json(ROOT / 'tests/fixtures/hia_service_lease_original_r3/gate-plan.json')
    selected = plan['gates'][args.selection]
    from tools.run_hia_unittest_gate import load_declared_suite
    suite, planned = load_declared_suite(selected['modules'])
    planned = list(planned)
    if planned != selected['ordered_ids']:
        raise ValueError('actual TestLoader identities differ from the complete declared gate')
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    started, stopped, outcomes = [], [], {}
    class Result(unittest.TextTestResult):
        def startTest(self, test):
            started.append(test.id()); outcomes[test.id()] = 'ok'
            super().startTest(test)
        def stopTest(self, test):
            stopped.append(test.id()); super().stopTest(test)
        def addFailure(self, test, err):
            outcomes[test.id()] = 'failure'; super().addFailure(test, err)
        def addError(self, test, err):
            outcomes[test.id()] = 'error'; super().addError(test, err)
        def addSkip(self, test, reason):
            outcomes[test.id()] = 'skip'; super().addSkip(test, reason)
        def addSubTest(self, test, subtest, err):
            if err is not None:
                outcomes[test.id()] = 'subtest-failure'
            super().addSubTest(test, subtest, err)
    start = time.monotonic()
    with (args.output / 'tests.log').open('x') as stream:
        result = unittest.TextTestRunner(stream=stream, verbosity=2, resultclass=Result).run(suite)
    after = product_snapshot(ROOT, before)
    passed = (result.wasSuccessful() and result.testsRun == len(planned)
              and planned == started == stopped and before == after
              and not any(getattr(result, key) for key in (
                  'failures', 'errors', 'skipped', 'expectedFailures', 'unexpectedSuccesses')))
    report = {'schema': 'hepta.service-lease.complete-tests.v1', 'selection': args.selection,
        'status': 'PASS' if passed else 'HOLD', 'planned': planned, 'started': started, 'stopped': stopped,
        'outcomes': outcomes, 'actual_tests': result.testsRun,
        'failures': [(test.id(), text) for test, text in result.failures],
        'errors': [(test.id(), text) for test, text in result.errors],
        'skips': [(test.id(), text) for test, text in result.skipped],
        'expected_failures': [(test.id(), text) for test, text in result.expectedFailures],
        'unexpected_successes': [test.id() for test in result.unexpectedSuccesses],
        'elapsed_seconds': time.monotonic() - start, 'runtime': sys.version,
        'pid': os.getpid(), 'ppid': os.getppid(), 'pgid': os.getpgid(0),
        'source_before': before, 'source_after': after,
        'test_log': pin(args.output / 'tests.log'), 'whole_native_qualified': False}
    write_json(args.output / 'report.json', report)
    print(json.dumps({key: report[key] for key in ('status', 'selection', 'actual_tests', 'elapsed_seconds')}))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
