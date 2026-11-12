"""Run every original Byte component without filtering or weakening results."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys
import time
import traceback
import unittest

class Result(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.executed = []
    def startTest(self, test):
        self.executed.append(test.id())
        super().startTest(test)

def leaves(suite):
    for test in suite:
        if isinstance(test, unittest.TestSuite):
            yield from leaves(test)
        else:
            yield test

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(args.source.resolve()))
    report = {'status': 'HOLD', 'current_cold': False, 'whole_native': False}
    start = time.monotonic()
    try:
        loader = unittest.TestLoader()
        suite = loader.loadTestsFromName('tests.test_hia_native_byte_abi_native')
        ids = [test.id() for test in leaves(suite)]
        report.update(loaded_ids=ids, loader_errors=loader.errors)
        if loader.errors or len(ids) != 25 or len(set(ids)) != 25:
            raise AssertionError('complete original Byte25 inventory differs')
        result = unittest.TextTestRunner(verbosity=2, resultclass=Result).run(suite)
        report.update(tests_run=result.testsRun, executed_ids=result.executed)
        for name in ('failures', 'errors', 'skipped', 'expectedFailures'):
            report[name] = [[test.id(), detail] for test, detail in getattr(result, name)]
        report['unexpectedSuccesses'] = [test.id() for test in result.unexpectedSuccesses]
        if (result.testsRun == 25 and result.executed == ids
                and not any(report[k] for k in ('failures', 'errors', 'skipped',
                                                'expectedFailures', 'unexpectedSuccesses'))):
            report['status'] = 'PASS'
    except BaseException:
        report['exception'] = traceback.format_exc()
    finally:
        report['seconds'] = time.monotonic() - start
        args.output.write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
        print(json.dumps({'status': report['status'], 'tests_run': report.get('tests_run'),
                          'seconds': report['seconds']}), flush=True)
    return 0 if report['status'] == 'PASS' else 1

if __name__ == '__main__':
    raise SystemExit(main())
