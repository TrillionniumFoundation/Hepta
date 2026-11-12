"""Exact complete context/retained Agent suites; no test filtering or retries."""
from __future__ import annotations

import argparse
from collections import Counter
from contextlib import ExitStack
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import time
import traceback
import unittest
from unittest.mock import patch


def flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        else:
            yield item


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--kind', required=True, choices=('component', 'original-agent'))
    parser.add_argument('--original-suite', required=True, type=Path)
    args = parser.parse_args()
    root = args.source.resolve(strict=True)
    sys.path.insert(0, str(root))
    report = {'schema': 'hia.context.exact-development-suite.v1',
              'status': 'STARTED', 'kind': args.kind, 'python': sys.version,
              'development_only': True, 'current_source_cold': False,
              'whole_stack_native': False, 'default_changed': False}
    start = time.monotonic_ns()
    reference_calls = []
    native_calls = Counter()
    try:
        expected_ids = None
        if args.kind == 'component':
            names = ['tests.test_hia_service_context_native', 'tests.test_hia_service_context_builder']
            expected_count = 46
        else:
            original = json.loads(args.original_suite.read_bytes())
            assert original['schema'] == 'hia.context.original-agent-suite.v1'
            assert original['base_commit'] == 'f8d9680a9b0ae609850c006480a7d1f68ea00979'
            for name, row in original['files'].items():
                raw = (root / name).read_bytes()
                assert len(raw) == row['bytes'] and sha256(raw).hexdigest() == row['sha256'], name
            names = original['modules']
            expected_ids = [test for module in names
                            for test in original['files'][module.replace('.', '/') + '.py']['expected_ids']]
            expected_count = original['expected_count']
            assert expected_count == len(expected_ids) == 48
            assert os.environ.get('HEPTA_HIA_SERVICE_CONTEXT_MANIFEST')
        report.update(modules=names, expected_count=expected_count)
        loader = unittest.TestLoader()
        suite = loader.loadTestsFromNames(names)
        loaded = [test.id() for test in flatten(suite)]
        report.update(loaded_ids=loaded, loader_errors=loader.errors)
        assert len(loaded) == len(set(loaded)) == expected_count and not loader.errors
        if expected_ids is not None:
            assert loaded == expected_ids, 'exact original ordered Agent discovery differs'

        class Result(unittest.TextTestResult):
            def __init__(self, *values, **options):
                super().__init__(*values, **options)
                self.executed = []

            def startTest(self, test):
                self.executed.append(test.id())
                super().startTest(test)

        with ExitStack() as stack:
            if args.kind == 'original-agent':
                from hepta.hia_agent_service import HIAAgentService
                from hepta.hia_service_context_native import NativeContextService

                def forbidden(*unused, **ignored):
                    reference_calls.append('retained context policy')
                    raise AssertionError('selected context invoked retained policy')

                for name in ('_hia_context_reference', '_context_reference',
                             '_budget_reference', '_remaining_ms_reference'):
                    stack.enter_context(patch.object(HIAAgentService, name, forbidden))
                actual_run = NativeContextService.run

                def counted(owner, mode, **values):
                    native_calls[mode] += 1
                    return actual_run(owner, mode, **values)

                stack.enter_context(patch.object(NativeContextService, 'run', counted))
                report['reference_poison_scope'] = 'test process; original child processes inherit explicit runtime selector, not this Python patch'
                report['existing_execution_budget_provider_replaced'] = False
            result = unittest.TextTestRunner(verbosity=2, resultclass=Result).run(suite)
        report.update(tests_run=result.testsRun, executed_ids=result.executed,
                      failures=[(test.id(), trace) for test, trace in result.failures],
                      errors=[(test.id(), trace) for test, trace in result.errors],
                      skips=[(test.id(), why) for test, why in result.skipped],
                      expected_failures=[(test.id(), trace) for test, trace in result.expectedFailures],
                      unexpected_successes=[test.id() for test in result.unexpectedSuccesses],
                      reference_calls=reference_calls, native_mode_calls=dict(native_calls))
        report['status'] = ('PASS' if result.wasSuccessful() and result.testsRun == expected_count
                            and result.executed == loaded and not result.skipped
                            and not result.expectedFailures and not result.unexpectedSuccesses
                            and not reference_calls else 'FAIL')
        if args.kind == 'original-agent' and (set(native_calls) != set(range(1, 7))
                                            or not all(native_calls.values())):
            report['status'] = 'FAIL'
            report['native_mode_custody_error'] = 'all six actual context routes must be observed'
    except BaseException:
        report.update(status='FAIL', traceback=traceback.format_exc())
    finally:
        report['elapsed_ns'] = time.monotonic_ns() - start
        with args.output.open('x') as stream:
            json.dump(report, stream, sort_keys=True, indent=2)
            stream.write('\n')
    print(json.dumps({'status': report['status'], 'tests_run': report.get('tests_run', 0)}), flush=True)
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
