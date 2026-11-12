"""Frozen emission development controls with complete source readback."""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import time
import traceback
import unittest


def files(root):
    return {p.relative_to(root).as_posix(): {'bytes': p.stat().st_size,
        'sha256': sha256(p.read_bytes()).hexdigest(), 'mode': oct(p.stat().st_mode & 0o777)}
        for p in sorted(root.rglob('*')) if p.is_file()
        and '.git' not in p.relative_to(root).parts and '__pycache__' not in p.parts and p.suffix != '.pyc'}


def flatten(suite):
    for value in suite:
        if isinstance(value, unittest.TestSuite):
            yield from flatten(value)
        else:
            yield value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--original-component', type=Path, required=True)
    args = parser.parse_args()
    root = args.source.resolve(strict=True)
    out = args.output.absolute(); out.mkdir(mode=0o700, exist_ok=False)
    sys.path.insert(0, str(root))
    report = {'schema': 'hia.emission-development.v1', 'stage': 'component',
        'python': sys.version, 'scope': 'DEVELOPMENT_ONLY', 'whole_qualification': False,
        'current_source_cold': False, 'default_forwarder_bytes_changed': True, 'native_default_activated': False}
    before = files(root)
    (out / 'source-before.json').write_text(json.dumps(before, sort_keys=True, indent=2) + '\n')
    start = time.monotonic_ns()
    try:
        original_raw = args.original_component.read_bytes()
        original = json.loads(original_raw)
        assert original['tests_run'] == 45 and len(original['loaded']) == 45
        report['original_component_sha256'] = sha256(original_raw).hexdigest()
        names = ['tests.test_hia_service_emission_native', 'tests.test_hia_service_emission_builder',
                 'tests.test_hia_service_emission_qualifier']
        count = 45
        loader = unittest.TestLoader()
        suite = loader.loadTestsFromNames(names)
        loaded = [test.id() for test in flatten(suite)]
        report.update(modules=names, expected_count=count, loaded_ids=loaded, loader_errors=loader.errors)
        assert not loader.errors and len(loaded) == len(set(loaded)) == count
        assert loaded == original['loaded']
        report['all_original_45_ids_and_relative_order_retained'] = True
        class Result(unittest.TextTestResult):
            def __init__(self, *values, **options):
                super().__init__(*values, **options)
                self.executed = []
            def startTest(self, test):
                self.executed.append(test.id())
                super().startTest(test)
        result = unittest.TextTestRunner(verbosity=2, resultclass=Result).run(suite)
        report.update(tests_run=result.testsRun, executed_ids=result.executed,
            failures=[(test.id(), error) for test, error in result.failures],
            errors=[(test.id(), error) for test, error in result.errors],
            skips=[(test.id(), reason) for test, reason in result.skipped],
            expected_failures=[(test.id(), error) for test, error in result.expectedFailures],
            unexpected_successes=[test.id() for test in result.unexpectedSuccesses])
        report['status'] = 'PASS' if (result.wasSuccessful() and result.testsRun == count
            and result.executed == loaded and not result.skipped and not result.expectedFailures
            and not result.unexpectedSuccesses) else 'FAIL'
    except BaseException:
        report.update(status='FAIL', traceback=traceback.format_exc())
    finally:
        report['elapsed_ns'] = time.monotonic_ns() - start
        after = files(root)
        (out / 'source-after.json').write_text(json.dumps(after, sort_keys=True, indent=2) + '\n')
        report['source_unchanged'] = after == before
        report['source_files'] = len(before)
        if after != before:
            report['status'] = 'FAIL'
            report['source_drift'] = sorted(name for name in set(before) | set(after) if before.get(name) != after.get(name))
        with (out / 'REPORT.json').open('x') as stream:
            json.dump(report, stream, sort_keys=True, indent=2); stream.write('\n')
    print(json.dumps({'status': report['status'], 'tests_run': report.get('tests_run', 0),
                      'source_unchanged': report['source_unchanged']}), flush=True)
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
