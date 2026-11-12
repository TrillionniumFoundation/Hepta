"""Run frozen comparison source/Core-VM controls; never native or a compiler."""
from __future__ import annotations

import argparse
import ast
from contextlib import ExitStack
import ctypes
from hashlib import sha256
import importlib
import json
import os
from pathlib import Path
import subprocess
import stat
import sys
import time
import traceback
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def pin(path):
    information = path.lstat()
    if not stat.S_ISREG(information.st_mode):
        raise ValueError('source pin is not a regular file: ' + str(path))
    raw = path.read_bytes()
    return {'path': str(path), 'mode': stat.S_IMODE(information.st_mode),
            'size': len(raw), 'sha256': sha256(raw).hexdigest()}


def save(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write('\n')


def flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        else:
            yield item


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    output = args.evidence.absolute()
    output.mkdir(mode=0o700)
    policy = json.loads((ROOT / 'PREEXEC.json').read_bytes())
    started = time.monotonic()
    report = {'schema': 'hepta.hia.core-compare-source-control.v1', 'status': 'HOLD',
        'scope': 'ACTUAL_PUBLIC_CORE_VM_AND_SOURCE_ONLY_NO_NATIVE',
        'expected_ids': policy['expected_ids'], 'loaded_ids': [], 'executed_ids': [],
        'native_image_or_compiler_calls': [], 'original116_executed': False,
        'original18_executed': False, 'cold_executed': False, 'remote_triggered': False,
        'runtime': sys.version, 'runtime_binary': pin(Path(sys.executable).resolve())}
    own_paths = [ROOT / row['path'] for row in policy['frozen_files']]
    base_paths = [Path(row['path']) for row in policy['dependency_files']]
    all_paths = own_paths + base_paths
    before = [pin(path) for path in all_paths]
    save(output / 'source-before.json', before)
    try:
        expected = [(row['mode'], row['size'], row['sha256']) for row in policy['frozen_files'] + policy['dependency_files']]
        if [(row['mode'], row['size'], row['sha256']) for row in before] != expected:
            raise ValueError('frozen source/dependency bytes differ')
        for path in own_paths:
            if path.suffix == '.py': ast.parse(path.read_bytes(), filename=str(path))
        base = Path(policy['base_root'])
        sys.path.insert(0, str(base))
        for package in ('hepta', 'tools', 'tests'):
            module = importlib.import_module(package)
            module.__path__ = [str(ROOT / 'inputs' / package), *module.__path__]
        os.environ['HEPTA_COMPARE_BASE_ROOT'] = str(base)
        os.environ['HEPTA_COMPARE_CONTROL_EVIDENCE'] = str(output / 'fixtures')
        # Install native/compiler prohibitions before importing the candidate.
        def forbidden(*arguments, **keywords):
            report['native_image_or_compiler_calls'].append('native-or-subprocess-attempt')
            raise AssertionError('native image/compiler/product subprocess forbidden')
        executed = []
        class Result(unittest.TextTestResult):
            def startTest(self, test):
                executed.append(test.id())
                super().startTest(test)
        with ExitStack() as stack:
            for name in ('CDLL', 'PyDLL', 'CFUNCTYPE', 'PYFUNCTYPE'):
                stack.enter_context(patch.object(ctypes, name, forbidden))
            stack.enter_context(patch.object(subprocess, 'Popen', forbidden))
            from hepta import hia_json_preflight_native as common_image
            stack.enter_context(patch.object(common_image.NativeHiaJsonImage, '__init__', forbidden))
            tests = importlib.import_module('tests.test_hia_core_compare_source')
            loader = unittest.TestLoader()
            suite = loader.loadTestsFromTestCase(tests.ExactNumericComparisonSourceTests)
            report['loaded_ids'] = [test.id() for test in flatten(suite)]
            if report['loaded_ids'] != policy['expected_ids'] or loader.errors:
                raise ValueError('fixed source control IDs differ')
            with (output / 'unittest.log').open('x') as stream:
                result = unittest.TextTestRunner(stream=stream, verbosity=2, resultclass=Result).run(suite)
            report.update(executed_ids=executed, tests_run=result.testsRun, loader_errors=list(loader.errors))
            for name in ('errors', 'failures', 'skipped', 'expectedFailures', 'unexpectedSuccesses'):
                report[name] = [(item[0].id(), item[1]) if isinstance(item, tuple) else item.id()
                                for item in getattr(result, name)]
            if (result.wasSuccessful() and report['loaded_ids'] == executed == policy['expected_ids']
                    and result.testsRun == len(policy['expected_ids'])
                    and not any(report[name] for name in ('loader_errors', 'errors', 'failures', 'skipped',
                        'expectedFailures', 'unexpectedSuccesses', 'native_image_or_compiler_calls'))):
                report['status'] = 'SOURCE_CORE_VM_PASS'
    except BaseException:
        report['status'] = 'HOLD'
        report['error'] = traceback.format_exc()
    finally:
        try:
            after = [pin(path) for path in all_paths]
            save(output / 'source-after.json', after)
            report['source_preserved'] = before == after
            if before != after: report['status'] = 'HOLD'
        except BaseException:
            report['status'] = 'HOLD'
            report['preservation_error'] = traceback.format_exc()
        report['seconds'] = time.monotonic() - started
        save(output / 'report.json', report)
        save(output / 'actual-originals.json', [pin(path) for path in sorted(output.rglob('*')) if path.is_file()])
    print(json.dumps({'status': report['status'], 'expected': len(policy['expected_ids']),
        'loaded': len(report['loaded_ids']), 'executed': len(report['executed_ids']), 'seconds': report['seconds']}))
    return 0 if report['status'] == 'SOURCE_CORE_VM_PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
