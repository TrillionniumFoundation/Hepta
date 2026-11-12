"""Isolated source/VM child with native, compiler and descendant-exec poisons."""
from __future__ import annotations
from contextlib import ExitStack
import ctypes
import importlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import time
import traceback
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import HERE, require, request, runtime, save


def flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        else:
            yield item


def main():
    policy = request()
    runtime(policy['runtime'])
    source = Path(policy['source_root'])
    sys.path.insert(0, str(source))
    operation = sys.argv[1]
    output = Path(policy['evidence_root']) / 'evidence'
    attempted = []
    def forbidden(*args, **kwargs):
        attempted.append('native/compiler/subprocess-attempt')
        raise AssertionError('source-only operation attempted native/compiler/subprocess execution')
    result_code = 1
    report = {'schema': 'hepta.hia.core-compare-integration-source-child.v1', 'status': 'HOLD',
        'native_or_compiler_or_process_attempts': attempted, 'native_executed': False,
        'complete116_executed': False, 'complete18_executed': False, 'cold_executed': False,
        'operation': operation, 'expected_ids': policy['expected_ids'] if operation == 'tests' else [],
        'loaded_ids': [], 'executed_ids': [], 'runtime': sys.version,
        'runtime_identity': runtime(policy['runtime'])}
    at = time.monotonic()
    try:
        with ExitStack() as stack:
            stack.enter_context(patch.object(subprocess, 'Popen', forbidden))
            from hepta import hia_json_preflight_native as images
            stack.enter_context(patch.object(images.NativeHiaJsonImage, '__init__', forbidden))
            from tools import qualify_hia_selfhost as compiler
            stack.enter_context(patch.object(compiler, 'compile_stage', forbidden))
            stack.enter_context(patch.object(compiler, 'build_seed', forbidden))
            if operation == 'module':
                module = sys.argv[2]
                require(module in ['tools.generate_hia_' + name for name in policy['generator_names']], 'module allowlist')
                sys.argv = [module]
                try:
                    runpy.run_module(module, run_name='__main__')
                except SystemExit as exit_value:
                    if exit_value.code not in (None, 0):
                        raise
            elif operation == 'script':
                name, arguments = sys.argv[2], sys.argv[3:]
                require([name, arguments] in policy['derivations'], 'derivation allowlist')
                sys.argv = [str(source / name), *arguments]
                try:
                    runpy.run_path(str(source / name), run_name='__main__')
                except SystemExit as exit_value:
                    if exit_value.code not in (None, 0):
                        raise
            elif operation == 'tests':
                os.environ['HEPTA_COMPARE_BASE_ROOT'] = str(source)
                os.environ['HEPTA_COMPARE_CONTROL_EVIDENCE'] = str(output / 'numeric-source-fixture')
                loader = unittest.TestLoader()
                # Import-time CPython function-pointer type declarations remain
                # mechanical host declarations. No image may be instantiated.
                suite = loader.loadTestsFromNames(policy['test_classes'])
                report['loaded_ids'] = [test.id() for test in flatten(suite)]
                report['loader_errors'] = list(loader.errors)
                require(report['loaded_ids'] == policy['expected_ids'] and not loader.errors,
                        'full frozen source method inventory differs')
                for name in ('CDLL', 'PyDLL', 'CFUNCTYPE', 'PYFUNCTYPE'):
                    stack.enter_context(patch.object(ctypes, name, forbidden))
                executed = report['executed_ids']
                class Result(unittest.TextTestResult):
                    def startTest(self, test):
                        executed.append(test.id())
                        super().startTest(test)
                with (output / 'source-unittest.log').open('x') as stream:
                    result = unittest.TextTestRunner(stream=stream, verbosity=2, resultclass=Result).run(suite)
                report['tests_run'] = result.testsRun
                for name in ('errors', 'failures', 'skipped', 'expectedFailures', 'unexpectedSuccesses'):
                    report[name] = [(item[0].id(), item[1]) if isinstance(item, tuple) else item.id()
                                    for item in getattr(result, name)]
                require(result.wasSuccessful() and executed == policy['expected_ids']
                        and result.testsRun == len(executed)
                        and not any(report[name] for name in ('loader_errors', 'errors', 'failures',
                            'skipped', 'expectedFailures', 'unexpectedSuccesses')),
                        'one or more complete frozen source controls failed')
            else:
                raise ValueError('unknown source-only child operation')
        require(not attempted, 'preserved native/compiler/process poison was triggered')
        report['status'] = 'SOURCE_CHILD_PASS'
        result_code = 0
    except BaseException:
        report['status'] = 'HOLD'
        report['error'] = traceback.format_exc()
    finally:
        report['seconds'] = time.monotonic() - at
        if operation == 'tests':
            save(output / 'source-tests.json', report)
        else:
            save(Path(os.environ['HEPTA_COMPARE_SOURCE_CHILD_REPORT']), report)
    print(json.dumps({key: report.get(key) for key in ('operation', 'status', 'seconds', 'error')}, sort_keys=True))
    return result_code


if __name__ == '__main__':
    raise SystemExit(main())
