"""Exactly one generation plus the four unchanged source/Core-VM methods."""
from __future__ import annotations
import argparse
from contextlib import ExitStack
import ctypes
import importlib
import json
import mmap
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import traceback
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import source_common as common

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--request', type=Path, required=True)
    parser.add_argument('--sha256', required=True)
    args = parser.parse_args()
    os.umask(0o077)
    request, materialization, request_pin = common.load_request(args.request, args.sha256)
    root = Path(request['source_root'])
    output = Path(request['output_root'])
    started = time.monotonic_ns()
    report = {'schema': 'hia.pc-forwarding.source4-result.v1', 'status': 'HOLD',
              'request_sha256': request_pin['sha256'], 'expected_ids': request['expected_ids'],
              'loaded_ids': [], 'started_ids': [], 'stopped_ids': [],
              'testsRun': 0, 'forbidden_attempts': [], 'generation': None,
              'native_executed': False, 'compiler_executed': False}
    before = common.source_snapshot(request, materialization)
    common.require_source_before(request, materialization, before)
    common.save_json(output / 'source-before.json', before)

    def forbidden(label):
        def refuse(*_args, **_kwargs):
            report['forbidden_attempts'].append(label)
            raise AssertionError('source-only forbidden entry: ' + label)
        return refuse

    def audit(event, _args):
        if event in {'subprocess.Popen', 'os.system', 'os.posix_spawn', 'os.fork',
                     'ctypes.dlopen', 'mmap.__new__', 'socket.__new__'}:
            forbidden('audit:' + event)()
    sys.addaudithook(audit)
    try:
        common.require(not any(key.startswith('HEPTA_HIA_') and value
                               for key, value in os.environ.items()), 'ambient native selector')
        sys.path.insert(0, str(root))
        with ExitStack() as stack:
            for module, name in ((subprocess, 'Popen'), (os, 'system'), (os, 'fork'),
                                 (ctypes, 'CDLL'), (ctypes, 'PyDLL')):
                if hasattr(module, name):
                    stack.enter_context(patch.object(module, name,
                        side_effect=forbidden(module.__name__ + '.' + name)))
            from tools import generate_hia_core_lowering as generator
            from hepta import hia_json_preflight_native as image_module
            stack.enter_context(patch.object(image_module.NativeHiaJsonImage, '__init__',
                                             side_effect=forbidden('NativeHiaJsonImage.__init__')))
            for module in (generator, image_module):
                common.require(Path(module.__file__).resolve().is_relative_to(root),
                               'product import escaped candidate')
            generation_started = time.monotonic_ns()
            paths = generator.write(root / 'examples/hia_bootstrap',
                                    root / 'hepta/hia_core_lowering_abi.json')
            expected = [str(root / p) for p in request['generated_assembly']]
            common.require(paths == expected and len(paths) == 39, '39 generated units differ')
            report['generation'] = {'seconds': (time.monotonic_ns() - generation_started) / 1e9,
                                    'paths': paths, 'count': len(paths)}
            common.save_json(output / 'generation.json', report['generation'])
            suite = unittest.defaultTestLoader.loadTestsFromName(
                'tests.test_hia_core_lowering_native.CoreLoweringSourceTests')
            def flatten(item):
                if isinstance(item, unittest.TestSuite):
                    return [test for child in item for test in flatten(child)]
                return [item]
            loaded = [test.id() for test in flatten(suite)]
            report['loaded_ids'] = loaded
            common.require(loaded == request['expected_ids']
                           and not unittest.defaultTestLoader.errors, 'original source4 IDs differ')

            class Result(unittest.TextTestResult):
                def startTest(self, test):
                    report['started_ids'].append(test.id())
                    super().startTest(test)
                def stopTest(self, test):
                    try:
                        super().stopTest(test)
                    finally:
                        report['stopped_ids'].append(test.id())

            with (output / 'source4.unittest.log').open('x', encoding='utf-8') as log:
                result = unittest.TextTestRunner(stream=log, verbosity=2, resultclass=Result).run(suite)
            report.update(testsRun=result.testsRun,
                failures=[{'id': test.id(), 'traceback': detail} for test, detail in result.failures],
                errors=[{'id': test.id(), 'traceback': detail} for test, detail in result.errors],
                skipped=[{'id': test.id(), 'reason': reason} for test, reason in result.skipped],
                expectedFailures=[{'id': test.id(), 'traceback': detail} for test, detail in result.expectedFailures],
                unexpectedSuccesses=[test.id() for test in result.unexpectedSuccesses],
                loader_errors=list(unittest.defaultTestLoader.errors))
            common.require(report['testsRun'] == 4
                and report['started_ids'] == report['stopped_ids'] == report['expected_ids']
                and result.wasSuccessful()
                and all(not report[key] for key in ('failures', 'errors', 'skipped',
                    'expectedFailures', 'unexpectedSuccesses', 'loader_errors'))
                and not report['forbidden_attempts'], 'original four source controls did not pass')
        report['status'] = 'SOURCE4_PASS_ONLY'
    except BaseException as error:
        report['exception'] = {'type': type(error).__name__, 'message': str(error),
                               'traceback': traceback.format_exc()}
    finally:
        try:
            after = common.source_snapshot(request, materialization)
            common.save_json(output / 'source-after.json', after)
            report['changed_paths'] = common.require_source_after(request, before, after)
            for value in request['inputs']:
                common.read_regular(value['path'], value)
        except BaseException as error:
            report['status'] = 'HOLD'
            report['final_check_error'] = {'type': type(error).__name__, 'message': str(error),
                                          'traceback': traceback.format_exc()}
        report['seconds'] = (time.monotonic_ns() - started) / 1e9
        common.save_json(output / 'source4-report.json', report)
    return 0 if report['status'] == 'SOURCE4_PASS_ONLY' else 1

if __name__ == '__main__':
    raise SystemExit(main())
