"""Reauthored r2 source/Core-VM worker. Never a compiler/native/SQLite run."""
from pathlib import Path
import ctypes
import importlib
import importlib.util
import json
import mmap
import os
import socket
import subprocess
import sys
import time
import traceback
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location('sqlite_source8_r2_support', ROOT / 'control/support.py')
support = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(support)
common = support.common

def main():
    request_path = Path(sys.argv[1])
    common.require(request_path == ROOT / 'REQUEST.json', 'exact r2 request path required')
    request_pin, raw = common.read(request_path)
    request = json.loads(raw)
    common.require(request['schema'] == 'hia.sqlite-varint.source-eight-request.v2'
        and request['status'] == 'REAUTHORED_CONTROLS_AFTER_ENVIRONMENT_CHANGE_UNEXECUTED'
        and request['qualification_seconds'] == 180 and request['cleanup_seconds'] == 3
        and request['expected_methods'] == len(request['expected_ids']) == 8
        and request['expected_vm_returns'] == sum(request['expected_vm_by_id'].values()) == 1618,
        'source-only r2 scope or original 180/3/8/1618 differs')
    runtime, _ = common.read(Path(sys.executable).resolve())
    common.require(all(runtime[key] == request['runtime'][key]
                       for key in ('path', 'bytes', 'sha256', 'git_blob', 'identity'))
                   and list(sys.version_info[:3]) == request['runtime_version'] == [3, 12, 14]
                   and dict(os.environ) == request['environment'],
                   'worker actual runtime or exact clean launch environment differs')
    output = Path(request['operation_root'])
    tests = output / 'tests'
    common.require(output.is_dir() and not tests.exists(), 'parent-owned fresh output required')
    tests.mkdir(mode=0o700)
    before = common.input_records(ROOT, request)
    source_before = support.source_records(request)
    before_pin = common.create(tests / 'SOURCE-BEFORE.json', source_before)
    report = {'schema': 'hia.sqlite-varint.source-eight-report.v2', 'status': 'HOLD',
              'request': request_pin, 'expected_ids': request['expected_ids'], 'loaded_ids': [],
              'actual_ids': [], 'success_ids': [], 'tests_run': 0, 'exception': None,
              'failures': [], 'errors': [], 'skipped': [], 'expected_failures': [],
              'unexpected_successes': [], 'denied_effects': [], 'secondary_errors': [],
              'inputs_before': before, 'inputs_after': None, 'source_before': before_pin,
              'source_after': None, 'imports': [], 'vm': None, 'core': None,
              'original_test_body_sha256': request['inputs']['candidate/inputs/tests/test_hia_sqlite_varint_source.py']['sha256'],
              'local_development_runtime': list(sys.version_info[:3]),
              'runtime': runtime,
              'old_source8_request_replayed': False}
    report.update({key: False for key in support.PUBLIC_FLAGS})
    def deny(label):
        def forbidden(*args, **kwargs):
            report['denied_effects'].append(label)
            raise RuntimeError('source-only effect refused: ' + label)
        return forbidden
    def audit(event, args):
        if (event in {'subprocess.Popen', 'os.system', 'os.fork', 'os.forkpty', 'os.posix_spawn',
                      'os.posix_spawnp', 'os.exec', 'pty.spawn', 'ctypes.dlopen', 'ctypes.dlsym', 'sqlite3.connect',
                      'mmap.__new__'}
                or event.startswith('socket.')):
            deny('audit:' + event)()
    started = time.monotonic()
    try:
        sys.addaudithook(audit)
        subprocess.Popen = deny('subprocess.Popen')
        os.system = deny('os.system')
        ctypes.CDLL = deny('ctypes.CDLL')
        ctypes.PyDLL = deny('ctypes.PyDLL')
        socket.create_connection = deny('socket.create_connection')
        mmap.mmap = deny('mmap.mmap')
        os.environ['HEPTA_SQLITE_VARINT_SOURCE_EVIDENCE'] = str(tests)
        os.environ['HEPTA_SQLITE_VARINT_DRAFT'] = str(ROOT / 'candidate')
        sys.dont_write_bytecode = True
        sys.pycache_prefix = str(output / 'unused-pycache')
        sys.path[:0] = [str(ROOT / 'candidate/inputs'), request['source_root']]
        hepta = importlib.import_module('hepta')
        hepta.__path__[:] = [str(ROOT / 'candidate/inputs/hepta'),
                            str(Path(request['source_root']) / 'hepta')]
        importlib.import_module('tools')
        importlib.import_module('tests')
        native = importlib.import_module('hepta.hia_json_preflight_native')
        native.NativeHiaJsonImage.__init__ = deny('NativeHiaJsonImage.__init__')
        test_path = ROOT / 'candidate/inputs/tests/test_hia_sqlite_varint_source.py'
        spec = importlib.util.spec_from_file_location(request['test_module'], test_path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[request['test_module']] = module
        spec.loader.exec_module(module)
        cls = module.SQLiteVarintSourceTests
        expected_names = [name.rsplit('.', 1)[1] for name in request['expected_ids']]
        common.require(tuple(expected_names) == module.EXPECTED_NAMES
            and {name for name in cls.__dict__ if name.startswith('test_')} == set(expected_names),
            'original eight class methods changed or omitted')
        suite = unittest.TestSuite(cls(name) for name in expected_names)
        report['loaded_ids'] = [test.id() for test in suite]
        common.require(report['loaded_ids'] == request['expected_ids'], 'loaded original method order differs')
        class Result(unittest.TextTestResult):
            def startTest(self, test):
                report['actual_ids'].append(test.id())
                super().startTest(test)
            def addSuccess(self, test):
                report['success_ids'].append(test.id())
                super().addSuccess(test)
        with (tests / 'unittest.log').open('x', encoding='utf-8') as log:
            result = unittest.TextTestRunner(stream=log, verbosity=2, resultclass=Result).run(suite)
            log.flush()
            os.fsync(log.fileno())
        report['tests_run'] = result.testsRun
        for name, values in [('failures', result.failures), ('errors', result.errors),
                             ('skipped', result.skipped), ('expected_failures', result.expectedFailures)]:
            report[name] = [{'id': test.id(), 'detail': detail} for test, detail in values]
        report['unexpected_successes'] = [test.id() for test in result.unexpectedSuccesses]
        report['imports'] = support.imported_sources(request)
        report['vm'] = support.inspect_vm(request, output)
        report['core'] = support.inspect_core(output)
    except BaseException as error:
        report['status'] = 'HOLD'
        report['exception'] = {'type': type(error).__module__ + '.' + type(error).__qualname__,
                               'message': str(error), 'traceback': traceback.format_exc()}
    finally:
        try:
            report['inputs_after'] = common.input_records(ROOT, request)
            after = support.source_records(request)
            report['source_after'] = common.create(tests / 'SOURCE-AFTER.json', after)
            common.require(report['inputs_after'] == before and after == source_before,
                           'source/control inputs changed during source-only run')
        except BaseException as error:
            report['status'] = 'HOLD'
            report['secondary_errors'].append({'type': type(error).__name__, 'message': str(error),
                                                'traceback': traceback.format_exc()})
    passed = (report['exception'] is None and not report['secondary_errors']
              and report['tests_run'] == 8
              and report['expected_ids'] == report['loaded_ids'] == report['actual_ids'] == report['success_ids']
              and all(report[key] == [] for key in ('failures', 'errors', 'skipped', 'expected_failures',
                                                    'unexpected_successes', 'denied_effects'))
              and report['inputs_after'] == before and report['source_after'] is not None
              and report['vm'] is not None and report['vm']['actual_return_count'] == 1618
              and report['core'] is not None)
    report['elapsed_seconds'] = time.monotonic() - started
    report['status'] = 'SQLITE_VARINT_SOURCE_EIGHT_VM_PASS_ONLY' if passed else 'HOLD'
    common.create(tests / 'REPORT.json', report)
    print(json.dumps({'status': report['status'], 'tests_run': report['tests_run'],
                      'actual_vm_returns': None if report['vm'] is None else report['vm']['actual_return_count']}))
    return 0 if passed else 1

if __name__ == '__main__':
    raise SystemExit(main())
