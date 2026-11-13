"""Separate finite source-control worker. Does not call the actual receiver."""
from pathlib import Path
import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import time
import traceback
import unittest

ROOT = Path(__file__).resolve().parent.parent

def create(path, value):
    raw = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    if path.read_bytes() != raw:
        raise RuntimeError('control report readback differs')

class Result(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.actual_ids, self.success_ids = [], []
    @staticmethod
    def name(test):
        return type(test).__name__ + '.' + test._testMethodName
    def startTest(self, test):
        self.actual_ids.append(self.name(test)); super().startTest(test)
    def addSuccess(self, test):
        self.success_ids.append(self.name(test)); super().addSuccess(test)

def main():
    request = json.loads((ROOT / 'CONTROL-REQUEST.json').read_bytes())
    output = Path(request['output'])
    if len(sys.argv) != 1 or os.path.lexists(output):
        raise RuntimeError('fresh fixed finite-control output required')
    output.mkdir(mode=0o700); (output / 'tmp').mkdir(mode=0o700)
    tempfile.tempdir = str(output / 'tmp')
    report = {'schema': 'hia.full32.stream-reader-finite-controls.v1', 'status': 'HOLD',
              'expected_ids': request['expected_ids'], 'loaded_ids': [], 'actual_ids': [], 'success_ids': [],
              'tests_run': 0, 'failures': [], 'errors': [], 'skipped': [], 'expected_failures': [],
              'unexpected_successes': [], 'denied_effects': [], 'provider_bytes_read': 0,
              'supplier_executed': False, 'product_executed': False, 'network_used': False}
    def pins():
        result = {}
        for name, expected in request['inputs'].items():
            raw = (ROOT / name).read_bytes()
            actual = {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
            if actual != expected:
                raise RuntimeError('frozen control byte pin differs')
            result[name] = actual
        return result
    started = time.monotonic_ns()
    try:
        before = pins(); report['inputs_before'] = before
        def audit(event, args):
            if event in {'subprocess.Popen', 'os.system', 'os.fork', 'os.forkpty', 'os.posix_spawn',
                         'os.exec', 'socket.__new__', 'socket.connect', 'socket.bind', 'ctypes.dlopen'}:
                report['denied_effects'].append({'event': event})
                raise RuntimeError('source-only external effect denied')
        sys.addaudithook(audit)
        spec = importlib.util.spec_from_file_location('stream_original_finite_controls', ROOT / 'controls/check_stream_consumer.py')
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        declared = [name + '.' + method for name in ('StreamFormatControls', 'LocalBoundaryControls')
                    for method in getattr(module, name).__dict__ if method.startswith('test_')]
        if declared != request['expected_ids'] or len(declared) != 24:
            raise RuntimeError('full finite-control class/ID set differs')
        suite = unittest.TestSuite(getattr(module, name.split('.')[0])(name.split('.')[1])
                                   for name in request['expected_ids'])
        report['loaded_ids'] = [Result.name(test) for test in suite]
        result = unittest.TextTestRunner(verbosity=2, resultclass=Result).run(suite)
        report.update(tests_run=result.testsRun, actual_ids=result.actual_ids, success_ids=result.success_ids,
            failures=[{'id': Result.name(test), 'traceback': raw} for test, raw in result.failures],
            errors=[{'id': Result.name(test), 'traceback': raw} for test, raw in result.errors],
            skipped=[{'id': Result.name(test), 'reason': raw} for test, raw in result.skipped],
            expected_failures=[{'id': Result.name(test), 'traceback': raw} for test, raw in result.expectedFailures],
            unexpected_successes=[Result.name(test) for test in result.unexpectedSuccesses])
        after = pins(); report['inputs_after'] = after
        if (report['loaded_ids'] != report['actual_ids'] or report['actual_ids'] != report['success_ids']
            or report['success_ids'] != request['expected_ids'] or result.testsRun != 24 or before != after
            or any(report[k] for k in ('failures', 'errors', 'skipped', 'expected_failures', 'unexpected_successes', 'denied_effects'))):
            raise RuntimeError('complete finite controls did not pass')
        report['status'] = 'SOURCE_FORMAT_IO_24_PASS_ONLY'
    except BaseException as error:
        report['status'] = 'HOLD'
        report['exception'] = {'type': type(error).__name__, 'message': str(error), 'traceback': traceback.format_exc()}
    report['elapsed_ns'] = time.monotonic_ns() - started
    create(output / 'REPORT.json', report)
    print(json.dumps({'status': report['status'], 'tests_run': report['tests_run'], 'provider_bytes_read': 0}))
    return 0 if report['status'] == 'SOURCE_FORMAT_IO_24_PASS_ONLY' and 'exception' not in report else 1

if __name__ == '__main__':
    raise SystemExit(main())
