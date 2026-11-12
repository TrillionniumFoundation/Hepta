"""Run the exact finite source/I/O population under the existing outer owner."""
from __future__ import annotations
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import time
import unittest

def read_record(path):
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise RuntimeError('fixed source must be single-link regular')
    raw = path.read_bytes()
    if path.lstat() != before or len(raw) != before.st_size:
        raise RuntimeError('fixed source changed during read')
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
            'identity': [before.st_dev, before.st_ino, before.st_mode, before.st_uid,
                         before.st_gid, before.st_nlink, before.st_size,
                         before.st_mtime_ns, before.st_ctime_ns]}

def write(path, value):
    raw = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    if path.read_bytes() != raw: raise RuntimeError('new evidence readback differs')

def main():
    config_path = Path(sys.argv[1]); config = json.loads(config_path.read_bytes())
    source = Path(config['source']); output = Path(config['output'])
    if os.path.lexists(output): raise RuntimeError('new output required')
    output.mkdir(mode=0o700); (output / 'fixtures').mkdir(mode=0o700)
    start = time.monotonic_ns()
    report = {'schema': 'hia.multipart.finite-source-io.v1', 'status': 'HOLD',
              'expected': config['expected'], 'loaded': [], 'executed': [],
              'failures': [], 'errors': [], 'skipped': [], 'expected_failures': [],
              'unexpected_successes': [], 'loader_errors': [], 'outer_errors': [],
              'native_or_product_executed': False, 'network_requested': False,
              'actual_capacity_qualified': False, 'workflow_installed_or_triggered': False}
    before = None; module = None
    try:
        before = {p: read_record(Path(p)) for p in config['pins']}
        if any(v['sha256'] != config['pins'][p] for p,v in before.items()):
            raise RuntimeError('fixed source SHA differs')
        write(output / 'SOURCE-BEFORE.json', before)
        os.environ['HIA_MULTIPART_SOURCE'] = str(source)
        os.environ['HIA_MULTIPART_ACTUAL'] = str(output)
        spec = importlib.util.spec_from_file_location('multipart_source_io', config['test'])
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        loader = unittest.TestLoader(); suite = loader.loadTestsFromTestCase(module.MultipartSourceIOTests)
        report['loader_errors'] = list(loader.errors)
        report['loaded'] = [test.id() for test in suite]
        if report['loaded'] != config['expected'] or loader.errors:
            raise RuntimeError('exact finite population differs')
        class Recording(unittest.TextTestResult):
            def startTest(self, test):
                report['executed'].append(test.id()); super().startTest(test)
        result = unittest.TextTestRunner(stream=sys.stdout, verbosity=2, resultclass=Recording).run(suite)
        report.update(tests_run=result.testsRun,
            failures=[{'id': t.id(), 'traceback': s} for t,s in result.failures],
            errors=[{'id': t.id(), 'traceback': s} for t,s in result.errors],
            skipped=[{'id': t.id(), 'reason': s} for t,s in result.skipped],
            expected_failures=[{'id': t.id(), 'traceback': s} for t,s in result.expectedFailures],
            unexpected_successes=[t.id() for t in result.unexpectedSuccesses])
        if (report['loaded'] == report['executed'] == config['expected']
            and result.testsRun == 21 and not any(report[k] for k in
            ('failures','errors','skipped','expected_failures','unexpected_successes','loader_errors'))):
            report['status'] = 'FINITE_SOURCE_IO_PASS_PENDING_OUTER_GUARDIAN'
    except BaseException as error:
        import traceback
        report['outer_errors'].append({'type': type(error).__name__, 'message': str(error),
                                       'traceback': traceback.format_exc()})
    finally:
        try:
            after = {p: read_record(Path(p)) for p in config['pins']}
            write(output / 'SOURCE-AFTER.json', after)
            report['source_preserved'] = before == after
            if before != after: report['status'] = 'HOLD'
        except BaseException as error:
            report['status'] = 'HOLD'; report['outer_errors'].append({'phase':'source-after','type':type(error).__name__})
        if module is not None: write(output / 'EVENTS.json', module.EVENTS)
        report['elapsed_ns'] = time.monotonic_ns() - start
        write(output / 'REPORT.json', report)
        print(json.dumps({'status':report['status'],'elapsed_ns':report['elapsed_ns'],'tests_run':report.get('tests_run')}),flush=True)
    return 0 if report['status'] == 'FINITE_SOURCE_IO_PASS_PENDING_OUTER_GUARDIAN' else 1

if __name__ == '__main__':
    raise SystemExit(main())
