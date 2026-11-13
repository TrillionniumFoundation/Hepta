"""Run exactly twelve frozen synthetic diagnostic relocation source/IO controls."""
from hashlib import sha256
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import traceback
import unittest

spec = importlib.util.spec_from_file_location('source12_common', Path(__file__).with_name('source_common.py'))
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--request', type=Path, required=True)
    parser.add_argument('--request-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    raw = C.read(args.request, 1 << 20)
    C.require(sha256(raw).hexdigest() == args.request_sha256, 'source12 request SHA differs')
    request = json.loads(raw)
    C.require(request['schema'] == 'hia.v92.diagnostic-relocation.source12-request.v1'
              and request['output_root'] == str(args.output)
              and request['qualification_seconds'] == 20 and request['cleanup_seconds'] == 3
              and len(request['expected_ids']) == 12 and len(set(request['expected_ids'])) == 12,
              'fixed source12 scope differs')
    C.require(sys.version == request['runtime']['version']
              and str(Path(sys.executable).resolve()) == request['runtime']['executable'],
              'source12 interpreter differs')
    before = C.check_inputs(request)
    C.create(args.output / 'INPUTS-BEFORE.json', before)
    report = {'schema': 'hia.v92.diagnostic-source12-report.v1', 'status': 'HOLD',
              'expected_ids': request['expected_ids'], 'loaded_ids': [], 'executed_ids': [], 'success_ids': [],
              'failures': [], 'errors': [], 'skips': [], 'expected_failures': [], 'unexpected_successes': [],
              'loader_errors': [], 'forbidden_attempts': [], 'exception': None,
              'synthetic_only': True, 'network_requests': 0, 'native_calls': 0, 'product_imported': False,
              'historical_460_originals_recovered': False, 'old_R4_owner_status': 'UNKNOWN_NOT_RECLASSIFIED'}
    forbidden = report['forbidden_attempts']
    def audit(event, arguments):
        if (event.startswith(('socket.', 'subprocess.', 'ctypes.', 'mmap.'))
                or event in ('os.system', 'os.exec', 'os.posix_spawn', 'os.fork', 'os.forkpty')):
            forbidden.append(event)
            raise RuntimeError('SOURCE_ONLY_FORBIDDEN_EFFECT:' + event)
    def refuse_process(*args, **kwargs):
        forbidden.append('Popen')
        raise RuntimeError('SOURCE_ONLY_SUBPROCESS_REFUSED')
    sys.addaudithook(audit)
    subprocess.Popen = refuse_process
    started = time.monotonic()
    def test_id(test):
        return test.__class__.__name__ + '.' + test._testMethodName
    class Result(unittest.TextTestResult):
        def startTest(self, test):
            report['executed_ids'].append(test_id(test))
            super().startTest(test)
        def addSuccess(self, test):
            report['success_ids'].append(test_id(test))
            super().addSuccess(test)
    try:
        tests = C.load('diagnostic_relocation_source12', request['tests_path'])
        C.require(tests.EXPECTED_IDS == request['expected_ids'], 'declared source method IDs differ')
        tests.OUTPUT = args.output / 'fixtures'
        tests.OUTPUT.mkdir(mode=0o700)
        loader = unittest.TestLoader()
        suite = unittest.TestSuite(loader.loadTestsFromName(name, tests) for name in request['expected_ids'])
        def ids(node):
            if isinstance(node, unittest.TestSuite):
                return [item for child in node for item in ids(child)]
            return [test_id(node)]
        report['loaded_ids'] = ids(suite)
        report['loader_errors'] = list(loader.errors)
        C.require(report['loaded_ids'] == report['expected_ids'] and not loader.errors, 'complete source12 load differs')
        with (args.output / 'unittest.log').open('x', encoding='utf-8') as stream:
            result = unittest.TextTestRunner(stream=stream, verbosity=2, resultclass=Result).run(suite)
            stream.flush()
            os.fsync(stream.fileno())
        for target, source in (('failures', result.failures), ('errors', result.errors),
                               ('skips', result.skipped), ('expected_failures', result.expectedFailures)):
            report[target] = [{'id': test_id(test), 'detail': detail} for test, detail in source]
        report['unexpected_successes'] = [test_id(test) for test in result.unexpectedSuccesses]
        C.require(report['expected_ids'] == report['loaded_ids'] == report['executed_ids'] == report['success_ids']
                  and result.testsRun == 12 and result.wasSuccessful()
                  and not any(report[key] for key in ('failures', 'errors', 'skips', 'expected_failures',
                                                       'unexpected_successes', 'loader_errors', 'forbidden_attempts')),
                  'complete source12 result has a missing ID or anomaly')
        report['status'] = 'SOURCE12_SYNTHETIC_IO_PASS_NOT_ARTIFACT_RECOVERY'
    except BaseException as exc:
        report['status'] = 'HOLD'
        report['exception'] = {'type': type(exc).__name__, 'traceback': traceback.format_exc()}
    finally:
        report['seconds'] = time.monotonic() - started
        try:
            after = C.check_inputs(request)
            C.create(args.output / 'INPUTS-AFTER.json', after)
            C.require(before == after, 'source12 input identities changed')
            report['inputs_unchanged'] = True
        except BaseException as exc:
            report['status'] = 'HOLD'
            report['input_failure'] = {'type': type(exc).__name__, 'traceback': traceback.format_exc()}
        C.create(args.output / 'REPORT.json', report)
    print(json.dumps({'status': report['status'], 'expected': len(report['expected_ids']),
                      'loaded': len(report['loaded_ids']), 'executed': len(report['executed_ids']),
                      'seconds': report['seconds'], 'product_executed': False}), flush=True)
    return 0 if report['status'] == 'SOURCE12_SYNTHETIC_IO_PASS_NOT_ARTIFACT_RECOVERY' else 1


if __name__ == '__main__':
    raise SystemExit(main())
