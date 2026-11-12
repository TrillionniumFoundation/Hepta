"""Execute the original eight source methods once; no supplier import or tool use."""
from pathlib import Path
import importlib.util
import json
import os
import sys
import time
import traceback
import unittest

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('rust195_source_eight_common', ROOT / 'control/common.py')
common = importlib.util.module_from_spec(spec)
spec.loader.exec_module(common)

class ExactResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.actual_ids, self.success_ids, self.events = [], [], []
    @staticmethod
    def fixed_id(test):
        return type(test).__name__ + '.' + test._testMethodName
    def startTest(self, test):
        name = self.fixed_id(test)
        self.actual_ids.append(name)
        self.events.append({'kind': 'start', 'id': name, 'monotonic_ns': time.monotonic_ns()})
        super().startTest(test)
    def stopTest(self, test):
        self.events.append({'kind': 'stop', 'id': self.fixed_id(test), 'monotonic_ns': time.monotonic_ns()})
        super().stopTest(test)
    def addSuccess(self, test):
        self.success_ids.append(self.fixed_id(test))
        super().addSuccess(test)

def main():
    common.require(len(sys.argv) == 2, 'one fixed request argument required')
    request_path = Path(sys.argv[1])
    common.require(request_path == ROOT / 'REQUEST.json', 'request path differs')
    request_pin, request_raw = common.read(request_path)
    request = json.loads(request_raw)
    output = Path(request['operation_root']) / 'tests'
    common.require(not os.path.lexists(output), 'test originals must be fresh')
    output.mkdir(mode=0o700)
    report = {'schema': 'hia.full32.rust195-source-eight-worker.v1', 'status': 'HOLD',
              'expected_ids': request['expected_ids'], 'loaded_ids': [], 'actual_ids': [],
              'tests_run': 0, 'success_ids': [], 'failures': [], 'errors': [], 'skipped': [],
              'expected_failures': [], 'unexpected_successes': [], 'denied_effects': [],
              'supplier_module_imported': False, 'supplier_executed': False, 'network_used': False,
              'Rustup_executed': False, 'APT_executed': False, 'native_executed': False,
              'product_qualification_executed': False, 'request': request_pin,
              'original_product_results_reclassified': False, 'product_source_binding': None}
    began = time.monotonic_ns()
    result = None
    try:
        before = common.input_records(ROOT, request)
        common.create(output / 'INPUTS-BEFORE.json', before)
        common.require(request['expected_methods'] == 8 and len(request['expected_ids']) == 8
                       and len(set(request['expected_ids'])) == 8,
                       'complete eight-method denominator required')
        def audit(event, args):
            denied = (event in {'subprocess.Popen', 'os.system', 'os.fork', 'os.forkpty',
                               'os.posix_spawn', 'os.exec', 'socket.__new__', 'socket.connect',
                               'socket.bind', 'ctypes.dlopen'}
                      or event == 'import' and args and str(args[0]).split('.')[0] == 'supply_v87')
            if event == 'open' and args:
                flags = args[2] if len(args) > 2 else 0
                mode = args[1] if len(args) > 1 else None
                writing = ((type(flags) is int and flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC))
                           or type(mode) is str and any(c in mode for c in 'wax+'))
                if writing:
                    name = args[0]
                    allowed = (type(name) is int or isinstance(name, (str, bytes, os.PathLike))
                               and Path(os.fsdecode(name)).is_absolute()
                               and Path(os.fsdecode(name)).is_relative_to(output))
                    # dir_fd-created originals use a fixed basename inside held output parents.
                    if isinstance(name, str) and name in {'INPUTS-AFTER.json', 'REPORT.json',
                                                         'TEST-EVENTS.json', 'EXCEPTION.json'}:
                        allowed = True
                    denied = denied or not allowed
            if denied:
                report['denied_effects'].append({'event': event, 'attempt_ordinal': len(report['denied_effects']) + 1})
                raise RuntimeError('source-only external effect denied: ' + event)
        sys.addaudithook(audit)
        path = ROOT / 'inputs/controls/check_rust195_self_update_r5.py'
        module_spec = importlib.util.spec_from_file_location('rust195_original_controls', path)
        module = importlib.util.module_from_spec(module_spec)
        module_spec.loader.exec_module(module)
        cls = module.Rust195SelfUpdateR5SourceControls
        declared = {name for name in cls.__dict__ if name.startswith('test_')}
        expected_names = [name.split('.', 1)[1] for name in request['expected_ids']]
        common.require(declared == set(expected_names) and len(declared) == 8,
                       'original class method set differs')
        suite = unittest.TestSuite(cls(name) for name in expected_names)
        report['loaded_ids'] = [ExactResult.fixed_id(test) for test in suite]
        common.require(report['loaded_ids'] == request['expected_ids'], 'declared method order differs')
        result = unittest.TextTestRunner(verbosity=2, resultclass=ExactResult).run(suite)
        report.update(tests_run=result.testsRun, actual_ids=result.actual_ids, success_ids=result.success_ids,
                      failures=[{'id': ExactResult.fixed_id(t), 'traceback': raw} for t, raw in result.failures],
                      errors=[{'id': ExactResult.fixed_id(t), 'traceback': raw} for t, raw in result.errors],
                      skipped=[{'id': ExactResult.fixed_id(t), 'reason': raw} for t, raw in result.skipped],
                      expected_failures=[{'id': ExactResult.fixed_id(t), 'traceback': raw} for t, raw in result.expectedFailures],
                      unexpected_successes=[ExactResult.fixed_id(t) for t in result.unexpectedSuccesses])
        after = common.input_records(ROOT, request)
        common.create(output / 'INPUTS-AFTER.json', after)
        report.update(inputs_before=before, inputs_after=after)
        common.require(before == after and report['loaded_ids'] == report['actual_ids'] == report['success_ids']
                       == request['expected_ids'] and result.testsRun == 8
                       and not any(report[key] for key in ('failures', 'errors', 'skipped',
                           'expected_failures', 'unexpected_successes', 'denied_effects')),
                       'eight inert controls or unchanged inputs did not pass')
        report['status'] = 'EIGHT_INERT_SOURCE_CONTROLS_PASS_ONLY'
    except BaseException as error:
        report['exception'] = {'type': type(error).__name__, 'message': str(error), 'traceback': traceback.format_exc()}
        common.create(output / 'EXCEPTION.json', report['exception'])
    finally:
        report['elapsed_ns'] = time.monotonic_ns() - began
        common.create(output / 'TEST-EVENTS.json', [] if result is None else result.events)
        common.create(output / 'REPORT.json', report)
    print(json.dumps({'status': report['status'], 'tests_run': report['tests_run'], 'output': str(output)}))
    return 0 if report['status'] == 'EIGHT_INERT_SOURCE_CONTROLS_PASS_ONLY' else 1

if __name__ == '__main__':
    raise SystemExit(main())
