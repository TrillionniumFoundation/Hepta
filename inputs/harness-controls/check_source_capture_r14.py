"""Exercise the R14 evidence path guards without executing product Source tests."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import traceback

ROOT = Path(__file__).resolve().parent
DRIVER = ROOT / 'harness/tools/materialize_candidate_r14.py'
OUT = ROOT / 'source-capture-r14-controls-r1'
NAMES = ('HEPTA_HIA_CANDIDATE_BUILD_TEST_EVIDENCE',
         'HEPTA_HIA_LINUX_STDIO_SOURCE_EVIDENCE',
         'HEPTA_HIA_LINUX_PROCESS_SOURCE_EVIDENCE')
LOCATIONS = ('hia-candidate-build-source', 'hia-linux-stdio-source', 'hia-linux-process-source')
ENVIRONMENT = {name: '@EVIDENCE@/checks/' + leaf
               for name, leaf in zip(NAMES, LOCATIONS)}


def blob(raw):
    return hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()


def main():
    assert blob(DIVER := DRIVER.read_bytes()) == 'cfe319279641b124bcd724437857686f36d1aa07'
    spec = importlib.util.spec_from_file_location('fixed_r14_guard_subject', DRIVER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    OUT.mkdir(exist_ok=False)
    (OUT / 'DRIVER.py').write_bytes(DIVER)
    cases = []
    original = module.python_command

    def execute(label, setup=None, behavior='success', expected_error=None,
                expected_pass=None, expected_calls=0):
        capture = module.Capture(OUT / label, '')
        capture.basic = ''
        capture.repo.mkdir()
        for key in NAMES:
            assert key not in capture.env
        inputs = {'source_registration': {'selectors': ['CONTROL_NO_PRODUCT_EXECUTION']},
                  'source_test_environment': deepcopy(ENVIRONMENT)}
        calls = []
        if setup:
            setup(capture, inputs)
        before_env = dict(capture.env)
        harness = OUT / 'fixed-harness'

        def observe(cap, arguments, command_label, **kwargs):
            assert cap is capture
            assert command_label == 'complete-source-tests'
            assert kwargs == {'limit': 1800, 'enforce': False, 'local_git_fixture': True}
            assert arguments == [str(harness / 'tools/run_source_gate.py'),
                                 '--registration', str(capture.root / 'SOURCE-REGISTRATION.json'),
                                 '--source', str(capture.repo),
                                 '--original-ids', str(harness / 'inputs/ORIGINAL-SOURCE-IDS.json'),
                                 '--output', str(capture.raw / 'checks/SOURCE-TESTS.json')]
            candidate, portable, process = [capture.raw / 'checks' / leaf for leaf in LOCATIONS]
            assert candidate.is_dir() and not portable.exists() and not portable.is_symlink()
            assert not process.exists() and not process.is_symlink()
            assert {key: capture.env[key] for key in NAMES} == {
                NAMES[0]: str(candidate), NAMES[1]: str(portable), NAMES[2]: str(process)}
            calls.append({'label': command_label, 'arguments': arguments, **kwargs,
                          'source_tests_executed': 0, 'observer_substituted': True})
            if behavior == 'raise':
                raise LookupError('CONTROL_RUNNER_EXCEPTION')
            portable.mkdir(exist_ok=False)
            if behavior != 'missing-readback':
                target = portable / 'RESOURCE-READBACK.json'
                if behavior == 'symlink-readback':
                    actual = capture.root / 'readback.json'
                    actual.write_bytes(b'{"scope":"GUARD_CONTROL_ONLY"}\n')
                    target.symlink_to(actual)
                else:
                    target.write_bytes(b'{"scope":"GUARD_CONTROL_ONLY"}\n')
            process.mkdir(exist_ok=False)
            if behavior != 'missing-process-readback':
                target = process / 'RESOURCE-READBACK.json'
                if behavior == 'symlink-process-readback':
                    actual = capture.root / 'process-readback.json'
                    actual.write_bytes(b'{"scope":"GUARD_CONTROL_ONLY"}\n')
                    target.symlink_to(actual)
                else:
                    target.write_bytes(b'{"scope":"GUARD_CONTROL_ONLY"}\n')
            if behavior != 'missing-report':
                (capture.raw / 'checks/SOURCE-TESTS.json').write_bytes(module.canonical({
                    'status': 'PASS', 'scope': 'SYNTHETIC_RUNNER_GUARD_CONTROL',
                    'tests_run': 0, 'whole_native': False}))
            return b'', {'returncode': 1 if behavior == 'nonzero' else 0,
                         'timed_out': behavior == 'timeout'}

        module.python_command = observe
        caught = None
        returned = None
        try:
            returned = module.source_gate(capture, inputs, harness)
        except Exception as error:
            caught = {'type': type(error).__name__, 'message': str(error)}
        finally:
            module.python_command = original
        assert capture.env == before_env, label + ': environment not restored'
        assert len(calls) == expected_calls, (label, calls)
        if expected_error is not None:
            assert caught is not None and expected_error in caught['message'], (label, caught)
        else:
            assert caught is None and returned[1] is expected_pass, (label, caught, returned)
        record = {'case': label, 'status': 'CONTROL_PASS', 'calls': calls,
                  'exception': caught, 'returned_pass_flag': returned[1] if returned else None,
                  'environment_restored': True, 'source_tests_executed': 0}
        (capture.root / 'CONTROL-RESULT.json').write_bytes(module.canonical(record))
        cases.append(record)

    execute('valid-fresh-paths', expected_pass=True, expected_calls=1)
    execute('missing-environment-map', lambda c, p: p.pop('source_test_environment'),
            expected_error='unreviewed Source evidence environment')
    execute('extra-environment-key',
            lambda c, p: p['source_test_environment'].update(UNREVIEWED='x'),
            expected_error='unreviewed Source evidence environment')
    execute('wrong-environment-path',
            lambda c, p: p['source_test_environment'].update({NAMES[1]: '@EVIDENCE@/wrong'}),
            expected_error='unreviewed Source evidence environment')
    for index, name in enumerate(NAMES):
        execute('ambient-' + str(index), lambda c, p, key=name: c.env.update({key: '/tmp/unreviewed'}),
                expected_error='ambient Source evidence path is not permitted')
        execute('existing-location-' + str(index),
                lambda c, p, leaf=LOCATIONS[index]: (c.raw / 'checks' / leaf).mkdir(parents=True),
                expected_error='Source evidence must use a fresh ordinary location')
        def dangling(capture, inputs, leaf=LOCATIONS[index]):
            (capture.raw / 'checks').mkdir()
            (capture.raw / 'checks' / leaf).symlink_to(capture.root / 'missing')
        execute('dangling-location-' + str(index), dangling,
                expected_error='Source evidence must use a fresh ordinary location')
    def inside(capture, inputs):
        capture.repo = capture.raw / 'checks'
        capture.repo.mkdir()
    execute('inside-source', inside, expected_error='Source evidence must be outside the source tree')
    def ancestor(capture, inputs):
        (capture.raw / 'checks').symlink_to(capture.repo, target_is_directory=True)
    execute('symlink-ancestor-into-source', ancestor,
            expected_error='Source evidence must be outside the source tree')
    for behavior in ('missing-report', 'nonzero', 'timeout'):
        execute(behavior, behavior=behavior, expected_pass=False, expected_calls=1)
    for behavior in ('missing-readback', 'symlink-readback'):
        execute(behavior, behavior=behavior,
                expected_error='successful portable Source fixture did not retain its original resource readback',
                expected_calls=1)
    for behavior in ('missing-process-readback', 'symlink-process-readback'):
        execute(behavior, behavior=behavior,
                expected_error='successful process portable Source fixture did not retain its original resource readback',
                expected_calls=1)
    execute('missing-process-environment-key',
            lambda c, p: p['source_test_environment'].pop(NAMES[2]),
            expected_error='unreviewed Source evidence environment')
    execute('runner-exception', behavior='raise', expected_error='CONTROL_RUNNER_EXCEPTION', expected_calls=1)
    report = {'schema': 'hia.source-capture-r14-guard-controls.v1', 'status': 'GUARD_CONTROLS_PASS',
              'driver_blob': blob(DIVER), 'cases': cases, 'case_count': len(cases),
              'source_tests_executed': 0, 'native_executions': 0, 'cold_qualifications': 0,
              'original_runner_invoked': False, 'runner_replaced_only_in_this_control': True,
              'scope': 'HARNESS_PATH_ENVIRONMENT_FAILURE_AND_RETURN_GUARDS_ONLY',
              'whole_native': False}
    (OUT / 'RESULT.json').write_bytes(module.canonical(report))
    print(json.dumps({k: v for k, v in report.items() if k != 'cases'}, sort_keys=True))


if __name__ == '__main__':
    main()
