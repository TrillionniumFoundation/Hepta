"""Run exactly the frozen nine Source methods once; retain every real frame."""
from pathlib import Path
import hashlib
import json
import os
import shutil
import sys
import time
import traceback
import unittest

from run_generation_r1 import ROOT, SOURCE, dump, inventory, pin, runtime, tree, write

PLAN_PATH = ROOT / 'SOURCE-EXECUTION-PLAN.json'
PLAN = json.loads(PLAN_PATH.read_text())
OUT = ROOT / 'evidence/source-r1'


def require(value, message):
    if not value:
        raise AssertionError(message)


def flatten(suite):
    values = []
    for item in suite:
        values.extend(flatten(item) if isinstance(item, unittest.TestSuite) else [item])
    return values


def child():
    started_at = time.monotonic()
    before = inventory(SOURCE)
    dump(OUT / 'SOURCE-BEFORE.json', before)
    require(tree(before) == PLAN['source_tree'] and len(before) == 3180, 'frozen Source preimage differs')
    dump(OUT / 'RUNTIME-BEFORE.json', runtime())
    sys.path.insert(0, str(SOURCE))
    event_file = (OUT / 'events.jsonl').open('x', buffering=1)
    events, started, stopped = [], [], []
    loaded = []
    report = {'status': 'FAIL', 'loaded': [], 'started': started, 'stopped': stopped,
              'Native': False, 'compile_count': 0, 'whole': False, 'cold': False,
              'max_steps_each_VM': 10000000, 'failfast': False}

    def event(kind, test=None, **data):
        row = {'sequence': len(events), 'kind': kind, 'id': test.id() if test is not None else None,
               'monotonic_ns': time.monotonic_ns(), **data}
        event_file.write(json.dumps(row, sort_keys=True, allow_nan=False) + '\n')
        event_file.flush()
        if kind in ('start', 'stop', 'loaded'):
            os.fsync(event_file.fileno())
        events.append(row)

    class ObservedResult(unittest.TextTestResult):
        def startTest(self, test):
            started.append(test.id())
            event('start', test)
            super().startTest(test)

        def stopTest(self, test):
            super().stopTest(test)
            stopped.append(test.id())
            event('stop', test)

        def addSuccess(self, test):
            event('success', test)
            super().addSuccess(test)

        def addFailure(self, test, err):
            event('failure', test, trace=self._exc_info_to_string(err, test))
            super().addFailure(test, err)

        def addError(self, test, err):
            event('error', test, trace=self._exc_info_to_string(err, test))
            super().addError(test, err)

        def addSubTest(self, test, subtest, err):
            event('subtest', test, subtest=subtest.id(),
                  status='PASS' if err is None else 'FAIL',
                  trace=None if err is None else self._exc_info_to_string(err, subtest))
            super().addSubTest(test, subtest, err)

        def addSkip(self, test, reason):
            event('skip', test, reason=reason)
            super().addSkip(test, reason)

        def addExpectedFailure(self, test, err):
            event('expected-failure', test, trace=self._exc_info_to_string(err, test))
            super().addExpectedFailure(test, err)

        def addUnexpectedSuccess(self, test):
            event('unexpected-success', test)
            super().addUnexpectedSuccess(test)

    try:
        suite = unittest.defaultTestLoader.loadTestsFromName(PLAN['selector'])
        loaded = [test.id() for test in flatten(suite)]
        report['loaded'] = loaded
        dump(OUT / 'LOADED.json', loaded)
        event('loaded', ordered_ids=loaded)
        require(loaded == PLAN['test_ids'] and len(loaded) == 9, 'exact frozen test order required')
        with (OUT / 'tests.log').open('x', buffering=1) as stream:
            result = unittest.TextTestRunner(stream=stream, verbosity=2, resultclass=ObservedResult,
                                            failfast=False, buffer=False).run(suite)
        report.update(testsRun=result.testsRun,
            failures=[{'id': test.id(), 'trace': trace} for test, trace in result.failures],
            errors=[{'id': test.id(), 'trace': trace} for test, trace in result.errors],
            skipped=[{'id': test.id(), 'reason': reason} for test, reason in result.skipped],
            expected_failures=[{'id': test.id(), 'trace': trace} for test, trace in result.expectedFailures],
            unexpected_successes=[test.id() for test in result.unexpectedSuccesses])
        require(result.testsRun == 9 and loaded == started == stopped, 'loaded/start/stop/run identity differs')
        require(result.wasSuccessful() and not result.skipped and not result.expectedFailures
                and not result.unexpectedSuccesses, 'original Source assertions failed')
        report['status'] = 'PASS'
        return 0
    except BaseException as error:
        report.update(exception_type=type(error).__name__, exception=str(error), traceback=traceback.format_exc())
        traceback.print_exc()
        return 1
    finally:
        event('suite-terminal', status=report['status'])
        event_file.close()
        after = inventory(SOURCE)
        dump(OUT / 'SOURCE-AFTER.json', after)
        report['source_unchanged'] = after == before
        if after != before:
            report['status'] = 'FAIL'
        report['elapsed_seconds'] = time.monotonic() - started_at
        report['events'] = len(events)
        report['real_observations_saved'] = len(list((OUT / 'controls').glob('case-*/OBSERVATION.json')))
        dump(OUT / 'RUNTIME-AFTER.json', runtime())
        dump(OUT / 'SOURCE-TESTS.json', report)
        print(json.dumps({key: report.get(key) for key in ('status', 'testsRun', 'elapsed_seconds',
              'source_unchanged', 'real_observations_saved', 'events')}, sort_keys=True), flush=True)


def driver():
    require(not OUT.exists(), 'new Source attempt required; no retry')
    OUT.mkdir(parents=True)
    write(OUT / 'RUNNER.py', Path(__file__).read_bytes())
    write(OUT / 'PLAN.json', PLAN_PATH.read_bytes())
    dump(OUT / 'RUNTIME.json', runtime())
    require(shutil.disk_usage(ROOT).free >= 456 * 1024 * 1024, 'Source evidence/formal artifact disk reserve required')
    before = inventory(SOURCE)
    require(tree(before) == PLAN['source_tree'] and len(before) == 3180, 'source tree changed before launch')
    sys.path.insert(0, str(SOURCE))
    from tools.hia_selfhost_process_owner import run_owned
    env = PLAN['environment']
    command = [sys.executable, '-B', str(Path(__file__).resolve()), '--child']
    dump(OUT / 'LAUNCH-INTENT.json', {'command': command, 'cwd': str(SOURCE), 'env': env,
         'supervisor_env': env, 'qualification_seconds': 180, 'cleanup_seconds': 3})
    started = time.monotonic()
    report = {'status': 'FAIL', 'Native': False, 'compile_count': 0, 'cold': False, 'whole': False}
    try:
        returned = run_owned(command, cwd=SOURCE, env=env, supervisor_env=env,
            stdout_path=OUT / 'child.stdout.bin', stderr_path=OUT / 'child.stderr.bin',
            receipt_path=OUT / 'OWNER.json', qualification_seconds=180, cleanup_seconds=3)
        dump(OUT / 'OWNER-RETURNED.json', returned)
        report['owner'] = returned
        raw = (OUT / 'OWNER.json').read_bytes()
        expected = json.loads(raw)
        expected['supervisor_returncode'] = returned.get('supervisor_returncode')
        expected['receipt_sha256'] = hashlib.sha256(raw).hexdigest()
        if expected['supervisor_returncode'] != 0 and expected['status'] == 'OWNED_PROCESS_COMPLETED':
            expected['status'] = 'OWNER_EXIT_MISMATCH_HOLD'
        require(returned == expected, 'complete owner protocol differs')
        passed = (returned['status'] == 'OWNED_PROCESS_COMPLETED' and returned['returncode'] == 0
                  and returned['supervisor_returncode'] == 0 and returned['qualification_seconds'] == 180
                  and returned['cleanup_seconds'] == 3 and returned['timed_out'] is False
                  and returned['exit_observed_before_deadline'] is True
                  and returned['cleanup']['complete'] is True and returned['cleanup']['observed_echild'] is True)
        if (OUT / 'SOURCE-TESTS.json').exists():
            report['tests'] = json.loads((OUT / 'SOURCE-TESTS.json').read_text())
        require(passed and report.get('tests', {}).get('status') == 'PASS', 'Source group failed; no retry')
        report['status'] = 'PASS_SOURCE_NINE_ONLY'
        return 0
    except BaseException as error:
        report.update(exception_type=type(error).__name__, exception=str(error), traceback=traceback.format_exc())
        traceback.print_exc()
        return 1
    finally:
        after = inventory(SOURCE)
        dump(OUT / 'TERMINAL-SOURCE.json', after)
        report['source_unchanged'] = before == after
        if after != before:
            report['status'] = 'FAIL'
        report['elapsed_seconds'] = time.monotonic() - started
        report['free_bytes'] = shutil.disk_usage(ROOT).free
        dump(OUT / 'OUTER.json', report)
        print(json.dumps({key: report.get(key) for key in ('status', 'elapsed_seconds', 'source_unchanged',
              'free_bytes', 'Native', 'compile_count')}, sort_keys=True), flush=True)


if __name__ == '__main__':
    require(sys.argv[1:] in ([], ['--child']), 'unknown execution argument')
    raise SystemExit(child() if sys.argv[1:] else driver())
