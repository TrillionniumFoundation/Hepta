"""Execute the union's new Source controls and original shared-resource gates."""
from __future__ import annotations

from collections import Counter
import importlib.util
import json
import os
from pathlib import Path
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / 'local-source-r1'
TREE = '91896bc788b306a44db3b1016a2ebcc140f2e121'
DRIVER = ROOT / 'harness/tools/materialize_candidate_r11.py'


def child():
    import unittest
    sys.path.insert(0, str(SOURCE))
    plan = json.loads((ROOT / 'harness/inputs/MATERIALIZATION-R5.json').read_bytes())
    registration = plan['source_registration']
    selected = registration['selectors'][-7:] + [
        'tests.test_hia_installed_fixture_resources.InstalledFixtureRoleInventoryTests',
        'tests.test_hia_agent_installed_resources.AgentInstalledResourceSourceTests',
        'tests.test_hia_candidate_preflight',
        'tests.test_hia_retained_agent_callers.RetainedAgentCallerSourceTests',
    ]
    def ids(suite):
        result = []
        for item in suite:
            result.extend(ids(item) if isinstance(item, unittest.TestSuite) else [item.id()])
        return result
    loader = unittest.TestLoader()
    complete = loader.loadTestsFromNames(registration['selectors'])
    all_ids = ids(complete)
    complete_errors = list(loader.errors)
    frozen = json.loads((ROOT / 'harness/inputs/ORIGINAL-SOURCE-IDS.json').read_bytes())
    def mapped(name):
        matches = [prefix for prefix in registration['selector_renames']
                   if name == prefix or name.startswith(prefix + '.')]
        if not matches:
            return name
        prefix = max(matches, key=len)
        return registration['selector_renames'][prefix] + name[len(prefix):]
    missing_main = list((Counter(frozen['main']['ids']) - Counter(all_ids)).elements())
    missing_dev = list((Counter(map(mapped, frozen['a733']['ids'])) - Counter(all_ids)).elements())
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromNames(selected)
    expected = ids(suite)
    selection_errors = list(loader.errors)
    output = Path(os.environ['HIA_JOINT_SOURCE_REPORT'])
    discovery = {'all_selectors': registration['selectors'], 'all_loaded_ids': all_ids,
        'all_loaded_count': len(all_ids), 'all_loader_errors': complete_errors,
        'all_duplicate_ids': {k: v for k, v in Counter(all_ids).items() if v != 1},
        'missing_frozen_main': missing_main, 'missing_frozen_development': missing_dev,
        'executed_selectors': selected, 'expected_ids': expected,
        'expected': len(expected), 'selection_loader_errors': selection_errors,
        'complete_source_suite_executed': False}
    output.with_name('DISCOVERY.json').write_text(json.dumps(discovery, indent=2, sort_keys=True) + '\n')
    assert len(all_ids) == len(set(all_ids)) == 1224
    assert not (complete_errors or selection_errors or missing_main or missing_dev)
    assert len(expected) == len(set(expected)) == 77
    assert set(expected) <= set(all_ids)
    events = output.with_suffix('.events.jsonl').open('x')
    class Result(unittest.TextTestResult):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.started_ids = []
            self.stopped_ids = []
        def startTest(self, test):
            self.started_ids.append(test.id())
            events.write(json.dumps({'event': 'start', 'id': test.id()}) + '\n')
            events.flush()
            super().startTest(test)
        def stopTest(self, test):
            self.stopped_ids.append(test.id())
            events.write(json.dumps({'event': 'stop', 'id': test.id()}) + '\n')
            events.flush()
            super().stopTest(test)
    started = time.monotonic()
    try:
        result = unittest.TextTestRunner(verbosity=2, resultclass=Result).run(suite)
    finally:
        events.close()
    complete = (result.testsRun == len(expected) and result.started_ids == expected
                and result.stopped_ids == expected)
    clean = not (result.errors or result.failures or result.skipped
                 or result.expectedFailures or result.unexpectedSuccesses)
    report = {**discovery, 'status': 'PASS' if complete and clean and result.wasSuccessful() else 'FAIL',
        'scope': 'LOCAL312_JOINT_SOURCE77_NOT_COMPLETE_SOURCE_OR_NATIVE_QUALIFICATION',
        'python': sys.version, 'source_tree': TREE, 'tests_run': result.testsRun,
        'actual_started_ids': result.started_ids, 'actual_stopped_ids': result.stopped_ids,
        'complete': complete, 'elapsed_seconds': time.monotonic() - started,
        'errors': [{'id': t.id(), 'traceback': trace} for t, trace in result.errors],
        'failures': [{'id': t.id(), 'traceback': trace} for t, trace in result.failures],
        'skipped': [{'id': t.id(), 'reason': reason} for t, reason in result.skipped],
        'expected_failures': [{'id': t.id(), 'traceback': trace} for t, trace in result.expectedFailures],
        'unexpected_successes': [t.id() for t in result.unexpectedSuccesses],
        'whole_native': False}
    with output.open('x') as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write('\n')
    print(json.dumps({k: report[k] for k in ('status', 'scope', 'expected', 'tests_run', 'elapsed_seconds')}))
    return 0 if report['status'] == 'PASS' else 1


def parent():
    spec = importlib.util.spec_from_file_location('r11_fixed_supervisor', DRIVER)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    raw = DRIVER.read_bytes()
    assert m.oid('blob', raw) == 'c63dec1726b9c9ac3d67147abd479583ea0b644e'
    capture = m.Capture(ROOT / 'joint-source-controls-r1', '')
    capture.basic = ''
    capture.repo = SOURCE
    capture.put('harness/DRIVER.py', raw)
    capture.put('harness/JOINT-SOURCE-CONTROLS.py', Path(__file__).read_bytes())
    evidence = capture.raw / 'vm-buffers'
    evidence.mkdir(exist_ok=False)
    report = capture.raw / 'JOINT-SOURCE-TESTS.json'
    capture.env['HEPTA_HIA_CANDIDATE_BUILD_TEST_EVIDENCE'] = str(evidence)
    capture.env['HIA_JOINT_SOURCE_REPORT'] = str(report)
    result = {'status': 'RUNNING', 'scope': 'LOCAL312_SOURCE77_DEVELOPMENT_ONLY',
              'source_tree': TREE, 'started_at': m.now(), 'whole_native': False, 'failures': []}
    try:
        m.assert_current_tree(capture, TREE, 'before-joint-source77')
        _, process = m.python_command(capture, [str(Path(__file__).resolve()), '--child'],
            'joint-source77', limit=1800, enforce=False, local_git_fixture=True)
        result['process'] = process
        if report.is_file():
            result['tests'] = m.strict_json(report.read_bytes())
        m.assert_current_tree(capture, TREE, 'after-joint-source77')
        result['source_unchanged'] = True
        result['status'] = ('PASS' if process['returncode'] == 0 and not process['timed_out']
                            and result.get('tests', {}).get('status') == 'PASS' else 'FAIL')
    except BaseException as error:
        result['status'] = 'FAIL'
        result['failures'].append({'type': type(error).__name__, 'error': str(error),
                                   'traceback': traceback.format_exc()})
    result['finished_at'] = m.now()
    capture.json('RESULT.json', result)
    print(json.dumps({k: v for k, v in result.items() if k not in ('tests', 'process')}, sort_keys=True))
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(child() if sys.argv[1:] == ['--child'] else parent())
