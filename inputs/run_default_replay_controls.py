"""Run the separate Source2 on an exact candidate or the unchanged original."""
from pathlib import Path
from hashlib import sha256
import argparse
import importlib.util
import json
import sys
import time
import traceback
import unittest

parser = argparse.ArgumentParser()
parser.add_argument('--source', type=Path, required=True)
parser.add_argument('--test-source', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
root = args.source.resolve(strict=True)
test_source = args.test_source.resolve(strict=True)
out = args.output.absolute()
out.mkdir(mode=0o700, exist_ok=False)
sys.path.insert(0, str(root))

def snapshot():
    return {p.relative_to(root).as_posix(): {'bytes': p.stat().st_size,
            'sha256': sha256(p.read_bytes()).hexdigest(), 'mode': format(p.stat().st_mode & 0o777, '04o')}
            for p in sorted(root.rglob('*')) if p.is_file() and '__pycache__' not in p.parts and p.suffix != '.pyc'}

before = snapshot()
test_before = test_source.read_bytes()
(out / 'source-before.json').write_text(json.dumps(before, sort_keys=True, indent=2) + '\n')
report = {'schema': 'hia.verification.default-replay.source-controls.v1', 'python': sys.version,
          'scope': 'ACTUAL_DEFAULT_REFERENCE_ONLY_NO_NATIVE_SELECTION', 'expected_count': 2,
          'test_source_sha256': sha256(test_before).hexdigest(), 'native_entries': 0,
          'current_cold': False, 'whole_native': False}
start = time.perf_counter_ns()
try:
    spec = importlib.util.spec_from_file_location('tests.test_hia_service_verification_default_replay', test_source)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    suite = unittest.TestLoader().loadTestsFromTestCase(module.ServiceVerificationDefaultReplaySourceTests)
    loaded = [test.id() for test in suite]
    assert len(loaded) == len(set(loaded)) == 2
    class Result(unittest.TextTestResult):
        def startTest(self, test):
            executed.append(test.id())
            super().startTest(test)
    executed = []
    result = unittest.TextTestRunner(verbosity=2, resultclass=Result).run(suite)
    report.update(loaded_ids=loaded, executed_ids=executed, tests_run=result.testsRun,
                  failures=[(test.id(), text) for test, text in result.failures],
                  errors=[(test.id(), text) for test, text in result.errors],
                  skips=[(test.id(), text) for test, text in result.skipped],
                  expected_failures=[(test.id(), text) for test, text in result.expectedFailures],
                  unexpected_successes=[test.id() for test in result.unexpectedSuccesses])
    report['status'] = 'PASS' if (result.wasSuccessful() and result.testsRun == 2 and executed == loaded
        and not result.skipped and not result.expectedFailures and not result.unexpectedSuccesses) else 'FAIL'
except BaseException:
    report.update(status='FAIL', traceback=traceback.format_exc())
finally:
    after = snapshot()
    report.update(source_unchanged=after == before,
                  test_source_unchanged=test_source.read_bytes() == test_before,
                  elapsed_ns=time.perf_counter_ns() - start, source_files=len(before))
    if not report['source_unchanged'] or not report['test_source_unchanged']:
        report['status'] = 'FAIL'
    (out / 'source-after.json').write_text(json.dumps(after, sort_keys=True, indent=2) + '\n')
    (out / 'REPORT.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print(json.dumps({key: report.get(key) for key in ('status', 'tests_run', 'source_unchanged', 'test_source_unchanged', 'elapsed_ns')}))
raise SystemExit(0 if report['status'] == 'PASS' else 1)
