"""Development observation of existing ordinary request-worker callers."""
from pathlib import Path
import json
import os
import sys
import time
import unittest
from unittest.mock import patch

from hepta import hia_agent_worker as worker
from hepta.hia_worker_report_native import WorkerSession, SELECTOR

ROOT = Path('/workspace/scratch/e26ed3e2edcf')
os.environ[SELECTOR] = str(ROOT / 'worker-report-development-r1/manifest.json')
os.environ['HEPTA_HIA_WORKER_REQUEST_DEVELOPMENT_MANIFEST'] = str(ROOT / 'worker-report-request-composition-r1/manifest.json')
suite = unittest.defaultTestLoader.loadTestsFromName('tests.test_hia_worker_request_native.WorkerRequestNativeTests')
def ids(suite):
    for test in suite:
        if isinstance(test, unittest.TestSuite):
            yield from ids(test)
        else:
            yield test.id()
loaded = list(ids(suite))
current = None
entered = {}
original = WorkerSession.step
def step(session, packet=None):
    entered[current] = entered.get(current, 0) + 1
    return original(session, packet)
class Result(unittest.TextTestResult):
    def startTest(self, test):
        global current
        current = test.id()
        super().startTest(test)
start = time.monotonic()
with patch.object(worker, '_reference_run', side_effect=AssertionError('retained report owner entered')), patch.object(WorkerSession, 'step', step):
    result = unittest.TextTestRunner(verbosity=2, resultclass=Result).run(suite)
ordinary = [name for name in loaded if not name.endswith('test_installed_wheel_resource_and_request_without_authoring_modules')]
passed = bool(loaded) and result.testsRun == len(loaded) and result.wasSuccessful() and not any((result.skipped, result.expectedFailures, result.unexpectedSuccesses)) and all(entered.get(name, 0) for name in ordinary)
record = {'schema': 'hia.worker-report-existing-callers-observation.v1', 'scope': 'EXPLICIT_DEVELOPMENT_ONLY_NOT_COLD',
          'status': 'PASS' if passed else 'FAIL', 'loaded_test_ids': loaded, 'executed_test_ids': loaded,
          'tests_run': result.testsRun, 'failures': len(result.failures), 'errors': len(result.errors),
          'skipped': len(result.skipped), 'expected_failures': len(result.expectedFailures),
          'unexpected_successes': len(result.unexpectedSuccesses), 'entered_native_policy_steps': entered,
          'ordinary_entry_ids': ordinary,
          'non_worker_entry_id': 'tests.test_hia_worker_request_native.WorkerRequestNativeTests.test_installed_wheel_resource_and_request_without_authoring_modules',
          'retained_report_owner_forbidden': True, 'development_exclusions': [],
          'executable': sys.executable, 'python': sys.version, 'wall_seconds': time.monotonic() - start}
(ROOT / 'worker-report-existing-callers-r1.json').write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
raise SystemExit(0 if passed else 1)
