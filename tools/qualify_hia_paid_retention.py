"""Retain a fresh regression attempt without replaying any older cell."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import resource
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument('--output', type=Path, required=True)
parser.add_argument('--expected-commit', required=True)
args = parser.parse_args()
args.output.mkdir(parents=True, exist_ok=False)
fixtures = args.output / 'fixtures'
fixtures.mkdir()
sys.path.insert(0, str(ROOT))
targets = ['tests.test_hia_paid_observation', 'tests.test_hia_paid_observation_retention']
expected_ids = ["tests.test_hia_paid_observation.PaidObservationTests.test_actual_paid_schema_read_changes_real_effect_without_label_input","tests.test_hia_paid_observation.PaidObservationTests.test_expensive_or_unaffordable_information_is_not_free","tests.test_hia_paid_observation.PaidObservationTests.test_failed_read_is_charged_and_does_not_authorize_repair","tests.test_hia_paid_observation.PaidObservationTests.test_full_registered_matrix_keeps_failure_control_and_ndu_not_run","tests.test_hia_paid_observation.PaidObservationTests.test_timed_out_observation_remains_unknown_without_retry","tests.test_hia_paid_observation.PaidObservationTests.test_voi_matches_independent_complete_tree_including_budget_and_stop","tests.test_hia_paid_observation.PaidObservationTests.test_wrong_repair_failure_and_exhausted_budget_stay_in_results","tests.test_hia_paid_observation_retention.PaidObservationRetentionTests.test_calibration_exception_preserves_all_original_databases_and_fee_intents","tests.test_hia_paid_observation_retention.PaidObservationRetentionTests.test_durable_intent_exhausting_deadline_never_dispatches_worker","tests.test_hia_paid_observation_retention.PaidObservationRetentionTests.test_effect_completed_then_evaluator_failure_retains_db_and_prior_cells","tests.test_hia_paid_observation_retention.PaidObservationRetentionTests.test_lost_effect_ack_keeps_original_owner_and_pending_operation","tests.test_hia_paid_observation_retention.PaidObservationRetentionTests.test_source_binding_cannot_change_during_read_only_recovery"]
paths = ['tools/qualify_hia_paid_observation.py', 'tests/test_hia_paid_observation.py',
         'tests/test_hia_paid_observation_retention.py', 'tools/qualify_hia_paid_retention.py',
         '.github/workflows/hia-paid-observation-retention.yml', 'docs/HIA_PAID_OBSERVATION.md',
         'benchmarks/hia_paid_observation/PROTOCOL.json']
source = {}
for name in paths:
    raw = (ROOT / name).read_bytes()
    target = args.output / 'source' / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(raw)
    source[name] = {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}
protocol = json.loads((ROOT / paths[-1]).read_bytes())
assert protocol['wall_budget_ns'] == 2000000000
def identity():
    def git(*args):
        return subprocess.check_output(['git', *args], cwd=ROOT, text=True).strip()
    return {'commit': git('rev-parse', 'HEAD'), 'tree': git('rev-parse', 'HEAD^{tree}'),
            'status': git('status', '--porcelain', '--untracked-files=all')}

source_before = identity()
if source_before['commit'] != args.expected_commit or source_before['status']:
    raise SystemExit('refuse an unexpected or dirty source checkout')
base = source_before['commit']
(args.output / 'source.patch').write_bytes(subprocess.check_output(['git', 'diff', '--binary'], cwd=ROOT))
current_test = None
retained = []
original_temporary_directory = tempfile.TemporaryDirectory

class RetainedDirectory(original_temporary_directory):
    def __init__(self, *positional, **keywords):
        keywords.setdefault('dir', str(fixtures))
        super().__init__(*positional, **keywords)
        self._finalizer.detach()
        retained.append({'test': current_test, 'directory': self.name})
        (args.output / 'fixtures.json').write_text(json.dumps(retained, indent=2) + '\n')

    def cleanup(self):
        pass

class Result(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.executed_test_ids = []

    def startTest(self, test):
        global current_test
        current_test = test.id()
        self.executed_test_ids.append(test.id())
        super().startTest(test)

def inventory(suite):
    ids = []
    for test in suite:
        ids.extend(inventory(test) if isinstance(test, unittest.TestSuite) else [test.id()])
    return ids

loader = unittest.TestLoader()
suite = loader.loadTestsFromNames(targets)
planned = suite.countTestCases()
loaded_ids = sorted(inventory(suite))
state = {'schema': 'hepta.hia.paid-retention-qualification.v1', 'status': 'RUNNING',
         'source_commit': base, 'source_before': source_before,
         'expected_test_ids': expected_ids, 'loaded_test_ids': loaded_ids, 'source': source, 'targets': targets, 'planned_tests': planned,
         'registered_wall_budget_ns': protocol['wall_budget_ns'],
         'fixture_wrapper': 'Only TemporaryDirectory cleanup is disabled; original test bodies and registered protocol are unchanged.',
         'old_job_replayed': False, 'ndu_status': 'NOT_RUN'}
(args.output / 'RUNNING.json').write_text(json.dumps(state, indent=2) + '\n')
started = time.perf_counter_ns()
before = [resource.getrusage(kind) for kind in (resource.RUSAGE_SELF, resource.RUSAGE_CHILDREN)]
tempfile.TemporaryDirectory = RetainedDirectory
try:
    result = unittest.TextTestRunner(verbosity=2, resultclass=Result).run(suite)
finally:
    tempfile.TemporaryDirectory = original_temporary_directory
after = [resource.getrusage(kind) for kind in (resource.RUSAGE_SELF, resource.RUSAGE_CHILDREN)]
source_after = identity()
source_unchanged = all(sha256((ROOT/name).read_bytes()).hexdigest()==value['sha256']
                       for name,value in source.items())
ok = (not loader.errors and loaded_ids == expected_ids
      and sorted(result.executed_test_ids) == expected_ids
      and result.testsRun == 12 and result.wasSuccessful() and not result.skipped
      and not result.expectedFailures and not result.unexpectedSuccesses
      and source_unchanged and source_before == source_after)
state.update(status='PASS' if ok else 'FAIL',
             source_after=source_after, executed_test_ids=result.executed_test_ids,
             loader_errors=loader.errors,
             expected_failures=[(test.id(), detail) for test,detail in result.expectedFailures],
             unexpected_successes=[test.id() for test in result.unexpectedSuccesses],
             tests_run=result.testsRun, skipped=[(test.id(), reason) for test, reason in result.skipped],
             failures=[(test.id(), detail) for test, detail in result.failures],
             errors=[(test.id(), detail) for test, detail in result.errors],
             wall_ns=time.perf_counter_ns()-started,
             parent_cpu_ns=round(((after[0].ru_utime+after[0].ru_stime)-(before[0].ru_utime+before[0].ru_stime))*1e9),
             child_cpu_ns=round(((after[1].ru_utime+after[1].ru_stime)-(before[1].ru_utime+before[1].ru_stime))*1e9),
             original_source_unchanged=source_unchanged,
             retained_fixtures=retained)
(args.output / 'RESULT.json').write_text(json.dumps(state, sort_keys=True, indent=2) + '\n')
print(json.dumps({'status':state['status'], 'tests_run':state['tests_run'], 'failures':len(state['failures']),
                  'errors':len(state['errors']), 'retained_fixtures':len(retained), 'output':str(args.output)}))
raise SystemExit(0 if state['status']=='PASS' else 1)
