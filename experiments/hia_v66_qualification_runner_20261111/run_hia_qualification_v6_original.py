"""Run complete source-bound gates with all retained prerequisites and v65 owners.

Component completion and a complete retained regression have different statuses.
The unchanged external guardian spans preparation and this runner. Cold replay
retains its existing 180-second owner and subreaper/ECHILD cleanup proof.
The compatible v5 report schema is retained for the byte-identical guardian;
harness_revision v6 records the additional mandatory gates and their outcomes.
"""
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import workflow_process
import qualification_prerequisites

p = argparse.ArgumentParser()
p.add_argument('--source', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
p.add_argument('--full', action='store_true')
p.add_argument('--prerequisite-environment', type=Path, required=True)
p.add_argument('--prerequisite-report', type=Path, required=True)
a = p.parse_args()
root = a.source.resolve(); out = a.output.resolve()
if out == root or out.is_relative_to(root):
    raise ValueError('qualification output must be outside the pinned source tree')
out.mkdir(parents=True, exist_ok=False)
os.chdir(root)
sys.path.insert(0, str(root))
from tools import hia_core_source_identity as source_identity
from tools.hia_selfhost_contract import validate_contract, CONTRACT_PATH


def _pinned_state():
    # This interface takes no root argument. Its ROOT and _git default root
    # belong to the module imported from the requested candidate checkout.
    if source_identity.ROOT.resolve() != root:
        raise ValueError('source identity helper belongs to another checkout')
    state = source_identity._source_state()
    if state['status']:
        raise ValueError('qualification requires a clean complete source checkout')
    return state


def file_record(path):
    return {'path': str(path), 'sha256': sha256(path.read_bytes()).hexdigest()}


source_before = _pinned_state()
source_before_path = out / 'source-before.json'
source_before_path.write_text(json.dumps(source_before, indent=2, sort_keys=True) + '\n')
sources = source_before['files']
contract = validate_contract()
cold_sources = {**contract['source_identity']['files'],
                CONTRACT_PATH: sha256((root / CONTRACT_PATH).read_bytes()).hexdigest()}
if any(sources.get(path) != digest for path, digest in cold_sources.items()):
    raise ValueError('cold source closure differs from the pinned complete Git source')
harness_paths = {'runner': Path(__file__).resolve(),
                 'workflow_process': Path(workflow_process.__file__).resolve(),
                 'qualification_prerequisites': Path(qualification_prerequisites.__file__).resolve()}
if harness_paths['workflow_process'] != harness_paths['runner'].with_name('workflow_process.py'):
    raise ValueError('workflow supervisor must be adjacent to this qualification runner')
if harness_paths['qualification_prerequisites'] != harness_paths['runner'].with_name('qualification_prerequisites.py'):
    raise ValueError('prerequisite admission must be adjacent to this qualification runner')
harness_before = {name: file_record(path) for name, path in harness_paths.items()}
(out / 'harness-before.json').write_text(json.dumps(harness_before, indent=2, sort_keys=True) + '\n')
run_workflow_step = workflow_process.run_workflow_step
environment, prerequisite_admission = qualification_prerequisites.admit(
    root, a.prerequisite_environment, a.prerequisite_report, sys.executable, dict(os.environ), out)
(out / 'prerequisite-admission.json').write_text(
    json.dumps(prerequisite_admission, indent=2, sort_keys=True) + '\n')
environment['PYTHONDONTWRITEBYTECODE'] = '1'
environment['PYTHONUNBUFFERED'] = '1'
development_selectors = ('HEPTA_HIA_AGENT_CANDIDATE_DEVELOPMENT_MANIFEST',
                         'HEPTA_HIA_COMPOSITE_TYPES_DEVELOPMENT_MANIFEST',
                         'HEPTA_HIA_COMPOSITE_FUNCTIONS_DEVELOPMENT_MANIFEST',
                         'HEPTA_HIA_COMPOSITE_CONSTRUCTOR_DEVELOPMENT_MANIFEST',
                         'HEPTA_HIA_COMPOSITE_OUTER_DEVELOPMENT_MANIFEST',
                         'HEPTA_HIA_WORKER_REQUEST_DEVELOPMENT_MANIFEST',
                         'HEPTA_HIA_TASK_HELPERS_DEVELOPMENT_MANIFEST',
                         'HEPTA_HIA_AGENT_JOURNAL_DEVELOPMENT_MANIFEST')
discarded_development_selectors = [name for name in development_selectors if name in environment]
for development_selector in development_selectors:
    environment.pop(development_selector, None)
cold = out / 'cold.json'
for name in ('AGENT_STDIO', 'CORE_MODULE_GRAPH', 'CAPABILITY_RENAMING',
             'FUNCTION_SHAPE', 'PROGRAM_SHAPE', 'INSTRUCTION_POLICY',
             'ARTIFACT_PUBLICATION', 'CORE_ADMISSION', 'CORE_ADMISSION_CLI',
             'CORE_PATCH', 'CORE_PATCH_CLI', 'CORE_PATCH_RESULT_CLI', 'COMPOSITE_TYPES',
             'WORKER_REQUEST', 'RELEASE_INSTALL', 'TASK_HELPERS', 'AGENT_JOURNAL',
             'COMPOSITE_FUNCTIONS', 'COMPOSITE_CONSTRUCTOR', 'COMPOSITE_OUTER'):
    environment['HEPTA_HIA_' + name + '_COLD_REPORT'] = str(cold)
steps = []
suite_outcomes = {}
caller_outcome = {'completed': False, 'passed': False, 'executed': False}


def run(name, args, *, timeout=1800):
    started = time.monotonic()
    stdout = out / (name + '.stdout.log')
    stderr = out / (name + '.stderr.log')
    result = {'name': name, 'command': [sys.executable, '-B', *args]}
    print(json.dumps({'starting': name}), flush=True)
    step_environment = dict(environment)
    step_environment['HEPTA_HIA_CORE_MODULE_GRAPH_OBSERVATIONS'] = str(out / (name + '-module-projects'))
    step_environment['HEPTA_HIA_RELEASE_INSTALL_OBSERVATIONS'] = str(out / (name + '-release-install'))
    step_environment['HEPTA_RAW_MODEL_TRANSCRIPT'] = str(out / (name + '-raw-model-transcript.jsonl'))
    step_environment['HEPTA_NDU_BOUNDARY_EVIDENCE'] = str(out / (name + '-ndu-boundary-evidence'))
    step_environment['HEPTA_HIA_COMPOSITE_FIXTURE_EVIDENCE'] = str(out / (name + '-composite-fixtures'))
    result['composite_fixture_evidence'] = step_environment['HEPTA_HIA_COMPOSITE_FIXTURE_EVIDENCE']
    owner = run_workflow_step(result['command'], cwd=root, env=step_environment,
                      stdout_path=stdout, stderr_path=stderr,
                      receipt_path=out / (name + '.owner.json'),
                      seconds=timeout)
    result['owner'] = owner
    result['returncode'] = owner.get('returncode')
    result['timeout'] = owner.get('timed_out') is not False
    result['seconds'] = time.monotonic() - started
    result['stdout'] = {'path': str(stdout), 'sha256': sha256(stdout.read_bytes()).hexdigest()}
    result['stderr'] = {'path': str(stderr), 'sha256': sha256(stderr.read_bytes()).hexdigest()}
    result['passed'] = (result['returncode'] == 0 and not result['timeout']
                       and owner.get('status') == 'WORKFLOW_STEP_COMPLETED'
                       and owner.get('cleanup', {}).get('complete') is True)
    steps.append(result)
    (out / 'steps.json').write_text(json.dumps(steps, indent=2) + '\n')
    print(json.dumps({k: result[k] for k in ('name', 'returncode', 'timeout', 'seconds')}), flush=True)
    return result['passed']


def suite(name, names=None, discover=False):
    result_path = out / (name + '.json')
    source = '''import json,unittest
loader=unittest.defaultTestLoader
suite=loader.discover('tests',top_level_dir='.') if DISCOVER else loader.loadTestsFromNames(NAMES)
def flatten(group):
    for test in group:
        if isinstance(test,unittest.TestSuite):
            yield from flatten(test)
        else:
            yield test
tests=list(flatten(suite))
loaded=[test.id() for test in tests]
executed=[]
class Result(unittest.TextTestResult):
    def startTest(self,test):
        executed.append(test.id())
        super().startTest(test)
r=unittest.TextTestRunner(verbosity=2,resultclass=Result).run(unittest.TestSuite(tests))
value={'tests_run':r.testsRun,'successful':r.wasSuccessful(),
       'expected_test_count':len(loaded),'loaded_test_ids':loaded,
       'executed_test_ids':executed,
       'errors':[{'test':str(t),'traceback':s} for t,s in r.errors],
       'failures':[{'test':str(t),'traceback':s} for t,s in r.failures],
       'skipped':[{'test':str(t),'reason':s} for t,s in r.skipped],
       'expected_failures':[str(t) for t,s in r.expectedFailures],
       'unexpected_successes':[str(t) for t in r.unexpectedSuccesses]}
open(RESULT,'w').write(json.dumps(value,indent=2)+'\\n')
raise SystemExit(0 if r.testsRun > 0 and r.testsRun==len(loaded) and loaded==executed
                 and r.wasSuccessful() and not r.skipped and not r.expectedFailures
                 and not r.unexpectedSuccesses else 1)
'''
    code = 'DISCOVER=' + repr(discover) + '\nNAMES=' + repr(names or []) + '\nRESULT=' + repr(str(result_path)) + '\n' + source
    completed = run(name, ['-c', code], timeout=5400 if discover else 1800)
    outcome = {'completed': completed, 'passed': False, 'discovery': discover}
    try:
        value = json.loads(result_path.read_text())
        outcome['result'] = file_record(result_path)
        outcome['tests_run'] = value.get('tests_run')
        loaded = value.get('loaded_test_ids')
        executed = value.get('executed_test_ids')
        expected_count = value.get('expected_test_count')
        complete_ids = (type(loaded) is list and bool(loaded)
                        and all(type(name) is str for name in loaded)
                        and loaded == executed and type(expected_count) is int
                        and expected_count == len(loaded) == value.get('tests_run'))
        outcome['expected_test_count'] = expected_count
        outcome['exact_loaded_executed_ids'] = complete_ids
        outcome['passed'] = (completed and type(value.get('tests_run')) is int
                             and value['tests_run'] > 0 and value.get('successful') is True
                             and complete_ids
                             and all(value.get(key) == [] for key in (
                                 'errors', 'failures', 'skipped',
                                 'expected_failures', 'unexpected_successes')))
    except (OSError, ValueError, AttributeError) as error:
        outcome['result_error'] = repr(error)
    suite_outcomes[name] = outcome
    steps[-1]['suite_result'] = outcome
    steps[-1]['passed'] = outcome['passed']
    (out / 'steps.json').write_text(json.dumps(steps, indent=2) + '\n')
    return outcome['passed']


CALLER_MODULES = (
    'tests.test_hia_agent_native_tools',
    'tests.test_hia_agent_native_proof_contract',
    'tests.test_hia_agent_native_lease_snapshot',
    'tests.test_hia_agent_native_machine_choices',
    'tests.test_hia_agent_native_campaign',
    'tests.test_hia_agent_candidate_native',
    'tests.test_hia_worker_request_native',
    'tests.test_hia_worker_request_review',
)


def selected_journal_callers():
    path = out / 'journal-selected-callers.json'
    command = ['tools/qualify_hia_agent_journal_callers.py',
               '--cold-report', str(cold), '--output', str(path)]
    for name in CALLER_MODULES:
        command.extend(['--module', name])
    completed = run('journal-selected-callers', command)
    outcome = {'completed': completed, 'passed': False, 'executed': True,
               'modules': list(CALLER_MODULES)}
    try:
        value = json.loads(path.read_bytes())
        loaded = value.get('loaded_test_ids')
        chosen = value.get('chosen_test_ids')
        executed = value.get('executed_test_ids')
        count = value.get('tests_run')
        if not (value.get('schema') == 'hepta.hia.agent-journal-selected-callers.v1'
                and value.get('status') == 'PASS'
                and value.get('scope') == 'MATCHING_SOURCE_COLD_SELECTED_CALLERS'
                and type(loaded) is list and bool(loaded)
                and all(type(name) is str for name in loaded)
                and len(set(loaded)) == len(loaded)
                and loaded == chosen == executed
                and type(count) is int and count > 0
                and count == len(loaded) == value.get('tests_loaded') == value.get('tests_chosen')
                and all(value.get(key) == [] for key in (
                    'failures', 'errors', 'skipped', 'expected_failures', 'unexpected_successes'))
                and value.get('explicit_development_exclusions') == {}
                and value.get('retained_call_owner_forbidden') is True
                and value.get('all_eleven_tools_entered_selected_driver') is True
                and type(value.get('actual_native_stage_returns')) is dict
                and bool(value['actual_native_stage_returns'])
                and all(type(n) is int and n > 0 for n in value['actual_native_stage_returns'].values())
                and all(any(test.startswith(module + '.') for test in loaded)
                        for module in CALLER_MODULES)
                and all(any(test.startswith(module + '.') for module in CALLER_MODULES)
                        for test in loaded)):
            raise ValueError('journal caller gate lacks complete native-selected test evidence')
        sources = value.get('source_sha256')
        if not isinstance(sources, dict) or not sources or any(
                not isinstance(name, str) or sources[name] != source_before['files'].get(name)
                for name in sources):
            raise ValueError('journal caller report differs from the tested source')
        outcome.update(passed=completed, tests_run=count, result=file_record(path),
                       retained_owner_forbidden=True, all_eleven_tools_observed=True,
                       exact_loaded_chosen_executed_ids=True)
    except (OSError, ValueError, KeyError, TypeError) as error:
        outcome['result_error'] = repr(error)
    steps[-1]['selected_caller_result'] = outcome
    steps[-1]['passed'] = outcome['passed']
    (out / 'steps.json').write_text(json.dumps(steps, indent=2) + '\n')
    return outcome


workflow = (root / '.github/workflows/hia-core.yml').read_text()
blocks = re.findall(r'          names = \((.*?)\n          \)', workflow, re.S)
if len(blocks) != 2:
    raise ValueError('expected both source and native workflow test-name groups')
named = [re.findall(r"'(tests\.[^']+)'", block) for block in blocks]
if not all(named):
    raise ValueError('workflow test-name groups must not be empty')
generator_match = re.search(r'for component in ([^;]+); do', workflow)
if generator_match is None:
    raise ValueError('workflow source-generator list is missing')
generators = generator_match.group(1).split()
if not generators or not all(re.fullmatch(r'[a-z0-9_]+', name) for name in generators):
    raise ValueError('workflow source-generator list is invalid')
reproduction = out / 'source-reproduction'
reproduction_report = out / 'source-reproduction.json'
reproduce_code = '''from pathlib import Path
from hashlib import sha256
import json,os,subprocess,sys
expected_raw=Path(EXPECTED).read_bytes()
if sha256(expected_raw).hexdigest()!=EXPECTED_SHA256:
    raise SystemExit('pinned source snapshot changed before source reproduction')
expected=json.loads(expected_raw)
subprocess.run(['git','--no-replace-objects','clone','--quiet','--no-hardlinks',
                '--no-checkout',SOURCE,COPY],check=True)
subprocess.run(['git','--no-replace-objects','-C',COPY,'checkout','--quiet',
                '--detach',expected['head']],check=True)
os.chdir(COPY)
sys.path.insert(0,COPY)
from tools.hia_core_source_identity import ROOT,_source_state
if ROOT.resolve()!=Path(COPY).resolve():
    raise SystemExit('reproduction identity helper belongs to another checkout')
before=_source_state()
if before!=expected or before['status']:
    raise SystemExit('reproduction copy differs from the pinned HEAD/tree/blob/mode snapshot')
for name in GENERATORS:
    print(json.dumps({'generator':name}),flush=True)
    subprocess.run([sys.executable,'-B','-m','tools.generate_hia_'+name],cwd=COPY,check=True)
subprocess.run([sys.executable,'-B','tests/test_hia_selfhost_language_coverage.py','--generate-inventory'],cwd=COPY,check=True)
after=_source_state()
if after!=expected or after['status']:
    raise SystemExit('generated source differs from the pinned HEAD/tree/blob/mode snapshot')
receipt={'schema':'hepta.hia.complete-source-reproduction.v1',
         'status':'SOURCE_REPRODUCTION_PASS','generators':GENERATORS,
         'expected_snapshot_sha256':EXPECTED_SHA256,
         'before':before,'after':after,'identical_to_tested_source':True,
         'raw_git_tree_blobs_and_modes_checked':True}
Path(RESULT).write_text(json.dumps(receipt,indent=2,sort_keys=True)+'\\n')
print(json.dumps({'generators':len(GENERATORS),'head':after['head'],
                  'tree':after['tree'],'identical_to_tested_source':True}),flush=True)
'''
reproduce_code = ('SOURCE=' + repr(str(root)) + '\nCOPY=' + repr(str(reproduction))
                  + '\nEXPECTED=' + repr(str(source_before_path))
                  + '\nEXPECTED_SHA256=' + repr(file_record(source_before_path)['sha256'])
                  + '\nRESULT=' + repr(str(reproduction_report))
                  + '\nGENERATORS=' + repr(generators) + '\n' + reproduce_code)
ok = run('source-reproduction', ['-c', reproduce_code])
ok = run('source-contract', ['tools/generate_hia_selfhost_contract.py', '--check']) and ok
ok = run('source-scope', ['tools/check_hia_core_only.py']) and ok
ok = suite('source-tests', named[0]) and ok
cold_completed = run('cold', ['tools/replay_hia_selfhost_cold.py', '--output', str(cold)], timeout=240)
cold_error = None
try:
    record = json.loads(cold.read_text())
    cold_ok = (cold_completed and record.get('status') == 'COLD_SELFHOST_REPLAY_PASS'
               and isinstance(record.get('checks'), dict) and bool(record['checks'])
               and all(value is True for value in record['checks'].values())
               and record.get('source_manifest') == cold_sources)
except (OSError, ValueError, AttributeError) as error:
    cold_error = repr(error)
    cold_ok = False
ok = cold_ok and ok
if cold_ok:
    ok = run('language', ['tests/test_hia_selfhost_language_coverage.py', '--output', str(out / 'language.json')]) and ok
    ok = suite('native-applications', named[1]) and ok
    groups = {
        'module-graph': ['tests.test_hia_core_module_graph_native'],
        'workspace': ['tests.test_hia_core_workspace_json_native', 'tests.test_hia_core_workspace_json_cli', 'tests.test_hia_core_workspace_pipeline'],
        'capability': ['tests.test_hia_capability_renaming_native'],
        'workspace-facts': ['tests.test_hia_core_workspace_facts_native', 'tests.test_hia_core_workspace_materialize_native'],
        'function-shape': ['tests.test_hia_function_shape_native'],
        'program-shape': ['tests.test_hia_program_shape_native'],
        'instruction-policy': ['tests.test_hia_instruction_policy_native'],
        'publication': ['tests.test_hia_artifact_publication_native', 'tests.test_hia_artifact_publication_route', 'tests.test_hia_agent_artifact_store_native'],
        'core-admission': ['tests.test_hia_core_admission_native'],
        'core-cli': ['tests.test_hia_core_admission_cli'],
        'patch': ['tests.test_hia_core_patch_native', 'tests.test_hia_core_patch_cli'],
        'agent-candidate': ['tests.test_hia_agent_candidate_native'],
        'patch-result-cli': ['tests.test_hia_core_patch_result_cli'],
        'composite-types': ['tests.test_hia_composite_types_native',
                            'tests.test_hia_composite_origins_native',
                            'tests.test_hia_composite_signatures_native',
                            'tests.test_hia_task_helpers_native',
                            'tests.test_hia_composite_native_composition',
                            'tests.test_hia_composite_function_tokens',
                            'tests.test_hia_composite_function_admission',
                            'tests.test_hia_composite_function_protocol_audit',
                            'tests.test_hia_composite_function_terms_native',
                            'tests.test_hia_composite_functions_native',
                            'tests.test_hia_composite_public_lifecycle',
                            'tests.test_hia_composite_constructor_native',
                            'tests.test_hia_composite_constructor_integration',
                            'tests.test_hia_composite_outer_native',
                            'tests.test_hia_composite_outer_integration',
                            'tests.test_hia_composite_nominal_lifecycle'],
        'worker-request': ['tests.test_hia_worker_request_native',
                           'tests.test_hia_worker_request_review'],
        'release-install': ['tests.test_hia_release_install'],
        'json-preflight': ['tests.test_hia_json_preflight_native'],
        'agent-journal': ['tests.test_hia_agent_journal_native'],
    }
    for name, names in groups.items():
        ok = suite(name, names) and ok
    caller_outcome = selected_journal_callers()
    ok = caller_outcome['passed'] and ok
    if a.full:
        ok = suite('full-retained-regression', discover=True) and ok
try:
    source_after = _pinned_state()
    preserved = source_after == source_before
except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
    source_after = {'error': repr(error)}
    preserved = False
source_after_path = out / 'source-after.json'
source_after_path.write_text(json.dumps(source_after, indent=2, sort_keys=True) + '\n')
harness_after = {}
for name, path in harness_paths.items():
    try:
        harness_after[name] = file_record(path)
    except OSError as error:
        harness_after[name] = {'path': str(path), 'error': repr(error)}
harness_preserved = harness_after == harness_before
try:
    prerequisite_after = qualification_prerequisites.recheck(prerequisite_admission)
    prerequisites_preserved = True
except (OSError, ValueError, KeyError, TypeError) as error:
    prerequisite_after = {'status': 'PREREQUISITE_IDENTITY_HOLD', 'error': repr(error)}
    prerequisites_preserved = False
(out / 'prerequisite-after.json').write_text(
    json.dumps(prerequisite_after, indent=2, sort_keys=True) + '\n')
mandatory_gates = {
    'source_bound_prerequisites_admitted': prerequisite_admission['status']
        == 'CURRENT_SOURCE_PREREQUISITES_ADMITTED_NOT_TEST_PASS',
    'prerequisites_preserved': prerequisites_preserved,
    'json_preflight_complete_module': suite_outcomes.get('json-preflight', {}).get('passed') is True,
    'agent_journal_source_and_native': suite_outcomes.get('agent-journal', {}).get('passed') is True,
    'composite_types_helpers_and_complete_nominal_lowering':
        suite_outcomes.get('composite-types', {}).get('passed') is True,
    'journal_selected_ordinary_callers': caller_outcome['passed'] is True,
}
all_passed = ok and preserved and harness_preserved and all(mandatory_gates.values())
full_outcome = suite_outcomes.get('full-retained-regression')
full_qualified = bool(a.full and full_outcome and full_outcome['passed'] and all_passed)
status = ('FULL_RETAINED_PASS' if full_qualified else
          'COMPONENTS_PASS' if all_passed and not a.full else 'HOLD')
result = {'schema': 'hepta.hia.native-rewrite-qualification.v5',
          'harness_revision': 'v6',
          'compatible_schema_reason': 'byte-identical reviewed external guardian',
          'status': status, 'source_manifest': sources,
          'source_identity': {'head': source_before['head'], 'tree': source_before['tree'],
                              'before': file_record(source_before_path),
                              'after': file_record(source_after_path),
                              'raw_git_tree_blobs_and_modes_checked': True},
          'source_reproduction': file_record(reproduction_report) if reproduction_report.exists() else None,
          'cold_source_manifest': cold_sources, 'cold_qualified': cold_ok,
          'cold_report': file_record(cold) if cold.exists() else None,
          'cold_error': cold_error,
          'source_preserved': preserved, 'steps': steps,
          'harness_identity_before': harness_before, 'harness_identity_after': harness_after,
          'harness_preserved': harness_preserved,
          'mandatory_v6_gates': mandatory_gates,
          'journal_selected_callers': caller_outcome,
          'prerequisites': {'admission': file_record(out / 'prerequisite-admission.json'),
                            'after': file_record(out / 'prerequisite-after.json'),
                            'preserved': prerequisites_preserved},
          'discarded_development_selectors': discarded_development_selectors,
          'whole_native_delivery_qualified': False,
          'full_retained_regression_requested': a.full,
          'full_retained_regression_executed': full_outcome is not None,
          'full_retained_regression_qualified': full_qualified,
          'full_retained_regression': full_outcome}
(out / 'QUALIFICATION.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
print(json.dumps({'status': result['status'], 'steps': len(steps), 'source_preserved': preserved}), flush=True)
raise SystemExit(0 if result['status'] in {'COMPONENTS_PASS', 'FULL_RETAINED_PASS'} else 1)
