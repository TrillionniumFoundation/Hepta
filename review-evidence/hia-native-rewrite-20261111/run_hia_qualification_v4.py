"""Run unchanged gates with pinned complete-source and per-step evidence.

Component completion and a complete retained regression have different statuses.
The external supervisor owns only its POSIX process group; cold replay retains
its existing 180-second owner and its separate subreaper/ECHILD cleanup proof.
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

p = argparse.ArgumentParser()
p.add_argument('--source', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
p.add_argument('--full', action='store_true')
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
                 'workflow_process': Path(workflow_process.__file__).resolve()}
if harness_paths['workflow_process'] != harness_paths['runner'].with_name('workflow_process.py'):
    raise ValueError('workflow supervisor must be adjacent to this qualification runner')
if harness_paths['runner'] != root / 'review-evidence/hia-native-rewrite-20261111/run_hia_qualification_v4.py':
    raise ValueError('qualification runner must belong to the pinned complete source checkout')
for path in harness_paths.values():
    if not path.is_relative_to(root) or sources.get(path.relative_to(root).as_posix()) != sha256(path.read_bytes()).hexdigest():
        raise ValueError('qualification harness differs from the pinned complete Git source')
harness_before = {name: file_record(path) for name, path in harness_paths.items()}
(out / 'harness-before.json').write_text(json.dumps(harness_before, indent=2, sort_keys=True) + '\n')
run_workflow_step = workflow_process.run_workflow_step
environment = dict(os.environ)
environment['PYTHONDONTWRITEBYTECODE'] = '1'
environment['PYTHONUNBUFFERED'] = '1'
development_selectors = ('HEPTA_HIA_AGENT_CANDIDATE_DEVELOPMENT_MANIFEST',
                         'HEPTA_HIA_COMPOSITE_TYPES_DEVELOPMENT_MANIFEST',
                         'HEPTA_HIA_TASK_HELPERS_DEVELOPMENT_MANIFEST',
                         'HEPTA_HIA_COMPOSITE_FUNCTIONS_DEVELOPMENT_MANIFEST',
                         'HEPTA_HIA_COMPOSITE_CONSTRUCTOR_DEVELOPMENT_MANIFEST',
                         'HEPTA_HIA_COMPOSITE_OUTER_DEVELOPMENT_MANIFEST',
                         'HEPTA_HIA_SOURCE_BUILD_DEVELOPMENT_MANIFEST',
                         'HEPTA_HIA_EXECUTION_BUDGET_DEVELOPMENT_COMPILER',
                         'HEPTA_HIA_WORKER_HELPERS_DEVELOPMENT_MANIFEST',
                         'HEPTA_HIA_WORKER_REQUEST_DEVELOPMENT_MANIFEST',
                         'HEPTA_HIA_AGENT_JOURNAL_DEVELOPMENT_MANIFEST',
                         'HEPTA_HIA_RETIREMENT_DEVELOPMENT_COMPILER')
discarded_development_selectors = [name for name in development_selectors if name in environment]
for development_selector in development_selectors:
    environment.pop(development_selector, None)
production_selectors = ('HEPTA_HIA_COMPOSITE_TYPES_MANIFEST',
                        'HEPTA_HIA_TASK_HELPERS_MANIFEST',
                        'HEPTA_HIA_COMPOSITE_FUNCTIONS_MANIFEST',
                        'HEPTA_HIA_COMPOSITE_CONSTRUCTOR_MANIFEST',
                        'HEPTA_HIA_COMPOSITE_OUTER_MANIFEST',
                        'HEPTA_HIA_EXECUTION_BUDGET_MANIFEST',
                        'HEPTA_HIA_AGENT_JOURNAL_MANIFEST',
                        'HEPTA_HIA_RETIREMENT_STATE_MANIFEST')
discarded_production_selectors = [name for name in production_selectors if name in environment]
for production_selector in production_selectors:
    environment.pop(production_selector, None)
cold = out / 'cold.json'
for name in ('AGENT_STDIO', 'CORE_MODULE_GRAPH', 'CAPABILITY_RENAMING',
             'FUNCTION_SHAPE', 'PROGRAM_SHAPE', 'INSTRUCTION_POLICY',
             'ARTIFACT_PUBLICATION', 'CORE_ADMISSION', 'CORE_ADMISSION_CLI',
             'CORE_PATCH', 'CORE_PATCH_CLI', 'CORE_PATCH_RESULT_CLI', 'COMPOSITE_TYPES',
             'TASK_HELPERS', 'COMPOSITE_FUNCTIONS', 'COMPOSITE_CONSTRUCTOR', 'COMPOSITE_OUTER',
             'WORKER_REQUEST', 'WORKER_HELPERS', 'AGENT_JOURNAL', 'RELEASE_INSTALL', 'RELEASE_SELECTION',
             'SOURCE_BUILD', 'NOMINAL_JSON', 'EXECUTION_BUDGET', 'RETIREMENT_STATE'):
    environment['HEPTA_HIA_' + name + '_COLD_REPORT'] = str(cold)
steps = []
suite_outcomes = {}


def run(name, args, *, timeout=1800):
    started = time.monotonic()
    stdout = out / (name + '.stdout.log')
    stderr = out / (name + '.stderr.log')
    result = {'name': name, 'command': [sys.executable, '-B', *args]}
    print(json.dumps({'starting': name}), flush=True)
    step_environment = dict(environment)
    step_environment['HEPTA_HIA_CORE_MODULE_GRAPH_OBSERVATIONS'] = str(out / (name + '-module-projects'))
    step_environment['HEPTA_HIA_COMPOSITE_FIXTURE_EVIDENCE'] = str(out / (name + '-nominal-fixture'))
    step_environment['HEPTA_HIA_RELEASE_INSTALL_OBSERVATIONS'] = str(out / (name + '-release-install'))
    step_environment['HEPTA_HIA_RELEASE_SELECTION_OBSERVATIONS'] = str(out / (name + '-release-selection'))
    step_environment['HEPTA_HIA_RETIREMENT_STATE_EVIDENCE'] = str(out / (name + '-retirement-state'))
    step_environment['HEPTA_HIA_SOURCE_BUILD_OBSERVATIONS'] = str(out / (name + '-source-build'))
    step_environment['HEPTA_HIA_EXECUTION_BUDGET_EVIDENCE'] = str(out / (name + '-execution-budget'))
    step_environment['HEPTA_HIA_NOMINAL_JSON_EVIDENCE'] = str(out / (name + '-nominal-json'))
    step_environment['HEPTA_HIA_NOMINAL_JSON_INGRESS_EVIDENCE'] = str(out / (name + '-nominal-json-ingress'))
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
expected=suite.countTestCases()
r=unittest.TextTestRunner(verbosity=2).run(suite)
value={'expected_tests':expected,'tests_run':r.testsRun,'successful':r.wasSuccessful(),
       'errors':[{'test':str(t),'traceback':s} for t,s in r.errors],
       'failures':[{'test':str(t),'traceback':s} for t,s in r.failures],
       'skipped':[{'test':str(t),'reason':s} for t,s in r.skipped],
       'expected_failures':[str(t) for t,s in r.expectedFailures],
       'unexpected_successes':[str(t) for t in r.unexpectedSuccesses]}
open(RESULT,'w').write(json.dumps(value,indent=2)+'\\n')
raise SystemExit(0 if r.testsRun == expected and expected > 0 and r.wasSuccessful() and not (r.errors or r.failures or r.skipped or r.expectedFailures or r.unexpectedSuccesses) else 1)
'''
    code = 'DISCOVER=' + repr(discover) + '\nNAMES=' + repr(names or []) + '\nRESULT=' + repr(str(result_path)) + '\n' + source
    completed = run(name, ['-c', code], timeout=5400 if discover else 1800)
    outcome = {'completed': completed, 'passed': False, 'discovery': discover}
    try:
        value = json.loads(result_path.read_text())
        outcome['result'] = file_record(result_path)
        outcome['tests_run'] = value.get('tests_run')
        outcome['expected_tests'] = value.get('expected_tests')
        outcome['passed'] = (completed and type(value.get('tests_run')) is int
                             and type(value.get('expected_tests')) is int
                             and value['tests_run'] == value['expected_tests'] > 0
                             and value.get('successful') is True
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
# Transfer the exact commit and its complete tree through Git's object protocol.
# A depth-one fetch excludes unrelated history, without shared/hardlinked
# objects or changing any HEAD, tree, raw-blob or file-mode comparison below.
subprocess.run(['git','--no-replace-objects','init','--quiet',COPY],check=True)
subprocess.run(['git','--no-replace-objects','-C',COPY,'fetch','--quiet',
                '--no-tags','--depth=1',SOURCE,expected['head']],check=True)
if (Path(COPY)/'.git/objects/info/alternates').exists():
    raise SystemExit('source reproduction must not borrow original Git objects')
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
         'git_history_scope':'exact immutable commit and its complete tracked source tree',
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
        'worker-request': ['tests.test_hia_worker_request_native', 'tests.test_hia_worker_request_review'],
        'worker-helpers': ['tests.test_hia_worker_native_helpers'],
        'agent-journal': ['tests.test_hia_agent_journal_native'],
        'execution-budget': ['tests.test_hia_execution_budget_native'],
        'release-install': ['tests.test_hia_release_install'],
        'release-selection': ['tests.test_hia_release_selection',
                              'tests.test_hia_release_selection_review'],
        'retirement-state': ['tests.test_hia_retirement_state_native'],
        'source-build': ['tests.test_hia_source_build'],
        'nominal-json': ['tests.test_hia_nominal_json_native',
                         'tests.test_hia_nominal_json_constructor_ingress'],
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
                            'tests.test_hia_composite_native_composition'],
        'composite-functions': ['tests.test_hia_composite_function_tokens',
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
    }
    for name, names in groups.items():
        ok = suite(name, names) and ok
    journal_modules = (
        'tests.test_hia_agent_native_tools',
        'tests.test_hia_agent_native_proof_contract',
        'tests.test_hia_agent_native_lease_snapshot',
        'tests.test_hia_agent_native_machine_choices',
        'tests.test_hia_agent_native_campaign',
        'tests.test_hia_agent_candidate_native',
        'tests.test_hia_worker_request_native',
        'tests.test_hia_worker_request_review',
    )
    journal_args = ['tools/qualify_hia_agent_journal_callers.py',
                    '--cold-report', str(cold),
                    '--output', str(out / 'journal-callers.json')]
    for module in journal_modules:
        journal_args.extend(['--module', module])
    ok = run('ordinary-journal-callers', journal_args) and ok
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
all_passed = ok and preserved and harness_preserved
full_outcome = suite_outcomes.get('full-retained-regression')
full_qualified = bool(a.full and full_outcome and full_outcome['passed'] and all_passed)
status = ('FULL_RETAINED_PASS' if full_qualified else
          'COMPONENTS_PASS' if all_passed and not a.full else 'HOLD')
result = {'schema': 'hepta.hia.native-rewrite-qualification.v4',
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
          'discarded_development_selectors': discarded_development_selectors,
          'discarded_production_selectors': discarded_production_selectors,
          'whole_native_delivery_qualified': False,
          'full_retained_regression_requested': a.full,
          'full_retained_regression_executed': full_outcome is not None,
          'full_retained_regression_qualified': full_qualified,
          'full_retained_regression': full_outcome}
(out / 'QUALIFICATION.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
print(json.dumps({'status': result['status'], 'steps': len(steps), 'source_preserved': preserved}), flush=True)
raise SystemExit(0 if result['status'] in {'COMPONENTS_PASS', 'FULL_RETAINED_PASS'} else 1)
