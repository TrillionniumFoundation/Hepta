"""Run source-bound gates with retained prerequisites and current native owners.

Component completion and a complete retained regression have different statuses.
The unchanged external guardian spans preparation and this runner. Cold replay
retains its existing 180-second owner and subreaper/ECHILD cleanup proof.
The compatible v5 report schema is retained for the byte-identical guardian;
harness_revision v8 records the additional mandatory gates and their outcomes.
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
import native_owner_gates

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
                 'qualification_prerequisites': Path(qualification_prerequisites.__file__).resolve(),
                 'native_owner_gates': Path(native_owner_gates.__file__).resolve()}
if harness_paths['workflow_process'] != harness_paths['runner'].with_name('workflow_process.py'):
    raise ValueError('workflow supervisor must be adjacent to this qualification runner')
if harness_paths['qualification_prerequisites'] != harness_paths['runner'].with_name('qualification_prerequisites.py'):
    raise ValueError('prerequisite admission must be adjacent to this qualification runner')
if harness_paths['native_owner_gates'] != harness_paths['runner'].with_name('native_owner_gates.py'):
    raise ValueError('new owner receipt admission must be adjacent to this qualification runner')
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
                         'HEPTA_HIA_AGENT_JOURNAL_DEVELOPMENT_MANIFEST',
                         'HEPTA_HIA_JSON_WIRE_DEVELOPMENT_MANIFEST',
                         'HEPTA_HIA_WORKER_REPORT_DEVELOPMENT_MANIFEST',
                         'HEPTA_HIA_MACHINE_PLAN_DEVELOPMENT_MANIFEST',
                         'HEPTA_HIA_MACHINE_ENCODING_DEVELOPMENT_MANIFEST',
                         'HEPTA_HIA_CLI_DEVELOPMENT_MANIFEST')
discarded_development_selectors = [name for name in development_selectors if name in environment]
for development_selector in development_selectors:
    environment.pop(development_selector, None)
cold = out / 'cold.json'
for name in ('AGENT_STDIO', 'CORE_MODULE_GRAPH', 'CAPABILITY_RENAMING',
             'FUNCTION_SHAPE', 'PROGRAM_SHAPE', 'INSTRUCTION_POLICY',
             'ARTIFACT_PUBLICATION', 'CORE_ADMISSION', 'CORE_ADMISSION_CLI',
             'CORE_PATCH', 'CORE_PATCH_CLI', 'CORE_PATCH_RESULT_CLI', 'COMPOSITE_TYPES',
             'WORKER_REQUEST', 'RELEASE_INSTALL', 'TASK_HELPERS', 'AGENT_JOURNAL',
             'COMPOSITE_FUNCTIONS', 'COMPOSITE_CONSTRUCTOR', 'COMPOSITE_OUTER',
             'JSON_WIRE', 'WORKER_REPORT', 'MACHINE_PLAN', 'MACHINE_ENCODING', 'CLI'):
    environment['HEPTA_HIA_' + name + '_COLD_REPORT'] = str(cold)
steps = []
suite_outcomes = {}
caller_outcome = {'completed': False, 'passed': False, 'executed': False}
machine_plan_caller_outcome = {'completed': False, 'passed': False, 'executed': False}
json_wire_caller_outcome = {'completed': False, 'passed': False, 'executed': False}
machine_encoding_caller_outcome = {'completed': False, 'passed': False, 'executed': False}
cli_fixture_outcome = {'completed': False, 'passed': False, 'executed': False}


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
    result['new_owner_fixture_evidence'] = {}
    for owner_name, stem in (('JSON_WIRE', 'json-wire'),
                             ('JSON_WIRE_ENTRY', 'json-wire-entry'),
                             ('WORKER_REPORT', 'worker-report'),
                             ('MACHINE_PLAN', 'machine-plan'),
                             ('JSON_WIRE_CACHE', 'json-wire-cache'),
                             ('MACHINE_ENCODING', 'machine-encoding'),
                             ('CLI', 'cli')):
        path = str(out / (name + '-' + stem + '-fixtures'))
        step_environment['HEPTA_HIA_' + owner_name + '_FIXTURE_EVIDENCE'] = path
        result['new_owner_fixture_evidence'][owner_name] = path
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


MACHINE_PLAN_CALLER_MODULES = (
    'tests.test_hia_machine_plan',
    'tests.test_hia_machine_registers',
    'tests.test_hia_machine_leaf_registers',
    'tests.test_hia_agent_native_machine_choices',
)


def selected_machine_plan_callers():
    path = out / 'machine-plan-selected-callers.json'
    evidence = out / 'machine-plan-selected-callers-evidence'
    cold_before = cold.read_bytes()
    cold_value = json.loads(cold_before)
    command = ['tools/qualify_hia_machine_plan_native_callers.py',
               '--cold-report', str(cold), '--output', str(path),
               '--evidence-dir', str(evidence)]
    for name in MACHINE_PLAN_CALLER_MODULES:
        command.extend(['--module', name])
    completed = run('machine-plan-selected-callers', command)
    outcome = {'completed': completed, 'passed': False, 'executed': True,
               'modules': list(MACHINE_PLAN_CALLER_MODULES)}
    try:
        value = json.loads(path.read_bytes())
        loaded = value.get('loaded_test_ids')
        executed = value.get('executed_test_ids')
        count = value.get('tests_run')
        entries = value.get('native_stage_entries')
        if not (value.get('schema') == 'hepta.hia.machine-plan-selected-callers.v1'
                and value.get('status') == 'PASS'
                and value.get('scope') == 'MATCHING_SOURCE_COLD_SELECTED_CALLERS'
                and type(loaded) is list and bool(loaded)
                and all(type(name) is str for name in loaded)
                and len(set(loaded)) == len(loaded)
                and loaded == executed
                and type(count) is int and count == 44
                and type(value.get('tests_loaded')) is int
                and count == len(loaded) == value.get('tests_loaded')
                and all(value.get(key) == [] for key in (
                    'failures', 'errors', 'skipped', 'expected_failures', 'unexpected_successes'))
                and value.get('retained_plan_owners_forbidden') is True
                and value.get('subprocesses_inherit_selector') is True
                and value.get('source_and_manifest_unchanged') is True
                and type(entries) is dict and bool(entries)
                and all(type(key) is str and type(n) is int and n > 0 for key, n in entries.items())
                and all(any(test.startswith(module + '.') for test in loaded)
                        for module in MACHINE_PLAN_CALLER_MODULES)
                and all(any(test.startswith(module + '.') for module in MACHINE_PLAN_CALLER_MODULES)
                        for test in loaded)):
            raise ValueError('machine-plan caller gate lacks complete native-selected test evidence')
        expected_sources = {name: digest for name, digest in source_before['files'].items()
                            if (Path(name).parent.as_posix() in ('hepta', 'tools', 'tests')
                                and Path(name).suffix == '.py')
                            or (Path(name).parent.as_posix() == 'examples/hia_bootstrap'
                                and Path(name).suffix == '.hiaasm')}
        if (not expected_sources or value.get('source_before_sha256') != expected_sources
                or value.get('source_after_sha256') != expected_sources):
            raise ValueError('machine-plan caller source snapshot differs from the pinned checkout')
        manifest = value.get('manifest')
        generations = cold_value.get('generation_sha256')
        if not (type(manifest) is dict
                and set(manifest) == {'schema', 'source_sha256', 'image_path', 'image_sha256', 'compiler_sha256'}
                and manifest['schema'] == 'hepta.hia.machine-plan-native.v1'
                and all(type(manifest[key]) is str
                        and re.fullmatch(r'[0-9a-f]{64}', manifest[key]) is not None
                        for key in ('source_sha256', 'image_sha256', 'compiler_sha256'))
                and manifest['source_sha256'] == sources.get('examples/hia_bootstrap/machine_plan.hiaasm')
                and type(manifest['image_path']) is str and bool(manifest['image_path'])
                and manifest['image_path'] not in ('.', '..')
                and Path(manifest['image_path']).name == manifest['image_path']
                and type(manifest['image_sha256']) is str
                and re.fullmatch(r'[0-9a-f]{64}', manifest['image_sha256']) is not None
                and value.get('image_sha256') == manifest['image_sha256']
                and type(generations) is list and len(generations) == 3
                and all(pin == manifest['compiler_sha256'] for pin in generations)
                and cold.read_bytes() == cold_before):
            raise ValueError('machine-plan manifest or cold compiler identity differs')
        if (value.get('actual_cold_build_retained') is not True
                or value.get('caller_build_evidence_directory') != str(evidence.resolve())):
            raise ValueError('machine-plan cold-built evidence was not retained at the requested path')
        manifest_path = evidence / 'build/manifest.json'
        build_path = evidence / 'build/build.json'
        image_path = manifest_path.parent / manifest['image_path']
        retained_manifest = json.loads(manifest_path.read_bytes())
        retained_build = json.loads(build_path.read_bytes())
        retained_image = image_path.read_bytes()
        native = retained_build.get('native_compile_receipt', {})
        if not (retained_manifest == manifest
                and sha256(retained_image).hexdigest() == manifest['image_sha256']
                and retained_build.get('schema') == 'hepta.hia.machine-plan-build.v1'
                and retained_build.get('status') == 'NATIVE_CANDIDATE_BUILT'
                and retained_build.get('manifest') == manifest
                and retained_build.get('cold_report_sha256') == sha256(cold_before).hexdigest()
                and retained_build.get('source_manifest') == cold_sources
                and native.get('status') == 'returned' and native.get('abi_status') == 0
                and native.get('source_unchanged') is True
                and native.get('produced_sha256') == manifest['image_sha256']
                and native.get('produced_bytes') == len(retained_image)
                and native.get('input_sha256') == manifest['source_sha256']
                and native.get('artifact_sha256') == manifest['compiler_sha256']
                and native.get('forbidden_compiler_modules_loaded') == []):
            raise ValueError('machine-plan retained build, image or cold source binding differs')
        outcome.update(passed=completed, tests_run=count, result=file_record(path),
                       native_stage_entries=entries, retained_owners_forbidden=True,
                       exact_loaded_executed_ids=True, source_and_manifest_stable=True,
                       manifest_source_and_cold_compiler_match=True,
                       cold_report_sha256=sha256(cold_before).hexdigest(),
                       actual_cold_build_retained=True,
                       retained_manifest=file_record(manifest_path),
                       retained_build=file_record(build_path), retained_image=file_record(image_path))
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        outcome['result_error'] = repr(error)
    steps[-1]['selected_machine_plan_caller_result'] = outcome
    steps[-1]['passed'] = outcome['passed']
    (out / 'steps.json').write_text(json.dumps(steps, indent=2) + '\n')
    return outcome


JSON_WIRE_CALLER_MODULES = (
    'tests.test_hia_bounded_agent_json',
    'tests.test_hia_inmemory_surrogate_wire',
    'tests.test_hia_inmemory_json_key_collisions',
    'tests.test_hia_inmemory_agent_node_ceiling',
    'tests.test_hia_agent_native_tools',
    'tests.test_hia_agent_native_proof_contract',
    'tests.test_hia_agent_native_lease_snapshot',
    'tests.test_hia_agent_native_machine_choices',
    'tests.test_hia_agent_native_campaign',
)
JSON_WIRE_CALLER_SOURCES = (
    'hepta/hia_json_wire_native.py', 'hepta/hia_program_tools.py',
    'hepta/hia_agent_store.py', 'tools/generate_hia_json_wire.py',
    'examples/hia_bootstrap/json_wire.hiaasm',
    'tools/qualify_hia_json_wire_native_callers.py',
)
JSON_WIRE_AGENT_TOOLS = (
    'hia_describe', 'hia_artifact', 'hia_read', 'hia_context', 'hia_inspect',
    'hia_candidate', 'hia_verify', 'hia_emit', 'hia_evaluate',
    'hia_adopt', 'hia_rollback',
)


def selected_json_wire_callers():
    path = out / 'json-wire-selected-callers.json'
    evidence = out / 'json-wire-selected-callers-evidence'
    cold_before = cold.read_bytes()
    cold_value = json.loads(cold_before)
    command = ['tools/qualify_hia_json_wire_native_callers.py',
               '--cold-report', str(cold), '--output', str(path),
               '--evidence-dir', str(evidence)]
    for name in JSON_WIRE_CALLER_MODULES:
        command.extend(['--module', name])
    completed = run('json-wire-selected-callers', command)
    outcome = {'completed': completed, 'passed': False, 'executed': True,
               'modules': list(JSON_WIRE_CALLER_MODULES)}
    try:
        value = json.loads(path.read_bytes())
        loaded = value.get('loaded_test_ids')
        count = value.get('tests_run')
        entries = value.get('actual_native_step_returns')
        calls = value.get('ordinary_wire_calls')
        tools_entered = value.get('agent_tools_with_native_wire')
        if not (value.get('schema') == 'hepta.hia.json-wire-selected-callers.v1'
                and value.get('status') == 'PASS'
                and value.get('scope') == 'MATCHING_SOURCE_COLD_SELECTED_CALLERS'
                and type(loaded) is list and bool(loaded)
                and all(type(name) is str for name in loaded)
                and len(set(loaded)) == len(loaded)
                and loaded == value.get('chosen_test_ids') == value.get('executed_test_ids')
                and type(count) is int and count > 0
                and type(value.get('tests_loaded')) is int
                and type(value.get('tests_chosen')) is int
                and count == len(loaded) == value['tests_loaded'] == value['tests_chosen']
                and value.get('explicit_development_exclusions') == {}
                and all(value.get(key) == [] for key in (
                    'failures', 'errors', 'skipped', 'expected_failures', 'unexpected_successes',
                    'retained_owner_entries', 'host_encoder_entries'))
                and value.get('retained_owner_forbidden') is True
                and value.get('host_encoder_forbidden_inside_native_owner') is True
                and value.get('subprocesses_inherit_selector') is True
                and value.get('source_manifest_image_stable') is True
                and value.get('matching_cold_source_closure_stable') is True
                and value.get('all_eleven_agent_tools_entered_selected_wire') is True
                and type(calls) is int and calls > 0
                and type(entries) is dict and bool(entries)
                and all(type(key) is str and type(n) is int and n > 0 for key, n in entries.items())
                and type(tools_entered) is dict
                and all(type(tools_entered.get(name)) is int and tools_entered[name] > 0
                        for name in JSON_WIRE_AGENT_TOOLS)
                and all(any(test.startswith(module + '.') for test in loaded)
                        for module in JSON_WIRE_CALLER_MODULES)
                and all(any(test.startswith(module + '.') for module in JSON_WIRE_CALLER_MODULES)
                        for test in loaded)):
            raise ValueError('JSON wire caller gate lacks complete native-selected test evidence')
        expected_sources = {name: sources[name] for name in JSON_WIRE_CALLER_SOURCES}
        if value.get('source_sha256') != expected_sources:
            raise ValueError('JSON wire caller source snapshot differs from the pinned checkout')
        manifest = value.get('manifest')
        generations = cold_value.get('generation_sha256')
        if not (type(manifest) is dict
                and set(manifest) == {'schema', 'source_sha256', 'image_path', 'image_sha256', 'compiler_sha256'}
                and manifest['schema'] == 'hepta.hia.json-wire-native.v1'
                and all(type(manifest[key]) is str
                        and re.fullmatch(r'[0-9a-f]{64}', manifest[key]) is not None
                        for key in ('source_sha256', 'image_sha256', 'compiler_sha256'))
                and manifest['source_sha256'] == sources.get('examples/hia_bootstrap/json_wire.hiaasm')
                and type(manifest['image_path']) is str and bool(manifest['image_path'])
                and manifest['image_path'] not in ('.', '..')
                and Path(manifest['image_path']).name == manifest['image_path']
                and value.get('image_sha256') == manifest['image_sha256']
                and type(generations) is list and len(generations) == 3
                and all(pin == manifest['compiler_sha256'] for pin in generations)
                and cold.read_bytes() == cold_before):
            raise ValueError('JSON wire manifest or cold compiler identity differs')
        manifest_path = evidence / 'wire/manifest.json'
        build_path = evidence / 'wire/build.json'
        image_path = manifest_path.parent / manifest['image_path']
        if not (value.get('evidence_dir_retained') is True
                and value.get('evidence_dir') == str(evidence.resolve())
                and value.get('manifest_path') == str(manifest_path.resolve())):
            raise ValueError('JSON wire cold-built evidence was not retained at the requested path')
        retained_manifest = json.loads(manifest_path.read_bytes())
        retained_build = json.loads(build_path.read_bytes())
        retained_image = image_path.read_bytes()
        native = retained_build.get('native_compile_receipt', {})
        profile = value.get('ordinary_entry_profile')
        if not (retained_manifest == manifest
                and sha256(retained_image).hexdigest() == manifest['image_sha256']
                and retained_build.get('schema') == 'hepta.hia.json-wire-build.v1'
                and retained_build.get('scope') == 'MATCHING_SOURCE_COLD_BUILD'
                and retained_build.get('manifest') == manifest
                and retained_build.get('cold_report_sha256') == sha256(cold_before).hexdigest()
                and retained_build.get('source_manifest') == cold_sources
                and type(profile) is dict
                and profile.get('schema') == 'hepta.hia.ordinary-json-wire-product-profile.v1'
                and profile.get('selector') == 'HEPTA_HIA_JSON_WIRE_MANIFEST'
                and profile.get('entire_python_call_domain_replaced') is False
                and retained_build.get('ordinary_entry_profile') == profile
                and native.get('status') == 'returned' and native.get('abi_status') == 0
                and native.get('source_unchanged') is True
                and native.get('produced_sha256') == manifest['image_sha256']
                and native.get('produced_bytes') == len(retained_image)
                and native.get('input_sha256') == manifest['source_sha256']
                and native.get('artifact_sha256') == manifest['compiler_sha256']
                and native.get('forbidden_compiler_modules_loaded') == []):
            raise ValueError('JSON wire retained build, image, profile or cold source binding differs')
        outcome.update(passed=completed, tests_run=count, result=file_record(path),
                       ordinary_wire_calls=calls, actual_native_step_returns=entries,
                       all_eleven_agent_tools_entered_selected_wire=True,
                       retained_and_host_encoder_entries_empty=True,
                       exact_loaded_chosen_executed_ids=True,
                       source_manifest_image_stable=True,
                       manifest_source_and_cold_compiler_match=True,
                       cold_report_sha256=sha256(cold_before).hexdigest(),
                       actual_cold_build_retained=True,
                       retained_manifest=file_record(manifest_path),
                       retained_build=file_record(build_path), retained_image=file_record(image_path),
                       ordinary_entry_profile=profile)
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        outcome['result_error'] = repr(error)
    steps[-1]['selected_json_wire_caller_result'] = outcome
    steps[-1]['passed'] = outcome['passed']
    (out / 'steps.json').write_text(json.dumps(steps, indent=2) + '\n')
    return outcome



def selected_machine_encoding_callers():
    evidence = out / 'machine-encoding-selected-callers-evidence'
    cold_before = cold.read_bytes()
    completed = run('machine-encoding-selected-callers', [
        'tools/qualify_hia_machine_encoding_native_callers.py',
        '--cold-report', str(cold), '--evidence', str(evidence)])
    outcome = {'completed': completed, 'passed': False, 'executed': True}
    try:
        receipt = native_owner_gates.encoding_callers(
            evidence, cold_before, cold_sources, contract['profile'])
        if cold.read_bytes() != cold_before:
            raise ValueError('cold report changed during instruction-byte callers')
        outcome.update(receipt, passed=completed)
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        outcome['result_error'] = repr(error)
    steps[-1]['selected_machine_encoding_caller_result'] = outcome
    steps[-1]['passed'] = outcome['passed']
    (out / 'steps.json').write_text(json.dumps(steps, indent=2) + '\n')
    return outcome


def retained_cli_fixture():
    completed = suite_outcomes.get('cli', {}).get('passed') is True
    outcome = {'completed': completed, 'passed': False,
               'executed': 'cli' in suite_outcomes}
    try:
        if not completed:
            raise ValueError('complete CLI module did not pass')
        if steps[-1]['name'] != 'cli':
            raise ValueError('CLI fixture check must immediately follow its complete module')
        cold_before = cold.read_bytes()
        receipt = native_owner_gates.cli_fixture(
            out / 'cli-cli-fixtures', cold_before, cold_sources, sources, contract['profile'])
        if cold.read_bytes() != cold_before:
            raise ValueError('cold report changed during CLI fixture admission')
        outcome.update(receipt, passed=True)
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        outcome['result_error'] = repr(error)
    steps[-1]['cli_fixture_result'] = outcome
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
        'json-wire': ['tests.test_hia_json_wire_native'],
        'json-wire-cache': ['tests.test_hia_json_wire_cache'],
        'ordinary-wire-entry': ['tests.test_hia_json_wire_entry'],
        'worker-report': ['tests.test_hia_worker_report_native'],
        'machine-plan': ['tests.test_hia_machine_plan_native'],
        'linked-observer': ['tests.test_hia_selfhost_linked_observer'],
        'cli': ['tests.test_hia_cli_native'],
    }
    for name, names in groups.items():
        ok = suite(name, names) and ok
    cli_fixture_outcome = retained_cli_fixture()
    ok = cli_fixture_outcome['passed'] and ok
    caller_outcome = selected_journal_callers()
    ok = caller_outcome['passed'] and ok
    machine_plan_caller_outcome = selected_machine_plan_callers()
    ok = machine_plan_caller_outcome['passed'] and ok
    machine_encoding_caller_outcome = selected_machine_encoding_callers()
    ok = machine_encoding_caller_outcome['passed'] and ok
    json_wire_caller_outcome = selected_json_wire_callers()
    ok = json_wire_caller_outcome['passed'] and ok
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
    'json_wire_complete_module': suite_outcomes.get('json-wire', {}).get('passed') is True,
    'ordinary_json_wire_entry_complete_module': suite_outcomes.get('ordinary-wire-entry', {}).get('passed') is True,
    'worker_report_complete_module': suite_outcomes.get('worker-report', {}).get('passed') is True,
    'machine_plan_complete_module': suite_outcomes.get('machine-plan', {}).get('passed') is True,
    'linked_observer_complete_module': suite_outcomes.get('linked-observer', {}).get('passed') is True,
    'machine_plan_selected_ordinary_callers': machine_plan_caller_outcome['passed'] is True,
    'json_wire_selected_ordinary_callers': json_wire_caller_outcome['passed'] is True,
}
mandatory_v8_gates = {
    **mandatory_gates,
    'json_wire_cache_complete_module': suite_outcomes.get('json-wire-cache', {}).get('passed') is True,
    'cli_complete_module_and_retained_cold_bundle':
        suite_outcomes.get('cli', {}).get('passed') is True and cli_fixture_outcome['passed'] is True,
    'machine_encoding_complete_component_and_original_callers': machine_encoding_caller_outcome['passed'] is True,
    'original_selected_caller_denominators_preserved':
        caller_outcome.get('tests_run') == 94
        and machine_plan_caller_outcome.get('tests_run') == 44
        and json_wire_caller_outcome.get('tests_run') == 89,
}
all_passed = ok and preserved and harness_preserved and all(mandatory_v8_gates.values())
full_outcome = suite_outcomes.get('full-retained-regression')
full_qualified = bool(a.full and full_outcome and full_outcome['passed'] and all_passed)
status = ('FULL_RETAINED_PASS' if full_qualified else
          'COMPONENTS_PASS' if all_passed and not a.full else 'HOLD')
result = {'schema': 'hepta.hia.native-rewrite-qualification.v5',
          'harness_revision': 'v8',
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
          'mandatory_v7_gates': mandatory_gates,
          'mandatory_v8_gates': mandatory_v8_gates,
          'machine_encoding_selected_callers': machine_encoding_caller_outcome,
          'cli_fixture_binding': cli_fixture_outcome,
          'journal_selected_callers': caller_outcome,
          'machine_plan_selected_callers': machine_plan_caller_outcome,
          'json_wire_selected_callers': json_wire_caller_outcome,
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
