"""Run all integrated families with unchanged pinned-source qualification gates.

Component completion and a complete retained regression have different statuses.
The external supervisor owns only its POSIX process group; cold replay retains
its existing 180-second owner and its separate subreaper/ECHILD cleanup proof.
"""
import argparse
import ast
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import workflow_process

COLD_REPORT_FAMILIES = (
    'AGENT_STDIO', 'CORE_MODULE_GRAPH', 'CAPABILITY_RENAMING',
    'FUNCTION_SHAPE', 'PROGRAM_SHAPE', 'INSTRUCTION_POLICY',
    'ARTIFACT_PUBLICATION', 'CORE_ADMISSION', 'CORE_ADMISSION_CLI',
    'CORE_PATCH', 'CORE_PATCH_CLI', 'CORE_PATCH_RESULT_CLI',
    'COMPOSITE_TYPES', 'TASK_HELPERS', 'ENUM_MATCH', 'ENUM_OPERATIONS',
    'RECORD_OPERATIONS', 'RECORD_TRANSITIONS', 'TASK_OPERATIONS',
    'COMPOSITE_FUNCTIONS', 'COMPOSITE_CONSTRUCTOR', 'COMPOSITE_OUTER',
    'CALL_PRIMITIVE', 'NOMINAL_TERMINATORS', 'NOMINAL_MODULE',
    'NOMINAL_ADMISSION', 'NOMINAL_FUNCTION', 'TASK_HELPER_CACHE',
    'EXECUTION_BUDGET', 'REQUEST_JOURNAL', 'RETIREMENT_STATE',
    'WORKER_REQUEST', 'RELEASE_INSTALL', 'RELEASE_SELECTION',
    'ARTIFACT_NAMESPACE', 'SLOT_LEDGER', 'AGENT_IDENTITY', 'PROGRAM_EXECUTION',
    'STATIC_BUDGET', 'HEAP_BOUND',
    'LINKED_OBSERVER', 'PROGRAM_NORMALIZATION', 'CORE_JSON_BYTES', 'NOMINAL_JSON',
    'SOURCE_BUILD', 'SOURCE_ADMISSION',
)

SOURCE_RELEASE_GROUP = [
    'tests.test_hia_source_build',
    'tests.test_hia_program_selfhost',
    'tests.test_hia_source_release_integration',
    'tests.test_hia_source_admission_native',
]

LINKED_OBSERVER_GROUP = ['tests.test_hia_selfhost_linked_observer']
RECEIPT_GROUP = [
    'tests.test_hia_original_select_fragments',
    'tests.test_hia_agent_identity_source_binding',
    'tests.test_hia_compile_receipt_binding',
]


def qualification_environment(inherited, cold_report):
    """Exclude inherited artifact choices; record every removed selector."""
    environment = dict(inherited)
    discarded = {'development': {}, 'production': {}, 'cold_report': {}, 'compiler': {}}
    for name in sorted(inherited):
        if not name.startswith('HEPTA_HIA_'):
            continue
        if name in {'HEPTA_HIA_COMPILE_RECEIPT_COMPILER',
                    'HEPTA_HIA_COMPILE_RECEIPT_COMPILER_SHA256'}:
            category = 'compiler'
        elif '_DEVELOPMENT_' in name or name.endswith('_DEVELOPMENT'):
            category = 'development'
        elif name.endswith('_MANIFEST'):
            category = 'production'
        elif name.endswith('_COLD_REPORT'):
            category = 'cold_report'
        else:
            continue
        value = environment.pop(name)
        encoded = os.fsencode(value)
        discarded[category][name] = {
            'value_sha256': sha256(encoded).hexdigest(),
            'value_bytes': len(encoded),
            'was_empty': value == '',
        }
    environment['PYTHONDONTWRITEBYTECODE'] = '1'
    environment['PYTHONUNBUFFERED'] = '1'
    selected = {'HEPTA_HIA_' + family + '_COLD_REPORT': str(cold_report)
                for family in COLD_REPORT_FAMILIES}
    environment.update(selected)
    record = {
        'schema': 'hepta.hia.qualification-environment.v2',
        'policy': 'Discard inherited HIA artifact choices and receipt compilers; select this run fresh cold report, then admit its actual B3 before selecting a compiler.',
        'discarded': discarded,
        'effective_cold_report_selectors': selected,
        'effective_qualified_compiler_selectors': {},
        'inherited_environment_claimed_unchanged': False,
        'runtime_overrides': {'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONUNBUFFERED': '1'},
        'other_environment_preserved': True,
    }
    return environment, record


p = argparse.ArgumentParser()
p.add_argument('--source', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
p.add_argument('--full', action='store_true')
a = p.parse_args()
root = a.source.resolve(); out = a.output.resolve()
if out == root or out.is_relative_to(root):
    raise ValueError('qualification output must be outside the pinned source tree')
out.mkdir(parents=True, exist_ok=False)
cold = out / 'cold.json'
environment, environment_selection = qualification_environment(os.environ, cold)
environment_record = out / 'environment-selection.json'
environment_record.write_text(json.dumps(environment_selection, indent=2, sort_keys=True) + '\n')
discarded_development_selectors = sorted(environment_selection['discarded']['development'])
discarded_production_selectors = sorted(environment_selection['discarded']['production'])
discarded_cold_report_selectors = sorted(environment_selection['discarded']['cold_report'])
discarded_compiler_selectors = sorted(environment_selection['discarded']['compiler'])
# Sanitize this runner before importing candidate modules, not only its children.
for category in environment_selection['discarded'].values():
    for name in category:
        os.environ.pop(name, None)
os.environ.update(environment_selection['effective_cold_report_selectors'])
os.environ['PYTHONDONTWRITEBYTECODE'] = '1'
os.environ['PYTHONUNBUFFERED'] = '1'
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
                 'python_frame_observations': Path(__file__).resolve().with_name('run_python_frame_observations.py'),
                 'historical_note_prerequisite': Path(__file__).resolve().with_name('check_normalization_note_reference.py')}
if harness_paths['workflow_process'] != harness_paths['runner'].with_name('workflow_process.py'):
    raise ValueError('workflow supervisor must be adjacent to this qualification runner')
harness_before = {name: file_record(path) for name, path in harness_paths.items()}
if harness_before['workflow_process']['sha256'] != 'f3ebc453de2d2c9ecd3825547e301c122b6c7fa05af1aacd9103b8a67893ee80':
    raise ValueError('original workflow process supervisor changed')
if harness_before['python_frame_observations']['sha256'] != '666d8198a171e6db723860606d337600a362557d9526bc5eab431fe376ab7ac5':
    raise ValueError('original independent Python-frame wrapper changed')
(out / 'harness-before.json').write_text(json.dumps(harness_before, indent=2, sort_keys=True) + '\n')
run_workflow_step = workflow_process.run_workflow_step
steps = []
suite_outcomes = {}
held_inputs_before = {}
normalization_outcomes = {}
cold_compiler_admission = None


def input_guard():
    return {path: sha256(Path(path).read_bytes()).hexdigest()
            for path in held_inputs_before} == held_inputs_before


def hold(name, reason, *, expected_tests=None, expected_observations=None):
    result = {'name': name, 'status': 'HOLD', 'passed': False,
              'execution_started': False, 'owner': None, 'reason': reason}
    if expected_tests is not None:
        result['expected_tests'] = expected_tests
    if expected_observations is not None:
        result['expected_observations'] = expected_observations
    steps.append(result)
    (out / 'steps.json').write_text(json.dumps(steps, indent=2) + '\n')
    print(json.dumps({'not_started': name, 'status': 'HOLD', 'reason': reason}), flush=True)
    return False


def admit_fresh_cold_compiler(raw):
    # Read actual fresh outputs, never inherit a retained development binary.
    from tools.build_hia_json_preflight import admit_cold_build
    record = json.loads(raw)
    if (type(record) is not dict
            or type(record.get('qualification_wall_limit_seconds')) is not int
            or record['qualification_wall_limit_seconds'] != 180
            or type(record.get('cleanup_wall_limit_seconds')) is not int
            or record['cleanup_wall_limit_seconds'] != 3
            or type(record.get('nested_report')) is not str):
        raise ValueError('cold report changed the original time limits or nested identity')
    nested_path = Path(record['nested_report']).resolve(strict=True)
    if not nested_path.is_relative_to(out):
        raise ValueError('nested qualification is outside this fresh run')
    nested_raw = nested_path.read_bytes()
    if sha256(nested_raw).hexdigest() != record.get('nested_report_sha256'):
        raise ValueError('nested qualification bytes do not match the cold report')
    nested = json.loads(nested_raw)
    if (type(nested) is not dict or nested.get('status') != 'SELF_HOSTED_FIXED_CORE_PASS'
            or nested.get('source_manifest') != cold_sources
            or type(nested.get('generations')) is not list or len(nested['generations']) != 3):
        raise ValueError('nested generations do not bind the current complete source')
    pins = {str(cold): sha256(raw).hexdigest(), str(nested_path): sha256(nested_raw).hexdigest()}
    generations = []
    for index, row in enumerate(nested['generations'], 1):
        if type(row) is not dict or type(row.get('produced_image')) is not str:
            raise ValueError('invalid actual generation image reference')
        path = Path(row['produced_image']).resolve(strict=True)
        if not path.is_relative_to(out):
            raise ValueError('generation image is outside this fresh run')
        image = path.read_bytes()
        digest = sha256(image).hexdigest()
        if (not image or type(row.get('produced_bytes')) is not int
                or row['produced_bytes'] != len(image) or row.get('produced_sha256') != digest):
            raise ValueError('generation image length/hash differs from actual bytes')
        pins[str(path)] = digest
        generations.append({'generation': index, 'path': str(path),
                            'bytes': len(image), 'sha256': digest})
    if admit_cold_build(image, raw) != cold_sources:
        raise ValueError('fresh compiler admission differs from the pinned source')
    if ([row['sha256'] for row in generations] != record.get('generation_sha256')
            or any(sha256(Path(path).read_bytes()).hexdigest() != digest for path, digest in pins.items())):
        raise ValueError('fresh compiler/report inputs changed during admission')
    held_inputs_before.update(pins)
    return {'schema': 'hepta.hia.qualification-actual-cold-compiler.v1',
            'status': 'CURRENT_COLD_B3_ADMITTED', 'generations': generations,
            'selected': generations[-1], 'inputs': pins,
            'source_manifest': cold_sources, 'inherited_compiler_used': False}


def run(name, args, *, timeout=1800):
    try:
        if not input_guard():
            return hold(name, 'held cold or prerequisite inputs changed before execution')
    except OSError as error:
        return hold(name, 'held input readback failed: ' + repr(error))
    started = time.monotonic()
    stdout = out / (name + '.stdout.log')
    stderr = out / (name + '.stderr.log')
    result = {'name': name, 'command': [sys.executable, '-B', *args]}
    print(json.dumps({'starting': name}), flush=True)
    step_environment = dict(environment)
    step_environment['HEPTA_HIA_CORE_MODULE_GRAPH_OBSERVATIONS'] = str(out / (name + '-module-projects'))
    step_environment['HEPTA_HIA_COMPOSITE_FIXTURE_EVIDENCE'] = str(out / (name + '-nominal-fixture'))
    for selector, suffix in (
        ('HEPTA_HIA_EXECUTION_BUDGET_EVIDENCE', 'execution-budget'),
        ('HEPTA_HIA_REQUEST_JOURNAL_EVIDENCE', 'request-journal'),
        ('HEPTA_HIA_RETIREMENT_STATE_EVIDENCE', 'retirement-state'),
        ('HEPTA_HIA_RELEASE_INSTALL_OBSERVATIONS', 'release-install'),
        ('HEPTA_HIA_RELEASE_SELECTION_OBSERVATIONS', 'release-selection'),
        ('HEPTA_HIA_ARTIFACT_NAMESPACE_EVIDENCE', 'artifact-namespace'),
        ('HEPTA_HIA_SLOT_LEDGER_EVIDENCE', 'slot-ledger'),
        ('HEPTA_HIA_PROGRAM_EXECUTION_EVIDENCE', 'program-execution'),
        ('HEPTA_HIA_PROGRAM_EXECUTION_SCALARS_OBSERVATIONS', 'program-execution-scalars'),
        ('HEPTA_HIA_STATIC_BUDGET_EVIDENCE', 'static-budget'),
        ('HEPTA_HIA_BIGINT_EVIDENCE', 'static-bigints'),
        ('HEPTA_HIA_HEAP_GRAPHS_EVIDENCE', 'static-graphs'),
        ('HEPTA_HIA_HEAP_BOUND_EVIDENCE', 'heap-bound'),
        ('HEPTA_HIA_HEAP_LIVE_ENGINE_EVIDENCE', 'heap-live-engine'),
        ('HEPTA_HIA_LINKED_OBSERVER_EVIDENCE', 'linked-observer'),
        ('HEPTA_HIA_COMPILE_RECEIPT_OBSERVATIONS', 'compile-receipts'),
        ('HEPTA_HIA_PROGRAM_NORMALIZATION_EVIDENCE', 'normalization'),
        ('HEPTA_HIA_CORE_JSON_BYTES_EVIDENCE', 'core-json-bytes'),
        ('HEPTA_HIA_NOMINAL_JSON_EVIDENCE', 'nominal-json'),
        ('HEPTA_HIA_SOURCE_BUILD_OBSERVATIONS', 'source-build'),
        ('HEPTA_HIA_SELFHOST_BUILD_EVIDENCE', 'selfhost-build'),
        ('HEPTA_HIA_SOURCE_ADMISSION_EVIDENCE', 'source-admission'),
    ):
        step_environment[selector] = str(out / (name + '-' + suffix))
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


def suite(name, names=None, discover=False, expected_tests=None):
    result_path = out / (name + '.json')
    source = '''import json,unittest
loader=unittest.defaultTestLoader
suite=loader.discover('tests',top_level_dir='.') if DISCOVER else loader.loadTestsFromNames(NAMES)
r=unittest.TextTestRunner(verbosity=2).run(suite)
value={'tests_run':r.testsRun,'successful':r.wasSuccessful(),
       'errors':[{'test':str(t),'traceback':s} for t,s in r.errors],
       'failures':[{'test':str(t),'traceback':s} for t,s in r.failures],
       'skipped':[{'test':str(t),'reason':s} for t,s in r.skipped],
       'expected_failures':[str(t) for t,s in r.expectedFailures],
       'unexpected_successes':[str(t) for t in r.unexpectedSuccesses]}
open(RESULT,'w').write(json.dumps(value,indent=2)+'\\n')
raise SystemExit(0 if r.testsRun > 0 and r.wasSuccessful() and not r.skipped and not r.expectedFailures else 1)
'''
    code = 'DISCOVER=' + repr(discover) + '\nNAMES=' + repr(names or []) + '\nRESULT=' + repr(str(result_path)) + '\n' + source
    completed = run(name, ['-c', code], timeout=5400 if discover else 1800)
    outcome = {'completed': completed, 'passed': False, 'discovery': discover,
               'expected_tests': expected_tests}
    try:
        value = json.loads(result_path.read_text())
        outcome['result'] = file_record(result_path)
        outcome['tests_run'] = value.get('tests_run')
        outcome['passed'] = (completed and type(value.get('tests_run')) is int
                             and value['tests_run'] > 0 and value.get('successful') is True
                             and (expected_tests is None or value['tests_run'] == expected_tests)
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
workflow_cold_selectors = set(re.findall(r'HEPTA_HIA_[A-Z0-9_]+_COLD_REPORT', workflow))
configured_cold_selectors = set(environment_selection['effective_cold_report_selectors'])
missing_cold_selectors = sorted(workflow_cold_selectors - configured_cold_selectors)
workflow_cold_coverage = out / 'workflow-cold-report-coverage.json'
workflow_cold_coverage.write_text(json.dumps({
    'schema': 'hepta.hia.workflow-cold-coverage.v1',
    'workflow_selectors': sorted(workflow_cold_selectors),
    'configured_selectors': sorted(configured_cold_selectors),
    'missing_selectors': missing_cold_selectors,
    'complete': not missing_cold_selectors,
}, indent=2, sort_keys=True) + '\n')
if missing_cold_selectors:
    raise ValueError('workflow cold report selectors are not covered: ' + ', '.join(missing_cold_selectors))
def workflow_test_names(step_name):
    """Read one complete literal tuple from its exact source-owned step."""
    marker = '      - name: ' + step_name + '\n'
    if workflow.count(marker) != 1:
        raise ValueError('expected one exact workflow step: ' + step_name)
    section = workflow.split(marker, 1)[1]
    section = re.split(r'(?m)^      - ', section, maxsplit=1)[0]
    blocks = re.findall(r'          names = \((.*?)\n          \)', section, re.S)
    if len(blocks) != 1:
        raise ValueError('expected one complete names tuple in: ' + step_name)
    values = ast.literal_eval('(' + blocks[0] + ')')
    if (type(values) is not tuple or not values
            or any(type(value) is not str or not re.fullmatch(r'tests\.[A-Za-z0-9_.]+', value)
                   for value in values)
            or len(set(values)) != len(values)):
        raise ValueError('workflow test names are invalid or duplicated: ' + step_name)
    return list(values), blocks[0]


source_names, source_block = workflow_test_names('Core source and independent reference controls')
native_names, native_block = workflow_test_names('Native applications and actual Core memory controls')
binding_names, binding_block = workflow_test_names('Native linked loader and compiler receipt bindings')
all_blocks = re.findall(r'          names = \((.*?)\n          \)', workflow, re.S)
if sorted(all_blocks) != sorted([source_block, native_block, binding_block]):
    raise ValueError('workflow contains unaccounted or duplicated names blocks')
named = [source_names, native_names]
binding_inventory = {
    'tests.test_hia_selfhost_linked_observer.LinkedObserverNativeTests': 27,
    'tests.test_hia_original_select_fragments.CompleteOutputObservationTests': 4,
    'tests.test_hia_compile_receipt_binding.CompileReceiptNativeTests': 6,
}
if binding_names != list(binding_inventory):
    raise ValueError('the complete 37-case workflow binding inventory changed')
coverage = []
for qualified, expected_count in binding_inventory.items():
    module_name, class_name = qualified.rsplit('.', 1)
    group = ('linked-observer' if module_name in LINKED_OBSERVER_GROUP else
             'source-select-compile-receipts' if module_name in RECEIPT_GROUP else None)
    if group is None:
        raise ValueError('workflow binding class is absent from the executed complete groups')
    relative = module_name.replace('.', '/') + '.py'
    raw = (root / relative).read_bytes()
    if sha256(raw).hexdigest() != sources.get(relative):
        raise ValueError('workflow binding source changed before inventory admission')
    module_ast = ast.parse(raw, filename=relative)
    classes = [node for node in module_ast.body if isinstance(node, ast.ClassDef)
               and node.name == class_name]
    if len(classes) != 1:
        raise ValueError('workflow binding class is missing or duplicated')
    cls = classes[0]
    if (len(cls.bases) != 1 or not isinstance(cls.bases[0], ast.Attribute)
            or not isinstance(cls.bases[0].value, ast.Name)
            or cls.bases[0].value.id != 'unittest' or cls.bases[0].attr != 'TestCase'):
        raise ValueError('binding inventory gained an unaccounted inherited test base')
    methods = [node.name for node in cls.body if isinstance(node, ast.FunctionDef)
               and node.name.startswith('test_')]
    if len(methods) != expected_count or len(set(methods)) != expected_count:
        raise ValueError('binding class test count changed')
    coverage.append({'class': qualified, 'tests': methods, 'count': len(methods),
                     'complete_group': group, 'source_path': relative,
                     'source_sha256': sha256(raw).hexdigest()})
if sum(row['count'] for row in coverage) != 37:
    raise ValueError('workflow binding coverage is incomplete')
workflow_named_groups = out / 'workflow-named-groups.json'
workflow_named_groups.write_text(json.dumps({
    'schema': 'hepta.hia.workflow-named-groups.v1',
    'source_names': source_names, 'native_application_names': native_names,
    'additional_binding_names': binding_names, 'binding_coverage': coverage,
    'all_three_names_blocks_accounted_for': True,
    'binding_tests_covered_by_complete_groups': 37,
    'test_inventory_admitted_without_import_or_execution': True,
}, indent=2, sort_keys=True) + '\n')
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
    cold_raw = cold.read_bytes()
    record = json.loads(cold_raw)
    cold_ok = (cold_completed and record.get('status') == 'COLD_SELFHOST_REPLAY_PASS'
               and isinstance(record.get('checks'), dict) and bool(record['checks'])
               and all(value is True for value in record['checks'].values())
               and record.get('source_manifest') == cold_sources)
    if cold_ok:
        cold_compiler_admission = admit_fresh_cold_compiler(cold_raw)
        selected = cold_compiler_admission['selected']
        compiler_selectors = {'HEPTA_HIA_COMPILE_RECEIPT_COMPILER': selected['path'],
                              'HEPTA_HIA_COMPILE_RECEIPT_COMPILER_SHA256': selected['sha256']}
        environment.update(compiler_selectors)
        os.environ.update(compiler_selectors)
        environment_selection['effective_qualified_compiler_selectors'] = compiler_selectors
        environment_record.write_text(json.dumps(environment_selection, indent=2, sort_keys=True) + '\n')
        (out / 'cold-compiler-admission.json').write_text(json.dumps(cold_compiler_admission, indent=2, sort_keys=True) + '\n')
except (OSError, ValueError, TypeError, KeyError, AttributeError) as error:
    cold_error = repr(error)
    cold_ok = False
ok = cold_ok and ok
if cold_ok:
    ok = run('language', ['tests/test_hia_selfhost_language_coverage.py', '--output', str(out / 'language.json')]) and ok
    ok = suite('native-applications', named[1]) and ok
    groups = {
        'heap-bound': ['tests.test_hia_heap_bound_native',
                       'tests.test_hia_heap_bound_integration',
                       'tests.test_hia_heap_live_engine_native'],
        'static-budget': ['tests.test_hia_static_budget_native',
                          'tests.test_hia_static_budget_integration',
                          'tests.test_hia_native_bigints',
                          'tests.test_hia_heap_graphs_native',
                          'tests.test_hia_native_binary_graph'],
        'program-execution': ['tests.test_hia_program_execution_native',
                              'tests.test_hia_program_execution_scalars',
                              'tests.test_hia_program_execution_integration'],
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
                            'tests.test_hia_task_helpers_native'],
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
        'nominal-operations': ['tests.test_hia_composite_native_composition',
                               'tests.test_hia_enum_match_native',
                               'tests.test_hia_enum_operations_native',
                               'tests.test_hia_record_operations_native',
                               'tests.test_hia_record_transitions_native',
                               'tests.test_hia_task_operations_native'],
        'nominal-controllers': ['tests.test_hia_native_value_graph',
                                'tests.test_hia_nominal_owner_routes',
                                'tests.test_hia_call_primitive_native',
                                'tests.test_hia_nominal_terminators_native',
                                'tests.test_hia_nominal_module_native',
                                'tests.test_hia_nominal_admission_native',
                                'tests.test_hia_nominal_function_native',
                                'tests.test_hia_task_helper_cache_native'],
        'durable-execution': ['tests.test_hia_execution_budget_native',
                              'tests.test_hia_request_journal_native'],
        'retirement-state': ['tests.test_hia_retirement_state_native'],
        'worker-request': ['tests.test_hia_worker_request_native',
                           'tests.test_hia_worker_request_review',
                           'tests.test_hia_worker_native_helpers',
                           'tests.test_hia_checker_identity',
                           'tests.test_hia_checker_identity_agent'],
        'release-install': ['tests.test_hia_release_install'],
        'release-selection': ['tests.test_hia_release_selection',
                              'tests.test_hia_release_selection_review'],
        'artifact-namespace': ['tests.test_hia_artifact_namespace_native'],
        'slot-ledger': ['tests.test_hia_slot_ledger_native'],
    }
    for name, names in groups.items():
        ok = suite(name, names) and ok
    # Append complete new families; the 27 retained groups above are unchanged.
    ok = suite('source-build-and-admission', SOURCE_RELEASE_GROUP, expected_tests=72) and ok
    ok = suite('linked-observer', LINKED_OBSERVER_GROUP, expected_tests=31) and ok
    ok = suite('source-select-compile-receipts', RECEIPT_GROUP, expected_tests=19) and ok
    a_name = 'normalization-A'
    a_ok = suite(a_name, [
        'tests.test_hia_program_normalization_native.ProgramNormalizationNativeTests',
        'tests.test_hia_cpython_note_packer_native.CPythonNotePackerNativeTests.test_independent_assembler_VM_and_actual_HIA_packer_complete_bytes',
        'tests.test_hia_core_json_bytes_native.CoreJSONBytesNativeTests',
        'tests.test_hia_nominal_json_native.NominalJSONNativeTests'], expected_tests=33)
    normalization_outcomes['A'] = suite_outcomes[a_name]
    ok = a_ok and ok
    # P reuses only A's source-bound production fixture; B never gates P.
    a_manifest = out / (a_name + '-normalization') / 'ProgramNormalizationNativeTests/native/manifest.json'
    p_output = out / 'normalization-P-observations'
    p_outcome = {'passed': False, 'expected_observations': 6,
                 'physical_C_stack_qualified': False, 'whole_owner_qualified': False}
    if a_manifest.is_file():
        p_completed = run('normalization-P', [str(harness_paths['python_frame_observations']),
            '--source', str(root), '--cold-report', str(cold), '--manifest', str(a_manifest),
            '--output', str(p_output)], timeout=90)
        p_outcome['completed'] = p_completed
        try:
            p_record = json.loads((p_output / 'RESULT.json').read_bytes())
            rows = p_record.get('observations')
            p_outcome['result'] = file_record(p_output / 'RESULT.json')
            p_outcome['observations'] = len(rows) if type(rows) is list else None
            p_outcome['passed'] = (p_completed
                and p_record.get('status') == 'NO_ACCEPTANCE_DIFFERENCE_IN_SELECTED_CASES'
                and type(rows) is list and len(rows) == 6
                and [row.get('offset_from_original_limit') for row in rows] == [32, 24, 16, 12, 8, 4]
                and all(row.get('same_acceptance') is True and row.get('recursion_limit_unchanged') is True for row in rows)
                and p_record.get('differences') == [] and p_record.get('failures') == []
                and p_record.get('source_unchanged') is True
                and p_record.get('held_inputs_unchanged') is True
                and p_record.get('physical_C_stack_qualified') is False)
        except (OSError, ValueError, TypeError, AttributeError) as error:
            p_outcome['result_error'] = repr(error)
    else:
        hold('normalization-P', 'A did not produce its required source-bound manifest', expected_observations=6)
        p_outcome['completed'] = False
        p_outcome['dependency_hold'] = 'A manifest unavailable; no child observations executed'
    steps[-1]['normalization_result'] = p_outcome
    steps[-1]['passed'] = p_outcome['passed']
    normalization_outcomes['P'] = p_outcome
    ok = p_outcome['passed'] and ok

    # B is an independent historical-reference prerequisite. A/P and full
    # discovery continue even if it is unavailable; a HOLD is never a PASS.
    b_preflight_output = out / 'normalization-B-reference-prerequisite'
    b_preflight_ok = run('normalization-B-prerequisite', [
        str(harness_paths['historical_note_prerequisite']), '--source', str(root),
        '--output', str(b_preflight_output)])
    b_prerequisite = {'passed': False}
    try:
        b_record = json.loads((b_preflight_output / 'RESULT.json').read_bytes())
        b_prerequisite['result'] = file_record(b_preflight_output / 'RESULT.json')
        b_prerequisite['passed'] = (b_preflight_ok
            and b_record.get('status') == 'EXACT_HISTORICAL_REFERENCE_AVAILABLE'
            and type(b_record.get('actual_image_bytes')) is int and b_record['actual_image_bytes'] == 260
            and b_record.get('actual_image_sha256') == 'e82fd51964ce25990f24e723fb0b3270b2e8b69c7fdc2e1b3999648df070db61'
            and b_record.get('held_inputs_unchanged') is True and b_record.get('failures') == [])
        if b_prerequisite['passed']:
            tools = b_record.get('tool_inputs')
            if type(tools) is not dict or not tools or any(
                    type(path) is not str or type(digest) is not str
                    or sha256(Path(path).read_bytes()).hexdigest() != digest for path, digest in tools.items()):
                raise ValueError('historical reference tools changed after preflight')
            held_inputs_before.update(tools)
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as error:
        b_prerequisite['passed'] = False
        b_prerequisite['result_error'] = repr(error)
    normalization_outcomes['B_prerequisite'] = b_prerequisite
    steps[-1]['prerequisite_result'] = b_prerequisite
    steps[-1]['passed'] = b_prerequisite['passed']
    if b_prerequisite['passed']:
        b_ok = suite('normalization-B', [
            'tests.test_hia_cpython_note_packer_native.CPythonNotePackerNativeTests.test_original_35_hosted_mechanism_controls_on_HIA_produced_bytes'],
            expected_tests=1)
        b_outcome = dict(suite_outcomes['normalization-B'], expected_observations=35)
        try:
            b_observations = out / 'normalization-B-normalization/CPythonNotePackerNativeTests/observations.json'
            b_observation_record = json.loads(b_observations.read_bytes())
            rows = b_observation_record.get('observations')
            b_outcome['observation_result'] = file_record(b_observations)
            b_outcome['observations'] = len(rows) if type(rows) is list else None
            b_outcome['passed'] = (b_ok and type(rows) is list and len(rows) == 35
                and b_observation_record.get('source_inputs_unchanged') is True)
        except (OSError, ValueError, TypeError, AttributeError) as error:
            b_outcome['passed'] = False
            b_outcome['result_error'] = repr(error)
        steps[-1]['normalization_result'] = b_outcome
        steps[-1]['passed'] = b_outcome['passed']
    else:
        hold('normalization-B', 'exact historical 260-byte C reference prerequisite unavailable; original 35 not executed',
             expected_tests=1, expected_observations=35)
        b_outcome = {'passed': False, 'status': 'HOLD', 'execution_started': False,
                     'tests_run': 0, 'observations': 0, 'expected_tests': 1, 'expected_observations': 35}
    normalization_outcomes['B'] = b_outcome
    ok = b_outcome['passed'] and ok
    (out / 'steps.json').write_text(json.dumps(steps, indent=2) + '\n')
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
held_inputs_after = {}
for path in held_inputs_before:
    try:
        held_inputs_after[path] = sha256(Path(path).read_bytes()).hexdigest()
    except OSError as error:
        held_inputs_after[path] = {'error': repr(error)}
held_inputs_preserved = held_inputs_after == held_inputs_before
all_passed = ok and preserved and harness_preserved and held_inputs_preserved
full_outcome = suite_outcomes.get('full-retained-regression')
full_qualified = bool(a.full and full_outcome and full_outcome['passed'] and all_passed)
status = ('FULL_RETAINED_PASS' if full_qualified else
          'COMPONENTS_PASS' if all_passed and not a.full else 'HOLD')
result = {'schema': 'hepta.hia.native-rewrite-qualification.v9',
          'status': status, 'source_manifest': sources,
          'source_identity': {'head': source_before['head'], 'tree': source_before['tree'],
                              'before': file_record(source_before_path),
                              'after': file_record(source_after_path),
                              'raw_git_tree_blobs_and_modes_checked': True},
          'source_reproduction': file_record(reproduction_report) if reproduction_report.exists() else None,
          'cold_source_manifest': cold_sources, 'cold_qualified': cold_ok,
          'cold_report': file_record(cold) if cold.exists() else None,
          'cold_error': cold_error, 'cold_compiler_admission': cold_compiler_admission,
          'held_inputs_before': held_inputs_before, 'held_inputs_after': held_inputs_after,
          'held_inputs_preserved': held_inputs_preserved,
          'source_preserved': preserved, 'steps': steps,
          'harness_identity_before': harness_before, 'harness_identity_after': harness_after,
          'harness_preserved': harness_preserved,
          'discarded_development_selectors': discarded_development_selectors,
          'discarded_production_selectors': discarded_production_selectors,
          'discarded_cold_report_selectors': discarded_cold_report_selectors,
          'discarded_compiler_selectors': discarded_compiler_selectors,
          'environment_selection': file_record(environment_record),
          'workflow_cold_report_coverage': file_record(workflow_cold_coverage),
          'workflow_named_groups': file_record(workflow_named_groups),
          'source_build_and_admission': suite_outcomes.get('source-build-and-admission'),
          'normalization': normalization_outcomes,
          'normalization_physical_recursion_qualified': False,
          'normalization_whole_owner_qualified': False,
          'whole_native_delivery_qualified': False,
          'full_retained_regression_requested': a.full,
          'full_retained_regression_executed': full_outcome is not None,
          'full_retained_regression_qualified': full_qualified,
          'full_retained_regression': full_outcome}
(out / 'QUALIFICATION.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
print(json.dumps({'status': result['status'], 'steps': len(steps), 'source_preserved': preserved}), flush=True)
raise SystemExit(0 if result['status'] in {'COMPONENTS_PASS', 'FULL_RETAINED_PASS'} else 1)
