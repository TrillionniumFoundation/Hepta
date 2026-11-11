"""Four-case phase diagnostic on unchanged e03 source and retained original images.

This is a NEW diagnostic, not a qualification or replay of original requests.
The two original test bodies and their 3000/1000 ms limits are unchanged.
"""
from pathlib import Path
from hashlib import sha256
from contextlib import ExitStack
from functools import wraps
from types import SimpleNamespace
import io, json, os, shutil, sys, time, traceback, unittest
from unittest.mock import patch

REAL_TIME_NS = time.time_ns
REAL_PERF_NS = time.perf_counter_ns
BASE = Path('/home/qq/hia-native-self-rewrite-20261111-dda7')
SOURCE = BASE / 'published-v68-e03c82d1-r1/source'
OUT = Path(__file__).resolve().parent / 'run'
INPUT = BASE / 'retained-e03-inputs-v70-r2/report.json'
EXPECTED_INPUT = '61fe5d7b8299b3424e4a6e634934c23d7a7c3415e658a60a7b59bea22dd3231a'
EXPECTED_HEAD = 'e03c82d1b5b7026ead9a5942336d54273b1a6931'
EXPECTED_TREE = 'bac117a8b24c506b60a65562cf81587ee0ec0c31'
OUT.mkdir(mode=0o700, exist_ok=False)
report = {
    'schema': 'hepta.hia.e03-deadline-phase-diagnostic.v1',
    'scope': 'NEW_FOUR_CASE_DIAGNOSTIC_WITH_ORIGINAL_TEST_BODIES_AND_RETAINED_IMAGES',
    'qualification': False, 'whole_native': False, 'default_native': False,
    'legacy_deletion': False, 'product_source_modified': False,
    'original_test_deadline_ms': {'max_total_wall_ms': 3000, 'max_native_wall_ms': 1000},
    'original_results_replaced': False, 'unknown_requests_replayed': False,
    'instrumentation': 'Inclusive call durations; captures builtin clocks before original test monkeypatches. Adds observation overhead and is not qualification.',
    'cases': [], 'instrumented_functions': [], 'capture_errors': [],
}
started = REAL_PERF_NS()
active = None
events = []
stack_ids = []
call_serial = 0
tracked = {}

def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')

def file_record(path):
    path = Path(path)
    raw = path.read_bytes()
    return {'path': str(path), 'size': len(raw), 'sha256': sha256(raw).hexdigest()}

def trace_wrap(original, label):
    @wraps(original)
    def observed(*args, **kwargs):
        global call_serial
        if active is None:
            return original(*args, **kwargs)
        call_serial += 1
        identity = call_serial
        parent = stack_ids[-1] if stack_ids else None
        item = {'id': identity, 'parent': parent, 'case': active, 'function': label,
                'start_perf_ns': REAL_PERF_NS() - started,
                'start_wall_ns': str(REAL_TIME_NS())}
        if label == 'service.call' and len(args) > 1 and type(args[1]) is str:
            item['tool'] = args[1]
        elif label == 'namespace._operate' and len(args) > 1 and type(args[1]) is int:
            item['operation'] = args[1]
        elif label == 'publication._execute_native' and len(args) > 1 and type(args[1]) is str:
            item['operation'] = args[1]
        stack_ids.append(identity)
        before = REAL_PERF_NS()
        try:
            result = original(*args, **kwargs)
            item['outcome'] = 'returned'
            if label == 'service.call' and type(result) is dict:
                item['response_status'] = result.get('status')
                if type(result.get('error')) is dict:
                    item['error_code'] = result['error'].get('code')
                    item['error_phase'] = result['error'].get('phase')
            return result
        except BaseException as error:
            item['outcome'] = 'raised'
            item['exception_type'] = type(error).__name__
            raise
        finally:
            item['inclusive_ns'] = REAL_PERF_NS() - before
            item['end_wall_ns'] = str(REAL_TIME_NS())
            stack_ids.pop()
            events.append(item)
    return observed

def install(stack, owner, name, label):
    original = getattr(owner, name)
    if not callable(original):
        raise TypeError(label)
    stack.enter_context(patch.object(owner, name, trace_wrap(original, label)))
    report['instrumented_functions'].append(label)

def preserve_fixture(case):
    destination = OUT / active / 'fixture-before-original-teardown'
    destination.parent.mkdir(mode=0o700, exist_ok=True)
    state = {
        'scope': 'READ_ONLY_OBSERVATIONS_AND_FILE_COPY_BEFORE_ORIGINAL_FIXTURE_TEARDOWN',
        'copy_is_original_authority': False,
        'source_temporary_root': str(case.root),
        'session_context': case.session.context,
        'client_records': case.client.records,
    }
    try:
        db = case.service.store.db
        tables = [row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
        wanted = ('contexts', 'requests', 'execution_budgets')
        state['tables'] = {
            name: [dict(row) for row in db.execute('SELECT * FROM "' + name + '"')]
            for name in wanted if name in tables
        }
        namespace = getattr(case.service.store, 'artifact_namespace', None)
        if namespace is not None:
            state['namespace_state'] = namespace.state.snapshot()
        write_json(destination.parent / 'state-observations.json', state)
        shutil.copytree(case.root, destination, symlinks=True)
        copied = []
        for path in sorted(destination.rglob('*')):
            if path.is_file() and not path.is_symlink():
                copied.append(file_record(path))
        write_json(destination.parent / 'copied-file-hashes.json', copied)
    except BaseException:
        report['capture_errors'].append({'case': active, 'traceback': traceback.format_exc()})
        write_json(destination.parent / 'partial-state-observations.json', state)

try:
    if Path.cwd().resolve() != SOURCE:
        raise ValueError('original pinned launcher did not select the e03 source')
    sys.path.insert(0, str(SOURCE))
    report['python'] = file_record(Path(sys.executable).resolve())
    report['python_version'] = sys.version
    report['driver'] = file_record(__file__)
    discarded = {}
    for name in list(os.environ):
        if name.startswith('HEPTA_HIA_') and (
            name.endswith('_MANIFEST') or name.endswith('_COLD_REPORT') or
            '_DEVELOPMENT_' in name or name.endswith('_DEVELOPMENT')):
            value = os.environ.pop(name)
            discarded[name] = {'bytes': len(os.fsencode(value)),
                               'sha256': sha256(os.fsencode(value)).hexdigest()}
    report['discarded_selector_values'] = discarded
    raw = INPUT.read_bytes()
    if sha256(raw).hexdigest() != EXPECTED_INPUT:
        raise ValueError('retained input receipt changed')
    inputs = json.loads(raw)
    if inputs.get('status') != 'ORIGINAL_RETAINED_INPUTS_VERIFIED':
        raise ValueError('retained original inputs were not verified')
    report['retained_inputs'] = file_record(INPUT)
    for info in (inputs['cold'], inputs['nested_report'], *inputs['generations']):
        tracked[info['path']] = info['sha256']
    for joint in inputs['joint_builds'].values():
        tracked[joint['record']['path']] = joint['record']['sha256']
        for info in joint['manifests'].values():
            tracked[info['record']['path']] = info['record']['sha256']
            tracked[info['image']['path']] = info['image']['sha256']
    for path, expected in tracked.items():
        if sha256(Path(path).read_bytes()).hexdigest() != expected:
            raise ValueError('retained artifact changed: ' + path)
    report['retained_artifacts_before'] = tracked

    from tools import hia_core_source_identity as source_identity
    from tools import hia_selfhost_contract as contract
    from tools import build_hia_json_preflight as preflight_builder
    from tools import build_hia_artifact_publication as publication_builder
    from hepta import artifact_publication_native as publication
    from hepta import hia_artifact_namespace_native as namespace
    from hepta import hia_agent_service as service
    from hepta import hia_execution_budget as budget
    from hepta.hia_agent_store import AgentStore
    from tests import test_hia_agent_native_tools as originals
    from tests.test_hia_artifact_namespace_native import ArtifactNamespaceNativeTests
    from tests.test_hia_slot_ledger_native import SlotLedgerNativeTests
    if source_identity.ROOT.resolve() != SOURCE:
        raise ValueError('identity helper belongs to another source')
    before_source = source_identity._source_state()
    if before_source['head'] != EXPECTED_HEAD or before_source['tree'] != EXPECTED_TREE or before_source['status']:
        raise ValueError('original source is not the pinned clean e03 tree')
    write_json(OUT / 'source-before.json', before_source)
    original_contract = contract.validate_contract()
    if len(original_contract['source_identity']['files']) != 751:
        raise ValueError('original source closure differs')
    report['source'] = {'head': EXPECTED_HEAD, 'tree': EXPECTED_TREE,
                        'contract_files': 751, 'complete_git_files': len(before_source['files'])}
    original_teardown = originals.AgentToolCase.tearDown
    def preserving_teardown(case):
        preserve_fixture(case)
        return original_teardown(case)

    methods = (
        'test_expired_evaluation_is_rejected_before_any_reference_or_native_runner',
        'test_reference_loop_cannot_restart_or_overrun_frozen_context_deadline',
    )
    report['test_methods'] = methods
    with ExitStack() as observation_stack:
        for owner, name, label in (
            (contract, 'file_digests', 'contract.file_digests'),
            (contract, 'support_contract', 'contract.support_contract'),
            (contract, 'validate_contract', 'contract.validate_contract'),
            (preflight_builder, 'current_sources', 'builder.current_sources'),
            (publication_builder, 'current_sources', 'publication_builder.current_sources'),
            (publication, '_admitted_code', 'publication._admitted_code'),
            (publication, '_execute_native', 'publication._execute_native'),
            (namespace.NativeArtifactNamespaceStore, '_operate', 'namespace._operate'),
            (namespace.NamespaceState, 'call', 'namespace.state.call'),
            (service.HIAAgentService, 'call', 'service.call'),
            (service.HIAAgentService, '_hia_context', 'service._hia_context'),
            (service.HIAAgentService, '_hia_verify', 'service._hia_verify'),
            (service.HIAAgentService, '_hia_emit', 'service._hia_emit'),
            (service.HIAAgentService, '_hia_evaluate', 'service._hia_evaluate'),
            (service.HIAAgentService, '_required_claims', 'service._required_claims'),
            (originals.AgentToolCase, 'build_pair', 'fixture.build_pair'),
        ):
            install(observation_stack, owner, name, label)
        observation_stack.enter_context(patch.object(originals.AgentToolCase, 'tearDown', preserving_teardown))
        for route in ('namespace', 'ledger'):
            manifests = inputs['joint_builds'][route]['manifests']
            dependency = SimpleNamespace(
                manifest=Path(manifests['namespace_manifest']['record']['path']),
                byte_manifest=Path(manifests['byte_manifest']['record']['path']),
                request_manifest=Path(manifests['request_manifest']['record']['path']),
                budget_manifest=Path(manifests['budget_manifest']['record']['path']),
            )
            ledger = SimpleNamespace(dependencies=dependency,
                manifest=Path(manifests['ledger_manifest']['record']['path'])) if route == 'ledger' else None
            with ExitStack() as selected:
                if route == 'namespace':
                    selected.enter_context(ArtifactNamespaceNativeTests.selected(dependency, joint=True))
                    selected.enter_context(ArtifactNamespaceNativeTests.old_namespace_forbidden(
                        dependency, hashing=False, payload_io=False))
                else:
                    selected.enter_context(SlotLedgerNativeTests.selected(ledger))
                    selected.enter_context(SlotLedgerNativeTests.old_ledger_forbidden(ledger))
                    def forbidden(*args, **kwargs):
                        raise AssertionError('original selected owner entered')
                    for name in ('put', 'json', 'get', 'get_json', 'resolve_uri', 'profile', 'check_profile', 'transaction'):
                        selected.enter_context(patch.object(AgentStore, '_' + name + '_reference', side_effect=forbidden))
                    selected.enter_context(patch.object(AgentStore, '_ref', side_effect=forbidden))
                selected.enter_context(patch.object(service.HIAAgentService, '_call_reference',
                    side_effect=AssertionError('old request policy')))
                for cls in (budget._ReferenceExecutionBudgetStore, budget._ReferenceBudgetClaim):
                    selected.enter_context(patch.object(cls, '__init__', side_effect=AssertionError('old budget policy')))
                for method in methods:
                    active = route + '--' + method
                    case_dir = OUT / active
                    case_dir.mkdir(mode=0o700, exist_ok=False)
                    case_start = REAL_PERF_NS()
                    first = len(events)
                    case = originals.NativeLifecycleTests(method)
                    stream = io.StringIO()
                    result = unittest.TextTestRunner(stream=stream, verbosity=2).run(unittest.TestSuite([case]))
                    active = None
                    duration = REAL_PERF_NS() - case_start
                    log = stream.getvalue()
                    (case_dir / 'unittest.log').write_text(log)
                    selected_events = events[first:]
                    write_json(case_dir / 'events.json', selected_events)
                    aggregate = {}
                    for event in selected_events:
                        item = aggregate.setdefault(event['function'], {'calls': 0, 'inclusive_ns': 0, 'raised': 0})
                        item['calls'] += 1
                        item['inclusive_ns'] += event['inclusive_ns']
                        item['raised'] += event['outcome'] == 'raised'
                    item = {'route': route, 'test': method, 'tests_run': result.testsRun,
                            'successful': result.wasSuccessful(), 'duration_ns': duration,
                            'failures': [{'test': str(t), 'traceback': text} for t, text in result.failures],
                            'errors': [{'test': str(t), 'traceback': text} for t, text in result.errors],
                            'skips': [{'test': str(t), 'reason': why} for t, why in result.skipped],
                            'expected_failures': [str(t) for t, _ in result.expectedFailures],
                            'unexpected_successes': [str(t) for t in result.unexpectedSuccesses],
                            'aggregate_inclusive': aggregate, 'event_count': len(selected_events),
                            'log': file_record(case_dir / 'unittest.log'),
                            'events': file_record(case_dir / 'events.json')}
                    report['cases'].append(item)
                    write_json(OUT / 'report.json', report)
                    print(json.dumps({'route': route, 'test': method, 'successful': result.wasSuccessful(),
                                      'failures': len(result.failures), 'errors': len(result.errors),
                                      'duration_ns': duration}), flush=True)
                    if result.testsRun != 1 or result.skipped or result.expectedFailures or result.unexpectedSuccesses:
                        raise AssertionError('diagnostic did not execute exactly one unchanged original case')
    after_source = source_identity._source_state()
    write_json(OUT / 'source-after.json', after_source)
    report['source_preserved'] = after_source == before_source
    report['retained_artifacts_preserved'] = all(
        sha256(Path(path).read_bytes()).hexdigest() == digest for path, digest in tracked.items())
    report['harness_preserved'] = file_record(__file__) == report['driver']
    if not all(report[key] for key in ('source_preserved', 'retained_artifacts_preserved', 'harness_preserved')):
        raise AssertionError('diagnostic inputs changed')
    if len(report['cases']) != 4 or report['capture_errors']:
        raise AssertionError('diagnostic observation or preservation incomplete')
    report['status'] = 'FOUR_ORIGINAL_CASES_OBSERVED'
except BaseException:
    report['status'] = 'DIAGNOSTIC_HARNESS_FAILED'
    report['harness_exception'] = traceback.format_exc()
    raise
finally:
    active = None
    report['duration_ns'] = REAL_PERF_NS() - started
    report['observed_tests_run'] = sum(case['tests_run'] for case in report['cases'])
    report['observed_tests_successful'] = len(report['cases']) == 4 and all(case['successful'] for case in report['cases'])
    write_json(OUT / 'report.json', report)
    print(json.dumps({'status': report.get('status'), 'report': file_record(OUT / 'report.json'),
                      'cases': len(report['cases'])}), flush=True)

raise SystemExit(0 if report['observed_tests_successful'] else 1)
