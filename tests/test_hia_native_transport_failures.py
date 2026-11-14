"""Native transport uncertainty is distinct from confirmed foreign rejection.

These controls retain the three original component test modules unchanged.
Disposable child processes own deliberately unknown SQLite/continuation
objects until process termination; no test clears their custody registries.
"""
from __future__ import annotations

import ast
from contextlib import ExitStack, redirect_stdout
import ctypes
import gc
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import sqlite3
import struct
import subprocess
import sys
import tempfile
import unittest
import weakref
from unittest.mock import patch

from hepta import hia_agent_service as service_api
from hepta import hia_agent_store as store_api
from hepta import hia_service_context_native as context_native
from hepta import hia_cost_ledger_native as ledger_native
from hepta import hia_store_lifecycle_native as store_native

ROOT = Path(__file__).resolve().parents[1]
COLD = 'HEPTA_HIA_NATIVE_TRANSPORT_COLD_REPORT'
DEVELOPMENT = 'HEPTA_HIA_NATIVE_TRANSPORT_DEVELOPMENT_COMPILER'
EVIDENCE = 'HEPTA_HIA_NATIVE_TRANSPORT_EVIDENCE'
REJECTIONS = (ValueError, TypeError, OSError, OverflowError, RecursionError, sqlite3.Error)
ORIGINAL_TEST_SHA256 = {'tests/test_hia_service_context_native.py': 'db7651b17a26b2606cb4c8c556b222a89f9d42b1e21b9bc97380b6f1dfdb3f9c', 'tests/test_hia_store_lifecycle_native.py': '27b6490472f2d1edeb806a28d1d382662bd83574f433b0f2f1f1122e05dfa583', 'tests/test_hia_cost_ledger_native.py': '3dfaf1397f66d8cc0c12b9af2a9c61ad9e017c4096ac90d06f73005cead005af'}


class MixedRejected(ValueError, RuntimeError):
    pass


def errors():
    for kind in (ValueError, TypeError, OSError, OverflowError, RecursionError,
                 sqlite3.OperationalError, MixedRejected, RuntimeError,
                 KeyboardInterrupt, SystemExit):
        yield kind.__name__, kind('injected native transport failure')


def observe_error(call):
    try:
        call()
    except BaseException as error:
        return error
    raise AssertionError('expected an actual exception')


def check_transport(error, injected, unknown):
    convert = isinstance(injected, Exception) and (
        not isinstance(injected, RuntimeError) or isinstance(injected, REJECTIONS))
    if convert:
        assert type(error) is unknown, (type(error), type(injected))
        assert error.__cause__ is injected
        assert not isinstance(error, REJECTIONS)
    else:
        assert error is injected, (type(error), type(injected))


def request_row(service, tool, arguments):
    key = store_api.digest({'tool': tool, 'key': arguments['request_key']})
    row = service.store.db.execute('SELECT * FROM requests WHERE key=?', (key,)).fetchone()
    assert row is not None
    return dict(row)


def pins():
    from tools.hia_selfhost_contract import file_digests
    return {**file_digests(), 'tests/test_hia_native_transport_failures.py':
            sha256(Path(__file__).read_bytes()).hexdigest()}


def encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(',', ':'), allow_nan=False).encode()


def clean_environment():
    return {key: value for key, value in os.environ.items()
            if key not in ('PYTHONPATH', 'PYTHONHOME') and not key.startswith('HEPTA_HIA_')}


class NativeTransportSourceTests(unittest.TestCase):
    def test_rejection_family_and_original_component_tests_are_exact(self):
        tree = ast.parse((ROOT / 'hepta/hia_agent_service.py').read_bytes())
        service = next(node for node in tree.body
                       if isinstance(node, ast.ClassDef) and node.name == 'HIAAgentService')
        method = next(node for node in service.body
                      if isinstance(node, ast.FunctionDef) and node.name == '_reference_call')
        handlers = [node for node in ast.walk(method) if isinstance(node, ast.ExceptHandler)
                    and isinstance(node.type, ast.Tuple)]
        self.assertEqual(len(handlers), 1)
        expression = ast.Expression(handlers[0].type)
        caught = eval(compile(expression, '<original request catch family>', 'eval'), vars(service_api))
        self.assertEqual(caught, REJECTIONS)
        self.assertTrue(issubclass(RecursionError, RuntimeError))
        self.assertTrue(issubclass(MixedRejected, RuntimeError))
        for module in (context_native, ledger_native, store_native):
            self.assertEqual(module._REQUEST_REJECTIONS, caught)
        self.assertEqual(len(ORIGINAL_TEST_SHA256), 3)
        for name, digest in ORIGINAL_TEST_SHA256.items():
            self.assertEqual(sha256((ROOT / name).read_bytes()).hexdigest(), digest)


class NativeTransportNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cold, development, evidence = (os.environ.get(name) for name in (COLD, DEVELOPMENT, EVIDENCE))
        if (cold is None) == (development is None) or cold == '' or development == '' or evidence == '':
            raise ValueError('choose exactly one nonempty matching cold report or explicit development compiler')
        cls.temporary = None
        if evidence is None:
            cls.temporary = tempfile.TemporaryDirectory(prefix='hia-native-transport-')
            cls.root = Path(cls.temporary.name)
        else:
            cls.root = Path(evidence).absolute()
            cls.root.mkdir(mode=0o700, parents=True, exist_ok=False)
        if cold is not None:
            outer = json.loads(Path(cold).read_bytes())
            nested = json.loads(Path(outer['nested_report']).read_bytes())
            compiler = Path(nested['generations'][-1]['produced_image'])
        else:
            compiler = Path(development)
        cls.compiler, cls.compiler_raw, cls.cold = compiler, compiler.read_bytes(), cold
        cls.before = pins()
        from tools.build_hia_service_context import build as context_build
        from tools.build_hia_cost_ledger import build as ledger_build
        from tools.build_hia_store_lifecycle import build as store_build
        cls.manifests = {name: str(build(cls.root / name, compiler, cold, development=cold is None))
                         for name, build in (('context', context_build), ('ledger', ledger_build), ('store', store_build))}
        cls.built = {str(path): sha256(path.read_bytes()).hexdigest()
                     for name in cls.manifests for path in sorted((cls.root / name).rglob('*')) if path.is_file()}

    @classmethod
    def tearDownClass(cls):
        after = pins()
        stable = (after == cls.before and cls.compiler.read_bytes() == cls.compiler_raw
                  and all(sha256(Path(path).read_bytes()).hexdigest() == digest
                          for path, digest in cls.built.items()))
        record = {'schema': 'hepta.hia.native-transport-test-custody.v1',
            'matching_cold_report': cls.cold, 'manifests': cls.manifests,
            'compiler_sha256': sha256(cls.compiler_raw).hexdigest(),
            'source_before': cls.before, 'source_after': after, 'build_files': cls.built,
            'source_compiler_and_build_unchanged': stable,
            'test_result_owned_by_outer_runner': True, 'whole_native_delivery_qualified': False}
        (cls.root / 'component-custody.json').write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
        if cls.temporary is not None:
            cls.temporary.cleanup()
        if not stable:
            raise AssertionError('native transport source, compiler or build changed')

    def run_child(self, kind):
        directory = self.root / self._testMethodName
        directory.mkdir()
        script = ('import sys;sys.path.insert(0,sys.argv.pop(1));'
                  'from tests.test_hia_native_transport_failures import run_child;run_child(*sys.argv[1:])')
        result = subprocess.run([sys.executable, '-I', '-B', '-c', script, str(ROOT), kind,
            str(directory), json.dumps(self.manifests)], cwd=directory, env=clean_environment(),
            capture_output=True, timeout=120)
        (directory / 'stdout.log').write_bytes(result.stdout)
        (directory / 'stderr.log').write_bytes(result.stderr)
        self.assertEqual(result.returncode, 0, result.stdout.decode(errors='replace') + result.stderr.decode(errors='replace'))
        record = json.loads((directory / 'observations.json').read_bytes())
        self.assertEqual(record['status'], 'PASS')
        return record

    def test_public_context_journal_preserves_unknown_intent_and_owner(self):
        self.run_child('context_public')

    def test_context_arithmetic_and_foreign_exception_identity(self):
        self.run_child('context_math')

    def test_ledger_binary_and_decoder_failures_never_send_foreign_error_ACK(self):
        self.run_child('ledger_matrix')

    def test_public_evaluation_ledger_failure_is_unknown_but_foreign_error_is_rejected(self):
        self.run_child('ledger_public')

    def test_store_unknown_connection_lives_and_confirmed_foreign_error_is_original(self):
        self.run_child('store_owner')

    def test_original_worker_distinguishes_store_construction_and_close(self):
        self.run_child('store_worker')


def _child_context_public(root, manifests):
    from tests.test_hia_service_context_native import context_arguments
    image = context_native.installed_service_context(manifests['context'])
    observations = []
    for name, injected in errors():
        service = service_api.HIAAgentService(root / name)
        arguments = context_arguments(service)
        reference = weakref.ref(service)
        calls, entry = [], image._entry

        def lost(source, size, output, capacity, state, extent):
            words = struct.unpack('<10Q', ctypes.string_at(source, size)) if size == 80 else None
            result = entry(source, size, output, capacity, state, extent)
            if words is not None and words[0] == context_native.REQUEST_MAGIC:
                calls.append((words[1], words[3]))
                if words[1:4:2] == (2, 44):
                    raise injected
            return result

        with patch.dict(os.environ, {context_native.SELECTOR: manifests['context']}), \
                patch.object(image, '_entry', lost), \
                patch.object(service_api, '_NATIVE_SERVICE_CONTEXT_FREEZE_REFERENCE',
                             side_effect=AssertionError('retained context entered')):
            error = observe_error(lambda: service.call('hia_context', arguments))
        check_transport(error, injected, context_native.ServiceContextUnknown)
        retained = request_row(service, 'hia_context', arguments)
        assert retained['state'] == 'running' and retained['response'] is None
        assert service.store.db.execute('SELECT COUNT(*) FROM contexts').fetchone()[0] == 1
        assert service.store.db.execute('SELECT COUNT(*) FROM execution_budgets').fetchone()[0] == 0
        frame, = [frame for frame in context_native._FRAME_CUSTODY.values() if frame.service is service]
        assert frame.fenced and frame.unconfirmed
        assert not any(event == 3 for event, port in calls)
        replay = service.call('hia_context', arguments)
        assert replay['status'] == 'rejected' and replay['error']['code'] == 'E_HIA_REQUEST_UNKNOWN'
        assert request_row(service, 'hia_context', arguments) == retained
        assert service.store.db.execute('SELECT COUNT(*) FROM contexts').fetchone()[0] == 1
        refused = observe_error(lambda: context_native.ContextFrame(image, 1, service, arguments))
        assert type(refused) is context_native.ServiceContextUnknown
        del service, arguments, frame, error
        gc.collect()
        assert reference() is not None
        assert reference().store.db.execute('SELECT 1').fetchone()[0] == 1
        observations.append({'fault': name, 'request': retained, 'replay': replay,
                             'context_inserts': 1, 'failure_event_sent': False, 'owner_live': True})
    return {'cases': observations, 'unknown_owners': context_native.unconfirmed_context_count()}


def _child_context_math(root, manifests):
    from tests.hia_service_context_fixtures import Fixture
    image = context_native.installed_service_context(manifests['context'])
    observations = []
    for point in ('entry', 'decode'):
        for name, injected in errors():
            fixture = Fixture()
            frame = context_native.ContextFrame(image, 4, fixture.service, fixture.context, namespace=fixture.namespace)
            events, entry = [], image._entry
            unpack = struct.unpack_from

            def actual(source, size, output, capacity, state, extent):
                magic, event = unpack('<2Q', ctypes.string_at(source, 16))
                result = entry(source, size, output, capacity, state, extent)
                if magic == context_native.REQUEST_MAGIC:
                    events.append(event)
                if point == 'entry' and magic == context_native.MATH_MAGIC:
                    raise injected
                return result

            def decoded(format, buffer, *arguments):
                result = unpack(format, buffer, *arguments)
                if point == 'decode' and format == '<4Q' and result[0] == context_native.MATH_RESULT_MAGIC:
                    raise injected
                return result

            with patch.object(image, '_entry', actual), patch.object(context_native.struct, 'unpack_from', decoded):
                error = observe_error(frame.finish)
            check_transport(error, injected, context_native.ServiceContextUnknown)
            assert frame.fenced and frame.unconfirmed and frame.native_failed
            assert 3 not in events
            assert id(frame) in context_native._FRAME_CUSTODY
            assert fixture.connection.execute('SELECT 1').fetchone()[0] == 1
            observations.append({'point': point, 'fault': name, 'failure_event_sent': False})
    foreign = []
    for name, injected in errors():
        fixture = Fixture()

        def provider(*args):
            raise injected

        fixture.service._profile = provider
        frame = context_native.ContextFrame(image, 1, fixture.service, fixture.args, namespace=fixture.namespace)
        error = observe_error(frame.finish)
        assert error is injected
        assert frame.receipt.phase == 5 and not frame.unconfirmed
        assert id(frame) not in context_native._FRAME_CUSTODY
        fixture.close()
        foreign.append({'fault': name, 'identity_preserved': True, 'confirmed_failure': True})
    return {'native_faults': observations, 'foreign_controls': foreign}


def _child_ledger_matrix(root, manifests):
    image = ledger_native.installed_cost_ledger(manifests['ledger'])
    service = service_api.HIAAgentService(root / 'state')
    policy = service.store.json({'external_costs': {'model_wall_ns': None},
        'external_costs_complete': False, 'expected_invocations': '0'}, 'cost-policy')
    context = {'ref': {'id': 'ctx'}, 'budget': {'cost_policy': policy}}
    service.store.db.execute('INSERT INTO costs(context_id,tool,request_id,wall_ns,status,details) VALUES(?,?,?,?,?,?)',
                            ('ctx', 'fixture', 'fixture', '17', 'completed', '{}'))
    observations = []
    for point in ('ack', 'binary_entry', 'binary_decode'):
        for name, injected in errors():
            frame = ledger_native.CostLedgerFrame(image, service, context, 9, 3)
            events, entry, unpack = [], image._entry, struct.unpack_from

            def actual(source, size, output, capacity, state, extent):
                raw = ctypes.string_at(source, size)
                event = unpack('<2Q', raw)[1]
                result = entry(source, size, output, capacity, state, extent)
                events.append(event)
                if point == 'ack' and size == 80 and event == 2 and unpack('<10Q', raw)[3] == 1:
                    raise injected
                if point == 'binary_entry' and event == 10:
                    raise injected
                return result

            def decoded(format, buffer, *arguments):
                result = unpack(format, buffer, *arguments)
                if point == 'binary_decode' and format == '<2Q' and result[0] == ledger_native.RESULT_MAGIC:
                    raise injected
                return result

            with patch.object(image, '_entry', actual), patch.object(ledger_native.struct, 'unpack_from', decoded):
                error = observe_error(frame.finish)
            check_transport(error, injected, ledger_native.CostLedgerUnknown)
            assert frame.fenced and frame.native_failed and not frame.finished
            assert 3 not in events
            assert type(observe_error(frame.finish)) is ledger_native.CostLedgerUnknown
            observations.append({'point': point, 'fault': name, 'failure_event_sent': False,
                                 'terminal_foreign_failure_fabricated': False})
    foreign = []
    for name, injected in errors():
        frame = ledger_native.CostLedgerFrame(image, service, context, 9, 3)
        events, entry = [], image._entry

        def actual(source, size, output, capacity, state, extent):
            event = struct.unpack('<2Q', ctypes.string_at(source, 16))[1]
            value = entry(source, size, output, capacity, state, extent)
            events.append(event)
            return value

        def provider(*args, **kwargs):
            raise injected

        with patch.object(service_api, 'decode_data', provider), patch.object(image, '_entry', actual):
            error = observe_error(frame.finish)
        assert error is injected
        assert frame.finished and not frame.native_failed and frame.receipt[2] == 5
        assert events.count(3) == 1
        foreign.append({'fault': name, 'identity_preserved': True, 'confirmed_failure': True})
    conversions = []
    for port in (11, 14):
        frame = ledger_native.CostLedgerFrame(image, service, context, 9, 3)
        injected = TypeError('confirmed identity encoding failure')
        events, entered, entry = [], [], image._entry
        identity_bytes = ledger_native.identity_bytes

        def actual(source, size, output, capacity, state, extent):
            event = struct.unpack('<2Q', ctypes.string_at(source, 16))[1]
            result = entry(source, size, output, capacity, state, extent)
            events.append(event)
            return result

        def encode(value):
            if frame.receipt[0] == port:
                entered.append(len(events))
                raise injected
            return identity_bytes(value)

        # An injected failure at the foreign encoding seam is deliberately
        # distinct from a claim that public SQLite rows admit opaque objects.
        with patch.object(ledger_native, 'identity_bytes', encode), patch.object(image, '_entry', actual):
            error = observe_error(frame.finish)
        assert error is injected
        assert frame.finished and not frame.native_failed and frame.receipt[2] == 5
        assert len(entered) == 1 and events[entered[0]:] == [3]
        conversions.append({'port': port, 'identity_preserved': True,
                            'native_arithmetic_entered_after_failure': False,
                            'confirmed_failure': True})
    service.close()
    return {'native_faults': observations, 'foreign_controls': foreign,
            'identity_encoding_controls': conversions}


def _child_ledger_public(root, manifests):
    from tests.test_hia_agent_native_tools import AgentToolCase
    from hepta import hia_agent_runner
    image = ledger_native.installed_cost_ledger(manifests['ledger'])
    case = AgentToolCase('runTest')
    case.setUp()
    workload = {'schema': 'hepta.hia.agent.workload.v1', 'cases': [{
        'function': 'transform', 'arguments': [0], 'expected': {'status': 'returned', 'values': [7]}}],
        'warmup_iterations': 0, 'repetitions': 1}
    _base, _candidate, baseline, built, receipts = case.build_pair(workload=workload,
        budget={'max_total_wall_ms': 120000, 'max_native_wall_ms': 60000})
    os.environ[ledger_native.SELECTOR] = manifests['ledger']
    records = []
    for point, injected in (('ack', ValueError('lost ledger read ACK')),
                            ('binary_entry', OSError('lost ledger sum')),
                            ('binary_decode', RecursionError('lost ledger decode'))):
        args = case.session.arguments(baseline_artifact=baseline['native_artifact'],
            candidate_artifact=built['native_artifact'], build_receipt=built['build_receipt'],
            verification_receipts=receipts)
        entry, unpack, actual_runner = image._entry, struct.unpack_from, hia_agent_runner.run_native_batch
        events, children = [], []

        def observed(*arguments, **keywords):
            value = actual_runner(*arguments, **keywords)
            if keywords.get('_mode') != 'reference':
                children.append(value)
            return value

        def actual(source, size, output, capacity, state, extent):
            raw = ctypes.string_at(source, size)
            event = unpack('<2Q', raw)[1]
            value = entry(source, size, output, capacity, state, extent)
            events.append(event)
            if point == 'ack' and size == 80 and event == 2 and unpack('<10Q', raw)[3] == 1:
                raise injected
            if point == 'binary_entry' and event == 10:
                raise injected
            return value

        def decoded(format, buffer, *arguments):
            value = unpack(format, buffer, *arguments)
            if point == 'binary_decode' and format == '<2Q' and value[0] == ledger_native.RESULT_MAGIC:
                raise injected
            return value

        with patch.object(image, '_entry', actual), patch.object(ledger_native.struct, 'unpack_from', decoded), \
                patch.object(hia_agent_runner, 'run_native_batch', observed), \
                patch.object(service_api.HIAAgentService, '_cost_ledger_reference',
                             side_effect=AssertionError('retained ledger entered')):
            error = observe_error(lambda: case.service.call('hia_evaluate', args))
        check_transport(error, injected, ledger_native.CostLedgerUnknown)
        assert len(children) == 2 and all(row['started'] and row['termination_confirmed'] for row in children)
        assert 3 not in events
        row = request_row(case.service, 'hia_evaluate', args)
        assert row['state'] == 'running' and row['response'] is None
        budget = dict(case.service.store.db.execute('SELECT * FROM execution_budgets WHERE context_id=?',
                      (args['context']['id'],)).fetchone())
        assert budget['owner'] is None and int(budget['used_native_ns']) > 0
        with patch.object(hia_agent_runner, 'run_native_batch', side_effect=AssertionError('unknown request reran native')):
            replay = case.service.call('hia_evaluate', args)
        assert replay['error']['code'] == 'E_HIA_REQUEST_UNKNOWN'
        assert request_row(case.service, 'hia_evaluate', args) == row
        assert dict(case.service.store.db.execute('SELECT * FROM execution_budgets WHERE context_id=?',
                    (args['context']['id'],)).fetchone()) == budget
        records.append({'point': point, 'request': row, 'budget': budget, 'native_children': children, 'replay': replay})
    # The original foreign JSON decoder still owns a malformed row rejection.
    case.service.store.db.execute('INSERT INTO costs(context_id,tool,request_id,wall_ns,status,details) VALUES(?,?,?,?,?,?)',
        (case.session.context['id'], 'fixture', 'bad-json', '1', 'completed', '{invalid-json'))
    args = case.session.arguments(baseline_artifact=baseline['native_artifact'],
        candidate_artifact=built['native_artifact'], build_receipt=built['build_receipt'], verification_receipts=receipts)
    response = case.service.call('hia_evaluate', args)
    row = request_row(case.service, 'hia_evaluate', args)
    assert response['status'] == 'rejected' and response['error']['code'] != 'E_HIA_REQUEST_UNKNOWN'
    assert row['state'] == 'completed' and row['response'] is not None
    with patch.object(hia_agent_runner, 'run_native_batch', side_effect=AssertionError('cached foreign rejection reran native')):
        assert case.service.call('hia_evaluate', args) == response
    records.append({'point': 'confirmed_foreign_JSON', 'request': row, 'response': response})
    case.tearDown()
    return {'cases': records}


def _child_store_owner(root, manifests):
    image = store_native.installed_store_lifecycle(manifests['store'])
    real_connect = sqlite3.connect
    closed, connections, observations = [], [], []

    class Connection(sqlite3.Connection):
        def close(self):
            closed.append(id(self))
            return super().close()

    def connect(*arguments, **keywords):
        value = real_connect(*arguments, **keywords, factory=Connection)
        connections.append(weakref.ref(value))
        return value

    for name, injected in errors():
        entry, events = image._entry, []

        def lost(source, size, output, capacity, state, extent):
            words = struct.unpack('<10Q', ctypes.string_at(source, size))
            value = entry(source, size, output, capacity, state, extent)
            events.append(words[1])
            if (words[1], words[3]) == (2, 23):
                raise injected
            return value

        before = store_native.unconfirmed_lifecycle_count()
        with patch.dict(os.environ, {store_native.SELECTOR: manifests['store']}), \
                patch.object(store_api.sqlite3, 'connect', connect), patch.object(image, '_entry', lost):
            error = observe_error(lambda: store_api.AgentStore(root / name))
        check_transport(error, injected, store_native.StoreLifecycleUnknown)
        assert store_native.unconfirmed_lifecycle_count() == before + 1
        frame = next(frame for frame in reversed(list(store_native._FRAME_CUSTODY.values()))
                     if frame.unconfirmed and frame.receipt.port == 23)
        assert frame.fenced and 3 not in events
        assert connections[-1]() is frame.store.db
        assert frame.store.db.execute('SELECT 1').fetchone() == (1,)
        assert type(observe_error(frame.store.close)) is store_native.StoreLifecycleUnknown
        assert type(observe_error(lambda: frame.call(2))) is store_native.StoreLifecycleUnknown
        reference = weakref.ref(frame.store)
        del frame, error
        gc.collect()
        assert reference() is not None and connections[-1]() is not None
        assert closed == []
        observations.append({'fault': name, 'connection_live': True, 'explicit_close_count': 0,
                             'failure_event_sent': False, 'owner_retained': True})
    foreign = []
    for name, injected in errors():
        before = store_native.unconfirmed_lifecycle_count()

        def failed(*arguments, **keywords):
            raise injected

        with patch.dict(os.environ, {store_native.SELECTOR: manifests['store']}), \
                patch.object(store_api.sqlite3, 'connect', failed):
            error = observe_error(lambda: store_api.AgentStore(root / ('foreign-' + name)))
        assert error is injected
        assert store_native.unconfirmed_lifecycle_count() == before
        foreign.append({'fault': name, 'identity_preserved': True, 'confirmed_failure': True})
    assert closed == []
    return {'native_faults': observations, 'foreign_controls': foreign,
            'unknown_owners': store_native.unconfirmed_lifecycle_count()}


def _child_store_worker(root, manifests):
    from hepta.hia_agent_worker import main as worker
    from hepta.hia_native_helpers import ABI, SCHEMA, TARGET, native_helpers_scope
    from tests.test_hia_service_context_native import context_arguments
    manifest = Path(manifests['store'])
    bundle = root / 'bundle.json'
    bundle.write_bytes(encoded({'schema': SCHEMA, 'target': TARGET, 'abi': ABI, 'helpers': [{
        'selector': store_native.SELECTOR, 'manifest_path': str(manifest),
        'manifest_sha256': sha256(manifest.read_bytes()).hexdigest()}]}))
    bundle_sha = sha256(bundle.read_bytes()).hexdigest()
    records = []
    for kind in ('transport_construct', 'transport_close', 'foreign_construct', 'foreign_close'):
        state = root / kind
        with native_helpers_scope(str(bundle), bundle_sha):
            service = service_api.HIAAgentService(state)
            arguments = context_arguments(service)
            catalog_sha256 = service.catalog_sha256
            service.close()
        request = {'schema': 'hia-agent-worker-request-v1', 'tool': 'hia_context',
            'arguments': arguments, 'profile_sha256': 'a' * 64, 'catalog_sha256': catalog_sha256}
        request['request_sha256'] = sha256(encoded(request)).hexdigest()
        injected = OSError('original foreign provider failed') if kind.startswith('foreign') else ValueError('native lifecycle ACK lost')
        initialize = store_native.NativeStoreLifecycleImage.__init__
        real_connect = sqlite3.connect

        def image_init(self, *arguments, **keywords):
            initialize(self, *arguments, **keywords)
            entry = self._entry

            def lost(source, size, output, capacity, buffer, extent):
                words = struct.unpack('<10Q', ctypes.string_at(source, size))
                result = entry(source, size, output, capacity, buffer, extent)
                target = 23 if kind.endswith('construct') else 71
                if kind.startswith('transport') and (words[1], words[3]) == (2, target):
                    raise injected
                return result

            self._entry = lost

        class Connection(sqlite3.Connection):
            def close(self):
                super().close()
                if kind == 'foreign_close':
                    raise injected

        def connect(*arguments, **keywords):
            if kind == 'foreign_construct':
                raise injected
            return real_connect(*arguments, **keywords, factory=Connection)

        stdin = io.TextIOWrapper(io.BytesIO(encoded(request)), encoding='utf-8')
        output = io.BytesIO()
        stdout = io.TextIOWrapper(output, encoding='utf-8')
        error = None
        with patch.object(store_native.NativeStoreLifecycleImage, '__init__', image_init), \
                patch.object(store_api.sqlite3, 'connect', connect), \
                patch.object(sys, 'stdin', stdin), redirect_stdout(stdout):
            try:
                code = worker(['--state-root', str(state), '--request-json-stdin',
                               '--native-helpers-manifest', str(bundle),
                               '--expected-native-helpers-sha256', bundle_sha])
            except BaseException as caught:
                error = caught
                code = None
            stdout.flush()
            raw = output.getvalue()
        with real_connect(state / 'state.sqlite3') as observer:
            observer.row_factory = sqlite3.Row
            rows = [dict(row) for row in observer.execute('SELECT * FROM requests')]
            contexts = observer.execute('SELECT COUNT(*) FROM contexts').fetchone()[0]
        if kind.endswith('construct'):
            assert rows == [] and contexts == 0
        else:
            assert len(rows) == 1 and rows[0]['state'] == 'completed' and rows[0]['response'] is not None
            assert contexts == 1
        if kind.startswith('transport'):
            check_transport(error, injected, store_native.StoreLifecycleUnknown)
            assert raw == b'' and code is None
            report = None
        else:
            assert error is None and code == 0
            report = json.loads(raw)
            expected = 'E_HIA_WORKER' if kind.endswith('construct') else 'E_HIA_REQUEST_UNKNOWN'
            assert report['response']['error']['code'] == expected
        records.append({'kind': kind, 'request_rows': rows, 'context_count': contexts,
                        'worker_report': report, 'transport_terminal_report_absent': kind.startswith('transport')})
    return {'cases': records}


def run_child(kind, directory, manifests):
    root = Path(directory)
    value = globals()['_child_' + kind](root, json.loads(manifests))
    report = {'schema': 'hepta.hia.native-transport-child.v1', 'status': 'PASS', 'kind': kind, **value}
    (root / 'observations.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'status': 'PASS', 'kind': kind}), flush=True)
    # Actual unknown owners remain live until this real process termination.
    os._exit(0)


if __name__ == '__main__':
    unittest.main()
