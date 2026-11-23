"""Disposable actual-image controls for shared native-delivery causality.

Fault callbacks run the admitted entry before losing its receipt. Deliberate
unknown owners remain in process custody; no test clears their registries.
"""
from __future__ import annotations

from contextlib import ExitStack
from contextvars import copy_context
import ctypes
import gc
from hashlib import sha256
import importlib
import json
import os
from pathlib import Path
import select
import shutil
import signal
import sqlite3
import struct
import subprocess
import sys
import threading
from types import SimpleNamespace
from unittest.mock import patch
import weakref

from hepta import hia_native_delivery as delivery
from hepta import hia_agent_service as api
from hepta import hia_agent_store as store_api
from hepta import hia_service_context_native as context
from hepta import hia_store_lifecycle_native as lifecycle
from hepta import hia_cost_ledger_native as ledger
from hepta import hia_evaluation_native as evaluation
from hepta import hia_native_build_admission_native as admission
from hepta import hia_emission_native as emission
from hepta import hia_execution_budget_native as execution
from hepta import hia_candidate_budget_native as candidate
from hepta import hia_agent_journal_native as journal

ROOT = Path(__file__).resolve().parents[1]
MODULES = {name: importlib.import_module('hepta.hia_' + name + '_native') for name in (
    'service_context', 'store_lifecycle', 'cost_ledger', 'evaluation',
    'native_build_admission', 'emission', 'execution_budget', 'candidate_budget', 'agent_journal')}


def encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False,
                      separators=(',', ':')).encode()


def raised(operation):
    try:
        operation()
    except BaseException as error:
        return error
    raise AssertionError('operation returned despite injected failure')


def images(manifests):
    result = {}
    for name, module in MODULES.items():
        path = manifests[name]
        if name in ('execution_budget', 'candidate_budget'):
            from hepta.hia_json_preflight_native import _installed_json_image
            kind = execution.NativeExecutionBudgetImage if name == 'execution_budget' else candidate.NativeCandidateBudgetImage
            result[name] = _installed_json_image(path, module.SOURCE, module.SCHEMA, kind)
        else:
            result[name] = getattr(module, 'installed_' + name)(path)
    return result


def math_loss(image, kind, fault, observed):
    original = image._entry
    def lost(source, size, output, capacity, state, extent):
        result = original(source, size, output, capacity, state, extent)
        observed.append({'request_bytes': size, 'native_return': result})
        raise fault
    with patch.object(image, '_entry', lost):
        if kind == 'cost_ledger':
            return image.add(ledger.integer_bytes(11), ledger.integer_bytes(7))
        return image.arithmetic(1, 11, 7)


def record_entry(image, calls):
    original = image._entry
    def counted(source, size, output, capacity, state, extent):
        raw = ctypes.string_at(source, size)
        if size >= 32:
            calls.append(list(struct.unpack_from('<4Q', raw)))
        return original(source, size, output, capacity, state, extent)
    return patch.object(image, '_entry', counted)


def frame(kind, image):
    owner = SimpleNamespace()
    if kind == 'service_context':
        return context.ContextFrame(image, 4, owner, {})
    if kind == 'store_lifecycle':
        return lifecycle.LifecycleFrame(image, 1, owner, 'unobserved-root')
    if kind == 'cost_ledger':
        return ledger.CostLedgerFrame(image, owner, {}, 0, 0)
    if kind == 'evaluation':
        return evaluation.EvaluationFrame(image, owner, {})
    if kind == 'native_build_admission':
        return admission.NativeBuildAdmissionFrame(image, 1, None, (None, ()))
    if kind == 'emission':
        return emission.EmissionFrame(image, 1, owner, (None, 'object', None, 1, ()))
    raise AssertionError(kind)


def _frames(root, manifests):
    selected = images(manifests)
    rows = []
    for index, parent_kind in enumerate(tuple(MODULES)[:6]):
        child_kind = ('cost_ledger', 'service_context', 'evaluation')[index % 3]
        for behavior in ('swallow', 'replace', 'memory'):
            outer = frame(parent_kind, selected[parent_kind])
            outer_ref = weakref.ref(outer)
            calls, children = [], []
            fault = ValueError('actual child native return lost')
            replacement = MemoryError('foreign replacement of true native loss')
            first_port = outer.receipt[0] if parent_kind == 'cost_ledger' else outer.receipt.port
            def provider(port):
                assert port == first_port
                error = raised(lambda: math_loss(selected[child_kind], child_kind, fault, children))
                assert error is fault or error.__cause__ is fault
                if behavior == 'replace':
                    raise ValueError('foreign replacement of true native loss')
                if behavior == 'memory':
                    raise replacement
                return 0
            with patch.object(outer, 'effect', provider), record_entry(selected[parent_kind], calls):
                error = raised(outer.finish)
            if behavior == 'memory':
                assert error is replacement and type(error) is MemoryError
            else:
                assert isinstance(error, RuntimeError) and not isinstance(error, ValueError)
            memory_identity = behavior == 'memory' and error is replacement
            assert outer._delivery.loss is not None and not outer._delivery.retired
            assert outer.fenced and outer.unconfirmed
            assert len(children) == 1
            assert not any(row[1] in (2, 3) for row in calls), calls
            replay = raised(outer.finish)
            assert isinstance(replay, RuntimeError)
            assert outer._delivery.loss.error is fault
            del outer, provider, error, replay, replacement
            gc.collect()
            assert outer_ref() is not None
            rows.append({'parent': parent_kind, 'child': child_kind, 'behavior': behavior,
                         'actual_parent_calls': calls, 'actual_child_calls': children,
                         'ack_or_foreign_error_ack_after_loss': False, 'owner_retained': True,
                         'memory_error_identity_preserved': memory_identity})
    return {'cases': rows}


def _cleanup(root, manifests):
    from tests.fixtures.hia_emission_original_73f1634 import hia_emission_original_oracle as oracle
    selected = images(manifests)
    rows = []
    for behavior in ('suppress', 'replace'):
        fixture = oracle.Fixture({'name': 'delivery-cleanup-' + behavior, 'mode': 1, 'kind': 'shared'})
        body = ValueError('original compile provider failed')
        fault = OSError('actual child loss inside active __exit__')
        seen, child_calls, calls = [], [], []
        class Manager:
            def __enter__(self):
                return 'VIRTUAL-TEMP'
            def __exit__(self, kind, error, traceback):
                seen.append((sys.exception() is body, error is body, traceback is body.__traceback__))
                lost = raised(lambda: math_loss(selected['cost_ledger'], 'cost_ledger', fault, child_calls))
                assert lost.__cause__ is fault
                assert sys.exception() is body
                if behavior == 'replace':
                    raise ValueError('cleanup replaced child loss')
                return True
        fixture.namespace['tempfile'] = SimpleNamespace(TemporaryDirectory=lambda **kw: Manager())
        def compile_provider(*args, **kwargs):
            raise body
        fixture.compile_program_machine = compile_provider
        with fixture.providers():
            outer = emission.EmissionFrame(selected['emission'], 1, fixture.service,
                                            fixture.arguments(), namespace=fixture.namespace)
            with record_entry(selected['emission'], calls):
                error = raised(outer.finish)
        assert isinstance(error, RuntimeError) and not isinstance(error, ValueError)
        assert seen == [(True, True, True)], seen
        assert outer._delivery.loss is not None and outer.unconfirmed
        exit_port = emission.PORT['compile_exit_exception']
        assert not any(row[1] in (2, 3) and row[3] == exit_port for row in calls), calls
        assert len(child_calls) == 1 and not fixture.store_effects
        rows.append({'behavior': behavior, 'active_exception_identity': list(seen[0]),
                     'child_calls': child_calls, 'parent_calls': calls, 'store_effects': []})
    return {'cases': rows}


def _safe(root, manifests):
    selected = images(manifests)
    rows = []
    before = len(delivery.custody_snapshot())
    safe = delivery.DeliveryRecord(object())
    with safe.foreign(observation=False):
        count = []
        with patch.object(selected['service_context'], '_entry', lambda *a: count.append(a)):
            error = raised(lambda: selected['service_context'].arithmetic(0, 1, 2))
        assert type(error) is context.ServiceContextUnknown and not count
        assert safe.loss is None
        session = selected['agent_journal'].session()
        instruction = session.prepare(b'{"tool":"not-a-tool","arguments":{}}')
        assert instruction.action == journal.REFUSE
        error = raised(session.raise_refusal)
        assert isinstance(error, ValueError) and safe.loss is None
        error = raised(lambda: execution.BudgetState(selected['execution_budget'], (1, 2), 0, ''))
        assert isinstance(error, ValueError) and safe.loss is None
    safe.retire()
    assert safe.retired
    for kind in tuple(MODULES)[:6]:
        outer = frame(kind, selected[kind])
        foreign = emission.EmissionUnknown('foreign exception with a native-looking class')
        def provider(port):
            assert selected['cost_ledger'].add(ledger.integer_bytes(2), ledger.integer_bytes(3)) == ledger.integer_bytes(5)
            raise foreign
        with patch.object(outer, 'effect', provider):
            error = raised(outer.finish)
        assert error is foreign, (kind, type(error))
        assert outer._delivery.loss is None and outer._delivery.retired
        phase = outer.receipt[2] if kind == 'cost_ledger' else outer.receipt.phase
        assert phase == 5
        rows.append({'owner': kind, 'foreign_exception_identity_preserved': True,
                     'confirmed_terminal': phase, 'loss': False})
    assert len(delivery.custody_snapshot()) == before
    return {'preentry_native_calls': 0, 'native_refusal_confirmed': True,
            'confirmed_arithmetic_followed_by_foreign_error': rows}


def request_row(service, tool, arguments):
    key = store_api.digest({'tool': tool, 'key': arguments['request_key']})
    row = service.store.db.execute('SELECT * FROM requests WHERE key=?', (key,)).fetchone()
    return None if row is None else dict(row)


def selected_lane(manifests, lane):
    scope = ExitStack()
    scope.enter_context(patch.dict(os.environ, {context.SELECTOR: manifests['service_context']}))
    if lane == 'native':
        scope.enter_context(patch.dict(os.environ, {journal.SELECTOR: manifests['agent_journal']}))
        scope.enter_context(patch.object(api.HIAAgentService, '_reference_call',
                                        side_effect=AssertionError('native lane entered ordinary journal')))
    return scope


def _requests(root, manifests):
    from tests.test_hia_service_context_native import context_arguments
    selected = images(manifests)
    rows = []
    for lane in ('ordinary', 'native'):
        for behavior in ('swallow', 'replace', 'memory'):
            with selected_lane(manifests, lane):
                service = api.HIAAgentService(root / (lane + '-' + behavior))
                args = context_arguments(service)
                calls, actual = [], selected['service_context']._entry
                original = service._hia_context
                replacement = MemoryError('foreign provider replaced loss with MemoryError')
                def lost(source, size, output, capacity, state, extent):
                    words = struct.unpack('<10Q', ctypes.string_at(source, size)) if size == 80 else None
                    result = actual(source, size, output, capacity, state, extent)
                    if words is not None and words[0] == context.REQUEST_MAGIC:
                        calls.append([words[1], words[3]])
                        if (words[1], words[3]) == (2, 44):
                            raise ValueError('context INSERT succeeded before native ACK loss')
                    return result
                def provider(arguments):
                    error = raised(lambda: original(arguments))
                    assert type(error) is context.ServiceContextUnknown
                    if behavior == 'replace':
                        raise ValueError('foreign provider replaced loss')
                    if behavior == 'memory':
                        raise replacement
                    return {'swallowed': True}
                with patch.object(selected['service_context'], '_entry', lost), patch.object(service, '_hia_context', provider):
                    error = raised(lambda: service.call('hia_context', args))
                if behavior == 'memory':
                    assert error is replacement and type(error) is MemoryError
                else:
                    assert isinstance(error, RuntimeError) and not isinstance(error, ValueError)
                retained = request_row(service, 'hia_context', args)
                assert retained['state'] == 'running' and retained['response'] is None
                assert service.store.db.execute('SELECT COUNT(*) FROM contexts').fetchone()[0] == 1
                assert service.store.db.execute('SELECT COUNT(*) FROM costs').fetchone()[0] == 0
                assert not any(event == 3 for event, port in calls)
                replay = service.call('hia_context', args)
                assert replay['error']['code'] == 'E_HIA_REQUEST_UNKNOWN'
                assert request_row(service, 'hia_context', args) == retained
                rows.append({'lane': lane, 'behavior': behavior, 'request': retained,
                             'replay': replay, 'context_count': 1, 'calls': calls,
                             'error_type': type(error).__name__,
                             'memory_error_identity_preserved': behavior == 'memory' and error is replacement})
    return {'cases': rows}


def _journal_gaps(root, manifests):
    from tests.test_hia_service_context_native import context_arguments
    selected = images(manifests)
    rows = []
    for lane in ('ordinary', 'native'):
        with selected_lane(manifests, lane):
            service = api.HIAAgentService(root / ('serialize-' + lane))
            args = context_arguments(service)
            module = api if lane == 'ordinary' else journal
            real_wire = module.wire
            child_calls = []
            def wire(value):
                if type(value) is dict and value.get('status') == 'completed':
                    raised(lambda: math_loss(selected['cost_ledger'], 'cost_ledger', ValueError('lost during wire'), child_calls))
                return real_wire(value)
            with patch.object(module, 'wire', wire):
                error = raised(lambda: service.call('hia_context', args))
            assert isinstance(error, RuntimeError) and child_calls
            retained = request_row(service, 'hia_context', args)
            assert retained['state'] == 'running' and retained['response'] is None
            rows.append({'lane': lane, 'boundary': 'terminal-serialization', 'request': retained,
                         'child_calls': child_calls})
    for failure in ('native-ack', 'before-ack-lookup', 'foreign-sql'):
        with selected_lane(manifests, 'native'):
            service = api.HIAAgentService(root / failure)
            args = context_arguments(service)
            active = []
            if failure == 'before-ack-lookup':
                class BrokenACK:
                    def __get__(self, instance, owner):
                        active.append('lookup-after-running-insert')
                        raise ValueError('ACK lookup lost after actual INSERT')
                control = patch.object(journal.JournalSession, 'reserved', BrokenACK())
            elif failure == 'native-ack':
                actual = selected['agent_journal']._entry
                def lost(source, size, output, capacity, state, extent):
                    stage = struct.unpack_from('<Q', ctypes.string_at(state, 8))[0]
                    result = actual(source, size, output, capacity, state, extent)
                    if stage == 2:
                        active.append('actual-native-ack-return')
                        raise ValueError('lost native reservation receipt')
                    return result
                control = patch.object(selected['agent_journal'], '_entry', lost)
            else:
                class Refusal(sqlite3.Connection):
                    def execute(self, sql, parameters=()):
                        if sql == 'INSERT INTO requests VALUES (?,?,?,?,?,?)':
                            active.append('foreign-sql-refusal')
                            raise sqlite3.OperationalError('ordinary provider refusal')
                        return super().execute(sql, parameters)
                substitute = sqlite3.connect(service.store.database, isolation_level=None, factory=Refusal)
                substitute.row_factory = sqlite3.Row
                control = patch.object(service.store, 'db', substitute)
            with control:
                if failure == 'foreign-sql':
                    answer = service.call('hia_context', args)
                    assert answer['status'] == 'rejected'
                else:
                    error = raised(lambda: service.call('hia_context', args))
                    assert isinstance(error, RuntimeError) and not isinstance(error, ValueError)
            assert active
            retained = request_row(service, 'hia_context', args)
            assert retained is None  # original rollback, no fabricated intent
            cost_count = service.store.db.execute('SELECT COUNT(*) FROM costs').fetchone()[0]
            assert cost_count == int(failure == 'foreign-sql')
            rows.append({'lane': 'native', 'boundary': failure, 'request': retained,
                         'cost_count': cost_count, 'observed': active})
            if failure == 'foreign-sql':
                substitute.close()
                service.close()
    # The complete retained 24-combination test remains independent. These
    # four controls additionally observe the exact SQL-ACK activation, proving
    # that its validated confirmation precedes a replaceable method's return.
    for operation, stage in (('reserved', 2), ('committed_inline', 7)):
        for after in (False, True):
            with selected_lane(manifests, 'native'):
                service = api.HIAAgentService(root / ('confirmed-%s-%s' % (operation, after)))
                service.store.db.execute('CREATE TABLE effect_probe (value TEXT)')
                arguments = {'catalog_sha256': service.catalog_sha256, 'request_key': 'ack-activation'}
                original = getattr(journal.JournalSession, operation)
                exception = MemoryError('original foreign failure after optional native ACK')
                activations, calls = [], []
                actual = selected['agent_journal']._entry
                before = sum(row['lost'] for row in delivery.custody_snapshot())
                def observed(source, size, output, capacity, state, extent):
                    current_stage = struct.unpack_from('<Q', ctypes.string_at(state, 8))[0]
                    result = actual(source, size, output, capacity, state, extent)
                    calls.append(current_stage)
                    return result
                def fail(session, *arguments):
                    activations.append(session._ack_delivery)
                    if after:
                        original(session, *arguments)
                    raise exception
                def effect(arguments):
                    service.store.db.execute("INSERT INTO effect_probe VALUES ('effect')")
                    return {'effect': 'would-have-committed'}
                with patch.object(api, 'validate', return_value=None), \
                        patch.object(service, '_hia_adopt', effect), \
                        patch.object(journal.JournalSession, operation, fail), \
                        patch.object(selected['agent_journal'], '_entry', observed):
                    error = raised(lambda: service.call('hia_adopt', arguments))
                assert error is exception and type(error) is MemoryError
                assert len(activations) == 1
                activation = activations[0]
                assert not activation.active and activation.complete is after
                assert activation.session._ack_delivery is None
                assert (stage in calls) is after
                assert not list(service.store.db.execute('SELECT * FROM effect_probe'))
                assert service.store.db.execute('SELECT COUNT(*) FROM costs').fetchone()[0] == 0
                added = sum(row['lost'] for row in delivery.custody_snapshot()) - before
                assert added == 0 if after else added > 0
                retained = request_row(service, 'hia_adopt', arguments)
                assert retained is None if operation == 'reserved' else retained['state'] == 'running'
                rows.append({'lane': 'native', 'boundary': 'exact-ACK-activation',
                             'operation': operation, 'after': after, 'stage': stage,
                             'calls': calls, 'complete': activation.complete,
                             'active_after_call': activation.active, 'new_lost_records': added,
                             'memory_error_identity_preserved': error is exception,
                             'request': retained})
    return {'cases': rows}


def _budgets(root, manifests):
    selected = images(manifests)
    rows = []
    # A long-lived budget store is created outside every request. Only each
    # actual later invocation gains the then-active causal ancestor.
    with patch.dict(os.environ, {execution.SELECTOR: manifests['execution_budget']}):
        store = store_api.AgentStore(root / 'execution')
    driver = store.execution_budgets
    driver.create('context-execution')
    claim = driver.claim('context-execution', 'a' * 64, 1000, 1)
    parent = frame('emission', selected['emission'])
    calls, actual = [], driver.image._entry
    def lost(source, size, output, capacity, state, extent):
        event = struct.unpack_from('<Q', ctypes.string_at(source, 16), 8)[0]
        result = actual(source, size, output, capacity, state, extent)
        calls.append(event)
        if event == 6:
            raise ValueError('actual execution outcome ACK lost')
        return result
    outcome = {'wall_ns': '7', 'termination_confirmed': True}
    def provider(port):
        error = raised(lambda: claim.run(lambda *a, **k: outcome, now=1, total_ms=1000))
        assert isinstance(error, ValueError)
        return 0
    with patch.object(driver.image, '_entry', lost), patch.object(parent, 'effect', provider):
        error = raised(parent.finish)
    assert isinstance(error, RuntimeError) and parent._delivery.loss is not None
    assert 6 in calls
    stored = dict(store.db.execute('SELECT * FROM execution_budgets WHERE context_id=?', ('context-execution',)).fetchone())
    assert stored['owner'] == 'a' * 64 and stored['used_native_ns'] == '0'
    assert any(record.owner is not None and record.loss is not None
               for record in delivery._CUSTODY.values())
    rows.append({'owner': 'execution', 'entry_events': calls, 'stored': stored,
                 'long_lived_store_constructed_outside_parent': True})

    from tests.test_hia_service_context_native import context_arguments
    for lane in ('ordinary', 'native'):
        for failure in ('native', 'foreign'):
            with selected_lane(manifests, lane), patch.dict(os.environ, {candidate.SELECTOR: manifests['candidate_budget']}):
                service = api.HIAAgentService(root / ('candidate-' + lane + '-' + failure))
                context_args = context_arguments(service)
                frozen = service.call('hia_context', context_args)
                assert frozen['status'] == 'completed', frozen
                ref = frozen['result']['context']
                # The original attempt route is before candidate input parsing.
                # A valid context plus malformed import must still be charged.
                from tools.hia_agent_native_qualification import Session, ToolClient, add_program
                session = Session(ToolClient(service.call), prefix='delivery-budget')
                session.context = ref
                source = session.artifact(add_program())
                args = {'catalog_sha256': service.catalog_sha256, 'request_key': 'candidate-loss',
                        'context': ref, 'change': {'kind': 'import', 'format': 'core-json', 'source': source}}
                original_consume = service._consume_attempt
                native_events = []
                if failure == 'native':
                    entry = service._candidate_budget.image._entry
                    def lose_native(source, size, output, capacity, state, extent):
                        event = struct.unpack_from('<Q', ctypes.string_at(source, 16), 8)[0]
                        result = entry(source, size, output, capacity, state, extent)
                        native_events.append(event)
                        if event == 4:
                            raise ValueError('candidate COMMIT native ACK lost')
                        return result
                    control = patch.object(service._candidate_budget.image, '_entry', lose_native)
                    def consume(*args, **kwargs):
                        raised(lambda: original_consume(*args, **kwargs))
                    outer_control = patch.object(service, '_consume_attempt', consume)
                else:
                    execute = service._candidate_budget._execute
                    def lose_foreign(sql, parameters=()):
                        result = execute(sql, parameters)
                        if sql == 'COMMIT':
                            raise OSError('original SQL provider raised after COMMIT')
                        return result
                    control = patch.object(service._candidate_budget, '_execute', lose_foreign)
                    outer_control = ExitStack()
                with control, outer_control:
                    if failure == 'native':
                        error = raised(lambda: service.call('hia_candidate', args))
                        assert isinstance(error, RuntimeError) and not isinstance(error, ValueError)
                    else:
                        answer = service.call('hia_candidate', args)
                        assert answer['error']['code'] == 'E_HIA_CANDIDATE_BUDGET_UNKNOWN', answer
                row = request_row(service, 'hia_candidate', args)
                attempts = service.store.db.execute('SELECT attempts FROM contexts WHERE id=?', (ref['id'],)).fetchone()[0]
                assert attempts == 1
                if failure == 'native':
                    assert row['state'] == 'running' and row['response'] is None and 4 in native_events
                    replay = service.call('hia_candidate', args)
                    assert replay['error']['code'] == 'E_HIA_REQUEST_UNKNOWN'
                else:
                    assert row['state'] == 'completed' and service.call('hia_candidate', args) == answer
                rows.append({'owner': 'candidate', 'lane': lane, 'failure': failure,
                             'request': row, 'attempts': attempts, 'native_events': native_events})
    return {'cases': rows}


def _ancestry(root, manifests):
    selected = images(manifests)
    creator_guards = []
    # Compare finish with the original direct call guard, before any entry or
    # provider. Each owner keeps its own class/message and post-refusal state.
    for kind in tuple(MODULES)[:6]:
        direct, completed = frame(kind, selected[kind]), frame(kind, selected[kind])
        outcomes, calls = [], []
        def foreign_owner():
            outcomes.append(raised(lambda: direct.call(1)))
            outcomes.append(raised(completed.finish))
        with record_entry(selected[kind], calls):
            thread = threading.Thread(target=foreign_owner)
            thread.start(); thread.join(5)
        assert not thread.is_alive() and len(outcomes) == 2
        expected, actual = outcomes
        assert type(actual) is type(expected) and str(actual) == str(expected)
        assert type(actual) is not delivery.NativeDeliveryUnknown
        assert calls == []
        assert direct._delivery.loss is completed._delivery.loss is None
        creator_guards.append({'owner': kind, 'exception_type': type(actual).__name__,
                               'message': str(actual), 'native_entries': 0,
                               'matches_original_direct_guard': True, 'causal_loss': False})
    stale = delivery.DeliveryRecord(object())
    token = stale.foreign(observation=False)
    with token:
        delayed = frame('emission', selected['emission'])
    stale.retire()
    assert stale.retired
    assert isinstance(raised(token.__enter__), delivery.NativeDeliveryUnknown)
    later = delivery.DeliveryRecord(object())
    child_calls = []
    def provider(port):
        raised(lambda: math_loss(selected['cost_ledger'], 'cost_ledger', ValueError('late invocation loss'), child_calls))
        return 0
    with later.foreign(observation=False), patch.object(delayed, 'effect', provider):
        raised(delayed.finish)
        assert later.loss is delayed._delivery.loss and later.loss is not None
    assert stale.loss is None
    threaded = []
    clean = delivery.DeliveryRecord(object())
    def worker():
        assert isinstance(raised(clean.check), delivery.NativeDeliveryUnknown)
        record = delivery.DeliveryRecord(object())
        assert record.parent is None
        with record.foreign(observation=False):
            assert selected['cost_ledger'].add(b'\x01', b'\x02') == b'\x03'
        record.retire()
        threaded.append(record.retired)
    with clean.foreign(observation=False):
        copied = copy_context()
        thread = threading.Thread(target=lambda: copied.run(worker))
        thread.start(); thread.join(10)
    assert not thread.is_alive() and threaded == [True]
    assert clean.loss is None
    clean.retire()

    # Fork while another thread owns the representation lock. Child callbacks
    # must replace the lock but retain inherited unknown resources unchanged.
    ready, release = threading.Event(), threading.Event()
    fork_parent = delivery.DeliveryRecord(object())
    def hold():
        with delivery._CUSTODY_LOCK:
            ready.set()
            release.wait(10)
    holder = threading.Thread(target=hold)
    holder.start()
    assert ready.wait(5)
    read_fd, write_fd = os.pipe()
    inherited_pid = delayed._delivery.pid
    inherited_owner = delayed._delivery.owner
    fork_scope = fork_parent.foreign(observation=False)
    fork_scope.__enter__()
    child = os.fork()
    if child == 0:
        os.close(read_fd)
        try:
            assert delayed._delivery.pid == inherited_pid != os.getpid()
            assert delayed._delivery.owner is inherited_owner
            assert isinstance(raised(delayed._delivery.check), delivery.NativeDeliveryUnknown)
            fresh = delivery.DeliveryRecord(object())
            assert fresh.parent is None and fresh.loss is None
            with fresh.foreign(observation=False):
                fresh.check()
            fresh.retire()
            os.write(write_fd, encoded({'status': 'PASS', 'old_pid_unchanged': True,
                                       'inherited_owner_retained': True, 'new_parent_absent': True}))
            os._exit(0)
        except BaseException:
            import traceback
            traceback.print_exc()
            os._exit(1)
    os.close(write_fd)
    fork_scope.__exit__(None, None, None)
    try:
        readable, _, _ = select.select([read_fd], [], [], 10)
        if not readable:
            os.kill(child, signal.SIGKILL)
            os.waitpid(child, 0)
            raise AssertionError('forked child blocked on inherited custody lock')
        raw = os.read(read_fd, 4096)
        waited, status = os.waitpid(child, 0)
        assert waited == child and os.waitstatus_to_exitcode(status) == 0
        forked = json.loads(raw)
    finally:
        os.close(read_fd)
        release.set(); holder.join(10)
    assert not holder.is_alive()
    fork_parent.retire()
    return {'owner_creator_guards': creator_guards,
            'late_frame_current_parent_poisoned': True, 'stale_parent_unpoisoned': True,
            'new_thread_unpoisoned': True, 'fork': forked, 'actual_child_calls': child_calls}


def _installed(root, manifests):
    from tests.test_hia_agent_installed_resources import RESOURCES, SDIST_SUPPORT_FILES
    from tests.test_hia_agent_native_tools import AgentToolCase
    from tests.test_hia_native_delivery import clean_environment
    from tools.hia_agent_native_qualification import add_program
    from hepta import hia_native_helpers as helpers
    staging = root / 'source'
    staging.mkdir()
    shutil.copytree(ROOT / 'hepta', staging / 'hepta', ignore=shutil.ignore_patterns('__pycache__'))
    for name in (*RESOURCES, *SDIST_SUPPORT_FILES, 'setup.py', 'pyproject.toml', 'MANIFEST.in'):
        target = staging / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)
    environment = dict(clean_environment(), PYTHONDONTWRITEBYTECODE='1')
    def run(label, arguments, body=None, expected=0):
        result = subprocess.run([sys.executable, '-B', *map(str, arguments)], cwd=root,
                                env=environment, input=body, capture_output=True, timeout=60)
        (root / (label + '.stdout')).write_bytes(result.stdout)
        (root / (label + '.stderr')).write_bytes(result.stderr)
        if expected is not None:
            assert result.returncode == expected, result.stdout + result.stderr
        return result
    from tests.hia_distribution_fixture import ordinary_wheel
    run('wheel', ['-m', 'pip', 'wheel', '--no-deps', '--no-build-isolation', '--no-index',
                  '--wheel-dir', root / 'wheels', ordinary_wheel(staging)])
    wheel, = (root / 'wheels').glob('*.whl')
    installed = root / 'installed'
    run('install', ['-m', 'pip', 'install', '--no-deps', '--no-index', '--no-compile',
                    '--target', installed, wheel])
    shared_path = installed / 'hepta/hia_native_delivery.py'
    assert shared_path.read_bytes() == (ROOT / 'hepta/hia_native_delivery.py').read_bytes()
    bundle = root / 'bundle.json'
    names = ('service_context', 'emission', 'agent_journal')
    bundle.write_bytes(encoded({'schema': helpers.SCHEMA, 'target': helpers.TARGET, 'abi': helpers.ABI,
        'helpers': [{'selector': MODULES[name].SELECTOR, 'manifest_path': manifests[name],
                     'manifest_sha256': sha256(Path(manifests[name]).read_bytes()).hexdigest()} for name in names]}))
    bundle_sha = sha256(bundle.read_bytes()).hexdigest()
    script = r'''import ctypes,importlib.abc,json,struct,sys
from hashlib import sha256
from pathlib import Path
installed=sys.argv.pop(1);mode=sys.argv.pop(1);sys.path.insert(0,installed)
class NoAuthoring(importlib.abc.MetaPathFinder):
    def find_spec(self,name,path=None,target=None):
        if name=='tools' or name.startswith('tools.') or name=='tests' or name.startswith('tests.'):
            raise AssertionError('installed worker imported authoring/test code')
sys.meta_path.insert(0,NoAuthoring())
from hepta import hia_native_delivery as delivery
from hepta import hia_service_context_native as context
from hepta import hia_emission_native as emission
from hepta import hia_agent_journal_native as journal
from hepta import hia_agent_service as api
from hepta.hia_agent_worker import main
assert Path(delivery.__file__).resolve()==Path(installed).resolve()/'hepta/hia_native_delivery.py'
counts={'context':0,'emission':0,'journal':0,'lost':0,'swallowed':0}
def forbidden(*a,**k):raise AssertionError('installed worker entered a retained owner')
for name in ('_compile_reference','_hia_emit_reference','_context_reference','_reference_call'):
    setattr(api.HIAAgentService,name,forbidden)
api._NATIVE_SERVICE_CONTEXT_LOOKUP_REFERENCE=forbidden
def in_emission():
    scope=delivery._ACTIVE.get()
    while type(scope) is delivery.ForeignCall:
        if scope.active and type(scope.record.owner) is emission.EmissionFrame:return True
        scope=scope.previous
    return False
for kind,label in ((context.NativeServiceContextImage,'context'),(emission.NativeEmission,'emission'),(journal.NativeAgentJournal,'journal')):
    original=kind.__init__
    def wrap(self,*a,_original=original,_label=label,**k):
        _original(self,*a,**k);entry=self._entry
        def observed(source,size,output,capacity,state,extent):
            result=entry(source,size,output,capacity,state,extent)
            counts[_label]+=1
            if _label=='context' and size==80 and mode!='normal' and in_emission():
                words=struct.unpack('<10Q',ctypes.string_at(source,size))
                if words[0]==context.REQUEST_MAGIC and (words[1],words[3])==(2,111):
                    counts['lost']+=1
                    raise ValueError('actual installed cross-owner ACK loss')
            return result
        self._entry=observed
    kind.__init__=wrap
original_context=api.HIAAgentService._context
last={}
def context_provider(self,*a,**k):
    try:
        value=original_context(self,*a,**k)
        last[id(self)]=value
        return value
    except context.ServiceContextUnknown:
        assert mode in ('swallow','replace') and in_emission() and id(self) in last
        counts['swallowed']+=1
        if mode=='replace':raise ValueError('foreign provider replaced actual installed loss')
        return last[id(self)]
api.HIAAgentService._context=context_provider
try:status=main(sys.argv[1:])
finally:
    counts['unknown_records']=sum(row['lost'] for row in delivery.custody_snapshot())
    counts['shared_module_sha256']=sha256(Path(delivery.__file__).read_bytes()).hexdigest()
    print('DELIVERY_COUNTS='+json.dumps(counts,sort_keys=True),file=sys.stderr)
raise SystemExit(status)
'''
    (root / 'worker-control.py').write_text(script)
    def observed(result):
        prefix = b'DELIVERY_COUNTS='
        found = [row[len(prefix):] for row in result.stderr.splitlines() if row.startswith(prefix)]
        assert len(found) == 1, result.stderr
        return json.loads(found[0])
    rows = []
    for mode in ('normal', 'swallow', 'replace'):
        case = AgentToolCase('runTest')
        with patch.dict(os.environ, environment, clear=True), helpers.native_helpers_scope(str(bundle), bundle_sha):
            case.setUp()
            case.session.freeze({'schema': 'hepta.hia.agent.workload.v1', 'cases': [{
                'function': 'transform', 'arguments': [0], 'expected': {'status': 'returned', 'values': [7]}}],
                'warmup_iterations': 0, 'repetitions': 1})
            imported = case.session.import_program(add_program(optimized=True))
            verification = case.session.verify(imported)
        try:
            arguments = case.session.arguments(candidate=imported, backend_profile=case.session.backend,
                output_kind='shared', codegen={'kind': 'canonical', 'lowering_profile': case.session.profiles['lowering']},
                verification_receipts=[verification['verification_receipt']])
            envelope = {'schema': 'hia-agent-worker-request-v1', 'tool': 'hia_emit', 'arguments': arguments,
                        'profile_sha256': 'a' * 64, 'catalog_sha256': case.service.catalog_sha256}
            envelope['request_sha256'] = sha256(encoded(envelope)).hexdigest()
            case.service.close()
            flags = ['-I', '-c', script, installed, mode, '--state-root', case.state_root,
                     '--artifact-root', case.files_root, '--request-json-stdin',
                     '--native-helpers-manifest', bundle, '--expected-native-helpers-sha256', bundle_sha]
            result = run('worker-' + mode, flags, encoded(envelope), expected=0 if mode == 'normal' else None)
            counts = observed(result)
            key = store_api.digest({'tool': 'hia_emit', 'key': arguments['request_key']})
            with sqlite3.connect(case.state_root / 'state.sqlite3') as db:
                db.row_factory = sqlite3.Row
                row = dict(db.execute('SELECT * FROM requests WHERE key=?', (key,)).fetchone())
                artifacts = [dict(item) for item in db.execute('SELECT * FROM artifacts ORDER BY id')]
            assert counts['context'] > 0 and counts['emission'] > 0 and counts['journal'] > 0
            if mode == 'normal':
                assert json.loads(result.stdout)['response']['status'] == 'completed'
                assert row['state'] == 'completed' and counts['lost'] == counts['unknown_records'] == 0
            else:
                assert result.returncode != 0 and result.stdout == b''
                assert counts['lost'] == counts['swallowed'] == 1 and counts['unknown_records'] >= 3
                assert row['state'] == 'running' and row['response'] is None
            replay_flags = list(flags)
            replay_flags[4] = 'normal'
            replay = run('replay-' + mode, replay_flags, encoded(envelope))
            replay_counts = observed(replay)
            assert replay_counts['context'] == replay_counts['emission'] == replay_counts['lost'] == 0
            replay_report = json.loads(replay.stdout)
            if mode == 'normal':
                assert replay.stdout == result.stdout
            else:
                assert replay_report['response']['error']['code'] == 'E_HIA_REQUEST_UNKNOWN'
            with sqlite3.connect(case.state_root / 'state.sqlite3') as db:
                db.row_factory = sqlite3.Row
                assert dict(db.execute('SELECT * FROM requests WHERE key=?', (key,)).fetchone()) == row
                assert [dict(item) for item in db.execute('SELECT * FROM artifacts ORDER BY id')] == artifacts
            rows.append({'mode': mode, 'worker_exit': result.returncode, 'counts': counts,
                         'request': row, 'replay_counts': replay_counts, 'replay_report': replay_report})
        finally:
            case.tearDown()
    return {'wheel': str(wheel), 'wheel_sha256': sha256(wheel.read_bytes()).hexdigest(),
            'installed_shared_module': str(shared_path), 'installed_shared_sha256': sha256(shared_path.read_bytes()).hexdigest(),
            'bundle': str(bundle), 'bundle_sha256': bundle_sha, 'cases': rows,
            'scope': 'actual installed worker; emission to context; native request journal',
            'all_D0_D3_owners_exercised_in_installed_child': False,
            'whole_native_delivery_qualified': False}


def run_child(kind, directory, manifests):
    root = Path(directory)
    value = globals()['_' + kind](root, json.loads(manifests))
    report = {'schema': 'hepta.hia.native-delivery-child.v1', 'status': 'PASS', 'kind': kind, **value}
    (root / 'observations.json').write_bytes(encoded(report) + b'\n')
    print(json.dumps({'kind': kind, 'status': 'PASS'}), flush=True)
    os._exit(0)
