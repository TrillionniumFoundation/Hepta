"""Actual journal/TX/SQLite controls, used only by disposable test children.

No shared record, parent.check, resource observation, or native receipt is
forged. Faults either replace an ACK's foreign method/lookup or occur after the
real admitted native entry returns. Unknown custody lasts until process exit.
"""
from __future__ import annotations

from collections import Counter
from contextlib import ExitStack, closing
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import sqlite3
import struct
import sys
import traceback
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
GROUPS = {
    'preentry': tuple({'id': 'preentry-pair-' + op, 'operation': op,
                      'phases': ['before', 'after']} for op in ('reserved', 'committed_inline')),
    'native': tuple({'id': 'native-' + op + '-' + kind, 'operation': op, 'error': kind}
                    for op in ('reserved', 'committed_inline')
                    for kind in ('RuntimeError', 'ValueError')),
    'suppressed': tuple({'id': 'suppressed-' + op + '-' + point,
                         'operation': op, 'point': point}
                        for op in ('reserved', 'committed_inline')
                        for point in ('lookup', 'method')),
    'cleanup': tuple({'id': 'cleanup-' + op + '-' + point,
                     'operation': op, 'point': point}
                    for op in ('reserved', 'committed_inline')
                    for point in ('rollback-native', 'lock-exit')),
}
METHOD_GROUP_ORDER = ('native', 'cleanup', 'preentry', 'suppressed')
ALL_IDS = tuple(case['id'] for group in METHOD_GROUP_ORDER for case in GROUPS[group])
TEST_FILES = ('tests/test_hia_transaction_journal_cleanup.py',
              'tests/hia_transaction_journal_controls.py')


def encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False,
                      separators=(',', ':')).encode()


def source_pins():
    from tools.hia_selfhost_contract import file_digests
    return {**file_digests(), **{name: sha256((ROOT / name).read_bytes()).hexdigest()
                               for name in TEST_FILES}}


def raised(operation):
    try:
        operation()
    except BaseException as error:
        return error
    raise AssertionError('operation returned despite the declared injected failure')


def exception_chain(error):
    rows, seen, pending = [], set(), [error]
    while pending:
        item = pending.pop()
        if item is None or id(item) in seen:
            continue
        seen.add(id(item))
        rows.append({'id': id(item), 'class': type(item).__module__ + '.' + type(item).__qualname__,
                     'args': list(item.args), 'suppress_context': item.__suppress_context__,
                     'cause_id': None if item.__cause__ is None else id(item.__cause__),
                     'context_id': None if item.__context__ is None else id(item.__context__)})
        pending.extend((item.__context__, item.__cause__))
    return rows


def contains_error(error, expected):
    return any(row['id'] == id(expected) for row in exception_chain(error))


def record_state(record):
    if record is None:
        return None
    origin = record.loss
    return {'id': id(record), 'native_pending': record.native_pending,
            'observation_pending': record.observation_pending,
            'terminal': record.terminal, 'retired': record.retired,
            'lost': origin is not None, 'origin_id': None if origin is None else id(origin),
            'origin_error_id': None if origin is None or origin.error is None else id(origin.error)}


def read_rows(connection):
    return {'requests': [list(row) for row in connection.execute('SELECT * FROM requests ORDER BY key')],
            'costs': [list(row) for row in connection.execute('SELECT * FROM costs ORDER BY rowid')],
            'effects': [list(row) for row in connection.execute('SELECT * FROM effect_probe ORDER BY rowid')]}


class Control:
    """A real service and two actual images, with observational wrappers only."""

    def __init__(self, directory, manifests, phase_name):
        from hepta import hia_agent_service as api
        from hepta import hia_agent_store as store_api
        from hepta import hia_agent_journal_native as journal
        from hepta import hia_store_transaction_native as tx
        from hepta import hia_native_delivery as delivery
        self.api, self.store_api, self.journal, self.tx, self.delivery = api, store_api, journal, tx, delivery
        self.directory, self.phase_name = Path(directory), phase_name
        self.directory.mkdir()
        self.events, self.references, self.frames, self.records = [], [], [], {}
        self.activations, self.ack_errors, self.lookup_observations = [], [], []
        self.close_effects, self.business_calls, self.suppressions, self.lock_exits = [], [], [], []
        self.public_calls = []
        self.phase = 'startup'
        self.outcome_error = None
        self.request_returned = False
        self.unexpected_response = None
        self.state_observed = None
        self.journal_record = self.body_fault = self.entry_fault = self.rollback_fault = None
        self.entry_fault_stage = None
        self.native_fault_fired = self.rollback_fault_fired = False
        self.closed = False
        self.native_counts = Counter()
        self.stack = ExitStack()
        self.stack.enter_context(patch.dict(os.environ, {
            journal.SELECTOR: manifests['agent_journal'], tx.SELECTOR: manifests['store_transaction']}))
        self.journal_image = journal.installed_agent_journal(manifests['agent_journal'])
        self.tx_image = tx.installed_store_transaction(manifests['store_transaction'])
        assert tx.installed_store_transaction(manifests['store_transaction']) is self.tx_image
        assert journal.installed_agent_journal(manifests['agent_journal']) is self.journal_image

        def forbidden(*arguments, **keywords):
            self.references.append(self.phase)
            raise AssertionError('selected journal/TX reached a retained original')
        forbidden.__wrapped__ = forbidden
        self.stack.enter_context(patch.object(api.HIAAgentService, '_reference_call', forbidden))
        self.stack.enter_context(patch.object(store_api, '_STORE_TRANSACTION_REFERENCE', forbidden))
        self.stack.enter_context(patch.object(store_api.AgentStore, '_transaction_reference', forbidden))

        journal_entry, tx_entry = self.journal_image._entry, self.tx_image._entry
        initializer, call, effect = tx.StoreTransactionFrame.__init__, tx.StoreTransactionFrame.call, tx.StoreTransactionFrame.effect
        close_original = store_api._NATIVE_STORE_CLOSE_REFERENCE
        public_original = api.HIAAgentService.call

        def journal_native(source, size, output, capacity, state, extent):
            stage = struct.unpack_from('<Q', ctypes.string_at(state, 8))[0]
            self.native_counts['journal:' + self.phase + ':' + str(stage)] += 1
            self.event('journal-entry', stage=stage)
            code = journal_entry(source, size, output, capacity, state, extent)
            self.event('journal-entry-return', stage=stage, code=code)
            if (self.phase == 'request' and stage == self.entry_fault_stage
                    and self.entry_fault is not None and not self.native_fault_fired):
                self.native_fault_fired = True
                self.event('journal-receipt-lost', stage=stage, error_id=id(self.entry_fault))
                raise self.entry_fault
            return code

        def transaction_native(source, size, output, capacity, state, extent):
            words = struct.unpack('<10Q', ctypes.string_at(source, tx.REQUEST_BYTES))
            assert size == tx.REQUEST_BYTES and words[0] == tx.REQUEST_MAGIC
            event, port = words[1], words[3]
            self.native_counts['tx:' + self.phase + ':' + str(event)] += 1
            self.event('tx-entry', event=event, port=port, sequence=words[2])
            code = tx_entry(source, size, output, capacity, state, extent)
            self.event('tx-entry-return', event=event, port=port, code=code)
            if (self.phase == 'request' and event == tx.SUCCEEDED and port == tx.PORT['rollback']
                    and self.rollback_fault is not None and not self.rollback_fault_fired):
                self.rollback_fault_fired = True
                self.event('rollback-receipt-lost', error_id=id(self.rollback_fault))
                raise self.rollback_fault
            return code

        def initialize(frame, image, *arguments, **keywords):
            assert image is self.tx_image, 'public transaction selected another image'
            initializer(frame, image, *arguments, **keywords)
            if self.phase == 'request':
                self.frames.append(frame)
                self.event('tx-frame', frame_id=id(frame))

        def observed_call(frame, event, observation=0):
            if self.phase == 'request':
                record = frame._delivery
                if record is not None:
                    self.records[id(record)] = record
                self.event('tx-call', event=event, frame_id=id(frame),
                           journal=record_state(self.journal_record),
                           active_body_error=sys.exception() is self.body_fault)
            result = call(frame, event, observation)
            if self.phase == 'request':
                self.event('tx-call-confirmed', event=event, frame_id=id(frame), receipt_phase=result.phase)
            return result

        def observed_effect(frame, port):
            name = tx.PORTS[port - 1]
            if self.phase == 'request':
                self.event('tx-effect', name=name, frame_id=id(frame),
                           journal=record_state(self.journal_record),
                           active_body_error=sys.exception() is self.body_fault)
            result = effect(frame, port)
            if self.phase == 'request':
                self.event('tx-effect-return', name=name, frame_id=id(frame))
            return result

        def observed_close(store):
            self.close_effects.append(id(store))
            return close_original(store)

        self.stack.enter_context(patch.object(self.journal_image, '_entry', journal_native))
        self.stack.enter_context(patch.object(self.tx_image, '_entry', transaction_native))
        self.stack.enter_context(patch.object(tx.StoreTransactionFrame, '__init__', initialize))
        self.stack.enter_context(patch.object(tx.StoreTransactionFrame, 'call', observed_call))
        self.stack.enter_context(patch.object(tx.StoreTransactionFrame, 'effect', observed_effect))
        self.stack.enter_context(patch.object(store_api, '_NATIVE_STORE_CLOSE_REFERENCE', observed_close))
        self.service = api.HIAAgentService(self.directory / 'state')
        self.service.store.db.execute('CREATE TABLE effect_probe (value TEXT)')
        self.service.store.db.set_trace_callback(lambda sql: self.event('sql', sql=sql))
        self.arguments = {'catalog_sha256': self.service.catalog_sha256, 'request_key': 'journal-cleanup-control'}

        def observed_public(service, tool, arguments):
            assert service is self.service
            self.public_calls.append({'phase': self.phase, 'tool': tool, 'arguments': dict(arguments)})
            return public_original(service, tool, arguments)

        self.stack.enter_context(patch.object(api.HIAAgentService, 'call', observed_public))

        def business(arguments):
            self.business_calls.append(dict(arguments))
            self.service.store.db.execute("INSERT INTO effect_probe VALUES ('effect')")
            return {'effect': 'would-have-committed'}
        # Same foreign business/schema setup as the unchanged original 24-case
        # journal test. SQLite and all selected native custody remain actual.
        self.stack.enter_context(patch.object(api, 'validate', return_value=None))
        self.stack.enter_context(patch.object(self.service, '_hia_adopt', business))
        self.phase = 'request'

    def event(self, tag, **fields):
        self.events.append({'index': len(self.events), 'phase': self.phase, 'tag': tag, **fields})

    def remember(self, record):
        assert type(record) is self.delivery.DeliveryRecord
        if self.journal_record is None:
            self.journal_record = record
        assert self.journal_record is record

    def ack_patch(self, operation, mode, fault):
        self.body_fault = fault
        original = getattr(self.journal.JournalSession, operation)
        control = self
        if mode == 'lookup':
            class LookupFailure:
                def __get__(self, instance, owner):
                    if instance is None:
                        return self
                    record = control.delivery.current_record()
                    control.remember(record)
                    row = {'record': record_state(record), 'error_id': id(fault),
                           'activation_absent': instance._ack_delivery is None}
                    control.lookup_observations.append(row)
                    control.event('ack-lookup-error', **row)
                    raise fault
            return patch.object(self.journal.JournalSession, operation, LookupFailure())

        def replacement(session, *arguments):
            activation = session._ack_delivery
            assert type(activation) is control.journal._JournalAcknowledgement
            control.remember(activation.record)
            control.activations.append(activation)
            control.event('ack-method-enter', mode=mode, activation_id=id(activation),
                          journal=record_state(activation.record))
            if mode == 'before':
                raise fault
            try:
                result = original(session, *arguments)
            except BaseException as error:
                row = {'error_id': id(error), 'journal': record_state(activation.record),
                       'activation_complete': activation.complete}
                control.ack_errors.append(row)
                control.event('ack-method-native-error', **row)
                raise
            control.event('ack-method-confirmed', activation_complete=activation.complete,
                          journal=record_state(activation.record))
            if mode == 'after':
                raise fault
            assert mode == 'delegate'
            return result
        return patch.object(self.journal.JournalSession, operation, replacement)

    def suppression_patch(self, fault):
        original = self.service.store.transaction
        control = self
        class SuppressAfterOriginal:
            def __init__(self):
                self.manager = original()
            def __enter__(self):
                return self.manager.__enter__()
            def __exit__(self, kind, error, traceback):
                result = self.manager.__exit__(kind, error, traceback)
                if error is fault:
                    row = {'error_id': id(error), 'original_identity': error is fault,
                           'original_exit_result': result,
                           'journal': record_state(control.journal_record)}
                    control.suppressions.append(row)
                    control.event('transaction-suppressed-after-real-cleanup', **row)
                    return True
                return result
        return patch.object(self.service.store, 'transaction', SuppressAfterOriginal)

    def lock_replacement_patch(self, fault, replacement):
        original, control = self.service.store.lock, self
        class RealLockReplacement:
            def __enter__(self):
                return original.__enter__()
            def __exit__(self, kind, error, traceback):
                result = original.__exit__(kind, error, traceback)
                if error is fault:
                    row = {'original_error_id': id(error), 'replacement_id': id(replacement),
                           'original_identity': error is fault,
                           'journal': record_state(control.journal_record)}
                    control.lock_exits.append(row)
                    control.event('real-lock-released-replacement', **row)
                    raise replacement
                return result
        return patch.object(self.service.store, 'lock', RealLockReplacement())

    def request(self):
        return self.service.call('hia_adopt', self.arguments)

    def request_error(self):
        try:
            result = self.request()
        except BaseException as error:
            self.outcome_error = error
            return error
        self.request_returned = True
        self.unexpected_response = result
        raise AssertionError('public request returned despite injected failure')

    def observation(self):
        self.phase = 'observe'
        local = read_rows(self.service.store.db)
        path = Path(self.service.store.database).resolve().as_uri() + '?mode=ro'
        with closing(sqlite3.connect(path, uri=True, isolation_level=None)) as readonly:
            durable = read_rows(readonly)
        self.state_observed = {'local': local, 'durable': durable,
                               'connection_in_transaction': self.service.store.db.in_transaction}
        return self.state_observed

    def assert_no_terminal(self):
        assert self.native_counts['journal:request:8'] == 0
        assert not self.references

    def assert_original_rollback(self, operation, state):
        assert not state['connection_in_transaction']
        assert state['local'] == state['durable']
        assert state['local']['effects'] == [] and state['local']['costs'] == []
        requests = state['local']['requests']
        if operation == 'reserved':
            assert requests == [] and self.business_calls == []
        else:
            assert len(requests) == 1 and requests[0][3:5] == ['running', None]
            assert len(self.business_calls) == 1
        assert sum(event['tag'] == 'sql' and event['phase'] == 'request'
                   and event['sql'] == 'ROLLBACK' for event in self.events) == 1
        body = [row for row in self.events if row['tag'] == 'tx-call-confirmed'
                and row['phase'] == 'request' and row['event'] == self.tx.BODY_RAISED]
        assert len(body) == 1
        assert self.frames and all(frame.finished and not frame.native_failed for frame in self.frames)
        assert all(frame._body_observation.retired and not frame._body_observation.pending
                   and frame._body_observation.loss is None for frame in self.frames)
        self.assert_no_terminal()

    def assert_unknown_retained(self):
        assert self.journal_record is not None and self.journal_record.loss is not None
        assert not self.journal_record.retired
        retained = [frame for frame in self.frames if not frame.finished and frame.native_failed]
        assert retained
        # Read-only membership in this single-thread child; do not allocate
        # observer generators while holding a production representation lock.
        assert all(self.tx._FRAME_CUSTODY.get(id(frame)) is frame for frame in retained)
        # Either the pending body result or the real cleanup-native record
        # retains this exact Store. No registry is written or emptied here.
        store = self.service.store
        body = any(frame._body_observation.loss is not None
                   and frame._body_observation.resource is store for frame in retained)
        actual = any(record.loss is not None and any(value is store for value, _ in record.resources)
                     for record in self.records.values())
        assert body or actual
        self.phase = 'close'
        close_error = raised(self.service.close)
        assert isinstance(close_error, self.delivery.NativeDeliveryUnknown)
        assert self.close_effects == []
        self.event('retirement-rejected', error=exception_chain(close_error),
                   body_observation_retained=body, native_resource_retained=actual)
        return close_error

    def close_confirmed(self):
        self.phase = 'close'
        self.service.close()
        self.closed = True
        assert self.close_effects == [id(self.service.store)]
        self.event('actual-store-close-completed')

    def retry_unknown(self):
        self.phase = 'retry'
        before = len(self.business_calls)
        response = self.request()
        assert response['status'] == 'rejected' and response['error']['code'] == 'E_HIA_REQUEST_UNKNOWN'
        assert len(self.business_calls) == before
        self.event('unknown-intent-retry', response=response, business_calls_unchanged=True)
        return response

    def report(self, operation, error, state, **extra):
        return {'phase_name': self.phase_name, 'operation': operation,
                'journal_image_sha256': self.journal_image.image_sha256,
                'transaction_image_sha256': self.tx_image.image_sha256,
                'exception': exception_chain(error), 'state_before_retry_or_close': state,
                'journal_record': record_state(self.journal_record),
                'activation_count': len(self.activations),
                'activations': [{'id': id(item), 'stage': item.stage, 'active': item.active,
                    'complete': item.complete, 'session_activation_reset': item.session._ack_delivery is None}
                    for item in self.activations],
                'lookup_observations': self.lookup_observations, 'ack_errors': self.ack_errors,
                'native_counts': dict(self.native_counts), 'events': self.events,
                'native_counts_scope': 'after actual image/catalog admission; startup plus request/retry/close',
                'public_calls': self.public_calls, 'public_call_count': len(self.public_calls),
                'references': self.references, 'business_calls': self.business_calls,
                'close_effects': self.close_effects, 'actual_store_closed': self.closed,
                'unknown_custody_not_force_retired': True, **extra}

    def save_attempt(self):
        # Preserve partial observations even when a following assertion fails.
        # This performs no new SQL, native call, close, or forced retirement.
        record = {'schema': 'hepta.hia.transaction-journal-control-attempt.v1',
                  'phase_name': self.phase_name, 'events': self.events,
                  'native_counts': dict(self.native_counts),
                  'public_calls': self.public_calls,
                  'journal_record': record_state(self.journal_record),
                  'exception': None if self.outcome_error is None else exception_chain(self.outcome_error),
                  'state_observed': self.state_observed,
                  'request_returned_unexpectedly': self.request_returned,
                  'unexpected_response': self.unexpected_response,
                  'business_calls': self.business_calls, 'close_effects': self.close_effects,
                  'references': self.references, 'actual_store_closed': self.closed,
                  'native_fault_fired': self.native_fault_fired,
                  'rollback_fault_fired': self.rollback_fault_fired,
                  'frames': [{'id': id(frame), 'finished': frame.finished,
                      'fenced': frame.fenced, 'native_failed': frame.native_failed,
                      'body_pending': frame._body_observation.pending,
                      'body_retired': frame._body_observation.retired,
                      'body_lost': frame._body_observation.loss is not None}
                      for frame in self.frames],
                  'assertions_passed': None,
                  'assertion_authority': 'case observations plus complete outer unittest method'}
        (self.directory / 'raw-observations.json').write_bytes(encoded(record) + b'\n')

    def restore_observers(self):
        # This restores wrappers only. Never close/rollback/release an unknown
        # Store or clear native/resource custody to satisfy test cleanup.
        try:
            self.save_attempt()
        finally:
            self.stack.close()


def preentry_case(case, root, manifests):
    attempts = []
    for phase in ('before', 'after'):
        c = Control(root / phase, manifests, phase)
        fault = MemoryError('original foreign ACK failure ' + phase)
        try:
            with c.ack_patch(case['operation'], phase, fault):
                error = c.request_error()
            assert error is fault and type(error) is MemoryError
            state = c.observation()
            c.assert_original_rollback(case['operation'], state)
            assert len(c.activations) == 1
            activation = c.activations[0]
            assert not activation.active and activation.complete is (phase == 'after')
            assert activation.session._ack_delivery is None
            stage = 2 if case['operation'] == 'reserved' else 7
            assert c.native_counts['journal:request:' + str(stage)] == int(phase == 'after')
            rollback = [event for event in c.events if event['phase'] == 'request'
                        and event['tag'] == 'tx-effect' and event['name'] == 'rollback']
            assert len(rollback) == 1 and rollback[0]['active_body_error'] is True
            assert rollback[0]['journal']['lost'] is False
            assert rollback[0]['journal']['observation_pending'] is (phase == 'before')
            if phase == 'before':
                assert c.journal_record.loss is not None and c.journal_record.loss.error is fault
                assert c.journal_record.observation_pending and not c.journal_record.retired
            else:
                assert c.journal_record.loss is None and not c.journal_record.observation_pending
                assert c.journal_record.retired
            retry = c.retry_unknown() if case['operation'] == 'committed_inline' else None
            c.close_confirmed()
            attempts.append(c.report(case['operation'], error, state,
                original_error_identity=True, retry=retry, native_ack_confirmed=phase == 'after'))
        finally:
            c.restore_observers()
    return attempts


def native_case(case, root, manifests):
    c = Control(root / 'attempt', manifests, 'actual-journal-native-loss')
    fault = {'RuntimeError': RuntimeError, 'ValueError': ValueError}[case['error']]('actual native journal receipt lost')
    try:
        c.entry_fault, c.entry_fault_stage = fault, 2 if case['operation'] == 'reserved' else 7
        with c.ack_patch(case['operation'], 'delegate', fault):
            error = c.request_error()
        assert c.native_fault_fired and contains_error(error, fault)
        assert c.native_counts['journal:request:' + str(c.entry_fault_stage)] == 1
        assert isinstance(error, c.tx.StoreTransactionUnknown)
        assert len(c.activations) == 1 and not c.activations[0].complete
        assert not c.activations[0].active and c.activations[0].session._ack_delivery is None
        assert c.ack_errors and c.ack_errors[0]['journal']['lost'] is True
        assert c.journal_record.loss.error is fault
        state = c.observation()
        assert state['connection_in_transaction']
        assert state['local']['costs'] == state['durable']['costs'] == []
        assert state['durable']['effects'] == []
        assert c.native_counts['tx:request:' + str(c.tx.BODY_RAISED)] == 0
        assert not any(row['tag'] == 'sql' and row['phase'] == 'request'
                       and row['sql'] == 'ROLLBACK' for row in c.events)
        if case['operation'] == 'reserved':
            assert state['durable']['requests'] == []
        else:
            assert len(state['durable']['requests']) == 1
            assert state['durable']['requests'][0][3:5] == ['running', None]
        c.assert_no_terminal()
        c.assert_unknown_retained()
        return [c.report(case['operation'], error, state, actual_native_loss_immediate=True)]
    finally:
        c.restore_observers()


def suppressed_case(case, root, manifests):
    c = Control(root / 'attempt', manifests, 'suppressed-' + case['point'])
    fault = MemoryError('original suppressed ACK ' + case['point'])
    try:
        mode = 'lookup' if case['point'] == 'lookup' else 'before'
        with c.suppression_patch(fault), c.ack_patch(case['operation'], mode, fault):
            error = c.request_error()
        assert isinstance(error, c.delivery.NativeDeliveryUnknown) and error is not fault
        assert len(c.suppressions) == 1 and c.suppressions[0]['original_identity'] is True
        assert c.suppressions[0]['original_exit_result'] is False
        assert c.suppressions[0]['journal']['lost'] is False
        assert c.suppressions[0]['journal']['observation_pending'] is True
        if mode == 'lookup':
            assert c.activations == [] and len(c.lookup_observations) == 1
            assert c.lookup_observations[0]['activation_absent'] is True
        else:
            assert len(c.activations) == 1 and not c.activations[0].complete
            assert contains_error(error, fault) and c.journal_record.loss.error is fault
        assert c.journal_record.loss is not None and c.journal_record.observation_pending
        state = c.observation()
        c.assert_original_rollback(case['operation'], state)
        stage = 2 if case['operation'] == 'reserved' else 7
        assert c.native_counts['journal:request:' + str(stage)] == 0
        if case['operation'] == 'reserved':
            assert c.native_counts['journal:request:5'] == 0
        c.close_confirmed()
        return [c.report(case['operation'], error, state, original_suppressed_error_identity=True,
                         continuation_blocked_before_terminal=True)]
    finally:
        c.restore_observers()


def cleanup_case(case, root, manifests):
    c = Control(root / 'attempt', manifests, case['point'])
    body = MemoryError('original ACK failure before cleanup')
    cleanup = (ValueError('actual rollback native receipt lost') if case['point'] == 'rollback-native'
               else RuntimeError('original lock exit replacement'))
    try:
        with ExitStack() as patches:
            patches.enter_context(c.ack_patch(case['operation'], 'before', body))
            if case['point'] == 'rollback-native':
                c.rollback_fault = cleanup
            else:
                patches.enter_context(c.lock_replacement_patch(body, cleanup))
            error = c.request_error()
        state = c.observation()
        assert not state['connection_in_transaction']
        assert state['local'] == state['durable']
        assert state['local']['effects'] == state['local']['costs'] == []
        assert c.journal_record.loss is not None and not c.journal_record.retired
        assert sum(row['tag'] == 'sql' and row['phase'] == 'request'
                   and row['sql'] == 'ROLLBACK' for row in c.events) == 1
        if case['operation'] == 'reserved':
            assert state['local']['requests'] == []
        else:
            assert len(state['local']['requests']) == 1
            assert state['local']['requests'][0][3:5] == ['running', None]
        c.assert_no_terminal()
        if case['point'] == 'rollback-native':
            assert c.rollback_fault_fired and isinstance(error, c.tx.StoreTransactionUnknown)
            assert contains_error(error, cleanup)
            assert c.journal_record.loss.error is cleanup
            c.assert_unknown_retained()
        else:
            assert error is cleanup and error.__context__ is body
            assert len(c.lock_exits) == 1 and c.lock_exits[0]['original_identity'] is True
            assert c.lock_exits[0]['journal']['lost'] is False
            assert c.journal_record.loss.error is body
            assert all(frame.finished and not frame.native_failed for frame in c.frames)
            c.close_confirmed()
        return [c.report(case['operation'], error, state,
                         original_body_error_id=id(body), cleanup_error_id=id(cleanup))]
    finally:
        c.restore_observers()


def run_group(group, directory, manifests_json, source_json):
    assert group in GROUPS and len(ALL_IDS) == len(set(ALL_IDS)) == 14
    directory = Path(directory)
    manifests, expected = json.loads(manifests_json), json.loads(Path(source_json).read_bytes())
    before = source_pins()
    assert before == expected
    for path in manifests.values():
        assert Path(path).resolve(strict=True).is_relative_to(directory.parent)
    # No descendant provider is part of these controls. Native entries are
    # actual in-process mapped calls, while compilation belongs to the parent.
    def audit(event, arguments):
        if event in ('subprocess.Popen', 'os.fork', 'os.forkpty', 'os.posix_spawn') or event.startswith('os.exec'):
            raise AssertionError('transaction journal control spawned a descendant: ' + event)
    sys.addaudithook(audit)
    selected = {'preentry': preentry_case, 'native': native_case,
                'suppressed': suppressed_case, 'cleanup': cleanup_case}[group]
    planned = [row['id'] for row in GROUPS[group]]
    started, stopped, results, failures = [], [], [], []
    for case in GROUPS[group]:
        started.append(case['id'])
        folder = directory / case['id'];folder.mkdir()
        try:
            attempts = selected(case, folder, manifests)
            record = {'id': case['id'], 'status': 'PASS', 'attempts': attempts}
        except BaseException as error:
            text = traceback.format_exc()
            (folder / 'failure.traceback.log').write_text(text)
            failures.append(case['id'])
            record = {'id': case['id'], 'status': 'HOLD', 'error': exception_chain(error),
                      'traceback_path': 'failure.traceback.log'}
        finally:
            stopped.append(case['id'])
        (folder / 'observations.json').write_bytes(encoded(record) + b'\n')
        results.append(record)
    after = source_pins()
    attempts = sum(len(row.get('attempts', ())) for row in results)
    expected_attempts = 4 if group == 'preentry' else len(planned)
    public_calls = sum(attempt['public_call_count'] for row in results
                       for attempt in row.get('attempts', ()))
    expected_public_calls = 6 if group == 'preentry' else len(planned)
    passed = (not failures and planned == started == stopped and before == after
              and attempts == expected_attempts and public_calls == expected_public_calls)
    record = {'schema': 'hepta.hia.transaction-journal-controls-group.v1',
              'status': 'PASS' if passed else 'HOLD', 'group': group,
              'planned': planned, 'started': started, 'stopped': stopped,
              'control_count': len(planned), 'request_attempts': attempts,
              'expected_request_attempts': expected_attempts,
              'public_call_count': public_calls, 'expected_public_call_count': expected_public_calls,
              'request_attempts_exclude_two_separate_unknown_intent_retries': True,
              'failures': failures, 'source_before': before, 'source_after': after,
              'source_unchanged': before == after, 'results': results,
              'original_21_or_61_tests_executed_here': False,
              'unknown_custody_lives_until_child_exit': True,
              'descendant_providers_forbidden': True,
              'journal_and_transaction_native_entries_are_actual': True}
    (directory / 'observations.json').write_bytes(encoded(record) + b'\n')
    print(encoded({'status': record['status'], 'group': group, 'controls': len(planned),
                   'request_attempts': attempts}).decode())
    if not passed:
        raise AssertionError('transaction journal controls are HOLD: ' + ','.join(failures))
