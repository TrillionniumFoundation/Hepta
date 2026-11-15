"""Focused native journal/transaction ACK regression controls.

Run separately from the unchanged 61 original caller methods. Each control has
its own process: deliberately unknown records and Store resources remain in
real custody until that process exits. No registry is cleared, no exception
traceback is edited, and no garbage collection is requested. Matching current
cold evidence builds both images with the existing builders; an alternative
explicit-manifest invocation claims only component scope. Raw failures and
actual lost-ACK buffers are retained.
"""
from __future__ import annotations

import argparse
from collections import Counter
from contextlib import ExitStack
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import signal
import struct
import subprocess
import sys
import time
import traceback
from unittest.mock import patch
import weakref
import zlib

ROOT = Path(__file__).resolve().parents[1]
CASE_SECONDS = 45
TOTAL_SECONDS = 600
CLEANUP_SECONDS = 3
ERROR_TYPES = (RuntimeError, MemoryError, KeyboardInterrupt, SystemExit)
CASES = tuple(
    {'id': operation + '-' + mode + '-' + error.__name__,
     'operation': operation, 'mode': mode, 'error': error.__name__}
    for operation in ('reserved', 'committed_inline')
    for mode, errors in (
        ('before', ERROR_TYPES), ('after', (RuntimeError,)),
        ('rollback-error', (RuntimeError,)), ('exit-error', (RuntimeError,)),
        ('suppress', (RuntimeError,)), ('native-return-loss', (RuntimeError,)),
        ('native-raised-loss', (RuntimeError,)))
    for error in errors
) + ({'id': 'explicit-owner-scope', 'mode': 'owner-scope'},)
EXPECTED_COUNT = 21
PIN_PATHS = (
    'tests/hia_store_transaction_ack_controls.py',
    'hepta/hia_agent_journal_native.py', 'hepta/hia_agent_service.py',
    'hepta/hia_agent_store.py', 'hepta/hia_store_transaction_native.py',
    'hepta/hia_store_transaction_protocol.py', 'hepta/hia_native_delivery.py',
    'tools/qualify_hia_store_transaction.py',
    'tools/build_hia_store_transaction.py', 'tools/build_hia_json_preflight.py',
    'tools/qualify_hia_selfhost.py', 'tools/hia_selfhost_contract.py',
    'tests/test_hia_agent_journal_native.py',
    'tests/test_hia_execution_budget_native.py',
    'tests/test_hia_slot_ledger_native.py',
    'tests/fixtures/hia_store_transaction_separate_5bf.json',
    'examples/hia_bootstrap/store_transaction.hepta',
    'examples/hia_bootstrap/agent_journal.hepta',
)


def encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
                      separators=(',', ':'), allow_nan=False).encode()


def source_pins():
    return {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in PIN_PATHS}


def image_pins(manifests):
    result = {}
    for path in manifests:
        path = path.resolve(strict=True)
        raw = path.read_bytes()
        image = path.parent / json.loads(raw)['image_path']
        result[str(path)] = sha256(raw).hexdigest()
        result[str(image)] = sha256(image.read_bytes()).hexdigest()
    return result


def error_observation(error):
    if error is None:
        return None
    return {'id': id(error), 'module': type(error).__module__,
            'type': type(error).__qualname__, 'args': list(error.args),
            'notes': list(getattr(error, '__notes__', ())),
            'context_id': None if error.__context__ is None else id(error.__context__),
            'cause_id': None if error.__cause__ is None else id(error.__cause__),
            'suppress_context': error.__suppress_context__,
            'traceback': traceback.format_exception(type(error), error, error.__traceback__)}


def record_observation(record):
    if record is None:
        return None
    return {'id': id(record), 'native_pending': record.native_pending,
            'observation_pending': record.observation_pending,
            'lost': record.loss is not None, 'retired': record.retired,
            'terminal': record.terminal,
            'loss_id': None if record.loss is None else id(record.loss),
            'loss_error_id': None if record.loss is None else id(record.loss.error),
            'resources': [id(resource) for resource, _token in record.resources]}


def raise_exact(error):
    # This provider owns no extra traceback -> frame-local -> error cycle.
    try:
        raise error
    finally:
        del error


class Payload:
    pass


class Observation:
    def __init__(self, path, case):
        self.path, self.case = path, case
        self.events, self.checks, self.packets = [], [], []
        self.record = self.session = None
        self.error = self.cleanup_error = self.outer = self.cause = None
        self.ack_called = False
        self.effect_count = self.close_count = 0
        self.journal_entries, self.transaction_entries = Counter(), Counter()

    def event(self, name, **values):
        self.events.append({'index': len(self.events), 'event': name, **values})

    def require(self, condition, label):
        self.checks.append({'check': label, 'passed': bool(condition)})
        if not condition:
            raise AssertionError(label)

    def raw(self, name, value):
        packed = zlib.compress(value)
        path = self.path / (name + '.zlib')
        path.write_bytes(packed)
        return {'path': path.name, 'raw_bytes': len(value),
                'raw_sha256': sha256(value).hexdigest(),
                'stored_bytes': len(packed), 'stored_sha256': sha256(packed).hexdigest(),
                'encoding': 'zlib; lossless, complete bytes including canaries'}

    def journal_packet(self, name, source, size, output, capacity, state, extent):
        packet = {'name': name,
            'source': self.raw(name + '-source', ctypes.string_at(source, size + 64)),
            'output': self.raw(name + '-output', ctypes.string_at(output, capacity + 64)),
            'state': self.raw(name + '-state', ctypes.string_at(state, extent + 64))}
        self.packets.append(packet)

    def transaction_entry(self, entry):
        def counted(source, size, output, capacity, state, extent):
            request = ctypes.string_at(source, size + 16)
            words = struct.unpack('<10Q', request[:size])
            row = {'event': words[1], 'request_hex': request.hex(),
                   'state_before_hex': ctypes.string_at(state, extent + 16).hex()}
            self.transaction_entries[str(words[1])] += 1
            self.event('transaction-native-enter', packet=row)
            try:
                code = entry(source, size, output, capacity, state, extent)
            except BaseException as error:
                row['raised'] = error_observation(error)
                raise
            else:
                row.update({'return_code': code,
                    'output_hex': ctypes.string_at(output, capacity + 16).hex(),
                    'state_after_hex': ctypes.string_at(state, extent + 16).hex()})
                return code
        return counted


class ObservedDB:
    def __init__(self, actual, observation):
        self.actual, self.observation = actual, observation

    def __getattr__(self, name):
        return getattr(self.actual, name)

    def execute(self, sql, *arguments):
        o = self.observation
        o.event('sql-enter', sql=sql, arguments=list(arguments),
                journal=record_observation(o.record))
        if sql == 'ROLLBACK' and o.case['mode'] == 'rollback-error' and o.ack_called:
            o.event('rollback-provider-error', error=error_observation(o.cleanup_error))
            raise_exact(o.cleanup_error)
        result = self.actual.execute(sql, *arguments)
        o.event('sql-return', sql=sql, in_transaction=self.actual.in_transaction,
                journal=record_observation(o.record))
        return result

    def close(self):
        o = self.observation
        o.close_count += 1
        o.event('db-close-enter', in_transaction=self.actual.in_transaction)
        result = self.actual.close()
        o.event('db-close-return')
        return result


class ObservedLock:
    def __init__(self, actual, observation):
        self.actual, self.observation = actual, observation

    def __enter__(self):
        self.observation.event('lock-enter')
        return self.actual.__enter__()

    def __exit__(self, kind, error, tb):
        o = self.observation
        o.event('lock-exit', error=error_observation(error),
                journal=record_observation(o.record))
        result = self.actual.__exit__(kind, error, tb)
        if o.ack_called and o.case['mode'] == 'exit-error':
            o.event('lock-exit-provider-error', error=error_observation(o.cleanup_error))
            raise_exact(o.cleanup_error)
        if o.ack_called and o.case['mode'] == 'suppress':
            o.event('lock-suppressed')
            return True
        return result


def invoke_with_context(service, arguments, observation):
    # The exact preexisting handler, explicit cause, notes, and payload remain
    # observable across SQL cleanup. The returned error is never normalized.
    try:
        raise observation.outer
    except LookupError:
        try:
            value = service.call('hia_adopt', arguments)
        except BaseException as error:
            return error
        observation.event('unexpected-return', value=value)
        return None


def poisoned_reference(*arguments, **keywords):
    raise AssertionError('selected control entered a retained transaction or journal owner')


poisoned_reference.__wrapped__ = poisoned_reference


def run_ack_case(case, folder, transaction_manifest, journal_manifest, o):
    from hepta import hia_agent_journal_native as journal
    from hepta import hia_agent_store as store_api
    from hepta import hia_native_delivery as delivery
    from hepta import hia_store_transaction_native as transaction
    from hepta.hia_agent_service import HIAAgentService
    from tools.qualify_hia_store_transaction import selected_transaction_owner

    transaction_image = transaction.installed_store_transaction(str(transaction_manifest))
    journal_image = journal.installed_agent_journal(str(journal_manifest))
    service = HIAAgentService(folder / 'state')
    actual_db = service.store.db
    actual_db.execute('CREATE TABLE effect_probe (value TEXT)')
    service.store.db = ObservedDB(actual_db, o)
    service.store.lock = ObservedLock(service.store.lock, o)
    o.error = next(kind for kind in ERROR_TYPES if kind.__name__ == case['error'])(case['id'])
    o.cleanup_error = RuntimeError('cleanup provider: ' + case['id'])
    o.outer, o.cause = LookupError('outer handler'), KeyError('explicit provider cause')
    o.error.__cause__ = o.cause
    o.error.add_note('exact ACK provider object')
    o.error.payload = Payload()
    payload = weakref.ref(o.error.payload)
    original_ack = getattr(journal.JournalSession, case['operation'])
    original_entry = journal_image._entry
    target_stage = 2 if case['operation'] == 'reserved' else 7
    custody_before = list(delivery.custody_snapshot())
    o.require(not custody_before, 'fresh process has no prior delivery custody')

    def effect(arguments):
        o.effect_count += 1
        o.event('business-effect')
        service.store.db.execute("INSERT INTO effect_probe VALUES ('effect')")
        return {'effect': 'would-have-committed'}

    def entry(source, size, output, capacity, state, extent):
        stage = struct.unpack('<Q', ctypes.string_at(state, 8))[0]
        o.journal_entries[str(stage)] += 1
        o.event('journal-native-enter', stage=stage)
        target = stage == target_stage and case['mode'].startswith('native-')
        if target:
            o.journal_packet('before-actual-ACK', source, size, output, capacity, state, extent)
        code = original_entry(source, size, output, capacity, state, extent)
        o.event('journal-native-return', stage=stage, code=code)
        if target:
            o.journal_packet('after-actual-ACK', source, size, output, capacity, state, extent)
            o.require(code == (journal.CONTINUE if target_stage == 2 else journal.NONE),
                      'actual native ACK returned its valid instruction before injected loss')
            if case['mode'] == 'native-return-loss':
                o.event('lost-ACK-return', actual_code=code, delivered_code=0xfffffffd)
                return 0xfffffffd
            o.event('lost-ACK-raised', error=error_observation(o.error))
            raise_exact(o.error)
        return code

    def ack(session, *arguments):
        o.record, o.session, o.ack_called = delivery.current_record(), session, True
        o.event('ACK-provider-enter', journal=record_observation(o.record))
        try:
            if case['mode'] in ('after', 'native-return-loss', 'native-raised-loss'):
                original_ack(session, *arguments)
            raise_exact(o.error)
        except BaseException as error:
            o.event('ACK-provider-raised', error=error_observation(error),
                    journal=record_observation(o.record))
            raise

    arguments = {'catalog_sha256': service.catalog_sha256, 'request_key': 'ack-control'}
    public_transaction = store_api.AgentStore.transaction
    with ExitStack() as scope:
        scope.enter_context(selected_transaction_owner(
            transaction_image, transaction_manifest, poisoned_reference))
        scope.enter_context(patch.dict(os.environ, {journal.SELECTOR: str(journal_manifest)}))
        scope.enter_context(patch.object(HIAAgentService, '_reference_call', poisoned_reference))
        # Admission above used the actual loader and immutable files. This
        # fixed image permits observation of its exact native entry below.
        scope.enter_context(patch.object(journal, 'installed_agent_journal', return_value=journal_image))
        scope.enter_context(patch.object(journal_image, '_entry', entry))
        scope.enter_context(patch.object(transaction_image, '_entry',
            o.transaction_entry(transaction_image._entry)))
        scope.enter_context(patch('hepta.hia_agent_service.validate', return_value=None))
        scope.enter_context(patch.object(service, '_hia_adopt', side_effect=effect))
        scope.enter_context(patch.object(journal.JournalSession, case['operation'], ack))
        received = invoke_with_context(service, arguments, o)
        o.event('call-outcome', error=error_observation(received),
                journal=record_observation(o.record), in_transaction=actual_db.in_transaction)
        o.require(received is not None and o.ack_called, 'the intended ACK fault actually ran')
        o.require(all(o.transaction_entries[str(event)] > 0 for event in (0, 1, 2)),
                  'actual transaction image initialized, claimed, and acknowledged effects')
        o.require(o.journal_entries[str(target_stage)] == int(case['mode'] in
                  ('after', 'native-return-loss', 'native-raised-loss')),
                  'target ACK native entry count distinguishes before-entry and entered faults')
        sql = [row['sql'] for row in o.events if row['event'] == 'sql-return']
        ack_error = next(row for row in o.events if row['event'] == 'ACK-provider-raised')
        o.require(o.effect_count == (case['operation'] == 'committed_inline'),
                  'no extra business effect executed')
        o.require('8' not in o.journal_entries, 'failed invocation never entered terminal journal finish')

        if case['mode'].startswith('native-'):
            o.require(type(received) is transaction.StoreTransactionUnknown,
                      'actual entered native loss fences transaction continuation')
            o.require(ack_error['journal']['lost'], 'child native loss published before ACK method unwound')
            o.require(o.record.loss is not None and o.record.loss is not o.record,
                      'loss origin is actual child native invocation')
            o.require(o.record.loss.native_pending and o.record.loss.owner is o.session,
                      'actual unconfirmed child handoff remains in custody')
            o.require(received.__context__ is o.record.loss.error,
                      'transaction resource fence keeps the actual child error as active context')
            o.require(any(resource is service.store for resource, _ in o.record.loss.resources),
                      'actual child loss retains the exact Store resource')
            if case['mode'] == 'native-raised-loss':
                o.require(o.record.loss.error is o.error, 'real native transport error identity retained')
            o.require('ROLLBACK' not in sql and actual_db.in_transaction,
                      'actual lost handoff cannot authorize rollback or transaction retirement')
            o.require(o.transaction_entries[str(transaction.BODY_RAISED)] == 0,
                      'actual lost child prevents even native BODY_RAISED resumption')
            first_outcome = len(o.events)
            try:
                service.close()
            except delivery.NativeDeliveryUnknown as error:
                o.event('close-refused', error=error_observation(error))
            else:
                o.require(False, 'unknown Store close must refuse')
            o.require(o.close_count == 0, 'unknown Store never entered database close')
            before_retry = (o.effect_count, sum(o.transaction_entries.values()))
            try:
                service.call('hia_adopt', arguments)
            except delivery.NativeDeliveryUnknown as error:
                o.event('retry-refused', error=error_observation(error))
            else:
                o.require(False, 'unknown Store retry must refuse')
            o.require(before_retry == (o.effect_count, sum(o.transaction_entries.values())),
                      'retry obtained no business or transaction native authority')
            o.require(not any(row['event'] == 'sql-enter' for row in o.events[first_outcome:]),
                      'retirement and retry performed no further SQL')
        else:
            o.require(not ack_error['journal']['lost'], 'method fault is not mistaken for actual native loss')
            o.require(ack_error['journal']['observation_pending'] == (case['mode'] != 'after'),
                      'only a fully confirmed ACK discharges the original SQL observation')
            if case['mode'] == 'suppress':
                o.require(isinstance(received, delivery.NativeDeliveryUnknown),
                          'lock suppression cannot permit normal continuation')
                o.require(received.__cause__ is o.error, 'suppression fence retains exact ACK error cause')
                o.require(any(row['event'] == 'lock-suppressed' for row in o.events),
                          'custom lock really suppressed the body error')
            elif case['mode'] in ('rollback-error', 'exit-error'):
                o.require(received is o.cleanup_error, 'cleanup replacement exception identity preserved')
                o.require(received.__context__ is o.error, 'cleanup error keeps original ACK context')
            else:
                o.require(received is o.error, 'exact ACK exception object propagated')
            o.require(o.error.__context__ is o.outer and o.error.__cause__ is o.cause,
                      'original exception context and explicit cause preserved')
            o.require(o.error.__notes__ == ['exact ACK provider object'], 'original exception notes preserved')
            rollback = [row for row in o.events if row['event'] == 'sql-enter' and row['sql'] == 'ROLLBACK']
            o.require(len(rollback) == 1, 'original transaction attempted rollback exactly once')
            o.require(o.transaction_entries[str(transaction.BODY_RAISED)] == 1,
                      'original raised body was actually delivered to selected native transaction')
            o.require(not rollback[0]['journal']['lost'], 'publication waits for this exact SQL cleanup')
            o.require(rollback[0]['journal']['observation_pending'] == (case['mode'] != 'after'),
                      'pending observation is retained throughout rollback')
            o.require(any(row['event'] == 'lock-exit' and row['error'] is not None for row in o.events),
                      'original exceptional lock exit occurred')
            o.require(('ROLLBACK' in sql) == (case['mode'] != 'rollback-error'),
                      'actual rollback return distinguishes rollback-provider failure')
            o.require(actual_db.in_transaction == (case['mode'] == 'rollback-error'),
                      'actual SQLite transaction state matches cleanup outcome')
            o.require(o.record.retired == (case['mode'] == 'after'),
                      'only acknowledged invocation retires its delivery record')
            if case['mode'] == 'after':
                o.require(o.record.loss is None, 'post-confirmed provider error creates no unknown debt')
            else:
                o.require(o.record.loss is o.record and o.record.error is o.error,
                          'finally publishes exact pending ACK error even after suppression or cleanup error')
            rows = [list(row) for row in actual_db.execute('SELECT state,response FROM requests ORDER BY key')]
            effects = [list(row) for row in actual_db.execute('SELECT * FROM effect_probe')]
            costs = [list(row) for row in actual_db.execute('SELECT * FROM costs')]
            o.event('observed-sql-state', requests=rows, effects=effects, costs=costs)
            if case['mode'] != 'rollback-error':
                o.require(not effects and not costs, 'real rollback removed business effects and all costs')
                o.require(rows == ([] if case['operation'] == 'reserved' else [['running', None]]),
                          'failed SQL ACK never produces a completed request')
            delivery.check_resource_retirement(service.store)
            o.event('resource-retirement-confirmed')
            service.close()
            o.require(o.close_count == 1, 'known transaction cleanup permits actual Store close')
            # Check the durable database through a new read-only connection.
            # A known rollback-provider error leaves rollback to SQLite close;
            # that is recorded separately from a returned ROLLBACK instruction.
            import sqlite3
            connection = sqlite3.connect('file:' + str(service.store.root / 'state.sqlite3') + '?mode=ro', uri=True)
            try:
                durable = {'requests': [list(row) for row in connection.execute('SELECT state,response FROM requests')],
                           'effects': [list(row) for row in connection.execute('SELECT * FROM effect_probe')],
                           'costs': [list(row) for row in connection.execute('SELECT * FROM costs')]}
            finally:
                connection.close()
            o.event('durable-after-close', **durable)
            o.require(durable == {'requests': [] if case['operation'] == 'reserved' else [['running', None]],
                                  'effects': [], 'costs': []},
                      'actual durable database has no rolled-back effect, completed request, or cost')

    o.require(store_api.AgentStore.transaction is public_transaction, 'public transaction binding restored')
    custody_after = list(delivery.custody_snapshot())
    o.event('custody-after', records=custody_after, journal=record_observation(o.record))
    if case['mode'] == 'after':
        o.require(not custody_after, 'fully acknowledged cleanup leaves no custody')
    else:
        o.require(bool(custody_after) and all(row['lost'] and not row['retired'] for row in custody_after),
                  'unknown records remain sticky and unretired; no registry was cleared')
    o.event('exception-final', ACK=error_observation(o.error), received=error_observation(received))
    o.error = o.cleanup_error = o.outer = o.cause = None
    del received
    retained_payload = case['mode'] not in ('after', 'native-return-loss')
    o.require((payload() is not None) == retained_payload,
              'only the actually lost error retains its payload; confirmed or unused errors release without GC')
    o.event('payload-lifetime', alive=payload() is not None)


def run_owner_scope(folder, transaction_manifest, o):
    from hepta import hia_agent_store as api
    from hepta import hia_native_delivery as delivery
    from hepta import hia_store_transaction_native as native
    from tools.qualify_hia_store_transaction import selected_transaction_owner

    image = native.installed_store_transaction(str(transaction_manifest))
    store = api.AgentStore(folder / 'state')
    store.db.execute('CREATE TABLE owner_probe (value INTEGER)')
    public, module_reference, class_reference = (
        api.AgentStore.transaction, api._STORE_TRANSACTION_REFERENCE, api.AgentStore._transaction_reference)
    environment = dict(os.environ)
    marker = RuntimeError('leave explicit selected-owner scope')
    try:
        with patch.object(image, '_entry', o.transaction_entry(image._entry)):
            try:
                with selected_transaction_owner(image, transaction_manifest, poisoned_reference) as selected:
                    with patch.dict(os.environ, {}, clear=True):
                        o.require(api.AgentStore.transaction is selected, 'explicit owner survives original empty environment')
                        o.require(api._STORE_TRANSACTION_REFERENCE is poisoned_reference
                                  and api.AgentStore._transaction_reference is poisoned_reference,
                                  'both original reference poisons remain active')
                        with store.transaction():
                            store.db.execute('INSERT INTO owner_probe VALUES (1)')
                    raise_exact(marker)
            except RuntimeError as error:
                o.require(error is marker, 'selected scope propagates exact caller exception')
            o.require(api.AgentStore.transaction is public
                      and api._STORE_TRANSACTION_REFERENCE is module_reference
                      and api.AgentStore._transaction_reference is class_reference,
                      'public binding and both references restore after exceptional scope exit')
            o.require(os.environ == environment, 'original environment restored after selected scope')
            count = sum(o.transaction_entries.values())
            o.require(count > 0, 'empty-environment selected body really entered native transaction')
            with patch.dict(os.environ, {}, clear=True):
                with store.transaction():
                    store.db.execute('INSERT INTO owner_probe VALUES (2)')
            o.require(sum(o.transaction_entries.values()) == count,
                      'unselected public route outside explicit scope remains unselected')
            rows = [list(row) for row in store.db.execute('SELECT value FROM owner_probe ORDER BY value')]
            o.event('scope-sql-rows', rows=rows)
            o.require(rows == [[1], [2]], 'selected and original unselected transactions actually committed')
        store.close()
    finally:
        o.event('scope-restoration', public=api.AgentStore.transaction is public,
                module_reference=api._STORE_TRANSACTION_REFERENCE is module_reference,
                class_reference=api.AgentStore._transaction_reference is class_reference)
    o.require(not delivery.custody_snapshot(), 'healthy explicit and unselected scopes leave no custody')


def execute_case(case, folder, transaction_manifest, journal_manifest):
    from tools.qualify_hia_store_transaction import admit_separate_inventory
    folder.mkdir(mode=0o700, parents=False, exist_ok=False)
    before, binaries_before = source_pins(), image_pins((transaction_manifest, journal_manifest))
    o = Observation(folder, case)
    status, failure = 'FAIL', None
    begin = time.monotonic()
    try:
        original = admit_separate_inventory()
        o.require(original['test_count'] == 61, 'all original 61 caller methods remain frozen')
        if case['mode'] == 'owner-scope':
            run_owner_scope(folder, transaction_manifest, o)
        else:
            run_ack_case(case, folder, transaction_manifest, journal_manifest, o)
        o.require(source_pins() == before and image_pins((transaction_manifest, journal_manifest)) == binaries_before,
                  'component sources and admitted image inputs stayed byte-identical')
        o.require(all(check['passed'] for check in o.checks),
                  'no intermediate assertion was hidden by a tested exception boundary')
        status = 'PASS'
    except BaseException as error:
        failure = error_observation(error)
        traceback.print_exception(type(error), error, error.__traceback__, file=sys.stderr)
    finally:
        record = {'schema': 'hepta.hia.transaction-ACK-control.v1', 'status': status,
            'case': case, 'failure': failure, 'events': o.events, 'checks': o.checks,
            'raw_lost_ACK_packets': o.packets, 'source_before': before, 'source_after': source_pins(),
            'image_inputs_before': binaries_before,
            'image_inputs_after': image_pins((transaction_manifest, journal_manifest)),
            'actual_journal_entries': dict(o.journal_entries),
            'actual_transaction_entries': dict(o.transaction_entries),
            'elapsed_seconds': time.monotonic() - begin,
            'registry_reset_or_explicit_GC_or_traceback_rewrite': False,
            'original_61_cases_executed_by_this_separate_control': False,
            'cold_build_qualification_claimed': False}
        (folder / 'observation.json').write_bytes(encoded(record) + b'\n')
        print(json.dumps({'case': case['id'], 'status': status}), flush=True)
    return 0 if status == 'PASS' else 1


def group_absent(pid):
    try:
        os.killpg(pid, 0)
    except ProcessLookupError:
        return True
    return False


def owned_process(command, output, stem, seconds, environment):
    timed_out, killed, cleanup_unknown = False, False, False
    started = time.monotonic()
    with (output / (stem + '.stdout')).open('wb') as stdout, (output / (stem + '.stderr')).open('wb') as stderr:
        process = subprocess.Popen(command, cwd=ROOT, env=environment,
                                   stdout=stdout, stderr=stderr, start_new_session=True)
        try:
            process.wait(timeout=seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
        absent = group_absent(process.pid)
        if timed_out or not absent:
            try:
                os.killpg(process.pid, signal.SIGKILL)
                killed = True
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=CLEANUP_SECONDS)
            except subprocess.TimeoutExpired:
                cleanup_unknown = True
            absent = group_absent(process.pid)
            cleanup_unknown = cleanup_unknown or not absent
    return {'command': command, 'pid': process.pid, 'returncode': process.returncode,
        'timed_out': timed_out, 'process_group_killed': killed,
        'owned_process_group_absent': absent, 'cleanup_unconfirmed': cleanup_unknown,
        'natural_termination': process.returncode is not None and not timed_out and not killed,
        'stdout_sha256': sha256((output / (stem + '.stdout')).read_bytes()).hexdigest(),
        'stderr_sha256': sha256((output / (stem + '.stderr')).read_bytes()).hexdigest(),
        'elapsed_seconds': time.monotonic() - started}


def natural_success(row):
    return (row['returncode'] == 0 and row['natural_termination']
            and row['owned_process_group_absent'] and not row['cleanup_unconfirmed'])


def cold_inputs(cold_report):
    raw = cold_report.read_bytes()
    nested_path = Path(json.loads(raw)['nested_report']).resolve(strict=True)
    nested_raw = nested_path.read_bytes()
    compiler = Path(json.loads(nested_raw)['generations'][-1]['produced_image']).resolve(strict=True)
    return compiler, {str(cold_report): sha256(raw).hexdigest(),
        str(nested_path): sha256(nested_raw).hexdigest(),
        str(compiler): sha256(compiler.read_bytes()).hexdigest()}


def execute_cold_build(cold_report, folder):
    folder.mkdir(mode=0o700, parents=False, exist_ok=False)
    before = source_pins()
    inputs = sources = compiler = transaction_manifest = journal_manifest = None
    status, failure = 'FAIL', None
    begin = time.monotonic()
    try:
        from tools.build_hia_json_preflight import admit_cold_build, current_sources, build as build_journal
        from tools.build_hia_store_transaction import build as build_transaction
        compiler, inputs = cold_inputs(cold_report)
        sources = admit_cold_build(compiler.read_bytes(), cold_report.read_bytes())
        if any(sources.get(name) != digest for name, digest in before.items()):
            raise ValueError('ACK control sources are not all pinned by this exact current cold report')
        transaction_manifest = build_transaction(folder / 'transaction', compiler, cold_report)
        journal_manifest = build_journal(folder / 'agent-journal', compiler, cold_report, candidate='agent-journal')
        if (source_pins() != before or cold_inputs(cold_report) != (compiler, inputs)
                or current_sources() != sources):
            raise ValueError('ACK control cold/compiler/source inputs changed during build')
        status = 'PASS'
    except BaseException as error:
        failure = error_observation(error)
        traceback.print_exception(type(error), error, error.__traceback__, file=sys.stderr)
    finally:
        record = {'schema': 'hepta.hia.transaction-ACK-cold-build.v1', 'status': status,
            'scope': 'MATCHING_CURRENT_SOURCE_COLD_COMPONENT', 'failure': failure,
            'compiler': None if compiler is None else str(compiler),
            'cold_compiler_inputs_before': inputs,
            'cold_compiler_inputs_after': None if inputs is None else cold_inputs(cold_report)[1],
            'full_current_source_manifest': sources,
            'source_before': before, 'source_after': source_pins(),
            'transaction_manifest': None if transaction_manifest is None else str(transaction_manifest),
            'journal_manifest': None if journal_manifest is None else str(journal_manifest),
            'elapsed_seconds': time.monotonic() - begin,
            'builders': ['tools.build_hia_store_transaction.build',
                         'tools.build_hia_json_preflight.build(candidate=agent-journal)'],
            'fallback_or_source_contract_override': False}
        (folder / 'cold-build.json').write_bytes(encoded(record) + b'\n')
        print(json.dumps({'status': status, 'scope': record['scope']}), flush=True)
    return 0 if status == 'PASS' else 1


def run_controls(output, transaction_manifest=None, journal_manifest=None, *, cold_report=None):
    if len(CASES) != EXPECTED_COUNT or len({row['id'] for row in CASES}) != EXPECTED_COUNT:
        raise AssertionError('focused ACK control inventory differs')
    begin = time.monotonic()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    before = source_pins()
    environment = {key: value for key, value in os.environ.items()
                   if key not in ('PYTHONPATH', 'PYTHONHOME') and not key.startswith('HEPTA_HIA_')}
    environment['PYTHONDONTWRITEBYTECODE'] = '1'
    rows, build_record, build_supervision, build_pins, full_sources = [], None, None, {}, None
    compiler_inputs, binaries_before = None, {}
    scope = ('MATCHING_CURRENT_SOURCE_COLD_ACK_CONTROLS' if cold_report is not None
             else 'EXPLICIT_ADMITTED_IMAGES_COMPONENT_ONLY_NOT_COLD_QUALIFIED')
    setup_failure = None
    try:
        if cold_report is not None:
            _compiler, compiler_inputs = cold_inputs(cold_report)
            command = [sys.executable, '-B', '-m', 'tests.hia_store_transaction_ack_controls',
                '--cold-report', str(cold_report), '--output', str(output / 'build'), '--build-cold']
            remaining = TOTAL_SECONDS - (time.monotonic() - begin)
            if remaining <= 0:
                raise TimeoutError('ACK control total bound expired before cold build')
            build_supervision = owned_process(command, output, 'cold-build', remaining, environment)
            path = output / 'build' / 'cold-build.json'
            build_record = json.loads(path.read_bytes()) if path.is_file() else None
            if (not natural_success(build_supervision) or build_record is None
                    or build_record['status'] != 'PASS'
                    or build_record['source_before'] != before or build_record['source_after'] != before
                    or build_record['cold_compiler_inputs_before'] != compiler_inputs
                    or build_record['cold_compiler_inputs_after'] != compiler_inputs):
                raise AssertionError('matching-current-source ACK image build did not terminate successfully')
            transaction_manifest = Path(build_record['transaction_manifest']).resolve(strict=True)
            journal_manifest = Path(build_record['journal_manifest']).resolve(strict=True)
            full_sources = build_record['full_current_source_manifest']
            build_pins = {str(path): sha256(path.read_bytes()).hexdigest()
                          for path in sorted((output / 'build').rglob('*')) if path.is_file()}
        binaries_before = image_pins((transaction_manifest, journal_manifest))
    except BaseException as error:
        setup_failure = error_observation(error)
        traceback.print_exception(type(error), error, error.__traceback__, file=sys.stderr)
    for number, case in enumerate(CASES, 1):
        if setup_failure is not None:
            break
        remaining = TOTAL_SECONDS - (time.monotonic() - begin)
        if remaining <= 0:
            break
        stem = '%02d-%s' % (number, case['id'])
        folder = output / stem
        command = [sys.executable, '-B', '-m', 'tests.hia_store_transaction_ack_controls',
                   '--transaction-manifest', str(transaction_manifest),
                   '--journal-manifest', str(journal_manifest),
                   '--output', str(folder), '--case', case['id']]
        supervision = owned_process(command, output, stem, min(CASE_SECONDS, remaining), environment)
        path = folder / 'observation.json'
        raw = path.read_bytes() if path.is_file() else None
        observation = json.loads(raw) if raw is not None else None
        passed = (natural_success(supervision) and observation is not None and observation['status'] == 'PASS'
                  and observation['case'] == case and all(check['passed'] for check in observation['checks'])
                  and observation['source_before'] == before and observation['source_after'] == before
                  and observation['image_inputs_before'] == binaries_before
                  and observation['image_inputs_after'] == binaries_before)
        row = {'id': case['id'], 'status': 'PASS' if passed else 'FAIL', **supervision,
            'observation_sha256': None if raw is None else sha256(raw).hexdigest(),
            'actual_journal_entries': {} if observation is None else observation['actual_journal_entries'],
            'actual_transaction_entries': {} if observation is None else observation['actual_transaction_entries']}
        rows.append(row)
        (output / 'progress.json').write_bytes(encoded(rows) + b'\n')
        if not passed:
            break
    after = source_pins()
    binaries_after = {} if not binaries_before else image_pins((transaction_manifest, journal_manifest))
    compiler_after = None if compiler_inputs is None else cold_inputs(cold_report)[1]
    full_sources_after = (None if full_sources is None else
                          {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in full_sources})
    builds_unchanged = all(Path(name).is_file() and sha256(Path(name).read_bytes()).hexdigest() == digest
                           for name, digest in build_pins.items())
    journal_entries, transaction_entries = Counter(), Counter()
    for row in rows:
        journal_entries.update(row['actual_journal_entries'])
        transaction_entries.update(row['actual_transaction_entries'])
    passed = (setup_failure is None and len(rows) == EXPECTED_COUNT
              and all(row['status'] == 'PASS' for row in rows)
              and all(journal_entries[str(stage)] > 0 for stage in (2, 7))
              and all(transaction_entries[str(event)] > 0 for event in (0, 1, 2, 4, 5))
              and before == after and binaries_before == binaries_after
              and compiler_inputs == compiler_after and full_sources == full_sources_after and builds_unchanged
              and time.monotonic() - begin < TOTAL_SECONDS)
    report = {'schema': 'hepta.hia.transaction-ACK-controls.v1',
        'status': 'PASS' if passed else 'FAIL', 'scope': scope, 'control_count': len(rows),
        'expected_control_count': EXPECTED_COUNT, 'controls': rows,
        'setup_failure': setup_failure, 'build_supervision': build_supervision,
        'cold_build': build_record, 'build_file_pins': build_pins, 'builds_unchanged': builds_unchanged,
        'cold_compiler_inputs_before': compiler_inputs, 'cold_compiler_inputs_after': compiler_after,
        'full_current_source_before': full_sources, 'full_current_source_after': full_sources_after,
        'actual_journal_entries': dict(journal_entries),
        'actual_transaction_entries': dict(transaction_entries),
        'unstarted': [row['id'] for row in CASES[len(rows):]],
        'source_before': before, 'source_after': after,
        'image_inputs_before': binaries_before, 'image_inputs_after': binaries_after,
        'case_seconds': CASE_SECONDS, 'aggregate_seconds': TOTAL_SECONDS,
        'cleanup_seconds': CLEANUP_SECONDS, 'elapsed_seconds': time.monotonic() - begin,
        'aggregate_bound_includes_cold_build': True,
        'existing_test_bodies_cases_deadlines_or_provenance_changed': False,
        'registry_reset_or_explicit_GC_or_traceback_rewrite': False,
        'original_61_gate_is_separate_and_still_required': True}
    (output / 'report.json').write_bytes(encoded(report) + b'\n')
    print(json.dumps({key: report[key] for key in ('status', 'control_count', 'expected_control_count')}))
    return 0 if passed else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument('--cold-report', type=Path)
    choice.add_argument('--transaction-manifest', type=Path)
    parser.add_argument('--journal-manifest', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--case', choices=[row['id'] for row in CASES], help=argparse.SUPPRESS)
    parser.add_argument('--build-cold', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    output = args.output.resolve()
    if args.cold_report is not None:
        if args.journal_manifest is not None or args.case is not None:
            parser.error('cold mode cannot be combined with explicit image or single-case inputs')
        cold_report = args.cold_report.resolve(strict=True)
        if args.build_cold:
            return execute_cold_build(cold_report, output)
        return run_controls(output, cold_report=cold_report)
    if args.journal_manifest is None or args.build_cold:
        parser.error('explicit component mode requires both manifests and cannot build cold images')
    transaction_manifest = args.transaction_manifest.resolve(strict=True)
    journal_manifest = args.journal_manifest.resolve(strict=True)
    if args.case is not None:
        case = next(row for row in CASES if row['id'] == args.case)
        return execute_case(case, output, transaction_manifest, journal_manifest)
    return run_controls(output, transaction_manifest, journal_manifest)


if __name__ == '__main__':
    raise SystemExit(main())
