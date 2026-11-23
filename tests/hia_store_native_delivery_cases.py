"""Disposable real-image D4 controls, independent of the Store policy graph.

Each injected native loss runs the admitted entry first. Genuine foreign
errors, safe pre-entry refusal and confirmed terminal calls stay distinct.
The original Store oracle, literal cases, budgets and caller gates are intact.
"""
from __future__ import annotations

from contextlib import ExitStack, closing
from contextvars import copy_context
import base64
import csv
import ctypes
import gc
from hashlib import sha256
import io
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
from unittest.mock import patch
import weakref
import zipfile

from hepta import hia_native_delivery as delivery
from hepta import hia_agent_service as api
from hepta import hia_agent_store as store_api
from hepta import hia_store_artifact_profile_native as store_native
from hepta import hia_service_context_native as context
from hepta import hia_agent_journal_native as journal
from tests import hia_native_delivery_cases as peers
from tests.test_hia_store_artifact_profile_native import (
    bound_fixture, normalized_arguments, original_cases, poison, providers,
)

ROOT = Path(__file__).resolve().parents[1]
FRAME_PEERS = ('service_context', 'store_lifecycle', 'cost_ledger', 'evaluation',
               'native_build_admission', 'emission')
_PROCESS_RESOURCES = []


def encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False,
                      separators=(',', ':')).encode()


def raised(operation):
    try:
        operation()
    except BaseException as error:
        return error
    raise AssertionError('operation returned despite required refusal')


def images(manifests):
    result = peers.images(manifests)
    result['store_artifact_profile'] = store_native.installed_store_artifact_profile(
        manifests['store_artifact_profile'])
    return result


def store_frame(image):
    row = {'id': 'a-D4', 'sha256': 'b' * 64, 'uri': 'hia://artifacts/D4'}
    return store_native.StoreArtifactProfileFrame(image, 3, None, (row,))


def frame(kind, image):
    return store_frame(image) if kind == 'store_artifact_profile' else peers.frame(kind, image)


def port_of(owner):
    return owner.receipt[0] if isinstance(owner.receipt, tuple) else owner.receipt.port


def phase_of(owner):
    return owner.receipt[2] if isinstance(owner.receipt, tuple) else owner.receipt.phase


def record_entry(image, calls):
    actual = image._entry
    def observed(source, size, output, capacity, state, extent):
        header = list(struct.unpack_from('<4Q', ctypes.string_at(source, size)))
        result = actual(source, size, output, capacity, state, extent)
        calls.append([*header, result])
        return result
    return patch.object(image, '_entry', observed)


def child_loss(kind, image, fault):
    child = frame(kind, image)
    first = port_of(child)
    calls, effects = [], []
    actual = image._entry
    def effect(port):
        assert port == first
        effects.append(port)
        return 0
    def lost(source, size, output, capacity, state, extent):
        header = list(struct.unpack_from('<4Q', ctypes.string_at(source, size)))
        result = actual(source, size, output, capacity, state, extent)
        calls.append([*header, result])
        if (header[1], header[3]) == (2, first):
            raise fault
        return result
    with patch.object(child, 'effect', effect), patch.object(image, '_entry', lost):
        error = raised(child.finish)
    assert error is fault or error.__cause__ is fault, (type(error), type(fault))
    assert child._delivery.loss is child._delivery
    assert child._delivery.loss.error is fault and not child._delivery.retired
    assert effects == [first] and any(row[1] == 2 for row in calls)
    assert not any(row[1] == 3 for row in calls)
    assert child.fenced and child.unconfirmed
    return child, error, calls


def _frames(root, manifests):
    selected, rows = images(manifests), []
    for peer in FRAME_PEERS:
        for parent_kind, child_kind in (('store_artifact_profile', peer), (peer, 'store_artifact_profile')):
            for behavior in ('swallow', 'replace'):
                for error_type in (ValueError, RuntimeError, KeyboardInterrupt):
                    outer = frame(parent_kind, selected[parent_kind])
                    reference = weakref.ref(outer)
                    first, calls, children = port_of(outer), [], []
                    fault = error_type('actual D4 child ACK return lost')
                    def provider(port):
                        assert port == first
                        child, error, entries = child_loss(child_kind, selected[child_kind], fault)
                        children.append((child, entries))
                        if behavior == 'replace':
                            raise ValueError('explicit foreign replacement of actual child loss')
                        return 0
                    with ExitStack() as stack:
                        poison(stack)
                        stack.enter_context(patch.object(outer, 'effect', provider))
                        stack.enter_context(record_entry(selected[parent_kind], calls))
                        error = raised(outer.finish)
                    assert isinstance(error, RuntimeError) and not isinstance(error, ValueError)
                    child, child_calls = children[0]
                    assert len(children) == 1 and outer._delivery.loss is child._delivery.loss
                    assert outer._delivery.loss.error is fault
                    assert outer.fenced and outer.unconfirmed and not outer._delivery.retired
                    assert not any(row[1] in (2, 3) for row in calls), calls
                    before = len(calls)
                    with record_entry(selected[parent_kind], calls):
                        replay = raised(outer.finish)
                    assert isinstance(replay, RuntimeError) and len(calls) == before
                    del outer, provider, error, replay
                    gc.collect()
                    assert reference() is not None
                    rows.append({'parent': parent_kind, 'child': child_kind, 'behavior': behavior,
                        'fault_class': error_type.__name__, 'parent_calls': calls, 'child_calls': child_calls,
                        'same_actual_loss_origin': True, 'no_parent_ACK_or_event3': True,
                        'no_replay_entry': True, 'unknown_owner_retained': True})
    assert len(rows) == 72
    return {'cases': rows, 'actual_both_directions': True, 'all_seven_frame_families': True}


def _cleanup(root, manifests):
    selected, rows = images(manifests), []
    originals = original_cases()
    for behavior in ('swallow', 'replace'):
        fixture = bound_fixture(originals['json.native'])
        calls, child_calls = [], []
        fault = ValueError('actual context return lost inside literal Store.put override')
        def overridden(*arguments, **keywords):
            error = raised(lambda: peers.math_loss(selected['service_context'], 'service_context', fault, child_calls))
            assert error.__cause__ is fault
            if behavior == 'replace':
                raise OSError('literal callable replaced child loss')
            return fixture.result_marker
        fixture.subject.put = overridden
        with providers(fixture, selected['store_artifact_profile']), ExitStack() as stack:
            poison(stack)
            args, kwargs = fixture.arguments()
            owner = store_native.StoreArtifactProfileFrame(selected['store_artifact_profile'], 2,
                fixture.subject, normalized_arguments('json', args, kwargs), namespace=fixture.namespace)
            with record_entry(selected['store_artifact_profile'], calls):
                error = raised(owner.finish)
        assert type(error) is store_native.StoreArtifactProfileUnknown
        assert owner._delivery.loss.error is fault and owner.unconfirmed
        assert len(child_calls) == 1
        target = store_native.PORT['json_call_put']
        assert not any(row[1] in (2, 3) and row[3] == target for row in calls)
        assert any(row[0] == store_native.REQUEST_MAGIC and row[1] == 0 for row in calls)
        rows.append({'boundary': 'literal-public-put', 'behavior': behavior,
                     'parent_and_argument_entries': calls, 'child_calls': child_calls,
                     'trace': fixture.events, 'ACK_after_loss': False})

    for behavior in ('suppress', 'replace'):
        fixture = bound_fixture(originals['put.fallback'])
        body = ValueError('original stream write failed')
        fault = OSError('actual context return lost during active Store __exit__')
        calls, child_calls, seen = [], [], []
        def write(data):
            raise body
        fixture.stream.write = write
        class Manager:
            def __enter__(self):
                fixture.state['stream_entered'] = True
                return fixture.stream
            def __exit__(self, kind, error, traceback):
                seen.append([sys.exception() is body, error is body, traceback is body.__traceback__])
                lost = raised(lambda: peers.math_loss(selected['service_context'], 'service_context', fault, child_calls))
                assert lost.__cause__ is fault and sys.exception() is body
                if behavior == 'replace':
                    raise ValueError('Store cleanup replaced true child loss')
                return True
        fixture.namespace['os'].fdopen = lambda descriptor, mode: Manager()
        with providers(fixture, selected['store_artifact_profile']), ExitStack() as stack:
            poison(stack)
            args, kwargs = fixture.arguments()
            owner = store_native.StoreArtifactProfileFrame(selected['store_artifact_profile'], 1,
                fixture.subject, normalized_arguments('put', args, kwargs), namespace=fixture.namespace)
            with record_entry(selected['store_artifact_profile'], calls):
                error = raised(owner.finish)
        assert type(error) is store_native.StoreArtifactProfileUnknown
        assert seen == [[True, True, True]] and len(child_calls) == 1
        assert owner._delivery.loss.error is fault and owner.unconfirmed
        assert fixture.state['temporary_exists']
        target = store_native.PORT['put_exit_exception']
        assert not any(row[1] in (2, 3) and row[3] == target for row in calls)
        rows.append({'boundary': 'active-except-exit', 'behavior': behavior,
                     'active_exception_identity': seen, 'calls': calls, 'child_calls': child_calls,
                     'temporary_retained': True, 'trace': fixture.events, 'no_cleanup_retry': True})
    return {'cases': rows, 'native_artifact_provider_D5_exercised': False}


def _initialization(root, manifests):
    selected, rows = images(manifests), []
    image = selected['store_artifact_profile']
    before = len(delivery.custody_snapshot())
    safe = delivery.DeliveryRecord(object())
    with safe.foreign(observation=False):
        calls = []
        with patch.object(image, '_entry', lambda *args: calls.append(args)):
            error = raised(lambda: store_native.StoreArtifactProfileFrame(image, 0, None, ()))
        assert type(error) is ValueError and not calls and safe.loss is None
        owner = object.__new__(store_native.StoreArtifactProfileFrame)
        fault = MemoryError('packet allocation before actual Store init handoff')
        with patch.object(store_native.struct, 'pack', side_effect=fault), \
                patch.object(image, '_entry', lambda *args: calls.append(args)):
            error = raised(lambda: owner.__init__(image, 3, None, ({},)))
        assert type(error) is store_native.StoreArtifactProfileUnknown and error.__cause__ is fault
        assert not calls and owner._delivery.loss is None and owner._delivery.retired
        assert id(owner) not in store_native._FRAME_CUSTODY and safe.loss is None
        rows.append({'boundary': 'safe-packet-allocation', 'actual_entries': 0,
                     'owner_reservation_retired': True, 'ancestor_loss': False})
    safe.retire()
    assert safe.retired and len(delivery.custody_snapshot()) == before
    parent = delivery.DeliveryRecord(object())
    calls, actual = [], image._entry
    fault = OSError('actual Store init receipt lost')
    owner = object.__new__(store_native.StoreArtifactProfileFrame)
    def lost(source, size, output, capacity, state, extent):
        header = list(struct.unpack_from('<4Q', ctypes.string_at(source, size)))
        result = actual(source, size, output, capacity, state, extent)
        calls.append([*header, result])
        raise fault
    with parent.foreign(observation=False), patch.object(image, '_entry', lost):
        error = raised(lambda: owner.__init__(image, 3, None, ({},)))
    assert type(error) is store_native.StoreArtifactProfileUnknown and error.__cause__ is fault
    assert len(calls) == 1 and calls[0][1] == 0
    assert owner.receipt is None and not owner.effect_started
    assert owner._delivery.loss is owner._delivery and parent.loss is owner._delivery
    assert owner._delivery.loss.error is fault and owner.unconfirmed
    assert store_native._FRAME_CUSTODY[id(owner)] is owner
    replay_calls = []
    with record_entry(image, replay_calls):
        replay = raised(lambda: owner.call(0))
    assert type(replay) is store_native.StoreArtifactProfileUnknown and not replay_calls
    rows.append({'boundary': 'actual-init-receipt-loss', 'actual_entries': calls,
                 'effect_started': False, 'init_unknown_owner_retained': True,
                 'same_actual_ancestor_origin': True, 'replay_entries': replay_calls})
    return {'cases': rows, 'exception_class_used_to_infer_loss': False}


def _safe(root, manifests):
    selected, rows = images(manifests), []
    image = selected['store_artifact_profile']
    before = len(delivery.custody_snapshot())
    for error_type in (ValueError, MemoryError, RuntimeError, KeyboardInterrupt,
                       SystemExit, store_native.StoreArtifactProfileUnknown):
        outer = store_frame(image)
        foreign = error_type('genuine foreign exception after a confirmed child')
        children, calls = [], []
        def provider(port):
            assert port == store_native.PORT['ref_arguments']
            child = store_frame(image)
            result = child.finish()
            assert result == {'id': 'a-D4', 'sha256': 'b' * 64, 'uri': 'hia://artifacts/D4'}
            assert child._delivery.terminal and child._delivery.retired and child._delivery.loss is None
            children.append(child)
            assert selected['service_context'].arithmetic(1, 11, 7) == 18
            raise foreign
        with patch.object(outer, 'effect', provider), record_entry(image, calls), ExitStack() as stack:
            poison(stack)
            error = raised(outer.finish)
        assert error is foreign
        assert outer.finished and phase_of(outer) == 5
        assert outer._delivery.terminal and outer._delivery.retired and outer._delivery.loss is None
        assert id(outer) not in store_native._FRAME_CUSTODY and len(children) == 1
        assert any(row[1] == 3 for row in calls)
        rows.append({'fault_class': error_type.__name__, 'same_exception_object': True,
            'confirmed_child_phase': 4, 'parent_confirmed_phase': 5,
            'parent_and_child_entries': calls, 'loss': False})
    assert len(delivery.custody_snapshot()) == before
    # Preserve the original exception-storage MemoryError identity. This is
    # outside call()'s distinct actual-native-entry normalization boundary.
    owner = store_frame(image)
    memory = MemoryError('lost foreign Store observation storage')
    foreign = ValueError('original foreign refusal whose observation cannot be stored')
    class UnavailableStorage(dict):
        def __setitem__(self, key, value):
            if key == 'exception':
                raise memory
            return super().__setitem__(key, value)
    owner.data = UnavailableStorage(owner.data)
    def provider(port):
        raise foreign
    calls = []
    with patch.object(owner, 'effect', provider), record_entry(image, calls):
        error = raised(owner.finish)
    assert error is memory and type(error) is MemoryError
    assert owner._delivery.loss is owner._delivery and owner._delivery.loss.error is memory
    assert owner.fenced and owner.unconfirmed and not owner.finished
    assert store_native._FRAME_CUSTODY[id(owner)] is owner
    assert not any(row[1] in (2, 3) for row in calls)
    return {'confirmed_foreign_cases': rows, 'foreign_observation_storage': {
        'same_MemoryError_object': True, 'original_foreign_class': type(foreign).__name__,
        'calls': calls, 'retained_unknown_observation': True, 'no_event3': True}}


def _fork_ancestry(image, inherited):
    assert hasattr(os, 'fork')
    parent = delivery.DeliveryRecord(object())
    ready, release = threading.Event(), threading.Event()
    def hold_locks():
        with delivery._CUSTODY_LOCK, store_native._CUSTODY_LOCK:
            ready.set()
            release.wait(10)
    with parent.foreign(observation=False):
        locker = threading.Thread(target=hold_locks)
        locker.start()
        assert ready.wait(5)
        read_fd, write_fd = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(read_fd)
            try:
                error = raised(inherited.finish)
                assert type(error) is store_native.StoreArtifactProfileUnknown
                fresh = store_frame(image)
                assert fresh._delivery.parent is None
                result = fresh.finish()
                assert result['id'] == 'a-D4'
                assert store_native._FRAME_CUSTODY[id(inherited)] is inherited
                raw = encoded({'status': 'PASS', 'fresh_parent': None,
                               'inherited_creator_unchanged': inherited.creator != os.getpid(),
                               'inherited_owner_retained': True})
                os.write(write_fd, raw)
                os._exit(0)
            except BaseException as error:
                os.write(write_fd, encoded({'status': 'FAIL', 'class': type(error).__name__, 'message': str(error)}))
                os._exit(1)
        os.close(write_fd)
        release.set()
        locker.join(5)
        assert not locker.is_alive()
        readable, _, _ = select.select([read_fd], [], [], 10)
        if not readable:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
            raise AssertionError('forked Store control did not finish without inherited locks')
        raw = os.read(read_fd, 16384)
        os.close(read_fd)
        ended, status = os.waitpid(pid, 0)
        assert ended == pid and os.waitstatus_to_exitcode(status) == 0, raw
    assert parent.loss is None
    parent.retire()
    result = json.loads(raw)
    assert result['status'] == 'PASS'
    return {'boundary': 'fork-with-parent-representation-locks-held', **result}


def _ancestry(root, manifests):
    selected, rows = images(manifests), []
    image = selected['store_artifact_profile']
    stale = delivery.DeliveryRecord(object())
    with stale.foreign(observation=False):
        prepared = store_frame(image)
    stale.retire()
    assert stale.retired and prepared._delivery.loss is None
    current = delivery.DeliveryRecord(object())
    child_calls, fault = [], ValueError('real loss under later actual parent')
    def provider(port):
        raised(lambda: peers.math_loss(selected['service_context'], 'service_context', fault, child_calls))
        return 0
    with current.foreign(observation=False), patch.object(prepared, 'effect', provider):
        error = raised(prepared.finish)
    assert type(error) is store_native.StoreArtifactProfileUnknown
    assert prepared._delivery.loss is current.loss and current.loss.error is fault
    assert stale.loss is None and len(child_calls) == 1
    rows.append({'boundary': 'prepared-before-actual-invocation', 'actual_parent_lost': True,
                 'old_parent_lost': False, 'actual_child_calls': child_calls})

    # Suppressed-exception release happens between ports in the original
    # driver. The ambient activation carries actual ancestry without an ACK.
    fixture = bound_fixture(original_cases()['put.fallback'])
    released, child_calls = [], []
    fault = ValueError('actual peer loss during implicit exception release')
    holder = {}
    class ReleasedError(ValueError):
        def __del__(self):
            record = delivery.current_record()
            active = delivery._ACTIVE.get()
            row = {'actual_owner': record is holder['owner']._delivery,
                   'ambient_observation': active.observation if active is not None else None,
                   'transport_error_type_preserved': False, 'original_native_cause_preserved': False,
                   'callback_failure': None}
            released.append(row)
            try:
                error = raised(lambda: peers.math_loss(selected['service_context'], 'service_context', fault, child_calls))
            except BaseException as unexpected:
                row['callback_failure'] = [type(unexpected).__name__, str(unexpected)]
            else:
                row['transport_error_type_preserved'] = type(error) is context.ServiceContextUnknown
                row['original_native_cause_preserved'] = error.__cause__ is fault
    def write(data):
        raise ReleasedError('ordinary suppressed write error')
    fixture.stream.write = write
    class Manager:
        def __enter__(self):
            return fixture.stream
        def __exit__(self, kind, error, traceback):
            assert type(error) is ReleasedError and sys.exception() is error
            return True
    fixture.namespace['os'].fdopen = lambda descriptor, mode: Manager()
    calls = []
    with providers(fixture, image):
        args, kwargs = fixture.arguments()
        owner = store_native.StoreArtifactProfileFrame(image, 1, fixture.subject, args,
                                                       namespace=fixture.namespace)
        holder['owner'] = owner
        with record_entry(image, calls):
            error = raised(owner.finish)
    assert type(error) is store_native.StoreArtifactProfileUnknown
    assert released == [{'actual_owner': True, 'ambient_observation': False,
                         'transport_error_type_preserved': True, 'original_native_cause_preserved': True,
                         'callback_failure': None}], released
    assert len(child_calls) == 1 and owner._delivery.loss.error is fault
    assert fixture.state['temporary_exists']
    assert not any(row[1] == 1 and row[3] == store_native.PORT['put_link'] for row in calls)
    rows.append({'boundary': 'implicit-release-between-ports', 'observed': released,
                 'calls': calls, 'child_calls': child_calls, 'temporary_retained': True})

    # The owner guard precedes the generic shared guard for a copied thread.
    inherited = store_frame(image)
    thread_calls, observed = [], []
    def transferred():
        before = len(thread_calls)
        error = raised(inherited.finish)
        assert type(error) is store_native.StoreArtifactProfileUnknown and len(thread_calls) == before
        observed.append('StoreArtifactProfileUnknown-with-zero-entry')
        fresh = store_frame(image)
        assert fresh._delivery.parent is None
        fresh.finish()
        observed.append('fresh-independent-finished')
    active = delivery.DeliveryRecord(object())
    with active.foreign(observation=False), record_entry(image, thread_calls):
        copied = copy_context()
        thread = threading.Thread(target=lambda: copied.run(transferred))
        thread.start()
        thread.join(5)
        assert not thread.is_alive()
    assert observed == ['StoreArtifactProfileUnknown-with-zero-entry', 'fresh-independent-finished'], observed
    assert active.loss is None and inherited._delivery.loss is None
    active.retire()
    inherited.finish()
    rows.append({'boundary': 'copied-thread-context', 'observed': observed,
                 'foreign_thread_cannot_poison_creator': True,
                 'fresh_thread_actual_entries': thread_calls})
    rows.append(_fork_ancestry(image, prepared))
    return {'cases': rows, 'no_global_custody_clear': True}


def store_snapshot(state_root, key):
    with closing(sqlite3.connect(Path(state_root) / 'state.sqlite3')) as database:
        database.row_factory = sqlite3.Row
        row = database.execute('SELECT * FROM requests WHERE key=?', (key,)).fetchone()
        return {'request': None if row is None else dict(row),
                'artifacts': [dict(item) for item in database.execute('SELECT * FROM artifacts ORDER BY id')],
                'profiles': [dict(item) for item in database.execute('SELECT * FROM profiles ORDER BY id,sha256')],
                'costs': [dict(item) for item in database.execute('SELECT * FROM costs ORDER BY sequence')]}


def _requests(root, manifests):
    from tests.test_hia_agent_native_tools import AgentToolCase
    from tests.test_hia_store_native_delivery import clean_environment
    selected, rows = images(manifests), []
    for lane in ('ordinary', 'native'):
        for behavior in ('swallow', 'replace', 'memory'):
            environment = dict(clean_environment(), **{
                store_native.SELECTOR: manifests['store_artifact_profile'],
                context.SELECTOR: manifests['service_context']})
            if lane == 'native':
                environment[journal.SELECTOR] = manifests['agent_journal']
            with ExitStack() as stack:
                stack.enter_context(patch.dict(os.environ, environment, clear=True))
                if lane == 'native':
                    stack.enter_context(patch.object(api.HIAAgentService, '_reference_call',
                        side_effect=AssertionError('native journal entered retained request body')))
                case = AgentToolCase('runTest')
                case.setUp()
                # These unknown resources are deliberately held to actual
                # child exit; no test teardown or global clearing releases them.
                _PROCESS_RESOURCES.append(case)
                arguments = case.session.arguments(context=False,
                    artifact_profile=case.session.profiles['artifact'],
                    source={'kind': 'utf8', 'text': 'D4 durable publication ' + lane + '-' + behavior})
                key = store_api.digest({'tool': 'hia_artifact', 'key': arguments['request_key']})
                before = store_snapshot(case.state_root, key)
                assert before['request'] is None
                calls, child_calls, inserts = [], [], []
                fault = ValueError('actual peer receipt lost after Store artifact INSERT')
                replacement = MemoryError('foreign replacement MemoryError after actual child loss')
                original = store_native.StoreArtifactProfileFrame.effect
                def provider(owner, port):
                    result = original(owner, port)
                    if port == store_native.PORT['put_insert']:
                        inserts.append(port)
                        error = raised(lambda: peers.math_loss(selected['service_context'],
                            'service_context', fault, child_calls))
                        assert type(error) is context.ServiceContextUnknown and error.__cause__ is fault
                        if behavior == 'replace':
                            raise ValueError('foreign provider replaced actual peer loss')
                        if behavior == 'memory':
                            raise replacement
                    return result
                poison(stack)
                with patch.object(store_native.StoreArtifactProfileFrame, 'effect', provider), \
                        record_entry(selected['store_artifact_profile'], calls):
                    error = raised(lambda: case.service.call('hia_artifact', arguments))
                if behavior == 'memory':
                    assert error is replacement and type(error) is MemoryError
                else:
                    assert type(error) is store_native.StoreArtifactProfileUnknown
                assert len(inserts) == len(child_calls) == 1
                assert not any(row[1] == 3 for row in calls)
                retained = store_snapshot(case.state_root, key)
                assert retained['request']['state'] == 'running' and retained['request']['response'] is None
                assert len(retained['artifacts']) == len(before['artifacts']) + 1
                assert retained['profiles'] == before['profiles'] and retained['costs'] == before['costs']
                added, = [row for row in retained['artifacts'] if row not in before['artifacts']]
                payload = (case.state_root / 'artifacts' / added['sha256']).read_bytes()
                assert payload == arguments['source']['text'].encode() and sha256(payload).hexdigest() == added['sha256']
                replay_calls = []
                with record_entry(selected['store_artifact_profile'], replay_calls), \
                        patch.object(selected['service_context'], '_entry',
                            side_effect=AssertionError('unknown replay reentered the lost peer')):
                    replay = case.service.call('hia_artifact', arguments)
                after = store_snapshot(case.state_root, key)
                assert replay['error']['code'] == 'E_HIA_REQUEST_UNKNOWN' and replay_calls == []
                assert after['request'] == retained['request'] and after['artifacts'] == retained['artifacts']
                assert after['profiles'] == retained['profiles']
                assert len(after['costs']) == len(retained['costs']) + 1
                rows.append({'lane': lane, 'behavior': behavior, 'raised': type(error).__name__,
                    'MemoryError_identity_preserved': behavior == 'memory' and error is replacement,
                    'before': before, 'retained_before_replay': retained, 'after_replay': after,
                    'Store_calls': calls, 'actual_peer_calls': child_calls,
                    'actual_publication_inserts': len(inserts), 'replay': replay,
                    'replay_Store_entries': replay_calls, 'durable_payload_sha256': sha256(payload).hexdigest(),
                    'native_artifact_provider_D5_not_selected': True})
    return {'cases': rows, 'ordinary_and_native_journal_lanes': True,
            'resources_retained_until_disposable_process_exit': True}

INSTALLED_CONTROL = r'''import ctypes,importlib.abc,json,os,struct,sys
from hashlib import sha256
from pathlib import Path
installed=sys.argv.pop(1);mode=sys.argv.pop(1);sys.path.insert(0,installed)
class NoAuthoring(importlib.abc.MetaPathFinder):
    def find_spec(self,name,path=None,target=None):
        if name=='tools' or name.startswith('tools.') or name=='tests' or name.startswith('tests.'):
            raise AssertionError('installed D4 worker imported authoring or tests')
sys.meta_path.insert(0,NoAuthoring())
from hepta import hia_native_delivery as delivery
from hepta import hia_store_artifact_profile_native as native
from hepta import hia_service_context_native as context
from hepta import hia_agent_journal_native as journal
from hepta import hia_agent_store as store
from hepta import hia_agent_service as api
from hepta import hia_agent_worker as worker_api
from hepta.hia_agent_worker import main
for module in (delivery,native,context,journal,worker_api):
    assert Path(module.__file__).resolve().is_relative_to(Path(installed).resolve()/'hepta')
counts={'startup':{'store':0,'context':0,'journal':0},
        'request':{'store':0,'context':0,'journal':0},
        'publication_inserts':0,'lost_returns':0,'swallowed':0,
        'close_attempts':0,'close_returns':0,'unknown_terminal_calls':0,
        'worker_terminal':None}
active=False;armed=False;reported=False
actual_loss_error_id=None;actual_primary_id=None;actual_cleanup_id=None
actual_peer_error_id=None;actual_replacement_error_id=None
def forbidden(*args,**kwargs):raise AssertionError('installed D4 worker entered retained owner')
for name in ('_put_reference','_json_reference','_ref_reference','_get_reference','_get_json_reference',
             '_resolve_uri_reference','_profile_reference','_check_profile_reference'):
    setattr(store.AgentStore,name,forbidden)
for name in tuple(store._STORE_ARTIFACT_PROFILE_REFERENCES):
    store._STORE_ARTIFACT_PROFILE_REFERENCES[name]=forbidden
api.HIAAgentService._reference_call=forbidden
api.HIAAgentService._context_reference=forbidden
api._NATIVE_SERVICE_CONTEXT_LOOKUP_REFERENCE=forbidden
original_call=api.HIAAgentService.call
def request_call(self,*arguments,**keywords):
    global active,actual_primary_id
    assert not active
    active=True
    try:return original_call(self,*arguments,**keywords)
    except BaseException as error:
        actual_primary_id=id(error)
        raise
    finally:active=False
api.HIAAgentService.call=request_call
original_close=api.HIAAgentService.close
def observe_close(self,*arguments,**keywords):
    global actual_cleanup_id
    value=None
    try:
        counts['close_attempts']+=1
        try:
            value=original_close(self,*arguments,**keywords)
        except BaseException as error:
            actual_cleanup_id=id(error)
            raise
        counts['close_returns']+=1
        return value
    finally:
        del self,arguments,keywords,value
api.HIAAgentService.close=observe_close
original_terminal=worker_api._unknown_request_exit
def observe_terminal(observation,terminal_error):
    # Observe the actual worker arguments without altering exceptions or custody.
    counts['unknown_terminal_calls']+=1
    origin=observation.origin
    primary=observation.primary_error
    cleanup=observation.cleanup_error
    facts={'schema':'hepta.hia.store-installed-worker-terminal.v2',
        'request_observer_inactive':not observation.active,
        'origin_present':origin is not None,
        'origin_error_is_injected':origin is not None and id(origin.error)==actual_loss_error_id,
        'origin_loss_is_self':origin is not None and origin.loss is origin,
        'origin_custodied':origin is not None and delivery._CUSTODY.get(id(origin)) is origin,
        'origin_retired':None if origin is None else origin.retired,
        'origin_native_pending':None if origin is None else origin.native_pending,
        'Store_frame_links_origin':origin is not None and any(
            frame.unconfirmed and frame._delivery.loss is origin
            for frame in native._FRAME_CUSTODY.values()),
        'primary_present':primary is not None,
        'primary_is_actual_call_error':primary is not None and id(primary)==actual_primary_id,
        'primary_type':None if primary is None else type(primary).__name__,
        'primary_cause_is_injected':primary is not None and primary.__cause__ is not None and id(primary.__cause__)==actual_loss_error_id,
        'peer_error_seen':actual_peer_error_id is not None,
        'replacement_error_seen':actual_replacement_error_id is not None,
        'primary_cause_is_replacement':primary is not None and type(primary.__cause__) is OSError and id(primary.__cause__)==actual_replacement_error_id,
        'replacement_context_is_peer_error':primary is not None and type(primary.__cause__) is OSError and type(primary.__cause__.__context__) is context.ServiceContextUnknown and id(primary.__cause__.__context__)==actual_peer_error_id,
        'peer_cause_is_injected':primary is not None and type(primary.__cause__) is OSError and type(primary.__cause__.__context__) is context.ServiceContextUnknown and primary.__cause__.__context__.__cause__ is not None and id(primary.__cause__.__context__.__cause__)==actual_loss_error_id,
        'cleanup_present':cleanup is not None,
        'cleanup_is_actual_close_error':cleanup is not None and id(cleanup)==actual_cleanup_id,
        'cleanup_type':None if cleanup is None else type(cleanup).__name__,
        'cleanup_context_is_primary':cleanup is not None and cleanup.__context__ is primary,
        'terminal_is_cleanup':terminal_error is cleanup}
    counts['worker_terminal']=facts
    result=original_terminal(observation,terminal_error)
    facts['returned_status']=result
    return result
worker_api._unknown_request_exit=observe_terminal
def emit_counts():
    global reported
    assert not reported
    reported=True
    custody=delivery.custody_snapshot()
    counts['shared_lost_records']=sum(row['lost'] for row in custody)
    counts['shared_pending_native_records']=sum(row['native_pending'] for row in custody)
    counts['Store_unknown_frames']=sum(frame.unconfirmed for frame in native._FRAME_CUSTODY.values())
    counts['shared_module_sha256']=sha256(Path(delivery.__file__).read_bytes()).hexdigest()
    counts['Store_adapter_sha256']=sha256(Path(native.__file__).read_bytes()).hexdigest()
    counts['worker_module_sha256']=sha256(Path(worker_api.__file__).read_bytes()).hexdigest()
    os.write(2,('D4_COUNTS='+json.dumps(counts,sort_keys=True)+'\n').encode())
for kind,label in ((native.NativeStoreArtifactProfile,'store'),
                   (context.NativeServiceContextImage,'context'),(journal.NativeAgentJournal,'journal')):
    initializer=kind.__init__
    def image_init(self,*arguments,_initializer=initializer,_label=label,**keywords):
        _initializer(self,*arguments,**keywords);entry=self._entry
        def observed(source,size,output,capacity,state,extent):
            global actual_loss_error_id
            result=entry(source,size,output,capacity,state,extent)
            counts['request' if active else 'startup'][_label]+=1
            if _label=='context' and armed and mode!='normal':
                counts['lost_returns']+=1
                if mode=='exit':
                    emit_counts();os._exit(73)
                try:
                    raise ValueError('actual installed peer result lost after Store publication')
                except ValueError as error:
                    actual_loss_error_id=id(error)
                    raise
            return result
        self._entry=observed
    kind.__init__=image_init
original_effect=native.StoreArtifactProfileFrame.effect
def store_effect(self,port):
    global armed,actual_peer_error_id,actual_replacement_error_id
    value=original_effect(self,port)
    if active and port==native.PORT['put_insert']:
        counts['publication_inserts']+=1
        peer=context.installed_service_context(os.environ[context.SELECTOR])
        armed=True
        try:
            try:assert peer.arithmetic(1,11,7)==18
            except context.ServiceContextUnknown as peer_error:
                actual_peer_error_id=id(peer_error)
                assert mode in ('swallow','replace')
                counts['swallowed']+=1
                if mode=='replace':
                    try:
                        raise OSError('installed foreign provider replaced actual peer loss')
                    except OSError as replacement_error:
                        actual_replacement_error_id=id(replacement_error)
                        raise
        finally:armed=False
    return value
native.StoreArtifactProfileFrame.effect=store_effect
assert mode in ('normal','swallow','replace','exit')
try:status=main(sys.argv[1:])
finally:
    if not reported:emit_counts()
raise SystemExit(status)
'''


def _installed_cases(root, manifests, modes, *, source_drift):
    from tests.test_hia_agent_installed_resources import RESOURCES, SDIST_SUPPORT_FILES
    from tests.test_hia_agent_native_tools import AgentToolCase
    from tests.test_hia_store_native_delivery import clean_environment
    from hepta import hia_native_helpers as helpers
    staging = root / 'source'
    staging.mkdir()
    shutil.copytree(ROOT / 'hepta', staging / 'hepta', ignore=shutil.ignore_patterns('__pycache__'))
    for name in (*RESOURCES, *SDIST_SUPPORT_FILES, 'setup.py', 'pyproject.toml', 'MANIFEST.in'):
        destination = staging / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, destination)
    environment = dict(clean_environment(), PYTHONDONTWRITEBYTECODE='1')
    def run(label, arguments, body=None, expected=0):
        result = subprocess.run([sys.executable, '-B', *map(str, arguments)], cwd=root,
            env=environment, input=body, capture_output=True, timeout=60)
        (root / (label + '.stdout')).write_bytes(result.stdout)
        (root / (label + '.stderr')).write_bytes(result.stderr)
        (root / (label + '.result.json')).write_bytes(encoded({
            'argv': [sys.executable, '-B', *map(str, arguments)],
            'cwd': str(root), 'timeout_seconds': 60,
            'returncode': result.returncode, 'expected_returncode': expected,
            'stdin': None if body is None else {'bytes': len(body), 'sha256': sha256(body).hexdigest()},
            'stdout': {'bytes': len(result.stdout), 'sha256': sha256(result.stdout).hexdigest()},
            'stderr': {'bytes': len(result.stderr), 'sha256': sha256(result.stderr).hexdigest()},
        }) + b'\n')
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
    installed_pins = {}
    with zipfile.ZipFile(wheel) as archive:
        record_name, = [name for name in archive.namelist() if name.endswith('.dist-info/RECORD')]
        records = list(csv.reader(io.StringIO(archive.read(record_name).decode())))
        for name in ('hepta/hia_native_delivery.py', 'hepta/hia_store_artifact_profile_native.py',
                     'hepta/hia_store_artifact_profile_protocol.py', 'hepta/hia_agent_worker.py'):
            assert archive.namelist().count(name) == 1
            raw = archive.read(name)
            row, = [row for row in records if row[0] == name]
            digest = base64.urlsafe_b64encode(sha256(raw).digest()).rstrip(b'=').decode()
            assert row[1:] == ['sha256=' + digest, str(len(raw))]
            assert raw == (ROOT / name).read_bytes() == (installed / name).read_bytes()
            installed_pins[name] = {'bytes': len(raw), 'sha256': sha256(raw).hexdigest(), 'wheel_record': row}
    bundle = root / 'bundle.json'
    modules = (store_native, context, journal)
    names = ('store_artifact_profile', 'service_context', 'agent_journal')
    bundle.write_bytes(encoded({'schema': helpers.SCHEMA, 'target': helpers.TARGET, 'abi': helpers.ABI,
        'helpers': [{'selector': module.SELECTOR, 'manifest_path': manifests[name],
                     'manifest_sha256': sha256(Path(manifests[name]).read_bytes()).hexdigest()}
                    for name, module in zip(names, modules, strict=True)]}))
    bundle_sha = sha256(bundle.read_bytes()).hexdigest()
    (root / 'worker-control.py').write_text(INSTALLED_CONTROL)
    def counts(result):
        prefix = b'D4_COUNTS='
        rows = [line[len(prefix):] for line in result.stderr.splitlines() if line.startswith(prefix)]
        assert len(rows) == 1, result.stderr
        value = json.loads(rows[0])
        assert value['shared_module_sha256'] == installed_pins['hepta/hia_native_delivery.py']['sha256']
        assert value['Store_adapter_sha256'] == installed_pins['hepta/hia_store_artifact_profile_native.py']['sha256']
        assert value['worker_module_sha256'] == installed_pins['hepta/hia_agent_worker.py']['sha256']
        return value
    observations = []
    for mode in modes:
        case = AgentToolCase('runTest')
        with patch.dict(os.environ, environment, clear=True), helpers.native_helpers_scope(str(bundle), bundle_sha):
            case.setUp()
        try:
            arguments = case.session.arguments(context=False,
                artifact_profile=case.session.profiles['artifact'],
                source={'kind': 'utf8', 'text': 'installed D4 durable artifact — 雪 ' + mode})
            request = {'schema': 'hia-agent-worker-request-v1', 'tool': 'hia_artifact',
                'arguments': arguments, 'profile_sha256': 'a' * 64,
                'catalog_sha256': case.service.catalog_sha256}
            request['request_sha256'] = store_api.digest(request)
            key = store_api.digest({'tool': 'hia_artifact', 'key': arguments['request_key']})
            case.service.close()
            before = store_snapshot(case.state_root, key)
            flags = ['-I', '-c', INSTALLED_CONTROL, installed, mode, '--state-root', case.state_root,
                     '--artifact-root', case.files_root, '--request-json-stdin',
                     '--native-helpers-manifest', bundle, '--expected-native-helpers-sha256', bundle_sha]
            result = run('worker-' + mode, flags, encoded(request),
                         expected=0 if mode == 'normal' else 73 if mode == 'exit' else 2)
            actual = counts(result)
            retained = store_snapshot(case.state_root, key)
            assert actual['startup']['store'] > 0
            assert all(actual['request'][name] > 0 for name in ('store', 'context', 'journal'))
            assert actual['publication_inserts'] == 1
            assert len(retained['artifacts']) == len(before['artifacts']) + 1
            assert retained['profiles'] == before['profiles']
            added = [row for row in retained['artifacts'] if row not in before['artifacts']]
            assert len(added) == 1
            payload = (case.state_root / 'artifacts' / added[0]['sha256']).read_bytes()
            assert payload == arguments['source']['text'].encode()
            assert sha256(payload).hexdigest() == added[0]['sha256']
            if mode == 'normal':
                report = json.loads(result.stdout)
                assert report['response']['status'] == 'completed'
                assert report['native_helpers_sha256'] == bundle_sha
                assert retained['request']['state'] == 'completed'
                assert len(retained['costs']) == len(before['costs']) + 1
                assert actual['lost_returns'] == actual['shared_lost_records'] == 0
                assert actual['close_attempts'] == actual['close_returns'] == 1
                assert actual['unknown_terminal_calls'] == 0 and actual['worker_terminal'] is None
                assert b'HIA_WORKER_DELIVERY_UNKNOWN' not in result.stderr
            else:
                report = None
                assert result.stdout == b'' and actual['lost_returns'] == 1
                assert retained['request']['state'] == 'running' and retained['request']['response'] is None
                assert retained['costs'] == before['costs']
                if mode == 'exit':
                    assert actual['shared_pending_native_records'] >= 1 and actual['swallowed'] == 0
                    assert actual['close_attempts'] == actual['close_returns'] == 0
                    assert actual['unknown_terminal_calls'] == 0 and actual['worker_terminal'] is None
                else:
                    assert actual['swallowed'] == 1 and actual['shared_lost_records'] >= 3
                    assert actual['Store_unknown_frames'] >= 1
                    assert actual['close_attempts'] == 1 and actual['close_returns'] == 0
                    assert actual['unknown_terminal_calls'] == 1
                    terminal = actual['worker_terminal']
                    assert terminal['schema'] == 'hepta.hia.store-installed-worker-terminal.v2'
                    assert all(terminal[name] is True for name in (
                        'request_observer_inactive', 'origin_present', 'origin_error_is_injected',
                        'origin_loss_is_self', 'origin_custodied', 'origin_native_pending',
                        'Store_frame_links_origin', 'primary_present', 'primary_is_actual_call_error',
                        'cleanup_present', 'cleanup_is_actual_close_error',
                        'cleanup_context_is_primary', 'terminal_is_cleanup'))
                    assert terminal['origin_retired'] is False and terminal['returned_status'] == 2
                    assert terminal['primary_type'] == 'StoreArtifactProfileUnknown'
                    assert terminal['peer_error_seen'] is True
                    if mode == 'swallow':
                        assert terminal['primary_cause_is_injected'] is True
                        assert terminal['replacement_error_seen'] is False
                        assert terminal['primary_cause_is_replacement'] is False
                        assert terminal['replacement_context_is_peer_error'] is False
                        assert terminal['peer_cause_is_injected'] is False
                    else:
                        assert mode == 'replace'
                        assert terminal['primary_cause_is_injected'] is False
                        assert all(terminal[name] is True for name in (
                            'replacement_error_seen', 'primary_cause_is_replacement',
                            'replacement_context_is_peer_error', 'peer_cause_is_injected'))
                    assert terminal['cleanup_type'] == 'NativeDeliveryUnknown'
                    assert result.stderr.startswith(b'HIA_WORKER_DELIVERY_UNKNOWN\n')
                    assert result.stderr.count(b'REQUEST_PRIMARY_EXCEPTION\n') == 1
                    assert result.stderr.count(b'REQUEST_CLEANUP_EXCEPTION\n') == 1
                    assert b'actual installed peer result lost after Store publication' in result.stderr
                    assert b'REQUEST_TERMINAL_EXCEPTION\n' not in result.stderr
                    assert b'diagnostic unavailable' not in result.stderr
            replay_flags = list(flags)
            replay_flags[4] = 'normal'
            replay = run('replay-' + mode, replay_flags, encoded(request))
            replay_counts = counts(replay)
            replay_report = json.loads(replay.stdout)
            after = store_snapshot(case.state_root, key)
            assert replay_counts['startup']['store'] > 0
            assert replay_counts['request']['store'] == replay_counts['request']['context'] == 0
            assert replay_counts['publication_inserts'] == replay_counts['lost_returns'] == 0
            assert replay_counts['unknown_terminal_calls'] == 0 and replay_counts['worker_terminal'] is None
            assert replay_counts['close_attempts'] == replay_counts['close_returns'] == 1
            assert b'HIA_WORKER_DELIVERY_UNKNOWN' not in replay.stderr
            assert after['request'] == retained['request'] and after['artifacts'] == retained['artifacts']
            assert after['profiles'] == retained['profiles']
            if mode == 'normal':
                assert replay_report['response'] == report['response'] and after == retained
            else:
                assert replay_report['response']['error']['code'] == 'E_HIA_REQUEST_UNKNOWN'
                assert len(after['costs']) == len(retained['costs']) + 1
            record = {'mode': mode, 'worker_exit': result.returncode, 'counts': actual,
                'worker_report': report, 'before': before, 'retained_before_replay': retained,
                'replay_exit': replay.returncode, 'replay_counts': replay_counts,
                'replay_report': replay_report, 'after_replay': after,
                'durable_payload_sha256': sha256(payload).hexdigest(),
                'native_artifact_provider_not_selected_or_qualified': True,
                'worker_terminal_contract': 'hepta.hia.store-installed-worker-terminal.v2',
                'independent_worker_finally_close_attempt_observed': mode != 'exit',
                'actual_close_refused_by_retained_resource_loss': mode in ('swallow', 'replace')}
            if source_drift:
                path = installed / 'hepta/_data/examples/hia_bootstrap/store_artifact_profile.hepta'
                original = path.read_bytes()
                assert original == store_native.SOURCE.read_bytes()
                try:
                    path.write_bytes(original + b'\n')
                    drift = run('source-drift', replay_flags, encoded(request), expected=None)
                    drift_counts = counts(drift)
                    assert drift.returncode != 0
                    assert all(value == 0 for row in ('startup', 'request') for value in drift_counts[row].values())
                    assert store_snapshot(case.state_root, key) == after
                    record['source_drift'] = {'worker_exit': drift.returncode, 'counts': drift_counts,
                        'before_sha256': sha256(original).hexdigest(),
                        'after_sha256': sha256(path.read_bytes()).hexdigest(), 'exact_change': 'one appended LF'}
                finally:
                    path.write_bytes(original)
            observations.append(record)
        finally:
            case.tearDown()
    return {'wheel': str(wheel), 'wheel_sha256': sha256(wheel.read_bytes()).hexdigest(),
            'installed_files': installed_pins, 'bundle': str(bundle), 'bundle_sha256': bundle_sha,
            'worker_control_sha256': sha256(INSTALLED_CONTROL.encode()).hexdigest(), 'cases': observations,
            'scope': 'actual installed worker; Store publication effect invokes context arithmetic; native journal',
            'startup_and_request_entries_separated': True,
            'retained_Store_and_journal_bodies_forbidden_in_actual_child': True,
            'authoring_and_test_imports_forbidden_in_actual_child': True,
            'all_D0_D3_owners_exercised_in_installed_child': False,
            'provider_internal_post_effect_delivery_qualified': False,
            'independent_worker_finally_close_resource_link_qualified': False,
            'remaining_D5_integrated': False, 'whole_native_delivery_qualified': False}


def _installed(root, manifests):
    return _installed_cases(root, manifests, ('normal', 'swallow', 'replace'), source_drift=False)


def _installed_process(root, manifests):
    return _installed_cases(root, manifests, ('exit',), source_drift=True)


def run_child(kind, directory, manifests):
    root = Path(directory)
    value = globals()['_' + kind](root, json.loads(manifests))
    record = {'schema': 'hepta.hia.store-native-delivery-child.v1', 'status': 'PASS', 'kind': kind, **value}
    (root / 'observations.json').write_bytes(encoded(record) + b'\n')
    print(json.dumps({'kind': kind, 'status': 'PASS'}), flush=True)
    os._exit(0)
