"""Isolated actual-image inspection/candidate controls; no fabricated loss flags."""
from __future__ import annotations
import argparse
from contextlib import ExitStack, contextmanager
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import signal
import sqlite3
import struct
import sys
import threading
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from hepta import hia_agent_service as api
from hepta import hia_service_inspection_native as native
from hepta import hia_native_delivery as delivery
from tests.hia_service_inspection_oracle import Fixture, canonical

ERRORS = (ValueError, TypeError, OSError, OverflowError, RecursionError,
          sqlite3.OperationalError, RuntimeError, MemoryError, KeyboardInterrupt, SystemExit)


def caught(function):
    try:
        return function(), None
    except BaseException as error:
        return None, error


def fixture_for(mode):
    case = ({'id': 'control-inspect', 'mode': 1, 'view': 'summary'}
            if mode == 1 else {'id': 'control-candidate', 'mode': 2,
                               'kind': 'import', 'format': 'hia-asm.v1'})
    fixture = Fixture(case)
    fixture.code = fixture.original().__code__
    return fixture


def frame_for(image, fixture):
    return native.ServiceInspectionFrame(image, fixture.case['mode'],
        fixture.service, fixture.arguments, namespace=fixture.namespace,
        global_builtins=fixture.namespace['__builtins__'],
        local_names=fixture.code.co_varnames + fixture.code.co_cellvars)


def observed_entry(image):
    rows, real = [], image._entry
    def entry(source, size, output, capacity, state, extent):
        packet = struct.unpack('<16Q', ctypes.string_at(source, size))
        code = real(source, size, output, capacity, state, extent)
        answer = struct.unpack('<12Q', ctypes.string_at(output, capacity))
        rows.append({'event': packet[1], 'port': packet[3], 'mode': packet[5],
                     'sequence': packet[2], 'code': code, 'phase': answer[4],
                     'returned_port': answer[2], 'failed': answer[6]})
        return code
    return rows, entry


def bundle(path, helpers):
    from hepta.hia_native_helpers import ABI, SCHEMA, TARGET
    path.write_bytes(canonical({'schema': SCHEMA, 'abi': ABI, 'target': TARGET,
        'helpers': [{'selector': selector, 'manifest_path': str(manifest),
                     'manifest_sha256': sha256(Path(manifest).read_bytes()).hexdigest()}
                    for selector, manifest in helpers]}))
    return sha256(path.read_bytes()).hexdigest()


def poison_handlers(stack):
    def forbidden(*arguments, **keywords):
        raise AssertionError('selected inspect/candidate executed an original complete body')
    for name in ('_SERVICE_INSPECTION_INSPECT_REFERENCE', '_SERVICE_INSPECTION_CANDIDATE_REFERENCE'):
        stack.enter_context(patch.object(api, name, forbidden))
    for name in ('_hia_inspect_reference', '_hia_candidate_reference'):
        stack.enter_context(patch.object(api.HIAAgentService, name, forbidden))


def foreign(image, args):
    rows = []
    for mode in (1, 2):
        for kind in (*ERRORS, delivery.NativeDeliveryUnknown, native.ServiceInspectionUnknown):
            fixture, fault = fixture_for(mode), kind('ordinary foreign provider failure')
            def failed(reference):
                raise fault
            if mode == 1:
                fixture.service._program = failed
            else:
                fixture.service._stable_store.get = failed
            entries, entry = observed_entry(image)
            with fixture.providers(), patch.object(image, '_entry', entry):
                frame = frame_for(image, fixture)
                _, error = caught(frame.finish)
            assert error is fault
            assert frame.finished and frame.receipt.phase == native.PROPAGATE
            assert frame._delivery.loss is None and frame._delivery.retired
            assert [row['event'] for row in entries].count(native.RAISED) == 1
            assert [row['event'] for row in entries].count(native.FINALIZE) == 1
            assert not delivery.custody_snapshot()
            rows.append({'mode': mode, 'error': kind.__name__, 'identity_preserved': True,
                         'confirmed_foreign': True, 'entries': entries})
    fixture = fixture_for(1)
    with fixture.providers():
        completed = frame_for(image, fixture)
        completed.finish()
    terminal_fault = MemoryError('ordinary caller after full terminal acknowledgement')
    def later_foreign():
        raise terminal_fault
    _, error = caught(later_foreign)
    assert error is terminal_fault and completed._delivery.loss is None and completed._delivery.retired
    assert not delivery.custody_snapshot()
    rows.append({'after_confirmed_terminal': True, 'same_MemoryError': True,
                 'did_not_create_causal_loss': True})
    return {'rows': rows, 'remaining_custody': delivery.custody_snapshot()}


def preparation(image, args):
    rows = []
    # A failure before the real entry must not acquire an unknown obligation.
    fixture, fault = fixture_for(1), MemoryError('request packet allocation before entry')
    frame = object.__new__(native.ServiceInspectionFrame)
    real_pack = native.struct.pack
    def refused_pack(format, *values):
        if format == '<16Q':
            raise fault
        return real_pack(format, *values)
    with fixture.providers(), patch.object(native.struct, 'pack', refused_pack):
        _, error = caught(lambda: native.ServiceInspectionFrame.__init__(frame, image, 1,
            fixture.service, fixture.arguments, namespace=fixture.namespace,
            global_builtins=fixture.namespace['__builtins__'],
            local_names=fixture.code.co_varnames + fixture.code.co_cellvars))
    assert error is fault and frame._delivery.loss is None and frame._delivery.retired
    assert not frame._delivery.native_pending and not delivery.custody_snapshot()
    rows.append({'cutpoint': 'before-INIT-entry', 'same_MemoryError': True,
                 'custody_released': True})
    real_foreign = delivery.DeliveryRecord.foreign
    for first in (True, False):
        fixture, fault = fixture_for(1), MemoryError('per-effect activation allocation refused')
        entries, entry = observed_entry(image)
        with fixture.providers(), patch.object(image, '_entry', entry):
            frame = frame_for(image, fixture)
            target = native.PORT['inspect_import' if first else 'inspect_release']
            def refused_foreign(record, *a, **k):
                if (record is frame._delivery and k.get('capture_resources') is True
                        and frame._whole is not None and frame.receipt.phase == native.CLAIMED
                        and frame.receipt.port == target):
                    raise fault
                return real_foreign(record, *a, **k)
            with patch.object(delivery.DeliveryRecord, 'foreign', refused_foreign):
                _, error = caught(frame.finish)
        assert error is fault and not any(row['event'] == native.RAISED for row in entries)
        if first:
            assert not frame._foreign_started and frame._delivery.loss is None and frame._delivery.retired
        else:
            assert frame._foreign_started and frame._delivery.loss is not None and not frame._delivery.retired
        rows.append({'cutpoint': 'first-activation' if first else 'later-activation-after-effects',
            'same_MemoryError': True, 'event3_not_fabricated': True,
            'unknown_after_earlier_effect': not first, 'entries': entries})
    return {'rows': rows, 'later_failed_owner_retained': len(delivery.custody_snapshot()) > 0}


def loss(image, args):
    rows = []
    for mode in (1, 2):
        first_port = native.PORT['inspect_program' if mode == 1 else 'candidate_import_data']
        result_port = native.PORT['inspect_result' if mode == 1 else 'candidate_diagnostics_json']
        release_port = native.PORT['inspect_release' if mode == 1 else 'candidate_release']
        targets = ((native.INITIALIZE, 0), (native.CLAIM, first_port),
                   (native.SUCCEEDED, first_port), (native.SUCCEEDED, result_port),
                   (native.SUCCEEDED, release_port), (native.FINALIZE, 0))
        for event, port in targets:
            for kind in (ValueError, OSError, MemoryError, RuntimeError, KeyboardInterrupt, SystemExit):
                fixture, fault = fixture_for(mode), kind('real native receipt was withheld')
                actual, entries, fired = image._entry, [], [False]
                def withheld(source, size, output, capacity, state, extent):
                    packet = struct.unpack('<16Q', ctypes.string_at(source, size))
                    code = actual(source, size, output, capacity, state, extent)
                    entries.append({'event': packet[1], 'port': packet[3], 'native_return': code})
                    if not fired[0] and (packet[1], packet[3]) == (event, port):
                        fired[0] = True
                        raise fault
                    return code
                frame = object.__new__(native.ServiceInspectionFrame)
                with fixture.providers(), patch.object(image, '_entry', withheld):
                    def run():
                        native.ServiceInspectionFrame.__init__(frame, image, mode,
                            fixture.service, fixture.arguments, namespace=fixture.namespace,
                            global_builtins=fixture.namespace['__builtins__'],
                            local_names=fixture.code.co_varnames + fixture.code.co_cellvars)
                        return frame.finish()
                    _, error = caught(run)
                    before = (len(entries), list(fixture.world.events))
                    _, again = caught(frame.finish)
                assert fired[0] and frame.fenced and frame.native_failed
                assert frame._delivery.loss is not None and not frame._delivery.retired
                if issubclass(kind, native._REQUEST_REJECTIONS):
                    assert type(error) is native.ServiceInspectionUnknown and error.__cause__ is fault
                else:
                    assert error is fault
                assert type(again) is native.ServiceInspectionUnknown
                assert before == (len(entries), fixture.world.events)
                assert not any(row['event'] == native.RAISED for row in entries)
                rows.append({'mode': mode, 'target': [event, port], 'fault': kind.__name__,
                    'actual_return_then_loss': True, 'identity_or_exact_cause': True,
                    'replay_new_entries': 0, 'retained': True, 'entries': entries})
    # Corrupt complete receipts only after executing the original machine entry.
    for word in (0, 1, 2, 3, 4, 6, 8, 11):
        fixture = fixture_for(1)
        real, fired, count = image._entry, [False], [0]
        def damaged(source, size, output, capacity, state, extent):
            packet = struct.unpack('<16Q', ctypes.string_at(source, size))
            code = real(source, size, output, capacity, state, extent); count[0] += 1
            if not fired[0] and packet[1:2] == (native.SUCCEEDED,):
                fired[0] = True
                raw = bytearray(ctypes.string_at(output, capacity)); raw[word * 8] ^= 1
                ctypes.memmove(output, bytes(raw), capacity)
            return code
        with fixture.providers(), patch.object(image, '_entry', damaged):
            frame = frame_for(image, fixture)
            _, error = caught(frame.finish)
            before = count[0]
            _, again = caught(frame.finish)
        assert fired[0] and isinstance(error, native.ServiceInspectionUnknown)
        assert frame._delivery.loss is not None and not frame._delivery.retired
        assert type(again) is native.ServiceInspectionUnknown and count[0] == before
        rows.append({'corrupt_receipt_word': word, 'actual_entry_first': True, 'replay_new_entries': 0})
    return {'rows': rows, 'retained_unknowns': len(delivery.custody_snapshot())}


def creator(image, args):
    fixture = fixture_for(1)
    with fixture.providers():
        frame = frame_for(image, fixture)
        before = list(fixture.world.events)
        results = []
        thread = threading.Thread(target=lambda: results.append(caught(frame.finish)))
        thread.start(); thread.join(5)
        assert not thread.is_alive() and len(results) == 1
        assert type(results[0][1]) is native.ServiceInspectionUnknown
        assert fixture.world.events == before
        result = frame.finish()
        assert result['next_cursor'] is None and frame.finished
    # Re-enter exactly the active Frame from its real provider and catch denial.
    fixture = fixture_for(1)
    seen, holder = [], []
    original = fixture.service._program
    def recursive(reference):
        before = (holder[0]._delivery.observation_pending, holder[0]._delivery.native_pending,
                  holder[0]._delivery.retired)
        _, error = caught(holder[0].finish)
        after = (holder[0]._delivery.observation_pending, holder[0]._delivery.native_pending,
                 holder[0]._delivery.retired)
        assert type(error) is native.ServiceInspectionUnknown and before == after
        seen.append({'denied_without_outer_cleanup': True})
        return original(reference)
    fixture.service._program = recursive
    with fixture.providers():
        frame = frame_for(image, fixture); holder.append(frame)
        frame.finish()
    assert seen and frame.finished and frame._delivery.retired and frame._delivery.loss is None
    # An inherited frame is invalid in the child; the parent's record remains usable.
    fixture = fixture_for(1)
    with fixture.providers():
        frame = frame_for(image, fixture)
        read_fd, write_fd = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(read_fd)
            try:
                _, error = caught(frame.finish)
                assert type(error) is native.ServiceInspectionUnknown
                os.write(write_fd, b'original-creator-guard')
                os._exit(0)
            except BaseException:
                os._exit(9)
        os.close(write_fd)
        try:
            import select
            ready, _, _ = select.select([read_fd], [], [], 5)
            assert ready
            assert os.read(read_fd, 128) == b'original-creator-guard'
            waited, status = os.waitpid(pid, 0)
            assert waited == pid and os.waitstatus_to_exitcode(status) == 0
            pid = None
        finally:
            os.close(read_fd)
            if pid is not None:
                try: os.kill(pid, signal.SIGKILL)
                except ProcessLookupError: pass
                os.waitpid(pid, 0)
        frame.finish()
    assert frame._delivery.retired and not delivery.custody_snapshot()
    return {'foreign_thread_rejected_then_creator_completed': True,
        'same_Frame_reentry_caught_without_retirement': seen,
        'child_fork_rejected_parent_continued': True, 'remaining_custody': []}


def peer(image, args):
    from hepta import hia_service_context_native as context
    peer_image = context.installed_service_context(str(args.context_manifest))
    rows = []
    for disposition in ('propagate', 'swallow', 'replace'):
        fixture, fault = fixture_for(1), ValueError('actual context native return withheld')
        actual, child_calls = peer_image._entry, []
        def lost(*values):
            code = actual(*values); child_calls.append(code)
            raise fault
        original = fixture.service._program
        def program(reference):
            try:
                peer_image.arithmetic(1, 3, 4)
            except context.ServiceContextUnknown:
                if disposition == 'propagate': raise
                if disposition == 'replace': raise ValueError('foreign replacement')
            return original(reference)
        fixture.service._program = program
        entries, entry = observed_entry(image)
        with fixture.providers(), patch.object(peer_image, '_entry', lost), patch.object(image, '_entry', entry):
            frame = frame_for(image, fixture)
            _, error = caught(frame.finish)
        assert child_calls and isinstance(error, RuntimeError)
        assert frame._delivery.loss is not None and not frame._delivery.retired
        assert not any(row['event'] == native.RAISED for row in entries)
        assert not any(row['event'] == native.SUCCEEDED and row['port'] == native.PORT['inspect_program']
                       for row in entries)
        rows.append({'direction': 'inspection-to-context', 'disposition': disposition,
                     'actual_child_entries': len(child_calls), 'entries': entries})
    # The actual context continuation surrounds an actual inspection Frame.
    for disposition in ('propagate', 'swallow', 'replace'):
        fixture, fault = fixture_for(2), ValueError('nested candidate final receipt withheld')
        real, child_frames, entries = image._entry, [], []
        def lost(source, size, output, capacity, state, extent):
            packet = struct.unpack('<16Q', ctypes.string_at(source, size))
            code = real(source, size, output, capacity, state, extent)
            entries.append({'event': packet[1], 'port': packet[3]})
            if packet[1] == native.FINALIZE:
                raise fault
            return code
        class Database:
            def execute(self, statement, parameters):
                frame = frame_for(image, fixture); child_frames.append(frame)
                try: frame.finish()
                except native.ServiceInspectionUnknown:
                    if disposition == 'propagate': raise
                    if disposition == 'replace': raise ValueError('replacement of candidate loss')
                return SimpleNamespace(fetchone=lambda: None)
        service = SimpleNamespace(store=SimpleNamespace(db=Database()))
        with fixture.providers(), patch.object(image, '_entry', lost):
            parent = context.ContextFrame(peer_image, 2, service,
                {'id': 'inspection-peer', 'sha256': 'a' * 64}, namespace=vars(api))
            _, error = caught(parent.finish)
            before = len(entries)
            _, replay = caught(parent.finish)
        assert len(child_frames) == 1 and isinstance(error, RuntimeError)
        assert parent._delivery.loss is child_frames[0]._delivery.loss
        assert type(replay) is context.ServiceContextUnknown and len(entries) == before
        assert not any(row['event'] == native.RAISED for row in entries)
        rows.append({'direction': 'context-to-candidate', 'disposition': disposition,
                     'actual_child_entries': len(entries), 'shared_actual_loss': True})
    return {'rows': rows, 'exceptions_alone_never_create_loss': True}


def resources(image, args):
    from hepta import hia_agent_store as store
    from hepta import hia_store_artifact_profile_native as store_native
    from hepta import hia_program_tools as program_tools
    from hepta import hia_agent_assembly as assembly
    from hepta import hia_service_context_native as context
    from hepta.hia_native_helpers import native_helpers_scope
    path = args.output / 'bundle.json'
    pin = bundle(path, [(native.SELECTOR, args.manifest), (store_native.SELECTOR, args.store_manifest),
                        (context.SELECTOR, args.context_manifest)])
    rows = []
    for mode in (1, 2):
        for target in ('later-release', 'FINALIZE'):
            directory = args.output / ('resource-' + str(mode) + '-' + target)
            with native_helpers_scope(str(path), pin):
                first, second = store.AgentStore(directory / 'a'), store.AgentStore(directory / 'b')
                source = first.put(b'fixture-source', 'input')
                program = SimpleNamespace(canonical_bytes=b'fixture-canonical',
                    input_sha256='a' * 64, sha256='b' * 64)
                lookups = []
                class Service:
                    def _program(self, reference): return program
                    @property
                    def store(self):
                        # The original call sites, and only those sites, select
                        # these actual Store identities. No provider is re-read.
                        lookups.append(len(lookups))
                        if mode == 1: return first
                        return first if len(lookups) in (1, 3) else second
                arguments = ({'program': source, 'view': 'summary'}
                    if mode == 1 else {'context': {'id': 'fixture-context'},
                        'change': {'kind': 'import', 'source': source, 'format': 'hia-asm.v1'}})
                real, entries, fired = image._entry, [], [False]
                release = native.PORT['inspect_release' if mode == 1 else 'candidate_release']
                def lost(source, size, output, capacity, state, extent):
                    packet = struct.unpack('<16Q', ctypes.string_at(source, size))
                    code = real(source, size, output, capacity, state, extent)
                    entries.append({'event': packet[1], 'port': packet[3]})
                    match = ((packet[1], packet[3]) == (native.SUCCEEDED, release)
                             if target == 'later-release' else packet[1] == native.FINALIZE)
                    if match:
                        fired[0] = True
                        raise ValueError('actual complete method acknowledgement missing')
                    return code
                with patch.object(program_tools, 'inspect_program', return_value={'summary': True}), \
                     patch.object(assembly, 'assemble_program', return_value=program), \
                     patch.object(image, '_entry', lost):
                    frame = native.ServiceInspectionFrame(image, mode, Service(), arguments)
                    _, error = caught(frame.finish)
                assert fired[0] and isinstance(error, RuntimeError) and frame._delivery.loss is not None
                assert lookups == list(range(1 if mode == 1 else 3))
                raw_close = store._NATIVE_STORE_CLOSE_REFERENCE
                close_calls = []
                def observed_close(receiver):
                    close_calls.append(receiver)
                    return raw_close(receiver)
                with patch.object(store, '_NATIVE_STORE_CLOSE_REFERENCE', observed_close):
                    _, first_error = caught(first.close)
                    _, second_error = caught(second.close)
                assert isinstance(first_error, RuntimeError) and first not in close_calls
                if mode == 2:
                    assert isinstance(second_error, RuntimeError) and second not in close_calls
                else:
                    assert second_error is None and close_calls == [second]
                rows.append({'mode': mode, 'target': target, 'actual_Store_lookups': len(lookups),
                    'actual_Store_count_fenced': mode, 'actual_original_close_body_entries': len(close_calls),
                    'later_per_port_ACKs_did_not_retire_whole_facts': True, 'entries': entries})
                # Unknown Store objects are deliberately not closed by the
                # validator. This owned child exits with their exact custody.
    # A real child loss during the original program temporary's release is
    # caught inside __del__, then asserted outside the unraisable boundary.
    from hepta import hia_service_context_native as context
    peer = context.installed_service_context(str(args.context_manifest))
    with native_helpers_scope(str(path), pin):
        retained = store.AgentStore(args.output / 'resource-release')
        source = retained.put(b'fixture-input', 'input')
        release_events, child_entries = [], []
        child_entry = peer._entry
        fault = ValueError('actual context delivery lost during program release')
        def child_lost(*values):
            code = child_entry(*values); child_entries.append(code)
            raise fault
        class ReleasedProgram:
            def __del__(self):
                try:
                    peer.arithmetic(1, 3, 4)
                except BaseException as error:
                    release_events.append({'type': type(error).__name__,
                        'cause_is_actual_fault': error.__cause__ is fault})
                else:
                    release_events.append({'unexpected_success': True})
        class Service:
            store = retained
            def _program(self, reference):
                return ReleasedProgram()
        entries, entry = observed_entry(image)
        with patch.object(program_tools, 'inspect_program', lambda value: {'summary': True}), \
             patch.object(peer, '_entry', child_lost), patch.object(image, '_entry', entry):
            frame = native.ServiceInspectionFrame(image, 1, Service(),
                {'program': source, 'view': 'summary'})
            _, error = caught(frame.finish)
        assert child_entries and release_events == [
            {'type': 'ServiceContextUnknown', 'cause_is_actual_fault': True}]
        assert isinstance(error, RuntimeError) and frame._delivery.loss is not None
        assert not any(row['event'] == native.SUCCEEDED and row['port'] == native.PORT['inspect_release']
                       for row in entries)
        assert not any(row['event'] == native.RAISED for row in entries)
        close_entries = []
        real_close = store._NATIVE_STORE_CLOSE_REFERENCE
        def close_body(receiver):
            close_entries.append(receiver)
            return real_close(receiver)
        with patch.object(store, '_NATIVE_STORE_CLOSE_REFERENCE', close_body):
            _, close_error = caught(retained.close)
        assert isinstance(close_error, RuntimeError) and not close_entries
        rows.append({'actual_program_release_child_loss': True,
            'destructor_observations_asserted_outside_destructor': release_events,
            'actual_child_entries': len(child_entries), 'Store_retirement_fenced': True,
            'entries': entries})
    return {'rows': rows, 'actual_Store_and_SQLite_providers': True,
            'raw_DB_lifetime_or_dead_Store_proved': False,
            'retained_unknowns': len(delivery.custody_snapshot())}


def public(image, args):
    from hepta import hia_store_artifact_profile_native as store_native
    from hepta.hia_native_helpers import native_helpers_scope
    from tests.test_hia_agent_native_tools import AgentToolCase
    from tools.hia_agent_native_qualification import add_program, exhaustive_u8_workload
    path = args.output / 'bundle.json'
    pin = bundle(path, [(native.SELECTOR, args.manifest), (store_native.SELECTOR, args.store_manifest)])
    case, initialized = AgentToolCase('runTest'), False
    rows = []
    try:
        with native_helpers_scope(str(path), pin), ExitStack() as stack:
            poison_handlers(stack)
            case.setUp(); initialized = True
            case.session.freeze(exhaustive_u8_workload())
            document = add_program()
            reference = case.session.artifact(document)
            arguments = case.session.arguments(change={'kind': 'import', 'format': 'core-json',
                                                       'source': reference})
            selected = native.installed_service_inspection(str(args.manifest))
            entries, observed = observed_entry(selected)
            with patch.object(selected, '_entry', observed):
                result = case.service.call('hia_candidate', arguments)
                assert result['status'] == 'completed', result
                candidate = result['result']['candidate']
                before_replay = len(entries)
                replay = case.service.call('hia_candidate', arguments)
                assert replay == result and len(entries) == before_replay
                inspected = case.service.call('hia_inspect', case.session.arguments(mutable=False,
                    program=candidate, view='summary'))
                assert inspected['status'] == 'completed', inspected
                assert inspected['result']['query_artifact'] is None
                assert inspected['result']['next_cursor'] is None
                summary, _ = case.service.store.get_json(inspected['result']['view_artifact'])
                assert isinstance(summary, dict)
                assert {row['mode'] for row in entries} == {1, 2}
                rows.append({'candidate': result, 'candidate_replay': replay,
                    'candidate_replay_extra_entries': 0, 'inspect': inspected,
                    'actual_summary_artifact': summary, 'entries': entries})
            assert not delivery.custody_snapshot()
    finally:
        if initialized:
            case.tearDown()
    return {'rows': rows, 'actual_Core_and_Store_providers': True,
        'original_two_handlers_poisoned': True, 'whole_native_stack_qualified': False}


def scope(image, args):
    from hepta.hia_native_helpers import native_helpers_scope
    source = native.SOURCE.read_bytes()
    alternate = args.output / 'alternate'; alternate.mkdir()
    manifest = alternate / 'manifest.json'; manifest.write_bytes(args.manifest.read_bytes())
    data = json.loads(manifest.read_bytes())
    binary = alternate / data['image_path']
    raw = (args.manifest.parent / data['image_path']).read_bytes(); binary.write_bytes(raw)
    assert native.installed_service_inspection(str(manifest)).image_sha256 == image.image_sha256
    path = args.output / 'bundle.json'
    pin = bundle(path, [(native.SELECTOR, args.manifest)])
    rows = []
    with native_helpers_scope(str(path), pin):
        assert native.installed_service_inspection(str(args.manifest)) is not None
        for selected in ('', str(manifest), str(args.output / 'absent')):
            _, error = caught(lambda: native.installed_service_inspection(selected))
            assert isinstance(error, (ValueError, OSError))
            rows.append({'active_scope_alternate': selected, 'rejected': True})
        try:
            native.SOURCE.write_bytes(source + b'\n')
            _, error = caught(lambda: native.installed_service_inspection(str(args.manifest)))
            assert isinstance(error, (ValueError, OSError))
            rows.append({'source_plus_LF': 'rejected'})
        finally:
            native.SOURCE.write_bytes(source)
    binary.write_bytes(raw + b'\0')
    _, error = caught(lambda: native.installed_service_inspection(str(manifest)))
    assert isinstance(error, ValueError)
    binary.write_bytes(raw)
    assert native.SOURCE.read_bytes() == source
    return {'rows': rows, 'image_byte_drift_rejected': True, 'source_restored': True}


MODES = ('foreign', 'preparation', 'loss', 'creator', 'peer', 'resources', 'public', 'scope')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', required=True, choices=MODES)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--store-manifest', type=Path, required=True)
    parser.add_argument('--context-manifest', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    from tools.build_hia_service_inspection import INPUTS
    before = {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in INPUTS}
    image = native.installed_service_inspection(str(args.manifest))
    observations = globals()[args.mode](image, args)
    after = {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in INPUTS}
    assert before == after
    report = {'schema': 'hepta.hia.service-inspection-isolated-controls.v1',
        'status': 'PASS', 'mode': args.mode, 'observations': observations,
        'source_before': before, 'source_after': after, 'source_unchanged': True,
        'native_image_sha256': image.image_sha256,
        'actual_input_scope_and_qualification_owned_by_outer_component': True,
        'whole_native_stack_qualified': False}
    (args.output / 'report.json').write_bytes(canonical(report))
    print(json.dumps({'status': 'PASS', 'mode': args.mode}))


if __name__ == '__main__':
    main()
