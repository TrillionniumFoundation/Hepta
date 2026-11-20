"""Isolated actual-image controls for read delivery, public routes and scope."""
from __future__ import annotations

import argparse
from contextlib import ExitStack
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
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
from hepta import hia_service_read_native as native
from hepta import hia_native_delivery as delivery
from tests.hia_service_read_fixture import canonical

ERRORS = (ValueError, TypeError, OSError, OverflowError, RecursionError,
          sqlite3.OperationalError, RuntimeError, MemoryError, KeyboardInterrupt, SystemExit)


def caught(function):
    try:
        return function(), None
    except BaseException as error:
        return None, error


class Fixture:
    def __init__(self, *, data=b'abcdef', limit=65536, cursor=False):
        self.events, self.effects = [], []
        self.ref = {'id': 'input', 'sha256': 'a' * 64}
        fixture = self
        class Cursor:
            def __init__(self, row):
                self.row = row
            def fetchone(self):
                fixture.events.append('fetchone')
                return self.row
        class Database:
            def execute(self, statement, arguments):
                fixture.events.append(('execute', statement, arguments))
                if statement.startswith('SELECT'):
                    return Cursor({'artifact_id': 'input', 'sha256': 'a' * 64, 'offset': 0})
                fixture.effects.append((statement, arguments))
                return Cursor(None)
        class Store:
            db = Database()
            def get(self, reference):
                fixture.events.append(('get', reference))
                return data, {}
        self.store = Store()
        self.service = SimpleNamespace(store=self.store)
        self.arguments = {'artifact': self.ref, 'max_bytes': limit}
        if cursor:
            self.arguments['cursor'] = 'prior'


def frame_for(image, fixture):
    return native.ServiceReadFrame(image, fixture.service, fixture.arguments)


def observe_entries(image):
    rows, real = [], image._entry
    def observed(source, size, output, capacity, state, extent):
        packet = struct.unpack('<10Q', ctypes.string_at(source, size))
        code = real(source, size, output, capacity, state, extent)
        answer = struct.unpack('<12Q', ctypes.string_at(output, capacity))
        rows.append({'event': packet[1], 'port': packet[3], 'sequence': packet[2],
                     'code': code, 'phase': answer[4], 'returned_port': answer[2]})
        return code
    return rows, observed


def foreign(image, args):
    rows = []
    for kind in (*ERRORS, delivery.NativeDeliveryUnknown, native.ServiceReadUnknown):
        fixture, fault = Fixture(), kind('confirmed ordinary foreign failure')
        def failed(reference):
            fixture.events.append('foreign-get-failure')
            raise fault
        fixture.store.get = failed
        entries, observed = observe_entries(image)
        with patch.object(image, '_entry', observed):
            frame = frame_for(image, fixture)
            _, error = caught(frame.finish)
        assert error is fault
        assert frame.finished and not frame.native_failed and frame.receipt.phase == native.PROPAGATE
        assert frame._delivery.loss is None and frame._delivery.retired
        assert [row['event'] for row in entries].count(native.RAISED) == 1
        assert not delivery.custody_snapshot()
        rows.append({'error_type': kind.__name__, 'same_exception_object': error is fault,
                     'entries': entries, 'events': fixture.events, 'confirmed_foreign': True})
    fixture, fault = Fixture(), MemoryError('before native packing')
    frame = object.__new__(native.ServiceReadFrame)
    actual_pack = native.struct.pack
    def failed_pack(format, *values):
        if format == '<10Q':
            raise fault
        return actual_pack(format, *values)
    with patch.object(native.struct, 'pack', failed_pack):
        _, error = caught(lambda: native.ServiceReadFrame.__init__(frame, image,
            fixture.service, fixture.arguments))
    assert error is fault and not frame._delivery.native_pending and frame._delivery.loss is None
    assert frame._delivery.retired and not fixture.events and not delivery.custody_snapshot()
    rows.append({'safe_preentry': True, 'same_exception_object': error is fault,
                 'no_foreign_effect': not fixture.events})
    fixture = Fixture()
    frame = frame_for(image, fixture)
    result = frame.finish()
    fault = ValueError('foreign caller after complete terminal')
    def after_terminal():
        assert result['content'] == 'abcdef'
        raise fault
    _, error = caught(after_terminal)
    assert error is fault and frame._delivery.loss is None and not delivery.custody_snapshot()
    rows.append({'after_confirmed_terminal_foreign': True, 'same_exception_object': error is fault})
    return {'rows': rows}


def loss(image, args):
    targets = ((native.INITIALIZE, 0), (native.CLAIM, native.PORT['artifact_get']),
               (native.SUCCEEDED, native.PORT['artifact_get']),
               (native.SUCCEEDED, native.PORT['whole_data_decode']),
               (native.SUCCEEDED, native.PORT['cursor_insert']),
               (native.SUCCEEDED, native.PORT['return']))
    rows = []
    for event, port in targets:
        for kind in (ValueError, OSError, MemoryError, RuntimeError, KeyboardInterrupt, SystemExit):
            fixture = Fixture(limit=3)
            fault = kind('read actual return lost after native entry')
            actual_entry, entries, fired = image._entry, [], [False]
            def lost(source, size, output, capacity, state, extent):
                packet = struct.unpack('<10Q', ctypes.string_at(source, size))
                code = actual_entry(source, size, output, capacity, state, extent)
                entries.append({'event': packet[1], 'port': packet[3], 'native_return': code})
                if not fired[0] and (packet[1], packet[3]) == (event, port):
                    fired[0] = True
                    raise fault
                return code
            frame = object.__new__(native.ServiceReadFrame)
            with patch.object(image, '_entry', lost):
                def run():
                    native.ServiceReadFrame.__init__(frame, image, fixture.service, fixture.arguments)
                    return frame.finish()
                _, error = caught(run)
                before = (len(entries), list(fixture.events), list(fixture.effects))
                _, repeated = caught(frame.finish)
            assert fired[0] and frame.fenced and frame.native_failed
            assert frame._delivery.loss is not None and not frame._delivery.retired
            if issubclass(kind, RuntimeError) or not issubclass(kind, Exception):
                assert error is fault
            else:
                assert type(error) is native.ServiceReadUnknown and error.__cause__ is fault
            assert type(repeated) is native.ServiceReadUnknown
            assert (len(entries), fixture.events, fixture.effects) == before
            assert not any(row['event'] == native.RAISED for row in entries)
            rows.append({'target': [event, port], 'fault': kind.__name__,
                'entries': entries, 'effects': fixture.effects, 'same_fault_or_exact_cause': True,
                'replay_new_entries': 0, 'owner_retained': True})
    fixture = Fixture()
    frame = frame_for(image, fixture)
    results = []
    worker = threading.Thread(target=lambda: results.append(caught(frame.finish)))
    worker.start(); worker.join(5)
    assert not worker.is_alive()
    assert len(results) == 1 and type(results[0][1]) is native.ServiceReadUnknown
    assert fixture.events == []
    assert frame.finish()['content'] == 'abcdef'
    rows.append({'foreign_thread': 'rejected by read owner before effects',
                 'creator_continued_healthy': True})
    return {'rows': rows, 'retained_unknown_count': len(delivery.custody_snapshot())}


def peer(image, args):
    from hepta import hia_service_context_native as context
    peer_image = context.installed_service_context(str(args.context_manifest))
    rows = []
    for disposition in ('propagate', 'swallow', 'replace'):
        fixture, fault = Fixture(), ValueError('actual peer return missing')
        peer_entry, peer_calls = peer_image._entry, []
        def peer_lost(*arguments):
            result = peer_entry(*arguments)
            peer_calls.append(result)
            raise fault
        def get(reference):
            try:
                peer_image.arithmetic(1, 3, 4)
            except context.ServiceContextUnknown:
                if disposition == 'propagate':
                    raise
                if disposition == 'replace':
                    raise ValueError('foreign replacement of actual child loss')
            return b'abc', {}
        fixture.store.get = get
        entries, observed = observe_entries(image)
        with patch.object(peer_image, '_entry', peer_lost), patch.object(image, '_entry', observed):
            frame = frame_for(image, fixture)
            _, error = caught(frame.finish)
        assert peer_calls and isinstance(error, RuntimeError)
        assert frame._delivery.loss is not None and frame.native_failed
        assert not any(row['event'] == native.RAISED for row in entries)
        assert not any(row['event'] == native.SUCCEEDED and row['port'] == native.PORT['artifact_get']
                       for row in entries)
        rows.append({'direction': 'read to context', 'disposition': disposition,
                     'actual_peer_entries': len(peer_calls), 'entries': entries,
                     'outer_unknown': True})
    fixture = Fixture()
    fault = context.ServiceContextUnknown('same name, no native delivery')
    def ordinary(reference):
        raise fault
    fixture.store.get = ordinary
    entries, observed = observe_entries(image)
    with patch.object(image, '_entry', observed):
        frame = frame_for(image, fixture)
        _, error = caught(frame.finish)
    assert error is fault and frame.finished and frame._delivery.loss is None
    assert sum(row['event'] == native.RAISED for row in entries) == 1
    rows.append({'same_named_exception_without_handoff': True, 'confirmed_foreign': True, 'entries': entries})
    # Reverse direction uses the peer's real mode-2 continuation and original
    # execute port. Its ordinary foreign provider enters the real read image;
    # the read's INSERT already happened before its ACK is deliberately lost.
    # This is separate from (and does not infer) resource association.
    for disposition in ('propagate', 'swallow', 'replace'):
        fixture, fault = Fixture(limit=3), ValueError('actual nested read ACK missing')
        read_entry, context_entry = image._entry, peer_image._entry
        read_entries, peer_entries, children = [], [], []
        fired = [False]
        def lost_read(source, size, output, capacity, state, extent):
            packet = struct.unpack('<10Q', ctypes.string_at(source, size))
            code = read_entry(source, size, output, capacity, state, extent)
            read_entries.append({'event': packet[1], 'port': packet[3], 'native_return': code})
            if not fired[0] and (packet[1], packet[3]) == (native.SUCCEEDED, native.PORT['cursor_insert']):
                fired[0] = True
                raise fault
            return code
        def observed_context(source, size, output, capacity, state, extent):
            packet = struct.unpack('<10Q', ctypes.string_at(source, size))
            code = context_entry(source, size, output, capacity, state, extent)
            peer_entries.append({'event': packet[1], 'port': packet[3], 'native_return': code})
            return code
        class Database:
            def execute(self, statement, arguments):
                child = frame_for(image, fixture)
                children.append(child)
                try:
                    child.finish()
                except native.ServiceReadUnknown:
                    if disposition == 'propagate':
                        raise
                    if disposition == 'replace':
                        raise ValueError('foreign replacement of actual nested read loss')
                return SimpleNamespace(fetchone=lambda: None)
        service = SimpleNamespace(store=SimpleNamespace(db=Database()))
        with patch.object(image, '_entry', lost_read), patch.object(peer_image, '_entry', observed_context):
            parent = context.ContextFrame(peer_image, 2, service,
                {'id': 'ctx-peer-read', 'sha256': 'a' * 64})
            _, error = caught(parent.finish)
            before = (len(read_entries), len(peer_entries), list(fixture.effects))
            _, repeated = caught(parent.finish)
        assert fired[0] and len(children) == 1 and len(fixture.effects) == 1
        assert isinstance(error, RuntimeError) and type(repeated) is context.ServiceContextUnknown
        assert parent._delivery.loss is children[0]._delivery.loss
        assert parent.native_failed and children[0].native_failed
        assert not any(row['event'] == native.RAISED for row in read_entries + peer_entries)
        assert not any(row['event'] == native.SUCCEEDED and row['port'] == 102 for row in peer_entries)
        assert (len(read_entries), len(peer_entries), fixture.effects) == before
        rows.append({'direction': 'context to read', 'disposition': disposition,
            'read_entries': read_entries, 'peer_entries': peer_entries,
            'actual_cursor_effects_before_lost_ACK': fixture.effects,
            'same_causal_loss_origin': True, 'replay_new_entries': 0})
    fault = native.ServiceReadUnknown('ordinary foreign error, no read invocation')
    peer_entries = []
    context_entry = peer_image._entry
    def observed_context(source, size, output, capacity, state, extent):
        packet = struct.unpack('<10Q', ctypes.string_at(source, size))
        code = context_entry(source, size, output, capacity, state, extent)
        peer_entries.append({'event': packet[1], 'port': packet[3], 'native_return': code})
        return code
    class RefusingDatabase:
        def execute(self, statement, arguments):
            raise fault
    service = SimpleNamespace(store=SimpleNamespace(db=RefusingDatabase()))
    with patch.object(peer_image, '_entry', observed_context):
        parent = context.ContextFrame(peer_image, 2, service,
            {'id': 'ctx-ordinary-refusal', 'sha256': 'a' * 64})
        _, error = caught(parent.finish)
    assert error is fault and parent._delivery.loss is None and parent._delivery.retired
    assert parent.receipt.phase == 5 and sum(row['event'] == 3 for row in peer_entries) == 1
    rows.append({'direction': 'context to ordinary read-named foreign error',
        'same_exception_object': True, 'confirmed_foreign': True, 'peer_entries': peer_entries})
    return {'rows': rows}


def bundle(path, helpers):
    from hepta.hia_native_helpers import ABI, SCHEMA, TARGET
    path.write_bytes(canonical({'schema': SCHEMA, 'abi': ABI, 'target': TARGET,
        'helpers': [{'selector': selector, 'manifest_path': str(manifest),
                     'manifest_sha256': sha256(manifest.read_bytes()).hexdigest()}
                    for selector, manifest in helpers]}))
    return sha256(path.read_bytes()).hexdigest()


def public(image, args):
    from hepta import hia_agent_store as store
    from hepta import hia_store_artifact_profile_native as store_native
    from tests.test_hia_agent_native_tools import AgentToolCase
    from hepta.hia_native_helpers import native_helpers_scope
    path = args.output / 'bundle.json'
    pin = bundle(path, [(native.SELECTOR, args.manifest), (store_native.SELECTOR, args.store_manifest)])
    case = AgentToolCase('runTest')
    initialized = False
    rows = []
    def forbidden(*a, **k):
        raise AssertionError('selected public read executed retained handler')
    try:
        with native_helpers_scope(str(path), pin), patch.object(api, '_SERVICE_READ_REFERENCE', forbidden), \
             patch.object(api.HIAAgentService, '_hia_read_reference', forbidden):
            case.setUp(); initialized = True
            content = 'x' * 511 + '雪z'
            reference = case.service.store.put(content.encode(), 'input')
            selected = native.installed_service_read(str(args.manifest))
            entries, observed = observe_entries(selected)
            with patch.object(selected, '_entry', observed):
                first = case.service.call('hia_read', case.session.arguments(mutable=False, context=False,
                    artifact=reference, max_bytes=512))
                assert first['status'] == 'completed', first
                result = first['result']
                assert result['content'] == 'x' * 511 and result['encoding'] == 'utf8' and result['next_cursor']
                row = case.service.store.db.execute('SELECT * FROM cursors WHERE id=?',
                    (result['next_cursor'],)).fetchone()
                assert row['artifact_id'] == reference['id'] and row['sha256'] == reference['sha256'] and row['offset'] == 511
                second = case.service.call('hia_read', case.session.arguments(mutable=False, context=False,
                    artifact=reference, cursor=result['next_cursor'], max_bytes=512))
                assert second['status'] == 'completed' and second['result']['content'] == '雪z'
                assert second['result']['next_cursor'] is None
                get = store.AgentStore.get
                gets = []
                def counted(receiver, artifact, *a, **k):
                    gets.append(artifact)
                    return get(receiver, artifact, *a, **k)
                with patch.object(store.AgentStore, 'get', counted):
                    alias = case.service.call('hia_resource_read', {'uri': reference['uri'], 'max_bytes': 65536})
                assert alias['status'] == 'completed' and alias['result']['content'] == content
                assert len(gets) == 2
                rows.append({'first': first, 'second': second, 'alias': alias,
                             'cursor_row': dict(row), 'alias_get_calls': len(gets), 'entries': entries})
            assert not delivery.custody_snapshot()
    finally:
        if initialized:
            case.tearDown()
    return {'rows': rows, 'actual_SQLite_cursor_effect': True,
            'original_resource_alias_two_gets': True, 'whole_native_stack_qualified': False}


def scope(image, args):
    from hepta.hia_native_helpers import native_helpers_scope
    original_source = native.SOURCE.read_bytes()
    alternate = args.output / 'alternate'; alternate.mkdir()
    manifest = alternate / 'manifest.json'
    manifest.write_bytes(args.manifest.read_bytes())
    value = json.loads(manifest.read_bytes())
    image_path = alternate / value['image_path']
    original_image = (args.manifest.parent / value['image_path']).read_bytes()
    image_path.write_bytes(original_image)
    accepted = native.installed_service_read(str(manifest))
    assert accepted.image_sha256 == image.image_sha256
    path = args.output / 'bundle.json'
    pin = bundle(path, [(native.SELECTOR, args.manifest)])
    rows = []
    with native_helpers_scope(str(path), pin):
        selected = native.installed_service_read(str(args.manifest))
        assert selected is not None
        for value in ('', str(manifest), str(args.output / 'absent')):
            _, error = caught(lambda: native.installed_service_read(value))
            assert isinstance(error, (ValueError, OSError))
            rows.append({'active_scope_alternate': value, 'rejected': True})
        try:
            native.SOURCE.write_bytes(original_source + b'\n')
            _, error = caught(lambda: native.installed_service_read(str(args.manifest)))
            assert isinstance(error, (ValueError, OSError))
            rows.append({'same_source_plus_LF': 'rejected'})
        finally:
            native.SOURCE.write_bytes(original_source)
    assert native.SOURCE.read_bytes() == original_source
    image_path.write_bytes(original_image + b'\0')
    _, error = caught(lambda: native.installed_service_read(str(manifest)))
    assert isinstance(error, ValueError)
    image_path.write_bytes(original_image)
    manifest.write_bytes(manifest.read_bytes() + b'\n')
    with native_helpers_scope(str(path), pin):
        _, error = caught(lambda: native.installed_service_read(str(manifest)))
        assert isinstance(error, ValueError)
    rows.append({'image_bytes_drift': 'rejected', 'unlisted_manifest': 'rejected'})
    return {'rows': rows, 'source_restored': True}


def protocol(image, args):
    from hepta.hia_agent_assembly import assemble_program
    from tests.test_hia_service_read_native import vm_call
    program = assemble_program(native.SOURCE.read_bytes())
    def raw(words, state=bytes(native.STATE_BYTES)):
        packet = struct.pack('<10Q', *words)
        output = bytes(native.OUTPUT_BYTES)
        expected = vm_call(program, packet, output, state)
        source, answer, retained = (ctypes.create_string_buffer(value, len(value))
                                   for value in (packet, output, state))
        code = image._entry(source, len(packet), answer, len(output), retained, len(state))
        actual = (code, answer.raw, retained.raw)
        assert actual == expected and source.raw == packet
        return actual
    initialize = [native.REQUEST_MAGIC, 0, 0, 0, 0, 1, 17, 29, 0, 0]
    state = raw(initialize)[2]
    rows = []
    for name, index, replacement in (('magic', 0, 0), ('mode', 5, 9), ('reserved', 8, 1)):
        packet = list(initialize); packet[index] = replacement
        actual = raw(packet)
        assert actual[0] != native.OUTPUT_BYTES
        rows.append({'case': name, 'return': actual[0]})
    packet = list(initialize); packet[6] = packet[7] = 0
    actual = raw(packet)
    assert actual[0] != native.OUTPUT_BYTES
    rows.append({'case': 'zero_identity', 'return': actual[0]})
    for name, event, sequence, port, observation, nonce in (
            ('stale_sequence', 1, 2, 1, 0, 17), ('wrong_port', 1, 1, 2, 0, 17),
            ('foreign_nonce', 1, 1, 1, 0, 99), ('unclaimed_ACK', 2, 1, 1, 0, 17),
            ('unknown_event', 9, 1, 1, 0, 17), ('claim_observation', 1, 1, 1, 1, 17)):
        actual = raw([native.REQUEST_MAGIC, event, sequence, port, observation, 1, nonce, 29, 0, 0], state)
        words = struct.unpack('<12Q', actual[1])
        assert actual[0] == native.OUTPUT_BYTES and words[1] == 1
        rows.append({'case': name, 'return': actual[0], 'status': words[1]})
    damaged = bytearray(state); damaged[80] ^= 1
    actual = raw([native.REQUEST_MAGIC, 1, 1, 1, 0, 1, 17, 29, 0, 0], bytes(damaged))
    assert actual[0] != native.OUTPUT_BYTES
    rows.append({'case': 'state_checksum', 'return': actual[0]})
    return {'rows': rows, 'actual_code_all_output_and_state_bytes_equal_VM': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', required=True, choices=('foreign', 'loss', 'peer', 'public', 'scope', 'protocol'))
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--store-manifest', type=Path, required=True)
    parser.add_argument('--context-manifest', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    from tools.build_hia_service_read import INPUTS
    before = {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in INPUTS}
    image = native.installed_service_read(str(args.manifest))
    value = globals()[args.mode](image, args)
    after = {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in INPUTS}
    assert before == after
    report = {'schema': 'hepta.hia.service-read-isolated-controls.v1', 'status': 'PASS',
              'mode': args.mode, 'observations': value, 'source_before': before,
              'source_after': after, 'source_unchanged': True,
              'scope': 'actual admitted image; qualification supplied by outer component',
              'native_image_sha256': image.image_sha256, 'whole_native_stack_qualified': False}
    (args.output / 'report.json').write_bytes(canonical(report))
    print(json.dumps({'status': 'PASS', 'mode': args.mode}))


if __name__ == '__main__':
    main()
