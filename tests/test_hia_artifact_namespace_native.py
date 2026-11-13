"""Native namespace policy, real same-journal effects and interruption custody."""
from __future__ import annotations

import ctypes
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager, ExitStack
import dis
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import struct
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import threading
from unittest.mock import patch
import uuid

from hepta.hia_artifact_namespace_native import (SOURCE, REQUEST_MAGIC, RESULT_MAGIC,
    GUARD_MAGIC, SELECTOR, BYTE_SELECTOR, NamespaceBinding, NativeArtifactNamespaceImage,
    ArtifactNamespaceUnknown, NamespaceState, SCHEMA)

ROOT = Path(__file__).resolve().parents[1]
IDENTITY, CONNECTION, NONCE = (11, 17), (31, 37), (41, 43)
CAPACITY = 16384


def wire(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()


def packet(event, sequence=0, *, operation=0, nonce=NONCE, values=(), payload=b'',
           token=0, connection=CONNECTION, scope_kind=0, scope_epoch=0, scope_nonce=(0, 0), callback=0):
    words = [REQUEST_MAGIC, event, sequence, token, *IDENTITY, *nonce, *connection,
             scope_kind, scope_epoch, *scope_nonce, callback, operation, *values]
    return struct.pack('<32Q', *(words + [0] * (32 - len(words)))) + payload


class VM:
    def __init__(self):
        from hepta.hia_agent_assembly import assemble_program
        self.program = assemble_program(SOURCE.read_bytes())
        self.entry = next(f for f in self.program.as_dict()['functions'] if f['name'] == 'f0')
        self.state = bytearray(CAPACITY)

    def call(self, raw, output_size=CAPACITY + 32):
        from hepta.hia_program_runtime import _Machine, _Owner, _View
        objects = [_Owner(-1, bytearray(raw)), _Owner(-2, bytearray(output_size)), _Owner(-3, self.state)]
        machine = _Machine(self.program, 100000000, 64 << 20, None, 128)
        count = machine.invoke(self.entry, [_View(objects[0], False), _View(objects[1], True),
                                           _View(objects[2], True)])[0]
        assert bytes(objects[0].data) == raw
        return count, bytes(objects[1].data[:count]), bytes(self.state)


class Machine:
    def __init__(self, image):
        self.image = image
        self.state = ctypes.create_string_buffer(CAPACITY + 16)
        ctypes.memset(ctypes.addressof(self.state) + CAPACITY, 0xb7, 16)

    def call(self, raw, output_size=CAPACITY + 32):
        source = ctypes.create_string_buffer(raw, len(raw))
        output = ctypes.create_string_buffer(output_size + 16)
        ctypes.memset(ctypes.addressof(output) + output_size, 0xa5, 16)
        count = self.image._entry(source, len(raw), output, output_size, self.state, CAPACITY)
        assert source.raw == raw
        assert output.raw[output_size:] == b'\xa5' * 16
        assert self.state.raw[CAPACITY:] == b'\xb7' * 16
        return count, output.raw[:count], self.state.raw[:CAPACITY]


class Protocol:
    """Independent controlled observations, with no production SQL adapter."""
    def __init__(self, engine):
        self.engine, self.sequence, self.operation = engine, 0, 0
        self.scope = {}
        self.observations = []
        self.send(0, nonce=(0, 0))

    def send(self, event, values=(), payload=b'', token=0, **kwargs):
        raw = packet(event, 0 if event == 90 else self.sequence, operation=self.operation,
            values=values, payload=payload, token=token, **(self.scope | kwargs))
        answer = self.engine.call(raw)
        count, returned, state = answer
        assert count >= 32, answer
        magic, status, sequence, extent = struct.unpack('<4Q', returned[:32])
        assert magic == RESULT_MAGIC and count == 32 + extent and returned[32:] == state[:extent]
        self.observations.append((raw, answer))
        self.status = status
        self.sequence = sequence
        self.words = struct.unpack('<64Q', returned[32:544])
        self.bytes = returned[32:]
        return self.words

    def begin(self, operation, *, data=b'', kind=None, metadata=None, identifier='',
              reference=None, expected=None, uri=None):
        self.operation = operation
        raw_kind = b'' if kind is None else kind.encode()
        metadata_wire = wire({} if metadata is None else metadata) if operation in (1, 4) else b''
        identifier_raw = identifier.encode() if operation == 4 else b''
        raw_expected = raw_id = raw_hash = raw_uri = expected_hash = b''
        shaped = types = expected_shape = expected_types = value_types = 0
        if kind is not None:
            value_types |= 1
        if operation == 4:
            value_types |= 2
        if operation == 2:
            raw_id, raw_hash, raw_uri = (reference[name].encode() for name in ('id', 'sha256', 'uri'))
            shaped, types = 1, 7
        elif operation == 3:
            raw_uri, types = uri.encode(), 4
        elif operation == 5:
            identifier_raw, raw_hash = (reference[name].encode() for name in ('id', 'sha256'))
            raw_expected, expected_hash = (expected[name].encode() for name in ('id', 'sha256'))
            shaped, types, expected_shape, expected_types, value_types = 1, 3, 1, 3, 6
        values = (int(operation in (1, 4)), len(data) if operation in (1, 4) else 0,
            len(raw_kind), len(metadata_wire), len(identifier_raw), int(kind is not None),
            shaped, types, expected_shape, expected_types, len(raw_expected), len(raw_id),
            len(raw_hash), len(raw_uri), len(expected_hash), value_types)
        payload = raw_kind + metadata_wire + identifier_raw + raw_expected + raw_id + raw_hash + raw_uri + expected_hash + bytes(range(32))
        self.data, self.kind, self.metadata_wire = data, kind, metadata_wire
        return self.send(1, values, payload)

    def outcome(self, values, payload=b''):
        token = self.words[6]
        action = self.words[5]
        self.send(2, token=token)
        assert self.status == 0 and self.words[3] == 2 and self.words[5] == action
        return self.send(3, values, payload, token)

    def row(self, row):
        if row is None:
            return self.outcome((0,))
        fields = tuple(row[name].encode() for name in ('id', 'sha256', 'uri', 'kind', 'metadata', 'content_key'))
        return self.outcome((1, *(len(raw) for raw in fields), 63), b''.join(fields))

    def verify_row_binding(self, row):
        assert self.words[5] == 2
        binding = self.bytes[self.words[34]:self.words[34] + self.words[35]]
        expected = wire({'sha256': row['sha256'], 'kind': row['kind'], 'metadata': json.loads(row['metadata'])})
        assert binding == expected
        self.outcome((1, len(binding), 64), sha256(binding).hexdigest().encode())

    def put(self, *, data=b'payload', kind='input', metadata=None, profile_id=None, previous=None):
        self.begin(4 if profile_id is not None else 1, data=data,
                   kind='profile' if profile_id is not None else kind,
                   metadata=metadata, identifier=profile_id or '')
        assert self.status == 0 and self.words[5] == 1
        content_hash = sha256(data).hexdigest()
        self.outcome((1, len(data), 64), content_hash.encode())
        binding = self.bytes[self.words[34]:self.words[34] + self.words[35]]
        expected = wire({'sha256': content_hash, 'kind': self.kind,
                         'metadata': {} if metadata is None else metadata})
        assert binding == expected, (binding, expected)
        content_key = sha256(expected).hexdigest()
        self.outcome((1, len(expected), 64), content_key.encode())
        self.row(previous)
        if previous is None:
            assert self.words[5] == 4
            self.outcome((1, len(data), 64), content_hash.encode())
            issued = {'id': self.bytes[768:802].decode(), 'sha256': content_hash,
                      'uri': self.bytes[832:880].decode()}
            assert uuid.UUID(issued['id'][2:]).version == 4
            assert uuid.UUID(issued['uri'][16:]).version == 4
            row = {**issued, 'kind': self.kind, 'metadata': self.metadata_wire.decode(), 'content_key': content_key}
            self.outcome((1, 1))
            self.row(row)
        else:
            row = previous
            issued = {key: row[key] for key in ('id', 'sha256', 'uri')}
        assert self.words[5] == 8
        self.outcome((1, len(data)))
        if profile_id is not None:
            assert self.words[5] == 10
            reference_wire = self.bytes[self.words[34]:self.words[34] + self.words[35]]
            assert reference_wire == wire(issued)
            self.outcome((1, 1))
            self.outcome((1, len(reference_wire), 1), reference_wire)
        assert self.status == 0 and self.words[3] == 3
        assert self.bytes[640:674].decode() == issued['id']
        return issued, row


class ArtifactNamespaceSourceTests(unittest.TestCase):
    def test_generated_source_matches_verified_hia(self):
        from hepta.hia_agent_assembly import render_assembly
        from tools.generate_hia_artifact_namespace import document
        self.assertEqual(SOURCE.read_text(), render_assembly(document()))

    def test_generated_cfg_respects_the_existing_bootstrap_arity_profile(self):
        from tools.generate_hia_artifact_namespace import document
        program = document()
        self.assertLessEqual(len(program['functions']), 128)
        self.assertLessEqual(sum(len(function['blocks']) for function in program['functions']), 1536)
        for function in program['functions']:
            self.assertLessEqual(len(function['params']), 16)
            self.assertLessEqual(len(function['blocks']), 256)
            for block in function['blocks']:
                self.assertLessEqual(len(block['params']), 16, (function['name'], block['id']))
                for instruction in block['ops']:
                    if instruction['op'] == 'call': self.assertLessEqual(len(instruction['args']), 16)

    def test_independent_vm_full_namespace_identity_and_json_binding(self):
        protocol = Protocol(VM())
        ref, row = protocol.put(data=b'', kind='\x00\b\t\n\f\r"\\雪', metadata={'雪': [None, 3, 'a"b']})
        self.assertEqual(protocol.put(data=b'', kind=row['kind'], metadata={'雪': [None, 3, 'a"b']}, previous=row)[0], ref)
        protocol.begin(2, kind=row['kind'], reference=ref)
        protocol.row(row)
        protocol.verify_row_binding(row)
        self.assertEqual(protocol.words[5], 8)
        protocol.outcome((1, 0))
        self.assertEqual(protocol.words[33], 2)
        protocol.begin(3, uri=ref['uri'])
        protocol.row(row)
        self.assertEqual(protocol.words[5], 7)
        protocol.row(row)
        protocol.verify_row_binding(row)
        protocol.outcome((1, 0))
        self.assertEqual(protocol.words[33], 3)

    def test_independent_vm_profile_checks_both_rows_and_file(self):
        protocol = Protocol(VM())
        ref, row = protocol.put(data=wire({'mode': 'profile'}), profile_id='hia-profile-雪')
        profile = {'id': 'hia-profile-雪', 'sha256': ref['sha256']}
        protocol.begin(5, reference=profile, expected=profile)
        self.assertEqual(protocol.words[5], 11)
        reference_wire = wire(ref)
        protocol.outcome((1, len(reference_wire), 1), reference_wire)
        self.assertEqual(protocol.words[5], 7)
        protocol.row(row)
        protocol.verify_row_binding(row)
        self.assertEqual(protocol.words[5], 8)
        protocol.outcome((1, len(wire({'mode': 'profile'}))))
        self.assertEqual(protocol.words[33], 5)
        bad = dict(profile, sha256='0' * 64)
        protocol.begin(5, reference=bad, expected=profile)
        self.assertEqual((protocol.status, protocol.words[3]), (5, 4))

    def test_invalid_selected_owner_refuses_before_store_creation(self):
        from hepta.hia_agent_store import AgentStore
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / 'invalid.json'; manifest.write_text('{}')
            target = root / 'must-not-exist'
            with patch.dict(os.environ, {SELECTOR: str(manifest)}):
                with self.assertRaises(ValueError): AgentStore(target)
            self.assertFalse(target.exists())

    def test_independent_vm_scope_guard_consumes_epoch_even_when_observed_closed(self):
        protocol = Protocol(VM())
        scope_nonce = (71, 73)
        protocol.send(20, nonce=(0, 0), scope_kind=1, scope_nonce=scope_nonce)
        self.assertEqual((protocol.status, protocol.words[40], protocol.words[44]), (0, 1, 14))
        epoch, token = protocol.words[41], protocol.words[45]
        protocol.send(21, token=token, nonce=(0, 0), scope_kind=1, scope_epoch=epoch, scope_nonce=scope_nonce)
        self.assertEqual(protocol.words[40], 2)
        for active, granted in ((0, 0), (1, 0)):
            raw = packet(24, nonce=(0, 0), scope_kind=1, scope_epoch=epoch,
                         scope_nonce=scope_nonce, values=(active,))
            count, output, state = protocol.engine.call(raw, 32)
            self.assertEqual((count, struct.unpack('<4Q', output)), (32, (GUARD_MAGIC, 0, granted, epoch)))
            words = struct.unpack('<64Q', state[:512])
            self.assertEqual((words[40], words[47]), (8, epoch))

    def test_bad_cold_builder_refuses_before_output_or_compilation(self):
        from tools.build_hia_artifact_namespace import build
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'compiler').write_bytes(b'not qualified')
            (root / 'cold').write_text('{}')
            with patch('tools.qualify_hia_selfhost.compile_stage', side_effect=AssertionError('compile entered')):
                with self.assertRaisesRegex(ValueError, 'completed matching native cold'):
                    build(root / 'output', root / 'compiler', root / 'cold')
            self.assertFalse((root / 'output').exists())

    def test_explicit_cold_fixture_never_enters_development_build(self):
        class ColdFixture(ArtifactNamespaceNativeTests):
            pass
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / 'cold.json'; report.write_text('{}')
            evidence = root / 'must-not-exist'
            env = {'HEPTA_HIA_ARTIFACT_NAMESPACE_COLD_REPORT': str(report),
                   'HEPTA_HIA_ARTIFACT_NAMESPACE_DEVELOPMENT_COMPILER': '',
                   'HEPTA_HIA_ARTIFACT_NAMESPACE_EVIDENCE': str(evidence)}
            with patch.dict(os.environ, env), patch('tools.qualify_hia_selfhost.build_seed',
                    side_effect=AssertionError('development seed entered')):
                with self.assertRaisesRegex(ValueError, 'cold report lacks a compiler'):
                    ColdFixture.setUpClass()
            self.assertFalse(evidence.exists())
            env['HEPTA_HIA_ARTIFACT_NAMESPACE_DEVELOPMENT_COMPILER'] = '/unread-compiler'
            with patch.dict(os.environ, env), patch.object(Path, 'read_bytes', side_effect=AssertionError('file read')):
                with self.assertRaisesRegex(ValueError, 'development compiler cannot be combined'):
                    ColdFixture.setUpClass()


@contextmanager
def interrupt_opcode(code, opname, name=None, predicate=lambda frame: True):
    """Actual interpreter boundary; the injected event must be witnessed."""
    offsets = {item.offset for item in dis.get_instructions(code)
               if item.opname == opname and (name is None or item.argval == name)}
    assert offsets, (opname, name)
    observations = []
    def trace(frame, event, arg):
        if frame.f_code is code:
            frame.f_trace_opcodes = True
            if event == 'opcode' and frame.f_lasti in offsets and not observations and predicate(frame):
                observations.append({'opcode': opname, 'name': name, 'offset': frame.f_lasti})
                raise KeyboardInterrupt('actual namespace interpreter handoff')
        return trace
    previous, frames, frame = sys.gettrace(), [], sys._getframe()
    while frame is not None:
        frames.append((frame, frame.f_trace_opcodes)); frame.f_trace_opcodes = True; frame = frame.f_back
    try:
        sys.settrace(trace)
        yield observations
    finally:
        sys.settrace(previous)
        for frame, flag in frames: frame.f_trace_opcodes = flag
        assert len(observations) == 1, 'requested opcode interruption did not occur'


class ArtifactNamespaceNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tools.qualify_hia_selfhost import compile_stage, build_seed, invoke
        from tools.build_hia_json_preflight import admit_cold_build, current_sources
        cold = os.environ.get('HEPTA_HIA_ARTIFACT_NAMESPACE_COLD_REPORT')
        development = os.environ.get('HEPTA_HIA_ARTIFACT_NAMESPACE_DEVELOPMENT_COMPILER')
        if cold and development:
            raise ValueError('development compiler cannot be combined with a namespace cold report')
        if cold:
            cold = Path(cold); cold_bytes = cold.read_bytes(); report = json.loads(cold_bytes)
            try:
                nested = json.loads(Path(report['nested_report']).read_bytes())
                compiler = Path(nested['generations'][-1]['produced_image'])
            except (KeyError, IndexError, TypeError) as error:
                raise ValueError('namespace cold report lacks a compiler') from error
            compiler_bytes = compiler.read_bytes()
            sources = admit_cold_build(compiler_bytes, cold_bytes)
        else:
            # Development runs also use the real source-custody check. An
            # unfinished integration contract must be prepared in a separate
            # labelled source export; never patch runtime admission to pass.
            sources = current_sources()
        cls.temporary = None
        evidence = os.environ.get('HEPTA_HIA_ARTIFACT_NAMESPACE_EVIDENCE')
        if evidence:
            base = Path(evidence); base.mkdir(mode=0o700, exist_ok=True)
            cls.folder = base / cls.__name__; cls.folder.mkdir(mode=0o700)
        else:
            cls.temporary = tempfile.TemporaryDirectory(prefix='hia-artifact-namespace-')
            cls.folder = Path(cls.temporary.name)
        cls.serial = 0
        if cold:
            from tools.build_hia_artifact_namespace import build as build_namespace
            from tools.build_hia_artifact_publication import build as build_publication
            from tools.build_hia_request_journal import build as build_request
            from tools.build_hia_execution_budget import build as build_budget
            cls.manifest = build_namespace(cls.folder / 'namespace', compiler, cold)
            app = build_publication(cls.folder / 'publication', compiler, cold)
            cls.byte_manifest = app.parent / 'build.json'
            cls.request_manifest = build_request(cls.folder / 'request', compiler, cold)
            cls.budget_manifest = build_budget(cls.folder / 'budget', compiler, cold)
            if compiler.read_bytes() != compiler_bytes or cold.read_bytes() != cold_bytes:
                raise AssertionError('namespace joint cold inputs changed')
            mode = 'MATCHING_CURRENT_SOURCE_COLD_BUILD'
        else:
            if development:
                compiler = Path(development); mode = 'DEVELOPMENT_REUSED_COMPILER'
            else:
                seed, _ = build_seed(cls.folder)
                source = (ROOT / 'examples/hia_bootstrap/selfhost.hepta').read_bytes()
                first, _ = compile_stage(cls.folder, 'B1', seed, source, image_format='seed-shared')
                compiler, _ = compile_stage(cls.folder, 'B2', first, source)
                assert first.read_bytes() == compiler.read_bytes()
                mode = 'DEVELOPMENT_B0_B1_B2'
            compiler_bytes = compiler.read_bytes()
            for label, source_name, schema, attribute in (
                ('namespace', 'artifact_namespace', SCHEMA, 'manifest'),
                ('request', 'request_journal', 'hepta.hia.request-journal-native.v1', 'request_manifest'),
                ('budget', 'execution_budget', 'hepta.hia.execution-budget-native.v1', 'budget_manifest')):
                source = (ROOT / 'examples/hia_bootstrap' / (source_name + '.hepta')).read_bytes()
                image, receipt = compile_stage(cls.folder, label, compiler, source)
                manifest = {'schema': schema, 'source_sha256': sha256(source).hexdigest(),
                    'image_path': image.name, 'image_sha256': sha256(image.read_bytes()).hexdigest(),
                    'compiler_sha256': sha256(compiler_bytes).hexdigest()}
                path = cls.folder / (label + '-manifest.json'); path.write_text(json.dumps(manifest, indent=2) + '\n')
                setattr(cls, attribute, path)
            from tools.build_hia_artifact_publication import SOURCES, OPERATIONS
            from tools.generate_hia_artifact_publication import MAGIC
            from tools.hia_selfhost_contract import PROFILE
            images = {}
            for label, name in zip(('policy', 'packer', 'sha256'), SOURCES[:3]):
                images[label], _ = compile_stage(cls.folder, label, compiler, (ROOT / name).read_bytes())
            policy, digest = images['policy'].read_bytes(), images['sha256'].read_bytes()
            frame = struct.pack('<3Q', MAGIC, len(policy), len(digest)) + policy + digest
            packed, output = invoke(cls.folder, 'publication-pack', images['packer'], frame)
            count = packed.get('core_u32')
            assert packed.get('status') == 'returned' and type(count) is int and 0 < count <= len(output)
            app = cls.folder / 'hia-artifact'; app.write_bytes(output[:count]); app.chmod(0o700)
            cls.byte_manifest = cls.folder / 'publication-build.json'
            cls.byte_manifest.write_text(json.dumps({
                'schema': 'hepta.hia.artifact-publication-build.v1', 'status': 'NATIVE_ARTIFACT_PUBLICATION_BUILT',
                'profile': PROFILE, 'source_manifest': sources, 'operations': OPERATIONS,
                'source_sha256': {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in SOURCES},
                'executable_path': app.name, 'executable_sha256': sha256(app.read_bytes()).hexdigest(),
                'development_only': True, 'matching_current_source_cold_qualified': False,
                'compiler_sha256': sha256(compiler_bytes).hexdigest(),
            }, indent=2) + '\n')
        manifest = json.loads(cls.manifest.read_bytes())
        image = cls.manifest.parent / manifest['image_path']
        cls.image = NativeArtifactNamespaceImage(image.read_bytes(), manifest['image_sha256'])
        if current_sources() != sources:
            raise AssertionError('namespace fixture source identity changed')
        (cls.folder / 'joint-build.json').write_text(json.dumps({
            'mode': mode, 'source_manifest': sources, 'compiler_sha256': sha256(compiler_bytes).hexdigest(),
            'namespace_manifest': str(cls.manifest), 'byte_manifest': str(cls.byte_manifest),
            'request_manifest': str(cls.request_manifest), 'budget_manifest': str(cls.budget_manifest),
            'matching_current_source_cold_qualified': bool(cold),
            'all_selected_dependencies_share_cold_report': bool(cold),
        }, indent=2) + '\n')

    @classmethod
    def tearDownClass(cls):
        if cls.temporary is not None: cls.temporary.cleanup()

    def setUp(self):
        type(self).serial += 1
        self.case = self.folder / ('case-' + str(type(self).serial)); self.case.mkdir(mode=0o700)

    def selected(self, *, joint=False):
        return patch.dict(os.environ, {SELECTOR: str(self.manifest), BYTE_SELECTOR: str(self.byte_manifest),
            'HEPTA_HIA_REQUEST_JOURNAL_MANIFEST': str(self.request_manifest) if joint else '',
            'HEPTA_HIA_EXECUTION_BUDGET_MANIFEST': str(self.budget_manifest) if joint else ''})

    @contextmanager
    def old_namespace_forbidden(self, *, hashing=True, payload_io=True):
        from hepta import hia_agent_store as source
        with ExitStack() as stack:
            for name in ('put', 'json', 'get', 'get_json', 'resolve_uri', 'profile', 'check_profile', 'transaction'):
                stack.enter_context(patch.object(source.AgentStore, '_' + name + '_reference',
                    side_effect=AssertionError('selected namespace entered original ' + name)))
            stack.enter_context(patch.object(source.AgentStore, '_ref', side_effect=AssertionError('host ref policy')))
            if hashing:
                stack.enter_context(patch.object(source, 'sha256', side_effect=AssertionError('host artifact hash')))
            if payload_io:
                stack.enter_context(patch.object(source, 'stable_read', side_effect=AssertionError('host artifact bytes')))
            yield

    def store(self, suffix='state'):
        from hepta.hia_agent_store import AgentStore
        store = AgentStore(self.case / suffix)
        self.addCleanup(store.close)
        return store

    def test_actual_all_seven_apis_dedup_restart_and_original_namespace_authority(self):
        from hepta.hia_agent_store import AgentStore, AgentRejected
        with self.selected(), self.old_namespace_forbidden():
            store = self.store()
            for payload in (b'', b'\x00native\xff', bytes(range(256)) * 1025):
                ref = store.put(payload, 'input', {'雪': len(payload)})
                self.assertEqual(store.get(ref, kind='input'), (payload, {'雪': len(payload)}))
                self.assertEqual(store.put(payload, 'input', {'雪': len(payload)}), ref)
                self.assertEqual(store.resolve_uri(ref['uri']), ref)
            value = {'ratio': 1.25, 'items': [None, True, '雪']}
            ref = store.json(value, 'data', [1, 2])
            self.assertEqual(store.get_json(ref, kind='data'), (value, [1, 2]))
            profile, artifact = store.profile('hia-test-雪', value)
            self.assertEqual(store.check_profile(profile, profile), value)
            self.assertEqual(store.profile('hia-test-雪', value), (profile, artifact))
            with AgentStoreClose(AgentStore(store.root)) as reopened:
                self.assertEqual(reopened.get_json(ref), (value, [1, 2]))
                self.assertEqual(reopened.check_profile(profile, profile), value)
            foreign = self.store('foreign')
            with self.assertRaises(AgentRejected) as caught: foreign.get(ref)
            self.assertEqual(caught.exception.code, 'E_HIA_ARTIFACT_IDENTITY')

    def test_actual_metadata_is_frozen_once_and_get_checks_the_content_binding(self):
        from hepta.hia_agent_store import AgentRejected
        with self.selected(), self.old_namespace_forbidden():
            store = self.store(); owner = store.artifact_namespace
            metadata = {'label': ['before']}; original = owner._invoke
            def mutate(operation, name, **kwargs):
                result = original(operation, name, **kwargs)
                if name == 'store-hash': metadata['label'][0] = 'after'
                return result
            with patch.object(owner, '_invoke', side_effect=mutate):
                ref = store.put(b'captured', 'input', metadata)
            self.assertEqual(store.get(ref)[1], {'label': ['before']})
            store.db.execute('UPDATE main.artifacts SET metadata=? WHERE id=?', (wire({'label': ['tampered']}).decode(), ref['id']))
            with self.assertRaises(AgentRejected) as caught: store.get(ref)
            self.assertEqual(caught.exception.code, 'E_HIA_ARTIFACT_CORRUPT')

    def test_actual_main_qualified_rows_ignore_temp_artifacts_and_profiles(self):
        with self.selected(), self.old_namespace_forbidden():
            store = self.store()
            store.db.execute('CREATE TEMP TABLE artifacts(id,sha256,uri,kind,metadata,content_key)')
            store.db.execute('CREATE TEMP TABLE profiles(id,sha256,artifact)')
            ref = store.put(b'main only', 'input')
            profile, artifact = store.profile('main-profile', {'mode': 'main'})
            self.assertEqual(store.get(ref)[0], b'main only')
            self.assertEqual(store.resolve_uri(ref['uri']), ref)
            self.assertEqual(store.check_profile(profile, profile), {'mode': 'main'})
            self.assertEqual(store.db.execute('SELECT count(*) FROM temp.artifacts').fetchone()[0], 0)
            self.assertEqual(store.db.execute('SELECT count(*) FROM temp.profiles').fetchone()[0], 0)
            self.assertEqual(store.db.execute('SELECT count(*) FROM main.artifacts').fetchone()[0], 2)
            self.assertEqual(store.db.execute('SELECT count(*) FROM main.profiles').fetchone()[0], 1)

    def test_actual_profile_row_cannot_substitute_another_artifact_or_kind(self):
        from hepta.hia_agent_store import AgentRejected
        with self.selected(), self.old_namespace_forbidden():
            store = self.store()
            profile, artifact = store.profile('profile', {'value': 1})
            other = store.json({'value': 2}, 'profile')
            store.db.execute('UPDATE main.profiles SET artifact=?', (wire(other).decode(),))
            with self.assertRaises(AgentRejected) as caught: store.check_profile(profile, profile)
            self.assertEqual(caught.exception.code, 'E_HIA_PROFILE_AUTHORITY')
            store.db.execute('UPDATE main.profiles SET artifact=?', (wire(artifact).decode(),))
            store.db.execute('UPDATE main.artifacts SET kind=? WHERE id=?', ('input', artifact['id']))
            with self.assertRaises(AgentRejected) as caught: store.check_profile(profile, profile)
            self.assertEqual(caught.exception.code, 'E_HIA_ARTIFACT_AUTHORITY')

    def test_actual_concurrent_dedup_returns_one_exact_issued_reference(self):
        from hepta.hia_agent_store import AgentStore
        with self.selected(), self.old_namespace_forbidden():
            first = self.store(); second = AgentStore(first.root); self.addCleanup(second.close)
            barrier = threading.Barrier(2)
            def hook(owner):
                original = owner._row_outcome
                def observe(operation, receipt, row):
                    if receipt.action == 3 and row is None: barrier.wait(10)
                    return original(operation, receipt, row)
                return observe
            with patch.object(first.artifact_namespace, '_row_outcome', side_effect=hook(first.artifact_namespace)), \
                    patch.object(second.artifact_namespace, '_row_outcome', side_effect=hook(second.artifact_namespace)), \
                    ThreadPoolExecutor(max_workers=2) as workers:
                futures = [workers.submit(store.put, b'concurrent', 'input', {'same': True}) for store in (first, second)]
                refs = [future.result(timeout=30) for future in futures]
            self.assertEqual(refs[0], refs[1])
            self.assertEqual(first.db.execute('SELECT count(*) FROM main.artifacts').fetchone()[0], 1)
            self.assertEqual(sorted(path.name for path in first.artifacts.iterdir()), [sha256(b'concurrent').hexdigest()])

    def test_actual_original_transaction_rollback_and_commit_keep_namespace_rows_atomic(self):
        from hepta.hia_agent_store import AgentRejected
        with self.selected(), self.old_namespace_forbidden():
            store = self.store()
            with self.assertRaisesRegex(ValueError, 'original callback error'):
                with store.transaction():
                    rolled = store.put(b'rolled-back row', 'input')
                    self.assertEqual(store.get(rolled)[0], b'rolled-back row')
                    raise ValueError('original callback error')
            self.assertFalse(store.db.in_transaction)
            self.assertEqual(store.db.execute('SELECT count(*) FROM main.artifacts').fetchone()[0], 0)
            self.assertTrue((store.artifacts / rolled['sha256']).is_file())
            with self.assertRaises(AgentRejected): store.get(rolled)
            with store.transaction():
                committed = store.put(b'committed', 'input')
            self.assertEqual(store.get(committed)[0], b'committed')
            self.assertEqual(store.artifact_namespace.state.snapshot()['legacy_scope_phase'], 0)

    def test_machine_matches_independent_vm_states_and_rejects_replayed_launches(self):
        protocol = Protocol(VM())
        protocol.put(data=b'raw protocol', kind='input', metadata={'x': 3})
        machine = Machine(self.image)
        for raw, expected in protocol.observations:
            self.assertEqual(machine.call(raw), expected)
        current = Protocol(Machine(self.image))
        current.begin(1, data=b'claimed', kind='input')
        token = current.words[6]
        current.send(2, token=token)
        before = current.observations[-1][1][2]
        current.send(2, token=token)
        self.assertEqual(current.status, 11)
        self.assertEqual(current.observations[-1][1][2], before)
        current.send(4, token=token)
        self.assertEqual(current.status, 8)
        self.assertEqual(current.observations[-1][1][2], before)

    def test_actual_native_bad_tokens_and_corrupted_state_emit_no_effect_claim(self):
        protocol = Protocol(Machine(self.image))
        protocol.begin(1, data=b'claimed', kind='input')
        valid = packet(2, protocol.sequence, operation=1, token=protocol.words[6])
        original = bytes(protocol.engine.state.raw)
        for word in (2, 3, 4, 6, 8, 10, 11, 12, 14, 15, 16, 31):
            raw = bytearray(valid)
            value = struct.unpack_from('<Q', raw, word * 8)[0]
            struct.pack_into('<Q', raw, word * 8, value ^ 1)
            count, returned, _ = protocol.engine.call(bytes(raw))
            self.assertGreaterEqual(count, 32)
            self.assertIn(struct.unpack('<4Q', returned[:32])[1], (8, 11))
            self.assertEqual(protocol.engine.state.raw, original)
        for size in (0, 1, 255):
            count, _, _ = protocol.engine.call(valid[:size])
            self.assertEqual(count, 4294967293)
            self.assertEqual(protocol.engine.state.raw, original)
        protocol.engine.state[620] = bytes([protocol.engine.state.raw[620] ^ 1])
        corrupted = protocol.engine.state.raw
        count, returned, _ = protocol.engine.call(valid)
        self.assertEqual((count, struct.unpack('<4Q', returned)), (32, (RESULT_MAGIC, 8, 0, 0)))
        self.assertEqual(protocol.engine.state.raw, corrupted)

    def test_actual_byte_admission_can_cancel_only_before_any_effect(self):
        from hepta.hia_agent_store import AgentRejected
        with self.selected(), self.old_namespace_forbidden():
            store = self.store(); owner = store.artifact_namespace
            with patch('hepta.hia_agent_store._native_artifact_admission',
                    side_effect=AgentRejected('E_HIA_ARTIFACT_NATIVE_CUSTODY', 'before first launch')), \
                    patch.object(owner, '_invoke', side_effect=AssertionError('effect entered')):
                with self.assertRaises(AgentRejected) as caught: store.put(b'input', 'input')
            self.assertEqual(caught.exception.code, 'E_HIA_ARTIFACT_NATIVE_CUSTODY')
            self.assertEqual((owner.state.receipt.phase, owner.state.receipt.words[39]), (4, 0))
            self.assertIsNone(owner.state.fenced)
            ref = store.put(b'new admitted operation', 'input')
            self.assertEqual(store.get(ref)[0], b'new admitted operation')

    def test_actual_read_refusal_is_known_but_mutating_refusal_stays_unknown(self):
        from hepta.hia_agent_store import AgentRejected
        import hepta.artifact_publication_native as byte_owner
        with self.selected(), self.old_namespace_forbidden():
            store = self.store()
            ref = store.put(b'authentic', 'input')
            path = store.artifacts / ref['sha256']; path.chmod(0o600); path.write_bytes(b'changed!')
            with self.assertRaises(AgentRejected) as caught: store.get(ref)
            self.assertEqual(caught.exception.code, 'E_HIA_ARTIFACT_CORRUPT')
            self.assertIsNone(store.artifact_namespace.state.fenced)
            fresh = store.put(b'other input', 'input')
            self.assertEqual(store.get(fresh)[0], b'other input')
            old_run = byte_owner.subprocess.run
            calls, trace = [], self.case / 'directory-fsync-failure.trace'
            # The publisher runs with PATH empty; strace itself is selected
            # before the fixed executable is launched, by its real host path.
            import shutil
            tracer = shutil.which('strace')
            self.assertIsNotNone(tracer, 'actual ptrace fault prerequisite is required')
            def absolute_failing(argv, *args, **kwargs):
                calls.append(argv[1])
                if argv[1] == 'store-put':
                    argv = [tracer, '-o', str(trace), '-e', 'trace=fsync,linkat,unlinkat',
                            '-e', 'inject=fsync:error=EIO:when=2', *argv]
                return old_run(argv, *args, **kwargs)
            with patch.object(byte_owner.subprocess, 'run', side_effect=absolute_failing):
                with self.assertRaises(ArtifactNamespaceUnknown): store.put(b'unconfirmed directory fsync', 'input')
                before = list(calls)
                with self.assertRaises(ArtifactNamespaceUnknown): store.put(b'no automatic replay', 'input')
                self.assertEqual(calls, before)
            self.assertIn('EIO', trace.read_text())
            self.assertTrue((store.artifacts / sha256(b'unconfirmed directory fsync').hexdigest()).is_file())
            self.assertEqual(store.db.execute('SELECT count(*) FROM main.artifacts').fetchone()[0], 2)
            self.assertEqual((store.artifact_namespace.state.receipt.phase,
                              store.artifact_namespace.state.receipt.action), (2, 4))

    def test_actual_publisher_return_loss_retains_file_without_index_or_replay(self):
        from hepta.hia_artifact_namespace_native import NativeArtifactNamespaceStore
        with self.selected(), self.old_namespace_forbidden():
            store = self.store(); owner = store.artifact_namespace
            with interrupt_opcode(NativeArtifactNamespaceStore._invoke.__code__, 'RETURN_VALUE',
                    predicate=lambda frame: frame.f_locals.get('name') == 'store-put') as observed:
                with self.assertRaises(KeyboardInterrupt): store.put(b'lost publisher ACK', 'input')
            self.assertEqual(len(observed), 1)
            self.assertEqual((owner.state.receipt.phase, owner.state.receipt.action), (2, 4))
            self.assertEqual(store.db.execute('SELECT count(*) FROM main.artifacts').fetchone()[0], 0)
            self.assertEqual((store.artifacts / sha256(b'lost publisher ACK').hexdigest()).read_bytes(), b'lost publisher ACK')
            with patch.object(owner, '_invoke', side_effect=AssertionError('effect repeated')):
                with self.assertRaises(ArtifactNamespaceUnknown): store.put(b'lost publisher ACK', 'input')

    def test_actual_sql_insert_return_loss_retains_committed_row_and_pending_owner(self):
        from hepta.hia_artifact_namespace_native import NativeArtifactNamespaceStore
        with self.selected(), self.old_namespace_forbidden():
            store = self.store(); owner = store.artifact_namespace
            with interrupt_opcode(NativeArtifactNamespaceStore._execute.__code__, 'RETURN_VALUE',
                    predicate=lambda frame: frame.f_locals.get('statement', '').startswith('INSERT OR IGNORE INTO main.artifacts')):
                with self.assertRaises(KeyboardInterrupt): store.put(b'lost SQL ACK', 'input')
            self.assertEqual(store.db.execute('SELECT count(*) FROM main.artifacts').fetchone()[0], 1)
            self.assertEqual((owner.state.receipt.phase, owner.state.receipt.action), (2, 5))
            with patch.object(owner, '_execute', side_effect=AssertionError('SQL repeated')):
                with self.assertRaises(ArtifactNamespaceUnknown): store.put(b'lost SQL ACK', 'input')

    def test_actual_native_receipt_store_loss_cannot_restart_the_completed_operation(self):
        with self.selected(), self.old_namespace_forbidden():
            store = self.store(); owner = store.artifact_namespace
            with interrupt_opcode(NamespaceState.call.__code__, 'STORE_ATTR', 'receipt',
                    predicate=lambda frame: frame.f_locals.get('event') == 3 and frame.f_locals['receipt'].phase == 3):
                with self.assertRaises(KeyboardInterrupt): store.put(b'native receipt lost', 'input')
            words = struct.unpack('<64Q', ctypes.string_at(owner.state.buffer, 512))
            self.assertEqual(words[3], 3)
            self.assertIsNotNone(owner.state.fenced)
            self.assertEqual(store.db.execute('SELECT count(*) FROM main.artifacts').fetchone()[0], 1)
            with patch.object(owner, '_invoke', side_effect=AssertionError('operation repeated')):
                with self.assertRaises(ArtifactNamespaceUnknown): store.put(b'native receipt lost', 'input')

    def test_actual_legacy_scope_lost_begin_commit_and_rollback_never_repeat(self):
        from hepta.hia_artifact_namespace_native import NativeArtifactNamespaceStore
        for statement in ('BEGIN IMMEDIATE', 'COMMIT', 'ROLLBACK'):
            with self.subTest(statement=statement), self.selected(), self.old_namespace_forbidden():
                store = self.store(statement.split()[0].lower()); owner = store.artifact_namespace
                calls, original = [], owner._execute_scope
                def counted(sql):
                    calls.append(sql); return original(sql)
                with patch.object(owner, '_execute_scope', side_effect=counted), \
                        interrupt_opcode(NativeArtifactNamespaceStore._execute_scope.__code__, 'RETURN_VALUE',
                            predicate=lambda frame: frame.f_locals.get('statement') == statement):
                    with self.assertRaises(ArtifactNamespaceUnknown):
                        with store.transaction():
                            store.put(b'scope contents', 'input')
                            if statement == 'ROLLBACK': raise ValueError('ordinary callback refusal')
                self.assertEqual(calls.count('BEGIN IMMEDIATE'), 1)
                self.assertLessEqual(calls.count('COMMIT'), 1)
                self.assertLessEqual(calls.count('ROLLBACK'), 1)
                if statement == 'COMMIT':
                    self.assertEqual(store.db.execute('SELECT count(*) FROM main.artifacts').fetchone()[0], 1)
                else:
                    self.assertEqual(store.db.execute('SELECT count(*) FROM main.artifacts').fetchone()[0], 0)
                self.assertFalse(store.db.in_transaction)
                before = list(calls)
                with patch.object(owner, '_execute_scope', side_effect=counted):
                    with self.assertRaises(ArtifactNamespaceUnknown):
                        with store.transaction(): pass
                self.assertEqual(calls, before)

    def test_actual_scope_cleanup_claim_precedes_fence_store_and_cannot_rebind(self):
        with self.selected(), self.old_namespace_forbidden():
            store = self.store(); owner = store.artifact_namespace
            calls, original = [], owner._execute_scope
            def unknown_rollback(sql):
                calls.append(sql)
                if sql == 'ROLLBACK': raise RuntimeError('rollback transport failed before effect')
                return original(sql)
            with patch.object(owner, '_execute_scope', side_effect=unknown_rollback), \
                    interrupt_opcode(NamespaceState.fence.__code__, 'STORE_ATTR', 'fenced'):
                with self.assertRaises(ArtifactNamespaceUnknown):
                    with store.transaction():
                        store.put(b'uncertain scope', 'input')
                        raise ValueError('original callback refusal')
            words = struct.unpack('<64Q', ctypes.string_at(owner.state.buffer, 512))
            self.assertEqual(calls.count('ROLLBACK'), 1)
            self.assertEqual(words[47], words[41])
            self.assertTrue(store.db.in_transaction)
            self.assertIsNone(owner.state.fenced)
            with patch.object(owner, '_execute_scope', side_effect=AssertionError('rollback repeated')):
                with self.assertRaises(ArtifactNamespaceUnknown): owner._scope_failed(owner._scope, RuntimeError('nested cleanup'))
            self.assertEqual(store.db.execute('SELECT count(*) FROM main.artifacts').fetchone()[0], 1)
            with self.assertRaises(ArtifactNamespaceUnknown): store.put(b'cannot borrow pending scope', 'input')

    def test_actual_reentry_is_refused_without_overwriting_the_outer_operation(self):
        with self.selected(), self.old_namespace_forbidden():
            store = self.store(); owner = store.artifact_namespace
            original, observed = owner._invoke, []
            def reenter(operation, name, **kwargs):
                result = original(operation, name, **kwargs)
                if name == 'store-put':
                    with self.assertRaises(ArtifactNamespaceUnknown): store.put(b'nested', 'input')
                    observed.append(owner._operation is operation)
                return result
            with patch.object(owner, '_invoke', side_effect=reenter): ref = store.put(b'outer', 'input')
            self.assertEqual(observed, [True])
            self.assertEqual(store.get(ref)[0], b'outer')
            self.assertEqual(store.db.execute('SELECT count(*) FROM main.artifacts').fetchone()[0], 1)

    def test_actual_atomic_request_and_legacy_scope_share_lock_order_and_revoke_capability(self):
        with self.selected(joint=True), self.old_namespace_forbidden(hashing=False, payload_io=False):
            store = self.store(); journal = store.request_journal
            self.assertIs(journal.lock, store.lock)
            ticket = journal.admit('hia_adopt', 'd' * 64, 'namespace-lock', lambda *_: None)
            entered, released, legacy_entered = threading.Event(), threading.Event(), threading.Event()
            capabilities, refs = [], []
            def invoke(connection):
                capabilities.append(connection); entered.set()
                if not released.wait(10): raise AssertionError('missing test release')
                ref = store.put(b'atomic', 'input', _connection=connection); refs.append(ref)
                connection.execute('INSERT INTO slots VALUES (?,?,?,?,?)', ('slot', 'context', '1', '1', 'a' * 64))
                return {'artifact': ref}
            def ordinary():
                with store.transaction():
                    legacy_entered.set()
                    refs.append(store.put(b'ordinary', 'input'))
            with ThreadPoolExecutor(max_workers=2) as workers:
                atomic = workers.submit(ticket.atomic, invoke, lambda result: {'status': 'completed', 'result': result})
                self.assertTrue(entered.wait(10))
                legacy = workers.submit(ordinary)
                try:
                    self.assertFalse(legacy_entered.wait(.15))
                finally:
                    released.set()
                atomic.result(timeout=30); legacy.result(timeout=30)
            self.assertTrue(legacy_entered.is_set())
            self.assertEqual(store.db.execute('SELECT count(*) FROM main.artifacts').fetchone()[0], 2)
            self.assertEqual(store.db.execute('SELECT count(*) FROM main.slots').fetchone()[0], 1)
            self.assertEqual(store.db.execute('SELECT state FROM main.requests').fetchone()[0], 'completed')
            with self.assertRaises(RuntimeError): store.put(b'stale capability', 'input', _connection=capabilities[0])
            self.assertEqual(store.db.execute('SELECT count(*) FROM main.artifacts').fetchone()[0], 2)

    def test_original_agent_tools_and_campaign_with_all_three_owners_and_no_namespace_reference(self):
        from hepta.hia_agent_service import HIAAgentService
        from hepta import hia_execution_budget as budget_reference
        classes = ('tests.test_hia_agent_native_tools.ArtifactContractTests',
                   'tests.test_hia_agent_native_tools.CandidateAndVerificationTests',
                   'tests.test_hia_agent_native_tools.MachinePlanTests',
                   'tests.test_hia_agent_native_tools.NativeLifecycleTests',
                   'tests.test_hia_agent_native_tools.AgentStoreDirectoryPermissionTests',
                   'tests.test_hia_agent_native_campaign.QualificationCampaignTests')
        cases = [case for name in classes for case in unittest.defaultTestLoader.loadTestsFromName(name)]
        stream = io.StringIO()
        with self.selected(joint=True), self.old_namespace_forbidden(hashing=False, payload_io=False), ExitStack() as stack:
            stack.enter_context(patch.object(HIAAgentService, '_call_reference', side_effect=AssertionError('old request policy')))
            for cls in (budget_reference._ReferenceExecutionBudgetStore, budget_reference._ReferenceBudgetClaim):
                stack.enter_context(patch.object(cls, '__init__', side_effect=AssertionError('old budget policy')))
            result = unittest.TextTestRunner(stream=stream, verbosity=2).run(unittest.TestSuite(cases))
        (self.case / 'original-suite.log').write_text(stream.getvalue())
        (self.case / 'original-suite.json').write_text(json.dumps({'tests_run': result.testsRun,
            'failures': len(result.failures), 'errors': len(result.errors), 'skipped': len(result.skipped),
            'classes': classes, 'original_namespace_request_and_budget_policy_forbidden': True}, indent=2) + '\n')
        self.assertTrue(result.wasSuccessful(), stream.getvalue())
        self.assertEqual(result.skipped, [], stream.getvalue())

    def test_actual_original_payload_quota_and_invalid_payload_precedes_other_inputs(self):
        from hepta.hia_agent_store import AgentRejected
        with self.selected(), self.old_namespace_forbidden():
            store = self.store(); owner = store.artifact_namespace
            payload = b'x' * (64 << 20)
            ref = store.put(payload, 'input')
            self.assertEqual(store.get(ref)[0], payload)
            rejected = payload + b'x'
            with patch.object(owner, '_invoke', side_effect=AssertionError('oversized payload launched')):
                for invalid in (rejected, True, bytearray(b'not exact bytes')):
                    with self.assertRaises(AgentRejected) as caught:
                        store.put(invalid, '\ud800', object())
                    self.assertEqual(caught.exception.code, 'E_HIA_ARTIFACT_LIMIT')
                    self.assertEqual(owner._operation.inputs.data, b'')
            self.assertEqual(store.db.execute('SELECT count(*) FROM main.artifacts').fetchone()[0], 1)

    def test_actual_unknown_namespace_effect_rolls_back_request_rows_and_keeps_original_intent(self):
        from hepta.hia_artifact_namespace_native import NativeArtifactNamespaceStore
        with self.selected(joint=True), self.old_namespace_forbidden(hashing=False, payload_io=False):
            store = self.store(); ticket = store.request_journal.admit('hia_adopt', 'e' * 64, 'unknown-artifact', lambda *_: None)
            retained = []
            def invoke(connection):
                retained.append(connection)
                connection.execute('INSERT INTO slots VALUES (?,?,?,?,?)', ('uncertain-slot', 'context', '1', '1', 'a' * 64))
                return {'artifact': store.put(b'unknown scoped publication', 'input', _connection=connection)}
            with interrupt_opcode(NativeArtifactNamespaceStore._invoke.__code__, 'RETURN_VALUE',
                    predicate=lambda frame: frame.f_locals.get('name') == 'store-put'):
                with self.assertRaises(RuntimeError): ticket.atomic(invoke, lambda result: {'status': 'completed', 'result': result})
            self.assertEqual(tuple(store.db.execute('SELECT state,response FROM main.requests').fetchone()), ('running', None))
            self.assertEqual(store.db.execute('SELECT count(*) FROM main.artifacts').fetchone()[0], 0)
            self.assertEqual(store.db.execute('SELECT count(*) FROM main.slots').fetchone()[0], 0)
            self.assertTrue((store.artifacts / sha256(b'unknown scoped publication').hexdigest()).is_file())
            owner = store.artifact_namespace
            self.assertEqual((owner.state.receipt.phase, owner.state.receipt.action), (2, 4))
            with patch.object(owner, '_invoke', side_effect=AssertionError('unknown effect was replayed')):
                with self.assertRaises(RuntimeError): store.put(b'unknown scoped publication', 'input', _connection=retained[0])
                with self.assertRaises(ArtifactNamespaceUnknown): store.put(b'unknown scoped publication', 'input')

    def test_actual_installed_wheel_namespace_request_atomicity_and_restart_without_authoring(self):
        import shutil
        from hepta.hia_agent_contract import DISCOVERY_FILES, NATIVE_SOURCE_FILES, SOURCE_BUILD_FILES, COMPILER_BUILD_FILES, PUBLICATION_BUILD_FILES, BACKEND_BUILD_FILES, EMITTER_BUILD_FILES, BYTE_WRAPPER_BUILD_FILES, MACHINE_OBJECT_BUILD_FILES, EXECUTION_OBSERVATION_BUILD_FILES, CONTINUATION_BUILD_FILES
        source = self.case / 'source'; source.mkdir()
        shutil.copytree(ROOT / 'hepta', source / 'hepta', ignore=shutil.ignore_patterns('__pycache__'))
        resources = tuple('docs/' + name for name in DISCOVERY_FILES) + NATIVE_SOURCE_FILES + SOURCE_BUILD_FILES + COMPILER_BUILD_FILES + PUBLICATION_BUILD_FILES + BACKEND_BUILD_FILES + EMITTER_BUILD_FILES + BYTE_WRAPPER_BUILD_FILES + MACHINE_OBJECT_BUILD_FILES + EXECUTION_OBSERVATION_BUILD_FILES + CONTINUATION_BUILD_FILES
        for name in (*resources, 'setup.py', 'pyproject.toml', 'MANIFEST.in'):
            target = source / name; target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        packaging = os.environ.get('HEPTA_HIA_TEST_PACKAGING_PYTHON', sys.executable)
        wheels, installed = self.case / 'wheels', self.case / 'installed'
        built = subprocess.run([packaging, '-B', '-m', 'pip', 'wheel', '--no-deps', '--no-index',
            '--no-build-isolation', '--wheel-dir', str(wheels), str(source)], cwd=self.case,
            capture_output=True, timeout=120)
        (self.case / 'wheel-build.log').write_bytes(built.stdout + built.stderr)
        self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
        wheel, = wheels.glob('*.whl')
        copied = subprocess.run([packaging, '-B', '-m', 'pip', 'install', '--no-deps', '--no-index',
            '--target', str(installed), str(wheel)], cwd=self.case, capture_output=True, timeout=120)
        (self.case / 'wheel-install.log').write_bytes(copied.stdout + copied.stderr)
        self.assertEqual(copied.returncode, 0, copied.stdout + copied.stderr)
        program = r'''import importlib.abc,json,os,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
class NoAuthoring(importlib.abc.MetaPathFinder):
    def find_spec(self,fullname,path=None,target=None):
        if fullname=='tools' or fullname.startswith('tools.'):
            raise AssertionError('installed namespace imported authoring code')
sys.meta_path.insert(0,NoAuthoring())
from hepta.hia_agent_service import HIAAgentService
from hepta.hia_agent_store import AgentStore,wire
from hepta.hia_artifact_namespace_native import SOURCE,SELECTOR,BYTE_SELECTOR
from hepta import hia_execution_budget as reference
assert Path(sys.argv[1]) in SOURCE.parents,SOURCE
def forbidden(*args,**kwargs):raise AssertionError('installed owner entered original namespace/request/budget policy')
for name in ('put','json','get','get_json','resolve_uri','profile','check_profile','transaction'):
    setattr(AgentStore,'_'+name+'_reference',forbidden)
AgentStore._ref=forbidden
HIAAgentService._call_reference=forbidden
reference._ReferenceExecutionBudgetStore.__init__=forbidden
reference._ReferenceBudgetClaim.__init__=forbidden
os.environ[SELECTOR]=sys.argv[2]
os.environ[BYTE_SELECTOR]=sys.argv[3]
os.environ['HEPTA_HIA_REQUEST_JOURNAL_MANIFEST']=sys.argv[4]
os.environ['HEPTA_HIA_EXECUTION_BUDGET_MANIFEST']=sys.argv[5]
service=HIAAgentService(sys.argv[6])
args={'catalog_sha256':service.catalog_sha256,'request_key':'installed-artifact',
    'artifact_profile':service.profiles['artifact'],'source':{'kind':'utf8','text':'installed native namespace'}}
response=service.call('hia_artifact',args)
assert response['status']=='completed',response
assert service.store.get(response['result']['artifact'])[0]==b'installed native namespace'
service._hia_artifact=forbidden
assert service.call('hia_artifact',args)==response
ticket=service.store.request_journal.admit('hia_adopt','d'*64,'installed-atomic',lambda *args:None)
retained=[]
def invoke(connection):
    retained.append(connection)
    ref=service.store.json({'scope':'atomic'},'input',_connection=connection)
    connection.execute('INSERT INTO slots VALUES (?,?,?,?,?)',('installed-slot','context','1','1','a'*64))
    return {'status':'completed','result':{'artifact':ref}}
atomic=ticket.atomic(invoke,lambda value:value)
assert service.store.db.execute('SELECT generation FROM main.slots').fetchone()[0]=='1'
try:service.store.put(b'revoked','input',_connection=retained[0])
except RuntimeError:pass
else:raise AssertionError('installed effect capability was not revoked')
service.close()
service=HIAAgentService(sys.argv[6]);service._hia_artifact=forbidden
assert service.call('hia_artifact',args)==response
def validate(raw,connection):
    decoded=json.loads(raw)
    assert service.store.get_json(decoded['result']['artifact'],kind='input',_connection=connection)[0]=={'scope':'atomic'}
replay=service.store.request_journal.admit('hia_adopt','d'*64,'installed-atomic',validate)
assert replay.replay_bytes==wire(atomic)
assert not any(name=='tools' or name.startswith('tools.') for name in sys.modules)
service.close()
print(json.dumps({'artifact_response':response,'atomic_response':atomic,'installed_source':str(SOURCE),
    'same_original_journal_restarted':True,'source_custody_checked':True,
    'authoring_imported':False,'reference_called':False},sort_keys=True))
'''
        child = subprocess.run([sys.executable, '-I', '-S', '-B', '-c', program, str(installed),
            str(self.manifest), str(self.byte_manifest), str(self.request_manifest),
            str(self.budget_manifest), str(self.case / 'installed-state')],
            cwd=self.case, capture_output=True, text=True, timeout=120)
        (self.case / 'actual.stdout').write_text(child.stdout); (self.case / 'actual.stderr').write_text(child.stderr)
        self.assertEqual(child.returncode, 0, child.stderr)
        self.assertTrue(json.loads(child.stdout)['source_custody_checked'])


class AgentStoreClose:
    def __init__(self, store): self.store = store
    def __enter__(self): return self.store
    def __exit__(self, *_): self.store.close()


if __name__ == '__main__':
    unittest.main()
