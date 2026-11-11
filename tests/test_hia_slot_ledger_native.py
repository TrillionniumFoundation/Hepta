"""Independent ledger protocol and real same-WAL/native transaction controls."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, contextmanager
import ctypes
import dis
from functools import lru_cache
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
import threading
import unittest
from unittest.mock import patch

from hepta.hia_slot_ledger_native import (SOURCE, SCHEMA, SELECTOR, REQUEST_MAGIC,
    RESULT_MAGIC, NativeSlotLedgerImage, SlotLedgerUnknown, LedgerState)

ROOT = Path(__file__).resolve().parents[1]
CAPACITY = 16384
NONCE, OFFICIAL, PRIVATE, SCOPE, SCOPE_OWNER = (11, 17), (31, 37), (41, 43), (53, 59), (61, 67)
ABSENT = (0, b'')
ABI = b'{"f":{"params":["u64"],"returns":["u64"]}}'


def wire(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()


def text_field(value):
    return 1, value.encode()


def integer(value):
    return 3, str(value).encode()


def reference(seed, payload=None):
    return {'id': 'a-' + seed * 32, 'uri': 'hia://artifacts/' + ('f' if seed != 'f' else 'e') * 32,
            'sha256': sha256(seed.encode() if payload is None else payload).hexdigest()}


def reference_field(value):
    return 2, wire(value)


def packet(event, operation, *, sequence=0, token=0, fields=(), known=0,
           scope_kind=0, epoch=0, scope=(0, 0), callback=0, connection=OFFICIAL,
           nonce=NONCE, scope_owner=SCOPE_OWNER, shape=0, count=0):
    words = [REQUEST_MAGIC, event, sequence, token, *nonce, *OFFICIAL, *connection,
        scope_kind, epoch, *scope, callback, operation, known, len(fields), shape, count,
        *scope_owner, *([0] * 10)]
    return struct.pack('<32Q', *words) + b''.join(struct.pack('<2Q', tag, len(raw)) + raw for tag, raw in fields)


@lru_cache(maxsize=1)
def vm_program(source):
    from hepta.hia_agent_assembly import assemble_program
    return assemble_program(source)


class VM:
    def __init__(self):
        self.program = vm_program(SOURCE.read_bytes())
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
    """Controlled observations; never calls the production SQL/state bridge."""
    def __init__(self, engine, operation, *, slot='slot', expected=('0', '0'),
                 candidate=None, baseline=None, retained='0', lease=None, epoch=7):
        self.engine, self.operation, self.sequence = engine, operation, 0
        self.scope = {}
        if operation in (2, 3):
            self.scope = dict(scope_kind=2, epoch=epoch, scope=SCOPE, callback=71, connection=PRIVATE)
        elif operation in (4, 6):
            self.scope = dict(scope_kind=1, epoch=epoch, scope=SCOPE)
        fields = [ABSENT] * 11
        fields[0] = text_field(slot)
        shape = count = 0
        if operation in (2, 3, 7):
            fields[2:4] = [text_field(value) for value in expected]
            shape, count = 7, 2
        if operation in (2, 3):
            fields[1] = text_field('ctx-new')
        if operation == 2:
            fields[4], fields[5], fields[10] = reference_field(candidate), reference_field(baseline), (4, ABI)
        if operation == 3:
            fields[6] = text_field(retained)
        if operation in (5, 6):
            fields[0] = text_field(lease['slot'])
            fields[7:10] = text_field(lease['id']), text_field(lease['generation']), reference_field(lease['artifact'])
            shape, count = 31, 4
        self.observations = []
        self.send(0, fields=fields, shape=shape, count=count)

    def send(self, event, *, fields=(), known=0, token=0, **changes):
        raw = packet(event, self.operation, sequence=0 if event == 90 else self.sequence,
            fields=fields, known=known, token=token, **(self.scope | changes))
        count, returned, state = self.engine.call(raw)
        magic, status, sequence, extent = struct.unpack('<4Q', returned[:32])
        assert magic == RESULT_MAGIC and count == 32 + extent and returned[32:] == state[:extent]
        assert extent >= 4096, (status, extent)
        self.observations.append((raw, returned))
        self.sequence, self.status = sequence, status
        self.words, self.bytes = struct.unpack('<64Q', returned[32:544]), returned[32:]
        return self.words
    def outcome(self, fields=(), *, known=1):
        action, token = self.words[5:7]
        self.send(2, token=token)
        assert self.status == 0 and self.words[3:7] == (2, self.operation, action, token)
        return self.send(3, fields=fields, known=known, token=token)

    def slot(self, generation='1', epoch='1', *, present=True, context='ctx-old', abi=None):
        fields = tuple(text_field(v) for v in ('slot', context, generation, epoch, abi or sha256(ABI).hexdigest()))
        return self.outcome(fields if present else (), known=int(present))

    def snapshot_rows(self, ref, generation='1', epoch='1', *, count=0):
        self.slot(generation, epoch)
        assert self.words[5] == 2
        self.outcome((reference_field(ref),))
        assert self.words[5] == 3
        self.outcome((integer(count),))

    def hash(self):
        assert self.words[5] == 17
        return self.outcome((text_field(sha256(ABI).hexdigest()), integer(len(ABI))))

    def generations(self, values):
        assert self.words[5] == 5
        token = self.words[6]
        self.send(2, token=token)
        for value in values:
            self.send(3, fields=(text_field(value),), known=1, token=token)
            assert self.status == 0 and self.words[3] == 2
        return self.send(3, token=token)

    def write_version_and_slot(self, candidate, generation, epoch):
        assert self.words[5] == 8
        self.outcome((integer(1),))
        assert self.words[5] == 11
        self.outcome((reference_field(candidate),))
        assert self.words[5] == 9
        self.outcome((integer(1),))
        assert self.words[5] == 10
        self.slot(generation, epoch, context='ctx-new')
        assert self.status == 0 and self.words[3] == 3

    def lease_row(self, lease, active=1):
        return self.outcome((*[text_field(lease[key]) for key in ('id', 'slot', 'generation')],
                             reference_field(lease['artifact']), integer(active)))

    def commit(self, *, epoch=None):
        certificate = struct.pack('<12Q', *SCOPE_OWNER,
            self.scope['epoch'] if epoch is None else epoch, *SCOPE, 0, 0, 0, 0, 0, 0, 101)
        return self.send(4, known=1, fields=((4, certificate),))


class DirectProtocol:
    """Independent opaque-handle observations, with no production bridge."""
    def __init__(self, engine, operation):
        self.engine, self.operation, self.sequence = engine, operation, 0
        self.scope = {} if operation in (8, 10) else dict(scope_kind=1, epoch=7, scope=SCOPE)
        self.send(0)

    def send(self, event, *, fields=(), known=0, token=0, **changes):
        raw = packet(event, self.operation, sequence=0 if event == 90 else self.sequence,
            fields=fields, known=known, token=token, **(self.scope | changes))
        count, returned, state = self.engine.call(raw)
        magic, self.status, self.sequence, extent = struct.unpack('<4Q', returned[:32])
        assert magic == RESULT_MAGIC and count == 32 + extent and extent == 4096
        assert returned[32:] == state[:extent]
        self.words, self.bytes = struct.unpack('<64Q', returned[32:544]), returned[32:]
        return self.words

    def outcome(self, *, predicate=None, entropy=None, void=False):
        action, token = self.words[5:7]
        old_live, consumed = self.words[21], self.words[45]
        self.send(2, token=token)
        assert self.status == 0 and self.words[3:7] == (2, self.operation, action, token)
        claimed = self.bytes
        self.send(2, token=token)
        assert self.status == 16 and self.bytes == claimed
        value = 0 if void else self.words[20] + 1 if predicate is None else int(predicate)
        result = self.send(3, known=1, token=token,
            fields=((4, struct.pack('<Q', value) if entropy is None else entropy),))
        expected_live = old_live ^ consumed
        if predicate is None and entropy is None and not void:
            expected_live |= 1 << (value - 1)
        assert self.words[21] == expected_live
        return result

    def commit(self):
        certificate = struct.pack('<12Q', *SCOPE_OWNER, 7, *SCOPE, 0, 0, 0, 0, 0, 0, 29)
        return self.send(4, known=1, fields=((4, certificate),))


def exercise_direct(test, make_engine):
    missing = DirectProtocol(make_engine(), 8)
    for expected in (100, 101):
        test.assertEqual(missing.words[5], expected); missing.outcome()
    missing.outcome(predicate=True)
    test.assertEqual((missing.status, missing.words[3], missing.words[40]), (0, 4, 1))
    lease = DirectProtocol(make_engine(), 11)
    predicates = {200: True, 202: True, 205: False, 209: False,
                  211: False, 215: False, 219: False, 224: False}
    actions = [v for v in range(200, 231) if v not in (212, 216, 220, 225)] + [241, 231]
    for action in actions:
        test.assertEqual(lease.words[5], action)
        if action in (215, 219, 224):
            test.assertEqual(lease.words[45], (1 << (lease.words[33] - 1)) | (1 << (lease.words[34] - 1)))
        lease.outcome(predicate=predicates.get(action), void=action in (241, 231))
    test.assertEqual((lease.status, lease.words[3], lease.words[40], lease.words[37]), (0, 3, 3, 1))
    before = lease.bytes
    lease.send(3, known=1, token=1, fields=((4, struct.pack('<Q', 1)),))
    test.assertEqual((lease.status, lease.bytes), (16, before))
    lease.commit(); test.assertEqual((lease.status, lease.words[3]), (0, 4))
    wrong = DirectProtocol(make_engine(), 10)
    wrong.outcome(predicate=False)
    test.assertEqual((wrong.status, wrong.words[3], wrong.words[36], wrong.words[37]), (11, 5, 1, 0))
    unknown = DirectProtocol(make_engine(), 8)
    token = unknown.words[6]; unknown.send(2, token=token)
    before = unknown.bytes
    unknown.send(3, known=1, token=token, fields=((4, struct.pack('<Q', 99)),))
    test.assertEqual((unknown.status, unknown.bytes), (16, before))
    unknown.send(5, known=1, token=token)
    test.assertEqual((unknown.status, unknown.words[3]), (22, 5))


def exercise_adoption(test, engine):
    baseline, candidate = reference('a'), reference('b')
    p = Protocol(engine, 2, candidate=candidate, baseline=baseline)
    p.slot(present=False); p.hash()
    test.assertEqual(p.words[5], 6)
    p.outcome((integer(1),)); p.slot('0', '0', context='ctx-new')
    test.assertEqual(p.words[5], 7)
    p.outcome((integer(1),)); p.outcome((reference_field(baseline),))
    p.generations(['0'])
    p.write_version_and_slot(candidate, '1', '1')
    test.assertEqual((p.words[21], p.words[22], p.words[29], p.words[30]), (0, 0, 1, 1))
    test.assertEqual(p.words[37], 4)
    previous = p.bytes
    p.send(3, known=1, token=1, fields=(integer(1),))
    test.assertEqual(p.status, 16); test.assertEqual(p.bytes, previous)
    return p


class SlotLedgerSourceTests(unittest.TestCase):
    def test_independent_vm_direct_handle_lifecycle_and_foreign_error(self):
        exercise_direct(self, VM)

    def test_generated_source_and_bootstrap_bounds(self):
        from hepta.hia_agent_assembly import render_assembly
        from tools.generate_hia_slot_ledger import document
        program = document()
        self.assertEqual(SOURCE.read_text(), render_assembly(program))
        self.assertLessEqual(len(program['functions']), 128)
        self.assertLessEqual(sum(len(function['blocks']) for function in program['functions']), 1536)
        for function in program['functions']:
            self.assertLessEqual(len(function['params']), 16)
            self.assertLessEqual(len(function['blocks']), 256)
            for block in function['blocks']:
                self.assertLessEqual(len(block['params']), 16)

    def test_vm_first_adoption_claims_and_exact_readbacks(self):
        exercise_adoption(self, VM())

    def test_vm_rollback_uses_retained_image_and_preserves_original_generation(self):
        active, retained = reference('b'), reference('a')
        p = Protocol(VM(), 3, expected=('1', '7'), retained='0')
        p.snapshot_rows(active, '1', '7', count=3)
        self.assertEqual(p.words[5], 12)
        p.outcome((reference_field(retained),))
        self.assertEqual(p.words[5], 4)
        p.outcome(((4, ABI),)); p.slot('1', '7'); p.hash()
        self.assertEqual(p.words[5], 9)
        p.outcome((integer(1),)); p.slot('0', '8', context='ctx-new')
        self.assertEqual((p.status, p.words[3], p.words[29], p.words[30]), (0, 3, 0, 8))
        self.assertEqual((p.words[21], p.words[22], p.words[33]), (1, 7, 3))

    def test_vm_stale_snapshot_never_grants_a_write(self):
        p = Protocol(VM(), 7, expected=('1', '1'))
        p.snapshot_rows(reference('c'), '2', '4', count=5)
        self.assertEqual((p.status, p.words[3], p.words[5], p.words[37]), (4, 5, 0, 0))
        self.assertEqual((p.words[21], p.words[22], p.words[33]), (2, 4, 5))

    def test_vm_hia_formats_uuid_after_native_image_admission(self):
        p = Protocol(VM(), 4)
        p.snapshot_rows(reference('a'), '3', '5')
        self.assertEqual(p.words[34], 0)
        p.outcome(((4, bytes(range(16))),))
        self.assertEqual(p.words[5], 14)
        self.assertEqual(p.bytes[1248:1248 + p.words[34]],
            b'lease-000102030405460788090a0b0c0d0e0f')

    def test_cold_builder_refuses_before_output_or_compilation(self):
        from tools.build_hia_slot_ledger import build
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory); (path / 'compiler').write_bytes(b'not a compiler')
            (path / 'cold').write_text('{}')
            with patch('tools.qualify_hia_selfhost.compile_stage', side_effect=AssertionError('compile entered')):
                with self.assertRaisesRegex(ValueError, 'completed matching native cold'):
                    build(path / 'out', path / 'compiler', path / 'cold')
            self.assertFalse((path / 'out').exists())

    def test_selected_missing_native_dependency_refuses_before_filesystem_creation(self):
        from hepta.hia_agent_store import AgentStore
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {
            SELECTOR: 'explicit', 'HEPTA_HIA_ARTIFACT_NAMESPACE_MANIFEST': '',
            'HEPTA_HIA_REQUEST_JOURNAL_MANIFEST': '', 'HEPTA_HIA_EXECUTION_BUDGET_MANIFEST': ''}), \
                patch('hepta.hia_slot_ledger_native._installed_json_image', return_value=object()):
            root = Path(directory) / 'state'
            with self.assertRaisesRegex(SlotLedgerUnknown, 'requires admitted native'):
                AgentStore(root)
            self.assertFalse(root.exists())

    def test_explicit_cold_and_development_configuration_never_mix(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'cold'; path.write_text('{}')
            with patch.dict(os.environ, {'HEPTA_HIA_SLOT_LEDGER_COLD_REPORT': str(path),
                'HEPTA_HIA_SLOT_LEDGER_DEVELOPMENT_COMPILER': ''}), \
                    patch('tools.qualify_hia_selfhost.build_seed', side_effect=AssertionError('seed entered')):
                with self.assertRaisesRegex(ValueError, 'cold report lacks a compiler'):
                    SlotLedgerNativeTests.setUpClass()
            with patch.dict(os.environ, {'HEPTA_HIA_SLOT_LEDGER_COLD_REPORT': str(path),
                'HEPTA_HIA_SLOT_LEDGER_DEVELOPMENT_COMPILER': 'explicit'}):
                with self.assertRaisesRegex(ValueError, 'development compiler cannot be combined'):
                    SlotLedgerNativeTests.setUpClass()


class _DependencyBuild:
    """A fixture holder, deliberately not an inherited unittest class."""


class SlotLedgerNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tests.test_hia_artifact_namespace_native import ArtifactNamespaceNativeTests
        from tools.build_hia_json_preflight import current_sources
        from tools.qualify_hia_selfhost import compile_stage
        cold = os.environ.get('HEPTA_HIA_SLOT_LEDGER_COLD_REPORT')
        development = os.environ.get('HEPTA_HIA_SLOT_LEDGER_DEVELOPMENT_COMPILER')
        if cold and development:
            raise ValueError('development compiler cannot be combined with a ledger cold report')
        if cold:
            report = json.loads(Path(cold).read_bytes())
            try:
                nested = json.loads(Path(report['nested_report']).read_bytes())
                compiler = Path(nested['generations'][-1]['produced_image'])
            except (KeyError, IndexError, TypeError) as error:
                raise ValueError('ledger cold report lacks a compiler') from error
        evidence = os.environ.get('HEPTA_HIA_SLOT_LEDGER_EVIDENCE', '')
        with patch.dict(os.environ, {
            'HEPTA_HIA_ARTIFACT_NAMESPACE_COLD_REPORT': cold or '',
            'HEPTA_HIA_ARTIFACT_NAMESPACE_DEVELOPMENT_COMPILER': development or '',
            'HEPTA_HIA_ARTIFACT_NAMESPACE_EVIDENCE': evidence,
        }):
            ArtifactNamespaceNativeTests.setUpClass.__func__(_DependencyBuild)
        cls.dependencies = _DependencyBuild
        cls.folder, cls.serial = _DependencyBuild.folder, 0
        if cold:
            from tools.build_hia_slot_ledger import build
            cls.manifest = build(cls.folder / 'slot-ledger', compiler, Path(cold))
            mode = 'MATCHING_CURRENT_SOURCE_COLD_BUILD'
        else:
            compiler = Path(development) if development else cls.folder / 'B2.image.bin'
            original = SOURCE.read_bytes(); compiler_bytes = compiler.read_bytes()
            image, receipt = compile_stage(cls.folder, 'slot-ledger', compiler, original)
            manifest = {'schema': SCHEMA, 'source_sha256': sha256(original).hexdigest(),
                'image_path': image.name, 'image_sha256': sha256(image.read_bytes()).hexdigest(),
                'compiler_sha256': sha256(compiler_bytes).hexdigest()}
            cls.manifest = cls.folder / 'slot-ledger-manifest.json'
            cls.manifest.write_text(json.dumps(manifest, indent=2) + '\n')
            if SOURCE.read_bytes() != original or compiler.read_bytes() != compiler_bytes:
                raise AssertionError('ledger development inputs changed')
            (cls.folder / 'slot-ledger-compile.json').write_text(json.dumps(receipt, indent=2) + '\n')
            mode = 'DEVELOPMENT_REUSED_COMPILER' if development else 'DEVELOPMENT_B0_B1_B2'
        manifest = json.loads(cls.manifest.read_bytes())
        cls.image = NativeSlotLedgerImage((cls.manifest.parent / manifest['image_path']).read_bytes(),
                                         manifest['image_sha256'])
        joint = json.loads((cls.folder / 'joint-build.json').read_bytes())
        if current_sources() != joint['source_manifest']:
            raise AssertionError('ledger joint fixture source identity changed')
        (cls.folder / 'ledger-joint-build.json').write_text(json.dumps({
            **joint, 'mode': mode, 'ledger_manifest': str(cls.manifest),
            'matching_current_source_cold_qualified': bool(cold),
            'all_selected_dependencies_share_cold_report': bool(cold),
        }, indent=2) + '\n')

    @classmethod
    def tearDownClass(cls):
        from tests.test_hia_artifact_namespace_native import ArtifactNamespaceNativeTests
        ArtifactNamespaceNativeTests.tearDownClass.__func__(cls.dependencies)

    def setUp(self):
        type(self).serial += 1
        self.case = self.folder / ('ledger-case-' + str(type(self).serial))
        self.case.mkdir(mode=0o700)

    def selected(self):
        d = self.dependencies
        return patch.dict(os.environ, {SELECTOR: str(self.manifest),
            'HEPTA_HIA_ARTIFACT_NAMESPACE_MANIFEST': str(d.manifest),
            'HEPTA_HIA_REQUEST_JOURNAL_MANIFEST': str(d.request_manifest),
            'HEPTA_HIA_EXECUTION_BUDGET_MANIFEST': str(d.budget_manifest),
            'HEPTA_HIA_AGENT_ARTIFACT_STORE_MANIFEST': str(d.byte_manifest)})

    @contextmanager
    def old_ledger_forbidden(self):
        from hepta.hia_agent_service import HIAAgentService
        with ExitStack() as stack:
            for name in ('slot_snapshot', 'conditional_slot', 'hia_adopt', 'hia_rollback',
                         'acquire_slot', 'lease', 'release_slot'):
                stack.enter_context(patch.object(HIAAgentService, '_' + name + '_reference',
                    side_effect=AssertionError('selected ledger entered original ' + name)))
            yield

    def service(self, name='state'):
        from hepta.hia_agent_service import HIAAgentService
        service = HIAAgentService(self.case / name)
        self.addCleanup(service.close)
        return service

    def fixture_rows(self, service, *, generation='3', epoch='5'):
        """Real issued bytes/rows; foreign semantic image checker is explicit."""
        ref = service.store.put(b'foreign-image-test-double', 'native')
        service.store.db.execute('INSERT INTO main.slots VALUES (?,?,?,?,?)',
            ('slot', 'ctx-old', generation, epoch, sha256(ABI).hexdigest()))
        service.store.db.execute('INSERT INTO main.versions VALUES (?,?,?)',
            ('slot', generation, wire(ref).decode()))
        return ref

    def test_actual_machine_first_adoption_and_wrong_outcome_replay(self):
        exercise_adoption(self, Machine(self.image))

    def test_actual_machine_direct_handle_lifecycle_and_foreign_error(self):
        exercise_direct(self, lambda: Machine(self.image))

    def test_actual_direct_sqlite_binding_domain_matches_original(self):
        from hepta.hia_agent_store import AgentRejected
        values = [('long', 'x' * 65537), ('unicode', '雪' * 257), ('empty', ''),
            ('nul', 'a\0b'), ('int', 7), ('bool', True), ('float', 1.25),
            ('blob', b'b\0lob'), ('bytearray', bytearray(b'array')), ('view', memoryview(b'view')),
            ('none', None), ('nan', float('nan')), ('inf', float('inf')),
            ('overflow', 1 << 100), ('surrogate', '\ud800'), ('unsupported', object())]
        observations = []
        with self.selected():
            with patch.dict(os.environ, {SELECTOR: ''}):
                reference_service = self.service('direct-reference')
            native_service = self.service('direct-native')
            for label, value in values:
                returned = []
                for service in (reference_service, native_service):
                    try:
                        result = service.inspect_slot(value)
                    except Exception as error:
                        returned.append(('raised', type(error).__name__, str(error)))
                    else:
                        self.assertIs(result['target_slot'], value)
                        self.assertEqual(result['current'], {'generation': '0', 'epoch': '0'})
                        returned.append(('returned', result['current'], result['active_artifact']))
                self.assertEqual(returned[0], returned[1], label)
                observations.append({'case': label, 'observations': returned})
            # Affinity is observable: acquire returns the supplied integer,
            # while the retained TEXT row supplies a string to lease admission.
            for service in (reference_service, native_service):
                ref = self.fixture_rows(service)
                service.store.db.execute("UPDATE main.slots SET name='7'")
                service.store.db.execute("UPDATE main.versions SET slot='7'")
                with patch.object(service, '_native', return_value=(b'foreign', {}, None)):
                    lease = service.acquire_slot(7)
                self.assertIs(type(lease['slot']), int)
                self.assertEqual(service.store.db.execute('SELECT slot FROM main.leases').fetchone()[0], '7')
                with self.assertRaises(AgentRejected) as refused:
                    service._lease(lease)
                self.assertEqual(refused.exception.code, 'E_HIA_LEASE')
                lease['slot'] = '7'
                self.assertEqual(service._lease(lease)['artifact'], ref)
                self.assertTrue(service.release_slot(lease)['released'])
            (self.case / 'direct-domain.json').write_text(json.dumps(observations, indent=2) + '\n')

    def test_actual_direct_stateful_adaptation_and_comparison_order(self):
        events = []
        class Bind:
            def __init__(self, values):
                self.values = iter(values)
            def __conform__(self, protocol):
                self_protocol = protocol
                if self_protocol is not sqlite3.PrepareProtocol:
                    raise AssertionError('wrong SQLite adaptation protocol')
                value = next(self.values); events.append(('bind', value)); return value
        class Truth:
            def __init__(self, label): self.label = label
            def __bool__(self): events.append(('truth', self.label)); return False
        with self.selected():
            with patch.dict(os.environ, {SELECTOR: ''}):
                reference_service = self.service('adapt-reference')
            native_service = self.service('adapt-native')
            transcripts = []
            for service in (reference_service, native_service):
                ref = self.fixture_rows(service)
                service.store.db.execute("UPDATE main.slots SET name='first'")
                service.store.db.execute("UPDATE main.versions SET slot='second'")
                service.store.db.execute('INSERT INTO main.leases VALUES (?,?,?,?,1)',
                    ('count-only', 'third', '3', wire(ref).decode()))
                events.clear()
                target = Bind(['first', 'second', 'third', 'fourth'])
                with patch.object(service, '_native', return_value=(b'foreign', {}, None)):
                    lease = service.acquire_slot(target)
                self.assertIs(lease['slot'], target)
                self.assertEqual(events, [('bind', name) for name in ('first', 'second', 'third', 'fourth')])
                self.assertEqual(service.store.db.execute('SELECT slot FROM main.leases WHERE id=?',
                    (lease['id'],)).fetchone()[0], 'fourth')
                supplied = {'id': None, 'slot': 'wrong', 'generation': 'wrong', 'artifact': None}
                class Compared:
                    def __init__(self, label): self.label = label
                    def __ne__(self, other):
                        events.append(('compare', self.label))
                        if self.label == 'slot': supplied['generation'] = Compared('generation')
                        if self.label == 'generation': supplied['artifact'] = Compared('artifact')
                        return Truth(self.label)
                class Identifier:
                    def __conform__(self, protocol):
                        events.append(('bind-id', 'once'))
                        supplied['slot'] = Compared('slot')
                        return lease['id']
                supplied['id'] = Identifier()
                events.clear()
                retained = service._lease(supplied)
                self.assertEqual(retained, {**lease, 'slot': 'fourth'})
                expected = [('bind-id', 'once'), ('compare', 'slot'), ('truth', 'slot'),
                    ('compare', 'generation'), ('truth', 'generation'),
                    ('compare', 'artifact'), ('truth', 'artifact')]
                self.assertEqual(events, expected)
                transcripts.append(events.copy())
                self.assertTrue(service.release_slot(retained)['released'])
            self.assertEqual(transcripts[0], transcripts[1])
            (self.case / 'direct-foreign-order.json').write_text(json.dumps(transcripts, indent=2) + '\n')

    def test_actual_direct_foreign_exception_and_zero_row_release_match_original(self):
        from hepta.hia_agent_store import AgentRejected
        class RaisingId:
            def __init__(self, error): self.error = error
            def __conform__(self, protocol): raise self.error
        class RaisingComparison:
            def __init__(self, error): self.error = error
            def __ne__(self, other): raise self.error
        class RaisingTruth:
            def __init__(self, error): self.error = error
            def __bool__(self): raise self.error
        class Compared:
            def __init__(self, result): self.result = result
            def __ne__(self, other): return self.result
        with self.selected():
            with patch.dict(os.environ, {SELECTOR: ''}):
                reference_service = self.service('error-reference')
            native_service = self.service('error-native')
            observations = []
            for service in (reference_service, native_service):
                ref = self.fixture_rows(service)
                lease = {'id': 'retained', 'slot': 'slot', 'generation': '3', 'artifact': ref}
                service.store.db.execute('INSERT INTO main.leases VALUES (?,?,?,?,1)',
                    ('retained', 'slot', '3', wire(ref).decode()))
                for label, error, field, value in (
                    ('binding', ValueError('original binding error'), 'id', RaisingId),
                    ('comparison', TypeError('original comparison error'), 'slot', RaisingComparison),
                    ('truth', RuntimeError('original truth error'), 'slot', lambda e: Compared(RaisingTruth(e))),
                ):
                    supplied = {**lease, field: value(error)}
                    with self.assertRaises(type(error)) as raised:
                        service.release_slot(supplied)
                    self.assertIs(raised.exception, error)
                    self.assertFalse(service.store.db.in_transaction)
                    self.assertEqual(service.store.db.execute('SELECT active FROM main.leases').fetchone()[0], 1)
                    self.assertEqual(service._lease(lease), lease)
                # Registered adapters are consulted at each original execute.
                # The historical API returned released=True even if the second
                # binding selected no row. No extra caller binding is permitted.
                calls = []
                def adapt(value):
                    calls.append(value)
                    return value if len(calls) == 1 else 'no-such-row'
                key = (str, sqlite3.PrepareProtocol)
                original = sqlite3.adapters.get(key)
                sqlite3.register_adapter(str, adapt)
                try:
                    released = service.release_slot(lease)
                finally:
                    if original is None: sqlite3.adapters.pop(key, None)
                    else: sqlite3.adapters[key] = original
                self.assertEqual(calls, ['retained', 'retained'])
                self.assertEqual(released, {'released': True, 'generation': '3', 'artifact_retained': True})
                self.assertEqual(service.store.db.execute('SELECT active FROM main.leases').fetchone()[0], 1)
                self.assertTrue(service.release_slot(lease)['released'])
                observations.append({'bindings': calls, 'legacy_response': released, 'active_after_zero_row_update': 1})
            self.assertEqual(observations[0], observations[1])
            (self.case / 'direct-error-and-affinity.json').write_text(json.dumps(observations, indent=2) + '\n')

    def test_actual_direct_comparison_result_handoff_loss_keeps_opaque_custody(self):
        from tests.test_hia_artifact_namespace_native import interrupt_opcode
        import gc
        import weakref
        from hepta.hia_slot_ledger_native import NativeSlotLedgerStore
        calls = []
        class Compared:
            def __ne__(self, other):
                calls.append(other)
                return False
        with self.selected(), self.old_ledger_forbidden():
            service = self.service(); ref = self.fixture_rows(service)
            service.store.db.execute('INSERT INTO main.leases VALUES (?,?,?,?,1)',
                ('retained', 'slot', '3', wire(ref).decode()))
            compared = Compared(); reference_to_object = weakref.ref(compared)
            supplied = {'id': 'retained', 'slot': compared, 'generation': '3', 'artifact': ref}
            owner = service.store.slot_ledger
            with interrupt_opcode(NativeSlotLedgerStore._direct_drive.__code__, 'STORE_ATTR', 'returned',
                    predicate=lambda frame: frame.f_locals.get('action') == 215) as hits:
                with self.assertRaises(SlotLedgerUnknown): service._lease(supplied)
            self.assertEqual(len(hits), 1)
            self.assertEqual(calls, ['slot'])
            self.assertEqual((owner.pending.receipt.phase, owner.pending.receipt.action), (2, 215))
            self.assertIs(owner.pending.objects[1], supplied)
            del supplied, compared
            gc.collect()
            self.assertIsNotNone(reference_to_object())
            with self.assertRaises(SlotLedgerUnknown): service._lease(owner.pending.objects[1])
            self.assertEqual(calls, ['slot'])
            self.assertEqual(service.store.db.execute('SELECT active FROM main.leases').fetchone()[0], 1)
            (self.case / 'direct-comparison-loss.json').write_text(json.dumps({
                'opcode_hits': hits, 'calls': calls, 'state': owner.snapshot(),
                'original_input_rooted_after_gc': True}, indent=2) + '\n')

    def test_actual_direct_comparison_temporary_finalizers_match_original(self):
        from hepta.hia_agent_store import AgentRejected
        with self.selected():
            with patch.dict(os.environ, {SELECTOR: ''}):
                reference_service = self.service('temporary-reference')
            native_service = self.service('temporary-native')
            transcripts = []
            for service in (reference_service, native_service):
                ref = self.fixture_rows(service)
                service.store.db.execute('INSERT INTO main.leases VALUES (?,?,?,?,1)',
                    ('retained', 'slot', '3', wire(ref).decode()))
                cases = []
                for field, changed_field in (('slot', 'generation'), ('generation', 'artifact'), ('artifact', 'id')):
                    events = []
                    supplied = {'id': 'retained', 'slot': 'slot', 'generation': '3', 'artifact': ref}
                    class Truth:
                        def __bool__(self): events.append('truth'); return False
                        def __del__(self):
                            events.append('truth-finalized')
                            supplied[changed_field] = 'wrong'
                    class Compared:
                        def __ne__(self, other): events.append('compare'); return Truth()
                    supplied[field] = Compared()
                    if field == 'artifact':
                        result = service._lease(supplied)
                        self.assertEqual(result['id'], 'retained')
                        outcome = 'retained'
                    else:
                        with self.assertRaises(AgentRejected) as raised:
                            service.release_slot(supplied)
                        self.assertEqual(raised.exception.code, 'E_HIA_LEASE')
                        outcome = raised.exception.code
                    self.assertEqual(events, ['compare', 'truth', 'truth-finalized'])
                    self.assertEqual(supplied[changed_field], 'wrong')
                    self.assertEqual(service.store.db.execute('SELECT active FROM main.leases').fetchone()[0], 1)
                    cases.append({'field': field, 'events': events.copy(), 'outcome': outcome})
                transcripts.append(cases)
            self.assertEqual(transcripts[0], transcripts[1])
            (self.case / 'direct-finalizer-results.json').write_text(json.dumps(transcripts, indent=2) + '\n')

    def test_actual_direct_consumed_operands_and_sql_parameters_match_original(self):
        from hepta.hia_agent_store import AgentRejected
        with self.selected():
            with patch.dict(os.environ, {SELECTOR: ''}):
                reference_service = self.service('operand-reference')
            native_service = self.service('operand-native')
            transcripts = []
            for service in (reference_service, native_service):
                ref = self.fixture_rows(service)
                service.store.db.execute('INSERT INTO main.leases VALUES (?,?,?,?,1)',
                    ('retained', 'slot', '3', wire(ref).decode()))
                events = []
                supplied = {'id': 'retained', 'slot': None, 'generation': '3', 'artifact': ref}
                class Truth:
                    def __bool__(self):
                        events.append(('truth', supplied['generation'])); return False
                    def __del__(self): events.append(('truth-finalized', None))
                class Compared:
                    def __ne__(self, other):
                        events.append(('compare', other))
                        del supplied['slot']
                        return Truth()
                    def __del__(self):
                        events.append(('operand-finalized', None))
                        supplied['generation'] = 'wrong'
                supplied['slot'] = Compared()
                with self.assertRaises(AgentRejected) as raised:
                    service.release_slot(supplied)
                self.assertEqual(raised.exception.code, 'E_HIA_LEASE')
                self.assertEqual(events, [('compare', 'slot'), ('operand-finalized', None),
                    ('truth', 'wrong'), ('truth-finalized', None)])
                compared_events = events.copy()
                supplied = {'id': None, 'slot': 'slot', 'generation': '3', 'artifact': ref}
                events.clear()
                class Identifier:
                    def __conform__(self, protocol):
                        events.append(('bind', None)); supplied['id'] = 'retained'; return 'retained'
                    def __del__(self):
                        events.append(('parameter-finalized', None)); supplied['generation'] = 'wrong'
                supplied['id'] = Identifier()
                with self.assertRaises(AgentRejected) as raised:
                    service.release_slot(supplied)
                self.assertEqual(raised.exception.code, 'E_HIA_LEASE')
                self.assertEqual(events, [('bind', None), ('parameter-finalized', None)])
                self.assertEqual(service.store.db.execute('SELECT active FROM main.leases').fetchone()[0], 1)
                transcripts.append({'comparison': compared_events, 'parameter': events.copy()})
            self.assertEqual(transcripts[0], transcripts[1])
            (self.case / 'direct-finalizer-operands.json').write_text(json.dumps(transcripts, indent=2) + '\n')

    def test_actual_direct_unused_native_result_and_completed_custody_match_original(self):
        import gc
        import weakref
        with self.selected():
            with patch.dict(os.environ, {SELECTOR: ''}):
                reference_service = self.service('scope-reference')
            native_service = self.service('scope-native')
            transcripts = []
            for service in (reference_service, native_service):
                self.fixture_rows(service)
                events = []
                class Target:
                    inserted_slot = 'before-finalizer'
                    calls = 0
                    def __conform__(self, protocol):
                        self.calls += 1
                        value = 'slot' if self.calls < 4 else self.inserted_slot
                        events.append(('bind', value)); return value
                    def __del__(self): events.append(('target-finalized', None))
                target = Target(); target_ref = weakref.ref(target)
                class Unused:
                    def __del__(self):
                        events.append(('unused-finalized', None))
                        target.inserted_slot = 'after-finalizer'
                def checker(*args, **kwargs):
                    events.append(('native-check', None)); return Unused()
                with patch.object(service, '_native', side_effect=checker):
                    lease = service.acquire_slot(target)
                self.assertIs(lease['slot'], target)
                self.assertEqual(service.store.db.execute('SELECT slot FROM main.leases').fetchone()[0], 'after-finalizer')
                self.assertEqual(events, [('bind', 'slot')] * 3 +
                    [('native-check', None), ('unused-finalized', None), ('bind', 'after-finalizer')])
                del lease, target
                gc.collect()
                self.assertIsNone(target_ref())
                self.assertEqual(events[-1], ('target-finalized', None))
                if service.store.slot_ledger is not None:
                    self.assertFalse(hasattr(service.store.slot_ledger.last, 'objects'))
                    self.assertFalse(service.store.slot_ledger.snapshot()['pending'])
                transcripts.append(events.copy())
            self.assertEqual(transcripts[0], transcripts[1])
            (self.case / 'direct-finalizer-scopes.json').write_text(json.dumps(transcripts, indent=2) + '\n')

    def test_actual_direct_consumption_return_loss_never_replays(self):
        from tests.test_hia_artifact_namespace_native import interrupt_opcode
        from hepta.hia_slot_ledger_native import DirectLedgerState
        calls = []
        class Compared:
            def __ne__(self, other): calls.append(other); return False
        with self.selected(), self.old_ledger_forbidden():
            service = self.service(); ref = self.fixture_rows(service)
            service.store.db.execute('INSERT INTO main.leases VALUES (?,?,?,?,1)',
                ('retained', 'slot', '3', wire(ref).decode()))
            supplied = {'id': 'retained', 'slot': Compared(), 'generation': '3', 'artifact': ref}
            owner = service.store.slot_ledger
            with interrupt_opcode(DirectLedgerState.take.__code__, 'RETURN_VALUE',
                    predicate=lambda frame: frame.f_locals.get('word') == 34
                    and frame.f_locals['r'].action == 215) as hits:
                with self.assertRaises(SlotLedgerUnknown): service.release_slot(supplied)
            self.assertEqual(len(hits), 1)
            self.assertEqual(calls, [])
            state = owner.pending
            self.assertEqual((state.receipt.phase, state.receipt.action), (2, 215))
            self.assertIs(state.objects[1], supplied)
            self.assertNotIn(state.receipt.words[33], state.objects)
            self.assertNotIn(state.receipt.words[34], state.objects)
            self.assertNotEqual(state.receipt.words[45], 0)
            with self.assertRaises(SlotLedgerUnknown): service.release_slot(supplied)
            self.assertEqual(calls, [])
            self.assertEqual(service.store.db.execute('SELECT active FROM main.leases').fetchone()[0], 1)
            (self.case / 'direct-consumption-loss.json').write_text(json.dumps({
                'opcode_hits': hits, 'calls': calls, 'state': owner.snapshot(),
                'native_consumption_mask': state.receipt.words[45],
                'remaining_handles': list(state.objects)}, indent=2) + '\n')

    def test_actual_existing_unbounded_slot_invocation_and_release(self):
        from tests.test_hia_agent_native_tools import AgentToolCase
        from hepta.hia_agent_store import AgentRejected
        with self.selected():
            with patch.dict(os.environ, {SELECTOR: ''}):
                case = AgentToolCase('runTest'); case.setUp()
            try:
                _, _, _, build, _ = case.build_pair()
                artifact = build['native_artifact']
                _, metadata, _ = case.service._native(artifact)
                slot = 'retained/雪/' + 'x' * 65537
                case.service.store.db.execute('INSERT INTO main.slots VALUES (?,?,?,?,?)',
                    (slot, case.session.context['id'], '1', '1', sha256(wire(metadata['signatures'])).hexdigest()))
                case.service.store.db.execute('INSERT INTO main.versions VALUES (?,?,?)',
                    (slot, '1', wire(artifact).decode()))
                old_lease = case.service.acquire_slot(slot)
                from hepta.hia_agent_service import HIAAgentService
                service = HIAAgentService(case.state_root, artifact_roots=(case.files_root,))
                try:
                    with self.old_ledger_forbidden():
                        self.assertEqual(service.inspect_slot(slot)['active_artifact'], artifact)
                        new_lease = service.acquire_slot(slot)
                        results = [service.invoke_lease(lease, 'transform', [250]) for lease in (old_lease, new_lease)]
                        for result in results:
                            self.assertEqual((result['status'], result['values']), ('returned', [1]))
                        for lease in (old_lease, new_lease):
                            self.assertTrue(service.release_slot(lease)['released'])
                            with self.assertRaises(AgentRejected) as refused:
                                service._lease(lease)
                            self.assertEqual(refused.exception.code, 'E_HIA_LEASE')
                        self.assertEqual(service.inspect_slot(slot)['in_flight_leases'], 0)
                        (self.case / 'direct-long-real-invocation.json').write_text(json.dumps({
                            'slot_bytes': len(slot.encode()), 'real_native_checker_and_runner': True,
                            'old_lease_admitted': True, 'new_lease_admitted': True, 'results': results}, indent=2) + '\n')
                finally:
                    service.close()
            finally:
                case.tearDown()

    def test_actual_machine_max_retained_generation_after_rollback(self):
        baseline, candidate = reference('a'), reference('b')
        p = Protocol(Machine(self.image), 2, expected=('0', '8'), candidate=candidate, baseline=baseline)
        p.snapshot_rows(baseline, '0', '8'); p.hash(); p.slot('0', '8')
        p.outcome(); p.generations(['0', '2', '1', '17'])
        p.write_version_and_slot(candidate, '18', '9')
        self.assertEqual((p.words[29], p.words[30]), (18, 9))

    def test_actual_machine_lease_commit_epoch_and_repeated_admission(self):
        ref = reference('a'); lease = {'id': 'lease-000102030405460788090a0b0c0d0e0f', 'slot': 'slot', 'generation': '3', 'artifact': ref}
        p = Protocol(Machine(self.image), 4)
        p.snapshot_rows(ref, '3', '5'); p.outcome(((4, bytes(range(16))),)); p.outcome((integer(1),)); p.lease_row(lease)
        self.assertEqual(p.words[3], 3)
        original = p.bytes; p.commit(epoch=8)
        self.assertEqual(p.status, 16); self.assertEqual(p.bytes, original)
        p.commit(); self.assertEqual((p.status, p.words[3]), (0, 4))
        for _ in range(2):
            p = Protocol(Machine(self.image), 5, lease=lease); p.lease_row(lease)
            self.assertEqual((p.status, p.words[3]), (0, 4))
        p = Protocol(Machine(self.image), 6, lease=lease)
        p.lease_row(lease); p.outcome((integer(1),)); p.lease_row(lease, active=0); p.commit()
        self.assertEqual((p.status, p.words[3]), (0, 4))

    def test_actual_machine_wrong_owner_corrupt_row_and_sequence_exhaustion(self):
        engine = Machine(self.image); p = Protocol(engine, 1)
        original = bytes(engine.state.raw)
        raw = packet(2, 1, sequence=p.sequence, token=p.words[6], nonce=(79, 83))
        count, returned, state = engine.call(raw)
        self.assertEqual((count, struct.unpack('<4Q', returned)), (32, (RESULT_MAGIC, 16, 0, 0)))
        self.assertEqual(engine.state.raw, original)
        # Reseal an otherwise valid independent state at its last u64 sequence.
        struct.pack_into('<Q', engine.state, 16, (1 << 64) - 1)
        data = bytearray(engine.state.raw[:CAPACITY]); value = 1469598103934665603
        words = struct.unpack('<64Q', data[:512])
        for word in words[:63]:
            value = (((value << 7) | (value >> 57)) & ((1 << 64) - 1)) ^ word
        for byte in data[512:words[55]]:
            value = (((value << 7) | (value >> 57)) & ((1 << 64) - 1)) ^ byte
        struct.pack_into('<Q', engine.state, 63 * 8, value)
        original = engine.state.raw
        raw = packet(2, 1, sequence=(1 << 64) - 1, token=p.words[6])
        count, returned, state = engine.call(raw)
        self.assertEqual(struct.unpack_from('<Q', returned, 8)[0], 18)
        self.assertEqual(engine.state.raw, original)
        corrupt = Protocol(Machine(self.image), 1)
        corrupt.slot('01', '1')
        self.assertEqual((corrupt.status, corrupt.words[3], corrupt.words[37]), (20, 6, 0))

    def test_actual_same_main_lease_rows_restart_and_reference_poison(self):
        from hepta.hia_agent_store import AgentRejected
        with self.selected(), self.old_ledger_forbidden():
            service = self.service(); ref = self.fixture_rows(service)
            service.store.db.executescript('CREATE TEMP TABLE slots(name,context_id,generation,epoch,abi_sha256);'
                'CREATE TEMP TABLE versions(slot,generation,artifact); CREATE TEMP TABLE leases(id,slot,generation,artifact,active);')
            with patch.object(service, '_native', return_value=(b'foreign', {'signatures': json.loads(ABI)}, None)):
                lease = service.acquire_slot('slot')
            self.assertEqual(lease['artifact'], ref)
            self.assertEqual(service.inspect_slot('slot')['in_flight_leases'], 1)
            self.assertEqual(service._lease(lease), lease)
            self.assertEqual(service._lease(lease), lease)
            for table in ('slots', 'versions', 'leases'):
                self.assertEqual(service.store.db.execute('SELECT count(*) FROM temp.' + table).fetchone()[0], 0)
            reopened = self.service('state')
            self.assertEqual(reopened._lease(lease), lease)
            self.assertEqual(reopened.release_slot(lease), {'released': True, 'generation': '3', 'artifact_retained': True})
            self.assertEqual(service.inspect_slot('slot')['in_flight_leases'], 0)
            for call in (service._lease, service.release_slot):
                with self.assertRaises(AgentRejected) as caught: call(lease)
                self.assertEqual(caught.exception.code, 'E_HIA_LEASE')
            self.assertEqual(service.store.get(ref)[0], b'foreign-image-test-double')

    def test_actual_lost_insert_ack_rolls_back_once_and_retains_native_claim(self):
        with self.selected(), self.old_ledger_forbidden():
            service = self.service(); self.fixture_rows(service)
            owner = service.store.slot_ledger; original = owner._execute; statements = []
            def lost(connection, statement, parameters=()):
                result = original(connection, statement, parameters)
                statements.append(statement)
                if statement.startswith('INSERT INTO main.leases'):
                    raise KeyboardInterrupt('lost SQL insert acknowledgement')
                return result
            with patch.object(service, '_native', return_value=(b'foreign', {}, None)), \
                    patch.object(owner, '_execute', side_effect=lost):
                with self.assertRaises(SlotLedgerUnknown): service.acquire_slot('slot')
            self.assertEqual(owner.pending.receipt.action, 124)
            self.assertEqual(owner.pending.receipt.phase, 2)
            self.assertTrue(owner.snapshot()['fenced'])
            self.assertEqual(service.store.db.execute('SELECT count(*) FROM main.leases').fetchone()[0], 0)
            with self.assertRaises(SlotLedgerUnknown): service.acquire_slot('slot')
            self.assertEqual(sum(sql.startswith('INSERT INTO main.leases') for sql in statements), 1)

    def test_actual_lost_commit_ack_keeps_committed_row_but_issues_no_lease(self):
        with self.selected(), self.old_ledger_forbidden():
            service = self.service(); self.fixture_rows(service)
            namespace = service.store.artifact_namespace; original = namespace._execute_scope; statements = []
            def lost(statement):
                result = original(statement); statements.append(statement)
                if statement == 'COMMIT': raise KeyboardInterrupt('lost actual COMMIT acknowledgement')
                return result
            with patch.object(service, '_native', return_value=(b'foreign', {}, None)), \
                    patch.object(namespace, '_execute_scope', side_effect=lost):
                with self.assertRaises(SlotLedgerUnknown): service.acquire_slot('slot')
            owner = service.store.slot_ledger
            self.assertEqual(owner.pending.receipt.phase, 3)
            self.assertTrue(owner.snapshot()['fenced'])
            self.assertEqual(statements, ['BEGIN IMMEDIATE', 'COMMIT'])
            self.assertEqual(service.store.db.execute('SELECT count(*) FROM main.leases WHERE active=1').fetchone()[0], 1)
            with self.assertRaises(SlotLedgerUnknown): service.acquire_slot('slot')

    def test_actual_request_capability_atomic_adopt_rollback_and_restart(self):
        from hepta.hia_agent_store import wire as production_wire
        from hepta.hia_request_journal_native import RequestJournalUnknown
        with self.selected(), self.old_ledger_forbidden():
            service = self.service(); store = service.store
            baseline = store.put(b'baseline', 'native'); candidate = store.put(b'candidate', 'native')
            capabilities = []
            def invoke(connection):
                capabilities.append(connection)
                official = store.db
                official.set_authorizer(lambda *_: sqlite3.SQLITE_DENY)
                try:
                    retained = store.slot_ledger.operate(2, service, slot='slot', context='ctx-new',
                        expected={'generation': '0', 'epoch': '0'}, candidate=candidate,
                        baseline=baseline, abi=ABI, connection=connection)
                    self.assertEqual(retained.phase, 3)
                    receipt = store.json({'generation': retained.current()}, 'adoption-receipt', _connection=connection)
                    return {'current': retained.current(), 'receipt': receipt}
                finally:
                    official.set_authorizer(None)
            ticket = store.request_journal.admit('hia_adopt', 'b' * 64, 'first-adoption', lambda *_: None)
            response = ticket.atomic(invoke, lambda value: {'status': 'completed', 'result': value})
            self.assertEqual(response['result']['current'], {'generation': '1', 'epoch': '1'})
            self.assertEqual(tuple(store.db.execute('SELECT state,response FROM main.requests').fetchone()),
                             ('completed', production_wire(response).decode()))
            with self.assertRaises(RequestJournalUnknown):
                store.slot_ledger.operate(1, service, slot='slot', connection=capabilities[0])
            ticket = store.request_journal.admit('hia_rollback', 'c' * 64, 'first-rollback', lambda *_: None)
            with patch.object(service, '_native', return_value=(b'baseline', {'signatures': json.loads(ABI)}, None)):
                rolled = ticket.atomic(lambda connection: store.slot_ledger.operate(3, service,
                    slot='slot', context='ctx-new', expected={'generation': '1', 'epoch': '1'},
                    retained='0', connection=connection).current(), lambda value: {'current': value})
            self.assertEqual(rolled, {'current': {'generation': '0', 'epoch': '2'}})
            reopened = self.service('state')
            replay = reopened.store.request_journal.admit('hia_adopt', 'b' * 64, 'first-adoption', lambda *_: None)
            self.assertEqual(replay.replay_bytes, production_wire(response))
            self.assertEqual(reopened.inspect_slot('slot')['current'], {'generation': '0', 'epoch': '2'})
            self.assertEqual(store.db.execute('SELECT count(*) FROM main.versions').fetchone()[0], 2)

    def test_actual_two_connections_race_one_conditional_generation_wins(self):
        from hepta.hia_agent_store import AgentRejected, wire as production_wire
        with self.selected(), self.old_ledger_forbidden():
            first, second = self.service(), self.service()
            baseline = first.store.put(b'baseline', 'native')
            candidates = [first.store.put(b'candidate-' + bytes([i]), 'native') for i in range(2)]
            ready = threading.Barrier(2)
            def race(index):
                service = (first, second)[index]
                ticket = service.store.request_journal.admit('hia_adopt', str(index + 1) * 64,
                    'race-' + str(index), lambda *_: None)
                ready.wait(timeout=10)
                try:
                    return ticket.atomic(lambda connection: service.store.slot_ledger.operate(2, service,
                        slot='slot', context='ctx-new', expected={'generation': '0', 'epoch': '0'},
                        candidate=candidates[index], baseline=baseline, abi=ABI, connection=connection).current(),
                        lambda value: {'current': value})
                except AgentRejected as error:
                    response = {'error': error.code, 'snapshot': error.pending_slot_snapshot}
                    ticket.finish(production_wire(response))
                    return response
            with ThreadPoolExecutor(2) as executor:
                outcomes = list(executor.map(race, range(2)))
            self.assertEqual(sum('current' in result for result in outcomes), 1)
            stale, = [result for result in outcomes if 'error' in result]
            self.assertEqual(stale['error'], 'E_HIA_GENERATION_STALE')
            self.assertEqual(stale['snapshot']['current'], {'generation': '1', 'epoch': '1'})
            self.assertEqual(first.store.db.execute('SELECT count(*) FROM main.versions').fetchone()[0], 2)
            self.assertEqual(first.store.db.execute("SELECT count(*) FROM main.requests WHERE state='completed'").fetchone()[0], 2)
            (self.case / 'concurrent-cas.json').write_text(json.dumps(outcomes, indent=2) + '\n')

    def test_actual_native_receipt_handoff_loss_retains_claim_after_sql_effect(self):
        from tests.test_hia_artifact_namespace_native import interrupt_opcode
        for opcode, name in (('STORE_FAST', 'size'), ('STORE_ATTR', 'receipt')):
            with self.subTest(opcode=opcode), self.selected(), self.old_ledger_forbidden():
                service = self.service('loss-' + name); self.fixture_rows(service)
                owner = service.store.slot_ledger
                def target(frame):
                    state = frame.f_locals['self']
                    return frame.f_locals.get('event') == 3 and state.receipt is not None and state.receipt.action == 124
                with patch.object(service, '_native', return_value=(b'foreign', {}, None)), \
                        interrupt_opcode(LedgerState.call.__code__, opcode, name, predicate=target) as hits:
                    with self.assertRaises(SlotLedgerUnknown): service.acquire_slot('slot')
                self.assertEqual(len(hits), 1)
                self.assertEqual((owner.pending.receipt.phase, owner.pending.receipt.action), (2, 124))
                # The native outcome did complete and selected commit. Losing
                # its Python receipt cannot make INSERT available a second time.
                raw_words = struct.unpack('<64Q', owner.pending.buffer.raw[:512])
                self.assertEqual((raw_words[3], raw_words[5], raw_words[37]), (3, 0, 1))
                self.assertEqual(service.store.db.execute('SELECT count(*) FROM main.leases').fetchone()[0], 0)
                with self.assertRaises(SlotLedgerUnknown): service.acquire_slot('slot')
                (self.case / ('native-handoff-' + name + '.json')).write_text(json.dumps({
                    'opcode': hits, 'state': owner.snapshot(), 'actual_native_words': raw_words}, indent=2) + '\n')

    def test_actual_pending_reentry_refuses_without_replacing_outer_claim(self):
        with self.selected(), self.old_ledger_forbidden():
            service = self.service(); self.fixture_rows(service)
            owner, observations = service.store.slot_ledger, []
            def verify(*args, **kwargs):
                original = owner.pending
                with self.assertRaises(SlotLedgerUnknown): service.inspect_slot('slot')
                with self.assertRaises(SlotLedgerUnknown): service.acquire_slot('slot')
                observations.append(original.receipt.pending)
                self.assertIs(owner.pending, original)
                self.assertEqual(original.receipt.action, 120)
                return b'foreign', {}, None
            with patch.object(service, '_native', side_effect=verify):
                lease = service.acquire_slot('slot')
            self.assertEqual(len(observations), 1)
            self.assertEqual(service._lease(lease), lease)
            self.assertFalse(owner.snapshot()['fenced'])

    def test_actual_request_commit_uncertainty_does_not_hide_advisory_slot_observation(self):
        from hepta.hia_request_journal_native import RequestJournalUnknown
        for after in (False, True):
            with self.subTest(after=after), self.selected(), self.old_ledger_forbidden():
                service = self.service('commit-' + str(int(after))); store = service.store
                baseline = store.put(b'base', 'native'); candidate = store.put(b'candidate', 'native')
                ticket = store.request_journal.admit('hia_adopt', 'd' * 64, 'uncertain', lambda *_: None)
                original = store.request_journal._execute
                def lost(statement, parameters=()):
                    if statement == 'COMMIT' and not after: raise KeyboardInterrupt('before atomic commit')
                    result = original(statement, parameters)
                    if statement == 'COMMIT': raise KeyboardInterrupt('after atomic commit')
                    return result
                with patch.object(store.request_journal, '_execute', side_effect=lost):
                    with self.assertRaises(RequestJournalUnknown):
                        ticket.atomic(lambda connection: store.slot_ledger.operate(2, service,
                            slot='slot', context='ctx-new', expected={'generation': '0', 'epoch': '0'},
                            candidate=candidate, baseline=baseline, abi=ABI, connection=connection).current(),
                            lambda value: {'current': value})
                observed = service.inspect_slot('slot')
                self.assertEqual(observed['current'], {'generation': '1' if after else '0', 'epoch': '1' if after else '0'})
                row = store.db.execute('SELECT state,response FROM main.requests').fetchone()
                self.assertEqual(row['state'], 'completed' if after else 'running')
                self.assertFalse(observed['snapshot_is_adoption_authority'])

    def test_actual_concurrent_invocations_finish_after_release_without_holding_ledger_lock(self):
        from copy import deepcopy
        from tests.test_hia_agent_native_tools import AgentToolCase
        from hepta.hia_agent_store import AgentRejected
        from hepta.hia_agent_runner import run_native_batch
        with self.selected(), self.old_ledger_forbidden():
            case = AgentToolCase('runTest'); case.setUp()
            try:
                _, _, baseline, built, receipts = case.build_pair()
                evaluation = case.session.evaluate(baseline, built, receipts=receipts)
                case.client.result('hia_adopt', case.session.arguments(target_slot='concurrent-lease',
                    expected_current={'generation': '0', 'epoch': '0'},
                    candidate_artifact=built['native_artifact'], evaluation_receipt=evaluation['evaluation_receipt'],
                    verification_receipts=receipts))
                supplied = case.service.acquire_slot('concurrent-lease'); retained = deepcopy(supplied)
                admitted, proceed = threading.Barrier(3), threading.Event()
                def paused(*arguments, **options):
                    admitted.wait(timeout=10)
                    self.assertTrue(proceed.wait(timeout=10))
                    return run_native_batch(*arguments, **options)
                with patch('hepta.hia_agent_runner.run_native_batch', side_effect=paused), ThreadPoolExecutor(2) as executor:
                    calls = [executor.submit(case.service.invoke_lease, supplied, 'transform', [250]) for _ in range(2)]
                    try:
                        admitted.wait(timeout=10)
                        released = case.service.release_slot(retained)
                        self.assertTrue(released['released'])
                        self.assertEqual(case.service.inspect_slot('concurrent-lease')['in_flight_leases'], 0)
                        supplied.clear()
                    finally:
                        proceed.set()
                    outcomes = [call.result(timeout=30) for call in calls]
                for result in outcomes:
                    self.assertEqual(result['status'], 'returned')
                    self.assertEqual(result['values'], [1])
                    self.assertEqual(result['generation'], retained['generation'])
                    self.assertEqual(result['artifact'], retained['artifact'])
                with patch('hepta.hia_agent_runner.run_native_batch', side_effect=AssertionError('released lease ran again')):
                    with self.assertRaises(AgentRejected) as refused:
                        case.service.invoke_lease(retained, 'transform', [250])
                self.assertEqual(refused.exception.code, 'E_HIA_LEASE')
                (self.case / 'concurrent-real-invocations.json').write_text(json.dumps({
                    'retained': retained, 'released': released, 'outcomes': outcomes,
                    'release_waited_for_or_cancelled_inflight_calls': False,
                    'real_native_runner_used': True}, indent=2) + '\n')
            finally:
                case.tearDown()

    def test_original_tools_campaign_buffers_and_lease_snapshot_with_four_native_owners(self):
        from hepta.hia_agent_service import HIAAgentService
        from hepta.hia_agent_store import AgentStore
        from hepta import hia_execution_budget as budget
        classes = ('tests.test_hia_agent_native_tools.ArtifactContractTests',
            'tests.test_hia_agent_native_tools.CandidateAndVerificationTests',
            'tests.test_hia_agent_native_tools.MachinePlanTests',
            'tests.test_hia_agent_native_tools.NativeLifecycleTests',
            'tests.test_hia_agent_native_tools.AgentStoreDirectoryPermissionTests',
            'tests.test_hia_agent_native_campaign.QualificationCampaignTests',
            'tests.test_hia_agent_buffer_lifecycle.BufferLifecycleTests',
            'tests.test_hia_agent_native_lease_snapshot.LeaseSnapshotTests')
        suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromName(name) for name in classes)
        expected = suite.countTestCases(); stream = io.StringIO()
        def forbidden(*args, **kwargs): raise AssertionError('original selected owner entered')
        with self.selected(), self.old_ledger_forbidden(), ExitStack() as stack:
            stack.enter_context(patch.object(HIAAgentService, '_call_reference', side_effect=forbidden))
            for name in ('put', 'json', 'get', 'get_json', 'resolve_uri', 'profile', 'check_profile', 'transaction'):
                stack.enter_context(patch.object(AgentStore, '_' + name + '_reference', side_effect=forbidden))
            stack.enter_context(patch.object(AgentStore, '_ref', side_effect=forbidden))
            for cls in (budget._ReferenceExecutionBudgetStore, budget._ReferenceBudgetClaim):
                stack.enter_context(patch.object(cls, '__init__', side_effect=forbidden))
            result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
        (self.case / 'original-suite.log').write_text(stream.getvalue())
        (self.case / 'original-suite.json').write_text(json.dumps({'classes': classes,
            'expected_tests': expected, 'tests_run': result.testsRun, 'failures': len(result.failures),
            'errors': len(result.errors), 'skips': len(result.skipped), 'original_limits_unchanged': True,
            'four_original_owners_forbidden_in_test_process': True,
            'cold_consumer_children_receive_explicit_selection': True}, indent=2) + '\n')
        self.assertEqual(expected, 48)
        self.assertEqual(result.testsRun, expected)
        self.assertTrue(result.wasSuccessful(), stream.getvalue())
        self.assertEqual(result.skipped, [], stream.getvalue())

    def test_actual_installed_wheel_ledger_and_source_custody_without_authoring(self):
        import shutil
        from hepta.hia_agent_contract import DISCOVERY_FILES, NATIVE_SOURCE_FILES, PUBLICATION_BUILD_FILES
        source = self.case / 'wheel-source'; source.mkdir()
        shutil.copytree(ROOT / 'hepta', source / 'hepta', ignore=shutil.ignore_patterns('__pycache__'))
        resources = tuple('docs/' + name for name in DISCOVERY_FILES) + NATIVE_SOURCE_FILES + PUBLICATION_BUILD_FILES
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
            raise AssertionError('installed ledger imported authoring code')
sys.meta_path.insert(0,NoAuthoring())
from hepta.hia_agent_service import HIAAgentService
from hepta.hia_agent_store import AgentStore,AgentRejected,wire
from hepta.hia_slot_ledger_native import SOURCE,SELECTOR,admitted_slot_ledger
from hepta import hia_execution_budget as budget
assert Path(sys.argv[1]) in SOURCE.parents,SOURCE
def forbidden(*args,**kwargs):raise AssertionError('installed owner entered original policy')
for name in ('slot_snapshot','conditional_slot','hia_adopt','hia_rollback','acquire_slot','lease','release_slot'):
    setattr(HIAAgentService,'_'+name+'_reference',forbidden)
for name in ('put','json','get','get_json','resolve_uri','profile','check_profile','transaction'):
    setattr(AgentStore,'_'+name+'_reference',forbidden)
HIAAgentService._call_reference=forbidden
AgentStore._ref=forbidden
budget._ReferenceExecutionBudgetStore.__init__=forbidden
budget._ReferenceBudgetClaim.__init__=forbidden
os.environ.update(json.loads(sys.argv[2]))
service=HIAAgentService(sys.argv[3]);store=service.store
base=store.put(b'installed-base','native');candidate=store.put(b'installed-candidate','native')
ticket=store.request_journal.admit('hia_adopt','a'*64,'installed-ledger',lambda *args:None)
def adopt(connection):
    result=store.slot_ledger.operate(2,service,slot='installed-slot',context='ctx-wheel',
        expected={'generation':'0','epoch':'0'},candidate=candidate,baseline=base,abi=b'{}',connection=connection)
    return {'current':result.current(),'receipt':store.json({'current':result.current()},'adoption-receipt',_connection=connection)}
committed=ticket.atomic(adopt,lambda value:value)
assert committed['current']=={'generation':'1','epoch':'1'}
# The installed ledger and SQL are real. Only this explicitly foreign image
# checker is stubbed; this wheel control makes no real child/proof claim.
service._native=lambda *args,**kwargs:(b'foreign',{'signatures':{}},None)
lease=service.acquire_slot('installed-slot')
assert service._lease(lease)==lease
assert service._lease(lease)==lease
service.close()
service=HIAAgentService(sys.argv[3]);store=service.store
assert store.request_journal.admit('hia_adopt','a'*64,'installed-ledger',lambda *args:None).replay_bytes==wire(committed)
assert service._lease(lease)==lease
assert service.release_slot(lease)['released'] is True
try:service._lease(lease)
except AgentRejected as error:assert error.code=='E_HIA_LEASE'
else:raise AssertionError('released lease admitted')
service.close()
original=SOURCE.read_bytes();SOURCE.write_bytes(original+b'\n# installed source changed\n')
try:
    try:admitted_slot_ledger(namespace_admission=object(),request_admission=object())
    except ValueError:pass
    else:raise AssertionError('warm source drift was hidden')
    missing=Path(sys.argv[3]).with_name('source-drift-state')
    try:AgentStore(missing)
    except (ValueError,RuntimeError):pass
    else:raise AssertionError('drifted installed source used a fallback')
    assert not missing.exists()
finally:SOURCE.write_bytes(original)
assert not any(name=='tools' or name.startswith('tools.') for name in sys.modules)
print(json.dumps({'installed_source':str(SOURCE),'atomic_response':committed,'lease':lease,
    'same_journal_restart':True,'source_custody_checked':True,'original_policy_forbidden':True,
    'foreign_native_image_checker_stubbed':True,'real_child_claimed':False,'authoring_imported':False},sort_keys=True))
'''
        d = self.dependencies
        selected = {SELECTOR: str(self.manifest),
            'HEPTA_HIA_ARTIFACT_NAMESPACE_MANIFEST': str(d.manifest),
            'HEPTA_HIA_REQUEST_JOURNAL_MANIFEST': str(d.request_manifest),
            'HEPTA_HIA_EXECUTION_BUDGET_MANIFEST': str(d.budget_manifest),
            'HEPTA_HIA_AGENT_ARTIFACT_STORE_MANIFEST': str(d.byte_manifest)}
        child = subprocess.run([sys.executable, '-I', '-S', '-B', '-c', program, str(installed),
            json.dumps(selected), str(self.case / 'wheel-state')], cwd=self.case,
            capture_output=True, text=True, timeout=120)
        (self.case / 'wheel-child.stdout').write_text(child.stdout)
        (self.case / 'wheel-child.stderr').write_text(child.stderr)
        self.assertEqual(child.returncode, 0, child.stderr)
        self.assertTrue(json.loads(child.stdout)['source_custody_checked'])


if __name__ == '__main__':
    unittest.main()
