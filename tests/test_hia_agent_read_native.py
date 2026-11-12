"""Original page-owner oracle, independent VM and actual HIA read decisions.

The page-only oracle calls the retained original service method on already
retrieved bytes and a real SQLite cursor table. It makes no artifact-authority
claim. The separate integration module exercises actual AgentStore files and
the installed worker envelope.
"""
from __future__ import annotations
import ctypes
from functools import lru_cache
from hashlib import sha256
import json
import os
from pathlib import Path
import sqlite3
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from hepta.hia_agent_read_native import (NativeAgentRead, NativeAgentReadStore,
    AgentReadReceipt, REQUEST_MAGIC, RESULT_MAGIC, SCHEMA, SELECTOR, SOURCE,
    request_packet, output_capacity)

ROOT = Path(__file__).resolve().parents[1]
_MISSING = object()


@lru_cache(maxsize=1)
def checked():
    from hepta.hia_agent_assembly import assemble_program
    program = assemble_program(SOURCE.read_bytes())
    entry = next(f for f in program.as_dict()['functions'] if f['name'] == 'f0')
    return program, entry


class VM:
    def __init__(self):
        self.program, self.entry = checked()

    def call(self, raw, data, capacity=None):
        from hepta.hia_program_runtime import _Machine, _Owner, _View
        capacity = output_capacity(raw) if capacity is None else capacity
        owners = [_Owner(-1, bytearray(raw)), _Owner(-2, bytearray(data)),
                  _Owner(-3, bytearray(b'\xa5' * capacity))]
        machine = _Machine(self.program, 4_000_000, 16 << 20, None, 128)
        count = machine.invoke(self.entry, [_View(owners[0], False),
            _View(owners[1], True), _View(owners[2], True)])[0]
        if bytes(owners[0].data) != raw or bytes(owners[1].data) != data:
            raise AssertionError('VM artifact-read input changed')
        return count, bytes(owners[2].data)


class Machine:
    def __init__(self, image):
        self.image = image

    def call(self, raw, data, capacity=None):
        capacity = output_capacity(raw) if capacity is None else capacity
        request = ctypes.create_string_buffer(len(raw) + 16)
        artifact = ctypes.create_string_buffer(len(data) + 16)
        output = ctypes.create_string_buffer(capacity + 16)
        if raw:
            ctypes.memmove(request, raw, len(raw))
        if data:
            ctypes.memmove(artifact, data, len(data))
        ctypes.memset(ctypes.addressof(request) + len(raw), 0xb7, 16)
        ctypes.memset(ctypes.addressof(artifact) + len(data), 0xd3, 16)
        ctypes.memset(output, 0xa5, capacity)
        ctypes.memset(ctypes.addressof(output) + capacity, 0xc9, 16)
        count = self.image._entry(request, len(raw), artifact, len(data), output, capacity)
        if (request.raw != raw + b'\xb7' * 16 or artifact.raw != data + b'\xd3' * 16
                or output.raw[capacity:] != b'\xc9' * 16):
            raise AssertionError('native artifact-read input or canary changed')
        return count, output.raw[:capacity]


def reference(data, *, escaped=False):
    if escaped:
        return {'id': 'artifact-\x00"\\\u2603', 'sha256': sha256(data).hexdigest(),
                'uri': 'hepta:\u03bb/\n"\\'}
    return {'id': 'artifact-page-fixture', 'sha256': sha256(data).hexdigest(),
            'uri': 'hepta:artifact-page-fixture'}


class PageStore:
    """Only semantic-oracle inputs, not a replacement for real Store authority."""
    def __init__(self, data):
        self.data = data
        self.db = sqlite3.connect(':memory:', isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute('CREATE TABLE cursors (id TEXT PRIMARY KEY, artifact_id TEXT, sha256 TEXT, offset INTEGER)')

    def get(self, ref):
        return self.data, {'kind': 'already-retrieved-oracle-input'}

    def close(self):
        self.db.close()


def _prepare(store, ref, maximum, cursor):
    args = {'artifact': dict(ref), 'max_bytes': maximum}
    if cursor is not _MISSING:
        args['cursor'] = 'retained-oracle-cursor'
        if cursor is not None:
            row = {'artifact_id': ref['id'], 'sha256': ref['sha256'], 'offset': 0} | cursor
            store.db.execute('INSERT INTO cursors VALUES (?,?,?,?)',
                (args['cursor'], row['artifact_id'], row['sha256'], row['offset']))
    return args


def _rows(store):
    return [list(row) for row in store.db.execute('SELECT * FROM cursors ORDER BY id')]


def original_page(data, ref, maximum, cursor=_MISSING):
    from hepta.hia_agent_service import HIAAgentService
    store = PageStore(data)
    try:
        args = _prepare(store, ref, maximum, cursor)
        # Force the original wire encoder as the independent semantic oracle.
        # This does not select or replace the actual native implementation.
        with patch.dict(os.environ, {}, clear=True):
            result = HIAAgentService._reference_hia_read(SimpleNamespace(store=store), args)
        return result, _rows(store)
    finally:
        store.close()


def native_page(image, data, ref, maximum, cursor=_MISSING):
    store = PageStore(data)
    try:
        args = _prepare(store, ref, maximum, cursor)
        result = NativeAgentReadStore(store, image).read(args)
        return result, _rows(store)
    finally:
        store.close()


def corpus():
    return [
        ('empty', b'', 512, _MISSING, False),
        ('ascii', b'abc', 512, _MISSING, False),
        ('boundary', b'a' * 511 + '\u20ac'.encode(), 512, _MISSING, False),
        ('complete-artifact-invalid', b'a' * 512 + b'\xff', 512, _MISSING, False),
        ('all-c0', bytes(range(32)) * 2, 512, _MISSING, False),
        ('binary-one-remainder', b'\xff' * 4, 512, _MISSING, False),
        ('escaped-cursor-identity', b'x' * 513, 512, _MISSING, True),
        ('negative-offset', b'x' * 520, 512, {'offset': -515}, False),
        ('positive-eof', b'abc', 512, {'offset': 3}, False),
        ('binary64-integral-limit', b'x' * 513, 512.0, _MISSING, False),
    ]


def packet_for(data, ref, maximum, cursor=_MISSING):
    row = None
    if cursor is not _MISSING and cursor is not None:
        row = {'artifact_id': ref['id'], 'sha256': ref['sha256'], 'offset': 0} | cursor
    return request_packet(ref, maximum, cursor_present=cursor is not _MISSING, row=row)


def decode_raw(result):
    count, output = result
    if count < 128 or count > len(output):
        raise AssertionError(('foreign read result', count, len(output)))
    raw = output[:count]
    h = struct.unpack_from('<16Q', raw)
    if h[:2] != (RESULT_MAGIC, 1):
        raise AssertionError('unexpected read magic/version')
    if h[2]:
        return h, (), raw
    lengths = struct.unpack_from('<5Q', raw, 128)
    at, fields = 168, []
    for length in lengths:
        fields.append(raw[at:at + length])
        at += length
    if at != count or sum(lengths) != h[11]:
        raise AssertionError('native field extents do not cover the output')
    return h, tuple(fields), raw


class AgentReadSourceTests(unittest.TestCase):
    def test_bad_cold_builder_refuses_before_output_or_compilation(self):
        from tools.build_hia_agent_read import build
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            compiler = folder / 'compiler'; compiler.write_bytes(b'not an admitted compiler')
            cold = folder / 'cold.json'; cold.write_text('{}')
            with patch('tools.qualify_hia_selfhost.compile_stage',
                       side_effect=AssertionError('native compile entered')):
                with self.assertRaisesRegex(ValueError, 'completed matching native cold'):
                    build(folder / 'must-not-exist', compiler, cold)
            self.assertFalse((folder / 'must-not-exist').exists())

    def test_fixture_requires_explicit_exclusive_mode_before_any_output(self):
        class Fixture(AgentReadNativeTests):
            pass
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            evidence = folder / 'evidence'
            cold = folder / 'cold.json'; cold.write_text('{}')
            env = {'HEPTA_HIA_AGENT_READ_EVIDENCE': str(evidence)}
            with patch.dict(os.environ, env, clear=True), patch(
                    'tools.qualify_hia_selfhost.compile_stage',
                    side_effect=AssertionError('native compile entered')), patch(
                    'tools.qualify_hia_selfhost.build_seed',
                    side_effect=AssertionError('implicit seed entered')):
                with self.assertRaisesRegex(ValueError, 'requires an explicit'):
                    Fixture.setUpClass()
            with patch.dict(os.environ, env | {'HEPTA_HIA_AGENT_READ_COLD_REPORT': str(cold)}, clear=True):
                with self.assertRaisesRegex(ValueError, 'cold report lacks a compiler'):
                    Fixture.setUpClass()
            with patch.dict(os.environ, env | {'HEPTA_HIA_AGENT_READ_COLD_REPORT': str(cold),
                    'HEPTA_HIA_AGENT_READ_DEVELOPMENT_COMPILER': '/unread'}, clear=True), patch.object(
                    Path, 'read_bytes', side_effect=AssertionError('read before conflicting-mode refusal')):
                with self.assertRaisesRegex(ValueError, 'cannot be combined'):
                    Fixture.setUpClass()
            self.assertFalse(evidence.exists())

    def test_selected_missing_or_empty_image_refuses_before_store_effects(self):
        from hepta.hia_agent_service import HIAAgentService
        from hepta.hia_agent_store import AgentRejected
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for selected in ('', str(root / 'missing-manifest')):
                with self.subTest(selected=selected), patch.dict(os.environ, {SELECTOR: selected}, clear=True), patch(
                        'hepta.hia_agent_service.AgentStore', side_effect=AssertionError('store opened')):
                    with self.assertRaises(AgentRejected) as rejected:
                        HIAAgentService(root / 'must-not-exist')
                    self.assertEqual(rejected.exception.code, 'E_HIA_READ_NATIVE_CUSTODY')
                self.assertFalse((root / 'must-not-exist').exists())

    def test_actual_sqlite_signed_offset_and_integral_binary64_transport(self):
        ref = reference(b'hello')
        store = PageStore(b'hello')
        try:
            for value in (-(1 << 63), -515, -1, 0, (1 << 63) - 1):
                with self.subTest(offset=value):
                    store.db.execute('DELETE FROM cursors')
                    store.db.execute('INSERT INTO cursors VALUES (?,?,?,?)',
                        ('page-test', ref['id'], ref['sha256'], value))
                    row = store.db.execute('SELECT * FROM cursors').fetchone()
                    raw = request_packet(ref, 512.0, cursor_present=True, row=row)
                    words = struct.unpack_from('<16Q', raw)
                    self.assertEqual(words[:4], (REQUEST_MAGIC, 1, 31, 512))
                    self.assertEqual(struct.unpack('<q', struct.pack('<Q', words[4]))[0], value)
                    self.assertEqual(words[5:], (5,) + (0,) * 10)
        finally:
            store.close()

class AgentReadNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tools.qualify_hia_selfhost import compile_stage
        cold = os.environ.get('HEPTA_HIA_AGENT_READ_COLD_REPORT')
        development = os.environ.get('HEPTA_HIA_AGENT_READ_DEVELOPMENT_COMPILER')
        if cold and development:
            raise ValueError('artifact read development compiler cannot be combined with a cold report')
        if not cold and not development:
            raise ValueError('artifact read fixture requires an explicit matching cold report or development compiler')
        cls.cold = Path(cold) if cold else None
        cls.temporary = None
        if cls.cold:
            from tools.build_hia_json_preflight import admit_cold_build
            cold_bytes = cls.cold.read_bytes()
            report = json.loads(cold_bytes)
            try:
                nested_bytes = Path(report['nested_report']).read_bytes()
                nested = json.loads(nested_bytes)
                cls.compiler = Path(nested['generations'][-1]['produced_image'])
            except (KeyError, IndexError, TypeError) as error:
                raise ValueError('artifact read cold report lacks a compiler') from error
            compiler_bytes = cls.compiler.read_bytes()
            admitted = admit_cold_build(compiler_bytes, cold_bytes)
        else:
            cls.compiler = Path(development).resolve(strict=True)
            compiler_bytes = cls.compiler.read_bytes()
        source_bytes = SOURCE.read_bytes()
        evidence = os.environ.get('HEPTA_HIA_AGENT_READ_EVIDENCE')
        if evidence:
            cls.folder = Path(evidence) / cls.__name__
            cls.folder.mkdir(mode=0o700, parents=True)
        else:
            cls.temporary = tempfile.TemporaryDirectory(prefix='hia-agent-read-')
            cls.folder = Path(cls.temporary.name)
        if cls.cold:
            from tools.build_hia_agent_read import build
            cls.manifest = build(cls.folder / 'qualified', cls.compiler, cls.cold)
            record = json.loads(cls.manifest.read_bytes())
            image_path = cls.manifest.parent / record['image_path']
            receipt = json.loads((cls.manifest.parent / 'build.json').read_bytes())['native_compile_receipt']
            mode = 'MATCHING_CURRENT_SOURCE_COLD_BUILD'
            if (cls.cold.read_bytes() != cold_bytes
                    or Path(report['nested_report']).read_bytes() != nested_bytes
                    or admit_cold_build(compiler_bytes, cold_bytes) != admitted):
                raise AssertionError('artifact read fixture cold evidence changed')
        else:
            image_path, receipt = compile_stage(cls.folder, 'agent-read-development',
                                               cls.compiler, source_bytes)
            raw_image = image_path.read_bytes()
            record = {'schema': SCHEMA, 'source_sha256': sha256(source_bytes).hexdigest(),
                'image_path': image_path.name, 'image_sha256': sha256(raw_image).hexdigest(),
                'compiler_sha256': sha256(compiler_bytes).hexdigest()}
            cls.manifest = cls.folder / 'manifest.json'
            cls.manifest.write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
            mode = 'EXPLICIT_DEVELOPMENT_COMPILER_NOT_COLD_QUALIFIED'
        image_bytes = image_path.read_bytes()
        cls.image = NativeAgentRead(image_bytes, record['image_sha256'])
        if SOURCE.read_bytes() != source_bytes or cls.compiler.read_bytes() != compiler_bytes:
            raise AssertionError('artifact read fixture source/compiler changed')
        (cls.folder / 'fixture.json').write_text(json.dumps({'mode': mode,
            'manifest': record, 'native_compile_receipt': receipt,
            'cold_report': str(cls.cold) if cls.cold else None,
            'matching_current_source_cold_qualified': bool(cls.cold)}, indent=2, sort_keys=True) + '\n')

    @classmethod
    def tearDownClass(cls):
        if cls.temporary is not None:
            cls.temporary.cleanup()


    def _evidence(self, name, raw, data, result, extra=None):
        root = self.folder / name
        root.mkdir(mode=0o700)
        count, output = result
        records = {}
        for filename, value in (('request.bin', raw), ('artifact.bin', data), ('workspace.bin', output)):
            path = root / filename
            path.write_bytes(value)
            records[filename] = {'path': str(path), 'bytes': len(value), 'sha256': sha256(value).hexdigest()}
        document = {'return': count, 'files': records, 'extra': extra or {}}
        (root / 'receipt.json').write_text(json.dumps(document, sort_keys=True, indent=2) + '\n')
        return document

    def test_actual_machine_matches_independent_vm_complete_workspace_and_original_page_owner(self):
        rows = []
        actual, vm = Machine(self.image), VM()
        for label, data, maximum, cursor, escaped in corpus():
            with self.subTest(case=label):
                ref = reference(data, escaped=escaped)
                raw = packet_for(data, ref, maximum, cursor)
                expected = vm.call(raw, data)
                observed = actual.call(raw, data)
                self.assertEqual(observed, expected)
                self.assertEqual(native_page(self.image, data, ref, maximum, cursor),
                                 original_page(data, ref, maximum, cursor))
                h, fields, _ = decode_raw(observed)
                self.assertEqual(h[2], 0)
                self.assertEqual(fields[:3], tuple(ref[key].encode() for key in ('id', 'sha256', 'uri')))
                rows.append(self._evidence('vm-' + label, raw, data, observed))
        (self.folder / 'native-vm-witnesses.json').write_text(json.dumps(rows, indent=2, sort_keys=True) + '\n')

    def test_actual_double_wire_budget_halving_matches_original_owner_for_all_escapes(self):
        from hepta.hia_agent_store import wire
        cases = {
            'all-c0': bytes(range(32)) * 2051,
            'nul': b'\0' * 65537,
            'quotes-backslashes': b'"\\' * 32769,
            'short-escapes': bytes((8, 9, 10, 12, 13)) * 13108,
            'unicode': ('\u03b1\U0001f600\U00010437\u6f22' * 6000).encode(),
            'mixed': ('\u03b1\0"\n\\\U0001f600' * 10000).encode(),
            'binary': bytes(range(256)) * 300,
            'invalid-only-after-first-page': b'a' * 65536 + b'\xff',
        }
        observations = []
        for name, data in cases.items():
            for maximum in (512, 65536):
                with self.subTest(case=name, maximum=maximum):
                    ref = reference(data, escaped=True)
                    result = native_page(self.image, data, ref, maximum)
                    expected = original_page(data, ref, maximum)
                    self.assertEqual(result, expected)
                    raw = packet_for(data, ref, maximum)
                    receipt = self.image.transition(raw, data)
                    with patch.dict(os.environ, {}, clear=True):
                        actual_budget = len(wire(result[0]['content'])) + len(wire(wire(result[0]['content']).decode()))
                    self.assertEqual(receipt.wire_budget, actual_budget)
                    self.assertLessEqual(actual_budget, 230000)
                    observations.append(self._evidence(name + '-' + str(maximum), raw, data,
                        Machine(self.image).call(raw, data),
                        {'original_owner_result': expected[0], 'original_cursor_rows': expected[1],
                         'actual_double_wire_bytes': actual_budget}))
        (self.folder / 'page-budget-witnesses.json').write_text(json.dumps(observations, indent=2, sort_keys=True) + '\n')

    def test_actual_utf8_whole_artifact_edges_and_retained_cursor_positions(self):
        valid = [b'\x00', b'\x7f', b'\xc2\x80', b'\xdf\xbf', b'\xe0\xa0\x80',
                 b'\xed\x9f\xbf', b'\xee\x80\x80', b'\xef\xbf\xbf',
                 b'\xf0\x90\x80\x80', b'\xf4\x8f\xbf\xbf']
        invalid = [b'\x80', b'\xc0\x80', b'\xc1\xbf', b'\xc2', b'\xdf',
                   b'\xe0\x9f\xbf', b'\xed\xa0\x80', b'\xef\xbf',
                   b'\xf0\x8f\xbf\xbf', b'\xf4\x90\x80\x80', b'\xf5\x80\x80\x80',
                   b'\xf0\x90\x80', b'\xff']
        rows = []
        for group, chunks in (('valid', valid), ('invalid', invalid)):
            for index, chunk in enumerate(chunks):
                data = b'a' * 511 + chunk + b'z' * 7
                ref = reference(data)
                with self.subTest(group=group, bytes=chunk.hex()):
                    actual = native_page(self.image, data, ref, 512)
                    self.assertEqual(actual, original_page(data, ref, 512))
                    self.assertEqual(actual[0]['encoding'], 'utf8' if group == 'valid' else 'base64')
                    rows.append({'group': group, 'tail_hex': chunk.hex(), 'result': actual})
        data = ('a\u20ac' * 135).encode()
        ref = reference(data)
        # Retained hand-written signed positions include inside-codepoint and
        # negative slices. Compare the original result without looping a
        # deliberately non-progressing corrupted cursor.
        for offset in (-(1 << 63), -541, -540, -539, -515, -1, 0, 1, 2, 3, 4, 539, 540, (1 << 63) - 1):
            with self.subTest(offset=offset):
                actual = native_page(self.image, data, ref, 512, {'offset': offset})
                self.assertEqual(actual, original_page(data, ref, 512, {'offset': offset}))
                rows.append({'offset': offset, 'result': actual})
        (self.folder / 'utf8-and-offset-witnesses.json').write_text(json.dumps(rows, indent=2, sort_keys=True) + '\n')

    def test_actual_cursor_missing_cross_artifact_and_sha_refusals_match_original(self):
        from hepta.hia_agent_store import AgentRejected
        data = b'original artifact bytes' * 31
        ref = reference(data)
        failures = [None, {'artifact_id': 'another-artifact'}, {'sha256': 'b' * 64},
                    {'artifact_id': b'not-text'}, {'sha256': None}]
        rows = []
        for index, cursor in enumerate(failures):
            with self.subTest(cursor=repr(cursor)):
                outcomes = []
                for operation in (native_page, lambda image, *a: original_page(*a)):
                    with self.assertRaises(AgentRejected) as rejected:
                        operation(self.image, data, ref, 512, cursor)
                    outcomes.append((rejected.exception.code, str(rejected.exception)))
                self.assertEqual(outcomes[0], outcomes[1])
                self.assertEqual(outcomes[0][0], 'E_HIA_CURSOR')
                raw = packet_for(data, ref, 512, cursor)
                rows.append(self._evidence('cursor-refusal-' + str(index), raw, data,
                                          Machine(self.image).call(raw, data), {'error': outcomes[0]}))
        (self.folder / 'cursor-refusals.json').write_text(json.dumps(rows, indent=2, sort_keys=True) + '\n')

    def test_actual_protocol_refusals_preserve_all_input_and_output_boundaries(self):
        data = b'data'
        raw = packet_for(data, reference(data), 512)
        variants = []
        def altered(offset, value):
            copy = bytearray(raw);struct.pack_into('<Q', copy, offset, value);return bytes(copy)
        for offset, value in ((0, 0), (8, 2), (16, 32), (16, 2), (24, 511),
                              (24, 65537), (40, 4), (48, 1), (128, (1 << 64) - 1),
                              (160, (1 << 64) - 1)):
            variants.append((altered(offset, value), None, 128))
        variants.append((raw + b'unclaimed', None, 128))
        variants.extend(((raw[:167], None, 4294967293), (b'', None, 4294967293),
                         (raw, 127, 4294967293),
                         (raw, output_capacity(raw) - 1, 4294967294)))
        rows = []
        for index, (request, capacity, returned) in enumerate(variants):
            with self.subTest(index=index):
                expected = VM().call(request, data, capacity)
                observed = Machine(self.image).call(request, data, capacity)
                self.assertEqual(observed, expected)
                self.assertEqual(observed[0], returned)
                if returned == 128:
                    h, fields, _ = decode_raw(observed)
                    self.assertEqual(h[2], 2)
                    self.assertFalse(fields)
                    self.assertFalse(any(h[3:]))
                    self.assertEqual(observed[1][128:], b'\xa5' * (len(observed[1]) - 128))
                else:
                    self.assertEqual(observed[1], b'\xa5' * len(observed[1]))
                rows.append(self._evidence('protocol-' + str(index), request, data, observed))
        (self.folder / 'protocol-refusals.json').write_text(json.dumps(rows, indent=2, sort_keys=True) + '\n')

    def test_actual_complete_original_64mib_artifact_limit_remains_readable(self):
        from hepta.hia_agent_store import AgentStore, MAX_ARTIFACT_BYTES
        self.assertEqual(MAX_ARTIFACT_BYTES, 64 * 1024 * 1024)
        data = b'x' * (MAX_ARTIFACT_BYTES - 1) + b'\xff'
        with tempfile.TemporaryDirectory(prefix='hia-read-full-artifact-') as temporary, patch.dict(
                os.environ, {}, clear=True):
            store = AgentStore(Path(temporary) / 'state')
            try:
                ref = store.put(data, 'artifact-read-full-limit-fixture')
                args = {'artifact': ref, 'max_bytes': 512}
                from hepta.hia_agent_service import HIAAgentService
                expected = HIAAgentService._reference_hia_read(SimpleNamespace(store=store), args)
                statements = []
                store.db.set_trace_callback(statements.append)
                try:
                    actual = NativeAgentReadStore(store, self.image).read(args)
                finally:
                    store.db.set_trace_callback(None)
                self.assertEqual(actual, expected)
                self.assertEqual(actual['encoding'], 'base64')
                self.assertFalse(any(statement in ('BEGIN', 'BEGIN IMMEDIATE', 'COMMIT', 'ROLLBACK')
                                     for statement in statements))
                self.assertEqual(store.db.execute('SELECT offset FROM cursors WHERE id=?',
                    (actual['next_cursor'],)).fetchone()[0], 512)
                raw = packet_for(data, ref, 512)
                beyond = self.image.transition(raw, data + b'x')
                self.assertEqual(beyond.status, 2)
                (self.folder / 'full-artifact-limit.json').write_text(json.dumps({
                    'actual_stored_bytes': len(data), 'source_sha256': sha256(data).hexdigest(),
                    'actual_result': actual, 'original_owner_result': expected,
                    'actual_sql_statements': statements,
                    'first_unsupported_artifact_extent': len(data) + 1,
                    'actual_extent_refusal_hex': beyond.raw.hex()}, indent=2, sort_keys=True) + '\n')
            finally:
                store.close()


if __name__ == '__main__':
    unittest.main()
