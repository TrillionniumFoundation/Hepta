"""Fixed finite source/VM controls for the ordered SQLite page-one decisions."""
from __future__ import annotations

import ast
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import unittest

from hepta import hia_sqlite_database_header_native as bridge
from hepta.hia_agent_assembly import assemble_program, render_assembly
from hepta.hia_program import verify_program
from hepta.hia_program_runtime import _Machine, _Owner, _View
from tools import generate_hia_sqlite_database_header as author

ROOT = Path(__file__).resolve().parents[2]
EXPECTED_NAMES = (
    'test_01_Core_roundtrip_and_all_original_caps',
    'test_02_all_page_sizes_and_reserves',
    'test_03_complete_read_write_version_byte_domains',
    'test_04_page_count_change_counter_and_writable_schema',
    'test_05_WAL_reread_precedes_later_header_checks',
    'test_06_resize_reread_precedes_count_and_usable_checks',
    'test_07_empty_and_reset_preserve_context_metadata',
    'test_08_protocol_refusals_preserve_all_spans',
    'test_09_bridge_full_span_custody_faults',
    'test_10_invalid_public_types_never_enter',
    'test_11_unused_header_words_and_vacuum_metadata',
    'test_12_complete_official_sources_and_explicit_scope',
)
EXPECTED_COUNTS = (0, 16, 512, 16, 18, 32, 16, 36, 6, 0, 18, 0)
PAGE_SIZES = (512, 1024, 2048, 4096, 8192, 16384, 32768, 65536)
DEFAULT_CONTEXT = {
    'page_size': 512, 'usable_size': 512, 'file_pages': 5,
    'reset_database': False, 'writable_schema': False, 'no_wal': False,
    'read_only': False, 'auto_vacuum': False, 'incremental_vacuum': False,
    'wal_ready': False,
}
FAULT_NAMES = ('source_byte', 'control_byte', 'output_canary',
               'entry_replacement', 'boolean_status', 'reserved_output_word')


def header_fixture(*, size=512, reserve=0, pages=5, change=7, valid_for=7,
                   write_version=1, read_version=1, auto=0, incremental=0):
    raw = bytearray(100)
    raw[:16] = b'SQLite format 3\0'
    raw[16:18] = (1 if size == 65536 else size).to_bytes(2, 'big')
    raw[18:24] = bytes((write_version, read_version, reserve, 64, 32, 32))
    for offset, value in ((24, change), (28, pages), (52, auto),
                          (64, incremental), (92, valid_for)):
        raw[offset:offset+4] = value.to_bytes(4, 'big')
    return bytes(raw)


def changed(raw, offset, value, width=1):
    result = bytearray(raw)
    result[offset:offset+width] = value.to_bytes(width, 'big')
    return bytes(result)


def command(context):
    flags = sum(int(context[name]) << bit for bit, name in enumerate(
        ('reset_database', 'writable_schema', 'no_wal', 'read_only',
         'auto_vacuum', 'incremental_vacuum')))
    return struct.pack('<16Q', bridge.COMMAND_MAGIC, 1, context['page_size'],
                       context['usable_size'], context['file_pages'], flags,
                       int(context['wal_ready']), *([0] * 9))


def expected_words(header, context):
    """Independent Python arithmetic projection of the retained full lockBtree."""
    words = [0] * 32
    words[0] = bridge.REPLY_MAGIC
    words[3] = int(context['read_only'])
    words[4] = context['page_size']
    words[5] = context['usable_size']
    words[7] = int(context['auto_vacuum'])
    words[8] = int(context['incremental_vacuum'])
    npage = int.from_bytes(header[28:32], 'big')
    if npage == 0 or header[24:28] != header[92:96]:
        npage = context['file_pages']
    if context['reset_database']:
        npage = 0
    if npage:
        if header[:16] != b'SQLite format 3\0':
            words[1:3] = [4, 26]
            return words
        if header[18] > 2:
            words[3] = 1
        if header[19] > 2:
            words[1:3] = [4, 26]
            return words
        if header[19] == 2 and not context['no_wal']:
            words[9] = 2
            if not context['wal_ready']:
                words[1] = 2
                return words
        else:
            words[9] = 1
        if header[21:24] != b'\x40\x20\x20':
            words[1:3] = [4, 26]
            return words
        page = (header[16] << 8) | (header[17] << 16)
        if page <= 256 or page > 65536 or (page & (page - 1)):
            words[1:3] = [4, 26]
            return words
        usable = page - header[20]
        if page != context['page_size']:
            words[1] = 3
            words[4:6] = [page, usable]
            words[10] = 1
            return words
        if npage > context['file_pages']:
            if not context['writable_schema']:
                words[1:3] = [4, 11]
                return words
            npage = context['file_pages']
        if usable < 480:
            words[1:3] = [4, 26]
            return words
        words[4:6] = [page, usable]
        words[10] = 1
        words[7] = int(int.from_bytes(header[52:56], 'big') != 0)
        words[8] = int(int.from_bytes(header[64:68], 'big') != 0)
    usable = words[5]
    # Positive bounded integers: Python // is independent of HIA divide32.
    maximum = ((usable - 12) * 64) // 255 - 23
    minimum = ((usable - 12) * 32) // 255 - 23
    words[1] = 1
    words[6] = npage
    words[11:16] = [maximum, minimum, usable - 35, minimum, min(maximum, 127)]
    return words


def expected_decision(words):
    return bridge.DatabaseHeaderDecision(
        {1: 'accept', 2: 'open_wal_and_reread', 3: 'resize_and_reread', 4: 'format_error'}[words[1]],
        words[2], bool(words[3]), words[4], words[5], words[6],
        bool(words[7]), bool(words[8]),
        {0: 'unchanged', 1: 'rollback_default', 2: 'wal_default'}[words[9]],
        bool(words[10]), *words[11:16])


class VMImage:
    def __init__(self, program):
        self.program = program
        self.calls = []
        self.label = 'unlabelled'
        self.expected = None

    def raw(self, source, output, control):
        owners = [_Owner(-1, bytearray(source)), _Owner(-2, bytearray(output)),
                  _Owner(-3, bytearray(control))]
        machine = _Machine(self.program, 200000, 1 << 20, None, 256)
        row = {'case': self.label, 'source_before_hex': bytes(source).hex(),
               'output_before_hex': bytes(output).hex(),
               'control_before_hex': bytes(control).hex(),
               'expected_words_before_call': self.expected, 'actual_returned': False}
        self.calls.append(row)
        try:
            status = machine.invoke(self.program.as_dict()['functions'][0],
                                    [_View(owners[0], False), _View(owners[1], True),
                                     _View(owners[2], False)])[0]
            row.update(status=status, actual_returned=True)
        except BaseException as exc:
            row['exception_type'] = type(exc).__module__ + '.' + type(exc).__qualname__
            raise
        finally:
            row.update(source_after_hex=bytes(owners[0].data).hex(),
                       output_after_hex=bytes(owners[1].data).hex(),
                       control_after_hex=bytes(owners[2].data).hex())
        return status, bytes(owners[1].data)

    def _entry(self, source, source_bytes, output, output_bytes, control, control_bytes):
        status, result = self.raw(ctypes.string_at(source, source_bytes),
                                  ctypes.string_at(output, output_bytes),
                                  ctypes.string_at(control, control_bytes))
        ctypes.memmove(output, result, output_bytes)
        return status


class SQLiteDatabaseHeaderSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.document = author.document()
        cls.program = verify_program(cls.document)
        cls.assembly = render_assembly(cls.document)
        cls.vm = VMImage(cls.program)
        cls.kernel = object.__new__(bridge.NativeSQLiteDatabaseHeader)
        cls.kernel._entry = cls.vm._entry
        cls.fault_records = []

    def setUp(self):
        self.vm.label = self.id()
        self.vm.expected = None
        self._before_calls = len(self.vm.calls)

    def tearDown(self):
        self.assertEqual(len(self.vm.calls) - self._before_calls,
                         EXPECTED_COUNTS[EXPECTED_NAMES.index(self._testMethodName)])

    @classmethod
    def tearDownClass(cls):
        evidence = os.environ.get('HEPTA_SQLITE_DATABASE_HEADER_SOURCE_EVIDENCE')
        if evidence is None:
            return
        records = {
            'sqlite_database_header.hiaasm': cls.assembly,
            'CORE.json': json.dumps(cls.document, sort_keys=True, indent=2) + '\n',
            'VM-RAW.json': json.dumps({
                'schema': 'hia.sqlite-database-header.source-vm-raw.v1',
                'native_executed': False, 'compiler_executed': False,
                'calls': cls.vm.calls, 'post_return_faults': cls.fault_records},
                sort_keys=True, indent=2) + '\n'}
        for name, text in records.items():
            with (Path(evidence) / name).open('x', encoding='utf-8') as stream:
                stream.write(text)
                stream.flush()
                os.fsync(stream.fileno())

    def check(self, header=None, **options):
        context = {**DEFAULT_CONTEXT, **options}
        header = header_fixture() if header is None else header
        expected = expected_words(header, context)
        self.vm.expected = list(expected)
        before = len(self.vm.calls)
        result = self.kernel.inspect_header(header, **context)
        self.assertEqual(len(self.vm.calls), before + 1)
        row = self.vm.calls[-1]
        self.assertEqual(row['status'], 256)
        self.assertEqual(row['source_before_hex'], header.hex())
        self.assertEqual(row['source_after_hex'], header.hex())
        self.assertEqual(row['control_before_hex'], command(context).hex())
        self.assertEqual(row['control_after_hex'], command(context).hex())
        self.assertEqual(row['output_before_hex'], (b'\xa5' * 256).hex())
        self.assertEqual(bytes.fromhex(row['output_after_hex']), struct.pack('<32Q', *expected))
        self.assertEqual(result, expected_decision(expected))
        return result

    def raw_refusal(self, source, control, capacity=256):
        self.vm.expected = None
        output = b'\xa5' * capacity
        before = len(self.vm.calls)
        self.assertEqual(self.vm.raw(source, output, control), (bridge.REFUSE_PROTOCOL, output))
        self.assertEqual(len(self.vm.calls), before + 1)
        row = self.vm.calls[-1]
        self.assertEqual(row['source_before_hex'], row['source_after_hex'])
        self.assertEqual(row['control_before_hex'], row['control_after_hex'])

    def test_01_Core_roundtrip_and_all_original_caps(self):
        self.assertEqual(assemble_program(self.assembly).as_dict(), self.program.as_dict())
        self.assertEqual(self.assembly, render_assembly(author.document()))
        self.assertLessEqual(len(self.assembly.encode()), 1 << 20)
        self.assertLessEqual(len(self.assembly.split('\n')), 16384)
        functions = self.document['functions']
        self.assertEqual(len(functions), 11)
        self.assertLessEqual(len(functions), 128)
        blocks = [block for fn in functions for block in fn['blocks']]
        self.assertLessEqual(len(blocks), 1536)
        self.assertLessEqual(sum(len(block['ops']) for block in blocks), 8192)
        for fn in functions:
            self.assertLessEqual(len(fn['blocks']), 256)
            self.assertLessEqual(len(fn['params']), 16)
            self.assertEqual(len(fn['returns']), 1)
        def walk(value):
            if isinstance(value, dict):
                for key, item in value.items():
                    if key in ('args', 'params') and isinstance(item, list):
                        self.assertLessEqual(len(item), 16)
                    yield from walk(item)
            elif isinstance(value, list):
                for item in value:
                    yield from walk(item)
            elif isinstance(value, str) and value.startswith('v') and value[1:].isdigit():
                yield int(value[1:])
        self.assertLessEqual(max(walk(self.document)), 2047)

    def test_02_all_page_sizes_and_reserves(self):
        for size in PAGE_SIZES:
            for reserve in (0, 32):
                with self.subTest(size=size, reserve=reserve):
                    result = self.check(header_fixture(size=size, reserve=reserve),
                                        page_size=size, usable_size=size-reserve)
                    self.assertEqual(result.action, 'accept')
                    self.assertEqual(result.usable_size, size-reserve)
                    self.assertEqual(result.max_leaf, size-reserve-35)

    def test_03_complete_read_write_version_byte_domains(self):
        for write_version in range(256):
            result = self.check(header_fixture(write_version=write_version),
                                read_only=bool(write_version & 1))
            self.assertEqual(result.action, 'accept')
            self.assertEqual(result.read_only, bool(write_version & 1) or write_version > 2)
        for read_version in range(256):
            result = self.check(header_fixture(read_version=read_version))
            self.assertEqual(result.action, 'accept' if read_version < 2 else
                             'open_wal_and_reread' if read_version == 2 else 'format_error')
            if read_version > 2:
                self.assertEqual(result.sqlite_rc, 26)

    def test_04_page_count_change_counter_and_writable_schema(self):
        maximum = (1 << 32) - 1
        cases = (
            (0, 0, 7, False, False), (0, 5, 7, False, False),
            (1, 5, 7, False, False), (5, 5, 7, False, False),
            (6, 5, 7, False, False), (6, 5, 7, True, False),
            (maximum, maximum, 7, False, False),
            (maximum, maximum-1, 7, False, False),
            (maximum, maximum-1, 7, True, False),
            (7, 0, 7, False, False), (7, 0, 7, True, False),
            (7, 3, 8, False, False), (0, maximum, 8, False, False),
            (maximum, 0, 8, False, False),
            (9, 5, 7, False, True), (9, 5, 8, True, True),
        )
        for declared, physical, valid_for, writable, reset in cases:
            self.check(header_fixture(pages=declared, valid_for=valid_for),
                       file_pages=physical, writable_schema=writable, reset_database=reset)

    def test_05_WAL_reread_precedes_later_header_checks(self):
        wal = header_fixture(read_version=2)
        cases = (
            (changed(wal, 21, 63), {}, changed(wal, 21, 63), {'wal_ready': True}, (2, 4)),
            (changed(changed(wal, 16, 1), 17, 0), {},
             changed(changed(wal, 16, 1), 17, 0), {'wal_ready': True}, (2, 4)),
            (changed(wal, 28, 6, 4), {}, changed(wal, 28, 6, 4), {'wal_ready': True}, (2, 4)),
            (changed(wal, 20, 255), {}, changed(wal, 20, 255), {'wal_ready': True}, (2, 4)),
            (changed(wal, 0, 0), {}, changed(wal, 0, 0), {'wal_ready': True}, (4, 4)),
            (changed(wal, 19, 3), {}, changed(wal, 19, 3), {'wal_ready': True}, (4, 4)),
            (wal, {}, wal, {'no_wal': True}, (2, 1)),
            (header_fixture(write_version=255, read_version=2), {},
             header_fixture(write_version=255, read_version=2), {'wal_ready': True}, (2, 1)),
            (changed(wal, 21, 63), {}, header_fixture(read_version=1), {'wal_ready': True}, (2, 1)),
        )
        action = {1: 'accept', 2: 'open_wal_and_reread', 3: 'resize_and_reread', 4: 'format_error'}
        for first, context1, refreshed, context2, expected in cases:
            a = self.check(first, **context1)
            b = self.check(refreshed, **context2)
            self.assertEqual((a.action, b.action), (action[expected[0]], action[expected[1]]))

    def test_06_resize_reread_precedes_count_and_usable_checks(self):
        for size in PAGE_SIZES:
            reserve = 255 if size == 512 else 32
            old_size = 1024 if size == 512 else 512
            head = header_fixture(size=size, reserve=reserve, pages=3)
            a = self.check(head, page_size=old_size, usable_size=old_size, file_pages=2)
            self.assertEqual(a.action, 'resize_and_reread')
            self.assertEqual((a.page_size, a.usable_size), (size, size-reserve))
            b = self.check(head, page_size=size, usable_size=size-reserve, file_pages=2)
            self.assertEqual((b.action, b.sqlite_rc), ('format_error', 11))
            c = self.check(head, page_size=size, usable_size=size-reserve, file_pages=2,
                           writable_schema=True)
            self.assertEqual((c.action, c.sqlite_rc),
                             ('format_error', 26) if size == 512 else ('accept', 0))
            d = self.check(header_fixture(size=size, pages=2), page_size=size,
                           usable_size=size-reserve, file_pages=2)
            self.assertEqual((d.action, d.usable_size), ('accept', size))

    def test_07_empty_and_reset_preserve_context_metadata(self):
        for index, size in enumerate(PAGE_SIZES):
            usable = size - 255
            for reset in (False, True):
                raw = bytearray(b'\xfa' * 100)
                raw[28:32] = (9 if reset else 0).to_bytes(4, 'big')
                result = self.check(bytes(raw), page_size=size, usable_size=usable,
                                    file_pages=10 if reset else 0, reset_database=reset,
                                    read_only=bool(index & 1), auto_vacuum=bool(index & 2),
                                    incremental_vacuum=bool(index & 4))
                self.assertEqual(result.action, 'accept')
                self.assertEqual(result.database_pages, 0)
                self.assertEqual((result.page_size, result.usable_size), (size, usable))
                self.assertEqual(result.sync_mode, 'unchanged')
                self.assertFalse(result.page_size_fixed)
                self.assertEqual((result.auto_vacuum, result.incremental_vacuum),
                                 (bool(index & 2), bool(index & 4)))

    def test_08_protocol_refusals_preserve_all_spans(self):
        good_header = header_fixture()
        good_command = command(DEFAULT_CONTEXT)
        words = list(struct.unpack('<16Q', good_command))
        mutations = ((0, words[0] ^ 1), (1, 0), (1, 2),
                     (2, 0), (2, 511), (2, 513), (2, 65537),
                     (3, 513), (3, 256), (4, 1 << 32), (5, 64), (6, 2))
        for index, value in mutations + tuple((i, 1) for i in range(7, 16)):
            changed_words = list(words)
            changed_words[index] = value
            self.raw_refusal(good_header, struct.pack('<16Q', *changed_words))
        for size in (0, 1, 99, 101, 128):
            self.raw_refusal((good_header + bytes(128))[:size], good_command)
        for size in (0, 1, 255, 257, 512):
            self.raw_refusal(good_header, good_command, capacity=size)
        for size in (0, 1, 127, 129, 256):
            self.raw_refusal(good_header, (good_command + bytes(128))[:size])

    def test_09_bridge_full_span_custody_faults(self):
        header = header_fixture()
        self.vm.expected = expected_words(header, DEFAULT_CONTEXT)
        for fault in FAULT_NAMES:
            image = object.__new__(bridge.NativeSQLiteDatabaseHeader)
            original = self.vm._entry
            row = {'fault': fault, 'test_id': self.id(), 'call_index': len(self.vm.calls),
                   'exception_observed': None}
            self.fault_records.append(row)
            def damaged(s, n, o, m, c, k):
                result = original(s, n, o, m, c, k)
                row['before_fault'] = [ctypes.string_at(s, n+64).hex(),
                                       ctypes.string_at(o, m+64).hex(),
                                       ctypes.string_at(c, k+64).hex()]
                if fault == 'source_byte':
                    ctypes.c_ubyte.from_address(ctypes.addressof(s)).value ^= 1
                elif fault == 'control_byte':
                    ctypes.c_ubyte.from_address(ctypes.addressof(c)).value ^= 1
                elif fault == 'output_canary':
                    ctypes.c_ubyte.from_address(ctypes.addressof(o)+m).value ^= 1
                elif fault == 'entry_replacement':
                    image._entry = original
                elif fault == 'reserved_output_word':
                    ctypes.memmove(ctypes.addressof(o)+16*8, struct.pack('<Q', 1), 8)
                row['after_fault'] = [ctypes.string_at(s, n+64).hex(),
                                      ctypes.string_at(o, m+64).hex(),
                                      ctypes.string_at(c, k+64).hex()]
                row['returned_status_type'] = 'bool' if fault == 'boolean_status' else type(result).__name__
                return False if fault == 'boolean_status' else result
            image._entry = damaged
            with self.assertRaises(bridge.SQLiteDatabaseHeaderProtocolError) as caught:
                image.inspect_header(header, **DEFAULT_CONTEXT)
            row['exception_observed'] = type(caught.exception).__name__
            self.assertEqual(len(self.vm.calls), row['call_index']+1)

    def test_10_invalid_public_types_never_enter(self):
        image = object.__new__(bridge.NativeSQLiteDatabaseHeader)
        attempts = []
        def forbidden(*args):
            attempts.append(args)
            raise AssertionError('invalid public input reached entry')
        image._entry = forbidden
        for header in ('SQLite', bytearray(100), memoryview(bytes(100)), bytes(99), bytes(101), None):
            with self.assertRaises((TypeError, ValueError)):
                image.inspect_header(header, **DEFAULT_CONTEXT)
        cases = (
            ('page_size', True), ('page_size', 512.0), ('page_size', 511),
            ('page_size', 513), ('page_size', 131072),
            ('usable_size', True), ('usable_size', 512.0), ('usable_size', 256),
            ('usable_size', 513), ('file_pages', True), ('file_pages', -1),
            ('file_pages', 1 << 32), ('file_pages', 5.0),
        )
        for name, value in cases:
            with self.assertRaises((TypeError, ValueError)):
                image.inspect_header(header_fixture(), **{**DEFAULT_CONTEXT, name: value})
        for name in ('reset_database', 'writable_schema', 'no_wal', 'read_only',
                     'auto_vacuum', 'incremental_vacuum', 'wal_ready'):
            for value in (0, 1, None):
                with self.assertRaises(TypeError):
                    image.inspect_header(header_fixture(), **{**DEFAULT_CONTEXT, name: value})
        self.assertEqual(attempts, [])

    def test_11_unused_header_words_and_vacuum_metadata(self):
        good = header_fixture()
        original_expected = expected_words(good, DEFAULT_CONTEXT)
        for offset in (40, 44, 48, 56, 60, 68, 72, 96):
            result = self.check(changed(good, offset, 0xffffffff, 4))
            self.assertEqual(result, expected_decision(original_expected))
        for auto in (0, 0xffffffff):
            for incremental in (0, 0x80000000):
                for initial in (False, True):
                    result = self.check(header_fixture(auto=auto, incremental=incremental),
                                        auto_vacuum=initial, incremental_vacuum=initial)
                    self.assertEqual((result.auto_vacuum, result.incremental_vacuum),
                                     (bool(auto), bool(incremental)))
        for version in (1, 255):
            result = self.check(header_fixture(write_version=version), read_only=True)
            self.assertTrue(result.read_only)

    def test_12_complete_official_sources_and_explicit_scope(self):
        manifest = json.loads((ROOT/'reference/UPSTREAM.json').read_text())
        self.assertEqual(manifest['versions'], ['3.46.0', '3.53.2'])
        excerpts = []
        for item in manifest['records']:
            body = (ROOT/'reference'/item['full_path']).read_bytes()
            self.assertEqual(len(body), item['full_bytes'])
            self.assertEqual(sha256(body).hexdigest(), item['full_sha256'])
            excerpt = (ROOT/'reference'/item['excerpt_path']).read_bytes()
            self.assertEqual(excerpt, body[item['start_byte']:item['end_byte_exclusive']])
            self.assertEqual(len(excerpt), 6334)
            self.assertEqual(sha256(excerpt).hexdigest(),
                             '050e7e148071ad26ff2b396e8d0693f3137808bc57d081f7f9d77da9dac8624c')
            self.assertEqual(excerpt.count(b'static int lockBtree(BtShared *pBt)'), 1)
            excerpts.append(excerpt)
        self.assertEqual(excerpts[0], excerpts[1])
        source_tree = ast.parse(author.source())
        helper = next(node for node in source_tree.body
                      if isinstance(node, ast.FunctionDef) and node.name == 'divide32')
        helper_text = ast.get_source_segment(author.source(), helper)
        self.assertEqual(sha256((helper_text + '\n\n').encode()).hexdigest(),
                         '66c11029e507a28ebe804f9ab84228d47b24e9378546dc11a5a690356b7a67b3')
        self.assertFalse(any(isinstance(node, (ast.Div, ast.FloorDiv, ast.Mod))
                             for node in ast.walk(source_tree)))
        abi = json.loads((ROOT/'inputs/hepta/hia_sqlite_database_header_abi.json').read_text())
        self.assertEqual(abi['physical_arguments'], 6)
        self.assertEqual(abi['arithmetic']['HIA_function_count'], 11)
        self.assertEqual(abi['upstream']['complete_lockBtree_identical'], True)
        self.assertEqual(abi['return_status']['4294967293'],
                         'protocol refusal, whole output unchanged')
        for boundary in ('OS read/write locks or I/O',
                         'actual WAL opening and pager page-size mutation or their error paths',
                         'SQL schema/text metadata validation',
                         'database creation/checkpoint/commit/fsync',
                         'default AgentStore activation'):
            self.assertIn(boundary, abi['not_implemented'])


if __name__ == '__main__':
    unittest.main()
