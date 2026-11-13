"""Fixed original-VM controls for the declared selected-cell byte contract."""
from __future__ import annotations
import ast
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import unittest

from hepta import hia_sqlite_btree_cell_native as bridge
from hepta.hia_agent_assembly import assemble_program, render_assembly
from hepta.hia_program import verify_program
from hepta.hia_program_runtime import _Machine, _Owner, _View
from tools import generate_hia_sqlite_btree_cell as author

ROOT = Path(__file__).resolve().parents[2]
EXPECTED_NAMES = (
    'test_01_Core_roundtrip_and_original_caps',
    'test_02_all_page_kinds_sizes_reserves_and_page_one',
    'test_03_all_rowid_boundaries_and_nonminimal_widths',
    'test_04_overflow_local_partition_and_large_payload_descriptors',
    'test_05_page_one_database_header_admission',
    'test_06_selected_cell_bounds_and_truncations',
    'test_07_protocol_controls_and_output_capacity',
    'test_08_pointer_geometry_index_and_page_number_refusals',
    'test_09_nonminimal_payload_width_and_numeric_limit',
    'test_10_minimum_cell_padding_and_zero_payloads',
    'test_11_bridge_custody_and_exact_public_types',
    'test_12_complete_upstream_sources_and_explicit_scope',
)
EXPECTED_COUNTS = (0, 72, 36, 108, 22, 14, 24, 14, 30, 16, 3, 0)
def varint(value, width=None):
    if type(value) is not int or not 0 <= value < 2**64:
        raise ValueError('exact u64 required by independent fixture encoder')
    minimum = 9 if value >= 2**56 else max(1, (value.bit_length() + 6) // 7)
    width = minimum if width is None else width
    if not minimum <= width <= 9:
        raise ValueError('fixture width cannot represent value')
    if width == 9:
        prefix = value >> 8
        return bytes([128 | ((prefix >> (7 * i)) & 127) for i in range(7, -1, -1)] + [value & 255])
    return bytes([((value >> (7 * i)) & 127) | (128 if i else 0) for i in range(width - 1, -1, -1)])


def command(size=512, reserved=0, page=2, index=0, pages=4294967294,
            magic=bridge.MAGIC, operation=1, zero=0):
    return struct.pack('<8Q', magic, operation, size, reserved, page, index, pages, zero)


def make_cell(kind, usable, payload=17, key=128, rowid_width=None, payload_width=None,
              child=3, overflow=4):
    prefix = child.to_bytes(4, 'big') if kind in (2, 5) else b''
    if kind != 5:
        prefix += varint(payload, payload_width)
    if kind in (5, 13):
        prefix += varint(key, rowid_width)
    if kind == 5:
        return prefix, {'size': len(prefix), 'payload': 0, 'local': 0, 'payload_relative': 0,
                        'child': child, 'key': key, 'overflow': 0, 'overflow_relative': 0,
                        'overflow_pages': 0, 'overflow_last': 0}
    # Reference fixture math uses Python divmod, independent of HIA division.
    maximum = usable - 35 if kind == 13 else ((usable - 12) * 64) // 255 - 23
    minimum = ((usable - 12) * 32) // 255 - 23
    local = payload
    if payload > maximum:
        _, remainder = divmod(payload - minimum, usable - 4)
        local = minimum + remainder
        if local > maximum:
            local = minimum
    body = bytes((i * 31 + 7) & 255 for i in range(local))
    cell = prefix + body
    overflow_relative = len(cell) if payload > local else 0
    count, final = 0, 0
    if payload > local:
        cell += overflow.to_bytes(4, 'big')
        count, final = divmod(payload - local, usable - 4)
        if final: count += 1
        else: final = usable - 4
    cell += b'\x9d' * max(0, 4 - len(cell))
    return cell, {'size': len(cell), 'payload': payload, 'local': local,
                  'payload_relative': len(prefix), 'child': child if kind == 2 else 0,
                  'key': key if kind == 13 else payload, 'overflow': overflow if payload > local else 0,
                  'overflow_relative': overflow_relative, 'overflow_pages': count,
                  'overflow_last': final}


def fixture(kind=13, size=512, reserved=0, page=2, payload=17, key=128,
            rowid_width=None, payload_width=None, pages=4294967294):
    usable = size - reserved
    cell, meta = make_cell(kind, usable, payload, key, rowid_width, payload_width)
    offset = usable - len(cell)
    header = 100 if page == 1 else 0
    pointer = header + (12 if kind in (2, 5) else 8)
    if offset < pointer + 2:
        raise ValueError('fixture selected cell cannot fit alongside its header')
    raw = bytearray(size)
    if page == 1:
        raw[:16] = b'SQLite format 3\0'
        raw[16:18] = (1 if size == 65536 else size).to_bytes(2, 'big')
        raw[18:24] = bytes((1, 1, reserved, 64, 32, 32))
        raw[24:28] = (7).to_bytes(4, 'big')
        raw[28:32] = pages.to_bytes(4, 'big')
        raw[44:48] = (4).to_bytes(4, 'big')
        raw[56:60] = (1).to_bytes(4, 'big')
        raw[92:96] = (7).to_bytes(4, 'big')
        raw[96:100] = (3053002).to_bytes(4, 'big')
    raw[header] = kind
    raw[header+3:header+5] = (1).to_bytes(2, 'big')
    raw[header+5:header+7] = offset.to_bytes(2, 'big')
    if kind in (2, 5): raw[header+8:header+12] = (5).to_bytes(4, 'big')
    raw[pointer:pointer+2] = offset.to_bytes(2, 'big')
    raw[offset:usable] = cell
    expected = (page, kind, usable, 1, 0, offset, meta['size'],
                0 if kind == 5 else offset + meta['payload_relative'],
                meta['payload'], meta['local'], meta['child'], meta['key'], meta['overflow'],
                0 if not meta['overflow'] else offset + meta['overflow_relative'],
                meta['overflow_pages'], meta['overflow_last'])
    return bytes(raw), command(size, reserved, page, pages=pages), struct.pack('<16Q', *expected), cell


def changed(raw, offset, value, width=1):
    result = bytearray(raw)
    result[offset:offset+width] = value.to_bytes(width, 'big')
    return bytes(result)


def boundary_cell(kind, cell, offset=None):
    raw, control, _, _ = fixture(kind=kind)
    out = bytearray(raw)
    offset = 512 - len(cell) if offset is None else offset
    pointer = 12 if kind in (2, 5) else 8
    out[5:7] = offset.to_bytes(2, 'big')
    out[pointer:pointer+2] = offset.to_bytes(2, 'big')
    out[offset:512] = cell[:512-offset]
    return bytes(out), control
class VMImage:
    def __init__(self, program):
        self.program, self.calls, self.label = program, [], 'unlabelled'

    def raw(self, source, output, control):
        owners = [_Owner(-1, bytearray(source)), _Owner(-2, bytearray(output)), _Owner(-3, bytearray(control))]
        # A declared bound for this new source test, not a change to Core gates.
        machine = _Machine(self.program, 10000000, 1 << 20, None, 256)
        row = {'case': self.label, 'source_before_hex': bytes(source).hex(),
               'output_before_hex': bytes(output).hex(), 'control_before_hex': bytes(control).hex(),
               'actual_returned': False}
        self.calls.append(row)
        try:
            status = machine.invoke(self.program.as_dict()['functions'][0],
                                    [_View(owners[0], False), _View(owners[1], True), _View(owners[2], True)])[0]
            row.update(status=status, actual_returned=True)
        except BaseException as exc:
            row['exception_type'] = type(exc).__module__ + '.' + type(exc).__qualname__
            raise
        finally:
            row.update(source_after_hex=bytes(owners[0].data).hex(), output_after_hex=bytes(owners[1].data).hex(),
                       control_after_hex=bytes(owners[2].data).hex())
        return status, bytes(owners[1].data), bytes(owners[2].data)

    def _entry(self, s, n, o, m, w, k):
        status, output, control = self.raw(ctypes.string_at(s, n), ctypes.string_at(o, m), ctypes.string_at(w, k))
        ctypes.memmove(o, output, m)
        ctypes.memmove(w, control, k)
        return status



class SQLiteBtreeCellSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.document = author.document()
        cls.program = verify_program(cls.document)
        cls.assembly = render_assembly(cls.document)
        cls.vm = VMImage(cls.program)
        cls.kernel = object.__new__(bridge.NativeSQLiteBtreeCell)
        cls.kernel._entry = cls.vm._entry

    def setUp(self):
        self.vm.label = self.id()

    @classmethod
    def tearDownClass(cls):
        name = os.environ.get('HEPTA_SQLITE_BTREE_CELL_SOURCE_EVIDENCE')
        if name is None: return
        root = Path(name)
        values = {'sqlite_btree_cell.hiaasm': cls.assembly,
                  'CORE.json': json.dumps(cls.document, sort_keys=True, indent=2) + '\n',
                  'VM-RAW.json': json.dumps({'schema': 'hia.sqlite-btree-cell.source-vm-raw.v1',
                     'native_executed': False, 'compiler_executed': False,
                     'calls': cls.vm.calls}, sort_keys=True, indent=2) + '\n'}
        for name, body in values.items():
            with (root / name).open('x', encoding='utf-8') as f:
                f.write(body); f.flush(); os.fsync(f.fileno())

    def accepted(self, **kwargs):
        raw, control, expected, cell = fixture(**kwargs)
        self.assertEqual(self.vm.raw(raw, b'\xa5' * 128, control), (128, expected, control))
        return raw, control, expected, cell

    def accept_raw(self, raw, control, expected):
        self.assertEqual(self.vm.raw(raw, b'\xa5' * 128, control), (128, expected, control))

    def refused(self, raw, status, control, capacity=128):
        output = b'\xa5' * capacity
        self.assertEqual(self.vm.raw(raw, output, control), (status, output, control))

    def test_01_Core_roundtrip_and_original_caps(self):
        self.assertEqual(assemble_program(self.assembly).as_dict(), self.program.as_dict())
        self.assertEqual(self.assembly, render_assembly(author.document()))
        self.assertLessEqual(len(self.assembly.encode()), 1 << 20)
        self.assertLessEqual(len(self.assembly.split('\n')), 16384)
        funcs = self.document['functions']; blocks = [b for f in funcs for b in f['blocks']]
        self.assertEqual(len(funcs), 10); self.assertLessEqual(len(blocks), 1536)
        self.assertLessEqual(sum(len(b['ops']) for b in blocks), 8192)
        for f in funcs:
            self.assertLessEqual(len(f['blocks']), 256); self.assertLessEqual(len(f['params']), 16)
        def walk(value):
            if isinstance(value, dict):
                for k, v in value.items():
                    if k in ('args', 'params') and isinstance(v, list):
                        self.assertLessEqual(len(v), 16)
                    yield from walk(v)
            elif isinstance(value, list):
                for v in value: yield from walk(v)
            elif isinstance(value, str) and value.startswith('v') and value[1:].isdigit():
                yield int(value[1:])
        self.assertLessEqual(max(walk(self.document)), 2047)

    def test_02_all_page_kinds_sizes_reserves_and_page_one(self):
        for size in (512, 1024, 2048, 4096, 8192, 16384, 32768, 65536):
            for kind in (2, 5, 10, 13):
                for reserved in (0, 32):
                    self.accepted(kind=kind, size=size, reserved=reserved)
        for size in (512, 65536):
            for kind in (5, 13):
                for reserved in (0, 32):
                    self.accepted(kind=kind, size=size, reserved=reserved, page=1)

    def test_03_all_rowid_boundaries_and_nonminimal_widths(self):
        for kind in (5, 13):
            for key in (0, 1, 127, 128, 16383, 16384, 2**63-1, 2**63, 2**64-1):
                self.accepted(kind=kind, key=key)
            for width in range(1, 10):
                self.accepted(kind=kind, key=1, rowid_width=width)

    def test_04_overflow_local_partition_and_large_payload_descriptors(self):
        for size in (512, 4096, 65536):
            for reserved in (0, 32):
                usable = size - reserved
                for kind in (2, 10, 13):
                    maximum = usable - 35 if kind == 13 else ((usable - 12) * 64) // 255 - 23
                    minimum = ((usable - 12) * 32) // 255 - 23
                    for payload in (maximum, maximum + 1, minimum + usable - 4,
                                    maximum + usable - 4, maximum + 1 + usable - 4, 2147483647):
                        self.accepted(kind=kind, size=size, reserved=reserved, payload=payload)

    def test_05_page_one_database_header_admission(self):
        raw, control, expected, _ = fixture(page=1, size=4096)
        edits = ((0, 0, 1), (15, 1, 1), (16, 512, 2), (18, 0, 1), (18, 3, 1),
                 (19, 0, 1), (19, 3, 1), (20, 1, 1), (21, 63, 1), (22, 31, 1),
                 (23, 31, 1), (44, 0, 4), (44, 5, 4), (56, 0, 4), (56, 4, 4),
                 (72, 1, 1), (91, 1, 1), (28, 4294967293, 4))
        for offset, value, width in edits:
            self.refused(changed(raw, offset, value, width), bridge.REFUSE_FORMAT, control)
        for write, read in ((2, 1), (1, 2), (2, 2)):
            self.accept_raw(changed(changed(raw, 18, write), 19, read), control, expected)
        stale = changed(changed(raw, 28, 99, 4), 92, 6, 4)
        self.accept_raw(stale, control, expected)

    def test_06_selected_cell_bounds_and_truncations(self):
        shapes = ((5, (3).to_bytes(4, 'big')),
                  (13, b'\x80' * 4), (10, b'\x80' * 4),
                  (2, (3).to_bytes(4, 'big')),
                  (13, b'\x14\x01\0\0'), (10, b'\x14\0\0\0'),
                  (2, (3).to_bytes(4, 'big') + b'\x14'),
                  (13, b'\0\x80\x80\x80'))
        for kind, cell in shapes:
            raw, control = boundary_cell(kind, cell)
            self.refused(raw, bridge.REFUSE_TRUNCATED, control)
        for kind in (2, 10, 13):
            _, _, _, cell = fixture(kind=kind, payload=1000)
            raw, control = boundary_cell(kind, cell[:-4])
            self.refused(raw, bridge.REFUSE_TRUNCATED, control)
        raw, control, _, _ = fixture()
        self.refused(raw[:-1], bridge.REFUSE_PROTOCOL, control)
        self.refused(raw + b'\0', bridge.REFUSE_PROTOCOL, control)
        self.refused(changed(raw, 5, 512, 2), bridge.REFUSE_FORMAT, control)

    def test_07_protocol_controls_and_output_capacity(self):
        raw, control, _, _ = fixture()
        for c in (b'', b'\0', control[:-1], control+b'\0', control+b'\0'*8):
            self.refused(raw, bridge.REFUSE_PROTOCOL, c)
        for fields in ({'magic': 0}, {'operation': 0}, {'operation': 2}, {'zero': 1}):
            self.refused(raw, bridge.REFUSE_PROTOCOL, command(**fields))
        for size in (0, 511, 513, 131072, 4096):
            self.refused(raw, bridge.REFUSE_PROTOCOL, command(size=size))
        for reserved in (256, 33):
            self.refused(raw, bridge.REFUSE_PROTOCOL, command(reserved=reserved))
        for fields in ({'page': 0}, {'pages': 0}, {'pages': 4294967295}, {'page': 2, 'pages': 1}):
            self.refused(raw, bridge.REFUSE_PROTOCOL, command(**fields))
        self.refused(raw, bridge.REFUSE_PROTOCOL, control, capacity=129)
        for capacity in (0, 127, 1):
            self.refused(raw, bridge.REFUSE_CAPACITY, control, capacity=capacity)

    def test_08_pointer_geometry_index_and_page_number_refusals(self):
        raw, control, expected, _ = fixture()
        offset = struct.unpack('<16Q', expected)[5]
        for where, value, width in ((0, 0, 1), (0, 3, 1), (7, 61, 1),
                                    (8, offset-1, 2), (8, 509, 2), (5, 9, 2),
                                    (5, 0, 2), (1, 1, 2), (1, 509, 2), (3, 65535, 2)):
            self.refused(changed(raw, where, value, width), bridge.REFUSE_FORMAT, control)
        for index in (1, 2**64-1):
            self.refused(raw, bridge.REFUSE_INDEX, command(index=index))
        raw, control, _, _ = fixture(kind=5)
        for right in (0, 2):
            self.refused(changed(raw, 8, right, 4), bridge.REFUSE_FORMAT, control)

    def test_09_nonminimal_payload_width_and_numeric_limit(self):
        for kind in (2, 10, 13):
            for width in range(1, 6):
                self.accepted(kind=kind, payload=1, payload_width=width)
            for width in range(6, 10):
                raw, control, _, _ = fixture(kind=kind, payload=1, payload_width=width)
                self.refused(raw, bridge.REFUSE_FORMAT, control)
            raw, control, _, _ = fixture(kind=kind, payload=2147483648)
            self.refused(raw, bridge.REFUSE_LIMIT, control)

    def test_10_minimum_cell_padding_and_zero_payloads(self):
        for kind in (2, 10, 13):
            for width in (1, 2):
                self.accepted(kind=kind, payload=0, key=1, payload_width=width,
                              rowid_width=width if kind == 13 else None)
            for payload in (1, 2):
                self.accepted(kind=kind, payload=payload, key=1)
        for width in (3, 9):
            self.accepted(kind=13, payload=0, key=1, rowid_width=width)
        for kind in (2, 10):
            self.accepted(kind=kind, payload=0, payload_width=5)

    def test_11_bridge_custody_and_exact_public_types(self):
        raw, control, expected, _ = fixture()
        options = dict(page_number=2, database_pages=4294967294, cell_index=0)
        for wrong in (bytearray(raw), '', None):
            with self.assertRaises(TypeError): self.kernel.layout(wrong, **options)
        for name in options:
            for wrong in (False, '1', None, -1):
                with self.assertRaises(ValueError): self.kernel.layout(raw, **{**options, name: wrong})
        for wrong in (False, -1, 33, 256, '0'):
            with self.assertRaises(ValueError): self.kernel.layout(raw, **options, reserved_bytes=wrong)
        for wrong in (b'', raw[:-1], raw+b'\0'):
            with self.assertRaises(ValueError): self.kernel.layout(wrong, **options)
        result = self.kernel.layout(raw, **options)
        self.assertEqual(tuple(result.values()), struct.unpack('<16Q', expected))
        with self.assertRaises(bridge.SQLiteBtreeCellRejected):
            self.kernel.layout(changed(raw, 0, 0), **options)
        raw, _, expected, _ = fixture(kind=5, key=2**64-1)
        result = self.kernel.layout(raw, **options)
        self.assertEqual(tuple(result.values()), struct.unpack('<16Q', expected))
        def bad_entry(kind):
            def entry(s, n, o, m, w, k):
                if kind == 'source': ctypes.memset(s, 0, n)
                if kind == 'control': ctypes.memset(w, 0, 1)
                if kind == 'tail': ctypes.memset(ctypes.addressof(o)+m, 255, 1)
                if kind == 'refused_write': ctypes.memset(o, 0, 1)
                if kind == 'envelope': return 128
                return {'status': 7, 'boolean': True}.get(kind, bridge.REFUSE_PROTOCOL)
            return entry
        fake = object.__new__(bridge.NativeSQLiteBtreeCell)
        for kind in ('source', 'control', 'tail', 'refused_write', 'status', 'boolean', 'envelope'):
            fake._entry = bad_entry(kind)
            with self.assertRaises(bridge.SQLiteBtreeCellProtocolError): fake.layout(raw, **options)

    def test_12_complete_upstream_sources_and_explicit_scope(self):
        pins = {'3.46.0': (400947, '3043b54506525cf526612a003b1923491b54945a41c552cf3054ff56d0e51af6'),
                '3.53.2': (404731, '8374f0b6867459af6d6f73ba6c22a8a6c2fdcaa967bbb913bff59e7612684086')}
        for version, pin in pins.items():
            raw = (ROOT / ('reference/sqlite-'+version+'/btree.c.original')).read_bytes()
            self.assertEqual((len(raw), sha256(raw).hexdigest()), pin)
            for name in ('btreeParseCellAdjustSizeForOverflow', 'btreeParseCellPtrNoPayload',
                         'btreeParseCellPtr', 'btreeParseCellPtrIndex'):
                self.assertIn(name.encode(), raw)
        abi = json.loads((ROOT / 'inputs/hepta/hia_sqlite_btree_cell_abi.json').read_bytes())
        self.assertTrue(abi['single_cell_validation_only'])
        self.assertFalse(abi['whole_page_cell_overlap_freeblock_chain_key_order_or_tree_integrity'])
        self.assertFalse(abi['SQL_pager_btree_mutation_transactions_locks_recovery'])
        self.assertFalse(abi['default_agent_store_changed'])
        self.assertNotIn('sqlite3', bridge.__dict__)
        self.assertNotIn('make_cell', bridge.__dict__)
        nodes = ast.parse(author.source()).body
        self.assertEqual(len(nodes), 10)


if __name__ == '__main__':
    unittest.main()
