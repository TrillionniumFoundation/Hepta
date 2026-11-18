"""Exercise the checked-in HIA snapshot and record sources with real SQLite bytes."""
from contextlib import closing
from hashlib import sha256
from pathlib import Path
import sqlite3
import struct
import tempfile
import unittest

from hepta.hia_agent_assembly import assemble_program
from hepta.hia_program_runtime import _Machine, _Owner, _View
from tools.build_hia_json_preflight import build
from tools.build_hia_sqlite_pager import build as build_pager


SOURCES = Path(__file__).resolve().parents[1] / 'examples' / 'hia_bootstrap'


def run_vm(program, request, output_size, scratch_size, *, scratch_out=None):
    owners = [_Owner(-1, bytearray(request)),
              _Owner(-2, bytearray(b'\xa7' * output_size)),
              _Owner(-3, bytearray(b'\xca' * scratch_size))]
    vm = _Machine(program, 4_000_000, 16 << 20, None, 128)
    status, = vm.invoke(vm.functions['f0'], [_View(owners[0], False),
                                             _View(owners[1], True),
                                             _View(owners[2], True)])
    if owners[0].data != request or vm.peak_bytes != 0:
        raise AssertionError('snapshot VM mutated the input or allocated a buffer')
    if scratch_out is not None:
        scratch_out[:] = owners[2].data
    return status, bytes(owners[1].data)


class SqliteSnapshotSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lookup = assemble_program((SOURCES / 'sqlite_rowid_lookup.hepta').read_bytes())
        cls.record = assemble_program((SOURCES / 'sqlite_record_layout.hepta').read_bytes())
        cls.row_import = assemble_program((SOURCES / 'sqlite_agent_row_import.hepta').read_bytes())
        cls.import_batch = assemble_program((SOURCES / 'sqlite_agent_import_batch.hepta').read_bytes())
        cls.cost_sequence = assemble_program((SOURCES / 'sqlite_agent_cost_sequence.hepta').read_bytes())
        cls.wal = assemble_program((SOURCES / 'sqlite_wal_snapshot.hepta').read_bytes())
        cls.key = -(1 << 63)
        cls.blob = bytes(range(256)) * 7
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'committed.sqlite'
            db = sqlite3.connect(path)
            try:
                db.executescript('PRAGMA page_size=512; CREATE TABLE sample(value);')
                db.execute('INSERT INTO sample(rowid,value) VALUES(?,?)', (cls.key, cls.blob))
                db.executemany('INSERT INTO sample(rowid,value) VALUES(?,?)',
                               ((i, b'x' * 171) for i in range(1, 65)))
                db.commit()
                cls.root, = db.execute(
                    "SELECT rootpage FROM sqlite_schema WHERE name='sample'").fetchone()
                cls.expected, = db.execute('SELECT value FROM sample WHERE rowid=?',
                                           (cls.key,)).fetchone()
            finally:
                db.close()
            cls.snapshot = path.read_bytes()

    def lookup_row(self, *, key=None, database=None, output_size=4096, scratch_size=64):
        source = struct.pack('<Qq', self.root, self.key if key is None else key)
        source += self.snapshot if database is None else database
        return run_vm(self.lookup, source, output_size, scratch_size)

    def test_signed_lookup_crosses_table_and_overflow_pages_and_decodes_record(self):
        self.assertEqual(self.snapshot[(self.root - 1) * 512], 5)
        status, out = self.lookup_row()
        self.assertEqual(status, 0)
        tag, size, encoding, leaf = struct.unpack_from('<8s3Q', out)
        self.assertEqual((tag, encoding), (b'HIAROW01', 1))
        self.assertNotEqual(leaf, self.root)
        self.assertEqual(out[32 + size:], b'\xa7' * (len(out) - 32 - size))
        payload = out[32:32 + size]
        status, layout = run_vm(self.record, payload, 72, 16)
        self.assertEqual(status, 0)
        tag, fields, consumed, header = struct.unpack_from('<8s3Q', layout)
        self.assertEqual((tag, fields, consumed), (b'HIASREC1', 1, len(payload)))
        serial, offset, length, scalar = struct.unpack_from('<4Q', layout, 32)
        self.assertEqual((serial, offset, length, scalar),
                         (12 + 2 * len(self.expected), header, len(self.expected), 0))
        self.assertEqual(payload[offset:offset + length], self.expected)
        self.assertEqual(layout[64:], b'\xa7' * 8)

    def test_refusals_leave_output_unchanged(self):
        arguments = [(1, {'database': self.snapshot[:-1]}),
                     (2, {'output_size': 31}),
                     (3, {'scratch_size': 63}),
                     (4, {'key': 0}),
                     (5, {'database': self.snapshot[:18] + b'\x02\x02' + self.snapshot[20:]})]
        for status, kwargs in arguments:
            with self.subTest(status=status):
                self.assertEqual(self.lookup_row(**kwargs),
                                 (status, b'\xa7' * kwargs.get('output_size', 4096)))

    def test_retained_wire_requests_only_path_and_overflow_pages(self):
        page_size = 512
        pages = [self.snapshot[i:i + page_size]
                 for i in range(0, len(self.snapshot), page_size)]
        first = pages[0][:18] + b'\x02\x02' + pages[0][20:]
        header = struct.pack('<I4sq', self.root, b'HSP1', self.key) + first
        resident = {}

        def request(entries, *, scratch_size=72):
            wire = header + struct.pack('<2Q', len(pages), len(entries))
            wire += b''.join(struct.pack('<Q', pgno) + data for pgno, data in entries)
            scratch = bytearray()
            status, output = run_vm(self.lookup, wire, 4096, scratch_size,
                                    scratch_out=scratch)
            return status, output, scratch

        unchanged = b'\xa7' * 4096
        self.assertEqual(request([], scratch_size=71)[:2], (3, unchanged))
        self.assertEqual(request([(1, first)])[:2], (1, unchanged))
        self.assertEqual(request([(3, pages[2]), (2, pages[1])])[:2], (1, unchanged))
        self.assertEqual(request([(2, pages[1][:-1])])[:2], (1, unchanged))
        self.assertEqual(request([(len(pages) + 1, pages[-1])])[:2], (1, unchanged))

        for _ in range(len(pages)):
            status, output, scratch = request(sorted(resident.items()))
            if status == 0:
                self.assertEqual((status, output), self.lookup_row())
                break
            self.assertEqual((status, output), (6, unchanged))
            page, = struct.unpack_from('<Q', scratch, 64)
            self.assertGreaterEqual(page, 2)
            self.assertLessEqual(page, len(pages))
            self.assertNotIn(page, resident)
            resident[page] = pages[page - 1]
        else:
            self.fail('lookup did not finish after receiving the requested pages')
        self.assertGreater(len(resident), 2)
        self.assertLess(len(resident), len(pages) - 1)

    def test_retained_page_walk_includes_all_rows_and_rightmost_child(self):
        size = 512
        pages = [self.snapshot[at:at + size] for at in range(0, len(self.snapshot), size)]
        first = pages[0][:18] + b'\x02\x02' + pages[0][20:]

        def walk(page, *, output_size=4096, include_page=True, reserved=0):
            source = struct.pack('<I4sQ', page, b'HSP2', reserved) + first
            extra = include_page and page != 1
            source += struct.pack('<2Q', len(pages), extra)
            if extra:
                source += struct.pack('<Q', page) + pages[page - 1]
            return run_vm(self.lookup, source, output_size, 72)

        self.assertEqual(walk(self.root, include_page=False), (6, b'\xa7' * 4096))
        self.assertEqual(walk(self.root, reserved=1), (1, b'\xa7' * 4096))
        self.assertEqual(walk(self.root, output_size=31), (2, b'\xa7' * 31))
        status, schema = walk(1)
        self.assertEqual(status, 0)
        self.assertEqual(struct.unpack_from('<8s3Qq', schema), (b'HIABTW01', 13, 1, 1, 1))
        todo = [self.root]
        seen = set()
        rowids = []
        while todo:
            page = todo.pop()
            self.assertNotIn(page, seen)
            seen.add(page)
            status, output = walk(page)
            self.assertEqual(status, 0)
            tag, kind, count, identity = struct.unpack_from('<8s3Q', output)
            self.assertEqual((tag, identity), (b'HIABTW01', page))
            end = 32 + count * 8
            self.assertEqual(output[end:], b'\xa7' * (len(output) - end))
            if kind == 5:
                todo.extend(reversed(struct.unpack_from(f'<{count}Q', output, 32)))
            else:
                self.assertEqual(kind, 13)
                rowids.extend(struct.unpack_from(f'<{count}q', output, 32))
        self.assertEqual(rowids, [self.key, *range(1, 65)])

    def test_sqlite_builds_require_matching_cold_compiler(self):
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            compiler = directory / 'compiler'
            cold = directory / 'cold.json'
            output = directory / 'output'
            compiler.write_bytes(b'not a qualified compiler')
            cold.write_text('{}')
            for candidate in ('sqlite-wal-snapshot', 'sqlite-rowid-lookup',
                              'sqlite-record-layout', 'sqlite-agent-row-import',
                              'sqlite-agent-import-batch', 'sqlite-agent-cost-sequence'):
                with self.subTest(candidate=candidate):
                    with self.assertRaisesRegex(ValueError, 'completed matching native cold'):
                        build(output, compiler, cold, candidate=candidate)
                    self.assertFalse(output.exists())
            with self.assertRaisesRegex(ValueError, 'completed matching native cold'):
                build_pager(output, compiler, cold)
            self.assertFalse(output.exists())

    def test_import_preserves_storage_classes_and_materializes_cost_rowid(self):
        def packet(table, rowid, payload, columns, encoding=1):
            status, layout = run_vm(self.record, payload, 32 + columns * 32, 16)
            self.assertEqual(status, 0)
            return struct.pack('<8sQq2Q', b'HIASQI01', table, rowid, encoding,
                               len(layout)) + layout + payload

        text = 'é'.encode()
        request = packet(2, 1, bytes((4, 17, 1, 0)) + text + b'\xff', 3)
        status, output = run_vm(self.row_import, request, 128, 0)
        wanted = struct.pack('<8s3Q', b'HIAROW01', 1, 2, 3)
        wanted += struct.pack('<9Q', 3, 104, 2, 1, 106, 8, 0, 114, 0)
        wanted += text + struct.pack('<q', -1)
        self.assertEqual((status, output), (0, wanted.ljust(128, b'\xa7')))
        bad = bytearray(request)
        struct.pack_into('<Q', bad, 72 + 32 + 24, 7)
        self.assertEqual(run_vm(self.row_import, bad, 128, 0), (1, b'\xa7' * 128))
        self.assertEqual(run_vm(self.row_import, request, 113, 0), (2, b'\xa7' * 113))
        other_encoding = packet(2, 1, bytes((4, 17, 1, 0)) + text + b'\xff', 3, 2)
        self.assertEqual(run_vm(self.row_import, other_encoding, 128, 0), (5, b'\xa7' * 128))

        key = (1 << 63) - 1
        costs = packet(5, key, bytes((8, 0, 0, 15, 15, 15, 15, 15)) + b'abcde', 7)
        status, output = run_vm(self.row_import, costs, 256, 0)
        self.assertEqual(status, 0)
        self.assertEqual(struct.unpack_from('<8s3Q', output), (b'HIAROW01', 1, 5, 7))
        self.assertEqual(struct.unpack_from('<3Q', output, 32), (1, 200, 8))
        self.assertEqual(output[200:213], struct.pack('<q', key) + b'abcde')

    def test_import_batch_packs_signed_rows_and_refuses_partial_proposals(self):
        # Use a real typed import for the proposal, including its variable offset.
        sqlite_row = bytes((4, 17, 1, 0, 0xC3, 0xA9, 0xFF))
        status, layout = run_vm(self.record, sqlite_row, 128, 16)
        self.assertEqual(status, 0)
        request = struct.pack('<8sQq2Q', b'HIASQI01', 2, 1, 1, len(layout))
        status, row = run_vm(self.row_import, request + layout + sqlite_row, 114, 0)
        self.assertEqual(status, 0)

        def frame(table, key, data):
            return struct.pack('<QqQ', table, key, len(data)) + data

        header = struct.pack('<8s3Q', b'HIASQB01', 1, 7, 2)
        first = frame(2, -(1 << 63), row)
        second = frame(2, -1, row)
        source = header + first + second
        expected = struct.pack('<8s3Q', b'HIATXB01', 1, 7, 2)
        expected += struct.pack('<QqQQ', 2, -(1 << 63), 96, len(row))
        expected += struct.pack('<QqQQ', 2, -1, 96 + len(row), len(row)) + row * 2
        self.assertEqual(run_vm(self.import_batch, source, len(expected) + 1, 0),
                         (0, expected + b'\xa7'))
        self.assertEqual(run_vm(self.import_batch, source, len(expected) - 1, 0),
                         (2, b'\xa7' * (len(expected) - 1)))

        malformed = (source[:-1], source + b'\x00', header + first * 2,
                     header + second + first, header + first + frame(3, 1, row))
        for request in malformed:
            self.assertEqual(run_vm(self.import_batch, request, len(expected), 0),
                             (1, b'\xa7' * len(expected)))

    def test_cost_sequence_seeds_and_removes_same_row_in_one_commit(self):
        high_water = 128
        header = struct.pack('<8s3Q', b'HIASQH01', 1, 7, 78)
        record = bytes((3, 23, 2)) + b'costs' + high_water.to_bytes(2, 'big')
        status, output = run_vm(self.cost_sequence, header + record, 657, 4096)
        self.assertEqual(status, 0)
        key = struct.pack('<8s2Qq', b'HIARID01', 1, 5, high_water)
        row = struct.pack('<8s3Q', b'HIAROW01', 1, 5, 7)
        row += struct.pack('<6Q', 1, 200, 8, 0, 208, 0)
        row += struct.pack('<3Q', 3, 208, 0) * 5 + struct.pack('<q', high_water)

        def wal(kind, table=0, key=b'', value=b'', count=0):
            prefix = struct.pack('<8s7Q', b'HIAWAL01', 96 + len(key) + len(value),
                                 7, kind, table, len(key), len(value), count)
            prefix += key + value
            return prefix + sha256(prefix).digest()

        expected = wal(1) + wal(2, 5, key, row) + wal(3, 5, key) + wal(4, count=2)
        self.assertEqual(output, expected + b'\xa7')
        already = struct.pack('<8s3Q', b'HIASQH01', 1, 7, high_water) + record
        malformed = header + bytes((3, 23, 2)) + b'costs' + b'\xff\xff'
        cases = ((already, 656, 4096, 4), (malformed, 656, 4096, 1),
                 (header + record[:-1], 656, 4096, 1),
                 (header + record, 655, 4096, 2), (header + record, 656, 4095, 3))
        for request, extent, workspace, code in cases:
            self.assertEqual(run_vm(self.cost_sequence, request, extent, workspace),
                             (code, b'\xa7' * extent))

    def test_wal_overlay_recovers_committed_row_and_ignores_torn_final_frame(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'wal.sqlite'
            with closing(sqlite3.connect(path, isolation_level=None)) as db:
                db.executescript('PRAGMA page_size=512; CREATE TABLE sample(value);')
                self.assertEqual(db.execute('PRAGMA journal_mode=WAL').fetchone(), ('wal',))
                db.execute('PRAGMA wal_autocheckpoint=0')
                db.execute('INSERT INTO sample(rowid,value) VALUES(?,?)', (self.key, b'first'))
                first_wal = path.with_name('wal.sqlite-wal').read_bytes()
                db.execute('UPDATE sample SET value=? WHERE rowid=?', (self.blob, self.key))
                updated_wal = path.with_name('wal.sqlite-wal').read_bytes()
                base = path.read_bytes()
                root, = db.execute(
                    "SELECT rootpage FROM sqlite_schema WHERE name='sample'").fetchone()
                live, = db.execute('SELECT value FROM sample WHERE rowid=?', (self.key,)).fetchone()
        self.assertTrue(updated_wal.startswith(first_wal))
        for source, expected, reason in ((updated_wal, live, 0), (updated_wal[:-1], b'first', 1)):
            with self.subTest(reason=reason):
                status, result = run_vm(self.wal, struct.pack('<Q', len(base)) + base + source,
                                        8192, 128)
                self.assertEqual(status, 0)
                tag, page, size, validated, committed, tail = struct.unpack_from('<8s5Q', result)
                self.assertEqual((tag, page, tail), (b'HIASNAP1', 512, reason))
                self.assertLessEqual(committed, validated)
                self.assertGreater(committed, 0)
                self.assertEqual(result[48 + size:], b'\xa7' * (len(result) - 48 - size))
                request = struct.pack('<Qq', root, self.key) + result[48:48 + size]
                status, row = run_vm(self.lookup, request, 4096, 64)
                self.assertEqual(status, 0)
                size, = struct.unpack_from('<Q', row, 8)
                payload = row[32:32 + size]
                status, layout = run_vm(self.record, payload, 64, 16)
                self.assertEqual(status, 0)
                serial, offset, length, scalar = struct.unpack_from('<4Q', layout, 32)
                self.assertEqual(serial, 12 + 2 * len(expected))
                self.assertEqual(payload[offset:offset + length], expected)
                self.assertEqual(scalar, 0)
