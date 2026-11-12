"""Actual-file paging and SQLite order oracle for the native view component.

The production HIA chooses every read range and every returned row. This
fixture only executes that range with os.pread. SQLite and Python history maps
are independent test oracles, never callbacks used by the HIA component.
"""
from __future__ import annotations

import contextlib
import gzip
import hashlib
import json
import math
import os
from pathlib import Path
import random
import struct
import tempfile
import unittest
import zipfile

from hepta.hia_agent_assembly import assemble_program
from hepta.hia_program_runtime import _Machine, _Owner, _View
from tests.hia_namespace_sqlite_reference import SQLiteReference, cell, envelope

ROOT = Path(__file__).resolve().parents[1]
MAGIC = int.from_bytes(b'HIANVW01', 'little')
RECORD_MAGIC = int.from_bytes(b'HIANLR01', 'little')
BAD = 0xfffffffd
MASK = (1 << 64)-1
WIDTH = {1: 6, 2: 3, 3: 5, 4: 6, 5: 7, 6: 4, 7: 5, 8: 3, 9: 5, 10: 3}


def record(kind, table, rowid, cells=()):
    payload = b'' if kind == 2 else struct.pack('<Q', len(cells))+b''.join(map(envelope, cells))
    span = 80+len(payload)
    return struct.pack('<8Q', RECORD_MAGIC, 1, kind, table, rowid&MASK, len(payload), span, 0)+payload+struct.pack('<QQ', span, RECORD_MAGIC)


def begin(table, order, pending, committed, *, session=(101, 202), view=701, generation=801):
    return struct.pack('<20Q', MAGIC, 1, *session, 1, 0, 0, 0, 501, view, generation, table, order, 601 if pending else 0, pending, 602, committed, 0, 0, 0)


def command(code, call, session=(101, 202)):
    return struct.pack('<20Q', MAGIC, code, *session, call, *([0]*15))


def acknowledgement(h, payload=b'', status=0, error=0):
    return struct.pack('<20Q', MAGIC, 3, *h[2:4], h[4], h[5], 1, status, h[8], h[9], len(payload), h[11], h[12], error, 0, 0, 0, 0, 0, 0)+payload


class ActualFiles:
    """Mechanical fixed-prefix descriptor mapping, with no row iteration."""
    def __init__(self, test, committed, pending=()):
        self.test = test
        self.directory = tempfile.TemporaryDirectory(prefix='hia-namespace-view-')
        self.paths = {601: Path(self.directory.name)/'pending', 602: Path(self.directory.name)/'data'}
        self.descriptors = {}
        self.rows = {}
        self.history = {601: list(pending), 602: list(committed)}
        self.ends = {}
        for lease, records in ((601, pending), (602, committed)):
            offset = 0
            with self.paths[lease].open('xb') as stream:
                for item in records:
                    raw = record(*item)
                    self.rows[lease, offset, len(raw)] = item
                    stream.write(raw)
                    offset += len(raw)
                stream.flush()
                os.fsync(stream.fileno())
            self.ends[lease] = offset
            self.descriptors[lease] = os.open(self.paths[lease], os.O_RDONLY)

    def read(self, h, limit=None):
        lease, offset, size = h[8:11]
        self.test.assertIn(lease, self.descriptors)
        self.test.assertGreater(size, 0)
        self.test.assertLessEqual(size, 4096)
        self.test.assertLessEqual(offset+size, self.ends[lease])
        if limit is not None:
            size = min(size, limit)
        payload = os.pread(self.descriptors[lease], size, offset)
        type(self.test).reads += 1
        type(self.test).bytes_read += len(payload)
        self.test.log({'kind': 'actual_pread', 'test_id': self.test.id(), 'lease': lease,
                       'offset': offset, 'requested': h[10], 'issued_syscall_count': size,
                       'returned_hex': payload.hex(), 'stat': self.stat(lease)})
        return payload

    def stat(self, lease):
        s = os.fstat(self.descriptors[lease])
        return {'device': s.st_dev, 'inode': s.st_ino, 'bytes': s.st_size, 'mode': s.st_mode,
                'mtime_ns': s.st_mtime_ns, 'ctime_ns': s.st_ctime_ns}

    def append(self, lease, item):
        raw = record(*item)
        offset = self.ends[lease]
        with self.paths[lease].open('ab') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        self.rows[lease, offset, len(raw)] = item
        self.ends[lease] += len(raw)
        self.history[lease].append(item)

    def close(self):
        for descriptor in self.descriptors.values():
            os.close(descriptor)
        self.directory.cleanup()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class Cursor:
    def __init__(self, test, files, table=8, order=1, *, session=(101, 202), view=701, generation=801):
        self.test, self.files = test, files
        self.session = session
        self.call = 1
        self.work = bytearray(12288)
        self.initial = begin(table, order, files.ends[601], files.ends[602], session=session, view=view, generation=generation)
        code, out = test.invoke(self.initial, self.work)
        test.assertEqual(code, 0)
        self.h = struct.unpack('<32Q', out)

    def send(self, raw):
        code, out = self.test.invoke(raw, self.work)
        self.h = struct.unpack('<32Q', out)
        self.test.assertEqual(self.h[:4], (MAGIC, code, *self.session))
        self.test.assertEqual(self.h[26:], (1, 0, 0, 0, 0, 0))
        if code != 1:
            self.test.assertEqual(self.h[7:11], (0, 0, 0, 0))
        return code

    def next(self, *, limit=None, eintr=False):
        self.call += 1
        code = self.send(command(2, self.call, self.session))
        if eintr and code == 1:
            old = self.h
            code = self.send(acknowledgement(old, status=1, error=4))
            self.test.assertEqual(code, 1)
            self.test.assertEqual(self.h[8:11], old[8:11])
            self.test.assertEqual(self.h[5], old[5]+1)
        while code == 1:
            code = self.send(acknowledgement(self.h, self.files.read(self.h, limit)))
        if code == 3:
            self.test.assertEqual(self.h[15:20], (0, 0, 0, 0, 0))
            return None
        self.test.assertEqual(code, 0, self.h)
        lease, offset, span, rowid, kind = self.h[15:20]
        self.test.assertEqual(kind, 1)
        self.test.assertIn((lease, offset, span), self.files.rows)
        item = self.files.rows[lease, offset, span]
        self.test.assertEqual((item[0], item[1], item[2]&MASK), (1, self.h[13], rowid))
        return item[2], (lease, offset, span)

    def all(self, **options):
        rows = []
        while True:
            item = self.next(**options)
            if item is None:
                return rows
            rows.append(item)

    def close(self):
        self.call += 1
        self.test.assertEqual(self.send(command(4, self.call, self.session)), 0)
        before = bytes(self.work)
        self.test.assertEqual(self.send(command(2, self.call+1, self.session)), BAD)
        self.test.assertEqual(bytes(self.work), before)


class NamespaceViewsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = (ROOT/'examples/hia_bootstrap/agent_namespace_views.hiaasm').read_bytes()
        cls.program = assemble_program(cls.raw)
        cls.entry = cls.program.as_dict()['functions'][0]
        cls.reference = SQLiteReference()
        if cls.reference.version != '3.46.1':
            raise RuntimeError('exact SQLite 3.46.1 view-order reference required')
        cls.entries = cls.observations = cls.reads = cls.bytes_read = 0
        cls.ledger = cls.pages = None
        cls.page_hashes = set()
        cls.evidence = Path(os.environ['HIA_NAMESPACE_VIEWS_LEDGER']) if os.environ.get('HIA_NAMESPACE_VIEWS_LEDGER') else None
        if cls.evidence:
            cls.evidence.mkdir(parents=True, exist_ok=False)
            cls.ledger = gzip.open(cls.evidence/'invocations.jsonl.gz', 'wt', encoding='utf-8')
            cls.pages = zipfile.ZipFile(cls.evidence/'workspace-pages.zip', 'w', zipfile.ZIP_DEFLATED, compresslevel=1)
        for table, width in WIDTH.items():
            cls.reference.execute('CREATE TABLE view%d(%s)' % (table, ','.join('c%d' % c for c in range(width))))

    @classmethod
    def tearDownClass(cls):
        if cls.ledger:
            cls.ledger.close()
            cls.pages.close()
            (cls.evidence/'counts.json').write_text(json.dumps({
                'scope': 'PAGED VIEW DEVELOPMENT ONLY; NO COMMIT/MIGRATION OR ORDINARY STORE QUALIFICATION',
                'entries': cls.entries, 'oracle_observations': cls.observations, 'actual_preads': cls.reads,
                'actual_pread_bytes': cls.bytes_read, 'workspace_bytes': 12288, 'max_requested_read_bytes': 4096,
                'unique_workspace_pages': len(cls.page_hashes), 'sqlite_version': cls.reference.version,
                'sqlite_source_id': cls.reference.source_id, 'sqlite_statements': cls.reference.entries,
                'source_sha256': hashlib.sha256(cls.raw).hexdigest()}, sort_keys=True, indent=2)+'\n')
        cls.reference.close()

    def capture(self, raw):
        chunks = []
        for at in range(0, len(raw), 4096):
            page = raw[at:at+4096]
            digest = hashlib.sha256(page).hexdigest()
            chunks.append(digest)
            if self.pages and digest not in self.page_hashes:
                self.pages.writestr(digest, page)
                self.page_hashes.add(digest)
        return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(), 'pages': chunks}

    def log(self, value):
        if self.ledger:
            self.ledger.write(json.dumps(value, sort_keys=True, separators=(',', ':'))+'\n')
            self.ledger.flush()

    def invoke(self, raw, work, output_size=256):
        original, before = bytes(raw), bytes(work)
        owners = [_Owner(-1, bytearray(original)), _Owner(-2, bytearray(output_size)), _Owner(-3, work)]
        machine = _Machine(self.program, 8000000, 128 << 20, None, 96)
        code = machine.invoke(self.entry, [_View(owners[0], False), _View(owners[1], True), _View(owners[2], True)])[0]
        out = bytes(owners[1].data)
        type(self).entries += 1
        self.assertEqual(bytes(owners[0].data), original)
        self.log({'kind': 'vm_entry', 'entry': type(self).entries, 'test_id': self.id(), 'input_hex': original.hex(),
                  'workspace_before': self.capture(before), 'workspace_after': self.capture(bytes(work)),
                  'output_hex': out.hex(), 'return': code, 'output_descriptor_bytes': output_size})
        return code, out

    def oracle(self, committed, pending, table, order):
        self.reference.execute('DELETE FROM view%d' % table)
        latest = {}
        for history in (committed, pending):
            for kind, target, rowid, *body in history:
                if target != table or kind == 3:
                    continue
                if kind == 2:
                    result = self.reference.execute('DELETE FROM view%d WHERE rowid=?1' % table, (cell(rowid),))
                    latest.pop(rowid, None)
                else:
                    cells = body[0]
                    sql = 'INSERT OR REPLACE INTO view%d(rowid,%s) VALUES(%s)' % (table, ','.join('c%d' % i for i in range(WIDTH[table])), ','.join('?%d' % (i+1) for i in range(WIDTH[table]+1)))
                    result = self.reference.execute(sql, (cell(rowid), *cells))
                    latest[rowid] = (kind, target, rowid, cells)
                self.assertIsNone(result['error'])
        order_by = 'rowid' if order == 1 else 'c0 COLLATE BINARY,c1 COLLATE BINARY,rowid'
        result = self.reference.execute('SELECT rowid FROM view%d ORDER BY %s' % (table, order_by))
        self.assertIsNone(result['error'])
        return [struct.unpack('<q', row[0][1])[0] for row in result['rows']], latest

    def compare(self, committed, pending=(), table=8, order=1, **options):
        expected, latest = self.oracle(committed, pending, table, order)
        with ActualFiles(self, committed, pending) as files:
            cursor = Cursor(self, files, table, order)
            rows = cursor.all(**options)
            self.assertEqual([rowid for rowid, _ in rows], expected)
            for rowid, descriptor in rows:
                self.assertEqual(files.rows[descriptor], latest[rowid])
            cursor.close()
        type(self).observations += 1
        self.log({'kind': 'sqlite_order', 'test_id': self.id(), 'table': table, 'order': order,
                  'expected_rowids': expected, 'actual_rowids': [item[0] for item in rows],
                  'committed_records_hex': [record(*item).hex() for item in committed],
                  'pending_records_hex': [record(*item).hex() for item in pending]})

    def reject(self, raw, work=None, output_size=256):
        state = bytearray(12288) if work is None else bytearray(work)
        self.assertEqual(self.invoke(raw, state, output_size)[0], BAD)
        after = bytes(state)
        self.assertEqual(self.invoke(begin(8, 1, 0, 0), state)[0], BAD)
        self.assertEqual(bytes(state), after)

    def test_signed_rowids_ten_tables_latest_tombstones_and_other_tables(self):
        for table, width in WIDTH.items():
            cells = tuple(cell(v) for v in [None, -7, 0.5, 'é\0', b'\xff', 9, '9'][:width])
            changed = tuple(cell(v) for v in [b'x', 0, -0.0, '', None, 8, '8'][:width])
            committed = [(1, table, -5, cells), (1, table, 0, cells), (1, table, 9, cells),
                         (1, table, 9, changed), (1, (table % 10)+1, 33, (cell(None),)*WIDTH[(table % 10)+1])]
            pending = [(2, table, 0), (1, table, -(1 << 63), cells), (1, table, (1 << 63)-1, cells),
                       (2, table, 9), (1, table, 9, cells)]
            self.compare(committed, pending, table)
        self.compare([(3, 5, 0, (cell('9223372036854775807x'),))], table=5)

    def test_versions_latest_key_before_order_and_signed_tie_break(self):
        def row(rowid, slot, generation):
            return 1, 8, rowid, (cell(slot), cell(generation), cell('artifact'))
        committed = [row(5, 'a', 0), row(-5, 'm', 1), row(2, 'm', 1), row(9, 'z', 9)]
        pending = [row(5, 'zz', -8), (2, 8, 9), row(-5, 'm', 1), row(3, 'a', 5)]
        self.compare(committed, pending, order=2)
        self.compare([row(1, 'old', 0), row(1, 'new', 0), (2, 8, 1)], order=2)
        self.compare([], order=2)

    def test_versions_five_classes_exact_integer_real_and_fixed_random(self):
        pairs = [(cell(None), cell(-1)), (cell(-1), cell(0.0)), (cell(0), cell(-0.0)),
                 (cell((1 << 53)+1), cell(float(1 << 53))), (cell(-(1 << 63)), cell(float(-(1 << 63)))),
                 (cell((1 << 63)-1), cell(float(1 << 63))), (cell(math.inf), cell('')), (cell(''), cell(b'')),
                 ((2, struct.pack('<Q', 0x7ff8000000000001)), cell(None)),
                 ((3, b'\xff\0'), (3, b'\xff\0\x01')), (cell(b'\x00'), cell(b'\xff'))]
        randomizer = random.Random(0x4849414e56573031)
        for _ in range(7):
            pairs.append(((1, struct.pack('<Q', randomizer.getrandbits(64))), (2, struct.pack('<Q', randomizer.getrandbits(64)))))
        for index, (left, right) in enumerate(pairs):
            values = [(1, 8, 7, (left, cell(3), cell('a'))), (1, 8, -2, (right, cell(3), cell('b')))]
            if index % 2:
                values = [(kind, table, rowid, (cell('same'), cells[0], cells[2])) for kind, table, rowid, cells in values]
            self.compare(values, order=2)

    def test_bounded_key_windows_and_unread_large_nonkey_payload(self):
        for kind in (3, 4):
            base = b'\xff\x00a\xc0'*4096+b'z'
            rows = [(1, 8, -1, ((kind, base+b'\x01'), cell(2), cell(b'x'*(1 << 20)))),
                    (1, 8, 1, ((kind, base+b'\x00'), cell(2), cell(b'end')))]
            before = type(self).bytes_read
            self.compare(rows, order=2)
            self.assertLess(type(self).bytes_read-before, 1 << 20)

    def test_actual_partial_reads_eintr_and_immutable_captured_extents(self):
        row = lambda n: (1, 8, n, (cell('x'), cell(n), cell('id')))
        self.compare([row(1)], limit=1, eintr=True)
        with ActualFiles(self, [row(1)], [row(2)]) as files:
            cursor = Cursor(self, files)
            files.append(601, (2, 8, 1))
            files.append(602, row(3))
            self.assertEqual([item[0] for item in cursor.all()], [1, 2])
            before = type(self).reads
            self.assertIsNone(cursor.next())
            self.assertEqual(type(self).reads, before)
            fresh = Cursor(self, files, session=(303, 404), view=702, generation=802)
            self.assertEqual([item[0] for item in fresh.all()], [2, 3])
            cursor.close()
            fresh.close()
        type(self).observations += 1

    def test_read_error_short_read_unknown_ack_and_protocol_correlation(self):
        with ActualFiles(self, [(2, 8, 4)]) as files:
            cursor = Cursor(self, files)
            cursor.call += 1
            self.assertEqual(cursor.send(command(2, cursor.call)), 1)
            work, h = bytes(cursor.work), cursor.h
            for status, errno, expected in ((0, 0, 522), (1, 5, 266)):
                state = bytearray(work)
                code, out = self.invoke(acknowledgement(h, status=status, error=errno), state)
                self.assertEqual((code, struct.unpack_from('<Q', out, 160)[0]), (2, expected))
                self.assertEqual(self.invoke(command(4, 3), state)[0], 0)
            self.reject(acknowledgement(h, status=2), work)
            valid = acknowledgement(h, files.read(h))
            for offset, value in ((0, 0), (8, 2), (16, 999), (24, 999), (32, 1), (40, 0), (48, 2),
                                  (56, 3), (64, 601), (72, h[9]+1), (80, 17), (88, 702), (96, 802),
                                  (104, 1), (112, 1), (152, 1)):
                bad = bytearray(valid)
                struct.pack_into('<Q', bad, offset, value)
                self.reject(bad, work)
            self.reject(valid+b'x', work)
            self.reject(valid[:-1], work)
            self.reject(command(4, 3), work)
            for offset, value in ((8, 1), (40, MASK), (48, 0), (56, 20), (568, 601), (576, 0),
                                  (584, 8), (592, 16), (600, 6144), (656, 1)):
                changed = bytearray(work)
                struct.pack_into('<Q', changed, offset, value)
                self.reject(valid, changed)

    def test_initial_closed_short_descriptors_and_call_boundaries(self):
        valid = begin(8, 1, 0, 0)
        for offset, value in ((0, 0), (8, 2), (32, 0), (40, 1), (64, 0), (72, 0), (80, 0),
                              (88, 0), (88, 11), (96, 0), (96, 3), (112, MASK), (120, 0), (128, MASK), (136, 1)):
            bad = bytearray(valid)
            struct.pack_into('<Q', bad, offset, value)
            self.reject(bad)
        self.reject(begin(7, 2, 0, 0))
        for n in (0, 1, 63, 159):
            self.reject(valid[:n])
        self.reject(valid+b'\0')
        self.reject(valid, output_size=255)
        work = bytearray(12287)
        self.assertEqual(self.invoke(valid, work)[0], BAD)
        self.assertEqual(work, bytes(12287))
        with ActualFiles(self, []) as files:
            cursor = Cursor(self, files)
            idle = bytes(cursor.work)
            for raw in (command(2, 1), command(2, 3), command(2, 2, (101, 203))):
                self.reject(raw, idle)
            exhausted = bytearray(idle)
            struct.pack_into('<Q', exhausted, 32, MASK)
            self.reject(command(2, 0), exhausted)
            cursor.close()

    def test_actual_corrupt_record_headers_footers_and_key_extents(self):
        valid = record(1, 8, 1, (cell('x'), cell(2), cell('id')))
        mutations = [(0, 0), (8, 2), (16, 4), (24, 11), (40, MASK), (48, len(valid)+1),
                     (56, 1), (len(valid)-16, len(valid)+1), (len(valid)-8, 0)]
        for offset, value in mutations:
            raw = bytearray(valid)
            struct.pack_into('<Q', raw, offset, value)
            with ActualFiles(self, []) as files:
                files.paths[602].write_bytes(raw)
                files.ends[602] = len(raw)
                cursor = Cursor(self, files)
                cursor.call += 1
                code = cursor.send(command(2, cursor.call))
                while code == 1:
                    code = cursor.send(acknowledgement(cursor.h, files.read(cursor.h)))
                self.assertEqual((code, cursor.h[20]), (2, 11))
                self.assertEqual(cursor.h[15:20], (0, 0, 0, 0, 0))
        for offset, value in ((64, 2), (72, 5), (80, MASK)):
            raw = bytearray(valid)
            struct.pack_into('<Q', raw, offset, value)
            second = record(1, 8, 2, (cell('y'), cell(3), cell('id')))
            with ActualFiles(self, []) as files:
                files.paths[602].write_bytes(raw+second)
                files.ends[602] = len(raw)+len(second)
                cursor = Cursor(self, files, order=2)
                cursor.call += 1
                code = cursor.send(command(2, cursor.call))
                while code == 1:
                    code = cursor.send(acknowledgement(cursor.h, files.read(cursor.h)))
                self.assertEqual((code, cursor.h[20]), (2, 11))


if __name__ == '__main__':
    unittest.main(verbosity=2)
