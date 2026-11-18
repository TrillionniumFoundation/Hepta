"""Exercise the checked-in HIA snapshot and record sources with real SQLite bytes."""
from pathlib import Path
import sqlite3
import struct
import tempfile
import unittest

from hepta.hia_agent_assembly import assemble_program
from hepta.hia_program_runtime import _Machine, _Owner, _View
from tools.build_hia_json_preflight import build


SOURCES = Path(__file__).resolve().parents[1] / 'examples' / 'hia_bootstrap'


def run_vm(program, request, output_size, scratch_size):
    owners = [_Owner(-1, bytearray(request)),
              _Owner(-2, bytearray(b'\xa7' * output_size)),
              _Owner(-3, bytearray(b'\xca' * scratch_size))]
    vm = _Machine(program, 4_000_000, 16 << 20, None, 128)
    status, = vm.invoke(vm.functions['f0'], [_View(owners[0], False),
                                             _View(owners[1], True),
                                             _View(owners[2], True)])
    if owners[0].data != request or vm.peak_bytes != 0:
        raise AssertionError('snapshot VM mutated the input or allocated a buffer')
    return status, bytes(owners[1].data)


class SqliteSnapshotSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lookup = assemble_program((SOURCES / 'sqlite_rowid_lookup.hepta').read_bytes())
        cls.record = assemble_program((SOURCES / 'sqlite_record_layout.hepta').read_bytes())
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

    def test_sqlite_builds_require_matching_cold_compiler(self):
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            compiler = directory / 'compiler'
            cold = directory / 'cold.json'
            output = directory / 'output'
            compiler.write_bytes(b'not a qualified compiler')
            cold.write_text('{}')
            for candidate in ('sqlite-rowid-lookup', 'sqlite-record-layout'):
                with self.subTest(candidate=candidate):
                    with self.assertRaisesRegex(ValueError, 'completed matching native cold'):
                        build(output, compiler, cold, candidate=candidate)
                    self.assertFalse(output.exists())
