"""Native Pager path startup with a real SQLite WAL."""

import argparse
from collections import Counter
from contextlib import closing
from pathlib import Path
import sqlite3
import struct
import subprocess
import tempfile
import unittest


EVENT = struct.Struct('<8s15Q')
NONCE = 983207517


class NativePagerArgv(unittest.TestCase):
    executable = None
    test_root = None

    def test_held_read_and_audit(self):
        if self.executable is None:
            self.skipTest('run with the cold-built native SQLite Pager')
        with tempfile.TemporaryDirectory(dir=self.test_root) as temporary:
            parent = Path(temporary)
            database = parent / 'source.sqlite3'
            database.touch(mode=0o600)
            args = [self.executable, parent, database.name]
            with closing(sqlite3.connect(database)) as writer:
                self.assertEqual(writer.execute('PRAGMA journal_mode=WAL').fetchone(), ('wal',))
                writer.execute('CREATE TABLE witness(value TEXT)')
                writer.execute('INSERT INTO witness VALUES (?)', ('retained source',))
                writer.commit()
                page_size, = writer.execute('PRAGMA page_size').fetchone()
                page_count, = writer.execute('PRAGMA page_count').fetchone()
                profile = 35302 if sqlite3.sqlite_version_info[:2] == (3, 53) else 34600
                original = database.read_bytes(), database.with_name(database.name + '-wal').read_bytes()
                result = self.run_pager(args, self.event(1, profile) + self.event(3, 1) + self.event(4))
                self.assertEqual(result.returncode, 0, result.stdout[:128])
                self.assertEqual(len(result.stdout), 3 * 1152 + page_size)
                ready = EVENT.unpack_from(result.stdout)
                self.assertEqual(ready[:4], (b'HIAPGOT2', 2, NONCE, 128))
                self.assertEqual(ready[9:11], (page_size, page_count))
                page = EVENT.unpack_from(result.stdout, 1152)
                self.assertEqual(page[:4], (b'HIAPGOT2', 2, NONCE, 129))
                self.assertEqual(page[9], page_size)
                self.assertEqual(result.stdout[2304:2320], b'SQLite format 3\0')
                closed = EVENT.unpack_from(result.stdout, 2304 + page_size)
                self.assertEqual(closed[:4], (b'HIAPGOT2', 2, NONCE, 130))
                self.audit(result.stderr)
                self.assertEqual(original, (database.read_bytes(),
                                            database.with_name(database.name + '-wal').read_bytes()))

            link = parent / 'alias'
            link.symlink_to(parent, target_is_directory=True)
            for path, basename, status in ((link, database.name, 74), (parent, '../source.sqlite3', 64)):
                result = self.run_pager([self.executable, path, basename])
                self.assertEqual((result.returncode, result.stdout, result.stderr), (status, b'', b''))

    @staticmethod
    def event(operation, argument=0):
        return EVENT.pack(b'HIAPGEV2', 2, NONCE, operation, 0, 0, 0, 0, argument, *([0] * 7))

    @staticmethod
    def run_pager(args, data=b''):
        return subprocess.run(args, input=data, capture_output=True, env={'PATH': ''}, timeout=15, check=False)

    def audit(self, stream):
        record = struct.Struct('<8s7Q')
        at, index = 0, 0
        kinds = Counter()
        while at < len(stream):
            magic, version, nonce, number, kind, count, _, _ = record.unpack_from(stream, at)
            index += 1
            self.assertEqual((magic, version, nonce, number), (b'HIAPGAU2', 2, NONCE, index))
            at += record.size + count
            kinds[kind] += 1
        self.assertEqual(at, len(stream))
        self.assertGreater(kinds[10], 0)
        self.assertEqual([kinds[kind] for kind in (11, 12, 13, 14)], [kinds[10]] * 4)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--executable', type=Path, required=True)
    parser.add_argument('--test-root', type=Path, required=True)
    arguments = parser.parse_args()
    NativePagerArgv.executable = arguments.executable.resolve()
    NativePagerArgv.test_root = arguments.test_root.resolve()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(NativePagerArgv)
    return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1


if __name__ == '__main__':
    raise SystemExit(main())
