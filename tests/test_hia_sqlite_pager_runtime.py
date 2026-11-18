"""Native Pager path startup with a real SQLite WAL."""

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import os
from pathlib import Path
import select
import sqlite3
import struct
import subprocess
import tempfile
import time
import unittest


EVENT = struct.Struct('<8s15Q')
COMPONENT_FRAME = struct.Struct('<8s3Q')
NONCE = 983207517


def read_exact(stream, size):
    deadline = time.monotonic() + 3
    result = bytearray()
    while len(result) < size:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([stream], [], [], remaining)[0]:
            raise TimeoutError('native reply did not arrive')
        chunk = os.read(stream.fileno(), size - len(result))
        if not chunk:
            raise EOFError('native reply is incomplete')
        result.extend(chunk)
    return bytes(result)


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
    def event(operation, argument=0, *, begin_mode=0, byte_count=0):
        return EVENT.pack(b'HIAPGEV2', 2, NONCE, operation, 0, 0, 0, 0,
                          argument, begin_mode, byte_count, *([0] * 5))

    def test_write_quiescent_snapshot_excludes_writers_until_end(self):
        if self.executable is None:
            self.skipTest('run with the cold-built native SQLite Pager')
        with tempfile.TemporaryDirectory(dir=self.test_root) as temporary:
            parent = Path(temporary)
            database = parent / 'source.sqlite3'
            wal = parent / 'source.sqlite3-wal'
            database.touch(mode=0o600)
            args = [self.executable, parent, database.name]
            profile = 35302 if sqlite3.sqlite_version_info[:2] == (3, 53) else 34600
            begin = self.event(1, profile, begin_mode=1)
            with closing(sqlite3.connect(database, isolation_level=None, timeout=0)) as writer:
                self.assertEqual(writer.execute('PRAGMA journal_mode=WAL').fetchone(), ('wal',))
                writer.execute('CREATE TABLE witness(value TEXT)')
                writer.execute('INSERT INTO witness VALUES (?)', ('retained source',))
                original = database.read_bytes(), wal.read_bytes()
                writer.execute('BEGIN IMMEDIATE')
                busy = self.run_pager(args, begin)
                writer.execute('ROLLBACK')
                self.assertEqual(busy.returncode, 1)
                self.assertEqual(EVENT.unpack_from(busy.stdout)[3:7],
                                 (131, 2, (1 << 64) - 11, 14))
                self.audit(busy.stderr)

                rejected = self.run_pager(args, self.event(1, profile, begin_mode=3))
                self.assertEqual((rejected.returncode, rejected.stdout), (65, b''))
                self.assertEqual(self.audit(rejected.stderr, effects_expected=False)[20], 0)
                with ThreadPoolExecutor(max_workers=1) as pool, subprocess.Popen(
                    args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    env={'PATH': ''},
                ) as pager:
                    audit = pool.submit(pager.stderr.read)
                    try:
                        pager.stdin.write(begin)
                        pager.stdin.flush()
                        ready = self.take_reply(pager)
                        self.assertEqual(ready[:4], (b'HIAPGOT2', 2, NONCE, 128))
                        self.assertEqual(ready[8] & 32, 32)  # The successful SHM write lock.
                        self.assertEqual(writer.execute('SELECT value FROM witness').fetchall(),
                                         [('retained source',)])
                        with self.assertRaises(sqlite3.OperationalError) as blocked:
                            writer.execute('BEGIN IMMEDIATE')
                        self.assertEqual(blocked.exception.sqlite_errorcode, sqlite3.SQLITE_BUSY)
                        self.assertEqual((database.read_bytes(), wal.read_bytes()), original)
                        pager.stdin.write(self.event(4))
                        pager.stdin.flush()
                        self.assertEqual(self.take_reply(pager)[3], 130)
                        self.assertEqual(pager.wait(timeout=3), 0)
                        journal = self.audit(audit.result(timeout=3))
                        self.assertGreater(journal[20], 0)
                        writer.execute('BEGIN IMMEDIATE')
                        writer.execute('INSERT INTO witness VALUES (?)', ('after unlock',))
                        writer.execute('COMMIT')
                        self.assertEqual(writer.execute('SELECT value FROM witness ORDER BY rowid').fetchall(),
                                         [('retained source',), ('after unlock',)])
                    finally:
                        if pager.poll() is None:
                            pager.kill()
                            pager.wait(timeout=3)

    def test_checkpointed_snapshot_has_no_sidecar_and_holds_source_lock(self):
        if self.executable is None:
            self.skipTest('run with the cold-built native SQLite Pager')
        with tempfile.TemporaryDirectory(dir=self.test_root) as temporary:
            parent = Path(temporary)
            database = parent / 'source.sqlite3'
            args = [self.executable, parent, database.name]
            profile = 35302 if sqlite3.sqlite_version_info[:2] == (3, 53) else 34600
            begin = self.event(1, profile, begin_mode=2)
            end = self.event(4)
            with closing(sqlite3.connect(database)) as writer:
                self.assertEqual(writer.execute('PRAGMA journal_mode=WAL').fetchone(), ('wal',))
                writer.execute('CREATE TABLE witness(value TEXT)')
                writer.execute('INSERT INTO witness VALUES (?)', ('checkpointed source',))
                writer.commit()
                page_size, = writer.execute('PRAGMA page_size').fetchone()
                page_count, = writer.execute('PRAGMA page_count').fetchone()
            original = database.read_bytes()
            self.assertEqual(set(parent.iterdir()), {database})

            for suffix in ('-wal', '-shm', '-journal'):
                sidecar = database.with_name(database.name + suffix)
                sidecar.symlink_to(parent / 'missing')
                refused = self.run_pager(args, begin)
                self.assertEqual(refused.returncode, 1)
                self.assertEqual(EVENT.unpack_from(refused.stdout)[3:5], (131, 4))
                self.audit(refused.stderr)
                self.assertTrue(sidecar.is_symlink())
                sidecar.unlink()

            token = 1
            result = self.run_pager(
                args, begin + self.event(6, page_count)
                + self.event(7, token, byte_count=page_size) + self.event(8, token) + end,
            )
            self.assertEqual(result.returncode, 0)
            frame_size = 1152
            ready = EVENT.unpack_from(result.stdout)
            self.assertEqual(ready[3:5], (128, 0))
            self.assertEqual(ready[8:13], (128, page_size, page_count, 0, 0))
            captured = EVENT.unpack_from(result.stdout, frame_size)
            self.assertEqual((captured[3], captured[13], captured[15]), (129, page_count, token))
            span_at = 2 * frame_size + page_size
            span = EVENT.unpack_from(result.stdout, span_at)
            self.assertEqual(span[3:8], (134, token, page_count, 0, page_size))
            self.assertEqual(result.stdout[2 * frame_size:span_at], original[-page_size:])
            drop_at = span_at + frame_size + page_size
            self.assertEqual(result.stdout[span_at + frame_size:drop_at], original[-page_size:])
            self.assertEqual(EVENT.unpack_from(result.stdout, drop_at)[3:6], (135, token, page_count))
            self.assertEqual(EVENT.unpack_from(result.stdout, drop_at + frame_size)[3], 130)
            self.assertEqual(len(result.stdout), drop_at + 2 * frame_size)
            self.audit(result.stderr)
            self.assertEqual(set(parent.iterdir()), {database})

            with ThreadPoolExecutor(max_workers=1) as pool, subprocess.Popen(
                args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env={'PATH': ''},
            ) as pager:
                audit = pool.submit(pager.stderr.read)
                try:
                    pager.stdin.write(begin)
                    pager.stdin.flush()
                    self.assertEqual(self.take_reply(pager)[3], 128)
                    with closing(sqlite3.connect(database, timeout=0, isolation_level=None)) as writer:
                        with self.assertRaises(sqlite3.OperationalError) as blocked:
                            writer.execute('BEGIN IMMEDIATE')
                        self.assertEqual(blocked.exception.sqlite_errorcode, sqlite3.SQLITE_BUSY)
                        self.assertEqual(set(parent.iterdir()), {database})
                        self.assertEqual(database.read_bytes(), original)
                        pager.stdin.write(end)
                        pager.stdin.flush()
                        self.assertEqual(self.take_reply(pager)[3], 130)
                        self.assertEqual(pager.wait(timeout=3), 0)
                        self.audit(audit.result(timeout=3))
                        writer.execute('BEGIN IMMEDIATE')
                        writer.execute('INSERT INTO witness VALUES (?)', ('after unlock',))
                        writer.execute('COMMIT')
                finally:
                    if pager.poll() is None:
                        pager.kill()
                        pager.wait(timeout=3)
            with closing(sqlite3.connect(database)) as reader:
                self.assertEqual(reader.execute('SELECT value FROM witness ORDER BY rowid').fetchall(),
                                 [('checkpointed source',), ('after unlock',)])

    @staticmethod
    def take_reply(pager):
        return EVENT.unpack_from(read_exact(pager.stdout, 1152))

    @staticmethod
    def run_pager(args, data=b''):
        return subprocess.run(args, input=data, capture_output=True, env={'PATH': ''}, timeout=15, check=False)

    def audit(self, stream, *, effects_expected=True):
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
        if effects_expected:
            self.assertGreater(kinds[20], 0)
        return kinds


class NativeSQLiteComponents(unittest.TestCase):
    root = None
    test_root = None

    @staticmethod
    def request(data, output, scratch):
        return COMPONENT_FRAME.pack(b'HIASCC01', len(data), output, scratch) + data

    def component(self, name, data, expected=0):
        result = subprocess.run([self.root / ('hia-sqlite-' + name)], input=data, capture_output=True,
                                env={'PATH': ''}, timeout=15, check=False)
        self.assertEqual((result.returncode, result.stderr), (expected, b''))
        replies, offset = [], 0
        while offset < len(result.stdout):
            magic, code, count, scratch = COMPONENT_FRAME.unpack_from(result.stdout, offset)
            self.assertEqual(magic, b'HIASCR01')
            offset += COMPONENT_FRAME.size
            self.assertLessEqual(offset + count + scratch, len(result.stdout))
            replies.append((code, result.stdout[offset:offset + count]))
            offset += count + scratch
        self.assertEqual(offset, len(result.stdout))
        return replies

    def test_catalog_continues_in_one_installed_process(self):
        if self.root is None:
            self.skipTest('run with the cold-built native SQLite components')
        from hepta.hia_agent_store import AgentStore

        with tempfile.TemporaryDirectory(dir=self.test_root) as temporary:
            store = AgentStore(Path(temporary) / 'agent')
            try:
                rows = store.db.execute(
                    'SELECT rowid, type, name, rootpage FROM sqlite_schema ORDER BY rowid').fetchall()
                pages, = store.db.execute('PRAGMA page_count').fetchone()
            finally:
                store.close()
            snapshot = bytearray(store.database.read_bytes())
        snapshot[18:20] = b'\1\1'  # Offline image ABI expects a rollback-format header.
        lookup_wire = b''.join(self.request(struct.pack('<Qq', 1, row[0]) + snapshot, 1024, 64)
                               for row in rows)
        records = []
        for code, output in self.component('rowid-lookup', lookup_wire):
            self.assertEqual(code, 0)
            magic, size, encoding, _ = COMPONENT_FRAME.unpack_from(output)
            self.assertEqual((magic, encoding), (b'HIAROW01', 1))
            records.append(output[32:32 + size])
        self.assertEqual(len(records), len(rows))
        descriptors = self.component('record-layout',
                                     b''.join(self.request(raw, 192, 16) for raw in records))
        self.assertEqual(len(descriptors), len(rows))
        frames = [self.request(struct.pack('<8s3Q', b'HIASCAT1', 1, pages, 1), 112, 1024)]
        for row, raw, (code, descriptor) in zip(rows, records, descriptors):
            self.assertEqual(code, 0)
            catalog_record = struct.pack('<8s3Q', b'HIASCAT1', 2, row[0], len(descriptor))
            frames.append(self.request(catalog_record + descriptor + raw, 112, 1024))
        finish = self.request(struct.pack('<8sQ', b'HIASCAT1', 3), 112, 1024)
        replies = self.component('agent-catalog', b''.join(frames) + finish + finish)
        self.assertEqual(replies[:len(frames)], [(0, bytes(112))] * len(frames))
        roots = {row[2]: row[3] for row in rows if row[1] == 'table'}
        order = ('artifacts', 'profiles', 'contexts', 'requests', 'costs', 'cursors',
                 'slots', 'versions', 'leases', 'execution_budgets', 'sqlite_sequence')
        expected = struct.pack('<8s13Q', b'HIASCOK1', 1, 11, *(roots[name] for name in order))
        self.assertEqual(replies[len(frames):], [(0, expected), (1, bytes(112))])
        self.assertEqual(self.component('agent-catalog', finish), [(1, bytes(112))])

    def test_partial_frame_and_changed_workspace_cannot_invoke(self):
        if self.root is None:
            self.skipTest('run with the cold-built native SQLite components')
        first = self.request(b'\x02\x09', 64, 16)
        normal = self.component('record-layout', first)
        self.assertEqual(normal[0][0], 0)
        self.assertEqual(normal[0][1][:8], b'HIASREC1')
        for refused in (first[:-1], first[:7], self.request(b'', 67108865, 16),
                        self.request(b'', 64, 17)):
            self.assertEqual(self.component('record-layout', first + refused, expected=64), normal)

    def test_table_walk_paces_real_retained_page_reads(self):
        if self.root is None or NativePagerArgv.executable is None:
            self.skipTest('run with the installed native Pager and retained table walk')
        with tempfile.TemporaryDirectory(dir=self.test_root) as temporary:
            folder = Path(temporary)
            database = folder/'source.sqlite3'
            expected = [-(1 << 63), *range(-32, 64), (1 << 63)-1]
            with closing(sqlite3.connect(database)) as db:
                db.execute('PRAGMA page_size=512')
                self.assertEqual(db.execute('PRAGMA journal_mode=WAL').fetchone(), ('wal',))
                db.execute('CREATE TABLE witness(data BLOB)')
                db.executemany('INSERT INTO witness(rowid,data) VALUES (?,?)',
                               ((key, bytes(171)) for key in expected))
                db.commit()
                root, = db.execute("SELECT rootpage FROM sqlite_schema WHERE name='witness'").fetchone()
                self.assertEqual([key for key, in db.execute('SELECT rowid FROM witness ORDER BY rowid')], expected)
            original = database.read_bytes()
            profile = 35302 if sqlite3.sqlite_version_info[:2] == (3, 53) else 34600
            with ThreadPoolExecutor(max_workers=1) as pool, subprocess.Popen(
                    [NativePagerArgv.executable, folder, database.name],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={'PATH': ''},
            ) as pager, subprocess.Popen(
                    [self.root/'hia-sqlite-table-walk'],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={'PATH': ''},
            ) as walk:
                audit = pool.submit(pager.stderr.read)
                try:
                    def pager_step(operation, argument=0, mode=0):
                        pager.stdin.write(NativePagerArgv.event(operation, argument, begin_mode=mode))
                        pager.stdin.flush()
                        state = read_exact(pager.stdout,1152)
                        return EVENT.unpack_from(state), state[128+288:128+312]

                    ready, identity = pager_step(1,profile,2)
                    self.assertEqual(ready[3],128)
                    page_size, page_count = ready[9:11]
                    self.assertEqual(page_size,512)
                    self.assertNotEqual(identity,bytes(24))

                    def read_page(number):
                        header, snapshot = pager_step(3,number)
                        self.assertEqual((header[3], snapshot), (129, identity))
                        return read_exact(pager.stdout,page_size)

                    def next_step(packet):
                        output = 32 + page_size*4
                        walk.stdin.write(self.request(packet,output,4096))
                        walk.stdin.flush()
                        reply = COMPONENT_FRAME.unpack(read_exact(walk.stdout,32))
                        self.assertEqual(reply,(b'HIASCR01',0,output,4096))
                        data = read_exact(walk.stdout,output)
                        read_exact(walk.stdout,4096)
                        tag, completed, following, count = COMPONENT_FRAME.unpack_from(data)
                        self.assertEqual(tag,b'HIASWA01')
                        return completed,following,struct.unpack_from(f'<{count}q',data,32)

                    first = read_page(1)
                    start = struct.pack('<8sQ24s2Q',b'HIASTW01',1,identity,page_count,root)
                    self.assertEqual(next_step(start),(0,root,()))
                    rowids = []
                    following = root
                    for ordinal in range(page_count):
                        page = following
                        data = read_page(page)  # Only HIA asks for the next table page.
                        packet = struct.pack('<I4sQ',page,b'HSP2',0)+first
                        packet += struct.pack('<3Q',page_count,1,page)+data
                        [(status, entries)] = self.component('rowid-lookup', self.request(packet,32+page_size*4,72))
                        self.assertEqual(status,0)
                        _, _, count, selected = COMPONENT_FRAME.unpack_from(entries)
                        self.assertEqual(selected,page)
                        completed,following,rows = next_step(
                            struct.pack('<8sQ24s',b'HIASTW01',2,identity)+entries[:32+count*8])
                        self.assertEqual(completed,page)
                        rowids.extend(rows)
                        if following == 0:
                            break
                    else:
                        self.fail('table walk did not terminate inside one retained snapshot')
                    self.assertGreater(ordinal,1)
                    self.assertEqual(rowids,expected)
                    self.assertEqual(database.read_bytes(),original)
                    self.assertEqual(pager_step(4)[0][3],130)
                    self.assertEqual(pager.wait(timeout=3),0)
                    NativePagerArgv().audit(audit.result(timeout=3))
                    walk.stdin.close()
                    self.assertEqual(walk.wait(timeout=3),0)
                    self.assertEqual(walk.stderr.read(),b'')
                finally:
                    for child in (walk,pager):
                        if child.poll() is None:
                            child.kill()
                            child.wait(timeout=3)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--executable', type=Path, required=True)
    parser.add_argument('--component-root', type=Path)
    parser.add_argument('--test-root', type=Path, required=True)
    arguments = parser.parse_args()
    NativePagerArgv.executable = arguments.executable.resolve()
    NativePagerArgv.test_root = arguments.test_root.resolve()
    suites = [unittest.defaultTestLoader.loadTestsFromTestCase(NativePagerArgv)]
    if arguments.component_root is not None:
        NativeSQLiteComponents.root = arguments.component_root.resolve()
        NativeSQLiteComponents.test_root = arguments.test_root.resolve()
        suites.append(unittest.defaultTestLoader.loadTestsFromTestCase(NativeSQLiteComponents))
    suite = unittest.TestSuite(suites)
    return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1


if __name__ == '__main__':
    raise SystemExit(main())
