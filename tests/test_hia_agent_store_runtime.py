"""Exercise the cold-built Agent Store's direct native argv and streaming ABI."""

import argparse
import fcntl
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest


def command(request, kind, target=0, body=b''):
    return struct.pack('<8s5Q', b'HIATCM01', 1, request, kind, target, len(body)) + body


def text_bindings(magic, values, *, insert_table=None):
    header_size = 32 if insert_table is None else 40
    offset = header_size + 24 * len(values)
    cells, contents = [], []
    for value in values:
        data = b'' if value is None else value.encode('utf-8')
        cells.append(struct.pack('<3Q', 0 if value is None else 3, offset, len(data)))
        contents.append(data)
        offset += len(data)
    if insert_table is None:
        header = struct.pack('<8s3Q', magic, 1, len(values), offset)
    else:
        header = struct.pack('<8s4Q', magic, 1, insert_table, 0, len(values))
    return header + b''.join(cells + contents)


class NativeStoreArgv(unittest.TestCase):
    test_root = None
    batch = None

    def run_native(self, arguments, data=b'', expected=0):
        result = subprocess.run(arguments, input=data, capture_output=True, env={'PATH': ''},
                                timeout=3, check=False)
        self.assertEqual(result.returncode, expected, result)
        self.assertEqual(result.stderr, b'')
        if expected:
            self.assertEqual(result.stdout, b'')
        return result.stdout

    def replies(self, output, kinds):
        at, acks, rows, receipts = 0, [], [], 0
        current = None
        while at < len(output):
            magic = output[at:at + 8]
            if magic == b'HIATXR01':
                _, version, request, kind, status, *_ = struct.unpack_from('<8s9Q', output, at)
                self.assertEqual((version, request, status), (1, len(acks), 0))
                acks.append(kind)
                at += 80
            elif magic == b'HIAWTA01':
                receipts += 1
                at += 256
            else:
                self.assertEqual(magic, b'HIAQRF01')
                _, kind, table, rowid, offset, size, _, reserved = struct.unpack_from(
                    '<8s7Q', output, at)
                body = output[at + 64:at + 64 + size]
                self.assertEqual((reserved, len(body)), (0, size))
                if kind == 1:
                    self.assertIsNone(current)
                    self.assertEqual((table, rowid, size, body[:8]), (4, 1, 128, b'HIAIXLF1'))
                    current = bytearray()
                elif kind == 2:
                    self.assertEqual((table, rowid, offset), (4, 1, len(current)))
                    current.extend(body)
                elif kind == 3:
                    self.assertEqual((table, rowid, offset), (4, 1, len(current)))
                    self.assertEqual(current[:8], b'HIAROW01')
                    columns, = struct.unpack_from('<Q', current, 24)
                    values = []
                    for i in range(columns):
                        tag, start, width = struct.unpack_from('<3Q', current, 32 + i * 24)
                        self.assertIn(tag, (0, 3))
                        values.append(None if tag == 0 else current[start:start + width].decode('utf-8'))
                    rows.append(tuple(values))
                    current = None
                else:
                    self.assertEqual((kind, size), (4, 416))
                    self.assertIsNone(current)
                    self.assertEqual(struct.unpack_from('<Q', body, 384)[0], 9)
                at += 64 + size
        self.assertEqual(at, len(output))
        self.assertIsNone(current)
        self.assertEqual(acks, [0, *kinds])
        return rows, receipts

    def test_direct_native_cli(self):
        if self.test_root is None:
            self.skipTest('run with the cold-built native Agent Store paths')
        with tempfile.TemporaryDirectory(dir=self.test_root) as temporary:
            parent = Path(temporary)
            self.run_native([self.initializer, parent, 'store'])
            args = [self.executable, parent, 'store', self.module_root]
            initial = self.state(parent)
            values = ('test-request', 'a' * 64, 'hia_artifact', 'running', None, '1234')
            entry = text_bindings(b'HIAINS01', values, insert_table=6)
            lookup = text_bindings(b'HIAQPA01', values[:1])
            insert = command(1, 27, 1, entry)
            select = command(2, 27, 12, lookup)
            rollback = command(3, 3)
            commit = command(3, 2)

            self.assertEqual(self.replies(self.run_native(args, insert + select + rollback), (27, 27, 3)),
                             ([values], 0))
            self.assertEqual(self.state(parent), initial)
            self.assertEqual(self.replies(self.run_native(args, command(1, 27, 12, lookup) + command(2, 3)),
                                          (27, 3)), ([], 0))
            self.assertEqual(self.replies(self.run_native(args, insert + select + commit), (27, 27, 2)),
                             ([values], 1))
            self.assertEqual(self.replies(self.run_native(args, command(1, 27, 12, lookup) + command(2, 3)),
                                          (27, 3)), ([values], 0))

            link = parent / 'module-link'
            link.symlink_to(self.module_root, target_is_directory=True)
            self.run_native([*args[:3], link], expected=74)
            self.run_native([*args[:2], '../store', self.module_root], expected=73)
            self.run_native([*args[:2], '', self.module_root], expected=73)
            self.run_native(args[:3], expected=64)

    def test_direct_migration_batch(self):
        if self.batch is None:
            self.skipTest('run with the cold-built native Agent batch commit path')
        with tempfile.TemporaryDirectory(dir=self.test_root) as temporary:
            parent = Path(temporary)
            self.run_native([self.initializer, parent, 'store'])
            store = parent / 'store'
            initial = self.state(parent)
            values = ('migrated-request', 'b' * 64, 'hia_artifact', 'running', None, '4321')
            cells = text_bindings(b'HIAROW01', values)[32:]
            row = struct.pack('<8s3Q', b'HIAROW01', 1, 4, len(values)) + cells
            proposal = (struct.pack('<8s3Q', b'HIATXB01', 1, 1, 1)
                        + struct.pack('<Qq2Q', 4, 1, 64, len(row)) + row)
            data = struct.pack('<Q', len(proposal)) + proposal
            args = [self.batch, store]

            for malformed in (data[:-1], data + b'\0', struct.pack('<Q', 1000000033)):
                self.run_native(args, malformed, expected=64)
            link = parent / 'linked-store'
            link.symlink_to(store, target_is_directory=True)
            self.run_native([self.batch, link], data, expected=74)
            self.run_native([self.batch, str(link) + '/'], data, expected=64)
            self.assertEqual(self.state(parent), initial)

            with (store / 'wal.lock').open('rb') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.run_native(args, data, expected=75)
            self.assertEqual(self.state(parent), initial)

            receipt = self.run_native(args, data)
            self.assertEqual((len(receipt), receipt[:8]), (256, b'HIAWTA01'))
            self.assertEqual(receipt[-128:], (store / 'anchor.0000000000000001').read_bytes())
            committed = self.state(parent)
            self.refused_batch(args, data)
            self.assertEqual(self.state(parent), committed)

            lookup = text_bindings(b'HIAQPA01', values[:1])
            query = command(1, 27, 12, lookup) + command(2, 3)
            reopened = self.run_native([self.executable, parent, 'store', self.module_root], query)
            self.assertEqual(self.replies(reopened, (27, 3)), ([values], 0))

    def refused_batch(self, args, data):
        result = subprocess.run(args, input=data, capture_output=True, env={'PATH': ''},
                                timeout=3, check=False)
        self.assertIn(result.returncode, (73, 74), result)
        self.assertEqual((result.stdout, result.stderr), (b'', b''))

    @staticmethod
    def state(parent):
        return {file.name: file.read_bytes() for file in (parent / 'store').iterdir()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ('executable', 'module-root', 'initializer', 'test-root'):
        parser.add_argument('--' + option, type=Path, required=True)
    parser.add_argument('--batch', type=Path)
    for key, value in vars(parser.parse_args()).items():
        setattr(NativeStoreArgv, key, value.resolve() if value is not None else None)
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(NativeStoreArgv)
    return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1


if __name__ == '__main__':
    raise SystemExit(main())
