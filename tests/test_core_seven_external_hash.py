"""Bounded real-filesystem controls for two-reader complete external scans.

These controls do not invoke Lean or grant acceptance. Source/support inventories
and existing historical test counts are unchanged.
"""
from copy import deepcopy
import errno
from hashlib import sha256
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from tools import core_seven_shared_acceptance_plan as p


def external(paths, root):
    value = object.__new__(p.External)
    value.executable = root / 'pinned/bin/lean'
    value.paths = {str(path): maximum for path, maximum in paths}
    value.inodes, value.parents, value.records = {}, {}, {}
    return value


def state(value):
    return deepcopy((value.inodes, value.parents, value.records))


class ExternalHashTests(unittest.TestCase):
    def setUp(self):
        # These original reader controls use arbitrary non-Git files. Isolate
        # the new source-tree gate here; real repository/stream integration is
        # exercised by GitSourceProvenanceTests in shared_acceptance.
        self.enterContext(patch.object(p, 'SOURCE_IDENTITY_PATHS', ()))
        self.enterContext(patch.object(p, 'require_canonical_git_blobs'))
        self.enterContext(patch.object(p.diagnostic, '_git_baseline',
            return_value={'head': '0' * 40, 'tree': '1' * 40}))

    def test_every_check_reads_all_bytes_in_original_chunks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            files = [root / 'a', root / 'b']
            for i, path in enumerate(files):
                path.write_bytes(bytes([65 + i]) * (65536 * 2 + 17 + i))
            value = external([(path, 200000) for path in files], root)
            original_read = p.os.read
            by_inode = {path.stat().st_ino: str(path) for path in files}
            counts = {str(path): 0 for path in files}
            requests = []
            lock = threading.Lock()

            def read(fd, size):
                name = by_inode[p.os.fstat(fd).st_ino]
                data = original_read(fd, size)
                with lock:
                    requests.append(size)
                    counts[name] += len(data)
                return data

            with patch.object(p.os, 'read', read):
                value.check()
                first = state(value)
                value.check()
            self.assertEqual(state(value), first)
            self.assertEqual(set(requests), {65536})
            for path in files:
                raw = path.read_bytes()
                self.assertEqual(counts[str(path)], 2 * len(raw))
                self.assertEqual(value.records[str(path)], {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()})

    def test_at_most_two_readers_and_immutable_observations(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            files = [root / str(i) for i in range(6)]
            for path in files:
                path.write_bytes(b'bounded real input')
            value = external([(path, 100) for path in files], root)
            original = p._external_file_observation
            barrier = threading.Barrier(2, timeout=5)
            lock = threading.Lock()
            active = peak = count = 0

            def observe(item):
                nonlocal active, peak, count
                with lock:
                    active += 1
                    peak = max(peak, active)
                    count += 1
                    first_pair = count <= 2
                try:
                    if first_pair:
                        barrier.wait()
                    result = original(item)
                    def immutable(x):
                        return type(x) in (str, int) or type(x) is tuple and all(immutable(y) for y in x)
                    self.assertTrue(immutable(result))
                    return result
                finally:
                    with lock:
                        active -= 1

            with patch.object(p, '_external_file_observation', observe):
                value.check()
            self.assertEqual((peak, active, count), (2, 0, len(files)))

    def test_worker_io_error_closes_descriptors_and_publishes_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            files = [root / 'a', root / 'b']
            for path in files:
                path.write_bytes(b'x' * 65537)
            value = external([(path, 100000) for path in files], root)
            value.check()
            before = state(value)
            descriptors = set(os.listdir('/proc/self/fd'))
            inode = files[0].stat().st_ino
            original_read = p.os.read

            def read(fd, size):
                if p.os.fstat(fd).st_ino == inode:
                    raise OSError(errno.EIO, 'injected file read failure')
                return original_read(fd, size)

            with patch.object(p.os, 'read', read), self.assertRaisesRegex(OSError, 'injected file read failure'):
                value.check()
            self.assertEqual(state(value), before)
            self.assertEqual(set(os.listdir('/proc/self/fd')), descriptors)

    def test_same_inode_rewrite_behind_reader_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'input'
            path.write_bytes(b'a' * 131073)
            value = external([(path, 200000)], root)
            value.check()
            before = state(value)
            original_read = p.os.read
            changed = False
            inode = path.stat().st_ino

            def read(fd, size):
                nonlocal changed
                data = original_read(fd, size)
                if data and not changed:
                    changed = True
                    # Change an already-read byte: a hash alone can still equal
                    # the baseline, so the descriptor/path stat checks matter.
                    with path.open('r+b') as stream:
                        stream.write(b'z')
                        stream.flush()
                        os.fsync(stream.fileno())
                    self.assertEqual(path.stat().st_ino, inode)
                return data

            with patch.object(p.os, 'read', read), self.assertRaisesRegex(ValueError, 'external read race'):
                value.check()
            self.assertTrue(changed)
            self.assertEqual(state(value), before)

    def test_ancestor_replacement_before_fstat_is_refused_without_baseline(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            parent = root / 'parent'
            parent.mkdir()
            path = parent / 'input'
            path.write_bytes(b'same file inode across directory replacement')
            value = external([(path, 100)], root)
            original_open = p.os.open
            changed = False

            def open_file(name, flags, *args, **kwargs):
                nonlocal changed
                fd = original_open(name, flags, *args, **kwargs)
                if Path(name) == path and not changed:
                    changed = True
                    previous = root / 'previous-parent'
                    parent.rename(previous)
                    parent.mkdir()
                    (previous / path.name).rename(path)
                return fd

            with patch.object(p.os, 'open', open_file), self.assertRaisesRegex(ValueError, 'external ancestor changed'):
                value.check()
            self.assertTrue(changed)
            self.assertEqual(state(value), ({}, {}, {}))

    def test_cross_worker_ancestor_observations_must_agree(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            parent = root / 'parent'
            parent.mkdir()
            a, b = parent / 'a', parent / 'b'
            a.write_bytes(b'a')
            b.write_bytes(b'b')
            value = external([(a, 100), (b, 100)], root)
            original = p._external_file_observation
            replacement_done = threading.Event()

            def observe(item):
                if item[0] == str(a):
                    result = original(item)
                    previous = root / 'previous-parent'
                    parent.rename(previous)
                    parent.mkdir()
                    for path in (a, b):
                        (previous / path.name).rename(path)
                    replacement_done.set()
                    return result
                self.assertTrue(replacement_done.wait(5))
                return original(item)

            with patch.object(p, '_external_file_observation', observe), self.assertRaisesRegex(ValueError, 'external ancestor changed'):
                value.check()
            self.assertEqual(state(value), ({}, {}, {}))

    def test_unsafe_files_and_sizes_are_refused(self):
        for case in ('symlink', 'hardlink', 'fifo', 'oversize'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                path = root / 'input'
                other = root / 'other'
                other.write_bytes(b'abc')
                if case == 'symlink':
                    path.symlink_to(other)
                elif case == 'hardlink':
                    os.link(other, path)
                elif case == 'fifo':
                    os.mkfifo(path)
                else:
                    path.write_bytes(b'abc')
                value = external([(path, 2 if case == 'oversize' else 100)], root)
                with self.assertRaises((OSError, ValueError)):
                    value.check()
                self.assertEqual(state(value), ({}, {}, {}))

    def test_final_git_refusal_does_not_publish_observations(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'input'
            path.write_bytes(b'complete bytes with a changed git baseline')
            value = external([(path, 100)], root)
            value.git = {'head': 'before'}
            with patch.object(p.diagnostic, '_git_baseline', return_value={'head': 'after'}), self.assertRaisesRegex(ValueError, 'git baseline changed'):
                value.check()
            self.assertEqual(state(value), ({}, {}, {}))


if __name__ == '__main__':
    unittest.main()
