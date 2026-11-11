"""Independent release-selector review against actual HIA and kernel behavior.

The kernel cases deliberately use broken/full pipes and real process death,
which exercise acknowledgment ambiguity without a ptrace simulation. The
shared fixture builds actual native images or admits the explicit cold report;
no successful result here implies whole-native delivery qualification.
"""
from __future__ import annotations

import concurrent.futures
import fcntl
from hashlib import sha256
import json
import os
import signal
import stat
import struct
import subprocess
import threading
import time
import unittest

from tests import test_hia_release_selection as selection_controls
from tests.test_hia_release_selection import CURRENT, LOCK, fields, observe, state, unpack_state


class ReleaseSelectionReviewPolicyTests(unittest.TestCase):
    def test_lock_and_state_uid_are_actual_hia_policy_decisions(self):
        # A synthetic stat record is input to the independent Core VM. This
        # tests the HIA UID decision without pretending an unprivileged test
        # runner can create foreign-owned kernel files.
        for phase, mode, size in ((7, 0o600, 0), (16, 0o400, 192)):
            base = fields(p0=phase, p64=1000)
            struct.pack_into('<Q', base, 912 + 16, 1)
            struct.pack_into('<II', base, 912 + 24, stat.S_IFREG | mode, 1000)
            struct.pack_into('<Q', base, 912 + 48, size)
            with self.subTest(phase=phase, owner='matching'):
                self.assertEqual(observe(b'', base)[0], 0)
            for owner in (0, 1001, 0xffffffff):
                changed = bytearray(base)
                struct.pack_into('<I', changed, 912 + 28, owner)
                with self.subTest(phase=phase, owner=owner):
                    self.assertEqual(observe(b'', changed)[0], 10)


class ReleaseSelectionReviewKernelTests(unittest.TestCase):
    # Share build/observation plumbing explicitly, without inheriting or
    # dynamically suppressing the author's test methods.
    setUpClass = classmethod(selection_controls.ReleaseSelectionKernelTests.setUpClass.__func__)
    tearDownClass = classmethod(selection_controls.ReleaseSelectionKernelTests.tearDownClass.__func__)
    setUp = selection_controls.ReleaseSelectionKernelTests.setUp
    run_app = selection_controls.ReleaseSelectionKernelTests.run_app
    selected = selection_controls.ReleaseSelectionKernelTests.selected

    def test_status_requires_its_exact_argv_and_never_reads_stdin(self):
        initial_names = sorted(p.name for p in self.root.iterdir())
        result = subprocess.run(
            [str(self.app), 'status', str(self.root), '', '', ''],
            capture_output=True, env={'PATH': ''}, timeout=5,
        )
        self.assertEqual((result.returncode, result.stdout), (64, b''))
        reader, writer = os.pipe()
        child = None
        try:
            # Keep the write end open: a program reading stdin cannot see EOF.
            child = subprocess.Popen(
                [str(self.app), 'status', str(self.root)], stdin=reader,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={'PATH': ''},
            )
            output, error = child.communicate(timeout=5)
            self.assertEqual(child.returncode, 0, error)
            receipt = json.loads(output)
            self.assertEqual((receipt['sequence'], receipt['release_verified']), (0, False))
        finally:
            if child is not None:
                if child.poll() is None:
                    child.kill()
                child.communicate(timeout=5)
            os.close(reader)
            os.close(writer)
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), initial_names)

    def test_preexisting_lock_symlinks_hardlinks_fifo_and_modes_refuse_untouched(self):
        path = self.root / LOCK
        peer = self.case / 'ordinary-lock-peer'
        peer.write_bytes(b'')
        peer.chmod(0o600)
        for variant in ('symlink', 'dangling', 'hardlink', 'fifo', 'directory',
                        'nonempty', 'readonly', 'writable-by-others', 'special-mode'):
            with self.subTest(variant=variant):
                if variant == 'symlink':
                    path.symlink_to(peer)
                elif variant == 'dangling':
                    path.symlink_to(self.case / 'absent-lock-peer')
                elif variant == 'hardlink':
                    os.link(peer, path)
                elif variant == 'fifo':
                    os.mkfifo(path, 0o600)
                elif variant == 'directory':
                    path.mkdir(mode=0o700)
                else:
                    path.write_bytes(b'x' if variant == 'nonempty' else b'')
                    path.chmod({'nonempty': 0o600, 'readonly': 0o400,
                                'writable-by-others': 0o666,
                                'special-mode': 0o1600}[variant])
                before = path.lstat()
                names = sorted(p.name for p in self.root.iterdir())
                try:
                    self.run_app(code=10)
                    self.run_app('activate', 0, None, 0, code=10)
                    after = path.lstat()
                    self.assertEqual(
                        (after.st_ino, after.st_mode, after.st_nlink, after.st_size),
                        (before.st_ino, before.st_mode, before.st_nlink, before.st_size),
                    )
                    self.assertEqual(sorted(p.name for p in self.root.iterdir()), names)
                    self.assertEqual(peer.read_bytes(), b'')
                    self.assertFalse((self.root / CURRENT).exists())
                finally:
                    if stat.S_ISDIR(path.lstat().st_mode):
                        path.rmdir()
                    else:
                        path.unlink()

    def test_status_refuses_present_state_without_its_lock(self):
        self.run_app('activate', 0, None, 0)
        path = self.root / CURRENT
        original, inode = path.read_bytes(), path.stat().st_ino
        (self.root / LOCK).unlink()
        self.run_app(code=10)
        self.assertFalse((self.root / LOCK).exists())
        self.assertEqual((path.read_bytes(), path.stat().st_ino), (original, inode))

    def test_checksumming_does_not_admit_impossible_state_records(self):
        self.run_app('activate', 0, None, 0)
        path = self.root / CURRENT
        a, b = self.ids[:2]
        variants = {
            'zero-sequence': state(0, a),
            'initial-rollback': state(1, a, action=2),
            'initial-predecessor': state(1, a, b),
            'later-missing-predecessor': state(2, a),
            'same-predecessor': state(2, a, a),
            'unknown-action': state(2, a, b, action=3),
            'current-nonhex': state(2, 'A' * 64, b),
            'previous-nonhex': state(2, a, 'G' * 64),
        }
        for label, offset, number in (('reserved', 24, 1), ('magic', 0, 0)):
            altered = bytearray(state(2, a, b))
            struct.pack_into('<Q', altered, offset, number)
            altered[160:] = sha256(altered[:160]).digest()
            variants[label] = bytes(altered)
        names = sorted(p.name for p in self.root.iterdir())
        for label, raw in variants.items():
            with self.subTest(variant=label):
                self.assertEqual(sha256(raw[:160]).digest(), raw[160:])
                path.chmod(0o600)
                path.write_bytes(raw)
                path.chmod(0o400)
                self.run_app(code=11)
                self.run_app('activate', 1, a, 1, code=11)
                self.assertEqual(path.read_bytes(), raw)
                self.assertEqual(sorted(p.name for p in self.root.iterdir()), names)
        path.chmod(0o600)
        path.write_bytes(b'')
        path.chmod(0o400)
        self.run_app(code=10)
        self.run_app('activate', 0, None, 0, code=10)
        self.assertEqual(path.read_bytes(), b'')

    def test_shared_reader_lock_allows_status_and_refuses_a_mutator(self):
        self.run_app('activate', 0, None, 0)
        with (self.root / LOCK).open('rb') as held:
            fcntl.flock(held, fcntl.LOCK_SH | fcntl.LOCK_NB)
            self.assertEqual(self.selected()['sequence'], 1)
            self.run_app('activate', 1, self.ids[0], 1, code=18)
        self.run_app('activate', 1, self.ids[0], 1)
        self.assertEqual(self.selected()['sequence'], 2)

    def test_two_live_initial_writers_have_one_cas_winner(self):
        # Both children exist before either receives EOF. Independent threads
        # release the complete requests together; communicate is not serialized.
        barrier = threading.Barrier(2)
        children = [subprocess.Popen(
            [str(self.app), 'activate', str(self.root), '0', '-', self.ids[i]],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={'PATH': ''},
        ) for i in (0, 1)]

        def submit(index):
            barrier.wait(timeout=5)
            return children[index].communicate(self.wires[index], timeout=10)

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                futures = [executor.submit(submit, i) for i in (0, 1)]
                outputs = [future.result(timeout=15) for future in futures]
        finally:
            for child in children:
                if child.poll() is None:
                    child.kill()
                child.wait(timeout=5)
        codes = [child.returncode for child in children]
        self.assertEqual(codes.count(0), 1, (codes, outputs))
        self.assertTrue(all(code in (0, 18, 19) for code in codes), codes)
        winner = codes.index(0)
        receipt = self.selected()
        self.assertEqual((receipt['sequence'], receipt['current'], receipt['previous']),
                         (1, self.ids[winner], None))
        self.assertEqual(unpack_state((self.root / CURRENT).read_bytes()),
                         (1, self.ids[winner], None, 1))
        self.observations.append({'case': self.id(), 'simultaneous_initial_returncodes': codes})

    def test_actual_broken_rollback_receipt_never_duplicates_a_transition(self):
        self.run_app('activate', 0, None, 0)
        self.run_app('activate', 1, self.ids[0], 1)
        reader, writer = os.pipe()
        os.close(reader)
        try:
            result = subprocess.run(
                [str(self.app), 'rollback', str(self.root), '2', self.ids[1], self.ids[0]],
                input=self.wires[0], stdout=writer, stderr=subprocess.PIPE,
                env={'PATH': ''}, timeout=10,
            )
        finally:
            os.close(writer)
        # Real EPIPE reaches the adapter; ignored SIGPIPE must not kill it.
        self.assertEqual(result.returncode, 15, result.stderr)
        path = self.root / CURRENT
        original, inode = path.read_bytes(), path.stat().st_ino
        self.assertEqual(unpack_state(original), (3, self.ids[0], self.ids[1], 2))
        self.assertEqual(self.selected()['sequence'], 3)
        self.run_app('rollback', 2, self.ids[1], 0, code=19)
        self.assertEqual((path.read_bytes(), path.stat().st_ino), (original, inode))
        self.run_app('rollback', 3, self.ids[0], 1)
        self.run_app('rollback', 2, self.ids[1], 0, code=19)
        self.assertEqual(self.selected()['sequence'], 4)
        self.observations.append({'case': self.id(), 'actual_broken_pipe_returncode': 15,
                                  'after_failed_receipt_sequence': 3})

    def test_sigkill_with_committed_state_and_blocked_receipt_releases_lock(self):
        reader, writer = os.pipe()
        filler = bytearray()
        child = None
        try:
            os.set_blocking(writer, False)
            while True:
                try:
                    filler.extend(b'x' * os.write(writer, b'x' * 4096))
                except BlockingIOError:
                    break
            os.set_blocking(writer, True)
            child = subprocess.Popen(
                [str(self.app), 'activate', str(self.root), '0', '-', self.ids[0]],
                stdin=subprocess.PIPE, stdout=writer, stderr=subprocess.PIPE,
                env={'PATH': ''},
            )
            os.close(writer)
            writer = None
            child.stdin.write(self.wires[0])
            child.stdin.close()
            child.stdin = None
            deadline = time.monotonic() + 10
            while not (self.root / CURRENT).exists() and time.monotonic() < deadline:
                self.assertIsNone(child.poll(), 'child exited before selection publication')
                time.sleep(0.001)
            self.assertTrue((self.root / CURRENT).exists(), 'selection was not published')
            self.assertIsNone(child.poll(), 'a full stdout pipe must prevent acknowledged success')
            self.run_app(code=18)
            child.kill()
            _, error = child.communicate(timeout=5)
            self.assertEqual(child.returncode, -signal.SIGKILL, error)
            captured = bytearray()
            while True:
                chunk = os.read(reader, 65536)
                if not chunk:
                    break
                captured.extend(chunk)
            self.assertEqual(captured, filler, 'no receipt byte fits into the full pipe')
            receipt = self.selected()
            self.assertEqual((receipt['sequence'], receipt['current']), (1, self.ids[0]))
            self.run_app('activate', 0, None, 0, code=19)
            self.observations.append({'case': self.id(), 'kill_after_commit_returncode': -signal.SIGKILL,
                                      'acknowledgment_bytes_written': 0, 'observed_sequence': 1})
        finally:
            if child is not None:
                if child.poll() is None:
                    child.kill()
                child.communicate(timeout=5)
            os.close(reader)
            if writer is not None:
                os.close(writer)


if __name__ == '__main__':
    unittest.main()
