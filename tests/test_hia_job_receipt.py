"""Verify the installed standalone HIA job receipt effect against the local filesystem."""
from __future__ import annotations

import errno
import fcntl
import json
import os
from pathlib import Path
import signal
import stat
import struct
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest


CAPACITY = 4 << 20
SEALS = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE


@unittest.skipUnless(os.environ.get('HIA_TEST_JOB_RECEIPT_EXE'), 'requires the installed HIA receipt writer')
class JobReceiptExecutableTests(unittest.TestCase):
    def setUp(self):
        self.executable = Path(os.environ['HIA_TEST_JOB_RECEIPT_EXE']).resolve(strict=True)
        root = TemporaryDirectory()
        self.addCleanup(root.cleanup)
        self.root = Path(root.name)

    def request(self, name=b'job_1.2@local', payload=b'{\n  "launch_state": "pending"\n}',
                *, parent=None, sealed=True, suffix=b'', magic=b'HIAJRQ01'):
        pid = os.getpid() if parent is None else parent
        frame = struct.pack('<8s3Q', magic, len(payload), pid, len(name)) + name + payload + suffix
        return self.invoke(frame, sealed=sealed)

    def invoke(self, frame, *, sealed=True, pass_fds=()):
        with os.fdopen(os.memfd_create('test-job-receipt', os.MFD_ALLOW_SEALING), 'wb', buffering=0) as source:
            self.assertEqual(len(frame), source.write(frame))
            if sealed:
                fcntl.fcntl(source, fcntl.F_ADD_SEALS, SEALS)
            directory = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                return subprocess.run([self.executable], stdin=source, stdout=directory,
                                      stderr=subprocess.PIPE, env={'PATH': ''}, timeout=5, pass_fds=pass_fds)
            finally:
                os.close(directory)

    def check_receipt(self, result, phase, status):
        self.assertEqual(result.returncode, 0)
        self.assertEqual(struct.unpack('<8sQq', result.stderr), (b'HIAJRW01', phase, status))

    def group_signal(self, leader, action, *, parent=None):
        caller = os.getpid() if parent is None else parent
        return self.invoke(struct.pack('<8s4Q', b'HIASGQ01', caller, leader, action, 0))

    def test_signal_is_issued_only_to_an_original_child_in_its_own_group(self):
        marker = ("import ctypes, time; "
                  "assert ctypes.CDLL(None).prctl(15, b'odd) name\\n)', 0, 0, 0) == 0; "
                  "print('ready', flush=True); time.sleep(20)")
        self.check_receipt(self.group_signal(0, 0), 0, 0)
        for operation, number in ((1, signal.SIGTERM), (2, signal.SIGKILL)):
            with self.subTest(number=number), subprocess.Popen(
                    [sys.executable, '-c', marker], start_new_session=True,
                    stdout=subprocess.PIPE, text=True) as child:
                try:
                    self.assertEqual(child.stdout.readline(), 'ready\n')
                    invalid = self.group_signal(child.pid, operation, parent=os.getppid())
                    self.assertEqual((invalid.returncode, invalid.stderr), (65, b''))
                    arbitrary = self.group_signal(child.pid, 15)
                    self.assertEqual((arbitrary.returncode, arbitrary.stderr), (65, b''))
                    self.assertIsNone(child.poll())
                    self.check_receipt(self.group_signal(child.pid, operation), 3, 0)
                    self.assertEqual(child.wait(timeout=5), -number)
                finally:
                    if child.poll() is None:
                        child.kill()

        with subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(20)']) as child:
            try:
                self.assertNotEqual(os.getpgid(child.pid), child.pid)
                self.check_receipt(self.group_signal(child.pid, 1), 2, -errno.EBADMSG)
                self.assertIsNone(child.poll())
            finally:
                child.terminate()
        self.assertEqual(list(self.root.iterdir()), [])

    def test_both_durable_publications_preserve_bytes_and_mode(self):
        destination = self.root / 'job_1.2@local.json'
        self.check_receipt(self.request(), 6, 0)
        self.assertEqual(destination.read_bytes(), b'{\n  "launch_state": "pending"\n}')
        old = destination.stat().st_ino
        result = b'{\n  "launch_state": "started"\n}'
        self.check_receipt(self.request(payload=result), 6, 0)
        self.assertEqual(destination.read_bytes(), result)
        self.assertNotEqual(old, destination.stat().st_ino)
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)
        self.assertEqual(list(self.root.iterdir()), [destination])

    def test_existing_temporary_is_not_overwritten_or_promoted(self):
        pending = self.root / f'job_1.2@local.json.tmp.{os.getpid()}'
        pending.write_bytes(b'frozen prior attempt')
        self.check_receipt(self.request(), 1, -errno.EEXIST)
        self.assertEqual(pending.read_bytes(), b'frozen prior attempt')
        self.assertEqual(list(self.root.iterdir()), [pending])

    def test_rename_failure_is_not_success_or_replayed(self):
        destination = self.root / 'job_1.2@local.json'
        destination.mkdir()
        self.check_receipt(self.request(payload=b'{}'), 5, -errno.EISDIR)
        pending = self.root / f'job_1.2@local.json.tmp.{os.getpid()}'
        self.assertEqual(pending.read_bytes(), b'{}')
        self.assertTrue(destination.is_dir())
        self.check_receipt(self.request(), 1, -errno.EEXIST)

    def test_bad_descriptor_and_frame_refuse_before_owning_a_name(self):
        for kwargs in ({'parent': os.getpid() + 1}, {'sealed': False}, {'suffix': b'x'},
                       {'name': b'../outside'}, {'name': b'x\0y'}, {'name': b'x' * 129},
                       {'payload': b'[]'}, {'payload': b'{}' * (CAPACITY // 2 + 1)}):
            with self.subTest(fields=tuple(kwargs)):
                refused = self.request(**kwargs)
                self.assertEqual((refused.returncode, refused.stderr), (65, b''))
                self.assertEqual(list(self.root.iterdir()), [])

    def test_original_registry_size_boundary(self):
        payload = b'{"value":"' + b'x' * (CAPACITY - 12) + b'"}'
        self.assertEqual(len(payload), CAPACITY)
        self.check_receipt(self.request(name=b'id', payload=payload), 6, 0)
        self.assertEqual((self.root / 'id.json').read_bytes(), payload)

    def test_terminal_wire_publishes_the_existing_newline_terminated_files(self):
        payload = b'{"terminal_publication_protocol": 1}\n'
        for name, raw, magic in ((b'exit', b'{}', b'HIAJRQ02'),
                                 (b'exit', b'{}\n\n', b'HIAJRQ02'),
                                 (b'exit.witnezz', payload, b'HIAJRQ02'),
                                 (b'job', payload, b'HIAJRQ02'),
                                 (b'exit', payload, b'HIAJRQ01')):
            refused = self.request(name=name, payload=raw, magic=magic)
            self.assertEqual((refused.returncode, refused.stderr), (65, b''))
            self.assertEqual(list(self.root.iterdir()), [])
        for name in (b'exit', b'exit.witness'):
            self.check_receipt(self.request(name=name, payload=payload, magic=b'HIAJRQ02'), 6, 0)
            destination = self.root / (name.decode('ascii') + '.json')
            self.assertEqual(destination.read_bytes(), payload)
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)

    def test_owner_wire_creates_both_exact_records_and_never_replaces_previous_intent(self):
        def owner(**kwargs):
            return self.request(name=b'', payload=b'{"supervisor_pid": 13}', magic=b'HIAJRO01', **kwargs)
        self.check_receipt(owner(), 6, 0)
        names = ('owner-intent.json', 'started.json')
        records = {name: (self.root / name).stat().st_ino for name in names}
        self.assertEqual(set(path.name for path in self.root.iterdir()), set(names))
        for name in names:
            record = self.root / name
            self.assertEqual(record.read_bytes(), b'{"supervisor_pid": 13}')
            self.assertEqual(stat.S_IMODE(record.stat().st_mode), 0o600)
        self.check_receipt(owner(), 1, -errno.EEXIST)
        self.assertEqual({name: (self.root / name).stat().st_ino for name in names}, records)

    def test_owner_wire_stops_at_partial_publication_without_retry(self):
        started = self.root / 'started.json'
        started.write_bytes(b'prior receipt')
        kwargs = {'name':b'', 'payload':b'{"supervisor_pid": 13}', 'magic':b'HIAJRO01'}
        self.check_receipt(self.request(**kwargs), 5, -errno.EEXIST)
        self.assertEqual(started.read_bytes(), b'prior receipt')
        intent = self.root / 'owner-intent.json'
        self.assertEqual(intent.read_bytes(), kwargs['payload'])
        previous = intent.stat().st_ino
        self.check_receipt(self.request(**kwargs), 1, -errno.EEXIST)
        self.assertEqual(intent.stat().st_ino, previous)

    def test_owner_wire_requires_seals_exact_parent_and_no_caller_names(self):
        request = {'name':b'', 'payload':b'{"supervisor_pid": 13}', 'magic':b'HIAJRO01'}
        for patch in ({'name':b'started'}, {'sealed':False}, {'parent':os.getpid()+1},
                      {'payload':b'{"supervisor_pid": 13}\n'}, {'suffix':b'x'},
                      {'payload':b'{'+b'x'*65535+b'}'}):
            refused = self.request(**(request | patch))
            self.assertEqual((refused.returncode, refused.stderr), (65, b''))
            self.assertEqual(list(self.root.iterdir()), [])

    def test_cancellation_publishes_before_signalling_only_the_original_pidfd(self):
        nonce = b'0123456789abcdef' * 2
        job = b'original-cancel'
        timestamp = 18446744073709551615
        record = self.root / 'cancel-request.json'
        staged = self.root / 'cancel-request.json.tmp'
        child = subprocess.Popen([sys.executable, '-I', '-S', '-c', 'import time; time.sleep(10)'])
        try:
            owner = os.pidfd_open(child.pid)
            try:
                def request(target=owner, name=job, token=nonce):
                    return struct.pack('<8s5Q32s', b'HIAJRC01', os.getpid(), target,
                                       timestamp, len(name), 0, token) + name

                for wrong in (request(target=1), request(name=b'not/a/name'), request(token=b'z' * 32)):
                    refused = self.invoke(wrong, pass_fds=(owner,))
                    self.assertEqual((refused.returncode, refused.stderr), (65, b''))
                    self.assertIsNone(child.poll())
                    self.assertEqual(list(self.root.iterdir()), [])
                staged.write_bytes(b'original incomplete cancellation')
                staged_inode = staged.stat().st_ino
                self.check_receipt(self.invoke(request(), pass_fds=(owner,)), 1, -errno.EEXIST)
                self.assertEqual(staged.stat().st_ino, staged_inode)
                self.assertFalse(record.exists())
                self.assertIsNone(child.poll())
                staged.unlink()
                self.check_receipt(self.invoke(request(), pass_fds=(owner,)), 7, 0)
                self.assertEqual(child.wait(timeout=4), -15)
                expected = {'at_unix_ms': timestamp, 'job_id': job.decode(), 'launch_nonce': nonce.decode()}
                self.assertEqual(record.read_bytes(), (json.dumps(expected, sort_keys=True) + '\n').encode())
                self.assertEqual(stat.S_IMODE(record.stat().st_mode), 0o600)
                self.assertFalse(staged.exists())
            finally:
                os.close(owner)
        finally:
            if child.poll() is None:
                child.terminate()
            child.wait(timeout=4)
