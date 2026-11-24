"""Exercise actual native job ownership and its filesystem publication barriers."""
from contextlib import ExitStack
import errno
import fcntl
from hashlib import sha256
import json
import os
from pathlib import Path
import signal
import struct
import subprocess
import tempfile
import time
import unittest

from tests import test_hia_subprocess as process_fixtures
from tests.test_hia_subprocess import FIELDS, memfd, request


@unittest.skipUnless(os.environ.get('HIA_TEST_JOB_SUPERVISOR_EXE'), 'requires the native HIA job supervisor')
class NativeJobSupervisorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        process_fixtures.NativeSubprocessTests.setUpClass.__func__(cls)

    def run_job(self, mode='c', *, data=b'', deadline=2, cancel_after=None,
                mutate=None, job_id=b'native-job-test', nonce=b'a'*32,
                invocation=b'b'*32, trace=None):
        executable = Path(os.environ['HIA_TEST_JOB_SUPERVISOR_EXE']).resolve(strict=True)
        with ExitStack() as stack:
            root = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix='hia-native-job-')))
            job, cwd = root/'job', root/'cwd'
            job.mkdir(mode=0o700)
            cwd.mkdir(mode=0o700)
            job_fd = os.open(job, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            directory = os.open(cwd, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            stack.callback(os.close, job_fd)
            stack.callback(os.close, directory)
            exe = memfd(stack, 'job-fixture-executable', self.fixture, sealed=True, mode=0o700)
            source = memfd(stack, 'job-fixture-input', data, sealed=True)

            def destination(name):
                fd = os.open(job/name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
                stack.callback(os.close, fd)
                return fd

            output, errors, receipt = (destination(name) for name in ('stdout.log', 'stderr.log', 'native-exit.bin'))
            values = dict(parent=os.getpid(), deadline=time.monotonic_ns()+int(deadline*1e9),
                          executable=exe, source=source, output=output, errors=errors, directory=directory,
                          receipt=receipt, argv=(b'job-fixture', mode.encode()), env=(),
                          output_limit=1<<20, error_limit=1<<20, grace_ns=100_000_000)
            if mutate:
                mutate(values, stack, job, job_fd)
            original = request(**values)
            metadata = struct.pack('<QQ32sQ32s', job_fd, len(job_id), nonce, len(invocation), invocation)
            wire = b'HIAJOB01'+original[8:128]+metadata+job_id+original[128:]
            frame = memfd(stack, 'job-owner-request', wire, sealed=True)
            argv = [str(executable)]
            if trace:
                argv = ['/usr/bin/strace', '-D', '-f', '-qq', '-e',
                        'trace=execve,execveat,fork,clone,wait4,kill,fsync,renameat2,flock,openat,newfstatat',
                        '-o', str(trace), *argv]
            passed = (exe, source, values['output'], values['errors'], directory, receipt, job_fd,
                      *values.get('pass_fds', ()))
            with subprocess.Popen(argv, stdin=frame, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  pass_fds=passed, env={'PATH': ''}) as process:
                if cancel_after is not None:
                    time.sleep(cancel_after)
                    process.send_signal(signal.SIGTERM)
                stdout, stderr = process.communicate(timeout=8)
                rc, pid = process.returncode, process.pid
            rows, raw = {}, {}
            for name in ('owner-intent.json', 'started.json', 'child.json', 'exit.json', 'exit.witness.json'):
                path = job/name
                if path.is_file() and not path.is_symlink():
                    raw[name] = path.read_bytes()
                    try:
                        rows[name] = json.loads(raw[name])
                    except json.JSONDecodeError:
                        rows[name] = None
            binary = os.pread(receipt, 129, 0)
            record = dict(zip(FIELDS, struct.unpack('<8sq14Q', binary), strict=True)) if binary else None
            return dict(rc=rc, pid=pid, stdout=os.pread(values['output'], (1<<20)+1, 0),
                        stderr=os.pread(values['errors'], (1<<20)+1, 0), wire_stdout=stdout,
                        wire_stderr=stderr, records=rows, raw=raw, receipt=record,
                        names=sorted(p.name for p in job.iterdir()))

    def assert_witness(self, result):
        rows, raw = result['records'], result['raw']
        self.assertEqual((result['wire_stdout'], result['wire_stderr']), (b'', b''))
        self.assertEqual(raw['owner-intent.json'], raw['started.json'])
        self.assertEqual(rows['started.json']['supervisor_pid'], result['pid'])
        self.assertEqual(rows['started.json']['invocation_id'], 'b'*32)
        self.assertEqual(rows['started.json']['supervisor_uid'], os.geteuid())
        self.assertEqual(rows['started.json']['supervisor_identity']['kind'], 'proc_start_ticks')
        self.assertRegex(rows['started.json']['supervisor_identity']['value'], r'^[0-9a-f-]{36}:[1-9][0-9]*$')
        self.assertEqual(rows['exit.witness.json'], {
            'exit_sha256': sha256(raw['exit.json']).hexdigest(),
            'job_id': 'native-job-test', 'launch_nonce': 'a'*32, 'terminal_publication_protocol': 1})
        self.assertEqual(rows['exit.json']['job_id'], 'native-job-test')
        self.assertEqual(rows['exit.json']['launch_nonce'], 'a'*32)
        self.assertEqual(rows['exit.json']['terminal_publication_protocol'], 1)
        self.assertFalse(any(name.endswith('.tmp') for name in result['names']))
        if result['receipt']['child_pid']:
            self.assertEqual(rows['child.json']['pid'], result['receipt']['child_pid'])
            self.assertEqual(rows['child.json']['identity']['kind'], 'proc_start_ticks')
            self.assertRegex(rows['child.json']['identity']['value'], r'^[0-9a-f-]{36}:[1-9][0-9]*$')
            with self.assertRaises(ProcessLookupError):
                os.kill(result['receipt']['child_pid'], 0)

    def test_native_records_bind_exact_output_and_original_child(self):
        result = self.run_job('s')
        self.assertEqual(result['rc'], 17, result)
        self.assert_witness(result)
        self.assertEqual((result['stdout'], result['stderr']), (b'out', b'err'))
        exit = result['records']['exit.json']
        self.assertEqual(exit['exit_code'], 17)
        self.assertEqual(exit['log_bytes'], {'stderr': {'seen': 3, 'stored': 3}, 'stdout': {'seen': 3, 'stored': 3}})
        self.assertTrue(exit['output_complete'])
        self.assertTrue(exit['output_durable'])

    def test_binary_input_and_durable_zero_exit(self):
        data = bytes(range(256))*511
        result = self.run_job(data=data)
        self.assertEqual(result['rc'], 0, result['records'])
        self.assert_witness(result)
        self.assertEqual(result['stdout'], data)
        self.assertEqual(result['records']['exit.json']['exit_code'], 0)

    def test_deadline_publishes_actual_terminal_observation(self):
        result = self.run_job('w', deadline=.2)
        self.assertEqual(result['rc'], 124, result)
        self.assert_witness(result)
        self.assertTrue(result['records']['exit.json']['timed_out'])
        self.assertFalse(result['records']['exit.json']['cancelled'])
        self.assertEqual(result['records']['exit.json']['exit_code'], 124)
        self.assertEqual(result['receipt']['exit_code'], -signal.SIGTERM)

    def test_signal_cancellation_publishes_reaped_child(self):
        result = self.run_job('w', cancel_after=.12)
        self.assertEqual(result['rc'], 1, result)
        self.assert_witness(result)
        self.assertTrue(result['records']['exit.json']['cancelled'])
        self.assertFalse(result['records']['exit.json']['timed_out'])
        self.assertEqual(result['records']['exit.json']['exit_code'], -signal.SIGTERM)

    def test_capture_error_remains_unknown_and_durable(self):
        def sealed_output(values, stack, job, directory):
            values['output'] = memfd(stack, 'job-failing-output')
            fcntl.fcntl(values['output'], fcntl.F_ADD_SEALS, fcntl.F_SEAL_GROW)
        result = self.run_job('o', mutate=sealed_output)
        self.assertEqual(result['rc'], 125, result)
        self.assert_witness(result)
        exit = result['records']['exit.json']
        self.assertEqual(exit['effect_outcome'], 'unknown')
        self.assertFalse(exit['status_authoritative'])
        self.assertFalse(exit['automatic_retry'])
        self.assertFalse(exit['output_complete'])
        self.assertFalse(exit['output_durable'])
        self.assertEqual(exit['log_errors']['stdout'], 'errno '+str(errno.EPERM))

    def test_existing_markers_and_dangling_links_never_replay(self):
        for name in ('owner-intent.json', 'child.json.tmp', 'exit.json', 'exit.witness.json.tmp'):
            def tombstone(values, stack, job, directory):
                (job/name).symlink_to('missing-owner-marker')
            with self.subTest(marker=name):
                result = self.run_job('s', mutate=tombstone)
                self.assertEqual(result['rc'], 65)
                self.assertIsNone(result['receipt'])
                self.assertEqual((result['stdout'], result['stderr']), (b'', b''))
                self.assertNotIn('started.json', result['records'])

    def test_original_lifetime_lock_prevents_a_second_owner(self):
        def hold(values, stack, job, directory):
            fd = os.open(job/'owner.lock', os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
            stack.callback(os.close, fd)
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = self.run_job('s', mutate=hold)
        self.assertEqual(result['rc'], 65)
        self.assertIsNone(result['receipt'])
        self.assertNotIn('started.json', result['records'])

    def test_metadata_refusals_precede_owner_publication(self):
        for values in ({'nonce': b'z'*32}, {'job_id': b'unsafe/job'}, {'invocation': b'bad'}):
            with self.subTest(values=values):
                result = self.run_job('s', **values)
                self.assertEqual(result['rc'], 65)
                self.assertIsNone(result['receipt'])
                self.assertNotIn('owner-intent.json', result['records'])

    def test_trace_owns_barriers_before_fork_without_an_interpreter(self):
        with tempfile.TemporaryDirectory(prefix='hia-job-trace-') as folder:
            trace = Path(folder)/'trace'
            result = self.run_job('s', trace=trace)
            self.assertEqual(result['rc'], 17, result)
            self.assert_witness(result)
            text = trace.read_text()
            executions = [line for line in text.splitlines() if 'execve(' in line or 'execveat(' in line]
            self.assertEqual(len(executions), 2, text)
            self.assertNotRegex('\n'.join(executions), r'python|/bin/(sh|bash)')
            self.assertLess(text.index('"started.json", RENAME_NOREPLACE'), text.index('fork('))
            self.assertIn('flock(', text)
            self.assertIn('"child.json", RENAME_NOREPLACE', text)
            self.assertIn('"exit.json", RENAME_NOREPLACE', text)
            self.assertIn('"exit.witness.json", RENAME_NOREPLACE', text)
            self.assertGreaterEqual(text.count('fsync('), 13)


if __name__ == '__main__':
    unittest.main()
