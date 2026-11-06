"""Refuse incomplete guest evidence and preserve real process failures."""
from contextlib import contextmanager
import ctypes
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from unittest import mock

from tools import qualify_hia_linux_baseline as baseline


RUN_ID = 'abcd1234abcd1234abcd1234'


def serial(*, missing=None, failed=None, duplicate=None, run_id=RUN_ID):
    events = [{'event': 'begin', 'pid': 1, 'run_id': run_id}]
    for key in baseline.CHECK_IDS:
        if key == missing:
            continue
        event = {'event': 'check', 'run_id': run_id, 'id': key, 'passed': key != failed, 'errno': 0}
        events.append(event)
        if key == duplicate:
            events.append(event.copy())
    events += [{'event': 'complete', 'run_id': run_id, 'total': len(baseline.CHECK_IDS),
                'passed': len(baseline.CHECK_IDS)-(failed is not None), 'failed': int(failed is not None)},
               {'event': 'shutdown', 'run_id': run_id, 'operation': 'poweroff'}]
    return '\n'.join(baseline.PREFIX + json.dumps(e) for e in events) + '\n[0.4] reboot: Power down\n'


class GuestEvidence(unittest.TestCase):
    def test_complete_inventory_requires_clean_exit_and_actual_powerdown(self):
        text = serial()
        self.assertEqual(baseline.parse_guest_serial(text, RUN_ID, 0, False)['status'], 'PASS')
        for code, timed_out in [(1, False), (-15, False), (0, True)]:
            self.assertEqual(baseline.parse_guest_serial(text, RUN_ID, code, timed_out)['status'], 'FAIL')
        self.assertEqual(baseline.parse_guest_serial(text.replace('reboot: Power down', ''), RUN_ID, 0, False)['status'], 'FAIL')

    def test_missing_check_keeps_not_run(self):
        verdict = baseline.parse_guest_serial(serial(missing='mmap_pages'), RUN_ID, 0, False)
        self.assertEqual(verdict['status'], 'FAIL')
        self.assertEqual(verdict['guest_tests']['not_run'], 1)
        self.assertEqual(verdict['guest_tests']['skipped'], 0)

    def test_one_actual_failed_check_is_retained(self):
        verdict = baseline.parse_guest_serial(serial(failed='file_lifecycle'), RUN_ID, 0, False)
        self.assertEqual(verdict['guest_tests']['failed'], 1)
        self.assertEqual(verdict['guest_tests']['passed'], 13)
        self.assertEqual(verdict['status'], 'FAIL')

    def test_duplicate_check_and_stale_nonce_rejected(self):
        for text in (serial(duplicate='pipe_roundtrip'), serial(run_id='0' * 24)):
            self.assertEqual(baseline.parse_guest_serial(text, RUN_ID, 0, False)['status'], 'FAIL')

    def test_malformed_or_nonboolean_protocol_is_not_ignored(self):
        for text in (serial() + baseline.PREFIX + '{bad}\n',
                     serial().replace('"passed": true', '"passed": 1', 1)):
            self.assertEqual(baseline.parse_guest_serial(text, RUN_ID, 0, False)['status'], 'FAIL')

    def test_empty_serial_and_completed_without_shutdown_rejected(self):
        for text in ('', '\n'.join(x for x in serial().splitlines() if 'shutdown' not in x)):
            self.assertEqual(baseline.parse_guest_serial(text, RUN_ID, 0, False)['status'], 'FAIL')

    def test_boolean_complete_count_is_not_an_integer_receipt(self):
        text = serial().replace('"failed": 0', '"failed": false')
        self.assertEqual(baseline.parse_guest_serial(text, RUN_ID, 0, False)['status'], 'FAIL')


    def test_complete_guest_stream_cannot_override_observed_host_group_failure(self):
        for failure in ({'incomplete_process_group': True},
                        {'process_group_cleanup': {'drained': False}},
                        {'interruption': {'type': 'RequestedCancellation', 'message': 'cancelled'}}):
            with self.subTest(failure=failure):
                record = {'exit_code': 0, 'timed_out': False, **failure}
                self.assertFalse(baseline.command_succeeded(record))
                verdict = baseline.parse_guest_serial(serial(), RUN_ID, 0, False, command_receipt=record)
                self.assertEqual(verdict['guest_tests']['passed'], 14)
                self.assertEqual(verdict['status'], 'FAIL')
                self.assertIn('host command process group did not complete', verdict['protocol_errors'])

    def test_legacy_or_partial_group_receipt_cannot_be_admitted(self):
        legacy = {'exit_code': 0, 'timed_out': False}
        verdict = baseline.parse_guest_serial(serial(), RUN_ID, 0, False, command_receipt=legacy)
        self.assertFalse(baseline.command_succeeded(legacy))
        self.assertEqual(verdict['guest_tests']['passed'], 14)
        self.assertEqual(verdict['status'], 'FAIL')
        self.assertIn('host command process group did not complete', verdict['protocol_errors'])
        group = 12345
        scoped = {**legacy, 'process_group': group}
        partial_receipts = (
            {'drained': True},
            {'group': group, 'scope': 'owned_linux_process_group', 'drained': True},
            {'group': group, 'scope': 'owned_linux_process_group', 'drained': True,
             'signals': [], 'live_members_after': [{'pid': 99, 'state': 'S'}], 'errors': []},
            {'group': group, 'scope': 'owned_linux_process_group', 'drained': True,
             'signals': [], 'live_members_after': []},
        )
        for cleanup in partial_receipts:
            with self.subTest(cleanup=cleanup):
                self.assertFalse(baseline.command_succeeded(
                    {**scoped, 'process_group_cleanup': cleanup}))
        complete_cleanup = {
            'group': group, 'scope': 'owned_linux_process_group', 'drained': True,
            'signals': [], 'live_members_after': [], 'errors': [], 'elapsed_ns': 0}
        complete_tree = {
            'schema': 'hepta.hia.process-tree-cleanup.v1',
            'supervisor_pid': group, 'target_pid': group + 1,
            'target_process_group': group + 1, 'target_exit_code': 0,
            'interrupted_signal': None, 'incomplete_process_tree': False,
            'adopted_children_before_cleanup': [], 'adopted_children_after_cleanup': [],
            'target_group_members_after': [], 'signals': [], 'errors': [],
            'drained': True, 'elapsed_ns': 0,
            'child_user_seconds': 0.0, 'child_system_seconds': 0.0}
        completed = {**scoped, 'process_group_cleanup': complete_cleanup,
                     'process_tree_cleanup': complete_tree}
        self.assertTrue(baseline.command_succeeded(completed))
        self.assertEqual(baseline.parse_guest_serial(
            serial(), RUN_ID, 0, False, command_receipt=completed)['status'], 'PASS')
        tampered = (
            {**completed, 'process_group': group + 1},
            {**scoped, 'process_group_cleanup': {**complete_cleanup, 'group': group + 1}},
            {**scoped, 'process_group_cleanup': {**complete_cleanup, 'scope': 'other'}},
            {**scoped, 'process_group_cleanup': {**complete_cleanup, 'signals': ['SIGTERM']}},
            {**scoped, 'process_group_cleanup': {**complete_cleanup, 'errors': [{'phase': 'observe'}]}},
            {**scoped, 'process_group_cleanup': {**complete_cleanup, 'elapsed_ns': -1}},
            {**scoped, 'process_group_cleanup': {**complete_cleanup, 'elapsed_ns': True}},
        )
        for record in tampered:
            with self.subTest(record=record):
                self.assertFalse(baseline.command_succeeded(record))


class InputsAndProcesses(unittest.TestCase):
    def test_module_directory_is_explicit_and_never_inherited_from_ambient_environment(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(os.environ, {'QEMU_MODULE_DIR': '/ambient/untrusted'}):
            root = Path(directory)
            env = baseline.build_environment(root/'llvm/bin', root/'sysroot')
            self.assertEqual(env['QEMU_MODULE_DIR'], str(root/'sysroot/usr/lib/x86_64-linux-gnu/qemu'))
            self.assertNotIn('QEMU_MODULE_DIR', baseline.build_environment(root/'llvm/bin'))
            with self.assertRaisesRegex(ValueError, 'runtime module is missing'):
                baseline.qemu_runtime_modules(env)
            modules = Path(env['QEMU_MODULE_DIR']); modules.mkdir(parents=True)
            target = modules/'accel-tcg-x86_64.so'; target.write_bytes(b'first module bytes')
            before = baseline.qemu_runtime_modules(env)
            target.write_bytes(b'different module bytes')
            self.assertNotEqual(baseline.qemu_runtime_modules(env), before)

    def test_preflight_keeps_cpu_paused_and_has_no_kernel_or_network(self):
        command = baseline.qemu_machine_command('qemu', 'data', 'bios', paused=True)
        self.assertIn('-S', command)
        self.assertEqual(command[command.index('-monitor')+1], 'stdio')
        self.assertEqual(command[command.index('-serial')+1], 'none')
        self.assertEqual(command[command.index('-nic')+1], 'none')
        self.assertNotIn('-kernel', command)
        self.assertNotIn('-initrd', command)

    def test_bounded_real_process_input_is_preserved_and_not_interactive(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = baseline.CommandRunner(directory, {'PATH': os.environ['PATH']})
            record = runner.run('quit-input', [sys.executable, '-c',
                'import sys; data=sys.stdin.buffer.read(); sys.stdout.buffer.write(data); sys.exit(0 if data==b"quit\\n" else 7)'],
                stdin_bytes=b'quit\n')
            self.assertTrue(baseline.command_succeeded(record))
            self.assertEqual(record['process_group_cleanup']['scope'], 'owned_linux_process_group')
            self.assertIs(type(record['process_group']), int)
            self.assertEqual(record['process_group'], record['process_group_cleanup']['group'])
            self.assertIs(type(record['process_group_cleanup']['group']), int)
            self.assertTrue(record['process_group_cleanup']['drained'])
            self.assertEqual(record['process_group_cleanup']['signals'], [])
            self.assertEqual(record['process_group_cleanup']['live_members_after'], [])
            self.assertEqual(record['process_group_cleanup']['errors'], [])
            self.assertIs(type(record['process_group_cleanup']['elapsed_ns']), int)
            self.assertEqual(Path(record['stdin']['path']).read_bytes(), b'quit\n')
            self.assertEqual(record['stdin']['sha256'], hashlib.sha256(b'quit\n').hexdigest())
            self.assertEqual(Path(record['stdout']['path']).read_bytes(), b'quit\n')
            with self.assertRaisesRegex(ValueError, 'bounded bytes'):
                runner.run('too-large', [sys.executable], stdin_bytes=b'x'*4097)

    def test_newc_preserves_executable_bytes_and_console_device(self):
        body = b'ELF fixture bytes\x00\xff'
        archive = baseline.newc([('init', stat.S_IFREG | 0o755, body, 0, 0),
                                 ('dev/console', stat.S_IFCHR | 0o600, b'', 5, 1)])
        offset, members = 0, {}
        while True:
            self.assertEqual(archive[offset:offset+6], b'070701')
            fields = [int(archive[offset+6+8*i:offset+14+8*i], 16) for i in range(13)]
            name = archive[offset+110:offset+110+fields[11]-1].decode()
            offset = (offset+110+fields[11]+3)//4*4
            data = archive[offset:offset+fields[6]]
            offset = (offset+fields[6]+3)//4*4
            if name == 'TRAILER!!!':
                break
            members[name] = (fields, data)
        self.assertEqual(members['init'][1], body)
        self.assertEqual(members['init'][0][1], stat.S_IFREG | 0o755)
        self.assertEqual(members['dev/console'][0][9:11], [5, 1])
        with self.assertRaises(ValueError):
            baseline.newc([('../escape', stat.S_IFREG, b'', 0, 0)])

    def test_initramfs_is_reproducible_and_not_host_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'init').write_bytes(b'not executed')
            baseline.create_initramfs(root/'init', root/'one.gz')
            baseline.create_initramfs(root/'init', root/'two.gz')
            self.assertEqual((root/'one.gz').read_bytes(), (root/'two.gz').read_bytes())
            self.assertIn(b'not executed', gzip.decompress((root/'one.gz').read_bytes()))

    def test_pristine_archive_checks_changed_added_and_symlink_members(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source = root/'source'; source.mkdir()
            (source/'unit.c').write_bytes(b'int unit;\n')
            (source/'link').symlink_to('unit.c')
            archive = root/'source.tar.xz'
            with tarfile.open(archive, 'w:xz') as stream:
                stream.add(source, arcname='linux-test', recursive=True)
            expected = baseline.sha(archive)
            self.assertEqual(len(baseline.verify_kernel_source(source, archive, expected)), 2)
            (source/'unit.c').write_bytes(b'int changed;\n')
            with self.assertRaisesRegex(ValueError, 'differs'):
                baseline.verify_kernel_source(source, archive, expected)
            (source/'unit.c').write_bytes(b'int unit;\n')
            (source/'extra').write_bytes(b'extra')
            with self.assertRaisesRegex(ValueError, 'differs'):
                baseline.verify_kernel_source(source, archive, expected)

    def test_config_parser_rejects_duplicate_and_retains_disabled_symbols(self):
        parsed = baseline.parse_config('CONFIG_SMP=y\n# CONFIG_UNSAFE is not set\n')
        self.assertEqual(parsed['CONFIG_UNSAFE'], 'n')
        with self.assertRaises(ValueError):
            baseline.parse_config('CONFIG_SMP=y\nCONFIG_SMP=n\n')

    def test_qemu_is_tcg_bounded_and_has_no_external_network(self):
        command = baseline.qemu_command('qemu', 'data', 'bios', 'bzImage', 'initrd', RUN_ID, '6.18.60')
        self.assertEqual(command[command.index('-accel')+1], 'tcg,thread=multi')
        self.assertEqual(command[command.index('-cpu')+1], 'qemu64,-popcnt')
        self.assertEqual(command[command.index('-nic')+1], 'none')
        self.assertIn('hia_run_id=' + RUN_ID, command[-1])
        with self.assertRaises(ValueError):
            baseline.qemu_command('qemu', 'data', 'bios', 'kernel', 'initrd', 'unsafe value', '6.18.60')

    def test_real_process_failure_and_timeout_keep_original_streams(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = baseline.CommandRunner(directory, {'PATH': os.environ['PATH']})
            record = runner.run('exit-seven', [sys.executable, '-c',
                'import sys; print("retained-out"); print("retained-err",file=sys.stderr);sys.exit(7)'], check=False)
            self.assertEqual(record['exit_code'], 7)
            self.assertEqual(Path(record['stdout']['path']).read_text(), 'retained-out\n')
            self.assertEqual(Path(record['stderr']['path']).read_text(), 'retained-err\n')
            timed = runner.run('real-timeout', [sys.executable, '-c', 'import time;time.sleep(5)'], timeout=0.05, check=False)
            self.assertTrue(timed['timed_out'])
            self.assertNotEqual(timed['exit_code'], 0)
            self.assertEqual(len(list((Path(directory)/'commands').glob('*.started.json'))), 2)

    def test_missing_executable_has_a_failed_command_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = baseline.CommandRunner(directory, {'PATH': os.environ['PATH']})
            record = runner.run('missing', ['/this-executable-does-not-exist'], check=False)
            self.assertEqual(record['exit_code'], 127)
            self.assertIn('spawn_error', record)
            tree = record['process_tree_cleanup']
            self.assertIsNone(tree['target_pid'])
            self.assertTrue(tree['incomplete_process_tree'])
            self.assertFalse(tree['drained'])
            self.assertEqual(tree['errors'][0]['type'], 'FileNotFoundError')
            self.assertEqual(record['spawn_error'], tree['errors'][0]['message'])
            self.assertTrue(record['incomplete_process_group'])
            self.assertFalse(baseline.command_succeeded(record))
            self.assertTrue(list((Path(directory)/'commands').glob('*-missing.json')))


class ProcessGroupTeardown(unittest.TestCase):
    """A leader's exit is not evidence that its descendants stopped writing."""

    @staticmethod
    @contextmanager
    def reap_orphaned_fixture_children():
        libc = ctypes.CDLL(None, use_errno=True)
        previous = ctypes.c_int()
        if libc.prctl(37, ctypes.byref(previous), 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), 'PR_GET_CHILD_SUBREAPER failed')
        if libc.prctl(36, 1, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), 'PR_SET_CHILD_SUBREAPER failed')
        try:
            yield
        finally:
            if libc.prctl(36, previous.value, 0, 0, 0) != 0:
                raise OSError(ctypes.get_errno(), 'restore child subreaper failed')

    @staticmethod
    def live(pid):
        try:
            fields = (Path('/proc') / str(pid) / 'stat').read_text().rsplit(')', 1)[1].split()
        except FileNotFoundError:
            return False
        return fields[0] not in ('Z', 'X')

    @staticmethod
    def child_command(root, *, leader_exits=False):
        script = root / 'group.py'
        script.write_text('''import os, pathlib, signal, sys, time
root = pathlib.Path(sys.argv[1])
(root / 'leader.pid').write_text(str(os.getpid()))
if os.fork() == 0:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    (root / 'child.pid').write_text(str(os.getpid()))
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        print('descendant-output', flush=True)
        time.sleep(0.02)
    os._exit(0)
if sys.argv[2] == 'exit':
    while not (root / 'child.pid').exists():
        time.sleep(0.005)
    sys.exit(0)
time.sleep(10)
''')
        return [sys.executable, '-u', str(script), str(root), 'exit' if leader_exits else 'wait']

    @staticmethod
    def cleanup_fixture(root, sentinel):
        # Only the session/group created by this fixture may be signalled.
        leader = root / 'leader.pid'
        if leader.exists():
            try:
                os.killpg(int(leader.read_text()), signal.SIGKILL)
            except ProcessLookupError:
                pass
        child = root / 'child.pid'
        if child.exists():
            pid = int(child.read_text())
            deadline = time.monotonic() + 3
            while True:
                try:
                    waited, _ = os.waitpid(pid, os.WNOHANG)
                except ChildProcessError:
                    break
                if waited == pid:
                    break
                if time.monotonic() >= deadline:
                    raise AssertionError('fixture child did not reap after SIGKILL')
                time.sleep(0.01)
        if sentinel.poll() is None:
            sentinel.terminate()
        sentinel.wait(timeout=3)

    def assert_quiescent(self, root, runner, sentinel, record, *, leader_exit=-signal.SIGTERM):
        child = int((root / 'child.pid').read_text())
        self.assertFalse(self.live(child), 'TERM-ignoring descendant survived command cleanup')
        self.assertIsNone(sentinel.poll(), 'cleanup signalled an unrelated session')
        self.assertEqual(record['exit_code'], leader_exit)
        self.assertEqual(len(runner.records), 1)
        self.assertTrue(record['process_group_cleanup']['drained'])
        tree = record['process_tree_cleanup']
        self.assertTrue(tree['drained'])
        self.assertEqual(tree['adopted_children_after_cleanup'], [])
        self.assertEqual(tree['target_group_members_after'], [])
        # The terminal receipt must describe final streams, after all writers stop.
        for key in ('stdout', 'stderr'):
            original = Path(record[key]['path']).read_bytes()
            self.assertEqual(hashlib.sha256(original).hexdigest(), record[key]['sha256'])
            time.sleep(0.03)
            self.assertEqual(Path(record[key]['path']).read_bytes(), original)

    def test_timeout_drains_term_ignoring_descendant_after_leader_exits(self):
        with tempfile.TemporaryDirectory() as directory, self.reap_orphaned_fixture_children():
            root = Path(directory)
            command = self.child_command(root)
            sentinel = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(10)'],
                                        start_new_session=True)
            runner = baseline.CommandRunner(root, {'PATH': os.environ['PATH']})
            try:
                with mock.patch.object(baseline, 'GROUP_TERM_GRACE_SECONDS', 0.1, create=True), \
                     mock.patch.object(baseline, 'GROUP_KILL_GRACE_SECONDS', 1.0, create=True):
                    record = runner.run('timeout-descendant', command, timeout=0.75, check=False)
                self.assertTrue(record['timed_out'])
                self.assert_quiescent(root, runner, sentinel, record)
            finally:
                self.cleanup_fixture(root, sentinel)

    def test_successful_leader_cannot_finalize_while_descendant_keeps_writing(self):
        with tempfile.TemporaryDirectory() as directory, self.reap_orphaned_fixture_children():
            root = Path(directory)
            command = self.child_command(root, leader_exits=True)
            sentinel = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(10)'],
                                        start_new_session=True)
            runner = baseline.CommandRunner(root, {'PATH': os.environ['PATH']})
            rejection = None
            try:
                with mock.patch.object(baseline, 'GROUP_TERM_GRACE_SECONDS', 0.1, create=True), \
                     mock.patch.object(baseline, 'GROUP_KILL_GRACE_SECONDS', 1.0, create=True):
                    try:
                        runner.run('orphaned-writer', command, timeout=4)
                    except ValueError as error:
                        rejection = error
                self.assertFalse(self.live(int((root / 'child.pid').read_text())),
                                 'successful leader left its output writer alive')
                self.assertIsNotNone(rejection, 'incomplete process group was accepted as a successful command')
                self.assertIn('command failed', str(rejection))
                record = runner.records[0]
                self.assertFalse(record['timed_out'])
                self.assertTrue(record['incomplete_process_group'])
                self.assert_quiescent(root, runner, sentinel, record, leader_exit=0)
            finally:
                self.cleanup_fixture(root, sentinel)

    def test_cancellation_drains_descendants_and_preserves_exception_and_receipt(self):
        class RequestedCancellation(BaseException):
            pass

        with tempfile.TemporaryDirectory() as directory, self.reap_orphaned_fixture_children():
            root = Path(directory)
            command = self.child_command(root)
            sentinel = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(10)'],
                                        start_new_session=True)
            runner = baseline.CommandRunner(root, {'PATH': os.environ['PATH']})
            cancellation = RequestedCancellation('cancel this owned command')
            real_wait, injected = subprocess.Popen.wait, False

            def interrupt_after_child_is_ready(process, *args, **kwargs):
                nonlocal injected
                if (isinstance(process.args, (list, tuple)) and len(process.args) > 1
                        and Path(process.args[1]) == baseline.PROCESS_SUPERVISOR and not injected):
                    deadline = time.monotonic() + 3
                    while not (root / 'child.pid').exists() and time.monotonic() < deadline:
                        time.sleep(0.005)
                    self.assertTrue((root / 'child.pid').exists(), 'real descendant did not start')
                    injected = True
                    raise cancellation
                return real_wait(process, *args, **kwargs)

            try:
                with mock.patch.object(subprocess.Popen, 'wait', interrupt_after_child_is_ready), \
                     mock.patch.object(baseline, 'GROUP_TERM_GRACE_SECONDS', 0.1, create=True), \
                     mock.patch.object(baseline, 'GROUP_KILL_GRACE_SECONDS', 1.0, create=True):
                    with self.assertRaises(RequestedCancellation) as caught:
                        runner.run('cancel-descendant', command, timeout=4)
                self.assertIs(caught.exception, cancellation)
                self.assertFalse(self.live(int((root / 'child.pid').read_text())),
                                 'cancelled command left a live descendant')
                self.assertEqual(len(runner.records), 1, 'interrupted command lost its terminal receipt')
                record = runner.records[0]
                self.assertFalse(record['timed_out'])
                self.assertEqual(record['interruption']['type'], 'RequestedCancellation')
                self.assertEqual(record['interruption']['message'], str(cancellation))
                self.assert_quiescent(root, runner, sentinel, record)
                final = root / 'commands/000-cancel-descendant.json'
                self.assertEqual(json.loads(final.read_text()), record)
            finally:
                self.cleanup_fixture(root, sentinel)


    def test_session_escaped_descendant_cannot_mutate_receipt_after_leader_exit(self):
        with tempfile.TemporaryDirectory() as directory, self.reap_orphaned_fixture_children():
            root = Path(directory)
            script = root / 'escaped-session.py'
            script.write_text('''import os, pathlib, signal, sys, time
root = pathlib.Path(sys.argv[1])
(root / 'leader.pid').write_text(str(os.getpid()))
if os.fork() == 0:
    os.setsid()
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    (root / 'child.pid').write_text(str(os.getpid()))
    (root / 'child.pgid').write_text(str(os.getpgrp()))
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        print('escaped-descendant-output', flush=True)
        time.sleep(0.02)
    os._exit(0)
deadline = time.monotonic() + 5
while not (root / 'child.pgid').exists() and time.monotonic() < deadline:
    time.sleep(0.005)
sys.exit(0 if (root / 'child.pgid').exists() else 7)
''')
            sentinel = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(10)'],
                                        start_new_session=True)
            runner = baseline.CommandRunner(root, {'PATH': os.environ['PATH']})
            try:
                record = runner.run('escaped-descendant',
                                    [sys.executable, '-u', str(script), str(root)],
                                    timeout=4, check=False)
                child = int((root / 'child.pid').read_text())
                child_group = int((root / 'child.pgid').read_text())
                self.assertNotEqual(child_group, record['process_group'])
                self.assertFalse(self.live(child), 'session-escaped descendant survived supervisor cleanup')
                self.assertTrue(record['incomplete_process_group'])
                self.assertTrue(record['process_group_cleanup']['drained'])
                self.assertEqual(record['process_group_cleanup']['live_members_after'], [])
                tree = record['process_tree_cleanup']
                self.assertTrue(tree['drained'])
                self.assertTrue(tree['incomplete_process_tree'])
                self.assertIn(child, [row['pid'] for row in tree['adopted_children_before_cleanup']])
                self.assertEqual(tree['adopted_children_after_cleanup'], [])
                self.assertIsNone(sentinel.poll(), 'cleanup signalled an unrelated session')
                self.assertFalse(
                    baseline.command_succeeded(record),
                    'leader exit was accepted while a session-escaped descendant remained live')
            finally:
                child_file = root / 'child.pid'
                if child_file.exists():
                    pid = int(child_file.read_text())
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    deadline = time.monotonic() + 3
                    while time.monotonic() < deadline:
                        try:
                            waited, _ = os.waitpid(pid, os.WNOHANG)
                        except ChildProcessError:
                            break
                        if waited == pid:
                            break
                        time.sleep(0.01)
                    else:
                        raise AssertionError('session-escaped fixture child did not reap after SIGKILL')
                if sentinel.poll() is None:
                    sentinel.terminate()
                sentinel.wait(timeout=3)


if __name__ == '__main__':
    unittest.main()
