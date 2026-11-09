"""Pure-Python fake children exercise bounded capture, never Lean/native targets."""
from contextlib import ExitStack
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tools import core_seven_part04_capture as capture
from tools.check_core_syntax_staged import SafeRoot

PLATFORM = {'sys_platform': 'linux', 'machine': 'x86_64',
            'os_release': {'ID': 'ubuntu', 'VERSION_ID': '24.04'}, 'libc': 'glibc 2.39'}


import errno

def planned():
    return [dict(id=capture.PREFIX + "%03d" % i, original_offset=i*100, instrumented_offset=i*135) for i in range(11)]

def lines():
    return b"".join(('"'+m["id"]+'" : String\n').encode() for m in planned())

class Part04CaptureTests(unittest.TestCase):
    def run_child(self, script, *, observer=None, markers=None, overrides=(), setup=None, platform_value=PLATFORM, target=capture.TARGET):
        markers = planned() if markers is None else markers
        real_popen = subprocess.Popen
        with tempfile.TemporaryDirectory() as folder, ExitStack() as stack:
            safe = SafeRoot(Path(folder) / 'fresh')
            stack.callback(safe.close)
            safe.write('SevenCertificatePart04.started.json', b'{}')
            executable = Path(folder) / 'pinned/bin/lean'
            executable.parent.mkdir(parents=True)
            executable.write_bytes(b'never executed')
            launches = []
            processes = []
            snapshot = set(os.listdir('/proc/self/fd'))
    
            def launch(argv, **kwargs):
                launches.append((argv, kwargs))
                self.assertEqual(argv, [str(executable), '--root=' + str(safe.path), '-o',
                                        str(safe.path / 'HiaSyntaxResearch/CertPart04.olean'), str(safe.path / 'HiaSyntaxResearch/CertPart04.lean')])
                self.assertTrue(os.isatty(kwargs['stdout']))
                self.assertEqual(kwargs['stderr'], subprocess.PIPE)
                self.assertEqual(kwargs['stdin'], subprocess.DEVNULL)
                self.assertTrue(kwargs['start_new_session'])
                self.assertTrue(kwargs['close_fds'])
                self.assertEqual(kwargs['env']['LEAN_PATH'], str(safe.path))
                self.assertNotIn('LEAN_SRC_PATH', kwargs['env'])
                # Only this test adapter substitutes a Python script for Lean.
                process = real_popen([sys.executable, '-c', script], **kwargs)
                processes.append(process)
                return process
    
            stack.enter_context(patch.object(capture, 'platform_observation', return_value=platform_value))
            stack.enter_context(patch.object(capture.subprocess, 'Popen', side_effect=launch))
            stack.enter_context(patch.object(capture, 'PROCESS_SECONDS', 1))
            stack.enter_context(patch.object(capture, 'CLEANUP_SECONDS', 1))
            for name, value in overrides:
                stack.enter_context(patch.object(capture, name, value))
            if setup is not None:
                setup(safe, stack)
            result = capture.capture_result(executable, safe.path / 'HiaSyntaxResearch/CertPart04.lean', safe.path / 'HiaSyntaxResearch/CertPart04.olean',
                                             safe.path, safe_root=safe, markers=markers, observer=observer, target=target,
                                             started_reference={'path':'SevenCertificatePart04.started.json','sha256':sha256(b'{}').hexdigest()})
            names, _ = capture.target_configuration(target)
            files = {name: (safe.path / name).read_bytes() for name in names
                     if (safe.path / name).is_file() and not (safe.path / name).is_symlink()}
            self.assertEqual(set(os.listdir('/proc/self/fd')), snapshot)
            for process in processes:
                self.assertIsNotNone(process.returncode)
                with self.assertRaises(ChildProcessError):
                    os.waitpid(process.pid, os.WNOHANG)
            self.assertFalse(result['kernel_core_syntax_connection_checked'])
            self.assertEqual(result['authority'], 'DENY_ALL')
            self.assertLessEqual(sum(result['observed_bytes'].values()), capture.RAW_LIMIT)
            self.assertLessEqual(result['raw_written_bytes'], capture.RAW_LIMIT)
            self.assertLessEqual(result['metadata_written_bytes'], capture.INTERNAL_METADATA_LIMIT)
            self.assertGreaterEqual(result['metadata_remaining_bytes'], 4096)
            if result['terminal_record_persisted']:
                events = files[names[2]]
                self.assertEqual(len(events), result['metadata_written_bytes'])
                self.assertEqual(result['compact_receipt_reference']['sha256'], sha256(events).hexdigest())
                self.assertEqual(json.loads(events.splitlines()[-1])['kind'], 'terminal')
                self.assertLessEqual(len(events), capture.EVENT_STREAM_LIMIT)
                self.assertNotIn(b'"kind":"receive"', events)
            return result, files, launches

    def test_platform_parser_accepts_quoted_values_and_rejects_duplicates(self):
        for content in (b'ID=ubuntu\nVERSION_ID="24.04"\n', b"ID='ubuntu'\nVERSION_ID=24.04\n"):
            with patch('builtins.open', return_value=io.BytesIO(content)), \
                    patch.object(capture.sys, 'platform', 'linux'), \
                    patch.object(capture.platform, 'machine', return_value='x86_64'), \
                    patch.object(capture.os, 'confstr', return_value='glibc 2.39'):
                self.assertEqual(capture.platform_observation(), PLATFORM)
        for content in (b'ID=ubuntu\nID=ubuntu\nVERSION_ID=24.04\n', b'ID="ubuntu\n',
                        b'ID=ubuntu debian\nVERSION_ID=24.04\n', b'ID=$(echo ubuntu)\n'):
            with self.subTest(content=content), patch('builtins.open', return_value=io.BytesIO(content)):
                with self.assertRaises(ValueError):
                    capture.platform_observation()

    def test_pty_allocation_configuration_readback_and_isatty_fail_closed(self):
        for target in ('openpty', 'isatty', 'setattr', 'readback'):
            def setup(safe, stack):
                if target == 'openpty':
                    stack.enter_context(patch.object(capture.os, 'openpty', side_effect=OSError('no PTY')))
                elif target == 'isatty':
                    stack.enter_context(patch.object(capture.os, 'isatty', return_value=False))
                elif target == 'setattr':
                    stack.enter_context(patch.object(capture.termios, 'tcsetattr', side_effect=OSError('termios refused')))
                else:
                    original = capture.termios.tcgetattr
                    def wrong(fd):
                        attrs = original(fd)
                        attrs[1] = 1
                        return attrs
                    stack.enter_context(patch.object(capture.termios, 'tcgetattr', side_effect=wrong))
            with self.subTest(target=target):
                result, _, launches = self.run_child('pass', setup=setup)
                self.assertEqual(result['status'], 'diagnostic_infrastructure_failed')
                self.assertEqual(launches, [])

    def test_shared_raw_limit_counts_every_read_and_kills_no_newline_flood(self):
        for stream in (1, 2):
            script = 'import os,time\nwhile True: os.write(%d,b"x"*8192)\n' % stream
            with self.subTest(stream=stream):
                result, files, _ = self.run_child(script, overrides=(('RAW_LIMIT', 32768),))
                self.assertEqual(result['status'], 'diagnostic_output_limit', result)
                self.assertEqual(sum(result['observed_bytes'].values()), 32768)
                self.assertEqual(result['raw_written_bytes'], 32768)
                self.assertTrue(result['output_truncated'])
                self.assertTrue(result['group_kill_sent'])
                self.assertEqual(sum(len(files[n]) for n in capture.DIAGNOSTIC_FILES[:2]), 32768)

    def test_timeout_empty_and_partial_output_reaps_leader_and_preserves_prefix(self):
        for prefix in (b'', b'partial marker without newline'):
            script = 'import os,time\nos.write(1,%r)\ntime.sleep(10)' % prefix
            with self.subTest(prefix=prefix):
                started = time.monotonic()
                result, files, _ = self.run_child(script, overrides=(('PROCESS_SECONDS', 0.15),))
                self.assertEqual(result['status'], 'diagnostic_timeout', result)
                self.assertEqual(files[capture.DIAGNOSTIC_FILES[0]], prefix)
                self.assertLess(time.monotonic() - started, 1.5)
                self.assertTrue(result['leader_reaped'])
                self.assertTrue(result['group_kill_sent'])
                self.assertEqual(result['signal'], signal.SIGKILL)

    def test_held_descendant_descriptors_are_killed_after_leader_exits(self):
        script = """import os,time
pid=os.fork()
if pid==0:
 time.sleep(10)
else:
 with open('/proc/'+str(pid)+'/stat') as stream:
  birth=stream.read().rpartition(')')[2].split()[19]
 os.write(1,(str(pid)+' '+birth+'\\n').encode())
"""
        started = time.monotonic()
        deadline = started + 1.5
        result, files, _ = self.run_child(script)
        self.assertLess(time.monotonic() - started, 1.5)
        self.assertTrue(result['group_kill_sent'])
        self.assertTrue(result['leader_reaped'])
        self.assertTrue(result['drain_complete'], result)
        self.assertFalse(result['cleanup_incomplete'], result)
        self.assertFalse(result['cleanup_deadline_exceeded'], result)
        child, birth = files[capture.DIAGNOSTIC_FILES[0]].strip().decode().split()
        identity = Path('/proc') / child / 'stat'
        # Closing inherited descriptors and publishing EXIT_ZOMBIE are separate
        # kernel exit observations. Keep the original total 1.5-second bound;
        # a signal receipt alone, a persistent live state, or a late Z is not
        # enough to pass this real-child termination control. A reused PID no
        # longer identifies this child, so compare its recorded start time too.
        observations = []
        while True:
            try:
                fields = identity.read_text().rpartition(')')[2].split()
                current, observed_birth, group = fields[0], fields[19], int(fields[2])
                same_identity = observed_birth == birth
            except FileNotFoundError:
                current, observed_birth, group, same_identity = None, None, None, False
            observed_at = time.monotonic()
            observation = [current, same_identity, observed_birth, group]
            if not observations or observations[-1][1:] != observation:
                observations.append([observed_at-started, *observation])
            if same_identity:
                self.assertEqual(group, result['pid'], ('descendant process group changed', observations))
            if observed_at >= deadline or current == 'Z' or not same_identity:
                break
            time.sleep(min(.001, deadline-observed_at))
        print(json.dumps(dict(descendant_pid=int(child), descendant_starttime=birth,
                              process_group=result['pid'],
                              states=observations, observed_elapsed=observed_at-started,
                              total_deadline_seconds=1.5)), flush=True)
        self.assertLess(observed_at, deadline, 'descendant exit observation exceeded the original total deadline')
        if same_identity:
            self.assertEqual(current, 'Z', 'descendant must not still execute')

    def test_simultaneous_stream_bursts_share_one_read_budget(self):
        script = """import os,threading
os.write(1,b'OUT')
os.write(2,b'ERR')
def flood(fd):
 while True: os.write(fd,b'x'*1024)
a=threading.Thread(target=flood,args=(1,));b=threading.Thread(target=flood,args=(2,))
a.start();b.start();a.join();b.join()
"""
        result, files, _ = self.run_child(script, overrides=(('RAW_LIMIT', 65536),))
        self.assertEqual(result['status'], 'diagnostic_output_limit')
        self.assertEqual(sum(result['observed_bytes'].values()), 65536)
        self.assertGreater(result['observed_bytes']['stdout'], 0)
        self.assertGreater(result['observed_bytes']['stderr'], 0)
        self.assertTrue(files[capture.DIAGNOSTIC_FILES[0]].startswith(b'OUT'))
        self.assertTrue(files[capture.DIAGNOSTIC_FILES[1]].startswith(b'ERR'))

    def test_unsafe_preexisting_log_files_block_without_launch_or_overwrite(self):
        for kind in ('symlink', 'hardlink', 'fifo', 'regular'):
            def setup(safe, stack):
                outside = safe.path.parent / 'outside'
                outside.write_bytes(b'keep unchanged')
                target = safe.path / capture.DIAGNOSTIC_FILES[0]
                if kind == 'symlink':
                    target.symlink_to(outside)
                elif kind == 'hardlink':
                    os.link(outside, target)
                elif kind == 'fifo':
                    os.mkfifo(target)
                else:
                    target.write_bytes(b'keep unchanged')
            with self.subTest(kind=kind):
                result, _, launches = self.run_child('raise AssertionError()', setup=setup)
                self.assertEqual(result['status'], 'diagnostic_infrastructure_failed')
                self.assertFalse(result['process_started'])
                self.assertEqual(launches, [])

    def test_append_budget_never_recovers_from_truncation_or_replacement(self):
        self.assertEqual(capture.TOTAL, 1048576)
        self.assertEqual(capture.DISPLAY_LABEL_RESERVE, 1024)
        self.assertEqual(capture.DURABLE_TOTAL, 523776)
        self.assertEqual(capture.RAW_LIMIT + capture.METADATA_LIMIT, capture.DURABLE_TOTAL)
        self.assertEqual(2 * capture.DURABLE_TOTAL + capture.DISPLAY_LABEL_RESERVE, capture.TOTAL)
        self.assertEqual(capture.RAW_LIMIT, 507392)
        self.assertEqual(capture.METADATA_LIMIT, 16384)
        self.assertEqual(capture.INTERNAL_METADATA_LIMIT, 12288)
        self.assertEqual(capture.PROCESS_SECONDS, 60)
        for mutation in ('truncate', 'replace', 'hardlink'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as folder:
                safe = SafeRoot(Path(folder) / 'fresh')
                sink = capture._Sink(safe, safe.path)
                try:
                    sink.record({'kind': 'test', 'payload': 'x' * 100})
                    used = sink.metadata_written
                    path = safe.path / capture.DIAGNOSTIC_FILES[2]
                    if mutation == 'truncate':
                        path.write_bytes(b'')
                    elif mutation == 'replace':
                        path.unlink()
                        path.write_bytes(b'')
                    else:
                        os.link(path, safe.path / 'extra-link')
                    with self.assertRaises(ValueError):
                        sink.record({'kind': 'must not append'})
                    self.assertEqual(sink.metadata_written, used)
                finally:
                    sink.close()
                    safe.close()

    def test_full_production_raw_cap_leaves_room_for_exact_single_display(self):
        result, files, _ = self.run_child('import os\nwhile True: os.write(2,b"x"*16384)')
        self.assertEqual(result['status'], 'diagnostic_output_limit')
        self.assertEqual(sum(result['observed_bytes'].values()), 507392)
        self.assertEqual(result['raw_written_bytes'], 507392)
        durable = sum(len(data) for data in files.values())
        runner_reserve = result['metadata_remaining_bytes']
        self.assertLessEqual(durable + runner_reserve, capture.DURABLE_TOTAL)
        self.assertLessEqual(2 * (durable + runner_reserve) + capture.DISPLAY_LABEL_RESERVE, capture.TOTAL)

    def test_timeout_eio_after_group_kill_before_waitid_exit_remains_timeout(self):
        state = {'killed': False, 'pending_exit': False, 'injected_eio': 0, 'pending_waitid': 0}
        def setup(safe, stack):
            real_read, real_killpg, real_waitid = os.read, os.killpg, os.waitid
            def killpg(pid, sig):
                value = real_killpg(pid, sig)
                state['killed'] = True
                return value
            def read(fd, count):
                if state['killed'] and os.isatty(fd):
                    state['pending_exit'] = True
                    state['injected_eio'] += 1
                    raise OSError(5, 'closed slave before waitid reports exit')
                return real_read(fd, count)
            def waitid(*args):
                if state['pending_exit']:
                    state['pending_exit'] = False
                    state['pending_waitid'] += 1
                    return None
                return real_waitid(*args)
            stack.enter_context(patch.object(capture.os, 'killpg', side_effect=killpg))
            stack.enter_context(patch.object(capture.os, 'read', side_effect=read))
            stack.enter_context(patch.object(capture.os, 'waitid', side_effect=waitid))
        result, files, _ = self.run_child('import os,time;os.write(1,b"partial");time.sleep(10)',
                                          setup=setup, overrides=(('PROCESS_SECONDS', 0.15),))
        self.assertGreater(state['injected_eio'], 0)
        self.assertGreater(state['pending_waitid'], 0)
        self.assertEqual(result['status'], 'diagnostic_timeout', result)
        self.assertTrue(result['leader_reaped'])
        self.assertTrue(result['group_kill_sent'])
        self.assertEqual(files[capture.DIAGNOSTIC_FILES[0]], b'partial')

    def setup_race(self, state, *, reopen=None, late=None, interrupt=False, cleanup_error=False,
                   timeout_after_first_eio=False):
        def setup(safe, stack):
            read, waitid, killpg, openpty, monotonic = os.read, os.waitid, os.killpg, os.openpty, time.monotonic
            state.update(eios=0, confirmations=0, waits=0, killed=False, offset=0)
            model_start = monotonic() if timeout_after_first_eio else None
            def allocate():
                master, slave = openpty()
                state['slave'] = os.ttyname(slave)
                return master, slave
            def receive(fd, count):
                if os.isatty(fd) and state['eios']:
                    state['confirmations'] += 1
                    self.assertFalse(state['killed'], 'confirmation must precede every group kill')
                    if interrupt:
                        raise KeyboardInterrupt('pending EIO interrupted')
                    if late == 'read':
                        state['offset'] = 0.1
                    if late == 'process_read':
                        state['offset'] = 2
                try:
                    return read(fd, count)
                except OSError as error:
                    if error.errno == errno.EIO and os.isatty(fd):
                        state['eios'] += 1
                        if timeout_after_first_eio and state['eios'] == 1:
                            state['first_eio_at'] = monotonic()
                        if late == 'exact' and 'frozen' not in state:
                            state['frozen'] = monotonic()
                    raise
            def observe(*args):
                info = waitid(*args)
                if state['eios'] == 0:
                    return None  # Force the actual PTY-close read before visibility.
                state['waits'] += 1
                if state['waits'] == 1:
                    return None  # Deterministic delayed natural-exit observation.
                if info is not None and not state['killed']:
                    if late == 'exact':
                        state['frozen'] += capture.PENDING_EIO_SECONDS
                    if late in ('observe', 'process_observe'):
                        state['offset'] = 0.1 if late == 'observe' else 2
                    if reopen is not None and 'reopened' not in state:
                        fd = os.open(state['slave'], os.O_RDWR | os.O_NOCTTY)
                        state['reopened'] = fd
                        stack.callback(lambda: os.close(state.pop('open_fd')) if 'open_fd' in state else None)
                        state['open_fd'] = fd
                        if reopen:
                            os.write(fd, reopen)
                return info
            def kill(pid, sig):
                state['killed'] = True
                if 'open_fd' in state:
                    os.close(state.pop('open_fd'))
                if cleanup_error:
                    raise PermissionError('injected cleanup failure')
                return killpg(pid, sig)
            stack.enter_context(patch.object(capture.os, 'openpty', side_effect=allocate))
            stack.enter_context(patch.object(capture.os, 'read', side_effect=receive))
            stack.enter_context(patch.object(capture.os, 'waitid', side_effect=observe))
            stack.enter_context(patch.object(capture.os, 'killpg', side_effect=kill))
            def clock():
                if timeout_after_first_eio:
                    # Establish a real first EIO before crossing the unchanged
                    # process deadline. Cleanup then progresses at wall-clock
                    # speed, so this is not a post-kill EOF control by accident.
                    if 'first_eio_at' not in state:
                        return model_start
                    return model_start + capture.PROCESS_SECONDS + monotonic() - state['first_eio_at']
                return state.get('frozen', monotonic()) + state['offset']
            stack.enter_context(patch.object(capture.time, 'monotonic', side_effect=clock))
        return setup

    def test_real_eio_delayed_natural_exit_resolves_before_group_kill(self):
        state = {}
        result, files, launches = self.run_child('import os;os.write(1,b"out");os.write(2,b"err")',
                                              setup=self.setup_race(state))
        self.assertEqual(result['status'], 'diagnostic_infrastructure_failed', result) # no planned markers
        self.assertTrue(result['drain_complete'])
        self.assertEqual(state['confirmations'], 1)
        self.assertEqual(state['eios'], 2)
        self.assertEqual(len(launches), 1)
        self.assertEqual(files['SevenCertificatePart04.stdout'], b'out')
        self.assertEqual(files['SevenCertificatePart04.stderr'], b'err')

    def test_real_live_child_close_expires_without_refresh_or_spin(self):
        state = {}
        start = time.monotonic()
        result, _, _ = self.run_child('import os,time;os.close(1);os.close(2);time.sleep(10)',
                                     setup=self.setup_race(state))
        self.assertEqual(result['status'], 'diagnostic_infrastructure_failed', result)
        self.assertIn('grace expired', result['error'])
        self.assertFalse(result['drain_complete'])
        self.assertEqual(state['eios'], 1)
        self.assertEqual(state['confirmations'], 0)
        self.assertLess(state['waits'], 200)
        self.assertLess(time.monotonic() - start, 1)
        self.assertEqual(result['signal'], signal.SIGKILL)

    def test_injected_eio_with_persistent_live_slave_never_resolves(self):
        def setup(safe, stack):
            read = os.read
            def receive(fd, count):
                if os.isatty(fd):
                    raise OSError(errno.EIO, 'injected with live slave')
                return read(fd, count)
            stack.enter_context(patch.object(capture.os, 'read', side_effect=receive))
        result, _, _ = self.run_child('import os,time;os.write(1,b"x");time.sleep(10)', setup=setup)
        self.assertEqual(result['status'], 'diagnostic_infrastructure_failed', result)
        self.assertFalse(result['drain_complete'])
        self.assertEqual(result['signal'], signal.SIGKILL)

    def test_real_reopened_slave_data_is_counted_discarded_before_kill(self):
        state = {}
        result, files, _ = self.run_child('pass', setup=self.setup_race(state, reopen=b'reopened'))
        self.assertEqual(result['status'], 'diagnostic_infrastructure_failed', result)
        self.assertIn('confirmation returned data', result['error'])
        self.assertEqual(result['observed_bytes']['stdout'], 8)
        self.assertEqual(result['raw_written_bytes'], 0)
        self.assertEqual(files['SevenCertificatePart04.stdout'], b'')
        self.assertFalse(result['drain_complete'])
        self.assertEqual(state['confirmations'], 1)

    def test_real_reopened_slave_eagain_fails_before_kill(self):
        state = {}
        result, _, _ = self.run_child('pass', setup=self.setup_race(state, reopen=b''))
        self.assertEqual(result['status'], 'diagnostic_infrastructure_failed', result)
        self.assertIn('BlockingIOError', result['error'])
        self.assertFalse(result['drain_complete'])

    def test_grace_deadline_checked_after_exit_observation_and_reread(self):
        for boundary in ('observe', 'read'):
            with self.subTest(boundary=boundary):
                state = {}
                result, _, _ = self.run_child('pass', setup=self.setup_race(state, late=boundary))
                self.assertEqual(result['status'], 'diagnostic_infrastructure_failed', result)
                self.assertIn('grace expired', result['error'])
                self.assertFalse(result['drain_complete'])
                self.assertEqual(state['confirmations'], int(boundary == 'read'))

    def test_process_deadline_checked_after_exit_observation_and_reread(self):
        for boundary in ('process_observe', 'process_read'):
            with self.subTest(boundary=boundary):
                state = {}
                result, _, _ = self.run_child('pass', setup=self.setup_race(state, late=boundary))
                self.assertEqual(result['status'], 'diagnostic_timeout', result)
                self.assertFalse(result['drain_complete'])

    def test_pending_eio_timeout_never_resolves_after_group_kill(self):
        state = {}
        result, _, _ = self.run_child('import os,time;os.close(1);time.sleep(10)',
                                     setup=self.setup_race(state, timeout_after_first_eio=True),
                                     overrides=(('PROCESS_SECONDS', 0.04),))
        self.assertEqual(result['status'], 'diagnostic_timeout', result)
        self.assertFalse(result['drain_complete'])
        self.assertEqual(state['eios'], 1)
        self.assertEqual(state['confirmations'], 0)

    def test_nonzero_natural_exit_remains_failed(self):
        state = {}
        result, _, _ = self.run_child('import sys;sys.exit(7)', setup=self.setup_race(state))
        self.assertEqual(result['status'], 'diagnostic_failed', result)
        self.assertEqual(result['returncode'], 7)
        self.assertTrue(result['drain_complete'])

    def test_interruption_never_resolves_pending_eio(self):
        state = {}
        result, _, _ = self.run_child('pass', setup=self.setup_race(state, interrupt=True))
        self.assertEqual(result['status'], 'diagnostic_failed', result)
        self.assertTrue(result['interrupted'])
        self.assertFalse(result['drain_complete'])

    def test_cleanup_error_never_yields_success(self):
        state = {}
        result, _, _ = self.run_child('pass', setup=self.setup_race(state, cleanup_error=True))
        self.assertEqual(result['status'], 'diagnostic_infrastructure_failed', result)
        self.assertTrue(result['cleanup_incomplete'])
        self.assertIn('group_cleanup_error', result)

    def test_descendant_stderr_owner_killed_only_after_confirmation(self):
        state = {}
        script = 'import os,time\npid=os.fork()\nif pid==0:\n os.close(1);time.sleep(10)\n'
        result, _, _ = self.run_child(script, setup=self.setup_race(state))
        self.assertEqual(result['status'], 'diagnostic_infrastructure_failed', result) # no planned markers
        self.assertTrue(result['group_kill_sent'])
        self.assertTrue(result['leader_reaped'])
        self.assertTrue(result['drain_complete'])
        self.assertEqual(state['confirmations'], 1)

    def test_exact_grace_boundary_is_rejected(self):
        state = {}
        result, _, _ = self.run_child('pass', setup=self.setup_race(state, late='exact'))
        self.assertEqual(result['status'], 'diagnostic_infrastructure_failed', result)
        self.assertIn('grace expired', result['error'])
        self.assertEqual(state['confirmations'], 0)
        self.assertFalse(result['drain_complete'])

    def test_confirmation_read_respects_remaining_combined_raw_quota(self):
        state = {}
        result, files, _ = self.run_child('import os;os.write(2,b"err")',
            setup=self.setup_race(state, reopen=b'x' * 100), overrides=(('RAW_LIMIT', 8),))
        self.assertEqual(result['status'], 'diagnostic_infrastructure_failed', result)
        self.assertEqual(result['observed_bytes'], {'stdout': 5, 'stderr': 3})
        self.assertEqual(result['raw_written_bytes'], 3)
        self.assertEqual(files['SevenCertificatePart04.stdout'], b'')
        self.assertEqual(files['SevenCertificatePart04.stderr'], b'err')

    def test_complete_fragmented_real_child_has_only_thirteen_events(self):
        payload = b'noise\n' + lines() + b'tail without newline\xff'
        script = 'import os\nfor b in %r: os.write(1,bytes([b]))\nos.write(2,b"stderr\\xff")' % payload
        progress = {}
        def setup(safe, stack):
            # This control checks every real one-byte fragment, retained byte,
            # and marker event. Model time does not turn fsync/scheduling cost
            # into an unrelated drain failure. Resume wall time after the known
            # finite payload is durable; real deadline controls are separate.
            append, monotonic = capture._Sink.append, time.monotonic
            origin = monotonic()
            expected = {capture.DIAGNOSTIC_FILES[0]: len(payload),
                        capture.DIAGNOSTIC_FILES[1]: len(b'stderr\xff')}
            progress.update(counts={name: 0 for name in expected}, resumed=None)
            def persist(sink, name, data, terminal=False):
                value = append(sink, name, data, terminal=terminal)
                if name in expected:
                    progress['counts'][name] += len(data)
                    if progress['counts'] == expected and progress['resumed'] is None:
                        progress['resumed'] = monotonic()
                return value
            def clock():
                return origin if progress['resumed'] is None else origin + monotonic() - progress['resumed']
            stack.enter_context(patch.object(capture._Sink, 'append', new=persist))
            stack.enter_context(patch.object(capture, 'time', SimpleNamespace(monotonic=clock)))
        result, files, launches = self.run_child(script, setup=setup, overrides=(('READ_CHUNK', 1),))
        self.assertEqual(result['status'], 'diagnostic_completed', result)
        self.assertIsNotNone(progress['resumed'])
        self.assertEqual(len(launches), 1)
        self.assertEqual(files[capture.DIAGNOSTIC_FILES[0]], payload)
        self.assertEqual(files[capture.DIAGNOSTIC_FILES[1]], b'stderr\xff')
        records = [json.loads(x) for x in files[capture.DIAGNOSTIC_FILES[2]].splitlines()]
        self.assertEqual([r['kind'] for r in records], ['start'] + ['marker']*11 + ['terminal'])
        self.assertEqual(records[0]['process']['trace'], capture.TRACE)
        self.assertEqual(records[-1]['process']['trace'], capture.TRACE)
        self.assertEqual(result['trace'], capture.TRACE)
        self.assertEqual(result['observed_bytes'], {'stdout':len(payload), 'stderr':7})
        self.assertEqual(result['raw_written_bytes'], len(payload)+7)
        self.assertTrue(result['drain_complete'])
        for name in capture.DIAGNOSTIC_FILES[:2]:
            self.assertEqual(result['raw_files'][name]['sha256'], sha256(files[name]).hexdigest())
        for row in records[1:-1]:
            self.assertEqual(row['event']['received_seconds'], row['received_seconds'])
        self.assertLessEqual(len(capture._record_bytes(records[0])), 2368)
        self.assertLessEqual(len(capture._record_bytes(records[-1])), 3584)

    def test_clean_prefix_nonzero_and_timeout(self):
        prefix = lines().splitlines(keepends=True)[0]
        for end, status in [('raise SystemExit(7)', 'diagnostic_failed'), ('import time;time.sleep(10)', 'diagnostic_timeout')]:
            result, files, _ = self.run_child('import os;os.write(1,%r);%s' % (prefix,end), overrides=(('PROCESS_SECONDS', .15),))
            self.assertEqual(result['status'], status, result)
            self.assertEqual(result['marker_count'], 1)
            self.assertEqual(files[capture.DIAGNOSTIC_FILES[0]], prefix)

    def test_partial_marker_eof_rejects(self):
        result, files, _ = self.run_child('import os;os.write(1,%r)' % lines().splitlines()[0])
        self.assertEqual(result['status'], 'diagnostic_infrastructure_failed')
        self.assertIn('partial diagnostic marker', result['error'])
        self.assertFalse(result['drain_complete'])

    def test_exact_raw_cap_and_overflow_both_refuse_success(self):
        for count in (4096,4097):
            result, files, _ = self.run_child('import os;os.write(1,b"x"*%d)' % count, overrides=(('RAW_LIMIT',4096),))
            self.assertEqual(result['status'], 'diagnostic_output_limit')
            self.assertEqual(result['raw_written_bytes'],4096)
            self.assertEqual(result['observed_bytes']['stdout'],4096)

    def test_metadata_subcap_failure_retains_terminal_reserve(self):
        result, files, _ = self.run_child('import os;os.write(1,%r)' % lines(), overrides=(('MARKER_LIMIT', 1),))
        self.assertEqual(result['status'], 'diagnostic_output_limit')
        self.assertTrue(result['terminal_record_persisted'])
        self.assertTrue(result['leader_reaped'])
        self.assertIn('metadata budget',result['error'])

    def test_large_unsafe_error_is_bounded_and_serializable(self):
        def setup(safe, stack):
            stack.enter_context(patch.object(capture.os, 'openpty', side_effect=OSError('\n"\\é'*10000)))
        result, files, launches = self.run_child('pass', setup=setup)
        self.assertEqual(launches, [])
        self.assertLessEqual(len(result['error'].encode()),128)
        self.assertNotIn('\\',result['error'])
        self.assertNotIn('"',result['error'])
        self.assertTrue(result['terminal_record_persisted'])

    def test_unsupported_platform_not_embedded_in_terminal(self):
        result, _, launches = self.run_child('pass',platform_value={'evil': 'x'*10000})
        self.assertEqual(launches, [])
        self.assertIsNone(result['platform'])
        self.assertTrue(result['terminal_record_persisted'])


    def test_invalid_final_clock_closes_files_and_refuses_terminal(self):
        def setup(safe, stack):
            stack.enter_context(patch.object(capture, 'validate_elapsed', side_effect=capture.CaptureFailure('invalid clock')))
        result, files, launches = self.run_child('pass', setup=setup)
        self.assertEqual(len(launches), 1)
        self.assertEqual(result['status'], 'diagnostic_infrastructure_failed')
        self.assertFalse(result['terminal_record_persisted'])
        self.assertIn('invalid process clock', result['error'])



class Part04GrammarTests(unittest.TestCase):
    def test_all_fragment_sizes_and_same_read(self):
        raw = b'ordinary\n'+lines()+b'ordinary tail'
        for size in range(1,len(raw)+1):
            observer = capture.MarkerObserver(planned())
            events = []
            for start in range(0,len(raw),size):
                events += observer('stdout',raw[start:start+size],start,.5)
            observer.finish('stdout')
            self.assertEqual(len(events),11)
            self.assertEqual([e['byte_offset'] for e in events], [9+i*len(lines().splitlines(keepends=True)[0]) for i in range(11)])
            self.assertEqual([e['original_offset'] for e in events], [i*100 for i in range(11)])

    def test_foreign_duplicate_reordered_excess_malformed(self):
        first = lines().splitlines(keepends=True)[0]
        for raw in (first+first, lines()+first, lines().splitlines(keepends=True)[1],
                    first.replace(b'P04',b'P02'), b'"HIA_DIAG_v1_LIN_000" : String\n',
                    b'"HIA_DIAG_v1_P02_000" : String\n', first.replace(b' : String',b' : Nat'),
                    first.replace(b'\n',b'\r\n'), b'prefix '+first, b'x'*1024+first):
            with self.subTest(raw=raw[:80]), self.assertRaises(capture.CaptureFailure):
                capture.MarkerObserver(planned())('stdout',raw,0,.1)
        with self.assertRaises(capture.CaptureFailure):
            capture.MarkerObserver(planned())('stderr',first,0,.1)

    def test_partial_foreign_and_long_markerlike_at_eof(self):
        for raw in (b'"HIA_DIAG',b'"HIA_SEVEN_DIAG',b'x'*1024+b'HIA_DIAG'):
            observer = capture.MarkerObserver(planned())
            observer('stdout',raw,0,.1)
            with self.assertRaises(capture.CaptureFailure): observer.finish('stdout')

    def test_exact_planned_count_and_target(self):
        for markers in ([], planned()[:10],planned()+planned()[:1]):
            with self.assertRaises(capture.CaptureFailure):capture.MarkerObserver(markers)
        for target in ('LinearTransport','CertPart02','SevenCertificatePart02',None):
            with self.assertRaises(capture.CaptureFailure):capture.target_configuration(target)

    def test_finite_path_settings_clock_signed_and_error_schema(self):
        for path in ('relative','/x y','/x"','/x\\y','/é','/x/../y','/'+'x'*128):
            with self.assertRaises(capture.CaptureFailure):capture.validate_path(path)
        capture.validate_path('/'+'x'*127)
        attrs=[2**32-1]*6+[[255]*32]
        self.assertEqual(capture.validate_settings(attrs),attrs)
        for bad in (attrs[:6],attrs+[[1]],[-1]+attrs[1:], [2**32]+attrs[1:],attrs[:6]+[[256]*32], attrs[:6]+[[1]*31]):
            with self.assertRaises(capture.CaptureFailure):capture.validate_settings(bad)
        for bad in (float('nan'),float('inf'),-1,600.000001,True):
            with self.assertRaises(capture.CaptureFailure):capture.validate_elapsed(bad)
        self.assertEqual(capture.validate_elapsed(.12345678),.123457)
        for bad in (-2**63-1,2**63,True,1.0):
            with self.assertRaises(capture.CaptureFailure):capture.validate_signed(bad)
        self.assertEqual(capture.validate_signed(-2**63),-2**63)
        self.assertEqual(capture.safe_error('"\\\né'), '????')
        self.assertEqual(len(capture.safe_error('x'*1000,32)),32)

    def test_unsafe_or_substituted_paths_fail_before_launch(self):
        with patch.object(capture.subprocess,'Popen') as popen:
            for root,exe,source,output in [('/safe','/bin/lean','/other.lean','/safe/HiaSyntaxResearch/CertPart04.olean'),
                                           ('/unsafe space','/bin/lean','x','y'),
                                           ('/safe','/bin/é','x','y')]:
                with self.assertRaises(capture.CaptureFailure):
                    capture.capture_result(exe,source,output,root,safe_root=None,markers=planned())
            popen.assert_not_called()

    def test_sink_enforces_tighter_serialized_caps(self):
        with tempfile.TemporaryDirectory() as folder:
            safe=SafeRoot(Path(folder)/'fresh'); sink=capture._Sink(safe,safe.path)
            try:
                for kind,limit,terminal in [('start',2368,False),('marker',224,False),('terminal',3584,True)]:
                    with self.assertRaises(capture.CaptureFailure):sink.record({'kind':kind,'payload':'x'*limit},terminal=terminal)
                sink.append(capture.DIAGNOSTIC_FILES[2],b'x'*8192)
                with self.assertRaises(capture.CaptureFailure):sink.append(capture.DIAGNOSTIC_FILES[2],b'x'*225,terminal=True)
            finally:sink.close();safe.close()

    def test_observation_clock_reversal_rejected(self):
        observer=capture.MarkerObserver(planned())
        observer('stdout',b'ordinary',0,.5)
        with self.assertRaises(capture.CaptureFailure):observer('stdout',b' tail',8,.4)

    def test_constant_caps_keep_original_and_new_envelopes(self):
        self.assertEqual(capture.RAW_LIMIT,507392)
        self.assertEqual(capture.PROCESS_SECONDS,60)
        self.assertEqual(capture.CLEANUP_SECONDS,2)
        self.assertEqual(capture.PENDING_EIO_SECONDS,.05)
        self.assertEqual(capture.MAX_MARKERS,11)
        self.assertLessEqual(capture.START_LIMIT+11*capture.MARKER_LIMIT,8192)
        self.assertEqual(capture.START_LIMIT+11*capture.MARKER_LIMIT+capture.TERMINAL_LIMIT,8416)
        self.assertEqual(capture.EVENT_STREAM_LIMIT+7968,16384)
