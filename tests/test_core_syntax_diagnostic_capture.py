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
import unittest
from unittest.mock import patch

from tools import core_syntax_diagnostic_capture as capture
from tools.check_core_syntax_staged import SafeRoot

PLATFORM = {'sys_platform': 'linux', 'machine': 'x86_64',
            'os_release': {'ID': 'ubuntu', 'VERSION_ID': '24.04'}, 'libc': 'glibc 2.39'}


class DiagnosticCaptureTests(unittest.TestCase):
    def run_child(self, script, *, observer=None, markers=(), overrides=(), setup=None, platform_value=PLATFORM, target="LinearTransport"):
        real_popen = subprocess.Popen
        with tempfile.TemporaryDirectory() as folder, ExitStack() as stack:
            safe = SafeRoot(Path(folder) / 'fresh')
            stack.callback(safe.close)
            safe.write('Input.lean', b'-- inert fake source')
            executable = Path(folder) / 'pinned/bin/lean'
            executable.parent.mkdir(parents=True)
            executable.write_bytes(b'never executed')
            launches = []
            processes = []
            snapshot = set(os.listdir('/proc/self/fd'))

            def launch(argv, **kwargs):
                launches.append((argv, kwargs))
                self.assertEqual(argv, [str(executable), '--root=' + str(safe.path), '-o',
                                        str(safe.path / 'Output.olean'), str(safe.path / 'Input.lean')])
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
            result = capture.capture_result(executable, safe.path / 'Input.lean', safe.path / 'Output.olean',
                                             safe.path, safe_root=safe, markers=markers, observer=observer, target=target)
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
            return result, files, launches

    def test_dual_stream_raw_bytes_no_newlines_or_controlling_terminal(self):
        script = """import os
assert os.isatty(1)
assert not os.isatty(2)
try:
 os.open('/dev/tty', os.O_RDWR)
except OSError:
 pass
else:
 raise AssertionError('unexpected controlling terminal')
os.write(1,b'out\\nraw\\r\\n\\xff')
os.write(2,b'err-without-newline\\xfe')
"""
        result, files, launches = self.run_child(script)
        self.assertEqual(result['status'], 'diagnostic_completed', result)
        self.assertEqual(files[capture.DIAGNOSTIC_FILES[0]], b'out\nraw\r\n\xff')
        self.assertEqual(files[capture.DIAGNOSTIC_FILES[1]], b'err-without-newline\xfe')
        self.assertEqual(result['pty']['after'][1], 0)
        self.assertEqual(len(launches), 1)
        self.assertTrue(result['leader_reaped'])
        self.assertTrue(result['drain_complete'])
        self.assertNotIn('stdout', result)
        self.assertNotIn('stderr', result)

    def test_platform_mismatch_missing_duplicate_identity_never_launches(self):
        variants = [dict(PLATFORM, sys_platform='darwin'), dict(PLATFORM, machine='aarch64'),
                    dict(PLATFORM, libc='glibc 2.40'), dict(PLATFORM, libc=None),
                    dict(PLATFORM, os_release={'ID': 'ubuntu', 'VERSION_ID': '24.10'}),
                    dict(PLATFORM, os_release={'ID': 'ubuntu'}),
                    dict(PLATFORM, os_release={'ID': 'debian', 'VERSION_ID': '24.04'})]
        for observed in variants:
            with self.subTest(platform=observed):
                result, _, launches = self.run_child('raise AssertionError()', platform_value=observed)
                self.assertEqual(result['status'], 'diagnostic_infrastructure_failed')
                self.assertFalse(result['process_started'])
                self.assertEqual(launches, [])
                self.assertEqual(result['platform'], observed)

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

    def test_observer_exception_terminates_group_without_retry(self):
        def observer(*args):
            raise ValueError('fake observer failure')
        result, files, launches = self.run_child('import os,time;os.write(1,b"x");time.sleep(10)', observer=observer)
        self.assertEqual(result['status'], 'diagnostic_infrastructure_failed')
        self.assertTrue(result['group_kill_sent'])
        self.assertEqual(len(launches), 1)
        self.assertEqual(files[capture.DIAGNOSTIC_FILES[0]], b'x')

    def test_held_descendant_descriptors_are_killed_after_leader_exits(self):
        script = """import os,time
pid=os.fork()
if pid==0:
 time.sleep(10)
else:
 os.write(1,str(pid).encode()+b'\\n')
"""
        started = time.monotonic()
        result, files, _ = self.run_child(script)
        self.assertLess(time.monotonic() - started, 1.5)
        self.assertTrue(result['group_kill_sent'])
        self.assertTrue(result['leader_reaped'])
        child = int(files[capture.DIAGNOSTIC_FILES[0]].strip())
        state = Path('/proc') / str(child) / 'stat'
        if state.exists():
            self.assertEqual(state.read_text().split()[2], 'Z', 'descendant must not still execute')

    def test_real_closed_slave_eio_is_eof_but_live_child_eio_is_failure(self):
        result, _, _ = self.run_child('pass')
        self.assertEqual(result['status'], 'diagnostic_completed')
        def setup(safe, stack):
            real_read = os.read
            def fail(fd, count):
                if os.isatty(fd):
                    raise OSError(5, 'injected unexpected EIO')
                return real_read(fd, count)
            stack.enter_context(patch.object(capture.os, 'read', side_effect=fail))
        result, _, _ = self.run_child('import os,time;os.write(1,b"x");time.sleep(10)', setup=setup)
        self.assertEqual(result['status'], 'diagnostic_infrastructure_failed')
        self.assertTrue(result['leader_reaped'])

    def test_metadata_exhaustion_preserves_terminal_reserve_and_stops_child(self):
        def observer(*args):
            return [{'payload': 'x' * 5000}]
        result, files, _ = self.run_child('import os,time;os.write(1,b"x");time.sleep(10)',
                                          observer=observer, overrides=(('INTERNAL_METADATA_LIMIT', 8192),))
        self.assertEqual(result['status'], 'diagnostic_infrastructure_failed')
        self.assertIn('metadata budget', result['error'])
        self.assertTrue(result['leader_reaped'])
        self.assertTrue(result['group_kill_sent'])
        self.assertTrue(result['terminal_record_persisted'])
        self.assertEqual(result['marker_count'], 0)
        self.assertNotIn(b'x' * 5000, files[capture.DIAGNOSTIC_FILES[2]])

    def test_cancellation_observation_is_nonaccepting_and_closes_every_descriptor(self):
        def cancel(*args):
            raise KeyboardInterrupt('fake cancellation')
        result, _, _ = self.run_child('import os,time;os.write(1,b"x");time.sleep(10)', observer=cancel)
        self.assertEqual(result['status'], 'diagnostic_failed')
        self.assertTrue(result['interrupted'])
        self.assertTrue(result['leader_reaped'])
        self.assertTrue(result['group_kill_sent'])

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

    def test_complete_marker_checkpoints_are_durable_and_raw_not_copied(self):
        markers = [{'id': 'HIA_DIAG_v1_LIN_000', 'original_offset': 50, 'instrumented_offset': 50}]
        line = b'"HIA_DIAG_v1_LIN_000" : String\n'
        script = 'import os,time;os.write(1,%r);time.sleep(10)' % line
        result, files, _ = self.run_child(script, markers=markers, overrides=(('PROCESS_SECONDS', 0.15),))
        records = [json.loads(line) for line in files[capture.DIAGNOSTIC_FILES[2]].splitlines()]
        events = [row for row in records if row['kind'] == 'marker']
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]['event']['original_offset'], 50)
        self.assertEqual(result['last_observed_marker']['id'], markers[0]['id'])
        self.assertEqual(result['status'], 'diagnostic_timeout')
        self.assertNotIn('stdout', records[-1]['process'])
        self.assertNotIn('stderr', records[-1]['process'])

    def test_terminal_receipt_records_actual_prefix_accounting_not_stale_zero_totals(self):
        result, files, _ = self.run_child('import os;os.write(1,b"stdout bytes");os.write(2,b"stderr bytes")')
        self.assertEqual(result['status'], 'diagnostic_completed')
        lines = files[capture.DIAGNOSTIC_FILES[2]].splitlines(keepends=True)
        terminal = json.loads(lines[-1])
        before = terminal['accounting_before_terminal']
        self.assertEqual(before['metadata_written_bytes'], sum(len(line) for line in lines[:-1]))
        self.assertEqual(before['raw_written_bytes'], sum(len(files[name]) for name in capture.DIAGNOSTIC_FILES[:2]))
        self.assertGreater(before['metadata_written_bytes'], 0)
        self.assertGreater(before['raw_written_bytes'], 0)
        self.assertEqual(result['metadata_written_bytes'], before['metadata_written_bytes'] + len(lines[-1]))
        self.assertEqual(result['raw_written_bytes'], before['raw_written_bytes'])
        for key in ('metadata_written_bytes', 'metadata_remaining_bytes', 'raw_written_bytes',
                    'compact_receipt_reference'):
            self.assertNotIn(key, terminal['process'])

    def test_full_production_raw_cap_leaves_room_for_exact_single_display(self):
        result, files, _ = self.run_child('import os\nwhile True: os.write(2,b"x"*16384)')
        self.assertEqual(result['status'], 'diagnostic_output_limit')
        self.assertEqual(sum(result['observed_bytes'].values()), 507392)
        self.assertEqual(result['raw_written_bytes'], 507392)
        durable = sum(len(data) for data in files.values())
        runner_reserve = result['metadata_remaining_bytes']
        self.assertLessEqual(durable + runner_reserve, capture.DURABLE_TOTAL)
        self.assertLessEqual(2 * (durable + runner_reserve) + capture.DISPLAY_LABEL_RESERVE, capture.TOTAL)

    def test_maximum_raw_and_metadata_writes_enforce_reserved_terminal_and_runner_space(self):
        with tempfile.TemporaryDirectory() as folder:
            safe = SafeRoot(Path(folder) / 'fresh')
            sink = capture._Sink(safe, safe.path)
            try:
                sink.append(capture.DIAGNOSTIC_FILES[0], b'x' * capture.RAW_LIMIT)
                with self.assertRaises(ValueError):
                    sink.append(capture.DIAGNOSTIC_FILES[1], b'x')
                live_cap = capture.INTERNAL_METADATA_LIMIT - capture.TERMINAL_RESERVE
                sink.append(capture.DIAGNOSTIC_FILES[2], b'm' * live_cap)
                with self.assertRaises(ValueError):
                    sink.append(capture.DIAGNOSTIC_FILES[2], b'm')
                sink.append(capture.DIAGNOSTIC_FILES[2], b't' * capture.TERMINAL_RESERVE, terminal=True)
                with self.assertRaises(ValueError):
                    sink.append(capture.DIAGNOSTIC_FILES[2], b't', terminal=True)
                self.assertEqual(sink.raw_written, capture.RAW_LIMIT)
                self.assertEqual(sink.metadata_written, capture.INTERNAL_METADATA_LIMIT)
                runner_reserve = capture.METADATA_LIMIT - sink.metadata_written
                self.assertEqual(runner_reserve, 4096)
                full_durable = sink.raw_written + sink.metadata_written + runner_reserve
                self.assertEqual(full_durable, capture.DURABLE_TOTAL)
                self.assertEqual(2 * full_durable + capture.DISPLAY_LABEL_RESERVE, capture.TOTAL)
            finally:
                sink.close()
                safe.close()

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


class DiagnosticMarkerTests(unittest.TestCase):
    def markers(self, count=2):
        return [{'id': 'HIA_DIAG_v1_LIN_%03d' % i, 'original_offset': i * 100,
                 'instrumented_offset': i * 130} for i in range(count)]

    def test_split_exact_records_stream_offsets_and_partial_final_marker(self):
        observer = capture.MarkerObserver(self.markers())
        first = b'"HIA_DIAG_v1_LIN_000" : String\n'
        second = b'"HIA_DIAG_v1_LIN_001" : String'
        self.assertEqual(observer('stderr', first, 0, 0.1), [])
        self.assertEqual(observer('stdout', first[:10], 0, 0.2), [])
        events = observer('stdout', first[10:] + second, 10, 0.3)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]['byte_offset'], 0)
        self.assertEqual(events[0]['original_offset'], 0)
        self.assertEqual(events[0]['received_seconds'], 0.3)
        events = observer('stdout', b'\n', len(first + second), 0.4)
        self.assertEqual(events[0]['byte_offset'], len(first))

    def test_longline_crlf_utf8_and_spoofed_text_do_not_observe_markers(self):
        observer = capture.MarkerObserver(self.markers(1))
        first = b'"HIA_DIAG_v1_LIN_000" : String'
        data = b'\xff\xe2' + b'x' * 1024 + first + b'\n' + first + b'\r\n' + b'prefix ' + first + b'\n'
        self.assertEqual(observer('stdout', data, 0, 0.1), [])
        self.assertLessEqual(len(observer.pending), 256)
        events = observer('stdout', first + b'\n', len(data), 0.2)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]['byte_offset'], len(data))

    def test_unknown_duplicate_reordered_and_over24_markers_are_rejected(self):
        for ident in ('001', '999'):
            observer = capture.MarkerObserver(self.markers())
            with self.assertRaises(ValueError):
                observer('stdout', ('"HIA_DIAG_v1_LIN_' + ident + '" : String\n').encode(), 0, 0.1)
        observer = capture.MarkerObserver(self.markers())
        line = b'"HIA_DIAG_v1_LIN_000" : String\n'
        observer('stdout', line, 0, 0.1)
        with self.assertRaises(ValueError):
            observer('stdout', line, len(line), 0.2)
        with self.assertRaises(ValueError):
            capture.MarkerObserver(self.markers(25))
