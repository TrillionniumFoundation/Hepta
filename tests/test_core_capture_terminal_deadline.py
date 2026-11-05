"""Real PTY children with controlled syscall observation delays; no Lean run."""
import errno
import os
import time
import unittest
from unittest.mock import patch

from tools import core_syntax_diagnostic_capture as capture
from tests import test_core_syntax_diagnostic_capture as diagnostic_tests
from tests import test_core_seven_certificate_diagnostic as seven_tests
from tests import test_core_seven_certificate_pending_eio as pending_tests


TARGETS = ('LinearTransport', 'CertPart02', 'SevenCertificatePart02')


class CaptureTerminalDeadlineTests(unittest.TestCase):
    def run_target(self, target, script, setup):
        if target == 'SevenCertificatePart02':
            return seven_tests.SevenCaptureTests().capture(script, setup=setup)
        return diagnostic_tests.DiagnosticCaptureTests().run_child(script, target=target, setup=setup)

    def test_first_eio_exit_observation_after_deadline_never_succeeds(self):
        for target in TARGETS:
            state = {'eio': False, 'delayed': False, 'offset': 0}

            def setup(safe, stack):
                read, waitid, monotonic = os.read, os.waitid, time.monotonic

                def receive(fd, count):
                    try:
                        return read(fd, count)
                    except OSError as error:
                        if error.errno == errno.EIO and os.isatty(fd):
                            state['eio'] = True
                        raise

                def observe(kind, pid, options):
                    if not state['eio']:
                        return None
                    if not state['delayed']:
                        # The actual child exits naturally. Only its observation
                        # clock is delayed; its identity remains unreaped.
                        result = waitid(kind, pid, os.WEXITED | os.WNOWAIT)
                        state.update(delayed=True, offset=2)
                        return result
                    return waitid(kind, pid, options)

                stack.enter_context(patch.object(capture.os, 'read', side_effect=receive))
                stack.enter_context(patch.object(capture.os, 'waitid', side_effect=observe))
                stack.enter_context(patch.object(capture.time, 'monotonic',
                    side_effect=lambda: monotonic() + state['offset']))

            with self.subTest(target=target):
                result, _, _ = self.run_target(target, 'pass', setup)
                self.assertTrue(state['delayed'])
                self.assertEqual(result['status'], 'diagnostic_timeout', result)
                self.assertTrue(result['leader_reaped'])
                self.assertFalse(result['drain_complete'])

    def test_eof_read_returning_after_deadline_never_succeeds(self):
        for target in TARGETS:
            for stream in ('stdout', 'stderr'):
                state = {'delayed': False, 'offset': 0}

                def setup(safe, stack):
                    read, waitid, monotonic = os.read, os.waitid, time.monotonic
                    popen = capture.subprocess.Popen

                    def launch(*args, **kwargs):
                        child = popen(*args, **kwargs)
                        state['stderr_fd'] = child.stderr.fileno()
                        return child

                    def receive(fd, count):
                        # Popen also reads its private exec-error pipe. Only the
                        # child's observed stderr belongs to this fault case.
                        actual_stream = ('stdout' if os.isatty(fd) else
                                         'stderr' if fd == state.get('stderr_fd') else None)
                        try:
                            data = read(fd, count)
                        except OSError as error:
                            if (actual_stream == stream and error.errno == errno.EIO
                                    and not state['delayed']):
                                state.update(delayed=True, offset=2)
                            raise
                        if actual_stream == stream and not data and not state['delayed']:
                            state.update(delayed=True, offset=2)
                        return data

                    def observe(*args):
                        return waitid(*args) if state['delayed'] else None

                    stack.enter_context(patch.object(capture.os, 'read', side_effect=receive))
                    stack.enter_context(patch.object(capture.os, 'waitid', side_effect=observe))
                    stack.enter_context(patch.object(capture.subprocess, 'Popen', side_effect=launch))
                    stack.enter_context(patch.object(capture.time, 'monotonic',
                        side_effect=lambda: monotonic() + state['offset']))

                with self.subTest(target=target, stream=stream):
                    result, _, _ = self.run_target(target, 'pass', setup)
                    self.assertTrue(state['delayed'])
                    self.assertEqual(result['status'], 'diagnostic_timeout', result)
                    self.assertTrue(result['leader_reaped'])
                    self.assertFalse(result['drain_complete'])

    def test_late_nonempty_read_counts_bytes_without_persisting_or_accepting(self):
        for target in TARGETS:
            state = {'delayed': False, 'offset': 0}

            def setup(safe, stack):
                read, monotonic = os.read, time.monotonic

                def receive(fd, count):
                    data = read(fd, count)
                    if os.isatty(fd) and data and not state['delayed']:
                        state.update(delayed=True, offset=2)
                    return data

                stack.enter_context(patch.object(capture.os, 'read', side_effect=receive))
                stack.enter_context(patch.object(capture.time, 'monotonic',
                    side_effect=lambda: monotonic() + state['offset']))

            with self.subTest(target=target):
                result, files, _ = self.run_target(target,
                    'import os,time;os.write(1,b"late");time.sleep(10)', setup)
                self.assertTrue(state['delayed'])
                self.assertEqual(result['status'], 'diagnostic_timeout', result)
                self.assertEqual(result['observed_bytes']['stdout'], 4)
                names, _ = capture.target_configuration(target)
                self.assertEqual(files[names[0]], b'')
                self.assertTrue(result['leader_reaped'])

    def test_delayed_natural_exit_confirmation_is_available_in_every_target(self):
        for target in TARGETS:
            state = {}
            with self.subTest(target=target):
                result, _, _ = self.run_target(target, 'pass',
                    pending_tests.SevenPendingEIOTests().setup_race(state))
                self.assertEqual(result['status'], 'diagnostic_completed', result)
                self.assertTrue(result['drain_complete'])
                self.assertTrue(result['leader_reaped'])
                self.assertEqual(state['confirmations'], 1)

    def test_cleanup_wait_returning_after_deadline_never_succeeds(self):
        for target in TARGETS:
            state = {'offset': 0, 'delayed': False}

            def setup(safe, stack):
                popen, monotonic = capture.subprocess.Popen, time.monotonic

                def launch(*args, **kwargs):
                    child = popen(*args, **kwargs)
                    wait = child.wait

                    def observe(*args, **kwargs):
                        result = wait(*args, **kwargs)
                        state.update(offset=3, delayed=True)
                        return result

                    child.wait = observe
                    return child

                stack.enter_context(patch.object(capture.subprocess, 'Popen', side_effect=launch))
                stack.enter_context(patch.object(capture.time, 'monotonic',
                    side_effect=lambda: monotonic() + state['offset']))

            with self.subTest(target=target):
                result, _, _ = self.run_target(target, 'pass', setup)
                self.assertTrue(state['delayed'])
                self.assertEqual(result['status'], 'diagnostic_infrastructure_failed', result)
                self.assertTrue(result['leader_reaped'])
                self.assertTrue(result['cleanup_deadline_exceeded'])
                self.assertTrue(result['cleanup_incomplete'])
                self.assertIn('reap observation', result['error'])

    def cleanup_read_setup(self, state, stream, nonempty):
        def setup(safe, stack):
            read, waitid, killpg, monotonic = os.read, os.waitid, os.killpg, time.monotonic
            popen = capture.subprocess.Popen

            def launch(*args, **kwargs):
                child = popen(*args, **kwargs)
                state['stderr_fd'] = child.stderr.fileno()
                wait = child.wait

                def reap(*args, **kwargs):
                    state['reap_timeout'] = kwargs['timeout']
                    return wait(*args, **kwargs)

                child.wait = reap
                return child

            def signal_group(*args):
                result = killpg(*args)
                state['cleanup'] = True
                return result

            def receive(fd, count):
                actual = ('stdout' if os.isatty(fd) else
                          'stderr' if fd == state.get('stderr_fd') else None)
                try:
                    data = read(fd, count)
                except OSError as error:
                    if (state.get('cleanup') and actual == stream and not nonempty
                            and error.errno == errno.EIO and not state['delayed']):
                        state.update(offset=3, delayed=True)
                    raise
                if (state.get('cleanup') and actual == stream and bool(data) == nonempty
                        and not state['delayed']):
                    state.update(offset=3, delayed=True)
                return data

            # The actual child exits before the first stream read. Its PID stays
            # unreaped; the real collector then starts its one cleanup deadline.
            stack.enter_context(patch.object(capture.os, 'waitid',
                side_effect=lambda kind, pid, flags: waitid(kind, pid, os.WEXITED | os.WNOWAIT)))
            stack.enter_context(patch.object(capture.os, 'killpg', side_effect=signal_group))
            stack.enter_context(patch.object(capture.os, 'read', side_effect=receive))
            stack.enter_context(patch.object(capture.subprocess, 'Popen', side_effect=launch))
            stack.enter_context(patch.object(capture.time, 'monotonic',
                side_effect=lambda: monotonic() + state['offset']))
        return setup

    def test_cleanup_eof_after_deadline_is_rejected_without_renewal(self):
        for target in TARGETS:
            for stream in ('stdout', 'stderr'):
                state = {'offset': 0, 'delayed': False}
                with self.subTest(target=target, stream=stream):
                    result, _, _ = self.run_target(target, 'pass',
                        self.cleanup_read_setup(state, stream, False))
                    self.assertTrue(state['delayed'])
                    self.assertEqual(result['status'], 'diagnostic_infrastructure_failed', result)
                    self.assertTrue(result['leader_reaped'])
                    self.assertTrue(result['cleanup_deadline_exceeded'])
                    self.assertFalse(result['drain_complete'])
                    self.assertEqual(state['reap_timeout'], 0)

    def test_cleanup_late_data_consumes_quota_without_persistence_or_renewal(self):
        for target in TARGETS:
            state = {'offset': 0, 'delayed': False}
            with self.subTest(target=target):
                result, files, _ = self.run_target(target, 'import os;os.write(1,b"late")',
                    self.cleanup_read_setup(state, 'stdout', True))
                self.assertTrue(state['delayed'])
                self.assertEqual(result['status'], 'diagnostic_infrastructure_failed', result)
                self.assertEqual(result['observed_bytes']['stdout'], 4)
                names, _ = capture.target_configuration(target)
                self.assertEqual(files[names[0]], b'')
                self.assertTrue(result['leader_reaped'])
                self.assertTrue(result['cleanup_deadline_exceeded'])
                self.assertFalse(result['drain_complete'])
                self.assertEqual(state['reap_timeout'], 0)

    def test_live_closed_streams_are_not_successful_eof_in_any_target(self):
        for target in TARGETS:
            state = {}
            with self.subTest(target=target):
                result, _, _ = self.run_target(target,
                    'import os,time;os.close(1);os.close(2);time.sleep(10)',
                    pending_tests.SevenPendingEIOTests().setup_race(state))
                self.assertEqual(result['status'], 'diagnostic_infrastructure_failed', result)
                self.assertIn('grace expired', result['error'])
                self.assertFalse(result['drain_complete'])
                self.assertTrue(result['leader_reaped'])
                self.assertEqual(state['confirmations'], 0)


if __name__ == '__main__':
    unittest.main()
