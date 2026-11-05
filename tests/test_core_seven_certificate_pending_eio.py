"""Real PTY shutdown regressions; Python children only, never extra Lean runs."""
import errno
import os
import signal
import time
import unittest
from unittest.mock import patch

from tools import core_syntax_diagnostic_capture as capture
from tests import test_core_seven_certificate_diagnostic as seven_tests


class SevenPendingEIOTests(unittest.TestCase):
    capture = seven_tests.SevenCaptureTests.capture

    def setup_race(self, state, *, reopen=None, late=None, interrupt=False, cleanup_error=False):
        def setup(safe, stack):
            read, waitid, killpg, openpty, monotonic = os.read, os.waitid, os.killpg, os.openpty, time.monotonic
            state.update(eios=0, confirmations=0, waits=0, killed=False, offset=0)
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
            stack.enter_context(patch.object(capture.time, 'monotonic', side_effect=lambda: state.get('frozen', monotonic()) + state['offset']))
        return setup

    def test_real_eio_delayed_natural_exit_resolves_before_group_kill(self):
        state = {}
        result, files, launches = self.capture('import os;os.write(1,b"out");os.write(2,b"err")',
                                              setup=self.setup_race(state))
        self.assertEqual(result['status'], 'diagnostic_completed', result)
        self.assertTrue(result['drain_complete'])
        self.assertEqual(state['confirmations'], 1)
        self.assertEqual(state['eios'], 2)
        self.assertEqual(len(launches), 1)
        self.assertEqual(files['SevenCertificatePart02.stdout'], b'out')
        self.assertEqual(files['SevenCertificatePart02.stderr'], b'err')

    def test_real_live_child_close_expires_without_refresh_or_spin(self):
        state = {}
        start = time.monotonic()
        result, _, _ = self.capture('import os,time;os.close(1);os.close(2);time.sleep(10)',
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
        result, _, _ = self.capture('import os,time;os.write(1,b"x");time.sleep(10)', setup=setup)
        self.assertEqual(result['status'], 'diagnostic_infrastructure_failed', result)
        self.assertFalse(result['drain_complete'])
        self.assertEqual(result['signal'], signal.SIGKILL)

    def test_real_reopened_slave_data_is_counted_discarded_before_kill(self):
        state = {}
        result, files, _ = self.capture('pass', setup=self.setup_race(state, reopen=b'reopened'))
        self.assertEqual(result['status'], 'diagnostic_infrastructure_failed', result)
        self.assertIn('confirmation returned data', result['error'])
        self.assertEqual(result['observed_bytes']['stdout'], 8)
        self.assertEqual(result['raw_written_bytes'], 0)
        self.assertEqual(files['SevenCertificatePart02.stdout'], b'')
        self.assertFalse(result['drain_complete'])
        self.assertEqual(state['confirmations'], 1)

    def test_real_reopened_slave_eagain_fails_before_kill(self):
        state = {}
        result, _, _ = self.capture('pass', setup=self.setup_race(state, reopen=b''))
        self.assertEqual(result['status'], 'diagnostic_infrastructure_failed', result)
        self.assertIn('BlockingIOError', result['error'])
        self.assertFalse(result['drain_complete'])

    def test_grace_deadline_checked_after_exit_observation_and_reread(self):
        for boundary in ('observe', 'read'):
            with self.subTest(boundary=boundary):
                state = {}
                result, _, _ = self.capture('pass', setup=self.setup_race(state, late=boundary))
                self.assertEqual(result['status'], 'diagnostic_infrastructure_failed', result)
                self.assertIn('grace expired', result['error'])
                self.assertFalse(result['drain_complete'])
                self.assertEqual(state['confirmations'], int(boundary == 'read'))

    def test_process_deadline_checked_after_exit_observation_and_reread(self):
        for boundary in ('process_observe', 'process_read'):
            with self.subTest(boundary=boundary):
                state = {}
                result, _, _ = self.capture('pass', setup=self.setup_race(state, late=boundary))
                self.assertEqual(result['status'], 'diagnostic_timeout', result)
                self.assertFalse(result['drain_complete'])

    def test_pending_eio_timeout_never_resolves_after_group_kill(self):
        state = {}
        result, _, _ = self.capture('import os,time;os.close(1);time.sleep(10)',
                                     setup=self.setup_race(state), overrides=(('PROCESS_SECONDS', 0.04),))
        self.assertEqual(result['status'], 'diagnostic_timeout', result)
        self.assertFalse(result['drain_complete'])
        self.assertEqual(state['confirmations'], 0)

    def test_nonzero_natural_exit_remains_failed(self):
        state = {}
        result, _, _ = self.capture('import sys;sys.exit(7)', setup=self.setup_race(state))
        self.assertEqual(result['status'], 'diagnostic_failed', result)
        self.assertEqual(result['returncode'], 7)
        self.assertTrue(result['drain_complete'])

    def test_interruption_never_resolves_pending_eio(self):
        state = {}
        result, _, _ = self.capture('pass', setup=self.setup_race(state, interrupt=True))
        self.assertEqual(result['status'], 'diagnostic_failed', result)
        self.assertTrue(result['interrupted'])
        self.assertFalse(result['drain_complete'])

    def test_cleanup_error_never_yields_success(self):
        state = {}
        result, _, _ = self.capture('pass', setup=self.setup_race(state, cleanup_error=True))
        self.assertEqual(result['status'], 'diagnostic_infrastructure_failed', result)
        self.assertTrue(result['cleanup_incomplete'])
        self.assertIn('group_cleanup_error', result)

    def test_descendant_stderr_owner_killed_only_after_confirmation(self):
        state = {}
        script = 'import os,time\npid=os.fork()\nif pid==0:\n os.close(1);time.sleep(10)\n'
        result, _, _ = self.capture(script, setup=self.setup_race(state))
        self.assertEqual(result['status'], 'diagnostic_completed', result)
        self.assertTrue(result['group_kill_sent'])
        self.assertTrue(result['leader_reaped'])
        self.assertTrue(result['drain_complete'])
        self.assertEqual(state['confirmations'], 1)

    def test_exact_grace_boundary_is_rejected(self):
        state = {}
        result, _, _ = self.capture('pass', setup=self.setup_race(state, late='exact'))
        self.assertEqual(result['status'], 'diagnostic_infrastructure_failed', result)
        self.assertIn('grace expired', result['error'])
        self.assertEqual(state['confirmations'], 0)
        self.assertFalse(result['drain_complete'])

    def test_confirmation_read_respects_remaining_combined_raw_quota(self):
        state = {}
        result, files, _ = self.capture('import os;os.write(2,b"err")',
            setup=self.setup_race(state, reopen=b'x' * 100), overrides=(('RAW_LIMIT', 8),))
        self.assertEqual(result['status'], 'diagnostic_infrastructure_failed', result)
        self.assertEqual(result['observed_bytes'], {'stdout': 5, 'stderr': 3})
        self.assertEqual(result['raw_written_bytes'], 3)
        self.assertEqual(files['SevenCertificatePart02.stdout'], b'')
        self.assertEqual(files['SevenCertificatePart02.stderr'], b'err')

    def test_both_legacy_modes_require_bounded_exit_and_eof_confirmation(self):
        from tests.test_core_syntax_diagnostic_capture import DiagnosticCaptureTests
        for target in ('LinearTransport', 'CertPart02'):
            with self.subTest(target=target):
                state = {}
                result, _, _ = DiagnosticCaptureTests().run_child('pass',
                    target=target, setup=self.setup_race(state))
                self.assertEqual(result['status'], 'diagnostic_completed', result)
                self.assertTrue(result['drain_complete'])
                self.assertEqual(state['confirmations'], 1)
                state = {}
                result, _, _ = DiagnosticCaptureTests().run_child(
                    'import os,time;os.close(1);os.close(2);time.sleep(10)',
                    target=target, setup=self.setup_race(state))
                self.assertEqual(result['status'], 'diagnostic_infrastructure_failed', result)
                self.assertFalse(result['drain_complete'])
                self.assertEqual(state['confirmations'], 0)
