"""Actual children with withheld reap confirmation; never leave live orphans.

The injected wait error happens only after Linux WNOWAIT has observed the real
child's exit. Recovery then uses the original Popen.wait to reap that same child.
These are lifecycle failure controls, not simulated successful native results.
"""
from __future__ import annotations

from contextlib import contextmanager
import errno
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
from threading import Event, Thread, current_thread
from time import monotonic, sleep
import unittest
from unittest import mock

import hepta.hia_native_differential as native
import hepta.hia_native_loan_probe as probe
from hepta.hia_native_version_dispatch import NativeVersionDispatcher
from tests.test_hia_native_version_dispatch import programs
from tools import qualify_hia_native_loans as producer

CLANG = shutil.which("clang-20")
SITE = ("swap_candidate", "entry", "loan")


def _native_process(arguments):
    return (type(arguments) in (list, tuple) and len(arguments) >= 5
            and arguments[3] == "-c" and arguments[4] in (native._WORKER, probe._WORKER))


@unittest.skipUnless(platform.system() == "Linux" and platform.machine().lower() in {"x86_64", "amd64"}
                     and CLANG and hasattr(os, "memfd_create"), "requires Linux x86-64, sealed memfd and Clang 20")
class NativeCleanupQuarantineTests(unittest.TestCase):
    def host(self, *, diagnostic=False):
        baseline, _ = programs()
        host = NativeVersionDispatcher(baseline.canonical_bytes, clang=CLANG,
            diagnostic_loan_site=SITE if diagnostic else None)
        self.addCleanup(host.close)
        return host

    def stage(self, host):
        candidate = programs()[1]
        job = host.stage_candidate_async(candidate.canonical_bytes)
        done = host.wait_candidate(job["job_id"], timeout=20)
        self.assertEqual(done["status"], "staged", done)
        host.activate(candidate.sha256, expected_generation=0)
        return candidate

    @contextmanager
    def withhold_reap_confirmation(self, host, *, recover=True):
        original_wait = subprocess.Popen.wait
        observations = {"exited_child_pids": set(), "injected_wait_failures": 0, "processes": {}}

        def failed_reap(process, *args, **kwargs):
            if not _native_process(process.args):
                return original_wait(process, *args, **kwargs)
            # Cleanup already sent SIGKILL. Confirm actual exit without reaping
            # before injecting a wait failure; there is no live orphan here.
            deadline = monotonic() + 2
            status = None
            while status is None and monotonic() < deadline:
                status = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOWAIT | os.WNOHANG)
                if status is None:
                    sleep(0.001)
            if status is None:
                original_wait(process, timeout=2)
                raise AssertionError("could not observe real child exit before injected reap failure")
            observations["exited_child_pids"].add(process.pid)
            observations["processes"][process.pid] = process
            observations["injected_wait_failures"] += 1
            raise subprocess.TimeoutExpired(process.args, kwargs.get("timeout", 0))

        patcher = mock.patch.object(subprocess.Popen, "wait", failed_reap)
        patcher.start()
        try:
            yield observations
        finally:
            patcher.stop()
            if recover:
                observations["recovery"] = host.retry_cleanup(timeout=2)
            # Even an intentionally failing old-code regression must not leave
            # an unreaped child behind if it lost the cleanup owner under test.
            def reap_remaining():
                for process in observations["processes"].values():
                    if process.returncode is None:
                        original_wait(process, timeout=2)
            if recover:
                reap_remaining()
            else:
                self.addCleanup(reap_remaining)

    def assert_closed(self, descriptor):
        with self.assertRaises(OSError) as error:
            os.fstat(descriptor)
        self.assertEqual(error.exception.errno, errno.EBADF)

    def test_ordinary_call_quarantines_image_until_real_reap_and_recovery_is_idempotent(self):
        host = self.host()
        candidate = self.stage(host)
        descriptor = host._versions[candidate.sha256].descriptor
        with self.withhold_reap_confirmation(host) as control:
            with self.assertRaises(native.NativeChildCleanupPending) as raised:
                host.execute("native_swap", [5, 0, 4, 0])
            pending = raised.exception.cleanup.snapshot()
            self.assertFalse(pending["cleanup_confirmed"])
            self.assertIn(pending["pid"], control["exited_child_pids"])
            snapshot = host.snapshot()
            self.assertEqual(snapshot["in_flight"], 1)
            self.assertEqual(snapshot["unconfirmed_child_reaps"], 1)
            self.assertEqual(snapshot["quarantined_calls"][0]["program_sha256"], candidate.sha256)
            host.rollback(expected_generation=1)
            self.assertGreater(os.fstat(descriptor).st_size, 0)
            self.assertFalse(host.close(wait=False)["drained"])
            # An unsuccessful bounded retry and repeated close must not
            # discard the same actual child owner or close its sealed image.
            retried = host.retry_cleanup(timeout=0)
            self.assertEqual(retried["recovered_call_ids"], [])
            self.assertEqual(len(retried["quarantined_call_ids"]), 1)
            self.assertFalse(host.close(wait=True, timeout=0.02)["drained"])
            self.assertFalse(host.close(wait=False)["drained"])
            self.assertGreater(os.fstat(descriptor).st_size, 0)
        self.assertEqual(len(control["recovery"]["recovered_call_ids"]), 1)
        self.assertTrue(control["recovery"]["drained"])
        self.assert_closed(descriptor)
        snapshot = host.snapshot()
        self.assertEqual(snapshot["in_flight"], 0)
        self.assertEqual(snapshot["unconfirmed_child_reaps"], 0)
        self.assertEqual(snapshot["released_artifacts"], 2)
        self.assertEqual(host.retry_cleanup(timeout=0)["recovered_call_ids"], [])
        self.assertTrue(host.close(wait=True, timeout=0)["drained"])
        self.assertEqual(host.snapshot()["released_artifacts"], 2)

    def test_diagnostic_reap_failure_retains_pin_and_recovery_does_not_invent_success(self):
        host = self.host(diagnostic=True)
        baseline = programs()[0]
        descriptor = host._versions[baseline.sha256].descriptor
        with self.withhold_reap_confirmation(host) as control:
            call = host.start_loan_probe("native_swap", [5, 0, 4, 0])
            call.wait_active()
            call.resume()
            with self.assertRaises(native.NativeChildCleanupPending):
                call.wait()
            partial = call.snapshot()
            self.assertTrue(partial["done"])
            self.assertTrue(partial["quarantined"])
            self.assertTrue(partial["child_process"]["spawn_observed"])
            self.assertTrue(partial["child_process"]["native_entry_observed"])
            self.assertFalse(partial["child_process"]["cleanup"]["cleanup_confirmed"])
            self.assertEqual(len(partial["events"]), 2)
            self.assertEqual(host.snapshot()["in_flight"], 1)
            self.assertFalse(host.close(wait=False)["drained"])
            self.assertGreater(os.fstat(descriptor).st_size, 0)
        self.assertEqual(len(control["recovery"]["recovered_call_ids"]), 1)
        recovered = call.snapshot()
        self.assertFalse(recovered["quarantined"])
        self.assertTrue(recovered["child_process"]["cleanup"]["cleanup_confirmed"])
        # Reaping cannot retrospectively turn the failed observation into a
        # successfully validated native return or re-execute the entry.
        with self.assertRaises(native.NativeChildCleanupPending):
            call.wait()
        self.assertTrue(host.snapshot()["drained"])
        self.assert_closed(descriptor)

    def test_timed_out_loan_with_unconfirmed_reap_stays_quarantined(self):
        host = self.host(diagnostic=True)
        with self.withhold_reap_confirmation(host) as control:
            call = host.start_loan_probe("native_swap", [5, 0, 4, 0], timeout=0.5)
            call.wait_active(timeout=0.4)
            with self.assertRaises(native.NativeChildCleanupPending):
                call.wait(timeout=4)
            observation = call.snapshot()
            self.assertEqual(len(observation["events"]), 1)
            self.assertFalse(observation["ack_sent"])
            self.assertTrue(observation["quarantined"])
            self.assertFalse(host.close(wait=False)["drained"])
            self.assertEqual(host.snapshot()["unconfirmed_child_reaps"], 1)
        self.assertEqual(len(control["recovery"]["recovered_call_ids"]), 1)
        self.assertTrue(host.snapshot()["drained"])
        self.assertEqual(len(call.snapshot()["events"]), 1)

    def test_failed_popen_reports_unknown_start_outcome_without_counting_attempt_as_entry(self):
        original = subprocess.Popen
        failed_spawns = []

        def fail_native(arguments, *args, **kwargs):
            if _native_process(arguments):
                failed_spawns.append(tuple(arguments[:4]))
                raise OSError(errno.EAGAIN, "injected native process creation failure")
            return original(arguments, *args, **kwargs)

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "new-evidence"
            with mock.patch.object(subprocess, "Popen", side_effect=fail_native):
                result = producer.qualify(output, clang=CLANG)
            self.assertEqual(len(failed_spawns), 1)
            self.assertFalse(result["ok"])
            self.assertFalse(result["execution_passed"])
            counts = result["counts"]
            self.assertEqual(counts["attempted_calls"], 1)
            self.assertEqual(counts["child_processes_started"], 0)
            self.assertFalse(counts["child_process_start_count_complete"])
            self.assertEqual(counts["unavailable_child_start_outcomes"], 1)
            self.assertEqual(counts["completed_observations"], 0)
            self.assertEqual(counts["native_entries_observed"], 0)
            self.assertIsNone(counts["native_entry_invocations"])
            self.assertTrue(result["close"]["drained"])
            self.assertEqual(result["final_dispatch"]["unconfirmed_child_reaps"], 0)

    def test_actual_setup_failure_counts_a_child_but_never_an_entry_invocation(self):
        marker = "library = ctypes.CDLL(lib)"
        self.assertEqual(probe._WORKER.count(marker), 1)
        stopped = probe._WORKER.replace(marker,
            'raise RuntimeError("injected setup refusal before HIA image load")', 1)
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(probe, "_WORKER", stopped):
                result = producer.qualify(Path(directory) / "new-evidence", clang=CLANG)
        self.assertFalse(result["ok"])
        self.assertFalse(result["execution_passed"])
        counts = result["counts"]
        self.assertEqual(counts["attempted_calls"], 1)
        self.assertEqual(counts["child_processes_started"], 1)
        self.assertTrue(counts["child_process_start_count_complete"])
        self.assertEqual(counts["child_processes_reaped"], 1)
        self.assertEqual(counts["completed_observations"], 0)
        self.assertEqual(counts["native_entries_observed"], 0)
        self.assertIsNone(counts["native_entry_invocations"])
        self.assertEqual(counts["unavailable_native_entry_outcomes"], 1)
        self.assertTrue(result["close"]["drained"])

    def test_ordinary_temporary_close_error_cannot_mask_unconfirmed_reap(self):
        host = self.host()
        baseline = programs()[0]
        descriptor = host._versions[baseline.sha256].descriptor
        original_temporary = tempfile.TemporaryFile
        close_faults = []

        class CloseFault:
            def __init__(self, stream):
                self.stream = stream
            def __enter__(self):
                return self.stream.__enter__()
            def __exit__(self, *arguments):
                self.stream.__exit__(*arguments)
                close_faults.append(True)
                raise OSError("injected temporary close fault after actual close")

        with self.withhold_reap_confirmation(host) as control:
            with mock.patch.object(tempfile, "TemporaryFile",
                                   side_effect=lambda *args, **kwargs: CloseFault(original_temporary(*args, **kwargs))):
                with self.assertRaises(native.NativeChildCleanupPending) as raised:
                    host.execute("native_swap", [5, 0, 4, 0])
            self.assertTrue(close_faults)
            self.assertEqual(host.snapshot()["in_flight"], 1)
            self.assertFalse(host.close(wait=False)["drained"])
            self.assertGreater(os.fstat(descriptor).st_size, 0)
            self.assertTrue(any("temporary close fault" in error["message"]
                for error in raised.exception.cleanup.snapshot()["secondary_errors"]))
        self.assertEqual(len(control["recovery"]["recovered_call_ids"]), 1)
        self.assertTrue(host.snapshot()["drained"])
        self.assert_closed(descriptor)

    def test_diagnostic_pipe_close_error_cannot_mask_unconfirmed_reap(self):
        host = self.host(diagnostic=True)
        original_close, original_pipe2 = os.close, os.pipe2
        owned_pipes = {}
        faults = []

        def remember_pipes(*args, **kwargs):
            result = original_pipe2(*args, **kwargs)
            if current_thread().name == "hia-native-loan-probe":
                for descriptor in result:
                    info = os.fstat(descriptor)
                    owned_pipes[descriptor] = (info.st_dev, info.st_ino)
            return result

        try:
            with self.withhold_reap_confirmation(host) as control:
                def close_with_fault(descriptor):
                    result = original_close(descriptor)
                    if (current_thread().name == "hia-native-loan-probe" and descriptor in owned_pipes
                            and control["injected_wait_failures"] and not faults):
                        faults.append(descriptor)
                        raise OSError("injected pipe close fault after actual close")
                    return result
                with mock.patch.object(os, "pipe2", side_effect=remember_pipes), \
                        mock.patch.object(os, "close", side_effect=close_with_fault):
                    call = host.start_loan_probe("native_swap", [5, 0, 4, 0])
                    call.wait_active()
                    call.resume()
                    with self.assertRaises(native.NativeChildCleanupPending):
                        call.wait()
                self.assertTrue(faults)
                observation = call.snapshot()
                self.assertTrue(observation["quarantined"])
                self.assertFalse(host.close(wait=False)["drained"])
                self.assertEqual(host.snapshot()["in_flight"], 1)
                self.assertTrue(any("pipe close fault" in error["message"]
                    for error in observation["child_process"]["cleanup"]["secondary_errors"]))
            self.assertEqual(len(control["recovery"]["recovered_call_ids"]), 1)
            self.assertTrue(host.snapshot()["drained"])
        finally:
            # Old-code failure may have stopped at the first close error.
            # Close only a still-open descriptor with the exact recorded inode.
            for descriptor, identity in owned_pipes.items():
                try:
                    info = os.fstat(descriptor)
                except OSError:
                    continue
                if (info.st_dev, info.st_ino) == identity:
                    original_close(descriptor)

    def test_zero_timeout_retry_snapshot_and_short_close_do_not_wait_behind_another_reap(self):
        host = self.host()
        with self.withhold_reap_confirmation(host, recover=False) as control:
            with self.assertRaises(native.NativeChildCleanupPending):
                host.execute("native_swap", [5, 0, 4, 0])
        self.assertFalse(host.close(wait=False)["drained"])
        original_wait = subprocess.Popen.wait
        entered, release, quick_done = Event(), Event(), Event()
        quick, slow = {}, {}

        def delayed_wait(process, *args, **kwargs):
            if _native_process(process.args):
                entered.set()
                if not release.wait(2):
                    raise subprocess.TimeoutExpired(process.args, kwargs.get("timeout", 0))
            return original_wait(process, *args, **kwargs)

        def slow_retry():
            try:
                slow["result"] = host.retry_cleanup(timeout=2)
            except BaseException as error:
                slow["error"] = error

        def quick_operations():
            try:
                quick["retry"] = host.retry_cleanup(timeout=0)
                quick["snapshot"] = host.snapshot()
                quick["close"] = host.close(wait=True, timeout=0.02)
            except BaseException as error:
                quick["error"] = error
            finally:
                quick_done.set()

        first = second = None
        try:
            with mock.patch.object(subprocess.Popen, "wait", delayed_wait):
                first = Thread(target=slow_retry, daemon=False)
                first.start()
                self.assertTrue(entered.wait(1))
                second = Thread(target=quick_operations, daemon=False)
                second.start()
                self.assertTrue(quick_done.wait(0.5), "zero/short timeout paths waited behind another reap")
                self.assertNotIn("error", quick)
                self.assertEqual(quick["retry"]["recovered_call_ids"], [])
                self.assertEqual(quick["snapshot"]["unconfirmed_child_reaps"], 1)
                self.assertFalse(quick["close"]["drained"])
        finally:
            release.set()
            for thread in (first, second):
                if thread is not None:
                    thread.join(3)
            host.retry_cleanup(timeout=2)
        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertNotIn("error", slow)
        self.assertTrue(host.snapshot()["drained"])
        self.assertTrue(control["exited_child_pids"])
