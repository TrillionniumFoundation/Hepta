"""Real native children with finite cleanup failure and admission controls.

The C DSO is a transport control, not a Hepta compiler qualification. Injected
wait failures occur only after WNOWAIT observes an actual exited child. Every
test also owns a final original wait so a failing regression leaves no orphan.
"""
from __future__ import annotations

from contextlib import contextmanager
import errno
import gc
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import tempfile
from threading import Event, Lock, Thread
from time import monotonic, sleep
import unittest
from unittest import mock
import weakref

import hepta.hia_native_differential as native


CLANG = os.environ.get("CLANG") or shutil.which("clang")


def native_process(process):
    args = process.args
    return isinstance(args, (list, tuple)) and len(args) >= 5 and args[4] == native._WORKER


@unittest.skipUnless(platform.system() == "Linux" and platform.machine().lower() in {"x86_64", "amd64"}
                     and CLANG and hasattr(os, "memfd_create"), "Linux x86-64, Clang and sealed memfd required")
class NativeCleanupOwnershipTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix="hia-native-cleanup-")
        root = Path(cls.directory.name)
        cls.library = root / "transport.so"
        source = root / "transport.c"
        source.write_text('''#include <stdint.h>
#include <stdio.h>
uint32_t echo(uint32_t x){return x;}
uint32_t spin(uint32_t x){
    (void)x;fputs("native entry reached\\n",stdout);fflush(stdout);
    for(;;){__asm__ volatile("" ::: "memory");}
}
''', encoding="utf-8")
        process = subprocess.run([CLANG, "-shared", "-fPIC", "-O2", str(source), "-o", str(cls.library)],
                                 capture_output=True, text=True, timeout=30, check=False)
        if process.returncode:
            cls.directory.cleanup()
            raise AssertionError(process.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def setUp(self):
        self.assertEqual(native.native_child_cleanup_snapshot()["reserved_native_children"], 0)
        self.assertEqual(native.native_child_cleanup_snapshot()["unconfirmed_child_reaps"], 0)
        _, _, self.descriptor = native._pin_native_artifact(self.library)
        self.addCleanup(os.close, self.descriptor)

    def tearDown(self):
        snapshot = native.retry_pending_native_cleanup(timeout=2)
        self.assertEqual(snapshot["reserved_native_children"], 0, snapshot)
        self.assertEqual(snapshot["unconfirmed_child_reaps"], 0, snapshot)

    def observe(self, symbol="echo", value=7, timeout=2):
        return native._observe_native(self.library, symbol, "u32", [value],
                                      timeout=timeout, pinned_fd=self.descriptor)

    @contextmanager
    def withhold_reap(self, *, already_reaped=False, recover=True):
        original_wait = subprocess.Popen.wait
        state = {"processes": {}, "wait_failures": 0}

        def fail(process, *args, **kwargs):
            if not native_process(process):
                return original_wait(process, *args, **kwargs)
            if process.returncode is None:
                deadline = monotonic() + 2
                observed = None
                while observed is None and monotonic() < deadline:
                    observed = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOWAIT | os.WNOHANG)
                    if observed is None:
                        sleep(0.001)
                if observed is None:
                    original_wait(process, timeout=2)
                    raise AssertionError("actual child exit was not observed before failure injection")
            state["processes"][process.pid] = process
            state["wait_failures"] += 1
            if already_reaped:
                original_wait(process, timeout=2)
            raise subprocess.TimeoutExpired(process.args, kwargs.get("timeout", 0))

        def finish():
            for process in state["processes"].values():
                original_wait(process, timeout=2)
            native.retry_pending_native_cleanup(timeout=2)

        try:
            with mock.patch.object(subprocess.Popen, "wait", fail):
                yield state
        finally:
            if recover:
                finish()
            else:
                self.addCleanup(finish)

    def test_failed_confirmation_retains_owner_and_retry_never_signals_twice(self):
        with mock.patch.object(native.os, "killpg", wraps=os.killpg) as signalled:
            with self.withhold_reap() as state:
                with self.assertRaises(native.NativeChildCleanupPending) as caught:
                    self.observe()
                owner = caught.exception.cleanup
                pending = owner.snapshot()
                self.assertFalse(pending["cleanup_confirmed"])
                self.assertTrue(pending["quarantined"])
                self.assertIn(pending["pid"], state["processes"])
                self.assertFalse(owner.try_reap(timeout=0))
                self.assertEqual(native.native_child_cleanup_snapshot()["reserved_native_children"], 1)
                self.assertEqual(signalled.call_count, 1)
            self.assertTrue(owner.confirmed)
            self.assertTrue(owner.try_reap(timeout=0))
            self.assertEqual(owner.snapshot()["returncode"], 0)
            self.assertEqual(signalled.call_count, 1)
            self.assertEqual(native.native_child_cleanup_snapshot()["unconfirmed_child_reaps"], 0)

    def test_discarded_exception_cannot_discard_owner_or_admit_another_child(self):
        with self.withhold_reap():
            try:
                self.observe()
            except native.NativeChildCleanupPending as error:
                reference = weakref.ref(error.cleanup)
            gc.collect()
            self.assertIsNotNone(reference())
            before = native.native_child_cleanup_snapshot()
            self.assertEqual(before["unconfirmed_child_reaps"], 1)
            with mock.patch.object(subprocess, "Popen", side_effect=AssertionError("new child forbidden")):
                with self.assertRaisesRegex(native.HIADifferentialRejected, "blocks new native observers"):
                    self.observe()
            after = native.retry_pending_native_cleanup(timeout=0)
            self.assertEqual(after["reserved_native_children"], 1)
            self.assertFalse(after["claims"]["failed_observation_reclassified_as_success"])
        self.assertEqual(self.observe(value=9), ("value", 9))

    def test_reap_error_after_actual_reap_does_not_resignal_reusable_pgid(self):
        with mock.patch.object(native.os, "killpg", wraps=os.killpg) as signalled:
            with self.withhold_reap(already_reaped=True) as state:
                with self.assertRaises(native.NativeChildCleanupPending) as caught:
                    self.observe()
                self.assertEqual([p.returncode for p in state["processes"].values()], [0])
                self.assertFalse(caught.exception.cleanup.confirmed)
            self.assertTrue(caught.exception.cleanup.confirmed)
            self.assertEqual(signalled.call_count, 1)

    def test_real_native_timeout_is_killed_reaped_and_never_counted_as_return(self):
        original_temporary = tempfile.TemporaryFile
        captured = []

        class Capture:
            def __init__(self):
                self.stream = original_temporary()
            def __enter__(self):
                return self.stream
            def __exit__(self, *exception):
                self.stream.seek(0)
                captured.append(self.stream.read(4097))
                return self.stream.__exit__(*exception)

        owners = []
        original_owner = native.NativeChildCleanup
        def owner(*args, **kwargs):
            result = original_owner(*args, **kwargs)
            owners.append(result)
            return result
        with (mock.patch.object(tempfile, "TemporaryFile", side_effect=Capture),
              mock.patch.object(native, "NativeChildCleanup", side_effect=owner)):
            with self.assertRaisesRegex(native.HIADifferentialRejected, "timed out"):
                self.observe("spin", timeout=0.5)
        self.assertIn(b"native entry reached\n", captured)
        self.assertEqual(len(owners), 1)
        self.assertTrue(owners[0].confirmed)
        self.assertEqual(owners[0].snapshot()["returncode"], -signal.SIGKILL)

    def test_timeout_with_withheld_reap_stays_failed_after_recovery(self):
        with self.withhold_reap() as state:
            with self.assertRaises(native.NativeChildCleanupPending) as caught:
                self.observe("spin", timeout=0.5)
            owner = caught.exception.cleanup
            self.assertEqual(len(state["processes"]), 1)
            self.assertFalse(owner.confirmed)
        self.assertTrue(owner.confirmed)
        self.assertEqual(owner.snapshot()["returncode"], -signal.SIGKILL)
        self.assertFalse(native.native_child_cleanup_snapshot()["claims"]["failed_observation_reclassified_as_success"])

    def test_temporary_close_fault_cannot_mask_the_unconfirmed_owner(self):
        original_temporary = tempfile.TemporaryFile
        class CloseFault:
            def __init__(self):
                self.stream = original_temporary()
            def __enter__(self):
                return self.stream
            def __exit__(self, *exception):
                self.stream.__exit__(*exception)
                raise OSError("injected close error after actual stream close")
        with self.withhold_reap():
            with mock.patch.object(tempfile, "TemporaryFile", side_effect=CloseFault):
                with self.assertRaises(native.NativeChildCleanupPending) as caught:
                    self.observe()
            self.assertTrue(any("actual stream close" in row["message"]
                for row in caught.exception.cleanup.snapshot()["secondary_errors"]))

    def test_outer_pinned_descriptor_close_error_cannot_mask_cleanup(self):
        class Oracle:
            return_words = (("echo", "u32"),)
            def run(self, name, arguments, *, max_steps):
                return arguments[0]
        original_pin, original_close = native._pin_native_artifact, os.close
        target = []
        def pin(path):
            result = original_pin(path)
            target.append(result[2])
            return result
        def close(descriptor):
            result = original_close(descriptor)
            if target and descriptor == target[-1]:
                raise OSError(errno.EIO, "injected pin close fault after actual close")
            return result
        with self.withhold_reap():
            with (mock.patch.object(native, "_pin_native_artifact", side_effect=pin),
                  mock.patch.object(native.os, "close", side_effect=close)):
                with self.assertRaises(native.NativeChildCleanupPending) as caught:
                    native.compare_oracle_with_native(Oracle(), self.library, {"echo": [[7]]})
            self.assertTrue(any("pin close fault" in row["message"]
                for row in caught.exception.cleanup.snapshot()["secondary_errors"]))

    def test_actual_inflight_children_enforce_admission_before_another_spawn(self):
        # A lower finite test limit exercises the actual shared admission path
        # without launching the production maximum of 32 concurrent workers.
        self.assertEqual(native.native_child_cleanup_snapshot()["max_native_children"], 32)
        original_wait = subprocess.Popen.wait
        all_waiting, release = Event(), Event()
        lock = Lock()
        waits, results, errors = [], [], []
        def held_wait(process, *args, **kwargs):
            if native_process(process):
                with lock:
                    waits.append(process.pid)
                    if len(waits) == 2:
                        all_waiting.set()
                if not release.wait(1.5):
                    raise subprocess.TimeoutExpired(process.args, kwargs.get("timeout", 0))
            return original_wait(process, *args, **kwargs)
        def invoke(value):
            try:
                results.append(self.observe(value=value))
            except BaseException as error:
                errors.append(error)
        threads = [Thread(target=invoke, args=(value,)) for value in (11, 12)]
        try:
            with (mock.patch.object(native, "_MAX_NATIVE_CHILDREN", 2),
                  mock.patch.object(subprocess.Popen, "wait", held_wait)):
                for thread in threads:
                    thread.start()
                self.assertTrue(all_waiting.wait(1))
                self.assertEqual(native.native_child_cleanup_snapshot()["reserved_native_children"], 2)
                with mock.patch.object(subprocess, "Popen", side_effect=AssertionError("third child forbidden")):
                    with self.assertRaisesRegex(native.HIADifferentialRejected, "child budget exhausted"):
                        self.observe(value=13)
                release.set()
                for thread in threads:
                    thread.join(2)
        finally:
            release.set()
            for thread in threads:
                if thread.ident is not None:
                    thread.join(3)
        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual(errors, [])
        self.assertCountEqual(results, [("value", 11), ("value", 12)])
        self.assertEqual(len(set(waits)), 2)

    def test_failed_spawn_releases_its_reservation(self):
        with mock.patch.object(subprocess, "Popen", side_effect=OSError(errno.EAGAIN, "injected spawn refusal")):
            with self.assertRaisesRegex(native.HIADifferentialRejected, "unavailable"):
                self.observe()
        self.assertEqual(native.native_child_cleanup_snapshot()["reserved_native_children"], 0)
        self.assertEqual(native.native_child_cleanup_snapshot()["unconfirmed_child_reaps"], 0)

    def test_zero_timeout_retry_and_snapshot_do_not_wait_behind_another_reap(self):
        with self.withhold_reap(recover=False):
            with self.assertRaises(native.NativeChildCleanupPending):
                self.observe()
        original_wait = subprocess.Popen.wait
        entered, release, quick_done = Event(), Event(), Event()
        errors, quick = [], []
        def delayed_wait(process, *args, **kwargs):
            if native_process(process):
                entered.set()
                if not release.wait(1.5):
                    raise subprocess.TimeoutExpired(process.args, kwargs.get("timeout", 0))
            return original_wait(process, *args, **kwargs)
        def slow():
            try:
                native.retry_pending_native_cleanup(timeout=2)
            except BaseException as error:
                errors.append(error)
        def fast():
            try:
                quick.append(native.retry_pending_native_cleanup(timeout=0))
                quick.append(native.native_child_cleanup_snapshot())
            except BaseException as error:
                errors.append(error)
            finally:
                quick_done.set()
        first, second = Thread(target=slow), Thread(target=fast)
        try:
            with mock.patch.object(subprocess.Popen, "wait", delayed_wait):
                first.start()
                self.assertTrue(entered.wait(1))
                second.start()
                self.assertTrue(quick_done.wait(0.5), "metadata/zero retry blocked on another OS wait")
                self.assertEqual([row["unconfirmed_child_reaps"] for row in quick], [1, 1])
        finally:
            release.set()
            for thread in (first, second):
                if thread.ident is not None:
                    thread.join(3)
        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertEqual(errors, [])

    def test_retry_budget_rejects_unbounded_or_type_confused_values(self):
        for timeout in (-1, 3, float("inf"), float("nan"), True, "1"):
            with self.subTest(timeout=repr(timeout)), self.assertRaises(ValueError):
                native.retry_pending_native_cleanup(timeout=timeout)


if __name__ == "__main__":
    unittest.main()
