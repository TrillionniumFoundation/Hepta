"""Representation-lock regressions; no native image or old gate is involved.

Each case loads the actual module in a fresh Python process. The short child
deadline bounds these new lock checks only; it does not alter caller budgets.
The forced GC case proves a same-thread callback boundary, not the cause of an
unobservable historical execution.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import unittest


_SOURCE = Path(__file__).resolve().parents[1] / "hepta" / "hia_native_delivery.py"
_CHILD_DEADLINE_SECONDS = 5
_CHILD = r'''
import faulthandler
import gc
import importlib.util
import json
import os
from pathlib import Path
import select
import signal
import sys
import threading
import weakref

spec = importlib.util.spec_from_file_location("delivery_lock_regression", Path(sys.argv[1]))
delivery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(delivery)
case = sys.argv[2]
faulthandler.dump_traceback_later(2, repeat=False)

if case == "gc_callback":
    gc.disable()

    class Resource:
        pass

    resource = Resource()
    resource.cycle = resource
    key = id(resource)
    delivery.bind_resource_lifetime(resource)
    reference = weakref.ref(resource)
    assert key in delivery._RESOURCE_LIFETIMES
    assert len(delivery._RESOURCE_LIFETIMES) == 1
    assert not delivery._CUSTODY and not delivery._RESOURCE_OBSERVATIONS
    del resource
    assert reference() is not None
    with delivery._custody_lock():
        gc.collect()
    assert reference() is None
    assert key not in delivery._RESOURCE_LIFETIMES
    assert not delivery._RESOURCE_LIFETIMES
    observations = {"weak_reference_cleared": True, "lifetime_registry_empty": True}

elif case == "other_thread":
    lock = delivery._custody_lock()
    attempted = threading.Event()
    acquired_after_release = threading.Event()
    attempt = {}

    def contender():
        entered = lock.acquire(blocking=False)
        attempt["entered_while_held"] = entered
        if entered:
            lock.release()
        attempted.set()
        with lock:
            acquired_after_release.set()

    thread = threading.Thread(target=contender, name="delivery-lock-contender")
    lock.acquire()
    try:
        thread.start()
        assert attempted.wait(1), "contender did not attempt the actual lock"
        assert attempt["entered_while_held"] is False
        assert not acquired_after_release.is_set()
    finally:
        lock.release()
    assert acquired_after_release.wait(1)
    thread.join(1)
    assert not thread.is_alive()
    observations = {"other_thread_excluded": True, "acquired_after_release": True,
                    "contender_joined": True}

elif case == "fork_reset":
    assert hasattr(os, "fork") and hasattr(os, "register_at_fork")
    original_lock = delivery._custody_lock()
    parent_pid = os.getpid()
    held = threading.Event()
    release_holder = threading.Event()

    def holder():
        with original_lock:
            held.set()
            release_holder.wait()

    thread = threading.Thread(target=holder, name="delivery-lock-fork-holder")
    read_fd, write_fd = os.pipe()
    child_pid = None
    reaped = False
    thread.start()
    try:
        assert held.wait(1), "parent thread did not hold the actual lock"
        child_pid = os.fork()
        if child_pid == 0:
            os.close(read_fd)
            try:
                assert delivery._CUSTODY_PID == os.getpid() != parent_pid
                assert delivery._CUSTODY_LOCK is not original_lock
                with delivery._custody_lock():
                    os.write(write_fd, b"child-reset-and-acquired")
            except BaseException:
                os._exit(23)
            os._exit(0)
        os.close(write_fd)
        write_fd = None
        ready, _, _ = select.select([read_fd], [], [], 1)
        assert ready, "child did not reset/acquire the inherited representation lock"
        payload = os.read(read_fd, 128)
        assert payload == b"child-reset-and-acquired", payload
        waited, status = os.waitpid(child_pid, 0)
        reaped = True
        assert waited == child_pid and os.waitstatus_to_exitcode(status) == 0
        assert delivery._CUSTODY_PID == parent_pid
        assert delivery._CUSTODY_LOCK is original_lock
        assert thread.is_alive() and not release_holder.is_set()
    finally:
        if child_pid and not reaped:
            try:
                os.kill(child_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.waitpid(child_pid, 0)
        os.close(read_fd)
        if write_fd is not None:
            os.close(write_fd)
        release_holder.set()
        thread.join(1)
    assert not thread.is_alive()
    observations = {"fork_child_reset_and_acquired": True,
                    "parent_lock_identity_unchanged": True,
                    "fork_child_reaped": True, "holder_joined": True}

else:
    raise AssertionError(case)

faulthandler.cancel_dump_traceback_later()
print(json.dumps({"case": case, "observations": observations}, sort_keys=True))
'''


class NativeDeliveryLockTests(unittest.TestCase):
    def _run_case(self, case):
        child = subprocess.Popen(
            [sys.executable, "-I", "-B", "-c", _CHILD, str(_SOURCE), case],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
        )
        try:
            stdout, stderr = child.communicate(timeout=_CHILD_DEADLINE_SECONDS)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            stdout, stderr = child.communicate(timeout=5)
            self.fail(
                f"new lock regression {case!r} exceeded its "
                f"{_CHILD_DEADLINE_SECONDS}s child deadline; "
                f"stdout={stdout!r}; stderr={stderr!r}"
            )
        except BaseException:
            if child.poll() is None:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            child.communicate(timeout=5)
            raise
        self.assertEqual(child.returncode, 0, (case, stdout, stderr))
        observed = json.loads(stdout)
        self.assertEqual(observed["case"], case)
        return observed["observations"]

    def test_same_thread_gc_weakref_callback_clears_lifetime(self):
        self.assertEqual(self._run_case("gc_callback"), {
            "weak_reference_cleared": True, "lifetime_registry_empty": True,
        })

    def test_other_thread_is_excluded_until_holder_releases(self):
        self.assertEqual(self._run_case("other_thread"), {
            "other_thread_excluded": True, "acquired_after_release": True,
            "contender_joined": True,
        })

    def test_fork_child_resets_lock_held_by_another_thread(self):
        self.assertEqual(self._run_case("fork_reset"), {
            "fork_child_reset_and_acquired": True,
            "parent_lock_identity_unchanged": True,
            "fork_child_reaped": True, "holder_joined": True,
        })
