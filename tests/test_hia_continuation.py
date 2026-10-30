"""Real owner continuations, stale-state refusal and transactional registration."""
from __future__ import annotations

import fcntl
import ctypes
import importlib.util
import os
from pathlib import Path
import shutil
import tempfile
import time
import threading
import unittest
from unittest.mock import patch

from hepta.hia_adaptive import AdaptiveRejected
from hepta.hia_stateful import OwnedAdaptiveRuntime
from tools.qualify_hia_stateful import programs, expected
from tools.qualify_hia_continuation import qualify

CLANG = os.environ.get("CLANG", "/usr/bin/clang-20")
NATIVE = shutil.which(CLANG) and hasattr(fcntl, "F_SEAL_WRITE") and importlib.util.find_spec("z3") is not None


@unittest.skipUnless(NATIVE, "Clang, Z3 and real Linux memfd seals required")
class OwnedContinuationTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="hia-continuation-test-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

    def runtime(self):
        runtime = OwnedAdaptiveRuntime(programs()[0], self.root/"runtime", [11,17], clang=CLANG)
        self.addCleanup(runtime.close)
        return runtime

    def test_actual_prefix_switch_suffix_and_resource_oracle(self):
        report = qualify(self.root/"qualification", clang=CLANG)
        self.assertTrue(report["passed"], report["controls"])
        self.assertFalse(report["external_effect_replay_authority"])

    def test_actual_prefix_crosses_item_boundary_before_version_switch(self):
        report = qualify(self.root/"cross-item", clang=CLANG, cancelled_prefix=22)
        self.assertTrue(report["passed"], report["controls"])
        self.assertEqual([item["committed"] for item in report["prefix"]["item_progress"]],[17,5])
        self.assertEqual(report["suffix"]["executed_steps"],18)

    def test_cancel_before_execution_can_continue_once_without_replaying(self):
        runtime = self.runtime()
        items = [{"slot":0,"delta":9,"iterations":3}]
        original = runtime.submit_queue(items)
        runtime.cancel(original)
        child = runtime.continue_queue(original)
        self.assertEqual(runtime.queue_status(original)["continued_by"], child)
        receipt = runtime.execute_committed(child)
        self.assertEqual(receipt["final_values"], expected([11,17],items))
        self.assertEqual(receipt["continuation"]["prior_executed_steps"],0)
        for token in (original, child):
            with self.assertRaises(AdaptiveRejected):runtime.continue_queue(token)
            with self.assertRaises(AdaptiveRejected):runtime.execute_committed(token)

    def test_live_loan_and_post_cancellation_mutation_refuse(self):
        runtime = self.runtime()
        queue = runtime.submit_queue([{"slot":0,"delta":1,"iterations":2}])
        runtime.cancel(queue)
        with runtime.borrow() as loan:
            self.assertEqual(loan.read(0),11)
            with self.assertRaisesRegex(AdaptiveRejected,"E_STATE_BUSY"):
                runtime.continue_queue(queue)
        with runtime.borrow(mutable=True) as loan:loan.write(0,11)
        with self.assertRaisesRegex(AdaptiveRejected,"E_STATE_STALE"):
            runtime.continue_queue(queue)

    def test_repeated_zero_progress_continuations_preserve_root_and_bound(self):
        runtime = self.runtime()
        root = token = runtime.submit_queue([{"slot":1,"delta":1,"iterations":2}])
        for _ in range(31):
            runtime.cancel(token)
            token = runtime.continue_queue(token)
            continuation=runtime.queue_status(token)["continuation"]
            self.assertEqual(continuation["root_queue"],root)
            self.assertEqual(continuation["prior_executed_steps"],0)
        runtime.cancel(token)
        with self.assertRaisesRegex(AdaptiveRejected,"32 retained"):
            runtime.continue_queue(token)
        self.assertEqual(runtime.snapshot()["state_values"],[11,17])

    def test_failed_registration_rolls_back_both_links_without_work(self):
        runtime = self.runtime()
        queue = runtime.submit_queue([{"slot":0,"delta":1,"iterations":2}])
        runtime.cancel(queue)
        before=runtime.snapshot()
        with patch.object(runtime,"_event",side_effect=RuntimeError("injected publication failure")):
            with self.assertRaisesRegex(RuntimeError,"injected publication"):
                runtime.continue_queue(queue)
        self.assertEqual(len(runtime._queues),1)
        self.assertIsNone(runtime.queue_status(queue)["continued_by"])
        self.assertEqual(runtime.snapshot()["state_values"],before["state_values"])
        child=runtime.continue_queue(queue)
        self.assertEqual(runtime.execute_committed(child)["executed_steps"],2)

    def test_pending_queue_failed_queue_and_unknown_progress_are_not_continuations(self):
        runtime = self.runtime()
        token=runtime.submit_queue([{"slot":0,"delta":1,"iterations":2}])
        for bad in (token,"unknown",False,[]):
            with self.assertRaises(AdaptiveRejected):runtime.continue_queue(bad)
        runtime.cancel(token)
        second=runtime.submit_queue([{"slot":1,"delta":1,"iterations":1}])
        with self.assertRaisesRegex(AdaptiveRejected,"one pending"):
            runtime.continue_queue(token)
        runtime.cancel(second)
        runtime._queues[token]["status"]="failed"
        with self.assertRaises(AdaptiveRejected):runtime.continue_queue(token)

    def test_continuation_event_append_then_interrupt_rolls_back_evidence(self):
        runtime=self.runtime()
        token=runtime.submit_queue([{"slot":0,"delta":1,"iterations":2}])
        runtime.cancel(token)
        before=runtime.snapshot()
        event=runtime._event
        def append_then_interrupt(*args,**kwargs):
            event(*args,**kwargs)
            raise KeyboardInterrupt("after actual event append")
        with patch.object(runtime,"_event",side_effect=append_then_interrupt):
            with self.assertRaises(KeyboardInterrupt):runtime.continue_queue(token)
        after=runtime.snapshot()
        for key in ("events","event_count","event_counts","state_values"):
            self.assertEqual(after[key],before[key])
        self.assertEqual(len(runtime._queues),1)
        self.assertIsNone(runtime.queue_status(token)["continued_by"])

    def test_queue_start_event_failure_keeps_owner_quiescent_and_cost_debt(self):
        runtime=self.runtime()
        items=[{"slot":0,"delta":3,"iterations":5}]
        token=runtime.submit_queue(items)
        before=runtime.snapshot()
        debt=runtime._unamortized_preparation_ns
        event=runtime._event
        def append_then_fail(*args,**kwargs):
            event(*args,**kwargs)
            raise RuntimeError("after actual queue start event")
        with patch.object(runtime,"_event",side_effect=append_then_fail):
            with self.assertRaisesRegex(RuntimeError,"after actual queue start"):
                runtime.execute_committed(token)
        self.assertEqual(runtime.queue_status(token)["status"],"submitted")
        self.assertEqual(runtime._active,0)
        self.assertGreaterEqual(runtime._unamortized_preparation_ns,debt)
        after=runtime.snapshot()
        for key in ("events","event_count","event_counts","state_values"):
            self.assertEqual(after[key],before[key])
        self.assertEqual(runtime.execute_committed(token)["final_values"],expected([11,17],items))

    def test_clock_interrupt_after_activation_restores_owner_and_preparation_debt(self):
        runtime=self.runtime()
        token=runtime.submit_queue([{"slot":0,"delta":1,"iterations":5}])
        before=runtime.snapshot()
        debt=runtime._unamortized_preparation_ns
        clock=time.monotonic_ns
        def interrupt_after_activation():
            if runtime._active:
                raise KeyboardInterrupt("before first native update")
            return clock()
        with patch("hepta.hia_queue_commit.time.monotonic_ns",side_effect=interrupt_after_activation):
            with self.assertRaises(KeyboardInterrupt):runtime.execute_committed(token)
        self.assertEqual(runtime._active,0)
        self.assertEqual(runtime.queue_status(token)["status"],"submitted")
        self.assertGreaterEqual(runtime._unamortized_preparation_ns,debt)
        self.assertEqual(runtime.snapshot()["state_values"],before["state_values"])
        self.assertEqual(runtime.snapshot()["events"],before["events"])
        self.assertEqual(runtime.execute_committed(token)["executed_steps"],5)

    def test_finish_diagnostic_failure_charges_prefix_once_before_real_continuation(self):
        runtime=self.runtime()
        items=[{"slot":0,"delta":3,"iterations":5}]
        token=runtime.submit_queue(items)
        apply=runtime._apply_items
        def cancel_after_two(state,work,image):
            self.assertEqual(runtime._driver.hs_apply(state,0,2,3,
                ctypes.cast(image.function,ctypes.c_void_p)),1)
            runtime._driver.hs_cancel(state)
            return False
        event=runtime._event
        def fail_after_finish(kind,**fields):
            event(kind,**fields)
            if kind=="state_queue_finished":raise RuntimeError("finished diagnostic failed")
        with patch.object(runtime,"_apply_items",side_effect=cancel_after_two), \
                patch.object(runtime,"_event",side_effect=fail_after_finish):
            with self.assertRaisesRegex(RuntimeError,"finished diagnostic"):
                runtime.execute_committed(token)
        first=runtime.queue_status(token)["receipt"]
        self.assertEqual(first["executed_steps"],2)
        self.assertTrue(first["cost_accounting_complete"])
        self.assertIn("commit_bookkeeping_ns",first)
        self.assertEqual(runtime._cumulative_deployment_cost_ns,first["deployment_cost_ns"])
        child=runtime.continue_queue(token)
        second=runtime.execute_committed(child)
        self.assertEqual(second["executed_steps"],3)
        self.assertEqual(second["final_values"],expected([11,17],items))
        self.assertEqual(runtime._cumulative_deployment_cost_ns,
                         first["deployment_cost_ns"]+second["deployment_cost_ns"])

    def test_unknown_finalization_cost_poison_refuses_further_work_but_releases_owner(self):
        runtime=self.runtime()
        token=runtime.submit_queue([{"slot":0,"delta":1,"iterations":2}])
        apply=runtime._apply_items
        clock=time.monotonic_ns
        completed=False
        def apply_then_mark(*args):
            nonlocal completed
            result=apply(*args)
            completed=True
            return result
        def fail_after_native():
            if completed:raise RuntimeError("finalization clock unavailable")
            return clock()
        with patch.object(runtime,"_apply_items",side_effect=apply_then_mark), \
                patch("hepta.hia_queue_commit.time.monotonic_ns",side_effect=fail_after_native):
            with self.assertRaisesRegex(RuntimeError,"finalization clock"):
                runtime.execute_committed(token)
        self.assertEqual(runtime._active,0)
        self.assertTrue(runtime.snapshot()["state_poisoned"])
        self.assertFalse(runtime.snapshot()["cost_accounting_complete"])
        with self.assertRaises(AdaptiveRejected):runtime.submit_queue([{"slot":0,"delta":1,"iterations":1}])
        runtime.close()
        self.assertEqual(runtime._final_ledger["live"],0)

    def test_start_rollback_keeps_real_concurrent_prepare_cost_and_event(self):
        from hepta import hia_adaptive
        runtime=self.runtime()
        token=runtime.submit_queue([{"slot":0,"delta":1,"iterations":5}])
        original_debt=runtime._unamortized_preparation_ns
        ready, publish, finished=threading.Event(),threading.Event(),threading.Event()
        main_thread=threading.current_thread()
        clock=time.monotonic_ns
        worker_times=[]
        values={}
        issue=hia_adaptive._issue
        def pause_after_real_proof(*args,**kwargs):
            result=issue(*args,**kwargs)
            if threading.current_thread() is not main_thread:
                ready.set()
                if not publish.wait(20):raise RuntimeError("prepare publication was never released")
            return result
        def observe_clock_and_interrupt():
            actual=clock()
            if threading.current_thread() is not main_thread:
                worker_times.append(actual)
            elif runtime._active:
                publish.set()
                # A real prepared image is ready, but its publication must
                # wait until this startup transaction has rolled back.
                if finished.wait(.02):raise AssertionError("prepare interleaved with startup rollback")
                raise KeyboardInterrupt("interrupt while prepare waits to publish")
            return actual
        def worker():
            try:values["token"]=runtime.prepare(programs()[1])
            except BaseException as exc:values["error"]=exc
            finally:finished.set()
        with patch("hepta.hia_adaptive._issue",side_effect=pause_after_real_proof), \
                patch("hepta.hia_queue_commit.time.monotonic_ns",side_effect=observe_clock_and_interrupt):
            thread=threading.Thread(target=worker)
            thread.start()
            try:
                self.assertTrue(ready.wait(20),values)
                with self.assertRaises(KeyboardInterrupt):runtime.execute_committed(token)
            finally:
                publish.set()
                thread.join(20)
        self.assertFalse(thread.is_alive())
        self.assertNotIn("error",values)
        self.assertIn(values["token"],runtime._images)
        self.assertEqual(runtime._active,0)
        self.assertEqual(runtime.queue_status(token)["status"],"submitted")
        self.assertGreaterEqual(runtime._unamortized_preparation_ns,
                                original_debt+worker_times[-1]-worker_times[0])
        self.assertEqual(runtime.snapshot()["event_counts"]["prepared"],1)
        self.assertEqual(runtime.execute_committed(token)["executed_steps"],5)


if __name__ == "__main__":unittest.main()
