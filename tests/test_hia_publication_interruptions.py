"""Real native ownership and bounded worker settlement under injected failure.

The fault sites simulate host interruption; synthetic ranking costs are only
used to reach publication. Verification, proof, compilation, loading, native
calls and retirement remain real. No speedup or async-unwind proof is claimed.
"""
from __future__ import annotations

from concurrent.futures import wait
import os
import tempfile
import threading
import unittest
from unittest.mock import patch

from hepta.hia_background_optimizer import BackgroundOptimizationRejected, BackgroundOptimizer
from hepta.hia_multiversion import PublicationCancellation, ScalarMultiversionRuntime
from tests.test_hia_background_optimizer import controlled_rank, measurements, objective, proposal
from tests.test_hia_multiversion import _CLANG, _NATIVE, scalar_program


def fd_open(fd):
    try:
        os.fstat(fd)
        return True
    except OSError:
        return False


@unittest.skipUnless(_NATIVE, "actual Clang, Z3 and Linux sealed native loading are required")
class NativeInterruptionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="hia-publication-interruption-")
        self.addCleanup(self.directory.cleanup)
        self.baseline = scalar_program()
        self.runtime = ScalarMultiversionRuntime(self.baseline, self.directory.name, clang=_CLANG)
        self.prepared = []
        self.addCleanup(self.cleanup_native)

    def cleanup_native(self):
        # Cleanup-only recovery keeps a future regression from double-closing
        # an already diagnosed stale entry. Assertions precede this recovery.
        for state in self.prepared:
            registered = self.runtime._states.get(state.info.generation) is state
            opened = fd_open(state.fd)
            if registered and not opened:
                self.runtime._states.pop(state.info.generation)
            elif not registered and opened:
                self.runtime._dispose(state.info.generation, state.library, state.functions,
                    state.fd, state.artifact, state.inode, state.identity_pin,
                    cause="test_failure_cleanup")
        self.runtime.close()

    def capture_prepare(self):
        prepare = self.runtime._prepare
        def capture(*args, **kwargs):
            state = prepare(*args, **kwargs)
            self.prepared.append(state)
            return state
        return patch.object(self.runtime, "_prepare", side_effect=capture)

    def publish(self, conditional, token):
        if conditional:
            return self.runtime.publish_if_current(scalar_program(None), 0, expected_epoch=0,
                max_prepare_ns=5_000_000_000, cancellation=token)
        return self.runtime.publish(scalar_program(None))

    def interrupted_registration(self, *, conditional, after):
        class InterruptedInsert(dict):
            def __setitem__(self, key, value):
                if key != 0:
                    if after:
                        super().__setitem__(key, value)
                    raise KeyboardInterrupt("injected image registration interruption")
                super().__setitem__(key, value)
        self.runtime._states = InterruptedInsert(self.runtime._states)
        token = PublicationCancellation()
        with self.capture_prepare(), self.assertRaises(KeyboardInterrupt):
            self.publish(conditional, token)
        state = self.prepared[-1]
        snapshot = self.runtime.snapshot()
        self.assertEqual(snapshot["current_generation"], 0)
        self.assertEqual(snapshot["selection_epoch"], 0)
        self.assertEqual([row["generation"] for row in snapshot["generations"]], [0])
        self.assertFalse(fd_open(state.fd))
        self.assertFalse(state.artifact.exists())
        self.assertEqual(state.functions, {})
        self.assertFalse(token.committed())
        self.assertTrue(token.cancel())
        self.assertEqual(snapshot["cleanup"]["pending_resource_count"], 0)
        self.assertEqual(self.runtime.call("calculate", [2**64 - 1]), 2**64 - 1)

    def test_plain_failure_before_registration_releases_prepared_image(self):
        self.interrupted_registration(conditional=False, after=False)

    def test_plain_failure_after_insertion_rolls_back_owner_transfer(self):
        self.interrupted_registration(conditional=False, after=True)

    def test_conditional_failure_before_registration_does_not_commit(self):
        self.interrupted_registration(conditional=True, after=False)

    def test_conditional_failure_after_insertion_does_not_leave_released_entry(self):
        self.interrupted_registration(conditional=True, after=True)

    def interrupted_commit_return(self, conditional):
        token = PublicationCancellation()
        commit = self.runtime._commit_prepared
        def after_commit(*args, **kwargs):
            commit(*args, **kwargs)
            raise KeyboardInterrupt("injected interruption after actual commit")
        with self.capture_prepare(), patch.object(self.runtime, "_commit_prepared", side_effect=after_commit), \
                self.assertRaises(KeyboardInterrupt):
            self.publish(conditional, token)
        state = self.prepared[-1]
        self.assertEqual(self.runtime.snapshot()["current_generation"], state.info.generation)
        self.assertEqual(self.runtime.snapshot()["selection_epoch"], 1)
        self.assertTrue(fd_open(state.fd))
        self.assertTrue(state.artifact.exists())
        if conditional:
            self.assertTrue(token.committed())
            self.assertFalse(token.cancel())
        for value in (0, 1, 2**63, 2**64 - 1):
            self.assertEqual(self.runtime.call("calculate", [value]), value)
        self.runtime.close()
        self.assertFalse(fd_open(state.fd))
        self.assertEqual(self.runtime.snapshot()["cleanup"]["pending_resource_count"], 0)

    def test_plain_postcommit_interruption_preserves_runtime_owner(self):
        self.interrupted_commit_return(False)

    def test_conditional_postcommit_interruption_cannot_cancel_or_unload(self):
        self.interrupted_commit_return(True)

    def test_retirement_return_interruption_never_recloses_a_reused_descriptor(self):
        first = self.runtime.publish(scalar_program(None))
        old = self.runtime._states[first.generation]
        release = self.runtime._attempt_cleanup
        def after_release(task):
            release(task)
            if task.generation == first.generation:
                raise KeyboardInterrupt("injected return after actual retirement")
        with patch.object(self.runtime, "_attempt_cleanup", side_effect=after_release), \
                self.assertRaises(KeyboardInterrupt):
            self.runtime.publish(scalar_program("bit.xor"))
        snapshot = self.runtime.snapshot()
        self.assertEqual(snapshot["current_generation"], 2)
        self.assertNotIn(first.generation, self.runtime._states)
        self.assertFalse(fd_open(old.fd))
        self.assertEqual(snapshot["cleanup"]["pending_resource_count"], 0)
        replacement = os.open(os.devnull, os.O_RDONLY)
        if replacement != old.fd:
            os.dup2(replacement, old.fd)
            os.close(replacement)
        try:
            self.assertEqual(self.runtime.call("calculate", [101]), 101)
            self.runtime.close()
            self.runtime.retry_cleanup()
            self.assertTrue(fd_open(old.fd))
        finally:
            if fd_open(old.fd):
                os.close(old.fd)

    def test_retirement_interrupted_before_release_keeps_one_deferred_owner(self):
        first = self.runtime.publish(scalar_program(None))
        old = self.runtime._states[first.generation]
        release = self.runtime._attempt_cleanup
        def before_release(task):
            if task.generation == first.generation:
                raise KeyboardInterrupt("injected before first retirement attempt")
            return release(task)
        with patch.object(self.runtime, "_attempt_cleanup", side_effect=before_release), \
                self.assertRaises(KeyboardInterrupt):
            self.runtime.publish(scalar_program("bit.xor"))
        self.assertNotIn(first.generation, self.runtime._states)
        task = self.runtime._cleanup_pending[first.generation]
        self.assertFalse(task.native_attempted)
        self.assertTrue(fd_open(old.fd))
        self.assertEqual(self.runtime.snapshot()["current_generation"], 2)
        self.runtime.retry_cleanup()
        self.assertTrue(task.native_attempted)
        self.assertFalse(fd_open(old.fd))
        self.assertEqual(self.runtime.snapshot()["cleanup"]["pending_resource_count"], 0)
        self.assertEqual(self.runtime.call("calculate", [103]), 103)

    def test_retry_completes_interrupted_retirement_registration_before_release(self):
        first = self.runtime.publish(scalar_program(None))
        old = self.runtime._states[first.generation]
        register = self.runtime._retirement_task
        def after_register(*args, **kwargs):
            task = register(*args, **kwargs)
            if task.generation == first.generation:
                raise KeyboardInterrupt("injected after retirement owner registration")
            return task
        with patch.object(self.runtime, "_retirement_task", side_effect=after_register), \
                self.assertRaises(KeyboardInterrupt):
            self.runtime.publish(scalar_program("bit.xor"))
        self.assertIn(first.generation, self.runtime._states)
        self.assertIn(first.generation, self.runtime._cleanup_pending)
        self.assertTrue(fd_open(old.fd))
        self.runtime.retry_cleanup()
        self.assertNotIn(first.generation, self.runtime._states)
        self.assertNotIn(first.generation, self.runtime._cleanup_pending)
        self.assertFalse(fd_open(old.fd))
        replacement = os.open(os.devnull, os.O_RDONLY)
        if replacement != old.fd:
            os.dup2(replacement, old.fd)
            os.close(replacement)
        try:
            self.assertEqual(self.runtime.call("calculate", [109]), 109)
            self.runtime.close()
            self.assertTrue(fd_open(old.fd))
        finally:
            if fd_open(old.fd):
                os.close(old.fd)

    def test_interrupted_close_attempts_other_images_and_can_finish_later(self):
        published = self.runtime.publish(scalar_program(None))
        candidate = self.runtime._states[published.generation]
        collect = self.runtime._collect
        def interrupt_baseline(state):
            if state.info.generation == 0:
                raise KeyboardInterrupt("injected before baseline retirement")
            return collect(state)
        with patch.object(self.runtime, "_collect", side_effect=interrupt_baseline), \
                self.assertRaises(KeyboardInterrupt):
            self.runtime.close()
        self.assertTrue(self.runtime.snapshot()["closed"])
        self.assertEqual(set(self.runtime._states), {0})
        self.assertFalse(fd_open(candidate.fd))
        self.runtime.close()
        self.assertEqual(self.runtime.snapshot()["generations"], [])
        self.assertEqual(self.runtime.snapshot()["cleanup"]["pending_resource_count"], 0)

    def coordinator(self, **options):
        coordinator = BackgroundOptimizer(self.runtime, self.baseline, function="calculate",
            bridge={"binary": "/unused/lifecycle-test", "build_receipt": "/unused/lifecycle-test"},
            **options)
        self.addCleanup(coordinator.shutdown)
        return coordinator

    def submit(self, coordinator):
        candidates = proposal()
        return coordinator.submit(candidates, measurements(self.baseline, candidates), objective())

    def assert_closed_worker(self, coordinator, futures):
        self.assertEqual(wait(futures, timeout=10).done, set(futures))
        coordinator.shutdown(cancel_pending=False)
        snapshot = coordinator.snapshot()
        self.assertTrue(snapshot["closed"])
        self.assertFalse(snapshot["worker_alive"])
        self.assertEqual(snapshot["outstanding"], 0)
        self.assertEqual(snapshot["queued"], 0)
        with self.assertRaisesRegex(BackgroundOptimizationRejected, "shut down"):
            self.submit(coordinator)
        return snapshot

    def test_worker_interruption_settles_active_and_queued_futures(self):
        coordinator = self.coordinator()
        entered, release = threading.Event(), threading.Event()
        def fail(*args, **kwargs):
            entered.set()
            self.assertTrue(release.wait(10))
            raise KeyboardInterrupt("injected optimizer interruption")
        with patch("hepta.hia_background_optimizer.rank_candidates", side_effect=fail) as rank:
            first = self.submit(coordinator)
            try:
                self.assertTrue(entered.wait(10))
                second = self.submit(coordinator)
            finally:
                release.set()
            snapshot = self.assert_closed_worker(coordinator, [first, second])
        self.assertEqual(rank.call_count, 1)
        for future in (first, second):
            result = future.result()
            self.assertEqual(result["status"], "rejected")
            self.assertFalse(result["publication_committed"])
        self.assertEqual(snapshot["worker_failure"]["type"], "KeyboardInterrupt")
        snapshot["worker_failure"]["type"] = "forged"
        self.assertEqual(coordinator.snapshot()["worker_failure"]["type"], "KeyboardInterrupt")
        self.assertEqual(self.runtime.snapshot()["current_generation"], 0)
        self.assertEqual(self.runtime.call("calculate", [79]), 79)

    def test_postcommit_worker_failure_reports_committed_selection_without_replay(self):
        coordinator = self.coordinator()
        entered, release = threading.Event(), threading.Event()
        publish = self.runtime.publish_if_current
        def after_publish(*args, **kwargs):
            entered.set()
            self.assertTrue(release.wait(10))
            publish(*args, **kwargs)
            raise RuntimeError("injected return failure after commit")
        with patch("hepta.hia_background_optimizer.rank_candidates", side_effect=controlled_rank) as rank, \
                patch.object(self.runtime, "publish_if_current", side_effect=after_publish):
            first = self.submit(coordinator)
            try:
                self.assertTrue(entered.wait(10))
                second = self.submit(coordinator)
            finally:
                release.set()
            self.assert_closed_worker(coordinator, [first, second])
        self.assertEqual(rank.call_count, 1)
        result = first.result()
        self.assertEqual(result["status"], "interrupted")
        self.assertTrue(result["publication_committed"])
        self.assertIsNone(result["selected_id"])
        self.assertFalse(first.cancel())
        self.assertEqual(second.result()["status"], "rejected")
        self.assertFalse(second.result()["publication_committed"])
        self.assertEqual(self.runtime.snapshot()["current_generation"], 1)
        self.assertEqual(self.runtime.call("calculate", [83]), 83)

    def test_completion_callback_interruption_cannot_strand_other_jobs(self):
        coordinator = self.coordinator()
        entered, release = threading.Event(), threading.Event()
        def delayed(*args, **kwargs):
            entered.set()
            self.assertTrue(release.wait(10))
            return controlled_rank(*args, **kwargs)
        def failed_callback(done):
            raise SystemExit("injected completion callback exit")
        with patch("hepta.hia_background_optimizer.rank_candidates", side_effect=delayed) as rank:
            first = self.submit(coordinator)
            try:
                self.assertTrue(entered.wait(10))
                first.add_done_callback(failed_callback)
                second, third = self.submit(coordinator), self.submit(coordinator)
                second.add_done_callback(failed_callback)
            finally:
                release.set()
            snapshot = self.assert_closed_worker(coordinator, [first, second, third])
        self.assertEqual(rank.call_count, 1)
        self.assertEqual(first.result()["status"], "published")
        self.assertEqual(second.result()["status"], "rejected")
        self.assertEqual(third.result()["status"], "rejected")
        self.assertEqual(snapshot["worker_failure"]["phase"], "complete")
        self.assertEqual(snapshot["worker_failure"]["completion_callback_failures"], 1)
        self.assertEqual(self.runtime.call("calculate", [89]), 89)

    def test_shutdown_attempts_all_cancellations_before_propagating_callback_exit(self):
        coordinator = self.coordinator()
        entered, release = threading.Event(), threading.Event()
        def delayed(*args, **kwargs):
            entered.set()
            self.assertTrue(release.wait(10))
            return controlled_rank(*args, **kwargs)
        def failed_callback(done):
            raise SystemExit("injected cancel callback exit")
        with patch("hepta.hia_background_optimizer.rank_candidates", side_effect=delayed) as rank:
            first = self.submit(coordinator)
            try:
                self.assertTrue(entered.wait(10))
                first.add_done_callback(failed_callback)
                second, third = self.submit(coordinator), self.submit(coordinator)
                with self.assertRaisesRegex(SystemExit, "cancel callback"):
                    coordinator.shutdown(wait=False)
                self.assertTrue(all(f.cancelled() for f in (first, second, third)))
            finally:
                release.set()
            self.assert_closed_worker(coordinator, [first, second, third])
        self.assertEqual(rank.call_count, 1)
        self.assertEqual(self.runtime.snapshot()["current_generation"], 0)
        self.assertEqual(self.runtime.call("calculate", [97]), 97)

    def test_token_cancel_interruption_before_future_transition_cannot_strand_job(self):
        coordinator = self.coordinator()
        entered, release = threading.Event(), threading.Event()
        def delayed(*args, **kwargs):
            entered.set()
            self.assertTrue(release.wait(10))
            return controlled_rank(*args, **kwargs)
        with patch("hepta.hia_background_optimizer.rank_candidates", side_effect=delayed) as rank:
            first = self.submit(coordinator)
            try:
                self.assertTrue(entered.wait(10))
                second = self.submit(coordinator)
                token = second._publication_cancellation
                cancel = token.cancel
                def interrupted_cancel():
                    cancel()
                    raise KeyboardInterrupt("injected after token cancellation")
                with patch.object(token, "cancel", side_effect=interrupted_cancel):
                    with self.assertRaises(KeyboardInterrupt):
                        second.cancel()
                self.assertTrue(token.cancelled())
                self.assertFalse(second.done())
                first.cancel()
            finally:
                release.set()
            self.assert_closed_worker(coordinator, [first, second])
        self.assertEqual(rank.call_count, 1)
        self.assertTrue(first.cancelled())
        self.assertTrue(second.cancelled())
        self.assertEqual(self.runtime.snapshot()["current_generation"], 0)
        self.assertEqual(self.runtime.call("calculate", [107]), 107)


if __name__ == "__main__":
    unittest.main()
