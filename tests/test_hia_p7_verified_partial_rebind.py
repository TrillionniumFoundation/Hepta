"""P7 bounded continuation rebind across one verified native image switch.

The test owner below exercises deterministic admission logic only. Native
prefix/suffix correctness is separately mandatory via test_hia_continuation.
No durable journal or external-effect exactly-once claim follows.
"""
from __future__ import annotations

from collections import Counter, deque
from types import SimpleNamespace
import unittest

from hepta.hia_adaptive import AdaptiveRejected
from tests.test_hia_stateful_queue_capture import fake_runtime


class PartialGenerationRebindTests(unittest.TestCase):
    def _owner(self, *, executed=1, switches=1, current="next"):
        runtime = fake_runtime()
        runtime._active = 0
        runtime._loans = {}
        runtime._state = object()
        runtime._allocation_address = 17
        runtime._driver = SimpleNamespace(hs_identity=lambda state: 17)
        runtime._event_count = 0
        runtime._event_counts = Counter()
        runtime._events = deque(maxlen=16)
        runtime._event = lambda *args, **kwargs: None
        runtime._current = "baseline"
        parent = runtime.submit_queue([{"slot": 0, "delta": 2, "iterations": 3}])
        row = runtime._queues[parent]
        row["status"] = "cancelled"
        if executed:
            row["version"] = "baseline"
            row["receipt"] = {
                "schema": "hepta.hia.owned-queue-execution.v1",
                "version": "baseline",
                "status": "cancelled",
                "executed_steps": executed,
                "final_values": [11, 17],
            }
            runtime._revision = executed
        runtime._generation = switches
        runtime._current = current
        return runtime, parent

    def test_actual_prefix_one_verified_switch_registers_only_suffix(self):
        runtime, parent = self._owner()
        child = runtime.continue_queue(parent)
        self.assertEqual(runtime._queues[child]["items"][0].iterations, 2)
        self.assertEqual(runtime._queues[child]["generation"], 1)
        self.assertEqual(runtime._queues[child]["continuation"]["parent_execution_generation"], 0)
        self.assertTrue(runtime._queues[child]["continuation"]["rebound_after_verified_image_switch"])
        self.assertEqual(runtime._queues[parent]["continued_by"], child)
        with self.assertRaises(AdaptiveRejected):
            runtime.continue_queue(parent)

    def test_cancelled_unexecuted_queue_never_inherits_new_generation(self):
        runtime, parent = self._owner(executed=0)
        with self.assertRaisesRegex(AdaptiveRejected, "E_STATE_FENCE"):
            runtime.continue_queue(parent)
        self.assertEqual(len(runtime._queues), 1)

    def test_two_version_switches_deny_old_prefix(self):
        runtime, parent = self._owner(switches=2)
        with self.assertRaisesRegex(AdaptiveRejected, "E_STATE_FENCE"):
            runtime.continue_queue(parent)

    def test_same_image_generation_bump_is_not_version_rebind(self):
        runtime, parent = self._owner(current="baseline")
        with self.assertRaisesRegex(AdaptiveRejected, "E_STATE_FENCE"):
            runtime.continue_queue(parent)

    def test_mismatched_execution_receipt_version_cannot_rebind(self):
        runtime, parent = self._owner()
        runtime._queues[parent]["receipt"]["version"] = "other"
        with self.assertRaisesRegex(AdaptiveRejected, "E_STATE_FENCE"):
            runtime.continue_queue(parent)

    def test_partial_receipt_requires_exact_owner_revision(self):
        runtime, parent = self._owner()
        runtime._revision += 1
        with self.assertRaisesRegex(AdaptiveRejected, "E_STATE_STALE"):
            runtime.continue_queue(parent)

    def test_partial_receipt_requires_identical_native_state(self):
        runtime, parent = self._owner()
        runtime._values = lambda: (19, 17)
        with self.assertRaisesRegex(AdaptiveRejected, "E_STATE_STALE"):
            runtime.continue_queue(parent)


if __name__ == "__main__":
    unittest.main()
