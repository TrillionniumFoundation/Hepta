"""P7: a queued operation must retain its owner *generation* until activation.

These regressions exercise the original owned queue, immutable wire, native
execution and cancelled continuation paths. Bounded fake-owner tests are
security admission controls, not a claim of native runtime qualification;
the separate pinned Clang20+Z3 test performs real owner work.
"""
from __future__ import annotations

from collections import Counter, deque
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest

from hepta.hia_adaptive import AdaptiveRejected
from hepta.hia_stateful import OwnedAdaptiveRuntime
from tests.test_hia_stateful_queue_capture import fake_runtime
from tools.qualify_hia_stateful import programs


WORK = [{"slot": 0, "delta": 2, "iterations": 3}]


def bounded_owner():
    runtime = fake_runtime()
    runtime._generation = 7
    runtime._active = 0
    runtime._loans = {}
    runtime._state = object()
    runtime._allocation_address = 41
    runtime._driver = SimpleNamespace(hs_identity=lambda unused: 41)
    runtime._event = lambda *args, **kwargs: None
    runtime._event_count = 0
    runtime._event_counts = Counter()
    runtime._events = deque(maxlen=16)

    def forbidden_plan(*args, **kwargs):
        raise AssertionError("a stale-generation queue reached candidate selection")
    runtime._plan_queue = forbidden_plan
    return runtime


class GenerationAdmissionTests(unittest.TestCase):
    def test_mutable_queue_rejects_generation_switch_without_state_mutation(self):
        runtime = bounded_owner()
        token = runtime.submit_queue(WORK)
        self.assertEqual(runtime._queues[token]["revision"], runtime._revision)
        runtime._generation += 1
        with self.assertRaisesRegex(AdaptiveRejected, "E_STATE_STALE"):
            runtime.execute_committed(token)
        self.assertEqual(runtime.queue_status(token)["status"], "stale")
        self.assertEqual(len(runtime._queues), 1)
        self.assertEqual(runtime._values(), (11, 17))

    def test_immutable_wire_does_not_authorize_later_generation(self):
        runtime = bounded_owner()
        wire = json.dumps({
            "schema": "hepta.hia.owner-queue-wire.v1",
            "owner_id": runtime._owner_id,
            "generation": runtime._generation,
            "revision": runtime._revision,
            "items": WORK,
        }, sort_keys=True, separators=(",", ":")).encode("utf-8")
        admission = runtime.submit_queue_wire(wire)
        self.assertEqual(admission["generation"], 7)
        runtime._generation = 8
        with self.assertRaisesRegex(AdaptiveRejected, "E_STATE_STALE"):
            runtime.execute_committed(admission["token"])
        self.assertEqual(runtime.queue_status(admission["token"])["status"], "stale")
        self.assertEqual(runtime._values(), (11, 17))

    def test_cancelled_queue_refuses_suffix_after_generation_switch(self):
        runtime = bounded_owner()
        token = runtime.submit_queue(WORK)
        runtime.cancel(token)
        runtime._generation += 1
        with self.assertRaisesRegex(AdaptiveRejected, "E_STATE_STALE"):
            runtime.continue_queue(token)
        self.assertEqual(len(runtime._queues), 1)
        self.assertEqual(runtime.queue_status(token)["status"], "cancelled")

    def test_live_cancelled_continuation_inherits_generation_fence(self):
        runtime = bounded_owner()
        parent = runtime.submit_queue(WORK)
        runtime.cancel(parent)
        child = runtime.continue_queue(parent)
        self.assertEqual(runtime._queues[child]["generation"], runtime._generation)
        self.assertEqual(runtime.queue_status(parent)["continued_by"], child)
        runtime._generation += 1
        with self.assertRaisesRegex(AdaptiveRejected, "E_STATE_STALE"):
            runtime.execute_committed(child)
        self.assertEqual(runtime.queue_status(child)["status"], "stale")


class NativeGenerationFenceTests(unittest.TestCase):
    def test_real_clang_owner_stale_queue_and_fresh_queue(self):
        # This is mandatory in pinned native CI, not a skip on missing tools.
        with tempfile.TemporaryDirectory(prefix="hia-generation-native-") as directory:
            base, proposed = programs()
            runtime = OwnedAdaptiveRuntime(
                base, Path(directory) / "owned", [11, 17],
                clang=os.environ.get("CLANG", "/usr/bin/clang-20"))
            try:
                old = runtime.submit_queue(WORK)
                original = runtime.snapshot()["state_values"]
                admitted_generation = runtime._generation
                candidate = runtime.prepare(proposed)
                result = runtime.select(candidate, mode="explicit")
                self.assertTrue(result["selected"], result)
                self.assertGreater(runtime._generation, admitted_generation)
                self.assertEqual(runtime.snapshot()["state_values"], original)
                with self.assertRaisesRegex(AdaptiveRejected, "E_STATE_STALE"):
                    runtime.execute_committed(old)
                self.assertEqual(runtime.queue_status(old)["status"], "stale")
                self.assertEqual(runtime.snapshot()["state_values"], original)
                fresh = runtime.submit_queue(WORK)
                receipt = runtime.execute_committed(fresh)
                self.assertEqual(receipt["executed_steps"], 3)
                self.assertEqual(receipt["replayed_steps"], 0)
                self.assertEqual(runtime.queue_status(fresh)["status"], "completed")
                self.assertNotEqual(receipt["final_values"], original)
            finally:
                runtime.close()


if __name__ == "__main__":
    unittest.main()
