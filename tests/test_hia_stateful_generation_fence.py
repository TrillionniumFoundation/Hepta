"""P7: queued work must bind the exact owner generation until activation.

Real Linux C-owned cells and sealed native HIA version switches. A queue
registered before a version switch cannot execute or continue on the new
generation simply because the data owner and revision are unchanged.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest

from hepta.hia_adaptive import AdaptiveRejected
from hepta.hia_stateful import OwnedAdaptiveRuntime
from tools.qualify_hia_stateful import programs


class QueueGenerationFenceTests(unittest.TestCase):
    def make_runtime(self, directory):
        base, candidate = programs()
        runtime = OwnedAdaptiveRuntime(
            base, directory / "native", [11, 17],
            clang=os.environ.get("CLANG", "/usr/bin/clang-20"))
        return runtime, candidate

    def test_old_immutable_wire_queue_cannot_execute_after_real_version_switch(self):
        with tempfile.TemporaryDirectory(prefix="hia-p7-queue-fence-") as tmp:
            runtime, candidate = self.make_runtime(Path(tmp))
            try:
                image = runtime.prepare(candidate)
                registered_generation = runtime._generation
                original = tuple(runtime.snapshot()["state_values"])
                wire = json.dumps({
                    "schema": "hepta.hia.owner-queue-wire.v1",
                    "owner_id": runtime._owner_id,
                    "generation": registered_generation,
                    "revision": runtime._revision,
                    "items": [{"slot": 0, "delta": 3, "iterations": 2}],
                }, sort_keys=True, separators=(",", ":")).encode()
                queue = runtime.submit_queue_wire(wire)["token"]
                self.assertTrue(runtime.select(image, mode="explicit")["selected"])
                self.assertGreater(runtime._generation, registered_generation)
                self.assertEqual(runtime._revision, 0)
                with self.assertRaisesRegex(AdaptiveRejected, "E_STATE_FENCE"):
                    runtime.execute_committed(queue)
                self.assertEqual(runtime.queue_status(queue)["status"], "stale")
                self.assertEqual(tuple(runtime.snapshot()["state_values"]), original)
                self.assertEqual(runtime.snapshot()["actual_progress"], 0)
            finally:
                runtime.close()

    def test_cancelled_queue_cannot_continue_across_native_generation_cutover(self):
        with tempfile.TemporaryDirectory(prefix="hia-p7-cont-fence-") as tmp:
            runtime, candidate = self.make_runtime(Path(tmp))
            try:
                image = runtime.prepare(candidate)
                queue = runtime.submit_queue([
                    {"slot": 1, "delta": 4, "iterations": 3}])
                original = tuple(runtime.snapshot()["state_values"])
                runtime.cancel(queue)
                self.assertEqual(runtime.queue_status(queue)["status"], "cancelled")
                self.assertTrue(runtime.select(image, mode="explicit")["selected"])
                before = len(runtime._queues)
                with self.assertRaisesRegex(AdaptiveRejected, "E_STATE_FENCE"):
                    runtime.continue_queue(queue)
                self.assertEqual(len(runtime._queues), before)
                self.assertEqual(tuple(runtime.snapshot()["state_values"]), original)
                self.assertNotIn("continued_by", runtime._queues[queue])
            finally:
                runtime.close()

    def test_same_generation_still_executes_the_real_native_queue(self):
        with tempfile.TemporaryDirectory(prefix="hia-p7-valid-fence-") as tmp:
            runtime, _ = self.make_runtime(Path(tmp))
            try:
                generation = runtime._generation
                queue = runtime.submit_queue([
                    {"slot": 0, "delta": 2, "iterations": 3}])
                self.assertEqual(runtime._queues[queue].get("generation"), generation)
                outcome = runtime.execute_committed(queue)
                self.assertEqual(outcome["executed_steps"], 3)
                self.assertEqual(outcome["status"], "completed")
                self.assertEqual(runtime.snapshot()["state_values"], [35, 17])
                self.assertEqual(runtime.queue_status(queue)["status"], "completed")
            finally:
                runtime.close()


if __name__ == "__main__":
    unittest.main()
