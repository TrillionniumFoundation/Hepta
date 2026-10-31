"""P7 adversarial native regression: interrupted clone work cannot certify a complete sample.

The owner and cloned C allocations are real; only the native driver's observable
early-return result is injected after actual first-item native progress. No
timing data or synthetic cost is used as a production/optimization claim.
"""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from hepta.hia_adaptive import AdaptiveRejected
from hepta.hia_stateful import OwnedAdaptiveRuntime
from tools.qualify_hia_stateful import programs


class InterruptedCloneRuntime(OwnedAdaptiveRuntime):
    """Force a partial *clone* execution while preserving real native work."""

    def _apply_items(self, state, items, image):
        if getattr(self, "_interrupt_clones", False) and state != self._state:
            if len(items) < 2:
                raise AssertionError("native interruption test requires two requested work items")
            completed_first = super()._apply_items(state, items[:1], image)
            if completed_first is not True:
                raise AssertionError("genuine first native clone work did not complete")
            self._interrupted_clones += 1
            # hs_apply=0 is a real interruption/partial-work outcome. Do not
            # fabricate progress or claim that the second native item ran.
            return False
        return super()._apply_items(state, items, image)


class HIACloneIncompleteTests(unittest.TestCase):
    def runtime(self, directory):
        base, _ = programs()
        runtime = InterruptedCloneRuntime(
            base, directory, [11, 17],
            clang=os.environ.get("CLANG", "/usr/bin/clang-20"))
        runtime._interrupt_clones = False
        runtime._interrupted_clones = 0
        return runtime

    def test_partial_native_calibration_clone_must_not_admit_sample(self):
        with tempfile.TemporaryDirectory(prefix="hia-partial-cal-") as directory:
            runtime = self.runtime(Path(directory) / "owned")
            try:
                _, proposed = programs()
                candidate = runtime.prepare(proposed)
                token = runtime.submit_queue([
                    {"slot": 0, "delta": 2, "iterations": 3},
                    {"slot": 1, "delta": 3, "iterations": 2},
                ])
                original = runtime.snapshot()["state_values"]
                live_before = runtime._ledger()["live"]
                runtime._interrupt_clones = True
                try:
                    with self.assertRaisesRegex(AdaptiveRejected, "incomplete native calibration"):
                        runtime._calibrate(runtime._queues[token], candidate,
                                           rounds=3, sample_limit=10000)
                finally:
                    runtime._interrupt_clones = False
                self.assertGreater(runtime._interrupted_clones, 0)
                self.assertEqual(runtime._ledger()["live"], live_before)
                self.assertEqual(runtime.snapshot()["state_values"], original)
                self.assertEqual(runtime.queue_status(token)["status"], "submitted")
            finally:
                runtime.close()

    def test_partial_native_audit_clone_must_not_certify_counterfactual(self):
        with tempfile.TemporaryDirectory(prefix="hia-partial-audit-") as directory:
            runtime = self.runtime(Path(directory) / "owned")
            try:
                token = runtime.submit_queue([
                    {"slot": 0, "delta": 2, "iterations": 3},
                    # Deliberately no-op: a truncated clone can have the SAME
                    # final values despite not completing committed work.
                    {"slot": 1, "delta": 0, "iterations": 2},
                ])
                receipt = runtime.execute_committed(token)
                self.assertEqual(receipt["executed_steps"], 5)
                live_before = runtime._ledger()["live"]
                state_before = runtime.snapshot()["state_values"]
                runtime._interrupt_clones = True
                try:
                    with self.assertRaisesRegex(AdaptiveRejected, "incomplete native counterfactual"):
                        runtime.audit_counterfactual(token)
                finally:
                    runtime._interrupt_clones = False
                self.assertGreater(runtime._interrupted_clones, 0)
                self.assertEqual(runtime._ledger()["live"], live_before)
                self.assertEqual(runtime.snapshot()["state_values"], state_before)
                self.assertNotIn("counterfactual_audit", runtime._queues[token])
            finally:
                runtime.close()


if __name__ == "__main__":
    unittest.main()
