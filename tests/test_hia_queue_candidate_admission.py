"""P7: queued candidate image labels must be bounded before any native-image mapping access.

An already captured queue can be submitted with a caller-chosen optional
candidate.  These tests cover the actual public commit path (not a separate
synthetic verifier), then run the original Clang20 native optimization owner.
They do NOT demonstrate restart, journal durability or release authority.
"""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from hepta.hia_adaptive import AdaptiveRejected
from hepta.hia_stateful import OwnedAdaptiveRuntime
from tests.test_hia_stateful_queue_capture import fake_runtime
from tools.qualify_hia_stateful import programs


class _CandidateMap(dict):
    def __init__(self):
        super().__init__(baseline=object())
        self.lookups = []

    def __contains__(self, key):
        self.lookups.append(key)
        if type(key) is str and (
            len(key) > 64 or not key.isascii() or not key.isprintable()
        ):
            raise AssertionError(
                "unbounded/untrusted candidate reached native image dictionary"
            )
        return super().__contains__(key)


def _captured_owner():
    # Retain the actual submit/execute/plan methods and the owner lock.
    # A fake native driver is not used to certify any native execution.
    runtime = fake_runtime()
    runtime._current = "baseline"
    runtime._images = _CandidateMap()
    runtime._active = 0
    runtime._loans = {}
    runtime._event = lambda *args, **kwargs: None
    token = runtime.submit_queue([{"slot": 0, "delta": 2, "iterations": 3}])
    return runtime, token


class CandidateAdmissionControls(unittest.TestCase):
    def test_overlong_builtin_candidate_does_not_reach_image_map(self):
        runtime, token = _captured_owner()
        initial_cost = runtime._unamortized_preparation_ns
        with self.assertRaises(AdaptiveRejected):
            runtime.execute_committed(token, candidate="x" * 100000)
        self.assertEqual(runtime._images.lookups, [])
        self.assertEqual(runtime.queue_status(token)["status"], "submitted")
        self.assertEqual(runtime._values(), (11, 17))
        # Existing transaction charges failed planning, not a zero-cost reject.
        self.assertGreater(runtime._unamortized_preparation_ns, initial_cost)

    def test_unicode_and_control_candidate_reject_before_mapping(self):
        for candidate in ("\u6d77\u6d77", "bad\nkey", "\x00", "x" * 65):
            with self.subTest(candidate=repr(candidate)):
                runtime, token = _captured_owner()
                with self.assertRaises(AdaptiveRejected):
                    runtime.execute_committed(token, candidate=candidate)
                self.assertEqual(runtime._images.lookups, [])
                self.assertEqual(runtime.queue_status(token)["status"], "submitted")

    def test_nonbuiltins_reject_without_dunder_callbacks(self):
        class Dangerous(str):
            def __hash__(self):
                raise AssertionError("caller-controlled candidate hash invoked")

        for candidate in (Dangerous("baseline"), object(), {"verified": True}):
            runtime, token = _captured_owner()
            with self.subTest(candidate=type(candidate).__name__):
                with self.assertRaises(AdaptiveRejected):
                    runtime.execute_committed(token, candidate=candidate)
                self.assertEqual(runtime._images.lookups, [])
                self.assertEqual(runtime.queue_status(token)["status"], "submitted")

    def test_valid_bounded_unknown_candidate_preserves_rejection_contract(self):
        runtime, token = _captured_owner()
        with self.assertRaisesRegex(AdaptiveRejected, "E_STATE_AUTHORITY"):
            runtime.execute_committed(token, candidate="a" * 32)
        self.assertEqual(runtime._images.lookups, ["a" * 32])
        self.assertEqual(runtime.queue_status(token)["status"], "submitted")


class NativeCandidateControl(unittest.TestCase):
    def test_real_pinned_native_candidate_still_settles_cost_and_progress(self):
        with tempfile.TemporaryDirectory(prefix="hia-candidate-native-") as tmp:
            base, proposed = programs()
            runtime = OwnedAdaptiveRuntime(
                base, Path(tmp) / "owner", [11, 17],
                clang=os.environ.get("CLANG", "/usr/bin/clang-20")
            )
            try:
                prepared = runtime.prepare(proposed)
                self.assertEqual(len(prepared), 32)
                token = runtime.submit_queue([
                    {"slot": 0, "delta": 2, "iterations": 3}
                ])
                receipt = runtime.execute_committed(
                    token, candidate=prepared, rounds=1, sample_limit=2
                )
                self.assertEqual(receipt["status"], "completed")
                self.assertEqual(receipt["executed_steps"], 3)
                self.assertEqual(receipt["final_values"], [35, 17])
                self.assertTrue(receipt["cost_accounting_complete"])
                self.assertGreater(receipt["deployment_cost_ns"], 0)
            finally:
                runtime.close()


if __name__ == "__main__":
    unittest.main()
