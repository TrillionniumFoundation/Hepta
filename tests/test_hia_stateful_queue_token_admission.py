"""P7: reject attacker-controlled queue tokens before any dictionary hash/equality.

Native execution remains unchanged. The first three tests exercise the actual
owner methods against a minimal live-owner fixture; one uses a genuine native
Clang20/Z3 owner to ensure legitimate opaque token flow still works.
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


class HostileToken:
    def __init__(self):
        self.hash_calls = 0
        self.eq_calls = 0

    def __hash__(self):
        self.hash_calls += 1
        raise AssertionError("untrusted token hash ran inside owner lock")

    def __eq__(self, _):
        self.eq_calls += 1
        raise AssertionError("untrusted token comparison ran inside owner lock")


class StringSubclassToken(str):
    def __hash__(self):
        raise AssertionError("str subclass hash was used")


class QueueTokenAdmissionTests(unittest.TestCase):
    def routes(self, owner, token):
        return (
            lambda: owner.cancel(token),
            lambda: owner.queue_status(token),
            lambda: owner.execute_committed(token),
            lambda: owner.audit_counterfactual(token),
            lambda: owner.continue_queue(token),
        )

    def test_no_untrusted_hash_or_equality_on_any_external_route(self):
        owner = fake_runtime()
        owner._generation = 0
        for create_token in (HostileToken, lambda: StringSubclassToken("unexpected")):
            for route_index in range(5):
                hostile = create_token()
                with self.subTest(token=type(hostile).__name__, route=route_index):
                    with self.assertRaisesRegex(AdaptiveRejected, "E_STATE_TOKEN"):
                        self.routes(owner, hostile)[route_index]()
                    self.assertEqual(getattr(hostile, "hash_calls", 0), 0)
                    self.assertEqual(getattr(hostile, "eq_calls", 0), 0)
                    self.assertEqual(owner._queues, {})

    def test_oversized_and_invalid_token_shapes_reject_before_lookup(self):
        owner = fake_runtime()
        owner._generation = 0
        for value in (None, [], {}, 7, True, b"token", "", "x"*65,
                      "\u6d77"*40, "\x00", "\u00e9", "\u000a"):
            for route_index in range(5):
                with self.subTest(value=type(value).__name__, route=route_index):
                    with self.assertRaisesRegex(AdaptiveRejected, "E_STATE_TOKEN"):
                        self.routes(owner, value)[route_index]()
                    self.assertEqual(owner._queues, {})

    def test_valid_legacy_short_internal_token_still_observable_and_cancellable(self):
        owner = fake_runtime()
        owner._generation = 0
        token = owner.submit_queue([{"slot": 0, "delta": 2, "iterations": 3}])
        self.assertEqual(owner.queue_status(token)["status"], "submitted")
        owner.cancel(token)
        self.assertEqual(owner.queue_status(token)["status"], "cancelled")

    def test_actual_native_queue_token_still_executes_under_generation_fence(self):
        with tempfile.TemporaryDirectory(prefix="hia-p7-token-native-") as tmp:
            base, _ = programs()
            owner = OwnedAdaptiveRuntime(base, Path(tmp)/"native", [11,17],
                    clang=os.environ.get("CLANG", "/usr/bin/clang-20"))
            try:
                token = owner.submit_queue([{"slot": 0, "delta": 2, "iterations": 3}])
                self.assertEqual(len(token), 32)
                result = owner.execute_committed(token)
                self.assertEqual(result["status"], "completed")
                self.assertEqual(result["final_values"], [35,17])
                self.assertEqual(owner.queue_status(token)["status"], "completed")
            finally:
                owner.close()


if __name__ == "__main__":
    unittest.main()
