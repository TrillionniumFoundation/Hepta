"""P7: source-owned queue JSON must be detached before checked values are used."""
from __future__ import annotations

from hashlib import sha256
import threading
import unittest
from unittest.mock import patch

import hepta.hia_stateful as stateful
from hepta.hia_adaptive import AdaptiveRejected
from hepta.hia_stateful import OwnedAdaptiveRuntime, _Work, _snapshot_queue_work_item


def fake_runtime():
    # Test exactly the real submit_queue intake and digest/record path without
    # replacing the native runtime with fake execution/performance evidence.
    runtime = object.__new__(OwnedAdaptiveRuntime)
    runtime._lock = threading.RLock()
    runtime._state_open = lambda: None
    runtime._queues = {}
    runtime._revision = 0
    runtime._generation = 0
    runtime._owner_id = "frozen-owner"
    runtime._size = 2
    runtime._values = lambda: (11, 17)
    runtime._unamortized_preparation_ns = 0
    return runtime


class HIAQueueIntakeTests(unittest.TestCase):
    def test_exact_three_field_capture_and_independence(self):
        original = {"slot": 1, "delta": 3, "iterations": 5}
        frozen = _snapshot_queue_work_item(original)
        original["slot"] = 999
        original.clear()
        self.assertEqual(frozen, (1, 3, 5))

    def test_legacy_check_use_mutation_cannot_change_frozen_work_or_digest(self):
        runtime = fake_runtime()
        original = {"slot": 0, "delta": 2, "iterations": 3}
        capture = stateful._snapshot_queue_work_item
        def mutate_after_capture(item):
            frozen = capture(item)
            item.clear()
            return frozen
        with patch.object(stateful, "_snapshot_queue_work_item",
                          side_effect=mutate_after_capture):
            token = runtime.submit_queue([original])
        self.assertEqual(original, {})
        self.assertEqual(runtime._queues[token]["items"], (_Work(0, 2, 3),))
        self.assertEqual(runtime._queues[token]["initial_values"], (11, 17))
        self.assertEqual(runtime.queue_status(token)["queue_sha256"],
                         sha256(b'[{"delta":2,"iterations":3,"slot":0}]').hexdigest())

    def test_bad_shapes_types_and_overbudget_fail_without_queue(self):
        for item in (
            {"slot": 0, "delta": 1},
            {"slot": 0, "delta": 1, "iterations": 3, "late": 1},
            {"slot": 0, "delta": 1, "iterations": 3, "extra": 1},
            {"slot": 0, "delta": 1, "iterations": 0},
            {"slot": 2, "delta": 1, "iterations": 1},
            {"slot": 0, "delta": True, "iterations": 1},
            {"slot": 0, "delta": 1, "iterations": True},
            {"slot": 0, "delta": 1 << 65, "iterations": 1},
            {"slot": 0, "delta": 1, "iterations": -1},
            {"slot": 0, "delta": 1, "iterations": 1, 5: 3},
            42,
        ):
            runtime = fake_runtime()
            with self.subTest(item=repr(item)), self.assertRaises(AdaptiveRejected):
                runtime.submit_queue([item])
            self.assertEqual(runtime._queues, {})
        runtime = fake_runtime()
        with self.assertRaises(AdaptiveRejected):
            runtime.submit_queue([
                {"slot": 0, "delta": 1, "iterations": 600_000_000},
                {"slot": 0, "delta": 1, "iterations": 600_000_000},
            ])
        self.assertEqual(runtime._queues, {})

    def test_mutable_subclasses_and_oversize_outer_list_reject(self):
        class Borrowed(dict): pass
        for items in (
            [{"slot": 0, "delta": 1, "iterations": 3}] * 129,
            [{"slot": 0, "delta": 1, "iterations": 3}, Borrowed(
                slot=0, delta=1, iterations=3)],
        ):
            runtime = fake_runtime()
            with self.assertRaises(AdaptiveRejected):
                runtime.submit_queue(items)
            self.assertEqual(runtime._queues, {})


if __name__ == "__main__":
    unittest.main()
