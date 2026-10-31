"""P7 red/green: duplicated random loan tokens must not resurrect stale handles.

This exercises production OwnedAdaptiveRuntime.borrow/_access/_end_loan with
bounded fake owner cells. It does not simulate physical performance or native
compiler refinement; real pinned-Clang owner tests are separate.
"""
from __future__ import annotations

from types import SimpleNamespace
import threading
import unittest
from unittest.mock import patch

import hepta.hia_stateful as stateful
from hepta.hia_adaptive import AdaptiveRejected
from hepta.hia_stateful import OwnedAdaptiveRuntime


def bounded_runtime():
    runtime = object.__new__(OwnedAdaptiveRuntime)
    runtime._lock = threading.RLock()
    runtime._state_open = lambda: None
    runtime._loans = {}
    runtime._loan_epoch = 0
    runtime._active = 0
    runtime._generation = 7
    runtime._owner_id = "pinned-owner"
    runtime._size = 2
    runtime._revision = 0
    runtime._state = object()
    runtime._event = lambda *a, **kw: None
    cells = [11, 17]
    def read(_pointer, slot):
        return cells[slot]
    def write(_pointer, slot, value):
        cells[slot] = value
    runtime._driver = SimpleNamespace(hs_read=read, hs_write=write)
    return runtime, cells


class HIALoanEpochFenceTests(unittest.TestCase):
    def test_active_shared_token_collision_refuses_without_clobber(self):
        runtime, _ = bounded_runtime()
        with patch.object(stateful.secrets, "token_hex", return_value="reused"):
            first = runtime.borrow()
            prior = runtime._loans.copy()
            with self.assertRaisesRegex(AdaptiveRejected, "collision"):
                runtime.borrow()
            self.assertEqual(runtime._loans, prior)
            self.assertEqual(first.read(0), 11)
            first.close()
            self.assertEqual(runtime._loans, {})

    def test_stale_handle_cannot_revive_on_reissued_random_token(self):
        runtime, cells = bounded_runtime()
        with patch.object(stateful.secrets, "token_hex", return_value="same"):
            previous = runtime.borrow(mutable=True)
            previous.write(0, 37)
            previous.close()
            current = runtime.borrow(mutable=True)
            with self.assertRaisesRegex(AdaptiveRejected, "STALE_LOAN"):
                previous.read(0)
            with self.assertRaisesRegex(AdaptiveRejected, "STALE_LOAN"):
                previous.write(1, 999)
            previous.close()
            self.assertEqual(current.read(0), 37)
            current.write(1, 23)
            current.close()
            self.assertEqual(cells, [37, 23])
            self.assertEqual(runtime._loans, {})

    def test_concurrent_distinct_shared_handles_remain_independent(self):
        runtime, _ = bounded_runtime()
        with patch.object(stateful.secrets, "token_hex", side_effect=("token-a", "token-b")):
            first = runtime.borrow()
            second = runtime.borrow()
            first.close()
            self.assertEqual(second.read(1), 17)
            second.close()
        self.assertEqual(runtime._loans, {})

    def test_old_generation_and_exclusive_mutation_rules_still_hold(self):
        runtime, cells = bounded_runtime()
        with runtime.borrow(mutable=True) as exclusive:
            exclusive.write(0, 99)
            with self.assertRaises(AdaptiveRejected):
                runtime.borrow()
        old = runtime.borrow()
        runtime._generation += 1
        with self.assertRaisesRegex(AdaptiveRejected, "STALE_LOAN"):
            old.read(0)
        old.close()
        self.assertEqual(runtime._loans, {})
        self.assertEqual(cells, [99, 17])


if __name__ == "__main__":
    unittest.main()
