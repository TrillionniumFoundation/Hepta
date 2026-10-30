"""Concurrent caller mutations must not cross the adaptive scalar boundary.

These tests run the real argument/dispatch methods with Python call spies.
They qualify capture, checking and dispatch wiring, not a native compiler,
loader, machine-code backend, or atomic capture of all nested caller lists.
"""
from __future__ import annotations

import inspect
import sys
import threading
from types import SimpleNamespace
import unittest
from unittest import mock

from hepta import hia_adaptive as adaptive


class AdaptiveArgumentSnapshotTests(unittest.TestCase):
    def runtime(self):
        runtime = object.__new__(adaptive.AdaptiveRuntime)
        runtime._lock = threading.RLock()
        runtime._closed = False
        runtime._current = "baseline"
        runtime._generation = runtime._active = runtime._calls = runtime._shadow_calls = 0
        runtime._identity = "argument-boundary-fixture"
        runtime._measurements = {}
        calls, events = [], []

        def invoke(*arguments):
            calls.append(arguments)
            return sum(arguments)

        state = {"params": [{"name": "value", "type": "u64"}], "entry": "transition"}
        runtime._images = {
            name: SimpleNamespace(state=state, function=invoke, preparation_ns=0,
                                  artifact_sha256=letter * 64)
            for name, letter in (("baseline", "a"), ("candidate", "b"))
        }
        runtime._event = lambda kind, **fields: events.append((kind, fields))
        return runtime, calls, events

    def mutate_at_boundary(self, action, marker, mutation):
        """Schedule a real producer thread at one observed check/use boundary.

        A line trace only controls interleaving. It does not replace validation,
        mutate its locals, or provide a checked result to production methods.
        """
        target = adaptive.AdaptiveRuntime._arguments.__code__
        source, first = inspect.getsourcelines(adaptive.AdaptiveRuntime._arguments)
        targets = [first + offset for offset, line in enumerate(source) if marker in line]
        self.assertEqual(len(targets), 1, "one real argument boundary must be observed")
        ready, done = threading.Event(), threading.Event()
        errors = []

        def producer():
            if not ready.wait(5):
                errors.append(AssertionError("argument boundary was not reached"))
                done.set()
                return
            try:
                mutation()
            except BaseException as error:
                errors.append(error)
            finally:
                done.set()

        worker = threading.Thread(target=producer)
        worker.start()
        reached = False

        def trace(frame, event, argument):
            nonlocal reached
            if (not reached and frame.f_code is target and event == "line"
                    and frame.f_lineno == targets[0]):
                reached = True
                ready.set()
                if not done.wait(5):
                    raise AssertionError("producer did not finish its controlled mutation")
                if errors:
                    raise errors[0]
            return trace

        previous = sys.gettrace()
        try:
            sys.settrace(trace)
            return action()
        finally:
            sys.settrace(previous)
            ready.set()
            worker.join(5)
            self.assertFalse(worker.is_alive(), "mutation worker must be joined")
            self.assertTrue(reached, "the production boundary must actually execute")
            if errors:
                raise errors[0]

    def test_post_check_scalar_mutation_cannot_reach_dispatch(self):
        for replacement in (2**64, -1, True):
            with self.subTest(replacement=replacement):
                runtime, calls, events = self.runtime()
                row = [7]
                result = self.mutate_at_boundary(
                    lambda: runtime.call_many([row]), "copied.append(",
                    lambda: row.__setitem__(0, replacement))
                self.assertEqual(result, [7])
                self.assertEqual(calls, [(7,)])
                self.assertIs(type(calls[0][0]), int)
                self.assertEqual(runtime._active, 0)
                self.assertEqual(runtime._calls, 1)
                self.assertEqual(events[-1][1]["replayed_calls"], 0)

    def test_post_check_row_growth_cannot_change_arity(self):
        runtime, calls, _events = self.runtime()
        row = [7]
        result = self.mutate_at_boundary(
            lambda: runtime.call_many([row]), "copied.append(",
            lambda: row.append(99))
        self.assertEqual(result, [7])
        self.assertEqual(calls, [(7,)])

    def test_post_check_mutation_cannot_enter_either_measurement_arm(self):
        runtime, calls, _events = self.runtime()
        row = [7]
        with mock.patch.object(adaptive, "_identity", return_value=runtime._identity):
            result = self.mutate_at_boundary(
                lambda: runtime.measure("candidate", [row]), "copied.append(",
                lambda: row.__setitem__(0, 2**64))
        self.assertEqual(calls, [(7,), (7,)])
        self.assertEqual(result["pairs"], 1)
        self.assertEqual(runtime._shadow_calls, 2)
        self.assertEqual(runtime._active, 0)

    def test_batch_growth_after_capture_does_not_add_dispatches(self):
        runtime, calls, _events = self.runtime()
        vectors = [[7]]
        with mock.patch.object(adaptive, "_MAX_BATCH", 3):
            result = self.mutate_at_boundary(
                lambda: runtime.call_many(vectors), "copied = []",
                lambda: vectors.extend([[8], [9], [10]]))
        self.assertEqual(result, [7])
        self.assertEqual(calls, [(7,)])

    def test_growth_before_batch_capture_rejects_before_dispatch(self):
        runtime, calls, _events = self.runtime()
        vectors = [[7]]
        source = inspect.getsource(adaptive.AdaptiveRuntime._arguments)
        # The historical implementation had no immutable capture; the retained
        # counterexample is scheduled just after its initial length check.
        marker = "frozen = tuple(vectors[" if "frozen = tuple(vectors[" in source else "copied = []"
        with mock.patch.object(adaptive, "_MAX_BATCH", 3):
            with self.assertRaisesRegex(adaptive.AdaptiveRejected, "bounded nonempty"):
                self.mutate_at_boundary(
                    lambda: runtime.call_many(vectors), marker,
                    lambda: vectors.extend([[8], [9], [10]]))
        self.assertEqual(calls, [])
        self.assertEqual(runtime._calls, 0)
        self.assertEqual(runtime._active, 0)

    def test_row_growth_before_capture_is_rejected(self):
        runtime, calls, _events = self.runtime()
        row = [7]
        source = inspect.getsource(adaptive.AdaptiveRuntime._arguments)
        marker = "args = tuple(args[" if "args = tuple(args[" in source else "if (type(args)"
        with self.assertRaisesRegex(adaptive.AdaptiveRejected, "exact u64"):
            self.mutate_at_boundary(
                lambda: runtime.call_many([row]), marker, lambda: row.append(8))
        self.assertEqual(calls, [])

    def test_invalid_inputs_never_reach_dispatch(self):
        for vectors in ([], (), ((7,),), [[True]], [[-1]], [[2**64]],
                        [[1.0]], [["7"]], [[]], [[7, 8]], [object()]):
            with self.subTest(vectors=repr(vectors)):
                runtime, calls, _events = self.runtime()
                with self.assertRaises(adaptive.AdaptiveRejected):
                    runtime.call_many(vectors)
                self.assertEqual(calls, [])
                self.assertEqual(runtime._active, 0)
        runtime, calls, _events = self.runtime()
        with mock.patch.object(adaptive, "_MAX_BATCH", 3):
            with self.assertRaises(adaptive.AdaptiveRejected):
                runtime.call_many([[1], [2], [3], [4]])
        self.assertEqual(calls, [])

    def test_captured_rows_are_detached_and_exact_boundaries_survive(self):
        row = [0, 2**64 - 1]
        vectors = [row]
        frozen = adaptive.AdaptiveRuntime._arguments(vectors, 2)
        row[:] = [True]
        vectors.clear()
        self.assertEqual(frozen, [(0, 2**64 - 1)])
        self.assertTrue(all(type(value) is int for value in frozen[0]))


if __name__ == "__main__":
    unittest.main()
