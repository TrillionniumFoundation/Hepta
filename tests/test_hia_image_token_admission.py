"""P7 negative controls: caller-owned version/mode objects never reach locks or maps.

These are deterministic Python boundary tests, not native safety or recovery proof.
The actual image dispatch remains separately qualified by pinned host workflows.
"""
from __future__ import annotations

import threading
import unittest

from hepta.hia_adaptive import AdaptiveRejected, AdaptiveRuntime
from hepta.hia_stateful import OwnedAdaptiveRuntime


class _HostileComparison:
    def __init__(self):
        self.calls = 0

    def __eq__(self, other):
        self.calls += 1
        raise AssertionError("caller-controlled __eq__ executed under owner lock")


class _HostileHash:
    def __init__(self):
        self.calls = 0

    def __hash__(self):
        self.calls += 1
        raise AssertionError("caller-controlled __hash__ reached image dictionary")


class _ProbeImages(dict):
    def __init__(self):
        super().__init__(baseline=object())
        self.lookups = 0

    def __contains__(self, token):
        self.lookups += 1
        if type(token) is str and len(token) > 64:
            raise AssertionError("overlong token was hashed before admission")
        return super().__contains__(token)


def _base_runtime():
    runtime = object.__new__(AdaptiveRuntime)
    runtime._lock = threading.RLock()
    runtime._closed = False
    runtime._images = _ProbeImages()
    runtime._current = "baseline"
    runtime._active = 0
    return runtime


def _owned_runtime():
    runtime = object.__new__(OwnedAdaptiveRuntime)
    runtime._lock = threading.RLock()
    runtime._state_open = lambda: None
    runtime._open = lambda: None
    runtime._loans = {}
    runtime._active = 0
    runtime._images = _ProbeImages()
    runtime._current = "baseline"
    runtime._unamortized_preparation_ns = 0
    return runtime


class NativeImageAdmissionTests(unittest.TestCase):
    def test_owned_selection_rejects_hostile_mode_without_calling_equality(self):
        runtime = _owned_runtime()
        hostile = _HostileComparison()
        with self.assertRaises(AdaptiveRejected):
            runtime.select("baseline", mode=hostile)
        self.assertEqual(hostile.calls, 0)
        self.assertEqual(runtime._images.lookups, 0)

    def test_live_loan_does_not_hide_invalid_selection_mode(self):
        runtime = _owned_runtime()
        runtime._loans = {"some-live-loan": {"mutable": False}}
        with self.assertRaises(AdaptiveRejected):
            runtime.select("baseline", mode=object())
        self.assertEqual(runtime._images.lookups, 0)

    def test_rollback_helper_rejects_untrusted_hash_before_lookup(self):
        runtime = _owned_runtime()
        hostile = _HostileHash()
        with self.assertRaises(AdaptiveRejected):
            runtime._restore_admitted(hostile)
        self.assertEqual(hostile.calls, 0)
        self.assertEqual(runtime._images.lookups, 0)

    def test_base_selection_never_hashes_overlong_token(self):
        runtime = _base_runtime()
        with self.assertRaises(AdaptiveRejected):
            runtime.select("x" * 100000, mode="explicit")
        self.assertEqual(runtime._images.lookups, 0)

    def test_base_measurement_never_hashes_overlong_token(self):
        runtime = _base_runtime()
        with self.assertRaises(AdaptiveRejected):
            runtime.measure("x" * 100000, [[1]])
        self.assertEqual(runtime._images.lookups, 0)

    def test_owned_selection_rejects_non_ascii_and_str_subclasses(self):
        runtime = _owned_runtime()
        class Derived(str):
            pass
        for bad in (Derived("baseline"), "错误", "x" * 65, ""):
            with self.subTest(type=type(bad).__name__, length=len(bad)):
                with self.assertRaises(AdaptiveRejected):
                    runtime.select(bad, mode="explicit")
        self.assertEqual(runtime._images.lookups, 0)

    def test_existing_real_tokens_are_within_admitted_domain(self):
        from hepta.hia_adaptive import _version_token, _selection_mode
        for token in ("baseline", "a" * 32):
            self.assertEqual(_version_token(token), token)
        self.assertEqual(_selection_mode("auto"), "auto")
        self.assertEqual(_selection_mode("explicit"), "explicit")


if __name__ == "__main__":
    unittest.main()
