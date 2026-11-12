"""Producer races at real native scalar/owner admission boundaries.

The producer thread mutates only caller-owned containers. Line tracing controls
the interleaving; verification, compilation, sealed loading, function pointers,
native owner allocation and queue execution remain the production operations.
Existing adaptive/stateful qualification covers active-call, alias and retirement
gates; this suite targets the newly fixed bounded-input capture obligations.
"""
from __future__ import annotations

import copy
import ctypes
import importlib.util
import inspect
import os
from pathlib import Path
import platform
import shutil
import tempfile
import unittest

from hepta.hia_adaptive import AdaptiveRejected, AdaptiveRuntime
from hepta.hia_program import verify_program
from hepta.hia_stateful import OwnedAdaptiveRuntime
from tests import test_hia_adaptive_arguments as argument_tests
from tools.qualify_hia_adaptive import programs


CLANG = os.environ.get("CLANG", "/usr/bin/clang-20")
NATIVE = (platform.system() == "Linux"
          and platform.machine().lower() in {"x86_64", "amd64"}
          and shutil.which(CLANG) and hasattr(os, "memfd_create")
          and importlib.util.find_spec("z3") is not None)


@unittest.skipUnless(NATIVE, "Pinned Z3, native Clang20 and Linux seals required")
class NativeInputSnapshotTests(unittest.TestCase):
    # Reuse the scheduling helper, without inheriting or rerunning its spy suite.
    mutate_at_boundary = argument_tests.AdaptiveArgumentSnapshotTests.mutate_at_boundary

    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="hia-native-input-snapshot-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

    def runtime(self, *, owned=False):
        base, _ = programs()
        if owned:
            base["functions"][0]["name"] = "transition"
        cls = OwnedAdaptiveRuntime if owned else AdaptiveRuntime
        args = (base, self.root / "runtime", [11, 17]) if owned else (base, self.root / "runtime")
        runtime = cls(*args, clang=CLANG)
        self.addCleanup(runtime.close)
        self.assertIsInstance(runtime._images["baseline"].function, ctypes._CFuncPtr)
        return runtime

    def test_checked_argument_snapshot_reaches_actual_native_code(self):
        runtime = self.runtime()
        function = runtime._images["baseline"].function
        for replacement in (2**64, -1, True):
            with self.subTest(replacement=replacement):
                row = [7, 2]
                result = self.mutate_at_boundary(
                    lambda: runtime.call_many([row]), "copied.append(",
                    lambda: row.__setitem__(0, replacement))
                self.assertEqual(result, [9])
                self.assertEqual(row[0], replacement)
                self.assertIs(runtime._images["baseline"].function, function)
        snapshot = runtime.snapshot()
        self.assertEqual(snapshot["completed_native_calls"], 3)
        self.assertEqual(snapshot["active_calls"], 0)

    def test_initial_owner_growth_is_rejected_before_any_build(self):
        base, _ = programs()
        values = [11]
        path = self.root / "overgrown-owner"
        source = inspect.getsource(OwnedAdaptiveRuntime.__init__)
        marker = ("values = tuple(values[" if "values = tuple(values[" in source
                  else "values = tuple(_u64(value)")
        with self.assertRaisesRegex(AdaptiveRejected, "E_STATE_SIZE"):
            self.mutate_at_boundary(
                lambda: OwnedAdaptiveRuntime(base, path, values, clang=CLANG), marker,
                lambda: values.extend([17] * 65536), method=OwnedAdaptiveRuntime.__init__)
        self.assertFalse(path.exists(), "an overlength input must not start native preparation")

    def test_initial_owner_uses_captured_cells_after_producer_mutation(self):
        base, _ = programs()
        values = [11, 17]

        def mutate():
            values[1] = True
            values.extend([23] * 65536)

        runtime = self.mutate_at_boundary(
            lambda: OwnedAdaptiveRuntime(base, self.root / "captured-owner", values, clang=CLANG),
            "values = tuple(_u64(value)", mutate, method=OwnedAdaptiveRuntime.__init__)
        self.addCleanup(runtime.close)
        snapshot = runtime.snapshot()
        self.assertEqual(snapshot["owner_state_schema"]["cells"], 2)
        self.assertEqual(snapshot["state_values"], [11, 17])
        self.assertEqual(snapshot["native_ledger"]["live"], 2)
        runtime.close()
        closed = runtime.snapshot()
        self.assertEqual(closed["native_ledger"]["live"], 0)
        self.assertEqual(closed["native_ledger"]["allocations"],
                         closed["native_ledger"]["frees"])

    def test_growth_after_queue_capture_cannot_add_native_work(self):
        runtime = self.runtime(owned=True)
        items = [{"slot": 0, "delta": 2, "iterations": 1}]
        queue = self.mutate_at_boundary(
            lambda: runtime.submit_queue(items), "work = []",
            lambda: items.extend([{"slot": 0, "delta": 2, "iterations": 1}] * 128),
            method=OwnedAdaptiveRuntime.submit_queue)
        self.assertEqual(len(items), 129)
        result = runtime.execute_committed(queue)
        self.assertEqual(result["executed_steps"], 1)
        self.assertEqual(result["final_values"], [13, 17])
        self.assertEqual(result["replayed_steps"], 0)
        self.assertEqual(len(result["item_progress"]), 1)

    def test_growth_before_queue_capture_cannot_be_admitted(self):
        runtime = self.runtime(owned=True)
        items = [{"slot": 0, "delta": 2, "iterations": 1}]
        source = inspect.getsource(OwnedAdaptiveRuntime.submit_queue)
        marker = ("items = tuple(items[" if "items = tuple(items[" in source
                  else "with self._lock:")
        before = runtime.snapshot()
        with self.assertRaisesRegex(AdaptiveRejected, "one to 128"):
            self.mutate_at_boundary(
                lambda: runtime.submit_queue(items), marker,
                lambda: items.extend([{"slot": 0, "delta": 2, "iterations": 1}] * 128),
                method=OwnedAdaptiveRuntime.submit_queue)
        self.assertEqual(runtime._queues, {})
        after = runtime.snapshot()
        self.assertEqual(after["state_values"], before["state_values"])
        self.assertEqual(after["native_ledger"], before["native_ledger"])

    def test_hidden_effectful_helper_cannot_enter_an_owned_native_version(self):
        runtime = self.runtime(owned=True)
        base, _ = programs()
        base["functions"][0]["name"] = "transition"
        effectful = copy.deepcopy(base)
        helper = copy.deepcopy(base["functions"][0])
        helper["name"] = "hidden_checked_helper"
        helper["effects"] = ["trap"]
        helper["blocks"][0]["ops"][-1]["op"] = "int.add.checked"
        effectful["functions"].append(helper)
        # Valid Core can still exceed the adaptive profile's effect contract.
        verify_program(effectful)
        before = runtime.snapshot()
        artifacts = set(runtime._root.glob("*.so"))
        with self.assertRaisesRegex(AdaptiveRejected, "E_STATE_PROFILE"):
            runtime.prepare(effectful)
        after = runtime.snapshot()
        self.assertEqual(after["native_images"], before["native_images"])
        self.assertEqual(after["state_values"], before["state_values"])
        self.assertEqual(after["allocation_identity"], before["allocation_identity"])
        self.assertEqual(set(runtime._root.glob("*.so")), artifacts)


if __name__ == "__main__":
    unittest.main()
