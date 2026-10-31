"""Real exclusive state, leases, committed queues and finite pure transitions."""
from __future__ import annotations
import copy
import json
from collections import Counter, deque
import errno
import fcntl
from hashlib import sha256
import importlib.util
import os
from pathlib import Path
import shutil
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from hepta.hia_adaptive import AdaptiveRejected
from hepta.hia_stateful import OwnedAdaptiveRuntime, _Work
from tools.qualify_hia_stateful import programs, qualify, measure_fresh_deployment

CLANG = os.environ.get("CLANG", "/usr/bin/clang-20")
NATIVE = (sys.platform == "linux" and shutil.which(CLANG) and hasattr(os, "memfd_create")
          and importlib.util.find_spec("z3") is not None)
# Missing Python seal constants do not justify skipping the actual Linux
# runtime. Its fixed-UAPI sealing and loaded-mapping checks must pass readback.

class OwnedProfileTests(unittest.TestCase):
    def test_near_zero_cost_policy_charges_commit_before_restore_decision(self):
        # A deterministic accounting boundary test, deliberately separate from
        # native qualification. No mocked timing is performance evidence.
        runtime = object.__new__(OwnedAdaptiveRuntime)
        runtime._lock = threading.RLock()
        runtime._state_open = lambda: None
        runtime._queues = {"q": {"status": "submitted", "revision": 0, "generation": 0,
                                  "owner": "o", "items": (_Work(0, 0, 1),), "sha256": "x"}}
        runtime._revision = runtime._active = runtime._calls = 0
        runtime._generation = 0
        runtime._owner_id, runtime._allocation_identity = "o", "a"
        runtime._loans = {}
        runtime._unamortized_preparation_ns = runtime._cumulative_deployment_cost_ns = 0
        runtime._current, runtime._state = "candidate", 1
        runtime._images = {"candidate": object()}
        runtime._driver = SimpleNamespace(hs_reset=lambda state: None, hs_progress=lambda state: 1)
        runtime._plan_queue = lambda *args, **kw: ("baseline", {"baseline_estimate_ns": 25}, True, "test")
        runtime._apply_items = lambda *args: True
        runtime._values, runtime._ledger = lambda: (0,), lambda: {}
        runtime._event = lambda *args, **kw: None
        runtime._event_count, runtime._event_counts, runtime._events = 0, Counter(), deque(maxlen=4096)
        restored = []
        runtime._restore_admitted = lambda token: restored.append(token) or {"selected": True}
        with patch("hepta.hia_stateful.time.monotonic_ns", side_effect=[0, 10, 20, 30, 40, 60, 70, 80]):
            result = runtime.execute_committed("q")
        self.assertEqual(result["commit_bookkeeping_ns"], 20)
        self.assertEqual(restored, ["baseline"])
        self.assertTrue(result["restored_after_forecast_loss"])
        self.assertEqual(result["restoration_cost_ns"], 10)
        self.assertEqual(result["deployment_cost_ns"], 50)
        self.assertEqual(result["cumulative_deployment_cost_ns"], 50)
        self.assertEqual(result["observed_net_against_baseline_forecast_ns"], -25)

    def test_finite_total_helpers_admitted_but_traps_cycles_resources_refuse(self):
        base, _ = programs()
        runtime = object.__new__(OwnedAdaptiveRuntime)
        checked, state = runtime._admit_profile(base)
        self.assertEqual(checked.as_dict(), base)
        self.assertEqual(state["entry"], "transition")
        trap = copy.deepcopy(base)
        trap["functions"][0]["effects"] = ["trap"]
        trap["functions"][1]["effects"] = ["trap"]
        trap["functions"][0]["blocks"][0]["ops"][-1]["op"] = "int.add.checked"
        recursive = copy.deepcopy(base)
        recursive["functions"][1]["blocks"][0]["ops"][0]["attrs"]["function"] = "transition"
        from tests.test_hia_program import resource_program
        for bad in (trap, recursive, resource_program()):
            with self.subTest(bad=bad["module"]), self.assertRaises(ValueError):
                runtime._admit_profile(bad)

@unittest.skipUnless(NATIVE, "Pinned Z3, native Clang20 and Linux seals required")
class OwnedNativeTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="hia-owned-test-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

    def runtime(self):
        base, _ = programs()
        runtime = OwnedAdaptiveRuntime(base, self.root / "runtime", [11, 17], clang=CLANG)
        self.addCleanup(runtime.close)
        return runtime


    def test_immutable_fenced_wire_executes_real_native_owner(self):
        runtime = self.runtime()
        envelope = {
            "schema": "hepta.hia.owner-queue-wire.v1",
            "owner_id": runtime._owner_id, "generation": runtime._generation,
            "revision": runtime._revision,
            "items": [{"slot": 0, "delta": 2, "iterations": 3}],
        }
        wire = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode()
        registration = runtime.submit_queue_wire(wire)
        self.assertEqual(registration["input_sha256"], sha256(wire).hexdigest())
        self.assertEqual(registration["authority"], "DENY_ALL")
        self.assertFalse(registration["durable_crash_recovery"])
        original = runtime.queue_status(registration["token"])
        result = runtime.execute_committed(registration["token"])
        self.assertEqual(result["executed_steps"], 3)
        self.assertEqual(result["queue_sha256"], original["queue_sha256"])
        self.assertEqual(result["final_values"], runtime.snapshot()["state_values"])
        self.assertEqual(runtime.queue_status(registration["token"])["status"], "completed")
        self.assertNotEqual(result["final_values"], [11, 17])

    def test_real_native_owner_uses_detached_work_even_after_producer_clears_dict(self):
        import hepta.hia_stateful as stateful
        runtime = self.runtime()
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
        expected_hash = sha256(b'[{"delta":2,"iterations":3,"slot":0}]').hexdigest()
        self.assertEqual(runtime.queue_status(token)["queue_sha256"], expected_hash)
        receipt = runtime.execute_committed(token)
        self.assertEqual(receipt["queue_sha256"], expected_hash)
        self.assertEqual(receipt["executed_steps"], 3)
        self.assertEqual(runtime.queue_status(token)["status"], "completed")
        self.assertEqual(receipt["final_values"], runtime.snapshot()["state_values"])

    def test_actual_ownership_switching_partial_native_cancel_and_negative_gain(self):
        report = qualify(self.root / "qualification", clang=CLANG)
        self.assertTrue(report["ok"], report.get("error"))
        self.assertTrue(all(report["controls"].values()))
        self.assertTrue(report["distinct_native_artifacts"])
        self.assertFalse(report["negative_gain_execution"]["automatic_selection"])
        self.assertLess(report["negative_gain_audit"]["measured_deployment_net_ns"], 0)
        self.assertGreater(report["partial_execution"]["executed_steps"], 0)
        self.assertLess(report["partial_execution"]["executed_steps"], 1_000_000_000)
        self.assertEqual(report["partial_execution"]["replayed_steps"], 0)
        self.assertEqual(report["final_native_ledger"]["live"], 0)
        self.assertEqual(len(report["admitted_native_images"]), 2)
        for retained in report["native_snapshots"].values():
            admitted = report["admitted_native_images"][retained["image_token"]]
            self.assertEqual(retained["loaded_mapping"], admitted["loaded_mapping"])
            self.assertEqual(retained["sha256"], admitted["artifact_sha256"])
            self.assertEqual(set(admitted["loaded_mapping"]["symbols"]), {"transition"})

    def test_whole_native_api_clock_keeps_audit_separate_and_retains_real_loss(self):
        measured = measure_fresh_deployment(self.root / "complete-wall", clang=CLANG, steps=1)
        wall = measured["outer_wall"]
        self.assertEqual(wall["total_experiment_wall_ns"], wall["finished_ns"] - wall["started_ns"])
        self.assertEqual(wall["whole_audit_api_ns"], wall["audit_finished_ns"] - wall["audit_started_ns"])
        self.assertEqual(wall["deployment_wall_ns"] + wall["whole_audit_api_ns"], wall["total_experiment_wall_ns"])
        self.assertGreaterEqual(wall["deployment_wall_ns"], measured["execution"]["deployment_cost_ns"])
        self.assertGreater(wall["additional_measured_overhead_ns"], 0)
        self.assertFalse(measured["deployment_net_positive"])
        self.assertLess(wall["measured_net_ns"], 0)
        self.assertEqual(measured["execution"]["executed_steps"], 1)
        self.assertEqual(measured["final_native_ledger"]["live"], 0)
        self.assertEqual(measured["final_native_ledger"]["allocations"], measured["final_native_ledger"]["frees"])
        self.assertEqual(len(measured["admitted_native_images"]), 2)

    def test_alias_modes_bounds_and_queue_staleness_are_real_state_gates(self):
        runtime = self.runtime()
        first, second = runtime.borrow(), runtime.borrow()
        try:
            self.assertEqual(first.read(0), 11)
            for action in (lambda: first.write(0, 5), lambda: first.read(-1), lambda: runtime.borrow(mutable=True)):
                with self.assertRaises(AdaptiveRejected):
                    action()
        finally:
            first.close(); second.close()
        queue = runtime.submit_queue([{"slot": 0, "delta": 1, "iterations": 4}])
        with runtime.borrow(mutable=True) as loan:
            loan.write(0, 19)
            with self.assertRaises(AdaptiveRejected):
                loan.write(0, None)
        with self.assertRaisesRegex(AdaptiveRejected, "owner changed"):
            runtime.execute_committed(queue)
        self.assertEqual(runtime.queue_status(queue)["status"], "stale")
        self.assertEqual(runtime.snapshot()["state_values"], [19, 17])
        with self.assertRaises(AdaptiveRejected):
            runtime.execute_committed(queue)
        snapshot = runtime.snapshot()
        snapshot["owner_state_schema"]["cells"] = 999
        self.assertEqual(runtime.snapshot()["owner_state_schema"]["cells"], 2)

    def test_native_loan_token_reuse_cannot_revive_stale_lease(self):
        # Exercise actual native owned cells and handles. A repeated RNG
        # output must not restore old read/write/close authority.
        import hepta.hia_stateful as stateful
        runtime = self.runtime()
        with patch.object(stateful.secrets, "token_hex", return_value="reissued-token"):
            former = runtime.borrow(mutable=True)
            former.write(0, 37)
            former.close()
            current = runtime.borrow(mutable=True)
            with self.assertRaisesRegex(AdaptiveRejected, "STALE_LOAN"):
                former.read(0)
            with self.assertRaisesRegex(AdaptiveRejected, "STALE_LOAN"):
                former.write(1, 999)
            former.close()
            self.assertEqual(current.read(0), 37)
            current.write(1, 23)
            current.close()
        self.assertEqual(runtime.snapshot()["state_values"], [37, 23])
        self.assertEqual(runtime.snapshot()["live_loans"], 0)

    def test_failed_preparation_producer_receipts_and_incompatible_schema_keep_owner(self):
        runtime = self.runtime()
        base, candidate = programs()
        changed = copy.deepcopy(candidate)
        changed["functions"][0]["blocks"][0]["ops"][0]["op"] = "int.sub.wrap"
        before = runtime.snapshot()
        with self.assertRaises(ValueError):
            runtime.prepare(changed)
        changed = copy.deepcopy(candidate)
        changed["functions"][0]["params"][0]["name"] = "other"
        with self.assertRaises(ValueError):
            runtime.prepare(changed)
        after = runtime.snapshot()
        self.assertEqual(before["allocation_identity"], after["allocation_identity"])
        self.assertEqual(after["state_values"], [11, 17])
        queue = runtime.submit_queue([{"slot": 0, "delta": 5, "iterations": 3}])
        before_failed_selection_cost = runtime._unamortized_preparation_ns
        with self.assertRaises(AdaptiveRejected):
            runtime.execute_committed(queue, candidate={"verified": True, "saving": 10**30})
        self.assertEqual(runtime.queue_status(queue)["status"], "submitted")
        self.assertGreater(runtime._unamortized_preparation_ns, before_failed_selection_cost)
        execution = runtime.execute_committed(queue)
        self.assertEqual(execution["final_values"], [71, 17])
        self.assertGreater(execution["unamortized_preparation_ns"], 0)
        observed = runtime.queue_status(queue)
        observed["receipt"]["executed_steps"] = 999
        self.assertEqual(runtime.queue_status(queue)["receipt"]["executed_steps"], 3)

    def test_sealed_images_and_admitted_rollback_preserve_actual_owner(self):
        runtime = self.runtime()
        _, candidate = programs()
        token = runtime.prepare(candidate)
        original = runtime.snapshot()
        image = runtime._images[token]
        image.artifact.write_bytes(b"changed publication path, not the admitted image")
        with self.assertRaises(OSError) as caught:
            os.write(image.fd, b"x")
        self.assertEqual(caught.exception.errno, errno.EPERM)
        self.assertTrue(runtime.select(token, mode="explicit")["selected"])
        queue = runtime.submit_queue([{"slot": 1, "delta": 3, "iterations": 5}])
        self.assertEqual(runtime.execute_committed(queue)["final_values"], [11, 77])
        with runtime._lock:
            restored = runtime._restore_admitted("baseline")
        self.assertTrue(restored["selected"])
        self.assertEqual(restored["authority"], "previously_admitted_sealed_image")
        queue = runtime.submit_queue([{"slot": 1, "delta": 7, "iterations": 3}])
        self.assertEqual(runtime.execute_committed(queue)["final_values"], [11, 161])
        self.assertEqual(runtime.snapshot()["allocation_identity"], original["allocation_identity"])

    def test_host_exception_after_real_native_progress_is_terminal_without_replay(self):
        class HostFault(OwnedAdaptiveRuntime):
            def _apply_items(self, state, items, image):
                if state == self._state:
                    # Inject a host exception only after the first work item
                    # actually ran and mutated the real native owner.
                    super()._apply_items(state, items[:1], image)
                    raise RuntimeError("injected host failure after native commit")
                return super()._apply_items(state, items, image)
        base, _ = programs()
        runtime = HostFault(base, self.root / "fault-runtime", [11, 17], clang=CLANG)
        self.addCleanup(runtime.close)
        queue = runtime.submit_queue([{"slot": 0, "delta": 3, "iterations": 2},
                                      {"slot": 1, "delta": 5, "iterations": 4}])
        with self.assertRaisesRegex(RuntimeError, "after native commit"):
            runtime.execute_committed(queue)
        receipt = runtime.queue_status(queue)["receipt"]
        self.assertEqual(receipt["status"], "failed")
        self.assertEqual(receipt["executed_steps"], 2)
        self.assertEqual(receipt["final_values"], [35, 17])
        self.assertEqual([row["committed"] for row in receipt["item_progress"]], [2, 0])
        with self.assertRaises(AdaptiveRejected):
            runtime.execute_committed(queue)
        self.assertEqual(runtime.snapshot()["state_values"], [35, 17])

    def test_queue_hash_binds_copied_work_after_producer_mutates_during_admission(self):
        import hepta.hia_stateful as stateful
        runtime = self.runtime()
        items = [{"slot": 0, "delta": 2, "iterations": 3}]
        real_token = stateful.secrets.token_hex
        def producer_mutation(count):
            # Token generation can yield to another thread. Exercise exactly
            # this copy/hash boundary; the actual native driver is unmodified.
            items[0]["iterations"] = 999
            return real_token(count)
        with patch.object(stateful.secrets, "token_hex", side_effect=producer_mutation):
            queue = runtime.submit_queue(items)
        digest = sha256(b'[{"delta":2,"iterations":3,"slot":0}]').hexdigest()
        self.assertEqual(runtime.queue_status(queue)["queue_sha256"], digest)
        result = runtime.execute_committed(queue)
        self.assertEqual(result["queue_sha256"], digest)
        self.assertEqual(result["executed_steps"], 3)
        self.assertEqual(result["final_values"], [35, 17])

if __name__ == "__main__":
    unittest.main()
