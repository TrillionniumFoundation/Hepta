"""Actual native state transitions, cancellation and leased code lifetimes."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import copy
import importlib.util
import os
from pathlib import Path
import platform
import shutil
import tempfile
import threading
import unittest
from unittest.mock import patch

from hepta.hia_multiversion import MultiversionRejected, ScalarMultiversionRuntime
from hepta.hia_program import SCHEMA, verify_program
from hepta.hia_scalar_state import (ScalarStateRejected, ScalarStateSession,
                                    ScalarTransitionCancellation, ScalarTransitionCancelled)


def transition_program(variant=0, typ="u64"):
    params = [{"name": "state", "type": typ}, {"name": "input", "type": typ}]
    operation = "bool.or" if typ == "bool" else "int.add.wrap"
    args = ["state", "input"] if variant == 0 else ["input", "state"]
    ops = [{"op": operation, "args": args, "out": [{"name": "next", "type": typ}], "attrs": {}}]
    result = "next"
    if variant == 2:
        ops += [{"op": "const", "args": [], "out": [{"name": "zero", "type": typ}],
                 "attrs": {"value": False if typ == "bool" else 0}},
                {"op": operation, "args": ["next", "zero"],
                 "out": [{"name": "answer", "type": typ}], "attrs": {}}]
        result = "answer"
    return {"schema": SCHEMA, "module": "scalar_state_test", "functions": [
        {"name": "transition", "params": params, "returns": [typ], "effects": [], "entry": "entry",
         "blocks": [{"id": "entry", "params": copy.deepcopy(params), "ops": ops,
                     "term": {"op": "ret", "values": [result]}}]}]}


_CLANG = os.environ.get("HEPTA_CLANG") or os.environ.get("CLANG") or "clang"
_NATIVE = (platform.system() == "Linux" and platform.machine() in {"x86_64", "amd64"}
           and hasattr(os, "memfd_create") and shutil.which(_CLANG)
           and importlib.util.find_spec("z3") is not None)


@unittest.skipUnless(_NATIVE, "actual Clang 20+, Z3 and Linux sealed memfd are required")
class ScalarStateNativeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="hia-scalar-state-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.runtime = self.make_runtime(transition_program())
        self.session = ScalarStateSession(self.runtime, "transition", 7)
        self.addCleanup(self.session.close)

    def make_runtime(self, program):
        runtime = ScalarMultiversionRuntime(program, self.root, clang=_CLANG)
        self.addCleanup(runtime.close)
        return runtime

    def hold_native(self, runtime, generation):
        state = runtime._states[generation]
        native = state.functions["transition"]
        entered, release = threading.Event(), threading.Event()
        calls = []

        def held(*args):
            calls.append(args)
            entered.set()
            if not release.wait(15):
                raise AssertionError("test did not release the native transition")
            return native(*args)

        return state, entered, release, calls, held

    def test_actual_state_survives_verified_publication_and_code_rollback(self):
        first = self.session.step([5], expected_revision=0)
        published = self.runtime.publish(transition_program(1))
        second = self.session.step([9], expected_revision=1)
        self.runtime.rollback()
        third = self.session.step([4], expected_revision=2)
        self.assertEqual([r["state_after"] for r in (first, second, third)], [12, 21, 25])
        self.assertEqual([r["generation"] for r in (first, second, third)], [0, published.generation, 0])
        self.assertEqual([r["revision_after"] for r in (first, second, third)], [1, 2, 3])
        self.assertGreater(third["selection_epoch"], second["selection_epoch"])
        self.assertEqual(len({r["state_contract_sha256"] for r in (first, second, third)}), 1)
        self.assertEqual(second["program_sha256"], published.program_sha256)
        self.assertEqual(second["artifact_sha256"], published.artifact_sha256)
        self.assertEqual(published.translation_proofs, 1)
        self.assertEqual(self.session.snapshot()["native_calls"], 3)

    def test_exact_unsigned_signed_and_boolean_state_domains(self):
        for typ, initial, argument, expected in (("u64", 2**64 - 1, 1, 0),
                                                 ("i8", -128, -1, 127),
                                                 ("u32", 2**32 - 1, 2, 1),
                                                 ("bool", False, True, True)):
            with self.subTest(typ=typ):
                runtime = self.make_runtime(transition_program(typ=typ))
                with ScalarStateSession(runtime, "transition", initial) as session:
                    runtime.publish(transition_program(1, typ))
                    receipt = session.step([argument], expected_revision=0)
                    self.assertEqual(receipt["state_after"], expected)
                    self.assertIs(type(receipt["state_after"]), type(expected))
                    for invalid in (1.0, None, "1", 1 if typ == "bool" else True):
                        with self.assertRaises(ScalarStateRejected):
                            session.step([invalid], expected_revision=1)
                    self.assertEqual(session.snapshot()["native_calls"], 1)

    def test_constructor_checks_actual_runtime_signature_initial_state_and_budget(self):
        for initial in (True, -1, 2**64, 7.0, "7"):
            with self.subTest(initial=initial), self.assertRaises(ScalarStateRejected):
                ScalarStateSession(self.runtime, "transition", initial)
        for limit in (0, -1, True, 1.0, 1000001):
            with self.subTest(limit=limit), self.assertRaises(ScalarStateRejected):
                ScalarStateSession(self.runtime, "transition", 0, max_native_calls=limit)
        with self.assertRaises(ScalarStateRejected):
            ScalarStateSession(object(), "transition", 0)
        with self.assertRaises(ScalarStateRejected):
            ScalarStateSession(self.runtime, "missing", 0)
        wrong = transition_program()
        fn = wrong["functions"][0]
        fn["returns"] = ["bool"]
        fn["blocks"][0]["ops"] = [{"op": "compare.eq", "args": ["state", "input"],
                                    "out": [{"name": "next", "type": "bool"}], "attrs": {}}]
        runtime = self.make_runtime(wrong)
        with self.assertRaisesRegex(ScalarStateRejected, "identical scalar state type"):
            ScalarStateSession(runtime, "transition", 0)
        self.assertEqual(self.runtime.snapshot()["generations"][0]["active_leases"], 0)

    def test_bad_arguments_revisions_and_exhausted_budget_never_invoke_native(self):
        with ScalarStateSession(self.runtime, "transition", 0, max_native_calls=1) as session:
            for args, revision in (([], 0), ([1, 2], 0), ([True], 0), ([1], True),
                                   ([1], -1), ([1], 2**63), ({"input": 1}, 0), ([1], 2)):
                with self.subTest(args=args, revision=revision), self.assertRaises(ScalarStateRejected):
                    session.step(args, expected_revision=revision)
            self.assertEqual(session.snapshot()["native_calls"], 0)
            self.assertEqual(session.step([11], expected_revision=0)["state_after"], 11)
            with self.assertRaisesRegex(ScalarStateRejected, "stale"):
                session.step([11], expected_revision=0)
            with self.assertRaisesRegex(ScalarStateRejected, "budget exhausted"):
                session.step([1], expected_revision=1)
            self.assertEqual(session.snapshot()["native_calls"], 1)
            self.assertEqual(session.snapshot()["state"], 11)

    def test_cancellation_before_execution_is_zero_cost_and_token_cannot_be_reused(self):
        token = ScalarTransitionCancellation()
        self.assertTrue(token.cancel())
        with self.assertRaises(ScalarTransitionCancelled):
            self.session.step([5], expected_revision=0, cancellation=token)
        with self.assertRaisesRegex(ScalarStateRejected, "one transition"):
            self.session.step([5], expected_revision=0, cancellation=token)
        snapshot = self.session.snapshot()
        self.assertEqual((snapshot["state"], snapshot["revision"], snapshot["native_calls"]), (7, 0, 0))
        self.assertEqual(snapshot["cancelled_before_execution"], 1)
        self.assertIsNone(snapshot["last_transition"])

    def test_concurrent_cancellation_discards_actual_result_and_charges_call_budget(self):
        with ScalarStateSession(self.runtime, "transition", 7, max_native_calls=1) as session:
            state, entered, release, calls, held = self.hold_native(self.runtime, 0)
            token = ScalarTransitionCancellation()
            with patch.dict(state.functions, {"transition": held}), ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(session.step, [5], expected_revision=0, cancellation=token)
                try:
                    self.assertTrue(entered.wait(10))
                    self.assertTrue(token.cancel())
                    self.assertEqual(self.runtime.snapshot()["generations"][0]["active_leases"], 1)
                finally:
                    release.set()
                with self.assertRaises(ScalarTransitionCancelled):
                    future.result(timeout=10)
            snapshot = session.snapshot()
            self.assertEqual(calls, [(7, 5)])
            self.assertEqual((snapshot["state"], snapshot["revision"], snapshot["native_calls"]), (7, 0, 1))
            self.assertEqual(snapshot["cancelled_after_execution"], 1)
            self.assertEqual(snapshot["failed_native_calls"], 0)
            with self.assertRaisesRegex(ScalarStateRejected, "budget exhausted"):
                session.step([1], expected_revision=0)
            self.assertEqual(self.runtime.snapshot()["generations"][0]["active_leases"], 0)

    def test_publish_and_rollback_during_call_pin_actual_code_until_state_commit(self):
        first = self.runtime.publish(transition_program(1))
        state, entered, release, calls, held = self.hold_native(self.runtime, first.generation)
        # The old function map is intentionally cleared by actual runtime retirement.
        # Do not restore that retired map with patch.dict after lease release.
        state.functions["transition"] = held
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(self.session.step, [5], expected_revision=0)
            try:
                self.assertTrue(entered.wait(10))
                second = self.runtime.publish(transition_program(2))
                self.runtime.rollback()
                generations = {g["generation"]: g for g in self.runtime.snapshot()["generations"]}
                self.assertTrue(generations[first.generation]["retired"])
                self.assertEqual(generations[first.generation]["active_leases"], 1)
                self.assertNotIn(second.generation, generations)
                os.fstat(state.fd)
            finally:
                release.set()
            receipt = future.result(timeout=10)
        self.assertEqual((receipt["generation"], receipt["state_after"]), (first.generation, 12))
        self.assertEqual(calls, [(7, 5)])
        self.assertNotIn(first.generation, self.runtime._states)
        self.assertFalse(state.artifact.exists())
        with self.assertRaises(OSError):
            os.fstat(state.fd)
        after = self.session.step([1], expected_revision=1)
        self.assertEqual((after["generation"], after["state_after"]), (0, 13))

    def test_runtime_shutdown_allows_inflight_lease_to_commit_but_prevents_next_call(self):
        state, entered, release, calls, held = self.hold_native(self.runtime, 0)
        state.functions["transition"] = held
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(self.session.step, [5], expected_revision=0)
            try:
                self.assertTrue(entered.wait(10))
                self.runtime.close()
                os.fstat(state.fd)
            finally:
                release.set()
            self.assertEqual(future.result(timeout=10)["state_after"], 12)
        token = ScalarTransitionCancellation()
        with self.assertRaisesRegex(MultiversionRejected, "closed"):
            self.session.step([1], expected_revision=1, cancellation=token)
        self.assertEqual(token.status(), "failed")
        self.assertEqual(self.session.snapshot()["native_calls"], 1)
        self.assertEqual(self.session.snapshot()["state"], 12)
        self.assertEqual(self.runtime.snapshot()["generations"], [])
        with self.assertRaises(OSError):
            os.fstat(state.fd)

    def test_native_failure_after_actual_call_preserves_state_and_never_replays(self):
        state = self.runtime._states[0]
        native, calls = state.functions["transition"], []

        def fails_after_native(*args):
            calls.append(native(*args))
            raise RuntimeError("injected host failure after actual native return")

        token = ScalarTransitionCancellation()
        with patch.dict(state.functions, {"transition": fails_after_native}):
            with self.assertRaisesRegex(RuntimeError, "injected host failure"):
                self.session.step([5], expected_revision=0, cancellation=token)
        snapshot = self.session.snapshot()
        self.assertEqual(calls, [12])
        self.assertEqual((snapshot["state"], snapshot["revision"], snapshot["native_calls"]), (7, 0, 1))
        self.assertEqual(snapshot["failed_native_calls"], 1)
        self.assertEqual(token.status(), "failed")
        self.assertFalse(token.cancel())
        with self.assertRaisesRegex(ScalarStateRejected, "one transition"):
            self.session.step([5], expected_revision=0, cancellation=token)
        self.assertEqual(self.session.step([5], expected_revision=0)["state_after"], 12)
        self.assertEqual(self.session.snapshot()["native_calls"], 2)
        self.assertEqual(self.runtime.snapshot()["generations"][0]["active_leases"], 0)

    def test_invalid_native_return_is_not_committed(self):
        state = self.runtime._states[0]
        native = state.functions["transition"]

        def invalid(*args):
            self.assertEqual(native(*args), 12)
            return True  # bool is not an exact u64, despite Python equality.

        with patch.dict(state.functions, {"transition": invalid}):
            with self.assertRaisesRegex(ScalarStateRejected, "native result"):
                self.session.step([5], expected_revision=0)
        self.assertEqual(self.session.snapshot()["state"], 7)
        self.assertEqual(self.session.snapshot()["failed_native_calls"], 1)

    def test_native_failure_racing_cancellation_remains_a_recorded_failure(self):
        state = self.runtime._states[0]
        native, actual_values = state.functions["transition"], []
        entered, release = threading.Event(), threading.Event()
        token = ScalarTransitionCancellation()

        def failure(*args):
            actual_values.append(native(*args))
            entered.set()
            if not release.wait(10):
                raise AssertionError("test did not release native return")
            raise RuntimeError("native host failure racing accepted cancellation")

        with patch.dict(state.functions, {"transition": failure}), ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(self.session.step, [5], expected_revision=0, cancellation=token)
            try:
                self.assertTrue(entered.wait(10))
                self.assertTrue(token.cancel())
            finally:
                release.set()
            with self.assertRaisesRegex(RuntimeError, "racing accepted cancellation"):
                future.result(timeout=10)
        snapshot = self.session.snapshot()
        self.assertEqual(actual_values, [12])
        self.assertEqual((snapshot["state"], snapshot["revision"], snapshot["native_calls"]), (7, 0, 1))
        self.assertEqual(snapshot["failed_native_calls"], 1)
        self.assertEqual(snapshot["cancelled_after_execution"], 0)
        self.assertEqual(snapshot["events"][-1]["event"], "native_transition_failed")
        self.assertTrue(snapshot["events"][-1]["cancellation_requested"])
        self.assertEqual(token.status(), "cancelled")
        self.assertEqual(self.runtime.snapshot()["generations"][0]["active_leases"], 0)

    def test_host_failure_after_commit_does_not_allow_duplicate_application(self):
        token = ScalarTransitionCancellation()
        with patch.object(self.session, "_event", side_effect=RuntimeError("delivery interrupted after commit")):
            with self.assertRaisesRegex(RuntimeError, "delivery interrupted"):
                self.session.step([5], expected_revision=0, cancellation=token)
        snapshot = self.session.snapshot()
        self.assertEqual((snapshot["state"], snapshot["revision"], snapshot["native_calls"]), (12, 1, 1))
        self.assertEqual(snapshot["last_transition"]["state_after"], 12)
        self.assertEqual(snapshot["last_transition"]["revision_after"], 1)
        self.assertEqual(snapshot["failed_native_calls"], 0)
        self.assertEqual(token.status(), "committed")
        self.assertFalse(token.cancel())
        with self.assertRaisesRegex(ScalarStateRejected, "stale"):
            self.session.step([5], expected_revision=0)
        self.assertEqual(self.session.snapshot()["native_calls"], 1)

    def test_two_concurrent_updates_with_same_revision_commit_exactly_once(self):
        ready = threading.Barrier(2)

        def update(value):
            ready.wait(timeout=10)
            try:
                return self.session.step([value], expected_revision=0)
            except ScalarStateRejected as exc:
                return exc

        with ThreadPoolExecutor(max_workers=2) as pool:
            left, right = pool.submit(update, 5), pool.submit(update, 9)
            results = [left.result(timeout=10), right.result(timeout=10)]
        successes = [r for r in results if isinstance(r, dict)]
        errors = [r for r in results if isinstance(r, ScalarStateRejected)]
        self.assertEqual((len(successes), len(errors)), (1, 1))
        self.assertIn("stale", str(errors[0]))
        snapshot = self.session.snapshot()
        self.assertEqual((snapshot["revision"], snapshot["native_calls"]), (1, 1))
        self.assertIn(snapshot["state"], (12, 16))

    def test_session_close_waits_for_transition_and_preserves_caller_runtime(self):
        state, entered, release, calls, held = self.hold_native(self.runtime, 0)
        closing = threading.Event()

        def close():
            closing.set()
            self.session.close()

        with patch.dict(state.functions, {"transition": held}), ThreadPoolExecutor(max_workers=2) as pool:
            future = pool.submit(self.session.step, [5], expected_revision=0)
            try:
                self.assertTrue(entered.wait(10))
                closed = pool.submit(close)
                self.assertTrue(closing.wait(10))
                self.assertFalse(closed.done())
            finally:
                release.set()
            self.assertEqual(future.result(timeout=10)["state_after"], 12)
            closed.result(timeout=10)
        self.assertTrue(self.session.snapshot()["closed"])
        with self.assertRaisesRegex(ScalarStateRejected, "closed"):
            self.session.step([1], expected_revision=1)
        self.assertEqual(self.runtime.call("transition", [12, 1]), 13)

    def test_snapshots_are_detached_history_is_bounded_and_ownership_cannot_be_copied(self):
        token = ScalarTransitionCancellation()
        first = self.session.step([1], expected_revision=0, cancellation=token)
        self.assertFalse(token.cancel())
        self.assertEqual(token.status(), "committed")
        first["state_after"] = 1000
        snapshot = self.session.snapshot()
        snapshot["state_contract"]["parameters"][0] = "bool"
        snapshot["last_transition"]["state_after"] = 2000
        snapshot["events"][0]["event"] = "forged"
        for value in (self.session, token):
            for operation in (copy.copy, copy.deepcopy):
                with self.assertRaises(ScalarStateRejected):
                    operation(value)
        for revision in range(1, 132):
            self.session.step([1], expected_revision=revision)
        current = self.session.snapshot()
        self.assertEqual((current["state"], current["revision"]), (139, 132))
        self.assertEqual((len(current["events"]), current["events_dropped"]), (128, 4))
        self.assertEqual(current["state_contract"]["parameters"][0], "u64")
        self.assertEqual(current["last_transition"]["state_after"], 139)
        self.assertTrue(current["claims"]["state_preserved_across_equivalent_generations"])
        self.assertFalse(current["claims"]["live_heap_or_loan_migration"])
        self.assertFalse(current["claims"]["automatic_profitability_established"])

    def test_unproved_code_rejection_preserves_state_and_selected_generation(self):
        self.session.step([5], expected_revision=0)
        changed = transition_program()
        changed["functions"][0]["blocks"][0]["ops"][0]["op"] = "int.sub.wrap"
        verify_program(changed)
        with self.assertRaisesRegex(MultiversionRejected, "disproved"):
            self.runtime.publish(changed)
        self.assertEqual(self.session.snapshot()["state"], 12)
        self.assertEqual(self.runtime.snapshot()["current_generation"], 0)
        self.assertEqual(self.session.step([1], expected_revision=1)["state_after"], 13)


if __name__ == "__main__":
    unittest.main()
