"""Actual interpreter calls across explicit, bounded generation transitions."""
from __future__ import annotations

from hashlib import sha256
from threading import Event, Thread
import unittest
from unittest import mock

import hepta.hia_version_dispatch as dispatch
from hepta.hia_program import HIAProgramRejected, verify_program
from hepta.hia_program_runtime import HIAProgramBudgetExceeded, HIAProgramTrap
from hepta.hia_swap_opt import rewrite_byte_swap
from tests.test_hia_program_composite import stored_loan_program
from tests.test_hia_swap_opt import source_program


def programs():
    baseline = verify_program(source_program())
    candidate = rewrite_byte_swap(baseline).program
    return baseline, candidate


class LocalVersionDispatchTests(unittest.TestCase):
    def test_staging_reproduces_exact_rewrite_and_never_activates_it(self):
        baseline, candidate = programs()
        host = dispatch.LocalVersionDispatcher(baseline.canonical_bytes)
        stage = host.stage_candidate(candidate.canonical_bytes)
        self.assertEqual(stage["relation"], "reproduced_byte_swap")
        self.assertEqual(stage["rewrite_replacements"], 1)
        self.assertFalse(stage["activated"])
        self.assertEqual(host.snapshot()["active_sha256"], baseline.sha256)
        self.assertEqual(host.snapshot()["generation"], 0)
        receipt = host.execute("swap_candidate", [5, 0, 4, 0])
        self.assertEqual(receipt["execution"]["result"], 55)
        self.assertEqual(receipt["program_sha256"], baseline.sha256)
        self.assertFalse(receipt["claims"]["native_executed"])

    def test_baseline_no_change_and_generation_compare_and_swap(self):
        baseline, candidate = programs()
        host = dispatch.LocalVersionDispatcher(baseline.canonical_bytes)
        self.assertEqual(host.stage_candidate(baseline.canonical_bytes)["relation"], "baseline")
        self.assertFalse(host.activate(baseline.sha256, expected_generation=0)["changed"])
        self.assertFalse(host.rollback(expected_generation=0)["changed"])
        with self.assertRaisesRegex(dispatch.HIAVersionDispatchRejected, "not staged"):
            host.activate(candidate.sha256, expected_generation=0)
        host.stage_candidate(candidate.canonical_bytes)
        self.assertEqual(host.activate(candidate.sha256, expected_generation=0)["generation"], 1)
        self.assertFalse(host.activate(candidate.sha256, expected_generation=1)["changed"])
        for stale in (0, True, -1, "1"):
            with self.subTest(stale=stale):
                with self.assertRaisesRegex(dispatch.HIAVersionDispatchRejected, "generation"):
                    host.rollback(expected_generation=stale)
        receipt = host.execute("swap_candidate", [5, 0, 4, 0])
        self.assertEqual(receipt["execution"]["result"], 55)
        self.assertEqual(receipt["program_sha256"], candidate.sha256)
        self.assertEqual(host.rollback(expected_generation=1)["generation"], 2)
        self.assertEqual(host.snapshot()["retired_versions"], 1)
        with self.assertRaisesRegex(dispatch.HIAVersionDispatchRejected, "retired"):
            host.activate(candidate.sha256, expected_generation=2)
        host.stage_candidate(candidate.canonical_bytes)
        self.assertEqual(host.activate(candidate.sha256, expected_generation=2)["generation"], 3)

    def test_type_safe_behavior_change_and_other_baseline_rewrite_are_rejected(self):
        baseline, candidate = programs()
        host = dispatch.LocalVersionDispatcher(baseline.canonical_bytes)
        altered = candidate.as_dict()
        byte = next(op for op in altered["functions"][0]["blocks"][0]["ops"]
                    if op["op"] == "const" and op["out"][0]["name"] == "byte4")
        byte["attrs"]["value"] = 99
        safe_but_wrong = verify_program(altered)
        self.assertEqual(dispatch.execute_program(safe_but_wrong, "swap_candidate",
                                                  [5, 0, 4, 0])["result"], 99)
        with self.assertRaisesRegex(dispatch.HIAVersionDispatchRejected, "exact allowed rewrite"):
            host.stage_candidate(safe_but_wrong.canonical_bytes)
        foreign_base = baseline.as_dict()
        foreign_base["module"] = "different_snapshot"
        foreign_candidate = rewrite_byte_swap(foreign_base).program
        with self.assertRaises(dispatch.HIAVersionDispatchRejected):
            host.stage_candidate(foreign_candidate.canonical_bytes)
        self.assertEqual(len(host.snapshot()["versions"]), 1)

    def test_immutable_input_and_finite_public_boundary_are_enforced(self):
        baseline, candidate = programs()
        for mutable in (baseline.as_dict(), bytearray(baseline.canonical_bytes), baseline):
            with self.subTest(type=type(mutable)):
                with self.assertRaisesRegex(dispatch.HIAVersionDispatchRejected, "immutable"):
                    dispatch.LocalVersionDispatcher(mutable)
        version7 = baseline.as_dict()
        version7["schema"] = "hepta.hia.program.v7"
        version7 = verify_program(version7)
        with self.assertRaisesRegex(dispatch.HIAVersionDispatchRejected, "v1-v6"):
            dispatch.LocalVersionDispatcher(version7.canonical_bytes)
        no_exports = baseline.as_dict()
        no_exports["exports"] = []
        no_exports = verify_program(no_exports)
        with self.assertRaisesRegex(dispatch.HIAVersionDispatchRejected, "public export"):
            dispatch.LocalVersionDispatcher(no_exports.canonical_bytes)
        host = dispatch.LocalVersionDispatcher(baseline.canonical_bytes)
        with self.assertRaisesRegex(dispatch.HIAVersionDispatchRejected, "immutable"):
            host.stage_candidate(candidate)
        with self.assertRaises(dispatch.HIAVersionDispatchRejected):
            host.execute("not_exported", [])
        for limit in (True, 0, 1025):
            with self.assertRaises(dispatch.HIAVersionDispatchRejected):
                dispatch.LocalVersionDispatcher(baseline.canonical_bytes, max_in_flight=limit)

    def test_valid_composite_and_v7_bytes_cannot_enter_staging_or_activation(self):
        baseline, _ = programs()
        host = dispatch.LocalVersionDispatcher(baseline.canonical_bytes)
        composite = verify_program(stored_loan_program())
        self.assertIsNotNone(composite.structured_bytes)
        version7 = baseline.as_dict()
        version7["schema"] = "hepta.hia.program.v7"
        version7 = verify_program(version7)
        for outside_profile in (composite.structured_bytes, version7.canonical_bytes):
            with self.subTest(schema=verify_program(outside_profile).as_dict()["schema"]):
                with self.assertRaisesRegex(dispatch.HIAVersionDispatchRejected, "v1-v6"):
                    dispatch.LocalVersionDispatcher(outside_profile)
                with self.assertRaisesRegex(dispatch.HIAVersionDispatchRejected, "v1-v6"):
                    host.stage_candidate(outside_profile)
        state = host.snapshot()
        self.assertEqual(state["active_sha256"], baseline.sha256)
        self.assertEqual(state["generation"], 0)
        self.assertEqual(len(state["versions"]), 1)

    def _start_delayed_call(self, host, delayed_identity, entered, release, *, name):
        """Delay only scheduling; the original VM still computes every result."""
        actual_execute = dispatch.execute_program
        outcome = {}

        def gated(core, function, arguments, **policy):
            if sha256(core).hexdigest() == delayed_identity:
                entered.set()
                if not release.wait(5):
                    raise AssertionError("test did not release delayed actual VM call")
            return actual_execute(core, function, arguments, **policy)

        def work():
            try:
                outcome["result"] = host.execute("swap_candidate", [5, 0, 4, 0])
            except BaseException as exc:
                outcome["error"] = exc

        patcher = mock.patch.object(dispatch, "execute_program", side_effect=gated)
        patcher.start()
        self.addCleanup(patcher.stop)
        thread = Thread(target=work, name=name, daemon=True)
        thread.start()
        return thread, outcome

    def test_activation_pins_old_call_and_routes_new_calls_to_candidate(self):
        baseline, candidate = programs()
        host = dispatch.LocalVersionDispatcher(baseline.canonical_bytes)
        host.stage_candidate(candidate.canonical_bytes)
        entered, release = Event(), Event()
        thread, outcome = self._start_delayed_call(
            host, baseline.sha256, entered, release, name="old-baseline-call")
        try:
            self.assertTrue(entered.wait(5), "old call did not pin its baseline")
            self.assertEqual(host.snapshot()["in_flight"], 1)
            host.activate(candidate.sha256, expected_generation=0)
            current = host.execute("swap_candidate", [5, 0, 4, 0])
            self.assertEqual(current["generation"], 1)
            self.assertEqual(current["program_sha256"], candidate.sha256)
            self.assertEqual(current["execution"]["result"], 55)
            held = {v["sha256"]: v for v in host.snapshot()["versions"]}
            self.assertEqual(held[baseline.sha256]["in_flight"], 1)
            self.assertEqual(held[baseline.sha256]["state"], "baseline_retained")
        finally:
            release.set()
            thread.join(5)
        self.assertFalse(thread.is_alive(), "old call did not finish")
        self.assertNotIn("error", outcome)
        self.assertEqual(outcome["result"]["generation"], 0)
        self.assertEqual(outcome["result"]["execution"]["program_sha256"], baseline.sha256)
        self.assertEqual(outcome["result"]["execution"]["result"], 55)
        self.assertEqual(host.snapshot()["in_flight"], 0)

    def test_rollback_drains_old_candidate_before_retirement(self):
        baseline, candidate = programs()
        host = dispatch.LocalVersionDispatcher(baseline.canonical_bytes)
        host.stage_candidate(candidate.canonical_bytes)
        host.activate(candidate.sha256, expected_generation=0)
        entered, release = Event(), Event()
        thread, outcome = self._start_delayed_call(
            host, candidate.sha256, entered, release, name="old-candidate-call")
        try:
            self.assertTrue(entered.wait(5), "candidate call did not pin its version")
            host.rollback(expected_generation=1)
            held = {v["sha256"]: v for v in host.snapshot()["versions"]}
            self.assertEqual(held[candidate.sha256]["state"], "draining")
            self.assertEqual(held[candidate.sha256]["in_flight"], 1)
            self.assertEqual(host.snapshot()["retired_versions"], 0)
            current = host.execute("swap_candidate", [5, 0, 4, 0])
            self.assertEqual(current["generation"], 2)
            self.assertEqual(current["program_sha256"], baseline.sha256)
            self.assertEqual(current["execution"]["result"], 55)
        finally:
            release.set()
            thread.join(5)
        self.assertFalse(thread.is_alive(), "draining call did not finish")
        self.assertNotIn("error", outcome)
        self.assertEqual(outcome["result"]["generation"], 1)
        self.assertEqual(outcome["result"]["execution"]["program_sha256"], candidate.sha256)
        self.assertEqual(outcome["result"]["execution"]["result"], 55)
        self.assertEqual(host.snapshot()["retired_versions"], 1)
        self.assertEqual([v["sha256"] for v in host.snapshot()["versions"]], [baseline.sha256])

    def test_real_trap_budget_and_input_failures_always_release_dispatch_pin(self):
        baseline, candidate = programs()
        host = dispatch.LocalVersionDispatcher(baseline.canonical_bytes)
        host.stage_candidate(candidate.canonical_bytes)
        host.activate(candidate.sha256, expected_generation=0)
        cases = (
            ([5, 99, 0, 0], {}, HIAProgramTrap),
            ([5, 0, 4, 0], {"max_steps": 1}, HIAProgramBudgetExceeded),
            ([5, 0, 4, 0], {"allocation_fail_at": 1}, HIAProgramTrap),
            ([True, 0, 4, 0], {}, HIAProgramRejected),
        )
        for arguments, policy, error in cases:
            with self.subTest(policy=policy, arguments=arguments):
                with self.assertRaises(error) as raised:
                    host.execute("swap_candidate", arguments, **policy)
                if getattr(raised.exception, "report", None) is not None:
                    self.assertEqual(raised.exception.report["program_sha256"], candidate.sha256)
                self.assertEqual(host.snapshot()["in_flight"], 0)
        host.rollback(expected_generation=1)
        self.assertEqual(host.snapshot()["retired_versions"], 1)

    def test_concurrent_admission_budget_refuses_without_waiting_or_extra_execution(self):
        baseline, _ = programs()
        host = dispatch.LocalVersionDispatcher(baseline.canonical_bytes, max_in_flight=1)
        entered, release = Event(), Event()
        thread, outcome = self._start_delayed_call(
            host, baseline.sha256, entered, release, name="bounded-call")
        try:
            self.assertTrue(entered.wait(5), "first call did not enter")
            with self.assertRaisesRegex(dispatch.HIAVersionDispatchRejected, "call budget"):
                host.execute("swap_candidate", [5, 0, 4, 0])
            self.assertEqual(host.snapshot()["in_flight"], 1)
        finally:
            release.set()
            thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertNotIn("error", outcome)
        self.assertEqual(outcome["result"]["execution"]["result"], 55)
        self.assertEqual(host.snapshot()["in_flight"], 0)


if __name__ == "__main__":
    unittest.main()
