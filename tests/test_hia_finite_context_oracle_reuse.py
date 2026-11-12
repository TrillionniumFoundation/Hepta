"""Reference reuse must not become execution, qualification or replay authority."""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from hepta import hia_finite_context as fc
from tests.test_hia_finite_context import events, request, result, shift_oracle, shift_program


def bank(*, reuse=True, identity="b" * 64, oracle=shift_oracle):
    owner = fc.FiniteU32Bank(fc._CONSTRUCTION, fc.checked_profile(shift_program()),
        ("baseline", "shift_4"), oracle, {}, reuse_oracle=reuse)
    owner._bank_sha256 = identity
    owner._driver = {"path": "unit-test-driver"}
    owner._images = tuple({"path": f"unit-test-image-{i}", "sha256": str(i) * 64} for i in range(2))
    return owner


class OracleReferenceTests(unittest.TestCase):
    def test_default_does_not_cache_and_opt_in_is_an_exact_boolean(self):
        calls = []
        def oracle(x, y):
            calls.append((x, y))
            return shift_oracle(x, y)
        owner = bank(reuse=False, oracle=oracle)
        for _ in range(2):
            owner.cancel(owner.prepare_trace([request()]))
        self.assertEqual(len(calls), 6)
        self.assertFalse(owner.oracle_reference_statistics()["enabled"])
        owner.close()
        for value in (1, None, "true", []):
            with self.subTest(value=value), self.assertRaises(fc.FiniteContextRejected):
                bank(reuse=value)

    def test_same_semantics_reuses_reference_but_every_trace_launch_is_independent(self):
        calls = []
        def oracle(x, y):
            calls.append((x, y))
            return shift_oracle(x, y)
        owner = bank(oracle=oracle)
        first = owner.prepare_trace([request()])
        second = owner.prepare_trace([request(ident=19, candidate="shift_4")])
        self.assertEqual(first.expected, second.expected)
        self.assertIsNot(first.token, second.token)
        self.assertNotEqual(first.sha256, second.sha256)
        self.assertEqual(len(calls), 3)
        with patch.object(fc, "run_bounded", side_effect=[result(events(first)), result(events(second))]) as launch:
            self.assertEqual(owner.run(first)["status"], "completed")
            self.assertEqual(owner.run(second)["status"], "completed")
            with self.assertRaises(fc.FiniteContextRejected):
                owner.run(first)
            self.assertEqual(launch.call_count, 2)
        stats = owner.oracle_reference_statistics()
        self.assertEqual((stats["misses"], stats["hits"], stats["entries"]), (1, 1, 1))
        stats["entries"] = 0
        self.assertEqual(owner.oracle_reference_statistics()["entries"], 1)
        release = owner.close()
        self.assertEqual(release["oracle_references"]["retained_canonical_bytes"], 0)
        self.assertEqual(release["oracle_references"]["entries"], 0)
        self.assertGreater(release["oracle_references"]["retained_canonical_byte_ns"], 0)
        self.assertTrue(release["complete"])

    def test_all_semantic_inputs_and_bank_namespace_are_bound(self):
        owner = bank()
        original = request()
        inputs = [original, request(seed=8), request(values=[1, 2, 1]),
                  request(mode="xor_fold", parameter=1), request(mode="xor_fold", parameter=2)]
        for item in inputs:
            trace = owner.prepare_trace([item])
            self.assertEqual(trace.expected, fc._expected(trace.requests, shift_oracle))
            owner.cancel(trace)
        self.assertEqual(owner.oracle_reference_statistics()["misses"], 5)
        original["values"][0] = 31
        owner.cancel(owner.prepare_trace([original]))
        self.assertEqual(owner.oracle_reference_statistics()["misses"], 6)
        other = bank(identity="c" * 64)
        other.cancel(other.prepare_trace([request()]))
        self.assertEqual(other.oracle_reference_statistics()["misses"], 1)
        self.assertNotEqual(owner.oracle_reference_statistics()["namespace_sha256"],
                            other.oracle_reference_statistics()["namespace_sha256"])
        owner._bank_sha256 = "d" * 64
        with self.assertRaisesRegex(fc.FiniteContextRejected, "namespace"):
            owner.prepare_trace([request()])
        owner.close()
        other.close()

    def test_checker_drift_and_unadmitted_candidates_reject_before_cache_hit(self):
        owner = bank()
        owner.cancel(owner.prepare_trace([request()]))
        with patch.object(fc, "_implementation", return_value="f" * 64):
            with self.assertRaisesRegex(fc.FiniteContextRejected, "implementation changed"):
                owner.prepare_trace([request()])
        with self.assertRaisesRegex(fc.FiniteContextRejected, "unadmitted"):
            owner.prepare_trace([request(candidate="new_unproved")])
        self.assertEqual(owner.oracle_reference_statistics()["hits"], 0)
        owner.close()

    def test_first_trap_position_is_preserved_and_cancel_does_not_reuse_nonce(self):
        owner = bank()
        first = owner.prepare_trace([request(values=[0, 32, 0])])
        self.assertEqual(first.expected, (("trapped", "overflow", 1),))
        owner.cancel(first)
        second = owner.prepare_trace([request(values=[0, 32, 0])])
        self.assertEqual(first.expected, second.expected)
        self.assertIsNot(first.token, second.token)
        with self.assertRaises(fc.FiniteContextRejected):
            owner.cancel(first)
        self.assertEqual(owner.state()["registered_traces"], 2)
        self.assertEqual(owner.oracle_reference_statistics()["hits"], 1)
        owner.close()

    def test_item_limit_and_byte_limit_each_force_computation_without_storage(self):
        owner = bank()
        for seed in range(fc.MAX_ORACLE_REFERENCES + 1):
            owner.cancel(owner.prepare_trace([request(seed=seed, values=[0])]))
        stats = owner.oracle_reference_statistics()
        self.assertEqual(stats["entries"], fc.MAX_ORACLE_REFERENCES)
        self.assertEqual(stats["capacity_bypasses"], 1)
        self.assertLess(stats["retained_canonical_bytes"], fc.MAX_ORACLE_REFERENCE_BYTES)
        owner.close()
        owner = bank()
        # The first item traps immediately, but its complete immutable input is
        # still the key. A changed tail must consume its own storage budget.
        huge = [fc.MASK32] * fc.MAX_CALLS
        for seed in (7, 8):
            owner.cancel(owner.prepare_trace([request(seed=seed, values=huge)]))
        stats = owner.oracle_reference_statistics()
        self.assertEqual(stats["entries"], 1)
        self.assertEqual(stats["capacity_bypasses"], 1)
        self.assertLessEqual(stats["retained_canonical_bytes"], fc.MAX_ORACLE_REFERENCE_BYTES)
        self.assertLess(stats["entries"], fc.MAX_ORACLE_REFERENCES)
        owner.close()

    def test_failed_oracle_result_is_never_cached(self):
        owner = bank(oracle=lambda x, y: True)
        for _ in range(2):
            with self.assertRaises(fc.FiniteContextRejected):
                owner.prepare_trace([request()])
        stats = owner.oracle_reference_statistics()
        self.assertEqual((stats["entries"], stats["hits"], stats["failed_computations"]), (0, 0, 2))
        owner.close()

    def test_native_failure_still_poisons_owner_even_after_reference_hit(self):
        owner = bank()
        owner.cancel(owner.prepare_trace([request()]))
        second = owner.prepare_trace([request()])
        with patch.object(fc, "run_bounded", return_value=result([], returncode=17)) as launch:
            with self.assertRaises(fc.FiniteContextRejected):
                owner.run(second)
            with self.assertRaisesRegex(fc.FiniteContextRejected, "poisoned"):
                owner.prepare_trace([request()])
            self.assertEqual(launch.call_count, 1)
        self.assertTrue(owner.close()["oracle_references"]["closed"])


class OracleReferenceNativeTests(unittest.TestCase):
    def test_two_real_children_reuse_only_the_reference(self):
        clang = os.environ.get("HEPTA_CLANG") or shutil.which("clang")
        if not clang:
            self.skipTest("actual Clang required")
        with tempfile.TemporaryDirectory(prefix="hia-context-reference-") as temporary:
            owner = fc.build_bank(shift_program(), {"baseline": shift_program()}, Path(temporary),
                clang=clang, cases=[[1, 0], [1, 4], [2, 1]], oracle=shift_oracle, reuse_oracle=True)
            try:
                reports = []
                for _ in range(2):
                    reports.append(owner.run(owner.prepare_trace([request()])))
                self.assertTrue(all(r["status"] == "completed" for r in reports))
                self.assertTrue(all(len(r["prefix"]["completed_requests"]) == 1 for r in reports))
                stats = owner.oracle_reference_statistics()
                self.assertEqual((stats["hits"], stats["misses"]), (1, 1))
                self.assertFalse(stats["native_result_cache"])
            finally:
                self.assertTrue(owner.close()["complete"])


if __name__ == "__main__":
    unittest.main()
