"""Exact replay of a real four-arm C/ELF native observer report."""
from __future__ import annotations

from copy import deepcopy
import json
import os
import sys
import unittest

from hepta.hia_full_cost_gate import assess_full_cost
from hepta.hia_native_paired_replay import (
    NativePairedReplayRejected, replay_native_paired,
)
from tests.test_hia_full_cost_gate import wire
from tests.test_hia_native_process_observer import (
    HIANNativeProcessObservationTests,
)
from tools.hia_native_process_observer import observe


@unittest.skipUnless(sys.platform == "linux" and hasattr(os, "wait4"),
                     "real Linux wait4 observer required")
class HIANativePairedReplayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        HIANNativeProcessObservationTests.setUpClass()
        cls.fixture = HIANNativeProcessObservationTests()
        cls.good = observe(wire(cls.fixture.registration()))
        assert cls.good["complete"]

    @classmethod
    def tearDownClass(cls):
        HIANNativeProcessObservationTests.tearDownClass()

    def test_real_native_samples_are_independently_replayed(self):
        verdict = replay_native_paired(wire(self.good))
        self.assertTrue(verdict["raw_summary_replay_consistent"])
        self.assertEqual(verdict["actual_direct_child_samples"], 64)
        self.assertEqual(verdict["repetitions_per_task_arm"], 2)
        self.assertFalse(verdict["paired_evidence"]["paired_evidence_supported"])
        self.assertEqual(verdict["authority"], "DENY_ALL")
        self.assertFalse(verdict["safety_certificate"])
        self.assertFalse(verdict["production_activation_allowed"])
        self.assertFalse(verdict["limitations"]["observations_independently_attested"])

    def test_forged_task_aggregate_with_recomputed_original_verdict_refuses(self):
        data = deepcopy(self.good)
        data["full_cost_input"]["arms"][3]["observations"][0]["execution_ns"] += 1
        data["full_cost_verdict"] = assess_full_cost(wire(data["full_cost_input"]))
        with self.assertRaisesRegex(NativePairedReplayRejected, "raw samples differ"):
            replay_native_paired(wire(data))

    def test_missing_and_mutated_actual_samples_cannot_hide(self):
        for change in (
            lambda x: x["raw_samples"]["ndu"]["task00"].pop(),
            lambda x: x["raw_samples"]["ndu"]["task00"][0].update(execution_ns=1),
            lambda x: x["raw_samples"]["ndu"]["task00"][0].update(
                stderr_bytes=3, valid=True),
            lambda x: x["raw_samples"]["ndu"]["task00"][0].update(
                exit_code=-9, valid=True),
            lambda x: x["raw_samples"]["ndu"]["task00"][0].update(
                stdout_digest="f"*64, valid=True),
            lambda x: x["raw_samples"]["ndu"]["task00"][0].update(
                repetition=1),
        ):
            data = deepcopy(self.good)
            change(data)
            with self.subTest(mutation=repr(change)):
                with self.assertRaises(NativePairedReplayRejected):
                    replay_native_paired(wire(data))

    def test_mismatched_frozen_elf_or_cost_receipt_refuses(self):
        for change in (
            lambda x: x["frozen_binaries"][2].update(sha256="e"*64),
            lambda x: x["frozen_binaries"][2].update(freeze_ns=10**16),
            lambda x: x["full_cost_verdict"].update(ndu_full_cost_saving_ns=999),
        ):
            data = deepcopy(self.good)
            change(data)
            with self.subTest(mutation=repr(change)):
                with self.assertRaises(NativePairedReplayRejected):
                    replay_native_paired(wire(data))

    def test_missing_failing_and_untrusted_report_refuse(self):
        data = deepcopy(self.good)
        data["complete"] = False
        with self.assertRaises(NativePairedReplayRejected):
            replay_native_paired(wire(data))
        data = deepcopy(self.good)
        data["claims"]["process_tree_resource_accounting"] = True
        with self.assertRaises(NativePairedReplayRejected):
            replay_native_paired(wire(data))
        data = deepcopy(self.good)
        data["production_activation_allowed"] = True
        with self.assertRaises(NativePairedReplayRejected):
            replay_native_paired(wire(data))

    def test_duplicate_nan_mutable_oversized_or_invalid_utf8_refuse(self):
        cases = (
            self.good, b'{"x":0,"x":1}', b'{"x":NaN}',
            bytes([0xff]), b" " * (8 * 1024 * 1024 + 1),
        )
        for raw in cases:
            with self.subTest(kind=type(raw).__name__):
                with self.assertRaises(NativePairedReplayRejected):
                    replay_native_paired(raw)


if __name__ == "__main__":
    unittest.main()
