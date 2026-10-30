"""Frozen optimization evidence rejects incomplete work and unbilled speedups."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from tools.qualify_ring_optimization import (
    PROTOCOL_PATH, inspect_ir_counters, summarize, validate_observation, write_trace,
)


class RingOptimizationQualificationTests(unittest.TestCase):
    def test_training_and_heldout_are_distinct_replayable_inputs(self):
        protocol = json.loads(PROTOCOL_PATH.read_text())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            training = write_trace(root / "training", protocol, "burst", protocol["training_seed"])
            heldout = write_trace(root / "heldout", protocol, "burst", protocol["held_out_seed"])
            replay = write_trace(root / "replay", protocol, "burst", protocol["held_out_seed"])
            self.assertNotEqual(training["sha256"], heldout["sha256"])
            self.assertEqual(heldout["sha256"], replay["sha256"])
            self.assertEqual(heldout["one_pass_checksum"], replay["one_pass_checksum"])
            with self.assertRaises(FileExistsError):
                write_trace(root / "heldout", protocol, "burst", protocol["held_out_seed"])

    def profile(self, values="[4, 9]", count=2, level="IR"):
        return ("Counters:\n  ring_buffer_queue:\n    Hash: 0x123\n    Counters: " + str(count)
            + "\n    Block counts: " + values + "\nInstrumentation level: " + level
            + "\nTotal functions: 1\nTotal count: 13\n")

    def test_actual_ir_counters_required(self):
        self.assertEqual(inspect_ir_counters(self.profile(), "ring_buffer_queue")["block_counts"], [4, 9])
        for text in (self.profile("[0, 0]"), self.profile("[4]"), self.profile("[4, -1]"),
                     self.profile("[4, 1.0]"), self.profile("[4, true]"),
                     self.profile("[4, 18446744073709551616]"), self.profile(level="Front-end")):
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    inspect_ir_counters(text, "ring_buffer_queue")

    def test_missing_or_wrong_transaction_work_is_rejected(self):
        trace = {"records": 4096, "one_pass_bytes": 10, "one_pass_checksum": 123}
        value = {"records": 4096, "repeats": 16, "transactions": 65536, "bytes": 160,
            "checksum": 1968, "setup_ns": 1, "run_ns": 10, "cleanup_ns": 2,
            "total_main_ns": 13, "batch_ns": [1] * 512}
        validate_observation(value, trace, 16)
        for key, wrong in (("transactions", 0), ("bytes", 0), ("checksum", 0),
                           ("batch_ns", [1] * 511), ("total_main_ns", 12)):
            changed = copy.deepcopy(value)
            changed[key] = wrong
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_observation(changed, trace, 16)

    def accounting_fixture(self):
        protocol = json.loads(PROTOCOL_PATH.read_text())
        samples = []
        for group in range(protocol["paired_groups"]):
            for profile in protocol["profiles"]:
                for arm in protocol["arms"]:
                    samples.append({"group": group, "profile": profile, "arm": arm,
                        "process_index": len(samples), "process_seconds": 0.9 if arm == "hepta_rust_native_lto" else 1.0,
                        "observation": {"run_ns": 100, "batch_ns": [10]},
                        "memory": {"child_wait4_ru_maxrss_kib": 1024}})
        return protocol, samples

    def test_steady_speedup_does_not_erase_preparation_cost(self):
        protocol, samples = self.accounting_fixture()
        elapsed = sum(x["process_seconds"] for x in samples) + 2.0
        _, ledger = summarize(samples, protocol, elapsed)
        self.assertGreater(ledger["gross_observed_seconds_saved"], 0)
        self.assertAlmostEqual(ledger["charged_non_holdout_campaign_seconds"], 2.0)
        self.assertLess(ledger["net_benefit_upper_bound_seconds"], 0)
        self.assertFalse(ledger["future_amortization_counted"])

    def test_duplicate_process_or_paired_key_cannot_inflate_evidence(self):
        protocol, samples = self.accounting_fixture()
        for field, value in (("process_index", samples[0]["process_index"]), ("arm", samples[0]["arm"])):
            changed = copy.deepcopy(samples)
            changed[1][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                summarize(changed, protocol, 100)

    def test_nonfinite_timing_cannot_pass_ledger(self):
        protocol, samples = self.accounting_fixture()
        samples[0]["process_seconds"] = float("nan")
        with self.assertRaises(ValueError):
            summarize(samples, protocol, 100)


if __name__ == "__main__":
    unittest.main()
