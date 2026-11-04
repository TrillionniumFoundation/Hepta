"""Frozen outline campaign cannot hide arms, cohorts, tails or costs."""
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from tools import qualify_hia_outlined_aot as campaign
from tools import qualify_hia_reduction_release as release
from tools import qualify_hia_empty_reduction as empty


class OutlineProtocolTests(unittest.TestCase):
    @staticmethod
    def cohort():
        spec = campaign.specification()
        rows = [
            {"workload": workload, "group": group["name"], "backend": arm,
             "n": n, "seed": seed, "calls": calls, "samples": spec["samples"],
             "times_ns": [1000] * spec["samples"], "elapsed_ns": 1000 * spec["samples"]}
            for workload in spec["historical_profile"]["workloads"] for group in spec["groups"]
            for arm in campaign.ARMS for n in group["sizes"] for seed in group["seeds"]
            for calls in spec["batch_loads"]
        ]
        return spec, rows

    def test_all_old_lengths_loads_thresholds_and_both_strong_rust_arms_remain(self):
        spec, rows = self.cohort()
        old = release.specification(release.INDUCTION_PROFILE)
        wrapper = empty.specification(empty.WRAPPER_PROFILE)
        self.assertEqual(spec["historical_profile"], old)
        self.assertEqual(spec["performance_gate"], {"median_ratio_maximum": 1.10, "p95_ratio_maximum": 1.20, "p99_ratio_maximum": 1.20})
        self.assertEqual(spec["groups"][2]["sizes"], wrapper["groups"][-1]["sizes"])
        self.assertEqual(spec["groups"][2]["seeds"], wrapper["groups"][-1]["seeds"])
        self.assertEqual(spec["batch_loads"], [1, 16, 64])
        self.assertEqual(set(spec["arms"]), set(release.ARMS) | {campaign.WRAPPER, campaign.CANDIDATE})
        self.assertEqual(len(rows), spec["timing_requests"])
        self.assertEqual(sum(len(r["times_ns"]) for r in rows), spec["timed_batches"])
        self.assertEqual(sum(r["calls"] * len(r["times_ns"]) for r in rows), spec["timed_kernel_calls"])
        observed = campaign.assess(rows, spec)
        self.assertEqual(observed["candidate_rust_comparisons_total"], 372)
        self.assertEqual(len(observed["comparisons"]), 930)
        self.assertTrue(observed["candidate_all_registered_rust_gates_passed"])

    def test_one_tail_failure_stays_visible_in_its_own_load(self):
        spec, rows = self.cohort()
        changed = next(r for r in rows if r["backend"] == campaign.CANDIDATE
                       and r["group"] == "prospective_lengths" and r["calls"] == 1)
        changed["times_ns"][-1] = 1201
        changed["elapsed_ns"] = sum(changed["times_ns"])
        observed = campaign.assess(rows, spec)
        self.assertFalse(observed["candidate_all_registered_rust_gates_passed"])
        failed = [r for r in observed["comparisons"] if not r["passed"]]
        self.assertEqual(len(failed), 5)
        self.assertTrue(all(r["calls"] == 1 and r["group"] == "prospective_lengths" for r in failed))
        self.assertFalse(observed["full_lifecycle_net_benefit_established"])

    def test_missing_rust_arm_duplicate_row_changed_sample_and_relaxed_gate_fail(self):
        spec, rows = self.cohort()
        for bad in (rows[:-1], rows + [rows[0]], [r for r in rows if r["backend"] != "rust_byte_release"]):
            with self.assertRaises(ValueError):
                campaign.assess(bad, spec)
        for key in ("median_ratio_maximum", "p95_ratio_maximum", "p99_ratio_maximum"):
            changed = deepcopy(spec); changed["performance_gate"][key] = 2.0
            with self.subTest(gate=key), self.assertRaises(ValueError):
                campaign.assess(rows, changed)
        changed = deepcopy(rows); changed[0]["times_ns"][0] = True
        with self.assertRaises(ValueError):
            campaign.assess(changed, spec)

    def test_committed_protocol_matches_executable_registration(self):
        path = Path(__file__).resolve().parents[1] / "benchmarks/hia_outlined_aot/PROTOCOL.json"
        self.assertEqual(json.loads(path.read_text()), campaign.specification())

    def test_declared_sample_count_is_required_and_exact_for_every_arm_and_load(self):
        spec, rows = self.cohort()
        missing = object()
        for arm in campaign.ARMS:
            for calls in spec["batch_loads"]:
                row = next(r for r in rows if r["backend"] == arm and r["calls"] == calls)
                for value in (missing, None, True, False, 21.0, "21", 0, 1, 20, 22):
                    with self.subTest(arm=arm, calls=calls, value=repr(value)):
                        if value is missing:
                            row.pop("samples", None)
                        else:
                            row["samples"] = value
                        with self.assertRaises(ValueError):
                            campaign.assess(rows, spec)
                row["samples"] = spec["samples"]

    def test_elapsed_total_is_required_and_exact_for_every_arm_and_load(self):
        spec, rows = self.cohort()
        missing = object()
        for arm in campaign.ARMS:
            for calls in spec["batch_loads"]:
                row = next(r for r in rows if r["backend"] == arm and r["calls"] == calls)
                total = sum(row["times_ns"])
                for value in (missing, None, True, False, float(total), str(total), 0, -1, 1,
                              total - 1, total + 1, 2**64):
                    with self.subTest(arm=arm, calls=calls, value=repr(value)):
                        if value is missing:
                            row.pop("elapsed_ns", None)
                        else:
                            row["elapsed_ns"] = value
                        with self.assertRaises(ValueError):
                            campaign.assess(rows, spec)
                row["elapsed_ns"] = total

    def test_native_uint64_sample_and_total_bounds_are_not_python_integer_bounds(self):
        spec, rows = self.cohort()
        for arm in campaign.ARMS:
            row = next(r for r in rows if r["backend"] == arm)
            for first in (2**64 - 1, 2**64, 2**65):
                with self.subTest(arm=arm, first=first):
                    row["times_ns"] = [first] + [1] * (spec["samples"] - 1)
                    row["elapsed_ns"] = sum(row["times_ns"])
                    with self.assertRaises(ValueError):
                        campaign.assess(rows, spec)
            row["times_ns"] = [1000] * spec["samples"]
            row["elapsed_ns"] = sum(row["times_ns"])

    def test_exact_maximum_uint64_total_remains_admissible(self):
        spec, rows = self.cohort()
        for row in rows:
            row["times_ns"] = [2**64 - spec["samples"]] + [1] * (spec["samples"] - 1)
            row["elapsed_ns"] = 2**64 - 1
        result = campaign.assess(rows, spec)
        self.assertEqual(result["candidate_rust_comparisons_passed"], 372)
        self.assertTrue(all(r["passed"] for r in result["comparisons"]))

    def test_wrapped_elapsed_total_cannot_mask_overflow(self):
        spec, rows = self.cohort()
        for first in (2**64 - 1, 2**64):
            with self.subTest(first=first):
                rows[-1]["times_ns"] = [first] + [1] * (spec["samples"] - 1)
                rows[-1]["elapsed_ns"] = sum(rows[-1]["times_ns"]) % 2**64
                with self.assertRaises(ValueError):
                    campaign.assess(rows, spec)

    def test_assessment_preserves_inputs_and_is_independent_of_row_order(self):
        spec, rows = self.cohort()
        original_spec, original_rows = deepcopy(spec), deepcopy(rows)
        forward = campaign.assess(rows, spec)
        self.assertEqual(spec, original_spec)
        self.assertEqual(rows, original_rows)
        self.assertEqual(campaign.assess(list(reversed(rows)), spec), forward)
        self.assertEqual(spec, original_spec)
        self.assertEqual(rows, original_rows)

    def test_missing_or_invalid_timing_vector_fails_closed(self):
        spec, rows = self.cohort()
        missing = object()
        for value in (missing, None, (), [1] * 20, [1] * 22, [True] * 21,
                      [1.0] * 21, [0] * 21, [-1] * 21):
            with self.subTest(value=repr(value)):
                if value is missing:
                    rows[-1].pop("times_ns", None)
                else:
                    rows[-1]["times_ns"] = value
                with self.assertRaises(ValueError):
                    campaign.assess(rows, spec)

    def test_every_receipt_uses_the_existing_native_measurement_contract(self):
        spec, rows = self.cohort()
        with patch.object(release, "check_measurement", wraps=release.check_measurement) as check:
            campaign.assess(rows, spec)
        self.assertEqual(check.call_count, len(rows))
        for call, row in zip(check.call_args_list, rows):
            self.assertIs(call.args[0], row)
            self.assertEqual(call.kwargs, {"n": row["n"], "seed": row["seed"],
                "calls": row["calls"], "samples": spec["samples"]})

    def test_final_cohort_accounting_cannot_be_ignored(self):
        spec, rows = self.cohort()
        rows[-1]["samples"] = 1
        rows[-1]["elapsed_ns"] = 1
        with self.assertRaises(ValueError):
            campaign.assess(rows, spec)


if __name__ == "__main__":
    unittest.main()
