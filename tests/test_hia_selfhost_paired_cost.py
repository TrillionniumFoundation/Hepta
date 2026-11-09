"""Synthetic evidence accounting tests; no benchmark or native timing claims."""
from copy import deepcopy
import unittest

from tools.analyze_hia_selfhost_machine_plans import (
    ARMS, ORIGINAL_SCHEMA, WORKLOADS, decode, schedule, summarize,
)


def fixture():
    values = {"canonical": [10, 20, 1000], "compact_immediates": [11, 9, 900],
              "compact_swapped_scratch": [12, 22, 1100]}
    report = {"schema": ORIGINAL_SCHEMA, "status": "passed", "repetitions": 3,
              "checkout": {"kind": "synthetic_test_only"},
              "campaign_cost": {"wall_ns": 100000, "parent_cpu_ns": 700, "children_cpu_ns": 7000},
              "arms": {}, "workload": {w: {"sha256": str(i + 1) * 64} for i, w in enumerate(WORKLOADS)},
              "native_invocations": [], "phases": []}

    def phase(label, cost=3000):
        report["phases"].append({"label": label, "status": "completed", "wall_ns": cost,
                                 "parent_cpu_ns": 1, "children_cpu_ns": 1,
                                 "started_monotonic_ns": 100, "finished_monotonic_ns": 100 + cost})

    phase("source_and_core_registration")
    for i, arm in enumerate(ARMS):
        report["arms"][arm] = {"shared_sha256": str(i + 3) * 64,
                               "timings_ns": {w: list(values[arm]) for w in WORKLOADS}}
        phase("emit/" + arm, 100 + i * 100)
        phase("rederive_link/" + arm, 100 + i * 100)
    for repeat, workload, arm in schedule(3):
        case = f"compile-{workload}-r{repeat}-{arm}"
        row = {"case": case, "status": "returned", "abi_status": 0, "source_unchanged": True,
               "native_elapsed_ns": values[arm][repeat], "wall_elapsed_ns": 2000,
               "input_sha256": report["workload"][workload]["sha256"],
               "source_sha256": report["workload"][workload]["sha256"],
               "artifact_sha256": report["arms"][arm]["shared_sha256"],
               "image_sha256": report["arms"][arm]["shared_sha256"],
               "core_u32": 10, "output_sha256": "a" * 64, "produced_sha256": "b" * 64}
        report["native_invocations"].append(row)
        phase("native/" + case)
    report["native_invocations"].extend(
        {"case": f"control-{i}", "status": "returned", "abi_status": 0, "source_unchanged": True}
        for i in range(39))
    return report


class PairedCompilerCostTests(unittest.TestCase):
    def test_original_pairs_not_difference_of_unpaired_medians(self):
        result = summarize(fixture())
        row = result["comparisons"][0]
        self.assertEqual(row["median_paired_saving_ns"], 11)
        self.assertEqual(row["positive_saving_pairs"], 2)
        self.assertEqual(row["conditional_observed_break_even_calls"], 19)
        self.assertEqual(result["original_campaign_cost"]["wall_ns"], 100000)
        self.assertEqual(result["acceptance"], "HOLD")
        self.assertFalse(result["full_lifecycle_cost_known"])
        self.assertIsNone(row["full_lifecycle_break_even_calls"])

    def test_tail_retains_the_slowest_original_observation(self):
        result = summarize(fixture())
        self.assertEqual(result["workloads"]["compiler"]["canonical"]["empirical_p95_ns"], 1000)
        self.assertEqual(result["comparisons"][1]["empirical_p95_ratio"], 1.1)
        self.assertIsNone(result["comparisons"][1]["conditional_observed_break_even_calls"])

    def test_incomplete_campaign_keeps_outer_cost_and_infers_no_saving(self):
        report = fixture()
        report.update(status="failed", error={"type": "TimeoutError", "message": "synthetic"})
        report["native_invocations"] = report["native_invocations"][:2]
        result = summarize(report)
        self.assertFalse(result["complete_paired_inventory"])
        self.assertEqual(result["comparisons"], [])
        self.assertEqual(result["original_campaign_cost"]["children_cpu_ns"], 7000)
        self.assertEqual(result["original_error"], report["error"])

    def test_missing_counterfactual_is_not_zero(self):
        report = fixture()
        del report["native_invocations"][0]
        with self.assertRaisesRegex(ValueError, "order or pair inventory"):
            summarize(report)

    def test_reordered_pair_refuses_paired_inference(self):
        report = fixture()
        rows = report["native_invocations"]
        rows[0], rows[1] = rows[1], rows[0]
        with self.assertRaisesRegex(ValueError, "order or pair inventory"):
            summarize(report)

    def test_summary_cannot_replace_original_timing(self):
        report = fixture()
        report["arms"]["compact_immediates"]["timings_ns"]["compiler"][0] = 1
        with self.assertRaisesRegex(ValueError, "summary does not match"):
            summarize(report)

    def test_equal_timings_do_not_replace_equal_inputs_and_outputs(self):
        for key in ("source_sha256", "input_sha256", "output_sha256", "produced_sha256", "artifact_sha256"):
            report = fixture()
            report["native_invocations"][1][key] = "f" * 64
            with self.subTest(key=key), self.assertRaises(ValueError):
                summarize(report)

    def test_missing_control_stays_in_original_denominator(self):
        report = fixture()
        report["native_invocations"].pop()
        with self.assertRaisesRegex(ValueError, "control inventory incomplete"):
            summarize(report)

    def test_failed_control_cannot_leave_report_passing(self):
        report = fixture()
        report["native_invocations"][-1]["status"] = "child_failed"
        with self.assertRaisesRegex(ValueError, "failed native call"):
            summarize(report)

    def test_native_and_outer_intervals_must_nest(self):
        for key, value in (("native_elapsed_ns", 3001), ("wall_elapsed_ns", 4000)):
            report = fixture()
            report["native_invocations"][0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                summarize(report)

    def test_missing_preparation_is_unknown_not_free(self):
        report = fixture()
        report["phases"] = [p for p in report["phases"] if p["label"] != "emit/compact_immediates"]
        with self.assertRaisesRegex(ValueError, "preparation phase absent"):
            summarize(report)

    def test_duplicate_and_nonfinite_json_fields_are_refused(self):
        for raw in ('{"wall_ns":1,"wall_ns":2}', '{"wall_ns":NaN}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                decode(raw)


if __name__ == "__main__":
    unittest.main()
