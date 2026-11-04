"""The experimental comparison cannot shrink or replace the historical gate."""
from copy import deepcopy
import unittest

from tools import qualify_hia_empty_reduction as experiment
from tools import qualify_hia_reduction_release as release


class EmptyReductionObservationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.spec = experiment.specification()
        cls.rows = [{"workload": w, "group": g["name"], "backend": a, "n": n,
                     "seed": seed, "calls": calls, "times_ns": [100] * cls.spec["samples"]}
                    for w in cls.spec["historical_profile"]["workloads"] for g in cls.spec["groups"]
                    for a in experiment.ARMS for n in g["sizes"] for seed in g["seeds"]
                    for calls in cls.spec["batch_loads"]]

    def test_full_v2_gate_and_both_rust_comparators_remain_present(self):
        self.assertEqual(self.spec["historical_profile"], release.specification(release.INDUCTION_PROFILE))
        result = experiment.assess(self.rows, self.spec)
        self.assertEqual(result["candidate_rust_comparisons_total"], 276)
        self.assertEqual(result["by_group"]["historical_regression"]["total"], 84)
        self.assertEqual(result["by_group"]["historical_holdout"]["total"], 96)
        self.assertEqual(result["by_group"]["prospective_lengths"]["total"], 96)
        self.assertFalse(result["broad_rust_performance_parity_established"])

    def test_wrapper_profile_keeps_historical_gate_and_uses_new_lengths(self):
        spec = experiment.specification(experiment.WRAPPER_PROFILE)
        self.assertEqual(spec["historical_profile"], self.spec["historical_profile"])
        self.assertEqual(spec["groups"][:2], self.spec["groups"][:2])
        self.assertEqual(spec["performance_gate"], self.spec["performance_gate"])
        self.assertFalse(set(spec["groups"][-1]["sizes"]) & set(self.spec["groups"][-1]["sizes"]))
        rows = [{"workload": w, "group": g["name"], "backend": a, "n": n,
                 "seed": seed, "calls": calls, "times_ns": [100] * spec["samples"]}
                for w in spec["historical_profile"]["workloads"] for g in spec["groups"]
                for a in experiment.ARMS for n in g["sizes"] for seed in g["seeds"] for calls in spec["batch_loads"]]
        self.assertEqual(experiment.assess(rows, spec)["candidate_rust_comparisons_total"], 276)

    def test_empty_input_regression_is_not_erased_by_faster_nonempty_cases(self):
        rows = deepcopy(self.rows)
        for row in rows:
            if row["backend"] == experiment.CANDIDATE:
                row["times_ns"] = [150 if row["n"] == 0 else 50] * self.spec["samples"]
        result = experiment.assess(rows, self.spec)
        self.assertFalse(result["candidate_all_registered_rust_gates_passed"])
        self.assertEqual(result["candidate_rust_comparisons_passed"], 264)
        self.assertEqual(result["by_group"]["historical_regression"]["passed"], 72)

    def test_registration_mutations_fail_closed(self):
        mutations = [lambda s: s["groups"].clear(), lambda s: s["arms"].pop(),
                     lambda s: s["groups"][0]["sizes"].remove(0),
                     lambda s: s["performance_gate"].update(p99_ratio_maximum=9),
                     lambda s: s.update(samples=1)]
        for mutate in mutations:
            spec = deepcopy(self.spec)
            mutate(spec)
            with self.assertRaises(ValueError):
                experiment.assess(self.rows, spec)

    def test_missing_duplicate_boolean_or_padded_samples_fail_closed(self):
        cases = [self.rows[:-1], self.rows + [self.rows[0]]]
        for value in ([], [True] * self.spec["samples"], [0] * self.spec["samples"], [100] * (self.spec["samples"] + 1)):
            changed = deepcopy(self.rows)
            changed[0]["times_ns"] = value
            cases.append(changed)
        for rows in cases:
            with self.assertRaises(ValueError):
                experiment.assess(rows, self.spec)

    def test_boolean_integer_aliases_are_refused_in_both_profiles(self):
        for profile in (experiment.CLONE_PROFILE, experiment.WRAPPER_PROFILE):
            spec = experiment.specification(profile)
            changed = deepcopy(spec)
            changed["groups"][0]["sizes"][0] = False
            with self.assertRaisesRegex(ValueError, "changed empty-entry observation registration"):
                experiment.assess([], changed)
            rows = [{"workload": w, "group": g["name"], "backend": a, "n": n,
                     "seed": seed, "calls": calls, "times_ns": [100] * spec["samples"]}
                    for w in spec["historical_profile"]["workloads"] for g in spec["groups"]
                    for a in experiment.ARMS for n in g["sizes"] for seed in g["seeds"] for calls in spec["batch_loads"]]
            for field, value in (("n", False), ("seed", True), ("calls", True),
                                 ("workload", 0), ("group", 0), ("backend", 0)):
                invalid = deepcopy(rows)
                invalid[0][field] = value
                with self.subTest(profile=profile, field=field), self.assertRaisesRegex(ValueError, "cohort field types"):
                    experiment.assess(invalid, spec)


if __name__ == "__main__":
    unittest.main()
