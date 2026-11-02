"""Registered prepared-gate integration controls; no native timing claims."""
from contextlib import contextmanager
from copy import deepcopy
from pathlib import Path
import unittest
from unittest.mock import patch

from tools import qualify_hia_native_ndu as native


def training_inputs(spec):
    training = {name: {"latency_ns": {str(n): 1000 for n in spec["sizes"]},
                      "preparation_ns": 5000, "resident_bytes": 4096}
                for name in spec["backends"]}
    products = {name: {"sha256": native.digest(name), "path": name} for name in spec["backends"]}
    return training, products


class PreparedGateProfileTests(unittest.TestCase):
    def test_registered_fast_skip_is_available_to_all_adaptive_controls_before_native_startup(self):
        spec = native.protocol("prepared-bank-v1")
        training, products = training_inputs(spec)
        for value in training.values():
            value["latency_ns"] = {str(n): 10000 for n in spec["sizes"]}
        training["hia"]["latency_ns"] = {str(n): 1 for n in spec["sizes"]}
        report = {"controller_calibration": {"status": "passed", "training_sha256": native.digest(training),
            "sha256": native.digest("unit-calibration"), "native_startup_ns": 8000, "native_shutdown_ns": 2000,
            "estimates_ns": {"exact_dp": 1000, "greedy": 1000, "native_ndu": 1000}}}
        owner = native.prepare_gate_bank(training, products, spec, report)

        class UnitDriver:
            def __init__(self):
                self.loaded = set()
            def load(self, name, unused):
                self.loaded.add(name)
                return {"transport_outer_ns": 1, "load_outer_ns": 1}
            def measure(self, *unused):
                return {"transport_outer_ns": 1}
            def mapping(self, unused):
                return {"backing_resident_bytes": 4096}

        @contextmanager
        def unit_driver(*unused):
            yield UnitDriver()

        with patch.object(native, "driver", unit_driver), \
                patch("hepta.hia_ndu_session.NduSession.for_stream_profile",
                      side_effect=AssertionError("zero savings cannot start native session")) as launch, \
                patch("hepta.hia_ndu_stateful.invocation_gate",
                      side_effect=AssertionError("prepared hot path cannot redo full intake")):
            native.execute_policies(Path("/unused-unit-fixture"), products, training, report, spec,
                                    "unused", "unused", prepared_bank=owner)
        launch.assert_not_called()
        self.assertEqual(len(report["policy_runs"]), 12)
        self.assertGreater(report["prepared_gate"]["actual_preparation_ns"], 0)
        for row in report["policy_runs"]:
            self.assertEqual(row["status"], "passed")
            self.assertEqual(row["native_invocations"], 0)
            self.assertEqual(row["incumbent_initializer"], "strong-training-fixed")
            self.assertEqual(row["initial_training_ready"], ["hia"])
            self.assertEqual([r["backend"] for r in row["initial_incumbent_loads"]], ["hia"])
            self.assertGreater(row["initial_selection_ns"], 0)
            for step in row["steps"]:
                self.assertGreater(step["controller_ns"], 0)
                self.assertEqual(step["chosen_ready"], ["hia"])
                if row["arm"] != "fixed":
                    self.assertEqual(step["invocation_gate"]["schema"],
                                     "hepta.hia.ndu.invocation-bound.lookup.v1")
                    self.assertEqual(step["invocation_gate"]["generation"], step["index"] + 1)
                    self.assertEqual(step["invocation_gate"]["budget_ns"], step["model"]["budget_ns"])
                else:
                    self.assertTrue(step["fixed_model_is_audit_only"])
        self.assertEqual(owner.close()["lookups"], 36)

    def test_future_episode_changes_do_not_change_training_only_prepared_bank(self):
        spec = native.protocol("prepared-bank-v1")
        training, products = training_inputs(spec)
        report, changed_report = {}, {}
        first = native.prepare_gate_bank(training, products, spec, report)
        changed = deepcopy(spec)
        changed["episodes"] = [{"sizes": [65536] * 4, "seeds": [99] * 4}]
        second = native.prepare_gate_bank(training, products, changed, changed_report)
        self.assertEqual(first.snapshot()["binding_sha256"], second.snapshot()["binding_sha256"])
        self.assertEqual(report["prepared_gate"]["future_evaluation_rows_used"], 0)
        first.close()
        second.close()

    def test_failed_preparation_retains_actual_work_and_never_publishes_an_owner(self):
        spec = native.protocol("prepared-bank-v1")
        training, products = training_inputs(spec)
        training["c"]["latency_ns"].pop("64")
        report = {}
        with self.assertRaises(KeyError):
            native.prepare_gate_bank(training, products, spec, report)
        self.assertEqual(report["prepared_gate"]["status"], "failed")
        self.assertGreater(report["prepared_gate"]["actual_preparation_ns"], 0)
        self.assertNotIn("initial", report["prepared_gate"])

    def test_actual_totals_and_standalone_preparation_never_weaken_fixed_costs(self):
        spec = native.protocol("prepared-bank-v1")
        report = {"offline_build_wall_ns": 10, "offline_validation_training_wall_ns": 20,
                  "failed_translation_outer_ns": 30, "runtime_identity_check_ns": 40,
                  "prepared_gate": {"actual_preparation_ns": 50, "close_ns": 6},
                  "controller_calibration": {"observed_attributed_cost_ns": {"exact_dp": 7, "greedy": 8, "native_ndu": 9},
                                             "shared_calibration_harness_ns": 11},
                  "reused_native_identity": {"build_cost": {"wall_ns": 10000}},
                  "policy_runs": [{"episode": episode, "arm": arm, "status": "passed", "actual_total_ns": 100 + episode}
                                  for episode in range(len(spec["episodes"])) for arm in spec["policy_arms"]]}
        result = native.prepared_observed_costs(report, spec)
        self.assertEqual(len(result["actual_total_comparisons_including_audit"]), 9)
        fixed = result["standalone_arm_known_components"]["fixed"]
        self.assertEqual(fixed["parts_ns"], {"common_bank_work_ns": 100, "actual_episode_totals_ns": 303,
                                           "controller_calibration_ns": 0, "prepared_owner_ns": 0})
        self.assertEqual(result["standalone_arm_known_components"]["native_ndu"]["parts_ns"]["prepared_owner_ns"], 56)
        self.assertEqual(result["calibration_harness_unassigned_ns"], 11)
        self.assertFalse(result["complete_lifecycle_cost_known"])
        self.assertFalse(result["whole_lifecycle_net_ndu_benefit_established"])
        report["policy_runs"].append(dict(report["policy_runs"][0]))
        with self.assertRaisesRegex(ValueError, "incomplete or repeated"):
            native.prepared_observed_costs(report, spec)

    def test_historical_default_and_new_registration_are_distinct(self):
        self.assertEqual(native.protocol()["schema"], "hepta.hia.native-economics.protocol.v3")
        new = native.protocol("prepared-bank-v1")
        self.assertEqual(new["schema"], "hepta.hia.native-economics.prepared-gate.protocol.v1")
        self.assertEqual(new["required_build_profile"], "verified-reduction-narrowed-release-v1")
        self.assertTrue(new["observed_total_gate"]["audit_is_included"])
        self.assertEqual(new["policy_arms"], ["fixed", "exact_dp", "greedy", "native_ndu"])
        self.assertNotEqual(new["episodes"], native.protocol()["episodes"])


if __name__ == "__main__":
    unittest.main()
