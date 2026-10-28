"""Registration drift and negative scientific outcomes cannot be hidden."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import qualify_hia_registered_followup as study


class RegisteredFollowupTests(unittest.TestCase):
    def fixture(self):
        return {"protocol": {"kind": "prepared-runtime", "queues": [{"id": 0}, {"id": 1}]},
                "source_bindings": {"real-source.py": "a" * 64}, "clang": {"sha256": "b" * 64},
                "python": {}, "environment": {}, "solver": {}}

    def register(self, root, value):
        destination = root / "registration.json"
        with patch.object(study, "inputs", return_value=value):
            study.register(destination, protocol_path="protocol", clang="clang")
        return destination

    def test_registration_rejects_source_tool_solver_or_environment_drift_before_work(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = self.fixture()
            registration = self.register(root, original)
            for field in ("source_bindings", "clang", "solver", "environment"):
                changed = deepcopy(original)
                changed[field]["new"] = "different"
                output = root / field
                with self.subTest(field=field), patch.object(study, "inputs", return_value=changed), \
                        patch.object(study, "runtime_sample", side_effect=AssertionError("executed")):
                    with self.assertRaisesRegex(ValueError, "changed after registration"):
                        study.run(output, registration_path=registration, protocol_path="protocol", clang="clang")
                self.assertFalse(output.exists())

    def test_registration_content_tampering_does_not_rewrite_the_expected_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = self.fixture()
            registration = self.register(root, value)
            data = json.loads(registration.read_bytes())
            data["registered_before_workloads"] = False
            registration.write_text(json.dumps(data))
            with patch.object(study, "inputs", return_value=value):
                with self.assertRaisesRegex(ValueError, "Registration bytes changed"):
                    study.require_registration(registration, protocol_path="protocol", clang="clang")

    def test_negative_queue_is_retained_and_fails_the_all_groups_benefit_gate(self):
        def sample(directory, *, profile, **kwargs):
            positive = profile["id"] == 0
            return {"status": "measured", "automatic_selected": positive,
                    "deployment_net_positive": positive, "measured_net_ns": 100 if positive else -100,
                    "deployment_entire_api_ns": 1000 if positive else 1200,
                    "baseline_native_execution_ns": 10**12 if positive else 0,
                    "audit_entire_api_ns": 0, "profile": profile}
        with tempfile.TemporaryDirectory() as temporary:
            root, value = Path(temporary), self.fixture()
            registration = self.register(root, value)
            with patch.object(study, "inputs", return_value=value), \
                    patch.object(study, "retain_sources", return_value={"files": 1}), \
                    patch.object(study, "runtime_sample", side_effect=sample):
                result = study.run(root / "result", registration_path=registration,
                                   protocol_path="protocol", clang="clang")
            self.assertEqual(result["status"], "completed")
            self.assertTrue(result["implementation_gate_passed"])
            self.assertFalse(result["finite_net_benefit_gate_passed"])
            self.assertEqual([r["profile"]["id"] for r in result["samples"]], [0, 1])
            self.assertLess(result["samples"][1]["net_after_validation_and_evidence_ns"], 0)
            self.assertTrue((root / "result/sample-1.json").exists())

    def test_native_failure_is_retained_as_failure_without_substituting_a_sample(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, value = Path(temporary), self.fixture()
            registration = self.register(root, value)
            with patch.object(study, "inputs", return_value=value), \
                    patch.object(study, "retain_sources", return_value={"files": 1}), \
                    patch.object(study, "runtime_sample", side_effect=RuntimeError("native failed")) as run:
                result = study.run(root / "failed", registration_path=registration,
                                   protocol_path="protocol", clang="clang")
            self.assertEqual(run.call_count, 1)
            self.assertEqual(result["status"], "failed-retained")
            self.assertFalse(result["implementation_gate_passed"])
            self.assertFalse(result["finite_net_benefit_gate_passed"])
            self.assertEqual(result["error"]["message"], "native failed")
            self.assertTrue((root / "failed/RESULT.json").exists())

    def test_changed_source_is_not_retained_as_the_registered_snapshot(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "source.py").write_text("changed source\n")
            with patch.object(study, "ROOT", root):
                with self.assertRaisesRegex(ValueError, "changed during snapshot"):
                    study.retain_sources(root / "evidence", {"source.py": "0" * 64})
            self.assertFalse((root / "evidence").exists())

    def test_ndu_median_win_does_not_override_total_cost_loss_or_missing_build_cost(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            native = root / "native.bin"
            native.write_bytes(b"identity-only-fake; this control never executes native code")
            value = self.fixture()
            value["protocol"] = {"kind": "stream-ndu", "graph": {}}
            value["native_build"] = {"binary": {"path": str(native), "sha256": study.sha(native.read_bytes())},
                                     "value": {"source": "synthetic-control"}}
            registration = self.register(root, value)
            for index, (ndu_cost, complete) in enumerate(((2 * 10**12, True), (1, False))):
                measured = {"study_wall_ns": 0, "all_episodes_completed": True,
                    "all_outputs_correct": True, "all_actual_budgets_passed": True,
                    "setup_accounting": {"cost_complete_within_scope": complete},
                    "ndu_descriptive_cost_lower_than_fixed": True,
                    "ndu_descriptive_cost_lower_than_light": True,
                    "standalone_total_cost_ns": {"ndu": ndu_cost, "fixed-best-plan": 10**12, "light": 9 * 10**11}}
                with patch.object(study, "inputs", return_value=value), \
                        patch.object(study, "retain_sources", return_value={"files": 1}), \
                        patch("tools.qualify_hia_ndu_graph.qualify", return_value=measured):
                    result = study.run(root / ("ndu-" + str(index)), registration_path=registration,
                                       protocol_path="protocol", clang="clang", native_identity="synthetic")
                self.assertEqual(result["status"], "completed")
                self.assertTrue(result["implementation_gate_passed"])
                self.assertFalse(result["finite_net_benefit_gate_passed"])
                self.assertGreaterEqual(result["standalone_total_cost_with_wrapper_ns"]["ndu"], ndu_cost)


if __name__ == "__main__":
    unittest.main()
