"""Resource/forecast boundaries of the separate native dynamic experiment."""
from copy import deepcopy
import unittest

from hepta.hia_ndu_dynamic import DynamicError, action, invocation_gate, validate_model
from tools.qualify_hia_ndu_dynamic import control_model, schedule, exhaustive_cost, independent_exact_minimum

class DynamicModelBoundaryTests(unittest.TestCase):
    def test_bool_is_not_integer_cost(self):
        model = control_model()
        model["budget_ns"] = True
        with self.assertRaises(DynamicError):
            validate_model(model)

    def test_unknown_model_field_refuses(self):
        model = control_model()
        model["execute"] = "foreign artifact"
        with self.assertRaises(DynamicError):
            validate_model(model)

    def test_custom_mapping_key_is_rejected_before_hashing(self):
        class Key:
            calls = 0
            def __hash__(self):
                type(self).calls += 1
                return 31
        model = control_model()
        del model["schema"]
        model[Key()] = "schema"
        before = Key.calls
        with self.assertRaises(DynamicError):
            validate_model(model)
        self.assertEqual(Key.calls, before)

    def test_schema_string_subclass_is_not_admitted(self):
        class PretendSchema(str):
            def __eq__(self, _):
                return True
        model = control_model()
        model["schema"] = PretendSchema("not-the-model-schema")
        with self.assertRaises(DynamicError):
            validate_model(model)

    def test_epoch_rollback_and_stale_future_refuse(self):
        for epochs in ([1, 2, 1], [0, 1, 2]):
            model = control_model()
            model["artifacts"][0]["epochs"] = list(epochs)
            with self.assertRaises(DynamicError):
                validate_model(model)

    def test_invalidation_retires_and_reacquires_same_bit(self):
        model = control_model(objects=1, horizon=2)
        model["ready_mask"] = 1
        model["ready_epochs"] = [1]
        model["artifacts"][0]["epochs"] = [2, 2]
        model = validate_model(model)
        step = action(model, 0, 1, 1)
        self.assertEqual((step["invalidated"], step["retired"], step["acquired"]), (1, 1, 1))
        self.assertEqual(step["mode"], "invoke")

    def test_resident_quota_cannot_be_relaxed_by_candidate(self):
        model = control_model(objects=2, horizon=1)
        model["ready_mask"] = 0
        model["ready_epochs"] = [0, 0]
        model["memory_quota_bytes"] = 64
        validate_model(model)
        with self.assertRaises(DynamicError):
            action(model, 0, 0, 3)

    def test_gate_does_not_launch_after_budget_consumed(self):
        model = control_model(objects=1, horizon=3)
        model["ready_mask"] = 0
        model["ready_epochs"] = [0]
        model["direct_ns"] = [100000] * 3
        model["packed_ns"] = [1] * 3
        model["budget_ns"] = 0
        self.assertFalse(invocation_gate(validate_model(model))["invoke"])

    def test_future_changes_pay_solver_but_reuse_does_not(self):
        model = validate_model(control_model(objects=1, horizon=2))
        changed = action(model, 1, 0, 1)
        self.assertEqual(changed["future_decision_ns"], 18)
        same = action(model, 1, 0, 0)
        self.assertEqual(same["future_decision_ns"], 0)

    def test_model_detaches_mutable_caller_data(self):
        raw = control_model()
        saved = deepcopy(raw)
        model = validate_model(raw)
        raw["artifacts"][0]["prepare_ns"] = 99999
        self.assertEqual(model, saved)

    def test_registered_inputs_do_not_depend_on_observations(self):
        specification = {"matrix_count": 6, "episode_steps": 24}
        first = schedule("invalidate_recover", 7001, specification)
        self.assertEqual(first, schedule("invalidate_recover", 7001, specification))
        self.assertEqual(sum(bool(v["mutations"]) for v in first), 3)
        self.assertEqual(len(first), 24)

    def test_offline_bottom_up_matches_full_schedule_enumeration(self):
        for seed in range(12):
            model = control_model(objects=1 + seed % 3, horizon=1 + seed % 3, seed=seed)
            self.assertEqual(independent_exact_minimum(model), exhaustive_cost(model))

    def test_empty_native_plan_is_not_proof_of_infeasibility(self):
        model = control_model(objects=1, horizon=1)
        self.assertIsNotNone(independent_exact_minimum(model))
        model["budget_ns"] = 0
        self.assertIsNone(independent_exact_minimum(model))

if __name__ == "__main__":
    unittest.main()
