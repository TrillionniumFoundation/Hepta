"""Finite boolean values drive CFG choices; resource verifier remains authority."""
from copy import deepcopy
import unittest

from test_hia_resource_trace import fixture
from hepta.hia_boolean_trace import (
    HIABooleanTraceRejected, replay_boolean_resource_path,
)


class HIABooleanTraceTests(unittest.TestCase):
    def test_true_and_false_input_drive_same_verified_owned_lifetime(self):
        graph, checked = fixture()
        for value, target in ((True, "yes"), (False, "no")):
            with self.subTest(value=value):
                result = replay_boolean_resource_path(graph, checked, "f", inputs={"p0": value})
                self.assertEqual(result["blocks_visited"], ["entry", target, "done"])
                self.assertEqual(result["edge_decisions"][0]["value"], value)
                self.assertEqual(result["resource_operation_counts"]["acquire"], 1)
                self.assertEqual(result["resource_operation_counts"]["drop"], 1)
                self.assertFalse(result["claims"]["source_to_ir_refinement_proved"])
                self.assertFalse(result["claims"]["full_memory_ssa_proved"])

    def test_false_loop_condition_exits_and_true_exhausts_fuel(self):
        graph, checked = fixture(loop=True)
        passed = replay_boolean_resource_path(graph, checked, "f", inputs={"p0": False})
        self.assertEqual(passed["blocks_visited"], ["entry", "header", "exit"])
        with self.assertRaisesRegex(HIABooleanTraceRejected, "fuel exhausted"):
            replay_boolean_resource_path(graph, checked, "f", inputs={"p0": True}, fuel=10)

    def test_borrowed_owner_retains_same_independent_resource_protection(self):
        graph, checked = fixture(borrow=True)
        report = replay_boolean_resource_path(graph, checked, "f", inputs={"p0": False})
        ops = report["resource_operation_counts"]
        self.assertEqual((ops["borrow"], ops["end_borrow"], ops["drop"]), (1, 1, 1))

    def test_forged_receipt_or_invalid_resource_path_refuses(self):
        graph, verified = fixture()
        mutations = (
            lambda g, v: v["claims"].update(termination_proved=0),
            lambda g, v: v.update(ir_sha256="f"*64),
            lambda g, v: g["functions"][0]["blocks"][2]["ops"].append(
                {"op": "drop", "src": "v0"}),
        )
        for mutate in mutations:
            g, r = deepcopy(graph), deepcopy(verified)
            mutate(g, r)
            with self.assertRaisesRegex(HIABooleanTraceRejected, "E_HIA_BOOL_TRACE"):
                replay_boolean_resource_path(g, r, "f", inputs={"p0": True})

    def test_unknown_computed_or_mutated_condition_refuses(self):
        graph, verified = fixture()
        graph["functions"][0]["blocks"][0]["term"]["condition"] = "v0"
        with self.assertRaisesRegex(HIABooleanTraceRejected, "computed/unknown"):
            replay_boolean_resource_path(graph, verified, "f", inputs={"p0": True})
        graph, verified = fixture()
        graph["functions"][0]["blocks"][0]["ops"].append(
            {"op": "use", "place": {"root": "p0", "path": []}, "mode": "write"})
        with self.assertRaisesRegex(HIABooleanTraceRejected, "may be mutated"):
            replay_boolean_resource_path(graph, verified, "f", inputs={"p0": True})

    def test_unhashable_resource_operands_reject_structurally(self):
        for replacement in (
            {"op": ["use"], "place": {"root": "p0", "path": []}, "mode": "write"},
            {"op": "use", "place": {"root": [], "path": []}, "mode": "write"},
            {"op": "use", "place": {"root": "p0", "path": []}, "mode": ["write"]},
        ):
            with self.subTest(replacement=replacement):
                graph, verified = fixture()
                graph["functions"][0]["blocks"][0]["ops"].append(replacement)
                with self.assertRaisesRegex(HIABooleanTraceRejected, "E_HIA_BOOL_TRACE"):
                    replay_boolean_resource_path(graph, verified, "f", inputs={"p0": True})

    def test_wrong_input_type_or_inventory_refuses(self):
        graph, verified = fixture()
        for args in ({"p0": 1}, {"p0": 0}, {"p0": "true"},
                     {"p0": True, "another": False}, {}, {"missing": True}):
            with self.subTest(args=args):
                with self.assertRaisesRegex(HIABooleanTraceRejected, "E_HIA_BOOL_TRACE"):
                    replay_boolean_resource_path(graph, verified, "f", inputs=args)

    def test_unknown_return_kind_and_fuel_bound_refuses(self):
        graph, verified = fixture()
        with self.assertRaisesRegex(HIABooleanTraceRejected, "E_HIA_BOOL_TRACE"):
            replay_boolean_resource_path(graph, verified, "f", inputs={"p0": True}, fuel=2)
        graph["functions"][0]["blocks"][0]["term"]["op"] = "switch"
        with self.assertRaisesRegex(HIABooleanTraceRejected, "E_HIA_BOOL_TRACE"):
            replay_boolean_resource_path(graph, verified, "f", inputs={"p0": True})

if __name__ == "__main__":
    unittest.main()
