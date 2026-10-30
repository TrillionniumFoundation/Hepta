"""Actual overwrite/self-move lifecycle and declaration-bound refusal controls."""
from __future__ import annotations

import copy
import os
from pathlib import Path
import shutil
import tempfile
import unittest

from hepta.cpp_unique_assignment import UniqueAssignmentTranslator
from hepta.cpp_unique_project import lower_unique_assignment_matrix
from tools.qualify_cpp_unique_assignment_project import EXAMPLE, cases, oracle, qualify

CLANGXX = os.environ.get("CLANGXX", "/usr/bin/clang++-20")
CLANG = os.environ.get("CLANG", "/usr/bin/clang-20")


class AssignmentModelTests(unittest.TestCase):
    def test_overwritten_destination_releases_forward_and_final_owner_reverse(self):
        row = oracle((3, 5, 7, 0, 0, 0, 0), "three_weight")
        self.assertEqual(row["events"], [[1, 1, 3], [1, 2, 5], [1, 3, 5], [1, 4, 3],
                                         [2, 3, 5], [2, 4, 3], [2, 2, 5], [2, 1, 3]])
        self.assertEqual(row["expected"], (7 ^ 91) * 3 + (7 ^ 37) + 8)
        self.assertEqual(row["allocated"], 4)

    def test_partial_destination_failure_cleans_partial_then_original(self):
        row = oracle((3, 5, 7, 0, 0, 0, 4), "five_weight")
        self.assertEqual(row["events"], [[1, 1, 3], [1, 2, 5], [1, 3, 5], [3, 4, 3],
                                         [2, 3, 5], [2, 2, 5], [2, 1, 3]])
        self.assertEqual((row["expected"], row["refusals"]), (1001, 1))

    def test_zero_sized_and_early_owners_do_not_invent_allocations(self):
        self.assertEqual(oracle((0, 0, 255, 0, 0, 0, 0), "three_weight")["events"], [])
        row = oracle((3, 5, 7, 0, 0, 1, 4), "three_weight")
        self.assertEqual((row["expected"], row["allocated"], row["refusals"]), (2001, 2, 0))
        for variant in ("three_weight", "five_weight"):
            families = {row["family"] for row in cases(variant)}
            self.assertTrue({"allocation_refusal_3", "allocation_refusal_4",
                             "replacement_self_move_cross_unit_success"} <= families)

    def translator(self):
        translator = object.__new__(UniqueAssignmentTranslator)
        translator.class_name = "Pair"
        translator.leaf_name = "Leaf"
        translator.fields = {}
        translator.serial = 0
        translator.stats = {"owner_move_assignments": 0, "owner_self_move_assignments": 0}
        translator.move_assignment = {"id": "assign", "kind": "CXXMethodDecl", "name": "operator=",
                                      "type": {"qualType": "Pair &(Pair &&) noexcept"}}
        return translator

    @staticmethod
    def owner(name, *, parameter=False):
        return {"kind": "DeclRefExpr", "type": {"qualType": "Pair"}, "valueCategory": "lvalue",
                "referencedDecl": {"id": name, "name": name,
                                   "kind": "ParmVarDecl" if parameter else "VarDecl",
                                   "type": {"qualType": "Pair"}}}

    def assignment(self, target="destination", source="source", *, parameter=False):
        return {"kind": "CXXOperatorCallExpr", "type": {"qualType": "Pair"}, "valueCategory": "lvalue",
                "inner": [{"kind": "ImplicitCastExpr", "castKind": "FunctionToPointerDecay",
                           "inner": [{"kind": "DeclRefExpr", "referencedDecl": self.translator().move_assignment}]},
                          self.owner(target, parameter=parameter),
                          {"kind": "CXXStaticCastExpr", "castKind": "NoOp", "valueCategory": "xvalue",
                           "type": {"qualType": "Pair"}, "inner": [self.owner(source, parameter=parameter)]}]}

    @staticmethod
    def environment():
        return {name: {"type": "owner", "cpp_type": "Pair", "source_name": name,
                       "emitted": "live_" + name, "alive": True} for name in ("destination", "source")}

    def lower(self, translator, node, env, **kwargs):
        return translator.extension_statement(node, env, context="lifecycle", const=False,
                                               nested=kwargs.get("nested", False), scope_depth=0)

    def test_distinct_owners_consume_source_and_rebind_destination(self):
        translator, env = self.translator(), self.environment()
        result = self.lower(translator, self.assignment(), env)
        self.assertEqual(result, ["let mut assigned1 = HeptaComposite_assign(move live_destination, move live_source);"])
        self.assertFalse(env["source"]["alive"])
        self.assertTrue(env["destination"]["alive"])
        self.assertEqual(env["destination"]["emitted"], "assigned1")
        with self.assertRaisesRegex(ValueError, "moved-from"):
            self.lower(translator, self.assignment(), env)

    def test_self_move_of_by_value_parameter_preserves_exact_environment(self):
        translator, env = self.translator(), self.environment()
        before = copy.deepcopy(env)
        self.assertEqual(self.lower(translator, self.assignment("source", "source", parameter=True), env), [])
        self.assertEqual(env, before)
        self.assertEqual(translator.stats["owner_self_move_assignments"], 1)

    def test_unbound_member_conditional_assignment_and_non_rvalue_reject(self):
        node = self.assignment()
        node["inner"][0]["inner"][0]["referencedDecl"]["id"] = "another_member"
        with self.assertRaisesRegex(ValueError, "captured defaulted member"):
            self.lower(self.translator(), node, self.environment())
        with self.assertRaisesRegex(ValueError, "top-level lifecycle"):
            self.lower(self.translator(), self.assignment(), self.environment(), nested=True)
        node = self.assignment()
        node["inner"][2]["castKind"] = "BitCast"
        with self.assertRaisesRegex(ValueError, "rvalue"):
            self.lower(self.translator(), node, self.environment())


@unittest.skipUnless(shutil.which(CLANGXX), "Actual Clang20+ and standard C++ headers required")
class UniqueAssignmentNativeTests(unittest.TestCase):
    def test_actual_two_configuration_destination_replacement(self):
        if not all(shutil.which(tool) for tool in (CLANG, "gcc", "g++")):
            self.skipTest("Actual native C/C++ compilers required")
        with tempfile.TemporaryDirectory(prefix="hepta-unique-assignment-") as temporary:
            report = qualify(Path(temporary) / "native", clangxx=CLANGXX, clang=CLANG)
        self.assertTrue(report["ok"], report.get("error"))
        self.assertEqual(len(report["variants"]), 2)
        for row in report["variants"]:
            self.assertEqual(row["case_count"], len(cases(row["name"])))
            self.assertEqual(row["expected"]["allocations"], row["expected"]["frees"])
            self.assertEqual(row["expected"]["live"], 0)
            self.assertEqual(row["migration"]["unconverted_declarations"], [])
            stats = row["migration"]["translation_statistics"]
            self.assertEqual(stats["owner_move_assignments"], 1)
            self.assertEqual(stats["owner_self_move_assignments"], 2)
            self.assertEqual(row["standalone_hia"]["original_cpp_link_inputs"], [])
            negative = report["negative_controls"]
            self.assertTrue(negative[row["name"] + "_missing_drop"]["rejected"])
            self.assertFalse(negative[row["name"] + "_missing_drop"]["artifact_exists"])
            self.assertTrue(negative[row["name"] + "_wrong_assignment_cleanup_order"]["detected"])

    def test_actual_leaf_without_self_move_guard_rejects(self):
        with tempfile.TemporaryDirectory(prefix="hepta-unique-assignment-invalid-") as temporary:
            project = Path(temporary) / "project"
            shutil.copytree(EXAMPLE, project)
            path = project / "owners.h"
            source = path.read_text()
            self.assertIn("if (this != &other)", source)
            path.write_text(source.replace("if (this != &other)", "if (true)"))
            with self.assertRaisesRegex(ValueError, "unique-array wrapper"):
                lower_unique_assignment_matrix(project / "matrix.json", clangxx=CLANGXX)


if __name__ == "__main__":
    unittest.main()
