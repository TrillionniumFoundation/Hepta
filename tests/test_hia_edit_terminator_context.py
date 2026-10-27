"""Every displayed terminator must have its local SSA inputs in the view.

An unaffected branch predicate or return value still decides what a displayed
block does. These controls check actual Core execution as well as the context
invariant; the editing view remains neither executable code nor an equivalence
proof.
"""
from __future__ import annotations

import copy
import unittest

from hepta.hia_edit_batch import apply_batch, prepare_batch, render_batch_context
from hepta.hia_edit_query import (
    MAX_VISIBLE_OPERATIONS, apply_edit, prepare_edit, render_edit_context,
)
from hepta.hia_program_runtime import execute_program
from hepta.hia_program_tools import HIAEditRejected
from tests.test_hia_edit_cfg_context import branch_and_join
from tests.test_hia_program import b, branch, c, f, i, jump, m, ret


class TerminatorContextTests(unittest.TestCase):
    def assert_locally_closed(self, params, instructions, term):
        """Independent view invariant, including every CFG alternative."""
        visible = {parameter["name"] for parameter in params}
        for entry in sorted(instructions, key=lambda item: item["index"]):
            operation = entry["operation"]
            self.assertTrue(set(operation["args"]).issubset(visible), operation)
            visible.update(output["name"] for output in operation["out"])
        if term["op"] == "ret":
            required = term["values"]
        elif term["op"] == "jump":
            required = term["args"]
        elif term["op"] == "branch":
            required = [term["cond"], *term["then"]["args"], *term["else"]["args"]]
        else:
            self.assertEqual(term["op"], "trap")
            required = []
        self.assertTrue(set(required).issubset(visible), (required, visible))

    def assert_query_closed(self, query):
        context = query["context"]
        self.assert_locally_closed(context["block_params"], [
            *context["dependencies"], *context["consumers"],
            {"index": context["operation_index"], "operation": context["operation"]},
        ], context["terminator"])
        for block in context["downstream"]:
            self.assert_locally_closed(block["params"], [
                *block["dependencies"], *block["consumers"],
            ], block["terminator"])

    def test_unaffected_branch_predicate_is_visible_with_real_branch_outcomes(self):
        source = branch_and_join()
        query = prepare_edit(source, function="calc", block="entry",
                             output="selected", fields=["op"])
        self.assert_query_closed(query)
        self.assertEqual([row["index"] for row in query["context"]["dependencies"]], [0, 1, 3])
        rendered = render_edit_context(query)
        self.assertIn("%test:bool = compare.eq(%x,%zero)", rendered)
        changed, _ = apply_edit(source, query, {"op": "int.sub.wrap"})
        self.assertEqual(execute_program(source, "calc", [0])["result"], 4)
        self.assertEqual(execute_program(changed, "calc", [0])["result"], 2**32 - 4)
        self.assertEqual(execute_program(changed, "calc", [7])["result"], 10)

    def test_independent_return_closes_inputs_without_becoming_an_affected_use(self):
        source = m(f("calc", [("x", "u32")], ["u32"], [], [
            b("entry", [("x", "u32")], [
                c("one", "u32", 1),
                i("int.add.wrap", ["x", "one"], [("selected", "u32")]),
                c("two", "u32", 2),
                i("int.mul.wrap", ["x", "two"], [("answer", "u32")]),
            ], ret("answer")),
        ]))
        query = prepare_edit(source, function="calc", block="entry",
                             output="selected", fields=["op"])
        self.assert_query_closed(query)
        self.assertEqual(query["context"]["consumers"], [])
        self.assertEqual([row["index"] for row in query["context"]["dependencies"]], [0, 2, 3])
        changed, _ = apply_edit(source, query, {"op": "int.sub.wrap"})
        self.assertEqual(execute_program(changed, "calc", [7])["result"], 14)

    def test_downstream_unaffected_branch_condition_and_alternate_value_are_closed(self):
        source = m(f("calc", [("x", "u32")], ["u32"], [], [
            b("entry", [("x", "u32")], [
                c("one", "u32", 1),
                i("int.add.wrap", ["x", "one"], [("selected", "u32")]),
            ], jump("middle", "selected", "x")),
            b("middle", [("carried", "u32"), ("original", "u32")], [
                c("zero", "u32", 0),
                i("compare.ne", ["original", "zero"], [("take", "bool")]),
                c("delta", "u32", 1),
                i("int.add.wrap", ["carried", "delta"], [("adjusted", "u32")]),
                c("fallback", "u32", 99),
            ], branch("take", ("done", "adjusted"), ("done", "fallback"))),
            b("done", [("answer", "u32")], [], ret("answer")),
        ]))
        query = prepare_edit(source, function="calc", block="entry",
                             output="selected", fields=["op"])
        self.assert_query_closed(query)
        middle = query["context"]["downstream"][0]
        self.assertEqual([row["index"] for row in middle["dependencies"]], [0, 1, 2, 4])
        self.assertEqual([row["index"] for row in middle["consumers"]], [3])
        self.assertFalse(middle["branch_condition_affected"])
        changed, _ = apply_edit(source, query, {"op": "int.sub.wrap"})
        self.assertEqual(execute_program(changed, "calc", [0])["result"], 99)
        self.assertEqual(execute_program(changed, "calc", [3])["result"], 3)

    def test_jump_closes_unaffected_forwarded_value_and_transitive_inputs(self):
        source = m(f("calc", [("x", "u32")], ["u32"], [], [
            b("entry", [("x", "u32")], [
                c("one", "u32", 1),
                i("int.add.wrap", ["x", "one"], [("selected", "u32")]),
                c("two", "u32", 2),
                i("int.mul.wrap", ["x", "two"], [("independent", "u32")]),
            ], jump("done", "selected", "independent")),
            b("done", [("left", "u32"), ("right", "u32")], [
                i("int.add.wrap", ["left", "right"], [("answer", "u32")]),
            ], ret("answer")),
        ]))
        query = prepare_edit(source, function="calc", block="entry",
                             output="selected", fields=["op"])
        self.assert_query_closed(query)
        self.assertEqual(query["context"]["downstream"][0]["affected_params"], ["left"])
        changed, _ = apply_edit(source, query, {"op": "int.sub.wrap"})
        self.assertEqual(execute_program(changed, "calc", [4])["result"], 11)

    def test_terminator_dependency_call_exposes_its_actual_callee_interface(self):
        source = m(
            f("predicate", [("arg", "u32")], ["bool"], [], [
                b("entry", [("arg", "u32")], [
                    c("zero", "u32", 0),
                    i("compare.eq", ["arg", "zero"], [("is_zero", "bool")]),
                ], ret("is_zero")),
            ]),
            f("calc", [("x", "u32")], ["u32"], [], [
                b("entry", [("x", "u32")], [
                    c("one", "u32", 1),
                    i("int.add.wrap", ["x", "one"], [("selected", "u32")]),
                    i("call", ["x"], [("take", "bool")], function="predicate"),
                ], branch("take", ("yes", "selected"), ("no", "selected"))),
                b("yes", [("yes_value", "u32")], [], ret("yes_value")),
                b("no", [("no_value", "u32")], [], ret("no_value")),
            ]),
        )
        query = prepare_edit(source, function="calc", block="entry",
                             output="selected", fields=["op"])
        self.assert_query_closed(query)
        self.assertEqual([callee["name"] for callee in query["context"]["callees"]], ["predicate"])

    def test_terminator_dependencies_count_toward_the_existing_view_budget(self):
        operations = [c("one", "u32", 1),
                      i("int.add.wrap", ["x", "one"], [("selected", "u32")])]
        for index in range(MAX_VISIBLE_OPERATIONS):
            previous = "x" if index == 0 else f"independent{index - 1}"
            operations.append(i("int.add.wrap", [previous, "one"],
                                [(f"independent{index}", "u32")]))
        source = m(f("calc", [("x", "u32")], ["u32"], [], [
            b("entry", [("x", "u32")], operations,
              ret(f"independent{MAX_VISIBLE_OPERATIONS - 1}")),
        ]))
        with self.assertRaisesRegex(HIAEditRejected, "transitive SSA view exceeds"):
            prepare_edit(source, function="calc", block="entry",
                         output="selected", fields=["op"])

    def test_atomic_batch_retains_terminator_context_without_duplicate_operations(self):
        source = branch_and_join()
        query = prepare_batch(source, [
            {"function": "calc", "block": "entry", "output": "selected", "fields": ["op"]},
            {"function": "calc", "block": "right", "output": "minus", "fields": ["op"]},
        ])
        for site in query["sites"]:
            self.assert_query_closed(site["query"])
        rendered = render_batch_context(query)
        self.assertEqual(rendered.count("%test:bool="), 1)
        self.assertEqual(rendered.count("%zero:u32="), 1)
        changed, receipt = apply_batch(source, query, {"edits": [
            {"site": 0, "changes": {"op": "int.sub.wrap"}},
            {"site": 1, "changes": {"op": "int.add.wrap"}},
        ]})
        self.assertEqual(execute_program(changed, "calc", [7])["result"], 14)
        self.assertFalse(receipt["edit_batch"]["intermediate_candidates_admitted"])

    def test_removing_the_branch_definition_invalidates_the_snapshot_query(self):
        source = branch_and_join()
        query = prepare_edit(source, function="calc", block="entry",
                             output="selected", fields=["op"])
        altered = copy.deepcopy(query)
        altered["context"]["dependencies"] = [
            row for row in altered["context"]["dependencies"] if row["index"] != 3
        ]
        with self.assertRaisesRegex(HIAEditRejected, "stale or modified"):
            apply_edit(source, altered, {"op": "int.sub.wrap"})


if __name__ == "__main__":
    unittest.main()
