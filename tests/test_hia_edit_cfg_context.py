"""P5 CFG-crossing SSA context, bounded replay and Agent batch regressions.

These tests exercise the existing canonical Core/VM and patcher; the new
context graph is only a presentation, never an execution authority.
"""
from __future__ import annotations

import unittest

from hepta.hia_edit_query import prepare_edit, apply_edit, render_edit_context, MAX_VISIBLE_OPERATIONS
from hepta.hia_edit_batch import prepare_batch, apply_batch, render_batch_context
from hepta.hia_program import verify_program
from hepta.hia_program_runtime import execute_program
from hepta.hia_program_tools import HIAEditRejected
from tests.test_hia_program import b, c, f, i, m, ret, jump, branch


def across_three_blocks():
    return m(f("calc", [("x", "u32")], ["u32"], [], [
        b("entry", [("x", "u32")], [
            c("one", "u32", 1),
            i("int.add.wrap", ["x", "one"], [("first", "u32")]),
        ], jump("middle", "first")),
        b("middle", [("carried", "u32")], [
            c("two", "u32", 2),
            i("int.mul.wrap", ["carried", "two"], [("second", "u32")]),
        ], jump("done", "second")),
        b("done", [("result_input", "u32")], [
            c("three", "u32", 3),
            i("int.add.wrap", ["result_input", "three"], [("result", "u32")]),
        ], ret("result")),
    ]))


def branch_and_join():
    return m(f("calc", [("x", "u32")], ["u32"], [], [
        b("entry", [("x", "u32")], [
            c("zero", "u32", 0),
            c("one", "u32", 1),
            i("int.add.wrap", ["x", "one"], [("selected", "u32")]),
            i("compare.eq", ["x", "zero"], [("test", "bool")]),
        ], branch("test", ("left", "selected"), ("right", "selected"))),
        b("left", [("left_arg", "u32")], [
            i("int.add.wrap", ["left_arg", "left_arg"], [("twice", "u32")]),
        ], jump("join", "twice")),
        b("right", [("right_arg", "u32")], [
            c("delta", "u32", 1),
            i("int.sub.wrap", ["right_arg", "delta"], [("minus", "u32")]),
        ], jump("join", "minus")),
        b("join", [("chosen", "u32")], [
            i("int.add.wrap", ["chosen", "chosen"], [("result", "u32")]),
        ], ret("result")),
    ]))


def backedge():
    return m(f("loop", [("n", "u32")], ["u32"], [], [
        b("entry", [("n", "u32")], [], jump("head", "n")),
        b("head", [("carry", "u32")], [
            c("one", "u32", 1),
            i("int.add.wrap", ["carry", "one"], [("changed", "u32")]),
        ], jump("head", "changed")),
    ]))


class CFGEditContextTests(unittest.TestCase):
    def test_cross_block_transitive_slice_and_reverified_patch(self):
        source = across_three_blocks()
        query = prepare_edit(source, function="calc", block="entry",
                             output="first", fields=["op"])
        self.assertEqual([x["id"] for x in query["context"]["downstream"]],
                         ["middle", "done"])
        self.assertEqual([x["affected_params"] for x in query["context"]["downstream"]],
                         [["carried"], ["result_input"]])
        self.assertEqual([x["index"] for x in query["context"]["downstream"][0]["dependencies"]], [0])
        shown = render_edit_context(query)
        self.assertIn("downstream block middle", shown)
        self.assertIn("%second:u32", shown)
        self.assertIn("downstream block done", shown)
        self.assertIn("%result:u32", shown)
        updated, receipt = apply_edit(source, query, {"op": "int.sub.wrap"})
        self.assertEqual(execute_program(source, "calc", [7])["result"], 19)
        self.assertEqual(execute_program(updated, "calc", [7])["result"], 15)
        self.assertTrue(receipt["edit_query"]["entire_module_reverified"])

    def test_branches_and_join_are_closed_without_guessing_selected_path(self):
        source = branch_and_join()
        verify_program(source)
        query = prepare_edit(source, function="calc", block="entry",
                             output="selected", fields=["op"])
        self.assertEqual([x["id"] for x in query["context"]["downstream"]],
                         ["left", "right", "join"])
        for n in (0, 1, 7):
            self.assertEqual(execute_program(source, "calc", [n])["status"], "returned")

    def test_crossblock_batch_displays_once_and_atomic_patch_replays(self):
        source = across_three_blocks()
        query = prepare_batch(source, [
            {"function": "calc", "block": "entry", "output": "first", "fields": ["op"]},
            {"function": "calc", "block": "middle", "output": "second", "fields": ["op"]},
        ])
        rendered = render_batch_context(query)
        self.assertEqual(rendered.count("%result:u32="), 1)
        self.assertIn("affected CFG inputs{carried}", rendered)
        self.assertEqual(rendered.count("@0{"), 1)
        self.assertEqual(rendered.count("@1{"), 1)
        updated, receipt = apply_batch(source, query, {"edits": [
            {"site": 0, "changes": {"op": "int.sub.wrap"}},
            {"site": 1, "changes": {"op": "int.add.wrap"}},
        ]})
        self.assertEqual(execute_program(updated, "calc", [7])["result"], 11)
        self.assertTrue(receipt["edit_batch"]["entire_module_reverified"])

    def test_source_block_backedge_refuses_compact_view_not_core_execution(self):
        source = backedge()
        verify_program(source)
        with self.assertRaisesRegex(HIAEditRejected, "cross-block SSA cycle"):
            prepare_edit(source, function="loop", block="head",
                         output="changed", fields=["op"])

    def test_large_downstream_slice_refuses_without_truncation(self):
        operations = [c("one", "u32", 1)]
        for index in range(MAX_VISIBLE_OPERATIONS + 2):
            argument = "carried" if index == 0 else f"step{index - 1}"
            operations.append(i("int.add.wrap", [argument, "one"],
                                [(f"step{index}", "u32")]))
        source = m(f("calc", [("x", "u32")], ["u32"], [], [
            b("entry", [("x", "u32")], [
                c("one_entry", "u32", 1),
                i("int.add.wrap", ["x", "one_entry"], [("changed", "u32")]),
            ], jump("body", "changed")),
            b("body", [("carried", "u32")], operations,
              ret(f"step{MAX_VISIBLE_OPERATIONS + 1}")),
        ]))
        with self.assertRaisesRegex(HIAEditRejected, "transitive SSA view exceeds"):
            prepare_edit(source, function="calc", block="entry",
                         output="changed", fields=["op"])


if __name__ == "__main__":
    unittest.main()
