"""P5 transitive same-block SSA context for atomic Hepta Agent editing."""
from __future__ import annotations

import unittest

from hepta.hia_edit_query import (
    MAX_VISIBLE_OPERATIONS, apply_edit, prepare_edit, render_edit_context,
)
from hepta.hia_edit_batch import apply_batch, prepare_batch, render_batch_context
from hepta.hia_program_runtime import execute_program
from hepta.hia_program_tools import HIAEditRejected
from tests.test_hia_program import b, c, f, i, m, ret


def chain():
    return m(f("work", [("x", "u32")], ["u32"], [], [
        b("entry", [("x", "u32")], [
            c("one", "u32", 1),
            c("two", "u32", 2),
            i("int.add.wrap", ["x", "one"], [("first", "u32")]),
            i("int.mul.wrap", ["first", "two"], [("second", "u32")]),
            i("int.add.wrap", ["second", "one"], [("third", "u32")]),
            c("independent", "u32", 7),
        ], ret("third")),
    ]))


def multi_output():
    return m(
        f("duplicate", [("value", "u32")], ["u32", "u32"], [], [
            b("entry", [("value", "u32")], [], ret("value", "value")),
        ]),
        f("work", [("x", "u32")], ["u32"], [], [
            b("entry", [("x", "u32")], [
                c("one", "u32", 1),
                i("call", ["x"], [("a", "u32"), ("b", "u32")], function="duplicate"),
                i("int.add.wrap", ["a", "one"], [("left", "u32")]),
                i("int.add.wrap", ["b", "one"], [("right", "u32")]),
                i("int.add.wrap", ["left", "right"], [("total", "u32")]),
            ], ret("total")),
        ]),
    )


class TransitiveSSAContextTests(unittest.TestCase):
    def test_transitive_consumers_are_included_without_unrelated_operations(self):
        source = chain()
        original = execute_program(source, "work", [10])
        self.assertEqual(original["result"], 23)
        query = prepare_edit(source, function="work", block="entry",
                             output="first", fields=["op"])
        context = query["context"]
        self.assertEqual([item["index"] for item in context["consumers"]], [3, 4])
        self.assertEqual([item["index"] for item in context["dependencies"]], [0, 1])
        self.assertNotIn("independent", render_edit_context(query))
        rendered = render_edit_context(query)
        self.assertLess(rendered.index("%first:u32"),
                        rendered.index("%second:u32"))
        self.assertLess(rendered.index("%second:u32"),
                        rendered.index("%third:u32"))
        revised, receipt = apply_edit(source, query, {"op": "int.sub.wrap"})
        self.assertEqual(execute_program(revised, "work", [10])["result"], 19)
        self.assertFalse(receipt["claims"]["behavior_equivalence_proved"])

    def test_multi_output_and_all_transitive_branches_are_visible(self):
        source = multi_output()
        query = prepare_edit(source, function="work", block="entry",
                             output="a", fields=["attrs"])
        self.assertEqual([item["index"] for item in query["context"]["consumers"]], [2, 3, 4])
        self.assertEqual(execute_program(source, "work", [9])["result"], 20)

    def test_batch_deduplicates_shared_transitive_context_and_verifies_result(self):
        source = chain()
        batch = prepare_batch(source, [
            {"function": "work", "block": "entry", "output": "first", "fields": ["op"]},
            {"function": "work", "block": "entry", "output": "second", "fields": ["op"]},
        ])
        shown = render_batch_context(batch)
        self.assertEqual(shown.count("%third:u32="), 1)
        self.assertLess(shown.index("@0{"), shown.index("@1{"))
        result, receipt = apply_batch(source, batch, {"edits": [
            {"site": 0, "changes": {"op": "int.sub.wrap"}},
            {"site": 1, "changes": {"op": "int.add.wrap"}},
        ]})
        self.assertEqual(execute_program(result, "work", [10])["result"], 12)
        self.assertTrue(receipt["edit_batch"]["entire_module_reverified"])

    def test_large_transitive_slice_refuses_instead_of_lying_by_truncation(self):
        # 260 chained uses fit the real finite HIA program grammar, but
        # exceed the bounded Agent presentation profile.
        operations = [c("one", "u32", 1),
                      i("int.add.wrap", ["x", "one"], [("v0", "u32")])]
        for index in range(1, MAX_VISIBLE_OPERATIONS + 4):
            operations.append(i("int.add.wrap", [f"v{index-1}", "one"],
                                [(f"v{index}", "u32")]))
        source = m(f("work", [("x", "u32")], ["u32"], [], [
            b("entry", [("x", "u32")], operations,
              ret(f"v{MAX_VISIBLE_OPERATIONS+3}")),
        ]))
        with self.assertRaisesRegex(HIAEditRejected, "transitive SSA view exceeds"):
            prepare_edit(source, function="work", block="entry",
                         output="v0", fields=["op"])


if __name__ == "__main__":
    unittest.main()
