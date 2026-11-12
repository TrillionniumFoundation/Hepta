"""Execute edits whose consequences travel through control, not SSA arguments."""
from copy import deepcopy
import unittest

from hepta.hia_edit_query import (prepare_edit, apply_edit, render_edit_context,
                                  MAX_VISIBLE_OPERATIONS, MAX_VISIBLE_BLOCKS)
from hepta.hia_edit_batch import prepare_batch, apply_batch, render_batch_context
from hepta.hia_program import verify_program
from hepta.hia_program_runtime import execute_program
from hepta.hia_program_tools import HIAEditRejected
from tests.test_hia_program import b, c, f, i, m, ret, jump, branch
from tests.test_hia_edit_cfg_context import branch_and_join


def choose(*, owned=False):
    prefix = [c("limit", "u32", 5)]
    if owned:
        prefix += [c("size", "usize", 8), i("buffer.new", ["size"], [("owner", "buffer")])]
    prefix += [i("compare.lt", ["x", "limit"], [("condition", "bool")])]
    return m(f("choose", [("x", "u32")], ["u32"], ["alloc", "trap"] if owned else [], [
        b("entry", [("x", "u32")], prefix,
          branch("condition", ("left", "owner") if owned else ("left",),
                 ("right", "owner") if owned else ("right",))),
        b("left", [("left_owner", "buffer")] if owned else [],
          ([i("owner.drop", ["left_owner"])] if owned else []) + [c("answer_left", "u32", 42)],
          ret("answer_left")),
        b("right", [("right_owner", "buffer")] if owned else [],
          ([i("owner.drop", ["right_owner"])] if owned else []) + [c("answer_right", "u32", 99)],
          ret("answer_right")),
    ]))


SELECTION = {"function": "choose", "block": "entry", "output": "condition", "fields": ["op"]}


class ControlContextTests(unittest.TestCase):
    def test_condition_without_forwarded_value_shows_both_execution_outcomes(self):
        source = choose()
        query = prepare_edit(source, **SELECTION)
        self.assertEqual(query["schema"], "hepta.hia.edit-query.v2")
        self.assertEqual([x["id"] for x in query["context"]["downstream"]], ["left", "right"])
        for block in query["context"]["downstream"]:
            self.assertEqual(block["affected_params"], [])
            self.assertTrue(block["control_reachable"])
        text = render_edit_context(query)
        self.assertIn("%answer_left:u32", text)
        self.assertIn("%answer_right:u32", text)
        changed, receipt = apply_edit(source, query, {"op": "compare.gt"})
        self.assertEqual([execute_program(source, "choose", [n])["result"] for n in (2, 9)], [42, 99])
        self.assertEqual([execute_program(changed, "choose", [n])["result"] for n in (2, 9)], [99, 42])
        self.assertTrue(receipt["edit_query"]["entire_module_reverified"])

    def test_control_region_retains_no_result_resource_cleanup(self):
        source = choose(owned=True)
        query = prepare_edit(source, **SELECTION)
        for block in query["context"]["downstream"]:
            ops = [x["operation"]["op"] for x in block["dependencies"] + block["consumers"]]
            self.assertIn("owner.drop", ops)
        rendered = render_edit_context(query)
        self.assertEqual(rendered.count("owner.drop("), 2)
        updated, _ = apply_edit(source, query, {"op": "compare.gt"})
        for n in (2, 9):
            self.assertEqual(execute_program(updated, "choose", [n])["status"], "returned")

    def test_unaffected_selected_terminator_inputs_are_closed(self):
        source = branch_and_join()
        query = prepare_edit(source, function="calc", block="entry", output="selected", fields=["op"])
        outputs = {out["name"] for item in query["context"]["dependencies"]
                   for out in item["operation"]["out"]}
        self.assertIn("test", outputs)
        self.assertIn("zero", outputs)
        self.assertIn("%test:bool", render_edit_context(query))

    def test_downstream_terminator_inputs_are_closed_even_when_independent(self):
        source = m(f("work", [("x", "u32")], ["u32"], [], [
            b("entry", [("x", "u32")], [c("one", "u32", 1),
              i("int.add.wrap", ["x", "one"], [("selected", "u32")])], jump("done", "selected")),
            b("done", [("unused", "u32")], [c("independent_result", "u32", 17)], ret("independent_result")),
        ]))
        query = prepare_edit(source, function="work", block="entry", output="selected", fields=["op"])
        self.assertIn("%independent_result:u32", render_edit_context(query))

    def test_batch_deduplicates_control_region_and_applies_all_changes(self):
        source = choose()
        batch = prepare_batch(source, [SELECTION, {"function": "choose", "block": "left",
                               "output": "answer_left", "fields": ["attrs"]}])
        text = render_batch_context(batch)
        self.assertEqual(text.count("%answer_left:u32="), 1)
        self.assertIn("affected-branch reachable region", text)
        updated, _ = apply_batch(source, batch, {"edits": [
            {"site": 0, "changes": {"op": "compare.gt"}},
            {"site": 1, "changes": {"attrs": {"value": 43}}},
        ]})
        self.assertEqual(execute_program(updated, "choose", [9])["result"], 43)

    def test_old_schema_and_forged_control_flags_refuse(self):
        source = choose()
        query = prepare_edit(source, **SELECTION)
        old = deepcopy(query)
        old["schema"] = "hepta.hia.edit-query.v1"
        with self.assertRaises(HIAEditRejected):
            render_edit_context(old)
        with self.assertRaises(HIAEditRejected):
            apply_edit(source, old, {"op": "compare.gt"})
        for flag in (1, "true", None):
            forged = deepcopy(query)
            forged["context"]["downstream"][0]["control_reachable"] = flag
            with self.subTest(flag=flag), self.assertRaises(HIAEditRejected):
                render_edit_context(forged)
        old_batch = prepare_batch(source, [SELECTION])
        old_batch["schema"] = "hepta.hia.edit-batch-query.v1"
        with self.assertRaises(HIAEditRejected):
            render_batch_context(old_batch)

    def test_changed_successor_invalidates_the_original_query(self):
        source = choose()
        query = prepare_edit(source, **SELECTION)
        source["functions"][0]["blocks"][1]["ops"][0]["attrs"]["value"] = 18
        with self.assertRaises(HIAEditRejected):
            apply_edit(source, query, {"op": "compare.gt"})

    def test_control_only_cycle_back_to_selected_block_refuses(self):
        source = m(f("loop", [("flag", "bool")], [], [], [
            b("entry", [("flag", "bool")], [], jump("head", "flag")),
            b("head", [("carry", "bool")], [i("bool.not", ["carry"], [("choice", "bool")])],
              branch("choice", ("body", "carry"), ("done",))),
            b("body", [("next", "bool")], [], jump("head", "next")),
            b("done", [], [], ret()),
        ]))
        verify_program(source)
        with self.assertRaisesRegex(HIAEditRejected, "cross-block SSA cycle"):
            prepare_edit(source, function="loop", block="head", output="choice", fields=["op"])

    def test_control_only_large_region_refuses_instead_of_hiding_operations(self):
        source = choose()
        source["functions"][0]["blocks"][1]["ops"][:0] = [
            c("padding" + str(n), "u32", n) for n in range(MAX_VISIBLE_OPERATIONS)]
        verify_program(source)
        with self.assertRaisesRegex(HIAEditRejected, "operation budget"):
            prepare_edit(source, **SELECTION)

    def test_operation_free_control_region_has_a_block_budget(self):
        source = choose()
        blocks = source["functions"][0]["blocks"]
        blocks[1]["term"] = jump("hop0")
        blocks.extend(b("hop" + str(n), [], [], jump("hop" + str(n + 1))
                        if n + 1 < MAX_VISIBLE_BLOCKS else jump("right"))
                      for n in range(MAX_VISIBLE_BLOCKS))
        verify_program(source)
        with self.assertRaisesRegex(HIAEditRejected, "block budget"):
            prepare_edit(source, **SELECTION)


if __name__ == "__main__":
    unittest.main()
