"""Batch display cannot merge conflicting snapshots or erase an edit site.

These are presentation-boundary controls, not a replacement for the existing
whole-module apply-time reconstruction and Core verification.
"""
from copy import deepcopy
import unittest

from hepta.hia_edit_batch import prepare_batch, render_batch_context, apply_batch
from hepta.hia_edit_query import prepare_edit, render_edit_context
from hepta.hia_program_runtime import execute_program
from hepta.hia_program_tools import HIAEditRejected
from tests.test_hia_edit_control_context import choose, SELECTION
from tests.test_hia_program import b, f, i, ret


LEFT = {"function": "choose", "block": "left", "output": "answer_left", "fields": ["attrs"]}


class BatchIdentityTests(unittest.TestCase):
    def test_duplicate_instruction_cannot_silently_erase_the_first_edit_marker(self):
        query = prepare_batch(choose(), [SELECTION, LEFT])
        query["sites"][1]["query"] = deepcopy(query["sites"][0]["query"])
        # The standalone view is well formed; only the batch knows that the
        # same immutable instruction now claims two distinct response IDs.
        render_edit_context(query["sites"][1]["query"])
        with self.assertRaises(HIAEditRejected):
            render_batch_context(query)

    def test_different_real_snapshots_cannot_share_one_batch_display(self):
        original = choose()
        changed = choose()
        changed["functions"][0]["blocks"][2]["ops"][0]["attrs"]["value"] = 100
        query = prepare_batch(original, [SELECTION, LEFT])
        query["sites"][1]["query"] = prepare_edit(changed, **LEFT)
        render_edit_context(query["sites"][1]["query"])
        self.assertNotEqual(query["base_sha256"], query["sites"][1]["query"]["base_sha256"])
        with self.assertRaises(HIAEditRejected):
            render_batch_context(query)
        # A source-identity mismatch matters even if normalized Core agrees.
        query = prepare_batch(original, [SELECTION, LEFT])
        query["sites"][1]["query"]["input_sha256"] = "0" * 64
        with self.assertRaises(HIAEditRejected):
            render_batch_context(query)

    def test_source_and_downstream_metadata_must_agree_in_either_selection_order(self):
        mutations = (
            lambda q: q["context"].__setitem__("terminator", ret("not_defined")),
            lambda q: q["context"]["block_params"].append({"name": "invented", "type": "u32"}),
            lambda q: q["context"]["function"]["effects"].append("read"),
        )
        for order in ([SELECTION, LEFT], [LEFT, SELECTION]):
            for mutate in mutations:
                query = prepare_batch(choose(), order)
                selected = next(item["query"] for item in query["sites"]
                                if item["query"]["selector"]["block"] == "left")
                mutate(selected)
                render_edit_context(selected)
                with self.subTest(order=order[0]["block"], mutation=mutate), self.assertRaises(HIAEditRejected):
                    render_batch_context(query)

    def test_no_result_resource_callee_remains_visible_and_conflicts_refuse(self):
        source = choose(owned=True)
        source["functions"][0]["blocks"][1]["ops"][0] = i(
            "call", ["left_owner"], function="release")
        source["functions"].append(f("release", [("owned", "buffer")], [], ["alloc"], [
            b("entry", [("owned", "buffer")], [i("owner.drop", ["owned"])], ret())]))
        limit = {"function": "choose", "block": "entry", "output": "limit", "fields": ["attrs"]}
        query = prepare_batch(source, [SELECTION, limit])
        displayed = render_batch_context(query)
        self.assertIn('call(%left_owner)', displayed)
        self.assertEqual(displayed.count('callee '), 1)
        changed, _ = apply_batch(source, query, {"edits": [
            {"site": 0, "changes": {"op": "compare.gt"}},
            {"site": 1, "changes": {"attrs": {"value": 6}}},
        ]})
        run = execute_program(changed, "choose", [9])
        self.assertEqual(run["result"], 42)
        self.assertEqual(run["resources"]["owners_created"], 1)
        self.assertEqual(run["resources"]["owners_dropped"], 1)
        conflict = deepcopy(query)
        conflict["sites"][1]["query"]["context"]["callees"][0]["effects"].append("read")
        render_edit_context(conflict["sites"][1]["query"])
        with self.assertRaises(HIAEditRejected):
            render_batch_context(conflict)

    def test_reversed_legal_selection_order_keeps_both_sites_and_complete_region(self):
        source = choose(owned=True)
        query = prepare_batch(source, [LEFT, SELECTION])
        shown = render_batch_context(query)
        self.assertEqual(shown.count("@0{"), 1)
        self.assertEqual(shown.count("@1{"), 1)
        self.assertEqual(shown.count("%answer_left:u32="), 1)
        self.assertEqual(shown.count("owner.drop("), 2)
        changed, receipt = apply_batch(source, query, {"edits": [
            {"site": 0, "changes": {"attrs": {"value": 43}}},
            {"site": 1, "changes": {"op": "compare.gt"}},
        ]})
        self.assertEqual(execute_program(changed, "choose", [9])["result"], 43)
        self.assertTrue(receipt["edit_batch"]["entire_module_reverified"])


if __name__ == "__main__":
    unittest.main()
