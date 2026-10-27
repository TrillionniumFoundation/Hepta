"""Atomic edits exercise real whole-program ownership and call verification."""
import copy
import json
import unittest

from hepta.hia_edit_batch import (MAX_RESPONSE_BYTES, apply_batch, prepare_batch,
                                  render_batch_context)
from hepta.hia_edit_query import apply_edit, prepare_edit
from hepta.hia_program import HIAProgramRejected, verify_program
from hepta.hia_program_runtime import execute_program
from hepta.hia_program_tools import HIAEditRejected
from tests.test_hia_program import b, c, f, i, ret


def loans():
    return {"schema": "hepta.hia.program.v6", "module": "atomic_loans", "functions": [
        f("work", [], ["u8"], ["alloc", "read", "write", "trap"], [b("entry", [], [
            c("size", "usize", 1), i("buffer.new", ["size"], [("a", "buffer")]),
            i("buffer.new", ["size"], [("z", "buffer")]),
            i("borrow.read", ["a"], [("reader", "readbuf")]),
            i("borrow.mut", ["z"], [("writer", "mutbuf")]),
            c("zero", "usize", 0), i("buffer.load", ["reader", "zero"], [("result", "u8")]),
            i("loan.end", ["reader"]), i("loan.end", ["writer"]),
            i("owner.drop", ["a"]), i("owner.drop", ["z"]),
        ], ret("result"))])
    ]}


def selected(output, field="args", function="work"):
    return {"function": function, "block": "entry", "output": output, "fields": [field]}


def swaps():
    return {"edits": [{"site": 0, "changes": {"args": ["z"]}},
                      {"site": 1, "changes": {"args": ["a"]}}]}


class HIAEditBatchTests(unittest.TestCase):
    def query(self, document=None):
        return prepare_batch(document or loans(), [selected("reader"), selected("writer")])

    def test_atomic_borrow_swap_succeeds_while_each_intermediate_is_rejected(self):
        source = loans()
        verify_program(source)
        for output, owner in (("reader", "z"), ("writer", "a")):
            with self.subTest(output=output), self.assertRaises(HIAProgramRejected):
                apply_edit(source, prepare_edit(source, **selected(output)), {"args": [owner]})
        changed, receipt = apply_batch(source, self.query(source), swaps())
        run = execute_program(changed, "work", [])
        self.assertEqual(run["result"], 0)
        self.assertEqual(run["status"], "returned")
        self.assertTrue(receipt["edit_batch"]["entire_module_reverified"])
        self.assertFalse(receipt["edit_batch"]["intermediate_candidates_admitted"])
        self.assertEqual(source, loans())

    def test_invalid_batch_preserves_input_and_does_not_admit_partial_result(self):
        source, query = loans(), self.query()
        before = json.dumps(source, sort_keys=True)
        bad = swaps()
        bad["edits"][1]["changes"]["args"] = ["missing"]
        with self.assertRaises(HIAProgramRejected):
            apply_batch(source, query, bad)
        self.assertEqual(json.dumps(source, sort_keys=True), before)

    def test_distinct_functions_are_reverified_with_their_callers(self):
        def kernel(name, factor):
            return f(name, [("x", "u32")], ["u32"], [], [b("entry", [("x", "u32")], [
                c("factor", "u32", factor), i("int.mul.wrap", ["x", "factor"], [("v", "u32")])], ret("v"))])
        source = {"schema": "hepta.hia.program.v6", "module": "two_sites", "exports": ["caller"],
                  "functions": [kernel("first", 2), kernel("second", 3),
                      f("caller", [("x", "u32")], ["u32"], [], [b("entry", [("x", "u32")], [
                          i("call", ["x"], [("a", "u32")], function="first"),
                          i("call", ["a"], [("z", "u32")], function="second")], ret("z"))])]}
        query = prepare_batch(source, [selected("factor", "attrs", "first"),
                                       selected("factor", "attrs", "second")])
        changed, _ = apply_batch(source, query, {"edits": [
            {"site": 1, "changes": {"attrs": {"value": 7}}},
            {"site": 0, "changes": {"attrs": {"value": 5}}}]})
        self.assertEqual(execute_program(changed, "caller", [11])["result"], 385)
        self.assertEqual(changed.as_dict()["exports"], ["caller"])
        self.assertEqual(changed.as_dict()["functions"][2], source["functions"][2])

    def test_dependency_rendering_is_deduplicated_and_in_program_order(self):
        text = render_batch_context(self.query())
        self.assertEqual(text.count("%size:usize="), 1)
        self.assertEqual(text.count("%a:buffer="), 1)
        self.assertEqual(text.count("%z:buffer="), 1)
        self.assertEqual(text.count("@0{"), 1)
        self.assertEqual(text.count("@1{"), 1)
        self.assertLess(text.index("%size:usize="), text.index("%a:buffer="))
        self.assertLess(text.index("%a:buffer="), text.index("@0{"))
        self.assertLess(text.index("@0{"), text.index("@1{"))

    def test_duplicate_sites_including_multivalue_aliases_reject(self):
        with self.assertRaises(HIAEditRejected):
            prepare_batch(loans(), [selected("reader"), selected("reader", "op")])
        source = loans()
        ops = source["functions"][0]["blocks"][0]["ops"]
        ops[1] = i("buffer.try_new", ["size"], [("a", "buffer"), ("ok", "bool")])
        with self.assertRaises(HIAEditRejected):
            prepare_batch(source, [selected("a"), selected("ok", "op")])

    def test_stale_or_forged_query_rejects_including_python_number_aliases(self):
        query = self.query()
        for change in (True, 1.0):
            forged = copy.deepcopy(query)
            forged["sites"][0]["query"]["context"]["dependencies"][0]["operation"]["attrs"]["value"] = change
            with self.subTest(change=change), self.assertRaises(HIAEditRejected):
                apply_batch(loans(), forged, swaps())
        stale = loans()
        stale["functions"][0]["blocks"][0]["ops"][0]["attrs"]["value"] = 2
        with self.assertRaises(HIAEditRejected):
            apply_batch(stale, query, swaps())

    def test_exact_sites_and_fields_cannot_be_forged(self):
        candidates = []
        for index in (True, 1.0, -1, 2, "0"):
            edit = swaps(); edit["edits"][0]["site"] = index; candidates.append(edit)
        duplicate = swaps(); duplicate["edits"][1]["site"] = 0; candidates.append(duplicate)
        missing = swaps(); missing["edits"].pop(); candidates.append(missing)
        extra = swaps(); extra["edits"][0]["changes"]["out"] = []; candidates.append(extra)
        candidates.extend([{}, {"edits": []}, {"edits": swaps()["edits"], "allow": True}])
        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(HIAEditRejected):
                apply_batch(loans(), self.query(), candidate)

    def test_json_duplicates_and_response_budget_reject(self):
        for response in ('{"edits":[],"edits":[]}', '{"edits":"' + 'x' * MAX_RESPONSE_BYTES + '"}'):
            with self.assertRaises(HIAEditRejected):
                apply_batch(loans(), self.query(), response)

    def test_selection_limit_and_unknown_fields_reject(self):
        for selections in ([], [selected("reader")] * 17, "reader", [{**selected("reader"), "override": True}]):
            with self.assertRaises(HIAEditRejected):
                prepare_batch(loans(), selections)


if __name__ == "__main__":
    unittest.main()
