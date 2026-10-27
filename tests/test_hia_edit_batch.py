"""Atomic edits exercise real whole-program ownership and call verification."""
import copy
import json
import unittest

from hepta.hia_edit_batch import (MAX_RESPONSE_BYTES, apply_batch, prepare_batch,
                                  render_batch_context)
from hepta.hia_edit_query import apply_edit, prepare_edit, render_edit_context
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
        rendered = render_batch_context(query)
        self.assertEqual(rendered.count("@0{attrs}"), 1)
        self.assertEqual(rendered.count("@1{attrs}"), 1)
        changed, _ = apply_batch(source, query, {"edits": [
            {"site": 1, "changes": {"attrs": {"value": 7}}},
            {"site": 0, "changes": {"attrs": {"value": 5}}}]})
        self.assertEqual(execute_program(changed, "caller", [11])["result"], 385)
        self.assertEqual(changed.as_dict()["exports"], ["caller"])
        self.assertEqual(changed.as_dict()["functions"][2], source["functions"][2])

        shared = prepare_batch(source, [
            selected("a", "attrs", "caller"),
            selected("z", "attrs", "caller"),
        ])
        text = render_batch_context(shared)
        self.assertEqual(text.count("@0{attrs}"), 1)
        self.assertEqual(text.count("@1{attrs}"), 1)
        callees = [json.loads(line[len("callee "):])
                   for line in text.splitlines() if line.startswith("callee ")]
        self.assertEqual([fn["name"] for fn in callees], ["first", "second"])
        self.assertEqual([fn["returns"] for fn in callees], [["u32"], ["u32"]])

        for conflict in ("across_sites", "within_list", "selected_function"):
            with self.subTest(conflict=conflict):
                bad = copy.deepcopy(shared)
                if conflict == "selected_function":
                    bad = prepare_batch(source, [
                        selected("factor", "attrs", "first"),
                        selected("a", "attrs", "caller"),
                    ])
                context = bad["sites"][1]["query"]["context"]
                if conflict == "within_list":
                    context["callees"].append(copy.deepcopy(context["callees"][0]))
                    context["callees"][-1]["returns"] = ["u8"]
                else:
                    context["callees"][0]["returns"] = ["u8"]
                render_edit_context(bad["sites"][1]["query"])
                with self.assertRaisesRegex(HIAEditRejected, "conflicting.*signature"):
                    render_batch_context(bad)

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

    def test_render_rejects_two_sites_for_one_instruction(self):
        for multivalue in (False, True):
            with self.subTest(multivalue=multivalue):
                source = loans()
                if multivalue:
                    source["functions"][0]["blocks"][0]["ops"][1] = i(
                        "buffer.try_new", ["size"],
                        [("a", "buffer"), ("ok", "bool")])
                    first = selected("a")
                    second = prepare_edit(source, **selected("ok", "op"))
                else:
                    first = selected("reader")
                    second = prepare_edit(source, **first)
                query = prepare_batch(source, [first])
                query["sites"].append({"site": 1, "query": second})
                for site in query["sites"]:
                    render_edit_context(site["query"])
                with self.assertRaisesRegex(HIAEditRejected, "overlap"):
                    render_batch_context(query)
                with self.assertRaisesRegex(HIAEditRejected, "overlap"):
                    apply_batch(source, query, swaps())

    def test_render_rejects_mixed_snapshot_bindings(self):
        for field in ("base_sha256", "input_sha256"):
            for location in ("outer", "nested"):
                with self.subTest(field=field, location=location):
                    query = self.query()
                    target = (query if location == "outer"
                              else query["sites"][1]["query"])
                    old = target[field]
                    target[field] = ("0" if old[0] != "0" else "1") + old[1:]
                    with self.assertRaisesRegex(HIAEditRejected, "snapshot"):
                        render_batch_context(query)

    def test_render_rejects_conflicting_shared_context(self):
        mutations = (
            lambda context: context["function"]["effects"].remove("write"),
            lambda context: context["block_params"].append(
                {"name": "ghost", "type": "u8"}),
            lambda context: context.__setitem__(
                "terminator", {"op": "trap", "code": "user"}),
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                query = self.query()
                nested = query["sites"][1]["query"]
                mutate(nested["context"])
                render_edit_context(nested)
                with self.assertRaisesRegex(HIAEditRejected, "conflicting"):
                    render_batch_context(query)

    def test_render_accepts_distinct_composite_input_and_core_hashes(self):
        from tests.test_hia_program_composite import stored_loan_program

        core = verify_program(stored_loan_program())
        function = core.as_dict()["functions"][0]
        block = next(b for b in function["blocks"]
                     if b["id"] == function["entry"])
        operation = next(op for op in block["ops"] if op["out"])
        selection = {
            "function": function["name"],
            "block": block["id"],
            "output": operation["out"][0]["name"],
            "fields": ["attrs"],
        }
        query = prepare_batch(core, [selection])
        self.assertEqual(query["base_sha256"], core.sha256)
        self.assertEqual(query["input_sha256"], core.input_sha256)
        self.assertNotEqual(query["base_sha256"], query["input_sha256"])
        self.assertIn("@0{attrs}", render_batch_context(query))

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
