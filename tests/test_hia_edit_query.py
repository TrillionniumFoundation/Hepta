"""Editing slices cannot grant permissions or replace whole-program checking."""
import copy
import json
import unittest

from hepta.hia_edit_query import apply_edit, prepare_edit, render_edit_context
from hepta.hia_program import HIAProgramRejected, verify_program
from hepta.hia_program_runtime import execute_program
from hepta.hia_program_tools import HIAEditRejected
from tests.test_hia_program import b, c, f, i, p, ret


def fixture():
    return {"schema": "hepta.hia.program.v6", "module": "query", "functions": [
        f("calculate", [("x", "u32")], ["u32"], ["trap"], [
            b("entry", [("x", "u32")], [c("one", "u32", 1), i("int.add.wrap", ["x", "one"], [("y", "u32")])], ret("y")),
        ]),
        f("caller", [("input", "u32")], ["u32"], ["trap"], [
            b("entry", [("input", "u32")], [i("call", ["input"], [("answer", "u32")], function="calculate")], ret("answer")),
        ]),
    ]}


class EditQueryTests(unittest.TestCase):
    def query(self, document=None):
        return prepare_edit(document or fixture(), function="calculate", block="entry", output="y", fields=["op"])

    def test_real_execution_and_unmodified_caller(self):
        source = fixture()
        updated, receipt = apply_edit(source, self.query(source), {"op": "int.sub.wrap"})
        self.assertEqual(execute_program(updated, "caller", [9])["result"], 8)
        self.assertEqual(source, fixture())
        self.assertEqual(updated.as_dict()["functions"][1], source["functions"][1])
        self.assertTrue(receipt["edit_query"]["entire_module_reverified"])

    def test_transitive_slice_includes_producer(self):
        query = self.query()
        self.assertEqual(query["context"]["dependencies"][0]["operation"]["out"][0]["name"], "one")
        self.assertEqual(query["context"]["terminator"], ret("y"))

    def test_consumer_other_inputs_are_closed_and_rendered_in_original_order(self):
        source = fixture()
        source["functions"][0]["blocks"][0]["ops"] = [
            c("one", "u32", 1), i("compare.lt", ["x", "one"], [("test", "bool")]),
            c("two", "u32", 2), i("int.add.wrap", ["one", "two"], [("yes", "u32")]),
            i("select", ["test", "yes", "x"], [("y", "u32")]),
        ]
        query = prepare_edit(source, function="calculate", block="entry", output="test", fields=["op"])
        self.assertEqual([item["index"] for item in query["context"]["dependencies"]], [0, 2, 3])
        rendered = render_edit_context(query)
        positions = [rendered.index(value) for value in
                     ("%one:u32 =", "EDIT %test:bool =", "%two:u32 =", "%yes:u32 =", "%y:u32 =")]
        self.assertEqual(positions, sorted(positions))
        self.assertEqual(rendered.count("EDIT "), 1)
        changed, _ = apply_edit(source, query, {"op": "compare.le"})
        self.assertEqual(execute_program(changed, "caller", [1])["result"], 3)

    def test_stale_base_and_forged_context_reject(self):
        query = self.query()
        changed = fixture()
        changed["functions"][0]["blocks"][0]["ops"][0]["attrs"]["value"] = 2
        with self.assertRaises(HIAEditRejected):
            apply_edit(changed, query, {"op": "int.sub.wrap"})
        query["context"]["dependencies"] = []
        with self.assertRaises(HIAEditRejected):
            apply_edit(fixture(), query, {"op": "int.sub.wrap"})

    def test_illegal_opcode_and_type_reject(self):
        for opcode in ("owner.drop", "not.real", "bool.and"):
            with self.subTest(opcode=opcode), self.assertRaises(HIAProgramRejected):
                apply_edit(fixture(), self.query(), {"op": opcode})

    def test_equal_python_numbers_cannot_forge_json_query_identity(self):
        for replacement in (True, 1.0):
            query = self.query()
            query["context"]["dependencies"][0]["operation"]["attrs"]["value"] = replacement
            with self.subTest(replacement=replacement), self.assertRaises(HIAEditRejected):
                apply_edit(fixture(), query, {"op": "int.sub.wrap"})

    def test_outputs_and_unknown_fields_cannot_change(self):
        for response in ({"out": [p("forged", "u32")]}, {"op": "int.sub.wrap", "expected": True}, {}):
            with self.subTest(response=response), self.assertRaises(HIAEditRejected):
                apply_edit(fixture(), self.query(), response)

    def test_duplicate_json_and_oversize_reject(self):
        for response in ('{"op":"int.sub.wrap","op":"int.add.wrap"}', '{"op":"' + 'a' * 17000 + '"}'):
            with self.assertRaises(HIAEditRejected):
                apply_edit(fixture(), self.query(), response)

    def test_json_roundtrip_and_multiple_results_identity(self):
        query = json.loads(json.dumps(self.query()))
        updated, _ = apply_edit(fixture(), query, '{"op":"int.mul.wrap"}')
        self.assertEqual(execute_program(updated, "caller", [7])["result"], 7)

    def test_effect_addition_is_rechecked(self):
        source = fixture()
        for fn in source["functions"]:
            fn["effects"] = []
        query = self.query(source)
        with self.assertRaises(HIAProgramRejected):
            apply_edit(source, query, {"op": "int.add.checked"})

    def test_invalid_fields_and_identities_reject(self):
        for fields in ([], ["op", "op"], ["out"], "op", [1]):
            with self.assertRaises(HIAEditRejected):
                prepare_edit(fixture(), function="calculate", block="entry", output="y", fields=fields)
        for output in ("missing", "x", 0):
            with self.assertRaises(HIAEditRejected):
                prepare_edit(fixture(), function="calculate", block="entry", output=output, fields=["op"])

    def test_reverified_forged_base(self):
        source = fixture()
        query = self.query(source)
        source["functions"][1]["blocks"][0]["ops"][0]["attrs"]["function"] = "missing"
        with self.assertRaises(HIAProgramRejected):
            apply_edit(source, query, {"op": "int.sub.wrap"})


if __name__ == "__main__":
    unittest.main()
