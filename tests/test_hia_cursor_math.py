"""The external arithmetic spec must distinguish equally well-lowered helpers."""
from __future__ import annotations

import copy
import unittest

from tools.qualify_hia_cursor_math import prove_cursor_math


def cursor_program():
    params = [{"name": "offset", "type": "usize"}, {"name": "index", "type": "u64"},
              {"name": "extent", "type": "usize"}]
    return {"schema": "hepta.hia.program.v1", "module": "math_spec_control", "functions": [{
        "name": "cursor", "params": params, "returns": ["usize"], "effects": ["trap"], "entry": "entry",
        "blocks": [{"id": "entry", "params": params, "ops": [
            {"op": "int.cast", "args": ["index"], "out": [{"name": "converted", "type": "usize"}], "attrs": {"mode": "wrap"}},
            {"op": "int.add.checked", "args": ["offset", "converted"], "out": [{"name": "sum", "type": "usize"}], "attrs": {}},
            {"op": "compare.lt", "args": ["sum", "extent"], "out": [{"name": "inside", "type": "bool"}], "attrs": {}}],
            "term": {"op": "branch", "cond": "inside", "then": {"target": "ok", "args": ["sum"]},
                     "else": {"target": "bad", "args": []}}},
            {"id": "ok", "params": [{"name": "answer", "type": "usize"}], "ops": [],
             "term": {"op": "ret", "values": ["answer"]}},
            {"id": "bad", "params": [], "ops": [], "term": {"op": "trap", "code": "user"}}]}]}


class HiaCursorMath(unittest.TestCase):
    def test_external_spec_accepts_all_input_bounds_and_rejects_wrong_return(self):
        program = cursor_program()
        accepted = prove_cursor_math(program, function="cursor")
        self.assertTrue(accepted["verified"], accepted)
        self.assertEqual(accepted["input_preconditions"], [])
        self.assertEqual(accepted["input_domain_bits"], 192)
        self.assertFalse(accepted["claims"]["pointer_provenance_or_allocation_validity_proved"])
        changed = copy.deepcopy(program)
        changed["functions"][0]["blocks"][0]["term"]["then"]["args"] = ["offset"]
        rejected = prove_cursor_math(changed, function="cursor")
        self.assertTrue(rejected["lowering"]["verified"], "wrong program can still be faithfully lowered")
        self.assertFalse(rejected["verified"])
        self.assertEqual(rejected["status"], "sat")
        self.assertIn("counterexample", rejected)


if __name__ == "__main__":
    unittest.main()
