"""Pure P1 reaching-dataflow capacity tests; no native toolchain required."""
from __future__ import annotations

import unittest

from hepta.ssa_reaching import ReachingRejected, reaching_states, verify_latest_reads


def name(variable, reference):
    return {"node": "expr", "operation": "name", "value": variable,
            "ssa_ref": reference, "operands": []}


def literal(value):
    return {"node": "expr", "operation": "int", "value": value, "operands": []}


class ReachingDataflowTests(unittest.TestCase):
    def test_dead_locals_do_not_multiply_per_block_state(self):
        types = {f"unused_{i}": "i32" for i in range(2048)}
        types["live"] = "i32"
        instructions = [{"ssa_value": literal(1),
                         "definition": {"variable": "live", "ssa_name": "live@0"}}]
        instructions.extend(
            {"ssa_value": literal(i),
             "definition": {"variable": f"unused_{i}", "ssa_name": f"unused_{i}@0"}}
            for i in range(2048)
        )
        function = {"entry": "b0000", "scalar_types": types, "parameters": [],
                    "blocks": [{"id": "b0000", "phis": [], "instructions": instructions,
                                "terminator": {"kind": "return", "value": name("live", "live@0")}}]}
        graph = {"predecessors": {"b0000": []}, "successors": {"b0000": []}}
        inside, outside = reaching_states(function, graph)
        self.assertEqual(set(inside["b0000"]), {"live"})
        self.assertEqual(set(outside["b0000"]), {"live"})
        self.assertEqual(verify_latest_reads(function, graph), 1)

    def test_capacity_excess_rejects_before_allocating_full_state(self):
        types = {f"v{i}": "i32" for i in range(500)}
        blocks = [{"id": f"b{i:04d}", "phis": [], "instructions": [],
                   "terminator": {"kind": "return", "value": None}}
                  for i in range(300)]
        blocks[0]["phis"] = [
            {"result": {"variable": name, "ssa_name": name + "@0"}, "incoming": []}
            for name in types
        ]
        function = {"entry": "b0000", "scalar_types": types,
                    "parameters": [], "blocks": blocks}
        graph = {"predecessors": {}, "successors": {}}
        with self.assertRaisesRegex(ReachingRejected, "LIMIT"):
            reaching_states(function, graph)


if __name__ == "__main__":
    unittest.main()
