"""Source record scalarization shares the bounded nominal Core profile."""
from __future__ import annotations

import unittest
from unittest.mock import patch

from hepta.hia_program import HIAProgramRejected, execute_program
from hepta.hia_program_composite import MAX_FLAT_FIELDS, MAX_TYPE_DEPTH, _Types
from hepta.hia_program_source import HIAProgramSourceRejected, _Lower, lower_source
from tests.test_hia_program_composite import record


def doubling_records(levels, *, zero_width=False):
    leaf = "Unit" if zero_width else "u8"
    declarations = ["struct R0{value:" + leaf + "}"]
    definitions = [record("R0", [] if zero_width else [("value", "u8")])]
    for index in range(1, levels + 1):
        previous = "R" + str(index - 1)
        declarations.append(f"struct R{index}{{left:{previous},right:{previous}}}")
        definitions.append(record("R" + str(index), [("left", previous), ("right", previous)]))
    source = "\n".join(declarations) + "\nfn run(x:u64)->u64 effects{}{return x;}"
    return source, definitions


class HIASourceLayoutLimitTests(unittest.TestCase):
    def test_unused_record_above_shared_flat_limit_rejects_before_core(self):
        levels = MAX_FLAT_FIELDS.bit_length()
        source, definitions = doubling_records(levels)
        # The existing nominal lowerer rejects the same flattened field graph.
        with self.assertRaisesRegex(HIAProgramRejected, "flattened nominal layout exceeds budget"):
            _Types(definitions).resolve("R" + str(levels))
        with self.assertRaisesRegex(HIAProgramSourceRejected, "flattened.*layout.*budget"):
            lower_source(source)

    def test_exact_shared_flat_boundary_remains_executable(self):
        levels = MAX_FLAT_FIELDS.bit_length() - 1
        source, definitions = doubling_records(levels)
        self.assertEqual(len(_Types(definitions).resolve("R" + str(levels)).flat), MAX_FLAT_FIELDS)
        self.assertEqual(execute_program(lower_source(source), "run", [73])["result"], 73)

    def test_unused_skinny_record_chain_exceeds_shared_depth_limit(self):
        declarations = ["struct R0{value:Unit}"]
        declarations.extend(f"struct R{i}{{value:R{i - 1}}}" for i in range(1, MAX_TYPE_DEPTH + 2))
        source = "\n".join(declarations) + "\nfn run(x:u64)->u64 effects{}{return x;}"
        with self.assertRaisesRegex(HIAProgramSourceRejected, "layout nesting exceeds budget"):
            lower_source(source)

    def test_zero_width_shared_record_dag_does_not_expand_exponentially(self):
        source, _ = doubling_records(12, zero_width=True)
        original = _Lower.layout
        calls = 0

        def bounded(lowering, *args, **kwargs):
            nonlocal calls
            calls += 1
            if calls > 400:
                self.fail("zero-width shared layouts exceeded the deterministic traversal budget")
            return original(lowering, *args, **kwargs)

        with patch.object(_Lower, "layout", bounded):
            core = lower_source(source)
        self.assertEqual(execute_program(core, "run", [19])["result"], 19)

    def test_recursive_record_still_rejects(self):
        with self.assertRaisesRegex(HIAProgramSourceRejected, "recursive by-value layout"):
            lower_source("struct Recursive{next:Recursive} fn run(x:u64)->u64 effects{}{return x;}")


if __name__ == "__main__":
    unittest.main()
