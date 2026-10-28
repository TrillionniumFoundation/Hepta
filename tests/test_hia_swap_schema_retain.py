"""A safe v4 swap peephole must never downgrade live v5/v6 memory opcodes."""
from __future__ import annotations

from hepta.hia_program import HIAProgramRejected, SCHEMA_V5, SCHEMA_V6, SCHEMA_V7, verify_program
from hepta.hia_program_runtime import execute_program
from hepta.hia_program_llvm import emit_program_llvm, PROFILE_V5, PROFILE_V6
from hepta.hia_swap_opt import rewrite_byte_swap
from tests.test_hia_offset_copy_v5 import copy_program
from tests.test_hia_range_fill_v6 import fill_program
import unittest


def param(name, typ):
    return {"name": name, "type": typ}


def ins(op, args=(), out=(), **attrs):
    return {"op": op, "args": list(args),
            "out": [param(*item) for item in out], "attrs": attrs}


def with_swap(program, loan):
    fn = program["functions"][0]
    ops = fn["blocks"][0]["ops"]
    pivot = next(index for index, op in enumerate(ops)
                 if op["op"] == "buffer.load" and op["out"] ==
                 [{"name": "answer", "type": "u8"}])
    ops[pivot:pivot] = [
        ins("const", out=[("swap_left", "usize")], value=0),
        ins("const", out=[("swap_right", "usize")], value=1),
        ins("buffer.load", [loan, "swap_left"], [("swap_first", "u8")]),
        ins("buffer.load", [loan, "swap_right"], [("swap_second", "u8")]),
        ins("buffer.store", [loan, "swap_left", "swap_second"]),
        ins("buffer.store", [loan, "swap_right", "swap_first"]),
    ]
    return program


class SchemaRetainingSwapTests(unittest.TestCase):
    def test_v7_keeps_its_version_and_independent_chain_operations(self):
        from tests.test_hia_swap_opt import source_program
        from tests.test_hia_program import i
        source = source_program()
        source["schema"] = SCHEMA_V7
        ops = source["functions"][0]["blocks"][0]["ops"]
        ops[:0] = [i("chain.empty", out=[("empty_chain", "chain")]),
                   i("owner.drop", ["empty_chain"])]
        before = verify_program(source)
        optimized = rewrite_byte_swap(before)
        self.assertEqual(optimized.replacements, 1)
        self.assertEqual(optimized.program.as_dict()["schema"], SCHEMA_V7)
        self.assertEqual(optimized.program.as_dict()["functions"][0]["blocks"][0]["ops"][:2], ops[:2])
        self.assertEqual(execute_program(before, "swap_candidate", [5, 0, 4, 0])["resources"],
                         execute_program(optimized.program, "swap_candidate", [5, 0, 4, 0])["resources"])
        self.assertEqual(execute_program(optimized.program, "swap_candidate", [5, 0, 4, 0])["result"], 55)

    def test_structured_identity_is_not_silently_erased(self):
        from hepta.hia_schema import COMPOSITE_SCHEMA
        from tests.test_hia_swap_opt import source_program
        source = source_program()
        source.update(schema=COMPOSITE_SCHEMA, types=[])
        composite = verify_program(source)
        self.assertIsNotNone(composite.structured_bytes)
        with self.assertRaisesRegex(HIAProgramRejected, "primitive Core identity"):
            rewrite_byte_swap(composite)

    def test_v5_keeps_distinct_owner_copy(self):
        before = verify_program(with_swap(copy_program(), "writer"))
        optimized = rewrite_byte_swap(before)
        self.assertEqual(optimized.replacements, 1)
        self.assertEqual(optimized.program.as_dict()["schema"], SCHEMA_V5)
        self.assertTrue(any(op["op"] == "buffer.copy_range"
                            for op in optimized.program.as_dict()["functions"][0]["blocks"][0]["ops"]))
        args = [5, 0, 0, 5, 0]
        self.assertEqual(execute_program(before, "copy_offset", args)["result"], 22)
        self.assertEqual(execute_program(optimized.program, "copy_offset", args)["result"], 22)
        ir = emit_program_llvm(optimized.program)
        self.assertEqual(ir.profile, PROFILE_V5)
        self.assertIn("llvm.memcpy", ir.text)
        self.assertEqual(ir.core_sha256, optimized.program.sha256)

    def test_v6_keeps_checked_range_fill(self):
        before = verify_program(with_swap(fill_program(), "writer"))
        optimized = rewrite_byte_swap(before)
        self.assertEqual(optimized.replacements, 1)
        self.assertEqual(optimized.program.as_dict()["schema"], SCHEMA_V6)
        self.assertTrue(any(op["op"] == "buffer.fill_range"
                            for op in optimized.program.as_dict()["functions"][0]["blocks"][0]["ops"]))
        for args in ((5,1,1,9,0), (5,1,1,9,1), (5,0,2,7,0),
                     (5,5,0,9,4)):
            with self.subTest(args=args):
                old = execute_program(before, "fill_range", list(args))
                new = execute_program(optimized.program, "fill_range", list(args))
                self.assertEqual(old["result"], new["result"])
                self.assertEqual(new["resources"]["live_owners"], 0)
        ir = emit_program_llvm(optimized.program)
        self.assertEqual(ir.profile, PROFILE_V6)
        self.assertIn("llvm.memset", ir.text)
        self.assertEqual(ir.core_sha256, optimized.program.sha256)

    def test_without_exact_swap_no_schema_rewrite(self):
        before = verify_program(fill_program())
        optimized = rewrite_byte_swap(before)
        self.assertEqual(optimized.replacements, 0)
        self.assertEqual(optimized.program.sha256, before.sha256)
        self.assertEqual(optimized.program.as_dict()["schema"], SCHEMA_V6)


if __name__ == "__main__":
    unittest.main()
