"""Verifier-gated byte swap peephole: equivalence observations and rejection gates."""
from __future__ import annotations

import copy
import unittest

from hepta.hia_program import SCHEMA, SCHEMA_V4, HIAProgramRejected, verify_program
from hepta.hia_program_runtime import execute_program
from hepta.hia_swap_opt import rewrite_byte_swap
from hepta.hia_program_llvm import emit_program_llvm, PROFILE_V4


def param(name, kind):
    return {"name": name, "type": kind}


def ins(op, args=(), out=(), **attrs):
    return {"op": op, "args": list(args), "out": [param(*x) for x in out], "attrs": attrs}


def source_program():
    params = [param(x, "usize") for x in ("length", "left", "right", "probe")]
    ops = [ins("buffer.new", ["length"], [("owner", "buffer")]),
           ins("borrow.mut", ["owner"], [("loan", "mutbuf")])]
    for i, value in enumerate((11, 22, 33, 44, 55)):
        ops.extend((ins("const", out=[(f"idx{i}", "usize")], value=i),
                    ins("const", out=[(f"byte{i}", "u8")], value=value),
                    ins("buffer.store", ["loan", f"idx{i}", f"byte{i}"])))
    ops.extend((
        ins("buffer.load", ["loan", "left"], [("first", "u8")]),
        ins("buffer.load", ["loan", "right"], [("second", "u8")]),
        ins("buffer.store", ["loan", "left", "second"]),
        ins("buffer.store", ["loan", "right", "first"]),
        ins("buffer.load", ["loan", "probe"], [("answer", "u8")]),
        ins("loan.end", ["loan"]), ins("owner.drop", ["owner"]),
    ))
    return {"schema": SCHEMA, "module": "swap_opt", "functions": [
        {"name": "swap_candidate", "params": params, "returns": ["u8"],
         "effects": ["alloc", "read", "write", "trap"], "entry": "entry",
         "blocks": [{"id": "entry", "params": params, "ops": ops,
                     "term": {"op": "ret", "values": ["answer"]}}]}]}


class HIASwapOptimizationTests(unittest.TestCase):
    def test_rewrite_only_complete_validated_pattern(self):
        before = verify_program(source_program())
        result = rewrite_byte_swap(before)
        self.assertEqual(result.replacements, 1)
        self.assertEqual(result.before_sha256, before.sha256)
        self.assertNotEqual(result.after_sha256, result.before_sha256)
        doc = result.program.as_dict()
        self.assertEqual(doc["schema"], SCHEMA_V4)
        ops = doc["functions"][0]["blocks"][0]["ops"]
        self.assertEqual(sum(x["op"] == "buffer.swap" for x in ops), 1)
        self.assertNotIn("first", [output["name"] for x in ops for output in x["out"]])
        self.assertFalse(result.claims["backend_refinement_proved"])
        self.assertEqual(rewrite_byte_swap(result.program).replacements, 0)

    def test_bounded_execution_equivalence_and_cleanup(self):
        source = verify_program(source_program())
        target = rewrite_byte_swap(source).program
        for left, right in ((0, 4), (4, 0), (2, 2), (1, 3)):
            for probe in range(5):
                args = [5, left, right, probe]
                with self.subTest(args=args):
                    before = execute_program(source, "swap_candidate", args)
                    after = execute_program(target, "swap_candidate", args)
                    self.assertEqual(before["result"], after["result"])
                    self.assertEqual(after["resources"]["live_owners"], 0)
                    self.assertEqual(after["resources"]["loans_started"],
                                     after["resources"]["loans_ended"])

    def test_extra_ssa_use_prevents_rewrite(self):
        original = source_program()
        ops = original["functions"][0]["blocks"][0]["ops"]
        pivot = next(i for i, x in enumerate(ops) if x["op"] == "buffer.load" and
                     x["out"][0]["name"] == "answer")
        ops.insert(pivot, ins("compare.eq", ["first", "first"], [("same", "bool")]))
        before = verify_program(original)
        result = rewrite_byte_swap(before)
        self.assertEqual(result.replacements, 0)
        self.assertEqual(result.after_sha256, before.sha256)

    def test_wrong_cross_store_does_not_rewrite(self):
        original = source_program()
        ops = original["functions"][0]["blocks"][0]["ops"]
        first_store = next(i for i, x in enumerate(ops) if x["op"] == "buffer.store" and
                           x["args"] == ["loan", "left", "second"])
        ops[first_store]["args"][2] = "first"
        result = rewrite_byte_swap(verify_program(original))
        self.assertEqual(result.replacements, 0)

    def test_unverified_program_is_rejected_before_rewrite(self):
        source = source_program()
        source["functions"][0]["effects"].remove("read")
        with self.assertRaises(HIAProgramRejected):
            rewrite_byte_swap(source)

    def test_optimized_llvm_consumes_same_verified_core(self):
        candidate = rewrite_byte_swap(source_program()).program
        ir = emit_program_llvm(candidate)
        self.assertEqual(ir.profile, PROFILE_V4)
        self.assertEqual(ir.core_sha256, candidate.sha256)
        self.assertIn("load i8, ptr", ir.text)
        self.assertNotIn("call void @llvm.memmove.p0.p0.i64", ir.text)


if __name__ == "__main__":
    unittest.main()
