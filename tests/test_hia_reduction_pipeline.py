"""Independent semantics, counterexamples, fallback, and publication checks."""
from __future__ import annotations

import copy
import ctypes
from hashlib import sha256
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_program import verify_program
from hepta.hia_program_source import lower_source
from hepta.hia_program_runtime import execute_program, HIAProgramTrap
from hepta.hia_optimization import DEFAULT_POLICY, OptimizationRejected, verify_optimization
from hepta.hia_guarded_optimization import BYTE_SUM_LIMIT, propose_guarded_reduction
from hepta.hia_reduction import (propose_byte_narrowing, propose_reduction_pipeline,
    verify_reduction_pipeline, reduction_program, build_reduction_native,
    reduction_checker_identity)

try:
    import z3
except ImportError:
    z3 = None

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "benchmarks/hia_native_ndu/kernel.hepta").read_text()


def expected(n, seed):
    # Direct mathematical oracle, independent of HIA lowering and both solvers.
    return sum((i + seed) % 256 for i in range(n))


@unittest.skipUnless(z3 is not None, "pinned Z3 required")
class ReductionPipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = lower_source(SOURCE)
        cls.proposal = propose_reduction_pipeline(cls.base)

    def test_actual_counted_kernel_has_two_independent_proofs(self):
        proof = verify_reduction_pipeline(self.base, self.proposal)
        self.assertEqual(proof["status"], "verified", proof)
        self.assertEqual(proof["input_assumptions"], [])
        self.assertEqual(proof["executed_guards"][0]["maximum"], BYTE_SUM_LIMIT)
        for stage in proof["proofs"].values():
            self.assertTrue(stage["obligations"])
            self.assertTrue(all(o["result"] == "unsat" for o in stage["obligations"]))
        self.assertFalse(proof["claims"]["backend_refinement_proved"])

    def test_truncation_is_valid_for_independent_modular_expression_shapes(self):
        expressions = ["wrapping_add(x,y)", "wrapping_sub(x,y)", "wrapping_mul(x,y)",
                       "(x ^ y)", "(x & y)", "(x | y)",
                       "wrapping_add(wrapping_mul(x,y),17)"]
        mathematical = [lambda a,b:a+b, lambda a,b:a-b, lambda a,b:a*b,
                        lambda a,b:a^b, lambda a,b:a&b, lambda a,b:a|b,
                        lambda a,b:a*b+17]
        values = [(0,0),(255,1),(256,257),(2**32-1,2**32-1),(2**32-1,1),(65537,314159)]
        for expression, oracle in zip(expressions, mathematical):
            base = lower_source('module narrow; export "C" fn value(x:u32,y:u32)->u8 effects {} {return ('+expression+') as u8;}')
            candidate, info = propose_byte_narrowing(base)
            self.assertTrue(info["changes"], expression)
            proof = verify_optimization(base, candidate)
            self.assertEqual(proof["status"], "verified", proof)
            for x,y in values:
                self.assertEqual(execute_program(candidate, "value", [x,y])["result"], oracle(x,y)%256)

    def test_narrowing_keeps_checked_operand_trap(self):
        base = lower_source('module checked; export "C" fn value(x:u32,y:u32)->u8 effects {panic} {let t:u32=x+y; return wrapping_add(t,1) as u8;}')
        candidate, info = propose_byte_narrowing(base)
        self.assertTrue(info["changes"])
        self.assertEqual(verify_optimization(base,candidate)["status"], "verified")
        for program in (base,candidate):
            with self.assertRaises(HIAProgramTrap) as caught:
                execute_program(program,"value",[2**32-1,1])
            self.assertEqual(caught.exception.code,"overflow")
        self.assertEqual(execute_program(candidate,"value",[254,1])["result"],0)

    def test_fast_boundary_and_fallback_preserve_lifetimes_and_refusal(self):
        proposal = propose_reduction_pipeline(self.base, maximum=16)
        candidate = reduction_program(self.base,proposal)
        for n in (0,1,15,16,17,31,257):
            for seed in (0,255,2**32-1):
                for fail_at in (None,1,2):
                    baseline = execute_program(self.base,"calculate",[n,seed],allocation_fail_at=fail_at)
                    actual = execute_program(candidate,"calculate",[n,seed],allocation_fail_at=fail_at)
                    self.assertEqual(actual["result"],1001 if n and fail_at==1 else expected(n,seed))
                    self.assertEqual(actual["resources"],baseline["resources"],(n,seed,fail_at))

    def test_guard_larger_than_byte_sum_limit_has_actual_counterexample(self):
        proposal = copy.deepcopy(self.proposal)
        for guard in proposal["guarded"]["guards"]:
            guard["maximum"] = 2**64-1
        for blocks in proposal["guarded"]["invariants"].values():
            for constraints in blocks.values():
                for c in constraints:
                    if c["op"] == "le_const": c["limit"] = 2**64-1
        proof = verify_reduction_pipeline(self.base,proposal)
        self.assertEqual(proof["status"],"rejected",proof)
        self.assertIn("counterexample",proof["proofs"]["guarded_reduction"]["obligations"][-1])

    def test_wrong_scalar_candidate_cannot_hide_behind_valid_induction(self):
        proposal = copy.deepcopy(self.proposal)
        changed = False
        for function in proposal["narrowed_core"]["functions"]:
            for block in function["blocks"]:
                for op in block["ops"]:
                    if op["op"] == "int.add.wrap" and op["out"][0]["type"] == "u8":
                        op["op"] = "bit.xor"
                        changed = True
        self.assertTrue(changed)
        # Rebuild a source-consistent guarded proposal: the scalar stage must
        # independently reject the semantic mutation, not just a stale hash.
        proposal["guarded"] = propose_guarded_reduction(proposal["narrowed_core"])
        proof = verify_reduction_pipeline(self.base,proposal)
        self.assertEqual(proof["status"],"rejected",proof)
        self.assertIn("counterexample",proof["proofs"]["narrowing"]["obligations"][-1])

    def test_nonzero_initial_accumulator_cannot_use_zero_prefix_invariant(self):
        base = lower_source(SOURCE.replace("let mut total:u64=0;","let mut total:u64=1;"))
        proof = verify_reduction_pipeline(base,propose_reduction_pipeline(base))
        self.assertEqual(proof["status"],"rejected",proof)

    def test_no_profile_length_is_an_input_assumption(self):
        self.assertGreater(BYTE_SUM_LIMIT,2**32)
        with self.assertRaises(OptimizationRejected):
            propose_reduction_pipeline(self.base,maximum=BYTE_SUM_LIMIT+1)
        for field in ("schema","base_sha256"):
            proposal = copy.deepcopy(self.proposal)
            proposal[field] = "forged"
            self.assertEqual(verify_reduction_pipeline(self.base,proposal)["status"],"rejected")

    def test_timeout_never_invokes_native_compiler_or_publishes(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)/"candidate.o"
            with patch("hepta.hia_program_llvm.build_program_native") as compiler:
                with self.assertRaises(OptimizationRejected):
                    build_reduction_native(self.base,self.proposal,output,
                        policy={**DEFAULT_POLICY,"timeout_ms":0},kind="object")
                compiler.assert_not_called()
            self.assertFalse(output.exists())

    def test_source_drift_during_native_build_withdraws_publication(self):
        identity = reduction_checker_identity()
        changed = False
        def observe(): return "changed" if changed else identity
        def compiler(program,output,**kwargs):
            nonlocal changed
            data = b"a deliberately simulated compiler output"
            Path(output).write_bytes(data)
            changed = True
            return {"artifact_sha256":sha256(data).hexdigest()}
        with tempfile.TemporaryDirectory() as temporary:
            output=Path(temporary)/"candidate.o"
            with patch("hepta.hia_reduction.reduction_checker_identity",side_effect=observe), patch("hepta.hia_program_llvm.build_program_native",side_effect=compiler):
                with self.assertRaisesRegex(OptimizationRejected,"E_HIA_REDUCTION_STALE"):
                    build_reduction_native(self.base,self.proposal,output,kind="object")
            self.assertFalse(output.exists())


@unittest.skipUnless(z3 is not None and shutil.which(os.environ.get("HEPTA_TEST_CLANG","clang")),"native Clang and Z3 required")
class ReductionNativeTests(unittest.TestCase):
    def test_native_fast_and_original_checked_fallback(self):
        base=lower_source(SOURCE)
        proposal=propose_reduction_pipeline(base,maximum=16)
        with tempfile.TemporaryDirectory() as temporary:
            target=Path(temporary)/"reduction.so"
            receipt=build_reduction_native(base,proposal,target,clang=os.environ.get("HEPTA_TEST_CLANG","clang"))
            self.assertTrue(receipt["claims"]["final_artifact_bound"])
            library=ctypes.CDLL(str(target))
            calculate=library.calculate
            calculate.argtypes=[ctypes.c_size_t,ctypes.c_uint32]
            calculate.restype=ctypes.c_uint64
            for n in (0,1,15,16,17,255,256,257,4097):
                for seed in (0,255,2**32-1):
                    self.assertEqual(calculate(n,seed),expected(n,seed))
            self.assertEqual(calculate(2**64-1,7),1001)


if __name__ == "__main__":
    unittest.main()
