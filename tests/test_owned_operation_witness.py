"""Owned LLVM must consume the existing source-bound Resource IR site witness.

Exercises real checked source, existing Resource IR verifier and original
Owned LLVM emitter. Does not prove instruction-level native refinement.
"""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
from unittest.mock import patch
import unittest

from hepta.checker import check
from hepta.parser import parse
from hepta.resource_ir import verify_resource_ir
from hepta.resource_lowering import lower_resource_ir
from hepta.owned_operation_witness import (
    OwnedOperationWitnessRejected, derive_owned_operation_witness,
)
from hepta.llvm_owned_backend import (
    LLVMOwnedRejected, _Function, emit_owned_llvm,
)


BASIC = """\
fn main() -> Unit effects {alloc,block,panic} {
    let bytes = buffer(8);
    drop(move bytes);
}
"""

FALLIBLE = """\
export "C" fn attempt(n:usize)->u32 effects {alloc,block,panic} {
    match try_buffer(n) {
        Result::Err(code)=>{return code as u32;},
        Result::Ok(bytes)=>{drop(move bytes);return 0;},
    }
}
"""

BRANCHED = """\
fn forward<T:Owned>(value:take T)->T effects {} {return move value;}
export "C" fn case(n:usize, early:u32)->u64 effects {alloc,block,panic} {
    let bytes=buffer(n);
    if early==0 {drop(move bytes);return 0;}
    let moved=forward::<Buffer<u8>>(move bytes);
    let count=len(moved) as u64;
    drop(move moved);
    return count;
}
"""

def fixture(source=BASIC):
    program = parse(source, "owner_witness.hepta")
    checked = check(program)
    if not checked.ok:
        raise AssertionError([item.to_dict() for item in checked.diagnostics])
    graph = lower_resource_ir(program, checked, project_sha256="f" * 64)
    verified = verify_resource_ir(graph)
    if verified.get("ok") is not True:
        raise AssertionError(verified)
    return program, checked, graph, verified


class OwnedOperationWitnessTests(unittest.TestCase):
    def test_real_resource_verifier_and_emitter_agree(self):
        for source, name, counts in (
            (BASIC, "main", (1, 0, 1)),
            (BRANCHED, "case", (1, 0, 2)),
            (FALLIBLE, "attempt", (0, 1, 1)),
        ):
            with self.subTest(name=name):
                program, checked, graph, verified = fixture(source)
                witness = derive_owned_operation_witness(graph, verified)
                actual = {entry[0]: entry[1:] for entry in witness.functions}
                self.assertEqual(actual[name], counts)
                self.assertEqual(witness.names, tuple(f.name for f in program.functions))
                witness.require_emitted(name, dict(zip(("buffer", "try_buffer", "drop"), counts)))
                ir = emit_owned_llvm(program, checked, project_sha256="f" * 64)
                self.assertIn("call void @__hepta_owned_try_buffer(", ir.text)
                self.assertIn("call void @__hepta_owned_drop", ir.text)
                self.assertEqual(ir.resource_ir_sha256, witness.graph_sha256)

    def test_missing_site_observation_rejects_before_ir_return(self):
        program, checked, _, _ = fixture()
        with patch.object(_Function, "observe_owned_call", return_value=None):
            with self.assertRaisesRegex(LLVMOwnedRejected, "E_OWNED_OPERATION_WITNESS"):
                emit_owned_llvm(program, checked, project_sha256="f" * 64)

    def test_omitted_native_drop_instruction_rejects(self):
        program, checked, _, _ = fixture()
        actual_emit = _Function.emit

        def remove_drop(self, instruction):
            if "call void @__hepta_owned_drop" in instruction:
                return
            return actual_emit(self, instruction)

        with patch.object(_Function, "emit", remove_drop):
            with self.assertRaisesRegex(LLVMOwnedRejected, "E_OWNED_OPERATION_WITNESS"):
                emit_owned_llvm(program, checked, project_sha256="f" * 64)

    def test_omitted_native_allocation_instruction_rejects(self):
        program, checked, _, _ = fixture()
        actual_emit = _Function.emit

        def remove_allocation(self, instruction):
            if "call void @__hepta_owned_try_buffer" in instruction:
                return
            return actual_emit(self, instruction)

        with patch.object(_Function, "emit", remove_allocation):
            with self.assertRaisesRegex(LLVMOwnedRejected, "E_OWNED_OPERATION_WITNESS"):
                emit_owned_llvm(program, checked, project_sha256="f" * 64)

    def test_missing_buffer_abort_guard_rejects(self):
        program, checked, _, _ = fixture()
        with patch.object(_Function, "guard", return_value=None):
            with self.assertRaisesRegex(LLVMOwnedRejected, "E_OWNED_OPERATION_WITNESS"):
                emit_owned_llvm(program, checked, project_sha256="f" * 64)

    def test_buffer_try_buffer_misclassification_rejects(self):
        program, checked, _, _ = fixture()
        genuine = _Function.observe_owned_call

        def wrong_kind(self, operation, fragment, start=None):
            return genuine(self, "try_buffer" if operation == "buffer" else operation,
                           fragment, start)

        with patch.object(_Function, "observe_owned_call", wrong_kind):
            with self.assertRaisesRegex(LLVMOwnedRejected, "E_OWNED_OPERATION_WITNESS"):
                emit_owned_llvm(program, checked, project_sha256="f" * 64)

    def test_independent_receipt_identity_and_claim_forgery_rejected(self):
        _, _, graph, verified = fixture()
        for mutate in (
            lambda g, v: g["claims"].update(native_codegen_uses_this_ir=True),
            lambda g, v: g["claims"].update(whole_language_soundness_proved=0),
            lambda g, v: v["claims"].update(whole_language_soundness_proved=0),
            lambda g, v: v.update(ir_sha256="0" * 64),
            lambda g, v: v.update(operations_checked=True),
            lambda g, v: v["functions"][0].update(reachable_blocks=0),
            lambda g, v: g.update(schema="hepta.resource-ir.v4"),
            lambda g, v: g["functions"][0].update(name="different_name"),
        ):
            candidate, receipt = deepcopy(graph), deepcopy(verified)
            mutate(candidate, receipt)
            with self.subTest(mutate=mutate.__code__.co_firstlineno):
                with self.assertRaisesRegex(OwnedOperationWitnessRejected, "E_OWNED_OPERATION_WITNESS"):
                    derive_owned_operation_witness(candidate, receipt)

    def test_resealed_unhashable_resource_kind_is_deterministic_rejection(self):
        _, _, graph, verified = fixture()
        changed, receipt = deepcopy(graph), deepcopy(verified)
        acquired = [op for fn in changed["functions"] for block in fn["blocks"]
                    for op in block["ops"] if op["op"] == "acquire"]
        self.assertTrue(acquired)
        acquired[0]["kind"] = ["buffer"]
        raw = json.dumps(changed, sort_keys=True, separators=(",", ":"),
                         allow_nan=False).encode()
        receipt["ir_sha256"] = sha256(raw).hexdigest()
        with self.assertRaisesRegex(OwnedOperationWitnessRejected, "E_OWNED_OPERATION_WITNESS"):
            derive_owned_operation_witness(changed, receipt)

    def test_unsupported_or_inaccurate_emission_counts_reject(self):
        _, _, graph, verified = fixture()
        witness = derive_owned_operation_witness(graph, verified)
        for emitted in (
            {"buffer": 1, "try_buffer": 0, "drop": 0},
            {"buffer": 0, "try_buffer": 1, "drop": 1},
            {"buffer": True, "try_buffer": 0, "drop": 1},
            {"buffer": 1, "try_buffer": 0, "drop": False},
            {"buffer": 1, "try_buffer": 0, "drop": 1, "unsafe": 0},
        ):
            with self.subTest(emitted=emitted):
                with self.assertRaisesRegex(OwnedOperationWitnessRejected, "E_OWNED_OPERATION_WITNESS"):
                    witness.require_emitted("main", emitted)
        with self.assertRaisesRegex(OwnedOperationWitnessRejected, "E_OWNED_OPERATION_WITNESS"):
            witness.require_emitted("missing", {"buffer": 1, "try_buffer": 0, "drop": 1})


    def test_one_block_owned_site_order_is_verified_before_native_ir(self):
        program, checked, graph, verified = fixture(BASIC)
        witness = derive_owned_operation_witness(graph, verified)
        self.assertEqual(witness.ordered_sites, (("main", ("buffer", "drop")),))
        self.assertTrue(witness.require_ordered("main", ("buffer", "drop")))
        for swapped in (("drop", "buffer"), ("buffer",), ("buffer", "drop", "drop"),
                        ["buffer", "drop"], ("buffer", 0)):
            with self.subTest(swapped=swapped):
                with self.assertRaisesRegex(OwnedOperationWitnessRejected, "E_OWNED_OPERATION_WITNESS"):
                    witness.require_ordered("main", swapped)

        real_observer = _Function.observe_owned_call
        def dishonest_order(self, operation, fragment, start=None):
            # Keep the exact same total counts and real emitted LLVM calls,
            # but corrupt the attested order before the final native gate.
            real_observer(self, operation, fragment, start)
            if operation == "drop":
                self.owner_order.reverse()

        with patch.object(_Function, "observe_owned_call", dishonest_order):
            with self.assertRaisesRegex(LLVMOwnedRejected, "E_OWNED_OPERATION_WITNESS"):
                emit_owned_llvm(program, checked, project_sha256="f" * 64)

    def test_branching_program_has_explicitly_unqualified_order(self):
        program, checked, graph, verified = fixture(BRANCHED)
        witness = derive_owned_operation_witness(graph, verified)
        self.assertIsNone(dict(witness.ordered_sites)["case"])
        self.assertFalse(witness.require_ordered("case", ("buffer", "drop", "drop")))
        # No accidental claim that the branch/early-return path is linear.
        ir = emit_owned_llvm(program, checked, project_sha256="f" * 64)
        self.assertIn("call void @__hepta_owned_drop", ir.text)

    def test_order_metadata_forgery_does_not_bypass_native_gate(self):
        from dataclasses import replace
        _, _, graph, verified = fixture()
        witness = derive_owned_operation_witness(graph, verified)
        for bad in (
            (),
            (("different", ("buffer", "drop")),),
            (("main", ("drop", "buffer")),),
            (("main", ["buffer", "drop"]),),
            (("main", ("buffer", True)),),
            (("main", ("buffer", [])),),
            (("main",),),
            ("malformed",),
            (("main", ("buffer", "drop")), ("main", None)),
        ):
            with self.subTest(bad=bad):
                forged = replace(witness, ordered_sites=bad)
                with self.assertRaisesRegex(OwnedOperationWitnessRejected, "E_OWNED_OPERATION_WITNESS"):
                    forged.require_ordered("main", ("buffer", "drop"))


if __name__ == "__main__":
    unittest.main()
