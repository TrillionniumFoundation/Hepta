"""The selected lowering validator consumes emitted instructions and guards."""
from __future__ import annotations

import unittest
import copy
from unittest.mock import patch

from hepta.hia_program import verify_program
from hepta.hia_program_llvm import emit_program_llvm
from hepta.hia_scalar_lowering_check import ScalarLoweringRejected, verify_scalar_lowering


def scalar_program(op, typ="u32", *, result=None, attrs=None, arity=2):
    arguments = [{"name": f"a{index}", "type": typ} for index in range(arity)]
    result = result or typ
    function = {"name": "checked_scalar", "params": arguments, "returns": [result],
                "effects": ["trap"] if "checked" in op or op == "int.cast" and attrs == {"mode": "checked"} else [],
                "entry": "entry", "blocks": [{"id": "entry", "params": arguments,
                "ops": [{"op": op, "args": [p["name"] for p in arguments],
                         "out": [{"name": "result", "type": result}], "attrs": attrs or {}}],
                "term": {"op": "ret", "values": ["result"]}}]}
    return {"schema": "hepta.hia.program.v1", "module": "selected_scalar", "functions": [function]}


class HiaScalarLoweringCheck(unittest.TestCase):
    def test_acyclic_cfg_phi_and_reordered_entry(self):
        program = scalar_program("compare.lt", "u32", result="bool")
        fn = program["functions"][0]
        fn["returns"] = ["u32"]
        entry = fn["blocks"][0]
        entry["term"] = {"op": "branch", "cond": "result",
                         "then": {"target": "yes", "args": ["a0"]},
                         "else": {"target": "no", "args": ["a1"]}}
        for name in ("yes", "no"):
            fn["blocks"].append({"id": name, "params": [{"name": name + "Value", "type": "u32"}],
                                 "ops": [], "term": {"op": "jump", "target": "join", "args": [name + "Value"]}})
        fn["blocks"].append({"id": "join", "params": [{"name": "chosen", "type": "u32"}],
                             "ops": [], "term": {"op": "ret", "values": ["chosen"]}})
        for reorder in (False, True):
            if reorder:
                fn["blocks"] = fn["blocks"][1:] + fn["blocks"][:1]
            with self.subTest(reorder=reorder):
                report = verify_scalar_lowering(program)
                self.assertEqual(report["status"], "verified", report)
                self.assertEqual(report["core_return_paths"], 2)
                ir = emit_program_llvm(verify_program(program)).text
                changed = ir.replace(" = icmp ult i32 ", " = icmp ugt i32 ")
                self.assertNotEqual(ir, changed)
                self.assertEqual(verify_scalar_lowering(program, llvm_text=changed)["status"], "refuted")

    def test_selected_body_in_real_multi_function_module(self):
        first = scalar_program("int.add.wrap")
        second = copy.deepcopy(first["functions"][0])
        second["name"] = "second"
        first["functions"].append(second)
        report = verify_scalar_lowering(first, function="second")
        self.assertEqual(report["status"], "verified")
        self.assertEqual(report["function_index"], 1)

    def test_calls_use_actual_callee_body_and_abort_paths(self):
        for operation in ("int.add.wrap", "int.div.checked"):
            with self.subTest(operation=operation):
                program = scalar_program(operation)
                second = copy.deepcopy(program["functions"][0])
                second["name"] = "second"
                ins = second["blocks"][0]["ops"][0]
                ins["op"], ins["attrs"] = "call", {"function": "checked_scalar"}
                program["functions"].append(second)
                report = verify_scalar_lowering(program, function="second")
                self.assertEqual(report["status"], "verified", report)
                self.assertEqual(report["call_closure"], ["checked_scalar", "second"])
                ir = emit_program_llvm(verify_program(program)).text
                if operation == "int.add.wrap":
                    changed = ir.replace(" = add i32 ", " = sub i32 ")
                else:
                    changed = ir.replace(" = icmp ne i32 %p_0_1, 0", " = icmp eq i32 %p_0_1, %p_0_1")
                self.assertNotEqual(changed, ir)
                self.assertEqual(verify_scalar_lowering(program, function="second", llvm_text=changed)["status"], "refuted")

    def test_mutated_recursive_llvm_call_is_refused(self):
        program = scalar_program("int.add.wrap")
        second = copy.deepcopy(program["functions"][0])
        second["name"] = "second"
        ins = second["blocks"][0]["ops"][0]
        ins["op"], ins["attrs"] = "call", {"function": "checked_scalar"}
        program["functions"].append(second)
        ir = emit_program_llvm(verify_program(program)).text
        changed = ir.replace(" = add i32 %p_0_0, %p_0_1",
                             " = call i32 @__hia_fn_1(i32 %p_0_0, i32 %p_0_1)")
        self.assertNotEqual(changed, ir)
        with self.assertRaisesRegex(ScalarLoweringRejected, "recursive LLVM call"):
            verify_scalar_lowering(program, function="second", llvm_text=changed)

    def test_unit_parameters_are_not_native_inputs(self):
        program = scalar_program("select", "unit", arity=3)
        fn = program["functions"][0]
        fn["params"][0]["type"] = "bool"
        with self.assertRaisesRegex(ScalarLoweringRejected, "scalar arguments"):
            verify_scalar_lowering(program)

    def test_loop_cannot_inherit_acyclic_proof(self):
        program = scalar_program("int.add.wrap", "u32")
        fn = program["functions"][0]
        fn["blocks"][0]["term"] = {"op": "jump", "target": "loop", "args": ["result", "a1"]}
        fn["blocks"].append({"id": "loop", "params": [{"name": "x", "type": "u32"},
                                                       {"name": "y", "type": "u32"}],
                             "ops": [], "term": {"op": "jump", "target": "loop", "args": ["x", "y"]}})
        with self.assertRaisesRegex(ScalarLoweringRejected, "cycles"):
            verify_scalar_lowering(program)

    def test_actual_checked_signed_unsigned_and_casts(self):
        cases = [scalar_program("int.add.checked", "i64"),
                 scalar_program("int.sub.checked", "u64"),
                 scalar_program("int.mul.checked", "i8"),
                 scalar_program("int.div.checked", "i32"),
                 scalar_program("int.shr.checked", "i64"),
                 scalar_program("int.cast", "u64", result="i32", attrs={"mode": "checked"}, arity=1),
                 scalar_program("int.cast", "i8", result="u64", attrs={"mode": "wrap"}, arity=1),
                 scalar_program("compare.lt", "u64", result="bool")]
        for program in cases:
            with self.subTest(operation=program["functions"][0]["blocks"][0]["ops"][0]):
                report = verify_scalar_lowering(program)
                self.assertEqual(report["status"], "verified", report)
                self.assertTrue(report["actual_emitter_output"])
                self.assertTrue(report["claims"]["selected_body_poison_unreachable"])
                self.assertFalse(report["claims"]["native_backend_refinement_proved"])

    def test_mutated_real_arithmetic_is_refuted(self):
        program = scalar_program("int.add.wrap", "u32")
        original = emit_program_llvm(verify_program(program)).text
        changed = original.replace(" = add i32 ", " = sub i32 ")
        self.assertNotEqual(original, changed)
        result = verify_scalar_lowering(program, llvm_text=changed)
        self.assertEqual(result["status"], "refuted")
        self.assertFalse(result["verified"])
        self.assertFalse(result["actual_emitter_output"])
        self.assertIn("counterexample", result)

    def test_missing_divide_guard_exposes_poison(self):
        program = scalar_program("int.div.checked", "u32")
        original = emit_program_llvm(verify_program(program)).text
        changed = original.replace(" = icmp ne i32 %p_0_1, 0", " = icmp eq i32 %p_0_1, %p_0_1")
        self.assertNotEqual(original, changed)
        result = verify_scalar_lowering(program, llvm_text=changed)
        self.assertEqual(result["status"], "refuted")
        self.assertEqual(result["counterexample"]["a1"], "0")

    def test_signed_shift_changed_to_logical_is_refuted(self):
        program = scalar_program("int.shr.checked", "i32")
        original = emit_program_llvm(verify_program(program)).text
        changed = original.replace(" = ashr i32 ", " = lshr i32 ")
        self.assertNotEqual(original, changed)
        self.assertEqual(verify_scalar_lowering(program, llvm_text=changed)["status"], "refuted")

    def test_unknown_llvm_flags_cannot_inherit_a_proof(self):
        program = scalar_program("int.add.wrap", "u32")
        original = emit_program_llvm(verify_program(program)).text
        changed = original.replace(" = add i32 ", " = add nsw i32 ")
        with self.assertRaisesRegex(ScalarLoweringRejected, "outside the audited profile"):
            verify_scalar_lowering(program, llvm_text=changed)

    def test_oversized_llvm_width_and_literal_refuse_before_smt_allocation(self):
        program = scalar_program("int.add.wrap", "u32")
        original = emit_program_llvm(verify_program(program)).text
        changed = original.replace(" = add i32 %p_0_0, %p_0_1", " = add i999999999 0, 0")
        with self.assertRaisesRegex(ScalarLoweringRejected, "width"):
            verify_scalar_lowering(program, llvm_text=changed)
        changed = original.replace(" = add i32 %p_0_0, %p_0_1", " = add i32 4294967296, 0")
        with self.assertRaisesRegex(ScalarLoweringRejected, "representable range"):
            verify_scalar_lowering(program, llvm_text=changed)
        for operation in ("zext", "sext"):
            changed = original.replace(" = add i32 %p_0_0, %p_0_1",
                                       f" = {operation} i32 %p_0_0 to i999999999")
            with self.subTest(operation=operation):
                with self.assertRaisesRegex(ScalarLoweringRejected, "width"):
                    verify_scalar_lowering(program, llvm_text=changed)

    def test_abort_runtime_override_cannot_inherit_termination_assumption(self):
        program = scalar_program("int.div.checked", "u32")
        original = emit_program_llvm(verify_program(program)).text
        for declaration in ('define void @abort() {\nentry:\n  ret void\n}',
                            'define void @"abort"() {\nentry:\n  ret void\n}',
                            '@abort = alias void (), ptr @foreign_abort'):
            with self.subTest(declaration=declaration):
                changed = original + "\n" + declaration + "\n"
                with self.assertRaisesRegex(ScalarLoweringRejected, "abort primitive"):
                    verify_scalar_lowering(program, llvm_text=changed)

    def test_unknown_solver_result_is_never_verified(self):
        import z3
        program = scalar_program("int.add.wrap", "u32")
        with patch.object(z3.Solver, "check", return_value=z3.unknown):
            result = verify_scalar_lowering(program)
        self.assertEqual(result["status"], "unknown")
        self.assertFalse(result["verified"])
        self.assertFalse(result["claims"]["selected_body_all_input_value_and_abort_equivalence"])


if __name__ == "__main__":
    unittest.main()
