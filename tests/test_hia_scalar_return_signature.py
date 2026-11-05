"""A selected LLVM function must type-check even when Core never returns.

These controls exercise the actual checker on malformed LLVM, independently
of solver reachability. They are not a proof of the whole LLVM parser.
"""
import re
import unittest
from unittest.mock import patch

from hepta.hia_program import verify_program
from hepta.hia_program_llvm import emit_program_llvm
from hepta import hia_scalar_lowering_check as check
from tests.test_hia_scalar_lowering_check import scalar_program


def always_trapping_program(return_type="u64"):
    program = scalar_program("int.div.checked", "u64")
    function = program["functions"][0]
    function["returns"] = [return_type]
    block = function["blocks"][0]
    block["ops"] = []
    block["term"] = {"op": "trap", "code": "bounds"}
    return program


def add_dead_return(program, llvm_type, literal):
    text = emit_program_llvm(verify_program(program)).text
    header = re.search(r"(?m)^define internal i\d+ @__hia_fn_0\([^\n]*\) \{\n", text)
    assert header is not None
    end = text.index("\n}\n", header.end())
    body = ("b0:\n  br i1 false, label %unused_return, label %always_abort\n"
            f"unused_return:\n  ret {llvm_type} {literal}\n"
            "always_abort:\n  call void @abort()\n  unreachable")
    return text[:header.end()] + body + text[end:]


class ScalarReturnSignatureTests(unittest.TestCase):
    def test_all_trap_core_and_actual_emission_remain_valid(self):
        for return_type in ("u64", "bool", "unit"):
            with self.subTest(return_type=return_type):
                result = check.verify_scalar_lowering(always_trapping_program(return_type))
                self.assertEqual(result["status"], "verified", result)
                self.assertTrue(result["actual_emitter_output"])
                self.assertEqual(result["core_return_paths"], 0)
                self.assertEqual(result["llvm_return_paths"], 0)
                self.assertFalse(result["claims"]["llvm_parser_correspondence_proved"])
                self.assertFalse(result["claims"]["native_backend_refinement_proved"])

    def test_well_typed_infeasible_return_preserves_trap_behavior(self):
        for return_type, llvm_type, literal in (("u64", "i64", "0"),
                                                ("bool", "i1", "false"),
                                                ("unit", "i8", "0")):
            with self.subTest(return_type=return_type):
                program = always_trapping_program(return_type)
                text = add_dead_return(program, llvm_type, literal)
                result = check.verify_scalar_lowering(program, llvm_text=text)
                self.assertEqual(result["status"], "verified", result)
                self.assertEqual(result["core_return_paths"], 0)
                self.assertEqual(result["llvm_return_paths"], 1)
                self.assertFalse(result["actual_emitter_output"])

    def test_wrong_dead_return_type_refuses_without_reference_return_paths(self):
        for return_type, llvm_type, literal in (("u64", "i8", "0"),
                                                ("u64", "i1", "false"),
                                                ("bool", "i64", "0"),
                                                ("unit", "i32", "0")):
            with self.subTest(return_type=return_type, llvm_type=llvm_type):
                program = always_trapping_program(return_type)
                text = add_dead_return(program, llvm_type, literal)
                with self.assertRaisesRegex(check.ScalarLoweringRejected,
                                            "return type differs from selected function signature"):
                    check.verify_scalar_lowering(program, llvm_text=text)

    def test_return_signature_is_checked_before_symbolic_path_execution(self):
        program = always_trapping_program()
        text = add_dead_return(program, "i8", "0")
        with patch.object(check._LLVM, "value", side_effect=AssertionError("symbolic path was entered")):
            with self.assertRaisesRegex(check.ScalarLoweringRejected,
                                        "return type differs from selected function signature"):
                check.verify_scalar_lowering(program, llvm_text=text)


if __name__ == "__main__":
    unittest.main()
