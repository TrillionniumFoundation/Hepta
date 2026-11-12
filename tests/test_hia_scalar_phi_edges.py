"""Actual LLVM PHIs require predecessor values, independently of path truth."""
from dataclasses import replace
from hashlib import sha256
import re
import unittest
from unittest.mock import patch

from hepta.hia_program import verify_program
from hepta.hia_program_llvm import emit_program_llvm
from hepta import hia_scalar_lowering_check as check
from tests.test_hia_scalar_lowering_check import scalar_program
from tools import qualify_hia_sequential_core as proof


def single_edge_program():
    program = scalar_program("int.add.wrap")
    fn = program["functions"][0]
    fn["blocks"][0]["term"] = {"op": "jump", "target": "join", "args": ["result", "result"]}
    fn["blocks"].append({"id": "join", "params": [
        {"name": "first", "type": "u32"}, {"name": "second", "type": "u32"}],
        "ops": [], "term": {"op": "ret", "values": ["second"]}})
    return program


def two_edge_program():
    params = [{"name": "left", "type": "u32"}, {"name": "right", "type": "u32"},
              {"name": "choice", "type": "bool"}]
    return {"schema": "hepta.hia.program.v1", "module": "phi_edges", "functions": [{
        "name": "checked_scalar", "params": params, "returns": ["u32"], "effects": [],
        "entry": "entry", "blocks": [
            {"id": "entry", "params": params, "ops": [], "term": {
                "op": "branch", "cond": "choice",
                "then": {"target": "join", "args": ["left", "right"]},
                "else": {"target": "join", "args": ["right", "left"]}}},
            {"id": "join", "params": [{"name": "first", "type": "u32"},
                                         {"name": "second", "type": "u32"}],
             "ops": [{"op": "int.sub.wrap", "args": ["first", "second"],
                      "out": [{"name": "difference", "type": "u32"}], "attrs": {}}],
             "term": {"op": "ret", "values": ["difference"]}}]}]}


def emitted(program):
    return emit_program_llvm(verify_program(program)).text


def phi_lines(text):
    return [line for line in text.splitlines() if " = phi i32 " in line]


def replace_incoming(text, phi_index, incoming_index, token):
    line = phi_lines(text)[phi_index]
    head, incoming = line.split(" = phi i32 ", 1)
    pieces = re.findall(r"\[ (%[A-Za-z_][A-Za-z_0-9]*|-?\d+), %([A-Za-z_0-9]+) \]", incoming)
    assert ", ".join(f"[ {value}, %{origin} ]" for value, origin in pieces) == incoming
    pieces[incoming_index] = (token, pieces[incoming_index][1])
    changed = head + " = phi i32 " + ", ".join(f"[ {value}, %{origin} ]" for value, origin in pieces)
    assert text.count(line) == 1 and changed != line
    return text.replace(line, changed, 1)


def reverse_phis(text):
    lines = phi_lines(text)
    assert len(lines) == 2 and text.count("\n".join(lines)) == 1
    return text.replace("\n".join(lines), "\n".join(reversed(lines)), 1)


class ScalarPhiEdgesTests(unittest.TestCase):
    def test_legal_dominating_values_and_phi_orders(self):
        for program in (single_edge_program(), two_edge_program()):
            original = emitted(program)
            for text in (original, reverse_phis(original)):
                with self.subTest(parameters=len(program["functions"][0]["params"]), reordered=text != original):
                    result = check.verify_scalar_lowering(program, llvm_text=text)
                    self.assertEqual(result["status"], "verified", result)
                    self.assertTrue(result["claims"]["selected_body_all_input_value_and_abort_equivalence"])
                    self.assertFalse(result["claims"]["llvm_parser_correspondence_proved"])

    def test_later_phi_cannot_read_earlier_phi_on_incoming_edge(self):
        program = single_edge_program()
        original = emitted(program)
        first = phi_lines(original)[0].strip().split(" = ")[0]
        changed = replace_incoming(original, 1, 0, first)
        with self.assertRaisesRegex(check.ScalarLoweringRejected, "does not dominate its incoming edge"):
            check.verify_scalar_lowering(program, llvm_text=changed)

    def test_self_and_later_phi_are_not_predecessor_values(self):
        program = single_edge_program()
        original = emitted(program)
        names = [line.strip().split(" = ")[0] for line in phi_lines(original)]
        for destination, source in ((0, 0), (0, 1), (1, 1)):
            with self.subTest(destination=destination, source=source):
                changed = replace_incoming(original, destination, 0, names[source])
                with self.assertRaisesRegex(check.ScalarLoweringRejected, "does not dominate its incoming edge"):
                    check.verify_scalar_lowering(program, llvm_text=changed)

    def test_every_incoming_edge_checked_before_symbolic_path_execution(self):
        program = two_edge_program()
        original = emitted(program)
        first = phi_lines(original)[0].strip().split(" = ")[0]
        for condition in ("true", "false"):
            for edge in (0, 1):
                changed = replace_incoming(original, 1, edge, first)
                self.assertIn("br i1 %p_0_2,", changed)
                changed = changed.replace("br i1 %p_0_2,", "br i1 " + condition + ",", 1)
                with self.subTest(condition=condition, edge=edge), \
                        patch.object(check._LLVM, "value", side_effect=AssertionError("symbolic path was entered")):
                    with self.assertRaisesRegex(check.ScalarLoweringRejected, "does not dominate its incoming edge"):
                        check.verify_scalar_lowering(program, llvm_text=changed)

    def test_other_predecessor_definition_cannot_cross_edges(self):
        program = two_edge_program()
        original = emitted(program)
        self.assertIn("edge_0:\n  br label %b1", original)
        changed = original.replace("edge_0:\n  br label %b1",
                                   "edge_0:\n  %edge_value = add i32 %p_0_0, 0\n  br label %b1", 1)
        changed = replace_incoming(changed, 1, 1, "%edge_value")
        with self.assertRaisesRegex(check.ScalarLoweringRejected, "does not dominate its incoming edge"):
            check.verify_scalar_lowering(program, llvm_text=changed)

    def test_undefined_incoming_value_refuses(self):
        program = two_edge_program()
        changed = replace_incoming(emitted(program), 1, 1, "%missing")
        with self.assertRaisesRegex(check.ScalarLoweringRejected, "undefined LLVM PHI value"):
            check.verify_scalar_lowering(program, llvm_text=changed)

    def test_parallel_cfg_edges_cannot_use_one_phi_entry(self):
        program = single_edge_program()
        original = emitted(program)
        self.assertIn("edge_0:\n  br label %b1", original)
        changed = original.replace("edge_0:\n  br label %b1",
                                   "edge_0:\n  br i1 true, label %b1, label %b1", 1)
        with self.assertRaisesRegex(check.ScalarLoweringRejected, "malformed LLVM PHI"):
            check.verify_scalar_lowering(program, llvm_text=changed)

    def test_duplicate_or_missing_phi_predecessor_refuses(self):
        program = two_edge_program()
        original = emitted(program)
        line = phi_lines(original)[1]
        head, incoming = line.split(" = phi i32 ", 1)
        pairs = incoming.split(" ], [ ")
        self.assertEqual(len(pairs), 2)
        first = pairs[0] + " ]"
        for replacement in (first, incoming + ", " + first):
            with self.subTest(replacement=replacement):
                changed = original.replace(line, head + " = phi i32 " + replacement, 1)
                with self.assertRaisesRegex(check.ScalarLoweringRejected, "malformed LLVM PHI"):
                    check.verify_scalar_lowering(program, llvm_text=changed)

    def test_false_incoming_edge_still_checks_value_type(self):
        program = two_edge_program()
        original = emitted(program)
        changed = replace_incoming(original, 1, 1, "%p_0_2")
        changed = changed.replace("br i1 %p_0_2,", "br i1 true,", 1)
        with self.assertRaisesRegex(check.ScalarLoweringRejected, "LLVM value type mismatch"):
            check.verify_scalar_lowering(program, llvm_text=changed)

    def test_phi_after_non_phi_refuses(self):
        program = single_edge_program()
        original = emitted(program)
        line = phi_lines(original)[0]
        changed = original.replace(line, "  %early = add i32 0, 0\n" + line, 1)
        with self.assertRaisesRegex(check.ScalarLoweringRejected, "misplaced LLVM PHI"):
            check.verify_scalar_lowering(program, llvm_text=changed)

    def test_sequential_proof_chain_rejects_malformed_actual_lowering(self):
        program = single_edge_program()
        ir = emit_program_llvm(verify_program(program))
        first = phi_lines(ir.text)[0].strip().split(" = ")[0]
        changed = replace_incoming(ir.text, 1, 0, first)
        with patch.object(proof, "emit_program_llvm", return_value=replace(
                ir, text=changed, sha256=sha256(changed.encode()).hexdigest())):
            result = proof.verify_sequential_core(program)
        self.assertFalse(result["passed"], result)
        self.assertEqual(result["reason"], "LLVM PHI value does not dominate its incoming edge")
        self.assertEqual(result["obligations"][0]["totality"]["status"], "proved")
        self.assertFalse(any(result["claims"].values()))
        self.assertFalse(result["execution_authority"])


if __name__ == "__main__":
    unittest.main()
