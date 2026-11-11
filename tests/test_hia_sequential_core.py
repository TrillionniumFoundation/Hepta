"""All-export proof composition must not hide traps or trust stale receipts."""
from copy import deepcopy
from dataclasses import replace
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_program import verify_program
from hepta.hia_program_llvm import emit_program_llvm
from tests.test_hia_program import arithmetic, b, f, jump, m
from tests.test_hia_scalar_totality import guarded_call_division
from tools import qualify_hia_sequential_core as proof


def selected_module():
    return json.loads((proof.ROOT / "formal/selected_sequential_u32.core.hepta").read_bytes())


@unittest.skipUnless(importlib.util.find_spec("z3"), "actual pinned Z3 is required")
class SequentialCoreProofTests(unittest.TestCase):
    def test_every_export_and_original_guarded_callee_receive_fresh_all_input_queries(self):
        source = selected_module()
        result = proof.verify_sequential_core(source)
        self.assertTrue(result["passed"], result)
        self.assertEqual(result["exports"], ["add_with_dead_literal", "calculate"])
        self.assertEqual([r["function"] for r in result["obligations"]], result["exports"])
        for row in result["obligations"]:
            self.assertTrue(row["passed"])
            self.assertEqual(row["totality"]["program_sha256"], result["core_sha256"])
            self.assertEqual(row["lowering"]["core_sha256"], result["core_sha256"])
            self.assertEqual(row["lowering"]["llvm_sha256"], result["llvm_sha256"])
            self.assertEqual(row["totality"]["solver"]["result"], "unsat")
            self.assertEqual(row["lowering"]["solver_result"], "unsat")
        call = result["obligations"][1]
        self.assertEqual(call["totality"]["call_closure"], ["calculate", "divide"])
        self.assertEqual(call["lowering"]["call_closure"], ["calculate", "divide"])
        self.assertFalse(result["claims"]["all_legal_programs_proved"])
        self.assertFalse(result["claims"]["all_programs_in_profile_proved"])
        self.assertFalse(result["claims"]["ownership_or_resource_safety_proved"])
        self.assertFalse(result["claims"]["native_machine_code_or_c_abi_proved"])
        self.assertFalse(result["execution_authority"])

    def test_private_trapping_helper_is_checked_at_actual_arguments_but_new_export_fails(self):
        source = guarded_call_division("u32")
        self.assertTrue(proof.verify_sequential_core(source)["passed"])
        source["exports"].append("divide")
        result = proof.verify_sequential_core(source)
        self.assertFalse(result["passed"], result)
        self.assertEqual(result["exports"], ["calculate", "divide"])
        self.assertEqual(result["reason"], "public_export_normal_return_not_proved:divide")
        self.assertEqual(result["obligations"][-1]["totality"]["counterexample"]["observation"],
                         {"status": "trapped", "code": "division_by_zero"})
        self.assertFalse(any(result["claims"].values()))

    def test_good_first_export_cannot_hide_other_export_overflow(self):
        source = selected_module()
        addition = source["functions"][2]["blocks"][0]["ops"][0]
        addition["op"] = "int.add.checked"
        source["functions"][2]["effects"] = ["trap"]
        # Order in the serialized export array cannot suppress a checked export.
        source["exports"] = ["calculate", "add_with_dead_literal"]
        result = proof.verify_sequential_core(source)
        self.assertFalse(result["passed"], result)
        self.assertEqual(result["obligations"][0]["totality"]["status"], "disproved")
        self.assertEqual(result["obligations"][0]["totality"]["counterexample"]["observation"]["code"], "overflow")

    def test_mutated_actual_llvm_return_is_refuted_after_core_totality_passes(self):
        source = json.loads((proof.ROOT / "formal/selected_u32_dead_literal.core.hepta").read_bytes())
        emitted = emit_program_llvm(verify_program(source))
        changed = emitted.text.replace(" = add i32 ", " = sub i32 ", 1)
        self.assertNotEqual(changed, emitted.text)
        with patch.object(proof, "emit_program_llvm", return_value=replace(
                emitted, text=changed, sha256=sha256(changed.encode()).hexdigest())):
            result = proof.verify_sequential_core(source)
        self.assertFalse(result["passed"], result)
        row = result["obligations"][0]
        self.assertEqual(row["totality"]["status"], "proved")
        self.assertEqual(row["lowering"]["status"], "refuted")
        self.assertIn("counterexample", row["lowering"])

    def test_unrelated_totality_receipt_cannot_enter_the_same_source_chain(self):
        source = arithmetic("int.add.wrap", "u32")
        actual = proof.validate_scalar_totality(source, function="calculate")
        for field, value in (("program_sha256", "0" * 64),
                             ("function", "unrelated"), ("input_sha256", "0" * 64)):
            changed = deepcopy(actual)
            changed[field] = value
            with patch.object(proof, "validate_scalar_totality", return_value=changed):
                result = proof.verify_sequential_core(source)
            self.assertFalse(result["passed"], result)
            self.assertIsNone(result["obligations"][0]["lowering"])

    def test_unknown_solver_or_drifting_source_never_composes_partial_evidence(self):
        source = arithmetic("int.add.wrap", "u32")
        with patch.object(proof, "validate_scalar_totality", return_value={"status": "unknown"}):
            unknown = proof.verify_sequential_core(source)
        self.assertFalse(unknown["passed"])
        with patch.object(proof, "_source_identity", side_effect=[{"source": "a"}, {"source": "b"}]):
            drift = proof.verify_sequential_core(source)
        self.assertEqual(drift["reason"], "proof_implementation_changed", drift)
        self.assertFalse(drift["passed"])
        self.assertFalse(any(drift["claims"].values()))

    def test_loops_empty_exports_and_unqualified_schema_do_not_inherit_profile(self):
        loop = m(f("calculate", [], ["u8"], [], [
            b("entry", [], [], jump("cycle")), b("cycle", [], [], jump("cycle"))]))
        empty = arithmetic("int.add.wrap", "u32")
        empty["exports"] = []
        later = arithmetic("int.add.wrap", "u32")
        later["schema"] = "hepta.hia.program.v8"
        for source in (loop, empty, later):
            verify_program(source)
            result = proof.verify_sequential_core(source)
            self.assertFalse(result["passed"], result)
            self.assertFalse(any(result["claims"].values()))

    def test_whole_chain_deadline_cannot_restart_for_each_export_or_proof(self):
        source = arithmetic("int.add.wrap", "u32")
        with patch.object(proof, "_now_ns", side_effect=[0, 10_000_000_001, 10_000_000_002]):
            result = proof.verify_sequential_core(source)
        self.assertFalse(result["passed"], result)
        self.assertEqual(result["reason"], "whole_proof_deadline_exhausted")
        self.assertEqual(result["obligations"], [])

    def test_qualification_retains_exact_core_actual_llvm_and_independently_replayable_lowering_query(self):
        import z3
        source = selected_module()
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "proof"
            result = proof.qualify(source, output)
            self.assertTrue(result["passed"], result)
            self.assertEqual(sha256((output/"core.core.hepta").read_bytes()).hexdigest(), result["core_sha256"])
            self.assertEqual(sha256((output/"program.ll").read_bytes()).hexdigest(), result["llvm_sha256"])
            for index in range(len(result["obligations"])):
                solver = z3.Solver()
                solver.from_string((output/f"lowering-{index:02d}.smt2").read_text())
                self.assertEqual(solver.check(), z3.unsat)
            for name, identity in json.loads((output/"manifest.json").read_bytes()).items():
                self.assertEqual(identity["sha256"], sha256((output/name).read_bytes()).hexdigest())
                self.assertEqual(identity["bytes"], (output/name).stat().st_size)


if __name__ == "__main__":
    unittest.main()
