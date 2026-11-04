"""Concrete signature diagnostics do not cast, repair, or change admission."""
from copy import deepcopy
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from hepta.hia_agent_assembly import assemble_program, diagnose_assembly, render_assembly
from hepta.hia_opcodes import OPCODES, WIDTHS, OpcodeRejected, check_instruction, opcode_catalog
from hepta.hia_program import HIAProgramRejected, verify_program
from hepta.hia_program_runtime import execute_program
from tests.test_hia_agent_assembly import SOURCE
from tests.test_hia_program import arithmetic


ROOT = Path(__file__).resolve().parents[1]


class TypeDiagnosticTests(unittest.TestCase):
    def rejected(self, name, operands, results, attrs=None, code="E_HIA_TYPE"):
        before = deepcopy((operands, results, attrs))
        with self.assertRaises(OpcodeRejected) as caught:
            check_instruction(OPCODES[name], operands, results, {} if attrs is None else attrs)
        self.assertEqual(caught.exception.code, code)
        self.assertEqual((operands, results, attrs), before)
        return str(caught.exception)

    def test_arithmetic_result_mismatches_report_actual_and_required_widths(self):
        for operation in ("add", "sub", "mul"):
            for mode in ("checked", "wrap"):
                for operand in WIDTHS:
                    for result in WIDTHS:
                        if operand == result:
                            continue
                        with self.subTest(operation=operation, mode=mode, operand=operand, result=result):
                            name = f"int.{operation}.{mode}"
                            self.assertEqual(self.rejected(name, [operand, operand], [result]),
                                f"{name}: output types must match ('=0',); "
                                f"expected {(operand,)!r}, got {(result,)!r}; "
                                f"operands {(operand, operand)!r}")

    def test_operand_mismatch_resolves_reference_without_losing_category(self):
        self.assertEqual(self.rejected("int.add.wrap", ["u32", "u64"], ["u32"]),
            "int.add.wrap: operand types must match ('integer', '=0'); "
            "expected ('integer', 'u32'), got ('u32', 'u64'); operands ('u32', 'u64')")

    def test_select_resolves_operand_one_for_input_and_output(self):
        self.assertEqual(self.rejected("select", ["bool", "u32", "u32"], ["u64"]),
            "select: output types must match ('=1',); expected ('u32',), "
            "got ('u64',); operands ('bool', 'u32', 'u32')")
        self.assertIn("expected ('bool', 'scalar', 'u32'), got ('bool', 'u32', 'u64')",
                      self.rejected("select", ["bool", "u32", "u64"], ["u64"]))

    def test_declared_categories_remain_categories_not_inferred_types(self):
        self.assertIn("expected ('declared:integer',), got ('bool',); operands ('u32',)",
                      self.rejected("int.cast", ["u32"], ["bool"], {"mode": "wrap"}))
        self.assertIn("expected ('declared:scalar',), got ('buffer',); operands ()",
                      self.rejected("const", [], ["buffer"], {"value": 0}))

    def test_exact_and_multi_result_types_are_not_collapsed(self):
        self.assertIn("expected ('bool',), got ('u32',)",
                      self.rejected("compare.eq", ["u32", "u32"], ["u32"]))
        self.assertIn("expected ('chain', 'buffer', 'bool'), got ('chain', 'buffer', 'u8')",
                      self.rejected("chain.pop", ["chain"], ["chain", "buffer", "u8"]))

    def test_owner_move_keeps_exact_owner_identity(self):
        for operand, result in (("buffer", "chain"), ("chain", "buffer")):
            with self.subTest(operand=operand):
                self.assertIn(f"expected {(operand,)!r}, got {(result,)!r}",
                              self.rejected("owner.move", [operand], [result]))
                self.assertEqual(check_instruction(OPCODES["owner.move"], [operand], [operand], {}),
                                 frozenset())

    def test_borrow_operand_code_and_output_code_remain_distinct(self):
        for name, operands, results, category in (
                ("borrow.read", ["u32"], ["readbuf"], "bytes"),
                ("borrow.mut", ["readbuf"], ["mutbuf"], "mutable_source")):
            with self.subTest(name=name):
                message = self.rejected(name, operands, results, code="E_HIA_LOAN")
                self.assertIn(f"expected {(category,)!r}, got {tuple(operands)!r}", message)
        self.assertIn("expected ('mutbuf',), got ('readbuf',)",
                      self.rejected("borrow.mut", ["buffer"], ["readbuf"]))

    def test_attribute_and_arity_errors_keep_original_text_and_priority(self):
        self.assertEqual(self.rejected("int.add.wrap", ["bool"], [], {"extra": 1},
                                       code="E_HIA_FORMAT"),
                         "int.add.wrap: expected exactly  attributes")
        self.assertEqual(self.rejected("int.add.wrap", ["bool"], []),
                         "int.add.wrap: wrong operand count")
        self.assertEqual(self.rejected("int.add.wrap", ["u32", "u32"], []),
                         "int.add.wrap: wrong output count")

    def test_operand_failure_still_precedes_output_arity_or_type_failure(self):
        for results in ([], ["bool"]):
            with self.subTest(results=results):
                message = self.rejected("int.add.wrap", ["u32", "u64"], results)
                self.assertTrue(message.startswith("int.add.wrap: operand types must match"))
                self.assertNotIn("output", message)

    def test_all_catalog_valid_signatures_keep_exact_effects_and_inputs(self):
        # An explicit representative for each closed category. References must
        # copy an earlier operand; this constructs no programs or ownership proof.
        representatives = {"integer": "u32", "scalar": "u32", "equality": "u32",
                           "owner": "buffer", "bytes": "buffer", "view": "readbuf",
                           "mutable_source": "buffer", "declared:scalar": "u32",
                           "declared:integer": "u64"}
        for spec in OPCODES.values():
            with self.subTest(opcode=spec.name):
                operands = []
                for rule in spec.operands or ():
                    operands.append(operands[int(rule[1:])] if rule.startswith("=")
                                    else representatives.get(rule, rule))
                results = [operands[int(rule[1:])] if rule.startswith("=")
                           else representatives.get(rule, rule) for rule in spec.results or ()]
                attrs = {"const": {"value": 0}, "int.cast": {"mode": "wrap"},
                         "call": {"function": "callee"}}.get(spec.name, {})
                before = deepcopy((operands, results, attrs))
                self.assertEqual(check_instruction(spec, operands, results, attrs), frozenset(spec.effects))
                self.assertEqual((operands, results, attrs), before)
        self.assertEqual(check_instruction(OPCODES["int.cast"], ["u64"], ["u8"], {"mode": "checked"}),
                         frozenset({"trap"}))

    def test_literal_and_cast_mode_failures_keep_original_messages(self):
        self.assertEqual(self.rejected("const", [], ["u8"], {"value": 256}),
                         "constant must be an exactly typed scalar")
        self.assertEqual(self.rejected("int.cast", ["u32"], ["u64"], {"mode": "implicit"}),
                         "unsupported integer cast")

    def test_public_verifier_preserves_code_and_rejects_without_mutation(self):
        document = arithmetic("int.add.wrap", "u32")
        document["functions"][0]["blocks"][0]["ops"][0]["out"][0]["type"] = "u64"
        before = deepcopy(document)
        with self.assertRaises(HIAProgramRejected) as caught:
            verify_program(document)
        self.assertEqual(caught.exception.code, "E_HIA_TYPE")
        self.assertIn("expected ('u32',), got ('u64',); operands ('u32', 'u32')", str(caught.exception))
        self.assertEqual(document, before)

    def test_public_assembly_diagnostic_preserves_type_phase_and_code(self):
        bad = SOURCE.replace("answer:u64 = int.add.wrap(a64,b64)",
                             "answer:u64 = int.add.wrap(a,b)")
        diagnostic = diagnose_assembly(bad)
        self.assertFalse(diagnostic["accepted"])
        self.assertEqual(diagnostic["diagnostic"]["code"], "E_HIA_TYPE")
        self.assertEqual(diagnostic["diagnostic"]["phase"], "core_verification")
        self.assertIsNone(diagnostic["diagnostic"]["line"])
        self.assertEqual(diagnostic["source_sha256"], sha256(bad.encode()).hexdigest())
        self.assertEqual(diagnostic["source_bytes"], len(bad.encode()))
        self.assertIn("expected ('u32',), got ('u64',)", diagnostic["diagnostic"]["message"])

    def test_list_and_tuple_signature_inputs_have_the_same_diagnostic(self):
        self.assertEqual(self.rejected("int.add.wrap", ["u32", "u32"], ["u64"]),
                         self.rejected("int.add.wrap", ("u32", "u32"), ("u64",)))

    def test_unused_invalid_catalog_reference_does_not_replace_prior_rejection(self):
        # Existing any() short-circuits on the first wrong operand. Formatting
        # must not turn that error into IndexError/ValueError on a later rule.
        for reference in ("=99", "=-99", "=not-an-index"):
            with self.subTest(reference=reference):
                spec = replace(OPCODES["int.add.wrap"], operands=("bool", reference))
                with self.assertRaises(OpcodeRejected) as caught:
                    check_instruction(spec, ["u32", "u32"], ["u32"], {})
                self.assertEqual(caught.exception.code, "E_HIA_TYPE")
                self.assertIn(f"expected {('bool', reference)!r}", str(caught.exception))

    def test_call_dynamic_signature_remains_the_callers_responsibility(self):
        self.assertEqual(check_instruction(OPCODES["call"], ["buffer", "u64"],
                                           ["mutbuf", "bool"], {"function": "callee"}), frozenset())

    def test_cli_exposes_concrete_diagnostic_and_nonzero_exit(self):
        document = arithmetic("int.mul.wrap", "u32")
        document["functions"][0]["blocks"][0]["ops"][0]["out"][0]["type"] = "u64"
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "bad.hia"
            source.write_text(json.dumps(document), encoding="utf-8")
            result = subprocess.run([sys.executable, "-B", "-m", "hepta", "hia", "verify", str(source)],
                                    cwd=ROOT, capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        payload = json.loads(result.stdout)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["diagnostics"][0]["code"], "E_DRIVER")
        self.assertIn("E_HIA_TYPE", result.stdout)
        self.assertIn("expected ('u32',), got ('u64',)", result.stdout)

    def test_valid_wrapping_semantics_are_not_repaired(self):
        document = arithmetic("int.add.wrap", "u32")
        original = verify_program(document)
        self.assertEqual(execute_program(original, "calculate", [2**32 - 1, 1])["result"], 0)
        self.assertEqual(verify_program(document).canonical_bytes, original.canonical_bytes)

    def test_accepted_core_assembly_and_catalog_identities_remain_unchanged(self):
        # Baseline identities recorded before the diagnostic change. The source
        # checker implementation identity intentionally is not held constant.
        self.assertEqual(verify_program(arithmetic("int.add.wrap", "u32")).sha256,
                         "18e87ce97ca8473508ccf95b8554aec10c04ebd2f8df2b3a77af627a1595ee8a")
        checked = assemble_program(SOURCE)
        self.assertEqual(checked.sha256,
                         "ff826286d9ca1f35e5f0195ee81b7d785749af1934a9e4acde3986ff01a7238e")
        self.assertEqual(render_assembly(checked), SOURCE)
        self.assertEqual(assemble_program(render_assembly(checked)).canonical_bytes, checked.canonical_bytes)
        catalog = opcode_catalog()
        self.assertEqual(catalog["catalog_sha256"],
                         "dd6fc836b5e71db165dcf81bfcdd233fda25dc6888f720dcc472dcdcf986ee54")
        self.assertEqual(json.loads(json.dumps(catalog)),
                         json.loads((ROOT / "docs/hia-opcode-catalog.v8.json").read_text()))


if __name__ == "__main__":
    unittest.main()
