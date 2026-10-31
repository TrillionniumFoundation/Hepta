"""The compact view must keep the actual Core, traps and resource checks."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from hepta.hia_agent_assembly import (
    HIAAssemblyRejected, MAX_LINE_BYTES, MAX_SOURCE_BYTES,
    assemble_program, diagnose_assembly, render_assembly,
)
from hepta.hia_program import HIAProgramRejected, verify_program
from hepta.hia_program_llvm import emit_program_llvm
from hepta.hia_program_runtime import HIAProgramTrap, execute_program
from tests.test_hia_program import arithmetic, joined_loan_program, resource_program


ROOT = Path(__file__).resolve().parents[1]
SOURCE = """hia-asm.v1 hepta.hia.program.v6 sums
exports(total)
fn total(a:u32,b:u32) -> (u64) effects() entry(entry)
block entry(a:u32,b:u32)
  a64:u64 = int.cast(a) {"mode":"wrap"}
  b64:u64 = int.cast(b) {"mode":"wrap"}
  answer:u64 = int.add.wrap(a64,b64)
  ret(answer)
end
"""


def v6(program):
    result = copy.deepcopy(program)
    result["schema"] = "hepta.hia.program.v6"
    return result


class HIAAgentAssemblyTests(unittest.TestCase):
    def test_actual_mathematical_wide_sum_and_canonical_rerender(self):
        program = assemble_program(SOURCE)
        for a, b in ((0, 0), (2**32 - 1, 1), (2**32 - 1, 2**32 - 1)):
            self.assertEqual(execute_program(program, "total", [a, b])["result"], a + b)
        self.assertEqual(render_assembly(program), SOURCE)
        self.assertEqual(assemble_program(SOURCE.encode()).canonical_bytes, program.canonical_bytes)

    def test_checked_overflow_and_declared_trap_are_not_dropped(self):
        original = verify_program(v6(arithmetic("int.add.checked", "u8")))
        restored = assemble_program(render_assembly(original))
        self.assertEqual(original.canonical_bytes, restored.canonical_bytes)
        reports = []
        for program in (original, restored):
            with self.assertRaises(HIAProgramTrap) as caught:
                execute_program(program, "calculate", [255, 1])
            reports.append(caught.exception.report)
        self.assertEqual(reports[0], reports[1])
        self.assertEqual(reports[0]["error"]["code"], "overflow")

    def test_owner_move_loans_and_cleanup_execute_in_existing_vm(self):
        original = verify_program(v6(resource_program()))
        restored = assemble_program(render_assembly(original))
        for n in (1, 7, 32):
            left = execute_program(original, "owned", [n, 231])
            right = execute_program(restored, "owned", [n, 231])
            self.assertEqual(left, right)
            self.assertEqual(right["result"], 231)
        self.assertEqual(emit_program_llvm(original).text, emit_program_llvm(restored).text)

    def test_real_joined_loans_cfg_parameters_preserve_origin(self):
        original = verify_program(v6(joined_loan_program()))
        restored = assemble_program(render_assembly(original))
        for branch in (False, True):
            self.assertEqual(execute_program(original, "join", [branch]),
                             execute_program(restored, "join", [branch]))
        self.assertEqual(original.canonical_bytes, restored.canonical_bytes)

    def test_recursive_chain_v7_roundtrip_and_failure_paths(self):
        original = verify_program((ROOT / "examples/hia_recursive_chain/core_v7.json").read_bytes())
        restored = assemble_program(render_assembly(original))
        self.assertEqual(original.canonical_bytes, restored.canonical_bytes)
        for count in (0, 1, 7):
            for failure in (None, 1, 3):
                self.assertEqual(
                    execute_program(original, "chain_checksum", [count], allocation_fail_at=failure),
                    execute_program(restored, "chain_checksum", [count], allocation_fail_at=failure))

    def test_explicit_empty_exports_and_absence_are_distinct(self):
        full = assemble_program(SOURCE).as_dict()
        for exports in (None, [], ["total"]):
            document = copy.deepcopy(full)
            if exports is None:
                document.pop("exports")
            else:
                document["exports"] = exports
            checked = verify_program(document)
            self.assertEqual(assemble_program(render_assembly(checked)).canonical_bytes,
                             checked.canonical_bytes)

    def test_dropped_owner_is_not_synthesized_to_repair_a_leak(self):
        source = render_assembly(v6(resource_program()))
        with self.assertRaises(HIAProgramRejected) as caught:
            assemble_program(source.replace("  _ = owner.drop(moved)\n", ""))
        self.assertEqual(caught.exception.code, "E_HIA_RESOURCE")

    def test_use_after_move_is_rejected_by_original_verifier(self):
        source = render_assembly(v6(resource_program()))
        with self.assertRaises(HIAProgramRejected):
            assemble_program(source.replace("owner.drop(moved)", "owner.drop(owner)"))

    def test_unsafe_loan_overlap_is_rejected_by_original_verifier(self):
        source = render_assembly(v6(resource_program()))
        with self.assertRaises(HIAProgramRejected):
            assemble_program(source.replace("  _ = loan.end(writer)\n", ""))

    def test_wrong_signature_unknown_operation_and_missing_attribute_reject(self):
        variants = (
            SOURCE.replace("block entry(a:u32,b:u32)", "block entry(a:u64,b:u32)"),
            SOURCE.replace("int.add.wrap", "int.add.guess"),
            SOURCE.replace(' {"mode":"wrap"}', ""),
            SOURCE.replace("answer:u64", "answer:u32"),
        )
        for source in variants:
            with self.subTest(source=source), self.assertRaises(HIAProgramRejected):
                assemble_program(source)

    def test_duplicate_ssa_keeps_core_error_without_guessing_a_location(self):
        diagnostic = diagnose_assembly(SOURCE.replace("b64:u64", "a64:u64"))
        self.assertFalse(diagnostic["accepted"])
        self.assertEqual(diagnostic["diagnostic"]["code"], "E_HIA_SSA")
        self.assertEqual(diagnostic["diagnostic"]["phase"], "core_verification")
        self.assertIsNone(diagnostic["diagnostic"]["line"])

    def test_unknown_header_historical_and_nominal_profiles_reject(self):
        for schema in ("hepta.hia.program.v2", "hepta.hia.composite.v1", "hepta.hia.program.v99"):
            with self.subTest(schema=schema), self.assertRaises(HIAAssemblyRejected):
                assemble_program(SOURCE.replace("hepta.hia.program.v6", schema))
        with self.assertRaises(HIAAssemblyRejected):
            render_assembly(arithmetic())
        composite = (ROOT / "examples/hia_recursive_chain/composite_v2.json").read_bytes()
        with self.assertRaises(HIAAssemblyRejected):
            render_assembly(composite)

    def test_duplicate_json_keys_nonfinite_and_nesting_are_not_accepted(self):
        for attrs in ('{"mode":"wrap","mode":"checked"}',
                      '{"mode":NaN}', '["wrap"]',
                      '{"mode":' + '[' * 17 + '0' + ']' * 17 + '}'):
            with self.subTest(attrs=attrs), self.assertRaises(HIAProgramRejected):
                assemble_program(SOURCE.replace('{"mode":"wrap"}', attrs, 1))

    def test_utf8_controls_and_explicit_line_diagnostic(self):
        for bad in (b"\xff", "\ufeff" + SOURCE, SOURCE + "\x00", SOURCE.replace("a64:u64", "a64\ru64")):
            with self.subTest(bad=str(bad)[:20]), self.assertRaises(HIAAssemblyRejected):
                assemble_program(bad)
        source = SOURCE.replace("a64:u64 =", "a64 =")
        diagnostic = diagnose_assembly(source)
        self.assertEqual(diagnostic["diagnostic"]["line"], 5)
        self.assertEqual(diagnostic["diagnostic"]["phase"], "syntax")
        self.assertEqual(assemble_program(SOURCE.replace("\n", "\r\n")).sha256,
                         assemble_program(SOURCE).sha256)

    def test_unicode_separators_and_invisible_formats_are_rejected_before_core(self):
        # Python regex \s matches Unicode whitespace even though this wire
        # format admits only ASCII spaces/tabs and LF/CRLF line endings.
        separators = ("\u00a0", "\u0085", "\u2009", "\u2028")
        formats = ("\u200b", "\u202e", "\u2066")
        with patch("hepta.hia_agent_assembly.verify_program") as verifier:
            for separator in separators:
                source = SOURCE.replace("hia-asm.v1 ", "hia-asm.v1" + separator, 1)
                with self.subTest(separator=ord(separator)):
                    with self.assertRaises(HIAAssemblyRejected) as caught:
                        assemble_program(source)
                    self.assertEqual(caught.exception.code, "E_HIA_ASSEMBLY")
                    diagnostic = diagnose_assembly(source)
                    self.assertFalse(diagnostic["accepted"])
                    self.assertEqual(diagnostic["diagnostic"]["phase"], "syntax")
            for control in formats:
                source = SOURCE + control
                with self.subTest(format=ord(control)):
                    with self.assertRaises(HIAAssemblyRejected) as caught:
                        assemble_program(source)
                    self.assertEqual(caught.exception.code, "E_HIA_ASSEMBLY")
            verifier.assert_not_called()
        # Existing ASCII whitespace and explicit CRLF are unchanged.
        baseline = assemble_program(SOURCE).canonical_bytes
        self.assertEqual(assemble_program(SOURCE.replace(
            "hia-asm.v1 ", "hia-asm.v1\t", 1)).canonical_bytes, baseline)
        self.assertEqual(assemble_program(SOURCE.replace(
            "\n", "\r\n")).canonical_bytes, baseline)

    def test_missing_terminator_end_extra_text_and_duplicate_exports_reject(self):
        variants = (SOURCE.replace("  ret(answer)\n", ""), SOURCE.removesuffix("end\n"),
                    SOURCE + "garbage\n", SOURCE.replace("exports(total)", "exports(total)\nexports(total)"),
                    SOURCE.replace("  ret(answer)", "  ret(answer)\n  ret(answer)"),
                    SOURCE.replace("block entry(a:u32,b:u32)", "block entry(a:u32,b:u32,)"))
        for source in variants:
            with self.subTest(source=source), self.assertRaises(HIAProgramRejected):
                assemble_program(source)

    def test_byte_line_and_inventory_limits_apply_before_core_verification(self):
        with patch("hepta.hia_agent_assembly.verify_program") as verifier:
            for source in (" " * (MAX_SOURCE_BYTES + 1), " " * (MAX_LINE_BYTES + 1),
                           "\n" * 16384, SOURCE.replace("a64:u64", "x" * 129 + ":u64")):
                with self.subTest(length=len(source)), self.assertRaises(HIAProgramRejected):
                    assemble_program(source)
            verifier.assert_not_called()
        with patch("hepta.hia_agent_assembly.MAX_OPERATIONS", 1):
            with self.assertRaisesRegex(HIAAssemblyRejected, "operation inventory"):
                assemble_program(SOURCE)
        with patch("hepta.hia_agent_assembly.MAX_FUNCTIONS", 0):
            with self.assertRaisesRegex(HIAAssemblyRejected, "function inventory"):
                assemble_program(SOURCE)
        with patch("hepta.hia_agent_assembly.MAX_BLOCKS", 0):
            with self.assertRaisesRegex(HIAAssemblyRejected, "block inventory"):
                assemble_program(SOURCE)

    def test_atomic_cross_function_interface_upgrade_needs_both_changes(self):
        source = SOURCE.replace("exports(total)", "exports(caller)") + """fn caller(x:u32,y:u32) -> (u64) effects() entry(start)
block start(x:u32,y:u32)
  value:u64 = call(x,y) {"function":"total"}
  ret(value)
end
"""
        self.assertEqual(execute_program(assemble_program(source), "caller", [2**32 - 1, 1])["result"], 2**32)
        changed = source.replace("fn total(a:u32,b:u32)", "fn total(a:u64,b:u64)").replace(
            "block entry(a:u32,b:u32)", "block entry(a:u64,b:u64)")
        with self.assertRaises(HIAProgramRejected):
            assemble_program(changed)
        changed = changed.replace('  value:u64 = call(x,y)',
            '  x64:u64 = int.cast(x) {"mode":"wrap"}\n'
            '  y64:u64 = int.cast(y) {"mode":"wrap"}\n  value:u64 = call(x64,y64)')
        self.assertEqual(execute_program(assemble_program(changed), "caller", [2**32 - 1, 1])["result"], 2**32)

    def test_accepted_diagnostic_is_not_a_deployment_receipt(self):
        diagnostic = diagnose_assembly(SOURCE)
        self.assertTrue(diagnostic["accepted"])
        for field in ("deployment_authority", "safety_certificate", "native_artifact_created"):
            self.assertFalse(diagnostic[field])
        self.assertEqual(diagnostic["core_sha256"], assemble_program(SOURCE).sha256)
        with self.assertRaises(HIAProgramRejected):
            assemble_program(json.dumps(diagnostic))


if __name__ == "__main__":
    unittest.main()
