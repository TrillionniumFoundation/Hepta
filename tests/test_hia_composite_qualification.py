"""Retained native evidence for combined nominal resources and cancellation."""
from copy import deepcopy
import os
from pathlib import Path
import shutil
import tempfile
import unittest

from hepta.hia_program import verify_core
from tools.qualify_hia_program_composite import qualify, validate_composite_receipt


CLANG = os.environ.get("CLANG") or shutil.which("clang")


@unittest.skipUnless(CLANG, "Actual Clang 20+ required")
class CompositeQualificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="hepta-composite-evidence-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name) / "native"
        cls.report = qualify(cls.root, clang=CLANG)
        if not cls.report["ok"]:
            raise AssertionError(cls.report.get("diagnostic"))

    def test_actual_allocator_faults_missing_free_mutant_and_protocol_aborts_retained(self):
        report = self.report
        self.assertEqual(report["native_result_executions"], 36)
        self.assertEqual(report["actual_null_refusal_observations"], 12)
        self.assertEqual(report["observed_successful_allocations"], 16)
        self.assertEqual(report["observed_frees"], 16)
        self.assertEqual(report["actual_protocol_aborts"], 4)
        for name in ("structured", "normalized"):
            native = report["native"][name]
            self.assertEqual(native["observed"]["allocator"],
                             {"attempts": 14, "allocations": 8, "frees": 8, "live": 0, "refusals": 6, "invalid_frees": 0})
            self.assertEqual(native["build"]["exports"], ["choose", "stored", "task_case"])
        wrong = report["missing_free_control"]
        self.assertFalse(wrong["qualified_hia_artifact"])
        self.assertEqual(wrong["observed"]["cases"], report["native"]["structured"]["observed"]["cases"])
        self.assertEqual((wrong["observed"]["allocator"]["frees"], wrong["observed"]["allocator"]["live"]), (0, 8))
        self.assertEqual(report["processes"][wrong["run_process"]]["returncode"], 91)
        self.assertEqual(len(report["static_rejections"]), 8)
        self.assertTrue(report["origin_tamper_control"]["rejected"])
        self.assertTrue((self.root / "missing-free.o").is_file())
        self.assertTrue((self.root / "poll_complete/program").is_file())
        structured = verify_core((self.root / "input.hia.json").read_bytes())
        normalized = verify_core((self.root / "normalized.hia.json").read_bytes())
        self.assertEqual(structured.canonical_bytes, normalized.canonical_bytes)
        self.assertEqual(structured.scalar_entrypoints, normalized.scalar_entrypoints)
        self.assertNotEqual(structured.input_sha256, normalized.input_sha256)
        self.assertEqual(report["source_bindings_before"], report["source_bindings_after"])

    def test_false_claims_changed_inputs_and_coordinated_link_receipt_rejected(self):
        changes = [
            lambda r: r.update(input_sha256="0" * 64),
            lambda r: r["claims"].update(physical_hardware_qualified=True),
            lambda r: r["native"]["normalized"]["observed"]["allocator"].update(frees=0),
            lambda r: r["cases"].pop(),
            lambda r: r["static_rejections"].__setitem__(1, deepcopy(r["static_rejections"][0])),
            lambda r: r["protocol_traps"].__setitem__(1, deepcopy(r["protocol_traps"][0])),
        ]
        for mutate in changes:
            altered = deepcopy(self.report); mutate(altered)
            with self.subTest(change=str(mutate)), self.assertRaises(ValueError):
                validate_composite_receipt(altered)
        altered = deepcopy(self.report)
        index = altered["native"]["structured"]["link_process"]
        altered["processes"][index]["argv"].append("unrelated-original-library.o")
        with self.assertRaisesRegex(ValueError, "only its direct core object"):
            validate_composite_receipt(altered)
        ir = self.root / "normalized.ll"
        before = ir.read_bytes()
        try:
            ir.write_bytes(before + b"; changed retained LLVM\n")
            with self.assertRaisesRegex(ValueError, "LLVM"):
                validate_composite_receipt(self.report)
        finally:
            ir.write_bytes(before)


if __name__ == "__main__":
    unittest.main()
