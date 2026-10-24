"""HSIR is a bounded typed-AST interchange, never an independent proof."""
import unittest

from hepta.checker import check
from hepta.parser import parse
from hepta.pipeline import analyze, hsir_analysis
from hepta.semantic_ir import lower_checked_program


class SemanticIRTests(unittest.TestCase):
    A = "fn add(a: i64, b: i64) -> i64 effects {panic} { return a + b; }"

    def lower(self, source):
        p = parse(source, "same.hepta")
        checked = check(p)
        self.assertTrue(checked.ok, [d.to_dict() for d in checked.diagnostics])
        return lower_checked_program(p, checked)

    def test_is_reproducible_across_fresh_parses(self):
        a = self.lower(self.A)
        b = self.lower(self.A)
        self.assertEqual(a, b)
        self.assertEqual(a["sha256"], b["sha256"])
        self.assertTrue(a["all_expressions_typed"])
        self.assertFalse(a["claims"]["native_borrow_validation"])
        self.assertEqual(a["functions"][0]["inferred_effects"], ["panic"])

    def test_source_change_invalidates_digest(self):
        first = self.lower(self.A)
        second = self.lower(self.A.replace("a + b", "b + a"))
        self.assertNotEqual(first["sha256"], second["sha256"])

    def test_project_identity_changes_digest(self):
        p = parse(self.A, "same.hepta")
        checked = check(p)
        a = lower_checked_program(p, checked, project_sha256="a")
        b = lower_checked_program(p, checked, project_sha256="b")
        self.assertNotEqual(a["sha256"], b["sha256"])

    def test_rejected_frontend_never_lowers(self):
        p = parse("fn broken() -> i64 effects {} { return false; }", "bad.hepta")
        checked = check(p)
        self.assertFalse(checked.ok)
        with self.assertRaises(ValueError):
            lower_checked_program(p, checked)

    def test_raw_pointer_marks_external_obligation(self):
        source = "extern \"C\" fn legacy(ptr: raw const u8) -> u64 effects {ffi, unsafe};"
        ir = self.lower(source)
        self.assertEqual(ir["external_obligations"][0]["status"],
                         "caller_obligation_not_dischargeable_by_hsir")
        self.assertIn("raw_pointer_signature", ir["external_obligations"][0]["reasons"])

    def test_frontend_only_never_claims_native_validation(self):
        analysis = analyze(self.A, "same.hepta", native=False)
        self.assertTrue(analysis.report["ok"])
        self.assertEqual(analysis.report["status"], "frontend_only")
        exported = hsir_analysis(analysis)
        self.assertTrue(exported["ok"])
        self.assertEqual(exported["status"], "frontend_only")
        self.assertFalse(exported["hsir"]["claims"]["whole_language_soundness_proved"])
        self.assertFalse(exported["hsir"]["claims"]["native_borrow_validation"])

    def test_failed_frontend_has_no_hsir(self):
        analysis = analyze("fn bad() -> i64 effects {} { return false; }",
                           "bad.hepta", native=False)
        self.assertFalse(analysis.report["ok"])
        exported = hsir_analysis(analysis)
        self.assertFalse(exported["ok"])
        self.assertIsNone(exported["hsir"])


if __name__ == "__main__":
    unittest.main()
