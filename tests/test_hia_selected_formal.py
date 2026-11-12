"""Actual selected-Core proofs plus fail-closed import and evidence controls."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import tempfile
import unittest

from tools import qualify_hia_selected_formal as formal


class SelectedFormalInputTests(unittest.TestCase):
    def test_export_uses_actual_instruction_order_and_independent_machine(self):
        checked, generated, mapping = formal.export_program(formal.SELECTED.read_bytes())
        self.assertIn("inductive Operation", generated)
        self.assertIn("def run : List Operation", generated)
        self.assertEqual([item["lean_operation"] for item in mapping["instructions"]],
                         [".add 0 1", ".literal (BitVec.ofNat 32 17)", ".add 2 3", ".sub 4 3"])
        self.assertEqual(mapping["result_register"], 5)
        self.assertEqual(len(checked.as_dict()["functions"][0]["blocks"][0]["ops"]), 4)
        self.assertNotIn("theorem selected_program_correct (x y : Word) : x + y = x + y", generated)

    def test_changed_real_opcode_changes_the_imported_program_but_not_specification(self):
        core = formal.export_program(formal.SELECTED.read_bytes())[0].as_dict()
        positive = formal.export_program(core)[1]
        for document in formal.mutation_documents(core).values():
            _, negative, _ = formal.export_program(document)
            self.assertNotEqual(positive, negative)
            self.assertIn("def specification (left right : Word) : Word := left + right", negative)

    def test_export_profile_rejects_checked_arithmetic_wrong_width_and_branch(self):
        for mutation in ("checked", "width", "more_functions"):
            document = json.loads(formal.SELECTED.read_bytes())
            fn = document["functions"][0]
            if mutation == "checked":
                fn["blocks"][0]["ops"][0]["op"] = "int.add.checked"
                fn["effects"] = ["trap"]
            elif mutation == "width":
                document = json.loads(json.dumps(document).replace('"u32"', '"u64"'))
            else:
                extra = copy.deepcopy(fn)
                extra["name"] = "other"
                document["functions"].append(extra)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                formal.export_program(document)

    def test_fake_lean_is_rejected_before_it_can_print_a_claim(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fake = root / "lean"
            fake.write_text("#!/bin/sh\ntouch '" + str(root / "executed") + "'\n")
            fake.chmod(0o755)
            with self.assertRaisesRegex(ValueError, "pinned binary SHA-256"):
                formal.qualify(fake, root / "output")
            self.assertFalse((root / "executed").exists())
            self.assertFalse((root / "output").exists())


class SelectedFormalKernelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        lean = os.environ.get("LEAN")
        if not lean or not Path(lean).is_file():
            raise unittest.SkipTest("set LEAN to the pinned 4.19.0 checker for actual proof controls")
        cls.temporary = tempfile.TemporaryDirectory(prefix="hia-selected-formal-tests-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.directory = Path(cls.temporary.name) / "qualification"
        cls.report = formal.qualify(lean, cls.directory, clang=os.environ.get("CLANG"))

    def test_real_kernel_proves_all_inputs_and_rejects_changed_actual_core(self):
        formal.validate_report(self.report, self.directory)
        self.assertTrue(self.report["ok"])
        self.assertEqual(self.report["input_domain_size"], str(2**64))
        self.assertEqual(set(self.report["theorems"]), formal.THEOREMS)
        self.assertEqual(len(self.report["negative_mutations"]), 2)
        self.assertFalse(self.report["claims"]["python_exporter_refinement_proved"])
        self.assertFalse(self.report["claims"]["llvm_or_native_refinement_proved"])
        self.assertFalse(self.report["claims"]["whole_language_soundness_proved"])
        for entry in self.report["negative_mutations"]:
            self.assertEqual(entry["returncode"], 1)
            self.assertIn("sorryAx", entry["theorems"]["selected_program_correct"])

    def test_receipts_cannot_drop_mutations_or_promote_the_claim(self):
        mutations = [
            lambda report: report["negative_mutations"].pop(),
            lambda report: report["claims"].update(whole_language_soundness_proved=True),
            lambda report: report["claims"].update(selected_imported_program_all_u32_inputs_proved=1),
            lambda report: report.update(core_sha256="0" * 64),
            lambda report: report.update(external_specification="every HIA program is safe"),
            lambda report: report["positive"].update(returncode=True),
        ]
        if self.report["native"]["performed"]:
            mutations.append(lambda report: report["native"]["cases"].__setitem__(1, copy.deepcopy(report["native"]["cases"][0])))
        for index, mutation in enumerate(mutations):
            report = copy.deepcopy(self.report)
            mutation(report)
            with self.subTest(index=index), self.assertRaises(ValueError):
                formal.validate_report(report, self.directory)

    def test_changed_generated_file_is_rejected_even_with_unmodified_receipt(self):
        path = self.directory / "positive.lean"
        original = path.read_bytes()
        try:
            path.write_bytes(original.replace(b".add 0 1", b".sub 0 1", 1))
            with self.assertRaises(ValueError):
                formal.validate_report(self.report, self.directory)
        finally:
            path.write_bytes(original)


if __name__ == "__main__":
    unittest.main()
