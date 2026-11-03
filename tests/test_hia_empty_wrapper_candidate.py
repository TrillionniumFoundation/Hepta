"""Experimental wrapper changes preserve complete Core calls and ABI admission."""
from dataclasses import replace
from hashlib import sha256
from pathlib import Path
import tempfile
import unittest

from hepta.hia_program import verify_program
from hepta.hia_program_llvm import (compile_program_llvm, emit_program_llvm,
                                    HIAProgramLLVMRejected)
from hepta.hia_program_source import lower_source
from tools.hia_empty_wrapper_candidate import emit_candidate


class EmptyWrapperCandidateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).resolve().parents[1] / "benchmarks/hia_reduction_release/linear.hepta"
        cls.program = lower_source(path.read_text())
        cls.length = next(p["name"] for p in cls.program.as_dict()["functions"][0]["params"] if p["type"] == "usize")

    def test_only_wrapper_changes_and_both_paths_call_the_complete_core(self):
        original = emit_program_llvm(self.program)
        text, report = emit_candidate(self.program, {"calculate": self.length})
        self.assertEqual(report["core_sha256"], self.program.sha256)
        restored = text
        for row in report["wrappers"]:
            restored = restored.replace(row["candidate_wrapper"], row["canonical_wrapper"])
            self.assertEqual(row["candidate_wrapper"].count(" call "), 2)
            self.assertIn("icmp eq i64 %a0, 0", row["candidate_wrapper"])
            self.assertIn("@__hia_fn_0(i64 0, i32 %a1) alwaysinline", row["candidate_wrapper"])
            self.assertIn("@__hia_fn_0(i64 %a0, i32 %a1) noinline", row["candidate_wrapper"])
            self.assertNotIn("ret i64 0", row["candidate_wrapper"])
        self.assertEqual(restored, original.text)
        self.assertFalse(report["production_admission"])

    def test_length_position_is_derived_from_verified_signature(self):
        data = self.program.as_dict()
        fn = data["functions"][0]
        fn["params"].reverse()
        entry = next(b for b in fn["blocks"] if b["id"] == fn["entry"])
        entry["params"].reverse()
        text, report = emit_candidate(verify_program(data), {"calculate": self.length})
        self.assertEqual(report["wrappers"][0]["parameter_index"], 1)
        self.assertIn("icmp eq i64 %a1, 0", text)
        self.assertIn("@__hia_fn_0(i32 %a0, i64 0) alwaysinline", text)

    def test_wrong_or_unknown_length_selection_is_refused(self):
        for selected in ({}, {"missing": "n"}, {"calculate": "missing"}, {"calculate": "seed"}):
            with self.assertRaises(ValueError):
                emit_candidate(self.program, selected)

    def test_production_compiler_still_refuses_experimental_ir(self):
        canonical = emit_program_llvm(self.program)
        text, _ = emit_candidate(self.program, {"calculate": self.length})
        altered = replace(canonical, text=text, sha256=sha256(text.encode()).hexdigest())
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(HIAProgramLLVMRejected, "differs from independently reverified"):
                compile_program_llvm(altered, program=self.program, output=Path(directory) / "not-created.o", kind="object")
