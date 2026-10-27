"""Actual multi-resource migration/native execution and evidence rejection."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from tools import qualify_cpp_composed_llvm as qualifier
from tools.validate_cpp_owned import _captured_streams, _identity

NATIVE = all(shutil.which(name) for name in
             ("clang", "clang++", "gcc", os.environ.get("RUSTC", "rustc")))


class ComposedLLVMPathTests(unittest.TestCase):
    def test_existing_directory_and_dangling_symlink_are_preserved(self):
        with tempfile.TemporaryDirectory(prefix="hepta-composed-llvm-path-") as temporary:
            root = Path(temporary)
            (root / "marker").write_text("retain")
            with self.assertRaisesRegex(ValueError, "new composed LLVM"):
                qualifier.qualify_cpp_composed_llvm(root)
            link = root / "dangling"
            link.symlink_to(root / "missing", target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "new composed LLVM"):
                qualifier.qualify_cpp_composed_llvm(link)
            self.assertTrue(link.is_symlink())
            self.assertFalse((root / "missing").exists())
            self.assertEqual((root / "marker").read_text(), "retain")


@unittest.skipUnless(NATIVE, "requires Clang20+, GCC and pinned Rust1.90")
class ComposedLLVMNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="hepta-composed-llvm-tests-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        cls.report = qualifier.qualify_cpp_composed_llvm(cls.root / "actual", rustc=os.environ.get("RUSTC"))
        if cls.report["ok"] is not True:
            raise AssertionError(cls.report["diagnostics"])

    def test_actual_1883_calls_allocator_refusal_order_and_leak_controls(self):
        report = self.report
        self.assertTrue(qualifier.validate_report(report))
        expected = {"pair": (437, 401, 196, "79fca1db8d2f0865"),
                    "triple": (613, 796, 307, "857e18f53bf7b178"),
                    "quad": (833, 1409, 423, "6d4d805955152153")}
        for name, (count, allocated, refusals, digest) in expected.items():
            with self.subTest(variant=name):
                row = report["variants"][name]
                self.assertEqual(row["observed"], {"ok": True, "cases": count,
                    "observations_fnv64": digest, "allocations": allocated,
                    "frees": allocated, "refusals": refusals, "live": 0})
                self.assertEqual(row["symbols"]["defined"], ["composed_case"])
                self.assertEqual(row["foreign_cpp_link_inputs"], [])
                for ordinal in range(1, qualifier.VARIANTS[name] + 1):
                    self.assertGreater(row["case_families"]["allocation_refusal_" + str(ordinal)], 0)
                for mutation, negative in row["negative_controls"].items():
                    self.assertEqual(negative["execution"]["returncode"], 3)
                    self.assertEqual(negative["observed"], qualifier.negative_oracle(name, mutation))
                    self.assertFalse(negative["qualified_compiler_output"])
        self.assertEqual(sum(r["observed"]["cases"] for r in report["variants"].values()), 1883)
        self.assertEqual(sum(r["observed"]["refusals"] for r in report["variants"].values()), 926)
        self.assertEqual(sum(r["observed"]["allocations"] for r in report["variants"].values()), 2606)

    def test_closed_report_rejects_changed_scope_commands_source_and_observations(self):
        mutations = {
            "broadened_scope": lambda r: r["claims"].update(source_equivalence_proved=True),
            "unknown_claim": lambda r: r.update(all_blockers_closed=True),
            "missing_variant": lambda r: r["variants"].pop("quad"),
            "stale_compiler": lambda r: r.update(compiler_sha256="0" * 64),
            "missing_order_control": lambda r: r["variants"]["pair"]["negative_controls"].pop("destruction_order"),
            "case_denominator": lambda r: r["variants"]["pair"].update(case_families={}),
            "ast_inventory": lambda r: r["variants"]["pair"]["migration"].update(active_declarations=True),
            "source_replay_omitted": lambda r: r["variants"]["pair"]["build"]["claims"].update(actual_source_replayed=False),
            "hidden_fallback": lambda r: r["variants"]["pair"]["build"]["native_backend"]["claims"].update(fallback_used=True),
            "rehashed_semantic_origin": lambda r: r["variants"]["pair"]["build"]["source_binding"].update(semantic_sha256="0" * 64),
            "legal_resource_count_tamper": lambda r: r["variants"]["pair"]["build"]["resource_verification"].update(ok=False),
            "foreign_implementation": lambda r: r["variants"]["pair"]["foreign_cpp_link_inputs"].append("original.o"),
            "link_command": lambda r: r["variants"]["pair"]["link"]["command"].insert(-2, "original.o"),
            "untyped_caller_flags": lambda r: r["variants"]["pair"]["link"]["command"].remove("-Werror=implicit-function-declaration"),
            "wrong_executable": lambda r: r["variants"]["pair"]["execution"].update(command=["/bin/true"]),
            "bool_exit_code": lambda r: r["variants"]["pair"]["execution"].update(returncode=False),
            "bool_observation": lambda r: r["variants"]["pair"]["observed"].update(live=False),
            "foreign_symbol": lambda r: r["variants"]["pair"]["symbols"]["undefined"].append("foreign_method"),
            "unchecked_llvm_claim": lambda r: r["variants"]["pair"]["negative_controls"]["leak"].update(qualified_compiler_output=True),
            "negative_not_executed": lambda r: r["variants"]["pair"]["negative_controls"]["leak"]["execution"].update(returncode=0),
        }
        for name, mutate in mutations.items():
            candidate = copy.deepcopy(self.report); mutate(candidate)
            with self.subTest(mutation=name), self.assertRaises(ValueError):
                qualifier.validate_report(candidate)

    def test_self_rehashed_llvm_cannot_replace_actual_source_projection(self):
        candidate = copy.deepcopy(self.report)
        row = candidate["variants"]["pair"]
        path = Path(row["llvm_source"]["path"]); original = path.read_bytes()
        try:
            path.write_bytes(original + b"\n; added after verified source lowering\n")
            row["llvm_source"] = _identity(path)
            with self.assertRaisesRegex(ValueError, "LLVM text differs from actual source"):
                qualifier.validate_report(candidate)
        finally:
            path.write_bytes(original)

    def test_native_object_mutation_is_not_replaced_by_a_report_hash(self):
        row = self.report["variants"]["pair"]
        path = Path(row["object"]["path"]); original = path.read_bytes()
        try:
            path.write_bytes(original + b"actual tamper")
            with self.assertRaisesRegex(ValueError, "Retained native artifact/source"):
                qualifier.validate_report(self.report)
        finally:
            path.write_bytes(original)

    def test_forged_negative_trace_with_resealed_output_still_rejects(self):
        candidate = copy.deepcopy(self.report)
        negative = candidate["variants"]["pair"]["negative_controls"]["destruction_order"]
        negative["observed"]["trace"] = "0" * 16
        negative["execution"].update(_captured_streams(json.dumps(negative["observed"]).encode() + b"\n", b""))
        with self.assertRaisesRegex(ValueError, "independent resource-event oracle"):
            qualifier.validate_report(candidate)

    def test_native_link_timeout_preserves_migration_object_and_partial_output(self):
        record = {"status": "timeout", "command": ["mock-link-driver"], "returncode": None,
                  "timeout_seconds": 1, **_captured_streams(b"partial\xff", b"diagnostic\xfe")}
        with patch.object(qualifier, "_run", return_value=record):
            report = qualifier.qualify_cpp_composed_llvm(self.root / "failed-link", rustc=os.environ.get("RUSTC"))
        self.assertFalse(report["ok"])
        row = report["variants"]["pair"]
        self.assertTrue(row["migration"]["ok"])
        self.assertTrue(row["build"]["ok"])
        self.assertTrue(Path(row["object"]["path"]).is_file())
        self.assertEqual(row["stage"], "native_link")
        self.assertEqual(row["link"], record)
        self.assertNotIn("execution", row)

    def test_report_cannot_select_an_executable_for_layout_replay(self):
        candidate = copy.deepcopy(self.report)
        candidate["tools"]["clang"] = {"driver": "/bin/true", **_identity("/bin/true")}
        with patch.object(qualifier, "probe_owned_target_layout", side_effect=AssertionError("unselected execution")):
            with self.assertRaisesRegex(ValueError, "Caller-selected Clang"):
                qualifier.validate_report(candidate)


if __name__ == "__main__":
    unittest.main()
