"""Real C/C++ -> HIA -> native/Python/Rust execution and evidence negatives."""
from copy import deepcopy
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from tools.qualify_hia_rust_migration import qualify, validate_report


@unittest.skipUnless(all(shutil.which(tool) for tool in ("cargo", "rustc", "clang", "clang++", "gcc", "g++")),
                     "Native/Rust tools unavailable: migrated Core parity NOT qualified")
class RustMigrationParity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="hepta-rust-migration-test-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.report = qualify(Path(cls.temporary.name) / "run")
        if not cls.report["ok"]:
            raise AssertionError("Actual migration/native/Rust run failed: " + repr(cls.report.get("diagnostic")))

    def test_fresh_migrated_programs_and_exact_distinct_denominators(self):
        report = self.report
        validate_report(report)
        self.assertEqual(report["denominators"]["total_native_result_executions"], 1102)
        self.assertEqual(report["denominators"]["total_python_rust_pairs"], 188)
        self.assertEqual(report["denominators"]["cpp_byte_owner_native_cases_per_implementation"], 475)
        self.assertEqual(report["denominators"]["cpp_byte_owner_python_rust_cases"], 112)
        self.assertEqual(len(report["programs_by_sha256"]), 3)
        self.assertIs(report["claims"]["entire_native_corpus_executed_by_rust"], False)
        self.assertIs(report["claims"]["rust_production_admission_authorized"], False)

    def test_altered_live_resource_ledger_rejects_even_with_matching_raw_stdout(self):
        forged = deepcopy(self.report)
        row = forged["observations"][0]
        row["rust"]["resources"]["live_owners"] = 1
        row["process"]["stdout"] = json.dumps(row["rust"])
        with self.assertRaisesRegex(ValueError, "resources"):
            validate_report(forged)

    def test_boolean_allocator_count_cannot_equal_integer_count(self):
        forged = deepcopy(self.report)
        row = next(row for row in forged["observations"] if row["rust"]["resources"]["allocations"] == 1)
        row["rust"]["resources"]["allocations"] = True
        row["process"]["stdout"] = json.dumps(row["rust"])
        with self.assertRaisesRegex(ValueError, "resources"):
            validate_report(forged)

    def test_removed_case_and_relabelled_native_denominator_reject(self):
        missing = deepcopy(self.report)
        missing["observations"].pop()
        with self.assertRaisesRegex(ValueError, "missing or additional"):
            validate_report(missing)
        relabelled = deepcopy(self.report)
        relabelled["denominators"]["cpp_byte_owner_python_rust_cases"] = 475
        with self.assertRaisesRegex(ValueError, "denominator"):
            validate_report(relabelled)

    def test_rebound_core_and_authority_promotion_reject(self):
        rebound = deepcopy(self.report)
        row = rebound["observations"][0]
        row["rust"]["program_sha256"] = "0" * 64
        row["process"]["stdout"] = json.dumps(row["rust"])
        with self.assertRaisesRegex(ValueError, "identity"):
            validate_report(rebound)
        promoted = deepcopy(self.report)
        promoted["claims"]["rust_production_admission_authorized"] = True
        with self.assertRaisesRegex(ValueError, "claim"):
            validate_report(promoted)


if __name__ == "__main__":
    unittest.main()
