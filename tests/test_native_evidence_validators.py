"""Use real local gate outputs to reject malformed and inflated evidence."""
from pathlib import Path
import os
import shutil
import tempfile
import unittest

from tests.native_evidence_cases import MUTATIONS, alter
from tools import verify_memory, validate_native_host, validate_debugger

ROOT = Path(__file__).resolve().parents[1]
LEAN = os.environ.get("LEAN", str(ROOT.parent / "toolchains/lean-4.19.0/bin/lean"))
RUSTC = os.environ.get("RUSTC") or shutil.which("rustc")


class NativeEvidenceValidatorTests(unittest.TestCase):
    def controls(self, family, report, validate):
        validate(report)
        for name, changes in MUTATIONS[family]:
            with self.subTest(family=family, case=name):
                with self.assertRaises(ValueError):
                    validate(alter(report, changes))
        for malformed in (None, [], "passed", {"status":"passed"}):
            with self.subTest(family=family, malformed=repr(malformed)):
                with self.assertRaises(ValueError):
                    validate(malformed)

    @unittest.skipUnless(Path(LEAN).is_file(), "pinned Lean is required")
    def test_memory_proof_report_requires_kernel_dependencies_and_scoped_claims(self):
        with tempfile.TemporaryDirectory(prefix="hepta-proof-evidence-test-") as directory:
            report = verify_memory.verify(LEAN, Path(directory) / "proof.json")
            self.controls("memory", report, verify_memory.validate_report)

    @unittest.skipUnless(RUSTC and shutil.which("gcc"), "native Rust/GCC host execution required")
    def test_host_report_requires_real_build_commands_and_same_host_targets(self):
        report = validate_native_host.run_host(rustc=RUSTC)
        self.controls("host", report, validate_native_host.validate_report)

    @unittest.skipUnless(RUSTC and shutil.which("gcc") and shutil.which("gdb"), "native Rust/GCC/GDB required")
    def test_debugger_report_binds_raw_observations_to_actual_source_mapping(self):
        report = validate_debugger.qualify()
        self.controls("debug", report, validate_debugger.validate_report)


if __name__ == "__main__":
    unittest.main()
