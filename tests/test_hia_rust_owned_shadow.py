"""Opt-in exact HIA Python ↔ Rust Owner/Loan CFG acceptance differential."""
import copy
import json
from pathlib import Path
import shutil
import subprocess
import unittest

from hepta.hia_program import HIAProgramRejected, verify_program
from tests.test_hia_program import resource_program, joined_loan_program

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "rust" / "hia-core-shadow" / "Cargo.toml"

@unittest.skipUnless(shutil.which("cargo"), "Cargo unavailable; NOT Rust-qualified")
class RustOwnerLoanShadow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        p = subprocess.run(["cargo", "build", "--manifest-path", str(MANIFEST)],
                           cwd=ROOT, capture_output=True, text=True, timeout=240)
        if p.returncode:
            raise AssertionError("Rust build failed: " + p.stderr[-6000:])

    def run_shadow(self, document):
        payload = (document if isinstance(document, bytes) else
                   json.dumps(document, ensure_ascii=False).encode("utf-8"))
        return subprocess.run([
            "cargo", "run", "--offline", "--quiet",
            "--manifest-path", str(MANIFEST), "--", "--owned-shadow"],
            input=payload, cwd=ROOT, capture_output=True, timeout=60)

    def test_checked_owner_path_and_cross_block_loan_match(self):
        for factory in (resource_program, joined_loan_program):
            with self.subTest(factory=factory.__name__):
                canonical = verify_program(factory())
                result = self.run_shadow(canonical.canonical_bytes)
                self.assertEqual(result.returncode, 0,
                                 result.stderr.decode(errors="replace"))
                report = json.loads(result.stdout)
                self.assertEqual(report["program_sha256"], canonical.sha256)
                self.assertIs(report["claims"]["cross_block_owner_loan_state_checked"], True)
                self.assertIs(report["claims"]["general_memory_provenance_proved"], False)
                self.assertIs(report["claims"]["rust_is_production_admission_authority"], False)

    def test_shared_denials(self):
        variants = []
        p = resource_program()
        p["functions"][0]["blocks"][0]["ops"][-1]["args"] = ["owner"]
        variants.append(p)  # old owner already consumed by move
        p = resource_program()
        p["functions"][0]["effects"] = ["alloc","write","trap"]
        variants.append(p)  # read effect lost
        p = joined_loan_program()
        p["functions"][0]["blocks"][0]["term"]["then"]["args"][1] = "a"
        variants.append(p)  # same Owner on one CFG edge twice
        for p in variants:
            with self.subTest(case=str(p["functions"][0]["name"])):
                with self.assertRaises(HIAProgramRejected):
                    verify_program(p)
                self.assertNotEqual(self.run_shadow(p).returncode, 0)

    def test_genuine_borrowed_v2_bulk_is_explicitly_unimplemented(self):
        p = resource_program()
        p["schema"] = "hepta.hia.program.v2"
        instructions = p["functions"][0]["blocks"][0]["ops"]
        instructions.insert(3, {
            "op":"buffer.fill", "args":["writer","value"], "out":[], "attrs":{}
        })
        verified = verify_program(p)
        result = self.run_shadow(verified.canonical_bytes)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"E_HIA_RUST_UNSUPPORTED", result.stderr)

if __name__ == "__main__":
    unittest.main()
