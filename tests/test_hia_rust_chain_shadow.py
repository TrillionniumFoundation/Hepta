"""HIA v7 Python-authority vs opt-in Rust Owner/Chain verifier differential.

Genuine canonical source fixtures are always verified in Python first.
Cargo absence is SKIPPED, not counted as Rust/native qualification.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import shutil
import subprocess
import unittest

from hepta.hia_program import HIAProgramRejected, verify_program
from tests.test_hia_program import b, c, f, i, ret
from tools.qualify_hia_recursive_chain import EXAMPLES

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "rust" / "hia-core-shadow" / "Cargo.toml"


def chain_primitive():
    return {
        "schema": "hepta.hia.program.v7", "module": "chain_differential",
        "functions": [
            f("entrypoint", [], [], ["alloc", "read", "trap"], [
                b("entry", [], [
                    i("chain.empty", out=[("tail", "chain")]),
                    c("zero", "usize", 0),
                    i("buffer.new", ["zero"], [("payload", "buffer")]),
                    i("chain.try_push", ["tail", "payload"],
                      [("full", "chain"), ("unused", "buffer"), ("ok", "bool")]),
                    i("chain.head_read", ["full"], [("head", "readbuf")]),
                    i("loan.end", ["head"]),
                    i("chain.pop", ["full"],
                      [("rest", "chain"), ("item", "buffer"), ("popped", "bool")]),
                    i("owner.drop", ["unused"]),
                    i("owner.drop", ["item"]),
                    i("owner.drop", ["rest"])
                ], ret())
            ])
        ]
    }


@unittest.skipUnless(shutil.which("cargo"), "Cargo unavailable: Rust v7 Chain NOT qualified")
class RustChainShadowDifferential(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        build = subprocess.run(
            ["cargo", "build", "--manifest-path", str(MANIFEST)],
            cwd=ROOT, capture_output=True, text=True, timeout=240,
            check=False)
        if build.returncode:
            raise AssertionError("Cargo build rejected v7 shadow:\n" + build.stderr[-5000:])

    @staticmethod
    def rust(document):
        raw = (document if isinstance(document, bytes) else
               json.dumps(document, ensure_ascii=False).encode("utf-8"))
        return subprocess.run(
            ["cargo", "run", "--quiet", "--offline",
             "--manifest-path", str(MANIFEST), "--", "--owned-shadow"],
            cwd=ROOT, input=raw, capture_output=True, timeout=60, check=False)

    def test_complete_real_recursive_chain_core_profile(self):
        # The original full Core includes 9 functions and CFG loops. All
        # function bodies, including unused helpers, must be checked.
        raw = (EXAMPLES / "core_v7.json").read_bytes()
        canonical = verify_program(raw)
        result = self.rust(canonical.canonical_bytes)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        report = json.loads(result.stdout)
        self.assertEqual(report["program_sha256"], canonical.sha256)
        self.assertEqual(report["functions_checked"], 9)
        self.assertIs(report["claims"]["v7_chain_owner_loan_cfg_checked"], True)
        self.assertIs(report["claims"]["v7_chain_native_semantics_proved"], False)
        self.assertIs(report["claims"]["rust_is_production_admission_authority"], False)

    def test_complete_primitive_and_older_version_negative(self):
        document = chain_primitive()
        verified = verify_program(document)
        result = self.rust(verified.canonical_bytes)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        self.assertEqual(json.loads(result.stdout)["program_sha256"], verified.sha256)

        for version in range(1, 7):
            older = copy.deepcopy(document)
            older["schema"] = f"hepta.hia.program.v{version}"
            with self.subTest(version=version):
                with self.assertRaises(HIAProgramRejected):
                    verify_program(older)
                self.assertNotEqual(self.rust(older).returncode, 0)

    def test_shared_real_loan_effect_alias_and_descriptor_denials(self):
        cases = []
        doc = chain_primitive()
        doc["functions"][0]["blocks"][0]["ops"][5] = i("owner.drop", ["full"])
        cases.append(doc)  # chain is still head-borrowed
        doc = chain_primitive()
        doc["functions"][0]["blocks"][0]["ops"][3]["out"][0]["type"] = "buffer"
        cases.append(doc)  # try_push must return chain, not buffer
        doc = chain_primitive()
        doc["functions"][0]["blocks"][0]["ops"][4] = i(
            "borrow.read", ["full"], [("head", "readbuf")])
        cases.append(doc)  # chain is not a byte buffer
        doc = chain_primitive()
        doc["functions"][0]["effects"] = ["alloc", "trap"]
        cases.append(doc)  # missing read effect
        doc = chain_primitive()
        doc["functions"][0]["blocks"][0]["ops"].append(i("owner.drop", ["rest"]))
        cases.append(doc)  # double drop
        for i_case, bad in enumerate(cases):
            with self.subTest(case=i_case):
                with self.assertRaises(HIAProgramRejected):
                    verify_program(bad)
                self.assertNotEqual(self.rust(bad).returncode, 0)


if __name__ == "__main__":
    unittest.main()
