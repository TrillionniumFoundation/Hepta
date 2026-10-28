"""Independent raw-byte admission: never replace Rust input with Python Core."""
from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import unittest

from hepta.hia_program import HIAProgramRejected, verify_program
from hepta.hia_program_runtime import execute_program

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "rust" / "hia-core-shadow" / "Cargo.toml"


def raw_constant(version, typ, token):
    source = {
        "schema": f"hepta.hia.program.v{version}", "module": "raw_integer",
        "functions": [{"name": "run", "params": [], "returns": [typ],
                       "effects": [], "entry": "entry", "blocks": [{
            "id": "entry", "params": [], "ops": [{"op": "const", "args": [],
                "out": [{"name": "zero", "type": typ}], "attrs": {"value": "RAW_TOKEN"}}],
            "term": {"op": "ret", "values": ["zero"]}}]}]}
    return json.dumps(source, separators=(",", ":")).replace('"RAW_TOKEN"', token).encode()


@unittest.skipUnless(shutil.which("cargo"), "Cargo missing: raw Rust parity NOT qualified")
class RustRawIntegerParity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        build = subprocess.run(
            ["cargo", "build", "--locked", "--offline", "--message-format=json",
             "--manifest-path", str(MANIFEST)], cwd=ROOT, capture_output=True,
            text=True, timeout=240, check=False)
        if build.returncode:
            raise AssertionError(build.stderr)
        executables = [row["executable"] for line in build.stdout.splitlines()
                       if (row := json.loads(line)).get("reason") == "compiler-artifact"
                       and row.get("executable") and "bin" in row["target"]["kind"]]
        if len(executables) != 1:
            raise AssertionError("Cargo did not identify one actual shadow binary")
        cls.executable = executables[0]

    def rust(self, raw, *arguments):
        return subprocess.run([self.executable, *arguments], input=raw, cwd=ROOT,
                              capture_output=True, check=False, timeout=15)

    def test_raw_negative_zero_has_same_identity_values_steps_and_resources(self):
        for version in range(1, 9):
            for typ in ("i8", "u64", "usize"):
                with self.subTest(version=version, typ=typ):
                    raw = raw_constant(version, typ, "-0")
                    self.assertIn(b'"value":-0', raw)
                    python = verify_program(raw)
                    ordinary = verify_program(raw_constant(version, typ, "0"))
                    self.assertEqual(python.canonical_bytes, ordinary.canonical_bytes)
                    admitted = self.rust(raw, "--owned-shadow")
                    self.assertEqual(admitted.returncode, 0, admitted.stderr)
                    self.assertEqual(json.loads(admitted.stdout)["program_sha256"], python.sha256)
                    execution = self.rust(raw, "--owned-run", "run", "[]", "20", "0", "none")
                    self.assertEqual(execution.returncode, 0, execution.stderr)
                    rust = json.loads(execution.stdout)
                    reference = execute_program(raw, "run", [], max_steps=20, max_heap_bytes=0,
                                                max_call_depth=32)
                    for key in ("status", "values", "steps", "resources", "program_sha256"):
                        self.assertEqual(rust[key], reference[key], key)
                    self.assertIs(rust["claims"]["production_admission_authorized"], False)

    def test_raw_float_malformed_and_quoted_spellings_are_independently_rejected(self):
        for token in ("-0.0", "0e0", "-0e0", "-0E+0", "-00", "00", "--0", "+0",
                      "- 0", "-0false", "-0:0", "-0 0", "0-0", '"-0"'):
            with self.subTest(token=token):
                raw = raw_constant(8, "i64", token)
                with self.assertRaises(HIAProgramRejected):
                    verify_program(raw)
                for args in (("--owned-shadow",), ("--owned-run", "run", "[]", "0", "0", "none")):
                    result = self.rust(raw, *args)
                    self.assertEqual(result.returncode, 1, result.stderr)
                    self.assertEqual(result.stdout, b"")
                    self.assertNotIn(b"panicked", result.stderr)

    def test_raw_cli_negative_zero_uses_same_argument_decoder(self):
        program = json.loads(raw_constant(8, "i64", "0"))
        fn = program["functions"][0]
        fn["params"] = fn["blocks"][0]["params"] = [{"name": "zero", "type": "i64"}]
        fn["blocks"][0]["ops"] = []
        raw = json.dumps(program, separators=(",", ":")).encode()
        result = self.rust(raw, "--owned-run", "run", "[-0]", "20", "0", "none")
        self.assertEqual(result.returncode, 0, result.stderr)
        rust = json.loads(result.stdout)
        reference = execute_program(raw, "run", json.loads("[-0]"), max_steps=20,
                                    max_heap_bytes=0, max_call_depth=32)
        for key in ("status", "values", "steps", "resources"):
            self.assertEqual(rust[key], reference[key], key)
        for arguments in ("[-0.0]", "[0e0]", "[-00]", '["-0"]'):
            refused = self.rust(raw, "--owned-run", "run", arguments, "20", "0", "none")
            self.assertEqual(refused.returncode, 1, refused.stderr)
            self.assertEqual(refused.stdout, b"")


if __name__ == "__main__":
    unittest.main()
