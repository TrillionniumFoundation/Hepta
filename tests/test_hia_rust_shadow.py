"""Opt-in Python↔Rust scalar Core parity; skips (does not pass) without cargo."""
import json
from pathlib import Path
import shutil
import subprocess
import unittest

from hepta.hia_program import verify_program, HIAProgramRejected

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "rust" / "hia-core-shadow" / "Cargo.toml"


def sample():
    return {
        "schema": "hepta.hia.program.v1", "module": "scalar_test",
        "functions": [{
            "name": "add", "params": [{"name": "a", "type": "u32"},
                                      {"name": "b", "type": "u32"}],
            "returns": ["u32"], "effects": ["trap"], "entry": "entry",
            "blocks": [{
                "id": "entry", "params": [{"name": "a", "type": "u32"},
                                         {"name": "b", "type": "u32"}],
                "ops": [{"op": "int.add.checked", "args": ["a", "b"],
                         "out": [{"name": "result", "type": "u32"}], "attrs": {}}],
                "term": {"op": "ret", "values": ["result"]}
            }]
        }]
    }


@unittest.skipUnless(shutil.which("cargo"), "Rust toolchain missing: NOT qualified")
class RustScalarShadow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        build = subprocess.run(
            ["cargo", "build", "--manifest-path", str(MANIFEST)],
            cwd=ROOT, capture_output=True, text=True, timeout=240, check=False)
        if build.returncode:
            raise AssertionError("Rust shadow build failed:\n" + build.stderr[-4000:])

    def run_rust(self, value):
        payload = (value if isinstance(value, bytes) else
                   json.dumps(value, ensure_ascii=False).encode("utf-8"))
        result = subprocess.run(
            ["cargo", "run", "--quiet", "--manifest-path", str(MANIFEST), "--offline"],
            cwd=ROOT, input=payload, capture_output=True, timeout=60, check=False)
        return result

    def test_reference_scalar_digest(self):
        for version in range(1, 8):
            source = sample()
            source["schema"] = f"hepta.hia.program.v{version}"
            reference = verify_program(source)
            rust = self.run_rust(reference.canonical_bytes)
            self.assertEqual(rust.returncode, 0, rust.stderr.decode(errors="replace"))
            report = json.loads(rust.stdout)
            self.assertEqual(report["program_sha256"], reference.sha256)
            self.assertIs(report["claims"]["backend_refinement_proved"], False)
            self.assertIs(report["claims"]["resource_provenance_verified"], False)

    def test_shared_negative_cases(self):
        variants = []
        invalid_effect = sample()
        invalid_effect["functions"][0]["effects"] = []
        variants.append(invalid_effect)
        undefined = sample()
        undefined["functions"][0]["blocks"][0]["ops"][0]["args"] = ["a", "absent"]
        variants.append(undefined)
        unknown_field = sample()
        unknown_field["new_proof"] = False
        variants.append(unknown_field)
        for bad in variants:
            with self.assertRaises(HIAProgramRejected):
                verify_program(bad)
            self.assertNotEqual(self.run_rust(bad).returncode, 0)

    def test_v7_hidden_resource_function_cannot_bypass_whole_module_check(self):
        # A public scalar export cannot smuggle a separate uncalled v7
        # resource function into the shadow's claimed scalar-only module.
        source = sample()
        source["schema"] = "hepta.hia.program.v7"
        source["exports"] = ["add"]
        source["functions"].append({
            "name": "hidden_chain", "params": [], "returns": [],
            "effects": ["alloc"], "entry": "hidden_entry",
            "blocks": [{
                "id": "hidden_entry", "params": [],
                "ops": [
                    {"op": "chain.empty", "args": [],
                     "out": [{"name": "chain_owner", "type": "chain"}], "attrs": {}},
                    {"op": "owner.drop", "args": ["chain_owner"],
                     "out": [], "attrs": {}}
                ],
                "term": {"op": "ret", "values": []}
            }]
        })
        canonical = verify_program(source)
        refused = self.run_rust(canonical.canonical_bytes)
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn(b"E_HIA_RUST_UNSUPPORTED", refused.stderr)

    def test_python_accepts_resource_but_rust_shadow_rejects(self):
        source = {
            "schema": "hepta.hia.program.v1", "module": "resource_test",
            "functions": [{
                "name": "owned", "params": [{"name": "n", "type": "usize"}],
                "returns": [], "effects": ["alloc", "trap"], "entry": "entry",
                "blocks": [{
                    "id": "entry", "params": [{"name": "n", "type": "usize"}],
                    "ops": [
                        {"op": "buffer.new", "args": ["n"],
                         "out": [{"name": "buf", "type": "buffer"}], "attrs": {}},
                        {"op": "owner.drop", "args": ["buf"], "out": [], "attrs": {}}
                    ], "term": {"op": "ret", "values": []}
                }]
            }]
        }
        reference = verify_program(source)
        rust = self.run_rust(reference.canonical_bytes)
        self.assertNotEqual(rust.returncode, 0)
        self.assertIn(b"E_HIA_RUST_UNSUPPORTED", rust.stderr)


if __name__ == "__main__":
    unittest.main()
