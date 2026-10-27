"""Exact-byte Rust HIA runner protocol and real producer integration.

The protocol class uses explicit fake scripts; the native class builds and
runs the actual Rust producer. Neither is a whole-language safety proof.
"""
from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest

from hepta.hia_rust_crosscheck import (HIARustCrosscheckRejected,
                                       crosscheck_rust_shadow)


def scalar_program():
    return {
        "schema": "hepta.hia.program.v1", "module": "scalar_shadow_gate",
        "functions": [{
            "name": "identity", "params": [{"name": "v", "type": "u32"}],
            "returns": ["u32"], "effects": [], "entry": "entry",
            "blocks": [{
                "id": "entry", "params": [{"name": "v", "type": "u32"}],
                "ops": [], "term": {"op": "ret", "values": ["v"]},
            }],
        }],
    }


def owned_program():
    return {
        "schema": "hepta.hia.program.v1", "module": "owned_shadow_gate",
        "functions": [{
            "name": "allocate_release", "params": [{"name": "n", "type": "usize"}],
            "returns": [], "effects": ["alloc", "trap"], "entry": "entry",
            "blocks": [{
                "id": "entry", "params": [{"name": "n", "type": "usize"}],
                "ops": [{"op": "buffer.new", "args": ["n"],
                         "out": [{"name": "owner", "type": "buffer"}], "attrs": {}},
                        {"op": "owner.drop", "args": ["owner"], "out": [], "attrs": {}}],
                "term": {"op": "ret", "values": []},
            }],
        }],
    }


@unittest.skipUnless(platform.system() == "Linux", "Linux exact-file execution required")
class RustShadowCrosscheckProtocol(unittest.TestCase):
    def make_fake(self, root: Path, *, mode: str = "valid", profile: str = "owned"):
        claims = {
            "scalar": {
                "scalar_ssa_and_cfg_checked": True,
                "v7_chain_resources_supported": False,
                "resource_provenance_verified": False,
                "full_hia_verifier_replaced": False,
                "whole_language_soundness_proved": False,
                "backend_refinement_proved": False,
                "ffi_supported": False,
                "native_executed": False,
            },
            "owned": {
                "finite_owner_loan_cfg_checked": True,
                "cross_block_owner_loan_state_checked": True,
                "v2_v6_bulk_byte_opcode_types_loans_and_effects_checked": True,
                "interprocedural_resource_calls_checked": True,
                "v7_chain_native_semantics_proved": False,
                "recursion_or_stack_bounds_proved": False,
                "general_memory_provenance_proved": False,
                "full_source_to_core_refinement_proved": False,
                "llvm_backend_refinement_proved": False,
                "whole_language_soundness_proved": False,
                "native_execution_qualified": False,
                "rust_is_production_admission_authority": False,
            },
        }
        script = f'''#!{sys.executable}
import sys, json, hashlib, time
mode = {mode!r}
profile = {profile!r}
data = sys.stdin.buffer.read()
doc = json.loads(data)
claims = {claims[profile]!r}
version_claim = 'v7_scalar_only_checked' if profile == 'scalar' else 'v7_chain_owner_loan_cfg_checked'
claims[version_claim] = doc['schema'] == 'hepta.hia.program.v7'
if mode == 'wrong_version': claims[version_claim] = not claims[version_claim]
if mode == 'integer_version': claims[version_claim] = int(claims[version_claim])
if mode == 'missing_version': del claims[version_claim]
if mode == 'sleep': time.sleep(2)
if mode == 'flood':
    sys.stdout.write('X' * 500000)
    sys.stdout.flush()
    sys.exit(0)
if mode == 'stderr':
    sys.stderr.write('unexpected report diagnostics')
if mode == 'proof_promoted': claims['whole_language_soundness_proved'] = 0
if mode == 'extra_claim': claims['future_claim'] = False
result = {{
    'schema': 'hepta.hia.rust-owner-shadow.v1' if profile == 'owned' else 'hepta.hia.rust-scalar-shadow.v1',
    'ok': True,
    'program_sha256': hashlib.sha256(data).hexdigest() if mode != 'wrong_digest' else '0' * 64,
    'functions_checked': len(doc['functions']),
    'blocks_checked': sum(len(fn['blocks']) for fn in doc['functions']),
    'claims': claims,
}}
if profile == 'scalar': result['source_required'] = False
if mode == 'duplicate':
    sys.stdout.write('{{"schema":"x","schema":"y"}}\\n')
else:
    print(json.dumps(result, sort_keys=True))
'''
        path = root / f"test-shadow-{mode}-{profile}"
        path.write_text(script, encoding="utf-8")
        path.chmod(0o700)
        return path, sha256(path.read_bytes()).hexdigest()

    def test_pinned_scalar_and_owned_hia_witnesses_are_corroborated(self):
        for profile, factory in (("scalar", scalar_program), ("owned", owned_program)):
            with self.subTest(profile=profile), tempfile.TemporaryDirectory() as td:
                exe, digest = self.make_fake(Path(td), profile=profile)
                result = crosscheck_rust_shadow(factory(), exe, executable_sha256=digest,
                                                profile=profile)
                self.assertEqual(result["status"], "shadow_corroborated_not_authority")
                self.assertIs(result["claims"]["rust_is_production_admission_authority"], False)
                self.assertIs(result["claims"]["native_backend_refinement_proved"], False)

    def test_forged_claims_wrong_digest_and_extra_metadata_refuse(self):
        for mode in ("proof_promoted", "wrong_digest", "extra_claim", "duplicate"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as td:
                exe, digest = self.make_fake(Path(td), mode=mode)
                with self.assertRaises(HIARustCrosscheckRejected):
                    crosscheck_rust_shadow(owned_program(), exe,
                                           executable_sha256=digest)

    def test_version_claims_bind_exact_core_and_profile(self):
        for profile, factory in (("scalar", scalar_program), ("owned", owned_program)):
            for version in (1, 6, 7):
                program = factory()
                program["schema"] = f"hepta.hia.program.v{version}"
                with self.subTest(profile=profile, version=version), tempfile.TemporaryDirectory() as td:
                    exe, digest = self.make_fake(Path(td), profile=profile)
                    result = crosscheck_rust_shadow(program, exe,
                                                   executable_sha256=digest,
                                                   profile=profile)
                    claim = ("v7_scalar_only_checked" if profile == "scalar"
                             else "v7_chain_owner_loan_cfg_checked")
                    self.assertIs(result["shadow_report"]["claims"][claim], version == 7)
                    for mode in ("wrong_version", "integer_version", "missing_version"):
                        exe, digest = self.make_fake(Path(td), mode=mode, profile=profile)
                        with self.assertRaises(HIARustCrosscheckRejected):
                            crosscheck_rust_shadow(program, exe,
                                                   executable_sha256=digest,
                                                   profile=profile)

    def test_exact_executable_identity_is_required(self):
        with tempfile.TemporaryDirectory() as td:
            exe, digest = self.make_fake(Path(td))
            with self.assertRaisesRegex(HIARustCrosscheckRejected, "SHA-256"):
                crosscheck_rust_shadow(owned_program(), exe,
                                       executable_sha256="0" * 64)
            symlink = Path(td) / "shadow-link"
            symlink.symlink_to(exe)
            with self.assertRaises(HIARustCrosscheckRejected):
                crosscheck_rust_shadow(owned_program(), symlink,
                                       executable_sha256=digest)
            with self.assertRaises(HIARustCrosscheckRejected):
                crosscheck_rust_shadow(owned_program(), exe,
                                       executable_sha256="0" * 64, profile="both")

    def test_child_cannot_spool_unbounded_output_or_hide_stderr(self):
        for mode in ("flood", "stderr"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as td:
                exe, digest = self.make_fake(Path(td), mode=mode)
                with self.assertRaises(HIARustCrosscheckRejected):
                    crosscheck_rust_shadow(owned_program(), exe,
                                           executable_sha256=digest)

    def test_deadline_is_enforced_without_success_receipt(self):
        with tempfile.TemporaryDirectory() as td:
            exe, digest = self.make_fake(Path(td), mode="sleep")
            with self.assertRaisesRegex(HIARustCrosscheckRejected, "deadline"):
                crosscheck_rust_shadow(owned_program(), exe, executable_sha256=digest,
                                       timeout=0.1)

@unittest.skipUnless(platform.system() == "Linux" and shutil.which("cargo"),
                     "Real Rust crosscheck requires Linux and Cargo; NOT qualified")
class RustShadowCrosscheckNative(unittest.TestCase):
    """Build the actual producer and exercise the complete pinned-byte runner.

    Fake protocol scripts cannot catch producer/consumer claim-shape drift.
    Cargo reports the executable path so an external CARGO_TARGET_DIR works.
    """

    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[1]
        manifest = root / "rust" / "hia-core-shadow" / "Cargo.toml"
        result = subprocess.run(
            ["cargo", "build", "--locked", "--offline", "--message-format=json",
             "--manifest-path", str(manifest)],
            cwd=root, capture_output=True, text=True, timeout=240, check=False)
        if result.returncode:
            raise AssertionError("Actual Rust shadow build failed:\n" + result.stderr[-6000:])
        artifacts = [json.loads(line) for line in result.stdout.splitlines() if line]
        executables = [item["executable"] for item in artifacts
                       if item.get("reason") == "compiler-artifact"
                       and item.get("executable")
                       and "bin" in item.get("target", {}).get("kind", [])]
        if len(executables) != 1:
            raise AssertionError("Cargo did not identify exactly one shadow executable")
        cls.executable = Path(executables[0])
        cls.digest = sha256(cls.executable.read_bytes()).hexdigest()

    def crosscheck(self, document, profile):
        return crosscheck_rust_shadow(document, self.executable,
                                      executable_sha256=self.digest, profile=profile)

    def test_actual_scalar_reports_v1_through_v7(self):
        for version in range(1, 8):
            program = scalar_program()
            program["schema"] = f"hepta.hia.program.v{version}"
            with self.subTest(version=version):
                report = self.crosscheck(program, "scalar")
                self.assertEqual(report["status"], "shadow_corroborated_not_authority")
                self.assertIs(report["shadow_report"]["claims"]["v7_scalar_only_checked"],
                              version == 7)

    def test_actual_owner_reports_and_opt_in_chain_module(self):
        from tools.qualify_hia_recursive_chain import EXAMPLES

        for version in range(1, 8):
            program = owned_program()
            program["schema"] = f"hepta.hia.program.v{version}"
            with self.subTest(version=version):
                report = self.crosscheck(program, "owned")
                self.assertIs(report["shadow_report"]["claims"]["v7_chain_owner_loan_cfg_checked"],
                              version == 7)
        chain = (EXAMPLES / "core_v7.json").read_bytes()
        report = self.crosscheck(chain, "owned")
        self.assertEqual(report["shadow_report"]["functions_checked"], 9)
        self.assertIs(report["claims"]["rust_is_production_admission_authority"], False)
        # The same canonical resource module must still reject under the
        # default scalar profile; a version match does not widen its grammar.
        with self.assertRaises(HIARustCrosscheckRejected):
            self.crosscheck(chain, "scalar")

    def test_normalized_nominal_resources_and_cooperative_tasks(self):
        # Rust checks primitive Core. Composite source must first take the
        # same canonical normalization and whole-module check as VM/LLVM.
        # These real fixtures cover stored loans, task cancellation and
        # generic records/enums instead of a separate synthetic grammar.
        root = Path(__file__).resolve().parents[1]
        fixtures = (
            "examples/hia_program/generic_owned_enum.hia",
            "examples/hia_program/stored_loan_record.hia",
            "examples/hia_program/cooperative_task.hia",
            "examples/hia_recursive_chain/composite_v2.json",
        )
        for name in fixtures:
            with self.subTest(fixture=name):
                report = self.crosscheck((root / name).read_bytes(), "owned")
                self.assertEqual(report["core_sha256"],
                                 report["shadow_report"]["program_sha256"])
                self.assertIs(report["claims"]["whole_language_soundness_proved"], False)

    def test_global_json_budget_matches_python_before_nested_suffix_decoding(self):
        from hepta.hia_program import HIAProgramRejected, verify_program

        cap = 262_144
        inputs = (
            ("[" + "0," * (cap - 2) + "0]", "E_HIA_FORMAT"),
            ("[" + "0," * (cap - 3) + "[0,1.5]]", "E_HIA_LIMIT"),
            ("[" + "0," * (cap - 3) + '{"tail":[1.5]}]', "E_HIA_LIMIT"),
            ("[" * 64 + "0" + "]" * 64, "E_HIA_FORMAT"),
            ("[" * 65 + "1.5" + "]" * 65, "E_HIA_LIMIT"),
        )
        for index, (source, expected) in enumerate(inputs):
            raw = source.encode("utf-8")
            with self.subTest(case=index):
                with self.assertRaises(HIAProgramRejected) as caught:
                    verify_program(raw)
                self.assertEqual(caught.exception.code, expected)
                for args in ([], ["--owned-shadow"]):
                    result = subprocess.run([str(self.executable), *args],
                                            input=raw, capture_output=True,
                                            timeout=15, check=False)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, b"")
                    self.assertTrue(result.stderr.startswith(expected.encode() + b":"),
                                    result.stderr.decode(errors="replace"))


if __name__ == "__main__":
    unittest.main()
