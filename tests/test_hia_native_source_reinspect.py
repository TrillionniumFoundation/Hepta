"""Actual source-stage HIA binary reinspection; no fake compiler attestation.

The shared objects/objects here are ordinary Clang C controls, NOT generated
from HIA. They deliberately exercise the *outer* source-facing ELF/object
trust boundary independently of the existing inner native compiler report.
"""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import unittest

from hepta.hia_program import verify_program
from hepta.hia_program_llvm import (TARGET, TARGET_AARCH64,
                                    emit_program_llvm)
from hepta.hia_source_bridge import (HIAHeptaBridgeRejected,
                                     _reinspect_source_native_bytes)
from hepta.elf_shared_abi import inspect_owned_shared_elf
from hepta.object_symbols import inspect_object_symbols


def core():
    return verify_program({
        "schema": "hepta.hia.program.v1", "module": "native_reinspect",
        "functions": [{
            "name": "trusted", "params": [], "returns": ["i32"],
            "effects": [], "entry": "b0",
            "blocks": [{"id": "b0", "params": [],
                        "ops": [{"op": "const", "args": [],
                                 "out": [{"name": "v", "type": "i32"}],
                                 "attrs": {"value": 7}}],
                        "term": {"op": "ret", "values": ["v"]}}],
        }],
    })


_CLAIMS = {
    "standalone_core_reverified": True,
    "source_ast_required": False,
    "rust_reference_required": False,
    "rust_codegen_used": False,
    "c_codegen_used": False,
    "fallback_used": False,
    "native_execution_qualified": False,
    "backend_refinement_proved": False,
    "cross_target_execution_qualified": False,
    "whole_language_soundness_proved": False,
    "foreign_buffer_entrypoints_exposed": False,
}


def receipt(ir, payload, path, *, kind, inventory):
    return {
        "schema": "hepta.hia.program.native.v1",
        "ok": True, "status": "native_compiled_not_executed",
        "profile": ir.profile, "target": ir.target,
        "kind": kind, "output": str(path),
        "core_sha256": ir.core_sha256, "llvm_ir_sha256": ir.sha256,
        "implementation_sha256": ir.implementation_sha256,
        "artifact_sha256": sha256(payload).hexdigest(),
        "artifact_bytes": len(payload),
        "exports": list(ir.exports), "binary_inventory": inventory,
        "external_abi": "test-only C control",
        "runtime_assumptions": [], "toolchain": {},
        "flags": [], "claims": dict(_CLAIMS),
    }


_SUPPORTED = (platform.system() == "Linux"
              and platform.machine().lower() in {"x86_64", "amd64"}
              and shutil.which("clang") is not None)


@unittest.skipUnless(_SUPPORTED, "needs Clang and Linux x86-64 ELF")
class HIASourceBinaryReinspectionTests(unittest.TestCase):
    def build(self, root, name, c_source, *, target=None, kind="shared"):
        c_path, binary = root / (name + ".c"), root / (name + (".so" if kind == "shared" else ".o"))
        c_path.write_text(c_source, encoding="ascii")
        command = ["clang", "-O0", "-fPIC"]
        if target is not None:
            command.append("--target=" + target)
        command += (["-shared"] if kind == "shared" else ["-c"])
        command += [str(c_path), "-o", str(binary)]
        subprocess.run(command, check=True, capture_output=True, timeout=30)
        return binary, binary.read_bytes()

    def test_real_shared_elf_matches_actual_bytes_and_rejects_forged_inventory(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            path, data = self.build(root, "good", "int trusted(void) { return 7; }")
            ir = emit_program_llvm(core(), target=TARGET)
            inventory = inspect_owned_shared_elf(data, ir.exports)
            honest = receipt(ir, data, path, kind="shared", inventory=inventory)
            self.assertEqual(_reinspect_source_native_bytes(
                data, ir, honest, target=TARGET, kind="shared", stage=path), inventory)
            for label, mutation in {
                "forged_exports": lambda r: r.update(exports=["renamed"]),
                "forged_binary_receipt": lambda r: r.update(binary_inventory={"defined": ["trusted"]}),
                "forged_profile": lambda r: r.update(profile="unreviewed"),
                "forged_proof": lambda r: r["claims"].update(backend_refinement_proved=True),
                "bool_integer_confusion": lambda r: r["claims"].update(native_execution_qualified=0),
                "wrong_path": lambda r: r.update(output=str(root / "other.so")),
                "wrong_digest": lambda r: r.update(artifact_sha256="a" * 64),
                "unknown_field": lambda r: r.update(unreviewed_allow=True),
            }.items():
                with self.subTest(case=label):
                    candidate = deepcopy(honest)
                    mutation(candidate)
                    with self.assertRaisesRegex(HIAHeptaBridgeRejected, "E_HIA_HEPTA_BRIDGE"):
                        _reinspect_source_native_bytes(
                            data, ir, candidate, target=TARGET, kind="shared", stage=path)

    def test_self_consistent_wrong_shared_export_or_import_is_not_authorized(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ir = emit_program_llvm(core(), target=TARGET)
            for name, source in (
                ("extra_export", "int trusted(void){return 7;} int foreign(void){return 0;}"),
                ("foreign_import", "extern long getpid(void); int trusted(void){return (int)getpid();}"),
            ):
                with self.subTest(name=name):
                    path, data = self.build(root, name, source)
                    # The receipt claims precisely the expected Core export
                    # and hashes the true mutated bytes. Neither is sufficient.
                    forged = receipt(ir, data, path, kind="shared",
                                     inventory={"schema": "hepta.elf-shared-abi.v1"})
                    with self.assertRaises(ValueError):
                        _reinspect_source_native_bytes(
                            data, ir, forged, target=TARGET, kind="shared", stage=path)

    def test_real_x86_and_aarch64_objects_and_unapproved_public_data(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for target, machine in ((TARGET, 62), (TARGET_AARCH64, 183)):
                with self.subTest(target=target):
                    ir = emit_program_llvm(core(), target=target)
                    path, data = self.build(root, "good_" + str(machine),
                                            "int trusted(void){return 7;}",
                                            target=target, kind="object")
                    symbols = inspect_object_symbols(data, "ELF64", machine)
                    inventory = {key: sorted(value) for key, value in symbols.items()}
                    approved = receipt(ir, data, path, kind="object", inventory=inventory)
                    self.assertEqual(_reinspect_source_native_bytes(
                        data, ir, approved, target=target, kind="object", stage=path), inventory)

                    bad_path, bad = self.build(root, "extra_data_" + str(machine),
                                               "int unapproved=5; int trusted(void){return 7;}",
                                               target=target, kind="object")
                    forged = receipt(ir, bad, bad_path, kind="object", inventory=inventory)
                    with self.assertRaises(ValueError):
                        _reinspect_source_native_bytes(
                            bad, ir, forged, target=target, kind="object", stage=bad_path)
                    other_target = TARGET_AARCH64 if target == TARGET else TARGET
                    other_ir = emit_program_llvm(core(), target=other_target)
                    wrong = receipt(other_ir, data, path, kind="object", inventory=inventory)
                    with self.assertRaises(ValueError):
                        _reinspect_source_native_bytes(
                            data, other_ir, wrong, target=other_target, kind="object", stage=path)


if __name__ == "__main__":
    unittest.main()
