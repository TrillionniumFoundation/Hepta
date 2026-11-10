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
                                    emit_program_llvm, native_host_profile)
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
    host = native_host_profile()
    return {
        "schema": "hepta.hia.program.native.v1",
        "ok": True, "status": "native_compiled_not_executed",
        "profile": ir.profile, "target": ir.target,
        "entry_layout": ir.layout,
        "kind": kind, "output": str(path),
        "build_host": host, "cross_target_compilation": ir.target != host["target"],
        "core_sha256": ir.core_sha256, "llvm_ir_sha256": ir.sha256,
        "input_sha256": ir.input_sha256,
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








if __name__ == "__main__":
    unittest.main()
