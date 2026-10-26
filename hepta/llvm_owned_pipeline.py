"""Source-facing, no-fallback compiler for the owned-byte LLVM host profile."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import tempfile

from .llvm_owned_backend import PROFILE, LLVMOwnedRejected, compile_owned_llvm, emit_owned_llvm
from .pipeline import analyze_project, compiler_hash
from .resource_ir import verify_resource_ir
from .resource_lowering import lower_resource_ir
from .elf_shared_abi import inspect_owned_shared_elf


def build_llvm_owned_source(source, output, *, rustc=None, clang="clang", kind="shared", locked=False):
    """Fresh source/reference/resource gates and no-replace native publication.

    A successful build is a compilation receipt, not an execution report or
    safety/refinement proof. Resource structs never cross the public C ABI.
    """
    report = {"schema": "hepta.build-llvm-owned.v1", "profile": PROFILE,
              "ok": False, "status": "rejected", "source": str(source), "output": str(output),
              "kind": kind, "claims": {"actual_source_replayed": False,
                  "independent_resource_cfg_verified": False, "native_rust_reference_required": True,
                  "native_artifact_compiled": False, "rust_codegen_used": False,
                  "c_codegen_used": False, "fallback_used": False, "native_execution_qualified": False,
                  "owned_foreign_abi_qualified": False, "backend_refinement_proved": False,
                  "whole_language_memory_safety_proved": False, "cross_target_execution_qualified": False}}
    try:
        if kind not in {"object", "shared"} or type(locked) is not bool:
            raise LLVMOwnedRejected("E_LLVM_OWNED_PROFILE: invalid native artifact or lock profile")
        destination = Path(os.path.abspath(output))
        if destination.exists() or destination.is_symlink() or not destination.parent.is_dir():
            raise LLVMOwnedRejected("E_LLVM_OWNED_OUTPUT: output must be a new file in an existing directory")
        analysis = analyze_project(source, backend="rust", native=True, rustc=rustc, locked=locked, crate_type="rlib")
        report["reference_validation"] = analysis.report
        if (analysis.report.get("ok") is not True or analysis.report.get("checks", {}).get("rust_borrows_types") != "rustc_checked"
                or analysis.report.get("assumptions") or analysis.program is None
                or analysis.checked is None or analysis.project is None):
            raise LLVMOwnedRejected("E_LLVM_OWNED_REFERENCE: fresh pinned Rust reference qualification required")
        project = analysis.project
        if destination.resolve(strict=False) in {Path(path).resolve() for path in project.sources}:
            raise LLVMOwnedRejected("E_LLVM_OWNED_OUTPUT: cannot replace source inputs")
        if not project.unchanged():
            raise LLVMOwnedRejected("E_LLVM_OWNED_STALE: source changed before lowering")
        graph = lower_resource_ir(analysis.program, analysis.checked, project_sha256=project.identity)
        verification = verify_resource_ir(graph)
        ir = emit_owned_llvm(analysis.program, analysis.checked, project_sha256=project.identity)
        report["resource_verification"] = verification
        report["source_binding"] = {"project_sha256": project.identity, "sources": dict(project.sources),
            "compiler_sha256": ir.compiler_sha256, "semantic_sha256": ir.semantic_sha256,
            "resource_ir_sha256": ir.resource_ir_sha256,
            "resource_verification_sha256": ir.resource_verification_sha256,
            "llvm_ir_sha256": ir.sha256, "exports": list(ir.functions), "specializations": list(ir.specializations)}
        if verification.get("ok") is not True or verification.get("ir_sha256") != ir.resource_ir_sha256:
            raise LLVMOwnedRejected("E_LLVM_OWNED_RESOURCE: exact resource verification identity required")
        with tempfile.TemporaryDirectory(prefix=".hepta-owned-source-", dir=destination.parent) as directory:
            stage = Path(directory) / ("native.o" if kind == "object" else "native.so")
            native = compile_owned_llvm(ir, program=analysis.program, checked=analysis.checked,
                project_sha256=project.identity, output=stage, clang=clang, kind=kind)
            data = stage.read_bytes() if stage.is_file() else b""
            if (native.get("ok") is not True or native.get("status") != "native_compiled_not_executed"
                    or native.get("profile") != PROFILE or native.get("kind") != kind
                    or native.get("llvm_ir_sha256") != ir.sha256
                    or native.get("semantic_sha256") != ir.semantic_sha256
                    or native.get("resource_ir_sha256") != ir.resource_ir_sha256
                    or native.get("resource_verification_sha256") != ir.resource_verification_sha256
                    or native.get("compiler_sha256") != ir.compiler_sha256
                    or native.get("claims", {}).get("checked_ast_resource_origin_replayed") is not True
                    or any(native.get("claims", {}).get(key) is not False for key in
                           ("rust_codegen_used", "c_codegen_used", "fallback_used", "backend_refinement_proved"))
                    or not data or native.get("artifact_sha256") != hashlib.sha256(data).hexdigest()
                    or type(native.get("artifact_bytes")) is not int or native["artifact_bytes"] != len(data)):
                raise LLVMOwnedRejected("E_LLVM_OWNED_ARTIFACT: exact staged native receipt required")
            # Independently parse the exact stage bytes, rather than trusting
            # a backend receipt that could be re-created with a new digest.
            if kind == "shared":
                dynamic_abi = inspect_owned_shared_elf(data, ir.functions)
                if (not isinstance(native.get("dynamic_abi"), dict)
                        or json.dumps(native["dynamic_abi"], sort_keys=True, allow_nan=False)
                        != json.dumps(dynamic_abi, sort_keys=True, allow_nan=False)):
                    raise LLVMOwnedRejected(
                        "E_LLVM_OWNED_ARTIFACT: native dynamic ABI receipt differs from staged ELF")
            elif native.get("dynamic_abi") is not None:
                raise LLVMOwnedRejected(
                    "E_LLVM_OWNED_ARTIFACT: relocatable object cannot claim a shared dynamic ABI")
            if not project.unchanged() or compiler_hash() != ir.compiler_sha256:
                raise LLVMOwnedRejected("E_LLVM_OWNED_STALE: source/compiler changed during native build")
            os.link(stage, destination)
        report["native_backend"] = dict(native, output=str(destination))
        report["claims"].update(actual_source_replayed=True, independent_resource_cfg_verified=True,
                                native_artifact_compiled=True)
        report.update(ok=True, status="native_compiled_not_executed")
    except (ValueError, OSError) as error:
        report["diagnostics"] = [{"code": str(error).split(":", 1)[0]
                                 if str(error).startswith("E_") else "E_LLVM_OWNED_PIPELINE",
                                 "message": str(error)}]
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--rustc", default=os.environ.get("RUSTC"))
    parser.add_argument("--clang", default="clang")
    parser.add_argument("--kind", choices=("shared", "object"), default="shared")
    parser.add_argument("--locked", action="store_true")
    arguments = parser.parse_args(argv)
    report = build_llvm_owned_source(arguments.source, arguments.output, rustc=arguments.rustc,
                                    clang=arguments.clang, kind=arguments.kind, locked=arguments.locked)
    print(json.dumps(report, sort_keys=True, allow_nan=False))
    return 0 if report["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
