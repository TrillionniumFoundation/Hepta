"""Rust-qualified source -> sole canonical HSIR -> verified scalar SSA -> LLVM.

This is a strict native i32-only build path. No complete backend refinement,
foreign C ABI or whole-language safety claim is granted by successful output.
"""
from __future__ import annotations

from hashlib import sha256
import os
from pathlib import Path
import tempfile

from .cfg import lower_hsir_cfg
from .hsir import lower_checked_program, verify_checked_source_projection
from .native_resource_gate import qualify_native_resource_source
from .llvm_ssa_backend import LLVMSSARejected, compile_scalar_ssa_llvm, emit_scalar_ssa_llvm
from .llvm_ssa_target import _TARGETS, compile_ssa_target_object
from .pipeline import analyze_project
from .ssa import lower_cfg_scalar_ssa
from .ssa_verify import verify_scalar_ssa


def build_llvm_ssa_source(source: str | Path, output: str | Path, *,
                          rustc: str | None = None,
                          clang: str = "clang",
                          target: str | None = None,
                          locked: bool = False) -> dict:
    """Publish a native object or host shared library only after every gate.

    The source graph is checked before and after compilation. The artifact
    is first built inside a private directory on the output filesystem and
    then hard-linked using no-replace publication. This coordinates neither
    noncooperating writers nor a malicious same-user filesystem adversary.
    """
    result = {
        "schema": "hepta.build-llvm-ssa.v1",
        "status": "rejected",
        "ok": False,
        "scope": "checked_i32_or_u32_scalar_ssa_with_pinned_rustc_reference_not_full_language",
        "source": str(source),
        "output": str(output),
        "target": target,
        "claims": {
            "native_rust_reference_required": True,
            "independent_scalar_ssa_structure_checked": False,
            "native_ssa_cfg_origin_rechecked": False,
            "semantic_source_projection_rechecked": False,
            "source_bound_resource_cfg_checked": False,
            "native_artifact_compiled": False,
            "target_program_executed": False,
            "foreign_c_abi_qualified": False,
            "backend_refinement_proved": False,
            "whole_language_soundness_proved": False,
        },
    }
    try:
        if target is not None and target not in _TARGETS:
            raise LLVMSSARejected("E_LLVM_SSA_TARGET: requested target is outside the qualified object subset")
        dest = Path(os.path.abspath(output))
        if dest.exists() or dest.is_symlink() or not dest.parent.is_dir():
            raise LLVMSSARejected("E_LLVM_SSA_OUTPUT: existing/symlink output or missing parent directory")
        analyzed = analyze_project(
            Path(source), backend="rust", rustc=rustc,
            native=True, crate_type="rlib", locked=locked)
        result["reference_validation"] = analyzed.report
        if (analyzed.report.get("ok") is not True
                or analyzed.report.get("checks", {}).get("rust_borrows_types") != "rustc_checked"
                or analyzed.program is None or analyzed.checked is None or analyzed.project is None):
            raise LLVMSSARejected("E_LLVM_SSA_REFERENCE: pinned native rustc qualification required")
        project = analyzed.project
        # Reject aliasing even through a symlinked parent directory. Never
        # follow the output leaf when determining overwrite behavior.
        protected = {Path(path).resolve() for path in project.sources}
        if dest.resolve(strict=False) in protected:
            raise LLVMSSARejected("E_LLVM_SSA_OUTPUT: refusing to write into a source input")
        if not project.unchanged():
            raise LLVMSSARejected("E_LLVM_SSA_STALE: source graph changed before semantic projection")
        scalar_hsir = lower_checked_program(analyzed.program, analyzed.checked)
        semantic_origin = verify_checked_source_projection(analyzed.program, analyzed.checked, scalar_hsir)
        result["claims"]["semantic_source_projection_rechecked"] = True
        # P1 is a *mandatory* pre-codegen condition, not a sidecar. An
        # unsupported resource profile/loan CFG fails closed without Clang.
        resource_receipt = qualify_native_resource_source(
            analyzed.program, analyzed.checked,
            canonical_hsir_sha256=semantic_origin["canonical_sha256"],
            project_sha256=getattr(project, "identity", None))
        if (resource_receipt.get("status") !=
                "source_bound_resource_cfg_checked_not_refinement_proof"
                or resource_receipt.get("claims", {}).get(
                    "exact_checked_source_resource_graph_rederived") is not True
                or resource_receipt.get("claims", {}).get(
                    "independent_resource_cfg_verified") is not True
                or resource_receipt.get("claims", {}).get(
                    "foreign_resource_obligations_absent") is not True
                or resource_receipt.get("claims", {}).get(
                    "whole_language_memory_safety_proved") is not False):
            raise LLVMSSARejected("E_NATIVE_RESOURCE_GATE: missing qualified source resource gate receipt")
        result["claims"]["source_bound_resource_cfg_checked"] = True
        cfg = lower_hsir_cfg(scalar_hsir)
        ssa = lower_cfg_scalar_ssa(cfg)
        verification = verify_scalar_ssa(ssa, cfg)
        ir = emit_scalar_ssa_llvm(ssa, cfg)
        if verification.sha256 != ir.verification_sha256:
            raise LLVMSSARejected("E_LLVM_SSA_VERIFY: emitted LLVM provenance does not match verifier")
        result["claims"]["independent_scalar_ssa_structure_checked"] = True
        result["identities"] = {
            "source_sha256": analyzed.report.get("source_sha256"),
            "compiler_sha256": analyzed.report.get("compiler_sha256"),
            "canonical_source_semantic_sha256": semantic_origin["canonical_sha256"],
            "semantic_origin_receipt_schema": semantic_origin["schema"],
            "resource_ir_sha256": resource_receipt["resource_ir_sha256"],
            "resource_origin_receipt_schema": resource_receipt["resource_source_receipt_schema"],
            "native_resource_gate_schema": resource_receipt["schema"],
            "derived_scalar_hsir_sha256": scalar_hsir.sha256,
            "cfg_sha256": cfg.sha256,
            "canonical_ssa_sha256": ssa.sha256,
            "structural_verification_sha256": verification.sha256,
            "llvm_ir_sha256": ir.sha256,
            "llvm_source_profile": ir.profile,
        }
        if not project.unchanged():
            raise LLVMSSARejected("E_LLVM_SSA_STALE: graph changed before native backend")
        with tempfile.TemporaryDirectory(prefix=".hepta-llvm-source-", dir=dest.parent) as directory:
            stage = Path(directory) / ("candidate.o" if target is not None else "candidate.so")
            native = (compile_ssa_target_object(ir, target=target, clang=clang, output=stage,
                                               ssa=ssa, cfg=cfg)
                      if target is not None else compile_scalar_ssa_llvm(
                          ir, clang=clang, output=stage, ssa=ssa, cfg=cfg))
            # Backend receipts cannot elevate an object-only or host-compile
            # result to a soundness proof. Bind status, source IR and verifier
            # identity to the exact artifact being staged.
            expected_status = ("cross_object_only_not_executed" if target is not None
                               else "native_host_compiled_unqualified")
            proof_key = ("structural_ssa_verification_sha256" if target is not None
                         else "ssa_verification_sha256")
            forbidden_claim = ("native_backend_semantics_proved" if target is not None
                               else "backend_refinement_proven")
            if (not isinstance(native, dict) or native.get("status") != expected_status
                    or native.get("llvm_ir_sha256") != ir.sha256
                    or native.get("llvm_source_profile") != ir.profile
                    or native.get("ssa_sha256") != ssa.sha256
                    or native.get(proof_key) != verification.sha256
                    or native.get("ssa_cfg_origin_rechecked") is not True
                    or not isinstance(native.get("claims"), dict)
                    or native["claims"].get(forbidden_claim) is not False
                    or (target is not None and (
                        native.get("target") != target
                        or native.get("object_symbols_qualified") is not True
                        or native.get("defined_export_symbols") != list(ir.functions)
                        or not isinstance(native.get("undefined_external_symbols"), list)
                        or any(item != "abort" for item in native["undefined_external_symbols"])))):
                raise LLVMSSARejected("E_LLVM_SSA_RECEIPT: native backend identity or proof scope mismatch")
            # Validate real staged bytes *before* external publication. An
            # incorrect compiler receipt must never leave a published output
            # even if the command subsequently reports rejection.
            artifact = stage.read_bytes() if stage.is_file() else b""
            if (not artifact or sha256(artifact).hexdigest() != native.get("artifact_sha256")
                    or len(artifact) != native.get("artifact_bytes")):
                raise LLVMSSARejected("E_LLVM_SSA_ARTIFACT: staged native bytes differ from compiler receipt")
            if not project.unchanged():
                raise LLVMSSARejected("E_LLVM_SSA_STALE: graph changed during native compilation")
            if dest.is_symlink() or dest.exists():
                raise LLVMSSARejected("E_LLVM_SSA_OUTPUT: concurrent destination publication")
            os.link(stage, dest)  # same filesystem, no overwrite
        result["native_backend"] = dict(native)
        result["native_backend"]["output"] = str(dest)
        result["native_backend"]["artifact_sha256"] = sha256(artifact).hexdigest()
        result["claims"]["native_ssa_cfg_origin_rechecked"] = True
        result["claims"]["native_artifact_compiled"] = True
        result["ok"] = True
        result["status"] = ("cross_object_only_not_executed" if target is not None
                            else "native_host_compiled_unqualified")
        return result
    except (ValueError, OSError, UnicodeError) as error:
        result["status"] = "rejected"
        result["diagnostics"] = [{
            "code": str(error).split(":", 1)[0] if str(error).startswith("E_") else "E_LLVM_SSA_PIPELINE",
            "message": str(error),
        }]
        return result
