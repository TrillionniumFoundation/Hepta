"""Mandatory source-bound Resource IR gate for the strict scalar LLVM build.

This is a bounded P1 resource/loan *structural* check, not a general MIR
borrow checker, pointer-provenance proof or semantic-refinement theorem.
The canonical Hepta semantic source remains hepta.semantic_ir. No second
parser, type checker or native code generator is introduced here.
"""
from __future__ import annotations

from hashlib import sha256
import json
import re

from .resource_ir import SCHEMA as RESOURCE_SCHEMA, verify_resource_ir
from .resource_lowering import lower_resource_ir, verify_resource_source_origin


class NativeResourceGateRejected(ValueError):
    """Strict native build cannot bind a verified resource graph to its source."""


_HEX = re.compile(r"[0-9a-f]{64}\Z")
_ALLOWED_RESOURCE_CLAIMS = {
    "source_to_ir_refinement_proved": False,
    "native_codegen_uses_this_ir": False,
    "whole_language_soundness_proved": False,
    "external_contracts_proved": False,
    "termination_proved": False,
    "scalar_value_semantics_verified": False,
}
_REQUIRED_SOURCE_CLAIMS = {
    "checked_source_rederived": True,
    "resource_ir_data_verified": True,
    "source_to_ir_refinement_proved": False,
    "native_codegen_uses_resource_ir": False,
    "whole_language_soundness_proved": False,
}


def _reject(message: str) -> None:
    raise NativeResourceGateRejected("E_NATIVE_RESOURCE_GATE: " + message)


def qualify_native_resource_source(program, checked, *, canonical_hsir_sha256: str,
                                   project_sha256: str | None = None) -> dict:
    """Recheck sole-source resource lowering before executable native codegen.

    Returns a bounded, **source-bound** receipt. The scalar LLVM build must
    invoke this routine after its actual Rust-checked AST and canonical HSIR
    qualification, *before* invoking the SSA→LLVM native compiler.

    A resource JSON blob with a plausible digest, or a standalone successful
    resource verifier result, is insufficient. Unknown resource operations,
    unsupported source profiles, foreign obligations and any proof-claim
    elevation fail closed. The abstract graph is not used for code generation.
    """
    if (getattr(checked, "ok", None) is not True or
            not isinstance(canonical_hsir_sha256, str) or
            _HEX.fullmatch(canonical_hsir_sha256) is None):
        _reject("checked frontend and exact canonical semantic hash required")
    if project_sha256 is not None and (
            not isinstance(project_sha256, str) or _HEX.fullmatch(project_sha256) is None):
        _reject("project graph identity must be a SHA-256 digest")
    # This also independently verifies graph structural resource invariants,
    # but has no authority to state that the source→graph translation is sound.
    try:
        graph = lower_resource_ir(program, checked, project_sha256=project_sha256)
        source = verify_resource_source_origin(
            program, checked, graph, project_sha256=project_sha256)
        structural = verify_resource_ir(graph)
    except (ValueError, KeyError, TypeError, OverflowError, RecursionError) as exc:
        raise NativeResourceGateRejected(
            "E_NATIVE_RESOURCE_GATE: unsupported or rejected source resource profile: "
            + str(exc)) from exc

    if not isinstance(graph, dict) or graph.get("schema") != RESOURCE_SCHEMA:
        _reject("resource snapshot version has no reviewed native-gate mapping")
    claims = graph.get("claims")
    if (not isinstance(claims, dict) or set(claims) != set(_ALLOWED_RESOURCE_CLAIMS)
            or any(claims[name] is not value for name, value in _ALLOWED_RESOURCE_CLAIMS.items())):
        _reject("resource graph claims changed or escalated")
    if graph.get("obligations") != {}:
        _reject("foreign pointer/effect/lifetime obligations cannot be certified as native safe")
    if (not isinstance(structural, dict) or structural.get("ok") is not True
            or structural.get("status") != "resource_cfg_verified"
            or structural.get("external_obligations") != {}
            or not isinstance(structural.get("claims"), dict)
            or set(structural["claims"]) != set(_ALLOWED_RESOURCE_CLAIMS)
            or any(structural["claims"][key] is not value
                   for key, value in _ALLOWED_RESOURCE_CLAIMS.items())):
        _reject("independent Resource IR validation or proof scope is unqualified")
    expected_functions = sorted(
        fn.name for fn in program.functions if not fn.extern_c)
    verified_functions = structural.get("functions")
    if (not isinstance(verified_functions, list)
            or len(verified_functions) != len(expected_functions)
            or any(not isinstance(item, dict)
                   or not isinstance(item.get("function"), str)
                   for item in verified_functions)
            or sorted(item["function"] for item in verified_functions) != expected_functions):
        _reject("resource function inventory differs from checked source")
    if (not isinstance(source, dict)
            or source.get("schema") != "hepta.resource.source-origin.v1"
            or source.get("status") != "exact_source_rederived_not_resource_semantics_proof"
            or source.get("canonical_hsir_sha256") != canonical_hsir_sha256
            or source.get("canonical_hsir_schema") != "hepta.hsir.v0"
            or source.get("resource_ir_schema") != RESOURCE_SCHEMA
            or source.get("resource_ir_sha256") != structural.get("ir_sha256")
            or source.get("source_sha256") != graph.get("source_sha256")
            or source.get("project_sha256") != project_sha256
            or not isinstance(source.get("claims"), dict)
            or set(source["claims"]) != set(_REQUIRED_SOURCE_CLAIMS)
            or any(source["claims"][key] is not value
                   for key, value in _REQUIRED_SOURCE_CLAIMS.items())):
        _reject("resource provenance is not bound to exact checked canonical HSIR")

    return {
        "schema": "hepta.native.resource-gate.v1",
        "status": "source_bound_resource_cfg_checked_not_refinement_proof",
        "canonical_hsir_sha256": canonical_hsir_sha256,
        "resource_ir_sha256": structural["ir_sha256"],
        "resource_source_receipt_schema": source["schema"],
        "source_sha256": graph["source_sha256"],
        "project_sha256": project_sha256,
        "functions_checked": len(expected_functions),
        "claims": {
            "exact_checked_source_resource_graph_rederived": True,
            "independent_resource_cfg_verified": True,
            "foreign_resource_obligations_absent": True,
            "source_to_resource_ir_refinement_proved": False,
            "native_codegen_consumes_resource_ir": False,
            "whole_language_memory_safety_proved": False,
        },
    }
