"""Mandatory checked-source Resource IR gate for the scalar LLVM native path.

This reuses the sole canonical semantic encoder, existing Resource IR lowerer,
and independent graph verifier. It is an abstract owner/loan CFG acceptance
check, not a translation-refinement, provenance, or universal safety theorem.
"""
from __future__ import annotations

from hashlib import sha256
import json
import re

from .resource_ir import verify_resource_ir
from .resource_lowering import lower_resource_ir
from .semantic_ir import lower_checked_program as canonical_checked_source


_HASH = re.compile(r"[0-9a-f]{64}\Z")
_RESOURCE_CLAIMS = {
    "source_to_ir_refinement_proved": False,
    "native_codegen_uses_this_ir": False,
    "whole_language_soundness_proved": False,
    "external_contracts_proved": False,
    "termination_proved": False,
    "scalar_value_semantics_verified": False,
}
_SEMANTIC_CLAIMS = {
    "native_borrow_validation": False,
    "translation_correctness_proved": False,
    "whole_language_soundness_proved": False,
    "foreign_contracts_proved": False,
}


class NativeResourceGateRejected(ValueError):
    """The native pipeline cannot certify this source-bound resource graph."""


def _reject(message: str):
    raise NativeResourceGateRejected("E_NATIVE_RESOURCE_GATE: " + message)


def qualify_native_resource_source(program, checked, *,
                                   canonical_hsir_sha256: str,
                                   project_sha256: str | None = None) -> dict:
    """Re-derive canonical source and owner CFG; reject before native codegen.

    A hash or untrusted standalone Resource IR receipt does not authenticate
    its source. This entry must receive the same checked AST as the native
    Rust-reference-validated build and never accepts an external IR document.
    """
    if (getattr(checked, "ok", None) is not True
            or type(canonical_hsir_sha256) is not str
            or _HASH.fullmatch(canonical_hsir_sha256) is None
            or (project_sha256 is not None and
                (type(project_sha256) is not str or
                 _HASH.fullmatch(project_sha256) is None))):
        _reject("checked frontend and exact canonical source/project identities required")
    try:
        canonical = canonical_checked_source(program, checked)
        if (canonical.get("schema") != "hepta.hsir.v0"
                or canonical.get("profile") != "checked_typed_ast_not_verified_mir"
                or canonical.get("sha256") != canonical_hsir_sha256
                or canonical.get("all_expressions_typed") is not True
                or canonical.get("untyped_expressions") != []
                or canonical.get("claims") != _SEMANTIC_CLAIMS
                or any(type(flag) is not bool or flag is not False
                       for flag in canonical["claims"].values())):
            _reject("canonical checked source identity/profile disagrees")
        # The strict scalar LLVM source subset cannot discharge foreign,
        # pointer, unsafe, volatile or unreviewed external obligations.
        if any(type(canonical.get(key)) is not list or canonical[key]
               for key in ("external_obligations", "foreign_assumptions",
                           "volatile_accesses", "owned_types")):
            _reject("foreign or owned semantics lie outside scalar native profile")

        graph = lower_resource_ir(program, checked, project_sha256=project_sha256)
        if (type(graph) is not dict
                or graph.get("schema") not in {
                    "hepta.resource-ir.v1", "hepta.resource-ir.v2",
                    "hepta.resource-ir.v3", "hepta.resource-ir.v4"}
                or graph.get("source_sha256") != canonical["source_sha256"]
                or graph.get("project_sha256") != project_sha256
                or graph.get("claims") != _RESOURCE_CLAIMS
                or any(type(value) is not bool or value is not False
                       for value in graph["claims"].values())
                or graph.get("obligations") != {}):
            _reject("resource graph source, scope or unproved claims do not match")

        verified = verify_resource_ir(graph)
        graph_digest = sha256(json.dumps(graph, sort_keys=True, separators=(",", ":"),
                                         allow_nan=False).encode("utf-8")).hexdigest()
        expected_names = sorted(fn.name for fn in program.functions if not fn.extern_c)
        functions = verified.get("functions") if type(verified) is dict else None
        if (type(verified) is not dict or verified.get("ok") is not True
                or verified.get("status") != "resource_cfg_verified"
                or verified.get("ir_sha256") != graph_digest
                or verified.get("external_obligations") != {}
                or verified.get("claims") != _RESOURCE_CLAIMS
                or any(type(value) is not bool or value is not False
                       for value in verified["claims"].values())
                or type(functions) is not list
                or len(functions) != len(expected_names)
                or any(type(fn) is not dict or type(fn.get("function")) is not str
                       for fn in functions)
                or sorted(fn["function"] for fn in functions) != expected_names):
            _reject("independent resource CFG or function/proof inventory not qualified")

        return {
            "schema": "hepta.native.resource-gate.v1",
            "status": "source_bound_resource_cfg_checked_not_refinement_proof",
            "canonical_hsir_sha256": canonical_hsir_sha256,
            "resource_ir_sha256": graph_digest,
            "source_sha256": canonical["source_sha256"],
            "project_sha256": project_sha256,
            "functions_checked": len(expected_names),
            "claims": {
                "exact_checked_source_resource_graph_rederived": True,
                "independent_resource_cfg_verified": True,
                "foreign_resource_obligations_absent": True,
                "source_to_resource_ir_refinement_proved": False,
                "native_codegen_consumes_resource_ir": False,
                "whole_language_memory_safety_proved": False,
            },
        }
    except NativeResourceGateRejected:
        raise
    except (KeyError, ValueError, TypeError, AttributeError, OverflowError,
            RecursionError) as exc:
        raise NativeResourceGateRejected(
            "E_NATIVE_RESOURCE_GATE: unsupported source resource profile: " + str(exc)) from exc
