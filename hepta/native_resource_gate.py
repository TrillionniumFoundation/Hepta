"""P1/P5: mandatory source-bound resource side-check for native scalar LLVM.

This deliberately uses the EXISTING resource lowering and independent Resource
IR verifier, not a second ownership implementation. The admitted profile is
limited to copy-only scalar programs already accepted by the sole canonical
source semantic producer and scalar CFG/SSA. New resource effects / unsupported
constructs fail closed rather than silently bypassing resource analysis.

This independent *abstract* verifier is not a proof of source/IR refinement,
pointer provenance, code generation soundness or general Rust-level safety.
"""
from __future__ import annotations

import json

from .hsir import HSIRSnapshot, lower_checked_program as lower_scalar_hsir
from .resource_ir import SCHEMA as RESOURCE_SCHEMA, ResourceIRError, verify_resource_ir
from .resource_lowering import lower_resource_ir, verify_resource_source_origin
from .ssa import SSASnapshot


class NativeResourceGateRejected(ValueError):
    """A source/Resource-IR consistency obligation for strict LLVM failed."""


def _reject(reason: str) -> None:
    raise NativeResourceGateRejected("E_LLVM_RESOURCE_GATE: " + reason)


def verify_native_scalar_resource_gate(program, checked, *,
                                       project_sha256: str | None = None,
                                       scalar_hsir: HSIRSnapshot,
                                       ssa: SSASnapshot) -> dict:
    """Re-derive and verify the exact checked-source resource flow before codegen.

    A scalar SSA verification cannot be promoted to ownership safety merely
    because its hashes are valid. This additional gate makes native source
    builds depend on the reviewed Resource IR abstraction and its source
    binding, with an exact function-inventory check. It remains an unproved
    abstract model and permits NO owned resources, FFI or foreign obligations.
    """
    if not getattr(checked, "ok", False):
        _reject("unchecked source is not a native resource authority")
    if not isinstance(scalar_hsir, HSIRSnapshot) or not isinstance(ssa, SSASnapshot):
        _reject("typed source-bound HSIR and scalar SSA required")
    try:
        # Independently rebuild the actual scalar semantic projection; a
        # typed+rehashed object supplied by an Agent is not trusted.
        fresh = lower_scalar_hsir(program, checked)
        if (scalar_hsir.schema != fresh.schema or
                scalar_hsir.canonical_json != fresh.canonical_json or
                scalar_hsir.sha256 != fresh.sha256):
            _reject("scalar HSIR differs from the sole checked-source producer")
        scalar = scalar_hsir.as_dict()
        if scalar.get("source_sha256") is None:
            _reject("missing scalar semantic source content identity")

        # Existing source lowerer models normal/early-return ownership, Move,
        # Borrow/Loan conflicts and Drop/linear resource operations. This
        # emitted Resource IR has its *own* source-origin verifier. No codegen
        # reads an arbitrary caller-supplied resource JSON graph.
        graph = lower_resource_ir(program, checked, project_sha256=project_sha256)
        if graph.get("schema") != RESOURCE_SCHEMA:
            _reject("unexpected Resource IR language/version contract")
        origin = verify_resource_source_origin(
            program, checked, graph, project_sha256=project_sha256)
        copied = json.loads(json.dumps(
            graph, ensure_ascii=False, sort_keys=True, allow_nan=False))
        verified = verify_resource_ir(copied)

        if (verified.get("ok") is not True
                or verified.get("status") != "resource_cfg_verified"
                or origin.get("status") != "exact_source_rederived_not_resource_semantics_proof"
                or verified.get("ir_sha256") != origin.get("resource_ir_sha256")
                or graph.get("source_sha256") != scalar["source_sha256"]
                or graph.get("project_sha256") != project_sha256
                or origin.get("source_sha256") != scalar["source_sha256"]
                or origin.get("project_sha256") != project_sha256):
            _reject("independent Resource IR verification/source identity disagrees")

        # No inherited foreign assumption or unmodeled owner can enter the
        # native scalar backend simply because the scalar SSA path checked.
        if (graph.get("obligations") != {}
                or verified.get("external_obligations") != {}
                or verified.get("owned_types") != []):
            _reject("native scalar code cannot hide owned or foreign resources")
        if not isinstance(graph.get("functions"), list):
            _reject("resource function inventory missing")
        graph_names = [fn.get("name") for fn in graph["functions"]]
        scalar_names = [fn.get("name") for fn in scalar.get("functions", [])]
        ssa_dict = ssa.as_dict()
        ssa_names = [fn.get("name") for fn in ssa_dict.get("functions", [])]
        if (not graph_names or graph_names != scalar_names
                or scalar_names != ssa_names
                or len(set(graph_names)) != len(graph_names)
                or any(fn.get("external") is not False
                       for fn in graph["functions"])):
            _reject("source, Resource IR and SSA function inventories disagree")

        claims = origin.get("claims")
        ir_claims = verified.get("claims")
        required_false = (
            "source_to_ir_refinement_proved",
            "native_codegen_uses_resource_ir",
            "whole_language_soundness_proved",
        )
        if (not isinstance(claims, dict)
                or claims.get("checked_source_rederived") is not True
                or claims.get("resource_ir_data_verified") is not True
                or any(claims.get(k) is not False for k in required_false)
                or not isinstance(ir_claims, dict)
                or any(ir_claims.get(k) is not False for k in required_false)):
            _reject("resource verifier tried to elevate an unproved claim")

        return {
            "schema": "hepta.llvm-native-resource-origin.v1",
            "status": "source_bound_copy_scalar_resource_cfg_checked_not_refinement_proved",
            "resource_ir_sha256": verified["ir_sha256"],
            "canonical_hsir_sha256": origin["canonical_hsir_sha256"],
            "source_sha256": origin["source_sha256"],
            "project_sha256": project_sha256,
            "scalar_hsir_sha256": scalar_hsir.sha256,
            "ssa_sha256": ssa.sha256,
            "functions": graph_names,
            "abstract_resource_operations_checked": verified["operations_checked"],
            "claims": {
                "source_resource_ir_origin_rechecked": True,
                "independent_abstract_resource_flow_checked": True,
                "no_owned_or_foreign_resource_in_admitted_scalar_subset": True,
                "source_to_ir_refinement_proved": False,
                "native_codegen_uses_resource_ir": False,
                "whole_language_soundness_proved": False,
                "pointer_provenance_proved": False,
                "native_backend_refinement_proved": False,
            },
        }
    except NativeResourceGateRejected:
        raise
    except (ResourceIRError, ValueError, TypeError, KeyError, RecursionError,
            OverflowError, UnicodeError) as exc:
        raise NativeResourceGateRejected(
            "E_LLVM_RESOURCE_GATE: unqualified native resource lowering: " + str(exc)
        ) from exc
