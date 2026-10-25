"""Bind HSIR v1 to an independently checked ownership/loan resource graph.

This is a concrete *consistency* gate, not a source-to-IR correctness proof.
Unsupported task, IO, borrowed-storage and CFG profiles are rejected by the
existing resource lowerer rather than silently being treated as safe.
"""
from __future__ import annotations

import hashlib
import json

from .hsir_v1 import HSIRV1Rejected, verify_v1


class HSIRResourceRejected(ValueError):
    pass


def checked_resource_snapshot(analysis, envelope: dict) -> dict:
    """Cross-check one checked Program and its hash-bound HSIR and resource IR.

    The original checked program identity, exact project identity, function
    inventory, and independently rechecked resource graph are mandatory.
    """
    try:
        verify_v1(envelope)
    except (HSIRV1Rejected, ValueError, KeyError, TypeError) as exc:
        raise HSIRResourceRejected("E_HSIR_RESOURCE_ENVELOPE: " + str(exc)) from exc

    if envelope["producer"]["wire_profile"] != "source_bound_v0":
        raise HSIRResourceRejected("E_HSIR_RESOURCE_PRODUCER: project-identity-bearing source profile required")
    program = getattr(analysis, "program", None)
    checked = getattr(analysis, "checked", None)
    report = getattr(analysis, "report", None)
    if program is None or checked is None or not checked.ok or not isinstance(report, dict) or not report.get("ok"):
        raise HSIRResourceRejected("E_HSIR_RESOURCE_CHECK: original frontend validation required")
    source_sha = hashlib.sha256(program.source.encode("utf-8")).hexdigest()
    project = getattr(getattr(analysis, "project", None), "identity", None)
    producer = envelope["producer"]
    if producer["source_sha256"] != source_sha or producer["project_sha256"] != project:
        raise HSIRResourceRejected("E_HSIR_RESOURCE_IDENTITY: source or project changed")
    if report.get("source_sha256") not in (None, source_sha):
        # Multi-file analysis may use the entry-source hash, not the flattened
        # parsed project's hash: in that case check the actual loaded entry.
        loaded = getattr(analysis, "project", None)
        if loaded is None or not hasattr(loaded, "source_bytes"):
            raise HSIRResourceRejected("E_HSIR_RESOURCE_ENTRY_IDENTITY")
        entry = str(loaded.entry)
        if hashlib.sha256(loaded.source_bytes[entry]).hexdigest() != report["source_sha256"]:
            raise HSIRResourceRejected("E_HSIR_RESOURCE_ENTRY_IDENTITY")

    original_names = [f.name for f in program.functions]
    projected_names = [f["name"] for f in envelope["interface_projection"]["functions"]]
    if original_names != projected_names or len(set(original_names)) != len(original_names):
        raise HSIRResourceRejected("E_HSIR_RESOURCE_INVENTORY")

    from .resource_lowering import lower_resource_ir
    from .resource_ir import ResourceIRError, verify_resource_ir

    try:
        graph = lower_resource_ir(program, checked, project_sha256=project)
        checked_graph = verify_resource_ir(graph)
    except (ResourceIRError, ValueError, TypeError, KeyError) as exc:
        raise HSIRResourceRejected("E_HSIR_RESOURCE_LOWER: " + str(exc)) from exc

    if not checked_graph.get("ok") or graph.get("source_sha256") != source_sha or graph.get("project_sha256") != project:
        raise HSIRResourceRejected("E_HSIR_RESOURCE_GRAPH_IDENTITY")
    graph_names = [f["name"] for f in graph.get("functions", [])]
    if graph_names != original_names:
        raise HSIRResourceRejected("E_HSIR_RESOURCE_GRAPH_INVENTORY")
    # External obligations are never discharged. The independent verifier
    # labels each external contract assumed_not_verified.
    obligations = graph.get("obligations")
    if not isinstance(obligations, dict) or any(
        not isinstance(v, dict) or v.get("status") != "assumed_not_verified"
        for v in obligations.values()
    ):
        raise HSIRResourceRejected("E_HSIR_RESOURCE_OBLIGATIONS")
    if any(v is not False for v in graph.get("claims", {}).values()):
        raise HSIRResourceRejected("E_HSIR_RESOURCE_GRAPH_CLAIMS")
    output = {
        "schema": "hepta.hsir-resource.binding.v1",
        "status": "independent_resource_cfg_checked_not_compiler_refinement",
        "source_sha256": source_sha,
        "project_sha256": project,
        "hsir_sha256": envelope["sha256"],
        "legacy_hsir_sha256": producer["legacy_sha256"],
        "resource_ir_sha256": checked_graph["ir_sha256"],
        "resource_ir": graph,
        "resource_verification": checked_graph,
        "claims": {
            "resource_cfg_independently_checked": True,
            "source_to_resource_ir_refinement_proved": False,
            "native_codegen_uses_this_ir": False,
            "pointer_provenance_proved": False,
            "foreign_contracts_proved": False,
            "whole_language_soundness_proved": False,
        },
    }
    blob = json.dumps(output, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")
    output["sha256"] = hashlib.sha256(blob).hexdigest()
    return output
