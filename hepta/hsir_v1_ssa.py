"""Fail-closed versioned HSIR integration through real CFG/SSA verifier.

PR14 producer profiles can enter only via an independently checked, closed
scalar translation. The existing PR36 frozen producer remains byte-identical.
A structural SSA result never authorizes machine code, FFI, or memory safety.
"""
from __future__ import annotations

from hashlib import sha256
import json

from .hsir_v1 import HSIRV1Rejected, verify_v1


class V1SSARejected(ValueError):
    pass


def lower_verified_v1_scalar_ssa(envelope: dict) -> dict:
    """Inspect verified provenance and run the independent scalar SSA verifier."""
    try:
        verify_v1(envelope)
    except HSIRV1Rejected as exc:
        raise V1SSARejected("E_V1_SSA_IDENTITY: " + str(exc)) from exc

    original = envelope["producer"]
    mapped = envelope
    receipt = None
    if original["wire_profile"] == "source_bound_v0":
        from .hsir_v1_scalar_bridge import ScalarBridgeRejected, source_bound_to_frozen
        try:
            receipt = source_bound_to_frozen(envelope)
        except ScalarBridgeRejected as exc:
            raise V1SSARejected("E_V1_SSA_UNSUPPORTED_PRODUCER: " + str(exc)) from exc
        mapped = receipt["mapped_hsir_v1"]
    elif original["wire_profile"] != "frozen_snapshot_v0":
        raise V1SSARejected("E_V1_SSA_UNSUPPORTED_PRODUCER")
    try:
        verify_v1(mapped)
    except HSIRV1Rejected as exc:
        raise V1SSARejected("E_V1_SSA_MAPPED_IDENTITY: " + str(exc)) from exc

    legacy = dict(mapped["opaque_producer_payload"])
    if legacy.get("external_assumptions") not in ([], {}):
        raise V1SSARejected("E_V1_SSA_FOREIGN_ASSUMPTIONS")
    digest = legacy.pop("sha256")
    source_json = json.dumps(legacy, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False, allow_nan=False)
    if sha256(source_json.encode("utf-8")).hexdigest() != digest:
        raise V1SSARejected("E_V1_SSA_SOURCE_HASH")

    from .hsir import HSIRSnapshot
    from .cfg import lower_hsir_cfg
    from .ssa import lower_cfg_scalar_ssa
    from .ssa_verify import verify_scalar_ssa

    h = HSIRSnapshot("hepta.hsir.v0", source_json, digest)
    cfg = lower_hsir_cfg(h)
    ssa = lower_cfg_scalar_ssa(cfg)
    verified = verify_scalar_ssa(ssa, cfg)
    cfg_data, ssa_data, check_data = cfg.as_dict(), ssa.as_dict(), verified.as_dict()
    producer = mapped["producer"]
    if (cfg_data.get("source_hsir_sha256") != producer["legacy_sha256"] or
        cfg_data.get("source_sha256") != original["source_sha256"] or
        ssa_data.get("source_cfg_sha256") != cfg.sha256 or
        check_data.get("cfg_sha256") != cfg.sha256 or
        check_data.get("ssa_sha256") != ssa.sha256):
        raise V1SSARejected("E_V1_SSA_LINK_IDENTITY")
    if receipt is not None and (receipt["source_hsir_v0_sha256"] != original["legacy_sha256"] or
                                receipt["mapped_hsir_v0_sha256"] != producer["legacy_sha256"]):
        raise V1SSARejected("E_V1_SSA_BRIDGE_LINK_IDENTITY")
    output = {
        "schema": "hepta.ssa.integration.v1",
        "status": "structural_scalar_ssa_only_not_codegen_qualified",
        "source_hsir_v1_sha256": envelope["sha256"],
        "source_hsir_v0_sha256": original["legacy_sha256"],
        "lowered_hsir_v0_sha256": producer["legacy_sha256"],
        "source_project_sha256": original.get("project_sha256"),
        "source_sha256": original["source_sha256"],
        "scalar_mapping": None if receipt is None else {
            "profile": receipt["projection_profile"],
            "source_v0_sha256": receipt["source_hsir_v0_sha256"],
            "mapped_v0_sha256": receipt["mapped_hsir_v0_sha256"],
            "semantic_equivalence_proven": False,
            "resource_provenance_proven": False,
        },
        "cfg": cfg_data, "ssa": ssa_data, "ssa_verification": check_data,
        "claims": {"structural_ssa_verified": True,
                   "source_to_ir_semantics_proved": False,
                   "memory_safety_proved": False,
                   "native_codegen_qualified_by_adapter": False,
                   "foreign_contracts_proved": False},
    }
    canonical = json.dumps(output, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False, allow_nan=False)
    output["sha256"] = sha256(canonical.encode("utf-8")).hexdigest()
    return output
