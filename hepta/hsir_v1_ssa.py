"""Checked HSIR-v1 exchange -> existing pr36 scalar CFG/SSA/verify consumer.

This adapter handles frozen_snapshot_v0 directly and maps a strict by-value,
no-FFI, no-owned-resource scalar subset of source_bound_v0. Every unsupported
construct fails closed. Neither path authorizes LLVM codegen by itself.
"""
from __future__ import annotations

from hashlib import sha256
import json

from .hsir_v1 import HSIRV1Rejected, verify_v1


class V1SSARejected(ValueError):
    pass


def lower_verified_v1_scalar_ssa(envelope: dict) -> dict:
    """Run existing typed CFG -> scalar SSA -> independent SSA verification.

    The input snapshot is checked twice: its v1 projection must reconstruct
    exactly from the original v0 payload, and all output graph identities
    must match the original legacy source and one another.
    """
    try:
        verify_v1(envelope)
    except HSIRV1Rejected as exc:
        raise V1SSARejected("E_V1_SSA_IDENTITY: " + str(exc)) from exc
    producer = envelope["producer"]
    from .hsir import HSIRSnapshot
    from .cfg import lower_hsir_cfg
    from .ssa import lower_cfg_scalar_ssa
    from .ssa_verify import verify_scalar_ssa

    legacy = dict(envelope["opaque_producer_payload"])
    if producer["wire_profile"] == "source_bound_v0":
        from .hsir_scalar_bridge import ScalarBridgeRejected, lower_source_bound_scalar
        try:
            # A deterministic derived typed tree, not a forged v0 producer.
            # Incompatible owned/borrowed/FFI/short-circuit semantics reject.
            source_json, digest = lower_source_bound_scalar(legacy)
        except ScalarBridgeRejected as exc:
            raise V1SSARejected("E_V1_SSA_UNSUPPORTED_PRODUCER: " + str(exc)) from exc
        mapping = "source_bound_scalar_structure_v1"
    elif producer["wire_profile"] == "frozen_snapshot_v0":
        # A hashed external assumption remains unproved; scalar SSA refuses it.
        if legacy.get("external_assumptions") not in ([], {}):
            raise V1SSARejected("E_V1_SSA_FOREIGN_ASSUMPTIONS: unverified external contract")
        digest = legacy.pop("sha256")
        source_json = json.dumps(legacy, sort_keys=True, separators=(",", ":"),
                                 ensure_ascii=False, allow_nan=False)
        if sha256(source_json.encode("utf-8")).hexdigest() != digest:
            raise V1SSARejected("E_V1_SSA_SOURCE_HASH")
        mapping = "original_frozen_snapshot_v0"
    else:
        raise V1SSARejected("E_V1_SSA_UNSUPPORTED_PRODUCER: unknown wire profile")
    snapshot = HSIRSnapshot("hepta.hsir.v0", source_json, digest)
    cfg = lower_hsir_cfg(snapshot)
    ssa = lower_cfg_scalar_ssa(cfg)
    check = verify_scalar_ssa(ssa, cfg)
    cfg_data, ssa_data, checked_data = cfg.as_dict(), ssa.as_dict(), check.as_dict()
    if (cfg_data.get("source_hsir_sha256") != digest or
        cfg_data.get("source_sha256") != producer["source_sha256"] or
        ssa_data.get("source_cfg_sha256") != cfg.sha256 or
        checked_data.get("cfg_sha256") != cfg.sha256 or
        checked_data.get("ssa_sha256") != ssa.sha256):
        raise V1SSARejected("E_V1_SSA_LINK_IDENTITY")
    output = {"schema": "hepta.ssa.integration.v1",
              "status": "structural_scalar_ssa_only_not_codegen_qualified",
              "source_hsir_v1_sha256": envelope["sha256"],
              "source_hsir_v0_sha256": producer["legacy_sha256"],
              "derived_hsir_sha256": digest,
              "scalar_mapping_profile": mapping,
              "source_project_sha256": producer.get("project_sha256"),
              "source_sha256": producer["source_sha256"],
              "cfg": cfg_data, "ssa": ssa_data, "ssa_verification": checked_data,
              "claims": {"structural_ssa_verified": True,
                         "source_to_ir_semantics_proved": False,
                         "memory_safety_proved": False,
                         "native_codegen_qualified_by_adapter": False,
                         "foreign_contracts_proved": False}}
    canonical = json.dumps(output, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False, allow_nan=False)
    output["sha256"] = sha256(canonical.encode("utf-8")).hexdigest()
    return output
