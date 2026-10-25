"""Checked HSIR-v1 exchange -> existing pr36 scalar CFG/SSA/verify consumer.

This adapter is limited to the frozen_snapshot_v0 producer representation, and
rejects source_bound_v0 from PR #14 until a separate typed-expression mapping
has been independently qualified. It cannot authorize LLVM codegen by itself.
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
    if producer["wire_profile"] != "frozen_snapshot_v0":
        raise V1SSARejected("E_V1_SSA_UNSUPPORTED_PRODUCER: cannot reinterpret PR14 source-bound expressions")
    from .hsir import HSIRSnapshot
    from .cfg import lower_hsir_cfg
    from .ssa import lower_cfg_scalar_ssa
    from .ssa_verify import verify_scalar_ssa

    legacy = dict(envelope["opaque_producer_payload"])
    # A hashed external assumption remains unproved; scalar SSA must refuse it.
    if legacy.get("external_assumptions") not in ([], {}):
        raise V1SSARejected("E_V1_SSA_FOREIGN_ASSUMPTIONS: unverified external contract")
    digest = legacy.pop("sha256")
    source_json = json.dumps(legacy, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False, allow_nan=False)
    if sha256(source_json.encode("utf-8")).hexdigest() != digest:
        raise V1SSARejected("E_V1_SSA_SOURCE_HASH")
    snapshot = HSIRSnapshot("hepta.hsir.v0", source_json, digest)
    cfg = lower_hsir_cfg(snapshot)
    ssa = lower_cfg_scalar_ssa(cfg)
    check = verify_scalar_ssa(ssa, cfg)
    cfg_data, ssa_data, checked_data = cfg.as_dict(), ssa.as_dict(), check.as_dict()
    if (cfg_data.get("source_hsir_sha256") != producer["legacy_sha256"] or
        cfg_data.get("source_sha256") != producer["source_sha256"] or
        ssa_data.get("source_cfg_sha256") != cfg.sha256 or
        checked_data.get("cfg_sha256") != cfg.sha256 or
        checked_data.get("ssa_sha256") != ssa.sha256):
        raise V1SSARejected("E_V1_SSA_LINK_IDENTITY")
    output = {"schema": "hepta.ssa.integration.v1",
              "status": "structural_scalar_ssa_only_not_codegen_qualified",
              "source_hsir_v1_sha256": envelope["sha256"],
              "source_hsir_v0_sha256": producer["legacy_sha256"],
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
