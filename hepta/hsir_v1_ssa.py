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


def lower_verified_v1_scalar_ssa(envelope: dict, *, source_text: str | None = None,
                                  source_path: str | None = None,
                                  verified_project_sha256: str | None = None) -> dict:
    """Recheck exact source for PR14; preserve existing frozen-v0 path.

    PR14's source-bound typed display fields can never be blindly cast into
    PR36's structural type system. Require fresh PR37 parsing/checking and
    node-for-node typed scalar AST agreement before CFG lowering.
    """
    try:
        verify_v1(envelope)
    except HSIRV1Rejected as exc:
        raise V1SSARejected("E_V1_SSA_IDENTITY: " + str(exc)) from exc
    producer = envelope["producer"]
    from .cfg import lower_hsir_cfg
    from .ssa import lower_cfg_scalar_ssa
    from .ssa_verify import verify_scalar_ssa

    profile = producer["wire_profile"]
    if profile == "source_bound_v0":
        if source_text is None or source_path is None:
            raise V1SSARejected("E_V1_SSA_SOURCE_REQUIRED: external source-bound producer requires exact checked bytes/path")
        from .hsir_v1_source_bound import SourceBoundRejected, recheck_source_bound
        try:
            snapshot = recheck_source_bound(envelope, source_text, source_path,
                                            verified_project_sha256=verified_project_sha256)
        except SourceBoundRejected as exc:
            raise V1SSARejected("E_V1_SSA_SOURCE_RECHECK: " + str(exc)) from exc
    elif profile == "frozen_snapshot_v0":
        from .hsir import HSIRSnapshot
        legacy = dict(envelope["opaque_producer_payload"])
        if legacy.get("external_assumptions") not in ([], {}):
            raise V1SSARejected("E_V1_SSA_FOREIGN_ASSUMPTIONS: unverified external contract")
        digest = legacy.pop("sha256")
        source_json = json.dumps(legacy, sort_keys=True, separators=(",", ":"),
                                 ensure_ascii=False, allow_nan=False)
        if sha256(source_json.encode("utf-8")).hexdigest() != digest:
            raise V1SSARejected("E_V1_SSA_SOURCE_HASH")
        snapshot = HSIRSnapshot("hepta.hsir.v0", source_json, digest)
    else:
        raise V1SSARejected("E_V1_SSA_UNSUPPORTED_PRODUCER: unknown v1 producer profile")

    cfg = lower_hsir_cfg(snapshot)
    ssa = lower_cfg_scalar_ssa(cfg)
    check = verify_scalar_ssa(ssa, cfg)
    cfg_data, ssa_data, checked_data = cfg.as_dict(), ssa.as_dict(), check.as_dict()
    if (cfg_data.get("source_hsir_sha256") != snapshot.sha256 or
        cfg_data.get("source_sha256") != producer["source_sha256"] or
        ssa_data.get("source_cfg_sha256") != cfg.sha256 or
        checked_data.get("cfg_sha256") != cfg.sha256 or
        checked_data.get("ssa_sha256") != ssa.sha256):
        raise V1SSARejected("E_V1_SSA_LINK_IDENTITY")
    output = {"schema": "hepta.ssa.integration.v1",
              "status": "structural_scalar_ssa_only_not_codegen_qualified",
              "source_hsir_v1_sha256": envelope["sha256"],
              "source_hsir_v0_sha256": producer["legacy_sha256"],
              "consumer_hsir_v0_sha256": snapshot.sha256,
              "producer_wire_profile": profile,
              "independent_scalar_reparse_checked": profile == "source_bound_v0",
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
