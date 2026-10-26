"""Fail-closed, versioned upgrade of the *existing* executable HIA byte Core.

This does not accept HSIR, raw Resource IR, or the unrelated composite-HIA
producer. The old hepta.hia.program.v2 spelling collides with an incompatible
producer and is therefore NEVER upgraded without an independently reviewed,
future versioned adapter. Other admitted versions have identical instruction
and CFG payloads after changing only the version; both sides are reverified.
"""
from __future__ import annotations

from .hia_program import (
    HIAProgramRejected, SCHEMA, SCHEMA_V2, SCHEMA_V3, SCHEMA_V4,
    SCHEMA_V5, SCHEMA_V6, VerifiedProgram, verify_program,
)


_SAFE_UPGRADE_SOURCES = frozenset({SCHEMA, SCHEMA_V3, SCHEMA_V4, SCHEMA_V5, SCHEMA_V6})


def upgrade_core_to_v6(document: object) -> tuple[VerifiedProgram, dict]:
    """Map only identical, reverified operational SSA to canonical v6.

    The program is standalone and source-free: no SHA, author string, or
    self-asserted validation field is evidence of producer identity or safety.
    In particular a legacy v2 program is *always* ambiguous even if one
    currently installed verifier happens to accept its byte layout.
    """
    source = verify_program(document)
    old = source.as_dict()
    schema = old["schema"]
    if schema == SCHEMA_V2:
        raise HIAProgramRejected(
            "v2 has incompatible historical producer semantics; explicit adapter required",
            "E_HIA_VERSION_COLLISION",
        )
    if schema not in _SAFE_UPGRADE_SOURCES:
        raise HIAProgramRejected("not an admitted HIA Core family", "E_HIA_UPGRADE")
    if schema == SCHEMA_V6:
        upgraded = source
    else:
        equivalent = dict(old)
        equivalent["schema"] = SCHEMA_V6
        upgraded = verify_program(equivalent)
    after = upgraded.as_dict()
    expected = dict(old)
    expected["schema"] = SCHEMA_V6
    if after != expected:
        raise HIAProgramRejected("upgrade changed operations/CFG/effects", "E_HIA_UPGRADE")
    report = {
        "schema": "hepta.hia.core-upgrade.v1", "ok": True,
        "source_schema": schema, "target_schema": SCHEMA_V6,
        "source_program_sha256": source.sha256,
        "target_program_sha256": upgraded.sha256,
        "source_functions": len(old["functions"]),
        "claims": {
            "source_hia_program_reverified": True,
            "target_hia_program_reverified": True,
            "operational_payload_unchanged_excluding_schema": True,
            "legacy_v2_wire_ambiguity_resolved": False,
            "producer_source_authenticated": False,
            "source_to_core_refinement_proved": False,
            "llvm_backend_refinement_proved": False,
            "whole_language_soundness_proved": False,
        },
    }
    return upgraded, report
