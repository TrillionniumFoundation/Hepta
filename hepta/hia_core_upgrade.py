"""Explicit, reverified adapters for the historical HIA wire formats.

The old primitive bulk-v2 and nominal-v2 producers shared a wire spelling.
Neither a version label nor a receipt authenticates a producer. The caller
must select one adapter; its entire source grammar, operations and resource
flow are checked before conversion, then the canonical v6 result is checked.
No adapter accepts HSIR, raw Resource IR, or unverified external evidence.
"""
from __future__ import annotations

from hashlib import sha256

from .hia_program import (
    HIAProgramRejected, SCHEMA, SCHEMA_V2, SCHEMA_V3, SCHEMA_V4,
    SCHEMA_V5, SCHEMA_V6, VerifiedProgram, _decode, _keys, verify_program,
)
from .hia_schema import (
    COMPOSITE_SCHEMA, LEGACY_COMPOSITE_PROFILE, LEGACY_COMPOSITE_SCHEMA,
    PROFILE_V2, profile_for_schema,
)


_SAFE_UPGRADE_SOURCES = frozenset({SCHEMA, SCHEMA_V3, SCHEMA_V4, SCHEMA_V5, SCHEMA_V6})


def upgrade_core_to_v6(document: object, *, legacy_profile: str | None = None
                       ) -> tuple[VerifiedProgram, dict]:
    """Map only identical, reverified operational SSA to canonical v6.

    The program is standalone and source-free: no SHA, author string, or
    self-asserted validation field is evidence of producer identity or safety.
    A primitive legacy-v2 caller must select PROFILE_V2 explicitly. A nominal
    legacy-v2 document instead requires import_legacy_composite_v2. Selecting
    the profile never skips verification or enables a newer instruction.
    """
    source = verify_program(document)
    old = source.as_dict()
    schema = old["schema"]
    if legacy_profile is not None and (schema != SCHEMA_V2 or legacy_profile != PROFILE_V2):
        raise HIAProgramRejected("legacy profile does not match this adapter/source",
                                 "E_HIA_VERSION_COLLISION")
    if schema == SCHEMA_V2 and legacy_profile != PROFILE_V2:
        raise HIAProgramRejected(
            "v2 has incompatible historical producer semantics; explicit adapter required",
            "E_HIA_VERSION_COLLISION",
        )
    if schema not in _SAFE_UPGRADE_SOURCES and schema != SCHEMA_V2:
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
        "source_input_schema": source.normalization_report["input_schema"],
        "source_input_sha256": source.input_sha256,
        "source_profile": profile_for_schema(schema),
        "target_profile": profile_for_schema(SCHEMA_V6),
        "selected_legacy_profile": legacy_profile,
        "source_program_sha256": source.sha256,
        "target_program_sha256": upgraded.sha256,
        "source_functions": len(old["functions"]),
        "claims": {
            "source_hia_program_reverified": True,
            "target_hia_program_reverified": True,
            "operational_payload_unchanged_excluding_schema": True,
            "legacy_v2_wire_ambiguity_resolved": schema == SCHEMA_V2 and legacy_profile == PROFILE_V2,
            "producer_source_authenticated": False,
            "source_to_core_refinement_proved": False,
            "llvm_backend_refinement_proved": False,
            "whole_language_soundness_proved": False,
        },
    }
    return upgraded, report


def import_legacy_composite_v2(document: object) -> tuple[VerifiedProgram, dict]:
    """Explicitly import the historical finite nominal profile into composite v1.

    Old nominal programs had only primitive-v1 memory operations after
    expansion. Rechecking that old output first is essential: merely changing
    the wire name would silently let a legacy document gain v6 operations.
    The returned object retains the new unambiguous structured input and is
    re-elaborated/rechecked by all existing consumers. The legacy source hash
    in the report records provenance; it grants no execution authority.
    """
    from .hia_program_composite import elaborate_program

    source, source_bytes = _decode(document)
    _keys(source, {"schema", "module", "types", "functions"}, "legacy nominal program")
    if source["schema"] != LEGACY_COMPOSITE_SCHEMA:
        raise HIAProgramRejected("explicit nominal-v2 adapter requires nominal-v2 input",
                                 "E_HIA_VERSION_COLLISION")
    renamed = dict(source)
    renamed["schema"] = COMPOSITE_SCHEMA
    old_payload = elaborate_program(renamed, legacy=True)
    old_payload["schema"] = SCHEMA
    old_core = verify_program(old_payload)
    imported = verify_program(renamed)
    expected = old_core.as_dict()
    expected["schema"] = SCHEMA_V6
    if imported.as_dict() != expected:
        raise HIAProgramRejected("nominal adapter changed primitive operations/CFG/effects",
                                 "E_HIA_UPGRADE")
    return imported, {
        "schema": "hepta.hia.legacy-composite-import.v1", "ok": True,
        "source_schema": LEGACY_COMPOSITE_SCHEMA,
        "source_profile": LEGACY_COMPOSITE_PROFILE,
        "source_input_sha256": sha256(source_bytes).hexdigest(),
        "source_primitive_schema": SCHEMA,
        "source_primitive_sha256": old_core.sha256,
        "target_schema": COMPOSITE_SCHEMA,
        "target_input_sha256": imported.input_sha256,
        "target_core_schema": SCHEMA_V6,
        "target_core_sha256": imported.sha256,
        "claims": {
            "explicit_nominal_profile_selected": True,
            "legacy_v1_instruction_set_reverified": True,
            "nominal_resource_flow_reverified": True,
            "target_v6_core_reverified": True,
            "primitive_payload_unchanged_excluding_schema": True,
            "producer_source_authenticated": False,
            "whole_language_soundness_proved": False,
            "backend_refinement_proved": False,
        },
    }
