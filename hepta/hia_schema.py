"""Unambiguous wire namespaces and checked HIA Core feature versions.

These descriptors select a verifier grammar; they are never verification
receipts. Every consumer still verifies the program's operations and resource
flow. The historical nominal-v2 producer used the primitive bulk-v2 spelling:
it is accepted only by an explicit, separately checked legacy adapter.
"""
from __future__ import annotations

from types import MappingProxyType


SCHEMA = "hepta.hia.program.v1"
SCHEMA_V2 = "hepta.hia.program.v2"
SCHEMA_V3 = "hepta.hia.program.v3"
SCHEMA_V4 = "hepta.hia.program.v4"
SCHEMA_V5 = "hepta.hia.program.v5"
SCHEMA_V6 = "hepta.hia.program.v6"
SCHEMA_V7 = "hepta.hia.program.v7"
PROFILE = "closed-ssa-integer-byte-resources-64-v1"
PROFILE_V2 = "closed-ssa-integer-byte-resources-bulk-64-v2"
PROFILE_V3 = "closed-ssa-integer-byte-resources-overlap-64-v3"
PROFILE_V4 = "closed-ssa-integer-byte-resources-swap-64-v4"
PROFILE_V5 = "closed-ssa-integer-byte-resources-offset-copy-64-v5"
PROFILE_V6 = "closed-ssa-integer-byte-resources-range-fill-64-v6"
PROFILE_V7 = "closed-ssa-integer-recursive-buffer-chain-64-v7"

COMPOSITE_SCHEMA = "hepta.hia.composite.v1"
COMPOSITE_PROFILE = "nominal-products-enums-cooperative-tasks-over-closed-ssa-v6"
COMPOSITE_SCHEMA_V2 = "hepta.hia.composite.v2"
COMPOSITE_PROFILE_V2 = "nominal-products-enums-cooperative-tasks-over-closed-ssa-v7"
COMPOSITE_PROFILES = MappingProxyType({
    COMPOSITE_SCHEMA: COMPOSITE_PROFILE,
    COMPOSITE_SCHEMA_V2: COMPOSITE_PROFILE_V2,
})
COMPOSITE_SCHEMAS = frozenset(COMPOSITE_PROFILES)
LEGACY_COMPOSITE_SCHEMA = SCHEMA_V2
LEGACY_COMPOSITE_PROFILE = "nominal-products-enums-cooperative-tasks-over-closed-ssa-v2"
CANONICAL_CORE_SCHEMA = SCHEMA_V6
LATEST_CORE_SCHEMA = SCHEMA_V7
LEGACY_COMPOSITE_OPERATIONS = frozenset({
    "record.make", "record.unpack", "record.get", "enum.make", "enum.tag",
    "task.create", "task.state", "task.start", "task.poll", "task.cancel",
    "task.join", "task.close",
})
COMPOSITE_OPERATIONS = LEGACY_COMPOSITE_OPERATIONS | {"record.borrow"}

PRIMITIVE_PROFILES = MappingProxyType({
    SCHEMA: PROFILE, SCHEMA_V2: PROFILE_V2, SCHEMA_V3: PROFILE_V3,
    SCHEMA_V4: PROFILE_V4, SCHEMA_V5: PROFILE_V5, SCHEMA_V6: PROFILE_V6,
    SCHEMA_V7: PROFILE_V7,
})
PRIMITIVE_SCHEMAS = frozenset(PRIMITIVE_PROFILES)
_FEATURE_ORDER = ("bulk_memory", "inplace_memory", "byte_swap", "offset_copy", "range_fill", "recursive_chain")
PRIMITIVE_FEATURES = MappingProxyType({
    schema: frozenset(_FEATURE_ORDER[:index])
    for index, schema in enumerate(PRIMITIVE_PROFILES)
})


def profile_for_schema(schema: str) -> str:
    """Return the exact declared grammar profile; unknown schemas raise KeyError."""
    if schema in COMPOSITE_PROFILES:
        return COMPOSITE_PROFILES[schema]
    return PRIMITIVE_PROFILES[schema]


def composite_core_schema(schema: str) -> str:
    """Existing nominal inputs retain their exact original primitive grammar."""
    return {COMPOSITE_SCHEMA: SCHEMA_V6, COMPOSITE_SCHEMA_V2: SCHEMA_V7}[schema]


def supports_feature(schema: str, feature: str) -> bool:
    """Report primitive grammar support, without making a safety assertion."""
    return feature in PRIMITIVE_FEATURES.get(schema, ())


def schema_registry() -> dict:
    """Detached machine-readable compatibility metadata for tools and agents."""
    return {
        "schema": "hepta.hia.schema-registry.v1",
        "canonical_core_schema": CANONICAL_CORE_SCHEMA,
        "latest_core_schema": LATEST_CORE_SCHEMA,
        "primitive": [
            {"schema": schema, "profile": profile,
             "features": sorted(PRIMITIVE_FEATURES[schema])}
            for schema, profile in PRIMITIVE_PROFILES.items()
        ],
        "composite": {"schema": COMPOSITE_SCHEMA, "profile": COMPOSITE_PROFILE,
                      "normalizes_to": CANONICAL_CORE_SCHEMA,
                      "nominal_operations": sorted(COMPOSITE_OPERATIONS)},
        "composite_versions": [
            {"schema": schema, "profile": profile,
             "normalizes_to": composite_core_schema(schema),
             "nominal_operations": sorted(COMPOSITE_OPERATIONS)}
            for schema, profile in COMPOSITE_PROFILES.items()
        ],
        "legacy_nominal": {"schema": LEGACY_COMPOSITE_SCHEMA,
                           "profile": LEGACY_COMPOSITE_PROFILE,
                           "implicit_dispatch": False,
                           "explicit_adapter": "import_legacy_composite_v2"},
        "schemas_are_not_safety_receipts": True,
    }
