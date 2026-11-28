"""Closed development models for real Worker protocol installations."""
from hashlib import sha256
from pathlib import Path

from tools.hia_worker_protocols import protocol as selected_protocol


def worker_model(root: Path, native_source_authority=None, *, protocol="03") -> dict:
    from tools.generate_hia_worker_manifest import model, current_model
    selected = selected_protocol(protocol)
    result = model(root) if protocol == "01" else current_model(root)
    if protocol == "03":
        from tools.build_hia_worker_release import AGENT_INSTALLED_HELPERS
        from tools.build_hia_json_preflight import CANDIDATES, image_manifest_schema
        from hepta import hia_core_lowering_selection as core
        from hepta.hia_native_continuation_selection import (
            INPROCESS_SCHEMA_V2, resource_names)
        if tuple(AGENT_INSTALLED_HELPERS) != (
                (20, "agent-query"), (21, "cli-inspect"),
                (22, "agent-native-metadata"), (23, "agent-json-wire")):
            raise ValueError("default Worker Agent role domain differs")
        for _, candidate in AGENT_INSTALLED_HELPERS:
            source, wire = CANDIDATES[candidate]
            result["helpers"].append(dict(
                role=len(result["helpers"]) + 1, name=candidate,
                source="examples/hia_bootstrap/" + source + ".hepta",
                image_path=wire + ".image.bin",
                schema=image_manifest_schema(candidate, wire), installed=True))
        matches = [f for f in result["families"] if f["name"] == "core-lowering"]
        if len(matches) != 1:
            raise ValueError("default Worker requires exactly one Core lowering family")
        family = matches[0]
        raw = (root / core.ABI_SOURCE_V2).read_bytes()
        abi = core.checked_abi_v2(raw)
        names = ("core_lowering_v2_pool", *abi["units"])
        if len(names) != 40 or len(set(names)) != 40:
            raise ValueError("Core v2 must contain all 39 controls and its separate pool")
        family.update(
            abi_source=core.ABI_SOURCE_V2, abi_sha256=sha256(raw).hexdigest(),
            schema=core.SCHEMA_V2, unit_schema=core.UNIT_SCHEMA_V2, abi=abi,
            units=[dict(name=name, source="examples/hia_bootstrap/" + name + ".hepta",
                        image_path=name + ".image.bin", schema=core.UNIT_SCHEMA_V2)
                   for name in names],
            continuation_schema=INPROCESS_SCHEMA_V2,
            continuation_resources=list(resource_names("core-lowering", core_v2=True)),
            continuation_runtime=list(result["continuation_runtime"]),
            continuation_policy="examples/hia_bootstrap/continuation_policy_v2.hepta",
            continuation_packer="examples/hia_bootstrap/continuation_inprocess_packer_v2.hepta",
            continuation_frontend="source_worker_continuation_pack_v2.hepta",
            continuation_pack_magic="HIACTPK2", implementation_label="native-core-lowering-v2",
        )
    ordinal = 1
    for family in result["families"]:
        for unit in family["units"]:
            unit["role"] = ordinal
            ordinal += 1
    if len(result["helpers"]) != selected.helper_count:
        raise ValueError("Worker helper domain differs from its explicit protocol")
    if len({h["name"] for h in result["helpers"]}) != len(result["helpers"]):
        raise ValueError("Worker helper roles are not unique")
    if native_source_authority is not None:
        from tools.hia_native_worker_source_authority import native_model
        result = native_model(result, native_source_authority)
    return result
