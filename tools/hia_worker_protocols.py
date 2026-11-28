"""Explicit development descriptions of the three native Worker protocols.

Only protocol 03 is the ordinary release entry. Protocols 01 and 02 have
separate real installation owners and are retained for complete compatibility
qualification. No runtime host-language selector is installed.
"""
from dataclasses import dataclass

DEFAULT_PROTOCOL = "03"
PROTOCOLS = ("01", "02", "03")


@dataclass(frozen=True)
class WorkerProtocol:
    number: str
    options_magic: bytes
    request_magic: bytes
    table_magic: bytes
    manifest_source: str
    manifest_table: str
    manifest_spec: str
    install_stem: str
    owner_executable: str
    entry_executable: str
    helper_count: int
    record_count: int
    core_profile: str


def protocol(number: str = DEFAULT_PROTOCOL) -> WorkerProtocol:
    if type(number) is not str or number not in PROTOCOLS:
        raise ValueError("Worker protocol must be explicitly 01, 02, or 03")
    manifest = {
        "01": ("source_worker_manifest_compat_v1", "worker_manifest_compat_v1_tables",
               "HIA_WORKER_MANIFEST_COMPAT_V1_RECORDS"),
        "02": ("source_worker_manifest_current", "worker_manifest_current_tables",
               "HIA_WORKER_MANIFEST_CURRENT_RECORDS"),
        "03": ("source_worker_manifest_default", "worker_manifest_default_tables",
               "HIA_WORKER_MANIFEST_DEFAULT_RECORDS"),
    }[number]
    suffix = "" if number == DEFAULT_PROTOCOL else "_v" + str(int(number))
    return WorkerProtocol(
        number=number,
        options_magic=("HIAWOP" + number).encode("ascii"),
        request_magic=("HIAWMF" + number).encode("ascii"),
        table_magic=("HIAWMT" + number).encode("ascii"),
        manifest_source="examples/hia_bootstrap/" + manifest[0] + ".hepta",
        manifest_table="examples/hia_bootstrap/" + manifest[1] + ".hiastd",
        manifest_spec="docs/" + manifest[2] + ".json",
        install_stem="worker_install" + suffix,
        owner_executable="hia-worker-install-owner",
        entry_executable="hia-worker-install",
        helper_count={"01": 37, "02": 41, "03": 45}[number],
        record_count={"01": 130, "02": 134, "03": 145}[number],
        core_profile="v2" if number == "03" else "v1",
    )


def recipe_path(number: str, kind: str) -> str:
    from tools.generate_hia_worker_install_owner import STAGES
    selected = protocol(number)
    if type(kind) is not str or kind not in STAGES:
        raise ValueError("unknown Worker installation stage")
    return "examples/hia_bootstrap/" + selected.install_stem + "_" + kind + ".hiastd"


# Source filter roles have fixed canonical module and named-source identities.
# Protocol-specific bytes and paths remain separate; no captured source is rewritten.
def canonical_module(number: str, physical_module: str) -> str:
    selected = protocol(number)
    kinds = ("owner", "dag", "owner_packer", "entry", "entry_packer", "entry_bind")
    for kind in kinds:
        if type(physical_module) is str and physical_module == selected.install_stem + "_" + kind:
            return "worker_install_" + kind
    raise ValueError("unknown physical Worker module for this protocol")


def member_source_map(number: str) -> dict[str, str]:
    selected = protocol(number)
    return {"worker_install_" + kind + ".hepta": selected.install_stem + "_" + kind + ".hepta"
            for kind in ("owner", "dag", "owner_packer")}
