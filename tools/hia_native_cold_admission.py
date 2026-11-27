"""Strict native-v2 cold report admission for development component builders.

This gate admits the HIA qualification's native source domain.  It does not
turn host authoring files into cold-qualified sources or manufacture the
legacy Python-isolation checks.  Physical phase archives are checked by the
native cold chain before it publishes a report.
"""
from hashlib import sha256
import json
import re


SCHEMA = "hepta.hia.selfhost-cold-replay.v2"
STATUS = "NATIVE_COLD_SELFHOST_REPLAY_PASS"


def read_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate native cold field: " + key)
            result[key] = value
        return result

    def invalid(value):
        raise ValueError("non-JSON number in native cold report: " + value)

    return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def integer(value, low, high):
    return type(value) is int and low <= value <= high


def digest(value):
    return (type(value) is str and value != "0" * 64
            and re.fullmatch(r"[0-9a-f]{64}", value) is not None)


def admit_native_report(compiler_bytes, cold_bytes, *, contract, sources,
                        observer_bytes):
    """Check all native-v2 fields against the current validated contract.

    The caller supplies independently read current source and observer bytes;
    no report field can select a weaker contract, profile, catalog or budget.
    """
    report = read_json(cold_bytes)
    require(type(report) is dict and report.get("schema") == SCHEMA
            and report.get("status") == STATUS,
            "a completed native-v2 cold qualification is required")
    require(integer(report.get("returncode"), 0, 0), "native cold exit is not zero")
    require(report.get("profile") == contract["profile"]
            and report.get("source_manifest") == sources,
            "native cold source/profile identity differs from current source")
    metadata = contract["native_cold_qualification"]
    require(metadata["schema"] == SCHEMA,
            "current contract does not declare the native cold domain")
    require(metadata["qualification_wall_limit_seconds"] == 180
            and metadata["cleanup_wall_limit_seconds"] == 3,
            "current native qualification limits changed")
    checks = report.get("checks")
    require(type(checks) is dict and len(checks) == 14
            and set(checks) == set(metadata["checks"])
            and all(value is True for value in checks.values()),
            "all fourteen exact native cold checks must pass")
    require(integer(report.get("qualification_wall_limit_seconds"), 180, 180)
            and integer(report.get("cleanup_wall_limit_seconds"), 3, 3)
            and integer(report.get("nested_wall_elapsed_ns"), 1, 180_000_000_000)
            and integer(report.get("cleanup_wall_elapsed_ns"), 0, 3_000_000_000),
            "native cold exceeded the unchanged 180+3 second limits")
    require(type(compiler_bytes) is bytes and 0 < len(compiler_bytes) <= 1_048_576,
            "invalid native cold compiler extent")
    compiler_sha = sha256(compiler_bytes).hexdigest()
    generations = report.get("generation_sha256")
    require(type(generations) is list and generations == [compiler_sha] * 3,
            "three native cold generations must match the selected compiler")
    modified = report.get("modified_generation_sha256")
    require(type(modified) is list and len(modified) == 3
            and all(digest(value) for value in modified)
            and modified[0] != modified[1] == modified[2]
            and modified[2] != compiler_sha and digest(report.get("seed_sha256")),
            "native modified-source self-hosting relationship failed")
    require(type(observer_bytes) is bytes and len(observer_bytes) == 1107
            and report.get("native_flat_observer_hex") == observer_bytes.hex(),
            "native cold observer differs from the independent ABI reference")
    limits = {"phase_workers": 2, "archive_workers": 1,
              "max_pending_archives": 2, "max_unsealed_phases": 4}
    peaks = {"peak_phase_workers": (1, 2), "peak_archive_workers": (1, 1),
             "peak_pending_archives": (0, 2), "peak_unsealed_phases": (1, 4)}
    scheduler = report.get("scheduler")
    require(metadata["scheduler"] == limits and type(scheduler) is dict
            and set(scheduler) == set(limits) | set(peaks)
            and all(integer(scheduler[name], value, value)
                    for name, value in limits.items())
            and all(integer(scheduler[name], *bounds) for name, bounds in peaks.items()),
            "native cold scheduler bounds or observed peaks differ")
    families = {"capacity", "cfg", "elf", "chain", "owned", "bulk", "loan",
                "resource", "tail", "select", "effects", "multi", "keyword",
                "signed", "scalar-casts", "explicit-traps", "cli", "names", "exports"}
    actual_families = report.get("qualification_families")
    require(type(actual_families) is dict and set(actual_families) == families
            and all(type(row) is dict and set(row) == {"original", "modified"}
                    and row["original"] is True and row["modified"] is True
                    for row in actual_families.values()),
            "all nineteen qualification families must pass with both compilers")
    entries = metadata["phase_plan_catalog"]
    catalog = {row["id"]: row for row in entries}
    phases = report.get("phases")
    require(len(catalog) == len(entries) == 60 and type(phases) is list
            and len(phases) == 60, "complete sixty-phase native catalog required")
    seen, base_seen = set(), False
    for row in phases:
        require(type(row) is dict and type(row.get("id")) is str,
                "invalid native phase record")
        identity = row["id"]
        require(identity in catalog and identity not in seen,
                "missing, foreign or duplicated native phase")
        expected = catalog[identity]
        seen.add(identity)
        require(all(row.get(key) == expected[key]
                    for key in ("kind", "family", "label", "plan_sha256"))
                and integer(row.get("node_count"), expected["node_count"], expected["node_count"])
                and integer(row.get("nodes_retained"), expected["node_count"], expected["node_count"])
                and integer(row.get("returncode"), 0, 0)
                and row.get("cleanup_complete") is True and row.get("sealed") is True
                and digest(row.get("journal_sha256")) and digest(row.get("archive_sha256")),
                "native phase plan, retained nodes, archive or cleanup differs: " + identity)
        if row["kind"] == "reference":
            require(not base_seen, "native reference was not before B0")
        elif row["kind"] == "base":
            require(not base_seen, "native base phase repeated")
            base_seen = True
        elif row["kind"] == "qualification":
            require(base_seen, "native qualification preceded its compiler generations")
        else:
            raise ValueError("unknown native phase kind")
    require(base_seen and seen == set(catalog), "native phase catalog is incomplete")
    return sources
