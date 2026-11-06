"""Measured stb_divide costs as inputs to the existing finite cache model.

This adapter runs no module and makes no program-refinement claim. Each task
compares retaining HIA with admitting ONE registered alternative image. The
input table is real measured evidence; forecasts composed from it remain
forecasts. Image file bytes are a declared accounting proxy, never an RSS cap.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path

from .hia_ndu_dynamic import (DynamicError, MODEL_SCHEMA, digest, integer,
                             validate_model)

ARMS = ("hia", "c-generic", "cpp-generic", "rust-generic", "c-native",
        "cpp-native", "rust-native", "rust-native-pgo")


def require(ok, message):
    if not ok:
        raise DynamicError("measured module input: " + message)


def validate_cost_report(report):
    require(type(report) is dict and report.get("schema") == "hepta.hia.stb-service.report.v1"
            and report.get("ok") is True and report.get("status") == "completed"
            and report.get("stage") == "study", "completed native study required")
    source = report.get("source_before")
    require(type(source) is dict and source == report.get("source_after")
            and type(source.get("head")) is str and len(source["head"]) == 40,
            "unchanged source identity required")
    p = report.get("protocol", {})
    require(p.get("arms") == list(ARMS) and p.get("groups") == 4
            and p.get("samples") == 41 and p.get("evaluation_pairs") == 257
            and p.get("repeats") == 128, "registered service dimensions")
    require(report.get("vm_observations") == 257 * 6
            and report.get("native_functional_observations") == len(ARMS) * 257 * 6,
            "complete six-function functional evidence")
    rows = report.get("observations")
    require(type(rows) is list and len(rows) == len(ARMS) * 4, "complete timing matrix")
    seen, checksums = set(), set()
    for row in rows:
        require(type(row) is dict and row.get("arm") in ARMS,
                "unknown service candidate")
        integer(row.get("group"), "service timing group", 3)
        key = (row["arm"], row["group"])
        require(key not in seen, "duplicate timing matrix cell")
        seen.add(key)
        require(row.get("cases") == 257 and row.get("samples") == 41
                and row.get("repeats") == 128
                and row.get("calls") == 257 * 6 * 41 * 128, "incomparable call denominator")
        integer(row.get("checksum"), "observed checksum", (1 << 64) - 1)
        checksums.add(row["checksum"])
        samples = row.get("batch_ns")
        require(type(samples) is list and len(samples) == 41, "native sample count")
        for value in [*samples, row.get("load_ns"), row.get("first_request_ns"),
                      row.get("peak_rss_kib")]:
            integer(value, "positive service observation")
            require(value > 0, "zero/padded timing or memory observation")
        require(row.get("cold_delivery_ns") == row["load_ns"] + row["first_request_ns"],
                "cold delivery arithmetic")
    require(len(checksums) == 1, "native candidate behavior differs")
    require(set(report.get("builds", {})) >= set(ARMS), "missing candidate build ledger")
    for name in ARMS:
        integer(report["builds"][name].get("wall_ns"), "native build wall")
    integer(report.get("whole_wall_ns"), "whole native study cost")
    require(report.get("pgo", {}).get("evaluation_rows_used") == 0,
            "PGO evaluation leakage")
    return report


def read_cost_report(path, *, expected_source):
    path = Path(path).resolve(strict=True)
    raw = path.read_bytes()
    require(len(raw) <= 8_000_000, "report byte limit")
    report = validate_cost_report(json.loads(raw))
    require(report["source_before"]["head"] == expected_source, "native study source differs from policy source")
    artifacts = {}
    for name in ARMS:
        build = report["builds"][name]
        if name == "hia":
            receipt = build["receipt"]
            require(receipt.get("ok") is True, "HIA native build not admitted")
            identity = {"path": receipt["output"], "sha256": receipt["artifact_sha256"],
                        "bytes": receipt["artifact_bytes"]}
        else:
            identity = build["artifact"]
        target = Path(identity["path"]).resolve(strict=True)
        require(target.parent == path.parent and target.name == name + ".so",
                "candidate image outside study directory")
        data = target.read_bytes()
        require(len(data) == identity["bytes"] and sha256(data).hexdigest() == identity["sha256"],
                "candidate image differs from native evidence")
        artifacts[name] = {"bytes": len(data), "sha256": identity["sha256"]}
    return {"schema": "hepta.hia.ndu.measured-module-costs.v1",
            "report": {"path": str(path), "sha256": sha256(raw).hexdigest()},
            "source_commit": expected_source, "native_report": report, "artifacts": artifacts,
            "scope": "pairwise HIA/incumbent versus one registered alternative; modeled image admission using real batch/load costs",
            "unknown_costs": ["unload time", "actual resident-memory limit", "new workload dispatch", "human review", "maintenance"],
            "assumptions": ["candidate binaries are already built; build cost retained separately",
                            "zero retirement time is an explicit model assumption",
                            "image file bytes are an accounting proxy, not RSS",
                            "same function corpus; timing-sample separation is not unseen semantic-task separation"]}


def module_models(bank, count, *, split):
    """No timing-value-dependent split, arm choice, rerun, or exclusion.

    Group 0 is training; group 1 has three disjoint selection sample windows;
    groups 2/3 are final. Every six-function ABI candidate is paired with HIA.
    """
    report = validate_cost_report(bank["native_report"])
    rows = {(r["arm"], r["group"]): r for r in report["observations"]}
    require(type(count) is int and 1 <= count <= 256, "bounded module model count")
    require(split in ("training", "selection-0", "selection-1", "selection-2", "final"), "registered module split")
    models = []
    for index in range(count):
        alternative = ARMS[1 + index % (len(ARMS) - 1)]
        if split == "training":
            group, start = 0, (index // 7 * 4) % 36
        elif split == "final":
            group, start = 2 + index % 2, (index // 14 * 4) % 36
        else:
            group, start = 1, int(split[-1]) * 12 + (index // 7 * 4) % 12
        base, other = rows[("hia", group)], rows[(alternative, group)]
        direct, packed = base["batch_ns"][start:start + 4], other["batch_ns"][start:start + 4]
        observation = {"report_sha256": bank["report"]["sha256"], "candidate": alternative,
                       "group": group, "sample_indices": list(range(start, start + 4)), "split": split}
        size = bank["artifacts"][alternative]["bytes"]
        model = {"schema": MODEL_SCHEMA, "generation": 1,
            "objective_digest": digest({"objective": "complete four six-function batches, minimize supplied wall model", "report": bank["report"]["sha256"]}),
            "observation_digest": digest(observation), "workload_sha256": bank["artifacts"]["hia"]["sha256"],
            "artifacts": [{"id": alternative, "resident_bytes": size, "prepare_ns": other["load_ns"],
                           "retire_ns": 0, "epochs": [1] * 4}],
            "targets": [0] * 4, "direct_ns": direct, "packed_ns": packed,
            "ready_mask": 0, "ready_epochs": [0], "memory_quota_bytes": size,
            "budget_ns": 1_000_000_000_000, "sunk_cost_ns": 0,
            "completion_value_ns": 500_000_000_000,
            "decision": {"gate_ns": 0, "solve_ns": 0, "transport_validation_ns": 0,
                         "startup_ns": 0, "close_ns": 0}, "session_ready": True}
        models.append(validate_model(model))
    return models
