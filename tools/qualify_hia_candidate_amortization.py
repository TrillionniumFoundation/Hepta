#!/usr/bin/env python3
"""Prospective adaptive follow-up: full-cost reuse of one byte_sum candidate.

The horizon was chosen after the earlier negative full-cost study. This is not
an unbiased confirmation, a new NDU ranking, or a legacy-application benchmark.
Every episode uses independent fresh proofs and internally built native images.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from hepta.hia_optimization import DEFAULT_POLICY
from hepta.hia_program_source import lower_source
from hepta.native_tool_identity import digest_executable
from tools.qualify_hia_ndu_graph import DRIVER
from tools.qualify_hia_ndu_loop import EpisodeBudget, measured
from tools.qualify_hia_ndu_narrowed_candidates import (
    frozen_sources, native_text, new_owner, observe, prepare)
from tools.qualify_hia_ndu_net_value import save

ARMS = ("base", "guarded", "guarded-narrowed")
UNIT = [4093] * 6 + [127, 4097]
PROFILE = ROOT / "experiments/hia_candidate_amortization"
PROTOCOL = PROFILE / "PROTOCOL_20261030.json"
WORKLOAD = ROOT / "experiments/hia_ndu_activation/byte_sum.hepta"
PRIOR_RESULT_SHA256 = "58239dbbb155cc896faac9a30c7bba0cb6956016298777ee17833a1373fd1cd5"
PRIOR_TRACKED_COST_NS = 199343918199


def validate_protocol(p):
    exact = {"schema": "hepta.hia.candidate-amortization.protocol.v1",
        "experiment_kind": "adaptive-follow-up", "module": "byte_sum",
        "arms": list(ARMS), "trace_unit": UNIT, "groups": 3,
        "trace_repetitions": 32, "deliveries_per_episode": 256,
        "calls": 65535, "holdout_seed": 197, "seed_policy": "fixed-all-deliveries",
        "guard_maximum": 4096, "episode_budget_ns": 180000000000,
        "prior_result_sha256": PRIOR_RESULT_SHA256,
        "prior_tracked_cost_ns": PRIOR_TRACKED_COST_NS,
        "proof_policy": dict(DEFAULT_POLICY, timeout_ms=30000),
        "session_limits": {"max_entries": 8, "max_retained_bytes": 33554432,
            "max_artifact_bytes": 1048576, "max_metadata_bytes": 1048576,
            "max_leases": 4, "max_executions": 256},
        "sample_exclusion": "none", "authority": "DENY_ALL",
        "safety_certificate": False, "previous_negative_results_replaced": False,
        "stop_after_registered_horizon": True}
    for key, value in exact.items():
        if type(p.get(key)) is not type(value) or p[key] != value:
            raise ValueError("unsupported frozen amortization protocol: " + key)
    return p


def episode(folder, target, group, base, clang, objcopy, driver, driver_sha, p):
    started = time.monotonic_ns()
    folder.mkdir()
    ledger, observations, admissions = [], [], []
    budget = EpisodeBudget(started, p["episode_budget_ns"])
    owner = None
    result = {"target": target, "group": group, "status": "running", "ledger": ledger,
        "observations": observations, "admissions": admissions,
        "external_proof_imported": False, "fresh_independent_session": True}

    def stage(label, operation):
        return budget.stage(label, ledger, operation)

    def admit(kind, parent):
        entry = stage("prepare." + kind, lambda: prepare(owner, base, parent, kind, p))
        receipt = owner._entries[entry["token"]].image.receipt
        text = stage("native.text." + kind, lambda: native_text(objcopy,
            receipt["native"]["output"], folder / (kind + ".text")))
        admission = {"target": kind, "entry": entry, "receipt": receipt, "native_text": text}
        admissions.append(admission)
        stage("record.admission." + kind, lambda: save(folder / (kind + ".admission.json"), admission))
        return entry

    try:
        owner = stage("session.create", lambda: new_owner(folder / "images", clang, p, driver, driver_sha))
        baseline = admit("base", None)
        selected = baseline if target == "base" else admit(target, baseline)
        for index, n in enumerate(p["trace_unit"] * p["trace_repetitions"]):
            row = stage("deliver." + str(index), lambda: observe(owner, selected, "byte_sum", n,
                p["calls"], p["holdout_seed"], budget.remaining_ns() / 1e9))
            row.update(target=target, index=index, trace_repeat=index // len(p["trace_unit"]))
            observations.append(row)
            stage("record.sample." + str(index), lambda: save(folder / f"sample-{index + 1:04d}.json", row))
            if row["status"] != "measured":
                raise RuntimeError("actual native output, image mapping or proof-reuse check failed")
        result["status"] = "completed"
    except Exception as error:
        result.update(status="failed", error=f"{type(error).__name__}: {error}")
    finally:
        if owner is not None:
            try:
                measured("session.close", ledger, owner.close)
            except Exception as error:
                result.update(status="failed", shutdown_error=f"{type(error).__name__}: {error}")
            result["session_closed"] = owner.snapshot()
    # The caller times this entire function, including the raw result write.
    # Its final cost fields are retained in the aggregate and a cost-only file.
    save(folder / "RAW_EPISODE.json", result)
    return result


def complete_episode_cost(row, wall_ns, p):
    ledger = row["ledger"]
    components = {
        "prepare_prove_build_seal_ns": sum(x["wall_ns"] for x in ledger if x["label"].startswith("prepare.")),
        "session_create_ns": sum(x["wall_ns"] for x in ledger if x["label"] == "session.create"),
        "native_text_inspection_ns": sum(x["wall_ns"] for x in ledger if x["label"].startswith("native.text.")),
        "delivery_stage_ns": sum(x["wall_ns"] for x in ledger if x["label"].startswith("deliver.")),
        "evidence_stage_ns": sum(x["wall_ns"] for x in ledger if x["label"].startswith("record.")),
        "cleanup_ns": sum(x["wall_ns"] for x in ledger if x["label"] == "session.close"),
    }
    components["other_accounted_wall_ns"] = wall_ns - sum(components.values())
    # These nested execution metrics are explanatory and are not added again.
    nested = {"delivery_observation_ns": sum(x["delivery_cost_ns"] for x in row["observations"]),
        "native_driver_elapsed_ns": sum(x.get("output", {}).get("elapsed_ns", 0) for x in row["observations"]),
        "native_driver_process_cpu_ns": sum(x.get("output", {}).get("process_cpu_ns", 0) for x in row["observations"])}
    state = row.get("session_closed", {})
    expected_admissions = 1 if row["target"] == "base" else 2
    distinct = row["target"] == "base" or (len(row["admissions"]) == 2
        and row["admissions"][0]["native_text"]["sha256"] != row["admissions"][1]["native_text"]["sha256"])
    admitted = (row["status"] == "completed" and 0 <= wall_ns <= p["episode_budget_ns"]
        and len(row["observations"]) == p["deliveries_per_episode"]
        and all(x["status"] == "measured" for x in row["observations"])
        and state.get("execution_attempts") == p["deliveries_per_episode"]
        and state.get("proof_attempts") == expected_admissions
        and state.get("successful_admissions") == expected_admissions
        and state.get("owned_native_release_complete") is True
        and state.get("charged_retained_bytes") == state.get("reserved_bytes") == state.get("outstanding_leases") == 0
        and state.get("pending_release_debt") == []
        and len(row["admissions"]) == expected_admissions
        and all(x["receipt"]["verification"]["status"] == "verified" for x in row["admissions"])
        and components["other_accounted_wall_ns"] >= 0 and distinct)
    row.update(wall_ns=wall_ns, components_ns=components, nested_execution_ns=nested,
        distinct_candidate_native_text=distinct, admitted=admitted)
    return row


def paired_gates(rows, p, identities_unchanged):
    cells = {(row["group"], row["target"]): row for row in rows}
    expected = {(group, target) for group in range(p["groups"]) for target in ARMS}
    functional = (identities_unchanged and len(rows) == len(expected)
        and set(cells) == expected and all(row["admitted"] for row in rows))
    pairs = []
    for group in range(p["groups"]):
        for target in ARMS[1:]:
            baseline, candidate = cells.get((group, "base")), cells.get((group, target))
            both = baseline is not None and candidate is not None and baseline["admitted"] and candidate["admitted"]
            pairs.append({"group": group, "target": target, "both_admitted": bool(both),
                "baseline_minus_candidate_complete_ns": baseline["wall_ns"] - candidate["wall_ns"] if both else None,
                "baseline_minus_candidate_delivery_ns": baseline["nested_execution_ns"]["delivery_observation_ns"]
                    - candidate["nested_execution_ns"]["delivery_observation_ns"] if both else None})
    by_candidate = {target: functional and all(x["both_admitted"]
        and x["baseline_minus_candidate_complete_ns"] > 0 for x in pairs if x["target"] == target)
        for target in ARMS[1:]}
    return {"functional_gate": functional, "paired_comparisons": pairs,
        "all_pairs_positive_by_candidate": by_candidate,
        "observed_complete_cost_gate": functional and all(by_candidate.values())}


def qualify(output, prior_cost_audit, clang, objcopy):
    started = time.monotonic_ns()
    output = Path(output).resolve()
    if output.is_relative_to(ROOT):
        raise ValueError("raw observations must be outside the committed source checkout")
    p = validate_protocol(json.loads(PROTOCOL.read_bytes()))
    commit, sources = frozen_sources(PROTOCOL)
    name, raw = str(Path(__file__).relative_to(ROOT)), Path(__file__).read_bytes()
    if subprocess.check_output(["git", "cat-file", "blob", commit + ":" + name], cwd=ROOT) != raw:
        raise RuntimeError("collector differs from the registered source")
    sources[name] = sha256(raw).hexdigest()
    prior_raw = Path(prior_cost_audit).read_bytes()
    prior = json.loads(prior_raw)
    if (prior.get("schema") != "hepta.hia.ndu.narrowed-independent-arithmetic-audit.v1"
            or prior.get("result_sha256") != PRIOR_RESULT_SHA256
            or prior.get("sum_tracked_costs_ns") != PRIOR_TRACKED_COST_NS
            or prior.get("checks_pass") is not True
            or sum(prior.get("separately_tracked_build_study_diagnostic_costs_ns", {}).values()) != PRIOR_TRACKED_COST_NS):
        raise ValueError("original prior-cost ledger required; no prior observation may be relabelled")
    tool_inputs = {}
    for name, executable in (("clang", clang), ("objcopy", objcopy), ("python", sys.executable)):
        found = shutil.which(executable)
        if found is None:
            raise ValueError("actual executable unavailable: " + name)
        path = str(Path(found).resolve())
        tool_inputs[name] = {"path": path, "sha256": digest_executable(path)}
    output.mkdir(parents=True, exist_ok=False)
    save(output / "REGISTRATION.json", {"source_commit": commit, "source_sha256": sources,
        "protocol": p, "protocol_sha256": sha256(PROTOCOL.read_bytes()).hexdigest(),
        "tools": tool_inputs, "registered_utc": datetime.now(timezone.utc).isoformat(),
        "prior_cost_audit_sha256": sha256(prior_raw).hexdigest(), "adaptive_follow_up": True})
    (output / "PRIOR_COST_AUDIT.json").write_bytes(prior_raw)
    base = lower_source(WORKLOAD.read_text())
    (output / "driver.c").write_text(DRIVER)
    driver = output / "driver"
    command = [tool_inputs["clang"]["path"], "-O3", "-std=c11", str(output / "driver.c"), "-ldl", "-o", str(driver)]
    compiled = subprocess.run(command, capture_output=True, timeout=60, check=False)
    save(output / "DRIVER_BUILD.json", {"command": command, "returncode": compiled.returncode,
        "stdout": compiled.stdout.decode(errors="replace"), "stderr": compiled.stderr.decode(errors="replace")})
    if compiled.returncode:
        raise RuntimeError("actual driver build failed")
    driver_sha = digest_executable(driver)
    common_setup_ns, rows = time.monotonic_ns() - started, []
    for group in range(p["groups"]):
        for target in ARMS[group:] + ARMS[:group]:
            folder = output / f"group-{group}-{target}"
            episode_started = time.monotonic_ns()
            row = episode(folder, target, group, base, tool_inputs["clang"]["path"],
                tool_inputs["objcopy"]["path"], driver, driver_sha, p)
            complete_episode_cost(row, time.monotonic_ns() - episode_started, p)
            rows.append(row)
            save(folder / "COST.json", {key: row[key] for key in ("target", "group", "wall_ns",
                "components_ns", "nested_execution_ns", "admitted", "distinct_candidate_native_text")})
            print(json.dumps({key: row[key] for key in ("target", "group", "admitted", "wall_ns", "components_ns")}), flush=True)
    source_unchanged = (all(sha256((ROOT / name).read_bytes()).hexdigest() == value for name, value in sources.items())
        and subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip() == commit
        and not subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT))
    tools_unchanged = (all(digest_executable(row["path"]) == row["sha256"] for row in tool_inputs.values())
        and digest_executable(driver) == driver_sha and Path(prior_cost_audit).read_bytes() == prior_raw)
    measured_study_ns = time.monotonic_ns() - started
    shared_residual_ns = measured_study_ns - common_setup_ns - sum(row["wall_ns"] for row in rows)
    result = {"schema": "hepta.hia.candidate-amortization.result.v1", "source_commit": commit,
        "source_unchanged": source_unchanged, "tool_inputs_unchanged": tools_unchanged,
        "adaptive_follow_up": True, "module_core_sha256": base.sha256, "episodes": rows,
        "common_setup_ns": common_setup_ns, "shared_dispatch_and_final_identity_ns": shared_residual_ns,
        "standalone_complete_ns": {target: common_setup_ns + shared_residual_ns
            + sum(row["wall_ns"] for row in rows if row["target"] == target) for target in ARMS},
        "new_study_ns_before_final_analysis_and_encoding": measured_study_ns,
        "prior_tracked_cost_ns": PRIOR_TRACKED_COST_NS,
        "prior_plus_new_tracked_cost_ns": PRIOR_TRACKED_COST_NS + measured_study_ns,
        "previous_negative_results_replaced": False, "prior_ndu_ranking_recomputed": False,
        "ndu_incremental_value_established": False, "legacy_application_win_established": False,
        "statistical_superiority_established": False, "unbiased_confirmation": False,
        "host": {"platform": platform.platform(), "python": sys.version, "exclusive": False,
            "physical_dot_verified": False, "affinity": sorted(os.sched_getaffinity(0))},
        "authority": "DENY_ALL", "safety_certificate": False,
        **paired_gates(rows, p, source_unchanged and tools_unchanged and shared_residual_ns >= 0)}
    save(output / "RESULT.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--prior-cost-audit", type=Path, required=True)
    parser.add_argument("--clang", default=os.environ.get("CLANG", "clang"))
    parser.add_argument("--objcopy", default="objcopy")
    args = parser.parse_args()
    started, existed = time.monotonic_ns(), args.output.exists()
    try:
        result = qualify(args.output, args.prior_cost_audit, args.clang, args.objcopy)
    except Exception as error:
        if not existed and (args.output / "REGISTRATION.json").is_file():
            save(args.output / "FAILURE.json", {"error": f"{type(error).__name__}: {error}",
                "wall_ns": time.monotonic_ns() - started, "all_prior_observations_retained": True,
                "functional_gate": False, "observed_complete_cost_gate": False})
        raise
    print(json.dumps({key: result[key] for key in ("source_commit", "functional_gate",
        "observed_complete_cost_gate", "all_pairs_positive_by_candidate", "standalone_complete_ns",
        "paired_comparisons", "prior_plus_new_tracked_cost_ns")}, indent=2))


if __name__ == "__main__":
    main()
