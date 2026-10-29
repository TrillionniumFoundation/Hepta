#!/usr/bin/env python3
"""Source-bound heterogeneous NDU activation and complete-cost experiment.

This is a new prospective experiment. It never changes the earlier measured
net-value result. Optimization, actual code admission and economic claims have
separate gates; advisory NDU selections never constitute safety credentials.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import shutil
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from hepta.hia_guarded_optimization import (
    build_guarded_native, guarded_checker_identity, propose_guarded_reduction,
    verify_guarded_optimization)
from hepta.hia_ndu import _read_json
from hepta.hia_ndu_session import STREAM_SOURCE_PIN
from hepta.hia_optimization import build_optimized_native, verify_optimization
from hepta.hia_program_source import lower_source
from tools.qualify_hia_ndu_graph import DRIVER
from tools.qualify_hia_ndu_loop import EpisodeBudget, digest, execute_sample, measured
from tools.qualify_hia_ndu_net_value import (
    APPLICATION_ARMS, CompilationCredits, complete_budget_dp, new_bridge,
    plan_key, rotated, save, select_native, standalone_totals,
    validate_build_envelope)

PROFILE = ROOT / "experiments/hia_ndu_activation"
PROTOCOL_PATH = PROFILE / "PROTOCOL_20261028.json"
TARGETS = ("base", "guard-small", "guard-wide")
MODULES = ("byte_sum", "packet_xor")


def validate_protocol(p):
    if (p.get("schema") != "hepta.hia.ndu.activation.protocol.v1"
            or p.get("native_source_pin") != STREAM_SOURCE_PIN
            or p.get("native_rustc") != "1.90.0"
            or p.get("modules") != list(MODULES)
            or p.get("arms") != list(APPLICATION_ARMS)
            or p.get("guard_limits") != {"guard-small": 128, "guard-wide": 65536}
            or p.get("calibration_sizes") != [127, 4093, 32749]
            or p.get("authority") != "DENY_ALL" or p.get("safety_certificate") is not False
            or p.get("previous_negative_results_replaced") is not False):
        raise ValueError("unsupported prospective activation profile")
    for key, lo, hi in (("groups", 1, 8), ("calls", 1, 1_000_000),
                        ("calibration_repetitions", 1, 8), ("training_seed", 0, 255),
                        ("holdout_seed", 0, 255), ("episode_budget_ns", 1, 1_000_000_000_000),
                        ("completion_value_ns", 1, 1_000_000_000_000)):
        if type(p.get(key)) is not int or not lo <= p[key] <= hi:
            raise ValueError("invalid bounded integer: " + key)
    if (type(p.get("controller_timeout_s")) not in {int, float}
            or not 0 < p["controller_timeout_s"] <= 120
            or set(p.get("application_profiles", {})) != {"stable-reuse", "changing-load", "shared-budget"}):
        raise ValueError("invalid profile inventory or controller timeout")
    for profile, spec in p["application_profiles"].items():
        ids, traces = spec["modules"], spec["module_sizes"]
        if (type(spec["compile_credits"]) is not int or spec["compile_credits"] != 1
                or not 1 <= len(ids) <= 2 or len(set(ids)) != len(ids)
                or any(name not in MODULES for name in ids) or len(ids) != len(traces)
                or not 2 <= len(traces[0]) <= 16 or len({len(row) for row in traces}) != 1
                or any(type(n) is not int or n not in p["calibration_sizes"] for row in traces for n in row)
                or (profile == "shared-budget" and ids != list(MODULES))):
            raise ValueError("invalid finite module trace")
    return p


def checksum(module, n, calls, seed):
    """Independent period-256 oracle for the declared bounded inputs only."""
    if module not in MODULES or not 0 <= n <= 65536 or not 0 < calls <= 1_000_000 or not 0 <= seed <= 255:
        raise ValueError("checksum outside the declared workload")
    values = []
    for offset in range(256):
        s = (seed + offset) & 255
        cycle = ([((i + s) & 255) for i in range(256)] if module == "byte_sum" else
                 [((13 * i + s) & 255) ^ ((i + (s ^ 90)) & 255) for i in range(256)])
        values.append((n // 256) * sum(cycle) + sum(cycle[:n % 256]))
    return ((calls // 256) * sum(values) + sum(values[:calls % 256])) & ((1 << 64) - 1)


def run_sample(module, driver, path, receipt, *, n, calls, seed, timeout):
    return execute_sample(driver, path, expected_artifact_sha256=receipt["native"]["artifact_sha256"],
        n=n, calls=calls, seed=seed, multiplier=1, timeout=timeout,
        checksum_oracle=lambda size, count, start, unused: checksum(module, size, count, start))


def calibration_order(repetition, size_index):
    pairs = tuple((module, target) for module in MODULES for target in TARGETS)
    return rotated(pairs, repetition, size_index)


def calibrate(bases, folder, driver, clang, p):
    folder.mkdir()
    banks, ledger = {}, []
    def stage(label, operation):
        try:
            return measured(label, ledger, operation)
        finally:
            # One immutable receipt per attempt survives later calibration
            # failure; a final successful BANK is not required to retain cost.
            save(folder / f"stage-{len(ledger):04d}.json", ledger[-1])
    for module, base in bases.items():
        target_dir = folder / module
        target_dir.mkdir()
        candidates = {}
        for target in TARGETS:
            path = target_dir / (target + ".so")
            start = time.monotonic_ns()
            proposal = None if target == "base" else stage("propose." + module + "." + target,
                lambda: propose_guarded_reduction(base, maximum=p["guard_limits"][target]))
            receipt = stage("build." + module + "." + target,
                lambda: build_optimized_native(base, base, path, clang=clang) if proposal is None
                else build_guarded_native(base, proposal, path, clang=clang))
            candidates[target] = {"artifact": str(path), "receipt": receipt,
                "setup_ns": time.monotonic_ns() - start, "verification": receipt["verification"],
                "proposal": proposal, "proposal_sha256": digest(proposal), "samples": []}
            save(target_dir / (target + ".admission.json"), candidates[target])
        refused = stage("refuse.unguarded." + module,
            lambda: verify_optimization(base, candidates["guard-wide"]["proposal"]["fast_core"]))
        save(target_dir / "unguarded-refusal.json", refused)
        if refused["status"] != "rejected":
            raise RuntimeError("unguarded optimization negative control accepted")
        banks[module] = {"base_sha256": base.sha256, "candidates": candidates, "unguarded_refusal": refused}
    order = []
    for rep in range(p["calibration_repetitions"]):
        for size_index, n in enumerate(p["calibration_sizes"]):
            for module, target in calibration_order(rep, size_index):
                row = banks[module]["candidates"][target]
                base = bases[module]
                proof = stage(f"fresh-proof.{rep}.{n}.{module}.{target}",
                    lambda: verify_optimization(base, base) if target == "base"
                    else verify_guarded_optimization(base, row["proposal"]))
                proof_ns = ledger[-1]["wall_ns"]
                if proof["status"] != "verified" or proof["candidate_sha256"] != row["receipt"]["verification"]["candidate_sha256"]:
                    raise RuntimeError("calibration proof does not bind candidate")
                result = stage(f"execute.{rep}.{n}.{module}.{target}",
                    lambda: run_sample(module, driver, row["artifact"], row["receipt"], n=n,
                        calls=p["calls"], seed=p["training_seed"], timeout=120))
                observation = dict(result, module=module, state=target, n=n, repetition=rep,
                    fresh_proof_wall_ns=proof_ns, delivery_cost_ns=proof_ns + result["outer_wall_ns"])
                row["samples"].append(observation)
                order.append({"module": module, "state": target, "n": n, "repetition": rep})
                save(folder / f"sample-{len(order):04d}.json", observation)
                if result["status"] != "measured" or result.get("loaded_mapping_verified") is not True:
                    raise RuntimeError("calibration output or loaded mapping failed")
    for bank in banks.values():
        for row in bank["candidates"].values():
            row["latency_ns"] = {str(n): round(statistics.median(s["delivery_cost_ns"] for s in row["samples"] if s["n"] == n))
                                 for n in p["calibration_sizes"]}
    bank = {"schema": "hepta.hia.ndu.activation.bank.v1", "modules": banks,
            "calibration_order": order, "ledger": ledger, "timing_information": "calibration only"}
    bank["bank_sha256"] = digest(bank)
    save(folder / "BANK.json", bank)
    return bank


def allocation_model(bank, spec, epoch, observations, artifacts, credits):
    """Update an exact observed cell only; do not extrapolate cross-size noise."""
    modules = []
    for index, (module, sizes) in enumerate(zip(spec["modules"], spec["module_sizes"])):
        options = []
        for target in TARGETS:
            row = bank["modules"][module]["candidates"][target]
            costs = []
            for n in sizes[epoch:]:
                observed = [s["delivery_cost_ns"] for s in observations
                            if s["module"] == module and s["state"] == target and s["n"] == n
                            and s["status"] == "measured"]
                costs.append(round(statistics.median(observed)) if observed else row["latency_ns"][str(n)])
            new_build = (module, target) not in artifacts
            options.append({"target": target, "credits": int(new_build),
                "cost_ns": sum(costs) + (row["setup_ns"] if new_build else 0),
                "verified": row["verification"]["status"] == "verified"})
        modules.append(options)
    return {"modules": modules, "remaining_credits": credits.remaining,
            "support": digest({"bank": bank["bank_sha256"], "module_ids": spec["modules"],
                "observations": observations, "available_artifacts": sorted(artifacts), "epoch": epoch})}


def episode(folder, arm, profile, group, p, manifest, identity, bases, bank, driver, clang):
    started, ledger, observations, artifacts = time.monotonic_ns(), [], [], {}
    folder.mkdir()
    budget = EpisodeBudget(started, p["episode_budget_ns"])
    spec, bridge = p["application_profiles"][profile], None
    credits = CompilationCredits(spec["compile_credits"])
    checker = guarded_checker_identity()
    record = {"arm": arm, "profile": profile, "group": group, "status": "running", "ledger": ledger,
              "observations": observations, "decisions": [], "same_initial_information": bank["bank_sha256"],
              "module_ids": spec["modules"], "future_timing_access": False}

    def stage(label, operation):
        return budget.stage(label, ledger, operation)

    def admit(module, target):
        if guarded_checker_identity() != checker:
            raise RuntimeError("checker source changed")
        base, row, key = bases[module], bank["modules"][module]["candidates"][target], (module, target)
        if key not in artifacts:
            path = folder / (module + "-" + target + ".so")
            if target == "base":
                receipt = stage("base-build." + module, lambda: build_optimized_native(base, base, path, clang=clang, policy=budget.policy()))
            else:
                credits.consume(module, target)
                proposal = stage("propose." + module + "." + target,
                    lambda: propose_guarded_reduction(base, maximum=p["guard_limits"][target]))
                if digest(proposal) != row["proposal_sha256"]:
                    raise RuntimeError("candidate proposal changed")
                receipt = stage("candidate-build." + module + "." + target,
                    lambda: build_guarded_native(base, proposal, path, clang=clang, policy=budget.policy()))
            artifacts[key] = path, receipt
        path, receipt = artifacts[key]
        proof = stage("fresh-proof." + module + "." + target,
            lambda: verify_optimization(base, base, policy=budget.policy()) if target == "base"
            else verify_guarded_optimization(base, row["proposal"], policy=budget.policy()))
        if proof["status"] != "verified" or proof["candidate_sha256"] != receipt["verification"]["candidate_sha256"]:
            raise RuntimeError("fresh proof does not bind candidate")
        return path, receipt

    def deliver(module, target, n, epoch):
        path, receipt = admit(module, target)
        proof_ns = ledger[-1]["wall_ns"]
        result = stage(f"execute.{epoch}.{module}.{target}", lambda: run_sample(module, driver, path, receipt,
            n=n, calls=p["calls"], seed=(p["holdout_seed"] + group) & 255, timeout=budget.remaining_ns() / 1e9))
        observations.append(dict(result, module=module, state=target, n=n, epoch=epoch,
            fresh_proof_wall_ns=proof_ns, delivery_cost_ns=proof_ns + result["outer_wall_ns"],
            declared_fast_guard_holds=target != "base" and n <= p["guard_limits"][target]))
        if result["status"] != "measured" or result.get("loaded_mapping_verified") is not True:
            raise RuntimeError("application output or loaded mapping failed")

    try:
        if arm.startswith("native"):
            bridge = stage("native.admission", lambda: new_bridge(arm, manifest, identity, folder / "native", p))
        for module in spec["modules"]:
            deliver(module, "base", p["calibration_sizes"][0], -1)
        fixed = None
        for epoch in range(len(spec["module_sizes"][0])):
            if arm == "fixed" and fixed is not None:
                model, selected, evidence = None, fixed, {"committed_fixed_plan_reused": True}
            else:
                model = allocation_model(bank, spec, epoch, observations, artifacts, credits)
                def choose():
                    if bridge:
                        bridge.timeout = min(p["controller_timeout_s"], budget.remaining_ns() / 1e9)
                        return select_native(model, p, epoch + 1, bridge)
                    return complete_budget_dp(model), {"algorithm": "complete-multiple-choice-budget-DP"}
                selected, evidence = stage(f"control.{epoch}", choose)
                if selected is None:
                    raise RuntimeError("no feasible finite allocation")
                if arm == "fixed":
                    fixed = deepcopy(selected)
            record["decisions"].append({"epoch": epoch, "model": model, "selected": selected, "evidence": evidence})
            for module, sizes, target in zip(spec["modules"], spec["module_sizes"], selected["targets"]):
                deliver(module, target, sizes[epoch], epoch)
        record["status"] = "completed"
    except Exception as error:
        record.update(status="failed", error=f"{type(error).__name__}: {error}")
    finally:
        if bridge:
            measured("native.shutdown", ledger, bridge.close)
            record["native_session"] = bridge.snapshot()
    record["compile_credit"] = {"limit": credits.limit, "used": credits.used, "attempts": credits.attempts}
    record["observations_expected"] = len(spec["modules"]) * (1 + len(spec["module_sizes"][0]))
    # Keep executable receipts after releasing this research runner's handles.
    record["artifacts"] = [{"module": m, "state": t, "path": str(path), "receipt": receipt}
                           for (m, t), (path, receipt) in sorted(artifacts.items())]
    artifacts.clear()
    save(folder / "RESULT.json", record)
    record["wall_ns"] = time.monotonic_ns() - started
    record["admitted"] = (record["status"] == "completed" and record["wall_ns"] <= p["episode_budget_ns"]
                          and len(observations) == record["observations_expected"] and credits.used <= credits.limit)
    return record


def decision_analysis(records):
    """Post-run audit only; no timings or target choices are modified."""
    audits, competing = [], []
    for row in records:
        for decision in row["decisions"]:
            model = decision["model"]
            if model is None:
                continue
            oracle = complete_budget_dp(model)
            selected = decision["selected"]
            profitable = []
            for module, options in zip(row["module_ids"], model["modules"]):
                base_cost = next(o["cost_ns"] for o in options if o["target"] == "base")
                if any(o["verified"] and o["credits"] > 0 and o["cost_ns"] < base_cost for o in options):
                    profitable.append(module)
            audit = {"arm": row["arm"], "profile": row["profile"], "group": row["group"],
                "epoch": decision["epoch"], "selected_targets": selected["targets"],
                "oracle_targets": oracle["targets"], "selection_regret_ns": selected["cost_ns"] - oracle["cost_ns"],
                "same_plan_key_as_exact_dp": plan_key(selected) == plan_key(oracle),
                "remaining_credits": model["remaining_credits"], "individually_profitable_modules": profitable}
            audits.append(audit)
            if len(profitable) > model["remaining_credits"] > 0:
                competing.append(audit)
    native_rows = [r for r in records if r["arm"].startswith("native")]
    native_audits = [a for a in audits if a["arm"].startswith("native")]
    native_competing = [a for a in competing if a["arm"].startswith("native")]
    builds = sum(r["compile_credit"]["used"] for r in native_rows)
    outputs = sum(o["state"] != "base" and o["status"] == "measured" for r in native_rows for o in r["observations"])
    competition_executed = any(a["same_plan_key_as_exact_dp"] and any(
        r["group"] == a["group"] and r["profile"] == a["profile"] and r["admitted"]
        and r["compile_credit"]["used"] == 1 and any(o["state"] != "base" and o["status"] == "measured" for o in r["observations"])
        for r in native_rows) for a in native_competing)
    return {"schema": "hepta.hia.ndu.activation.analysis.v1", "decision_audits": audits,
        "competing_decisions": competing, "ndu_candidate_build_attempts": builds,
        "ndu_candidate_correct_outputs": outputs,
        "ndu_nonbaseline_guard_input_observations": sum(o["declared_fast_guard_holds"] for r in native_rows for o in r["observations"]),
        "ndu_selections_match_complete_dp": bool(native_audits) and all(a["same_plan_key_as_exact_dp"] for a in native_audits),
        "ndu_candidate_activation_observed": builds > 0 and outputs > 0,
        "ndu_shared_budget_competition_executed": competition_executed,
        "activation_implies_net_benefit": False}


def qualify(output, identity, build_envelope, clang, protocol_path=PROTOCOL_PATH):
    started = time.monotonic_ns()
    output, identity, protocol_path = Path(output).resolve(), Path(identity).resolve(), Path(protocol_path).resolve()
    if output.is_relative_to(ROOT) or not protocol_path.is_relative_to(ROOT):
        raise ValueError("raw output must be external and protocol source-bound")
    p = validate_protocol(json.loads(protocol_path.read_bytes()))
    if subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT):
        raise RuntimeError("prospective registration requires a clean committed worktree")
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    manifest_raw, envelope_raw = identity.read_bytes(), Path(build_envelope).read_bytes()
    manifest, envelope = _read_json(manifest_raw), _read_json(envelope_raw)
    if (manifest.get("identity", {}).get("source_commit") != p["native_source_pin"]
            or not manifest["identity"].get("rustc", "").startswith("rustc " + p["native_rustc"] + " ")):
        raise ValueError("native source/tool differs from registration")
    full_build_ns = validate_build_envelope(envelope, manifest, manifest_raw, commit)
    clang_path = Path(shutil.which(clang) or clang).resolve(strict=True)
    tool_inputs = {"clang": {"path": str(clang_path), "sha256": sha256(clang_path.read_bytes()).hexdigest()},
                   "python": {"path": str(Path(sys.executable).resolve()),
                              "sha256": sha256(Path(sys.executable).resolve().read_bytes()).hexdigest()}}
    names = sorted({*(str(path.relative_to(ROOT)) for path in (ROOT / "hepta").glob("*.py")),
        str(protocol_path.relative_to(ROOT)), str(Path(__file__).relative_to(ROOT)),
        "tools/qualify_hia_ndu_loop.py", "tools/qualify_hia_ndu_graph.py", "tools/qualify_hia_ndu_net_value.py",
        "tools/measure_hia_ndu_build.py", "tools/build_hia_recursive_ndu_bridge.py",
        *(f"experiments/hia_ndu_activation/{m}.hepta" for m in MODULES)})
    source = {}
    for name in names:
        raw = (ROOT / name).read_bytes()
        if subprocess.check_output(["git", "cat-file", "blob", commit + ":" + name], cwd=ROOT) != raw:
            raise RuntimeError("source differs from committed identity: " + name)
        source[name] = sha256(raw).hexdigest()
    output.mkdir(parents=True, exist_ok=False)
    save(output / "REGISTRATION.json", {"source_commit": commit, "source_sha256": source,
        "protocol": p, "protocol_sha256": sha256(protocol_path.read_bytes()).hexdigest(),
        "tool_inputs": tool_inputs,
        "registered_utc": datetime.now(timezone.utc).isoformat(), "native_binary_sha256": manifest["binary_sha256"],
        "previous_outcomes_preserved": True})
    (output / "NATIVE_BUILD_IDENTITY.json").write_bytes(manifest_raw)
    (output / "NATIVE_BUILD_ENVELOPE.json").write_bytes(envelope_raw)
    before = time.monotonic_ns()
    bases = {module: lower_source((PROFILE / (module + ".hepta")).read_text()) for module in MODULES}
    (output / "driver.c").write_text(DRIVER)
    driver = output / "driver"
    command = [clang, "-O3", "-std=c11", str(output / "driver.c"), "-ldl", "-o", str(driver)]
    completed = subprocess.run(command, capture_output=True, timeout=60, check=False)
    (output / "driver.stdout").write_bytes(completed.stdout)
    (output / "driver.stderr").write_bytes(completed.stderr)
    driver_sha256 = sha256(driver.read_bytes()).hexdigest() if driver.exists() else None
    save(output / "DRIVER_BUILD.json", {"command": command, "returncode": completed.returncode,
        "driver_sha256": driver_sha256})
    if completed.returncode:
        raise RuntimeError("native driver build failed")
    bank = calibrate(bases, output / "calibration", driver, clang, p)
    setup_ns = time.monotonic_ns() - before
    common_ns = time.monotonic_ns() - started - setup_ns
    records = []
    for group in range(p["groups"]):
        for index, profile in enumerate(p["application_profiles"]):
            for arm in rotated(APPLICATION_ARMS, group, index):
                record = episode(output / f"application-{group}-{profile}-{arm}", arm, profile, group, p,
                                 manifest, identity, bases, bank, driver, clang)
                records.append(record)
                print(json.dumps({"group": group, "profile": profile, "arm": arm,
                    "admitted": record["admitted"], "candidate_builds": record["compile_credit"]["used"],
                    "wall_ns": record["wall_ns"]}), flush=True)
    unchanged = all(sha256((ROOT / name).read_bytes()).hexdigest() == value for name, value in source.items())
    unchanged = unchanged and identity.read_bytes() == manifest_raw
    unchanged = unchanged and subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip() == commit
    unchanged = unchanged and not subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT)
    tool_inputs_unchanged = all(sha256(Path(row["path"]).read_bytes()).hexdigest() == row["sha256"] for row in tool_inputs.values())
    driver_unchanged = sha256(driver.read_bytes()).hexdigest() == driver_sha256
    residual_ns = max(0, time.monotonic_ns() - started - common_ns - setup_ns - sum(r["wall_ns"] for r in records))
    totals = standalone_totals(records, APPLICATION_ARMS, common_ns + setup_ns, 0, residual_ns, full_build_ns)
    profiles = {}
    expected = {(group, arm) for group in range(p["groups"]) for arm in APPLICATION_ARMS}
    for profile in p["application_profiles"]:
        selected = [r for r in records if r["profile"] == profile]
        complete = len(selected) == len(expected) and {(r["group"], r["arm"]) for r in selected} == expected
        correct = unchanged and tool_inputs_unchanged and driver_unchanged and complete and all(r["admitted"] for r in selected)
        costs = standalone_totals(selected, APPLICATION_ARMS, common_ns + setup_ns, 0, residual_ns, full_build_ns)
        costs.update(all_outputs_and_budgets_admitted=correct, full_cost_advantage=bool(correct and all(
            costs["standalone_cold_ns"]["native-stream-sealed"] < costs["standalone_cold_ns"][arm] for arm in ("fixed", "dp"))))
        profiles[profile] = costs
    analysis_started = time.monotonic_ns()
    analysis = decision_analysis(records)
    analysis["post_run_analysis_ns"] = time.monotonic_ns() - analysis_started
    save(output / "ANALYSIS.json", analysis)
    result = {"schema": "hepta.hia.ndu.activation.result.v1", "source_commit": commit, "source_unchanged": unchanged,
        "tool_inputs": tool_inputs, "tool_inputs_unchanged": tool_inputs_unchanged, "driver_unchanged": driver_unchanged,
        "application_episodes": records, "application_totals": totals, "application_profile_totals": profiles,
        "common_setup_ns_once_per_standalone_arm": common_ns + setup_ns,
        "residual_ns_conservatively_charged_to_each_native_arm": residual_ns,
        "native_complete_build_wall_ns": full_build_ns, "analysis": analysis,
        "different_semantic_core_hashes": len({base.sha256 for base in bases.values()}) == len(MODULES),
        "module_core_sha256": {key: base.sha256 for key, base in bases.items()},
        "all_application_outputs_and_budgets_admitted": all(r["all_outputs_and_budgets_admitted"] for r in profiles.values()),
        "registered_full_cost_advantage": all(r["full_cost_advantage"] for r in profiles.values()),
        "statistical_superiority_established": False, "prior_negative_results_replaced": False,
        "host": {"platform": platform.platform(), "python": sys.version, "cpu_count": os.cpu_count(),
            "affinity": sorted(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else None,
            "dot_runtime_observable": False, "exclusive_host": False},
        "authority": "DENY_ALL", "safety_certificate": False}
    save(output / "RESULT.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--identity", type=Path, required=True)
    parser.add_argument("--build-envelope", type=Path, required=True)
    parser.add_argument("--clang", default=os.environ.get("CLANG", "clang"))
    parser.add_argument("--protocol", type=Path, default=PROTOCOL_PATH)
    args = parser.parse_args()
    started = time.monotonic_ns()
    output_existed = args.output.exists()
    try:
        result = qualify(args.output, args.identity, args.build_envelope, args.clang, args.protocol)
    except Exception as error:
        if not output_existed and args.output.is_dir() and (args.output / "REGISTRATION.json").is_file():
            save(args.output / "FAILURE.json", {"schema": "hepta.hia.ndu.activation.failure.v1",
                "error": f"{type(error).__name__}: {error}", "wall_ns": time.monotonic_ns() - started,
                "all_prior_observations_retained": True, "registered_full_cost_advantage": False,
                "scope": "driver invocation after imports/argparse through failure; final receipt encoding excluded",
                "authority": "DENY_ALL", "safety_certificate": False})
        raise
    print(json.dumps({key: result[key] for key in ("source_commit", "source_unchanged",
        "all_application_outputs_and_budgets_admitted", "registered_full_cost_advantage",
        "application_totals", "application_profile_totals")}, indent=2))


if __name__ == "__main__":
    main()
