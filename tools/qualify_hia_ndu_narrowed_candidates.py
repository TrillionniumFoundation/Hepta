#!/usr/bin/env python3
"""Measure real narrowed candidates with matched fixed/greedy/DP/NDU controls.

This is a separately frozen follow-up, not a rescore of earlier negative runs.
The framework remains advisory. Every deployed candidate is independently
proved, built and sealed by the same bounded session available to every arm.
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
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from hepta.hia_artifact_session import PreparedArtifactSession
from hepta.hia_guarded_optimization import propose_guarded_reduction
from hepta.hia_narrowing import propose_guarded_narrowing
from hepta.hia_ndu import _read_json
from hepta.hia_ndu_session import STREAM_SOURCE_PIN
from hepta.hia_optimization import DEFAULT_POLICY
from hepta.hia_program_source import lower_source
from hepta.native_tool_identity import digest_executable
from tools.qualify_hia_ndu_activation import checksum
from tools.qualify_hia_ndu_graph import DRIVER
from tools.qualify_hia_ndu_loop import EpisodeBudget, digest, measured
from tools.qualify_hia_ndu_net_value import (
    CompilationCredits, complete_budget_dp, new_bridge, save, select_native,
    validate_build_envelope)

MODULES = ("byte_sum", "packet_xor")
TARGETS = ("base", "guarded", "guarded-narrowed")
ARMS = ("fixed", "feedback-greedy", "dp", "native-stream-sealed")
COMPARATORS = ARMS[:-1]
PROFILE = ROOT / "experiments/hia_ndu_narrowed_candidates"
PROTOCOL = PROFILE / "PROTOCOL_20261030.json"
WORKLOADS = ROOT / "experiments/hia_ndu_activation"


def validate_protocol(p):
    if (p.get("schema") != "hepta.hia.ndu.narrowed-candidates.protocol.v1"
            or p.get("native_source_pin") != STREAM_SOURCE_PIN
            or p.get("native_rustc") != "1.90.0" or p.get("modules") != list(MODULES)
            or p.get("targets") != list(TARGETS) or p.get("arms") != list(ARMS)
            or p.get("groups") != 4 or p.get("calls") != 65535
            or p.get("calibration_repetitions") != 2 or p.get("sizes") != [127, 4093, 4097]
            or p.get("trace") != [4093] * 6 + [127, 4097]
            or p.get("guard_maximum") != 4096 or p.get("compile_credits") != 1
            or p.get("training_seed") != 17 or p.get("holdout_seed") != 113
            or p.get("proof_policy") != dict(DEFAULT_POLICY, timeout_ms=30000)
            or p.get("session_limits") != {"max_entries": 8, "max_retained_bytes": 33554432,
                "max_artifact_bytes": 1048576, "max_metadata_bytes": 1048576,
                "max_leases": 4, "max_executions": 256}
            or p.get("controller_timeout_s") != 10
            or p.get("episode_budget_ns") != 180000000000
            or p.get("completion_value_ns") != 240000000000
            or p.get("authority") != "DENY_ALL" or p.get("safety_certificate") is not False
            or p.get("previous_negative_results_replaced") is not False):
        raise ValueError("unsupported frozen narrowed-candidate protocol")
    return p


def new_owner(folder, clang, p, driver, driver_sha):
    owner = PreparedArtifactSession(folder, clang=clang, policy=p["proof_policy"], **p["session_limits"])
    try:
        owner.bind_driver(driver, driver_sha)
    except BaseException:
        owner.close()
        raise
    return owner


def prepare(owner, base, base_entry, target, p):
    if target == "base":
        return owner.prepare_base(base)
    if target == "guarded":
        proposal = propose_guarded_reduction(base, maximum=p["guard_maximum"])
        return owner.prepare_guarded(base_entry["token"], proposal)
    if target == "guarded-narrowed":
        proposal = propose_guarded_narrowing(base, maximum=p["guard_maximum"])
        return owner.prepare_guarded_narrowed(base_entry["token"], proposal)
    raise ValueError("unknown prepared candidate")


def observe(owner, entry, module, n, calls, seed, timeout):
    started = time.monotonic_ns()
    before = owner.snapshot()["proof_attempts"]
    with owner.lease(entry["token"]) as lease:
        remaining = timeout - (time.monotonic_ns() - started) / 1e9
        if remaining <= 0:
            raise RuntimeError("lease admission consumed delivery budget")
        row = lease.run(n, calls, seed, timeout=min(120, remaining))
    row.update(module=module, n=n, calls=calls, seed=seed)
    row["run_status"] = row["status"]
    if row["status"] == "completed":
        output = json.loads(row["stdout"])
        expected = checksum(module, n, calls, seed)
        row.update(output=output, expected_checksum=expected)
        row["status"] = "measured" if (output["checksum"] == expected
            and output["loaded_mapping_verified"] is True and row["new_solver_call"] is False
            and owner.snapshot()["proof_attempts"] == before) else "wrong-output-or-binding"
    row["delivery_cost_ns"] = time.monotonic_ns() - started
    return row


def native_text(objcopy, path, output):
    source_sha = sha256(Path(path).read_bytes()).hexdigest()
    command = [objcopy, "--dump-section", ".text=" + str(output), str(path),
               str(output.with_suffix(".inspection.elf"))]
    completed = subprocess.run(command, capture_output=True, timeout=30, check=False)
    source_unchanged = sha256(Path(path).read_bytes()).hexdigest() == source_sha
    save(output.with_suffix(".command.json"), {"command": command, "returncode": completed.returncode,
        "source_sha256": source_sha, "source_unchanged": source_unchanged,
        "stdout": completed.stdout.decode(errors="replace"), "stderr": completed.stderr.decode(errors="replace")})
    if completed.returncode or not source_unchanged or not output.is_file() or not output.stat().st_size:
        raise RuntimeError("actual native .text extraction failed")
    raw = output.read_bytes()
    return {"bytes": len(raw), "sha256": sha256(raw).hexdigest()}


def calibrate(folder, bases, clang, objcopy, driver, driver_sha, p):
    folder.mkdir()
    started, ledger, bank, owner = time.monotonic_ns(), [], {}, None
    try:
        owner = measured("session.create", ledger, lambda: new_owner(folder / "images", clang, p, driver, driver_sha))
        for module in MODULES:
            bank[module], base_entry = {}, None
            for target in TARGETS:
                setup_started = time.monotonic_ns()
                entry = measured("prepare." + module + "." + target, ledger,
                    lambda: prepare(owner, bases[module], base_entry, target, p))
                setup_ns = time.monotonic_ns() - setup_started
                if target == "base":
                    base_entry = entry
                receipt = owner._entries[entry["token"]].image.receipt
                text = native_text(objcopy, receipt["native"]["output"], folder / (module + "." + target + ".text"))
                bank[module][target] = {"entry": entry, "setup_ns": setup_ns, "receipt": receipt,
                    "native_text": text, "samples": []}
                save(folder / (module + "." + target + ".admission.json"), bank[module][target])
        observations = []
        for rep in range(p["calibration_repetitions"]):
            for n in p["sizes"]:
                for offset, module in enumerate(MODULES):
                    order = TARGETS[(rep + offset) % 3:] + TARGETS[:(rep + offset) % 3]
                    for target in order:
                        candidate = bank[module][target]
                        row = measured(f"sample.{rep}.{module}.{target}.{n}", ledger,
                            lambda: observe(owner, candidate["entry"], module, n, p["calls"], p["training_seed"], 120))
                        row.update(target=target, repetition=rep)
                        observations.append(row)
                        candidate["samples"].append(row)
                        save(folder / f"sample-{len(observations):04d}.json", row)
                        if row["status"] != "measured":
                            raise RuntimeError("actual calibration failed")
        for module in MODULES:
            for target in TARGETS:
                candidate = bank[module][target]
                candidate["latency_ns"] = {str(n): round(statistics.median(row["delivery_cost_ns"]
                    for row in candidate["samples"] if row["n"] == n)) for n in p["sizes"]}
    finally:
        if owner is not None:
            measured("session.close", ledger, owner.close)
            state = owner.snapshot()
            save(folder / "SESSION_CLOSED.json", state)
            if not state["owned_native_release_complete"]:
                raise RuntimeError("calibration has unresolved release debt")
    result = {"modules": bank, "ledger": ledger, "wall_ns": time.monotonic_ns() - started,
        "different_native_text": {module: bank[module]["base"]["native_text"]["sha256"]
            != bank[module]["guarded-narrowed"]["native_text"]["sha256"] for module in MODULES},
        "session_closed": state, "observations": len(observations)}
    result["bank_sha256"] = digest(result)
    save(folder / "BANK.json", result)
    return result


def allocation_model(bank, modules, trace, epoch, observed, artifacts, credits, *, current_epoch_only=False):
    choices = []
    horizon = trace[epoch:epoch + 1] if current_epoch_only else trace[epoch:]
    for module in modules:
        options = []
        for target in TARGETS:
            candidate = bank["modules"][module][target]
            costs = []
            for n in horizon:
                actual = [row["delivery_cost_ns"] for row in observed if row["module"] == module
                    and row["target"] == target and row["n"] == n and row["status"] == "measured"]
                costs.append(round(statistics.median(actual)) if actual else candidate["latency_ns"][str(n)])
            new_build = (module, target) not in artifacts
            options.append({"target": target, "credits": int(new_build),
                "cost_ns": sum(costs) + (candidate["setup_ns"] if new_build else 0),
                "verified": candidate["receipt"]["verification"]["status"] == "verified"})
        choices.append(options)
    return {"modules": choices, "remaining_credits": credits.remaining,
        "modeled_horizon": horizon,
        "support": digest({"bank": bank["bank_sha256"], "modules": modules, "epoch": epoch,
            "horizon": horizon, "observations": observed, "artifacts": sorted(artifacts)})}


def feedback_greedy(model):
    """Spend the one shared credit only on a positive current-epoch saving.

    Available images cost no new credit. Starting from the cheapest admitted
    image for each module, choose the largest positive single-build saving.
    The registered model includes this build's complete measured setup cost
    and only the current input. No suffix costs or future observations enter.
    """
    if model["remaining_credits"] not in (0, 1):
        raise ValueError("registered feedback control supports at most one credit")
    selected = []
    for choices in model["modules"]:
        available = [row for row in choices if row["verified"] and row["credits"] == 0]
        if not available:
            return None
        selected.append(min(available, key=lambda row: (row["cost_ns"], row["target"])))
    if model["remaining_credits"]:
        improvements = [(selected[index]["cost_ns"] - row["cost_ns"], index, row)
            for index, choices in enumerate(model["modules"]) for row in choices
            if row["verified"] and row["credits"] == 1 and row["cost_ns"] < selected[index]["cost_ns"]]
        if improvements:
            _, index, choice = min(improvements,
                key=lambda item: (-item[0], item[1], item[2]["target"]))
            selected[index] = choice
    targets = [row["target"] for row in selected]
    return {"id": "allocation-" + digest(targets)[:20], "targets": targets,
        "credits": sum(row["credits"] for row in selected),
        "cost_ns": sum(row["cost_ns"] for row in selected), "verified": True}


def episode(folder, arm, group, bases, bank, clang, driver, driver_sha, p, manifest, identity,
            *, only_module=None, forced_target=None):
    started, ledger, observed, decisions, artifacts = time.monotonic_ns(), [], [], [], {}
    folder.mkdir()
    modules = [only_module] if only_module else list(MODULES)
    credits = CompilationCredits(p["compile_credits"])
    budget = EpisodeBudget(started, p["episode_budget_ns"])
    owner, bridge, fixed = None, None, None
    result = {"arm": arm, "group": group, "modules": modules, "status": "running",
        "ledger": ledger, "observations": observed, "decisions": decisions,
        "same_initial_information": bank["bank_sha256"], "future_timing_access": False,
        "forced_post_run_control": forced_target}
    def stage(label, operation):
        return budget.stage(label, ledger, operation)
    try:
        owner = stage("session.create", lambda: new_owner(folder / "images", clang, p, driver, driver_sha))
        if arm == "native-stream-sealed":
            bridge = stage("native.open", lambda: new_bridge(arm, manifest, identity, folder / "native", p))
        for module in modules:
            artifacts[module, "base"] = stage("base." + module, lambda: prepare(owner, bases[module], None, "base", p))
        for epoch, n in enumerate(p["trace"]):
            model, evidence = None, None
            if forced_target is not None:
                selected = {"targets": [forced_target]}
            elif arm == "fixed" and fixed is not None:
                selected = fixed
            else:
                model = stage("model." + str(epoch), lambda: allocation_model(bank, modules, p["trace"],
                    epoch, observed, artifacts, credits, current_epoch_only=arm == "feedback-greedy"))
                if bridge is not None:
                    selected, evidence = stage("control." + str(epoch), lambda: select_native(model, p,
                        group * 1000 + epoch + 1, bridge))
                elif arm == "feedback-greedy":
                    selected = stage("control." + str(epoch), lambda: feedback_greedy(model))
                else:
                    selected = stage("control." + str(epoch), lambda: complete_budget_dp(model))
                if selected is None:
                    raise RuntimeError("no feasible finite allocation")
                if arm == "fixed":
                    fixed = selected
            decisions.append({"epoch": epoch, "model": model, "selected": selected, "evidence": evidence})
            for module, target in zip(modules, selected["targets"]):
                key = module, target
                if key not in artifacts:
                    credits.consume(module, target)
                    artifacts[key] = stage("candidate." + module + "." + target,
                        lambda: prepare(owner, bases[module], artifacts[module, "base"], target, p))
                row = stage(f"deliver.{epoch}.{module}.{target}", lambda: observe(owner, artifacts[key],
                    module, n, p["calls"], p["holdout_seed"] + group, budget.remaining_ns() / 1e9))
                row.update(target=target, epoch=epoch)
                observed.append(row)
                save(folder / f"sample-{len(observed):04d}.json", row)
                if row["status"] != "measured":
                    raise RuntimeError("actual output, native mapping or reuse check failed")
        result["status"] = "completed"
    except Exception as error:
        result.update(status="failed", error=f"{type(error).__name__}: {error}")
    finally:
        for name, value in (("native", bridge), ("artifact", owner)):
            if value is not None:
                try:
                    measured(name + ".shutdown", ledger, value.close)
                except Exception as error:
                    result.update(status="failed", shutdown_error=f"{type(error).__name__}: {error}")
                result[name + "_session"] = value.snapshot()
    result["credits"] = {"used": credits.used, "limit": credits.limit, "attempts": credits.attempts}
    result["artifacts"] = [{"module": module, "target": target, "entry": entry}
        for (module, target), entry in sorted(artifacts.items())]
    save(folder / "RESULT.json", result)
    result["wall_ns"] = time.monotonic_ns() - started
    result["admitted"] = (result["status"] == "completed" and result["wall_ns"] <= p["episode_budget_ns"]
        and len(observed) == len(modules) * len(p["trace"]) and credits.used <= credits.limit
        and result.get("artifact_session", {}).get("owned_native_release_complete") is True)
    return result


def frozen_sources(protocol):
    if subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT):
        raise RuntimeError("prospective registration requires clean committed source")
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    paths = sorted((ROOT / "hepta").glob("*.py")) + [Path(__file__), protocol,
        *[ROOT / "tools" / name for name in ("qualify_hia_ndu_activation.py", "qualify_hia_ndu_graph.py",
            "qualify_hia_ndu_loop.py", "qualify_hia_ndu_net_value.py", "measure_hia_ndu_build.py",
            "build_hia_recursive_ndu_bridge.py")],
        *[WORKLOADS / (module + ".hepta") for module in MODULES]]
    source = {}
    for path in paths:
        name, raw = str(path.relative_to(ROOT)), path.read_bytes()
        if subprocess.check_output(["git", "cat-file", "blob", commit + ":" + name], cwd=ROOT) != raw:
            raise RuntimeError("source differs from commit: " + name)
        source[name] = sha256(raw).hexdigest()
    return commit, source


def qualify(output, identity, build_envelope, clang, objcopy):
    started = time.monotonic_ns()
    output, identity = Path(output).resolve(), Path(identity).resolve()
    if output.is_relative_to(ROOT):
        raise ValueError("raw output must be external to the source checkout")
    p = validate_protocol(json.loads(PROTOCOL.read_bytes()))
    commit, sources = frozen_sources(PROTOCOL)
    manifest_raw, envelope_raw = identity.read_bytes(), Path(build_envelope).read_bytes()
    manifest, envelope = _read_json(manifest_raw), _read_json(envelope_raw)
    if (manifest.get("identity", {}).get("source_commit") != STREAM_SOURCE_PIN
            or not manifest["identity"].get("rustc", "").startswith("rustc 1.90.0 ")):
        raise ValueError("native controller differs from the frozen source/tool")
    # A separately committed builder checkpoint is allowed only with identical
    # actual builder bytes, identity, upstream source and empty-target receipt.
    # Its original source_commit is retained; it is not relabelled as this one.
    build_ns = validate_build_envelope(envelope, manifest, manifest_raw, envelope["source_commit"])
    tools = {}
    for name, executable in (("clang", clang), ("objcopy", objcopy), ("python", sys.executable)):
        found = shutil.which(executable)
        if found is None:
            raise ValueError("actual executable unavailable: " + name)
        path = str(Path(found).resolve())
        tools[name] = {"path": path, "sha256": digest_executable(path)}
    output.mkdir(parents=True, exist_ok=False)
    save(output / "REGISTRATION.json", {"source_commit": commit, "source_sha256": sources, "protocol": p,
        "protocol_sha256": sha256(PROTOCOL.read_bytes()).hexdigest(), "tools": tools,
        "registered_utc": datetime.now(timezone.utc).isoformat(), "native_build_source_commit": envelope["source_commit"]})
    (output / "NATIVE_IDENTITY.json").write_bytes(manifest_raw)
    (output / "NATIVE_BUILD_ENVELOPE.json").write_bytes(envelope_raw)
    bases = {module: lower_source((WORKLOADS / (module + ".hepta")).read_text()) for module in MODULES}
    (output / "driver.c").write_text(DRIVER)
    driver = output / "driver"
    command = [tools["clang"]["path"], "-O3", "-std=c11", str(output / "driver.c"), "-ldl", "-o", str(driver)]
    compiled = subprocess.run(command, capture_output=True, timeout=60, check=False)
    save(output / "DRIVER_BUILD.json", {"command": command, "returncode": compiled.returncode,
        "stdout": compiled.stdout.decode(errors="replace"), "stderr": compiled.stderr.decode(errors="replace")})
    if compiled.returncode:
        raise RuntimeError("actual driver build failed")
    driver_sha = digest_executable(driver)
    bank = calibrate(output / "calibration", bases, tools["clang"]["path"], tools["objcopy"]["path"], driver, driver_sha, p)
    common_ns, records = time.monotonic_ns() - started, []
    for group in range(p["groups"]):
        order = ARMS[group:] + ARMS[:group]
        for arm in order:
            row = episode(output / f"policy-{group}-{arm}", arm, group, bases, bank,
                tools["clang"]["path"], driver, driver_sha, p, manifest, identity)
            records.append(row)
            print(json.dumps({"arm": arm, "group": group, "admitted": row["admitted"],
                "wall_ns": row["wall_ns"], "builds": row["credits"]["used"]}), flush=True)
    policy_finished = time.monotonic_ns()
    controls, control_started = [], time.monotonic_ns()
    for index, module in enumerate(MODULES):
        for target in TARGETS[index:] + TARGETS[:index]:
            row = episode(output / ("control-" + module + "-" + target), "opportunity-" + target, 0,
                bases, bank, tools["clang"]["path"], driver, driver_sha, p, manifest, identity,
                only_module=module, forced_target=target)
            controls.append(row)
            print(json.dumps({"module": module, "target": target, "admitted": row["admitted"],
                "wall_ns": row["wall_ns"]}), flush=True)
    control_ns, check_started = time.monotonic_ns() - control_started, time.monotonic_ns()
    unchanged = all(sha256((ROOT / name).read_bytes()).hexdigest() == expected for name, expected in sources.items())
    unchanged = unchanged and subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip() == commit
    unchanged = unchanged and not subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT)
    tool_unchanged = all(digest_executable(row["path"]) == row["sha256"] for row in tools.values())
    tool_unchanged = tool_unchanged and digest_executable(driver) == driver_sha and identity.read_bytes() == manifest_raw
    residual_ns = max(0, policy_finished - started - common_ns - sum(row["wall_ns"] for row in records))
    residual_ns += time.monotonic_ns() - check_started
    warm = {arm: common_ns + sum(row["wall_ns"] for row in records if row["arm"] == arm)
        + (residual_ns if arm == "native-stream-sealed" else 0) for arm in ARMS}
    cold = {arm: cost + (build_ns if arm == "native-stream-sealed" else 0) for arm, cost in warm.items()}
    audits = []
    for row in records:
        if row["arm"] == "native-stream-sealed":
            for decision in row["decisions"]:
                oracle, selected = complete_budget_dp(decision["model"]), decision["selected"]
                audits.append({"group": row["group"], "epoch": decision["epoch"],
                    "same_exact_dp_plan": oracle == selected,
                    "modeled_cost_regret_ns": selected["cost_ns"] - oracle["cost_ns"],
                    "selected_targets": selected["targets"]})
    opportunity = {}
    for module in MODULES:
        rows = {row["forced_post_run_control"]: row for row in controls if row["modules"] == [module]}
        opportunity[module] = {target: {"both_admitted": rows["base"]["admitted"] and rows[target]["admitted"],
            "baseline_minus_candidate_ns": rows["base"]["wall_ns"] - rows[target]["wall_ns"]}
            for target in TARGETS[1:]}
    valid = (unchanged and tool_unchanged and len(records) == p["groups"] * len(ARMS)
        and all(row["admitted"] for row in records + controls)
        and all(bank["different_native_text"].values()))
    result = {"schema": "hepta.hia.ndu.narrowed-candidates.result.v1", "source_commit": commit,
        "source_unchanged": unchanged, "tool_inputs_unchanged": tool_unchanged,
        "module_core_sha256": {name: value.sha256 for name, value in bases.items()},
        "different_guarded_narrowed_native_text": bank["different_native_text"],
        "calibration_bank_sha256": bank["bank_sha256"], "common_setup_ns": common_ns,
        "conservative_residual_charged_to_ndu_ns": residual_ns, "native_build_ns": build_ns,
        "native_build_source_commit": envelope["source_commit"], "native_build_identity_sha256": sha256(manifest_raw).hexdigest(),
        "policy_episodes": records, "opportunity_controls": controls, "opportunity_analysis": opportunity,
        "standalone_warm_ns": warm, "standalone_with_reported_empty_target_build_ns": cold,
        "actual_same_model_dp_audit": audits,
        "functional_gate": valid,
        "observed_warm_net_cost_gate": valid and all(warm["native-stream-sealed"] < warm[a] for a in COMPARATORS),
        "observed_build_inclusive_net_cost_gate": valid and all(cold["native-stream-sealed"] < cold[a] for a in COMPARATORS),
        "post_run_opportunity_controls_ns": control_ns,
        "total_study_ns_before_final_encoding": time.monotonic_ns() - started,
        "shared_prepared_reuse_is_not_ndu_advantage": True, "previous_negative_results_replaced": False,
        "statistical_superiority_established": False, "global_optimality_established": False,
        "host": {"platform": platform.platform(), "python": sys.version, "exclusive": False,
            "physical_dot_verified": False, "affinity": sorted(os.sched_getaffinity(0))},
        "authority": "DENY_ALL", "safety_certificate": False}
    save(output / "RESULT.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--identity", type=Path, required=True)
    parser.add_argument("--build-envelope", type=Path, required=True)
    parser.add_argument("--clang", default=os.environ.get("CLANG", "clang"))
    parser.add_argument("--objcopy", default="objcopy")
    args = parser.parse_args()
    started, existed = time.monotonic_ns(), args.output.exists()
    try:
        result = qualify(args.output, args.identity, args.build_envelope, args.clang, args.objcopy)
    except Exception as error:
        if not existed and (args.output / "REGISTRATION.json").is_file():
            save(args.output / "FAILURE.json", {"error": f"{type(error).__name__}: {error}",
                "wall_ns": time.monotonic_ns() - started, "all_prior_observations_retained": True,
                "functional_gate": False, "observed_build_inclusive_net_cost_gate": False})
        raise
    print(json.dumps({key: result[key] for key in ("source_commit", "functional_gate",
        "observed_warm_net_cost_gate", "observed_build_inclusive_net_cost_gate", "standalone_warm_ns",
        "standalone_with_reported_empty_target_build_ns", "opportunity_analysis")}, indent=2))


if __name__ == "__main__":
    main()
