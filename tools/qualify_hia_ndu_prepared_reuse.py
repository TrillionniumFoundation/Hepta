#!/usr/bin/env python3
"""Prospective NDU comparison with actual bounded internal artifact reuse.

Every policy receives identical prepared-image eligibility. This experiment
does not attribute a shared proof-reuse benefit to the NDU algorithm, and it
does not replace the earlier fresh-proof negative experiment.
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

from hepta.hia_artifact_session import PreparedArtifactSession
from hepta.hia_guarded_optimization import propose_guarded_reduction, verify_guarded_optimization
from hepta.hia_ndu import _read_json
from hepta.hia_ndu_session import STREAM_SOURCE_PIN
from hepta.hia_optimization import DEFAULT_POLICY, verify_optimization
from hepta.hia_program_source import lower_source
from hepta.native_tool_identity import digest_executable
from tools.qualify_hia_ndu_activation import (
    MODULES, TARGETS, PROFILE as PROGRAMS, allocation_model, calibration_order,
    checksum, decision_analysis)
from tools.qualify_hia_ndu_graph import DRIVER
from tools.qualify_hia_ndu_loop import EpisodeBudget, digest, measured
from tools.qualify_hia_ndu_net_value import (
    APPLICATION_ARMS, CompilationCredits, complete_budget_dp, new_bridge,
    rotated, save, select_native, validate_build_envelope)

PROFILE = ROOT / "experiments/hia_ndu_prepared_reuse"
PROTOCOL_PATH = PROFILE / "PROTOCOL_20261029.json"
PROFILES = ("short-lived", "stable-reuse", "changing-load", "shared-budget")


def validate_protocol(p):
    if (p.get("schema") != "hepta.hia.ndu.prepared-reuse.protocol.v1"
            or p.get("purpose") not in {"qualification", "functional-smoke"}
            or p.get("native_source_pin") != STREAM_SOURCE_PIN
            or p.get("native_rustc") != "1.90.0"
            or p.get("modules") != list(MODULES) or p.get("arms") != list(APPLICATION_ARMS)
            or p.get("guard_limits") != {"guard-small": 128, "guard-wide": 4096}
            or p.get("calibration_sizes") != [127, 4093, 32749]
            or p.get("proof_policy") != dict(DEFAULT_POLICY, timeout_ms=30000)
            or p.get("authority") != "DENY_ALL" or p.get("safety_certificate") is not False
            or p.get("previous_negative_results_replaced") is not False):
        raise ValueError("unsupported prospective prepared-reuse profile")
    for key, lo, hi in (("groups", 1, 3), ("calls", 1, 1_000_000),
            ("calibration_repetitions", 1, 4), ("training_seed", 0, 255),
            ("holdout_seed", 0, 254), ("episode_budget_ns", 1, 1_000_000_000_000),
            ("completion_value_ns", 1, 1_000_000_000_000), ("proof_reuse_pairs", 1, 4)):
        if type(p.get(key)) is not int or not lo <= p[key] <= hi:
            raise ValueError("invalid bounded integer: " + key)
    if (type(p.get("controller_timeout_s")) not in {int, float}
            or not 0 < p["controller_timeout_s"] <= 120
            or list(p.get("application_profiles", {})) != list(PROFILES)
            or p.get("session_limits") != {"max_entries": 8, "max_retained_bytes": 33554432,
                "max_artifact_bytes": 1048576, "max_metadata_bytes": 1048576,
                "max_leases": 4, "max_executions": 256}):
        raise ValueError("invalid finite profile inventory or runtime limits")
    for profile, spec in p["application_profiles"].items():
        ids, traces = spec["modules"], spec["module_sizes"]
        if (type(spec["compile_credits"]) is not int or spec["compile_credits"] != 1
                or not 1 <= len(ids) <= 2 or len(set(ids)) != len(ids)
                or any(name not in MODULES for name in ids) or len(ids) != len(traces)
                or not 2 <= len(traces[0]) <= 32 or len({len(row) for row in traces}) != 1
                or any(type(n) is not int or n not in p["calibration_sizes"] for row in traces for n in row)
                or (profile == "shared-budget" and ids != list(MODULES))):
            raise ValueError("invalid finite module trace")
    return p


def new_owner(folder, clang, p):
    return PreparedArtifactSession(folder, clang=clang, policy=p["proof_policy"], **p["session_limits"])


def reuse_sample(owner, entry, module, *, n, calls, seed, timeout):
    started = time.monotonic_ns()
    before = owner.snapshot()["proof_attempts"]
    with owner.lease(entry["token"]) as lease:
        remaining = timeout - (time.monotonic_ns() - started) / 1e9
        if remaining <= 0:
            raise RuntimeError("delivery deadline exhausted during lease admission")
        row = lease.run(n, calls, seed, timeout=min(120, remaining))
    row["run_status"] = row["status"]
    after = owner.snapshot()["proof_attempts"]
    row.update(proof_attempts_before=before, proof_attempts_after=after,
               lease_acquisition_and_release_included=True)
    if row["run_status"] != "completed":
        row.update(status="failed", delivery_cost_ns=time.monotonic_ns() - started)
        return row
    output = json.loads(row["stdout"])
    expected = checksum(module, n, calls, seed)
    row.update(output)
    row.update(expected_checksum=expected,
        status="measured" if (output["checksum"] == expected and output["loaded_mapping_verified"] is True
                               and before == after and row["new_solver_call"] is False) else "wrong-output-or-binding",
        delivery_cost_ns=time.monotonic_ns() - started)
    return row


def calibrate(bases, folder, driver, driver_sha, clang, p):
    folder.mkdir()
    ledger, banks, owner, observations = [], {}, None, []
    def stage(label, operation):
        try:
            return measured(label, ledger, operation)
        finally:
            save(folder / f"stage-{len(ledger):04d}.json", ledger[-1])
    try:
        owner = stage("session.create", lambda: new_owner(folder / "images", clang, p))
        stage("driver.bind", lambda: owner.bind_driver(driver, driver_sha))
        for module, base in bases.items():
            candidates, baseline = {}, None
            for target in TARGETS:
                before = time.monotonic_ns()
                proposal = None if target == "base" else stage("propose." + module + "." + target,
                    lambda: propose_guarded_reduction(base, maximum=p["guard_limits"][target]))
                entry = stage("prepare." + module + "." + target,
                    lambda: owner.prepare_base(base) if proposal is None
                    else owner.prepare_guarded(baseline["token"], proposal))
                if target == "base":
                    baseline = entry
                # This read records the internally produced proof as evidence.
                # No external receipt is ever imported to authorize execution.
                receipt = deepcopy(owner._entries[entry["token"]].image.receipt)
                candidates[target] = {"entry": entry, "setup_ns": time.monotonic_ns() - before,
                    "receipt": receipt, "verification": receipt["verification"],
                    "proposal": proposal, "proposal_sha256": digest(proposal), "samples": []}
                save(folder / (module + "." + target + ".admission.json"), candidates[target])
            rejected = stage("refuse.unguarded." + module,
                lambda: verify_optimization(base, candidates["guard-wide"]["proposal"]["fast_core"], policy=p["proof_policy"]))
            save(folder / (module + ".unguarded-refusal.json"), rejected)
            if rejected["status"] != "rejected":
                raise RuntimeError("unguarded negative control was not rejected")
            banks[module] = {"base_sha256": base.sha256, "candidates": candidates, "unguarded_refusal": rejected}
        for rep in range(p["calibration_repetitions"]):
            for size_index, n in enumerate(p["calibration_sizes"]):
                for module, target in calibration_order(rep, size_index):
                    candidate = banks[module]["candidates"][target]
                    row = stage(f"reuse.{rep}.{n}.{module}.{target}", lambda: reuse_sample(owner, candidate["entry"], module,
                        n=n, calls=p["calls"], seed=p["training_seed"], timeout=120))
                    row.update(module=module, state=target, n=n, repetition=rep,
                               declared_fast_guard_holds=target != "base" and n <= p["guard_limits"][target])
                    candidate["samples"].append(row)
                    observations.append(row)
                    save(folder / f"sample-{len(observations):04d}.json", row)
                    if row["status"] != "measured":
                        raise RuntimeError("calibration checksum, mapping or proof-reuse check failed")
        for bank in banks.values():
            for row in bank["candidates"].values():
                row["latency_ns"] = {str(n): round(statistics.median(s["delivery_cost_ns"] for s in row["samples"] if s["n"] == n))
                    for n in p["calibration_sizes"]}
        # Paired mechanism control: same admitted bytes and identity checks;
        # the fresh arm additionally solves the exact guarded theorem again.
        pairs = []
        for repetition in range(p["proof_reuse_pairs"]):
            for module in MODULES:
                candidate = banks[module]["candidates"]["guard-wide"]
                for arm in rotated(("fresh-equivalence", "prepared-equivalence"), repetition, MODULES.index(module)):
                    before = time.monotonic_ns()
                    proof = None
                    if arm == "fresh-equivalence":
                        proof = stage("mechanism.fresh." + module,
                            lambda: verify_guarded_optimization(bases[module], candidate["proposal"], policy=p["proof_policy"]))
                        if (proof["status"] != "verified"
                                or proof["candidate_sha256"] != candidate["entry"]["core_sha256"]
                                or proof["policy_sha256"] != digest(p["proof_policy"])):
                            raise RuntimeError("mechanism control reproof binding failed")
                    row = stage("mechanism.execute." + module, lambda: reuse_sample(owner, candidate["entry"], module,
                        n=4093, calls=p["calls"], seed=p["training_seed"], timeout=120))
                    pair = {"arm": arm, "module": module, "repetition": repetition,
                        "wall_ns": time.monotonic_ns() - before, "fresh_verification": proof, "observation": row}
                    pairs.append(pair)
                    save(folder / f"mechanism-{len(pairs):04d}.json", pair)
                    if row["status"] != "measured":
                        raise RuntimeError("proof-reuse mechanism control output failed")
        bank = {"schema": "hepta.hia.ndu.prepared-reuse.bank.v1", "modules": banks,
                "ledger": ledger, "proof_reuse_control": pairs, "timing_information": "calibration only"}
    finally:
        if owner is not None:
            stage("session.close", owner.close)
            state = owner.snapshot()
            save(folder / "SESSION_CLOSED.json", state)
            if not state["owned_native_release_complete"]:
                raise RuntimeError("calibration retained native-release debt")
    bank["session_closed"] = state
    bank["bank_sha256"] = digest(bank)
    save(folder / "BANK.json", bank)
    return bank


def episode(folder, arm, profile, group, p, manifest, identity, bases, bank, driver, driver_sha, clang,
            *, forced_targets=None, spec_override=None):
    started, ledger, observations, artifacts = time.monotonic_ns(), [], [], {}
    folder.mkdir()
    budget = EpisodeBudget(started, p["episode_budget_ns"])
    spec, bridge, owner = spec_override or p["application_profiles"][profile], None, None
    credits = CompilationCredits(spec["compile_credits"])
    record = {"arm": arm, "profile": profile, "group": group, "status": "running", "ledger": ledger,
        "observations": observations, "decisions": [], "same_initial_information": bank["bank_sha256"],
        "module_ids": spec["modules"], "future_timing_access": False,
        "forced_post_run_opportunity_control": forced_targets is not None}
    def stage(label, operation):
        try:
            return budget.stage(label, ledger, operation)
        finally:
            if ledger:
                save(folder / f"stage-{len(ledger):04d}.json", ledger[-1])
    def admit(module, target):
        key = module, target
        if key not in artifacts:
            base, row = bases[module], bank["modules"][module]["candidates"][target]
            if target == "base":
                info = stage("base-prepare." + module, lambda: owner.prepare_base(base,
                    max_prepare_ns=min(120_000_000_000, budget.remaining_ns())))
            else:
                credits.consume(module, target)
                proposal = stage("propose." + module + "." + target,
                    lambda: propose_guarded_reduction(base, maximum=p["guard_limits"][target]))
                if digest(proposal) != row["proposal_sha256"]:
                    raise RuntimeError("proposal differs from the calibration source")
                info = stage("candidate-prepare." + module + "." + target,
                    lambda: owner.prepare_guarded(artifacts[(module, "base")]["token"], proposal,
                        max_prepare_ns=min(120_000_000_000, budget.remaining_ns())))
            artifacts[key] = info
            save(folder / (module + "." + target + ".admission.json"), {
                "entry": info, "receipt": owner._entries[info["token"]].image.receipt})
        return artifacts[key]
    def deliver(module, target, n, epoch):
        info = admit(module, target)
        row = stage(f"execute.{epoch}.{module}.{target}", lambda: reuse_sample(owner, info, module,
            n=n, calls=p["calls"], seed=(p["holdout_seed"] + group) & 255,
            timeout=min(120, budget.remaining_ns() / 1e9)))
        row.update(module=module, state=target, n=n, epoch=epoch,
                   declared_fast_guard_holds=target != "base" and n <= p["guard_limits"][target])
        observations.append(row)
        save(folder / f"sample-{len(observations):04d}.json", row)
        if row["status"] != "measured":
            raise RuntimeError("application checksum, mapping or proof-reuse binding failed")
    try:
        owner = stage("session.create", lambda: new_owner(folder / "images", clang, p))
        stage("driver.bind", lambda: owner.bind_driver(driver, driver_sha))
        if arm.startswith("native"):
            bridge = stage("native.admission", lambda: new_bridge(arm, manifest, identity, folder / "native", p))
        for module in spec["modules"]:
            deliver(module, "base", p["calibration_sizes"][0], -1)
        fixed = None
        for epoch in range(len(spec["module_sizes"][0])):
            if forced_targets is not None:
                model, selected, evidence = None, {"targets": list(forced_targets)}, {"post_run_control": True}
            elif arm == "fixed" and fixed is not None:
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
        for label, value in (("native", bridge), ("artifact", owner)):
            if value is not None:
                try:
                    measured(label + ".shutdown", ledger, value.close)
                except Exception as error:
                    record.update(status="failed", shutdown_error=f"{type(error).__name__}: {error}")
                record[label + "_session"] = value.snapshot()
    record["compile_credit"] = {"limit": credits.limit, "used": credits.used, "attempts": credits.attempts}
    record["observations_expected"] = len(spec["modules"]) * (1 + len(spec["module_sizes"][0]))
    record["artifacts"] = [{"module": module, "state": target, "entry": info}
                           for (module, target), info in sorted(artifacts.items())]
    save(folder / "RESULT.json", record)
    record["wall_ns"] = time.monotonic_ns() - started
    record["admitted"] = (record["status"] == "completed" and record["wall_ns"] <= p["episode_budget_ns"]
        and len(observations) == record["observations_expected"] and credits.used <= credits.limit
        and record.get("artifact_session", {}).get("owned_native_release_complete") is True)
    return record


def opportunity_targets(bank, p):
    spec = p["application_profiles"]["shared-budget"]
    result = {}
    for module, sizes in zip(spec["modules"], spec["module_sizes"]):
        rows = bank["modules"][module]["candidates"]
        result[module] = min(TARGETS[1:], key=lambda target: (
            rows[target]["setup_ns"] + sum(rows[target]["latency_ns"][str(n)] for n in sizes), target))
    return result


def opportunity_analysis(rows, targets):
    modules = {}
    for module in MODULES:
        selected = [row for row in rows if row["module_ids"] == [module]]
        base = next((row for row in selected if row["arm"] == "opportunity-base"), None)
        candidate = next((row for row in selected if row["arm"] == "opportunity-candidate"), None)
        admitted = bool(base and candidate and base["admitted"] and candidate["admitted"])
        net = base["wall_ns"] - candidate["wall_ns"] if base and candidate else None
        modules[module] = {"target": targets[module], "both_real_controls_admitted": admitted,
            "base_wall_ns": base["wall_ns"] if base else None,
            "candidate_wall_ns": candidate["wall_ns"] if candidate else None,
            "observed_net_saving_ns": net, "positive_observed_net_saving": bool(admitted and net > 0)}
    return {"modules": modules, "two_observed_positive_amortized_opportunities":
        all(row["positive_observed_net_saving"] for row in modules.values()),
        "statistical_benefit_established": False,
        "scope": "One complete real baseline/candidate control pair per semantic module, including own preparation and cleanup; no universal or statistical guarantee."}


def competition_attribution(records, targets):
    """Bind the real opportunity controls to exactly the first NDU decision.

    Group zero has the same held-out inputs as the post-run controls. Later
    suffix decisions or another profitable target cannot stand in for these
    exact complete-trace baseline/candidate counterfactuals.
    """
    evidence = []
    for record in records:
        if (record["arm"] != "native-stream-sealed" or record["profile"] != "shared-budget"
                or record["group"] != 0 or not record["admitted"]):
            continue
        decision = next((row for row in record["decisions"] if row["epoch"] == 0), None)
        if not decision or not decision["model"] or decision["model"]["remaining_credits"] != 1:
            continue
        model, advantages = decision["model"], {}
        for module, options in zip(MODULES, model["modules"]):
            base = next(row for row in options if row["target"] == "base")
            candidate = next(row for row in options if row["target"] == targets[module])
            advantages[module] = {"target": targets[module], "new_build_credits": candidate["credits"],
                "predicted_net_saving_ns": base["cost_ns"] - candidate["cost_ns"], "verified": candidate["verified"]}
        oracle, selected = complete_budget_dp(model), decision["selected"]
        selected_builds = [{"module": module, "target": target}
            for module, target in zip(MODULES, selected["targets"]) if target == targets[module]]
        exact = (selected["targets"] == oracle["targets"] and selected["cost_ns"] == oracle["cost_ns"]
                 and selected["credits"] == oracle["credits"])
        actual = len(selected_builds) == 1 and any(
            attempt["module"] == selected_builds[0]["module"] and attempt["target"] == selected_builds[0]["target"]
            for attempt in record["compile_credit"]["attempts"])
        actual = actual and any(row["module"] == selected_builds[0]["module"]
            and row["state"] == selected_builds[0]["target"] and row["status"] == "measured"
            for row in record["observations"]) if actual else False
        qualifies = exact and actual and all(row["new_build_credits"] == 1 and row["verified"]
            and row["predicted_net_saving_ns"] > 0 for row in advantages.values())
        evidence.append({"group": 0, "epoch": 0, "opportunity_targets": advantages,
            "selected_targets": selected["targets"], "exact_dp_plan": oracle["targets"],
            "same_exact_dp_selection": exact, "actual_matching_candidate_build_and_output": actual,
            "two_exact_targets_competed_for_one_credit": qualifies})
    return evidence


def totals(records, shared_ns, residual_ns, historical_build_ns):
    warm = {arm: shared_ns + (residual_ns if arm.startswith("native") else 0)
        + sum(row["wall_ns"] for row in records if row["arm"] == arm) for arm in APPLICATION_ARMS}
    historical = {arm: cost + (historical_build_ns if arm.startswith("native") else 0) for arm, cost in warm.items()}
    return {"standalone_current_warm_ns": warm, "current_warm_plus_historical_controller_build_ns": historical,
        "new_cold_controller_build_measured": False,
        "ndu_warm_observed_below_fixed_and_dp": all(warm["native-stream-sealed"] < warm[arm] for arm in ("fixed", "dp"))}


def qualify(output, identity, historical_build, clang, protocol_path=PROTOCOL_PATH):
    started, registered_utc = time.monotonic_ns(), datetime.now(timezone.utc).isoformat()
    output, identity, protocol_path = Path(output).resolve(), Path(identity).resolve(), Path(protocol_path).resolve()
    if output.is_relative_to(ROOT) or not protocol_path.is_relative_to(ROOT):
        raise ValueError("raw output must be external and protocol source-bound")
    p = validate_protocol(json.loads(protocol_path.read_bytes()))
    if subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT):
        raise RuntimeError("prospective registration requires a clean committed worktree")
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    manifest_raw, envelope_raw = identity.read_bytes(), Path(historical_build).read_bytes()
    manifest, envelope = _read_json(manifest_raw), _read_json(envelope_raw)
    if (manifest.get("identity", {}).get("source_commit") != p["native_source_pin"]
            or not manifest["identity"].get("rustc", "").startswith("rustc " + p["native_rustc"] + " ")):
        raise ValueError("native source/tool differs from registration")
    historical_ns = validate_build_envelope(envelope, manifest, manifest_raw, envelope["source_commit"])
    # The previous envelope is historical. Its exact controller/build sources
    # must still match; it is never relabeled as a new cold measurement.
    names = sorted({*(str(path.relative_to(ROOT)) for path in (ROOT / "hepta").glob("*.py")),
        str(protocol_path.relative_to(ROOT)), str(Path(__file__).relative_to(ROOT)),
        "tools/qualify_hia_ndu_loop.py", "tools/qualify_hia_ndu_graph.py", "tools/qualify_hia_ndu_net_value.py",
        "tools/qualify_hia_ndu_activation.py", "tools/measure_hia_ndu_build.py", "tools/build_hia_recursive_ndu_bridge.py",
        *(f"experiments/hia_ndu_activation/{module}.hepta" for module in MODULES)})
    source = {}
    for name in names:
        raw = (ROOT / name).read_bytes()
        if subprocess.check_output(["git", "cat-file", "blob", commit + ":" + name], cwd=ROOT) != raw:
            raise RuntimeError("source differs from committed identity: " + name)
        source[name] = sha256(raw).hexdigest()
    found = shutil.which(clang)
    if found is None:
        raise ValueError("actual Clang executable is unavailable")
    tools = {"clang": {"path": str(Path(found).resolve()), "sha256": digest_executable(Path(found).resolve())},
        "python": {"path": str(Path(sys.executable).resolve()), "sha256": digest_executable(Path(sys.executable).resolve())}}
    output.mkdir(parents=True, exist_ok=False)
    save(output / "REGISTRATION.json", {"source_commit": commit, "source_sha256": source,
        "protocol": p, "protocol_sha256": sha256(protocol_path.read_bytes()).hexdigest(),
        "tool_inputs": tools, "registered_utc": registered_utc, "native_binary_sha256": manifest["binary_sha256"],
        "historical_controller_build_source": envelope["source_commit"], "new_cold_build_measured": False})
    (output / "NATIVE_BUILD_IDENTITY.json").write_bytes(manifest_raw)
    (output / "HISTORICAL_NATIVE_BUILD_ENVELOPE.json").write_bytes(envelope_raw)
    bases = {module: lower_source((PROGRAMS / (module + ".hepta")).read_text()) for module in MODULES}
    (output / "driver.c").write_text(DRIVER)
    driver = output / "driver"
    command = [clang, "-O3", "-std=c11", str(output / "driver.c"), "-ldl", "-o", str(driver)]
    completed = subprocess.run(command, capture_output=True, timeout=60, check=False)
    (output / "driver.stdout").write_bytes(completed.stdout)
    (output / "driver.stderr").write_bytes(completed.stderr)
    driver_sha = digest_executable(driver) if driver.exists() else None
    save(output / "DRIVER_BUILD.json", {"command": command, "returncode": completed.returncode, "driver_sha256": driver_sha})
    if completed.returncode:
        raise RuntimeError("native driver build failed")
    bank = calibrate(bases, output / "calibration", driver, driver_sha, clang, p)
    choices = opportunity_targets(bank, p)
    save(output / "PREREGISTERED_POST_RUN_CONTROL_TARGETS.json", {
        "rule": "minimum calibrated setup plus complete shared-profile trace among nonbaseline candidates",
        "targets": choices, "bank_sha256": bank["bank_sha256"], "chosen_before_holdout_execution": True})
    shared_ns, records = time.monotonic_ns() - started, []
    for group in range(p["groups"]):
        for index, profile in enumerate(PROFILES):
            for arm in rotated(APPLICATION_ARMS, group, index):
                row = episode(output / f"application-{group}-{profile}-{arm}", arm, profile, group, p,
                    manifest, identity, bases, bank, driver, driver_sha, clang)
                records.append(row)
                print(json.dumps({"group": group, "profile": profile, "arm": arm, "admitted": row["admitted"],
                    "candidate_builds": row["compile_credit"]["used"], "wall_ns": row["wall_ns"]}), flush=True)
    primary_finished = time.monotonic_ns()
    # These real counterfactual controls run only after all policy episodes.
    # Their held-out outputs cannot feed the policy forecasts or selections.
    controls, shared_spec = [], p["application_profiles"]["shared-budget"]
    control_started = time.monotonic_ns()
    for index, (module, sizes) in enumerate(zip(shared_spec["modules"], shared_spec["module_sizes"])):
        spec = {"modules": [module], "module_sizes": [sizes], "compile_credits": 1}
        for arm in rotated(("opportunity-base", "opportunity-candidate"), 0, index):
            row = episode(output / (module + "-" + arm), arm, "post-run-opportunity", 0, p,
                manifest, identity, bases, bank, driver, driver_sha, clang,
                forced_targets=["base" if arm == "opportunity-base" else choices[module]], spec_override=spec)
            controls.append(row)
            print(json.dumps({"post_run_control": module, "arm": arm, "admitted": row["admitted"], "wall_ns": row["wall_ns"]}), flush=True)
    control_ns = time.monotonic_ns() - control_started
    before_identity = time.monotonic_ns()
    unchanged = all(sha256((ROOT / name).read_bytes()).hexdigest() == value for name, value in source.items())
    unchanged = unchanged and identity.read_bytes() == manifest_raw
    unchanged = unchanged and subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip() == commit
    unchanged = unchanged and not subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT)
    tools_unchanged = all(digest_executable(row["path"]) == row["sha256"] for row in tools.values())
    driver_unchanged = digest_executable(driver) == driver_sha
    residual_ns = max(0, primary_finished - started - shared_ns - sum(row["wall_ns"] for row in records))
    residual_ns += time.monotonic_ns() - before_identity
    application_totals = totals(records, shared_ns, residual_ns, historical_ns)
    analysis_started = time.monotonic_ns()
    analysis = decision_analysis(records)
    opportunity = opportunity_analysis(controls, choices)
    profile_totals = {}
    for profile in PROFILES:
        selected = [row for row in records if row["profile"] == profile]
        costs = totals(selected, shared_ns, residual_ns, historical_ns)
        complete = len(selected) == p["groups"] * len(APPLICATION_ARMS)
        valid = complete and unchanged and tools_unchanged and driver_unchanged and all(row["admitted"] for row in selected)
        costs["all_outputs_budgets_and_release_admitted"] = valid
        costs["ndu_warm_net_benefit_gate"] = bool(p["purpose"] == "qualification" and valid and costs["ndu_warm_observed_below_fixed_and_dp"])
        profile_totals[profile] = costs
    attribution = competition_attribution(records, choices)
    opportunity["exact_ndu_competition_attribution"] = attribution
    opportunity["ndu_competition_on_observed_profitable_candidates"] = bool(p["purpose"] == "qualification"
        and opportunity["two_observed_positive_amortized_opportunities"]
        and any(row["two_exact_targets_competed_for_one_credit"] for row in attribution)
        and all(row["admitted"] for row in records if row["profile"] == "shared-budget"))
    result = {"schema": "hepta.hia.ndu.prepared-reuse.result.v1", "source_commit": commit,
        "purpose": p["purpose"], "source_unchanged": unchanged, "tool_inputs": tools,
        "tool_inputs_unchanged": tools_unchanged, "driver_unchanged": driver_unchanged,
        "module_core_sha256": {name: base.sha256 for name, base in bases.items()},
        "different_semantic_core_hashes": len({base.sha256 for base in bases.values()}) == len(MODULES),
        "application_episodes": records, "application_totals": application_totals,
        "application_profile_totals": profile_totals, "analysis": analysis,
        "opportunity_controls": controls, "opportunity_analysis": opportunity,
        "common_setup_ns_once_per_standalone_arm": shared_ns,
        "residual_ns_conservatively_charged_to_each_native_arm": residual_ns,
        "historical_controller_build_wall_ns": historical_ns,
        "historical_controller_build_source_commit": envelope["source_commit"],
        "new_cold_controller_build_measured": False, "new_cold_net_benefit_qualified": False,
        "post_run_opportunity_controls_wall_ns": control_ns,
        "post_run_analysis_ns": time.monotonic_ns() - analysis_started,
        "observed_total_driver_ns_before_final_encoding": time.monotonic_ns() - started,
        "all_application_outputs_budgets_and_release_admitted": all(row["all_outputs_budgets_and_release_admitted"] for row in profile_totals.values()),
        "ndu_warm_net_benefit_all_profiles": all(row["ndu_warm_net_benefit_gate"] for row in profile_totals.values()),
        "proof_reuse_is_shared_runtime_benefit_not_ndu_algorithm_benefit": True,
        "statistical_superiority_established": False, "prior_negative_results_replaced": False,
        "host": {"platform": platform.platform(), "python": sys.version, "cpu_count": os.cpu_count(),
            "affinity": sorted(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else None,
            "dot_runtime_observable": False, "exclusive_host": False},
        "authority": "DENY_ALL", "safety_certificate": False}
    save(output / "ANALYSIS.json", {"decision_analysis": analysis, "opportunity_analysis": opportunity})
    save(output / "RESULT.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--identity", type=Path, required=True)
    parser.add_argument("--historical-build-envelope", type=Path, required=True)
    parser.add_argument("--clang", default=os.environ.get("CLANG", "clang"))
    parser.add_argument("--protocol", type=Path, default=PROTOCOL_PATH)
    args = parser.parse_args()
    started, existed = time.monotonic_ns(), args.output.exists()
    try:
        result = qualify(args.output, args.identity, args.historical_build_envelope, args.clang, args.protocol)
    except Exception as error:
        if not existed and args.output.is_dir() and (args.output / "REGISTRATION.json").is_file():
            save(args.output / "FAILURE.json", {"schema": "hepta.hia.ndu.prepared-reuse.failure.v1",
                "error": f"{type(error).__name__}: {error}", "wall_ns": time.monotonic_ns() - started,
                "all_prior_observations_retained": True, "performance_qualified": False,
                "authority": "DENY_ALL", "safety_certificate": False})
        raise
    print(json.dumps({key: result[key] for key in ("source_commit", "source_unchanged",
        "all_application_outputs_budgets_and_release_admitted", "ndu_warm_net_benefit_all_profiles",
        "application_totals", "application_profile_totals", "opportunity_analysis")}, indent=2))


if __name__ == "__main__":
    main()
