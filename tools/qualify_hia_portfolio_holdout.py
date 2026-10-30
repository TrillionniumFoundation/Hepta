#!/usr/bin/env python3
"""Prospective real HIA portfolio experiment; no substituted native evaluator.

The formal entry refuses source drift relative to a supplied registration commit
before calibration. Development/oracle unit tests are separate. All native work
uses the existing independent HIA verifier, builders and sealed-image driver.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta.hia_portfolio import (canonical, digest, evaluate_portfolio_choices,
    exact_portfolio, exhaustive_portfolio_oracle, lightweight_portfolio,
    native_portfolio_request, selected_plan)

PROTOCOL_PATH = ROOT / "benchmarks/hia_portfolio_holdout/PROTOCOL.json"
ARMS = ("fixed-base", "fixed-best-plan", "light-greedy-single", "exact-q32-dp", "native-ndu")


def save(path, value):
    Path(path).write_bytes(json.dumps(value, sort_keys=True, indent=2, allow_nan=False).encode() + b"\n")


def file_identity(path):
    path = Path(path).resolve(strict=True)
    return {"path": str(path), "sha256": sha256(path.read_bytes()).hexdigest(), "bytes": path.stat().st_size}


def source_paths():
    return sorted(set((ROOT / "hepta").glob("*.py")) | {
        Path(__file__), PROTOCOL_PATH,
        ROOT / "tools/qualify_hia_ndu_graph.py", ROOT / "tools/qualify_hia_ndu_loop.py",
        ROOT / "tools/build_hia_recursive_ndu_bridge.py", ROOT / "tools/build_hia_portfolio_native.py",
        ROOT / "experiments/hia_optimizer_eval/kernels.hepta",
        ROOT / "tests/test_hia_portfolio.py", ROOT / "tests/test_hia_portfolio_holdout.py"})


def verify_registration(commit):
    if type(commit) is not str or re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise ValueError("exact 40-character registration commit required")
    subprocess.run(["git", "merge-base", "--is-ancestor", commit, "HEAD"], cwd=ROOT,
                   check=True, capture_output=True)
    bindings = {}
    for path in source_paths():
        relative = str(path.relative_to(ROOT))
        current = path.read_bytes()
        registered = subprocess.check_output(["git", "show", commit + ":" + relative], cwd=ROOT)
        if current != registered:
            raise ValueError("prospective registration source drift: " + relative)
        bindings[relative] = sha256(current).hexdigest()
    cfg = json.loads(PROTOCOL_PATH.read_bytes())
    if cfg["schema"] != "hepta.hia.portfolio.holdout.protocol.v1" or cfg["arms"] != list(ARMS):
        raise ValueError("unsupported registered protocol or control arms")
    if cfg["groups"] != len(cfg["holdout_seeds"]) or not set(cfg["holdout_seeds"]).isdisjoint({cfg["training_seed"]}):
        raise ValueError("training and heldout episode seeds must be separate")
    return cfg, bindings


def measured(label, ledger, operation):
    start = time.monotonic_ns()
    row = {"label": label, "status": "running"}
    ledger.append(row)
    try:
        value = operation()
        row["status"] = "completed"
        return value
    except Exception as error:
        row.update(status="failed", error={"type": type(error).__name__, "message": str(error)})
        raise
    finally:
        row["wall_ns"] = time.monotonic_ns() - start


def native_build_cost(manifest, identity_path, envelope_path=None):
    """Unknown native preparation is null, never silently counted as zero."""
    inner = manifest.get("build_cost")
    inner_ns = inner.get("wall_ns") if type(inner) is dict else None
    if type(inner_ns) is not int or inner_ns < 0:
        inner_ns = None
    result = {"inner_reported_wall_ns": inner_ns, "outer_empty_target_wall_ns": None,
              "source_pin": manifest.get("identity", {}).get("source_commit"),
              "outer_receipt": None, "complete_cold_build_scope_known": False}
    if envelope_path is None:
        return result
    envelope = json.loads(Path(envelope_path).read_bytes())
    if (envelope.get("schema") != "hepta.hia.ndu.outer-build-cost.v1"
            or envelope.get("status") != "measured"
            or envelope.get("builder_sha256") != file_identity(ROOT / "tools/build_hia_recursive_ndu_bridge.py")["sha256"]
            or envelope.get("identity_sha256") != file_identity(identity_path)["sha256"]
            or envelope.get("binary_sha256") != manifest.get("binary_sha256")
            or envelope.get("native_source_pin") != result["source_pin"]
            or envelope.get("returncode") != 0 or envelope.get("source_unchanged") is not True
            or envelope.get("target_cache") != "empty" or type(inner) is not dict
            or inner.get("target_cache") != "empty" or inner_ns is None
            or type(envelope.get("wall_ns")) is not int or envelope["wall_ns"] < inner_ns
            or envelope.get("authority") != "DENY_ALL" or envelope.get("safety_certificate") is not False):
        raise ValueError("native build envelope is not the exact original empty-target outer measurement")
    result.update(outer_empty_target_wall_ns=envelope["wall_ns"],
                  outer_receipt=file_identity(envelope_path), complete_cold_build_scope_known=True)
    return result


def portfolio_problem(bank, cfg, *, remaining_indices, initial_artifacts, observations,
                      remaining_ns, retained_limit, generation):
    artifacts = {}
    for name, row in bank["candidates"].items():
        verified = row["verification"]["status"] == "verified"
        artifacts[name] = {"activation_ns": row["setup_ns"],
            "retained_bytes": row.get("artifact_bytes", 0),
            "verification_sha256": digest(row["verification"]), "source_sha256": row["source_sha256"],
            "status": "verified" if verified else "rejected"}
    ratios = {}
    for observed in observations:
        if observed["status"] == "measured":
            calibration = bank["candidates"][observed["artifact"]]["latency_ns"][str(observed["n"])]
            if calibration <= 0:
                raise ValueError("positive measured calibration duration required")
            ratios[observed["artifact"]] = (max(calibration, min(16 * calibration, 4 * observed["outer_wall_ns"])), 4 * calibration)
    regions = []
    for index in remaining_indices:
        n = cfg["batch_sizes"][index]
        options = []
        for name, row in bank["candidates"].items():
            if row["verification"]["status"] != "verified":
                # Rejected alternatives remain in the problem so exclusion is explicit.
                run = 0
            else:
                run = row["latency_ns"][str(n)]
                if name in ratios:
                    numerator, denominator = ratios[name]
                    run = run * numerator // denominator
            options.append({"artifact": name, "run_ns": run, "scratch_bytes": n * 4,
                "support_sha256": digest({"bank": bank["bank_sha256"], "artifact": name,
                    "region": index, "n": n, "own_observations": observations})})
        regions.append({"id": "region" + str(index), "options": options})
    return {"schema": "hepta.hia.portfolio.problem.v1", "objective_sha256": digest(cfg),
        "snapshot_sha256": digest({"bank": bank["bank_sha256"], "remaining": remaining_indices,
            "initial": sorted(initial_artifacts), "observations": observations, "generation": generation}),
        "generation": generation, "artifacts": artifacts, "regions": regions,
        "initial_artifacts": sorted(initial_artifacts), "budget_ns": max(0, remaining_ns),
        "retained_bytes_limit": retained_limit, "scratch_bytes_limit": cfg["scratch_byte_limit"],
        "completion_value_ns": cfg["completion_value_ns"]}


def native_parity(result, response):
    expected = result["values_q32"]
    actual = {path["id"]: path["values_q32"][0] for path in response["paths"]}
    if (actual != expected or sorted(response["pareto_candidate_ids"]) != result["pareto_candidate_ids"]
            or response["advisory_candidate_id"] != result["advisory_candidate_id"]):
        raise ValueError("original native NDU differs from the same-objective Q32 control")


def _episode(arm, group, cfg, bank, base, driver, bridge, clang, root, retained_limit):
    # Import the real proof/build/execute path, never a benchmark-only replacement.
    from hepta.hia_guarded_optimization import build_guarded_native, propose_guarded_reduction
    from hepta.hia_narrowing import build_guarded_narrowed_native, propose_guarded_narrowing
    from hepta.hia_optimization import build_optimized_native, DEFAULT_POLICY
    from tools.qualify_hia_ndu_loop import execute_sample
    start = time.monotonic_ns()
    deadline = start + cfg["episode_budget_ns"]
    folder = root / f"episode-{group}-{arm}"
    folder.mkdir()
    record = {"arm": arm, "group": group, "seed": cfg["holdout_seeds"][group],
        "status": "incomplete", "ledger": [], "decisions": [], "observations": [],
        "activations": [], "native_parity_checked": arm != "native-ndu"}
    active, fixed = {}, None

    def remaining():
        left = deadline - time.monotonic_ns()
        if left <= 0:
            raise TimeoutError("actual shared episode wall budget exhausted")
        return left

    def stage(label, operation):
        remaining()
        value = measured(label, record["ledger"], operation)
        remaining()
        return value

    def activate(name, index):
        row = bank["candidates"][name]
        if row["verification"]["status"] != "verified":
            raise ValueError("unverified candidate reached activation")
        policy = dict(DEFAULT_POLICY, timeout_ms=max(1, min(30000, remaining() // 1_000_000)))
        target = folder / (name + ".so")
        if name == "base":
            receipt = stage("fresh-proof-build.base", lambda: build_optimized_native(base, base, target, clang=clang, policy=policy))
        else:
            narrow = name in cfg["narrow_targets"]
            propose = propose_guarded_narrowing if narrow else propose_guarded_reduction
            build = build_guarded_narrowed_native if narrow else build_guarded_native
            proposal = stage("fresh-proposal." + name, lambda: propose(base, maximum=cfg["guard_limits"][name]))
            if digest(proposal) != row["proposal_sha256"]:
                raise ValueError("candidate proposal drift before fresh independent verification")
            receipt = stage("fresh-proof-build." + name, lambda: build(base, proposal, target, clang=clang, policy=policy))
        if (receipt["verification"]["status"] != "verified"
                or receipt["verification"]["candidate_sha256"] != row["source_sha256"]):
            raise ValueError("fresh candidate verification/source mismatch")
        actual = file_identity(target)
        if actual["sha256"] != receipt["native"]["artifact_sha256"]:
            raise ValueError("fresh executable differs from verifier/build receipt")
        if sum(v["actual_image_bytes"] for v in active.values()) + actual["bytes"] > retained_limit:
            raise ValueError("actual retained executable bytes exceed the common ceiling")
        value = {"artifact": str(target), "receipt": receipt, "actual_image_bytes": actual["bytes"]}
        active[name] = value
        record["activations"].append({"region": index, "artifact": name, **value})

    try:
        for index, n in enumerate(cfg["batch_sizes"]):
            def choose():
                problem = portfolio_problem(bank, cfg, remaining_indices=list(range(index, len(cfg["batch_sizes"]))),
                    initial_artifacts=list(active), observations=record["observations"], remaining_ns=remaining(),
                    retained_limit=retained_limit, generation=1 + group * 100 + index)
                # Already rebuilt images have observations, not just calibration
                # estimates. Preserve their actual current retained footprint.
                for name, value in active.items():
                    problem["artifacts"][name]["retained_bytes"] = value["actual_image_bytes"]
                problem["snapshot_sha256"] = digest({"prior": problem["snapshot_sha256"],
                    "actual_retained_image_bytes": {name: value["actual_image_bytes"] for name, value in active.items()}})
                if arm == "fixed-base":
                    result = evaluate_portfolio_choices(problem, ["base"] * len(problem["regions"]))
                elif arm == "fixed-best-plan" and fixed is not None:
                    result = evaluate_portfolio_choices(problem, fixed[index:])
                elif arm == "light-greedy-single":
                    result = lightweight_portfolio(problem)
                else:
                    result = exact_portfolio(problem, max_work=cfg["max_search_work"],
                        max_states=cfg["max_search_states"], max_witnesses=cfg["max_native_witnesses"])
                response = None
                if arm == "native-ndu":
                    # Exact search is a disclosed preparation cost, not a neural policy.
                    request = native_portfolio_request(problem, result)
                    bridge.timeout = max(0.001, min(10.0, remaining() / 1_000_000_000))
                    response = bridge.evaluate(request)
                    native_parity(result, response)
                    record["native_parity_checked"] = True
                plan = selected_plan(result, response)
                return problem, result, response, plan
            problem, result, response, plan = stage("decision." + str(index), choose)
            record["decisions"].append({"region": index, "problem": problem, "search": result,
                "native_response": response, "selected_plan": plan["id"] if plan else None})
            if plan is None:
                raise ValueError("controller abstained or preserved an unresolved value tie")
            if arm == "fixed-best-plan" and fixed is None:
                fixed = list(plan["choices"])
                record["committed_fixed_choices"] = fixed
            name = plan["choices"][0]
            if name not in active:
                activate(name, index)
            admitted = active[name]
            observed = stage("run." + str(index), lambda: execute_sample(driver, admitted["artifact"],
                expected_artifact_sha256=admitted["receipt"]["native"]["artifact_sha256"], n=n,
                calls=cfg["calls"], seed=cfg["holdout_seeds"][group], multiplier=1,
                timeout=max(0.001, min(60.0, remaining() / 1_000_000_000))))
            record["observations"].append({**observed, "artifact": name, "n": n, "region": index})
            save(folder / f"region-{index}.json", {"decision": record["decisions"][-1], "observation": record["observations"][-1]})
            if observed["status"] != "measured":
                raise ValueError("actual artifact failed independent checksum, mapping, or process check")
            remaining()
        record["status"] = "completed"
    except Exception as error:
        record["error"] = {"type": type(error).__name__, "message": str(error)}
        record["status"] = "failed"
    record["admission_wall_ns"] = time.monotonic_ns() - start
    record["all_outputs_correct"] = (len(record["observations"]) == len(cfg["batch_sizes"])
                                      and all(x["status"] == "measured" for x in record["observations"]))
    record["actual_budget_passed"] = record["admission_wall_ns"] <= cfg["episode_budget_ns"]
    save(folder / "RESULT.json", record)
    return record


def finish_episode_evidence(episode, folder, *, started_ns, budget_ns):
    """Charge this arm for its evidence write before closing its timer.

    A file cannot contain the eventual duration of its own completed write.
    OUTER.json therefore labels its pre-write lower bound; the aggregate's
    episode row contains the inclusive observed wall time. A failed write
    remains a failed, charged attempt and never becomes common preparation.
    """
    evidence_start = time.monotonic_ns()
    try:
        save(Path(folder) / "OUTER.json", {
            "pre_outer_evidence_wall_ns": evidence_start - started_ns,
            "scope": "lower bound before this file write; inclusive wall time is in the aggregate episode row",
            "status_before_evidence_write": episode["status"],
        })
    except Exception as error:
        episode.update(status="failed", evidence_error={"type": type(error).__name__, "message": str(error)})
    finally:
        finished = time.monotonic_ns()
        episode["outer_evidence_write_ns"] = finished - evidence_start
        episode["outer_wall_ns"] = finished - started_ns
        episode["actual_budget_passed"] &= episode["outer_wall_ns"] <= budget_ns


def cost_report(episodes, *, cfg, study_ns, controller_ns, build, competition):
    if type(study_ns) is not int or study_ns < 0 or set(controller_ns) != set(ARMS):
        raise ValueError("exact nonnegative wall times and every control arm required")
    if any(type(row.get("outer_wall_ns")) is not int or row["outer_wall_ns"] < 0 or row["arm"] not in ARMS for row in episodes):
        raise ValueError("invalid observed episode cost")
    identities = [(row["arm"], row["group"]) for row in episodes]
    expected = {(arm, group) for arm in ARMS for group in range(cfg["groups"])}
    if len(set(identities)) != len(identities) or not set(identities) <= expected:
        raise ValueError("duplicate or out-of-protocol episode identity")
    totals = {arm: sum(row["outer_wall_ns"] for row in episodes if row["arm"] == arm) for arm in ARMS}
    common = study_ns - sum(totals.values()) - sum(controller_ns.values())
    if common < 0 or any(type(x) is not int or x < 0 for x in controller_ns.values()):
        raise ValueError("negative or overlapping wall-time accounting")
    warm = {arm: common + totals[arm] + controller_ns[arm] for arm in ARMS}
    outer = build["outer_empty_target_wall_ns"]
    cold = {arm: warm[arm] if arm != "native-ndu" else (warm[arm] + outer if outer is not None else None) for arm in ARMS}
    complete = (set(identities) == expected
                and all(row["status"] == "completed" and row["all_outputs_correct"]
                        and row["actual_budget_passed"] and row["native_parity_checked"] for row in episodes))
    controls = ("fixed-best-plan", "light-greedy-single", "exact-q32-dp")
    savings = {arm: None if cold["native-ndu"] is None else cold[arm] - cold["native-ndu"] for arm in controls}
    return {"common_observed_preparation_ns": common, "controller_setup_ns": controller_ns,
        "actual_episode_totals_ns": totals, "already_built_marginal_total_ns": warm,
        "standalone_with_original_outer_build_ns": cold, "native_build": build,
        "native_known_inner_build_total_ns": (None if build["inner_reported_wall_ns"] is None
                                                else warm["native-ndu"] + build["inner_reported_wall_ns"]),
        "native_cold_savings_against_controls_ns": savings,
        "all_registered_execution_checks_passed": complete,
        "descriptive_measured_scope_net_gain": (complete and competition["established"]
            and build["complete_cold_build_scope_known"] and all(v is not None and v > 0 for v in savings.values())),
        "unknown_costs": {"toolchain_acquisition_ns": None, "dependency_acquisition_ns": None,
            "human_work_ns": None, "persistent_storage_ns": None, "process_startup_before_main_ns": None,
            "final_aggregate_result_encoding_and_write_ns": None},
        "complete_lifetime_net_gain_proved": False, "statistical_superiority_established": False,
        "global_program_optimality_claim": False, "safety_from_ndu_claim": False,
        "accounting": "Observed common preparation is charged once to each standalone arm; per-arm work is counted once; original native build is charged only to native NDU. Missing costs are null."}


def run(output, *, registration_commit, identity, clang, build_envelope=None):
    started = time.monotonic_ns()
    root = Path(output).resolve()
    root.mkdir(parents=True, exist_ok=False)
    record = {"schema": "hepta.hia.portfolio.holdout.result.v1", "status": "incomplete",
        "registration_commit": registration_commit, "previous_negative_results_replaced": False,
        "authority": "DENY_ALL", "safety_certificate": False, "ledger": []}
    try:
        cfg, bindings = measured("registration.admission", record["ledger"], lambda: verify_registration(registration_commit))
        resolved_clang = shutil.which(clang)
        if resolved_clang is None:
            raise ValueError("registered experiment needs an actual native compiler")
        clang = str(Path(resolved_clang).resolve(strict=True))
        manifest = json.loads(Path(identity).read_bytes())
        record.update(protocol=cfg, protocol_sha256=digest(cfg), source_bindings=bindings,
            host={"platform": platform.platform(), "machine": platform.machine(), "python": sys.version,
                  "started_utc": datetime.now(timezone.utc).isoformat()}, compiler=file_identity(clang),
            native_identity=file_identity(identity))
        save(root / "PLAN.json", {**record, "formal_observations_before_plan": 0})
        for relative in bindings:
            destination = root / "sources" / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes((ROOT / relative).read_bytes())
        from hepta.hia_ndu import NduBridge
        from hepta.hia_program_source import lower_source
        from tools.qualify_hia_ndu_graph import calibration, DRIVER
        controller = {arm: [] for arm in ARMS}
        bridge = measured("native.identity-admission", controller["native-ndu"],
            lambda: NduBridge.for_finite_profile(manifest["binary"], identity))
        build = native_build_cost(manifest, identity, build_envelope)
        base = measured("source.lower", record["ledger"], lambda: lower_source(
            (ROOT / "experiments/hia_optimizer_eval/kernels.hepta").read_text()))
        save(root / "BASE.json", base.as_dict())
        (root / "driver.c").write_text(DRIVER)
        driver = root / "driver"

        def build_driver():
            argv = [clang, "-O3", "-std=c11", str(root / "driver.c"), "-ldl", "-o", str(driver)]
            completed = subprocess.run(argv, capture_output=True, timeout=60)
            (root / "driver.stdout").write_bytes(completed.stdout)
            (root / "driver.stderr").write_bytes(completed.stderr)
            save(root / "DRIVER_BUILD.json", {"argv": argv, "returncode": completed.returncode})
            if completed.returncode:
                raise RuntimeError("native driver build failed; actual streams retained")
            return file_identity(driver)

        record["driver"] = measured("driver.build", record["ledger"], build_driver)
        calibration_root = root / "calibration"
        calibration_root.mkdir()
        bank = measured("real-proof-build-calibration", record["ledger"],
            lambda: calibration(base, calibration_root, driver, clang, cfg, []))
        sizes = []
        for row in bank["candidates"].values():
            if row["verification"]["status"] == "verified":
                row["artifact_bytes"] = file_identity(row["artifact"])["bytes"]
                sizes.append(row["artifact_bytes"])
        if len(sizes) < 3:
            raise ValueError("fewer than three independently verified real candidate artifacts")
        retained_limit = sum(sorted(sizes, reverse=True)[:2])
        # Bind added measured resource evidence without retaining an obsolete digest.
        bank.pop("bank_sha256")
        bank["bank_sha256"] = digest(bank)
        save(root / "BANK.json", bank)
        oracle_problem = portfolio_problem(bank, cfg, remaining_indices=list(range(4)), initial_artifacts=[],
            observations=[], remaining_ns=cfg["episode_budget_ns"], retained_limit=retained_limit, generation=1)

        def oracle_check():
            dp, oracle = exact_portfolio(oracle_problem), exhaustive_portfolio_oracle(oracle_problem)
            if (dp["plans"] != oracle["plans"] or dp["values_q32"] != oracle["values_q32"]
                    or dp["pareto_candidate_ids"] != oracle["pareto_candidate_ids"]):
                raise ValueError("independent measured-bank oracle disagrees with DP")
            return {"problem": oracle_problem, "dp": dp, "independent_oracle": oracle}

        save(root / "ORACLE.json", measured("independent-small-oracle", record["ledger"], oracle_check))
        episodes = []
        record["episodes"] = episodes  # Preserve all completed/failed attempts if a later stage rejects.
        for group in range(cfg["groups"]):
            order = ARMS[group % len(ARMS):] + ARMS[:group % len(ARMS)]
            if group % 2:
                order = order[::-1]
            for arm in order:
                before = time.monotonic_ns()
                episode = _episode(arm, group, cfg, bank, base, driver, bridge, clang, root, retained_limit)
                episodes.append(episode)
                finish_episode_evidence(episode, root / f"episode-{group}-{arm}",
                    started_ns=before, budget_ns=cfg["episode_budget_ns"])
        modeled_profitable = {}
        baseline = bank["candidates"]["base"]
        for name, row in bank["candidates"].items():
            if name == "base" or row["verification"]["status"] != "verified":
                continue
            savings = {str(n): baseline["setup_ns"] + baseline["latency_ns"][str(n)]
                               - row["setup_ns"] - row["latency_ns"][str(n)] for n in set(cfg["batch_sizes"])}
            full_savings = baseline["setup_ns"] - row["setup_ns"] + sum(
                baseline["latency_ns"][str(n)] - row["latency_ns"][str(n)] for n in cfg["batch_sizes"])
            modeled_profitable[name] = {"standalone_calibration_savings_ns": savings,
                "complete_horizon_single_activation_savings_ns": full_savings,
                "positive_complete_horizon": full_savings > 0}
        actually_used = sorted({o["artifact"] for e in episodes if e["status"] == "completed"
                                for o in e["observations"] if o["artifact"] != "base"})
        competition = {"modeled_nonbaseline": modeled_profitable, "actual_nonbaseline_artifacts": actually_used,
            "established": sum(v["positive_complete_horizon"] for v in modeled_profitable.values()) >= 2 and len(actually_used) >= 2}
        if any(sha256((ROOT / relative).read_bytes()).hexdigest() != expected for relative, expected in bindings.items()):
            raise ValueError("source drift during formal experiment")
        if file_identity(clang) != record["compiler"] or file_identity(identity) != record["native_identity"]:
            raise ValueError("tool or native build identity drift during formal experiment")
        controller_ns = {arm: sum(row["wall_ns"] for row in rows) for arm, rows in controller.items()}
        record.update(status="complete", episodes=episodes, competition=competition,
            native_controller_ledger=controller, native_build=build, actual_retained_image_limit_bytes=retained_limit,
            study_wall_ns=time.monotonic_ns() - started)
        record["costs"] = cost_report(episodes, cfg=cfg, study_ns=record["study_wall_ns"],
                                     controller_ns=controller_ns, build=build, competition=competition)
        record["source_unchanged"] = True
    except Exception as error:
        record.update(status="failed", error={"type": type(error).__name__, "message": str(error)},
                      observed_attempt_ns=time.monotonic_ns() - started, complete_lifetime_net_gain_proved=False)
    save(root / "RESULT.json", record)
    print(json.dumps({"status": record["status"], "error": record.get("error"),
                      "competition": record.get("competition"), "costs": record.get("costs")}, sort_keys=True))
    return 0 if record["status"] == "complete" and record["costs"]["all_registered_execution_checks_passed"] else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--registration-commit", required=True)
    parser.add_argument("--identity", required=True)
    parser.add_argument("--clang", required=True)
    parser.add_argument("--native-build-envelope")
    args = parser.parse_args(argv)
    return run(args.output, registration_commit=args.registration_commit, identity=args.identity,
               clang=args.clang, build_envelope=args.native_build_envelope)


if __name__ == "__main__":
    raise SystemExit(main())
