#!/usr/bin/env python3
"""Fresh real-library candidates and matched fixed/greedy/DP/native-NDU study.

Correctness qualification is a separate stage with tiny real requests.  The
economic stage always recaptures, reproves, recompiles and measures every
registered arm.  It cannot import qualification or native-result authority.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from hashlib import sha256, shake_256
from itertools import product
import json
import os
from pathlib import Path
import shutil
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta.hia_finite_context import build_bank
from hepta.hia_ndu import REQUEST_SCHEMA, candidate, event
from hepta.hia_ndu_optimizer import ns_to_ms_q32
from hepta.hia_ndu_session import STREAM_SOURCE_PIN
from hepta.hia_stb_specialization import LABELS, candidates, capture, edge_cases, oracle
from hepta.hia_program import verify_program
from hepta.hia_optimization import _solver_identity
from hepta.native_tool_identity import digest_executable
from tools.qualify_hia_integrated import _digest_file
from tools.qualify_hia_ndu_loop import EpisodeBudget, measured
from tools.qualify_hia_ndu_net_value import RecordedSession

HERE = ROOT / "experiments/hia_stb_ndu_20261030"
PROTOCOL = HERE / "PROTOCOL.json"
ARMS = ("fixed", "feedback-greedy", "light-dp", "native-ndu")


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(value):
    return sha256(wire(value)).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError("E_HIA_STB_NDU: " + message)


def save(path, value):
    Path(path).write_bytes(wire(value) + b"\n")


def identity(path):
    path = Path(path).resolve(strict=True)
    return {"path": str(path), "bytes": path.stat().st_size, "sha256": _digest_file(path)}


def solver_identity():
    import z3
    return _solver_identity(z3)


def frontend_libraries():
    paths = set()
    for directory in (os.environ.get("LD_LIBRARY_PATH") or "").split(os.pathsep):
        if directory:
            for pattern in ("libLLVM*.so*", "libclang*.so*"):
                paths.update(p.resolve() for p in Path(directory).glob(pattern) if p.is_file())
    return {"LD_LIBRARY_PATH": os.environ.get("LD_LIBRARY_PATH"),
            "configured_llvm_clang_libraries": [identity(p) for p in sorted(paths)],
            "all_system_loader_dependencies_attested": False}


def protocol():
    p = json.loads(PROTOCOL.read_bytes())
    require(p["schema"] == "hepta.hia.stb-ndu.protocol.v1"
        and p["targets"] == list(LABELS) and p["arms"] == list(ARMS)
        and p["native_source_pin"] == STREAM_SOURCE_PIN and p["native_rustc"] == "1.90.0"
        and p["groups"] == 4 and p["trace"] == [8, 8, 10, 10, 13, 8, 10, 13]
        and p["parameters"] == [8, 10, 13] and p["values_per_request"] == 4096
        and p["repetitions"] == 4096 and p["calls_per_request"] == 16777216
        and p["calibration_repetitions"] == 2 and p["planning_horizon"] == 3
        and p["max_paths"] == 64 and p["controller_timeout_s"] == 10
        and p["episode_budget_ns"] == 120000000000 and p["study_budget_ns"] == 900000000000
        and p["completion_value_ns"] == 240000000000
        and p["reference_cache"] == {"enabled": True, "max_entries": 256,
            "max_canonical_bytes": 1048576, "prewarm_all_15_semantic_requests": True,
            "native_result_reuse": False, "trace_nonce_reuse": False}
        and p["previous_negative_results_replaced"] is False and p["authority"] == "DENY_ALL"
        and p["safety_certificate"] is False, "unsupported frozen protocol")
    expected = (p["groups"] * (len(ARMS) + 1) * len(p["trace"])
                + p["calibration_repetitions"] * len(LABELS) * len(p["parameters"])) * p["calls_per_request"]
    require(expected == p["expected_actual_kernel_calls"], "registered actual-work denominator differs")
    return p


def sources(expected_head):
    """Raw Git blob/mode binding for the declared complete executable closure.

    Evidence-only historical archives may be sparse; they are not imported by
    this runner. Every hepta/tools Python source, the exact fixture and protocol
    are checked against the immutable raw tree, independently of index flags.
    """
    git = lambda *args: subprocess.check_output(["git", "--no-replace-objects", *args], cwd=ROOT)
    head = git("rev-parse", "HEAD").decode().strip()
    require(head == expected_head and len(head) == 40, "exact committed source required")
    require(not git("status", "--porcelain", "--untracked-files=all"), "clean checkout required")
    prefixes = ["hepta", "tools", "tests/fixtures/c_migration/stb_divide",
                "experiments/hia_stb_ndu_20261030", "rust/hia-ndu-bridge",
                "tests/test_hia_scalar_call_validation.py", "tests/test_hia_stb_specialization.py",
                "tests/test_hia_finite_context_map_repeat.py"]
    entries = git("ls-tree", "-r", "--full-tree", "-z", head, "--", *prefixes)
    result = {}
    for raw in entries.split(b"\0")[:-1]:
        metadata, name = raw.split(b"\t", 1)
        mode, kind, blob = metadata.decode().split()
        name = name.decode()
        require(kind == "blob" and mode in {"100644", "100755"}
                and all(part not in {"", ".", "..", ".git"} for part in name.split("/")),
                "unsafe source tree member")
        result[name] = _digest_file(ROOT / name, expected_mode=mode, expected_blob=blob)
    require(str(Path(__file__).relative_to(ROOT)) in result and "hepta/hia_scalar_call_validation.py" in result,
            "required new source absent from commit")
    require(git("rev-parse", "HEAD").decode().strip() == head, "source moved during read")
    return {"head": head, "tree": git("rev-parse", head + "^{tree}").decode().strip(),
            "scope": prefixes, "files": result}


def input_vectors(p):
    vectors = {}
    for group in (-1, *range(p["groups"])):
        phase = "training" if group == -1 else "validation"
        raw = shake_256((p["input_domain"] + "/" + phase + "/" + str(group)).encode()).digest(4 * p["values_per_request"])
        values = [int.from_bytes(raw[i:i + 4], "little") for i in range(0, len(raw), 4)]
        values[:8] = p["input_boundaries"]
        require(len(values) == 4096 and len(set(values)) >= 4000
                and sum(v < 2**31 for v in values) >= 1500
                and sum(v >= 2**31 for v in values) >= 1500, "input entropy/sign gate failed")
        vectors[group] = values
    require(len({digest(v) for v in vectors.values()}) == 5, "training/validation inputs repeat")
    return vectors


def request(p, values, parameter, target, ident=0, *, tiny=False):
    return {"id": ident, "candidate": target, "seed": 0, "mode": "map_repeat",
            "parameter": parameter, "values": values[:8] if tiny else values,
            "repetitions": 3 if tiny else p["repetitions"]}


def prepare_references(bank, vectors, p, folder):
    rows = []
    for group, values in vectors.items():
        for parameter in p["parameters"]:
            trace = bank.prepare_trace([request(p, values, parameter, "baseline")])
            rows.append({"group": group, "parameter": parameter, "input_sha256": digest(values),
                         "expected": trace.expected, "cancel": bank.cancel(trace)})
    stats = bank.oracle_reference_statistics()
    require(stats["entries"] == 15 and stats["misses"] == 15 and stats["capacity_bypasses"] == 0,
            "complete equal reference prewarm did not fit its original cache quotas")
    save(folder / "REFERENCES.json", {"rows": rows, "statistics": stats,
        "native_execution": False, "native_result_reuse": False})
    return stats


def deliver(bank, p, values, parameter, target, directory, number, *, tiny=False):
    started = time.monotonic_ns()
    row = {"target": target, "parameter": parameter, "status": "attempted"}
    native = {}
    try:
        trace = bank.prepare_trace([request(p, values, parameter, target, ident=number, tiny=tiny)])
        save(directory / f"{number:04d}.plan.json", {"trace_sha256": trace.sha256,
            "requests": trace.requests, "expected": trace.expected, "images": trace.images})
        bank.run(trace, report=native)
        require(native["status"] == "completed" and native["prefix"]["complete"], "native delivery incomplete")
        observed = native["prefix"]["completed_requests"]
        expected_calls = 24 if tiny else p["calls_per_request"]
        require(len(observed) == 1 and observed[0]["calls"] == expected_calls,
                "native actual-call denominator differs")
        row.update(status="completed", calls=expected_calls, kernel_ns=observed[0]["kernel_ns"],
                   checksum=observed[0]["checksum"], trace_sha256=trace.sha256,
                   native_evidence=str(directory / f"{number:04d}.native.json"))
    except BaseException as error:
        row["error"] = {"type": type(error).__name__, "message": str(error)}
        raise
    finally:
        # Retain partially acquired/executed/failed native prefixes as well as
        # their actual costs.  Failure is not an empty or free observation.
        save(directory / f"{number:04d}.native.json", native)
        row["delivery_ns"] = time.monotonic_ns() - started
        save(directory / f"{number:04d}.observation.json", row)
    return row


def calibrate(bank, vectors, p, directory):
    directory.mkdir()
    started, rows = time.monotonic_ns(), []
    for repetition in range(p["calibration_repetitions"]):
        for index, parameter in enumerate(p["parameters"]):
            shift = (repetition + index) % len(LABELS)
            order = LABELS[shift:] + LABELS[:shift]
            for target in order:
                row = deliver(bank, p, vectors[-1], parameter, target, directory, len(rows))
                row.update(repetition=repetition)
                rows.append(row)
    latency = {str(parameter): {target: round(statistics.median(r["delivery_ns"] for r in rows
        if (r["parameter"], r["target"]) == (parameter, target))) for target in LABELS} for parameter in p["parameters"]}
    require(len(rows) == p["expected_calibration_deliveries"], "calibration incomplete")
    result = {"rows": rows, "latency_ns": latency, "wall_ns": time.monotonic_ns() - started}
    save(directory / "CALIBRATION.json", result)
    return result


def estimates(calibration, observations, parameter):
    result = {}
    for target in LABELS:
        own = [r["delivery_ns"] for r in observations if r["target"] == target and r["parameter"] == parameter]
        result[target] = round(statistics.median(own)) if own else calibration["latency_ns"][str(parameter)][target]
    return result


def model(calibration, observations, p, epoch, remaining_ns, bank_report):
    horizon = p["trace"][epoch:epoch + p["planning_horizon"]]
    costs = [estimates(calibration, observations, parameter) for parameter in horizon]
    support = {"bank_sha256": bank_report["bank_sha256"], "calibration_sha256": digest(calibration),
               "observations": observations, "epoch": epoch, "horizon": horizon}
    return {"costs": costs, "remaining_ns": remaining_ns, "support_sha256": digest(support),
            "epoch": epoch, "horizon": horizon,
            "proofs": {target: digest(bank_report["candidates"][target]["translation"]) for target in LABELS}}


def plans(m):
    return [{"targets": list(sequence), "cost_ns": sum(cost[target] for cost, target in zip(m["costs"], sequence)),
             "id": "p-" + digest(sequence)[:24]} for sequence in product(LABELS, repeat=len(m["costs"]))]


def plan_key(row):
    return row["cost_ns"], tuple(row["targets"])


def light_dp(m):
    """Independent exact finite additive DP; no native response is consulted."""
    tail = {"targets": [], "cost_ns": 0}
    for cost in reversed(m["costs"]):
        tail = min(({"targets": [target, *tail["targets"]], "cost_ns": cost[target] + tail["cost_ns"]}
                    for target in LABELS), key=plan_key)
    if tail["cost_ns"] > m["remaining_ns"]:
        return None
    return dict(tail, id="p-" + digest(tail["targets"])[:24])


def native_plan(m, p, generation, bridge):
    supplied = plans(m)
    require(len(supplied) <= p["max_paths"], "native path denominator exceeds registered bound")
    objective, snapshot = digest(p), digest({"model": m, "generation": generation})
    candidates_wire = []
    for plan in supplied:
        candidates_wire.append(candidate(candidate_id=plan["id"], verified=True,
            verification_digest=digest([m["proofs"][target] for target in plan["targets"]]),
            support_digest=m["support_sha256"], events=[event(
                identity=snapshot + ":" + plan["id"] + ":" + str(index),
                instant_q32=-ns_to_ms_q32(m["costs"][index][target]), preference_digest=objective)
                for index, target in enumerate(plan["targets"])],
            terminal_q32=ns_to_ms_q32(p["completion_value_ns"]),
            resource_cost_q32=ns_to_ms_q32(plan["cost_ns"])))
    candidates_wire.append(candidate(candidate_id="abstain", verified=True,
        verification_digest=digest("literal-no-effect"), support_digest=m["support_sha256"],
        events=[event(identity=snapshot + ":abstain", instant_q32=0, preference_digest=objective)], terminal_q32=0))
    request_wire = {"schema": REQUEST_SCHEMA, "objective_digest": objective, "snapshot_digest": snapshot,
        "generation": generation, "utility_unit": "completion-minus-wall-milliseconds",
        "resource_unit": "modeled-work", "risk_unit": "probability",
        "resource_budget_q32": ns_to_ms_q32(m["remaining_ns"]), "risk_ceiling_q32": 1 << 32,
        "candidates": candidates_wire}
    response = bridge.evaluate(request_wire)
    by_id = {row["id"]: row for row in supplied}
    selected, tie = response["advisory_candidate_id"], False
    if selected is None:
        frontier = [by_id[name] for name in response["pareto_candidate_ids"] if name in by_id]
        if frontier:
            selected, tie = min(frontier, key=plan_key)["id"], True
    require(selected in by_id and by_id[selected]["cost_ns"] <= m["remaining_ns"],
            "native advice abstained or has no executable budget-feasible path")
    return by_id[selected], {"request": request_wire, "response": response,
                             "frontier_tie_rule_used": tie, "model": m}


def episode(arm, group, bank, bank_report, calibration, vectors, p, manifest, identity_path, directory):
    directory.mkdir()
    started, ledger, observations, decisions, bridge = time.monotonic_ns(), [], [], [], None
    budget = EpisodeBudget(started, p["episode_budget_ns"])
    result = {"arm": arm, "group": group, "status": "failed", "ledger": ledger,
              "observations": observations, "decisions": decisions,
              "cache_before": bank.oracle_reference_statistics()}
    try:
        if arm == "native-ndu":
            bridge = budget.stage("native.startup", ledger, lambda: RecordedSession(manifest["binary"],
                identity_path, directory / "stream", timeout=p["controller_timeout_s"], image_check="sealed"))
        fixed = None
        if arm == "fixed":
            fixed = budget.stage("fixed.commit_dispatch", ledger, lambda: [
                min(LABELS, key=lambda target: (calibration["latency_ns"][str(d)][target], target)) for d in p["trace"]])
            save(directory / "FIXED_PLAN.json", {"targets": fixed, "calibration_sha256": digest(calibration)})
        for epoch, parameter in enumerate(p["trace"]):
            if arm == "baseline-only":
                target = "baseline"
            elif arm == "fixed":
                target = fixed[epoch]
            elif arm == "feedback-greedy":
                cost = budget.stage("feedback.model", ledger, lambda: estimates(calibration, observations, parameter))
                target = budget.stage("feedback.choose", ledger, lambda: min(LABELS, key=lambda label: (cost[label], label)))
            else:
                m = budget.stage("planner.model", ledger, lambda: model(calibration, observations, p, epoch,
                                                                       budget.remaining_ns(), bank_report))
                if arm == "light-dp":
                    chosen = budget.stage("planner.dp", ledger, lambda: light_dp(m))
                    require(chosen is not None, "DP has no executable path within remaining budget")
                    decision = {"model": m, "chosen": chosen}
                else:
                    chosen, decision = budget.stage("planner.native", ledger,
                        lambda: native_plan(m, p, epoch + 1, bridge))
                    decision["chosen"] = chosen
                target = chosen["targets"][0]
                decision["epoch"] = epoch
                decisions.append(decision)
                save(directory / f"{epoch:04d}.decision.json", decision)
            row = budget.stage("deliver." + str(epoch), ledger, lambda: deliver(bank, p, vectors[group],
                parameter, target, directory, epoch))
            row["epoch"] = epoch
            observations.append(row)
        result["status"] = "completed"
    except BaseException as error:
        result["error"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        if bridge is not None:
            try:
                measured("native.shutdown", ledger, bridge.close)
                result["native_session"] = bridge.snapshot()
                require(result["native_session"]["closed"] is True
                        and bridge._process is not None and bridge._process.poll() is not None,
                        "native controller did not terminate")
                result["native_session"]["process_exited"] = True
            except BaseException as error:
                result.update(status="failed", cleanup_error={"type": type(error).__name__, "message": str(error)})
        result["cache_after"] = bank.oracle_reference_statistics()
        result["wall_ns"] = time.monotonic_ns() - started
        result["complete"] = (result["status"] == "completed" and len(observations) == len(p["trace"])
                              and result["wall_ns"] <= p["episode_budget_ns"])
        save(directory / "EPISODE.json", result)
    return result


def qualify(*, output, expected_head, clang, identity_path, stage):
    started = time.monotonic_ns()
    p = protocol()
    out = Path(output).resolve()
    require(not out.is_relative_to(ROOT), "external new output required")
    out.mkdir(parents=True, exist_ok=False)
    ledger, bank, base_bank = [], None, None
    report = {"schema": "hepta.hia.stb-ndu.result.v1", "stage": stage, "status": "failed",
        "qualified": False, "protocol": p, "protocol_sha256": sha256(PROTOCOL.read_bytes()).hexdigest(),
        "started_utc": datetime.now(timezone.utc).isoformat(), "ledger": ledger, "episodes": [],
        "registration": "frozen-local-source-before-economic-run", "performance_timing_qualified": False,
        "source_C_refinement_proved": False, "machine_code_refinement_proved": False,
        "statistical_superiority_established": False, "old_results_replaced": False}
    save(out / "FROZEN_PROTOCOL.json", p)
    deadline = EpisodeBudget(started, p["study_budget_ns"])
    run = lambda label, fn: deadline.stage(label, ledger, fn)
    try:
        before = report["source_before"] = run("source.before", lambda: sources(expected_head))
        snapshot = out / "source_snapshot"
        for name in before["files"]:
            path = snapshot / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((ROOT / name).read_bytes())
        tools = report["tools_before"] = {"clang": identity(shutil.which(clang) or clang), "python": identity(sys.executable),
            "native_manifest": identity(identity_path)}
        report["solver_before"] = run("solver.before", solver_identity)
        report["frontend_libraries_before"] = run("frontend_libraries.before", frontend_libraries)
        manifest = json.loads(Path(identity_path).read_bytes())
        require(manifest["identity"]["source_commit"] == STREAM_SOURCE_PIN
                and manifest["identity"]["rustc"].startswith("rustc 1.90.0 "), "wrong original stream profile")
        tools["native_binary"] = identity(manifest["binary"])
        require(tools["native_binary"]["sha256"] == manifest["binary_sha256"], "native bridge image differs")
        save(out / "NATIVE_IDENTITY.json", manifest)
        report["historical_native_build_ns"] = manifest["build_cost"]["wall_ns"]
        require(type(report["historical_native_build_ns"]) is int and report["historical_native_build_ns"] > 0,
                "actual original native build allocation required")
        baseline, captured = run("source.capture_and_bridge", lambda: capture(out / "capture", clang=clang))
        report["capture"] = captured
        proposed = run("candidate.generate", lambda: candidates(baseline))
        for name, document in proposed.items():
            (out / (name + ".hia.json")).write_bytes(verify_program(document).canonical_bytes)
        report["bank"] = bank_report = {}
        (out / "bank").mkdir()
        bank = run("candidate.prepare_bank", lambda: build_bank(baseline, proposed, out / "bank",
            clang=clang, cases=edge_cases(), oracle=oracle, report=bank_report, reuse_oracle=True, allow_map_repeat=True))
        run("candidate.distinct_code", lambda: require(
            len({r["code"]["sha256"] for r in bank_report["candidates"].values()}) == len(LABELS),
            "registered candidates do not have four distinct exported native bodies"))
        vectors = run("input.construct", lambda: input_vectors(p))
        save(out / "INPUTS.json", {str(k): {"values": v, "sha256": digest(v)} for k, v in vectors.items()})
        if stage == "qualification":
            (out / "tiny").mkdir()
            report["tiny"] = [run("qualification." + target, lambda target=target, index=index:
                deliver(bank, p, vectors[0], p["parameters"][index % 3], target, out / "tiny", index, tiny=True))
                for index, target in enumerate(LABELS)]
            report.update(status="correctness-qualified", qualified=True, economic_study_executed=False,
                          native_controller_executed=False)
        else:
            report["reference_bank"] = run("reference.prepare", lambda: prepare_references(bank, vectors, p, out))
            calibration = report["calibration"] = run("calibration", lambda: calibrate(bank, vectors, p, out / "calibration"))
            report["baseline_bank"] = base_report = {}
            (out / "baseline-bank").mkdir()
            base_bank = run("baseline.prepare_bank", lambda: build_bank(baseline, {"baseline": baseline}, out / "baseline-bank",
                clang=clang, cases=edge_cases(), oracle=oracle, report=base_report, reuse_oracle=True, allow_map_repeat=True))
            report["baseline_reference_bank"] = run("baseline.reference", lambda: prepare_references(base_bank, vectors, p, out / "baseline-bank"))
            for group in range(p["groups"]):
                order = list(ARMS[group:] + ARMS[:group])
                order.insert(0 if group % 2 == 0 else len(order), "baseline-only")
                for arm in order:
                    record = run("episode." + arm, lambda arm=arm: episode(arm, group,
                        base_bank if arm == "baseline-only" else bank,
                        base_report if arm == "baseline-only" else bank_report,
                        calibration, vectors, p, manifest, identity_path, out / f"group-{group}-{arm}"))
                    report["episodes"].append(record)
                    print(json.dumps({"group": group, "arm": arm, "complete": record["complete"],
                        "calls": sum(r.get("calls", 0) for r in record["observations"]), "wall_ns": record["wall_ns"]}), flush=True)
                    require(record["complete"], "registered policy episode failed; no retry or discarded sample")
            report.update(status="all-registered-deliveries-completed", qualified=True, economic_study_executed=True,
                          native_controller_executed=True)
    except BaseException as error:
        report["error"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        for name, owner in (("bank", bank), ("baseline_bank", base_bank)):
            if owner is not None:
                try:
                    released = measured(name + ".close", ledger, owner.close)
                    report[name + "_release"] = released
                    if not released["complete"]: report["qualified"] = False
                except BaseException as error:
                    report[name + "_cleanup_error"] = {"type": type(error).__name__, "message": str(error)}
                    report["qualified"] = False
        for name, callback in (("source_after", lambda: sources(expected_head)),
                               ("tools_after", lambda: {k: identity(v["path"]) for k, v in report.get("tools_before", {}).items()}),
                               ("solver_after", solver_identity), ("frontend_libraries_after", frontend_libraries)):
            try:
                report[name] = measured(name, ledger, callback)
            except BaseException as error:
                report[name + "_error"] = {"type": type(error).__name__, "message": str(error)}
                report["qualified"] = False
        report["identities_unchanged"] = (report.get("source_after") == report.get("source_before")
            and report.get("tools_after") == report.get("tools_before")
            and report.get("solver_after") == report.get("solver_before")
            and report.get("frontend_libraries_after") == report.get("frontend_libraries_before")
            and "source_before" in report)
        report["qualified"] = report["qualified"] and report["identities_unchanged"]
        report["wall_ns_before_analysis_and_final_encoding"] = time.monotonic_ns() - started
        if stage == "study" and report["qualified"]:
            try:
                report["analysis"] = measured("post-policy.analysis", ledger, lambda: analyze(report, p))
            except BaseException as error:
                report["analysis_error"] = {"type": type(error).__name__, "message": str(error)}
                report["qualified"] = False
        report["wall_ns_before_final_encoding"] = time.monotonic_ns() - started
        save(out / "RESULT.json", report)
    return report


def analyze(report, p):
    episodes = report["episodes"]
    require(len(episodes) == p["expected_policy_episodes"] + p["expected_baseline_episodes"]
            and all(r["complete"] for r in episodes), "complete registered episode denominator required")
    require(sum(sum(x["calls"] for x in r["observations"]) for r in episodes)
            + sum(x["calls"] for x in report["calibration"]["rows"]) == p["expected_actual_kernel_calls"],
            "actual work denominator differs")
    costs = {}
    for row in report["ledger"]:
        costs[row["label"]] = costs.get(row["label"], 0) + row["wall_ns"]
    baseline_specific = sum(costs.get(k, 0) for k in ("baseline.prepare_bank", "baseline.reference", "baseline_bank.close"))
    search_specific = sum(costs.get(k, 0) for k in ("candidate.generate", "candidate.prepare_bank", "candidate.distinct_code",
                                                  "reference.prepare", "calibration", "bank.close"))
    episode_total = sum(costs.get("episode." + arm, 0) for arm in (*ARMS, "baseline-only"))
    # Unallocated setup, source/tool checks, snapshots and evidence work are
    # charged in full to every standalone arm, rather than silently omitted.
    common = report["wall_ns_before_analysis_and_final_encoding"] - baseline_specific - search_specific - episode_total
    require(common >= 0, "cost attribution double-counted a nested stage")
    totals = {arm: common + search_specific + costs.get("episode." + arm, 0) for arm in ARMS}
    baseline = common + baseline_specific + costs.get("episode.baseline-only", 0)
    native_cold = totals["native-ndu"] + report["historical_native_build_ns"]
    audit = []
    for row in episodes:
        if row["arm"] == "native-ndu":
            for decision in row["decisions"]:
                expected = light_dp(decision["model"])
                audit.append({"group": row["group"], "epoch": decision["epoch"],
                    "native": decision["chosen"], "same_model_dp": expected,
                    "same_choice": decision["chosen"] == expected,
                    "modeled_regret_ns": None if expected is None else decision["chosen"]["cost_ns"] - expected["cost_ns"]})
    return {"standalone_measured_ns": totals, "baseline_only_standalone_ns": baseline,
        "common_charged_once_per_arm_ns": common, "complete_search_preparation_ns": search_specific,
        "baseline_only_preparation_ns": baseline_specific, "native_build_inclusive_ns": native_cold,
        "historical_native_build_allocation_ns": report["historical_native_build_ns"],
        "new_native_build_performed": False, "same_model_audit": audit,
        "candidate_cold_observed_net_gate": totals["fixed"] < baseline,
        "ndu_warm_observed_net_gate": all(totals["native-ndu"] < totals[a] for a in ARMS[:-1]),
        "ndu_build_inclusive_observed_net_gate": all(native_cold < totals[a] for a in ARMS[:-1]),
        "same_model_algorithmic_improvement_established": False,
        "candidate_opportunity_is_NDU_increment": False,
        "statistical_superiority_established": False,
        "actual_kernel_calls": p["expected_actual_kernel_calls"],
        "final_encoding_and_outer_startup": "see actual external process receipt; not assigned zero"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", choices=("qualification", "study"), required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--clang", required=True)
    parser.add_argument("--identity", required=True)
    args = parser.parse_args()
    result = qualify(output=args.output, expected_head=args.expected_head, clang=args.clang,
                     identity_path=args.identity, stage=args.stage)
    print(json.dumps({k: result.get(k) for k in ("stage", "status", "qualified", "error", "analysis")}))
    return 0 if result["qualified"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
