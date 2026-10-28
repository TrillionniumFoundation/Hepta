#!/usr/bin/env python3
"""Measure a finite, proof-gated NDU compiler graph with strong cost controls.

Actual guarded reductions are reproved, compiled, and loaded from receipt-matched
sealed bytes. Native NDU ranks a declared finite continuation graph. A lightweight
control searches the same complete graph; a strong fixed control commits its best
whole calibrated plan. All costs and failed samples remain in the evidence.
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
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from hepta.hia_guarded_optimization import (build_guarded_native,
    guarded_checker_identity, propose_guarded_reduction, verify_guarded_optimization)
from hepta.hia_ndu import FINITE_RUSTC_VERSION, FINITE_SOURCE_PIN, NduBridge, finite_plan_request
from hepta.hia_optimization import (DEFAULT_POLICY, OptimizationRejected,
    build_optimized_native, verify_optimization)
from hepta.hia_program_source import lower_source
from tools.qualify_hia_ndu_loop import (EpisodeBudget, EpisodeBudgetExceeded,
    digest, execute_sample, measured, require_snapshot, save)

ARMS = ("fixed-base", "fixed-small", "fixed-wide", "fixed-best-plan", "light", "ndu")
PROTOCOL = {
    "schema": "hepta.hia.ndu.graph.protocol.v1", "groups": 3,
    "calls": 32771, "probe_size": 64, "batch_sizes": [64, 4096, 16384],
    "training_seed": 7, "holdout_seed": 91, "calibration_repetitions": 3,
    "guard_limits": {"guard-small": 256, "guard-wide": 65536},
    "episode_budget_ns": 120_000_000_000, "completion_value_ns": 120_000_000_000,
    "arms": list(ARMS), "function": "full_lifecycle",
    "same_information": "complete measured candidate bank and each episode's completed observations",
    "future_information": "registered workload inputs; no holdout execution times",
    "fixed_control": "complete minimum-cost calibrated plan, committed after common first probe",
    "light_control": "complete additive finite-horizon dynamic programming, replanned after actual observations",
    "control_encoding": "fixed/light avoid native request/event serialization; same graph and path cap",
    "native_control": "original NDU recursive utility and feasibility/Pareto evaluation",
    "native_profile": {"source_pin": FINITE_SOURCE_PIN, "rustc": FINITE_RUSTC_VERSION,
                       "environment": "HEPTA_FINITE_NDU_BRIDGE/HEPTA_FINITE_NDU_IDENTITY"},
    "cost_model": "per-size calibration median scaled by observed same-state wall ratios",
    "recompilation": "every changed state reproposes and independently proves/builds new bytes",
    "decision_value": "future increments; historical costs remain in the total ledger",
    "budget": "same before/after-stage deadline and remaining native-process timeout for every arm",
    "artifact_execution": "SHA-matched sealed inherited memfd, including loader/process overhead",
    "setup": "common calibration once per standalone strategy; native build/admission charged to NDU",
    "sample_exclusion": "none", "general_performance_claim": False,
}

DRIVER = r'''#define _POSIX_C_SOURCE 200809L
#include <dlfcn.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
static uint64_t ns(clockid_t clock) { struct timespec t; if(clock_gettime(clock,&t)) exit(3); return (uint64_t)t.tv_sec*1000000000ULL+t.tv_nsec; }
int main(int argc,char **argv) {
  if(argc!=5) return 2;
  uint64_t n=strtoull(argv[2],0,10), calls=strtoull(argv[3],0,10), seed=strtoull(argv[4],0,10);
  if(n>65536 || calls==0 || calls>10000000 || seed>255) return 2;
  void *lib=dlopen(argv[1],RTLD_NOW|RTLD_LOCAL); if(!lib) { fprintf(stderr,"%s",dlerror()); return 4; }
  uint64_t (*work)(size_t,uint32_t); *(void**)(&work)=dlsym(lib,"full_lifecycle"); if(!work) return 5;
  uint64_t sum=0, start=ns(CLOCK_MONOTONIC), cpu=ns(CLOCK_PROCESS_CPUTIME_ID);
  for(uint64_t i=0;i<calls;i++) sum+=work(n,(uint32_t)((seed+i)&255));
  cpu=ns(CLOCK_PROCESS_CPUTIME_ID)-cpu; uint64_t elapsed=ns(CLOCK_MONOTONIC)-start;
  printf("{\"elapsed_ns\":%" PRIu64 ",\"process_cpu_ns\":%" PRIu64 ",\"checksum\":%" PRIu64 "}\n",elapsed,cpu,sum);
  dlclose(lib); return 0;
}
'''


def arithmetic_choice(bundle, *, remaining_ns, completion_ns):
    """Search every supplied path. Explicit exact ties prefer less compilation.

    Then prefer fewer active decisions and the declared action-name order. This
    external control policy does not alter native NDU's unresolved frontier.
    """
    feasible = [p for p in bundle["plans"].values() if p["verified"]
                and p["estimated_cost_ns"] <= min(remaining_ns, completion_ns)]
    if not feasible:
        return None
    return min(feasible, key=_plan_key)


def _plan_key(plan):
    return (plan["estimated_cost_ns"], sum(a["mode"] == "transition" for a in plan["actions"]),
            sum(a["mode"] != "stopped" for a in plan["actions"]),
            tuple(a["id"] for a in plan["actions"]))


def graph_fields(bank, *, current, remaining_sizes, observations, remaining_ns,
                 decision_ns, protocol, snapshot, generation):
    states, costs, transitions = {}, {}, []
    for name, row in bank["candidates"].items():
        proof = row["verification"]
        states[name] = {"source_sha256": row["source_sha256"],
                        "verification_sha256": proof["verification_sha256"], "status": proof["status"]}
        ratios = [s["outer_wall_ns"] / row["latency_ns"][str(s["n"])]
                  for s in observations if s.get("state") == name and s.get("status") == "measured"]
        scale = statistics.median(ratios) if ratios else 1.0
        costs[name] = [max(1, round(row["latency_ns"][str(n)] * scale))
                       if proof["status"] == "verified" else 0 for n in remaining_sizes]
    for source in ("base", "guard-small", "guard-wide"):
        for target in ("guard-small", "guard-wide", "refused-unguarded"):
            if source == target:
                continue
            row = bank["candidates"][target]
            transitions.append({"id": "install-" + target + "-from-" + source,
                "source": source, "target": target, "setup_ns": row["setup_ns"],
                "status": row["verification"]["status"],
                "verification_sha256": row["verification"]["verification_sha256"],
                "support_sha256": digest({"bank": bank["bank_sha256"], "target": target,
                                           "measured_setup_ns": row["setup_ns"]})})
    return dict(objective_digest=digest(protocol), snapshot_digest=snapshot,
        generation=generation, initial_state=current, states=states, transitions=transitions,
        batch_costs_ns=costs, remaining_budget_ns=remaining_ns,
        completion_value_ns=protocol["completion_value_ns"], decision_cost_ns=decision_ns,
        observations=observations)


def graph_bundle(bank, **arguments):
    return finite_plan_request(**graph_fields(bank, **arguments))


def light_bundle(bank, *, fixed_target=None, **arguments):
    """Exact additive finite-horizon DP, without native-event/wire overhead.

    It covers the same paths as explicit enumeration, including its disclosed
    path cap. Because all feasible paths have the same completion value and
    resource cost equals wall cost, minimizing cost also solves the common
    resource-constrained choice. No greedy pruning or future timing is used.
    """
    fields = graph_fields(bank, **arguments)
    states, costs = fields["states"], fields["batch_costs_ns"]
    current, horizon = fields["initial_state"], len(fields["batch_costs_ns"][fields["initial_state"]])
    decision = fields["decision_cost_ns"]
    outgoing = {name: [edge for edge in fields["transitions"] if edge["source"] == name] for name in states}
    counts, cache = {}, {}

    def count(state, batch):
        if batch == horizon:
            return 1
        key = (state, batch)
        if key not in counts:
            counts[key] = 1 + sum(count(e["target"], batch + 1) for e in outgoing[state])
            if batch + 1 < horizon:
                counts[key] += count(state, batch + 1)
        return counts[key]

    covered = count(current, 0)
    if covered > 127:
        raise OptimizationRejected("E_HIA_NDU_PATH_BUDGET: same complete-graph path cap exhausted")

    def summarize(actions):
        return {"id": "plan-" + digest(actions)[:24], "actions": actions,
            "verified": all(a["status"] == "verified" and states[a["target"]]["status"] == "verified" for a in actions),
            "estimated_cost_ns": sum(a["setup_ns"] + a["decision_ns"] + a["execution_ns"] for a in actions)}

    def stop(state, batch):
        return [{"id": "stop", "mode": "stop" if i == batch else "stopped", "source": state,
            "target": state, "batch": i, "setup_ns": 0,
            "decision_ns": decision if i == batch and i else 0,
            "execution_ns": costs[state][i], "status": "verified",
            "verification_sha256": states[state]["verification_sha256"]} for i in range(batch, horizon)]

    def action(edge, batch):
        return {"id": edge["id"], "mode": "hold" if edge["id"] == "hold" else "transition",
            "source": edge["source"], "target": edge["target"], "batch": batch,
            "setup_ns": edge["setup_ns"], "decision_ns": decision if batch else 0,
            "execution_ns": costs[edge["target"]][batch], "status": edge["status"],
            "verification_sha256": edge["verification_sha256"]}

    def best(state, batch):
        if batch == horizon:
            return summarize([])
        key = (state, batch)
        if key not in cache:
            options = [summarize(stop(state, batch))]
            edges = list(outgoing[state])
            if batch + 1 < horizon:
                edges.append({"id": "hold", "source": state, "target": state, "setup_ns": 0,
                    "status": "verified", "verification_sha256": states[state]["verification_sha256"]})
            for edge in edges:
                if edge["status"] == "verified" and states[edge["target"]]["status"] == "verified":
                    options.append(summarize([action(edge, batch)] + best(edge["target"], batch + 1)["actions"]))
            cache[key] = min(options, key=_plan_key)
        return cache[key]

    if fixed_target is None:
        selected = best(current, 0)
    elif fixed_target == current:
        selected = summarize(stop(current, 0))
    else:
        edge = next(e for e in outgoing[current] if e["target"] == fixed_target)
        selected = summarize([action(edge, 0)] + stop(fixed_target, 1))
    return {"schema": "hepta.hia.ndu.light-graph.v1", "plans": {selected["id"]: selected},
        "support_evidence": fields, "covered_path_count": covered, "search_complete": True,
        "enumeration_complete": False, "algorithm": "complete-additive-finite-horizon-dynamic-programming",
        "authority": "DENY_ALL", "safety_certificate": False}


def calibration(base, root, driver, clang, protocol, ledger):
    candidates, proposals = {}, {}
    for name, maximum in protocol["guard_limits"].items():
        proposals[name] = measured("propose." + name, ledger,
                                  lambda limit=maximum: propose_guarded_reduction(base, maximum=limit))
        proposal_ns = ledger[-1]["wall_ns"]
        save(root / (name + ".proposal.json"), proposals[name])
        path = root / (name + ".so")
        receipt = measured("prove-build." + name, ledger,
            lambda p=proposals[name], out=path: build_guarded_native(base, p, out, clang=clang))
        candidates[name] = {"receipt": receipt, "verification": receipt["verification"],
            "source_sha256": receipt["verification"]["candidate_sha256"],
            "proposal_sha256": digest(proposals[name]), "setup_ns": proposal_ns + ledger[-1]["wall_ns"],
            "artifact": str(path)}
    path = root / "base.so"
    receipt = measured("prove-build.base", ledger,
                       lambda: build_optimized_native(base, base, path, clang=clang))
    candidates["base"] = {"receipt": receipt, "verification": receipt["verification"],
        "source_sha256": base.sha256, "setup_ns": ledger[-1]["wall_ns"], "artifact": str(path)}
    unguarded = proposals["guard-wide"]["fast_core"]
    refusal = measured("reject.unguarded-fast-body", ledger,
                       lambda: verify_optimization(base, unguarded))
    if refusal["status"] != "rejected":
        raise RuntimeError("unguarded fast-body negative control did not reject")
    save(root / "refused-unguarded.source.json", unguarded)
    candidates["refused-unguarded"] = {"verification": refusal,
        "source_sha256": refusal.get("candidate_sha256", digest(unguarded)),
        "setup_ns": ledger[-1]["wall_ns"], "artifact": None, "receipt": None}
    sizes = sorted(set([protocol["probe_size"], *protocol["batch_sizes"]]))
    for name, row in candidates.items():
        samples = []
        if row["verification"]["status"] == "verified":
            for repetition in range(protocol["calibration_repetitions"]):
                for n in sizes:
                    sample = measured(f"measure.{name}.{repetition}.{n}", ledger,
                        lambda size=n, candidate=row: execute_sample(driver, candidate["artifact"],
                            expected_artifact_sha256=candidate["receipt"]["native"]["artifact_sha256"],
                            n=size, calls=protocol["calls"], seed=protocol["training_seed"], multiplier=1, timeout=60))
                    if sample["status"] != "measured":
                        raise RuntimeError("calibration artifact failed its independent checksum")
                    samples.append(dict(sample, n=n, repetition=repetition))
        row["samples"] = samples
        row["latency_ns"] = {str(n): round(statistics.median(s["outer_wall_ns"] for s in samples if s["n"] == n))
                              for n in sizes} if samples else {}
        save(root / (name + ".json"), row)
    bank = {"schema": "hepta.hia.ndu.graph.bank.v1", "candidates": candidates,
            "ledger": ledger, "timing_information": "calibration only", "base_sha256": base.sha256}
    bank["bank_sha256"] = digest(bank)
    return bank


def selected_native_plan(bundle, response):
    selected = response["advisory_candidate_id"]
    if selected == "abstain":
        return None
    if selected is None:
        raise OptimizationRejected("E_HIA_NDU_UNRESOLVED: native Pareto frontier has no recommendation")
    plan = bundle["plans"].get(selected)
    if plan is None or not plan["verified"]:
        raise OptimizationRejected("E_HIA_NDU_INELIGIBLE: advisory named an unverified path")
    return plan


def run_episode(arm, group, base, bank, root, driver, bridge, clang, protocol, decision_costs):
    folder = root / f"episode-{group}-{arm}"
    folder.mkdir()
    started, ledger, observations = time.monotonic_ns(), [], []
    budget = EpisodeBudget(started, protocol["episode_budget_ns"])
    record = {"arm": arm, "group": group, "status": "running", "ledger": ledger,
              "observations": observations, "decisions": [], "transitions": [],
              "same_initial_information": bank["bank_sha256"], "future_timing_access": False}
    source = folder / "base.json"
    save(source, base.as_dict())
    source_sha = sha256(source.read_bytes()).hexdigest()
    checker = guarded_checker_identity()

    def admit_snapshot():
        require_snapshot(source, source_sha)
        if guarded_checker_identity() != checker:
            raise OptimizationRejected("E_HIA_NDU_CHECKER_DRIFT: independent verifier changed")

    def stage(label, operation):
        return budget.stage(label, ledger, operation)

    def deliver(state, artifact, receipt, n, batch):
        admit_snapshot()
        result = stage("execute." + str(batch) + "." + state,
            lambda: execute_sample(driver, artifact,
                expected_artifact_sha256=receipt["native"]["artifact_sha256"], n=n,
                calls=protocol["calls"], seed=(protocol["holdout_seed"] + group) & 255,
                multiplier=1, timeout=budget.remaining_ns() / 1e9))
        observations.append(dict(result, state=state, n=n, batch=batch))
        if result["status"] != "measured":
            raise RuntimeError("native workload failed its independent checksum")

    try:
        current, artifact = "base", folder / "base.so"
        receipt = stage("initial.prove-build", lambda: build_optimized_native(
            base, base, artifact, clang=clang, policy=budget.policy()))
        record["initial_receipt"] = receipt
        deliver(current, artifact, receipt, protocol["probe_size"], -1)
        closed, fixed_actions = False, None
        for batch, n in enumerate(protocol["batch_sizes"]):
            budget.remaining_ns()
            if not closed:
                admit_snapshot()
                snapshot = digest({"bank": bank["bank_sha256"], "source": source_sha,
                    "current": current, "artifact": receipt["native"]["artifact_sha256"],
                    "verification": receipt["verification"]["verification_sha256"],
                    "checker": checker, "completed": observations, "ledger": ledger})

                def choose():
                    nonlocal fixed_actions
                    remaining = budget.remaining_ns()
                    inputs = dict(current=current,
                        remaining_sizes=protocol["batch_sizes"][batch:], observations=observations,
                        remaining_ns=remaining, decision_ns=decision_costs.get(arm, 0),
                        protocol=protocol, snapshot=snapshot, generation=batch + 1)
                    response = None
                    if arm == "ndu":
                        bundle = graph_bundle(bank, **inputs)
                        previous_timeout = bridge.timeout
                        try:
                            bridge.timeout = min(previous_timeout, budget.remaining_ns() / 1e9)
                            response = bridge.evaluate(bundle["request"])
                        finally:
                            bridge.timeout = previous_timeout
                        selected = selected_native_plan(bundle, response)
                    elif arm in {"light", "fixed-best-plan"}:
                        bundle = light_bundle(bank, **inputs)
                        selected = arithmetic_choice(bundle, remaining_ns=remaining,
                                                     completion_ns=protocol["completion_value_ns"])
                        if arm == "fixed-best-plan" and fixed_actions is None:
                            fixed_actions = deepcopy(selected["actions"]) if selected else []
                    else:
                        target = {"fixed-base": "base", "fixed-small": "guard-small", "fixed-wide": "guard-wide"}[arm]
                        bundle = light_bundle(bank, fixed_target=target, **inputs)
                        selected = arithmetic_choice(bundle,
                            remaining_ns=remaining, completion_ns=protocol["completion_value_ns"])
                        if selected:
                            fixed_actions = deepcopy(selected["actions"])
                    return bundle, response, selected

                if fixed_actions is None:
                    bundle, response, selected = stage("control." + str(batch), choose)
                    record["decisions"].append({"batch": batch, "snapshot_sha256": snapshot,
                        "bundle": bundle, "native_response": response,
                        "selected_plan": selected["id"] if selected else "abstain"})
                    if selected is None:
                        record["status"] = "abstained"
                        break
                    action = selected["actions"][0]
                else:
                    action = fixed_actions[batch]
                if action["source"] != current:
                    raise OptimizationRejected("E_HIA_NDU_PLAN_DRIFT: committed plan has a different source state")
                if action["mode"] in {"stop", "stopped"}:
                    closed = True
                elif action["mode"] == "transition":
                    target = action["target"]
                    if target not in protocol["guard_limits"] or bank["candidates"][target]["verification"]["status"] != "verified":
                        raise OptimizationRejected("E_HIA_NDU_UNVERIFIED: no executable candidate was admitted")
                    proposed = stage("repropose." + str(batch) + "." + target,
                        lambda: propose_guarded_reduction(base, maximum=protocol["guard_limits"][target]))
                    if digest(proposed) != bank["candidates"][target]["proposal_sha256"]:
                        raise OptimizationRejected("E_HIA_NDU_PROPOSAL_DRIFT: observed candidate changed")
                    admit_snapshot()
                    artifact = folder / (f"transition-{batch}-" + target + ".so")
                    receipt = stage("reprove-build." + str(batch) + "." + target,
                        lambda: build_guarded_native(base, proposed, artifact, clang=clang,
                            policy=dict(DEFAULT_POLICY, timeout_ms=min(30000, budget.remaining_ns() // 1_000_000))))
                    if receipt["verification"]["candidate_sha256"] != bank["candidates"][target]["source_sha256"]:
                        raise OptimizationRejected("E_HIA_NDU_FINAL_CORE_DRIFT: final receipt differs from selected candidate")
                    record["transitions"].append({"batch": batch, "source": current, "target": target,
                                                  "receipt": receipt})
                    current = target
            deliver(current, artifact, receipt, n, batch)
        else:
            record["status"] = "completed"
    except EpisodeBudgetExceeded as error:
        record.update(status="budget-exhausted", error=str(error))
    except Exception as error:
        record.update(status="rejected-or-failed", error=f"{type(error).__name__}: {error}")
    record["episode_wall_ns"] = time.monotonic_ns() - started
    record["actual_budget_passed"] = record["episode_wall_ns"] <= protocol["episode_budget_ns"]
    record["completion_admitted"] = record["status"] == "completed" and record["actual_budget_passed"]
    record["net_cost_ns"] = record["episode_wall_ns"]
    record["net_utility_ns"] = (protocol["completion_value_ns"] if record["completion_admitted"] else 0) - record["net_cost_ns"]
    record["reported_cost_scope"] = "episode entry through final admission, all proof/build/control/load/run and intermediate evidence writes"
    save(folder / "RESULT.json", record)
    return record


def failure_probes(base, bank, root, driver, protocol, ledger):
    proposed = propose_guarded_reduction(base, maximum=protocol["guard_limits"]["guard-wide"])
    timeout = measured("fault.verifier-deadline", ledger, lambda: verify_guarded_optimization(
        base, proposed, dict(DEFAULT_POLICY, timeout_ms=0)))
    if timeout["status"] != "timeout":
        raise RuntimeError("actual zero-deadline verifier did not fail closed")
    source = root / "drift-probe.json"
    save(source, base.as_dict())
    previous = sha256(source.read_bytes()).hexdigest()
    source.write_bytes(source.read_bytes() + b" ")
    def drift():
        try:
            require_snapshot(source, previous)
        except OptimizationRejected as error:
            return {"status": "rejected", "reason": str(error), "execution_attempted": False}
        raise RuntimeError("actual changed snapshot was accepted")
    moved = measured("fault.snapshot-drift", ledger, drift)
    baseline = bank["candidates"]["base"]
    artifact_mismatch = measured("fault.artifact-digest", ledger, lambda: execute_sample(
        driver, baseline["artifact"], expected_artifact_sha256="0" * 64,
        n=1, calls=1, seed=1, multiplier=1))
    process_timeout = measured("fault.process-deadline", ledger, lambda: execute_sample(
        driver, baseline["artifact"], expected_artifact_sha256=baseline["receipt"]["native"]["artifact_sha256"],
        n=65536, calls=10000000, seed=1, multiplier=1, timeout=0.001))
    if artifact_mismatch["status"] != "artifact-rejected" or artifact_mismatch["execution_attempted"]:
        raise RuntimeError("artifact identity mismatch reached execution")
    if process_timeout["status"] != "timeout":
        raise RuntimeError("actual native process deadline probe did not time out")
    return {"verifier_timeout": timeout, "snapshot_drift": moved, "artifact_mismatch": artifact_mismatch,
            "process_timeout": process_timeout, "ledger": ledger}


def qualify(output, *, identity, clang, protocol=None):
    protocol = deepcopy(PROTOCOL if protocol is None else protocol)
    root = Path(output).resolve()
    root.mkdir(parents=True, exist_ok=False)
    repository = Path(__file__).resolve().parents[1]
    start, shared, controller_setup = time.monotonic_ns(), [], {"light": [], "ndu": []}
    source_paths = sorted((repository / "hepta").glob("*.py")) + [Path(__file__),
        repository / "tools/qualify_hia_ndu_loop.py", repository / "tools/build_hia_recursive_ndu_bridge.py",
        repository / "tests/test_hia_ndu_graph.py", repository / "experiments/hia_optimizer_eval/kernels.hepta"]
    source_identity = {}
    for source in source_paths:
        relative = str(source.relative_to(repository))
        raw = source.read_bytes()
        source_identity[relative] = sha256(raw).hexdigest()
        copy = root / "sources" / relative
        copy.parent.mkdir(parents=True, exist_ok=True)
        copy.write_bytes(raw)
    save(root / "SOURCE_IDENTITY.json", source_identity)
    save(root / "PROTOCOL.json", protocol)
    host = {"platform": platform.platform(), "machine": platform.machine(), "python": sys.version,
            "cpu_count": os.cpu_count(), "started_utc": datetime.now(timezone.utc).isoformat(),
            "cpu_affinity": sorted(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else None}
    save(root / "HOST.json", host)
    base = measured("source.lower", shared, lambda: lower_source(
        (repository / "experiments/hia_optimizer_eval/kernels.hepta").read_text()))
    save(root / "BASE.json", base.as_dict())
    manifest = json.loads(Path(identity).read_bytes())
    save(root / "NATIVE_BUILD_IDENTITY.json", manifest)
    bridge = measured("native.admission", controller_setup["ndu"],
                      lambda: NduBridge.for_finite_profile(manifest["binary"], identity))
    (root / "driver.c").write_text(DRIVER)
    driver = root / "driver"
    def build_driver():
        command = [clang, "-O3", "-std=c11", str(root / "driver.c"), "-ldl", "-o", str(driver)]
        result = subprocess.run(command, capture_output=True, timeout=60, check=False)
        if result.returncode:
            raise RuntimeError(result.stderr.decode(errors="replace"))
        return {"command": command, "sha256": sha256(driver.read_bytes()).hexdigest(),
                "source_sha256": sha256(DRIVER.encode()).hexdigest()}
    driver_identity = measured("driver.build", shared, build_driver)
    bank = measured("calibration.all", shared, lambda: calibration(base, root, driver, clang, protocol, []))
    save(root / "BANK.json", bank)
    faults = measured("failure-probes.all", shared, lambda: failure_probes(base, bank, root, driver, protocol, []))
    save(root / "FAULTS.json", faults)
    decision_costs = {}
    for arm in ("light", "ndu"):
        def sample_control():
            inputs = dict(current="base", remaining_sizes=protocol["batch_sizes"],
                observations=[], remaining_ns=protocol["episode_budget_ns"], decision_ns=0,
                protocol=protocol, snapshot=digest({"calibration": bank["bank_sha256"], "arm": arm}), generation=1)
            if arm == "ndu":
                bundle = graph_bundle(bank, **inputs)
                return bridge.evaluate(bundle["request"])
            bundle = light_bundle(bank, **inputs)
            return arithmetic_choice(bundle, remaining_ns=protocol["episode_budget_ns"],
                                     completion_ns=protocol["completion_value_ns"])
        samples = [measured("control.calibration." + str(i), controller_setup[arm], sample_control) for i in range(3)]
        save(root / (arm + ".control-calibration.json"), samples)
        decision_costs[arm] = round(statistics.median(row["wall_ns"] for row in controller_setup[arm]
                                                     if row["label"].startswith("control.calibration.")))
    save(root / "CONTROLLER_SETUP.json", {"ledger": controller_setup, "forecast_decision_ns": decision_costs})
    episodes = []
    for group in range(protocol["groups"]):
        shift = group % len(ARMS)
        order = ARMS[shift:] + ARMS[:shift]
        if group % 2:
            order = order[::-1]
        for arm in order:
            before = time.monotonic_ns()
            row = run_episode(arm, group, base, bank, root, driver, bridge, clang, protocol, decision_costs)
            outer = time.monotonic_ns() - before
            # Attribute the full per-arm evidence encoding/write to that arm.
            # Native receipts are larger; charging their serialization to shared
            # setup would conceal part of NDU's actual cost from its comparison.
            row["admission_wall_ns"] = row["episode_wall_ns"]
            row["evidence_serialization_and_write_ns"] = outer - row["episode_wall_ns"]
            row["episode_wall_ns"] = row["net_cost_ns"] = outer
            row["actual_budget_passed"] = outer <= protocol["episode_budget_ns"]
            row["completion_admitted"] = row["status"] == "completed" and row["actual_budget_passed"]
            row["net_utility_ns"] = (protocol["completion_value_ns"] if row["completion_admitted"] else 0) - outer
            row["reported_cost_scope"] = "outer observed episode, including its full evidence encoding/write; this aggregate report's final write excluded"
            episodes.append(row)
    if any(sha256((repository / name).read_bytes()).hexdigest() != expected for name, expected in source_identity.items()):
        raise RuntimeError("source changed during graph measurement; retain the attempt without qualification")
    study_ns = time.monotonic_ns() - start
    costs = {arm: [r["net_cost_ns"] for r in episodes if r["arm"] == arm] for arm in ARMS}
    medians = {arm: statistics.median(values) for arm, values in costs.items()}
    controller_ns = {arm: sum(row["wall_ns"] for row in controller_setup.get(arm, [])) for arm in ARMS}
    common_ns = study_ns - sum(r["episode_wall_ns"] for r in episodes) - sum(controller_ns.values())
    build_cost = manifest.get("build_cost")
    build_ns = build_cost["wall_ns"] if build_cost else 0
    own_ns = {arm: controller_ns[arm] + (build_ns if arm == "ndu" else 0) for arm in ARMS}
    amortized = {arm: medians[arm] + (common_ns + own_ns[arm]) / len(costs[arm]) for arm in ARMS}
    complete = bool(build_cost and build_cost["target_cache"] == "empty")
    all_completed = all(r["completion_admitted"] for r in episodes)
    result = {"schema": "hepta.hia.ndu.graph.result.v1", "protocol_sha256": digest(protocol),
        "host": host, "source_identity": source_identity, "native_identity": manifest["identity"],
        "native_binary_sha256": manifest["binary_sha256"], "driver": driver_identity,
        "bank_sha256": bank["bank_sha256"], "shared_setup_ledger": shared,
        "controller_setup_ledger": controller_setup, "shared_setup_wall_ns": common_ns,
        "setup_accounting": {"common_once_per_standalone_strategy": True,
            "native_build_charged_to": "ndu", "native_build_cost": build_cost,
            "controller_setup_ns": controller_ns, "cost_complete_within_scope": complete,
            "scope": "reported native build plus source/proof/calibration/control/compiler/loader/workload wall time",
            "excluded": ["toolchain installation", "preexisting dependency cache acquisition",
                         "build process startup and final manifest write", "final aggregate report write"]},
        "episodes": episodes, "median_episode_cost_ns": medians, "median_amortized_cost_ns": amortized,
        "standalone_total_cost_ns": {arm: common_ns + own_ns[arm] + sum(costs[arm]) for arm in ARMS},
        "all_episodes_completed": all_completed,
        "all_outputs_correct": all(len(r["observations"]) == len(protocol["batch_sizes"]) + 1
                                   and all(s["status"] == "measured" for s in r["observations"]) for r in episodes),
        "all_actual_budgets_passed": all(r["actual_budget_passed"] for r in episodes),
        "actual_transitions": sum(len(r["transitions"]) for r in episodes),
        "ndu_descriptive_cost_lower_than_fixed": complete and all_completed and amortized["ndu"] < amortized["fixed-best-plan"],
        "ndu_descriptive_cost_lower_than_light": complete and all_completed and amortized["ndu"] < amortized["light"],
        "statistical_superiority_established": False, "global_optimality_claim": False,
        "safety_from_ndu_claim": False, "authority": "DENY_ALL", "safety_certificate": False,
        "study_wall_ns": study_ns, "study_plus_native_build_wall_ns": study_ns + build_ns}
    save(root / "RESULT.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--identity", type=Path, required=True)
    parser.add_argument("--clang", default="clang")
    args = parser.parse_args()
    result = qualify(args.output, identity=args.identity, clang=args.clang)
    print(json.dumps({key: result[key] for key in ("all_episodes_completed", "actual_transitions",
          "median_episode_cost_ns", "median_amortized_cost_ns")}, indent=2))
    if not result["all_episodes_completed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
