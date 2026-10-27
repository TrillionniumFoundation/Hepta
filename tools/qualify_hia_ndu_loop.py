#!/usr/bin/env python3
"""Execute a bounded NDU compiler experiment with real builds and full costs.

The native NDU ranks supplied legal continuation paths. It sees only calibration
measurements and the episode's already completed first workload. Both fixed
policies and a lightweight arithmetic controller receive the same information
and candidate/budget envelope. This is a small mechanism qualification, not a
claim of a globally optimal compiler or a general performance improvement.
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
import resource
import statistics
import subprocess
import sys
import time

from hepta.hia_ndu import NduBridge, Q32, REQUEST_SCHEMA, candidate, event
from hepta.hia_native_differential import _pin_native_artifact
from hepta.hia_optimization import (DEFAULT_POLICY, OptimizationRejected,
                                   build_optimized_native, checker_identity,
                                   fold_constants, verify_optimization)
from hepta.hia_program import verify_program

ARMS = ("fixed-stop", "fixed-fold", "fixed-selected", "light", "ndu")
PROTOCOL = {
    "schema": "hepta.hia.ndu.loop.protocol.v1",
    "groups": 3, "calls": 32771, "training_sizes": [127, 511],
    "holdout_sizes": [257, 1021], "training_seed": 7, "holdout_seed": 91,
    "calibration_multiplier": 13, "deployment_multiplier_start": 17,
    "build_cache": "fresh paired source-to-execution sessions; calibration source differs",
    "episode_budget_ns": 30_000_000_000, "completion_value_us": 1_000_000,
    "candidate_set": ["identity", "constant-fold", "invalid-constant"],
    "arms": list(ARMS), "sample_exclusion": "none",
    "utility": "fixed completion value minus all episode wall microseconds",
    "acceptance": "execution/proof/identity gates; timing superiority reported separately",
    "future_information": "calibration and already delivered first workload only",
    "decision_value": "future incremental utility; sunk costs retained in support and full net cost",
    "artifact_execution": "receipt-matched bytes in a sealed inherited Linux memfd",
    "shared_calibration": "count once as study cost and once per standalone strategy comparison",
    "candidate_admission": "NDU pays to propose and verify current candidates; fixed and light defer this work until needed",
    "deadline_scope": "all arms check before/after each stage; no later execution after observed overrun",
    "general_performance_claim": False,
}


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(value):
    return sha256(wire(value)).hexdigest()


def save(path, value):
    Path(path).write_bytes(wire(value) + b"\n")


def program(multiplier=13):
    def p(name):
        return {"name": name, "type": "u64"}
    def op(kind, args, name, value=None, typ="u64"):
        return {"op": kind, "args": args, "out": [{"name": name, "type": typ}],
                "attrs": {"value": value} if kind == "const" else {}}
    def block(name, params, ops, term):
        return {"id": name, "params": [p(x) for x in params], "ops": ops, "term": term}
    def jump(name, *args):
        return {"op": "jump", "target": name, "args": list(args)}
    body = [op("const", [], "one", 1), op("const", [], "mask", 255),
            op("int.mul.wrap", ["bi", "bm"], "scaled"),
            op("int.add.wrap", ["scaled", "bx"], "shifted"),
            op("bit.and", ["shifted", "mask"], "byte"),
            op("int.add.wrap", ["bs", "byte"], "next_sum"),
            op("int.add.wrap", ["bi", "one"], "next_index")]
    return {"schema": "hepta.hia.program.v1", "module": "ndu_finite_loop",
            "functions": [{"name": "work", "params": [p("n"), p("seed")],
                "returns": ["u64"], "effects": [], "entry": "entry", "blocks": [
                    block("entry", ["n", "seed"], [op("const", [], "zero", 0),
                        op("const", [], "three", 3), op("const", [], "ten", multiplier - 3),
                        op("int.add.wrap", ["three", "ten"], "multiplier")],
                        jump("loop", "n", "seed", "zero", "zero", "multiplier")),
                    block("loop", ["ln", "lx", "li", "ls", "lm"],
                        [op("compare.lt", ["li", "ln"], "more", typ="bool")],
                        {"op": "branch", "cond": "more",
                         "then": {"target": "body", "args": ["ln", "lx", "li", "ls", "lm"]},
                         "else": {"target": "done", "args": ["ls"]}}),
                    block("body", ["bn", "bx", "bi", "bs", "bm"], body,
                          jump("loop", "bn", "bx", "next_index", "next_sum", "bm")),
                    block("done", ["answer"], [], {"op": "ret", "values": ["answer"]})]}]}


DRIVER = r'''#define _POSIX_C_SOURCE 200809L
#include <dlfcn.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
static uint64_t ns(clockid_t clock) { struct timespec t; if (clock_gettime(clock,&t)) exit(3); return (uint64_t)t.tv_sec*1000000000ULL+t.tv_nsec; }
int main(int argc,char **argv) {
  if(argc!=5) return 2;
  uint64_t n=strtoull(argv[2],0,10), calls=strtoull(argv[3],0,10), seed=strtoull(argv[4],0,10);
  if(n>4096 || calls==0 || calls>10000000 || seed>255) return 2;
  void *lib=dlopen(argv[1],RTLD_NOW|RTLD_LOCAL); if(!lib) { fprintf(stderr,"%s",dlerror()); return 4; }
  uint64_t (*work)(uint64_t,uint64_t); *(void**)(&work)=dlsym(lib,"work"); if(!work) return 5;
  uint64_t sum=0, start=ns(CLOCK_MONOTONIC), cpu=ns(CLOCK_PROCESS_CPUTIME_ID);
  for(uint64_t i=0;i<calls;i++) sum+=work(n,(seed+i)&255);
  cpu=ns(CLOCK_PROCESS_CPUTIME_ID)-cpu; uint64_t elapsed=ns(CLOCK_MONOTONIC)-start;
  printf("{\"elapsed_ns\":%" PRIu64 ",\"process_cpu_ns\":%" PRIu64 ",\"checksum\":%" PRIu64 "}\n",elapsed,cpu,sum);
  dlclose(lib); return 0;
}
'''


def oracle(n, calls, seed, multiplier=13):
    # Every odd multiplier permutes the residues modulo 256, independently of LLVM.
    if multiplier % 2 != 1:
        raise ValueError("oracle requires the registered odd multiplier")
    def one(s):
        return n // 256 * 32640 + sum((multiplier * i + s) & 255 for i in range(n % 256))
    return (calls // 256 * n * 32640 + sum(one((seed + i) & 255) for i in range(calls % 256))) & ((1 << 64) - 1)


def measured(label, ledger, operation):
    start, cpu = time.monotonic_ns(), time.process_time_ns()
    child = resource.getrusage(resource.RUSAGE_CHILDREN)
    row = {"label": label, "started_monotonic_ns": start, "status": "running"}
    ledger.append(row)
    try:
        result = operation()
        row["status"] = "completed"
        return result
    except Exception as error:
        row.update(status="failed", error=f"{type(error).__name__}: {error}")
        raise
    finally:
        end_child = resource.getrusage(resource.RUSAGE_CHILDREN)
        row.update(wall_ns=time.monotonic_ns() - start,
                   parent_cpu_ns=time.process_time_ns() - cpu,
                   child_cpu_ns=round(1e9 * ((end_child.ru_utime - child.ru_utime) +
                                           (end_child.ru_stime - child.ru_stime))))


class EpisodeBudgetExceeded(RuntimeError):
    pass


class EpisodeBudget:
    """A common admission deadline; an overrun is recorded as an unsuccessful job.

    Native executions also receive the remaining subprocess timeout. Python/SMT
    and compiler work is checked after each stage; this is not hard real time.
    """
    def __init__(self, started, limit_ns):
        self.deadline = started + limit_ns

    def remaining_ns(self):
        remaining = self.deadline - time.monotonic_ns()
        if remaining <= 0:
            raise EpisodeBudgetExceeded("common episode deadline exhausted")
        return remaining

    def stage(self, label, ledger, operation):
        self.remaining_ns()
        result = measured(label, ledger, operation)
        self.remaining_ns()
        return result

    def policy(self):
        return dict(DEFAULT_POLICY, timeout_ms=min(DEFAULT_POLICY["timeout_ms"],
                                                  self.remaining_ns() // 1_000_000))


def execute_sample(driver, library, *, expected_artifact_sha256, n, calls, seed, multiplier=13, timeout=10):
    started = time.monotonic_ns()
    original_path = str(library)
    try:
        loaded_bytes, identity, pinned_fd = _pin_native_artifact(Path(library))
    except Exception as error:
        return {"status": "artifact-rejected", "execution_attempted": False,
                "artifact_source_path": original_path, "reason": str(error),
                "outer_wall_ns": time.monotonic_ns() - started}
    actual_sha = sha256(loaded_bytes).hexdigest()
    artifact = {"artifact_source_path": original_path, "artifact_sha256": actual_sha,
                "expected_artifact_sha256": expected_artifact_sha256,
                "artifact_source_identity": list(identity), "artifact_load": "sealed-memfd",
                "loaded_snapshot_sealed": True}
    command = [str(driver), f"/proc/self/fd/{pinned_fd}", str(n), str(calls), str(seed)]
    try:
        if actual_sha != expected_artifact_sha256:
            return dict(artifact, status="artifact-rejected", execution_attempted=False,
                        reason="sealed bytes differ from independently bound receipt",
                        outer_wall_ns=time.monotonic_ns() - started)
        remaining_timeout = timeout - (time.monotonic_ns() - started) / 1e9
        if remaining_timeout <= 0:
            return dict(artifact, status="timeout", execution_attempted=False,
                        reason="deadline exhausted during sealed artifact admission",
                        outer_wall_ns=time.monotonic_ns() - started)
        try:
            result = subprocess.run(command, capture_output=True, timeout=remaining_timeout, check=False,
                                    pass_fds=(pinned_fd,))
        except subprocess.TimeoutExpired as error:
            return dict(artifact, status="timeout", execution_attempted=True, command=command,
                outer_wall_ns=time.monotonic_ns() - started,
                stdout=(error.stdout or b"").decode(errors="replace"),
                stderr=(error.stderr or b"").decode(errors="replace"))
    finally:
        os.close(pinned_fd)
    row = {**artifact, "command": command, "returncode": result.returncode, "execution_attempted": True,
           "stdout": result.stdout.decode(errors="replace"), "stderr": result.stderr.decode(errors="replace"),
           "outer_wall_ns": time.monotonic_ns() - started}
    if result.returncode:
        return dict(row, status="failed")
    measured_output = json.loads(result.stdout)
    expected = oracle(n, calls, seed, multiplier)
    row["outer_wall_ns"] = time.monotonic_ns() - started
    return dict(row, **measured_output, expected_checksum=expected, multiplier=multiplier,
                status="measured" if measured_output["checksum"] == expected else "wrong-output")


def require_snapshot(source, expected):
    if sha256(Path(source).read_bytes()).hexdigest() != expected:
        raise OptimizationRejected("E_HIA_NDU_SNAPSHOT_DRIFT: current source bytes changed")


def candidate_build(base, revised, output, *, expected_status, clang, policy=None):
    started = time.monotonic_ns()
    verification = verify_optimization(base, revised, policy)
    if verification["status"] != expected_status:
        raise RuntimeError(f"unexpected verifier result: {verification['status']}")
    result = {"verification": verification, "native": None, "artifact_created": False}
    if verification["status"] == "verified":
        result["native"] = build_optimized_native(base, revised, output, policy=policy, clang=clang)
        result["artifact_created"] = Path(output).is_file()
    elif Path(output).exists():
        raise RuntimeError("unverified candidate produced an artifact")
    result["wall_ns"] = time.monotonic_ns() - started
    return result


def calibration(base, root, driver, clang, protocol, ledger):
    original = verify_program(base)
    folded, proposal = measured("calibration.fold-proposal", ledger, lambda: fold_constants(original))
    invalid = deepcopy(base)
    invalid["functions"][0]["blocks"][0]["ops"][2]["attrs"]["value"] += 1
    sources = {"identity": original, "constant-fold": folded, "invalid-constant": invalid}
    bank = {"schema": "hepta.hia.ndu.loop.bank.v1", "proposal": proposal, "candidates": {}}
    for name, source in sources.items():
        save(root / f"calibration-{name}.source.json", source.as_dict() if hasattr(source, "as_dict") else source)
        path = root / f"calibration-{name}.so"
        receipt = measured(f"calibration.verify-build.{name}", ledger,
            lambda s=source, p=path, k=name: candidate_build(original, s, p,
                expected_status="rejected" if k == "invalid-constant" else "verified", clang=clang))
        samples = []
        if receipt["artifact_created"]:
            for n in protocol["training_sizes"]:
                sample = measured(f"calibration.measure.{name}.{n}", ledger,
                    lambda size=n: execute_sample(driver, path, n=size, calls=protocol["calls"], seed=protocol["training_seed"],
                        expected_artifact_sha256=receipt["native"]["native"]["artifact_sha256"]))
                if sample["status"] != "measured":
                    raise RuntimeError("calibration execution failed")
                samples.append(dict(sample, n=n, calls=protocol["calls"]))
        bank["candidates"][name] = {"receipt": receipt, "samples": samples}
        save(root / f"calibration-{name}.json", bank["candidates"][name])
    identity = bank["candidates"]["identity"]
    folded_row = bank["candidates"]["constant-fold"]
    def rate(row):
        return statistics.median(s["elapsed_ns"] / (s["n"] * s["calls"]) for s in row["samples"])
    bank["native_bytes_identical"] = (identity["receipt"]["native"]["native"]["artifact_sha256"] ==
                                      folded_row["receipt"]["native"]["native"]["artifact_sha256"])
    bank["fold_to_baseline_rate"] = 1.0 if bank["native_bytes_identical"] else rate(folded_row) / rate(identity)
    # Fixed selection uses calibration only and includes the one-time build.
    ordinary_cost = sum(s["outer_wall_ns"] for s in identity["samples"])
    folded_cost = ledger[0]["wall_ns"] + folded_row["receipt"]["wall_ns"] + sum(s["outer_wall_ns"] for s in folded_row["samples"])
    bank["selected_fixed"] = "constant-fold" if folded_cost < ordinary_cost else "stop"
    bank["fold_proposal_ns"] = ledger[0]["wall_ns"]
    bank["ledger"] = ledger
    bank["bank_sha256"] = digest(bank)
    return bank


def forecast_costs(bank, first):
    stop_ns = first["outer_wall_ns"]
    fold_build_ns = bank["candidates"]["constant-fold"]["receipt"]["wall_ns"] + bank["fold_proposal_ns"]
    fold_run_ns = max(1, round(stop_ns * bank["fold_to_baseline_rate"]))
    return {"stop_ns": stop_ns, "fold_build_ns": fold_build_ns,
            "fold_run_ns": fold_run_ns, "future_observed": False}


def decision_request(bank, first, observed, *, snapshot, verification, folded_verification,
                     rejected_verification, remaining_ns, protocol):
    forecast = forecast_costs(bank, first)
    # This proposal was already executed above; retain its observed cost only.
    forecast["fold_build_ns"] -= bank["fold_proposal_ns"]
    objective = digest(protocol)
    support_evidence = {"bank": bank["bank_sha256"], "completed_first": first,
                        "completed_steps": deepcopy(observed)}
    support = digest(support_evidence)
    forecast["support_evidence"] = support_evidence
    forecast["observed_sunk_cost_ns"] = sum(row["wall_ns"] for row in observed)
    plans = []
    def resource_q(ns):
        return (ns * Q32) // 1000
    def utility_q(ns):
        return (ns * Q32) // 1_000_000
    # Compare future increments at the current decision point. The literal
    # abstain candidate is zero, so adding sunk costs to only the working paths
    # would incorrectly make an affordable continuation lose to abstention.
    for name, build_ns, run_ns, proof in (
            ("stop", 0, forecast["stop_ns"], verification),
            ("constant-fold", forecast["fold_build_ns"], forecast["fold_run_ns"], folded_verification),
            ("invalid-constant", 0, 0, rejected_verification)):
        steps = [event(identity=f"{snapshot}:{name}:build-or-stop", instant_q32=-utility_q(build_ns), preference_digest=objective),
                 event(identity=f"{snapshot}:{name}:future-work", instant_q32=-utility_q(run_ns), preference_digest=objective)]
        plans.append(candidate(candidate_id=name, verified=proof["status"] == "verified",
            verification_digest=proof["verification_sha256"], support_digest=support, events=steps,
            terminal_q32=protocol["completion_value_us"] * Q32 // 1000,
            resource_cost_q32=resource_q(build_ns + run_ns)))
    plans.append(candidate(candidate_id="abstain", verified=True,
        verification_digest=digest("literal-no-effect"), support_digest=support,
        events=[event(identity=f"{snapshot}:abstain", instant_q32=0, preference_digest=objective)], terminal_q32=0))
    return {"schema": REQUEST_SCHEMA, "objective_digest": objective, "snapshot_digest": snapshot,
            "generation": 1, "utility_unit": "completion-minus-wall-milliseconds",
            "resource_unit": "microseconds", "risk_unit": "probability", "risk_ceiling_q32": Q32,
            "resource_budget_q32": resource_q(max(0, remaining_ns)),
            "candidates": plans}, forecast


def run_episode(arm, group, n, multiplier, base, bank, root, driver, bridge, clang, protocol):
    folder = root / f"episode-{group}-{n}-{arm}"
    folder.mkdir()
    started = time.monotonic_ns()
    ledger = []
    budget = EpisodeBudget(started, protocol["episode_budget_ns"])
    def stage(label, operation):
        return budget.stage(label, ledger, operation)
    record = {"arm": arm, "group": group, "n": n, "multiplier": multiplier,
              "selected": None, "status": "running", "ledger": ledger,
              "same_initial_information": bank["bank_sha256"], "future_access": False}
    source = folder / "current.json"
    save(source, base)
    source_sha = sha256(source.read_bytes()).hexdigest()
    baseline = folder / "baseline.so"
    try:
        receipt = stage("baseline.verify-build",
            lambda: candidate_build(base, base, baseline, expected_status="verified", clang=clang, policy=budget.policy()))
        record["baseline"] = receipt
        first = stage("first-delivery", lambda: execute_sample(driver, baseline, n=n, calls=protocol["calls"],
            seed=protocol["holdout_seed"], multiplier=multiplier, timeout=budget.remaining_ns() / 1e9,
            expected_artifact_sha256=receipt["native"]["native"]["artifact_sha256"]))
        record["initial"] = first
        if first["status"] != "measured":
            raise RuntimeError("first delivery failed")
        snapshot = digest({"source": source_sha, "artifact": receipt["native"]["native"]["artifact_sha256"],
                           "first": first, "bank": bank["bank_sha256"], "group": group, "n": n})
        forecast = forecast_costs(bank, first)
        revised = None
        request = None
        if arm == "ndu":
            revised, proposal = stage("planning.fold-proposal", lambda: fold_constants(base))
            save(folder / "PROPOSED_FOLD.json", revised.as_dict())
            folded_proof = stage("planning.verify-fold", lambda: verify_optimization(base, revised, budget.policy()))
            invalid = deepcopy(base)
            invalid["functions"][0]["blocks"][0]["ops"][2]["attrs"]["value"] += 1
            save(folder / "REJECTED_CANDIDATE.json", invalid)
            rejected_proof = stage("planning.reject-invalid", lambda: verify_optimization(base, invalid, budget.policy()))
            if folded_proof["status"] != "verified" or rejected_proof["status"] != "rejected":
                raise RuntimeError("current candidate admission did not produce the required proof/refusal")
            record["current_candidate_admission"] = {"folded": folded_proof, "invalid": rejected_proof,
                                                       "proposal": proposal}
            snapshot = digest({"initial": snapshot, "admission": record["current_candidate_admission"],
                               "observed": ledger})
            request, forecast = decision_request(bank, first, ledger, snapshot=snapshot,
                verification=receipt["verification"], folded_verification=folded_proof,
                rejected_verification=rejected_proof, remaining_ns=budget.remaining_ns(), protocol=protocol)
        def choose():
            require_snapshot(source, source_sha)
            if arm == "ndu":
                previous_timeout = bridge.timeout
                try:
                    bridge.timeout = min(previous_timeout, budget.remaining_ns() / 1e9)
                    result = bridge.evaluate(request)
                finally:
                    bridge.timeout = previous_timeout
                selected = result["advisory_candidate_id"]
            else:
                selected = {"fixed-stop": "stop", "fixed-fold": "constant-fold",
                            "fixed-selected": bank["selected_fixed"],
                            "light": "constant-fold" if forecast["fold_build_ns"] + forecast["fold_run_ns"] < forecast["stop_ns"] else "stop"}[arm]
                result = {"advisory_candidate_id": selected, "authority": "DENY_ALL"}
            predicted = forecast["stop_ns"] if selected == "stop" else forecast["fold_build_ns"] + forecast["fold_run_ns"]
            if predicted > budget.remaining_ns():
                raise EpisodeBudgetExceeded("predicted continuation exceeds common remaining budget")
            return selected, result
        selected, selection = stage("control.select", choose)
        record.update(selected=selected, request=request, forecast=forecast, selection=selection)
        chosen, chosen_receipt = baseline, receipt
        if selected == "constant-fold":
            if revised is None:
                revised, proposal = stage("continuation.fold", lambda: fold_constants(base))
            save(folder / "FOLDED.json", revised.as_dict())
            chosen = folder / "folded.so"
            chosen_receipt = stage("continuation.verify-build",
                lambda: candidate_build(base, revised, chosen, expected_status="verified", clang=clang, policy=budget.policy()))
            save(folder / "proposal.json", proposal)
        elif selected != "stop":
            raise RuntimeError("no feasible continuation; abstention is not task completion")
        def execute_final():
            require_snapshot(source, source_sha)
            expected = chosen_receipt["native"]["native"]["artifact_sha256"]
            if sha256(chosen.read_bytes()).hexdigest() != expected:
                raise RuntimeError("chosen artifact drift")
            return execute_sample(driver, chosen, n=n, calls=protocol["calls"],
                seed=protocol["holdout_seed"], multiplier=multiplier, timeout=budget.remaining_ns() / 1e9,
                expected_artifact_sha256=expected)
        final = stage("continuation.execute", execute_final)
        record.update(final=final, chosen=chosen_receipt,
                      status="completed" if final["status"] == "measured" else "failed")
        require_snapshot(source, source_sha)
    except EpisodeBudgetExceeded as error:
        record.update(status="budget-exhausted", error=str(error), completion_admitted=False)
    except Exception as error:
        record.update(status="failed", error=f"{type(error).__name__}: {error}", completion_admitted=False)
    save(folder / "EPISODE.json", record)
    record["episode_wall_ns"] = time.monotonic_ns() - started
    record["stage_wall_ns"] = sum(row["wall_ns"] for row in ledger)
    record["bookkeeping_and_unattributed_wall_ns"] = record["episode_wall_ns"] - record["stage_wall_ns"]
    record["net_cost_ns"] = record["episode_wall_ns"]
    record["actual_budget_passed"] = record["episode_wall_ns"] <= protocol["episode_budget_ns"]
    if not record["actual_budget_passed"]:
        record["status"] = "budget-exhausted"
    record["completion_admitted"] = record["status"] == "completed" and record["actual_budget_passed"]
    save(folder / "EPISODE.json", record)
    return record


def faults(base, root, driver, clang, bank, ledger):
    policy = dict(DEFAULT_POLICY, timeout_ms=0)
    timeout = measured("fault.verifier-deadline", ledger,
        lambda: candidate_build(base, base, root / "timeout-must-not-exist.so", expected_status="timeout", clang=clang, policy=policy))
    source = root / "drift.json"
    save(source, base)
    frozen = sha256(source.read_bytes()).hexdigest()
    changed = deepcopy(base)
    changed["functions"][0]["blocks"][0]["ops"][2]["attrs"]["value"] = 11
    save(source, changed)
    def drift():
        try:
            require_snapshot(source, frozen)
        except OptimizationRejected as error:
            return {"status": "rejected", "reason": str(error), "execution_attempted": False}
        raise RuntimeError("snapshot drift was admitted")
    stale = measured("fault.snapshot-drift", ledger, drift)
    process_timeout = measured("fault.native-timeout", ledger,
        lambda: execute_sample(driver, root / "calibration-identity.so", n=4096,
            calls=10_000_000, seed=3, timeout=0.01,
            expected_artifact_sha256=bank["candidates"]["identity"]["receipt"]["native"]["native"]["artifact_sha256"]))
    if process_timeout["status"] != "timeout":
        raise RuntimeError("the actual process deadline probe did not time out")
    return {"verifier_timeout": timeout, "snapshot_drift": stale, "process_timeout": process_timeout,
            "ledger": ledger}


def qualify(output, *, identity, clang, protocol=None, executable=None):
    protocol = dict(PROTOCOL if protocol is None else protocol)
    root = Path(output).resolve()
    root.mkdir(parents=True, exist_ok=False)
    started = time.monotonic_ns()
    ledger = []
    source_pin = checker_identity()
    host = {"platform": platform.platform(), "machine": platform.machine(),
            "python": sys.version, "cpu_count": os.cpu_count(),
            "cpu_affinity": sorted(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else None,
            "started_utc": datetime.now(timezone.utc).isoformat()}
    save(root / "HOST.json", host)
    repository = Path(__file__).resolve().parents[1]
    source_paths = ["tools/qualify_hia_ndu_loop.py", "tools/build_hia_recursive_ndu_bridge.py",
                    "tests/test_hia_ndu.py", "tests/test_hia_ndu_loop.py"]
    source_paths.extend(str(path.relative_to(repository)) for path in sorted((repository / "hepta").glob("*.py")))
    source_identity = {}
    for name in source_paths:
        data = (repository / name).read_bytes()
        destination = root / "sources" / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
        source_identity[name] = sha256(data).hexdigest()
    save(root / "SOURCE_IDENTITY.json", source_identity)
    save(root / "PROTOCOL.json", protocol)
    base = program(protocol["calibration_multiplier"])
    save(root / "BASE.json", base)
    manifest = json.loads(Path(identity).read_text())
    save(root / "NATIVE_BUILD_IDENTITY.json", manifest)
    bridge = measured("study.native-bridge-admission", ledger,
                      lambda: NduBridge(executable or manifest["binary"], identity))
    (root / "driver.c").write_text(DRIVER)
    driver = root / "driver"
    def build_driver():
        result = subprocess.run([clang, "-O3", "-std=c11", str(root / "driver.c"), "-ldl", "-o", str(driver)],
                                capture_output=True, timeout=60, check=False)
        if result.returncode:
            raise RuntimeError(result.stderr.decode(errors="replace"))
        return {"sha256": sha256(driver.read_bytes()).hexdigest(), "source_sha256": sha256(DRIVER.encode()).hexdigest()}
    driver_identity = measured("study.driver-build", ledger, build_driver)
    bank = measured("study.calibration-total", ledger, lambda: calibration(base, root, driver, clang, protocol, []))
    save(root / "BANK.json", bank)
    fault_result = measured("study.failure-probes-total", ledger, lambda: faults(base, root, driver, clang, bank, []))
    save(root / "FAULTS.json", fault_result)
    episodes = []
    for group in range(protocol["groups"]):
        for ni, n in enumerate(protocol["holdout_sizes"]):
            multiplier = protocol["deployment_multiplier_start"] + 2 * (group * len(protocol["holdout_sizes"]) + ni)
            deployment_base = program(multiplier)
            shift = (group + ni) % len(ARMS)
            order = ARMS[shift:] + ARMS[:shift]
            if group % 2:
                order = order[::-1]
            for arm in order:
                episodes.append(run_episode(arm, group, n, multiplier, deployment_base,
                                            bank, root, driver, bridge, clang, protocol))
    if checker_identity() != source_pin:
        raise RuntimeError("checker source changed during experiment; retain attempt without a qualification")
    if any(sha256((repository / name).read_bytes()).hexdigest() != value for name, value in source_identity.items()):
        raise RuntimeError("execution source changed during experiment; retain the original attempt")
    costs = {arm: [row["net_cost_ns"] for row in episodes if row["arm"] == arm] for arm in ARMS}
    median_costs = {arm: statistics.median(values) for arm, values in costs.items()}
    study_wall = time.monotonic_ns() - started
    bridge_admission = ledger[0]["wall_ns"]
    shared_wall = study_wall - sum(row["episode_wall_ns"] for row in episodes) - bridge_admission
    build_cost = manifest.get("build_cost")
    build_wall = build_cost["wall_ns"] if build_cost else 0
    own_setup = {arm: build_wall + bridge_admission if arm == "ndu" else 0 for arm in ARMS}
    standalone_total = {arm: shared_wall + own_setup[arm] + sum(costs[arm]) for arm in ARMS}
    amortized = {arm: median_costs[arm] + (shared_wall + own_setup[arm]) / len(costs[arm]) for arm in ARMS}
    all_completed = all(row["completion_admitted"] for row in episodes)
    result = {"schema": "hepta.hia.ndu.loop.result.v1", "protocol_sha256": digest(protocol),
              "host": host,
              "checker_sha256": source_pin, "native_identity": manifest["identity"],
              "native_binary_sha256": manifest["binary_sha256"], "driver": driver_identity,
              "bank_sha256": bank["bank_sha256"], "shared_setup_ledger": ledger,
              "shared_setup_wall_ns": shared_wall,
              "setup_accounting": {"shared_charged_once_per_standalone_strategy": True,
                  "actual_experiment_shared_cost_charged_once": True,
                  "native_build_cost": build_cost, "native_bridge_admission_ns": bridge_admission,
                  "native_build_charged_to": "ndu", "common_driver_and_calibration_charge": "all arms equally",
                  "cost_complete": bool(build_cost and build_cost["target_cache"] == "empty"),
                  "scope": "recorded build session, this qualifier and native child processes",
                  "excluded": ["toolchain installation", "preexisting dependency source cache acquisition",
                               "build manifest final write and build process startup"]},
              "standalone_total_cost_ns": standalone_total,
              "median_amortized_net_cost_ns": amortized,
              "episodes": episodes, "median_net_cost_ns": median_costs,
              "all_actual_outputs_correct": all(row.get("final", {}).get("status") == "measured" for row in episodes),
              "all_episodes_completed": all_completed,
              "all_actual_budgets_passed": all(row["actual_budget_passed"] for row in episodes),
              "source_identity": source_identity,
              "ndu_descriptive_cost_lower_than_selected_fixed": all_completed and amortized["ndu"] < amortized["fixed-selected"],
              "ndu_descriptive_cost_lower_than_light": all_completed and amortized["ndu"] < amortized["light"],
              "statistical_superiority_established": False, "global_optimality_claim": False,
              "safety_from_ndu_claim": False, "authority": "DENY_ALL",
              "total_study_wall_ns": study_wall,
              "study_plus_native_build_wall_ns": study_wall + build_wall,
              "interpretation": "Actual finite builds and costs; fixed controls may avoid optional proposal/verification work; no general performance conclusion."}
    save(root / "RESULT.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--identity", type=Path, required=True)
    parser.add_argument("--bridge", type=Path,
                        help="Exact recursive bridge; defaults to the explicitly supplied identity manifest")
    parser.add_argument("--clang", default="clang")
    args = parser.parse_args()
    result = qualify(args.output, identity=args.identity, executable=args.bridge, clang=args.clang)
    print(json.dumps({key: result[key] for key in ("all_actual_outputs_correct", "median_net_cost_ns",
          "ndu_descriptive_cost_lower_than_selected_fixed", "ndu_descriptive_cost_lower_than_light")}, indent=2))
    if not result["all_episodes_completed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
