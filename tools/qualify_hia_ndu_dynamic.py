#!/usr/bin/env python3
"""Register and measure an explicitly native, finite dynamic cache experiment.

The six arms share workload observations and the actual compiled image. The
beam/beam_ndu pair differs only by original NDU evaluation. All original
frames, rejected controls, failures, prediction errors and exact-DP gaps stay
in the output. No result here qualifies an HIA compiler or a language speedup.
"""
from __future__ import annotations
import argparse
from copy import deepcopy
from hashlib import sha256
import itertools
import json
import math
import os
from pathlib import Path
import random
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from hepta.hia_ndu_dynamic import (DynamicError, JsonProcess, MODEL_SCHEMA, MODES, REQUEST_SCHEMA,
    REFUSAL_SCHEMA, UPSTREAM, action, call_cost, digest, integer, invocation_gate, live_mask,
    read_json, require, resident_bytes, validate_model, wire)

PROTOCOL = ROOT / "benchmarks/hia_ndu_dynamic/PROTOCOL.json"
ADAPTER = ROOT / "rust/hia-ndu-dynamic-model"

def write(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")

def timed(fn):
    started = time.monotonic_ns()
    value = fn()
    return value, time.monotonic_ns() - started

def median(values):
    return round(statistics.median(values))

def identity(path):
    p = Path(path).absolute()
    return {"path": str(p), "resolved": str(p.resolve(strict=True)),
            "bytes": p.stat().st_size, "sha256": sha256(p.read_bytes()).hexdigest()}

def source_state():
    def git(*args):
        return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()
    return {"commit": git("rev-parse", "HEAD"), "tree": git("rev-parse", "HEAD^{tree}"),
            "status": git("status", "--porcelain", "--untracked-files=no")}

def source_inventory():
    paths = [*ADAPTER.rglob("*"), PROTOCOL, Path(__file__), ROOT / "hepta/hia_ndu_dynamic.py",
        ROOT / "hepta/hia_ndu.py", ROOT / "hepta/hia_native_differential.py",
        ROOT / "tools/build_hia_ndu_bridge.py", ROOT / "tools/build_hia_ndu_dynamic_bridge.py"]
    return {str(p.relative_to(ROOT)): sha256(p.read_bytes()).hexdigest() for p in sorted(set(paths)) if p.is_file()}

def schedule(family, seed, specification):
    """Pure registered input generation, independent of training or timing."""
    count, steps = specification["matrix_count"], specification["episode_steps"]
    order = list(range(count))
    random.Random(seed).shuffle(order)
    epochs = [1] * count
    result = []
    for step in range(steps):
        if family == "persistent_pair":
            target, repeats = order[step % 2], 8
        elif family == "phase_reuse":
            target, repeats = order[(step // 4) % count], 2 if step % 4 == 0 else 8
        elif family == "cyclic_pressure":
            target, repeats = order[step % count], 1
        elif family == "short_bursts":
            target, repeats = order[(step // 2) % count], 1
        elif family == "invalidate_recover":
            target, repeats = order[step % 2], 8
        elif family == "mixed_regime":
            target, repeats = order[(step * 5 + step // 3) % count], [1, 8, 2, 1][step % 4]
        else:
            raise ValueError("unregistered schedule family")
        mutations = []
        if (family == "invalidate_recover" and step in (6, 12, 18)) or (family == "mixed_regime" and step in (8, 16)):
            changed = order[(step // 6) % 2] if family == "invalidate_recover" else target
            epochs[changed] += 1
            mutations.append({"command": "mutate", "id": changed, "epoch": epochs[changed],
                              "seed": (seed * 31 + step * 97 + changed * 101) & 0xffffffff})
        result.append({"step": step, "target": target, "repeats": repeats,
            "vector_seed": (seed + step * 17) & 0xffffffff, "mutations": mutations})
    return result

def cohorts(specification):
    return [{"family": family, "n": n, "seed": seed,
             "id": f"{family}-n{n}-s{seed}", "jobs": schedule(family, seed, specification)}
        for family in specification["schedule_families"]
        for n in specification["holdout_dimensions"] for seed in specification["holdout_seeds"]]

def freeze(args):
    state = source_state()
    require(state["status"] == "" and state["commit"] == args.source_commit, "freeze requires exact clean source commit")
    specification = read_json(PROTOCOL.read_bytes())
    build = read_json(Path(args.manifest).read_bytes())
    require(build.get("upstream", {}).get("commit") == UPSTREAM and build.get("build_cost", {}).get("completed") is True,
            "completed pinned build required")
    require(build.get("build_cost", {}).get("target_cache_at_start") == "absent", "standalone campaign build target must start absent")
    binary = identity(args.binary)
    require(binary["sha256"] == build["binary_sha256"], "registered binary differs from build")
    expected = {str(p.relative_to(ADAPTER)): sha256(p.read_bytes()).hexdigest() for p in ADAPTER.rglob("*") if p.is_file()}
    require(build.get("adapter_files") == expected, "built adapter differs from frozen source")
    registration = {"schema": "hepta.hia.ndu.dynamic-cache.registration.v1", "source": state,
        "sources": source_inventory(), "protocol": specification, "protocol_sha256": sha256(PROTOCOL.read_bytes()).hexdigest(),
        "binary": binary, "build_manifest": identity(args.manifest), "python": identity(sys.executable),
        "cohorts": cohorts(specification), "cpu_affinity": sorted(os.sched_getaffinity(0)),
        "uname": list(os.uname()), "registered_unix_ns": time.time_ns(),
        "upstream": build["upstream"], "command": sys.argv,
        "holdout_measurement_started": False, "native_rust_experiment": True,
        "hia_compiler_qualification": False, "production_activation": False,
        "full_lifecycle_cost_known": False}
    write(args.output, registration)
    print(json.dumps({"registration": str(args.output), "sha256": sha256(Path(args.output).read_bytes()).hexdigest(),
        "cohorts": len(registration["cohorts"]), "planned_episodes": specification["expected_episode_count"]}, sort_keys=True))

def launch(binary, manifest, output, name, role):
    return JsonProcess(binary, manifest, role=role, log=output / (name + ".jsonl"))

def ask_workload(process, value):
    response, frame = process.ask(value)
    require(response.get("schema") == "hepta.hia.ndu.dynamic-cache.workload.response.v1", "workload refused: " + str(response.get("reason")))
    require(response.get("hia_compiler_qualification") is False, "workload claim drift")
    state = response["state"]
    require(state["resident_bytes"] <= state["quota_bytes"], "driver resident quota")
    return response, frame

def close_workload(process):
    result = None
    try:
        if process.process.poll() is None:
            result, _ = ask_workload(process, {"command": "close"})
            require(result["state"]["resident_bytes"] == 0 and result["state"]["baseline_bytes"] == 0,
                    "workload cleanup retains logical allocations")
            require(result["state"]["allocations"] == result["state"]["retirements"], "cache allocation/retirement imbalance")
    finally:
        process.close()
    require(process.returncode == 0, "workload process exit")
    return result

def train(binary, manifest, output, specification):
    rows, fees = [], {}
    for n in specification["training_dimensions"]:
        samples = {("direct", r): [] for r in specification["training_repeats"]}
        samples.update({("packed", r): [] for r in specification["training_repeats"]})
        prepares, retires = [], []
        for seed in specification["training_seeds"]:
            child = launch(binary, manifest, output, f"training-n{n}-s{seed}", "--workload-stream")
            try:
                ask_workload(child, {"command": "init", "count": 1, "n": n, "seed": seed, "quota_bytes": n*n*4})
                for repeat in specification["training_repeats"]:
                    for dispatch in ("direct", "packed"):
                        if dispatch == "packed":
                            _, elapsed = timed(lambda: ask_workload(child, {"command": "prepare", "id": 0, "epoch": 1}))
                            prepares.append(elapsed)
                        for _ in range(specification["warmup_calls"]):
                            ask_workload(child, {"command": "run", "id": 0, "vector_seed": seed,
                                "repeats": repeat, "dispatch": dispatch})
                        for sample in range(specification["training_samples_per_combination"]):
                            (response, _), elapsed = timed(lambda: ask_workload(child,
                                {"command": "run", "id": 0, "vector_seed": seed + sample,
                                 "repeats": repeat, "dispatch": dispatch}))
                            samples[(dispatch, repeat)].append(elapsed)
                            rows.append({"n": n, "seed": seed, "repeat": repeat, "dispatch": dispatch,
                                "sample": sample, "wall_ns": elapsed, "result": response})
                        if dispatch == "packed":
                            _, elapsed = timed(lambda: ask_workload(child, {"command": "retire", "id": 0}))
                            retires.append(elapsed)
            finally:
                close_workload(child)
        fees[str(n)] = {"execution_ns": {f"{mode}:{r}": median(values) for (mode, r), values in samples.items()},
            "prepare_ns": median(prepares), "retire_ns": median(retires),
            "raw_prepare_ns": prepares, "raw_retire_ns": retires}
    result = {"schema": "hepta.hia.ndu.dynamic-cache.training.v1", "dimensions": fees, "observations": rows,
        "holdout_timings_used": False, "forecast_rule": specification["forecast"]}
    result["binding_sha256"] = digest(result)
    write(output / "TRAINING.json", result)
    return result

def forecast(training, n, key, repeat=None):
    bank = training.get("_prepared_forecast_bank")
    if bank is not None:
        return bank[n][f"{key}:{repeat}" if repeat is not None else key]
    dimensions = sorted(map(int, training["dimensions"]))
    low = max((d for d in dimensions if d <= n), default=dimensions[0])
    high = min((d for d in dimensions if d >= n), default=dimensions[-1])
    def value(d):
        row = training["dimensions"][str(d)]
        raw = row["execution_ns"][f"{key}:{repeat}"] if repeat is not None else row[key]
        return raw / (d * d) if key != "retire_ns" else raw
    weight = 0 if high == low else (n - low) / (high - low)
    estimate = value(low) * (1 - weight) + value(high) * weight
    return max(0, round(estimate * (n * n if key != "retire_ns" else 1)))

def prepare_forecast_bank(training, specification, output):
    """Freeze arithmetic forecasts once; this caches no proof or NDU response."""
    from types import MappingProxyType
    started = time.monotonic_ns()
    rows = {}
    for n in sorted(set(specification["training_dimensions"] + specification["holdout_dimensions"])):
        rows[n] = {f"{mode}:{repeat}": forecast(training, n, mode, repeat)
                   for mode in ("direct", "packed") for repeat in specification["training_repeats"]}
        rows[n].update({key: forecast(training, n, key) for key in ("prepare_ns", "retire_ns")})
    binding = digest({"training_sha256": training["binding_sha256"], "rows": rows})
    training["_prepared_forecast_bank"] = MappingProxyType({n: MappingProxyType(v) for n, v in rows.items()})
    training["forecast_bank_sha256"] = binding
    result = {"schema": "hepta.hia.ndu.dynamic-cache.forecast-bank.v1", "training_sha256": training["binding_sha256"],
        "rows": rows, "binding_sha256": binding, "preparation_ns": time.monotonic_ns() - started,
        "cached_proof_or_native_response": False, "holdout_timings_used": False, "authority": "DENY_ALL"}
    write(output / "FORECAST_BANK.json", result)
    return result

def model_for(training, specification, workload_hash, cohort, index, state, costs, spent, session):
    window = cohort["jobs"][index:index + specification["lookahead"]]
    epochs = list(state["epochs"])
    arrays = [[] for _ in epochs]
    for offset, job in enumerate(window):
        if offset:
            for mutation in job["mutations"]:
                epochs[mutation["id"]] = mutation["epoch"]
        for i, epoch in enumerate(epochs):
            arrays[i].append(epoch)
    ready = sum(1 << i for i in state["ready"])
    n = cohort["n"]
    value = {"schema": MODEL_SCHEMA, "generation": index + 1,
        "objective_digest": digest(specification), "observation_digest": digest({"training": training["binding_sha256"],
            "forecast_bank": training.get("forecast_bank_sha256"),
            "announced_window": window, "current_epochs": state["epochs"], "n": n}),
        "workload_sha256": workload_hash,
        "artifacts": [{"id": f"matrix-{i}", "resident_bytes": n*n*4,
            "prepare_ns": forecast(training, n, "prepare_ns"), "retire_ns": forecast(training, n, "retire_ns"),
            "epochs": arr} for i, arr in enumerate(arrays)],
        "targets": [j["target"] for j in window],
        "direct_ns": [forecast(training, n, "direct", j["repeats"]) for j in window],
        "packed_ns": [forecast(training, n, "packed", j["repeats"]) for j in window],
        "ready_mask": ready, "ready_epochs": [e if ready & (1 << i) else 0 for i, e in enumerate(state["epochs"])],
        "memory_quota_bytes": n*n*4*specification["cache_slots"],
        "budget_ns": max(0, specification["episode_budget_ns"] - spent), "sunk_cost_ns": min(spent, 1_000_000_000_000),
        "completion_value_ns": specification["completion_value_ns"], "decision": costs, "session_ready": session}
    return validate_model(value)

def fixed_selection(training, specification):
    count = specification["matrix_count"]
    masks = [m for m in range(1 << count) if m.bit_count() <= specification["cache_slots"]]
    candidates = []
    for mask in masks:
        total = 0
        for n, seed, family in itertools.product(specification["training_dimensions"],
                                               specification["training_seeds"], specification["schedule_families"]):
            ready = 0
            for job in schedule(family, seed, specification):
                for change in job["mutations"]:
                    if ready & (1 << change["id"]):
                        total += forecast(training, n, "retire_ns")
                        ready &= ~(1 << change["id"])
                total += (mask & ~ready).bit_count() * forecast(training, n, "prepare_ns")
                ready = mask
                direct = forecast(training, n, "direct", job["repeats"])
                packed = forecast(training, n, "packed", job["repeats"])
                total += min(direct, packed) if ready & (1 << job["target"]) else direct
            total += ready.bit_count() * forecast(training, n, "retire_ns")
        candidates.append({"mask": mask, "training_modeled_ns": total})
    selected = min(candidates, key=lambda r: (r["training_modeled_ns"], r["mask"]))
    return {"candidates": candidates, "selected": selected, "exhaustive_static_sets": True,
            "holdout_times_or_queues_used": False}

def calibrate(binary, manifest, output, training, specification, workload_hash):
    zero = dict.fromkeys(("gate_ns", "solve_ns", "transport_validation_ns", "startup_ns", "close_ns"), 0)
    cohort = {"n": specification["training_dimensions"][1], "jobs": schedule("phase_reuse", 19, specification)}
    state = {"ready": [], "epochs": [1] * specification["matrix_count"]}
    model = model_for(training, specification, workload_hash, cohort, 0, state, zero, 0, False)
    def construct_and_gate():
        current = model_for(training, specification, workload_hash, cohort, 0, state, zero, 0, False)
        return invocation_gate(current)
    gate = median([timed(construct_and_gate)[1] for _ in range(21)])
    result = {"direct": zero, "fixed": zero}
    observations = {}
    for mode in MODES:
        session = launch(binary, manifest, output, "calibration-" + mode, "--planner-stream")
        calls = []
        try:
            for i in range(7):
                sample = deepcopy(model)
                sample["session_ready"] = i != 0
                response, row = session.evaluate(sample, mode)
                calls.append({"response_search_ns": response["search_ns"], "outer_call_ns": row["outer_call_ns"],
                              "validation_ns": row["validation_ns"], "evaluation_ns": response["evaluation_ns"]})
        finally:
            close = session.close()
        # Search is separated using the native clock. Everything else remains
        # one actual outer request remainder; no invented decomposition.
        result[mode] = {"gate_ns": gate, "solve_ns": median([v["response_search_ns"] for v in calls]),
            "transport_validation_ns": median([max(0, v["outer_call_ns"] - v["response_search_ns"]) for v in calls]),
            "startup_ns": session.startup_ns, "close_ns": close}
        observations[mode] = {"calls": calls, "startup_ns": session.startup_ns, "close_ns": close,
                              "forecast_costs": result[mode]}
    write(output / "CALIBRATION.json", {"costs": result, "observations": observations,
        "future_costs_are_forecasts": True, "native_search_and_outer_remainder_are_disjoint": True,
        "gate_ns_includes_future_model_construction": True})
    return result

def control_model(objects=3, horizon=3, seed=0):
    rng = random.Random(seed)
    ready = rng.randrange(1 << objects)
    return {"schema": MODEL_SCHEMA, "generation": 1, "objective_digest": digest("control objective"),
        "observation_digest": digest(["control observation", seed]), "workload_sha256": digest("finite control workload"),
        "artifacts": [{"id": f"matrix-{i}", "resident_bytes": 64, "prepare_ns": rng.randrange(1, 200),
            "retire_ns": rng.randrange(1, 40), "epochs": [1 + int(b >= 1 + (i+seed)%2) for b in range(horizon)]}
            for i in range(objects)],
        "targets": [rng.randrange(objects) for _ in range(horizon)],
        "direct_ns": [rng.randrange(50, 500) for _ in range(horizon)],
        "packed_ns": [rng.randrange(1, 150) for _ in range(horizon)], "ready_mask": ready,
        "ready_epochs": [1 if ready & (1 << i) else 0 for i in range(objects)],
        "memory_quota_bytes": 64 * objects, "budget_ns": 100_000_000,
        "sunk_cost_ns": 0, "completion_value_ns": 1_000_000_000,
        "decision": {"gate_ns": 3, "solve_ns": 11, "transport_validation_ns": 7, "startup_ns": 13, "close_ns": 5},
        "session_ready": seed % 2 == 0}

def exhaustive_cost(model):
    """Qualification-only exhaustive schedule enumeration; never the hot path."""
    masks = [m for m in range(1 << len(model["artifacts"])) if resident_bytes(model, m) <= model["memory_quota_bytes"]]
    best = None
    for path in itertools.product(masks, repeat=len(model["targets"])):
        ready = model["ready_mask"]
        total = call_cost(model, model["session_ready"]) + model["decision"]["close_ns"]
        for batch, target in enumerate(path):
            step = action(model, batch, ready, target)
            total += step["total_ns"]
            ready = target
        if total <= model["budget_ns"] and (best is None or total < best):
            best = total
    return best

def independent_exact_minimum(raw):
    """Offline independent bottom-up value proof over every legal cache state.

    This does not call the Rust planner, its witnesses, `action`, or any NDU
    API. No result is used to dispatch a workload. Its measured cost belongs
    to the post-campaign audit, never just the exact-DP online comparator.
    """
    model = validate_model(raw)
    artifacts = model["artifacts"]
    count, horizon = len(artifacts), len(model["targets"])
    all_masks = range(1 << count)
    capacity = [sum(a["resident_bytes"] for i, a in enumerate(artifacts) if mask & (1 << i)) for mask in all_masks]
    masks = [mask for mask in all_masks if capacity[mask] <= model["memory_quota_bytes"]]
    preparation = [sum(a["prepare_ns"] for i, a in enumerate(artifacts) if mask & (1 << i)) for mask in all_masks]
    retirement = [sum(a["retire_ns"] for i, a in enumerate(artifacts) if mask & (1 << i)) for mask in all_masks]
    fees = model["decision"]
    steady = fees["solve_ns"] + fees["transport_validation_ns"]
    values = {mask: fees["close_ns"] for mask in masks}
    for batch in range(horizon - 1, -1, -1):
        valid_bits = sum(1 << i for i, a in enumerate(artifacts)
            if (model["ready_epochs"][i] if batch == 0 else a["epochs"][batch - 1]) == a["epochs"][batch])
        execution = {target: (min(model["direct_ns"][batch], model["packed_ns"][batch])
            if target & (1 << model["targets"][batch]) else model["direct_ns"][batch]) for target in masks}
        next_values = {}
        for before in masks:
            live = before & valid_bits
            next_values[before] = min(
                execution[target] + preparation[target & ~live] + retirement[before & ~(target & live)]
                + fees["gate_ns"] + (steady if batch > 0 and target != live else 0) + values[target]
                for target in masks)
        values = next_values
    current = steady + (0 if model["session_ready"] else fees["startup_ns"])
    minimum = values[model["ready_mask"]] + current
    return minimum if minimum <= model["budget_ns"] else None

def correctness(binary, manifest, output, specification, registration):
    started = time.monotonic_ns()
    checks, rejected = [], []
    planner = launch(binary, manifest, output, "correctness-planner", "--planner-stream")
    try:
        for seed in range(36):
            model = validate_model(control_model(1 + seed % 3, 1 + (seed // 3) % 3, seed))
            if seed % 5 == 0:
                model["budget_ns"] = 0
            if seed % 7 == 0:
                model["ready_mask"] = 0
                model["ready_epochs"] = [0] * len(model["artifacts"])
                model["memory_quota_bytes"] = 0
            oracle = exhaustive_cost(model)
            require(independent_exact_minimum(model) == oracle, "independent bottom-up oracle disagrees with exhaustive enumeration")
            responses = {}
            for mode in MODES:
                response, _ = planner.evaluate(model, mode)
                responses[mode] = response
                costs = [p["total_ns"] for p in response["bundle"]["plans"].values()]
                actual = min(costs, default=None)
                if mode == "exact_dp":
                    require(actual == oracle, "native exact DP disagrees with exhaustive schedule enumeration")
                else:
                    require(actual is None or oracle is not None and actual >= oracle, "approximate plan beats exact arithmetic")
            require(responses["beam"]["bundle"] == responses["beam_ndu"]["bundle"]
                and responses["beam"]["pareto_candidate_ids"] == responses["beam_ndu"]["pareto_candidate_ids"]
                and responses["beam"]["selected_first_action"] == responses["beam_ndu"]["selected_first_action"], "NDU ablation changed candidate search or scalar result")
            checks.append({"case": seed, "exact_exhaustive_ns": oracle, "all_four_modes_validated": True})
        example = control_model()
        variants = []
        for label, mutate in (
            ("unknown_field", lambda m: m.update(unsupported=True)),
            ("boolean_budget", lambda m: m.update(budget_ns=True)),
            ("overflow_cost", lambda m: m.update(direct_ns=[2**63]*3)),
            ("empty_artifacts", lambda m: m.update(artifacts=[])),
            ("zero_generation", lambda m: m.update(generation=0)),
            ("unknown_ready_bit", lambda m: m.update(ready_mask=256)),
            ("epoch_shape", lambda m: m["artifacts"][0].update(epochs=[])),
            ("epoch_rollback", lambda m: m["artifacts"][0].update(epochs=[1,2,1])),
            ("false_source_digest", lambda m: m.update(workload_sha256="0"*64)),
        ):
            value = deepcopy(example)
            mutate(value)
            variants.append((label, {"schema": REQUEST_SCHEMA, "mode": "exact_dp", "model": value}))
        variants += [("unknown_mode", {"schema": REQUEST_SCHEMA, "mode": "execute", "model": example}),
                     ("wrong_role", {"command": "init", "count": 1, "n": 8, "seed": 1, "quota_bytes": 256})]
        for label, request in variants:
            response, _ = planner.ask(request)
            require(response.get("schema") == REFUSAL_SCHEMA and response.get("execution_authorized") is False, "native invalid model was not refused")
            rejected.append({"case": label, "response": response})
        planner.evaluate(example, "exact_dp")
        # Mutations of an otherwise valid witness exercise caller admission.
        response, record = planner.evaluate(example, "exact_dp")
        from hepta.hia_ndu_dynamic import validate_response
        payload = wire({"schema": REQUEST_SCHEMA, "mode": "exact_dp", "model": example})
        for label in ("quota", "total", "boolean_projection", "authority"):
            value = deepcopy(response)
            plan = next(iter(value["bundle"]["plans"].values()))
            if label == "quota":
                plan["actions"][0]["ready_after"] = 256
            elif label == "total":
                plan["total_ns"] -= 1
            elif label == "boolean_projection":
                value["selected_first_action"]["gate_ns"] = True
            else:
                value["execution_authorized"] = True
            try:
                validate_response(example, "exact_dp", payload, value)
            except DynamicError as error:
                rejected.append({"case": "witness_" + label, "reason": str(error)})
            else:
                raise DynamicError("mutated native witness was accepted")
    finally:
        planner.close()
    child = launch(binary, manifest, output, "correctness-workload", "--workload-stream")
    try:
        ask_workload(child, {"command": "init", "count": 3, "n": 17, "seed": 0xffffffff, "quota_bytes": 17*17*4})
        first, _ = ask_workload(child, {"command": "prepare", "id": 0, "epoch": 1})
        reused, _ = ask_workload(child, {"command": "prepare", "id": 0, "epoch": 1})
        require(reused["state"]["allocations"] == first["state"]["allocations"] and reused["result"]["reused"] is True, "physical cache reuse")
        for label, request in (
            ("quota", {"command": "prepare", "id": 1, "epoch": 1}),
            ("stale_epoch", {"command": "prepare", "id": 0, "epoch": 2}),
            ("missing_resident", {"command": "run", "id": 1, "vector_seed": 7, "repeats": 1, "dispatch": "packed"}),
            ("workload_wrong_role", {"schema": REQUEST_SCHEMA, "mode": "exact_dp", "model": example}),
        ):
            before, _ = ask_workload(child, {"command": "state"})
            result, _ = child.ask(request)
            after, _ = ask_workload(child, {"command": "state"})
            require(result.get("schema") == REFUSAL_SCHEMA and before["state"] == after["state"], "workload refusal changed resource state")
            rejected.append({"case": label, "response": result, "state_unchanged": True})
        direct, _ = ask_workload(child, {"command": "run", "id": 0, "vector_seed": 0xffffffef, "repeats": 2, "dispatch": "direct"})
        packed, _ = ask_workload(child, {"command": "run", "id": 0, "vector_seed": 0xffffffef, "repeats": 2, "dispatch": "packed"})
        require(direct["result"]["checksum"] == packed["result"]["checksum"], "physical kernel mismatch")
        mutated, _ = ask_workload(child, {"command": "mutate", "id": 0, "epoch": 2, "seed": 811})
        require(mutated["state"]["resident_bytes"] == 0 and mutated["result"]["invalidated_cache"], "epoch did not drop cache")
        result, _ = child.ask({"command": "run", "id": 0, "vector_seed": 7, "repeats": 1, "dispatch": "packed"})
        require(result.get("schema") == REFUSAL_SCHEMA, "stale data cache dispatched")
        rejected.append({"case": "post_invalidation_dispatch", "response": result})
        ask_workload(child, {"command": "prepare", "id": 0, "epoch": 2})
        recovered, _ = ask_workload(child, {"command": "run", "id": 0, "vector_seed": 7, "repeats": 1, "dispatch": "packed"})
        checks.append({"case": "actual_prepare_reuse_quota_invalidate_reprepare", "response": recovered})
    finally:
        cleanup = close_workload(child)
    require(planner.returncode == 0 and child.returncode == 0, "control streams not reaped")
    result = {"passed": True, "checks": checks, "refusals": rejected, "skips": 0,
        "native_planner_calls": planner.calls, "native_workload_calls": child.calls,
        "cleanup": cleanup, "wall_ns": time.monotonic_ns() - started,
        "scope": "finite cross-implementation arithmetic, resource refusals, generated matrix family, no HIA or whole-language theorem"}
    write(output / "CONTROLS.json", result)
    return result

def summarize_audits(audit):
    result = {}
    for mode in MODES:
        rows = [r for r in audit["rows"] if r["policy"] == mode]
        gaps = [r["selected_plan_gap_ns"] for r in rows if r["selected_plan_gap_ns"] is not None]
        result[mode] = {"requests": len(rows), "defined_gaps": len(gaps), "zero_gap": sum(g == 0 for g in gaps),
            "positive_gap": sum(g > 0 for g in gaps), "maximum_gap_ns": max(gaps, default=None),
            "sum_model_gap_ns": sum(gaps), "online_search_sum_ns": sum(r["online_search_ns"] for r in rows),
            "online_call_sum_ns": sum(r["online_call_ns"] for r in rows),
            "reference_exact_search_sum_ns": sum(r["exact_search_ns"] for r in rows),
            "reference_exact_call_sum_ns": sum(r["exact_outer_call_ns"] for r in rows),
            "independent_bottom_up_audit_sum_ns": sum(r["independent_bottom_up_wall_ns"] for r in rows),
            "every_exact_minimum_independently_checked": all(r["native_exact_minimum_independently_checked"] for r in rows),
            "model_gap_is_not_actual_execution_regret": True}
    return result

def summarize_comparisons(rows, registration):
    result = []
    for cohort in registration["cohorts"]:
        values = {}
        complete = True
        for policy in registration["protocol"]["arms"]:
            selected = [r for r in rows if r["cohort"] == cohort["id"] and r["policy"] == policy]
            valid = len(selected) == registration["protocol"]["repetitions"] and all(r["status"] == "passed" for r in selected)
            complete &= valid
            values[policy] = {"count": len(selected), "passed": sum(r["status"] == "passed" for r in selected),
                "service_total_ns": sum(r["service_wall_ns"] for r in selected),
                "service_median_ns": median([r["service_wall_ns"] for r in selected]) if valid else None}
        native = values["beam_ndu"]["service_median_ns"]
        controls = [v["service_median_ns"] for p, v in values.items() if p != "beam_ndu"]
        result.append({"cohort": cohort["id"], "complete": complete, "arms": values,
            "native_service_beats_every_control": complete and all(native < v for v in controls),
            "native_over_best_control": native / min(controls) if complete else None,
            "native_over_no_ndu_beam": native / values["beam"]["service_median_ns"] if complete else None,
            "service_only_not_full_cost_claim": True})
    return result

def count_rows(rows, specification):
    requests = sum(len(r["steps"]) for r in rows)
    passed = sum(r["status"] == "passed" for r in rows)
    return {"planned_episodes": specification["expected_episode_count"], "episodes": len(rows), "passed": passed,
        "failed": len(rows) - passed, "planned_workload_executions": specification["expected_online_workload_requests"],
        "workload_executions": requests, "planner_requests": sum(r["planner_requests"] for r in rows),
        "actual_ndu_requests": sum(r["native_ndu_requests"] for r in rows),
        "invocation_skips": sum(r["invocation_skips"] for r in rows),
        "optional_budget_withholdings": sum(r["optional_budget_withholdings"] for r in rows),
        "preparations": sum(len(s["prepared"]) for r in rows for s in r["steps"]),
        "policy_retirements": sum(len(s["retired"]) for r in rows for s in r["steps"]),
        "reuse_events": sum(len(s["reused"]) for r in rows for s in r["steps"]),
        "actual_cache_invalidations": sum(int(m["response"]["result"]["invalidated_cache"]) for r in rows for s in r["steps"] for m in s["mutations"]),
        "complete": len(rows) == passed == specification["expected_episode_count"]
            and requests == specification["expected_online_workload_requests"]}

def episode(binary, manifest, output, registration, training, costs, fixed, cohort, repeat, policy, audit_rows):
    specification = registration["protocol"]
    name = f"r{repeat}-{cohort['id']}-{policy}"
    started = time.monotonic_ns()
    row = {"id": name, "cohort": cohort["id"], "family": cohort["family"], "n": cohort["n"], "seed": cohort["seed"],
        "repeat": repeat, "policy": policy, "status": "running", "steps": [], "native_ndu_requests": 0,
        "planner_requests": 0, "invocation_skips": 0, "optional_budget_withholdings": 0,
        "component_ns": {}, "error": None}
    child = session = None
    model_hash = registration["sources"]["rust/hia-ndu-dynamic-model/src/workload.rs"]
    try:
        child, elapsed = timed(lambda: launch(binary, manifest, output, name + "-workload", "--workload-stream"))
        row["component_ns"]["workload_startup"] = elapsed
        (response, _), elapsed = timed(lambda: ask_workload(child, {"command": "init", "count": specification["matrix_count"],
            "n": cohort["n"], "seed": cohort["seed"], "quota_bytes": cohort["n"]**2*4*specification["cache_slots"]}))
        row["component_ns"]["initialization"] = elapsed
        state = response["state"]
        for index, job in enumerate(cohort["jobs"]):
            step = {"index": index, "job": job, "mutations": [], "retired": [], "prepared": []}
            for change in job["mutations"]:
                (response, _), elapsed = timed(lambda change=change: ask_workload(child, change))
                step["mutations"].append({"response": response, "wall_ns": elapsed})
                state = response["state"]
            make = time.monotonic_ns()
            model = model_for(training, specification, model_hash, cohort, index, state, costs[policy],
                              time.monotonic_ns() - started, session is not None)
            step["model_construction_ns"] = time.monotonic_ns() - make
            decision_start = time.monotonic_ns()
            selected = None
            response = None
            if policy in ("direct", "fixed"):
                destination = 0 if policy == "direct" else fixed["selected"]["mask"]
                selected = action(model, 0, model["ready_mask"], destination)
                decision = {"policy": policy, "fixed_mask": destination, "native_evaluation": False}
            else:
                gate = invocation_gate(model)
                decision = {"gate": gate}
                if not gate["invoke"]:
                    row["invocation_skips"] += 1
                    selected = action(model, 0, model["ready_mask"], live_mask(model, 0, model["ready_mask"]))
                else:
                    if session is None:
                        session = launch(binary, manifest, output, name + "-planner", "--planner-stream")
                        decision["session_startup_ns"] = session.startup_ns
                    response, receipt = session.evaluate(model, policy)
                    selected = response["selected_first_action"]
                    decision.update(receipt=receipt, response=response)
                    row["planner_requests"] += 1
                    row["native_ndu_requests"] += int(policy == "beam_ndu")
                    audit_rows.append({"episode": name, "step": index, "policy": policy, "model": model,
                        "response": response, "online_call_ns": receipt["outer_call_ns"]})
            elapsed = time.monotonic_ns() - decision_start
            if selected is not None and selected["mode"] == "invoke" and elapsed >= model["budget_ns"]:
                decision["optional_action_withheld"] = True
                row["optional_budget_withholdings"] += 1
                selected = None
            if selected is None:
                selected = action(model, 0, model["ready_mask"], live_mask(model, 0, model["ready_mask"]))
            step["decision"], step["decision_wall_ns"] = decision, elapsed
            step["forecast"], step["selected_action"] = model, selected
            destination = selected["ready_after"]
            # Independent actual-state admission; a proposal cannot increase
            # quota, change a data epoch or smuggle a foreign matrix identity.
            actual_mask = sum(1 << i for i in state["ready"])
            require(actual_mask == model["ready_mask"] and state["epochs"] == [a["epochs"][0] for a in model["artifacts"]], "actual state drift")
            require(resident_bytes(model, destination) <= state["quota_bytes"], "actual quota admission")
            step["reused"] = [i for i in state["ready"] if destination & (1 << i)]
            for i in list(state["ready"]):
                if not destination & (1 << i):
                    (response, _), elapsed = timed(lambda i=i: ask_workload(child, {"command": "retire", "id": i}))
                    step["retired"].append({"id": i, "wall_ns": elapsed, "response": response})
                    state = response["state"]
            for i in range(specification["matrix_count"]):
                if destination & (1 << i) and i not in state["ready"]:
                    # Actual elapsed budget is checked again immediately before
                    # each optional allocation, after all preceding real work.
                    if time.monotonic_ns() - started >= specification["episode_budget_ns"]:
                        row["optional_budget_withholdings"] += 1
                        step.setdefault("prepare_withheld", []).append(i)
                        continue
                    (response, _), elapsed = timed(lambda i=i: ask_workload(child,
                        {"command": "prepare", "id": i, "epoch": state["epochs"][i]}))
                    step["prepared"].append({"id": i, "wall_ns": elapsed, "response": response})
                    state = response["state"]
            dispatch = "packed" if job["target"] in state["ready"] and model["packed_ns"][0] < model["direct_ns"][0] else "direct"
            (response, _), elapsed = timed(lambda: ask_workload(child, {"command": "run", "id": job["target"],
                "vector_seed": job["vector_seed"], "repeats": job["repeats"], "dispatch": dispatch}))
            step["execution"], step["execution_wall_ns"] = response, elapsed
            predicted = model["packed_ns"][0] if dispatch == "packed" else model["direct_ns"][0]
            step["prediction_error_ns"] = elapsed - predicted
            step["predicted_execution_ns"] = predicted
            step["execution_dispatch"] = dispatch
            state = response["state"]
            row["steps"].append(step)
        row["status"] = "passed"
    except Exception as error:
        row["status"] = "failed"
        row["error"] = f"{type(error).__name__}: {error}"
    finally:
        cleanup_errors = []
        if session is not None:
            try:
                row["component_ns"]["planner_close"] = session.close()
                require(session.returncode == 0, "planner exit")
            except BaseException as error:
                cleanup_errors.append(f"planner: {type(error).__name__}: {error}")
        if child is not None:
            try:
                cleanup, elapsed = timed(lambda: close_workload(child))
                row["cleanup"] = cleanup
                row["component_ns"]["workload_close"] = elapsed
            except BaseException as error:
                cleanup_errors.append(f"workload: {type(error).__name__}: {error}")
        row["cleanup_errors"] = cleanup_errors
        if cleanup_errors:
            row["status"] = "failed"
        row["service_wall_ns"] = time.monotonic_ns() - started
        parts = dict(row["component_ns"])
        parts["model_construction"] = sum(s["model_construction_ns"] for s in row["steps"])
        parts["decision_including_startup_and_replay"] = sum(s["decision_wall_ns"] for s in row["steps"])
        parts["data_mutation_and_invalidation"] = sum(m["wall_ns"] for s in row["steps"] for m in s["mutations"])
        parts["prepare"] = sum(p["wall_ns"] for s in row["steps"] for p in s["prepared"])
        parts["policy_retire"] = sum(p["wall_ns"] for s in row["steps"] for p in s["retired"])
        parts["execution_including_oracle_and_transport"] = sum(s["execution_wall_ns"] for s in row["steps"])
        row["disjoint_service_components_ns"] = parts
        row["other_service_ns"] = row["service_wall_ns"] - sum(parts.values())
        if row["other_service_ns"] < 0:
            row["status"] = "failed"
            row["error"] = "overlapping service component accounting"
        write(output / (name + ".json"), row)
    return row

def exact_audit(binary, manifest, output, rows):
    started = time.monotonic_ns()
    audits = []
    session = None
    try:
        for index, item in enumerate(rows):
            if session is None or session.calls >= 4000:
                if session is not None:
                    session.close()
                session = launch(binary, manifest, output, f"exact-audit-{index}", "--planner-stream")
            response, receipt = session.evaluate(item["model"], "exact_dp")
            exact = min((p["total_ns"] for p in response["bundle"]["plans"].values()), default=None)
            independent, independent_ns = timed(lambda: independent_exact_minimum(item["model"]))
            require(exact == independent, "native exact minimum or search completeness failed independent full-state audit")
            selected_ids = item["response"]["pareto_candidate_ids"]
            selected_cost = (min((item["response"]["bundle"]["plans"][key]["total_ns"]
                for key in selected_ids if key != "abstain"), default=None)
                if item["response"]["selected_first_action"] is not None else None)
            gap = None if exact is None or selected_cost is None else selected_cost - exact
            require(gap is None or gap >= 0, "negative exact DP gap")
            audits.append({"episode": item["episode"], "step": item["step"], "policy": item["policy"],
                "model_sha256": digest(item["model"]), "selected_model_total_ns": selected_cost,
                "same_information_exact_model_total_ns": exact, "selected_plan_gap_ns": gap,
                "exact_search_ns": response["search_ns"], "exact_outer_call_ns": receipt["outer_call_ns"],
                "independent_bottom_up_minimum_ns": independent, "independent_bottom_up_wall_ns": independent_ns,
                "native_exact_minimum_independently_checked": True,
                "online_search_ns": item["response"]["search_ns"], "online_call_ns": item["online_call_ns"],
                "gap_is_model_cost_not_measured_regret": True})
    finally:
        if session is not None:
            session.close()
    result = {"rows": audits, "wall_ns": time.monotonic_ns() - started,
              "fed_online_decisions": False, "same_information_per_model": True,
              "every_native_exact_minimum_independently_checked": True}
    write(output / "EXACT_AUDIT.json", result)
    return result

def qualify(args):
    registration = read_json(Path(args.registration).read_bytes())
    require(registration["schema"] == "hepta.hia.ndu.dynamic-cache.registration.v1", "registration schema")
    require(source_state() == registration["source"] and source_inventory() == registration["sources"], "source changed after registration")
    require(identity(args.binary) == registration["binary"] and identity(args.manifest) == registration["build_manifest"], "registered executable/manifest changed")
    require(sorted(os.sched_getaffinity(0)) == registration["cpu_affinity"], "CPU affinity differs from freeze")
    require(identity(sys.executable) == registration["python"], "Python identity changed")
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=False)
    started = time.monotonic_ns()
    specification = registration["protocol"]
    report = {"schema": "hepta.hia.ndu.dynamic-cache.qualification.v1", "status": "running",
        "registration_sha256": sha256(Path(args.registration).read_bytes()).hexdigest(), "source": registration["source"],
        "native_rust_experiment": True, "hia_compiler_qualification": False, "rows": [],
        "full_lifecycle_cost_known": False, "previous_hia_result": specification["previous_negative_baseline"], "errors": []}
    write(output / "REGISTRATION.json", registration)
    try:
        controls = correctness(args.binary, args.manifest, output, specification, registration)
        report["correctness"] = controls
        require(controls["passed"], "correctness/refusal gate failed")
        training = train(args.binary, args.manifest, output, specification)
        report["forecast_bank"] = prepare_forecast_bank(training, specification, output)
        fixed, fixed_ns = timed(lambda: fixed_selection(training, specification))
        write(output / "FIXED_SELECTION.json", {**fixed, "wall_ns": fixed_ns})
        costs = calibrate(args.binary, args.manifest, output, training, specification,
            registration["sources"]["rust/hia-ndu-dynamic-model/src/workload.rs"])
        report["offline_before_online_ns"] = time.monotonic_ns() - started
        audit_rows = []
        for repeat in range(specification["repetitions"]):
            for cohort_index, cohort in enumerate(registration["cohorts"]):
                arms = specification["arms"]
                offset = (repeat + cohort_index) % len(arms)
                for policy in arms[offset:] + arms[:offset]:
                    report["rows"].append(episode(args.binary, args.manifest, output, registration,
                        training, costs, fixed, cohort, repeat, policy, audit_rows))
        audit = exact_audit(args.binary, args.manifest, output, audit_rows)
        report["exact_audit_summary"] = summarize_audits(audit)
        report["audit_wall_ns"] = audit["wall_ns"]
        report["comparisons"] = summarize_comparisons(report["rows"], registration)
        report["counts"] = count_rows(report["rows"], specification)
        report["source_unchanged"] = source_state() == registration["source"] and source_inventory() == registration["sources"]
        report["tools_unchanged"] = identity(args.binary) == registration["binary"] and identity(args.manifest) == registration["build_manifest"] and identity(sys.executable) == registration["python"]
        report["status"] = "passed" if report["counts"]["complete"] and report["source_unchanged"] and report["tools_unchanged"] else "failed"
    except BaseException as error:
        report["status"] = "failed"
        report["errors"].append(f"{type(error).__name__}: {error}")
    finally:
        report["campaign_internal_before_report_ns"] = time.monotonic_ns() - started
        build = read_json(Path(args.manifest).read_bytes())
        service = {p: sum(r["service_wall_ns"] for r in report["rows"] if r["policy"] == p) for p in specification["arms"]}
        remainder = report["campaign_internal_before_report_ns"] - sum(service.values())
        report["costs"] = {"actual_service_sum_ns": sum(service.values()), "service_by_arm_ns": service,
            "actual_campaign_internal_before_report_ns": report["campaign_internal_before_report_ns"],
            "shared_campaign_remainder_ns": remainder, "observed_build_inner_ns": build["build_cost"]["wall_ns"],
            "conservative_alternative_allocations_before_outer_correction_ns": {
                p: service[p] + remainder + build["build_cost"]["wall_ns"] for p in service},
            "allocations_overlap_do_not_sum": True, "all_arms_use_same_native_image": True,
            "separate_non_ndu_build_cost_not_isolated": True,
            "outer_process_and_build_wrapper_correction_required": True,
            "unknown_costs": ["historical tool/dependency acquisition", "human engineering/review", "long-term operation and retention"]}
        require(remainder >= 0, "overlapping service accounting")
        write(output / "RESULT.json", report)
        print(json.dumps({"status": report["status"], "output": str(output), "counts": report.get("counts"),
                          "comparisons": report.get("comparisons")}, sort_keys=True))
    return 0 if report["status"] == "passed" else 1

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    register = commands.add_parser("freeze")
    register.add_argument("--source-commit", required=True)
    register.add_argument("--binary", required=True)
    register.add_argument("--manifest", required=True)
    register.add_argument("--output", required=True)
    run = commands.add_parser("run")
    run.add_argument("--registration", required=True)
    run.add_argument("--binary", required=True)
    run.add_argument("--manifest", required=True)
    run.add_argument("--output", required=True)
    args = parser.parse_args()
    return freeze(args) if args.command == "freeze" else qualify(args)

if __name__ == "__main__":
    raise SystemExit(main())
