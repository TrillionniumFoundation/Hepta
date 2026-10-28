#!/usr/bin/env python3
"""Registered native NDU cost study; safety still belongs to the HIA verifier.

The controller layer measures finite models only. The application layer executes
real proof-gated native code and a shared, consumable compilation-attempt quota.
All previous outcomes remain immutable. A failed economic gate is a valid result.
"""
from __future__ import annotations

import argparse
from collections import OrderedDict
from copy import deepcopy
from datetime import datetime, timezone
from functools import lru_cache
from hashlib import sha256
from itertools import product
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys
from threading import Lock
import time

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from hepta.hia_ndu import NduBridge, NduBridgeError, Q32, REQUEST_SCHEMA, candidate, event, _read_json
from hepta.hia_ndu_cache import NduDecisionCache, _wire
from hepta.hia_ndu_session import NduSession, STREAM_SOURCE_PIN
from hepta.hia_ndu_optimizer import ns_to_ms_q32
from hepta.hia_guarded_optimization import (build_guarded_native, guarded_checker_identity,
    propose_guarded_reduction, verify_guarded_optimization)
from hepta.hia_optimization import build_optimized_native, verify_optimization
from hepta.hia_program_source import lower_source
from tools.qualify_hia_ndu_graph import DRIVER, calibration
from tools.qualify_hia_ndu_loop import EpisodeBudget, digest, execute_sample, measured

PROTOCOL_PATH = ROOT / "experiments/hia_ndu_net_value/PROTOCOL_20261028.json"
CONTROLLER_ARMS = ("fixed-reuse", "dp-reuse", "native-oneshot", "native-stream-rehash",
                   "native-stream-sealed", "native-stream-sealed-cache")
APPLICATION_ARMS = ("fixed", "dp", "native-stream-sealed")


def save(path, value):
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True, indent=2, allow_nan=False)
        stream.write("\n")


def validate_protocol(p):
    if (p.get("schema") != "hepta.hia.ndu.net-value.protocol.v1"
            or p.get("native_source_pin") != STREAM_SOURCE_PIN
            or p.get("native_rustc") != "1.90.0"
            or p.get("controller_arms") != list(CONTROLLER_ARMS)
            or p.get("application_arms") != list(APPLICATION_ARMS)
            or p.get("controller_profiles") != ["identical-retries", "changed-generation"]
            or p.get("authority") != "DENY_ALL" or p.get("safety_certificate") is not False):
        raise ValueError("unsupported registered net-value profile")
    for key, low, high in (("groups", 1, 8), ("controller_keys", 1, 8),
                          ("controller_repetitions", 2, 16), ("calls", 1, 1_000_000),
                          ("calibration_repetitions", 1, 8), ("cache_entries", 1, 128)):
        if type(p.get(key)) is not int or not low <= p[key] <= high:
            raise ValueError("invalid registered integer: " + key)
    if p["controller_keys"] * p["controller_repetitions"] > 256:
        raise ValueError("trace exceeds original native session request bound")
    for key in ("episode_budget_ns", "completion_value_ns", "cache_payload_bytes"):
        if type(p.get(key)) is not int or not 1 <= p[key] <= 1_000_000_000_000:
            raise ValueError("invalid positive bounded integer: " + key)
    if (type(p.get("controller_timeout_s")) not in {int, float}
            or not 0 < p["controller_timeout_s"] <= 120
            or p.get("guard_limits") != {"guard-small": 128, "guard-wide": 16384}
            or p.get("calibration_sizes") != [31, 1021, 8191]
            or p.get("default_cache_enabled") is not False
            or p.get("sample_exclusion") != "none; failed, refused and timed-out attempts retained with their incurred cost"):
        raise ValueError("invalid protocol boundary")
    if set(p["application_profiles"]) != {"stable-reuse", "changing-load", "shared-budget"}:
        raise ValueError("registered application profiles changed")
    for spec in p["application_profiles"].values():
        traces = spec["module_sizes"]
        if (not 1 <= len(traces) <= 2 or not 1 <= spec["compile_credits"] <= 2
                or not 2 <= len(traces[0]) <= 12 or len({len(row) for row in traces}) != 1
                or any(type(n) is not int or n not in p["calibration_sizes"] for row in traces for n in row)):
            raise ValueError("invalid bounded application trace")
    return p


class CompilationCredits:
    """One owner consumes actual build-attempt permits, including failed builds."""
    def __init__(self, limit):
        if type(limit) is not int or not 0 <= limit <= 16:
            raise ValueError("compile credit limit must be a bounded integer")
        self.limit, self.used, self.attempts, self._lock = limit, 0, [], Lock()

    @property
    def remaining(self):
        with self._lock:
            return self.limit - self.used

    def consume(self, module, target):
        with self._lock:
            if self.used >= self.limit:
                raise RuntimeError("shared compilation-attempt budget exhausted")
            self.used += 1
            self.attempts.append({"sequence": self.used, "module": module, "target": target})
            return self.used


def plan_key(plan):
    return plan["cost_ns"], plan["credits"], tuple(plan["targets"])


def enumerate_plans(model):
    result = []
    for choices in product(*model["modules"]):
        targets = [c["target"] for c in choices]
        result.append({"id": "allocation-" + digest(targets)[:20], "targets": targets,
                       "credits": sum(c["credits"] for c in choices),
                       "cost_ns": sum(c["cost_ns"] for c in choices),
                       "verified": all(c["verified"] for c in choices)})
    return result


def complete_budget_dp(model):
    """Exact multiple-choice DP over the same stationary suffix allocations."""
    @lru_cache(None)
    def best(index, credits):
        if index == len(model["modules"]):
            return {"targets": [], "credits": 0, "cost_ns": 0, "verified": True}
        options = []
        for row in model["modules"][index]:
            if row["verified"] and row["credits"] <= credits:
                tail = best(index + 1, credits - row["credits"])
                if tail is not None:
                    options.append({"targets": [row["target"], *tail["targets"]],
                                    "credits": row["credits"] + tail["credits"],
                                    "cost_ns": row["cost_ns"] + tail["cost_ns"], "verified": True})
        return min(options, key=plan_key) if options else None
    result = best(0, model["remaining_credits"])
    if result is not None:
        result = dict(result, id="allocation-" + digest(result["targets"])[:20])
    return result


def native_request(model, protocol, generation):
    objective = digest({"protocol": protocol, "scope": "registered-stationary-suffix-allocations"})
    snapshot = digest({"model": model, "generation": generation})
    paths = enumerate_plans(model)
    rows = [candidate(candidate_id=row["id"], verified=row["verified"],
        verification_digest=digest({"upstream_proof_support": model["support"], "targets": row["targets"]}),
        support_digest=digest(model), events=[event(identity=snapshot + ":" + row["id"],
            instant_q32=-ns_to_ms_q32(row["cost_ns"]), preference_digest=objective)],
        terminal_q32=ns_to_ms_q32(protocol["completion_value_ns"]),
        resource_cost_q32=row["credits"] * Q32) for row in paths]
    # The known rejected candidate is deliberately tempting and must never win.
    rows.append(candidate(candidate_id="known-refused", verified=False,
        verification_digest=digest("known-refusal"), support_digest=digest(model),
        events=[event(identity=snapshot + ":refused", instant_q32=Q32, preference_digest=objective)],
        terminal_q32=ns_to_ms_q32(protocol["completion_value_ns"])))
    rows.append(candidate(candidate_id="abstain", verified=True,
        verification_digest=digest("literal-no-effect"), support_digest=digest(model),
        events=[event(identity=snapshot + ":abstain", instant_q32=0, preference_digest=objective)],
        terminal_q32=0))
    return {"schema": REQUEST_SCHEMA, "objective_digest": objective, "snapshot_digest": snapshot,
            "generation": generation, "utility_unit": "completion-minus-wall-milliseconds",
            "resource_unit": "modeled-work", "risk_unit": "probability",
            "resource_budget_q32": model["remaining_credits"] * Q32, "risk_ceiling_q32": Q32,
            "candidates": rows}, {row["id"]: row for row in paths}


def select_native(model, protocol, generation, bridge, cache=None):
    request, plans = native_request(model, protocol, generation)
    response, reuse = (cache.evaluate_with_receipt(request) if cache else (bridge.evaluate(request), None))
    chosen = response["advisory_candidate_id"]
    tied = False
    if chosen is None:
        feasible = [plans[key] for key in response["pareto_candidate_ids"] if key in plans]
        if not feasible:
            raise RuntimeError("native frontier has no admitted executable allocation")
        chosen = min(feasible, key=plan_key)["id"]
        tied = True
    if chosen not in plans or not plans[chosen]["verified"] or plans[chosen]["credits"] > model["remaining_credits"]:
        raise RuntimeError("native advice has no legal allocation")
    return plans[chosen], {"request": request, "response": response, "reuse": reuse,
                          "registered_frontier_tie_rule_used": tied}


class RecordedSession(NduSession):
    def __init__(self, binary, identity, folder, **options):
        self._record_folder, self._record_number = Path(folder), 0
        self._record_folder.mkdir()
        super().__init__(binary, identity, **options)

    def _exchange(self, payload):
        self._record_number += 1
        stem = self._record_folder / f"{self._record_number:04d}"
        started, failure = time.monotonic_ns(), None
        try:
            return super()._exchange(payload)
        except BaseException as error:
            failure = f"{type(error).__name__}: {error}"
            raise
        finally:
            sent = payload + b"\n" if payload is not None else b""
            received = getattr(self, "_last_received_frame", b"")
            stem.with_suffix(".stdin").write_bytes(sent)
            stem.with_suffix(".stdout").write_bytes(received)
            stem.with_suffix(".stderr").write_bytes(bytes(getattr(self, "_stderr", b"")))
            save(stem.with_suffix(".json"), {"wall_ns_before_record": time.monotonic_ns() - started,
                "error": failure, "stdin_sha256": sha256(sent).hexdigest(),
                "stdout_sha256": sha256(received).hexdigest()})


class RecordedOneShot(NduBridge):
    def __init__(self, binary, identity, folder, **options):
        self._folder, self.commands = Path(folder), 0
        self._folder.mkdir()
        super().__init__(binary, identity, **options)

    def _invoke(self, arguments, payload):
        self.commands += 1
        stem = self._folder / f"{self.commands:04d}"
        started, result, failure, stdout, stderr = time.monotonic_ns(), None, None, b"", b""
        try:
            result = subprocess.run([str(self.executable), *arguments], input=payload,
                                    capture_output=True, timeout=self.timeout, check=False)
            stdout, stderr = result.stdout, result.stderr
        except subprocess.TimeoutExpired as error:
            stdout, stderr = error.stdout or b"", error.stderr or b""
            failure = "native one-shot timeout"
            raise NduBridgeError(failure) from error
        except OSError as error:
            failure = "native one-shot launch: " + str(error)
            raise NduBridgeError(failure) from error
        finally:
            for name, data in (("stdin", payload), ("stdout", stdout), ("stderr", stderr)):
                stem.with_suffix("." + name).write_bytes(data)
            save(stem.with_suffix(".json"), {"argv": [str(self.executable), *arguments],
                 "returncode": result.returncode if result else None, "error": failure,
                 "wall_ns_before_record": time.monotonic_ns() - started})
        response = _read_json(result.stdout)
        if (result.returncode or response.get("status") == "error"
                or response.get("authority") != "DENY_ALL" or response.get("safety_certificate") is not False):
            raise NduBridgeError(str(response.get("error", "native one-shot refusal")))
        return response


def new_bridge(arm, manifest, identity, folder, protocol):
    if arm == "native-oneshot":
        return RecordedOneShot(manifest["binary"], identity, folder, timeout=protocol["controller_timeout_s"])
    return RecordedSession(manifest["binary"], identity, folder,
                           timeout=protocol["controller_timeout_s"],
                           image_check="rehash" if arm == "native-stream-rehash" else "sealed")


def rotated(arms, group, offset):
    shift = (group + offset) % len(arms)
    order = list(arms[shift:] + arms[:shift])
    return order[::-1] if group % 2 else order


def controller_model(key):
    return {"remaining_credits": 1, "support": digest({"finite-controller-model": key}),
            "modules": [[{"target": "base", "credits": 0, "cost_ns": 15_000_000 + key, "verified": True},
                         {"target": "fast", "credits": 1, "cost_ns": 4_000_000 + key, "verified": True}],
                        [{"target": "base", "credits": 0, "cost_ns": 25_000_000 + key, "verified": True},
                         {"target": "fast", "credits": 1, "cost_ns": 2_000_000 + key, "verified": True}]]}


def controller_episode(folder, arm, profile, group, p, manifest, identity):
    started = time.monotonic_ns()
    folder.mkdir()
    bridge, cache, controls = None, None, OrderedDict()
    result = {"arm": arm, "profile": profile, "group": group, "status": "running", "samples": []}
    try:
        if arm.startswith("native"):
            bridge = new_bridge(arm, manifest, identity, folder / "native", p)
            if arm.endswith("-cache"):
                cache = NduDecisionCache(bridge, max_entries=p["cache_entries"], max_bytes=p["cache_payload_bytes"])
        for repetition in range(p["controller_repetitions"]):
            for key in range(p["controller_keys"]):
                serial = repetition * p["controller_keys"] + key
                generation = group * 1000 + (key if profile == "identical-retries" else serial) + 1
                model = controller_model(key)
                input_key = digest({"model": model, "generation": generation})
                before = time.monotonic_ns()
                if bridge:
                    chosen, evidence = select_native(model, p, generation, bridge, cache)
                else:
                    hit = input_key in controls
                    if not hit:
                        controls[input_key] = complete_budget_dp(model)
                        while len(controls) > p["cache_entries"]:
                            controls.popitem(last=False)
                    controls.move_to_end(input_key)
                    chosen, evidence = deepcopy(controls[input_key]), {"reused_exact_input": hit}
                if chosen["targets"] != ["base", "fast"]:
                    raise RuntimeError("controller disagrees with independent finite allocation oracle")
                row = {"serial": serial, "input_sha256": input_key, "selected": chosen,
                       "wall_ns_before_evidence": time.monotonic_ns() - before, "evidence": evidence}
                save(folder / f"query-{serial:04d}.json", row)
                result["samples"].append({"serial": serial, "correct": True, "input_sha256": input_key})
        result["status"] = "completed"
    except Exception as error:
        result.update(status="failed", error=f"{type(error).__name__}: {error}")
    finally:
        result["cache_closed"] = cache.close() if cache else None
        if isinstance(bridge, NduSession):
            bridge.close()
            result["native_session"] = bridge.snapshot()
        controls.clear()
    save(folder / "RESULT.json", result)
    result["wall_ns"] = time.monotonic_ns() - started
    return result


def application_model(bank, trace, epoch, observations, artifacts, credits):
    modules = []
    for module, sizes in enumerate(trace):
        options = []
        for target in ("base", "guard-small", "guard-wide"):
            row = bank["candidates"][target]
            ratios = [o["outer_wall_ns"] / row["latency_ns"][str(o["n"])]
                      for o in observations if o["module"] == module and o["state"] == target]
            scale = statistics.median(ratios) if ratios else 1.0
            new_build = (module, target) not in artifacts
            cost = sum(max(1, round(row["latency_ns"][str(n)] * scale)) for n in sizes[epoch:])
            options.append({"target": target, "credits": int(new_build),
                            "cost_ns": cost + (row["setup_ns"] if new_build else 0),
                            "verified": row["verification"]["status"] == "verified"})
        modules.append(options)
    return {"modules": modules, "remaining_credits": credits.remaining,
            "support": digest({"bank": bank["bank_sha256"], "observations": observations,
                               "available_artifacts": sorted(artifacts), "epoch": epoch})}


def application_episode(folder, arm, profile, group, p, manifest, identity, base, bank, driver, clang):
    started, ledger, observations, artifacts = time.monotonic_ns(), [], [], {}
    folder.mkdir()
    budget = EpisodeBudget(started, p["episode_budget_ns"])
    spec, bridge = p["application_profiles"][profile], None
    credits = CompilationCredits(spec["compile_credits"])
    record = {"arm": arm, "profile": profile, "group": group, "status": "running",
              "ledger": ledger, "observations": observations, "decisions": [],
              "same_initial_information": bank["bank_sha256"], "future_timing_access": False}
    checker = guarded_checker_identity()

    def stage(label, operation):
        return budget.stage(label, ledger, operation)

    def admit(module, target):
        if guarded_checker_identity() != checker:
            raise RuntimeError("independent checker identity changed")
        key = module, target
        if key not in artifacts:
            path = folder / f"module-{module}-{target}.so"
            if target == "base":
                receipt = stage(f"base-build.{module}", lambda: build_optimized_native(
                    base, base, path, clang=clang, policy=budget.policy()))
            else:
                credits.consume(module, target)
                proposed = stage(f"propose.{module}.{target}", lambda: propose_guarded_reduction(
                    base, maximum=p["guard_limits"][target]))
                if digest(proposed) != bank["candidates"][target]["proposal_sha256"]:
                    raise RuntimeError("proposal differs from the frozen candidate bank")
                receipt = stage(f"candidate-build.{module}.{target}", lambda: build_guarded_native(
                    base, proposed, path, clang=clang, policy=budget.policy()))
            artifacts[key] = path, receipt
        path, receipt = artifacts[key]
        if target == "base":
            proof = stage(f"fresh-proof.{module}.{target}", lambda: verify_optimization(base, base, policy=budget.policy()))
        else:
            proposal = bank["candidates"][target]["proposal"]
            proof = stage(f"fresh-proof.{module}.{target}", lambda: verify_guarded_optimization(base, proposal, policy=budget.policy()))
        if proof["status"] != "verified":
            raise RuntimeError("fresh independent proof did not verify")
        if proof["candidate_sha256"] != receipt["verification"]["candidate_sha256"]:
            raise RuntimeError("fresh proof does not bind the originally admitted artifact")
        return path, receipt

    def deliver(module, target, n, epoch):
        path, receipt = admit(module, target)
        result = stage(f"execute.{epoch}.{module}.{target}", lambda: execute_sample(
            driver, path, expected_artifact_sha256=receipt["native"]["artifact_sha256"], n=n,
            calls=p["calls"], seed=(p["holdout_seed"] + group) & 255, multiplier=1,
            timeout=budget.remaining_ns() / 1e9))
        observations.append(dict(result, module=module, state=target, epoch=epoch, n=n))
        if result["status"] != "measured" or result.get("loaded_mapping_verified") is not True:
            raise RuntimeError("native output or actual loaded image check failed")

    try:
        if arm.startswith("native"):
            bridge = stage("native.admission", lambda: new_bridge(arm, manifest, identity, folder / "native", p))
        trace = spec["module_sizes"]
        for module in range(len(trace)):
            deliver(module, "base", p["calibration_sizes"][0], -1)
        fixed = None
        for epoch in range(len(trace[0])):
            if arm == "fixed" and fixed is not None:
                # A committed fixed plan needs no new forecast construction.
                # Do not charge it dynamic planner work only to fill a log.
                model = None
                chosen, evidence = fixed, {"committed_fixed_plan_reused": True}
            else:
                model = application_model(bank, trace, epoch, observations, artifacts, credits)
                def choose():
                    if bridge:
                        bridge.timeout = min(p["controller_timeout_s"], budget.remaining_ns() / 1e9)
                        return select_native(model, p, epoch + 1, bridge)
                    return complete_budget_dp(model), {"algorithm": "complete-multiple-choice-budget-DP"}
                chosen, evidence = stage(f"control.{epoch}", choose)
                if chosen is None:
                    raise RuntimeError("complete budget control has no feasible allocation")
                if arm == "fixed":
                    fixed = deepcopy(chosen)
            record["decisions"].append({"epoch": epoch, "model": model, "selected": chosen, "evidence": evidence})
            for module, target in enumerate(chosen["targets"]):
                deliver(module, target, trace[module][epoch], epoch)
        record["status"] = "completed"
    except Exception as error:
        record.update(status="failed", error=f"{type(error).__name__}: {error}")
    finally:
        if bridge:
            measured("native.shutdown", ledger, bridge.close)
            record["native_session"] = bridge.snapshot()
        artifacts.clear()
    record["compile_credit"] = {"limit": credits.limit, "used": credits.used, "attempts": credits.attempts,
                                "scope": p["resource_scope"]}
    record["observations_expected"] = len(spec["module_sizes"]) * (1 + len(spec["module_sizes"][0]))
    save(folder / "RESULT.json", record)
    record["wall_ns"] = time.monotonic_ns() - started
    record["admitted"] = (record["status"] == "completed" and record["wall_ns"] <= p["episode_budget_ns"]
                          and len(observations) == record["observations_expected"] and credits.used <= credits.limit)
    return record


def validate_build_envelope(envelope, manifest, manifest_raw, source_commit):
    if (envelope.get("schema") != "hepta.hia.ndu.outer-build-cost.v1"
            or envelope.get("returncode") != 0 or envelope.get("source_unchanged") is not True
            or envelope.get("source_commit") != source_commit or envelope.get("target_cache") != "empty"
            or envelope.get("identity_sha256") != sha256(manifest_raw).hexdigest()
            or envelope.get("binary_sha256") != manifest["binary_sha256"]
            or envelope.get("native_source_pin") != STREAM_SOURCE_PIN
            or envelope.get("inner_build_cost") != manifest["build_cost"]
            or type(envelope.get("wall_ns")) is not int
            or envelope["wall_ns"] < manifest["build_cost"]["wall_ns"]
            or envelope.get("authority") != "DENY_ALL" or envelope.get("safety_certificate") is not False):
        raise ValueError("complete source-bound native build envelope required")
    for name in ("tools/measure_hia_ndu_build.py", "tools/build_hia_recursive_ndu_bridge.py"):
        if envelope.get("source_sha256", {}).get(name) != sha256((ROOT / name).read_bytes()).hexdigest():
            raise ValueError("native build wrapper source differs")
    return envelope["wall_ns"]


def standalone_totals(rows, arms, shared_ns, native_setup_ns, residual_ns, full_build_ns):
    """Costs for one standalone workload; shared setup is charged once per arm."""
    warm = {arm: shared_ns + (native_setup_ns + residual_ns if arm.startswith("native") else 0)
            + sum(row["wall_ns"] for row in rows if row["arm"] == arm) for arm in arms}
    cold = {arm: value + (full_build_ns if arm.startswith("native") else 0)
            for arm, value in warm.items()}
    return {"standalone_warm_ns": warm, "standalone_cold_ns": cold}


def application_profile_totals(rows, protocol, shared_ns, native_setup_ns, residual_ns,
                               full_build_ns, *, source_unchanged):
    """Evaluate each preregistered workload independently, including cold cost.

    Each profile is a separate standalone interpretation of the observations:
    the full common calibration, registration and native build are charged
    once to every applicable arm. These tables must not be summed to obtain
    the combined-workload total, which charges each common cost only once.
    The registered acceptance rule requires a win in every profile.
    """
    profiles = {}
    expected = {(group, arm) for group in range(protocol["groups"]) for arm in APPLICATION_ARMS}
    for profile in protocol["application_profiles"]:
        selected = [row for row in rows if row["profile"] == profile]
        actual = [(row["group"], row["arm"]) for row in selected]
        complete = len(actual) == len(expected) and set(actual) == expected
        correct = source_unchanged and complete and all(row["admitted"] for row in selected)
        result = standalone_totals(selected, APPLICATION_ARMS, shared_ns, native_setup_ns,
                                   residual_ns, full_build_ns)
        cold = result["standalone_cold_ns"]
        result.update(complete_registered_groups=complete,
            all_application_outputs_and_budgets_admitted=correct,
            full_cost_advantage=bool(correct and all(cold["native-stream-sealed"] < cold[arm]
                                                     for arm in ("fixed", "dp"))))
        profiles[profile] = result
    return profiles


def qualify(output, identity, clang, protocol_path=PROTOCOL_PATH, *, layer="all", build_envelope=None):
    started = time.monotonic_ns()
    output, identity, protocol_path = Path(output).resolve(), Path(identity).resolve(), Path(protocol_path).resolve()
    if output.is_relative_to(ROOT):
        raise ValueError("raw study output must be outside the source checkout")
    if not protocol_path.is_relative_to(ROOT) or layer not in {"all", "controller", "application"}:
        raise ValueError("invalid source-bound protocol or layer")
    p = validate_protocol(json.loads(protocol_path.read_bytes()))
    native_setup_start = time.monotonic_ns()
    manifest_raw = identity.read_bytes()
    manifest = _read_json(manifest_raw)
    build = manifest.get("build_cost", {})
    if (manifest.get("identity", {}).get("source_commit") != p["native_source_pin"]
            or not manifest["identity"].get("rustc", "").startswith("rustc " + p["native_rustc"] + " ")
            or type(build.get("wall_ns")) is not int or build["wall_ns"] < 0
            or build.get("target_cache") != "empty"):
        raise ValueError("exact native source/tool and original empty-target build receipt required")
    native_setup_ns = time.monotonic_ns() - native_setup_start
    status = subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True)
    if status:
        raise RuntimeError("registration requires a clean committed source/protocol worktree")
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    native_setup_start = time.monotonic_ns()
    if build_envelope is None:
        raise ValueError("an outer native build envelope is required for full cold cost")
    envelope_raw = Path(build_envelope).read_bytes()
    envelope = _read_json(envelope_raw)
    full_build_ns = validate_build_envelope(envelope, manifest, manifest_raw, commit)
    native_setup_ns += time.monotonic_ns() - native_setup_start
    paths = sorted((ROOT / "hepta").glob("*.py")) + [Path(__file__), protocol_path,
        ROOT / "tools/qualify_hia_ndu_graph.py", ROOT / "tools/qualify_hia_ndu_loop.py",
        ROOT / "tools/measure_hia_ndu_build.py", ROOT / "tools/build_hia_recursive_ndu_bridge.py",
        ROOT / "experiments/hia_optimizer_eval/kernels.hepta"]
    source = {}
    for path in paths:
        relative, raw = str(path.relative_to(ROOT)), path.read_bytes()
        committed = subprocess.check_output(["git", "cat-file", "blob", commit + ":" + relative], cwd=ROOT)
        if raw != committed:
            raise RuntimeError("source differs from registered commit: " + relative)
        source[relative] = sha256(raw).hexdigest()
    output.mkdir(parents=True, exist_ok=False)
    for path in paths:
        target = output / "sources" / path.relative_to(ROOT)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(path.read_bytes())
    save(output / "REGISTRATION.json", {"source_commit": commit, "source_sha256": source, "layer": layer,
        "protocol_sha256": sha256(protocol_path.read_bytes()).hexdigest(), "native_binary_sha256": manifest["binary_sha256"],
        "registered_utc": datetime.now(timezone.utc).isoformat(), "prior_outcomes_preserved": True})
    native_setup_start = time.monotonic_ns()
    (output / "NATIVE_BUILD_IDENTITY.json").write_bytes(manifest_raw)
    (output / "NATIVE_BUILD_ENVELOPE.json").write_bytes(envelope_raw)
    native_setup_ns += time.monotonic_ns() - native_setup_start
    common_ns = time.monotonic_ns() - started - native_setup_ns
    controllers, applications, setup_ns = [], [], 0
    if layer in {"all", "controller"}:
        for group in range(p["groups"]):
            for index, profile in enumerate(p["controller_profiles"]):
                for arm in rotated(CONTROLLER_ARMS, group, index):
                    controllers.append(controller_episode(output / f"controller-{group}-{profile}-{arm}",
                        arm, profile, group, p, manifest, identity))
    if layer in {"all", "application"}:
        before = time.monotonic_ns()
        bank_dir = output / "calibration"
        bank_dir.mkdir()
        base = lower_source((ROOT / "experiments/hia_optimizer_eval/kernels.hepta").read_text())
        (bank_dir / "driver.c").write_text(DRIVER)
        driver = bank_dir / "driver"
        completed = subprocess.run([clang, "-O3", "-std=c11", str(bank_dir / "driver.c"), "-ldl", "-o", str(driver)],
                                   capture_output=True, check=False, timeout=60)
        (bank_dir / "driver.stdout").write_bytes(completed.stdout)
        (bank_dir / "driver.stderr").write_bytes(completed.stderr)
        if completed.returncode:
            raise RuntimeError("actual native driver failed compilation")
        calibration_protocol = dict(p, probe_size=p["calibration_sizes"][0],
                                    batch_sizes=p["calibration_sizes"], function="full_lifecycle")
        bank = calibration(base, bank_dir, driver, clang, calibration_protocol, [])
        for target in p["guard_limits"]:
            bank["candidates"][target]["proposal"] = json.loads((bank_dir / (target + ".proposal.json")).read_bytes())
        save(bank_dir / "BANK.json", bank)
        setup_ns = time.monotonic_ns() - before
        for group in range(p["groups"]):
            for index, profile in enumerate(p["application_profiles"]):
                for arm in rotated(APPLICATION_ARMS, group, index):
                    applications.append(application_episode(output / f"application-{group}-{profile}-{arm}",
                        arm, profile, group, p, manifest, identity, base, bank, driver, clang))
    unchanged = (all(sha256((ROOT / name).read_bytes()).hexdigest() == value for name, value in source.items())
                 and identity.read_bytes() == manifest_raw)
    residual_ns = max(0, time.monotonic_ns() - started - common_ns - native_setup_ns - setup_ns
                      - sum(row["wall_ns"] for row in controllers + applications))
    ct = standalone_totals(controllers, CONTROLLER_ARMS, common_ns, native_setup_ns,
                           residual_ns, full_build_ns) if controllers else None
    at = standalone_totals(applications, APPLICATION_ARMS, common_ns + setup_ns, native_setup_ns,
                           residual_ns, full_build_ns) if applications else None
    apt = application_profile_totals(applications, p, common_ns + setup_ns, native_setup_ns,
        residual_ns, full_build_ns, source_unchanged=unchanged) if applications else {}
    correct = bool(apt) and all(row["all_application_outputs_and_budgets_admitted"] for row in apt.values())
    accepted = bool(correct and all(row["full_cost_advantage"] for row in apt.values()))
    result = {"schema": "hepta.hia.ndu.net-value.result.v1", "source_commit": commit, "protocol": p,
        "source_unchanged": unchanged, "layer": layer, "controller_episodes": controllers,
        "application_episodes": applications, "controller_totals": ct, "application_totals": at,
        "application_profile_totals": apt,
        "application_profile_cost_scope": "Each profile independently charges the full common registration/calibration and native identity/residual/build costs once per applicable standalone arm; do not sum these tables to obtain the combined-workload total",
        "common_source_registration_ns_once_per_standalone_arm": common_ns,
        "common_application_calibration_ns_once_per_standalone_arm": setup_ns,
        "native_build_cost": build, "native_complete_build_wall_ns": full_build_ns,
        "native_identity_setup_ns_once_per_native_arm": native_setup_ns,
        "outer_dispatch_and_final_source_check_ns_conservatively_charged_to_each_native_arm": residual_ns,
        "all_application_outputs_and_budgets_admitted": correct,
        "registered_full_cost_advantage": accepted, "statistical_superiority_established": False,
        "controller_correct": bool(controllers) and all(r["status"] == "completed" for r in controllers),
        "previous_negative_results_replaced": False, "default_cache_enabled": False,
        "authority": "DENY_ALL", "safety_certificate": False,
        "host": {"platform": platform.platform(), "python": sys.version, "cpu_count": os.cpu_count(),
                 "affinity": sorted(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else None}}
    save(output / "RESULT.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--identity", type=Path, required=True)
    parser.add_argument("--build-envelope", type=Path, required=True)
    parser.add_argument("--clang", default=os.environ.get("CLANG", "clang"))
    parser.add_argument("--protocol", type=Path, default=PROTOCOL_PATH)
    parser.add_argument("--layer", choices=("all", "controller", "application"), default="all")
    args = parser.parse_args()
    result = qualify(args.output, args.identity, args.clang, args.protocol, layer=args.layer,
                     build_envelope=args.build_envelope)
    print(json.dumps({key: result[key] for key in ("source_commit", "controller_correct",
        "all_application_outputs_and_budgets_admitted", "registered_full_cost_advantage",
        "controller_totals", "application_totals", "application_profile_totals")}, indent=2))


if __name__ == "__main__":
    main()

