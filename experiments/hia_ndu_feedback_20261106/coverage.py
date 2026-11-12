"""Complete registered state/support coverage beside the unchanged v1 study.

This qualification has two deliberately distinct inputs. Supplied-state grids
exercise the public decision interface even where a posterior is not reachable
from the original episode prior. Natural-support tapes enumerate every current
request/signal history and derive its posterior from the declared likelihoods.
All states and all no-change results are retained. Witness selection uses only
registered logical predicates and sorted state identities, never native timing.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
from dataclasses import asdict, replace
from fractions import Fraction
from hashlib import sha256
import itertools
import json
from pathlib import Path
import subprocess
import time
import traceback

from . import model

ROOT = Path(__file__).resolve().parents[2]
PROTOCOL = ROOT / "benchmarks/hia_ndu_feedback_state_coverage/PROTOCOL.json"
SCHEMA = "hepta.hia.ndu.state-coverage.v1"


def _wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _write(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")


def _rational(value):
    return [value.numerator, value.denominator]


def load_protocol(path=PROTOCOL):
    p = json.loads(Path(path).read_text())
    if p.get("schema") != "hepta.hia.ndu.state-coverage-protocol.v1":
        raise model.FeedbackError("state coverage protocol schema")
    if p["environments"] != ["adaptive", "fixed", "misleading"]:
        raise model.FeedbackError("state coverage environment inventory")
    grid, boundary, natural = p["supplied_grid"], p["boundary_grid"], p["natural_support"]
    if (grid["current_requests"] != [0, 1] or grid["residents"] != [-1, 0, 1]
            or grid["beliefs"] != [[1, 10], [1, 2], [9, 10]]
            or grid["remaining_resources"] != [[6, 24], [12, 24], [24, 24], [24, 6], [24, 12]]
            or grid["horizons"] != [2, 3] or grid["load_costs"] != [4, 8]
            or grid["initial_resources"] != [24, 24]):
        raise model.FeedbackError("coarse complete state grid changed")
    if (boundary["current_requests"] != [0, 1]
            or boundary["resident_rule"] != "opposite-current-request"
            or boundary["belief_numerators"] != list(range(65)) or boundary["belief_denominator"] != 64
            or boundary["remaining_budgets"] != list(range(9, 14))
            or boundary["remaining_deadline"] != 24 or boundary["horizon"] != 2
            or boundary["load_cost"] != 4 or boundary["initial_resources"] != [24, 24]):
        raise model.FeedbackError("complete boundary mesh changed")
    if (natural["horizon"] != 3 or natural["initial_residents"] != [-1, 0, 1]
            or natural["initial_resource_pairs"] != [[12, 24], [24, 12], [24, 24]]
            or natural["load_costs"] != [4, 8]
            or natural["alphabet"] != [[0, 0], [0, 1], [1, 0], [1, 1]]
            or natural["owner_policy"] != "same-objective" or natural["all_tapes"] != 64):
        raise model.FeedbackError("natural support inventory changed")
    if (p["registered_fixed_action"] != 0 or p["per_decision_transition_cap"] != 20000
            or p["per_arm_transition_cap"] != 20000000):
        raise model.FeedbackError("coverage work allowance changed")
    raw = (ROOT / "experiments/hia_ndu_feedback_20261106/model.py").read_bytes()
    if sha256(raw).hexdigest() != p["base_model_sha256"]:
        raise model.FeedbackError("v1 model changed; a new explicit protocol is required")
    return p


def source_identity(*, require_clean=False):
    result = {"files": {}}
    for name in ("experiments/hia_ndu_feedback_20261106/model.py",
                 "experiments/hia_ndu_feedback_20261106/native.py",
                 "experiments/hia_ndu_feedback_20261106/coverage.py",
                 "tests/test_hia_ndu_feedback_coverage.py",
                 "benchmarks/hia_ndu_feedback_state_coverage/PROTOCOL.json"):
        path = ROOT / name
        if path.exists():
            raw = path.read_bytes()
            result["files"][name] = sha256(raw).hexdigest()
            if require_clean:
                committed = subprocess.check_output(["git", "cat-file", "blob", "HEAD:"+name], cwd=ROOT)
                if committed != raw:
                    raise model.FeedbackError("coverage input differs from canonical Git bytes: "+name)
        elif require_clean:
            raise model.FeedbackError("coverage input missing: "+name)
    status = subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True)
    if require_clean and status:
        raise model.FeedbackError("coverage registration requires committed clean source")
    result["commit"] = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    result["tree"] = subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=ROOT, text=True).strip()
    result["clean"] = not bool(status)
    return result


def input_identity(path):
    path = Path(path).resolve(strict=True)
    raw = path.read_bytes()
    return {"path": str(path), "bytes": len(raw), "sha256": sha256(raw).hexdigest()}


def bind_native_inputs(binary, manifest):
    if bool(binary) != bool(manifest):
        raise model.FeedbackError("native executable and receipt must be bound together")
    if binary is None:
        return None
    inputs = {"binary": input_identity(binary), "manifest": input_identity(manifest)}
    receipt = json.loads(Path(inputs["manifest"]["path"]).read_text())
    if (receipt.get("schema") != "hepta.hia.ndu-build.v1"
            or receipt.get("binary_sha256") != inputs["binary"]["sha256"]
            or receipt.get("original_rust_sources_unchanged") is not True
            or receipt.get("all_original_non_manifest_inputs_unchanged") is not True
            or receipt.get("build_inputs_unchanged") is not True):
        raise model.FeedbackError("coverage native source/binary receipt mismatch")
    return inputs


def check_native_inputs(registry):
    inputs = registry.get("native_inputs")
    if inputs is None:
        return None
    observed = bind_native_inputs(inputs["binary"]["path"], inputs["manifest"]["path"])
    if observed != inputs:
        raise model.FeedbackError("registered native executable or receipt bytes changed")
    return observed


def supplied_states(protocol):
    g = protocol["supplied_grid"]
    products = itertools.product(protocol["environments"], g["current_requests"], g["residents"],
                                 g["beliefs"], g["remaining_resources"], g["horizons"], g["load_costs"])
    for index, (environment, request, resident, belief, resource, horizon, load) in enumerate(products):
        scenario = replace(model.SCENARIOS[environment], horizon=horizon, load_cost=load,
                           initial_budget=g["initial_resources"][0], initial_deadline=g["initial_resources"][1])
        b = Fraction(*belief)
        observation = model.Observation(0, request, 0, resident, *resource, b.numerator, b.denominator)
        yield scenario, observation, {"id": f"grid-{index:04}", "family": "supplied-grid",
            "environment": environment, "natural_posterior_claim": False}
    bgrid = protocol["boundary_grid"]
    products = itertools.product(protocol["environments"], bgrid["current_requests"],
                                 bgrid["belief_numerators"], bgrid["remaining_budgets"])
    for index, (environment, request, numerator, budget) in enumerate(products):
        scenario = replace(model.SCENARIOS[environment], horizon=bgrid["horizon"], load_cost=bgrid["load_cost"],
                           initial_budget=bgrid["initial_resources"][0], initial_deadline=bgrid["initial_resources"][1])
        belief = Fraction(numerator, bgrid["belief_denominator"])
        observation = model.Observation(0, request, 0, 1-request, budget, bgrid["remaining_deadline"],
                                        belief.numerator, belief.denominator)
        yield scenario, observation, {"id": f"boundary-{index:04}", "family": "supplied-boundary",
            "environment": environment, "natural_posterior_claim": False}


def natural_profiles(protocol):
    n = protocol["natural_support"]
    products = itertools.product(protocol["environments"], n["initial_residents"],
                                 n["initial_resource_pairs"], n["load_costs"])
    for index, (name, resident, resources, load) in enumerate(products):
        scenario = replace(model.SCENARIOS[name], horizon=n["horizon"], initial_resident=resident,
                           initial_budget=resources[0], initial_deadline=resources[1], load_cost=load)
        yield f"natural-profile-{index:02}", scenario


def tape_probability(scenario, tape):
    """Exact joint probability; does not depend on any controller's actions."""
    total = Fraction(0)
    for z, prior in ((0, Fraction(scenario.prior0_num, scenario.prior0_den)),
                     (1, 1-Fraction(scenario.prior0_num, scenario.prior0_den))):
        request0 = Fraction(scenario.request_p0_z0_num, scenario.request_p0_z0_den) if z == 0 else Fraction(scenario.request_p0_z1_num, scenario.request_p0_z1_den)
        sensor0 = Fraction(scenario.signal_correct_num, scenario.signal_correct_den) if z == 0 else 1-Fraction(scenario.signal_correct_num, scenario.signal_correct_den)
        value = prior
        for request, signal in tape:
            value *= (request0 if request == 0 else 1-request0) * (sensor0 if signal == 0 else 1-sensor0)
        total += value
    return total


def observe_tape(scenario, tape, choose):
    """Replay physical model transitions, exposing only one public prefix.

    ``choose`` is never passed the tape or hidden regime. A terminal abstention
    leaves later requested events in the tape and planned-request denominator.
    """
    if len(tape) != scenario.horizon or any(tuple(e) not in ((0, 0), (0, 1), (1, 0), (1, 1)) for e in tape):
        raise model.FeedbackError("complete request/signal tape required")
    belief = Fraction(scenario.prior0_num, scenario.prior0_den)
    resident, budget, deadline = scenario.initial_resident, scenario.initial_budget, scenario.initial_deadline
    rows, delivered, actual_cost = [], 0, 0
    for step, (request, signal) in enumerate(tape):
        belief = model.posterior(scenario, belief, request, signal)
        observation = model.Observation(step, request, signal, resident, budget, deadline, belief.numerator, belief.denominator)
        decision = choose(scenario, observation)
        action = decision["action"]
        row = {"observation": asdict(observation), "action": action,
               "selected_action": model.action_name(action), "state_digest": observation.state_digest}
        if "coverage_state_id" in decision:
            row["coverage_state_id"] = decision["coverage_state_id"]
        if action is None:
            row.update(status="abstained", predicted_cost=0, delivered=False)
            rows.append(row)
            break
        cost = model.action_cost(scenario, observation, action)["total"]
        if cost > min(budget, deadline):
            raise model.FeedbackError("support owner selected infeasible transition")
        resident, budget, deadline = action, budget-cost, deadline-cost
        delivered += 1
        actual_cost += cost
        row.update(status="delivered", predicted_cost=cost, delivered=True,
                   resident_after=resident, remaining_budget=budget, remaining_deadline=deadline)
        rows.append(row)
    return {"tape": [list(v) for v in tape], "probability": _rational(tape_probability(scenario, tape)),
            "steps": rows, "planned_requests": scenario.horizon, "delivered": delivered,
            "missing_requests": scenario.horizon-delivered, "modeled_cost": actual_cost,
            "scope": "declared model execution of all registered public-event support; no measured latency"}


def build_registry(protocol=None, *, require_clean=False, native_binary=None, native_manifest=None):
    p = protocol or load_protocol()
    began = time.perf_counter_ns()
    before = source_identity(require_clean=require_clean)
    native_inputs = bind_native_inputs(native_binary, native_manifest)
    states, memberships, owner_cache = {}, [], {}
    owner_transitions = 0
    def add(scenario, observation, membership):
        raw = {"scenario": asdict(scenario), "observation": asdict(observation)}
        identity = model.digest(raw)
        if identity not in states:
            states[identity] = {"id": identity, **raw, "families": []}
        if membership["family"] not in states[identity]["families"]:
            states[identity]["families"].append(membership["family"])
        memberships.append({**membership, "state_id": identity})
        return identity
    for scenario, observation, membership in supplied_states(p):
        add(scenario, observation, membership)
    tapes, profiles = [], []
    for profile_id, scenario in natural_profiles(p):
        profile_mass = Fraction(0)
        def choose(sc, observation):
            nonlocal owner_transitions
            raw = {"scenario": asdict(sc), "observation": asdict(observation)}
            identity = model.digest(raw)
            # Inventory construction uses a fixed ordinary policy and only its
            # public state. Native qualification later repeats a full search.
            if identity not in owner_cache:
                answer = model.plan(sc, observation, "same-objective", max_transitions=p["per_decision_transition_cap"])
                owner_transitions += answer["search"]["transitions"]
                if owner_transitions > p["per_arm_transition_cap"]:
                    raise model.SearchBudgetExhausted("support registry owner budget", transitions=owner_transitions)
                owner_cache[identity] = {"action": answer["action"]}
            return {**owner_cache[identity], "coverage_state_id": identity}
        for tape_index, tape in enumerate(itertools.product(p["natural_support"]["alphabet"], repeat=scenario.horizon)):
            replay = observe_tape(scenario, tape, choose)
            replay.update(id=f"{profile_id}/tape-{tape_index:02}", profile=profile_id, environment=scenario.name)
            for step in replay["steps"]:
                observation = model.Observation(**step["observation"])
                identity = add(scenario, observation, {"id": replay["id"]+f"/step-{observation.step}",
                    "family": "natural-support", "environment": scenario.name,
                    "natural_posterior_claim": True, "profile": profile_id,
                    "prefix": replay["tape"][:observation.step+1]})
                if step["coverage_state_id"] != identity:
                    raise model.FeedbackError("natural support state binding mismatch")
            profile_mass += Fraction(*replay["probability"])
            tapes.append(replay)
        if profile_mass != 1:
            raise model.FeedbackError("whole natural support probability does not sum to one")
        profiles.append({"id": profile_id, "scenario": asdict(scenario), "tapes": 64,
                         "probability_sum": _rational(profile_mass), "all_tapes_preserved": True})
    for value in states.values():
        value["families"].sort()
    registry = {"schema": SCHEMA+".registration", "protocol": p, "protocol_sha256": model.digest(p),
                "source": before, "native_inputs": native_inputs, "states": [states[k] for k in sorted(states)],
                "memberships": memberships, "natural_tapes": tapes, "natural_profiles": profiles,
                "preparation": {"wall_ns": time.perf_counter_ns()-began,
                    "owner_search_transitions": owner_transitions,
                    "owner_distinct_states": len(owner_cache), "native_calls": 0,
                    "scope": "complete state inventory and ordinary reference model support; no workload latency"},
                "authority": "DENY_ALL", "production_activation": False}
    if before != source_identity(require_clean=require_clean):
        raise model.FeedbackError("coverage source changed while enumerating support")
    check_native_inputs(registry)
    registry["registration_sha256"] = model.digest(registry)
    return registry


def validate_registry(registry, *, require_clean=False):
    if registry.get("schema") != SCHEMA+".registration":
        raise model.FeedbackError("coverage registration schema")
    body = {k: v for k, v in registry.items() if k != "registration_sha256"}
    if model.digest(body) != registry.get("registration_sha256"):
        raise model.FeedbackError("registered coverage bytes changed")
    p = load_protocol()
    if registry["protocol"] != p or registry["protocol_sha256"] != model.digest(p):
        raise model.FeedbackError("registered coverage protocol drift")
    if registry["source"] != source_identity(require_clean=require_clean):
        raise model.FeedbackError("registered coverage source identity drift")
    check_native_inputs(registry)
    ids = [row["id"] for row in registry["states"]]
    if ids != sorted(set(ids)):
        raise model.FeedbackError("duplicate or unsorted registered states")
    for row in registry["states"]:
        if row["id"] != model.digest({"scenario": row["scenario"], "observation": row["observation"]}):
            raise model.FeedbackError("registered state identity")
    known_ids = set(ids)
    if any(row["state_id"] not in known_ids for row in registry["memberships"]):
        raise model.FeedbackError("unknown state membership")
    families = defaultdict(int)
    for row in registry["memberships"]:
        families[row["family"]] += 1
    if families["supplied-grid"] != 1080 or families["supplied-boundary"] != 1950:
        raise model.FeedbackError("complete supplied-state denominator changed")
    if len(registry["natural_profiles"]) != 54 or len(registry["natural_tapes"]) != 3456:
        raise model.FeedbackError("complete natural support denominator changed")
    return p


def fixed_policy_value(scenario, observation, *, fixed_action=0, cap=20000):
    """Value of one registered fixed policy, with the common external objective.

    This evaluates its whole policy; it does not compare just the root action.
    Future actions are constrained by that same fixed policy and its registered
    feasibility fallback. No optimizing child oracle is substituted.
    """
    began = time.perf_counter_ns()
    cache, count = {}, 0
    def solve(state):
        nonlocal count
        if state in cache:
            return cache[state]
        if count >= cap:
            raise model.SearchBudgetExhausted("fixed policy value budget", transitions=count)
        try:
            answer = model.plan(scenario, state, "fixed", fixed_action=fixed_action, max_transitions=cap-count)
        except Exception as error:
            spent = getattr(error, "search_stats", {}).get("transitions", 0)
            error.search_stats = {"transitions": count+spent, "states": len(cache)}
            error.transitions = count+spent
            raise
        count += answer["search"]["transitions"]
        action = answer["action"]
        remaining = scenario.horizon-state.step
        if action is None:
            value = -scenario.miss_penalty_q32*remaining
        else:
            cost = model.action_cost(scenario, state, action)["total"]
            pref = model.preferences(scenario, state)
            future = []
            if remaining > 1:
                for probability, request, signal, belief in model.forecast(scenario, state):
                    child = model.Observation(state.step+1, request, signal, action,
                        state.budget-cost, state.deadline-cost, belief.numerator, belief.denominator)
                    future.append((probability, solve(child)))
            value = model.immediate(scenario, cost, pref)+model.mul_q32(pref["discount_q32"], model.certainty_equivalent(future, pref["risk_q32"]))
        cache[state] = value
        return value
    value = solve(observation)
    return {"value_q32": value, "fixed_action": fixed_action, "states": len(cache),
            "transitions": count, "wall_ns": time.perf_counter_ns()-began}


def _compact(answer):
    return {k: answer[k] for k in ("arm", "action", "selected_action", "value_q32", "candidate_values_q32",
                                  "preference", "search", "controller_wall_ns", "native_backend_used")}


def is_original_backend(backend):
    # A recording/mock callback exercises the integration API but does not
    # establish original-source execution. The real class also verifies its
    # frozen source receipt and seals/binds the executable during admission.
    from .native import NativeValueBackend
    return isinstance(backend, NativeValueBackend)


def qualify_state(state, protocol, *, backend=None, per_arm_remaining=None):
    scenario = model.Scenario(**state["scenario"])
    observation = model.Observation(**state["observation"])
    cap = protocol["per_decision_transition_cap"]
    began = time.perf_counter_ns()
    answers, attempts = {}, []
    native_before = getattr(backend, "calls", None)
    native_function = backend if backend is not None else model.scalar_backend
    remaining = per_arm_remaining or {}
    def execute(arm):
        allowance = min(cap, remaining.get(arm, cap))
        started = time.perf_counter_ns()
        try:
            if allowance <= 0:
                raise model.SearchBudgetExhausted("coverage arm lifecycle budget exhausted before decision", transitions=0)
            answer = model.plan(scenario, observation, arm,
                backend=native_function if arm in ("dynamic-ndu", "fixed-preference-ndu") else None,
                max_transitions=allowance)
            attempts.append({"arm": arm, "status": "completed", "wall_ns": time.perf_counter_ns()-started,
                             "search": answer["search"]})
            answers[arm] = answer
        except BaseException as error:
            attempts.append({"arm": arm, "status": "failed", "wall_ns": time.perf_counter_ns()-started,
                             "search": getattr(error, "search_stats", None),
                             "error": {"type": type(error).__name__, "message": str(error)}})
            raise
    try:
        for arm in ("same-objective", "ordinary-mpc", "state-greedy", "wrong-forecast", "no-adaptation", "exact-oracle", "dynamic-ndu", "fixed-preference-ndu"):
            execute(arm)
        started = time.perf_counter_ns()
        try:
            allowance = min(cap, remaining.get("fixed-policy-value", cap))
            if allowance <= 0:
                raise model.SearchBudgetExhausted("fixed-policy lifecycle allowance exhausted", transitions=0)
            fixed_value = fixed_policy_value(scenario, observation, fixed_action=protocol["registered_fixed_action"], cap=allowance)
            attempts.append({"arm": "fixed-policy-value", "status": "completed", "wall_ns": time.perf_counter_ns()-started,
                             "search": {"transitions": fixed_value["transitions"], "states": fixed_value["states"], "backend_calls": 0}})
        except BaseException as error:
            attempts.append({"arm": "fixed-policy-value", "status": "failed", "wall_ns": time.perf_counter_ns()-started,
                             "search": getattr(error, "search_stats", None),
                             "error": {"type": type(error).__name__, "message": str(error)}})
            raise
    except BaseException as error:
        error.coverage_partial = {"answers": {arm: _compact(answer) for arm, answer in answers.items()},
            "attempts": attempts, "wall_ns": time.perf_counter_ns()-began,
            "native_request_range": None if native_before is None else [native_before+1, getattr(backend, "calls", native_before)]}
        raise
    native_after = getattr(backend, "calls", None)
    expected, ordinary, dynamic, fixed_pref = (answers[a] for a in
                                              ("exact-oracle", "same-objective", "dynamic-ndu", "fixed-preference-ndu"))
    expected_values = expected["candidate_values_q32"]
    regrets = {arm: expected["value_q32"]-expected_values[answer["selected_action"]]
               for arm, answer in answers.items()}
    same_target = all((a["action"], a["value_q32"], a["candidate_values_q32"]) ==
                     (expected["action"], expected["value_q32"], expected_values) for a in (ordinary, dynamic))
    same_feasibility = [c["feasible"] for c in dynamic["candidates"]] == [c["feasible"] for c in fixed_pref["candidates"]]
    prefs = [dynamic["preference"][k] != fixed_pref["preference"][k] for k in ("price_q32", "discount_q32", "risk_q32")]
    flags = {"same_objective_exact": same_target, "same_feasibility": same_feasibility,
             "root_preference_numeric_change": any(prefs),
             "recursive_numeric_change": dynamic["candidate_values_q32"] != fixed_pref["candidate_values_q32"],
             "preference_action_change": dynamic["action"] != fixed_pref["action"],
             "preference_external_gain": regrets["fixed-preference-ndu"] > 0,
             "preference_both_deliver": dynamic["action"] is not None and fixed_pref["action"] is not None,
             "state_information_value": regrets["no-adaptation"] > 0,
             "planning_value_over_greedy": regrets["state-greedy"] > 0,
             "misleading_belief_cost": regrets["wrong-forecast"] > 0,
             "fixed_policy_sufficient": fixed_value["value_q32"] == expected["value_q32"]}
    flags["strict_preference_action_reversal"] = (same_target and same_feasibility and flags["preference_action_change"]
        and flags["preference_external_gain"] and flags["preference_both_deliver"])
    return {"id": state["id"], "environment": scenario.name, "families": state["families"],
            "scenario": state["scenario"], "observation": state["observation"],
            "answers": {arm: _compact(answer) for arm, answer in answers.items()},
            "fixed_policy": fixed_value, "external_conditional_regret_q32": regrets, "flags": flags,
            "status": "passed" if same_target and same_feasibility else "failed",
            "original_native_executed": is_original_backend(backend), "attempts": attempts,
            "qualification_type": "original-native" if is_original_backend(backend) else "reference-only",
            "native_request_range": None if native_before is None else [native_before+1, native_after],
            "wall_ns": time.perf_counter_ns()-began,
            "value_scope": "conditional finite-model objective, all arms scored with unchanged dynamic external objective",
            "authority": "DENY_ALL"}


def summarize_rows(rows, registry):
    counts = {}
    witnesses = {}
    by_id = {r["id"]: r for r in rows}
    flags = ("root_preference_numeric_change", "recursive_numeric_change", "preference_action_change",
             "preference_external_gain", "state_information_value", "planning_value_over_greedy",
             "misleading_belief_cost", "fixed_policy_sufficient", "strict_preference_action_reversal")
    for family in ("all-distinct", "supplied-grid", "supplied-boundary", "natural-support"):
        counts[family] = {}
        for environment in registry["protocol"]["environments"]:
            members = [r for r in rows if r["environment"] == environment and
                       (family == "all-distinct" or family in r["families"])]
            counts[family][environment] = {"distinct_states": len(members),
                "passed": sum(r["status"] == "passed" for r in members),
                **{flag: sum(r.get("flags", {}).get(flag, False) for r in members) for flag in flags}}
            witness_key = f"{family}/{environment}"
            witnesses[witness_key] = {}
            for flag in flags:
                matches = sorted(r["id"] for r in members if r["status"] == "passed" and r.get("flags", {}).get(flag, False))
                witnesses[witness_key][flag] = {"all_state_ids": matches, "first_state_id": matches[0] if matches else None}
    # Each tape keeps its probability and original denominator even if the
    # reference owner has already stopped; no renormalizing surviving tapes.
    profiles = []
    for profile in registry["natural_profiles"]:
        tapes = [t for t in registry["natural_tapes"] if t["profile"] == profile["id"]]
        expected_missing = sum(Fraction(*t["probability"])*t["missing_requests"] for t in tapes)
        flags_by_tape = {flag: 0 for flag in flags}
        masses = {flag: Fraction(0) for flag in flags}
        for tape in tapes:
            states = [by_id.get(s["coverage_state_id"], {"status": "not_run", "flags": {}}) for s in tape["steps"]]
            for flag in flags:
                observed = any(s.get("flags", {}).get(flag, False) for s in states)
                flags_by_tape[flag] += int(observed)
                if observed:
                    masses[flag] += Fraction(*tape["probability"])
        profiles.append({"id": profile["id"], "environment": profile["scenario"]["name"],
            "tapes": len(tapes), "probability_sum": _rational(sum((Fraction(*t["probability"]) for t in tapes), Fraction(0))),
            "unqualified_state_references": sum(by_id.get(s["coverage_state_id"], {}).get("status") != "passed" for t in tapes for s in t["steps"]), "expected_missing_requests": _rational(expected_missing),
            "tape_event_counts": flags_by_tape, "tape_event_probability": {k: _rational(v) for k, v in masses.items()},
            "scope": "exact support probability; correlated prefixes and model states are not independent experimental samples"})
    return {"counts": counts, "witnesses": witnesses, "natural_profile_coverage": profiles,
            "net_benefit_established": False, "ndu_exclusive_advantage_established": False,
            "interpretation": "Whole retained state coverage diagnoses mechanism activation and finite-model regret; native timing is not a selection variable."}


def _unrun_row(state, reason):
    return {"id": state["id"], "environment": state["scenario"]["name"], "families": state["families"],
            "scenario": state["scenario"], "observation": state["observation"],
            "status": "not_run", "reason": reason, "flags": {}, "answers": {}, "attempts": [],
            "original_native_executed": False, "wall_ns": 0, "authority": "DENY_ALL"}


def qualify(registry, *, backend=None, output=None, checkpoint=None, progress=None, require_clean=False):
    """Retain each completed state and finish a full-denominator failure report.

    A failed native session is not replaced by a scalar mock. All remaining
    registered states are explicitly not-run. Successful and failed attempts,
    partial answers, unknown counters and their wall time remain available.
    """
    started = time.perf_counter_ns()
    rows, errors, work, unknown_work = [], [], defaultdict(int), []
    before_calls = getattr(backend, "calls", 0)
    checkpoint_path = Path(checkpoint) if checkpoint else Path(output).with_suffix(".states.jsonl") if output else None
    stream = None
    protocol = registry["protocol"]
    preflight_ns = postflight_ns = 0
    stopped = None
    def retain(row):
        rows.append(row)
        if stream is not None:
            stream.write(_wire(row).decode()+"\n")
            stream.flush()
        for attempt in row.get("attempts", []):
            counter = attempt.get("search")
            if type(counter) is dict and type(counter.get("transitions")) is int:
                work[attempt["arm"]] += counter["transitions"]
            else:
                unknown_work.append({"state_id": row["id"], "arm": attempt["arm"],
                                     "status": attempt["status"], "reason": "no exact counter returned; wall retained"})
    try:
        if checkpoint_path:
            checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
            stream = checkpoint_path.open("x", encoding="utf-8")
        preflight = time.perf_counter_ns()
        protocol = validate_registry(registry, require_clean=require_clean)
        if require_clean:
            if not is_original_backend(backend):
                raise model.FeedbackError("formal qualification requires the admitted original native backend")
            if registry.get("native_inputs") is None:
                raise model.FeedbackError("formal native coverage lacks frozen executable/manifest inputs")
            if getattr(backend, "binary_sha256", None) != registry["native_inputs"]["binary"]["sha256"]:
                raise model.FeedbackError("running native backend differs from frozen executable")
        preflight_ns = time.perf_counter_ns()-preflight
        for index, state in enumerate(registry["states"]):
            state_started = time.perf_counter_ns()
            try:
                remaining = {arm: protocol["per_arm_transition_cap"]-work[arm]
                             for arm in [*protocol["comparison_arms"], "fixed-policy-value"]}
                row = qualify_state(state, protocol, backend=backend, per_arm_remaining=remaining)
            except BaseException as error:
                partial = getattr(error, "coverage_partial", {})
                row = {**_unrun_row(state, "state execution failed"), **partial,
                    "status": "failed", "wall_ns": time.perf_counter_ns()-state_started,
                    "original_native_executed": is_original_backend(backend),
                    "error": {"type": type(error).__name__, "message": str(error), "traceback": traceback.format_exc()}}
                retain(row)
                stopped = "state execution failed; remaining states were not retried"
                errors.append({"phase": "state", "state_id": state["id"], **row["error"]})
                break
            retain(row)
            if progress and (index+1) % 100 == 0:
                progress({"completed_states": index+1, "planned_states": len(registry["states"]),
                          "native_calls": getattr(backend, "calls", 0)-before_calls})
    except BaseException as error:
        stopped = "coverage preflight or evidence failure"
        errors.append({"phase": "preflight-or-evidence", "type": type(error).__name__,
                       "message": str(error), "traceback": traceback.format_exc()})
    finally:
        known = {row["id"] for row in rows}
        for state in registry["states"]:
            if state["id"] not in known:
                retain(_unrun_row(state, stopped or "not executed"))
        if stream is not None:
            stream.close()
        postflight = time.perf_counter_ns()
        try:
            if registry["source"] != source_identity(require_clean=require_clean):
                raise model.FeedbackError("coverage source changed during qualification")
            check_native_inputs(registry)
        except BaseException as error:
            errors.append({"phase": "postflight", "type": type(error).__name__, "message": str(error)})
        postflight_ns = time.perf_counter_ns()-postflight
        result = {"schema": SCHEMA+".result", "registration_sha256": registry["registration_sha256"],
            "source": registry["source"], "native_inputs": registry.get("native_inputs"),
            "planned_distinct_states": len(registry["states"]),
            "planned_supplied_memberships": 3030, "planned_natural_tapes": 3456,
            "rows": rows, "summary": summarize_rows(rows, registry), "errors": errors,
            "status": "passed" if not errors and all(r["status"] == "passed" for r in rows) else "failed",
            "completed_states": sum(r["status"] == "passed" for r in rows),
            "failed_states": sum(r["status"] == "failed" for r in rows),
            "not_run_states": sum(r["status"] == "not_run" for r in rows),
            "original_native_executed": is_original_backend(backend),
            "native_calls": getattr(backend, "calls", 0)-before_calls,
            "native_session_calls_before": before_calls, "native_session_calls_after": getattr(backend, "calls", 0),
            "work": dict(work), "unknown_work_counters": unknown_work,
            "all_states_original_native_qualified": is_original_backend(backend) and not errors and all(r["status"] == "passed" and r.get("original_native_executed") is True for r in rows),
            "preflight_wall_ns": preflight_ns, "postflight_wall_ns": postflight_ns,
            "qualification_wall_ns": time.perf_counter_ns()-started,
            "checkpoint": str(checkpoint_path) if checkpoint_path else None,
            "authority": "DENY_ALL", "production_activation": False}
        if output:
            _write(output, result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    freeze = sub.add_parser("freeze")
    freeze.add_argument("--output", type=Path, required=True)
    freeze.add_argument("--native-binary", type=Path, required=True)
    freeze.add_argument("--native-manifest", type=Path, required=True)
    run = sub.add_parser("run")
    run.add_argument("--registration", type=Path, required=True)
    run.add_argument("--output", type=Path, required=True)
    # Explicit run paths may confirm, but cannot replace, frozen identities.
    run.add_argument("--native-binary", type=Path)
    run.add_argument("--native-manifest", type=Path)
    run.add_argument("--native-log", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "freeze":
        began = time.perf_counter_ns()
        try:
            registration = build_registry(require_clean=True, native_binary=args.native_binary,
                                          native_manifest=args.native_manifest)
            _write(args.output, registration)
        except BaseException as error:
            _write(args.output.with_suffix(".failure.json"), {"schema": SCHEMA+".registration-failure",
                "error": {"type": type(error).__name__, "message": str(error), "traceback": traceback.format_exc()},
                "wall_ns": time.perf_counter_ns()-began, "authority": "DENY_ALL"})
            raise
        print(json.dumps({"states": len(registration["states"]), "tapes": len(registration["natural_tapes"]),
                          "registration_sha256": registration["registration_sha256"]}))
        return
    from .native import NativeValueBackend
    registration = json.loads(args.registration.read_text())
    backend, result = None, None
    began = time.perf_counter_ns()
    outer_errors = []
    try:
        validate_registry(registration, require_clean=True)
        inputs = registration.get("native_inputs")
        if inputs is None:
            raise model.FeedbackError("run requires source-bound native inputs frozen beforehand")
        if args.native_binary and input_identity(args.native_binary) != inputs["binary"]:
            raise model.FeedbackError("run executable is not the frozen input")
        if args.native_manifest and input_identity(args.native_manifest) != inputs["manifest"]:
            raise model.FeedbackError("run receipt is not the frozen input")
        backend = NativeValueBackend(inputs["binary"]["path"], inputs["manifest"]["path"], log=args.native_log)
        result = qualify(registration, backend=backend, checkpoint=args.output.with_suffix(".states.jsonl"),
                         progress=lambda value: print(json.dumps(value), flush=True), require_clean=True)
    except BaseException as error:
        outer_errors.append({"phase": "native-admission-or-qualification", "type": type(error).__name__,
                             "message": str(error), "traceback": traceback.format_exc()})
    finally:
        close = None
        if backend is not None:
            try:
                backend.close()
            except BaseException as error:
                outer_errors.append({"phase": "native-close", "type": type(error).__name__, "message": str(error)})
            close = {"returncode": backend.returncode, "close_ns": backend.close_ns,
                     "startup_ns": backend.startup_ns, "call_wall_ns": backend.total_call_ns}
        try:
            check_native_inputs(registration)
            if registration["source"] != source_identity(require_clean=True):
                raise model.FeedbackError("source changed after native cleanup")
        except BaseException as error:
            outer_errors.append({"phase": "final-input-check", "type": type(error).__name__, "message": str(error)})
        if result is None:
            rows = [_unrun_row(s, "native admission or preflight failed") for s in registration["states"]]
            result = {"schema": SCHEMA+".result", "registration_sha256": registration["registration_sha256"],
                "source": registration["source"], "native_inputs": registration.get("native_inputs"),
                "status": "failed", "rows": rows, "summary": summarize_rows(rows, registration),
                "planned_distinct_states": len(rows), "completed_states": 0, "failed_states": 0,
                "not_run_states": len(rows), "planned_supplied_memberships": 3030, "planned_natural_tapes": 3456,
                "errors": [], "work": {}, "original_native_executed": False,
                "native_calls": getattr(backend, "calls", 0), "authority": "DENY_ALL", "production_activation": False}
        result["errors"].extend(outer_errors)
        if outer_errors:
            result["status"] = "failed"
            result["all_states_original_native_qualified"] = False
        result["native_close"] = close
        result["outer_wall_ns"] = time.perf_counter_ns()-began
        result["scope"] = "source and frozen-input checks, full state qualification, raw evidence and native cleanup; nested clocks not additive"
        _write(args.output, result)
    print(json.dumps({"states": len(result["rows"]), "native_calls": result["native_calls"],
                      "status": result["status"], "completed": result["completed_states"],
                      "failed": result["failed_states"], "not_run": result["not_run_states"]}))
    if result["status"] != "passed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
