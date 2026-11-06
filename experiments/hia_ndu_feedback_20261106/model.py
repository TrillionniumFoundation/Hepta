"""Finite feedback-cache research model; no compiler or production authority.

A hidden, episode-constant demand regime emits each *current* request and a
noisy signal. The controller receives an immutable posterior and physical cache
state, never the seed, hidden regime, future requests or future measurements.
Every possible next observation is integrated over the published likelihoods.
Native NDU, when selected, evaluates all actions at every Bellman backup before
that node's action is selected. A separately written bottom-up reference checks
those backups. This is an explicitly finite model, not an FBSDE solver.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from fractions import Fraction
from hashlib import sha256
import json
import random
import time
from typing import Callable

Q32 = 1 << 32
AUTHORITY = "DENY_ALL"
ARMS = ("fixed", "state-greedy", "ordinary-mpc", "same-objective", "fixed-preference-ndu",
        "dynamic-ndu", "exact-oracle")
ACTIONS = (-1, 0, 1)
CANDIDATE_IDS = ("direct", "cache-0", "cache-1", "abstain")


class FeedbackError(ValueError):
    pass


class SearchBudgetExhausted(FeedbackError):
    def __init__(self, message, *, transitions=0, statistics=None):
        super().__init__(message)
        self.transitions = transitions
        self.search_stats = dict(statistics or {"transitions": transitions})
        self.search_stats["transitions"] = transitions


def digest(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def round_fraction(value: Fraction) -> int:
    """Exact nearest integer, ties to even, including negative values."""
    q, r = divmod(value.numerator, value.denominator)
    return q + int(2 * r > value.denominator or (2 * r == value.denominator and q % 2))


def q32(value) -> int:
    return round_fraction(Fraction(value) * Q32)


def mul_q32(left: int, right: int) -> int:
    return round_fraction(Fraction(left * right, Q32))


def action_name(action: int | None) -> str:
    if action is None:
        return "abstain"
    if action not in ACTIONS or type(action) is not int:
        raise FeedbackError("invalid cache action")
    return "direct" if action == -1 else f"cache-{action}"


def action_number(name: str) -> int | None:
    values = {action_name(a): a for a in (*ACTIONS, None)}
    if name not in values:
        raise FeedbackError("unknown selected action")
    return values[name]


@dataclass(frozen=True)
class Scenario:
    name: str
    horizon: int = 3
    request_p0_z0_num: int = 9
    request_p0_z0_den: int = 10
    request_p0_z1_num: int = 1
    request_p0_z1_den: int = 10
    signal_correct_num: int = 4
    signal_correct_den: int = 5
    prior0_num: int = 1
    prior0_den: int = 2
    direct_cost: int = 6
    hot_cost: int = 1
    load_cost: int = 4
    retire_cost: int = 0
    holding_cost: int = 0
    initial_resident: int = -1
    initial_budget: int = 20
    initial_deadline: int = 20
    cost_unit: int = 1
    completion_reward_q32: int = 20 * Q32
    miss_penalty_q32: int = 30 * Q32
    discount_q32: int = 15 * Q32 // 16
    risk_aversion_q32: int = Q32 // 4
    dynamic_preferences: bool = True
    cost_unit_label: str = "declared model cost units"

    def __post_init__(self):
        ints = [getattr(self, name) for name in self.__dataclass_fields__
                if name not in {"name", "dynamic_preferences", "cost_unit_label"}]
        if any(type(x) is not int for x in ints):
            raise FeedbackError("scenario integers must have exact types")
        if type(self.name) is not str or not self.name or type(self.dynamic_preferences) is not bool:
            raise FeedbackError("scenario identity or preference flag")
        if not 1 <= self.horizon <= 4 or self.initial_resident not in ACTIONS:
            raise FeedbackError("horizon or initial cache bound")
        for prefix in ("request_p0_z0", "request_p0_z1", "signal_correct", "prior0"):
            n, d = getattr(self, prefix + "_num"), getattr(self, prefix + "_den")
            if not 0 <= n <= d or not 1 <= d <= 1000000:
                raise FeedbackError("probability bounds")
        if not 0 <= self.discount_q32 <= Q32 or not 0 <= self.risk_aversion_q32 <= Q32:
            raise FeedbackError("discount or risk bound")
        if min(self.direct_cost, self.hot_cost, self.load_cost, self.retire_cost,
               self.holding_cost, self.initial_budget, self.initial_deadline) < 0 or self.cost_unit <= 0:
            raise FeedbackError("negative costs or zero cost unit")
        if max(self.direct_cost, self.hot_cost, self.load_cost, self.initial_budget,
               self.initial_deadline, self.cost_unit) > 10**12:
            raise FeedbackError("cost bound")
        if self.hot_cost > self.direct_cost:
            raise FeedbackError("hot path must not be more expensive than direct")

    @property
    def objective_digest(self):
        return digest({"rule": "state-price-plus-discounted-mean-downside-v1", "scenario": asdict(self)})


SCENARIOS = {
    "adaptive": Scenario("adaptive"),
    "fixed": Scenario("fixed", request_p0_z0_num=99, request_p0_z0_den=100,
                      request_p0_z1_num=99, request_p0_z1_den=100,
                      signal_correct_num=1, signal_correct_den=2,
                      initial_resident=0),
    "misleading": Scenario("misleading", signal_correct_num=1, signal_correct_den=5),
}


@dataclass(frozen=True)
class Observation:
    step: int
    request: int
    signal: int
    resident: int
    budget: int
    deadline: int
    belief_num: int
    belief_den: int

    @property
    def belief(self):
        return Fraction(self.belief_num, self.belief_den)

    @property
    def state_digest(self):
        return digest(asdict(self))


def validate_observation(scenario: Scenario, observation: Observation):
    if type(observation) is not Observation:
        raise FeedbackError("controller requires a plain immutable Observation")
    if any(type(getattr(observation, f)) is not int for f in observation.__dataclass_fields__):
        raise FeedbackError("observation integer types")
    if not 0 <= observation.step < scenario.horizon or observation.request not in (0, 1) or observation.signal not in (0, 1):
        raise FeedbackError("current request/signal/step bound")
    if observation.resident not in ACTIONS or observation.budget < 0 or observation.deadline < 0:
        raise FeedbackError("cache or remaining resource bound")
    if not 0 <= observation.belief_num <= observation.belief_den or observation.belief_den < 1:
        raise FeedbackError("belief is not a probability")
    if observation.belief_den > 10**24:
        raise FeedbackError("belief denominator bound")
    return observation


def _probabilities(scenario, regime):
    p = Fraction(scenario.request_p0_z0_num, scenario.request_p0_z0_den) if regime == 0 else Fraction(scenario.request_p0_z1_num, scenario.request_p0_z1_den)
    sensor = Fraction(scenario.signal_correct_num, scenario.signal_correct_den)
    return p, sensor if regime == 0 else 1 - sensor


def posterior(scenario, prior, request, signal):
    terms = []
    for z, mass in ((0, prior), (1, 1 - prior)):
        p0, s0 = _probabilities(scenario, z)
        terms.append(mass * (p0 if request == 0 else 1 - p0) * (s0 if signal == 0 else 1 - s0))
    total = sum(terms)
    if not total:
        raise FeedbackError("observed event has zero probability in declared model")
    return terms[0] / total


def forecast(scenario, observation):
    """Distribution of future request/signal, never a realized future sample."""
    branches = []
    for request in (0, 1):
        for signal in (0, 1):
            terms = []
            for z, mass in ((0, observation.belief), (1, 1 - observation.belief)):
                p0, s0 = _probabilities(scenario, z)
                terms.append(mass * (p0 if request == 0 else 1 - p0) * (s0 if signal == 0 else 1 - s0))
            probability = sum(terms)
            if probability:
                branches.append((probability, request, signal, terms[0] / probability))
    if sum(p for p, *_ in branches) != 1:
        raise FeedbackError("forecast mass does not sum to one")
    return branches


def action_cost(scenario, observation, action):
    if action is None:
        raise FeedbackError("abstention has no workload action or dispatch")
    action_name(action)
    prepare = scenario.load_cost if action >= 0 and action != observation.resident else 0
    retire = scenario.retire_cost if observation.resident >= 0 and action != observation.resident else 0
    execution = scenario.hot_cost if action == observation.request else scenario.direct_cost
    hold = scenario.holding_cost if action >= 0 else 0
    return {"prepare": prepare, "retire": retire, "execution": execution, "hold": hold,
            "total": prepare + retire + execution + hold,
            "dispatch": "packed" if action == observation.request else "direct"}


def preferences(scenario, observation, *, fixed=False):
    """An external registered state rule; all policies are scored by this rule.

    At resource slack >= the cost of remaining direct requests, price=1. Below
    it, scarcity raises latency price and downside aversion continuously. The
    fixed-preference ablation uses the initial-slack values for every state.
    """
    remaining = scenario.horizon - observation.step
    target = max(scenario.cost_unit, remaining * scenario.direct_cost)
    if not scenario.dynamic_preferences:
        scarcity = Fraction(0)
    elif fixed:
        initial_target = max(scenario.cost_unit, scenario.horizon * scenario.direct_cost)
        initial_slack = min(scenario.initial_budget, scenario.initial_deadline)
        scarcity = max(Fraction(0), 1 - Fraction(initial_slack, initial_target))
    else:
        slack = min(observation.budget, observation.deadline)
        scarcity = max(Fraction(0), 1 - Fraction(slack, target))
    price = q32(1 + scarcity)
    risk = min(Q32, scenario.risk_aversion_q32 + q32(scarcity / 4))
    return {"price_q32": price, "discount_q32": scenario.discount_q32,
            "risk_q32": risk, "scarcity_num": scarcity.numerator, "scarcity_den": scarcity.denominator}


def immediate(scenario, cost, pref):
    return scenario.completion_reward_q32 - mul_q32(pref["price_q32"], q32(Fraction(cost, scenario.cost_unit)))


def certainty_equivalent(weighted_values, risk_q32):
    if not weighted_values:
        return 0
    mean = sum(p * value for p, value in weighted_values)
    downside = sum(p * max(Fraction(0), mean - value) for p, value in weighted_values)
    return round_fraction(mean - Fraction(risk_q32, Q32) * downside)


def scalar_backend(candidates, *, state_digest, preference_digest, objective_digest,
                   resource_budget_q32=0, risk_ceiling_q32=Q32):
    """Independent arithmetic control, never represented as native NDU."""
    values = {c["id"]: c["instant_q32"] + mul_q32(c["discount_q32"], c["terminal_q32"]) for c in candidates}
    eligible = [c["id"] for c in candidates if c["feasible"] and c["resource_q32"] <= resource_budget_q32 and c["risk_q32"] <= risk_ceiling_q32]
    maximum = max((values[k] for k in eligible), default=None)
    return {"values": values, "winners": sorted(k for k in eligible if values[k] == maximum),
            "native": False}


def _call_backend(backend, candidates, scenario, observation, pref, *, objective_digest=None):
    fn = backend.evaluate if hasattr(backend, "evaluate") else backend
    response = fn(candidates, state_digest=observation.state_digest,
                  preference_digest=digest(pref), objective_digest=objective_digest or scenario.objective_digest,
                  resource_budget_q32=q32(Fraction(min(observation.budget, observation.deadline), scenario.cost_unit)),
                  risk_ceiling_q32=Q32)
    values, winners = response.get("values"), response.get("winners")
    ids = {c["id"] for c in candidates}
    if type(values) is not dict or set(values) != ids or any(type(v) is not int for v in values.values()):
        raise FeedbackError("backend omitted or invalid candidate values")
    if type(winners) is not list or not winners or any(type(k) is not str or k not in ids for k in winners):
        raise FeedbackError("backend winner structure")
    eligible = [c["id"] for c in candidates if c["feasible"]]
    best = max(values[k] for k in eligible)
    if winners != sorted(k for k in eligible if values[k] == best):
        raise FeedbackError("backend winners contradict candidate values")
    return response


def plan(scenario: Scenario, observation: Observation, arm: str, *, backend=None,
         max_transitions: int = 20000, fixed_action: int = 0, compute_profile=None):
    """Choose a real cache action using only the current public observation.

    Forecasts are fixed before execution. Search-budget failure raises before
    advice is returned; callers must retain that failure rather than use a
    partially searched candidate. All planning arms use the full remaining
    finite horizon; ordinary MPC uses a different additive-cost objective.

    An explicit compute-resource profile adds each depth's frozen controller
    forecast to resource transitions and utility, including a future abstention.
    It never turns forecasts into observed timing guarantees. The default v1
    path and its independent oracle retain their original workload-only model.
    """
    validate_observation(scenario, observation)
    if arm not in ARMS and arm not in {"wrong-forecast", "no-adaptation"}:
        raise FeedbackError("unknown comparison arm")
    if type(max_transitions) is not int or not 1 <= max_transitions <= 1000000:
        raise FeedbackError("search budget bounds")
    if fixed_action not in ACTIONS or type(fixed_action) is not int:
        raise FeedbackError("fixed action must be a cache slot or empty")
    if arm in {"dynamic-ndu", "fixed-preference-ndu"} and backend is None:
        raise FeedbackError("native arm requires an explicit native backend")
    compute_objective = None
    if compute_profile is not None:
        from .compute_debit import after_compute, validate_profile
        validate_profile(compute_profile, scenario)
        if arm == "exact-oracle":
            raise FeedbackError("the v1 independent oracle does not implement compute-resource debits")
        compute_objective = compute_profile.objective_digest(scenario)
    if arm == "exact-oracle":
        return independent_oracle(scenario, observation, max_transitions=max_transitions)
    start = time.perf_counter_ns()
    counters = {"states": 0, "transitions": 0, "backups": 0, "backend_calls": 0}
    node_receipts = []
    memo = {}
    fixed = arm in {"fixed-preference-ndu", "no-adaptation"}
    depth = 1 if arm in {"fixed", "state-greedy"} else scenario.horizon - observation.step
    modeling = scenario
    planning_observation = observation
    if arm == "wrong-forecast":
        # An explicit model-error intervention: invert the current posterior.
        # No hidden label or future sample is used to make this wrong forecast.
        planning_observation = replace(observation, belief_num=observation.belief_den-observation.belief_num)
    elif arm == "no-adaptation":
        planning_observation = replace(observation, belief_num=scenario.prior0_num, belief_den=scenario.prior0_den)
    evaluator = backend if arm in {"dynamic-ndu", "fixed-preference-ndu"} else scalar_backend

    def solve(state, remaining):
        key = (state, remaining)
        if key in memo:
            return memo[key]
        counters["states"] += 1
        pref = preferences(modeling, state, fixed=fixed)
        candidates = []
        if arm == "ordinary-mpc":
            pref = {"price_q32": Q32, "discount_q32": Q32, "risk_q32": 0, "scarcity_num": 0, "scarcity_den": 1}
        compute_ns = 0 if compute_profile is None else compute_profile.forecast(modeling, state)
        available = state if compute_profile is None else after_compute(modeling, state, compute_ns)
        # The price is fixed at the observed, pre-computation state for this
        # entire step, matching FeedbackEnvironment.step's actual-cost rule.
        # A deadline already reached by computation permits no new service,
        # including a declared zero-duration workload. Abstention remains legal.
        compute_exhausted = compute_profile is not None and compute_ns >= min(state.budget, state.deadline)
        for action in ACTIONS:
            counters["transitions"] += 1
            if counters["transitions"] > max_transitions:
                raise SearchBudgetExhausted(f"search exceeded {max_transitions} action expansions", transitions=max_transitions, statistics=counters)
            cost = action_cost(modeling, state, action)["total"]
            total_cost = cost + compute_ns
            feasible = not compute_exhausted and cost <= min(available.budget, available.deadline)
            continuation = []
            if feasible and remaining > 1:
                for probability, request, signal, belief in forecast(modeling, state):
                    child = Observation(state.step + 1, request, signal, action, available.budget - cost,
                                        available.deadline - cost, belief.numerator, belief.denominator)
                    continuation.append((probability, solve(child, remaining - 1)[0]))
            value = certainty_equivalent(continuation, pref["risk_q32"])
            instant = -q32(Fraction(total_cost, modeling.cost_unit)) if arm == "ordinary-mpc" else immediate(modeling, total_cost, pref)
            candidates.append({"id": action_name(action), "instant_q32": instant,
                               "terminal_q32": value, "discount_q32": pref["discount_q32"],
                               "feasible": feasible, "resource_q32": q32(Fraction(total_cost, modeling.cost_unit)), "risk_q32": 0})
        # Upstream requires an explicit feasible abstention candidate. This
        # terminates delivery and incurs the registered remaining-request loss;
        # it is never an over-budget direct dispatch disguised as abstention.
        counters["transitions"] += 1
        if counters["transitions"] > max_transitions:
            raise SearchBudgetExhausted(f"search exceeded {max_transitions} action expansions", transitions=max_transitions, statistics=counters)
        candidates.append({"id": "abstain",
                           "instant_q32": -modeling.miss_penalty_q32 * (modeling.horizon-state.step)
                               - mul_q32(pref["price_q32"], q32(Fraction(compute_ns, modeling.cost_unit))),
                           "terminal_q32": 0, "discount_q32": Q32, "feasible": True,
                           "resource_q32": 0, "risk_q32": 0})
        counters["backups"] += 1
        counters["backend_calls"] += int(evaluator is not scalar_backend)
        response = _call_backend(evaluator, candidates, modeling, state, pref,
                                 objective_digest=compute_objective)
        chosen = response["winners"][0]
        if arm == "fixed":
            desired = action_name(fixed_action)
            fallback = [c for c in candidates if c["feasible"] and c["id"] != "abstain"]
            chosen = desired if next(c for c in candidates if c["id"] == desired)["feasible"] else min(fallback, key=lambda c: (c["resource_q32"], c["id"]))["id"] if fallback else "abstain"
        values = response["values"]
        result = (values[chosen], action_number(chosen), values, candidates, pref)
        # A compact search proof trace contains every node and no hidden values.
        node_receipt = {"state_digest": state.state_digest, "preference": pref,
                        "candidate_ids": [c["id"] for c in candidates],
                        "eligible": [c["id"] for c in candidates if c["feasible"]],
                        "selected": chosen, "values_q32": values}
        if compute_profile is not None:
            node_receipt["compute_debit"] = {"forecast_ns": compute_ns,
                "budget_before": state.budget, "deadline_before": state.deadline,
                "budget_after": available.budget, "deadline_after": available.deadline,
                "service_deadline_exhausted": compute_exhausted}
        node_receipts.append(node_receipt)
        memo[key] = result
        return result

    try:
        value, selected, values, candidates, pref = solve(planning_observation, depth)
    except Exception as error:
        error.search_stats = {**counters, "transitions": min(counters["transitions"], max_transitions)}
        error.transitions = error.search_stats["transitions"]
        error.controller_wall_ns = time.perf_counter_ns()-start
        raise
    result = {"schema": "hepta.hia.ndu.feedback-plan.v1", "arm": arm, "action": selected,
            "selected_action": action_name(selected),
            "value_q32": value, "candidate_values_q32": values, "candidates": candidates,
            "preference": pref, "observation": asdict(observation), "state_digest": observation.state_digest,
            "forecast": [{"probability": [p.numerator, p.denominator], "request": r, "signal": s,
                          "belief": [b.numerator, b.denominator]} for p, r, s, b in forecast(modeling, planning_observation)],
            "planning_belief": [planning_observation.belief_num, planning_observation.belief_den],
            "forecast_intervention": "posterior-inversion" if arm == "wrong-forecast" else "reset-to-prior" if arm == "no-adaptation" else None,
            "search": counters, "search_complete": depth == scenario.horizon - observation.step,
            "depth": depth, "search_trace": node_receipts, "controller_wall_ns": time.perf_counter_ns() - start,
            "native_backend_used": evaluator is not scalar_backend,
            "scope": "finite declared model; ordinary MPC has a different additive objective",
            "authority": AUTHORITY, "production_activation": False}
    if compute_profile is not None:
        from .compute_debit import PLAN_SCHEMA, SCHEMA
        result["schema"] = PLAN_SCHEMA
        result["compute_debit"] = {"schema": SCHEMA, "profile_sha256": compute_profile.identity,
            "profile": asdict(compute_profile), "objective_digest": compute_objective,
            "forecast_is_physical_guarantee": False, "hard_realtime_guarantee": False,
            "cost_rule": "compute plus workload once at each modeled decision; measured total at dispatch"}
    return result


def independent_oracle(scenario, observation, *, max_transitions=20000):
    """Separately encoded tuple-state backward induction over the same objective.

    It does not call plan, forecast, action_cost, preferences, immediate,
    certainty_equivalent or scalar_backend. It enumerates the joint emission
    distribution afresh and computes each integer backup with Fraction.
    """
    validate_observation(scenario, observation)
    started = time.perf_counter_ns()
    cache, count = {}, [0, 0]
    def rounded(x):
        integer, remainder = divmod(x.numerator, x.denominator)
        return integer + int(remainder * 2 > x.denominator or (remainder * 2 == x.denominator and integer % 2 != 0))
    def solve(key):
        if key in cache:
            return cache[key]
        t, request, resident, budget, deadline, bnum, bden = key
        count[0] += 1
        remaining = scenario.horizon - t
        slack = min(budget, deadline)
        scarcity = max(Fraction(0), 1 - Fraction(slack, max(scenario.cost_unit, remaining * scenario.direct_cost))) if scenario.dynamic_preferences else Fraction(0)
        price = rounded((1 + scarcity) * Q32)
        risk = min(Q32, scenario.risk_aversion_q32 + rounded(scarcity * Q32 / 4))
        values, eligible = {}, {}
        for target in (-1, 0, 1):
            count[1] += 1
            if count[1] > max_transitions:
                raise SearchBudgetExhausted("independent oracle search budget", transitions=max_transitions, statistics={"states": count[0], "transitions": max_transitions, "backend_calls": 0})
            cost = (scenario.hot_cost if target == request else scenario.direct_cost)
            cost += scenario.load_cost * int(target != -1 and target != resident)
            cost += scenario.retire_cost * int(resident != -1 and target != resident)
            cost += scenario.holding_cost * int(target != -1)
            feasible = cost <= slack
            eligible[target] = feasible
            vals = []
            if feasible and remaining > 1:
                for nr in (0, 1):
                    for ns in (0, 1):
                        masses = []
                        for z in (0, 1):
                            prior = Fraction(bnum, bden) if z == 0 else 1 - Fraction(bnum, bden)
                            preq0 = Fraction(scenario.request_p0_z0_num, scenario.request_p0_z0_den) if z == 0 else Fraction(scenario.request_p0_z1_num, scenario.request_p0_z1_den)
                            psig0 = Fraction(scenario.signal_correct_num, scenario.signal_correct_den) if z == 0 else 1 - Fraction(scenario.signal_correct_num, scenario.signal_correct_den)
                            masses.append(prior * (preq0 if nr == 0 else 1 - preq0) * (psig0 if ns == 0 else 1 - psig0))
                        mass = sum(masses)
                        if mass:
                            bp = masses[0] / mass
                            next_value, _, _ = solve((t+1, nr, target, budget-cost, deadline-cost, bp.numerator, bp.denominator))
                            vals.append((mass, next_value))
            average = sum((p * v for p, v in vals), Fraction(0))
            tail = sum((p * max(Fraction(0), average-v) for p, v in vals), Fraction(0))
            cont = rounded(average - Fraction(risk, Q32) * tail)
            cost_raw = rounded(Fraction(cost * Q32, scenario.cost_unit))
            reward = scenario.completion_reward_q32 - rounded(Fraction(price * cost_raw, Q32))
            total = reward + rounded(Fraction(scenario.discount_q32 * cont, Q32))
            values[target] = total
        count[1] += 1
        if count[1] > max_transitions:
            raise SearchBudgetExhausted("independent oracle search budget", transitions=max_transitions, statistics={"states": count[0], "transitions": max_transitions, "backend_calls": 0})
        values[None] = -scenario.miss_penalty_q32 * remaining
        eligible[None] = True
        result = (max(v for a, v in values.items() if eligible[a]), values, eligible)
        cache[key] = result
        return result
    try:
        value, raw_values, eligible = solve((observation.step, observation.request, observation.resident,
                                  observation.budget, observation.deadline, observation.belief_num, observation.belief_den))
    except Exception as error:
        error.search_stats = {"states": count[0], "transitions": min(count[1], max_transitions), "backend_calls": 0}
        error.transitions = error.search_stats["transitions"]
        error.controller_wall_ns = time.perf_counter_ns()-started
        raise
    winners = sorted(action_name(a) for a, v in raw_values.items() if eligible[a] and v == value)
    selected = action_number(winners[0]) if winners else None
    return {"schema": "hepta.hia.ndu.feedback-plan.v1", "arm": "exact-oracle", "action": selected,
            "selected_action": winners[0] if winners else None,
            "value_q32": value, "candidate_values_q32": {action_name(a): v for a, v in raw_values.items()},
            "eligibility": {action_name(a): feasible for a, feasible in eligible.items()},
            "search": {"states": count[0], "transitions": count[1], "backups": count[0], "backend_calls": 0},
            "search_complete": True, "depth": scenario.horizon-observation.step,
            "observation": asdict(observation), "state_digest": observation.state_digest,
            "preference": preferences(scenario, observation),
            "controller_wall_ns": time.perf_counter_ns()-started, "native_backend_used": False,
            "scope": "separate exact finite-model encoding; no realized-future access",
            "authority": AUTHORITY, "production_activation": False}


class FeedbackEnvironment:
    """Owns hidden randomness. Only observe() is supplied to a controller.

    The Python object boundary is a causal interface, not a security sandbox.
    A malicious process with arbitrary host access could inspect its memory.
    """
    def __init__(self, scenario: Scenario, seed: int):
        if type(seed) is not int or seed < 0:
            raise FeedbackError("nonnegative episode seed required")
        self.scenario = scenario
        self._rng = random.Random(seed)
        self._regime = 0 if self._rng.random() < float(Fraction(scenario.prior0_num, scenario.prior0_den)) else 1
        self._step = 0
        self._resident = scenario.initial_resident
        self._budget, self._deadline = scenario.initial_budget, scenario.initial_deadline
        self._belief = Fraction(scenario.prior0_num, scenario.prior0_den)
        self._done = False
        self._current = None
        self.outcomes = []
        self._sample()

    def _sample(self):
        p0, s0 = _probabilities(self.scenario, self._regime)
        request = 0 if self._rng.random() < float(p0) else 1
        signal = 0 if self._rng.random() < float(s0) else 1
        self._belief = posterior(self.scenario, self._belief, request, signal)
        self._current = Observation(self._step, request, signal, self._resident,
                                    self._budget, self._deadline, self._belief.numerator, self._belief.denominator)

    def observe(self):
        if self._done:
            raise FeedbackError("completed episode has no current observation")
        return self._current

    @property
    def done(self):
        return self._done

    def step(self, action, *, actual_cost=None):
        if self._done:
            raise FeedbackError("cannot execute after terminal outcome")
        observation = self.observe()
        if action is None:
            # The workload does not run, but already spent controller time is
            # irrecoverable. The caller may supply that real measured cost.
            if actual_cost is None:
                actual_cost = 0
            if type(actual_cost) is not int or not 0 <= actual_cost <= 10**12:
                raise FeedbackError("actual abstention cost must be observed nonnegative integer units")
            preference = preferences(self.scenario, observation)
            self._budget = max(0, self._budget-actual_cost)
            self._deadline = max(0, self._deadline-actual_cost)
            self._done = True
            failed_reward = -self.scenario.miss_penalty_q32*(self.scenario.horizon-self._step)
            spent_cost = mul_q32(preference["price_q32"], q32(Fraction(actual_cost, self.scenario.cost_unit)))
            outcome = {"observation": asdict(observation), "action": None, "executed_action": None,
                       "delivered": False, "status": "abstained", "cost": actual_cost,
                       "predicted_cost": 0, "cost_unit": self.scenario.cost_unit_label,
                       "resident_after": self._resident, "remaining_budget": self._budget,
                       "remaining_deadline": self._deadline, "prepared": False, "retired": False,
                       "reward_q32": failed_reward-spent_cost,
                       "discount_q32": self.scenario.discount_q32, "preference": preference}
            self.outcomes.append(outcome)
            return outcome
        costs = action_cost(self.scenario, observation, action)
        if costs["total"] > min(observation.budget, observation.deadline):
            raise FeedbackError("selected action violates declared resource feasibility")
        if actual_cost is None:
            actual_cost = costs["total"]
        if type(actual_cost) is not int or not 0 <= actual_cost <= 10**12:
            raise FeedbackError("actual cost must be observed nonnegative integer units")
        preference = preferences(self.scenario, observation)
        delivered = actual_cost <= min(observation.budget, observation.deadline)
        self._resident = action
        self._budget = max(0, self._budget-actual_cost)
        self._deadline = max(0, self._deadline-actual_cost)
        self._step += 1
        self._done = not delivered or self._step == self.scenario.horizon
        outcome = {"observation": asdict(observation), "action": action, "executed_action": action,
                   "delivered": delivered, "status": "delivered" if delivered else "actual_budget_exceeded",
                   "predicted_cost": costs["total"], "cost": actual_cost,
                   "cost_unit": self.scenario.cost_unit_label, "dispatch": costs["dispatch"],
                   "prepared": action >= 0 and action != observation.resident,
                   "retired": observation.resident >= 0 and action != observation.resident,
                   "resident_after": self._resident, "remaining_budget": self._budget,
                   "remaining_deadline": self._deadline,
                   "reward_q32": immediate(self.scenario, actual_cost, preference) if delivered else -self.scenario.miss_penalty_q32*(self.scenario.horizon-observation.step)-mul_q32(preference["price_q32"], q32(Fraction(actual_cost, self.scenario.cost_unit))),
                   "discount_q32": preference["discount_q32"], "preference": preference}
        self.outcomes.append(outcome)
        if not self._done:
            self._sample()
        return outcome


def run_episode(scenario, seed, arm, *, backend=None, fixed_action=0, max_transitions=20000, executor=None):
    """Run actual chosen transitions, optionally with a real workload executor.

    executor(observation, action) returns nonnegative actual cost in Scenario's
    declared unit. It never receives future requests. All public arms see the
    same seed's exogenous request/signal history; actions affect resource state.
    """
    env = FeedbackEnvironment(scenario, seed)
    records = []
    while not env.done:
        obs = env.observe()
        decision = plan(scenario, obs, arm, backend=backend, max_transitions=max_transitions, fixed_action=fixed_action)
        actual = executor(obs, decision["action"]) if executor and decision["action"] is not None else None
        outcome = env.step(decision["action"], actual_cost=actual)
        if decision["action"] != outcome["executed_action"]:
            raise FeedbackError("selected versus executed action mismatch")
        records.append({"decision": decision, "outcome": outcome})
    realized = 0
    for row in reversed(records):
        outcome = row["outcome"]
        realized = outcome["reward_q32"] + mul_q32(outcome["discount_q32"], realized)
    return {"scenario": scenario.name, "arm": arm, "seed": seed,
            "steps": records, "planned_requests": scenario.horizon,
            "delivered": sum(r["outcome"]["delivered"] for r in records),
            "actual_cost": sum(r["outcome"]["cost"] for r in records),
            "cost_unit": scenario.cost_unit_label,
            "controller_wall_ns": sum(r["decision"]["controller_wall_ns"] for r in records),
            "search_transitions": sum(r["decision"]["search"]["transitions"] for r in records),
            "realized_discounted_utility_q32": realized,
            "realized_utility_scope": "pathwise registered rewards and discount; not the nested conditional downside objective",
            "authority": AUTHORITY, "production_activation": False}


def select_fixed(scenario, training_seeds):
    if type(training_seeds) is not list or not training_seeds or len(training_seeds) > 256 or len(set(training_seeds)) != len(training_seeds):
        raise FeedbackError("bounded unique training seed inventory required")
    rows = []
    for action in ACTIONS:
        evaluations = [run_episode(scenario, seed, "fixed", fixed_action=action) for seed in training_seeds]
        rows.append({"action": action, "training_utility_q32": sum(r["realized_discounted_utility_q32"] for r in evaluations),
                     "training_cost": sum(r["actual_cost"] for r in evaluations),
                     "training_controller_wall_ns": sum(r["controller_wall_ns"] for r in evaluations),
                     "training_search_transitions": sum(r["search_transitions"] for r in evaluations)})
    chosen = max(rows, key=lambda r: (r["training_utility_q32"], -r["training_cost"], -r["action"]))
    return {"action": chosen["action"], "all_candidates": rows, "training_seeds": list(training_seeds),
            "final_holdout_used": False, "authority": AUTHORITY}


def wiring_probes(backend=None):
    """Hand-computable, non-dominated candidate reversals, including native path."""
    evaluate = backend if backend is not None else scalar_backend
    retention = Scenario("hand-retention", horizon=2, request_p0_z0_num=1, request_p0_z0_den=1,
                         request_p0_z1_num=0, request_p0_z1_den=1,
                         signal_correct_num=1, signal_correct_den=2,
                         initial_resident=1, initial_budget=100, initial_deadline=100,
                         discount_q32=Q32, risk_aversion_q32=0, dynamic_preferences=False)
    rows = []
    for next_b in (Fraction(9, 10), Fraction(1, 10)):
        belief = 1-next_b
        obs = Observation(0, 0, 0, 1, 100, 100, belief.numerator, belief.denominator)
        ordinary = plan(retention, obs, "same-objective")
        native = plan(retention, obs, "dynamic-ndu", backend=evaluate)
        oracle = independent_oracle(retention, obs)
        # At the last step one may change the cache, so keep=11-4p, switch=6+4p.
        costs = {"cache-1": Fraction(11)-4*next_b, "cache-0": Fraction(6)+4*next_b}
        expected = min(costs, key=costs.get)
        rows.append({"next_b_probability": str(next_b), "observation": asdict(obs),
                     "hand_expected_cost": {k: str(v) for k, v in costs.items()},
                     "expected_action": expected, "ordinary": ordinary, "native": native,
                     "oracle": oracle,
                     "passed": ordinary["selected_action"] == native["selected_action"] == oracle["selected_action"] == expected})
    price_rows = []
    for lam in (Fraction(1, 20), Fraction(1, 5)):
        candidates = [{"id": name, "instant_q32": q32(quality-lam*cost), "terminal_q32": 0,
                       "discount_q32": Q32, "feasible": True, "resource_q32": q32(cost), "risk_q32": 0}
                      for name, quality, cost in (("A", Fraction(4, 5), 1), ("B", Fraction(1), 3))]
        candidates.append({"id": "abstain", "instant_q32": 0, "terminal_q32": 0,
                           "discount_q32": Q32, "feasible": True, "resource_q32": 0, "risk_q32": 0})
        fn = evaluate.evaluate if hasattr(evaluate, "evaluate") else evaluate
        result = fn(candidates, state_digest=digest({"lambda": str(lam)}), preference_digest=digest({"numeric_price": str(lam)}),
                    objective_digest=digest("hand quality minus price times cost"), resource_budget_q32=4*Q32, risk_ceiling_q32=Q32)
        expected = "B" if lam == Fraction(1, 20) else "A"
        price_rows.append({"lambda": str(lam), "candidates": candidates, "result": result,
                           "expected_action": expected, "passed": result["winners"] == [expected]})
    return {"retention": rows, "numeric_preference": price_rows,
            "all_passed": all(r["passed"] for r in rows+price_rows),
            "native_backend_supplied": backend is not None, "authority": AUTHORITY}


def degeneration_probe(backend=None):
    """Unit discount linear events have exactly the same total-cost ranking."""
    evaluate = backend if backend is not None else scalar_backend
    fn = evaluate.evaluate if hasattr(evaluate, "evaluate") else evaluate
    rows = []
    for costs in ((3, 5, 2, 1), (1, 2, 6, 2), (4, 1, 1, 3)):
        total = sum(costs)
        candidates = [{"id": "collapsed", "instant_q32": -total*Q32, "terminal_q32": 20*Q32,
                       "discount_q32": Q32, "feasible": True, "resource_q32": 0, "risk_q32": 0},
                      {"id": "four-events", "instant_q32": -costs[0]*Q32,
                       "terminal_q32": (20-sum(costs[1:]))*Q32,
                       "discount_q32": Q32, "feasible": True, "resource_q32": 0, "risk_q32": 0}]
        candidates.append({"id": "abstain", "instant_q32": 0, "terminal_q32": 0,
                           "discount_q32": Q32, "feasible": True, "resource_q32": 0, "risk_q32": 0})
        response = fn(candidates, state_digest=digest(costs), preference_digest=digest("fixed"),
                      objective_digest=digest("unit discount linear sum"), resource_budget_q32=0, risk_ceiling_q32=Q32)
        rows.append({"costs": list(costs), "expected_q32": (20-total)*Q32, "response": response,
                     "passed": response["values"] == {"collapsed": (20-total)*Q32, "four-events": (20-total)*Q32, "abstain": 0}
                               and response["winners"] == ["collapsed", "four-events"]})
    return {"rows": rows, "all_passed": all(r["passed"] for r in rows), "authority": AUTHORITY}


def plan_gated(scenario, observation, *, backend=None, compute_penalty_q32=0,
               max_transitions=20000, fixed_action=0):
    """Skip native planning when its finite-model benefit cannot cover its price.

    The incumbent is a cheap state-greedy policy. Its *whole remaining policy*
    value is evaluated on the public finite stochastic model without optimizing
    future actions. An independent optimistic bound gives every future delivery
    the cheapest possible execution cost, free loading/retirement, no scarcity
    surcharge and no downside penalty. Therefore it is at least the value of
    any feasible policy in this declared model. The bound includes each step's
    Q32 rounding, optional abstention and the root's true action feasibility.

    ``compute_penalty_q32`` is a caller-supplied frozen price for additional
    computation in objective units. It may be calibrated on training data; it
    is not a theorem about future elapsed time. A zero gross-gap certificate
    requires no such cost assumption. Gate work is charged even on a skip, and
    any invoked native work shares the original expansion allowance.
    """
    started = time.perf_counter_ns()
    validate_observation(scenario, observation)
    if type(compute_penalty_q32) is not int or compute_penalty_q32 < 0:
        raise FeedbackError("compute penalty must be a nonnegative exact Q32 integer")
    if type(max_transitions) is not int or not 1 <= max_transitions <= 1000000:
        raise FeedbackError("gate search budget bounds")
    if type(fixed_action) is not int or fixed_action not in ACTIONS:
        raise FeedbackError("registered fixed-action identity")
    incumbent = plan(scenario, observation, "state-greedy", max_transitions=max_transitions)
    charged = incumbent["search"]["transitions"]
    evaluation_started = time.perf_counter_ns()
    memo = {}
    policy_states = 0

    def charge():
        nonlocal charged
        if charged >= max_transitions:
            raise SearchBudgetExhausted("compute gate exhausted original expansion allowance", transitions=charged,
                                        statistics={"transitions": charged, "states": policy_states, "backend_calls": 0})
        charged += 1

    def evaluate_greedy(state):
        nonlocal charged, policy_states
        if state in memo:
            return memo[state]
        policy_states += 1
        remaining = scenario.horizon-state.step
        pref = preferences(scenario, state)
        choices = [("abstain", -scenario.miss_penalty_q32*remaining, 0)]
        charge()
        for action in ACTIONS:
            charge()
            cost = action_cost(scenario, state, action)["total"]
            if cost <= min(state.budget, state.deadline):
                choices.append((action_name(action), immediate(scenario, cost, pref), cost))
        name, reward, cost = min(choices, key=lambda c: (-c[1], c[0]))
        if name == "abstain" or remaining == 1:
            value = reward
        else:
            future = []
            action = action_number(name)
            for probability, request, signal, belief in forecast(scenario, state):
                child = Observation(state.step+1, request, signal, action,
                                    state.budget-cost, state.deadline-cost,
                                    belief.numerator, belief.denominator)
                future.append((probability, evaluate_greedy(child)))
            value = reward + mul_q32(pref["discount_q32"], certainty_equivalent(future, pref["risk_q32"]))
        memo[state] = value
        return value

    try:
        incumbent_value = evaluate_greedy(observation)
    except Exception as error:
        error.search_stats = {"transitions": charged, "states": policy_states, "backend_calls": 0}
        error.transitions = charged
        error.controller_wall_ns = time.perf_counter_ns()-started
        raise
    policy_evaluation_wall_ns = time.perf_counter_ns()-evaluation_started
    bound_started = time.perf_counter_ns()
    # At every deliverable state, price >= 1 and cost >= this nonnegative
    # relaxed minimum. Rounding and nonnegative discounts are monotone. The
    # conditional downside CE is <= max(child value). Applying that inequality
    # backward proves these upper bounds, including a possible stop at any step.
    minimum_cost = min(scenario.direct_cost, scenario.hot_cost+scenario.holding_cost)
    maximum_reward = scenario.completion_reward_q32-q32(Fraction(minimum_cost, scenario.cost_unit))
    remaining = scenario.horizon-observation.step
    future_upper = [0]
    for horizon in range(1, remaining):
        charge()
        future_upper.append(max(-scenario.miss_penalty_q32*horizon,
                                maximum_reward+mul_q32(scenario.discount_q32, future_upper[-1])))
    pref = preferences(scenario, observation)
    upper_by_action = {"abstain": -scenario.miss_penalty_q32*remaining}
    charge()
    for action in ACTIONS:
        charge()
        cost = action_cost(scenario, observation, action)["total"]
        if cost <= min(observation.budget, observation.deadline):
            upper_by_action[action_name(action)] = immediate(scenario, cost, pref)+mul_q32(pref["discount_q32"], future_upper[-1])
    optimal_upper = max(upper_by_action.values())
    if optimal_upper < incumbent_value:
        error = FeedbackError("optimistic computation bound contradicts incumbent policy")
        error.search_stats = {"transitions": charged, "states": policy_states, "backend_calls": 0}
        error.transitions = charged
        raise error
    gap = optimal_upper-incumbent_value
    invoke = gap > compute_penalty_q32
    gate = {"schema": "hepta.hia.ndu.compute-value-gate.v1", "invoke": invoke,
            "reason": "positive_model_gain_upper_bound" if invoke else
                      "zero_model_gain_gap" if gap == 0 else "gain_upper_bound_below_registered_compute_price",
            "incumbent": "state-greedy", "incumbent_action": incumbent["selected_action"],
            "registered_fixed_action": fixed_action,
            "incumbent_policy_value_q32": incumbent_value, "optimal_value_upper_q32": optimal_upper,
            "gross_gain_upper_q32": gap, "compute_penalty_q32": compute_penalty_q32,
            "upper_by_root_action_q32": upper_by_action,
            "relaxed_minimum_delivery_cost": minimum_cost,
            "future_upper_q32": future_upper,
            "certificate": "nonnegative-cost-state-price-at-least-one;CE-at-most-child-maximum;monotone-Q32-backward-bound",
            "policy_evaluation_states": policy_states, "search_transitions": charged,
            "incumbent_root_wall_ns": incumbent["controller_wall_ns"],
            "policy_evaluation_wall_ns": policy_evaluation_wall_ns,
            "bound_calculation_wall_ns": time.perf_counter_ns()-bound_started,
            "cost_threshold_is_observed_guarantee": False,
            "scope": "declared finite stochastic model; excludes unknown physical prediction error",
            "authority": AUTHORITY}
    gate["total_gate_wall_ns"] = time.perf_counter_ns()-started
    if invoke:
        allowance = max_transitions-charged
        if allowance < 1:
            raise SearchBudgetExhausted("no native allowance remains after charged gate", transitions=charged)
        try:
            decision = plan(scenario, observation, "dynamic-ndu", backend=backend, max_transitions=allowance)
        except Exception as error:
            stats = getattr(error, "search_stats", {"transitions": 0})
            error.search_stats = {**stats, "gate_transitions": charged,
                                  "transitions": charged+stats["transitions"]}
            error.transitions = error.search_stats["transitions"]
            error.controller_wall_ns = time.perf_counter_ns()-started
            raise
        native_transitions = decision["search"]["transitions"]
        decision["search"] = {**decision["search"], "native_search_transitions": native_transitions,
                              "gate_transitions": charged, "transitions": charged+native_transitions}
    else:
        decision = incumbent
        decision["native_backend_used"] = False
        decision["search"] = {**decision["search"], "native_search_transitions": 0,
                              "gate_transitions": charged, "transitions": charged}
        if gap == 0:
            # Equal admissible upper and incumbent lower bounds establish the
            # exact full-horizon value of this selected incumbent policy.
            decision["value_q32"] = incumbent_value
            decision["value_scope"] = "certified full-horizon incumbent and optimal value"
        else:
            decision["value_scope"] = "immediate greedy value; whole-policy value and regret bound in compute_gate"
    decision["arm"] = "dynamic-ndu-gated"
    decision["compute_gate"] = gate
    decision["controller_wall_ns"] = time.perf_counter_ns()-started
    return decision
