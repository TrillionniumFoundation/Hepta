"""All-action reachability and whole-policy values for the frozen finite model.

This is an offline audit, never a controller input. Action branches have no
probability law until a policy is specified. Only the exogenous observation
edges are probabilistic. A policy is evaluated under the environment's law and
the same external dynamic objective, including when its own forecast is wrong.
The arithmetic below is separate from the planner and its exact-action oracle.
"""
from collections import deque
from dataclasses import asdict
from fractions import Fraction

from .model import FeedbackError, Observation, Q32, digest, validate_observation


def _round(value):
    quotient, remainder = divmod(value.numerator, value.denominator)
    return quotient + int(2 * remainder > value.denominator or
                          (2 * remainder == value.denominator and quotient % 2))


def _product(left, right):
    return _round(Fraction(left * right, Q32))


def _cost(scenario, state, action):
    return ((scenario.hot_cost if action == state.request else scenario.direct_cost)
            + scenario.load_cost * int(action >= 0 and action != state.resident)
            + scenario.retire_cost * int(state.resident >= 0 and action != state.resident)
            + scenario.holding_cost * int(action >= 0))


def _events(scenario, belief):
    events = []
    for request in (0, 1):
        for signal in (0, 1):
            masses = []
            for regime in (0, 1):
                request0 = (Fraction(scenario.request_p0_z0_num, scenario.request_p0_z0_den)
                            if regime == 0 else
                            Fraction(scenario.request_p0_z1_num, scenario.request_p0_z1_den))
                correct = Fraction(scenario.signal_correct_num, scenario.signal_correct_den)
                signal0 = correct if regime == 0 else 1 - correct
                mass = belief if regime == 0 else 1 - belief
                masses.append(mass * (request0 if request == 0 else 1 - request0)
                              * (signal0 if signal == 0 else 1 - signal0))
            probability = sum(masses)
            if probability:
                events.append((probability, request, signal, masses[0] / probability))
    if sum((event[0] for event in events), Fraction(0)) != 1:
        raise FeedbackError("policy audit observation law must have unit mass")
    return events


def build_graph(scenario, max_states=10000, max_edges=100000):
    """Enumerate every legal action prefix, including terminating abstention.

    States are deduplicated by their entire public observation. Each action
    retains its own complete successor distribution; there is deliberately no
    sum of probabilities across different actions or alleged IID state count.
    Limits apply before insertion, and exhaustion returns no partial graph.
    """
    for value in (max_states, max_edges):
        if type(value) is not int or value < 1:
            raise FeedbackError("policy audit graph limits must be positive integers")
    roots, pending, seen, nodes = [], deque(), set(), {}
    edges = 0

    def remember(state):
        validate_observation(scenario, state)
        if state not in seen:
            if len(seen) >= max_states:
                raise FeedbackError("policy audit state limit exhausted")
            seen.add(state)
            pending.append(state)

    prior = Fraction(scenario.prior0_num, scenario.prior0_den)
    for probability, request, signal, belief in _events(scenario, prior):
        state = Observation(0, request, signal, scenario.initial_resident,
                            scenario.initial_budget, scenario.initial_deadline,
                            belief.numerator, belief.denominator)
        remember(state)
        roots.append((probability, state))
    while pending:
        state = pending.popleft()
        actions = {None: []}
        for action in (-1, 0, 1):
            cost = _cost(scenario, state, action)
            if cost > min(state.budget, state.deadline):
                continue
            successors = []
            if state.step + 1 < scenario.horizon:
                for probability, request, signal, belief in _events(scenario, state.belief):
                    if edges >= max_edges:
                        raise FeedbackError("policy audit edge limit exhausted")
                    child = Observation(state.step + 1, request, signal, action,
                                        state.budget - cost, state.deadline - cost,
                                        belief.numerator, belief.denominator)
                    remember(child)
                    successors.append((probability, child))
                    edges += 1
            actions[action] = successors
        nodes[state] = actions
    return {"roots": roots, "nodes": nodes, "edges": edges,
            "scenario_digest": digest(asdict(scenario))}


def _validate_graph(scenario, graph):
    """Refuse incomplete or altered transition graphs before calling a policy."""
    if type(graph) is not dict or graph.get("scenario_digest") != digest(asdict(scenario)):
        raise FeedbackError("policy audit scenario/graph binding")
    nodes, roots = graph.get("nodes"), graph.get("roots")
    if type(nodes) is not dict or not nodes or type(roots) is not list or not roots:
        raise FeedbackError("policy audit graph inventory")
    expected_roots = []
    for mass, request, signal, belief in _events(scenario, Fraction(scenario.prior0_num, scenario.prior0_den)):
        expected_roots.append((mass, Observation(0, request, signal, scenario.initial_resident,
            scenario.initial_budget, scenario.initial_deadline, belief.numerator, belief.denominator)))
    if roots != expected_roots:
        raise FeedbackError("policy audit root observation distribution")
    reachable, pending, edges = set(), deque(state for _, state in roots), 0
    while pending:
        state = pending.popleft()
        if state in reachable:
            continue
        reachable.add(state)
        validate_observation(scenario, state)
        if state not in nodes or type(nodes[state]) is not dict:
            raise FeedbackError("policy audit missing reachable state")
        expected_actions = {None}
        for action in (-1, 0, 1):
            cost = _cost(scenario, state, action)
            if cost > min(state.budget, state.deadline):
                continue
            expected_actions.add(action)
            expected = []
            if state.step + 1 < scenario.horizon:
                for mass, request, signal, belief in _events(scenario, state.belief):
                    child = Observation(state.step + 1, request, signal, action,
                        state.budget-cost, state.deadline-cost, belief.numerator, belief.denominator)
                    expected.append((mass, child))
            if nodes[state].get(action) != expected:
                raise FeedbackError("policy audit altered or omitted successor distribution")
            edges += len(expected)
            pending.extend(child for _, child in expected)
        if (set(nodes[state]) != expected_actions or nodes[state].get(None) != []
                or any(action is not None and type(action) is not int for action in nodes[state])):
            raise FeedbackError("policy audit legal action inventory")
    if reachable != set(nodes) or type(graph.get("edges")) is not int or graph["edges"] != edges:
        raise FeedbackError("policy audit graph coverage or edge accounting")
    return nodes, roots


def evaluate_policy(scenario, graph, choose):
    """Evaluate a whole policy under true transitions and one external objective.

    ``choose`` receives only a single current Observation, exactly once per
    reachable node. Every later node uses that same callback; no oracle value
    replaces a continuation. This function performs no native work itself.
    Expected deliveries and costs use ordinary probabilities. Nested utility
    applies the registered downside functional at each observed decision node.
    Before the first observation, root values use their exact probability mean,
    rounded once to Q32. That convention is shared by every compared policy.
    """
    nodes, roots = _validate_graph(scenario, graph)
    actions, values, deliveries, costs = {}, {}, {}, {}
    for state in sorted(nodes, key=lambda s: tuple(asdict(s).values()), reverse=True):
        action = choose(state)
        if ((action is not None and type(action) is not int) or action not in nodes[state]):
            raise FeedbackError("policy audit selected an illegal action")
        actions[state] = action
        remaining = scenario.horizon - state.step
        if action is None:
            values[state] = -scenario.miss_penalty_q32 * remaining
            deliveries[state] = costs[state] = Fraction(0)
            continue
        cost = _cost(scenario, state, action)
        target = max(scenario.cost_unit, remaining * scenario.direct_cost)
        scarcity = (max(Fraction(0), 1 - Fraction(min(state.budget, state.deadline), target))
                    if scenario.dynamic_preferences else Fraction(0))
        price = _round((1 + scarcity) * Q32)
        risk = min(Q32, scenario.risk_aversion_q32 + _round(scarcity * Q32 / 4))
        successors = nodes[state][action]
        mean = sum((mass * values[child] for mass, child in successors), Fraction(0))
        downside = sum((mass * max(Fraction(0), mean-values[child])
                        for mass, child in successors), Fraction(0))
        continuation = _round(mean - Fraction(risk, Q32) * downside)
        reward = scenario.completion_reward_q32 - _product(price, _round(Fraction(cost * Q32, scenario.cost_unit)))
        values[state] = reward + _product(scenario.discount_q32, continuation)
        deliveries[state] = 1 + sum((mass * deliveries[child] for mass, child in successors), Fraction(0))
        costs[state] = cost + sum((mass * costs[child] for mass, child in successors), Fraction(0))
    return {"value_q32": _round(sum((mass * values[state] for mass, state in roots), Fraction(0))),
            "state_values": values, "actions": actions,
            "expected_delivered": sum((mass * deliveries[state] for mass, state in roots), Fraction(0)),
            "expected_cost": sum((mass * costs[state] for mass, state in roots), Fraction(0))}
