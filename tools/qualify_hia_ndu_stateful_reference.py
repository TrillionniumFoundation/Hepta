"""Independent bounded subset-schedule oracle for stateful preparation models.

This implementation does not call the production prepared-set graph compiler,
finite graph builder, pruning algorithm or native evaluator. It is a numerical
reference, never a substitute NDU implementation or executable-code verifier.
"""
from __future__ import annotations

from functools import lru_cache
from itertools import combinations

Q32 = 1 << 32
MAX_ORACLE_NODES = 200_000
MAX_ORACLE_WINNERS = 4096


def _data(model):
    variants = {v["id"]: v for v in model["variants"]}
    initial = frozenset(model["initial_ready"])
    names = sorted(name for name, value in variants.items() if value["status"] == "verified")
    possible = []
    for size in range(len(names) + 1):
        for subset in combinations(names, size):
            ready = frozenset(subset)
            if initial <= ready and sum(variants[n]["resident_bytes"] for n in ready) <= model["memory_budget_bytes"]:
                possible.append(ready)
    return variants, initial, possible


def _step(model, variants, old, ready, batch):
    setup = sum(variants[n]["preparation_ns"] for n in ready - old)
    latency = min([model["baseline"]["latency_ns"][batch],
                   *(variants[n]["latency_ns"][batch] for n in ready)])
    holding = sum(variants[n]["holding_ns"][batch] for n in ready)
    # The native v1 wire rounds the nonnegative setup and delivery phases
    # separately toward zero, then subtracts the resulting exact Q32 integers.
    debit = setup * Q32 // 1_000_000 + (latency + holding) * Q32 // 1_000_000
    return setup + latency + holding, debit


def score_schedule(model, schedule):
    variants, current, possible = _data(model)
    horizon = len(model["baseline"]["latency_ns"])
    if len(schedule) != horizon:
        raise ValueError("reference schedule does not cover the complete horizon")
    total, debit = 0, 0
    for batch, names in enumerate(schedule):
        ready = frozenset(names)
        if ready not in possible or not current <= ready:
            raise ValueError("reference schedule acquires unavailable state or forgets preparation")
        cost, delta = _step(model, variants, current, ready, batch)
        total += cost
        debit += delta
        current = ready
    return {"schedule": [sorted(ready) for ready in schedule], "cost_ns": total,
            "value_q32": model["completion_value_ns"] * Q32 // 1_000_000 - debit,
            "feasible": total <= model["budget_ns"]}


def _finish(model, rows, nodes, algorithm):
    feasible = [row for row in rows if row["feasible"]]
    best = max([0, *(row["value_q32"] for row in feasible)])
    winners = [row for row in feasible if row["value_q32"] == best]
    if len(winners) > MAX_ORACLE_WINNERS:
        raise ValueError("reference winning schedules exceed the complete witness bound")
    return {"schema": "hepta.hia.ndu.stateful-reference.v1", "algorithm": algorithm,
            "best_value_q32": best, "winners": winners, "abstain_is_optimal": best == 0,
            "visited_nodes": nodes, "scope": "supplied finite deterministic model",
            "native_evaluation": False, "safety_certificate": False, "authority": "DENY_ALL"}


def exhaustive_oracle(model):
    variants, initial, possible = _data(model)
    horizon = len(model["baseline"]["latency_ns"])
    complete, visited = [], 0

    def visit(current, batch, schedule):
        nonlocal visited
        visited += 1
        if visited > MAX_ORACLE_NODES:
            raise ValueError("exhaustive oracle work bound exhausted; no partial optimum")
        if batch == horizon:
            complete.append(score_schedule(model, schedule))
            return
        for ready in possible:
            if current <= ready:
                visit(ready, batch + 1, [*schedule, ready])

    visit(initial, 0, [])
    return _finish(model, complete, visited, "independent-exhaustive-prepared-subset-sequences")


def exact_dp_control(model):
    """Independent resource-aware DP on prepared sets; no production graph calls."""
    variants, initial, possible = _data(model)
    horizon = len(model["baseline"]["latency_ns"])
    visits = 0

    @lru_cache(maxsize=None)
    def solve(current, batch, budget):
        nonlocal visits
        visits += 1
        if visits > MAX_ORACLE_NODES:
            raise ValueError("reference DP work bound exhausted; no partial optimum")
        if batch == horizon:
            return 0, ((),)
        best, paths = None, []
        for ready in possible:
            if not current <= ready:
                continue
            cost, debit = _step(model, variants, current, ready, batch)
            if cost > budget:
                continue
            continuation = solve(ready, batch + 1, budget - cost)
            if continuation is None:
                continue
            value, suffixes = continuation
            total = debit + value
            if best is None or total < best:
                best, paths = total, []
            if total == best:
                paths.extend((tuple(sorted(ready)), *suffix) for suffix in suffixes)
                if len(paths) > MAX_ORACLE_WINNERS:
                    raise ValueError("reference DP complete value ties exceed witness bound")
        return None if best is None else (best, tuple(paths))

    answer = solve(initial, 0, model["budget_ns"])
    rows = [] if answer is None else [score_schedule(model, path) for path in answer[1]]
    return _finish(model, rows, visits, "independent-exact-resource-dp")


def fixed_configuration_control(model):
    """Best complete fixed resident set, including every combined specialization."""
    _, _, possible = _data(model)
    horizon = len(model["baseline"]["latency_ns"])
    rows = [score_schedule(model, [ready] * horizon) for ready in possible]
    return _finish(model, rows, len(rows), "strong-fixed-configuration-with-combined-variants")


def greedy_control(model):
    """Same-information one-step controller; planned failure remains an outcome."""
    variants, current, possible = _data(model)
    schedule = []
    for batch in range(len(model["baseline"]["latency_ns"])):
        options = [(ready, _step(model, variants, current, ready, batch)) for ready in possible if current <= ready]
        ready, _ = min(options, key=lambda row: (row[1][1], tuple(sorted(row[0]))))
        schedule.append(ready)
        current = ready
    row = score_schedule(model, schedule)
    result = _finish(model, [row], len(schedule), "same-information-one-step-greedy")
    result["attempted_schedule"] = row
    return result
