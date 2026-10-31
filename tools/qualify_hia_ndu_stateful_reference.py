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


def _step(model, variants, old, ready, batch, *, active_decision=True):
    setup = sum(variants[n]["preparation_ns"] for n in ready - old)
    decision = model.get("future_decision_cost_ns", 0) if batch and active_decision else 0
    latency = min([model["baseline"]["latency_ns"][batch],
                   *(variants[n]["latency_ns"][batch] for n in ready)])
    holding = sum(variants[n]["holding_ns"][batch] for n in ready)
    # The native v1 wire rounds the nonnegative setup and delivery phases
    # separately toward zero, then subtracts the resulting exact Q32 integers.
    debit = (setup + decision) * Q32 // 1_000_000 + (latency + holding) * Q32 // 1_000_000
    return setup + decision + latency + holding, debit


def score_schedule(model, schedule):
    variants, current, possible = _data(model)
    horizon = len(model["baseline"]["latency_ns"])
    if len(schedule) != horizon:
        raise ValueError("reference schedule does not cover the complete horizon")
    # A prepared-set schedule uses the cheapest compatible stop placement.
    # A transition at batch j requires the next decision at j+1 to stop, unless
    # j was the final batch. A constant incumbent schedule stops at batch zero.
    previous = current
    last_change = -1
    for batch, names in enumerate(schedule):
        ready = frozenset(names)
        if ready != previous:
            last_change = batch
        previous = ready
    stop_batch = min(last_change + 1, horizon - 1)
    total, debit = 0, 0
    for batch, names in enumerate(schedule):
        ready = frozenset(names)
        if ready not in possible or not current <= ready:
            raise ValueError("reference schedule acquires unavailable state or forgets preparation")
        cost, delta = _step(model, variants, current, ready, batch,
                            active_decision=batch <= stop_batch)
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
    if model.get("future_decision_cost_ns", 0):
        return _costed_dp_control(model)
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


def _costed_dp_control(model):
    """Independently account for active decisions and an absorbing stop state.

    Zero-cost v1 uses the historical implementation above unchanged. This
    recurrence chooses either delivery of the complete remaining constant set,
    with one current stop decision, or one active step followed by a new
    subproblem. It does not import the production graph or pruning functions.
    """
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
        tail = [_step(model, variants, current, current, i,
                      active_decision=i == batch) for i in range(batch, horizon)]
        cost, debit = sum(x[0] for x in tail), sum(x[1] for x in tail)
        best = debit if cost <= budget else None
        paths = {tuple(tuple(sorted(current)) for _ in range(batch, horizon))} if best is not None else set()
        for ready in possible:
            if not current <= ready or (ready == current and batch + 1 == horizon):
                continue
            cost, debit = _step(model, variants, current, ready, batch)
            if cost > budget:
                continue
            suffix = solve(ready, batch + 1, budget - cost)
            if suffix is None:
                continue
            total = debit + suffix[0]
            if best is None or total < best:
                best, paths = total, set()
            if total == best:
                paths.update((tuple(sorted(ready)), *rest) for rest in suffix[1])
                if len(paths) > MAX_ORACLE_WINNERS:
                    raise ValueError("reference DP complete value ties exceed witness bound")
        return None if best is None else (best, tuple(sorted(paths)))

    answer = solve(initial, 0, model["budget_ns"])
    rows = [] if answer is None else [score_schedule(model, path) for path in answer[1]]
    return _finish(model, rows, visits, "independent-exact-resource-dp-with-stop-cost")


def fixed_configuration_control(model):
    """Best complete fixed set; precommitment needs no future controller call."""
    _, _, possible = _data(model)
    horizon = len(model["baseline"]["latency_ns"])
    fixed_model = ({**model, "future_decision_cost_ns": 0}
                   if model.get("future_decision_cost_ns", 0) else model)
    rows = [score_schedule(fixed_model, [ready] * horizon) for ready in possible]
    result = _finish(model, rows, len(rows), "strong-fixed-configuration-with-combined-variants")
    if "future_decision_cost_ns" in model:
        result["future_controller_calls"] = 0
        result["future_cost_policy"] = "complete fixed resident set is committed in the current call"
    return result


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
