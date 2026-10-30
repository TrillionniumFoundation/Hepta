"""Bounded, same-objective planning for independently verified HIA regions.

This is a compiler search and an explicit exact-DP control.  It is not a learned
NDU policy, a proof checker, or an admission authority.  The optional native
request uses the existing original Rust recursive-utility protocol unchanged.

A region selects one artifact. Artifacts have one-time activation costs and
retained-byte costs shared by every region using them. Per-region run costs are
estimates bound to a calibration snapshot, never future measurements. Initial
artifacts remain retained but their past activation cost is not charged twice.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from itertools import product
from fractions import Fraction
import json
import re
from typing import Any

Q32 = 1 << 32
SCHEMA = "hepta.hia.portfolio.problem.v1"
MAX_WORK = 200_000
MAX_STATES = 16_384
MAX_WITNESSES = 127
_ID = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,47}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")


class PortfolioRejected(ValueError):
    """Invalid or over-bound search: no incomplete optimum is published."""


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode()


def digest(value: Any) -> str:
    return sha256(canonical(value)).hexdigest()


def _integer(value, label, maximum=1_000_000_000_000):
    if type(value) is not int or not 0 <= value <= maximum:
        raise PortfolioRejected(f"{label}: integer in 0..{maximum} required")
    return value


def _identifier(value, label):
    if type(value) is not str or not _ID.fullmatch(value):
        raise PortfolioRejected(f"{label}: bounded identifier required")
    return value


def _hash(value, label):
    if type(value) is not str or not _HASH.fullmatch(value) or value == "0" * 64:
        raise PortfolioRejected(f"{label}: nonzero lowercase SHA-256 required")


def _keys(value, expected, label):
    if type(value) is not dict or set(value) != set(expected):
        raise PortfolioRejected(f"{label}: expected exactly {sorted(expected)}")


def validate_problem(problem):
    """Validate structure and resource accounting, not external proof claims."""
    _keys(problem, {"schema", "objective_sha256", "snapshot_sha256", "generation",
                    "artifacts", "regions", "initial_artifacts", "budget_ns",
                    "retained_bytes_limit", "scratch_bytes_limit", "completion_value_ns"}, "problem")
    if problem["schema"] != SCHEMA:
        raise PortfolioRejected("unknown portfolio schema")
    for name in ("objective_sha256", "snapshot_sha256"):
        _hash(problem[name], name)
    if type(problem["generation"]) is not int or not 1 <= problem["generation"] <= (1 << 63) - 1:
        raise PortfolioRejected("generation: positive exact integer required")
    for name in ("budget_ns", "retained_bytes_limit", "scratch_bytes_limit", "completion_value_ns"):
        _integer(problem[name], name)
    artifacts = problem["artifacts"]
    if type(artifacts) is not dict or not 1 <= len(artifacts) <= 16:
        raise PortfolioRejected("require 1..16 artifacts")
    for name, artifact in artifacts.items():
        _identifier(name, "artifact id")
        _keys(artifact, {"activation_ns", "retained_bytes", "verification_sha256",
                         "source_sha256", "status"}, name)
        for field in ("activation_ns", "retained_bytes"):
            _integer(artifact[field], name + "." + field)
        for field in ("verification_sha256", "source_sha256"):
            _hash(artifact[field], name + "." + field)
        if type(artifact["status"]) is not str or artifact["status"] not in {"verified", "rejected", "timeout", "unavailable"}:
            raise PortfolioRejected("unknown artifact verification status")
    initial = problem["initial_artifacts"]
    if (type(initial) is not list or any(type(x) is not str for x in initial)
            or len(set(initial)) != len(initial) or not set(initial) <= set(artifacts)):
        raise PortfolioRejected("initial artifacts must be unique known identifiers")
    if any(artifacts[name]["status"] != "verified" for name in initial):
        raise PortfolioRejected("initial artifacts must have upstream verification")
    if sum(artifacts[x]["retained_bytes"] for x in initial) > problem["retained_bytes_limit"]:
        raise PortfolioRejected("initial retained bytes already exceed the ceiling")
    regions = problem["regions"]
    if type(regions) is not list or not 1 <= len(regions) <= 32:
        raise PortfolioRejected("require 1..32 regions")
    seen = set()
    for region in regions:
        _keys(region, {"id", "options"}, "region")
        name = _identifier(region["id"], "region id")
        if name in seen:
            raise PortfolioRejected("duplicate region id")
        seen.add(name)
        options = region["options"]
        if type(options) is not list or not 1 <= len(options) <= 16:
            raise PortfolioRejected("require 1..16 options per region")
        selected = set()
        for option in options:
            _keys(option, {"artifact", "run_ns", "scratch_bytes", "support_sha256"}, "option")
            artifact = option["artifact"]
            if type(artifact) is not str or artifact not in artifacts or artifact in selected:
                raise PortfolioRejected("region options must name distinct known artifacts")
            selected.add(artifact)
            for field in ("run_ns", "scratch_bytes"):
                _integer(option[field], name + "." + field)
            _hash(option["support_sha256"], name + ".support_sha256")
    if len(canonical(problem)) > 1_048_576:
        raise PortfolioRejected("portfolio input exceeds 1 MiB")
    return problem


def _debit(ns):
    # One event per acquisition and per region, exactly as the native request.
    return ns * Q32 // 1_000_000


@dataclass(frozen=True)
class _Label:
    cost: int
    debit: int
    count: int
    paths: tuple[tuple[str, ...], ...]


def _prune(rows, *, witness_limit):
    merged = {}
    for row in rows:
        key = row.cost, row.debit
        previous = merged.get(key)
        paths = row.paths if previous is None else previous.paths + row.paths
        count = row.count if previous is None else previous.count + row.count
        # Count every tied prefix while bounding its stored witnesses. A large
        # dominated label can later disappear without causing false exhaustion;
        # a required winning tie never becomes an invented unique candidate.
        merged[key] = _Label(row.cost, row.debit, count, paths[:witness_limit + 1])
    kept, best_debit = [], None
    for row in sorted(merged.values(), key=lambda r: (r.cost, r.debit)):
        # Strict improvement preserves every equal-utility native frontier tie.
        if best_debit is not None and best_debit < row.debit:
            continue
        kept.append(row)
        best_debit = row.debit if best_debit is None else min(best_debit, row.debit)
    return kept


def _plan(problem, choices, *, known_cost=None, known_debit=None):
    used = set(problem["initial_artifacts"])
    events, peak_scratch = [], 0
    for region, choice in zip(problem["regions"], choices, strict=True):
        option = next(x for x in region["options"] if x["artifact"] == choice)
        if choice not in used:
            used.add(choice)
            events.append({"kind": "activation", "id": choice,
                           "cost_ns": problem["artifacts"][choice]["activation_ns"]})
        events.append({"kind": "run", "id": region["id"], "artifact": choice,
                       "cost_ns": option["run_ns"]})
        peak_scratch = max(peak_scratch, option["scratch_bytes"])
    total = sum(event["cost_ns"] for event in events)
    debit = sum(_debit(event["cost_ns"]) for event in events)
    if known_cost is not None and (total != known_cost or debit != known_debit):
        raise PortfolioRejected("internal label/path disagreement")
    result = {"choices": list(choices), "events": events, "cost_ns": total,
              "debit_q32": debit, "value_q32": _debit(problem["completion_value_ns"]) - debit,
              "retained_bytes": sum(problem["artifacts"][x]["retained_bytes"] for x in used),
              "peak_scratch_bytes": peak_scratch, "used_artifacts": sorted(used)}
    result["id"] = "p" + digest({"snapshot": digest(problem), "choices": choices})[:40]
    return result


def _result(problem, plans, *, algorithm, work, complete=True):
    values = {"abstain": 0, **{p["id"]: p["value_q32"] for p in plans}}
    maximum = max(values.values())
    frontier = sorted(k for k, value in values.items() if value == maximum)
    return {"schema": "hepta.hia.portfolio.result.v1", "problem_sha256": digest(problem),
            "algorithm": algorithm, "plans": sorted(plans, key=lambda p: p["id"]),
            "values_q32": values, "pareto_candidate_ids": frontier,
            "advisory_candidate_id": frontier[0] if len(frontier) == 1 else None,
            "complete_within_declared_model": complete, "work": work,
            "learned_policy": False, "global_program_optimality": False,
            "authority": "DENY_ALL", "safety_certificate": False}


def exact_portfolio(problem, *, max_work=MAX_WORK, max_states=MAX_STATES,
                    max_witnesses=MAX_WITNESSES):
    """Retain every best feasible complete path for each first artifact.

    The state includes the complete paid/retained artifact set, so sharing an
    acquisition across regions is not mistaken for an independent additive cost.
    Cost and event-rounded Q32 value are separate labels; capacity/time ceilings
    and ties are preserved. Bound exhaustion rejects instead of returning a
    partial graph as an exact optimum.
    """
    validate_problem(problem)
    for value, name, ceiling in ((max_work, "max_work", MAX_WORK),
                                 (max_states, "max_states", MAX_STATES),
                                 (max_witnesses, "max_witnesses", MAX_WITNESSES)):
        if type(value) is not int or not 1 <= value <= ceiling:
            raise PortfolioRejected(f"{name} outside supported bound")
    names = sorted(problem["artifacts"])
    bits = {name: 1 << i for i, name in enumerate(names)}
    initial = sum(bits[x] for x in problem["initial_artifacts"])
    retained_cache = {}

    def retained(mask):
        if mask not in retained_cache:
            retained_cache[mask] = sum(problem["artifacts"][x]["retained_bytes"] for x in names if mask & bits[x])
        return retained_cache[mask]

    states = {(initial, None): [_Label(0, 0, 1, ((),))]}
    work = {"generated_labels": 0, "peak_states": 1, "regions_completed": 0,
            "verification_exclusions": 0, "capacity_exclusions": 0, "budget_exclusions": 0}
    for region in problem["regions"]:
        following = {}
        for (mask, first), labels in states.items():
            for option in region["options"]:
                name = option["artifact"]
                artifact = problem["artifacts"][name]
                if artifact["status"] != "verified":
                    work["verification_exclusions"] += 1
                    continue
                new_mask = mask | bits[name]
                if retained(new_mask) > problem["retained_bytes_limit"] or option["scratch_bytes"] > problem["scratch_bytes_limit"]:
                    work["capacity_exclusions"] += 1
                    continue
                setup = 0 if mask & bits[name] else artifact["activation_ns"]
                for row in labels:
                    work["generated_labels"] += 1
                    if work["generated_labels"] > max_work:
                        raise PortfolioRejected("portfolio work budget exhausted; no partial optimum")
                    cost = row.cost + setup + option["run_ns"]
                    if cost > problem["budget_ns"]:
                        work["budget_exclusions"] += 1
                        continue
                    next_row = _Label(cost, row.debit + _debit(setup) + _debit(option["run_ns"]), row.count,
                                      tuple(path + (name,) for path in row.paths))
                    following.setdefault((new_mask, name if first is None else first), []).append(next_row)
        if len(following) > max_states:
            raise PortfolioRejected("portfolio state budget exhausted; no partial optimum")
        states = {key: _prune(rows, witness_limit=max_witnesses) for key, rows in following.items()}
        work["peak_states"] = max(work["peak_states"], len(states))
        work["regions_completed"] += 1
    by_first = {}
    for (_, first), rows in states.items():
        by_first.setdefault(first, []).extend(rows)
    plans = []
    for first, rows in sorted(by_first.items()):
        best = min(row.debit for row in rows)
        for row in rows:
            if row.debit == best:
                if len(plans) + row.count > max_witnesses or len(row.paths) != row.count:
                    raise PortfolioRejected("complete best-per-first frontier exceeds native slots")
                plans.extend(_plan(problem, path, known_cost=row.cost, known_debit=row.debit) for path in row.paths)
    return _result(problem, plans, algorithm="exact-resource-label-dp", work=work)


def exhaustive_portfolio_oracle(problem, *, max_combinations=200_000):
    """Independent small Cartesian oracle; does not call the DP recurrence."""
    validate_problem(problem)
    if type(max_combinations) is not int or not 1 <= max_combinations <= MAX_WORK:
        raise PortfolioRejected("oracle bound outside supported range")
    count = 1
    for region in problem["regions"]:
        count *= len(region["options"])
    if count > max_combinations:
        raise PortfolioRejected("independent exhaustive oracle bound exceeded")
    by_first = {}
    for options in product(*(r["options"] for r in problem["regions"])):
        used = set(problem["initial_artifacts"]) | {o["artifact"] for o in options}
        if any(problem["artifacts"][x]["status"] != "verified" for x in used):
            continue
        if sum(problem["artifacts"][x]["retained_bytes"] for x in used) > problem["retained_bytes_limit"]:
            continue
        if max(o["scratch_bytes"] for o in options) > problem["scratch_bytes_limit"]:
            continue
        new_artifacts = used - set(problem["initial_artifacts"])
        cost = sum(problem["artifacts"][x]["activation_ns"] for x in new_artifacts) + sum(o["run_ns"] for o in options)
        if cost > problem["budget_ns"]:
            continue
        # Independent direct complete-choice summation, not prefix label reuse.
        debit = sum(problem["artifacts"][x]["activation_ns"] * (1 << 32) // 1_000_000 for x in new_artifacts)
        debit += sum(o["run_ns"] * (1 << 32) // 1_000_000 for o in options)
        first = options[0]["artifact"]
        row = (debit, tuple(o["artifact"] for o in options), cost)
        if first not in by_first or debit < by_first[first][0][0]:
            by_first[first] = [row]
        elif debit == by_first[first][0][0]:
            by_first[first].append(row)
    plans = [_plan(problem, choices, known_cost=cost, known_debit=debit)
             for rows in by_first.values() for debit, choices, cost in rows]
    if len(plans) > MAX_WITNESSES:
        raise PortfolioRejected("complete oracle frontier exceeds native slots")
    return _result(problem, plans, algorithm="independent-cartesian-oracle",
                   work={"complete_combinations": count})


def lightweight_portfolio(problem):
    """Strong cheap control: amortized greedy plus all feasible single-artifact plans.

    Ties use the lexicographic choice tuple, explicitly a control policy rather
    than a change to the native unresolved-frontier contract.
    """
    validate_problem(problem)
    choices, used = [], set(problem["initial_artifacts"])
    for i, region in enumerate(problem["regions"]):
        ranked = []
        for option in region["options"]:
            name = option["artifact"]
            if problem["artifacts"][name]["status"] != "verified" or option["scratch_bytes"] > problem["scratch_bytes_limit"]:
                continue
            if sum(problem["artifacts"][x]["retained_bytes"] for x in used | {name}) > problem["retained_bytes_limit"]:
                continue
            uses = sum(any(o["artifact"] == name for o in r["options"]) for r in problem["regions"][i:])
            setup = 0 if name in used else problem["artifacts"][name]["activation_ns"]
            ranked.append((Fraction(option["run_ns"] * uses + setup, uses), name))
        if not ranked:
            choices = []
            break
        _, name = min(ranked)
        choices.append(name)
        used.add(name)
    possible = [tuple(choices)] if choices else []
    for name, artifact in problem["artifacts"].items():
        if artifact["status"] == "verified" and all(any(o["artifact"] == name for o in r["options"]) for r in problem["regions"]):
            possible.append(tuple(name for _ in problem["regions"]))
    plans = []
    for path in set(possible):
        plan = _plan(problem, path)
        if (plan["cost_ns"] <= problem["budget_ns"] and plan["retained_bytes"] <= problem["retained_bytes_limit"]
                and plan["peak_scratch_bytes"] <= problem["scratch_bytes_limit"]):
            plans.append(plan)
    return _result(problem, plans, algorithm="amortized-greedy-plus-every-single-artifact",
                   work={"evaluated_complete_plans": len(possible)}, complete=False)


def evaluate_portfolio_choices(problem, choices):
    """Check one fixed control's complete choices under exactly the same model."""
    validate_problem(problem)
    if (type(choices) not in {list, tuple} or len(choices) != len(problem["regions"])
            or any(type(name) is not str for name in choices)):
        raise PortfolioRejected("one artifact choice per region required")
    for region, name in zip(problem["regions"], choices, strict=True):
        if (name not in {o["artifact"] for o in region["options"]}
                or problem["artifacts"][name]["status"] != "verified"):
            raise PortfolioRejected("fixed plan uses an unavailable option")
    plan = _plan(problem, tuple(choices))
    if (plan["cost_ns"] > problem["budget_ns"]
            or plan["retained_bytes"] > problem["retained_bytes_limit"]
            or plan["peak_scratch_bytes"] > problem["scratch_bytes_limit"]):
        raise PortfolioRejected("fixed plan violates a resource ceiling")
    return _result(problem, [plan], algorithm="registered-fixed-choice", work={"evaluated_complete_plans": 1}, complete=False)


def native_portfolio_request(problem, result):
    """Encode retained genuine paths for the existing original Rust evaluator.

    Independent caller verification is still required. This function does not
    sign or authenticate a proof, measured timing, resource bound or build.
    """
    validate_problem(problem)
    if (result.get("problem_sha256") != digest(problem)
            or result.get("algorithm") != "exact-resource-label-dp"
            or result.get("complete_within_declared_model") is not True):
        raise PortfolioRejected("native request needs the matching complete DP search result")
    if not 0 <= len(result["plans"]) <= MAX_WITNESSES:
        raise PortfolioRejected("native candidate count exhausted")
    candidates = []
    support = digest({"problem": problem, "search": result})
    for plan in result["plans"]:
        rebuilt = _plan(problem, tuple(plan["choices"]))
        if rebuilt != plan:
            raise PortfolioRejected("candidate path/label drift")
        used = plan["used_artifacts"]
        if (any(problem["artifacts"][x]["status"] != "verified" for x in used)
                or plan["cost_ns"] > problem["budget_ns"]
                or plan["retained_bytes"] > problem["retained_bytes_limit"]
                or plan["peak_scratch_bytes"] > problem["scratch_bytes_limit"]):
            raise PortfolioRejected("candidate is no longer feasible")
        candidates.append({"id": plan["id"], "verified": True,
            "verification_digest": digest({x: problem["artifacts"][x]["verification_sha256"] for x in used}),
            "support_digest": support, "resource_cost_q32": plan["cost_ns"] * Q32 // 1000,
            "risk_q32": 0, "uncertainty_q32": 0,
            "terminal_q32": _debit(problem["completion_value_ns"]),
            "events": [{"event_digest": digest({"snapshot": digest(problem), "plan": plan["id"], "index": i}),
                        "preference_digest": problem["objective_sha256"],
                        "instant_q32": -_debit(event["cost_ns"]), "discount_q32": Q32}
                       for i, event in enumerate(plan["events"])]})
    candidates.append({"id": "abstain", "verified": True,
        "verification_digest": digest("literal-no-effect"), "support_digest": support,
        "resource_cost_q32": 0, "risk_q32": 0, "uncertainty_q32": 0, "terminal_q32": 0,
        "events": [{"event_digest": digest({"snapshot": digest(problem), "event": "abstain"}),
                    "preference_digest": problem["objective_sha256"], "instant_q32": 0, "discount_q32": Q32}]})
    request = {"schema": "hepta.hia.ndu.request.v1", "objective_digest": problem["objective_sha256"],
        "snapshot_digest": problem["snapshot_sha256"], "generation": problem["generation"],
        "utility_unit": "completion-minus-wall-milliseconds", "resource_unit": "microseconds",
        "risk_unit": "probability", "risk_ceiling_q32": Q32,
        "resource_budget_q32": problem["budget_ns"] * Q32 // 1000, "candidates": candidates}
    if len(canonical(request)) > 1_048_576:
        raise PortfolioRejected("native request exceeds 1 MiB")
    return request


def selected_plan(result, response=None):
    """Resolve only a unique, available recommendation; ties remain unresolved."""
    advice = result if response is None else response
    identity = advice.get("advisory_candidate_id")
    if identity is None or identity == "abstain":
        return None
    choices = [p for p in result["plans"] if p["id"] == identity]
    if len(choices) != 1:
        raise PortfolioRejected("advice is not a unique retained candidate")
    return choices[0]
