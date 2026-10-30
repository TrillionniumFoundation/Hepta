"""Exact candidate compression for the disclosed finite-graph NDU profile.

This is a bounded compiler search, not a replacement native NDU evaluator. It
uses precisely the existing graph's information and integer wire conversion.
The native process still evaluates genuine retained paths. No learned-FBSDE,
unrestricted optimality, execution safety or measured speedup is implied.
"""
from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from .hia_ndu import NduBridgeError, Q32, finite_plan_request

MAX_FRONTIER_LABELS = 4096
MAX_GENERATED_LABELS = 65536


def compact_finite_plan_request(**fields: Any) -> dict[str, Any]:
    """Build a native request without enumerating strictly inferior paths.

    The v1 profile has unit discounts, one common terminal value, zero risk,
    nonnegative additive costs and a single total-cost ceiling. Each first
    action keeps *all* its best feasible paths. Equal utility is never broken by
    source ID, path length or lower resource cost. Too many tied witnesses fails
    closed instead of changing native NDU's unresolved-frontier behavior.
    """
    if "search" in fields:
        raise NduBridgeError("compact finite graph selects its own search profile")
    return finite_plan_request(**fields, search="dynamic-frontier")


def exact_finite_plan(**fields: Any) -> dict[str, Any]:
    """Same-information Q32 control without native transport or event encoding.

    It retains the original validator, the same bounded DP and all value ties.
    Its advice is explicitly Python arithmetic, not a native NDU receipt.
    """
    if "search" in fields:
        raise NduBridgeError("exact finite graph selects its own search profile")
    return finite_plan_request(**fields, search="dynamic-light")


def _exact_plan_advice(plans: dict[str, dict[str, Any]], completion_ns: int) -> dict[str, Any]:
    terminal = completion_ns * Q32 // 1_000_000
    values = {"abstain": 0}
    for identity, plan in plans.items():
        debit = sum((a["setup_ns"] + a["decision_ns"]) * Q32 // 1_000_000
                    + a["execution_ns"] * Q32 // 1_000_000 for a in plan["actions"])
        values[identity] = terminal - debit
    maximum = max(values.values())
    frontier = sorted(identity for identity, value in values.items() if value == maximum)
    disposition = ("InfeasibleExplicitAbstain" if not plans else
                   "UniqueParetoRecommendation" if len(frontier) == 1 else "ParetoSetRequiresSlowPath")
    return {"schema": "hepta.hia.ndu.exact-profile-advice.v1",
            "computed_by": "python-exact-q32-profile-control", "native_evaluation": False,
            "advisory_candidate_id": frontier[0] if len(frontier) == 1 else None,
            "pareto_candidate_ids": frontier, "disposition": disposition, "values_q32": values,
            "authority": "DENY_ALL", "safety_certificate": False}


@dataclass(frozen=True)
class _Label:
    cost_ns: int
    debit_q32: int
    count: int
    paths: tuple[tuple[dict[str, Any], ...], ...]


def _compact_finite_actions(graph: dict[str, Any], budget_ns: int, *,
                            max_paths: int) -> tuple[list[list[dict[str, Any]]], dict[str, Any]]:
    """Input validation belongs to finite_plan_request; no public raw intake.

    A suffix label is (total resource nanoseconds, sum of per-event Q32 debits).
    A strictly smaller debit with no greater resource cost dominates a label
    under *every* shared prefix. Equal debit is retained, even at greater cost:
    if both fit the eventual budget native NDU must retain their value tie.
    The witness cap limits stored paths, not multiplicities or completeness.
    If a needed multiplicity exceeds that cap, no request is emitted.
    """
    states = graph["states"]
    costs = graph["batch_costs_ns"]
    horizon = graph["horizon"]
    decision = graph["future_decision_cost_ns"]
    initial = graph["initial_state"]
    outgoing = {state: [edge for edge in graph["transitions"] if edge["source"] == state]
                for state in states}
    witness_limit = max_paths + 1
    counters = {"generated_labels": 0, "dominated_labels": 0,
                "over_budget_labels": 0, "memoized_subproblems": 0,
                "largest_frontier": 0}

    def stop(state: str, batch: int) -> tuple[dict[str, Any], ...]:
        return tuple({"id": "stop", "mode": "stop" if i == batch else "stopped",
                      "source": state, "target": state, "batch": i,
                      "setup_ns": 0, "decision_ns": decision if i == batch and i else 0,
                      "execution_ns": costs[state][i], "status": "verified",
                      "verification_sha256": states[state]["verification_sha256"]}
                     for i in range(batch, horizon))

    def edges(state: str, batch: int) -> list[dict[str, Any]]:
        result = list(outgoing[state])
        if batch + 1 < horizon:
            result.append({"id": "hold", "source": state, "target": state,
                           "setup_ns": 0, "status": "verified",
                           "verification_sha256": states[state]["verification_sha256"]})
        return result

    def action(edge: dict[str, Any], batch: int) -> dict[str, Any]:
        return {"id": edge["id"], "mode": "hold" if edge["id"] == "hold" else "transition",
                "source": edge["source"], "target": edge["target"], "batch": batch,
                "setup_ns": edge["setup_ns"], "decision_ns": decision if batch else 0,
                "execution_ns": costs[edge["target"]][batch], "status": edge["status"],
                "verification_sha256": edge["verification_sha256"]}

    def label(path: tuple[dict[str, Any], ...]) -> _Label:
        total = sum(a["setup_ns"] + a["decision_ns"] + a["execution_ns"] for a in path)
        # Native events round setup+decision and execution separately. Summing
        # nanoseconds first would erase the profile's real quantization ties.
        debit = sum((a["setup_ns"] + a["decision_ns"]) * Q32 // 1_000_000
                    + a["execution_ns"] * Q32 // 1_000_000 for a in path)
        return _Label(total, debit, 1, (path,))

    def key(path: tuple[dict[str, Any], ...]) -> tuple[tuple[Any, ...], ...]:
        return tuple((a["batch"], a["id"], a["mode"], a["source"], a["target"]) for a in path)

    def witnesses(paths: Any) -> tuple[tuple[dict[str, Any], ...], ...]:
        # Ordering is solely deterministic storage; all required ties are sent.
        return tuple(sorted(paths, key=key)[:witness_limit])

    def frontier(rows: list[_Label]) -> tuple[_Label, ...]:
        merged: dict[tuple[int, int], _Label] = {}
        for row in rows:
            counters["generated_labels"] += 1
            if counters["generated_labels"] > MAX_GENERATED_LABELS:
                raise NduBridgeError("finite graph: dynamic label work budget exhausted; no partial plan")
            if row.cost_ns > budget_ns:
                counters["over_budget_labels"] += 1
                continue
            identity = (row.cost_ns, row.debit_q32)
            previous = merged.get(identity)
            merged[identity] = row if previous is None else _Label(
                row.cost_ns, row.debit_q32, previous.count + row.count,
                witnesses((*previous.paths, *row.paths)))
        kept = []
        best_debit = None
        for row in sorted(merged.values(), key=lambda r: (r.cost_ns, r.debit_q32)):
            if best_debit is not None and best_debit < row.debit_q32:
                counters["dominated_labels"] += 1
                continue
            kept.append(row)
            best_debit = row.debit_q32 if best_debit is None else min(best_debit, row.debit_q32)
        if len(kept) > MAX_FRONTIER_LABELS:
            raise NduBridgeError("finite graph: dynamic frontier bound exhausted; no partial plan")
        counters["largest_frontier"] = max(counters["largest_frontier"], len(kept))
        return tuple(kept)

    def prepend(head: dict[str, Any], suffix: _Label) -> _Label:
        prefix = label((head,))
        return _Label(prefix.cost_ns + suffix.cost_ns, prefix.debit_q32 + suffix.debit_q32,
                      suffix.count, tuple((head, *path) for path in suffix.paths))

    @lru_cache(maxsize=None)
    def best(state: str, batch: int) -> tuple[_Label, ...]:
        if batch == horizon:
            return (_Label(0, 0, 1, ((),)),)
        counters["memoized_subproblems"] += 1
        rows = [label(stop(state, batch))]
        for edge in edges(state, batch):
            if edge["status"] == "verified" and states[edge["target"]]["status"] == "verified":
                rows.extend(prepend(action(edge, batch), suffix)
                            for suffix in best(edge["target"], batch + 1))
        return frontier(rows)

    @lru_cache(maxsize=None)
    def verification_counts(state: str, batch: int) -> tuple[tuple[tuple[str, ...], int], ...]:
        if batch == horizon:
            return (((), 1),)
        bad_stop = () if states[state]["status"] == "verified" else (states[state]["status"],)
        counts = {bad_stop: 1}
        for edge in edges(state, batch):
            bad = {status for status in (edge["status"], states[edge["target"]]["status"])
                   if status != "verified"}
            for suffix, count in verification_counts(edge["target"], batch + 1):
                combined = tuple(sorted(bad | set(suffix)))
                counts[combined] = counts.get(combined, 0) + count
        return tuple(sorted(counts.items()))

    groups: list[tuple[str, tuple[_Label, ...]]] = [("stop", frontier([label(stop(initial, 0))]))]
    for edge in edges(initial, 0):
        if edge["status"] == "verified" and states[edge["target"]]["status"] == "verified":
            rows = [prepend(action(edge, 0), suffix) for suffix in best(edge["target"], 1)]
            groups.append((edge["id"], frontier(rows)))

    selected: list[list[dict[str, Any]]] = []
    summaries = []
    required = 0
    for first_action, rows in groups:
        if not rows:
            summaries.append({"first_action": first_action, "status": "no-budget-feasible-path",
                              "retained_path_count": 0})
            continue
        minimum = min(row.debit_q32 for row in rows)
        winners = [row for row in rows if row.debit_q32 == minimum]
        count = sum(row.count for row in winners)
        required += count
        summaries.append({"first_action": first_action, "status": "best-feasible-paths",
                          "retained_path_count": count, "debit_q32": minimum,
                          "resource_costs_ns": [row.cost_ns for row in winners]})
        if required <= max_paths:
            for row in winners:
                if len(row.paths) != row.count:
                    raise NduBridgeError("finite graph: complete tied witnesses exceed native candidate budget")
                selected.extend(list(path) for path in row.paths)
    if required > max_paths:
        raise NduBridgeError(
            f"finite graph: complete tied witnesses need {required} native slots, budget is {max_paths}; no partial plan")

    verdicts = verification_counts(initial, 0)
    total = sum(count for _, count in verdicts)
    verified = sum(count for status, count in verdicts if not status)
    evidence = {"schema": "hepta.hia.ndu.finite-graph-compression.v1",
                "algorithm": "exact-q32-resource-labels-all-best-paths-per-first-action",
                "scope": "finite-graph.v1-unit-discount-common-terminal-zero-risk",
                "covered_path_count": total, "verified_path_count": verified,
                "excluded_verification_path_counts": [
                    {"statuses": list(status), "count": count}
                    for status, count in verdicts if status],
                "retained_path_count": required, "first_actions": summaries,
                "complete_native_winning_frontier_preserved": True,
                "native_rejected_list_preserved": False,
                "rejected_path_policy": "excluded with exact status counts; no fabricated native rejection receipt",
                "candidate_values_computed_by": "profile-specific compiler pruning; no native receipt produced here",
                "search_complete": True, "enumeration_complete": False,
                "work": counters, "authority": "DENY_ALL", "safety_certificate": False}
    return selected, evidence
