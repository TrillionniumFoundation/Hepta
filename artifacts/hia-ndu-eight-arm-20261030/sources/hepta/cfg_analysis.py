"""Fail-closed CFG dominance and natural-loop analysis for Hepta P1.

No SSA, phi nodes, borrowing or executable lowering is implemented here.
This verifier consumes structural hepta.cfg.v0 artifacts, not source text.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json

from .cfg import CFGSnapshot

MAX_ANALYSIS_BLOCKS = 512


class CFGAnalysisRejected(ValueError):
    pass


@dataclass(frozen=True)
class CFGAnalysisSnapshot:
    schema: str
    canonical_json: str
    sha256: str

    def as_dict(self) -> dict:
        obj = json.loads(self.canonical_json)
        obj["sha256"] = self.sha256
        return obj


def _targets(terminator: object) -> list[str]:
    if not isinstance(terminator, dict):
        raise CFGAnalysisRejected("E_DOM_TERMINATOR: expected a structured terminator")
    kind = terminator.get("kind")
    if kind == "goto":
        result = [terminator.get("target")]
    elif kind == "branch":
        result = [terminator.get("then"), terminator.get("else")]
    elif kind == "range_next":
        result = [terminator.get("body"), terminator.get("exit")]
    elif kind == "switch":
        arms = terminator.get("arms")
        if not isinstance(arms, list) or not arms:
            raise CFGAnalysisRejected("E_DOM_TERMINATOR: switch has no structured arms")
        if any(not isinstance(arm, dict) for arm in arms):
            raise CFGAnalysisRejected("E_DOM_TERMINATOR: malformed switch arm")
        result = [arm.get("target") for arm in arms]
    elif kind in {"return", "fallthrough"}:
        result = []
    else:
        raise CFGAnalysisRejected(f"E_DOM_TERMINATOR: unknown terminator {kind!r}")
    if any(not isinstance(x, str) for x in result):
        raise CFGAnalysisRejected("E_DOM_TERMINATOR: successors must be strings")
    return result


def _analyze_function(fn: dict) -> dict:
    blocks = fn.get("blocks")
    edges = fn.get("edges")
    if not isinstance(blocks, list) or not 1 <= len(blocks) <= MAX_ANALYSIS_BLOCKS:
        raise CFGAnalysisRejected("E_DOM_LIMIT: expected 1..512 basic blocks")
    if not isinstance(edges, list):
        raise CFGAnalysisRejected("E_DOM_EDGES: malformed edge list")
    ids = [b.get("id") if isinstance(b, dict) else None for b in blocks]
    if ids != [f"b{i:04d}" for i in range(len(blocks))]:
        raise CFGAnalysisRejected("E_DOM_BLOCKS: blocks must have unique canonical identifiers")
    entry = fn.get("entry")
    if entry not in ids:
        raise CFGAnalysisRejected("E_DOM_ENTRY: missing entry block")
    successors = {b: [] for b in ids}
    expected_edges = []
    for block in blocks:
        bid = block["id"]
        for dest in _targets(block.get("terminator")):
            if dest not in successors:
                raise CFGAnalysisRejected("E_DOM_EDGE: dangling successor")
            successors[bid].append(dest)
            expected_edges.append({"from": bid, "to": dest})
    if edges != expected_edges:
        raise CFGAnalysisRejected("E_DOM_EDGES: CFG edges do not match block terminators")
    predecessors = {b: [] for b in ids}
    for edge in expected_edges:
        if edge["from"] not in predecessors[edge["to"]]:
            predecessors[edge["to"]].append(edge["from"])
    reachable = {entry}
    todo = [entry]
    while todo:
        bid = todo.pop()
        for dest in successors[bid]:
            if dest not in reachable:
                reachable.add(dest)
                todo.append(dest)
    if len(reachable) != len(ids):
        raise CFGAnalysisRejected("E_DOM_UNREACHABLE: basic blocks not reachable from entry")
    all_ids = set(ids)
    dominators = {bid: ({entry} if bid == entry else set(all_ids)) for bid in ids}
    changed = True
    while changed:
        changed = False
        for bid in ids:
            if bid == entry:
                continue
            if not predecessors[bid]:
                raise CFGAnalysisRejected("E_DOM_PREDECESSOR: nonentry block lacks predecessor")
            intersection = set(all_ids)
            for pred in predecessors[bid]:
                intersection &= dominators[pred]
            updated = {bid} | intersection
            if dominators[bid] != updated:
                dominators[bid] = updated
                changed = True
    immediate = {entry: None}
    for bid in ids:
        if bid == entry:
            continue
        strict = dominators[bid] - {bid}
        candidates = [d for d in strict if all(o in dominators[d] for o in strict if o != d)]
        if len(candidates) != 1:
            raise CFGAnalysisRejected("E_DOM_IDOM: ambiguous immediate dominator")
        immediate[bid] = candidates[0]
    frontier = {bid: set() for bid in ids}
    for bid in ids:
        if len(predecessors[bid]) < 2:
            continue
        for pred in predecessors[bid]:
            runner = pred
            while runner is not None and runner != immediate[bid]:
                frontier[runner].add(bid)
                runner = immediate[runner]
    backedges = []
    for edge in expected_edges:
        tail, header = edge["from"], edge["to"]
        if header in dominators[tail]:
            members = {header, tail}
            stack = [tail] if tail != header else []
            while stack:
                node = stack.pop()
                for pred in predecessors[node]:
                    if pred not in members:
                        members.add(pred)
                        if pred != header:
                            stack.append(pred)
            backedges.append({"tail": tail, "header": header,
                              "natural_loop": sorted(members)})
    return {"name": fn.get("name"), "entry": entry, "blocks": len(ids),
            "predecessors": predecessors, "successors": successors,
            "dominators": {k: sorted(v) for k, v in dominators.items()},
            "immediate_dominators": immediate,
            "dominance_frontiers": {k: sorted(v) for k, v in frontier.items()},
            "backedges": backedges}


def analyze_cfg(snapshot: CFGSnapshot) -> CFGAnalysisSnapshot:
    """Validate structure and derive dominance facts without claiming SSA."""
    if not isinstance(snapshot, CFGSnapshot) or snapshot.schema != "hepta.cfg.v0":
        raise CFGAnalysisRejected("E_DOM_INPUT: requires structural hepta.cfg.v0")
    if sha256(snapshot.canonical_json.encode("utf-8")).hexdigest() != snapshot.sha256:
        raise CFGAnalysisRejected("E_DOM_INPUT: structural CFG digest mismatch")
    try:
        cfg = json.loads(snapshot.canonical_json)
    except (ValueError, TypeError) as exc:
        raise CFGAnalysisRejected("E_DOM_INPUT: invalid CFG JSON") from exc
    if cfg.get("schema") != "hepta.cfg.v0" or cfg.get("status") != "structural_cfg_only_not_proved":
        raise CFGAnalysisRejected("E_DOM_INPUT: unexpected CFG status or schema")
    if not isinstance(cfg.get("functions"), list):
        raise CFGAnalysisRejected("E_DOM_INPUT: missing functions")
    if any(not isinstance(f, dict) for f in cfg["functions"]):
        raise CFGAnalysisRejected("E_DOM_FUNCTION: malformed function")
    functions = [_analyze_function(fn) for fn in cfg["functions"]]
    payload = {"schema": "hepta.cfg.analysis.v0", "status": "structural_analysis_only_not_proved",
               "cfg_sha256": snapshot.sha256, "functions": functions,
               "claims": {"cfg_edges_validated": True, "dominators_computed": True,
                          "natural_loops_identified": True, "ssa_constructed": False,
                          "phi_nodes_generated": False, "borrow_or_drop_proved": False,
                          "backend_refinement_proved": False}}
    canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False,
                           allow_nan=False, separators=(",", ":"))
    return CFGAnalysisSnapshot("hepta.cfg.analysis.v0", canonical,
                               sha256(canonical.encode("utf-8")).hexdigest())
