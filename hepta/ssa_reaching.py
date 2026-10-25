"""Independent, finite reaching-definition verifier for scalar SSA snapshots.

Dominance by itself is insufficient: a forged SSA input can refer to an older
version of a variable after a newer assignment. Derive actual reaching versions
for all CFG edges and require exact last-definition identity at every read/PHI.
This does not prove the Hepta frontend or LLVM backend semantics.
"""
from __future__ import annotations

from collections import deque


class ReachingRejected(ValueError):
    """A renamed scalar use does not match its source reaching definition."""


def reaching_states(function: dict, graph: dict) -> tuple[dict, dict]:
    """Compute source reaching definitions from independently verified CFG edges.

    An empty set is the iterative bottom state; {None} is an uninitialized
    source variable. A value with multiple SSA versions requires a PHI before
    it may be read. The algorithm never trusts the producer's renaming stack.
    """
    names = tuple(sorted(function["scalar_types"]))
    blocks = {block["id"]: block for block in function["blocks"]}
    entry = function["entry"]
    preds, succ = graph["predecessors"], graph["successors"]
    if (set(blocks) != set(preds) or set(blocks) != set(succ)
            or entry not in blocks or preds[entry]):
        raise ReachingRejected("E_SSA_VERIFY_REACHING: malformed CFG entry/inventory")
    params = {p["variable"]: p["ssa_name"] for p in function["parameters"]}
    if len(params) != len(function["parameters"]) or not set(params) <= set(names):
        raise ReachingRejected("E_SSA_VERIFY_REACHING: invalid parameter definitions")
    seed = {name: frozenset((params.get(name),)) for name in names}
    empty = {name: frozenset() for name in names}
    at_entry = {bid: dict(empty) for bid in blocks}
    at_exit = {bid: dict(empty) for bid in blocks}
    pending = deque((entry,))
    queued, visited = {entry}, set()
    while pending:
        bid = pending.popleft()
        queued.remove(bid)
        if bid == entry:
            before = dict(seed)
        else:
            before = {
                name: frozenset().union(*(at_exit[p][name] for p in preds[bid]))
                for name in names
            }
        after = dict(before)
        for phi in blocks[bid]["phis"]:
            definition = phi["result"]
            after[definition["variable"]] = frozenset((definition["ssa_name"],))
        for instruction in blocks[bid]["instructions"]:
            definition = instruction.get("definition")
            if definition is not None:
                after[definition["variable"]] = frozenset((definition["ssa_name"],))
        changed = after != at_exit[bid]
        at_entry[bid], at_exit[bid] = before, after
        if changed or bid not in visited:
            visited.add(bid)
            for nxt in succ[bid]:
                if nxt not in queued:
                    pending.append(nxt)
                    queued.add(nxt)
    if len(visited) != len(blocks):
        raise ReachingRejected("E_SSA_VERIFY_REACHING: unreachable CFG block")
    return at_entry, at_exit


def verify_latest_reads(function: dict, graph: dict) -> int:
    """Check the reaching version at each expression read and incoming PHI edge."""
    incoming, outgoing = reaching_states(function, graph)
    verified_reads = 0

    def check(expression: dict, state: dict, depth: int = 0) -> None:
        nonlocal verified_reads
        if (depth > 64 or not isinstance(expression, dict)
                or expression.get("node") != "expr"):
            raise ReachingRejected("E_SSA_VERIFY_REACHING: malformed scalar expression")
        if expression.get("operation") == "name":
            name, ref = expression.get("value"), expression.get("ssa_ref")
            if name not in state or state[name] != frozenset((ref,)):
                raise ReachingRejected(
                    f"E_SSA_VERIFY_REACHING: stale or ambiguous reference to {name!r}")
            verified_reads += 1
        else:
            operands = expression.get("operands")
            if not isinstance(operands, list):
                raise ReachingRejected("E_SSA_VERIFY_REACHING: malformed operands")
            for operand in operands:
                check(operand, state, depth + 1)

    for block in function["blocks"]:
        bid = block["id"]
        state = dict(incoming[bid])
        for phi in block["phis"]:
            name = phi["result"]["variable"]
            for edge in phi["incoming"]:
                pred, reference = edge["from"], edge["ssa_ref"]
                if outgoing[pred][name] != frozenset((reference,)):
                    raise ReachingRejected(
                        f"E_SSA_VERIFY_REACHING: stale PHI input on {pred}->{bid} ({name})")
            state[name] = frozenset((phi["result"]["ssa_name"],))
        for instruction in block["instructions"]:
            check(instruction["ssa_value"], state)
            definition = instruction.get("definition")
            if definition is not None:
                state[definition["variable"]] = frozenset((definition["ssa_name"],))
        term = block["terminator"]
        value = (term.get("condition") if term["kind"] == "branch"
                 else term.get("value") if term["kind"] == "return" else None)
        if value is not None:
            check(value, state)
        if state != outgoing[bid]:
            raise ReachingRejected("E_SSA_VERIFY_REACHING: invalid transfer state")
    return verified_reads
