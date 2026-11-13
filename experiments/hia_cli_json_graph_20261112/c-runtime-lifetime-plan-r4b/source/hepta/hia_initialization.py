"""Conservative CFG witness checker for full initialization before byte reads.

The canonical Core verifier remains the ownership/type authority. This checker
only selects the existing native malloc path for local allocations. It checks
complete counted-store loops, exact roots/limits and dominance of every read;
unknown operations, ambiguous roots and incomplete shapes keep calloc.
"""
from __future__ import annotations

from collections import deque
from hashlib import sha256
from pathlib import Path

from .hia_opcodes import SCALARS

SCHEMA = "hepta.hia.initialization-coverage.v1"
MAX_BLOCKS = 128
MAX_OPERATIONS = 2048
MAX_VALUES = 4096
MAX_FLOW_STEPS = 4096
MAX_FLOW_WORK = 262144
_TOP = frozenset({None})
_PURE = frozenset({"const", "int.cast", "int.neg.checked", "select",
    "bool.not", "bool.and", "bool.or", "bit.and", "bit.or", "bit.xor", "bit.not",
    *["compare." + kind for kind in ("eq", "ne", "lt", "le", "gt", "ge")],
    *[f"int.{kind}.{mode}" for kind in ("add", "sub", "mul") for mode in ("checked", "wrap")],
    *[f"int.{kind}.checked" for kind in ("div", "rem", "shl", "shr")]})
_RESOURCE = frozenset({"buffer.new", "buffer.try_new", "buffer.len", "buffer.store", "buffer.load",
                       "borrow.read", "borrow.mut", "loan.end", "owner.move", "owner.drop"})


def _edges(block):
    term = block["term"]
    return ([term] if term["op"] == "jump" else [term["then"], term["else"]]
            if term["op"] == "branch" else [])


def _one(origins):
    return next(iter(origins)) if len(origins) == 1 and origins != _TOP else None


def _union(left, right):
    combined = left | right
    return _TOP if None in combined or len(combined) > 2 else combined


def _analyze(function):
    blocks = {block["id"]: block for block in function["blocks"]}
    if (not blocks or len(blocks) > MAX_BLOCKS
            or sum(len(b["ops"]) for b in blocks.values()) > MAX_OPERATIONS
            or sum(len(b["params"]) + sum(len(op["out"]) for op in b["ops"]) for b in blocks.values()) > MAX_VALUES
            or any(p["type"] not in SCALARS for p in function["params"])
            or any(t not in SCALARS for t in function["returns"])
            or any(b["term"]["op"] not in {"ret", "jump", "branch", "trap"}
                   or any(op["op"] not in _PURE | _RESOURCE for op in b["ops"])
                   for b in blocks.values())):
        return False, [], "outside_closed_local_buffer_profile"
    predecessors = {name: set() for name in blocks}
    for name, block in blocks.items():
        for edge in _edges(block):
            predecessors[edge["target"]].add(name)
    allocations = {op["out"][0]["name"]: (name, op)
                   for name, block in blocks.items() for op in block["ops"]
                   if op["op"] in {"buffer.new", "buffer.try_new"}}
    if not allocations:
        return False, [], "no_local_allocation"
    # One static root must mean at most one dynamic allocation per invocation.
    # Allocation sites inside a cycle cannot inherit an earlier instance's fill.
    for block_name, _ in allocations.values():
        pending = [edge["target"] for edge in _edges(blocks[block_name])]
        seen = set()
        while pending:
            name = pending.pop()
            if name == block_name:
                return False, [], "allocation_site_can_repeat"
            if name not in seen:
                seen.add(name)
                pending.extend(edge["target"] for edge in _edges(blocks[name]))
    origins, types, definitions = {}, {}, {}
    for block in blocks.values():
        for p in block["params"]:
            types[p["name"]], origins[p["name"]] = p["type"], frozenset()
        for op in block["ops"]:
            for out in op["out"]:
                types[out["name"]] = out["type"]
                definitions[out["name"]] = op
    for p in function["params"]:
        origins[p["name"]] = frozenset({("argument", p["name"])})
    pending, queued, steps, work = deque([function["entry"]]), {function["entry"]}, 0, 0
    while pending:
        name = pending.popleft()
        queued.remove(name)
        steps += 1
        block = blocks[name]
        work += 1 + len(block["ops"]) + sum(len(edge["args"]) for edge in _edges(block))
        if steps > MAX_FLOW_STEPS or work > MAX_FLOW_WORK:
            return False, [], "origin_flow_budget_exhausted"
        for op in block["ops"]:
            for out in op["out"]:
                value = out["name"]
                if op["op"] == "const":
                    new = frozenset({("constant", out["type"], op["attrs"]["value"])})
                elif op["op"] in {"borrow.read", "borrow.mut", "owner.move"}:
                    new = origins.get(op["args"][0], frozenset())
                elif op["op"] in {"buffer.new", "buffer.try_new"} and out["type"] == "buffer":
                    new = frozenset({("allocation", value)})
                elif op["op"] == "int.cast" and types[op["args"][0]] == out["type"]:
                    new = origins.get(op["args"][0], frozenset())
                else:
                    new = frozenset({("value", value)})
                origins[value] = _union(origins.get(value, frozenset()), new)
        for edge in _edges(block):
            changed = False
            for p, arg in zip(blocks[edge["target"]]["params"], edge["args"]):
                before = origins[p["name"]]
                after = _union(before, origins.get(arg, frozenset()))
                if after != before:
                    origins[p["name"]] = after
                    changed = True
            if changed and edge["target"] not in queued:
                pending.append(edge["target"])
                queued.add(edge["target"])
    if any(not origins[p["name"]] for b in blocks.values() for p in b["params"]):
        return False, [], "incomplete_origin_flow"
    dominators = {name: ({name} if name == function["entry"] else set(blocks)) for name in blocks}
    changed = True
    while changed:
        changed = False
        for name in blocks:
            if name == function["entry"]:
                continue
            incoming = predecessors[name]
            if not incoming:
                return False, [], "unreachable_block"
            found = {name} | set.intersection(*(dominators[p] for p in incoming))
            if found != dominators[name]:
                dominators[name] = found
                changed = True
    witnesses = []
    for header in blocks.values():
        term = header["term"]
        if term["op"] != "branch" or len(header["ops"]) != 1:
            continue
        compare = header["ops"][0]
        if compare["op"] != "compare.lt" or compare["out"][0]["name"] != term["cond"]:
            continue
        index, limit = compare["args"]
        parameter_names = [p["name"] for p in header["params"]]
        if index not in parameter_names or limit not in parameter_names or types[index] != "usize" or types[limit] != "usize":
            continue
        body, exit_block = blocks[term["then"]["target"]], blocks[term["else"]["target"]]
        if (predecessors[body["id"]] != {header["id"]}
                or predecessors[exit_block["id"]] != {header["id"]}
                or body["term"]["op"] != "jump" or body["term"]["target"] != header["id"]):
            continue
        stores = [op for op in body["ops"] if op["op"] == "buffer.store"]
        if len(stores) != 1 or any(op["op"] not in _PURE | {"borrow.mut", "loan.end", "buffer.store"} for op in body["ops"]):
            continue
        index_position, limit_position = parameter_names.index(index), parameter_names.index(limit)
        body_index = body["params"][term["then"]["args"].index(index)]["name"] if index in term["then"]["args"] else None
        store = stores[0]
        if body_index is None or store["args"][1] != body_index:
            continue
        root = _one(origins.get(store["args"][0], frozenset()))
        if root is None or root[0] != "allocation" or root[1] not in allocations:
            continue
        allocation = allocations[root[1]][1]
        requested = _one(origins.get(allocation["args"][0], frozenset()))
        if requested is None or _one(origins[limit]) != requested:
            continue
        step_name = body["term"]["args"][index_position]
        step = definitions.get(step_name)
        if (step is None or step not in body["ops"] or step["op"] not in {"int.add.checked", "int.add.wrap"}
                or len(step["out"]) != 1 or step["out"][0]["type"] != "usize"
                or step["args"][0] != body_index
                or _one(origins.get(step["args"][1], frozenset())) != ("constant", "usize", 1)
                or body["ops"].index(step) <= body["ops"].index(store)
                or _one(origins.get(body["term"]["args"][limit_position], frozenset())) != requested):
            continue
        entry_edges = [(blocks[p], edge) for p in predecessors[header["id"]] if p != body["id"]
                       for edge in _edges(blocks[p]) if edge["target"] == header["id"]]
        if not entry_edges or any(_one(origins.get(edge["args"][index_position], frozenset())) != ("constant", "usize", 0)
                                  or _one(origins.get(edge["args"][limit_position], frozenset())) != requested
                                  for _, edge in entry_edges):
            continue
        witnesses.append({"allocation": root[1], "header": header["id"], "body": body["id"],
                          "completed_exit": exit_block["id"], "index": index, "limit": limit,
                          "store_index": body_index, "step": step_name,
                          "invariant": "all indices below i initialized; 0 <= i <= allocation length",
                          "induction": "i=0; store[i] when i<n; successor=i+1; normal exit i=n"})
    reads = [(name, op) for name, block in blocks.items() for op in block["ops"] if op["op"] == "buffer.load"]
    for name, op in reads:
        root = _one(origins.get(op["args"][0], frozenset()))
        if (root is None or root[0] != "allocation"
                or not any(w["allocation"] == root[1] and w["completed_exit"] in dominators[name] for w in witnesses)):
            return False, witnesses, "read_not_dominated_by_complete_same_root_fill"
    return True, witnesses, "all_local_byte_reads_follow_complete_initialization"


def initialization_coverage(function):
    """Internal structural witness; caller must supply canonically checked Core."""
    try:
        eligible, witnesses, reason = _analyze(function)
    except (KeyError, IndexError, TypeError, ValueError, RecursionError):
        eligible, witnesses, reason = False, [], "malformed_or_unsupported_function"
    return {"schema": SCHEMA, "eligible": eligible, "function": function.get("name"),
            "reason": reason, "witnesses": witnesses,
            "claims": {"whole_language_soundness_proved": False, "backend_refinement_proved": False}}


def verify_initialization_coverage(program):
    """Reverify actual Core bytes; a saved witness never authorizes emission."""
    from .hia_program import verify_program
    before = sha256(Path(__file__).read_bytes()).hexdigest()
    checked = verify_program(program)
    functions = [initialization_coverage(fn) for fn in checked.as_dict()["functions"]]
    if sha256(Path(__file__).read_bytes()).hexdigest() != before:
        raise ValueError("initialization checker changed during coverage analysis")
    return {"schema": SCHEMA, "core_sha256": checked.sha256,
            "checker_sha256": before, "functions": functions,
            "limits": ["Closed local scalar/buffer profile and structurally checked complete counted-store loops only.",
                       "Mathematical prefix theorem does not machine-prove the Python CFG bridge or LLVM implementation.",
                       "Allocation/refusal/bounds/drop stay observable; allocator family choice and initialization work can change."]}
