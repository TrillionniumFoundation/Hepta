"""A deliberately small, resource-aware projection of actual checked HIA Core.

Accepted control flow has one live byte-owner at a time, literal scalar results,
fallible allocation, explicit drop, boolean branches and a declared trap. A
single-block allocator callee may transfer its owner/result pair to its caller.
This module does not grant execution authority and does not prove that the
production checker, exporter, VM, LLVM or machine code refines the Lean model.
"""
from __future__ import annotations

from dataclasses import dataclass
import json

from .hia_program import verify_program

SCHEMA = "hepta.hia.owned-exit-profile.v1"
MAX_OBJECT_BYTES = (1 << 63) - 1
MAX_NODES = 512
MAX_BLOCKS = 32
ALLOWED_SCHEMAS = {"hepta.hia.program.v7", "hepta.hia.program.v8"}


class OwnedExitRejected(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise OwnedExitRejected("E_HIA_OWNED_EXIT: " + message)


@dataclass(frozen=True)
class Node:
    tag: str
    value: object = None
    children: tuple = ()

    def wire(self):
        return {"op": self.tag, "value": self.value,
                "children": [child.wire() for child in self.children]}


@dataclass(frozen=True)
class Exported:
    core_bytes: bytes
    core_sha256: str
    tree: Node
    entry: str
    allocator: str
    instruction_map_bytes: bytes

    def mapping(self):
        return json.loads(self.instruction_map_bytes)


def _wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode()


def erase_calls(node):
    return Node("allocate" if node.tag == "call_allocate" else node.tag,
                node.value, tuple(erase_calls(c) for c in node.children))


def export_core(document, *, entry="run", allocator="make"):
    """Recheck and project actual Core; never trust a producer's model or receipt."""
    checked = verify_program(document)
    doc = checked.as_dict()
    require(doc["schema"] in ALLOWED_SCHEMAS, "explicit v7/v8 Core is required")
    functions = {f["name"]: f for f in doc["functions"]}
    require(type(entry) is str and type(allocator) is str and entry != allocator
            and set(functions) == {entry, allocator},
            "exactly the public entry and one closed allocator are required")
    maker, function = functions[allocator], functions[entry]
    require([p["type"] for p in maker["params"]] == ["usize"]
            and maker["returns"] == ["buffer", "bool"]
            and set(maker["effects"]) == {"alloc"}
            and len(maker["blocks"]) == 1, "allocator interface/body is outside profile")
    leaf = maker["blocks"][0]
    require(leaf["id"] == maker["entry"] and len(leaf["ops"]) == 1,
            "allocator must contain exactly one fallible allocation")
    ins = leaf["ops"][0]
    require(ins["op"] == "buffer.try_new" and ins["args"] == [maker["params"][0]["name"]]
            and [p["type"] for p in ins["out"]] == ["buffer", "bool"]
            and leaf["term"] == {"op": "ret", "values": [p["name"] for p in ins["out"]]},
            "allocator must transfer precisely its actual owner and success flag")
    require([p["type"] for p in function["params"]] == ["usize", "bool", "bool"]
            and function["returns"] == ["u8"]
            and set(function["effects"]) <= {"alloc", "trap"},
            "entry requires (size:usize,cancel:bool,abort:bool)->u8")
    require(1 <= len(function["blocks"]) <= MAX_BLOCKS
            and sum(len(b["ops"]) for b in function["blocks"]) <= 128,
            "bounded selected control flow is required")
    blocks = {b["id"]: b for b in function["blocks"]}
    seen, records = set(), []
    nodes = 0

    def make(tag, value=None, children=()):
        nonlocal nodes
        nodes += 1
        require(nodes <= MAX_NODES, "expanded control tree exceeds selected bound")
        return Node(tag, value, tuple(children))

    def extent(atom):
        require(atom[0] == "extent", "allocation extent must be the actual size parameter or literal")
        return atom[1:]

    def condition(atom, last):
        require(atom[0] == "condition", "branch is outside the selected boolean language")
        if atom[1] == "ok":
            require(atom[2] == last, "an older allocation flag cannot denote the current result")
            return ("ok",)
        return atom[1:]

    def target(edge, env, owner, last, stack):
        block = blocks[edge["target"]]
        values = [env[name] for name in edge["args"]]
        owners = [a[1] for a in values if a[0] == "owner"]
        require(owners == ([] if owner is None else [owner]),
                "each CFG edge must transfer the single actual live owner exactly once")
        return walk(block["id"], dict(zip((p["name"] for p in block["params"]), values)),
                    owner, last, stack)

    def walk(block_id, env, owner, last, stack):
        require(block_id not in stack, "cycles are outside the selected finite profile")
        stack = (*stack, block_id)
        seen.add(block_id)
        block = blocks[block_id]

        def operations(index, frame, active, latest):
            if index < len(block["ops"]):
                op = block["ops"][index]
                args, out = [frame[n] for n in op["args"]], op["out"]
                records.append({"function": entry, "block": block_id, "operation": index,
                                "opcode": op["op"], "owner_phase": "empty" if active is None else "owned"})
                updated = dict(frame)
                if op["op"] == "const":
                    typ, value = out[0]["type"], op["attrs"]["value"]
                    require(typ in {"usize", "u8", "bool"}, "literal type outside selected profile")
                    atom = (("extent", "literal", value) if typ == "usize" else
                            ("return", value) if typ == "u8" else ("condition", "literal", value))
                    updated[out[0]["name"]] = atom
                    return operations(index + 1, updated, active, latest)
                if op["op"] in {"buffer.try_new", "call"}:
                    require(active is None, "allocation requires the empty owner phase")
                    if op["op"] == "call":
                        require(op["attrs"] == {"function": allocator},
                                "only the complete checked allocator call is selected")
                    require(len(args) == 1 and [p["type"] for p in out] == ["buffer", "bool"],
                            "allocation/transfer output shape differs")
                    length = extent(args[0])
                    token = (block_id, index)
                    updated[out[0]["name"]] = ("owner", token)
                    updated[out[1]["name"]] = ("condition", "ok", token)
                    continuation = operations(index + 1, updated, token, token)
                    return make("call_allocate" if op["op"] == "call" else "allocate",
                                length, (continuation,))
                if op["op"] == "owner.drop":
                    require(len(args) == 1 and active is not None and args[0] == ("owner", active),
                            "drop must consume the actual live owner")
                    del updated[op["args"][0]]
                    return make("drop", children=(operations(index + 1, updated, None, latest),))
                raise OwnedExitRejected("E_HIA_OWNED_EXIT: unsupported actual opcode " + op["op"])
            term = block["term"]
            if term["op"] == "ret":
                require(active is None and len(term["values"]) == 1,
                        "ordinary exit must have no live owner")
                value = frame[term["values"][0]]
                require(value[0] == "return", "return value must be an actual u8 literal")
                return make("return", value[1])
            if term["op"] == "trap":
                require(term["code"] == "division_by_zero", "only the explicit selected trap is modeled")
                return make("trap")
            if term["op"] == "jump":
                return target(term, frame, active, latest, stack)
            require(term["op"] == "branch", "terminator outside selected profile")
            test = condition(frame[term["cond"]], latest)
            return make("branch", test, (
                target(term["then"], frame, active, latest, stack),
                target(term["else"], frame, active, latest, stack)))

        return operations(0, env, owner, last)

    atoms = (("extent", "input"), ("condition", "cancel"), ("condition", "abort"))
    tree = walk(function["entry"], dict(zip((p["name"] for p in function["params"]), atoms)),
                None, None, ())
    require(seen == set(blocks), "unreachable blocks cannot inherit this selected qualification")
    mapping = {"schema": SCHEMA, "core_sha256": checked.sha256, "entry": entry,
               "allocator": allocator, "allocator_body": leaf,
               "instructions": records, "control_tree": tree.wire(), "nodes": nodes}
    return Exported(checked.canonical_bytes, checked.sha256, tree, entry, allocator, _wire(mapping))


def check_call_erasure(source, candidate, *, entry="run", allocator="make"):
    left = export_core(source, entry=entry, allocator=allocator)
    right = export_core(candidate, entry=entry, allocator=allocator)
    require(erase_calls(left.tree) == right.tree,
            "actual candidate differs from the selected call-erasure relation")
    return left, right


def lean_program(node):
    """Render only constructors and validated literals; no Core identifier enters Lean."""
    if node.tag == "return":
        return f"(.ret {node.value})"
    if node.tag == "trap":
        return ".trap"
    if node.tag == "drop":
        return f"(.drop {lean_program(node.children[0])})"
    if node.tag in {"allocate", "call_allocate"}:
        extent = ".input" if node.value[0] == "input" else f"(.literal {node.value[1]})"
        ctor = "allocate" if node.tag == "allocate" else "callAllocate"
        return f"(.{ctor} {extent} {lean_program(node.children[0])})"
    test = node.value
    condition = (".ok" if test[0] == "ok" else "." + test[0]
                 if test[0] in {"cancel", "abort"} else f"(.literal {str(test[1]).lower()})")
    require(node.tag == "branch", "unknown model constructor")
    return f"(.branch {condition} {lean_program(node.children[0])} {lean_program(node.children[1])})"


def evaluate_model(tree, size, cancel, abort, *, quota, allocation_fail_at=None):
    """Executable independent model; models payload/capabilities, never host RSS."""
    require(type(size) is int and 0 <= size < 1 << 64 and type(quota) is int and quota >= 0
            and type(cancel) is bool and type(abort) is bool
            and (allocation_fail_at is None or type(allocation_fail_at) is int and allocation_fail_at > 0),
            "exact selected invocation is required")
    ledger = {"allocations": 0, "frees": 0, "allocation_attempts": 0,
              "owners_created": 0, "owners_dropped": 0, "live_owners": 0,
              "live_bytes": 0, "peak_bytes": 0}
    events, owner, ok = [], None, False
    node = tree
    while True:
        if node.tag in {"allocate", "call_allocate"}:
            require(owner is None, "model allocation in owned phase")
            called = node.tag == "call_allocate"
            if called:
                events.append({"kind": "call_enter"})
            requested = size if node.value[0] == "input" else node.value[1]
            if requested == 0:
                payload, ok = 0, True
            elif requested > MAX_OBJECT_BYTES:
                payload, ok = 0, False
            elif requested > quota:
                events.append({"kind": "heap_stop", "requested": requested})
                status, value, error = "budget_exceeded", None, "heap"
                break
            else:
                ledger["allocation_attempts"] += 1
                ok = ledger["allocation_attempts"] != allocation_fail_at
                payload = requested if ok else 0
            ledger["owners_created"] += 1
            owner = (ledger["owners_created"], payload)
            ledger["allocations"] += int(payload != 0)
            ledger["live_owners"], ledger["live_bytes"] = 1, payload
            ledger["peak_bytes"] = max(ledger["peak_bytes"], payload)
            events.append({"kind": "allocate", "requested": requested, "owner": owner[0],
                           "bytes": payload, "ok": ok})
            if called:
                events.append({"kind": "call_return"})
            node = node.children[0]
        elif node.tag == "drop":
            require(owner is not None, "model drop in empty phase")
            events.append({"kind": "drop", "owner": owner[0], "bytes": owner[1]})
            ledger["owners_dropped"] += 1
            ledger["frees"] += int(owner[1] != 0)
            ledger["live_owners"] = ledger["live_bytes"] = 0
            owner, node = None, node.children[0]
        elif node.tag == "branch":
            test = node.value
            flag = {"ok": ok, "cancel": cancel, "abort": abort}.get(test[0])
            if test[0] == "literal":
                flag = test[1]
            require(type(flag) is bool, "unknown model condition")
            node = node.children[0 if flag else 1]
        elif node.tag == "return":
            require(owner is None, "model ordinary return with live owner")
            status, value, error = "returned", node.value, None
            break
        else:
            require(node.tag == "trap", "unknown model instruction")
            status, value, error = "trapped", None, "division_by_zero"
            break
    return {"status": status, "value": value, "error": error, "resources": ledger,
            "events": events,
            "resource_events": [e for e in events if e["kind"] not in {"call_enter", "call_return"}]}

