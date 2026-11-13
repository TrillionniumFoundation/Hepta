"""Independent normal-exit resource protocol checker for hosted concurrency.

This IR makes group/task join obligations and worker Buffer transfer explicit.
It checks every CFG edge, including loop backedges. It does not check scheduling,
queue values, races inside the runtime, resource budgets, or source refinement.
No parser, frontend checker, Rust compiler or source object is imported here.
"""
from __future__ import annotations

import hashlib
import json
import re

SCHEMA = "hepta.concurrent-ir.v1"
OWNERS = {"Buffer<u8>", "Task<u64>", "TaskGroup"}
CAPABILITIES = {"Cancellation", "Sender<u64>"}
CLAIMS = {
    "normal_exit_join_obligations_verified": True,
    "worker_input_transfer_verified": True,
    "source_to_ir_refinement_proved": False,
    "runtime_data_race_freedom_proved": False,
    "runtime_budget_bounds_proved": False,
    "deadlock_freedom_proved": False,
    "cancellation_termination_proved": False,
    "whole_language_soundness_proved": False,
}
GROUP_OPERATIONS = {
    "group_seal", "group_cancel", "group_receive", "group_receive_timeout",
    "group_snapshot", "group_budget_configure", "group_budget_snapshot", "group_tree_snapshot",
}
SENDER_OPERATIONS = {"group_send", "group_send_timeout", "group_fail"}


class ConcurrentIRError(ValueError):
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


def fail(code, message):
    raise ConcurrentIRError(code, message)


def fields(value, keys):
    if not isinstance(value, dict) or set(value) != set(keys):
        fail("E_CIR_SCHEMA", "Object fields do not match the concurrent IR schema")
    return value


def identifier(value):
    if not isinstance(value, str) or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,255}", value) is None:
        fail("E_CIR_SCHEMA", "Expected a bounded plain identifier")
    return value


def sequence(value, maximum=4096):
    if not isinstance(value, list) or len(value) > maximum:
        fail("E_CIR_SCHEMA", "Expected a bounded list")
    return value


def scalar(typ):
    # Structured Copy results are opaque here; they cannot be resource slots.
    if not isinstance(typ, str) or len(typ) > 256:
        return False
    primitives = {"u8", "u16", "u32", "u64", "u128", "usize", "i8", "i16", "i32", "i64", "i128", "isize", "bool", "f32", "f64", "Unit"}
    if typ in primitives | {"GroupReport", "GroupBudgetReport", "GroupTreeReport"}:
        return True
    if typ.startswith("Result<") and typ.endswith(">"):
        parts = typ[7:-1].split(", ")
        return len(parts) == 2 and all(part in primitives for part in parts)
    return re.fullmatch(r"\[(?:u8|u64|i64); [0-9]+\]", typ) is not None


def _verify(document: object) -> dict:
    doc = fields(document, {"schema", "source_sha256", "project_sha256", "functions", "claims"})
    if (doc["schema"] != SCHEMA or doc["claims"] != CLAIMS
            or any(type(v) is not bool for v in doc["claims"].values())):
        fail("E_CIR_SCHEMA", "Unknown concurrent IR schema or upgraded proof claims")
    for key in ("source_sha256", "project_sha256"):
        if key == "project_sha256" and doc[key] is None:
            continue
        if not isinstance(doc[key], str) or re.fullmatch(r"[a-f0-9]{64}", doc[key]) is None:
            fail("E_CIR_IDENTITY", "Invalid source/project identity")
    functions = {}
    for fn in sequence(doc["functions"], 512):
        fields(fn, {"name", "params", "returns", "slots", "entry", "blocks"})
        name = identifier(fn["name"])
        if name in functions:
            fail("E_CIR_FUNCTION", "Duplicate function")
        functions[name] = fn
        if fn["returns"] != "Buffer<u8>" and not scalar(fn["returns"]):
            fail("E_CIR_SCOPE", "Task/group/capability returns and unknown value types are outside this profile")
        if not isinstance(fn["slots"], dict) or len(fn["slots"]) > 8192:
            fail("E_CIR_SCHEMA", "Invalid slot table")
        for slot, typ in fn["slots"].items():
            identifier(slot)
            if typ not in OWNERS:
                fail("E_CIR_TYPE", "Only known owned runtime values can occupy resource slots")
        seen = set()
        for param in sequence(fn["params"], 128):
            fields(param, {"id", "type", "mode"})
            identifier(param["id"])
            if param["id"] in seen:
                fail("E_CIR_FUNCTION", "Duplicate parameter")
            seen.add(param["id"])
            typ, mode = param["type"], param["mode"]
            if typ == "Buffer<u8>":
                if mode not in {"take", "read", "mut"} or fn["slots"].get(param["id"]) != typ:
                    fail("E_CIR_TYPE", "Buffer parameters require explicit ownership/borrowing and matching slots")
            elif typ in CAPABILITIES:
                if mode != "read" or param["id"] in fn["slots"]:
                    fail("E_CIR_CAPABILITY", "Runtime capabilities can only be read-borrowed parameters")
            elif not scalar(typ) or mode not in {"value", "read", "mut"} or param["id"] in fn["slots"]:
                fail("E_CIR_TYPE", "Unknown parameter type/mode or escaping task group")
    if not functions:
        fail("E_CIR_FUNCTION", "No functions")
    totals = {"functions": len(functions), "blocks": 0, "operations": 0,
              "group_spawns": 0, "task_spawns": 0, "group_adoptions": 0, "tree_joins": 0, "normal_exits": 0}
    for fn in functions.values():
        params = {p["id"]: p for p in fn["params"]}
        slots = fn["slots"]
        blocks = {}
        for block in sequence(fn["blocks"]):
            fields(block, {"id", "operations", "terminator"})
            at = identifier(block["id"])
            if at in blocks:
                fail("E_CIR_CFG", "Duplicate block")
            blocks[at] = block
            sequence(block["operations"], 16384)
            totals["operations"] += len(block["operations"])
        if not blocks or fn["entry"] not in blocks or totals["operations"] > 100000:
            fail("E_CIR_CFG", "Missing entry, empty graph, or operation limit exceeded")
        totals["blocks"] += len(blocks)
        incoming = {fn["entry"]: frozenset(p["id"] for p in fn["params"] if p["mode"] == "take")}
        pending = [fn["entry"]]
        visited = set()
        while pending:
            at = pending.pop()
            if at in visited:
                continue
            visited.add(at)
            live = set(incoming[at])

            def use(slot, typ=None, *, own=False):
                if slot not in slots or (typ is not None and slots[slot] != typ):
                    fail("E_CIR_TYPE", "Operation refers to an unknown or wrong resource kind")
                borrowed = slot in params and params[slot]["mode"] in {"read", "mut"}
                if slot not in live and not (borrowed and not own):
                    fail("E_CIR_USE_AFTER_MOVE", "Resource is moved, uninitialized, or only borrowed: " + slot)

            def consume(slot, typ=None):
                use(slot, typ, own=True)
                live.remove(slot)

            def create(slot, typ):
                if slots.get(slot) != typ or slot in live or slot in params:
                    fail("E_CIR_OVERWRITE", "Resource definition overwrites a live owner/parameter or changes its type")
                live.add(slot)

            def capability(slot, typ):
                if slot not in params or params[slot] != {"id": slot, "type": typ, "mode": "read"}:
                    fail("E_CIR_CAPABILITY", "Sender/cancellation use requires its scoped borrowed capability")

            for op in blocks[at]["operations"]:
                if not isinstance(op, dict):
                    fail("E_CIR_SCHEMA", "Operation must be an object")
                kind = op.get("op")
                if kind == "create":
                    fields(op, {"op", "dest", "type"})
                    if op["type"] not in {"Buffer<u8>", "TaskGroup"}:
                        fail("E_CIR_TYPE", "Task ownership is introduced only by spawn")
                    create(op["dest"], op["type"])
                elif kind == "move":
                    fields(op, {"op", "src", "dest"})
                    use(op["src"], own=True)
                    typ = slots[op["src"]]
                    consume(op["src"])
                    create(op["dest"], typ)
                elif kind == "borrow":
                    fields(op, {"op", "src"})
                    use(op["src"])
                elif kind == "drop_buffer":
                    fields(op, {"op", "src"})
                    consume(op["src"], "Buffer<u8>")
                elif kind == "spawn":
                    fields(op, {"op", "group", "worker", "input", "task"})
                    target = functions.get(op["worker"])
                    expected = [("Buffer<u8>", "take"), ("Cancellation", "read")]
                    if op["group"] is not None:
                        use(op["group"], "TaskGroup", own=True)
                        expected.append(("Sender<u64>", "read"))
                        if op["task"] is not None:
                            fail("E_CIR_SPAWN", "A group owns its worker join handles internally")
                        totals["group_spawns"] += 1
                    else:
                        totals["task_spawns"] += 1
                    if (target is None or [(p["type"], p["mode"]) for p in target["params"]] != expected
                            or target["returns"] != "u64"):
                        fail("E_CIR_SPAWN", "Worker signature does not preserve owned input and borrowed capabilities")
                    consume(op["input"], "Buffer<u8>")
                    if op["group"] is None:
                        create(op["task"], "Task<u64>")
                elif kind == "adopt":
                    fields(op, {"op", "parent", "child", "refusal"})
                    if op["refusal"] != "cancel_and_join_child_subtree":
                        fail("E_CIR_ADOPT", "Refused adoption must consume, cancel and join the child subtree")
                    if op["parent"] == op["child"]:
                        fail("E_CIR_ALIAS", "A group cannot adopt itself")
                    use(op["parent"], "TaskGroup", own=True)
                    # Success transfers the subtree's obligation into this live
                    # parent owner. Refusal joins it immediately. The parent
                    # must still reach a join on every normal CFG exit; moves
                    # preserve that linear owner and cancellation cannot erase it.
                    # Runtime topology/scheduling/refinement are not proved here.
                    consume(op["child"], "TaskGroup")
                    totals["group_adoptions"] += 1
                elif kind == "join":
                    fields(op, {"op", "src", "mode"})
                    modes = {"join": "Task<u64>", "cancel_and_join": "Task<u64>",
                             "group_join": "TaskGroup", "group_cancel_and_join": "TaskGroup", "group_drain_and_join": "TaskGroup",
                             "group_tree_join": "TaskGroup", "group_tree_cancel_and_join": "TaskGroup"}
                    if op["mode"] not in modes:
                        fail("E_CIR_JOIN", "Unknown join operation")
                    consume(op["src"], modes[op["mode"]])
                    if op["mode"] in {"group_tree_join", "group_tree_cancel_and_join"}:
                        totals["tree_joins"] += 1
                elif kind == "group":
                    fields(op, {"op", "src", "mode"})
                    if op["mode"] not in GROUP_OPERATIONS:
                        fail("E_CIR_OPERATION", "Unknown non-consuming group operation")
                    use(op["src"], "TaskGroup", own=True)
                elif kind == "group_pair":
                    fields(op, {"op", "left", "right", "mode"})
                    if op["mode"] not in {"group_select_receive", "group_budget_share"}:
                        fail("E_CIR_OPERATION", "Unknown two-group operation")
                    use(op["left"], "TaskGroup", own=True)
                    use(op["right"], "TaskGroup", own=True)
                    if op["mode"] == "group_budget_share" and op["left"] == op["right"]:
                        fail("E_CIR_ALIAS", "Budget attachment cannot borrow one group twice mutably")
                elif kind == "sender":
                    fields(op, {"op", "src", "mode"})
                    if op["mode"] not in SENDER_OPERATIONS:
                        fail("E_CIR_OPERATION", "Unknown sender operation")
                    capability(op["src"], "Sender<u64>")
                elif kind == "cancel_test":
                    fields(op, {"op", "src"})
                    capability(op["src"], "Cancellation")
                elif kind == "call":
                    fields(op, {"op", "function", "arguments", "dest"})
                    target = functions.get(op["function"])
                    arguments = sequence(op["arguments"], 128)
                    if target is None or len(arguments) != len(target["params"]):
                        fail("E_CIR_CALL", "Unknown function or wrong argument denominator")
                    borrowed = set()
                    mutable = set()
                    taken = set()
                    for arg, param in zip(arguments, target["params"]):
                        typ, mode = param["type"], param["mode"]
                        if typ == "Buffer<u8>":
                            use(arg, typ, own=mode == "take")
                            if mode == "mut" and arg in params and params[arg]["mode"] == "read":
                                fail("E_CIR_ALIAS", "Read-only input cannot be passed to a mutable parameter")
                            if mode == "take":
                                if arg in taken or arg in borrowed:
                                    fail("E_CIR_ALIAS", "Call consumes an owner twice or while borrowed")
                                taken.add(arg)
                            else:
                                if arg in taken or arg in mutable or mode == "mut" and arg in borrowed:
                                    fail("E_CIR_ALIAS", "Conflicting buffer arguments")
                                borrowed.add(arg)
                                if mode == "mut":
                                    mutable.add(arg)
                        elif typ in CAPABILITIES:
                            capability(arg, typ)
                        elif arg is not None:
                            fail("E_CIR_CALL", "Scalar arguments cannot hide runtime resource identities")
                    for arg in taken:
                        consume(arg, "Buffer<u8>")
                    if target["returns"] == "Buffer<u8>":
                        create(op["dest"], "Buffer<u8>")
                    elif op["dest"] is not None:
                        fail("E_CIR_CALL", "Scalar result cannot create an owner")
                else:
                    fail("E_CIR_OPERATION", "Unknown operation")
            term = blocks[at]["terminator"]
            if not isinstance(term, dict):
                fail("E_CIR_CFG", "Missing terminator")
            if term.get("op") == "return":
                fields(term, {"op", "owner"})
                if fn["returns"] == "Buffer<u8>":
                    consume(term["owner"], "Buffer<u8>")
                elif term["owner"] is not None:
                    fail("E_CIR_RETURN", "Scalar return cannot hide an owned value")
                if live:
                    fail("E_CIR_UNCONSUMED", "Normal exit retains resources or pending joins: " + ", ".join(sorted(live)))
                totals["normal_exits"] += 1
                successors = []
            elif term.get("op") == "jump":
                fields(term, {"op", "targets"})
                successors = sequence(term["targets"], 128)
                if not successors or len(successors) != len(set(successors)):
                    fail("E_CIR_CFG", "CFG edges must have distinct nonempty successors")
            else:
                fail("E_CIR_CFG", "Unknown terminator")
            for target in successors:
                if target not in blocks:
                    fail("E_CIR_CFG", "Dangling CFG edge")
                after = frozenset(live)
                if target in incoming and incoming[target] != after:
                    fail("E_CIR_JOIN_STATE", "Control-flow merge/backedge has inconsistent ownership and join obligations")
                if target not in incoming:
                    incoming[target] = after
                    pending.append(target)
        if visited != set(blocks):
            fail("E_CIR_CFG", "Unreachable blocks cannot hide unchecked operations")
    encoded = json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()
    return {"schema": "hepta.concurrent-ir.verification.v1", "ok": True,
            "ir_sha256": hashlib.sha256(encoded).hexdigest(), **totals, "claims": dict(CLAIMS)}


def verify_concurrent_ir(document: object) -> dict:
    try:
        return _verify(document)
    except (ConcurrentIRError, ValueError, TypeError, KeyError, RecursionError) as exc:
        return {"schema": "hepta.concurrent-ir.verification.v1", "ok": False,
                "diagnostics": [{"code": getattr(exc, "code", "E_CIR_SCHEMA"), "message": str(exc)}],
                "claims": dict(CLAIMS)}


def read_graph(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                fail("E_CIR_JSON", "Duplicate JSON field: " + key)
            result[key] = value
        return result
    with open(path, "rb") as stream:
        data = stream.read(16 * 1024 * 1024 + 1)
    if len(data) > 16 * 1024 * 1024:
        fail("E_CIR_LIMIT", "Serialized concurrent graph exceeds 16 MiB")
    return json.loads(data, object_pairs_hook=unique,
                      parse_constant=lambda value: fail("E_CIR_JSON", "Nonfinite constant: " + value))


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("graph")
    args = parser.parse_args(argv)
    try:
        report = verify_concurrent_ir(read_graph(args.graph))
    except (OSError, ValueError, RecursionError) as exc:
        report = {"schema": "hepta.concurrent-ir.verification.v1", "ok": False,
                  "diagnostics": [{"code": getattr(exc, "code", "E_CIR_JSON"), "message": str(exc)}],
                  "claims": dict(CLAIMS)}
    report["source_binding_verified"] = False
    print(json.dumps(report, sort_keys=True, indent=2))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
