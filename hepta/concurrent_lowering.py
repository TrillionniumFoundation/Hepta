"""Lower the explicit hosted task/Buffer profile into independent protocol IR.

Scalar values and predicates are abstracted nondeterministically. Owned ADTs,
stored references, raw pointers, externs and generic bodies are rejected here;
the separate general resource IR handles more sequential ownership semantics.
"""
from __future__ import annotations

import hashlib

from .concurrent_ir import (CAPABILITIES, CLAIMS, GROUP_OPERATIONS, OWNERS,
                            SCHEMA, SENDER_OPERATIONS, ConcurrentIRError, scalar)


def unsupported(message):
    raise ConcurrentIRError("E_CIR_LOWER", message)


class Builder:
    def __init__(self, fn, program, checked):
        self.fn, self.checked = fn, checked
        self.functions = {f.name: f for f in program.functions}
        self.slots, self.env, self.blocks = {}, {}, []
        self.next_slot = 0
        self.at = self.block()
        self.params = []
        for p in fn.params:
            typ = str(p.type)
            if typ not in OWNERS | CAPABILITIES and not scalar(typ):
                unsupported("Unsupported concurrent parameter type: " + typ)
            slot = self.fresh(typ, parameter=True)
            self.env[p.name] = (slot, typ)
            self.params.append({"id": slot, "type": typ, "mode": p.mode})

    def fresh(self, typ, parameter=False):
        slot = "v" + str(self.next_slot)
        self.next_slot += 1
        if typ in OWNERS:
            self.slots[slot] = typ
        elif not parameter:
            unsupported("Only owned values need fresh resource temporaries")
        return slot

    def block(self):
        if len(self.blocks) >= 4096:
            unsupported("Concurrent CFG block limit")
        ident = "bb" + str(len(self.blocks))
        self.blocks.append({"id": ident, "operations": [], "terminator": None})
        return ident

    def current(self):
        if self.at is None:
            unsupported("Unreachable statement")
        return self.blocks[int(self.at[2:])]

    def emit(self, op, **values):
        current = self.current()
        if len(current["operations"]) >= 16384:
            unsupported("Concurrent operation limit")
        current["operations"].append({"op": op, **values})

    def term(self, **values):
        self.current()["terminator"] = values
        self.at = None

    def jump(self, *targets):
        self.term(op="jump", targets=list(targets))

    def typ(self, expr):
        typ = self.checked.expr_types.get(id(expr))
        if typ is None:
            unsupported("Missing checked expression type")
        text = str(typ)
        if text not in OWNERS | CAPABILITIES and not scalar(text):
            unsupported("Unsupported concurrent expression type: " + text)
        return text

    def named(self, expr):
        if expr.kind == "unary" and expr.value in {"read", "mut"}:
            expr = expr.children[0]
        if expr.kind != "name" or expr.value not in self.env:
            unsupported("Runtime capabilities and group borrows require named local places")
        return self.env[expr.value][0]

    def value(self, expr):
        if expr is None:
            return None
        typ = self.typ(expr)
        if expr.kind == "name":
            if typ in OWNERS | CAPABILITIES:
                slot = self.named(expr)
                if typ in OWNERS:
                    self.emit("borrow", src=slot)
                return slot
            return None
        if expr.kind == "unary" and expr.value == "move":
            child = expr.children[0]
            if typ not in OWNERS:
                unsupported("Only known owned resources move in this profile")
            if child.kind == "name":
                dest = self.fresh(typ)
                self.emit("move", src=self.named(child), dest=dest)
                return dest
            if child.kind != "call":
                unsupported("Partial/aggregate moves belong to the sequential resource IR profile")
            return self.value(child)
        if expr.kind == "unary" and expr.value in {"read", "mut"}:
            child = expr.children[0]
            if typ in OWNERS | CAPABILITIES:
                slot = self.named(expr)
                if typ in OWNERS:
                    self.emit("borrow", src=slot)
                return slot
            self.value(child)
            return None
        if expr.kind == "call":
            return self.call(expr, typ)
        # Scalar short-circuit operators are lowered as branches because their
        # right side may perform spawn/drop/cancel. Eager scanning is unsound.
        if expr.kind == "binary" and expr.value in {"&&", "||"}:
            self.value(expr.children[0])
            yes, no, merge = self.block(), self.block(), self.block()
            self.jump(yes, no)
            self.at = yes
            self.value(expr.children[1])
            self.jump(merge)
            self.at = no
            self.jump(merge)
            self.at = merge
            return None
        if expr.kind == "index":
            base, index = expr.children
            owner = self.value(base)
            if self.value(index) is not None:
                unsupported("An index cannot erase an owned resource")
            if owner is not None:
                if self.typ(base) != "Buffer<u8>":
                    unsupported("Only Buffer indexing can retain an owned base")
                # The actual access occurs after evaluating its index. A
                # nested index computation may have moved/dropped the base;
                # the earlier operand read alone cannot validate that use.
                self.emit("borrow", src=owner)
            return None
        if typ in OWNERS | CAPABILITIES:
            unsupported("Resource construction/selection is not supported in this concurrent profile")
        for child in expr.children:
            if self.value(child) is not None:
                unsupported("A scalar operation would erase a runtime resource")
        return None

    def call(self, expr, typ):
        name, args = expr.value, expr.children
        if name in {"buffer", "task_group"}:
            for arg in args:
                if self.value(arg) is not None:
                    unsupported("Resource constructor arguments must be scalar")
            dest = self.fresh(typ)
            self.emit("create", dest=dest, type=typ)
            return dest
        if name in {"spawn", "group_spawn"}:
            grouped = name == "group_spawn"
            group = self.named(args[0]) if grouped else None
            worker, data = args[1:] if grouped else args
            if worker.kind != "name":
                unsupported("Spawn requires a statically resolved worker function")
            owner = self.value(data)
            task = None if grouped else self.fresh("Task<u64>")
            self.emit("spawn", group=group, worker=worker.value, input=owner, task=task)
            return task
        if name in {"drop", "release"}:
            owner = self.value(args[0])
            self.emit("drop_buffer", src=owner)
            return None
        if name in {"join", "cancel_and_join", "group_join", "group_cancel_and_join", "group_drain_and_join"}:
            self.emit("join", src=self.value(args[0]), mode=name)
            return None
        if name in GROUP_OPERATIONS:
            group = self.named(args[0])
            for arg in args[1:]:
                if self.value(arg) is not None:
                    unsupported("Group scalar/output arguments cannot contain owners")
            # Arguments are evaluated before the runtime operation. In
            # particular a later operand must not join this earlier group.
            self.emit("group", src=group, mode=name)
            return None
        if name in {"group_select_receive", "group_budget_share"}:
            left, right = self.named(args[0]), self.named(args[1])
            for arg in args[2:]:
                if self.value(arg) is not None:
                    unsupported("Two-group scalar/output arguments cannot contain owners")
            self.emit("group_pair", left=left, right=right, mode=name)
            return None
        if name in SENDER_OPERATIONS:
            sender = self.named(args[0])
            for arg in args[1:]:
                if self.value(arg) is not None:
                    unsupported("Sender operation cannot conceal resource transfers")
            self.emit("sender", src=sender, mode=name)
            return None
        if name == "cancelled":
            self.emit("cancel_test", src=self.named(args[0]))
            return None
        if name in self.functions:
            target = self.functions[name]
            values = []
            for param, arg in zip(target.params, args):
                value = self.value(arg)
                if str(param.type) in OWNERS | CAPABILITIES:
                    values.append(value)
                else:
                    if value is not None:
                        unsupported("Scalar argument cannot conceal an owner")
                    values.append(None)
            dest = self.fresh(typ) if typ == "Buffer<u8>" else None
            self.emit("call", function=name, arguments=values, dest=dest)
            return dest
        if name in {"len", "load", "store"}:
            for i, arg in enumerate(args):
                value = self.value(arg)
                if value is not None and (i != 0 or self.typ(arg) != "Buffer<u8>"
                                          or arg.kind == "unary" and arg.value == "move"):
                    unsupported("Sequence operation cannot consume a resource")
            return None
        if name in {"wrapping_add", "wrapping_sub", "wrapping_mul", "assert", "print_i64", "min", "max"}:
            for arg in args:
                if self.value(arg) is not None:
                    unsupported("Scalar builtin cannot conceal resources")
            return None
        unsupported("Unsupported concurrent builtin/call: " + name)

    def sequence(self, statements):
        for stmt in statements:
            self.current()
            data = stmt.data
            if stmt.kind == "let":
                expr = data["expr"]
                value = self.value(expr)
                if value is not None:
                    typ = self.typ(expr)
                    if typ not in OWNERS:
                        unsupported("Scoped runtime capabilities cannot be stored")
                    dest = self.fresh(typ)
                    self.emit("move", src=value, dest=dest)
                    self.env[data["name"]] = (dest, typ)
            elif stmt.kind == "expr":
                if self.value(data["expr"]) is not None:
                    unsupported("Discarded resource expression")
            elif stmt.kind == "assign":
                if self.value(data["expr"]) is not None:
                    unsupported("Assignment of an owner requires a separate place initialization model")
                # Scalar field assignments may borrow a resource; it is safe to
                # reject such shapes until represented explicitly.
                if self.typ(data["target"]) in OWNERS | CAPABILITIES:
                    unsupported("Resource assignment is outside the profile")
                self.value(data["target"])
            elif stmt.kind == "return":
                owner = self.value(data["expr"])
                self.term(op="return", owner=owner)
            elif stmt.kind == "if":
                self.value(data["condition"])
                yes, no = self.block(), self.block()
                self.jump(yes, no)
                before = dict(self.env)
                ends = []
                for entry, body in ((yes, data["then"]), (no, data["else"])):
                    self.at, self.env = entry, dict(before)
                    self.sequence(body)
                    if self.at is not None:
                        ends.append(self.at)
                self.env = before
                if ends:
                    merge = self.block()
                    for end in ends:
                        self.at = end
                        self.jump(merge)
                    self.at = merge
            elif stmt.kind in {"while", "for"}:
                if stmt.kind == "for":
                    self.value(data["start"])
                    self.value(data["end"])
                condition, body, done = self.block(), self.block(), self.block()
                self.jump(condition)
                self.at = condition
                if stmt.kind == "while":
                    self.value(data["condition"])
                self.jump(body, done)
                self.at = body
                before = dict(self.env)
                self.sequence(data["body"])
                if self.at is not None:
                    self.jump(condition)
                self.env, self.at = before, done
            elif stmt.kind == "match":
                if self.value(data["expr"]) is not None:
                    unsupported("Owned matches use the sequential resource IR profile")
                entries = [self.block() for _ in data["arms"]]
                self.jump(*entries)
                before, ends = dict(self.env), []
                for entry, arm in zip(entries, data["arms"]):
                    self.at, self.env = entry, dict(before)
                    self.sequence(arm.body)
                    if self.at is not None:
                        ends.append(self.at)
                self.env = before
                if ends:
                    merge = self.block()
                    for end in ends:
                        self.at = end
                        self.jump(merge)
                    self.at = merge
            else:
                unsupported("Unsupported concurrent statement: " + stmt.kind)

    def finish(self):
        self.sequence(self.fn.body)
        if self.at is not None:
            if str(self.fn.return_type) != "Unit":
                unsupported("Non-Unit fallthrough")
            self.term(op="return", owner=None)
        return {"name": self.fn.name, "params": self.params, "returns": str(self.fn.return_type),
                "slots": self.slots, "entry": "bb0", "blocks": self.blocks}


def lower_concurrent_ir(program, checked, *, project_sha256=None):
    if not checked.ok:
        unsupported("Cannot lower a frontend-rejected program")
    functions = []
    for fn in program.functions:
        if fn.body is None or fn.extern_c or fn.export_c or fn.type_params or fn.return_mode != "value":
            unsupported("Extern/C exports, generic bodies and returned borrows are outside the concurrent profile")
        functions.append(Builder(fn, program, checked).finish())
    return {"schema": SCHEMA, "source_sha256": hashlib.sha256(program.source.encode()).hexdigest(),
            "project_sha256": project_sha256, "functions": functions, "claims": dict(CLAIMS)}
