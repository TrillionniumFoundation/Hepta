"""Independent bounded interpreter for executable-core v1 operations.

This module executes core opcodes directly; it does not evaluate original
Hepta source, generated Rust/C, or LLVM. Python integers are narrowed under
the core's explicit bit semantics. Buffers carry independent liveness and
loan state, and resource events are measured by the interpreter itself.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .executable_core import WIDTHS, SCALARS, PROFILE, reject


class _Trap(Exception):
    pass


class _Budget(Exception):
    pass


class _Return(Exception):
    def __init__(self, value):
        self.value = value


_MOVED = object()


@dataclass
class _Buffer:
    identity: int
    data: bytearray
    alive: bool = True
    loans: dict = field(default_factory=dict)


@dataclass
class _Loan:
    buffer: _Buffer
    identity: int
    mutable: bool
    ancestors: frozenset
    active: bool = True


@dataclass
class _Result:
    variant: str
    value: object


@dataclass
class _Cell:
    value: object
    mutable: bool


def _owns(value):
    return isinstance(value, _Buffer) or isinstance(value, _Result) and _owns(value.value)


def _bounded(value, typ, *, wrap=False):
    if typ == "bool":
        if type(value) is not bool:
            raise _Trap("type: bool required")
        return value
    if typ == "Unit":
        if value is not None:
            raise _Trap("type: Unit required")
        return None
    if typ not in WIDTHS or type(value) is not int:
        raise _Trap("type: fixed-width integer required")
    bits = WIDTHS[typ]
    signed = typ.startswith("i")
    if wrap:
        value %= 1 << bits
        if signed and value >= 1 << (bits - 1):
            value -= 1 << bits
    lower, upper = (-(1 << (bits - 1)), (1 << (bits - 1)) - 1) if signed else (0, (1 << bits) - 1)
    if not lower <= value <= upper:
        raise _Trap("overflow: " + typ)
    return value


class _Runtime:
    def __init__(self, core, max_steps, max_heap_bytes, allocation_fail_at):
        self.functions = {fn["name"]: fn for fn in core["functions"]}
        self.max_steps, self.max_heap_bytes = max_steps, max_heap_bytes
        self.fail_at = allocation_fail_at
        self.steps = self.depth = self.loan_sequence = 0
        self.buffers = {}
        self.events = []
        self.live_bytes = self.peak_bytes = self.allocations = self.frees = self.attempts = self.refusals = 0

    def tick(self):
        self.steps += 1
        if self.steps > self.max_steps:
            raise _Budget("instruction budget exhausted")

    def event(self, event):
        if len(self.events) >= 65536:
            raise _Budget("resource-event budget exhausted")
        self.events.append(event)

    def cell(self, expr, env):
        if expr["op"] != "local.get" or expr["name"] not in env:
            raise _Trap("resource: named live local required")
        cell = env[expr["name"]]
        if cell.value is _MOVED:
            raise _Trap("resource: use after move")
        return cell

    def sequence(self, expr, env):
        if expr["op"] in {"borrow.read", "borrow.mut"}:
            expr = expr["args"][0]
        value = self.cell(expr, env).value
        if not isinstance(value, (_Buffer, _Loan)):
            raise _Trap("resource: byte sequence required")
        return value

    def access(self, value, *, write=False):
        owner = value.buffer if isinstance(value, _Loan) else value
        if not isinstance(owner, _Buffer) or not owner.alive:
            raise _Trap("resource: released byte owner")
        allowed = set()
        if isinstance(value, _Loan):
            if not value.active or (write and not value.mutable):
                raise _Trap("resource: inactive or read-only loan")
            allowed = set(value.ancestors) | {value.identity}
        for identity, loan in owner.loans.items():
            if identity not in allowed and loan.active and (write or loan.mutable):
                raise _Trap("resource: access conflicts with live loan")
        return owner

    def borrow(self, expr, env, mode):
        if expr["op"] in {"borrow.read", "borrow.mut"}:
            if expr["op"] != "borrow." + mode:
                raise _Trap("resource: loan mode mismatch")
            expr = expr["args"][0]
        cell = self.cell(expr, env)
        value = cell.value
        mutable = mode == "mut"
        if mutable and not cell.mutable:
            raise _Trap("resource: mutable borrow of immutable binding")
        owner = self.access(value, write=mutable)
        ancestors = (value.ancestors | {value.identity}) if isinstance(value, _Loan) else frozenset()
        self.loan_sequence += 1
        loan = _Loan(owner, self.loan_sequence, mutable, frozenset(ancestors))
        owner.loans[loan.identity] = loan
        self.event({"event": "borrow", "owner": owner.identity, "loan": loan.identity, "mode": mode})
        return loan

    def end(self, loan):
        if not loan.active:
            raise _Trap("resource: loan ended twice")
        if any(loan.identity in child.ancestors for child in loan.buffer.loans.values() if child.active):
            raise _Trap("resource: parent loan ended before child")
        loan.active = False
        loan.buffer.loans.pop(loan.identity)
        self.event({"event": "end_borrow", "owner": loan.buffer.identity, "loan": loan.identity})

    def movable(self, value):
        if isinstance(value, _Buffer):
            if not value.alive or value.loans:
                raise _Trap("resource: move/drop of borrowed or released owner")
        elif isinstance(value, _Result):
            self.movable(value.value)
        elif isinstance(value, _Loan):
            raise _Trap("resource: borrowed values cannot be moved as owners")

    def drop(self, value):
        if isinstance(value, _Result):
            self.drop(value.value)
            return
        if not isinstance(value, _Buffer):
            return
        self.movable(value)
        value.alive = False
        size = len(value.data)
        value.data = bytearray()
        self.live_bytes -= size
        if size:
            self.frees += 1
        self.event({"event": "drop", "owner": value.identity, "bytes": size})

    def allocation(self, size):
        if size > (1 << 63) - 1:
            self.refusals += 1
            self.event({"event": "allocation_refused", "reason": "capacity"})
            return _Result("Err", 1)
        if size:
            self.attempts += 1
            if self.fail_at == self.attempts:
                self.refusals += 1
                self.event({"event": "allocation_refused", "reason": "injected", "attempt": self.attempts})
                return _Result("Err", 1)
        if self.live_bytes + size > self.max_heap_bytes:
            raise _Budget("interpreter live-byte budget exhausted")
        if len(self.buffers) >= 32768:
            raise _Budget("owner-identity budget exhausted")
        identity = len(self.buffers) + 1
        try:
            owner = _Buffer(identity, bytearray(size))
        except MemoryError as exc:
            raise _Budget("interpreter host memory unavailable") from exc
        self.buffers[identity] = owner
        self.live_bytes += size
        self.peak_bytes = max(self.peak_bytes, self.live_bytes)
        if size:
            self.allocations += 1
        self.event({"event": "allocate", "owner": identity, "bytes": size})
        return _Result("Ok", owner)

    def expr(self, expr, env):
        if expr is None:
            return None
        self.tick()
        op, args, typ = expr["op"], expr["args"], expr["type"]["name"]
        if op.startswith("const."):
            return _bounded(expr["value"], typ)
        if op == "local.get":
            value = self.cell(expr, env).value
            if _owns(value) or isinstance(value, _Loan):
                raise _Trap("resource: owner/loan copied without explicit operation")
            return value
        if op == "owner.move":
            cell = self.cell(args[0], env)
            value = cell.value
            self.movable(value)
            if _owns(value):
                cell.value = _MOVED
                self.event({"event": "move", "local": args[0]["name"]})
            return value
        if op == "buffer.load":
            owner = self.access(self.sequence(args[0], env))
            offset = self.expr(args[1], env)
            if not 0 <= offset < len(owner.data):
                raise _Trap("bounds: byte index")
            return owner.data[offset]
        if op == "buffer.length":
            return len(self.access(self.sequence(args[0], env)).data)
        if op in {"buffer.new", "buffer.try_new"}:
            result = self.allocation(self.expr(args[0], env))
            if op == "buffer.try_new":
                return result
            if result.variant == "Err":
                raise _Trap("allocation: infallible allocation refused")
            return result.value
        if op in {"owner.drop", "owner.release"}:
            self.drop(self.expr(args[0], env))
            return None
        if op == "guard.assert":
            if self.expr(args[0], env) is not True:
                raise _Trap("assert: false")
            return None
        if op == "result.make":
            return _Result(expr["variant"], self.expr(args[0], env))
        if op == "function.call":
            fn = self.functions[expr["function"]]
            values, loans = [], []
            try:
                for arg, parameter in zip(args, fn["params"]):
                    if parameter["mode"] in {"read", "mut"}:
                        value = self.borrow(arg, env, parameter["mode"])
                        loans.append(value)
                    else:
                        value = self.expr(arg, env)
                    values.append(value)
                return self.call(fn, values)
            finally:
                for loan in reversed(loans):
                    self.end(loan)
        if op == "bool.and.short":
            return self.expr(args[0], env) and self.expr(args[1], env)
        if op == "bool.or.short":
            return self.expr(args[0], env) or self.expr(args[1], env)
        if op == "int.neg.checked" and args[0]["op"] == "const.int":
            return _bounded(-args[0]["value"], typ)
        left = self.expr(args[0], env)
        if op == "value.identity":
            return left
        if op == "int.cast":
            return _bounded(left, typ, wrap=True)
        if op == "int.neg.checked":
            return _bounded(-left, typ)
        if op == "bit.not":
            return not left if typ == "bool" else _bounded(~left, typ, wrap=True)
        right = self.expr(args[1], env)
        if op.startswith("compare."):
            return {"compare.eq": lambda: left == right, "compare.ne": lambda: left != right,
                    "compare.lt": lambda: left < right, "compare.le": lambda: left <= right,
                    "compare.gt": lambda: left > right, "compare.ge": lambda: left >= right}[op]()
        if op in {"int.add.checked", "int.add.wrap"}:
            value = left + right
        elif op in {"int.sub.checked", "int.sub.wrap"}:
            value = left - right
        elif op in {"int.mul.checked", "int.mul.wrap"}:
            value = left * right
        elif op in {"int.div.checked", "int.rem.checked"}:
            if right == 0 or (typ.startswith("i") and left == -(1 << (WIDTHS[typ] - 1)) and right == -1):
                raise _Trap("arithmetic: division by zero or signed overflow")
            quotient = abs(left) // abs(right) * (-1 if (left < 0) != (right < 0) else 1)
            value = quotient if op == "int.div.checked" else left - quotient * right
        elif op in {"int.shl.checked", "int.shr.checked"}:
            if not 0 <= right < WIDTHS[typ]:
                raise _Trap("arithmetic: shift count")
            return _bounded(left << right if op == "int.shl.checked" else left >> right, typ, wrap=True)
        elif op in {"bit.and", "bit.or", "bit.xor"}:
            value = {"bit.and": lambda: left & right, "bit.or": lambda: left | right,
                     "bit.xor": lambda: left ^ right}[op]()
        elif op in {"int.min", "int.max"}:
            value = min(left, right) if op == "int.min" else max(left, right)
        else:
            raise _Trap("unsupported executable opcode: " + op)
        return _bounded(value, typ, wrap=op.endswith(".wrap"))

    def block(self, ops, env, bindings=None):
        previous = dict(env)
        if bindings:
            env.update(bindings)
        aborted = False
        try:
            for op in ops:
                self.tick()
                kind = op["op"]
                if kind == "local.bind":
                    env[op["name"]] = _Cell(self.expr(op["value"], env), op["mutable"])
                elif kind == "place.write":
                    value, target = self.expr(op["value"], env), op["target"]
                    if target["op"] == "local.get":
                        cell = self.cell(target, env)
                        if not cell.mutable or _owns(cell.value):
                            raise _Trap("resource: invalid local overwrite")
                        cell.value = value
                    else:
                        raw = self.sequence(target["args"][0], env)
                        root = target["args"][0]
                        if root["op"] == "local.get" and not env[root["name"]].mutable:
                            raise _Trap("resource: write through immutable binding")
                        owner = self.access(raw, write=True)
                        offset = self.expr(target["args"][1], env)
                        if not 0 <= offset < len(owner.data):
                            raise _Trap("bounds: byte store")
                        owner.data[offset] = _bounded(value, "u8")
                elif kind == "evaluate":
                    value = self.expr(op["value"], env)
                    if _owns(value):
                        raise _Trap("resource: discarded owner")
                elif kind == "return":
                    raise _Return(self.expr(op["value"], env))
                elif kind == "if":
                    self.block(op["then"] if self.expr(op["condition"], env) else op["otherwise"], env)
                elif kind == "while":
                    while self.expr(op["condition"], env):
                        self.block(op["body"], env)
                elif kind == "for":
                    start, end = self.expr(op["start"], env), self.expr(op["end"], env)
                    for value in range(start, end):
                        self.tick()
                        self.block(op["body"], env, {op["name"]: _Cell(value, False)})
                elif kind == "result.match":
                    value = self.expr(op["value"], env)
                    if not isinstance(value, _Result):
                        raise _Trap("type: Result required")
                    arm = next(a for a in op["arms"] if a["variant"] == value.variant)
                    binding = arm["bindings"][0]
                    if binding == "_" and _owns(value.value):
                        raise _Trap("resource: discarded Result owner")
                    self.block(arm["body"], env, {} if binding == "_" else {binding: _Cell(value.value, False)})
                else:
                    raise _Trap("unsupported executable statement: " + kind)
        except (_Trap, _Budget):
            aborted = True
            raise
        finally:
            if not aborted:
                for name, cell in env.items():
                    if previous.get(name) is not cell and _owns(cell.value):
                        raise _Trap("resource: scope exited with unconsumed owner " + name)
            env.clear()
            env.update(previous)

    def call(self, fn, values):
        self.tick()
        self.depth += 1
        if self.depth > 64:
            raise _Budget("call-depth budget exhausted")
        env = {param["name"]: _Cell(value, param["mode"] == "mut")
               for param, value in zip(fn["params"], values)}
        try:
            try:
                self.block(fn["body"], env)
                result = None
            except _Return as returned:
                result = returned.value
            if any(_owns(cell.value) for cell in env.values()):
                raise _Trap("resource: function returned with unconsumed parameter")
            return result
        finally:
            self.depth -= 1


def execute_verified_core(core, function, arguments, *, max_steps=1000000,
                          max_heap_bytes=1024 * 1024, allocation_fail_at=None):
    """Internal executor: callers must use executable_core.execute_executable_core.

    The public wrapper performs exact source replay. Limits distinguish
    harness exhaustion from the program's own checked abort behavior.
    """
    for value, maximum, label in [(max_steps, 10000000, "steps"),
                                  (max_heap_bytes, 16 * 1024 * 1024, "heap bytes")]:
        if type(value) is not int or not 1 <= value <= maximum:
            reject("Invalid interpreter " + label + " limit", "E_CORE_LIMIT")
    if allocation_fail_at is not None and (type(allocation_fail_at) is not int or not 1 <= allocation_fail_at <= 1000000):
        reject("Invalid allocation-failure injection", "E_CORE_LIMIT")
    if type(function) is not str or type(arguments) not in (list, tuple):
        reject("Entry function and argument list required", "E_CORE_ENTRY")
    runtime = _Runtime(core, max_steps, max_heap_bytes, allocation_fail_at)
    fn = runtime.functions.get(function)
    if fn is None or len(arguments) != len(fn["params"]):
        reject("Entry signature mismatch", "E_CORE_ENTRY")
    if (fn["returns"]["name"] not in SCALARS or any(p["mode"] != "value" or p["type"]["name"] not in SCALARS for p in fn["params"])):
        reject("External interpreter entries use scalar values only", "E_CORE_ENTRY")
    try:
        values = [_bounded(value, param["type"]["name"]) for value, param in zip(arguments, fn["params"])]
    except _Trap as exc:
        reject(str(exc), "E_CORE_ENTRY")
    result, diagnostic, status = None, None, "returned"
    try:
        result = runtime.call(fn, values)
        result = _bounded(result, fn["returns"]["name"])
        if any(owner.alive for owner in runtime.buffers.values()):
            raise _Trap("resource: scalar entry leaked an owner")
    except _Trap as exc:
        status, diagnostic = "trapped", str(exc)
    except _Budget as exc:
        status, diagnostic = "budget_exhausted", str(exc)
    return {"schema": "hepta.executable-core-execution.v1", "profile": PROFILE,
        "ok": status == "returned", "status": status, "function": function,
        "arguments": list(arguments), "result": result if status == "returned" else None,
        "diagnostic": diagnostic, "core_sha256": core["sha256"], "steps": runtime.steps,
        "limits": {"max_steps": max_steps, "max_heap_bytes": max_heap_bytes, "call_depth": 64},
        "allocation_failure_injection": allocation_fail_at,
        "resources": {"allocations": runtime.allocations, "frees": runtime.frees,
            "live_owners": sum(owner.alive for owner in runtime.buffers.values()),
            "live_bytes": runtime.live_bytes, "peak_live_bytes": runtime.peak_bytes,
            "allocation_refusals": runtime.refusals},
        "events": runtime.events,
        "claims": {"actual_core_operations_executed": True, "native_execution": False,
            "host_allocator_failure_observed": False, "termination_proved": False,
            "whole_language_soundness_proved": False}}
