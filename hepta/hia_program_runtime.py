"""Finite direct interpreter for standalone typed HIA operations.

No source AST, source compiler, LLVM, or producer receipt participates.  Defined
program traps and analysis budgets are different outcomes.  Resource counters
describe the stopped program state; traps/budget stops do not pretend that an
aborting native process performed normal-path destructor cleanup.
"""
from __future__ import annotations

from dataclasses import dataclass

from .hia_program import (HIAProgramRejected, RESOURCES, SCALARS, WIDTHS,
                          integer_range, scalar_value_valid, verify_program)


class HIAProgramTrap(ArithmeticError):
    """A specified aborting program operation, not an interpreter budget."""

    def __init__(self, code, message):
        self.code, self.report = code, None
        super().__init__(f"E_HIA_TRAP_{code.upper()}: {message}")


class HIAProgramBudgetExceeded(RuntimeError):
    """A finite evaluator resource limit; says nothing about termination."""

    def __init__(self, code, message):
        self.code, self.report = code, None
        super().__init__(f"E_HIA_BUDGET_{code.upper()}: {message}")


@dataclass(eq=False)
class _Owner:
    ident: int
    data: bytearray
    active: bool = True


@dataclass(eq=False)
class _View:
    parent: _Owner | _View
    mutable: bool
    active: bool = True


def _underlying(value):
    seen = set()
    while isinstance(value, _View):
        if not value.active or id(value) in seen:
            raise HIAProgramRejected("expired/cyclic runtime view", "E_HIA_RUNTIME_INVARIANT")
        seen.add(id(value))
        value = value.parent
    if not isinstance(value, _Owner) or not value.active:
        raise HIAProgramRejected("expired runtime owner", "E_HIA_RUNTIME_INVARIANT")
    return value


def _wrap(value, typ):
    width = WIDTHS[typ]
    value &= (1 << width) - 1
    if typ.startswith("i") and value >= (1 << (width - 1)):
        value -= 1 << width
    return value


def _checked(value, typ):
    lo, hi = integer_range(typ)
    if not lo <= value <= hi:
        raise HIAProgramTrap("overflow", f"result is outside {typ}")
    return value


class _Machine:
    def __init__(self, program, max_steps, max_heap_bytes, allocation_fail_at, max_call_depth):
        self.program = program
        self.functions = {f["name"]: f for f in program.as_dict()["functions"]}
        self.max_steps, self.max_heap_bytes = max_steps, max_heap_bytes
        self.allocation_fail_at, self.max_call_depth = allocation_fail_at, max_call_depth
        self.steps = self.allocations = self.frees = self.allocation_attempts = 0
        self.live_bytes = self.peak_bytes = self.owner_count = self.drops = 0
        self.loans_started = self.loans_ended = 0
        self.owners = {}

    def tick(self):
        self.steps += 1
        if self.steps > self.max_steps:
            raise HIAProgramBudgetExceeded("steps", "finite step limit reached")

    def resources(self):
        return {"allocations": self.allocations, "frees": self.frees,
                "allocation_attempts": self.allocation_attempts,
                "owners_created": self.owner_count, "owners_dropped": self.drops,
                "live_owners": len(self.owners), "live_bytes": self.live_bytes,
                "peak_bytes": self.peak_bytes,
                "loans_started": self.loans_started, "loans_ended": self.loans_ended,
                "live_local_loans": self.loans_started - self.loans_ended}

    def new_owner(self, data):
        self.owner_count += 1
        owner = _Owner(self.owner_count, data)
        self.owners[owner.ident] = owner
        if data:
            self.allocations += 1
        self.live_bytes += len(data)
        self.peak_bytes = max(self.peak_bytes, self.live_bytes)
        return owner

    def allocate(self, size, optional):
        # Zero-size owners are real capabilities but require no allocator call,
        # cannot fail, and do not consume the deterministic failure injection.
        if size == 0:
            return self.new_owner(bytearray()), True
        if size > (1 << 63) - 1:
            if optional:
                return self.new_owner(bytearray()), False
            raise HIAProgramTrap("allocation", "allocation exceeds the 64-bit object-size model")
        # A host evaluator budget is not reported as a program malloc failure.
        if size > self.max_heap_bytes - self.live_bytes:
            raise HIAProgramBudgetExceeded("heap", "finite live-byte limit reached")
        self.allocation_attempts += 1
        failed = self.allocation_fail_at == self.allocation_attempts
        if not failed:
            try:
                return self.new_owner(bytearray(size)), True
            except (MemoryError, OverflowError):
                failed = True
        if failed and optional:
            return self.new_owner(bytearray()), False
        raise HIAProgramTrap("allocation", "allocator returned failure")

    def drop(self, owner):
        owner = _underlying(owner)
        if owner.ident not in self.owners:
            raise HIAProgramRejected("duplicate runtime drop", "E_HIA_RUNTIME_INVARIANT")
        del self.owners[owner.ident]
        self.drops += 1
        if owner.data:
            self.frees += 1
        self.live_bytes -= len(owner.data)
        owner.active = False
        owner.data = bytearray()

    def operation(self, ins, env, depth):
        op, attrs = ins["op"], ins["attrs"]
        names = ins["args"]
        args = [env[name] for name in names]
        outputs = ins["out"]
        typ = outputs[0]["type"] if outputs else None
        result = []
        if op == "const":
            result = [attrs["value"]]
        elif op in {f"int.{a}.{m}" for a in ("add", "sub", "mul") for m in ("checked", "wrap")}:
            a, b = args
            kind = op.split(".")[1]
            value = a + b if kind == "add" else a - b if kind == "sub" else a * b
            result = [(_checked if op.endswith("checked") else _wrap)(value, typ)]
        elif op in {"int.div.checked", "int.rem.checked"}:
            a, b = args
            if b == 0:
                raise HIAProgramTrap("division_by_zero", "integer divisor is zero")
            lo, _ = integer_range(typ)
            if typ.startswith("i") and a == lo and b == -1:
                raise HIAProgramTrap("overflow", "signed minimum divided by minus one")
            quotient = abs(a) // abs(b)
            if (a < 0) != (b < 0):
                quotient = -quotient
            result = [quotient if op == "int.div.checked" else a - quotient * b]
        elif op in {"int.shl.checked", "int.shr.checked"}:
            a, b = args
            if not 0 <= b < WIDTHS[typ]:
                raise HIAProgramTrap("overflow", "shift count is outside the word width")
            result = [_wrap(a << b, typ) if op == "int.shl.checked" else a >> b]
        elif op == "int.neg.checked":
            result = [_checked(-args[0], typ)]
        elif op in {"bit.and", "bit.or", "bit.xor"}:
            a, b = args
            value = a & b if op == "bit.and" else a | b if op == "bit.or" else a ^ b
            result = [_wrap(value, typ)]
        elif op == "bit.not":
            result = [_wrap(~args[0], typ)]
        elif op.startswith("compare."):
            a, b = args
            result = [{"compare.eq": a == b, "compare.ne": a != b,
                       "compare.lt": a < b, "compare.le": a <= b,
                       "compare.gt": a > b, "compare.ge": a >= b}[op]]
        elif op == "bool.not":
            result = [not args[0]]
        elif op == "bool.and":
            result = [args[0] and args[1]]
        elif op == "bool.or":
            result = [args[0] or args[1]]
        elif op == "int.cast":
            result = [(_checked if attrs["mode"] == "checked" else _wrap)(args[0], typ)]
        elif op == "select":
            result = [args[1] if args[0] else args[2]]
        elif op in {"buffer.new", "buffer.try_new"}:
            owner, ok = self.allocate(args[0], op == "buffer.try_new")
            result = [owner] + ([ok] if op == "buffer.try_new" else [])
        elif op == "buffer.len":
            result = [len(_underlying(args[0]).data)]
        elif op in {"borrow.read", "borrow.mut"}:
            _underlying(args[0])
            result = [_View(args[0], op == "borrow.mut")]
            self.loans_started += 1
        elif op == "loan.end":
            view = args[0]
            _underlying(view)
            if not isinstance(view, _View):
                raise HIAProgramRejected("end of non-view", "E_HIA_RUNTIME_INVARIANT")
            view.active = False
            self.loans_ended += 1
            del env[names[0]]
        elif op == "owner.move":
            _underlying(args[0])
            result = [env.pop(names[0])]
        elif op == "owner.drop":
            self.drop(args[0])
            del env[names[0]]
        elif op == "buffer.load":
            owner, index = _underlying(args[0]), args[1]
            if index >= len(owner.data):
                raise HIAProgramTrap("bounds", "byte load outside the borrowed buffer")
            result = [owner.data[index]]
        elif op == "buffer.store":
            owner, index, value = _underlying(args[0]), args[1], args[2]
            if not isinstance(args[0], _View) or not args[0].mutable:
                raise HIAProgramRejected("write through non-mutable view", "E_HIA_RUNTIME_INVARIANT")
            if index >= len(owner.data):
                raise HIAProgramTrap("bounds", "byte store outside the borrowed buffer")
            owner.data[index] = value
        elif op == "buffer.fill":
            owner, value = _underlying(args[0]), args[1]
            if not isinstance(args[0], _View) or not args[0].mutable:
                raise HIAProgramRejected("fill without a mutable view", "E_HIA_RUNTIME_INVARIANT")
            # One verified operation, with no byte-by-byte interpreter overhead.
            # This may allocate temporary Python storage, not a Core owner.
            try:
                owner.data[:] = bytes((value,)) * len(owner.data)
            except MemoryError as exc:
                raise HIAProgramBudgetExceeded("host_memory", "bulk fill exceeds host memory") from exc
        elif op == "buffer.copy":
            destination, source, size = _underlying(args[0]), _underlying(args[1]), args[2]
            if not isinstance(args[0], _View) or not args[0].mutable or not isinstance(args[1], _View):
                raise HIAProgramRejected("copy requires checked mutable and shared loans", "E_HIA_RUNTIME_INVARIANT")
            if destination is source:
                raise HIAProgramRejected("copy alias escaped static owner verification", "E_HIA_RUNTIME_INVARIANT")
            if size > len(destination.data) or size > len(source.data):
                raise HIAProgramTrap("bounds", "bulk copy exceeds an owner extent")
            # Distinct live allocations are guaranteed by the verified roots.
            memoryview(destination.data)[:size] = memoryview(source.data)[:size]
        elif op == "buffer.move_within":
            # Exact memmove semantics, including overlapping byte ranges.
            # All offsets are already verified usize; prove each subrange
            # fits before any write (subtraction cannot underflow here).
            owner = _underlying(args[0])
            destination, source, size = args[1:]
            if not isinstance(args[0], _View) or not args[0].mutable:
                raise HIAProgramRejected("in-place move needs a unique mutable loan",
                                         "E_HIA_RUNTIME_INVARIANT")
            extent = len(owner.data)
            if (destination > extent or source > extent
                    or size > extent - destination or size > extent - source):
                raise HIAProgramTrap("bounds", "in-place byte range exceeds owned extent")
            if size:
                # RHS materializes an independent bytearray snapshot, so
                # overlapping regions copy as if through a temporary.
                try:
                    owner.data[destination:destination + size] = owner.data[source:source + size]
                except MemoryError as exc:
                    raise HIAProgramBudgetExceeded(
                        "host_memory", "in-place copy needs temporary host memory") from exc
        elif op == "call":
            callee = self.functions[attrs["function"]]
            for name, param in zip(names, callee["params"]):
                if param["type"] == "buffer":
                    del env[name]
            result = self.invoke(callee, args, depth + 1)
        else:
            raise HIAProgramRejected("unhandled verified opcode", "E_HIA_RUNTIME_INVARIANT")
        if len(result) != len(outputs):
            raise HIAProgramRejected("runtime result arity mismatch", "E_HIA_RUNTIME_INVARIANT")
        for output, value in zip(outputs, result):
            if output["type"] in SCALARS and not scalar_value_valid(value, output["type"]):
                raise HIAProgramRejected("runtime produced an invalid scalar", "E_HIA_RUNTIME_INVARIANT")
            env[output["name"]] = value

    def invoke(self, fn, arguments, depth=0):
        if depth > self.max_call_depth:
            raise HIAProgramBudgetExceeded("calls", "finite call-depth limit reached")
        self.tick()
        blocks = {b["id"]: b for b in fn["blocks"]}
        current = fn["entry"]
        env = {p["name"]: a for p, a in zip(fn["params"], arguments)}
        while True:
            block = blocks[current]
            for ins in block["ops"]:
                self.tick()
                self.operation(ins, env, depth)
            self.tick()
            term = block["term"]
            if term["op"] == "ret":
                return [env[name] for name in term["values"]]
            if term["op"] == "trap":
                raise HIAProgramTrap(term["code"], "explicit core trap")
            edge = term if term["op"] == "jump" else term["then"] if env[term["cond"]] else term["else"]
            target = blocks[edge["target"]]
            values = [env[name] for name in edge["args"]]
            # All block inputs are evaluated simultaneously. Loop iterations
            # create new dynamic instances of the same static SSA names.
            env = {p["name"]: a for p, a in zip(target["params"], values)}
            current = target["id"]

    def report(self, function, status, values=None, error=None):
        result = {"schema": "hepta.hia.program-execution.v1", "status": status,
                  "program_sha256": self.program.sha256, "function": function,
                  "steps": self.steps, "resources": self.resources(),
                  "word_bits": 64, "source_used": False,
                  "claims": {"finite_core_execution": True,
                             "whole_language_soundness_proved": False,
                             "backend_refinement_proved": False}}
        if values is not None:
            result["values"] = values
            result["result"] = values[0] if len(values) == 1 else values
        if error is not None:
            result["error"] = {"code": error.code, "message": str(error)}
        return result


def execute_program(program, function, arguments, *, max_steps=1_000_000,
                    max_heap_bytes=16 * 1024 * 1024, allocation_fail_at=None,
                    max_call_depth=256):
    """Verify immutable bytes, then execute a scalar public entry point.

    Owners and views can be created, moved and called internally. Python callers
    cannot fabricate them: public interpreter inputs/outputs are scalar values.
    Resource-returning functions remain available as internal core functions.
    """
    checked = verify_program(program)
    if (type(function) is not str or type(arguments) not in (list, tuple)
            or type(max_steps) is not int or not 1 <= max_steps <= 10_000_000
            or type(max_heap_bytes) is not int or not 0 <= max_heap_bytes <= 1024 * 1024 * 1024
            or type(max_call_depth) is not int or not 1 <= max_call_depth <= 256
            or allocation_fail_at is not None and
               (type(allocation_fail_at) is not int or allocation_fail_at < 1)):
        raise HIAProgramRejected("invalid entry arguments/evaluator limits", "E_HIA_INPUT")
    machine = _Machine(checked, max_steps, max_heap_bytes, allocation_fail_at, max_call_depth)
    fn = machine.functions.get(function)
    if fn is None or len(fn["params"]) != len(arguments):
        raise HIAProgramRejected("unknown entry/wrong argument count", "E_HIA_INPUT")
    if any(p["type"] in RESOURCES for p in fn["params"]) or any(t in RESOURCES for t in fn["returns"]):
        raise HIAProgramRejected("public evaluator boundary cannot carry capabilities", "E_HIA_INPUT")
    if any(not scalar_value_valid(a, p["type"]) for p, a in zip(fn["params"], arguments)):
        raise HIAProgramRejected("entry arguments are not exactly typed machine values", "E_HIA_INPUT")
    try:
        values = machine.invoke(fn, list(arguments))
    except HIAProgramTrap as exc:
        exc.report = machine.report(function, "trapped", error=exc)
        raise
    except HIAProgramBudgetExceeded as exc:
        exc.report = machine.report(function, "budget_exceeded", error=exc)
        raise
    except RecursionError as exc:
        limit = HIAProgramBudgetExceeded("calls", "host recursion limit reached")
        limit.report = machine.report(function, "budget_exceeded", error=limit)
        raise limit from exc
    if machine.owners or machine.loans_started != machine.loans_ended:
        raise HIAProgramRejected("successful scalar entry leaked a verified resource", "E_HIA_RUNTIME_INVARIANT")
    return machine.report(function, "returned", values)
