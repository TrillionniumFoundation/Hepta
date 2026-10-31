"""Finite direct interpreter for standalone typed HIA operations.

No source AST, source compiler, LLVM, or producer receipt participates.  Defined
program traps and analysis budgets are different outcomes.  Resource counters
describe the stopped program state; traps/budget stops do not pretend that an
aborting native process performed normal-path destructor cleanup.
"""
from __future__ import annotations

from dataclasses import dataclass

from .hia_program import (HIAProgramRejected, OWNERS, RESOURCES, SCALARS, WIDTHS,
                          integer_range, scalar_value_valid, verify_program)
from .hia_bounded_memory import fill_bytes, move_bytes
from .hia_schema import supports_feature
from .hia_opcodes import (CHAIN_NODE_STORAGE_BYTES, ExecutionObservationRejected,
                          validate_execution_observation)


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


@dataclass(eq=False)
class _ChainNode:
    storage: _Owner
    payload: _Owner
    tail: _ChainNode | None


@dataclass(eq=False)
class _Chain:
    ident: int
    head: _ChainNode | None
    active: bool = True


# The native v7 object model has a 16-byte buffer descriptor and one 8-byte
# successor pointer. Node storage is charged to the same live-byte budget as
# user buffers, and consumes the same allocation-failure sequence.
CHAIN_NODE_BYTES = CHAIN_NODE_STORAGE_BYTES


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
        document = program.as_dict()
        self.functions = {f["name"]: f for f in document["functions"]}
        self.recursive_chain = supports_feature(document["schema"], "recursive_chain")
        self.max_steps, self.max_heap_bytes = max_steps, max_heap_bytes
        self.allocation_fail_at, self.max_call_depth = allocation_fail_at, max_call_depth
        self.steps = self.allocations = self.frees = self.allocation_attempts = 0
        self.live_bytes = self.peak_bytes = self.owner_count = self.drops = 0
        self.loans_started = self.loans_ended = 0
        self.owners = {}
        self.chains = {}
        self.chains_created = self.chains_consumed = 0
        self.chain_nodes_created = self.chain_nodes_dropped = 0

    def tick(self):
        self.steps += 1
        if self.steps > self.max_steps:
            raise HIAProgramBudgetExceeded("steps", "finite step limit reached")

    def resources(self):
        result = {"allocations": self.allocations, "frees": self.frees,
                "allocation_attempts": self.allocation_attempts,
                "owners_created": self.owner_count, "owners_dropped": self.drops,
                "live_owners": len(self.owners), "live_bytes": self.live_bytes,
                "peak_bytes": self.peak_bytes,
                "loans_started": self.loans_started, "loans_ended": self.loans_ended,
                "live_local_loans": self.loans_started - self.loans_ended}
        # Existing profiles retain the original report shape. New counters
        # describe the recursive data structure independently of byte owners.
        if self.recursive_chain:
            result.update({"chains_created": self.chains_created,
                           "chains_consumed": self.chains_consumed,
                           "live_chains": len(self.chains),
                           "chain_nodes_created": self.chain_nodes_created,
                           "chain_nodes_dropped": self.chain_nodes_dropped,
                           "live_chain_nodes": self.chain_nodes_created - self.chain_nodes_dropped})
        return result

    def new_chain(self, head=None):
        self.chains_created += 1
        chain = _Chain(self.chains_created, head)
        self.chains[chain.ident] = chain
        return chain

    def chain_head(self, chain):
        if not isinstance(chain, _Chain) or not chain.active or self.chains.get(chain.ident) is not chain:
            raise HIAProgramRejected("expired runtime chain", "E_HIA_RUNTIME_INVARIANT")
        return chain.head

    def consume_chain(self, chain):
        head = self.chain_head(chain)
        del self.chains[chain.ident]
        chain.active, chain.head = False, None
        self.chains_consumed += 1
        return head

    def drop_chain(self, chain):
        head = self.consume_chain(chain)
        # Destruction is iterative. A runtime-sized list does not consume one
        # Python/native stack frame per node. Charge work to the step budget;
        # an interrupted destruction is a budget stop, not claimed cleanup.
        while head is not None:
            self.tick()
            tail = head.tail
            self.drop(head.payload)
            self.drop(head.storage)
            self.chain_nodes_dropped += 1
            head.tail = None
            head = tail

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
        elif op == "chain.empty":
            result = [self.new_chain()]
        elif op == "chain.try_push":
            chain, payload = args
            head = self.chain_head(chain)
            _underlying(payload)
            storage, ok = self.allocate(CHAIN_NODE_BYTES, True)
            if ok:
                node = _ChainNode(storage, payload, head)
                self.chain_nodes_created += 1
                fallback = self.new_owner(bytearray())
                self.consume_chain(chain)
                result = [self.new_chain(node), fallback, True]
            else:
                # The failed allocation's logical empty owner is internal.
                # Both caller-owned inputs survive in fresh output names.
                self.drop(storage)
                self.consume_chain(chain)
                result = [self.new_chain(head), payload, False]
            for name in names:
                del env[name]
        elif op == "chain.pop":
            head = self.consume_chain(args[0])
            if head is None:
                result = [self.new_chain(), self.new_owner(bytearray()), False]
            else:
                tail, payload = head.tail, head.payload
                self.drop(head.storage)
                self.chain_nodes_dropped += 1
                head.tail = None
                result = [self.new_chain(tail), payload, True]
            del env[names[0]]
        elif op == "chain.is_empty":
            result = [self.chain_head(args[0]) is None]
        elif op in {"chain.head_read", "chain.head_mut"}:
            head = self.chain_head(args[0])
            if head is None:
                raise HIAProgramTrap("bounds", "head borrow of an empty chain")
            _underlying(head.payload)
            result = [_View(head.payload, op == "chain.head_mut")]
            self.loans_started += 1
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
            if isinstance(args[0], _Chain):
                self.chain_head(args[0])
            else:
                _underlying(args[0])
            result = [env.pop(names[0])]
        elif op == "owner.drop":
            if isinstance(args[0], _Chain):
                self.drop_chain(args[0])
            else:
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
            # Bounded host scratch, not an O(owner_length) temporary.
            # The HIA Owner allocation and its declared effects are unchanged.
            try:
                fill_bytes(owner.data, 0, len(owner.data), value)
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
                # Match memmove overlap semantics without O(size) host scratch.
                try:
                    move_bytes(owner.data, destination, source, size)
                except MemoryError as exc:
                    raise HIAProgramBudgetExceeded(
                        "host_memory", "in-place copy exceeds host memory") from exc
        elif op == "buffer.fill_range":
            view, offset, size, value = args
            owner = _underlying(view)
            if not isinstance(view, _View) or not view.mutable:
                raise HIAProgramRejected("range fill requires unique mutable loan",
                                         "E_HIA_RUNTIME_INVARIANT")
            extent = len(owner.data)
            if offset > extent or size > extent - offset:
                raise HIAProgramTrap("bounds", "fill range exceeds owned extent")
            if size:
                try:
                    fill_bytes(owner.data, offset, size, value)
                except MemoryError as exc:
                    raise HIAProgramBudgetExceeded(
                        "host_memory", "range fill exceeds host memory") from exc
        elif op == "buffer.copy_range":
            dest_view, src_view = args[:2]
            destination, source = _underlying(dest_view), _underlying(src_view)
            dst_offset, src_offset, size = args[2:]
            if (not isinstance(dest_view, _View) or not dest_view.mutable
                    or not isinstance(src_view, _View) or destination is source):
                raise HIAProgramRejected("range copy violates checked distinct-owner loans",
                                         "E_HIA_RUNTIME_INVARIANT")
            dst_size, src_size = len(destination.data), len(source.data)
            if (dst_offset > dst_size or src_offset > src_size
                    or size > dst_size - dst_offset or size > src_size - src_offset):
                raise HIAProgramTrap("bounds", "cross-owner range copy exceeds byte extent")
            if size:
                memoryview(destination.data)[dst_offset:dst_offset + size] = (
                    memoryview(source.data)[src_offset:src_offset + size])
        elif op == "buffer.swap":
            owner = _underlying(args[0])
            left, right = args[1:]
            if not isinstance(args[0], _View) or not args[0].mutable:
                raise HIAProgramRejected("swap needs one live mutable borrow",
                                         "E_HIA_RUNTIME_INVARIANT")
            # Snapshot both source bytes before modifying either position.
            if left >= len(owner.data) or right >= len(owner.data):
                raise HIAProgramTrap("bounds", "swap byte offset outside owner extent")
            a, b = owner.data[left], owner.data[right]
            owner.data[left], owner.data[right] = b, a
        elif op == "call":
            callee = self.functions[attrs["function"]]
            for name, param in zip(names, callee["params"]):
                if param["type"] in OWNERS:
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
        # Root invocation occupies frame 1 (depth=0), matching the static
        # max_call_depth budget. A limit of N admits exactly N live frames.
        # Refuse the (N+1)th BEFORE its call-entry tick or any side effect.
        if depth >= self.max_call_depth:
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
                values = [env[name] for name in term["values"]]
                bindings = {p["name"]: a for p, a in zip(fn["params"], arguments)}
                for index, (typ, origin) in enumerate(zip(fn["returns"], fn.get("return_loans", [None] * len(values)))):
                    if typ not in {"readbuf", "mutbuf"}:
                        continue
                    value, parent = values[index], bindings[origin]
                    _underlying(value)
                    _underlying(parent)
                    if (not isinstance(value, _View) or not isinstance(parent, _View)
                            or typ == "mutbuf" and (not value.mutable or not parent.mutable)):
                        raise HIAProgramRejected("returned view permission invariant", "E_HIA_RUNTIME_INVARIANT")
                    if value is parent:
                        # Forwarding must not expose one consumable runtime view
                        # as both the caller's parent and its returned child.
                        values[index] = _View(parent, typ == "mutbuf")
                        self.loans_started += 1
                    elif value.parent is not parent:
                        raise HIAProgramRejected("returned view origin invariant", "E_HIA_RUNTIME_INVARIANT")
                return values
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
        resources = self.resources()
        try:
            validate_execution_observation(status, resources, steps=self.steps,
                max_steps=self.max_steps, max_heap_bytes=self.max_heap_bytes,
                error_code=error.code if error is not None else None,
                with_chains=self.recursive_chain, allow_host_memory=True)
        except ExecutionObservationRejected as exc:
            raise HIAProgramRejected(str(exc), "E_HIA_RUNTIME_INVARIANT") from exc
        result = {"schema": "hepta.hia.program-execution.v1", "status": status,
                  "program_sha256": self.program.sha256, "function": function,
                  "input_sha256": self.program.input_sha256,
                  "steps": self.steps, "resources": resources,
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
    # Validate and execute one immutable invocation. The caller may mutate an
    # exact list while scalar validation runs; rereading it after validation
    # could substitute an untyped value, change arity or alter an allocation
    # extent. Admitted scalar values themselves are immutable built-ins.
    arguments = tuple(arguments)
    if function not in checked.scalar_entrypoints:
        raise HIAProgramRejected("nominal/internal signatures are not public scalar entries", "E_HIA_INPUT")
    machine = _Machine(checked, max_steps, max_heap_bytes, allocation_fail_at, max_call_depth)
    fn = machine.functions.get(function)
    if fn is None or len(fn["params"]) != len(arguments):
        raise HIAProgramRejected("unknown entry/wrong argument count", "E_HIA_INPUT")
    if any(p["type"] in RESOURCES for p in fn["params"]) or any(t in RESOURCES for t in fn["returns"]):
        raise HIAProgramRejected("public evaluator boundary cannot carry capabilities", "E_HIA_INPUT")
    if any(not scalar_value_valid(a, p["type"]) for p, a in zip(fn["params"], arguments)):
        raise HIAProgramRejected("entry arguments are not exactly typed machine values", "E_HIA_INPUT")
    try:
        values = machine.invoke(fn, arguments)
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
    if machine.owners or machine.chains or machine.loans_started != machine.loans_ended:
        raise HIAProgramRejected("successful scalar entry leaked a verified resource", "E_HIA_RUNTIME_INVARIANT")
    return machine.report(function, "returned", values)
