"""Standalone HIA v1: closed, typed SSA blocks with checked resource flow.

The authority is this program's operations, not a source file, producer hash,
claim, or source-checker receipt.  Blocks are closed: all incoming values are
explicit block parameters.  The profile has 64-bit usize/isize, byte owners,
lexical/reborrowed views, finite machine integers and non-escaping call loans.

This is an executable checker, not a machine-checked soundness/refinement proof.
In particular explicit/arithmetic traps abort; cleanup is required at ordinary
returns (including error-as-value returns), not promised after an abort.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from hashlib import sha256
import json
import re


SCHEMA = "hepta.hia.program.v1"
SCHEMA_V2 = "hepta.hia.program.v2"
SCHEMA_V3 = "hepta.hia.program.v3"
SCHEMA_V4 = "hepta.hia.program.v4"
SCHEMA_V5 = "hepta.hia.program.v5"
PROFILE = "closed-ssa-integer-byte-resources-64-v1"
PROFILE_V2 = "closed-ssa-integer-byte-resources-bulk-64-v2"
PROFILE_V3 = "closed-ssa-integer-byte-resources-overlap-64-v3"
PROFILE_V4 = "closed-ssa-integer-byte-resources-swap-64-v4"
PROFILE_V5 = "closed-ssa-integer-byte-resources-offset-copy-64-v5"
WORD_BITS = 64
WIDTHS = {**{f"{s}{n}": n for s in ("i", "u") for n in (8, 16, 32, 64)},
          "isize": 64, "usize": 64}
SCALARS = frozenset(WIDTHS) | {"bool", "unit"}
RESOURCES = frozenset({"buffer", "readbuf", "mutbuf"})
TYPES = SCALARS | RESOURCES
EFFECTS = frozenset({"alloc", "read", "write", "trap"})
TRAP_CODES = frozenset({"user", "overflow", "division_by_zero", "bounds", "allocation"})
_IDENT = re.compile(r"[A-Za-z_][A-Za-z_0-9]{0,127}\Z")
_RESERVED_FUNCTIONS = frozenset({"abort", "calloc", "malloc", "free", "memcpy", "memmove", "memset"})
MAX_BYTES = 8 * 1024 * 1024
MAX_NODES = 262144
MAX_DEPTH = 64
MAX_FUNCTIONS = 1024
MAX_BLOCKS = 4096


class HIAProgramRejected(ValueError):
    """Malformed, unsupported or statically unsafe standalone core."""

    def __init__(self, message, code="E_HIA_PROGRAM"):
        self.code = code
        super().__init__(f"{code}: {message}")


def _reject(message, code="E_HIA_PROGRAM"):
    raise HIAProgramRejected(message, code)


def _keys(value, fields, where):
    if type(value) is not dict or set(value) != set(fields):
        _reject(f"{where}: expected exactly {', '.join(sorted(fields))}", "E_HIA_FORMAT")


def _ident(value, where):
    if (type(value) is not str or _IDENT.fullmatch(value) is None
            or value.startswith("__hia_")):
        _reject(f"{where}: invalid/reserved ASCII identifier", "E_HIA_NAME")
    return value


def _type(value):
    if type(value) is not str or value not in TYPES:
        _reject("type is outside the closed v1 profile", "E_HIA_TYPE")
    return value


def integer_range(typ):
    if typ not in WIDTHS:
        _reject("expected integer type", "E_HIA_TYPE")
    width = WIDTHS[typ]
    signed = typ.startswith("i")
    return (-(1 << (width - 1)), (1 << (width - 1)) - 1) if signed else (0, (1 << width) - 1)


def scalar_value_valid(value, typ):
    if typ in WIDTHS:
        lo, hi = integer_range(typ)
        return type(value) is int and lo <= value <= hi
    if typ == "bool":
        return type(value) is bool
    if typ == "unit":
        return value is None
    return False


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _reject("duplicate JSON object field", "E_HIA_FORMAT")
        result[key] = value
    return result


def _bad_constant(value):
    _reject("nonfinite JSON value", "E_HIA_FORMAT")


def _structure(value):
    pending, count = [(value, 0)], 0
    while pending:
        current, depth = pending.pop()
        count += 1
        if count > MAX_NODES or depth > MAX_DEPTH:
            _reject("program exceeds structural budget", "E_HIA_LIMIT")
        if type(current) is dict:
            if any(type(k) is not str for k in current):
                _reject("non-string JSON key", "E_HIA_FORMAT")
            pending.extend((v, depth + 1) for v in current.values())
        elif type(current) is list:
            pending.extend((v, depth + 1) for v in current)
        elif type(current) not in (str, int, bool, type(None)):
            _reject("only bounded integer JSON values are supported", "E_HIA_FORMAT")


def _decode(value):
    if isinstance(value, VerifiedProgram):
        value = value.canonical_bytes
    try:
        if type(value) is bytes:
            if len(value) > MAX_BYTES:
                _reject("program exceeds byte budget", "E_HIA_LIMIT")
            value = value.decode("utf-8")
        if type(value) is str:
            if len(value.encode("utf-8")) > MAX_BYTES:
                _reject("program exceeds byte budget", "E_HIA_LIMIT")
            value = json.loads(value, object_pairs_hook=_unique_pairs,
                               parse_constant=_bad_constant)
        _structure(value)
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False, allow_nan=False).encode("utf-8")
        if len(raw) > MAX_BYTES:
            _reject("program exceeds byte budget", "E_HIA_LIMIT")
        # Validation uses a detached snapshot, never the caller's mutable dict.
        return json.loads(raw), raw
    except HIAProgramRejected:
        raise
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError) as exc:
        raise HIAProgramRejected("invalid/deep UTF-8 JSON", "E_HIA_FORMAT") from exc


@dataclass(frozen=True, slots=True)
class VerifiedProgram:
    """Immutable bytes, not an unforgeable receipt; consumers reverify them."""

    canonical_bytes: bytes

    @property
    def sha256(self):
        return sha256(self.canonical_bytes).hexdigest()

    @property
    def canonical_json(self):
        return self.canonical_bytes.decode("utf-8")

    def as_dict(self):
        return json.loads(self.canonical_bytes)

    def report(self):
        # This public constructor is intentionally not an authority. Even a
        # report rechecks the immutable bytes instead of trusting its class.
        checked = verify_program(self)
        data = checked.as_dict()
        profile = (PROFILE_V5 if data["schema"] == SCHEMA_V5 else
                   PROFILE_V4 if data["schema"] == SCHEMA_V4 else
                   PROFILE_V3 if data["schema"] == SCHEMA_V3 else
                   PROFILE_V2 if data["schema"] == SCHEMA_V2 else PROFILE)
        return {"schema": "hepta.hia.program-verification.v1", "ok": True,
                "profile": profile, "program_sha256": checked.sha256,
                "word_bits": WORD_BITS, "functions_checked": len(data["functions"]),
                "blocks_checked": sum(len(f["blocks"]) for f in data["functions"]),
                "source_required": False,
                "claims": {"typed_closed_ssa_checked": True,
                           "linear_resources_and_loan_provenance_checked": True,
                           "whole_language_soundness_proved": False,
                           "backend_refinement_proved": False,
                           "foreign_code_supported": False,
                           "escaping_loans_supported": False,
                           "concurrency_supported": False}}


@dataclass(frozen=True)
class _Capability:
    typ: str
    root: str
    parent: str | None = None
    external: bool = False


def _parameters(value, where):
    if type(value) is not list:
        _reject(f"{where}: expected parameter list", "E_HIA_FORMAT")
    seen = set()
    for param in value:
        _keys(param, {"name", "type"}, where)
        name = _ident(param["name"], where)
        _type(param["type"])
        if name in seen:
            _reject(f"{where}: duplicate parameter {name}", "E_HIA_SSA")
        seen.add(name)
    return value


def _names(value, where):
    if type(value) is not list:
        _reject(f"{where}: expected value list", "E_HIA_FORMAT")
    for name in value:
        _ident(name, where)
    return value


def _edge(value):
    _keys(value, {"target", "args"}, "CFG edge")
    _ident(value["target"], "edge target")
    _names(value["args"], "edge arguments")
    return value


def _edges(term):
    if type(term) is not dict or type(term.get("op")) is not str:
        _reject("missing terminator", "E_HIA_CFG")
    op = term["op"]
    if op == "jump":
        _keys(term, {"op", "target", "args"}, "jump")
        return [_edge({"target": term["target"], "args": term["args"]})]
    if op == "branch":
        _keys(term, {"op", "cond", "then", "else"}, "branch")
        _ident(term["cond"], "branch condition")
        return [_edge(term["then"]), _edge(term["else"])]
    if op == "ret":
        _keys(term, {"op", "values"}, "return")
        _names(term["values"], "return values")
        return []
    if op == "trap":
        _keys(term, {"op", "code"}, "trap")
        if type(term["code"]) is not str or term["code"] not in TRAP_CODES:
            _reject("unknown trap code", "E_HIA_CFG")
        return []
    _reject("unknown terminator", "E_HIA_CFG")


def _function_shape(fn):
    _keys(fn, {"name", "params", "returns", "effects", "entry", "blocks"}, "function")
    name = _ident(fn["name"], "function")
    if name in _RESERVED_FUNCTIONS:
        _reject("function collides with native runtime symbol", "E_HIA_NAME")
    _parameters(fn["params"], "function parameters")
    if type(fn["returns"]) is not list:
        _reject("returns must be a list", "E_HIA_TYPE")
    for typ in fn["returns"]:
        _type(typ)
        if typ in {"readbuf", "mutbuf"}:
            _reject("call loans may not escape in v1", "E_HIA_LOAN")
    effects = fn["effects"]
    if (type(effects) is not list or any(type(e) is not str or e not in EFFECTS for e in effects)
            or len(effects) != len(set(effects))):
        _reject("unknown/duplicate function effect", "E_HIA_EFFECT")
    _ident(fn["entry"], "entry")
    if type(fn["blocks"]) is not list or not 1 <= len(fn["blocks"]) <= MAX_BLOCKS:
        _reject("invalid block inventory", "E_HIA_CFG")
    by_id, definitions = {}, set()
    for block in fn["blocks"]:
        _keys(block, {"id", "params", "ops", "term"}, "block")
        ident = _ident(block["id"], "block id")
        if ident in by_id:
            _reject("duplicate block", "E_HIA_CFG")
        by_id[ident] = block
        params = _parameters(block["params"], "block parameters")
        if type(block["ops"]) is not list:
            _reject("block operations must be a list", "E_HIA_FORMAT")
        current = [p["name"] for p in params]
        for instruction in block["ops"]:
            _keys(instruction, {"op", "args", "out", "attrs"}, "instruction")
            if type(instruction["op"]) is not str:
                _reject("opcode must be text", "E_HIA_FORMAT")
            _names(instruction["args"], "instruction arguments")
            outputs = _parameters(instruction["out"], "instruction outputs")
            if type(instruction["attrs"]) is not dict:
                _reject("instruction attributes must be an object", "E_HIA_FORMAT")
            current.extend(p["name"] for p in outputs)
        for value in current:
            if value in definitions:
                _reject(f"SSA value {value} is defined more than once", "E_HIA_SSA")
            definitions.add(value)
        _edges(block["term"])
    if fn["entry"] not in by_id or by_id[fn["entry"]]["params"] != fn["params"]:
        _reject("entry parameters must equal the function signature", "E_HIA_CFG")
    graph = {}
    for ident, block in by_id.items():
        graph[ident] = []
        for edge in _edges(block["term"]):
            if edge["target"] not in by_id:
                _reject("jump to missing block", "E_HIA_CFG")
            if edge["target"] == fn["entry"]:
                _reject("entry cannot have incoming CFG edges; use a loop header", "E_HIA_CFG")
            if len(edge["args"]) != len(by_id[edge["target"]]["params"]):
                _reject("edge arity differs from block parameters", "E_HIA_CFG")
            graph[ident].append(edge["target"])
    pending, reached = [fn["entry"]], set()
    while pending:
        ident = pending.pop()
        if ident in reached:
            continue
        reached.add(ident)
        pending.extend(graph[ident])
    if reached != set(by_id):
        _reject("unreachable blocks are not admitted", "E_HIA_CFG")
    return by_id


class _BlockCheck:
    def __init__(self, fn, block, capabilities, functions, *, bulk_memory=False, inplace_memory=False, byte_swap=False, offset_copy=False):
        self.fn, self.block, self.functions = fn, block, functions
        self.bulk_memory = bulk_memory
        self.inplace_memory = inplace_memory
        self.byte_swap = byte_swap
        self.offset_copy = offset_copy
        self.env = {p["name"]: p["type"] for p in block["params"]}
        self.caps = dict(capabilities)
        self.required = set()

    def value(self, name):
        if name not in self.env:
            _reject(f"{self.fn['name']}/{self.block['id']}: undefined/nonlocal value {name}", "E_HIA_SSA")
        typ = self.env[name]
        if typ in RESOURCES and name not in self.caps:
            _reject(f"use of consumed resource {name}", "E_HIA_RESOURCE")
        return typ

    def children(self, name):
        return [n for n, cap in self.caps.items() if cap.parent == name]

    def ancestors(self, name):
        out = set()
        while self.caps[name].parent is not None:
            name = self.caps[name].parent
            if name in out or name not in self.caps:
                _reject("invalid loan parent graph", "E_HIA_LOAN")
            out.add(name)
        return out

    def owner_free(self, name):
        if self.value(name) != "buffer":
            _reject("operation requires an owner", "E_HIA_TYPE")
        if any(cap.root == name and other != name for other, cap in self.caps.items()):
            _reject("owner moved/dropped/returned while borrowed", "E_HIA_LOAN")

    def access(self, name, mutable=False):
        typ = self.value(name)
        if typ not in ({"mutbuf"} if mutable else {"readbuf", "mutbuf"}):
            _reject("memory access requires appropriate view", "E_HIA_TYPE")
        if self.children(name):
            _reject("parent view is suspended until child loans end", "E_HIA_LOAN")

    def borrow(self, source, output, mutable):
        typ = self.value(source)
        allowed = {"buffer", "mutbuf"} if mutable else RESOURCES
        if typ not in allowed:
            _reject("invalid borrow permission", "E_HIA_LOAN")
        root = self.caps[source].root
        allowed_ancestors = self.ancestors(source) | {source}
        others = [cap for name, cap in self.caps.items()
                  if cap.root == root and name not in allowed_ancestors]
        if mutable and others or not mutable and any(c.typ == "mutbuf" for c in others):
            _reject("conflicting live borrow", "E_HIA_LOAN")
        self.caps[output] = _Capability("mutbuf" if mutable else "readbuf", root, source)

    def instruction(self, ins):
        op, args, out, attrs = ins["op"], ins["args"], ins["out"], ins["attrs"]
        actual = [self.value(a) for a in args]
        names, types = [o["name"] for o in out], [o["type"] for o in out]
        expected = None

        def arity(n):
            if len(args) != n:
                _reject(f"{op}: wrong operand count", "E_HIA_TYPE")

        def integer_binary():
            arity(2)
            if actual[0] not in WIDTHS or actual[0] != actual[1]:
                _reject(f"{op}: same-width integer operands required", "E_HIA_TYPE")
            return actual[0]

        if op == "const":
            _keys(attrs, {"value"}, op)
            arity(0)
            if len(out) != 1 or not scalar_value_valid(attrs["value"], types[0]):
                _reject("constant must be an exactly typed scalar", "E_HIA_TYPE")
            expected = types
        elif op in {f"int.{a}.{m}" for a in ("add", "sub", "mul") for m in ("checked", "wrap")}:
            expected = [integer_binary()]
            if op.endswith("checked"):
                self.required.add("trap")
        elif op in {"int.div.checked", "int.rem.checked", "int.shl.checked", "int.shr.checked"}:
            expected = [integer_binary()]
            self.required.add("trap")
        elif op in {"bit.and", "bit.or", "bit.xor"}:
            expected = [integer_binary()]
        elif op in {"bit.not", "int.neg.checked"}:
            arity(1)
            if actual[0] not in WIDTHS:
                _reject("integer unary operand required", "E_HIA_TYPE")
            expected = actual
            if op == "int.neg.checked":
                self.required.add("trap")
        elif op.startswith("compare.") and op[8:] in {"eq", "ne", "lt", "le", "gt", "ge"}:
            arity(2)
            if (actual[0] != actual[1] or actual[0] not in WIDTHS
                    and not (actual[0] == "bool" and op in {"compare.eq", "compare.ne"})):
                _reject("comparison operands have incompatible types", "E_HIA_TYPE")
            expected = ["bool"]
        elif op in {"bool.not", "bool.and", "bool.or"}:
            arity(1 if op == "bool.not" else 2)
            if any(t != "bool" for t in actual):
                _reject("boolean operands required", "E_HIA_TYPE")
            expected = ["bool"]
        elif op == "int.cast":
            _keys(attrs, {"mode"}, op)
            arity(1)
            if (actual[0] not in WIDTHS or len(types) != 1 or types[0] not in WIDTHS
                    or type(attrs["mode"]) is not str or attrs["mode"] not in {"checked", "wrap"}):
                _reject("unsupported integer cast", "E_HIA_TYPE")
            expected = types
            if attrs["mode"] == "checked":
                self.required.add("trap")
        elif op == "select":
            arity(3)
            if actual[0] != "bool" or actual[1] != actual[2] or actual[1] not in SCALARS:
                _reject("select is restricted to compatible scalar values", "E_HIA_TYPE")
            expected = [actual[1]]
        elif op in {"buffer.new", "buffer.try_new"}:
            arity(1)
            if actual != ["usize"]:
                _reject("allocation size must be usize", "E_HIA_TYPE")
            expected = ["buffer"] + (["bool"] if op == "buffer.try_new" else [])
            self.required.add("alloc")
            if op == "buffer.new":
                self.required.add("trap")
        elif op == "buffer.len":
            arity(1)
            if actual[0] not in RESOURCES:
                _reject("buffer length requires owner/view", "E_HIA_TYPE")
            expected = ["usize"]
        elif op in {"borrow.read", "borrow.mut"}:
            arity(1)
            expected = ["readbuf" if op == "borrow.read" else "mutbuf"]
        elif op == "loan.end":
            arity(1)
            if actual[0] not in {"readbuf", "mutbuf"}:
                _reject("loan.end requires a view", "E_HIA_TYPE")
            if self.caps[args[0]].external:
                _reject("callee cannot end its caller's loan", "E_HIA_LOAN")
            if self.children(args[0]):
                _reject("end child loans before their parent", "E_HIA_LOAN")
            expected = []
        elif op in {"owner.move", "owner.drop"}:
            arity(1)
            self.owner_free(args[0])
            expected = ["buffer"] if op == "owner.move" else []
            if op == "owner.drop":
                self.required.add("alloc")
        elif op == "buffer.load":
            arity(2)
            self.access(args[0])
            if actual[1] != "usize":
                _reject("buffer index must be usize", "E_HIA_TYPE")
            expected = ["u8"]
            self.required.update({"read", "trap"})
        elif op == "buffer.store":
            arity(3)
            self.access(args[0], True)
            if actual[1:] != ["usize", "u8"]:
                _reject("store needs usize index and u8 value", "E_HIA_TYPE")
            expected = []
            self.required.update({"write", "trap"})
        elif op == "buffer.fill":
            if not self.bulk_memory:
                _reject("bulk byte operations require HIA program v2", "E_HIA_OPCODE")
            arity(2)
            self.access(args[0], True)
            if actual != ["mutbuf", "u8"]:
                _reject("fill requires a mutable byte view and u8 value", "E_HIA_TYPE")
            expected = []
            self.required.add("write")
        elif op == "buffer.copy":
            if not self.bulk_memory:
                _reject("bulk byte operations require HIA program v2", "E_HIA_OPCODE")
            arity(3)
            self.access(args[0], True)
            self.access(args[1])
            if actual != ["mutbuf", "readbuf", "usize"]:
                _reject("copy requires distinct mutable/read byte views and usize length", "E_HIA_TYPE")
            if self.caps[args[0]].root == self.caps[args[1]].root:
                _reject("bulk copy aliases the destination owner", "E_HIA_LOAN")
            expected = []
            self.required.update({"read", "write", "trap"})
        elif op == "buffer.move_within":
            # v3: overlapping source/destination ranges in ONE uniquely
            # borrowed allocation. Unlike v2 buffer.copy, this is memmove.
            if not self.inplace_memory:
                _reject("in-place overlapping move requires HIA program v3", "E_HIA_OPCODE")
            arity(4)
            self.access(args[0], True)
            if actual != ["mutbuf", "usize", "usize", "usize"]:
                _reject("in-place move requires mutbuf, dest, source, length as usize", "E_HIA_TYPE")
            expected = []
            self.required.update({"read", "write", "trap"})
        elif op == "buffer.copy_range":
            # v5: checked offset memcpy between two *distinct* owner roots.
            if not self.offset_copy:
                _reject("offset copy requires HIA program v5", "E_HIA_OPCODE")
            arity(5)
            self.access(args[0], True)
            self.access(args[1])
            if actual != ["mutbuf", "readbuf", "usize", "usize", "usize"]:
                _reject("copy_range needs mutable/read views and three usize offsets", "E_HIA_TYPE")
            if self.caps[args[0]].root == self.caps[args[1]].root:
                _reject("copy_range may not alias one owner", "E_HIA_LOAN")
            expected = []
            self.required.update({"read", "write", "trap"})
        elif op == "buffer.swap":
            # v4: two byte positions in ONE live uniquely borrowed owner.
            # The runtime and LLVM must check BOTH bounds before mutation.
            if not self.byte_swap:
                _reject("byte swap requires HIA program v4", "E_HIA_OPCODE")
            arity(3)
            self.access(args[0], True)
            if actual != ["mutbuf", "usize", "usize"]:
                _reject("swap requires mutbuf, left, right as usize", "E_HIA_TYPE")
            expected = []
            self.required.update({"read", "write", "trap"})
        elif op == "call":
            _keys(attrs, {"function"}, op)
            callee_name = _ident(attrs["function"], "callee")
            if callee_name not in self.functions:
                _reject("unknown callee", "E_HIA_CALL")
            callee = self.functions[callee_name]
            if len(args) != len(callee["params"]):
                _reject("call arity mismatch", "E_HIA_CALL")
            used_owners, views = set(), []
            for name, typ, param in zip(args, actual, callee["params"]):
                formal = param["type"]
                if typ != formal and not (formal == "readbuf" and typ == "mutbuf"):
                    _reject("call argument type mismatch", "E_HIA_CALL")
                if typ == "buffer":
                    self.owner_free(name)
                    if name in used_owners:
                        _reject("owner supplied twice to call", "E_HIA_RESOURCE")
                    used_owners.add(name)
                elif typ in {"readbuf", "mutbuf"}:
                    self.access(name, formal == "mutbuf")
                    root = self.caps[name].root
                    if any(r == root and (m or formal == "mutbuf") for r, m in views):
                        _reject("aliased exclusive call arguments", "E_HIA_LOAN")
                    views.append((root, formal == "mutbuf"))
            expected = callee["returns"]
            self.required.update(callee["effects"])
        else:
            _reject(f"unsupported opcode {op}", "E_HIA_OPCODE")
        if op not in {"const", "int.cast", "call"}:
            _keys(attrs, set(), op)
        if types != expected:
            _reject(f"{op}: output types must be {expected}", "E_HIA_TYPE")

        # Resource transitions happen only after all operand/output checks.
        if op in {"buffer.new", "buffer.try_new"}:
            self.caps[names[0]] = _Capability("buffer", names[0])
        elif op in {"borrow.read", "borrow.mut"}:
            self.borrow(args[0], names[0], op == "borrow.mut")
        elif op in {"loan.end", "owner.drop"}:
            del self.caps[args[0]]
        elif op == "owner.move":
            del self.caps[args[0]]
            self.caps[names[0]] = _Capability("buffer", names[0])
        elif op == "call":
            for name, typ in zip(args, actual):
                if typ == "buffer":
                    del self.caps[name]
            for name, typ in zip(names, types):
                if typ == "buffer":
                    self.caps[name] = _Capability("buffer", name)
        self.env.update(zip(names, types))

    def transfer(self, edge, target):
        arguments = edge["args"]
        actual = [self.value(a) for a in arguments]
        if actual != [p["type"] for p in target["params"]]:
            _reject("edge values do not match block parameter types", "E_HIA_CFG")
        resources = [a for a, t in zip(arguments, actual) if t in RESOURCES]
        if len(resources) != len(set(resources)):
            _reject("linear capability duplicated across an edge", "E_HIA_RESOURCE")
        required = {name for name, cap in self.caps.items() if not cap.external}
        if not required.issubset(resources):
            _reject("edge drops a live owner or local loan", "E_HIA_RESOURCE")
        remap = {a: p["name"] for a, p in zip(arguments, target["params"])
                 if p["type"] in RESOURCES}
        result = {}
        for arg, param in zip(arguments, target["params"]):
            if param["type"] not in RESOURCES:
                continue
            cap = self.caps[arg]
            if cap.root not in remap or cap.parent is not None and cap.parent not in remap:
                _reject("loan must travel with its owner/parent capability", "E_HIA_LOAN")
            result[param["name"]] = _Capability(cap.typ, remap[cap.root],
                remap[cap.parent] if cap.parent is not None else None, cap.external)
        return result

    def finish(self):
        term = self.block["term"]
        if term["op"] == "branch" and self.value(term["cond"]) != "bool":
            _reject("branch condition is not bool", "E_HIA_CFG")
        if term["op"] == "ret":
            names = term["values"]
            types = [self.value(n) for n in names]
            if types != self.fn["returns"]:
                _reject("return type/arity mismatch", "E_HIA_TYPE")
            owners = [n for n, t in zip(names, types) if t == "buffer"]
            if len(owners) != len(set(owners)):
                _reject("same owner returned twice", "E_HIA_RESOURCE")
            for name in owners:
                self.owner_free(name)
                del self.caps[name]
            if any(not cap.external for cap in self.caps.values()):
                _reject("return leaves live owner/local loan", "E_HIA_RESOURCE")
        elif term["op"] == "trap":
            self.required.add("trap")
        if not self.required.issubset(self.fn["effects"]):
            _reject(f"missing effects {sorted(self.required - set(self.fn['effects']))}", "E_HIA_EFFECT")


def verify_program(program) -> VerifiedProgram:
    """Check standalone operations and every CFG edge; no source/hash authority.

    Even a manually constructed VerifiedProgram is parsed and fully rechecked.
    Caller-owned dictionaries and decoded dictionaries never back execution.
    """
    data, raw = _decode(program)
    _keys(data, {"schema", "module", "functions"}, "program")
    if data["schema"] not in {SCHEMA, SCHEMA_V2, SCHEMA_V3, SCHEMA_V4, SCHEMA_V5}:
        _reject("unsupported program schema", "E_HIA_SCHEMA")
    _ident(data["module"], "module")
    if type(data["functions"]) is not list or not 1 <= len(data["functions"]) <= MAX_FUNCTIONS:
        _reject("invalid function inventory", "E_HIA_FORMAT")
    functions, block_maps = {}, {}
    for fn in data["functions"]:
        blocks = _function_shape(fn)
        if fn["name"] in functions:
            _reject("duplicate function", "E_HIA_NAME")
        functions[fn["name"]], block_maps[fn["name"]] = fn, blocks
    for fn in functions.values():
        blocks = block_maps[fn["name"]]
        initial = {p["name"]: _Capability(p["type"], p["name"], external=p["type"] != "buffer")
                   for p in fn["params"] if p["type"] in RESOURCES}
        incoming = {fn["entry"]: initial}
        pending = deque([fn["entry"]])
        processed = set()
        while pending:
            ident = pending.popleft()
            if ident in processed:
                continue
            processed.add(ident)
            block = blocks[ident]
            check = _BlockCheck(fn, block, incoming[ident], functions,
                                bulk_memory=data["schema"] in {SCHEMA_V2, SCHEMA_V3, SCHEMA_V4, SCHEMA_V5},
                                inplace_memory=data["schema"] in {SCHEMA_V3, SCHEMA_V4, SCHEMA_V5},
                                byte_swap=data["schema"] in {SCHEMA_V4, SCHEMA_V5},
                                offset_copy=data["schema"] == SCHEMA_V5)
            for ins in block["ops"]:
                check.instruction(ins)
            check.finish()
            for edge in _edges(block["term"]):
                target = edge["target"]
                state = check.transfer(edge, blocks[target])
                if target in incoming and incoming[target] != state:
                    _reject("predecessors disagree on loan origins/permissions", "E_HIA_LOAN")
                if target not in incoming:
                    incoming[target] = state
                    pending.append(target)
        if processed != set(blocks):
            _reject("not all blocks were checked", "E_HIA_CFG")
    return VerifiedProgram(raw)


def execute_program(program, function, arguments, **kwargs):
    """Convenience entry point; implementation is an independent core consumer."""
    from .hia_program_runtime import execute_program as execute
    return execute(program, function, arguments, **kwargs)


# Public language-level spelling: verification of a program, not source replay.
verify_core = verify_program
