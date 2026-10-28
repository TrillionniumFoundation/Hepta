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

from .hia_json_preflight import preflight_hia_json
from .hia_schema import (
    COMPOSITE_SCHEMA, COMPOSITE_SCHEMAS, PRIMITIVE_SCHEMAS, PROFILE, PROFILE_V2, PROFILE_V3,
    PROFILE_V4, PROFILE_V5, PROFILE_V6, PROFILE_V7, SCHEMA, SCHEMA_V2, SCHEMA_V3,
    SCHEMA_V4, SCHEMA_V5, SCHEMA_V6, SCHEMA_V7, profile_for_schema, supports_feature,
)
WORD_BITS = 64
WIDTHS = {**{f"{s}{n}": n for s in ("i", "u") for n in (8, 16, 32, 64)},
          "isize": 64, "usize": 64}
SCALARS = frozenset(WIDTHS) | {"bool", "unit"}
OWNERS = frozenset({"buffer", "chain"})
BYTE_RESOURCES = frozenset({"buffer", "readbuf", "mutbuf"})
RESOURCES = BYTE_RESOURCES | OWNERS
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
        _reject("type is outside the closed primitive profile", "E_HIA_TYPE")
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


def _json_string_bytes(value, remaining):
    """Exact UTF-8 length of ensure_ascii=False compact JSON string output.

    No escaped/encoded string is materialized during this preflight. In
    particular a short sequence of control characters may require six
    serialized bytes for every source character.
    """
    if len(value) + 2 > remaining:
        _reject("program exceeds byte budget before encoding", "E_HIA_LIMIT")
    size = 2  # opening and closing JSON quotes
    for char in value:
        point = ord(char)
        if point < 32:
            width = 2 if point in (8, 9, 10, 12, 13) else 6
        elif point in (34, 92):  # escaped double quote/backslash
            width = 2
        elif point < 0x80:
            width = 1
        elif 0xD800 <= point <= 0xDFFF:
            _reject("unpaired Unicode surrogate", "E_HIA_FORMAT")
        elif point < 0x800:
            width = 2
        elif point < 0x10000:
            width = 3
        else:
            width = 4
        size += width
        if size > remaining:
            _reject("program exceeds byte budget before encoding", "E_HIA_LIMIT")
    return size


def _structure(value):
    """Count exact canonical JSON bytes AND nodes before json.dumps.

    In-process dicts are not byte-bounded by the text preflight. The active
    identity set also refuses cycles, and queued leaf counts refuse huge
    container fanout before extending the work stack. This is a size gate,
    not a replacement for the canonical HIA typed SSA/ownership verifier.
    """
    pending = [(value, 0, False)]
    active = set()
    count, queued, size = 0, 1, 0
    while pending:
        current, depth, leaving = pending.pop()
        if leaving:
            active.remove(id(current))
            continue
        queued -= 1
        count += 1
        if count > MAX_NODES or depth > MAX_DEPTH:
            _reject("program exceeds structural budget", "E_HIA_LIMIT")
        if type(current) in (dict, list):
            identity = id(current)
            if identity in active:
                _reject("cyclic HIA JSON structure", "E_HIA_FORMAT")
            active.add(identity)
            children = len(current)
            if children > MAX_NODES - count - queued:
                _reject("program exceeds queued-node budget", "E_HIA_LIMIT")
            queued += children
            size += 2 + max(0, children - 1)  # container plus commas
            if type(current) is dict:
                size += children  # colons
                for key in current:
                    if type(key) is not str:
                        _reject("non-string JSON key", "E_HIA_FORMAT")
                    size += _json_string_bytes(key, MAX_BYTES - size)
                values = current.values()
            else:
                values = current
            pending.append((current, depth, True))
            pending.extend((child, depth + 1, False) for child in values)
        elif type(current) is str:
            size += _json_string_bytes(current, MAX_BYTES - size)
        elif type(current) is bool:
            size += 4 if current else 5
        elif type(current) is int:
            # Fail without converting a potentially enormous host integer
            # into a decimal string merely to discover it exceeds 8 MiB.
            if current.bit_length() > MAX_BYTES * 4:
                _reject("integer exceeds JSON byte budget", "E_HIA_LIMIT")
            size += len(str(current))
        elif current is None:
            size += 4
        else:
            _reject("only bounded integer JSON values are supported", "E_HIA_FORMAT")
        if size > MAX_BYTES:
            _reject("program exceeds byte budget before encoding", "E_HIA_LIMIT")
    return size


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
            # Enforce structural limits before json.loads allocates a complete
            # object graph. This is a syntax preflight, not a second parser or
            # a shortcut around the canonical v7/composite Core verifier.
            try:
                preflight_hia_json(value, max_nodes=MAX_NODES, max_depth=MAX_DEPTH)
            except OverflowError as exc:
                raise HIAProgramRejected(
                    "program exceeds structural budget before JSON allocation",
                    "E_HIA_LIMIT") from exc
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
    structured_bytes: bytes | None = None

    @property
    def sha256(self):
        return sha256(self.canonical_bytes).hexdigest()

    @property
    def canonical_json(self):
        return self.canonical_bytes.decode("utf-8")

    @property
    def input_sha256(self):
        return sha256(self.structured_bytes if self.structured_bytes is not None
                      else self.canonical_bytes).hexdigest()

    @property
    def scalar_entrypoints(self):
        # A nominal aggregate erased into scalar slots is still not a scalar
        # public signature.  Generated protocol helpers are internal too.
        document = self.as_dict()
        if "exports" in document:
            return frozenset(document["exports"])
        return frozenset(fn["name"] for fn in document["functions"]
                         if all(type(p["type"]) is str and p["type"] in SCALARS for p in fn["params"])
                         and all(type(t) is str and t in SCALARS for t in fn["returns"]))

    @property
    def normalization_report(self):
        checked = verify_program(self)
        core = checked.as_dict()
        original = (json.loads(checked.structured_bytes)
                    if checked.structured_bytes is not None else core)
        return {"input_sha256": checked.input_sha256,
                "core_sha256": checked.sha256,
                "input_schema": original["schema"],
                "input_profile": profile_for_schema(original["schema"]),
                "core_schema": core["schema"],
                "core_profile": profile_for_schema(core["schema"]),
                "structured_elaboration_rechecked": checked.structured_bytes is not None,
                "primitive_core_rechecked": True,
                "source_ast_required": False,
                "public_scalar_entrypoints": sorted(checked.scalar_entrypoints)}

    def as_dict(self):
        return json.loads(self.canonical_bytes)

    def report(self):
        # This public constructor is intentionally not an authority. Even a
        # report rechecks the immutable bytes instead of trusting its class.
        checked = verify_program(self)
        data = checked.as_dict()
        profile = profile_for_schema(data["schema"])
        return {"schema": "hepta.hia.program-verification.v1", "ok": True,
                "profile": profile, "program_sha256": checked.sha256,
                "input_sha256": checked.input_sha256,
                "normalization": checked.normalization_report,
                "word_bits": WORD_BITS, "functions_checked": len(data["functions"]),
                "blocks_checked": sum(len(f["blocks"]) for f in data["functions"]),
                "source_required": False,
                "claims": {"typed_closed_ssa_checked": True,
                           "linear_resources_and_loan_provenance_checked": True,
                           "whole_language_soundness_proved": False,
                           "backend_refinement_proved": False,
                           "foreign_code_supported": False,
                           "escaping_loans_supported": False,
                           "concurrency_supported": False,
                           "nominal_products_and_enums_checked": checked.structured_bytes is not None,
                           "local_stored_loan_identity_checked": checked.structured_bytes is not None,
                           "record_field_borrow_provenance_checked": checked.structured_bytes is not None,
                           "cooperative_task_protocol_checked": checked.structured_bytes is not None,
                           "background_tasks_supported": False,
                           "recursive_heap_adts_supported": False,
                           "recursive_buffer_chains_supported": supports_feature(data["schema"], "recursive_chain"),
                           "preemptive_or_async_cancellation_supported": False}}


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


def _function_shape(fn, *, recursive_chain=False):
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
    if not recursive_chain:
        declared = [p["type"] for p in fn["params"]] + fn["returns"]
        declared += [p["type"] for block in fn["blocks"] for p in block["params"]]
        declared += [p["type"] for block in fn["blocks"] for ins in block["ops"] for p in ins["out"]]
        if "chain" in declared:
            _reject("recursive chain types require HIA program v7", "E_HIA_TYPE")
    return by_id


@dataclass(frozen=True, slots=True)
class _FunctionInterface:
    params: tuple[str, ...]
    returns: tuple[str, ...]
    effects: frozenset[str]


class _BlockCheck:
    def __init__(self, fn, block, capabilities, functions, *, bulk_memory=False, inplace_memory=False, byte_swap=False, offset_copy=False, range_fill=False, recursive_chain=False):
        self.fn, self.block, self.functions = fn, block, functions
        self.bulk_memory = bulk_memory
        self.inplace_memory = inplace_memory
        self.byte_swap = byte_swap
        self.offset_copy = offset_copy
        self.range_fill = range_fill
        self.recursive_chain = recursive_chain
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
        if self.value(name) not in OWNERS:
            _reject("operation requires an owner", "E_HIA_TYPE")
        if any(cap.root == name and other != name for other, cap in self.caps.items()):
            _reject("owner moved/dropped/returned while borrowed", "E_HIA_LOAN")

    def access(self, name, mutable=False):
        typ = self.value(name)
        if typ not in ({"mutbuf"} if mutable else {"readbuf", "mutbuf"}):
            _reject("memory access requires appropriate view", "E_HIA_TYPE")
        if self.children(name):
            _reject("parent view is suspended until child loans end", "E_HIA_LOAN")

    def borrow(self, source, output, mutable, *, chain_head=False):
        typ = self.value(source)
        allowed = {"chain"} if chain_head else ({"buffer", "mutbuf"} if mutable else BYTE_RESOURCES)
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
        if op.startswith("chain.") and not self.recursive_chain:
            _reject("recursive chain operations require HIA program v7", "E_HIA_OPCODE")

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
            if actual[0] not in BYTE_RESOURCES:
                _reject("buffer length requires owner/view", "E_HIA_TYPE")
            expected = ["usize"]
        elif op == "chain.empty":
            arity(0)
            expected = ["chain"]
        elif op == "chain.try_push":
            arity(2)
            if actual != ["chain", "buffer"]:
                _reject("chain.try_push requires an owned tail and owned byte payload", "E_HIA_TYPE")
            for name in args:
                self.owner_free(name)
            expected = ["chain", "buffer", "bool"]
            self.required.add("alloc")
        elif op == "chain.pop":
            arity(1)
            if actual != ["chain"]:
                _reject("chain.pop requires an owned chain", "E_HIA_TYPE")
            self.owner_free(args[0])
            expected = ["chain", "buffer", "bool"]
            self.required.add("alloc")
        elif op == "chain.is_empty":
            arity(1)
            if actual != ["chain"]:
                _reject("chain.is_empty requires an owned chain", "E_HIA_TYPE")
            expected = ["bool"]
        elif op in {"chain.head_read", "chain.head_mut"}:
            arity(1)
            if actual != ["chain"]:
                _reject("chain head borrowing requires an owned chain", "E_HIA_TYPE")
            expected = ["readbuf" if op == "chain.head_read" else "mutbuf"]
            self.required.update({"read", "trap"})
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
            expected = actual if op == "owner.move" else []
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
        elif op == "buffer.fill_range":
            # v6: checked partial write under exactly one live mutable loan.
            # Native and VM guard offset <= extent and count <= extent-offset
            # before computing an address or performing any mutation.
            if not self.range_fill:
                _reject("range fill requires HIA program v6", "E_HIA_OPCODE")
            arity(4)
            self.access(args[0], True)
            if actual != ["mutbuf", "usize", "usize", "u8"]:
                _reject("fill_range needs mutbuf, offset, count, u8", "E_HIA_TYPE")
            expected = []
            self.required.update({"write", "trap"})
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
            if len(args) != len(callee.params):
                _reject("call arity mismatch", "E_HIA_CALL")
            used_owners, views = set(), []
            for name, typ, formal in zip(args, actual, callee.params):
                if typ != formal and not (formal == "readbuf" and typ == "mutbuf"):
                    _reject("call argument type mismatch", "E_HIA_CALL")
                if typ in OWNERS:
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
            expected = list(callee.returns)
            self.required.update(callee.effects)
        else:
            _reject(f"unsupported opcode {op}", "E_HIA_OPCODE")
        if op not in {"const", "int.cast", "call"}:
            _keys(attrs, set(), op)
        if types != expected:
            _reject(f"{op}: output types must be {expected}", "E_HIA_TYPE")

        # Resource transitions happen only after all operand/output checks.
        if op in {"buffer.new", "buffer.try_new"}:
            self.caps[names[0]] = _Capability("buffer", names[0])
        elif op == "chain.empty":
            self.caps[names[0]] = _Capability("chain", names[0])
        elif op in {"chain.try_push", "chain.pop"}:
            for name in args:
                del self.caps[name]
            for name, typ in zip(names, types):
                if typ in OWNERS:
                    self.caps[name] = _Capability(typ, name)
        elif op in {"chain.head_read", "chain.head_mut"}:
            self.borrow(args[0], names[0], op == "chain.head_mut", chain_head=True)
        elif op in {"borrow.read", "borrow.mut"}:
            self.borrow(args[0], names[0], op == "borrow.mut")
        elif op in {"loan.end", "owner.drop"}:
            del self.caps[args[0]]
        elif op == "owner.move":
            del self.caps[args[0]]
            self.caps[names[0]] = _Capability(actual[0], names[0])
        elif op == "call":
            for name, typ in zip(args, actual):
                if typ in OWNERS:
                    del self.caps[name]
            for name, typ in zip(names, types):
                if typ in OWNERS:
                    self.caps[name] = _Capability(typ, name)
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
            owners = [n for n, t in zip(names, types) if t in OWNERS]
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


def _primitive_structure(data):
    """Check all global declarations, shapes and exports in original order.

    This pass is never cached by the incremental verifier. It visits every
    function, block, operation shape, SSA definition and CFG edge.
    """
    fields = {"schema", "module", "functions"}
    if type(data) is dict and "exports" in data:
        fields.add("exports")
    _keys(data, fields, "program")
    if type(data["schema"]) is not str or data["schema"] not in PRIMITIVE_SCHEMAS:
        _reject("unsupported program schema", "E_HIA_SCHEMA")
    _ident(data["module"], "module")
    if type(data["functions"]) is not list or not 1 <= len(data["functions"]) <= MAX_FUNCTIONS:
        _reject("invalid function inventory", "E_HIA_FORMAT")
    functions, block_maps = {}, {}
    for fn in data["functions"]:
        blocks = _function_shape(fn, recursive_chain=supports_feature(data["schema"], "recursive_chain"))
        if fn["name"] in functions:
            _reject("duplicate function", "E_HIA_NAME")
        functions[fn["name"]], block_maps[fn["name"]] = fn, blocks
    if "exports" in data:
        _names(data["exports"], "explicit scalar exports")
        if len(data["exports"]) != len(set(data["exports"])):
            _reject("duplicate explicit scalar export", "E_HIA_NAME")
        for name in data["exports"]:
            if name not in functions:
                _reject("explicit export names a missing function", "E_HIA_CALL")
            fn = functions[name]
            if any(p["type"] not in SCALARS for p in fn["params"]) or any(t not in SCALARS for t in fn["returns"]):
                _reject("public exports cannot carry resource descriptors", "E_HIA_TYPE")
    return functions, block_maps


def _function_interfaces(functions):
    """Only these immutable facts cross a function-verification boundary."""
    return {name: _FunctionInterface(
                tuple(p["type"] for p in fn["params"]),
                tuple(fn["returns"]), frozenset(fn["effects"]))
            for name, fn in functions.items()}


def _verify_function(schema, fn, blocks, interfaces):
    """Verify one closed body using only its bytes and callee interfaces.

    The finite incremental contract is deliberately structural: callee bodies,
    global storage, external declarations and caller verification receipts are
    absent from the argument types. New cross-function/global obligations must
    invalidate this contract and use full verification until modeled.
    """
    initial = {p["name"]: _Capability(p["type"], p["name"], external=p["type"] not in OWNERS)
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
        check = _BlockCheck(fn, block, incoming[ident], interfaces,
                            bulk_memory=supports_feature(schema, "bulk_memory"),
                            inplace_memory=supports_feature(schema, "inplace_memory"),
                            byte_swap=supports_feature(schema, "byte_swap"),
                            offset_copy=supports_feature(schema, "offset_copy"),
                            range_fill=supports_feature(schema, "range_fill"),
                            recursive_chain=supports_feature(schema, "recursive_chain"))
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


def verify_program(program) -> VerifiedProgram:
    """Check standalone operations and every CFG edge; no source/hash authority.

    Even a manually constructed VerifiedProgram is parsed and fully rechecked.
    Caller-owned dictionaries and decoded dictionaries never back execution.
    """
    if isinstance(program, VerifiedProgram) and program.structured_bytes is not None:
        if type(program.structured_bytes) is not bytes:
            _reject("structured input must be immutable canonical bytes", "E_HIA_FORMAT")
        checked = verify_program(program.structured_bytes)
        if (checked.structured_bytes != program.structured_bytes
                or checked.canonical_bytes != program.canonical_bytes):
            _reject("structured input and executable core differ", "E_HIA_CORE")
        return checked
    data, raw = _decode(program)
    if (type(data) is dict and type(data.get("schema")) is str
            and data["schema"] in COMPOSITE_SCHEMAS):
        from .hia_program_composite import elaborate_program
        # The entire input was bounded/strictly decoded above.  The whole
        # generated program is independently checked, with no receipt bypass.
        core = verify_program(elaborate_program(data))
        return VerifiedProgram(core.canonical_bytes, raw)
    if type(data) is dict and data.get("schema") == SCHEMA_V2 and "types" in data:
        _reject("historical nominal v2 requires import_legacy_composite_v2; "
                "the primitive v2 namespace cannot infer a producer profile",
                "E_HIA_VERSION_COLLISION")
    functions, block_maps = _primitive_structure(data)
    interfaces = _function_interfaces(functions)
    for fn in functions.values():
        _verify_function(data["schema"], fn, block_maps[fn["name"]], interfaces)
    return VerifiedProgram(raw)


def execute_program(program, function, arguments, **kwargs):
    """Convenience entry point; implementation is an independent core consumer."""
    from .hia_program_runtime import execute_program as execute
    return execute(program, function, arguments, **kwargs)


# Public language-level spelling: verification of a program, not source replay.
verify_core = verify_program
