"""Standalone HIA v1-v8: closed, typed SSA blocks with checked resource flow.

The authority is this program's operations, not a source file, producer hash,
claim, or source-checker receipt.  Blocks are closed: all incoming values are
explicit block parameters.  The profile has 64-bit usize/isize, byte owners,
lexical/reborrowed views and finite machine integers. V8 admits explicitly
parameter-bound returned loans through the return_loans contract; v1-v7 keep
non-escaping call loans. Versioned bulk-byte operations and v7 recursive
byte-owner chains follow the shared schema registry. Composite v1/v2/v3/v4
normalize to their explicitly versioned primitive v6/v7/v8 target before the
complete resource flow is checked.

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
    PROFILE_V4, PROFILE_V5, PROFILE_V6, PROFILE_V7, PROFILE_V8, SCHEMA, SCHEMA_V2, SCHEMA_V3,
    SCHEMA_V4, SCHEMA_V5, SCHEMA_V6, SCHEMA_V7, SCHEMA_V8, profile_for_schema, supports_feature,
)
from .hia_opcodes import (
    BYTE_RESOURCES, EFFECTS, OWNERS, RESOURCES, SCALARS, TRAP_CODES, TYPES, WIDTHS,
    TERMINATORS, OpcodeRejected, check_instruction, opcode_spec,
    scalar_value_valid as _catalog_scalar_value_valid,
)
WORD_BITS = 64
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
    return _catalog_scalar_value_valid(value, typ)


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


def _bounded_input_utf8_bytes(text):
    """Count encoded JSON-input bytes without materializing the entire wire.

    HIA accepts at most MAX_BYTES of UTF-8 input.  Encoding a large caller
    string just to check its size creates an unbounded pre-admission copy.
    Exact built-in str values are immutable; count them in bounded chunks.
    Each encoded temporary is at most 16 KiB (4096 Unicode code points).
    """
    if len(text) > MAX_BYTES:
        _reject("program exceeds byte budget", "E_HIA_LIMIT")
    if text.isascii():
        return len(text)
    total = 0
    for offset in range(0, len(text), 4096):
        total += len(text[offset:offset + 4096].encode("utf-8"))
        if total > MAX_BYTES:
            _reject("program exceeds byte budget", "E_HIA_LIMIT")
    return total


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



def _bounded_detached_snapshot(root):
    """Capture caller-owned JSON containers before byte accounting/encoding.

    `_structure(original)` followed by `json.dumps(original)` is a check/use
    race if another thread mutates the original dict or list. Instead retain
    bounded references to each container's children, build a separate plain
    dict/list tree, and validate/serialize *that exact detached tree*.
    A nested caller tree is not claimed to be atomically snapshotted.
    Every supported capture is independently rechecked by _structure.
    """
    pending = [(root, None, None, 0, False)]
    active = set()
    count, queued = 0, 1
    result = None
    while pending:
        node, parent, slot, depth, leaving = pending.pop()
        if leaving:
            active.remove(id(node))
            continue
        queued -= 1
        count += 1
        if count > MAX_NODES or depth > MAX_DEPTH:
            _reject("caller-owned tree exceeds snapshot budget", "E_HIA_LIMIT")
        kind = type(node)
        if kind in (dict, list):
            identity = id(node)
            if identity in active:
                _reject("cyclic caller-owned HIA tree", "E_HIA_FORMAT")
            active.add(identity)
            available = MAX_NODES - count - queued
            if len(node) > available:
                _reject("caller-owned tree exceeds queued-node budget", "E_HIA_LIMIT")
            children = []
            try:
                if kind is dict:
                    for key, child in node.items():
                        if type(key) is not str:
                            _reject("non-string caller-owned JSON key", "E_HIA_FORMAT")
                        if len(children) >= available:
                            _reject("caller-owned dictionary grew past node budget",
                                    "E_HIA_LIMIT")
                        children.append((key, child))
                    copy = {}
                else:
                    for child in node:
                        if len(children) >= available:
                            _reject("caller-owned list grew past node budget",
                                    "E_HIA_LIMIT")
                        children.append(child)
                    copy = [None] * len(children)
            except RuntimeError as exc:
                raise HIAProgramRejected(
                    "caller-owned tree mutated during bounded snapshot",
                    "E_HIA_FORMAT") from exc
            if parent is None:
                result = copy
            else:
                parent[slot] = copy
            queued += len(children)
            pending.append((node, None, None, depth, True))
            if kind is dict:
                pending.extend((child, copy, key, depth + 1, False)
                               for key, child in reversed(children))
            else:
                pending.extend((child, copy, index, depth + 1, False)
                               for index, child in reversed(list(enumerate(children))))
        else:
            if kind not in (str, int, bool) and node is not None:
                _reject("unsupported caller-owned JSON node", "E_HIA_FORMAT")
            if parent is None:
                result = node
            else:
                parent[slot] = node
    return result

def _decode(value):
    if isinstance(value, VerifiedProgram):
        value = value.canonical_bytes
    try:
        caller_owned = type(value) in (dict, list)
        if type(value) is bytes:
            if len(value) > MAX_BYTES:
                _reject("program exceeds byte budget", "E_HIA_LIMIT")
            value = value.decode("utf-8")
        if type(value) is str:
            _bounded_input_utf8_bytes(value)
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
        if caller_owned:
            value = _bounded_detached_snapshot(value)
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
                           "parameter_bound_loan_returns_supported": supports_feature(data["schema"], "parameter_loan_returns"),
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
    # Original function parameter identity, independent of CFG SSA renaming.
    # Only functions with v8 borrowed results track this extra restriction.
    origin: str | None = None


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
    if op not in TERMINATORS:
        _reject("unknown terminator", "E_HIA_CFG")
    _keys(term, TERMINATORS[op], op)
    if op == "jump":
        return [_edge({"target": term["target"], "args": term["args"]})]
    if op == "branch":
        _ident(term["cond"], "branch condition")
        return [_edge(term["then"]), _edge(term["else"])]
    if op == "ret":
        _names(term["values"], "return values")
        return []
    if op == "trap":
        if type(term["code"]) is not str or term["code"] not in TRAP_CODES:
            _reject("unknown trap code", "E_HIA_CFG")
        return []
    _reject("unknown terminator", "E_HIA_CFG")


def _function_shape(fn, *, recursive_chain=False, parameter_loan_returns=False):
    fields = {"name", "params", "returns", "effects", "entry", "blocks"}
    if parameter_loan_returns and type(fn) is dict and "return_loans" in fn:
        fields.add("return_loans")
    _keys(fn, fields, "function")
    name = _ident(fn["name"], "function")
    if name in _RESERVED_FUNCTIONS:
        _reject("function collides with native runtime symbol", "E_HIA_NAME")
    _parameters(fn["params"], "function parameters")
    if type(fn["returns"]) is not list:
        _reject("returns must be a list", "E_HIA_TYPE")
    for typ in fn["returns"]:
        _type(typ)
        if typ in {"readbuf", "mutbuf"} and not parameter_loan_returns:
            _reject("call loans require the v8 parameter-return contract", "E_HIA_LOAN")
    if parameter_loan_returns:
        origins = fn.get("return_loans", [None] * len(fn["returns"]))
        if type(origins) is not list or len(origins) != len(fn["returns"]):
            _reject("return_loans must match the return arity", "E_HIA_LOAN")
        parameters = {p["name"]: p["type"] for p in fn["params"]}
        for typ, origin in zip(fn["returns"], origins):
            if typ not in {"readbuf", "mutbuf"}:
                if origin is not None:
                    _reject("nonloan result requires a null return_loans entry", "E_HIA_LOAN")
            elif (type(origin) is not str or parameters.get(origin) not in {"readbuf", "mutbuf"}
                  or typ == "mutbuf" and parameters[origin] != "mutbuf"):
                _reject("borrowed result must name an input loan with sufficient permission", "E_HIA_LOAN")
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
    # Original formal identities are semantic inputs in v8: return_loans names
    # a formal, not whichever same-typed or aliased argument happens to survive.
    params: tuple[str, ...]
    param_names: tuple[str, ...]
    returns: tuple[str, ...]
    return_loans: tuple[str | None, ...]
    effects: frozenset[str]


class _BlockCheck:
    def __init__(self, fn, block, capabilities, functions, *, schema):
        self.fn, self.block, self.functions = fn, block, functions
        self.schema = schema
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
        self.caps[output] = _Capability("mutbuf" if mutable else "readbuf", root, source,
                                        origin=self.caps[source].origin)

    def instruction(self, ins):
        op, args, out, attrs = ins["op"], ins["args"], ins["out"], ins["attrs"]
        actual = [self.value(a) for a in args]
        names, types = [o["name"] for o in out], [o["type"] for o in out]
        try:
            spec = opcode_spec(op, self.schema)
            self.required.update(check_instruction(spec, actual, types, attrs))
        except OpcodeRejected as exc:
            _reject(str(exc), exc.code)

        # The catalog selects the guards. These small context-dependent checks
        # still inspect actual capabilities, never declarations or receipts.
        for guard in spec.guards:
            parts = guard.split(":")
            rule = parts[0]
            if rule == "callee_interface":
                continue
            name = args[int(parts[1])]
            if rule == "free":
                self.owner_free(name)
            elif rule in {"read", "write"}:
                self.access(name, rule == "write")
            elif rule == "distinct":
                if self.caps[name].root == self.caps[args[int(parts[2])]].root:
                    _reject(op + " may not alias one owner", "E_HIA_LOAN")
            elif rule == "end_local_loan":
                if self.caps[name].external:
                    _reject("callee cannot end its caller's loan", "E_HIA_LOAN")
                if self.children(name):
                    _reject("end child loans before their parent", "E_HIA_LOAN")
            else:
                _reject("unsupported catalog resource guard", "E_HIA_OPCODE")
        if spec.resource_transition == "call":
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
            if types != list(callee.returns):
                _reject(f"{op}: output types must be {list(callee.returns)}", "E_HIA_TYPE")
            self.required.update(callee.effects)

        # Resource transitions happen only after all operand/output checks.
        transition = spec.resource_transition
        if transition == "allocate":
            self.caps[names[0]] = _Capability("buffer", names[0])
        elif transition == "empty_chain":
            self.caps[names[0]] = _Capability("chain", names[0])
        elif transition == "chain_transfer":
            for name in args:
                del self.caps[name]
            for name, typ in zip(names, types):
                if typ in OWNERS:
                    self.caps[name] = _Capability(typ, name)
        elif transition == "chain_borrow":
            self.borrow(args[0], names[0], op == "chain.head_mut", chain_head=True)
        elif transition == "borrow":
            self.borrow(args[0], names[0], op == "borrow.mut")
        elif transition in {"end_loan", "drop_owner"}:
            del self.caps[args[0]]
        elif transition == "move_owner":
            del self.caps[args[0]]
            self.caps[names[0]] = _Capability(actual[0], names[0])
        elif transition == "call":
            for name, typ in zip(args, actual):
                if typ in OWNERS:
                    del self.caps[name]
            bindings = dict(zip(callee.param_names, args))
            for name, typ, origin in zip(names, types, callee.return_loans):
                if typ in OWNERS:
                    self.caps[name] = _Capability(typ, name)
                elif typ in {"readbuf", "mutbuf"}:
                    self.borrow(bindings[origin], name, typ == "mutbuf")
        elif transition != "none":
            _reject("unsupported catalog resource transition", "E_HIA_OPCODE")
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
                remap[cap.parent] if cap.parent is not None else None, cap.external, cap.origin)
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
            loans = [n for n, t in zip(names, types) if t in {"readbuf", "mutbuf"}]
            if len(loans) != len(set(loans)):
                _reject("same loan capability returned twice", "E_HIA_LOAN")
            for name, typ, origin in zip(names, types, self.fn.get("return_loans", [None] * len(types))):
                if typ not in {"readbuf", "mutbuf"}:
                    continue
                cap = self.caps[name]
                parent = self.caps.get(cap.parent)
                if (cap.origin != origin or self.children(name)
                        or not (cap.external or parent is not None and parent.external)):
                    _reject("returned loan must be its declared parameter or a direct child", "E_HIA_LOAN")
            for name in loans:
                del self.caps[name]
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
    """Check every declaration, shape, SSA identity, CFG edge and export.

    Incremental admission never caches this pass. It establishes every
    function interface before any function body can be reused or checked.
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
        blocks = _function_shape(fn, recursive_chain=supports_feature(data["schema"], "recursive_chain"),
                                 parameter_loan_returns=supports_feature(data["schema"], "parameter_loan_returns"))
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
    """Detached immutable facts visible across a body-checking boundary."""
    return {name: _FunctionInterface(
                tuple(p["type"] for p in fn["params"]),
                tuple(p["name"] for p in fn["params"]),
                tuple(fn["returns"]),
                tuple(fn.get("return_loans", [None] * len(fn["returns"]))),
                frozenset(fn["effects"]))
            for name, fn in functions.items()}


def _verify_function(schema, fn, blocks, interfaces):
    """Verify a closed body using its bytes and immutable callee interfaces.

    V8 formal identities and returned-loan declarations are dependencies.
    Callee bodies, caller receipts and hidden global summaries are not inputs.
    Any future cross-function obligation must extend the cache contract first.
    """
    track_origins = supports_feature(schema, "parameter_loan_returns") and any(
        typ in {"readbuf", "mutbuf"} for typ in fn["returns"])
    initial = {p["name"]: _Capability(p["type"], p["name"], external=p["type"] not in OWNERS,
                                     origin=p["name"] if track_origins and p["type"] not in OWNERS else None)
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
        check = _BlockCheck(fn, block, incoming[ident], interfaces, schema=schema)
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
