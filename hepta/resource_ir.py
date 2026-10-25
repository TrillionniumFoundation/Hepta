"""Independent JSON resource/loan verifier; no parser or frontend dependency.

This IR abstracts copied scalar values and is not executable machine IR. The
verifier checks its own declared types, ownership transitions, loans and CFG
joins. It does not establish that a source-to-IR translator preserves behavior.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
import hashlib
import json
import re


SCHEMA = "hepta.resource-ir.v2"
LEGACY_SCHEMA = "hepta.resource-ir.v1"
_SCALARS = {"i8", "i16", "i32", "i64", "i128", "isize", "u8", "u16", "u32", "u64", "u128", "usize", "f32", "f64", "bool", "Unit"}
_EXTERNAL_REQUIREMENTS = ["abi", "aliasing", "effects", "lifetime", "ownership"]
_CLAIMS = {"source_to_ir_refinement_proved": False, "native_codegen_uses_this_ir": False,
           "whole_language_soundness_proved": False, "external_contracts_proved": False,
           "termination_proved": False, "scalar_value_semantics_verified": False}


class ResourceIRError(ValueError):
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


def _fail(code: str, message: str) -> None:
    raise ResourceIRError(code, message)


def _fields(value: object, expected: set[str], context: str) -> dict:
    if not isinstance(value, dict) or set(value) != expected:
        _fail("E_RIR_SCHEMA", f"{context} requires exactly {sorted(expected)}")
    return value


def _id(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 1024:
        _fail("E_RIR_SCHEMA", "Expected a bounded nonempty identifier")
    return value


def _list(value: object, maximum: int = 4096) -> list:
    if not isinstance(value, list) or len(value) > maximum:
        _fail("E_RIR_SCHEMA", "Expected a bounded list")
    return value


def _mode(value: object, modes: set[str]) -> str:
    if not isinstance(value, str) or value not in modes:
        _fail("E_RIR_SCHEMA", f"Expected a mode in {sorted(modes)}")
    return value


def _overlap(left: tuple[str, tuple[str, ...]], right: tuple[str, tuple[str, ...]]) -> bool:
    if left[0] != right[0]:
        return False
    for a, b in zip(left[1], right[1]):
        if "*" in (a, b):
            return True
        if a != b:
            return False
    return True


@dataclass
class _State:
    owners: set[str] = field(default_factory=set)
    # loan -> (root, field/index path, mode, exposed pointee type)
    loans: dict[str, tuple[str, tuple[str, ...], str, str]] = field(default_factory=dict)
    variants: dict[str, str] = field(default_factory=dict)

    def copy(self) -> _State:
        return _State(set(self.owners), dict(self.loans), dict(self.variants))


class _Verifier:
    def __init__(self, doc: dict):
        self.doc = doc
        self.types: dict = {}
        self.owned: dict[str, bool] = {}
        self.type_parameters: dict[str, frozenset[str]] = {}
        self.functions: dict = {}
        self.assumptions: dict = {}
        self.function = ""
        self.block = ""
        self.slots: dict[str, dict] = {}
        self.params: dict[str, dict] = {}
        self.operation_count = 0
        self.static_operation_count = 0
        self.generic_calls_checked = 0

    def type_(self, name: object) -> dict:
        name = _id(name)
        if name not in self.types:
            _fail("E_RIR_TYPE", f"Unknown type {name}")
        return self.types[name]

    def validate_types(self) -> None:
        if not isinstance(self.doc["types"], dict) or not 1 <= len(self.doc["types"]) <= 4096:
            _fail("E_RIR_TYPE", "Expected 1..4096 type definitions")
        self.types = self.doc["types"]
        dependencies = {}
        for tid, typ in self.types.items():
            _id(tid)
            if not isinstance(typ, dict):
                _fail("E_RIR_TYPE", "Type definitions must be objects")
            kind = typ.get("kind")
            deps = []
            if kind == "scalar":
                _fields(typ, {"kind", "name"}, "scalar type")
                if typ["name"] not in _SCALARS or tid != typ["name"]:
                    _fail("E_RIR_TYPE", "Scalar identity must name a supported primitive")
            elif kind == "parameter":
                _fields(typ, {"kind", "function", "name", "bound"}, "type parameter")
                if self.doc["schema"] != SCHEMA:
                    _fail("E_RIR_SCHEMA", "Generic resource types require resource IR v2")
                owner, name = _id(typ["function"]), _id(typ["name"])
                if any(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", part) is None for part in (owner, name)):
                    _fail("E_RIR_TYPE", "Generic owners and names must be plain identifiers")
                if typ["bound"] not in {"Copy", "Owned"} or tid != "@" + owner + "::" + name:
                    _fail("E_RIR_GENERIC", "Generic identity and finite Copy/Owned constraint must agree")
            elif kind in {"buffer", "slice", "array"}:
                _fields(typ, {"kind", "element"} | ({"length"} if kind == "array" else set()), "sequence type")
                element = _id(typ["element"])
                deps.append(element)
                if kind == "buffer":
                    canonical = "Buffer<" + element + ">"
                    if element != "u8":
                        _fail("E_RIR_TYPE", "This resource profile supports Buffer<u8>")
                elif kind == "slice":
                    canonical = "[" + element + "]"
                else:
                    if type(typ["length"]) is not int or not 0 <= typ["length"] <= 2**32:
                        _fail("E_RIR_TYPE", "Invalid array length")
                    canonical = f"[{element}; {typ['length']}]"
                if tid != canonical:
                    _fail("E_RIR_TYPE", "Sequence identity does not match its definition")
            elif kind in {"struct", "enum"}:
                _fields(typ, {"kind", "name", "args", "fields" if kind == "struct" else "variants"}, "aggregate type")
                name = _id(typ["name"])
                if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) is None:
                    _fail("E_RIR_TYPE", "Nominal identities must be plain identifiers, not disguised compound types")
                if name in _SCALARS | {"Buffer", "Task", "TaskGroup", "Cancellation", "Sender"}:
                    _fail("E_RIR_TYPE", "Reserved aggregate identity")
                args = [_id(a) for a in _list(typ["args"], 64)]
                canonical = name + ("<" + ", ".join(args) + ">" if args else "")
                if tid != canonical:
                    _fail("E_RIR_TYPE", "Aggregate identity does not match its arguments")
                deps.extend(args)
                if kind == "struct":
                    names = set()
                    for f in _list(typ["fields"], 128):
                        _fields(f, {"name", "type"}, "struct field")
                        if _id(f["name"]) in names or f["name"] == "*":
                            _fail("E_RIR_TYPE", "Duplicate or invalid struct field")
                        names.add(f["name"])
                        deps.append(_id(f["type"]))
                else:
                    names = set()
                    for variant in _list(typ["variants"], 128):
                        _fields(variant, {"name", "fields"}, "enum variant")
                        if _id(variant["name"]) in names:
                            _fail("E_RIR_TYPE", "Duplicate enum variant")
                        names.add(variant["name"])
                        deps.extend(_id(f) for f in _list(variant["fields"], 128))
                    if not names:
                        _fail("E_RIR_TYPE", "Empty enums are outside this profile")
                if name == "Result" and (kind != "enum" or len(args) != 2 or typ["variants"] != [
                        {"name": "Ok", "fields": [args[0]]}, {"name": "Err", "fields": [args[1]]}]):
                    _fail("E_RIR_TYPE", "Result must retain both typed payloads")
            else:
                _fail("E_RIR_TYPE", f"Unsupported resource type kind {kind}")
            dependencies[tid] = deps
        active = set()

        def owned(tid: str, depth: int = 0) -> bool:
            self.type_(tid)
            if tid in self.owned:
                return self.owned[tid]
            if tid in active or depth > 128:
                _fail("E_RIR_TYPE", "Recursive or excessively nested value type")
            active.add(tid)
            children = [owned(child, depth + 1) for child in dependencies[tid]]
            kind = self.types[tid]["kind"]
            if kind in {"slice", "array"} and any(children):
                _fail("E_RIR_TYPE", "Resource-bearing arrays/slices are unsupported")
            self.owned[tid] = kind == "buffer" or kind == "parameter" and self.types[tid]["bound"] == "Owned" or any(children)
            self.type_parameters[tid] = (frozenset({tid}) if kind == "parameter" else
                                         frozenset().union(*(self.type_parameters[child] for child in dependencies[tid])))
            active.remove(tid)
            return self.owned[tid]

        for tid in self.types:
            owned(tid)

    def validate_signatures(self) -> None:
        if not isinstance(self.doc["obligations"], dict) or len(self.doc["obligations"]) > 512:
            _fail("E_RIR_EXTERNAL", "Expected an external obligation table")
        for oid, obligation in self.doc["obligations"].items():
            _id(oid)
            _fields(obligation, {"function", "status", "requirements"}, "external obligation")
            if obligation["status"] != "assumed_not_verified" or obligation["requirements"] != _EXTERNAL_REQUIREMENTS:
                _fail("E_RIR_EXTERNAL", "External obligations must explicitly retain all unproved requirements")
            _id(obligation["function"])
        for fn in _list(self.doc["functions"], 512):
            _fields(fn, {"name", "params", "returns", "external", "obligation", "locals", "entry", "blocks"} |
                    ({"type_params"} if "type_params" in fn else set()), "function")
            name = _id(fn["name"])
            if name in self.functions:
                _fail("E_RIR_FUNCTION", "Duplicate function")
            self.functions[name] = fn
            declared = _list(fn.get("type_params", []), 64)
            if declared and self.doc["schema"] != SCHEMA:
                _fail("E_RIR_SCHEMA", "Generic functions require resource IR v2")
            if len(set(_id(t) for t in declared)) != len(declared):
                _fail("E_RIR_GENERIC", "Generic parameter identities must be unique")
            for tid in declared:
                descriptor = self.type_(tid)
                if descriptor["kind"] != "parameter" or descriptor["function"] != name:
                    _fail("E_RIR_GENERIC", "Function must bind its own declared type parameters")
            params = {}
            for p in _list(fn["params"], 128):
                _fields(p, {"id", "type", "mode"}, "parameter")
                pid = _id(p["id"])
                self.type_(p["type"])
                self.check_type_scope(p["type"], fn)
                _mode(p["mode"], {"value", "take", "read", "mut"})
                if pid in params:
                    _fail("E_RIR_FUNCTION", "Duplicate parameter")
                if self.owned[p["type"]] and p["mode"] == "value":
                    _fail("E_RIR_OWNERSHIP", "An owned parameter needs take/read/mut")
                if not self.owned[p["type"]] and p["mode"] == "take":
                    _fail("E_RIR_OWNERSHIP", "take must transfer an owned type")
                if self.types[p["type"]]["kind"] == "slice" and p["mode"] not in {"read", "mut"}:
                    _fail("E_RIR_TYPE", "Slices are borrowed only")
                params[pid] = p
            ret = _fields(fn["returns"], {"type", "mode", "origin"}, "return signature")
            self.type_(ret["type"])
            self.check_type_scope(ret["type"], fn)
            _mode(ret["mode"], {"value", "read", "mut"})
            if ret["mode"] == "value":
                if ret["origin"] is not None or self.types[ret["type"]]["kind"] == "slice":
                    _fail("E_RIR_RETURN", "Value returns cannot name a borrow origin or unsized slice")
            else:
                borrowed = [p for p in params.values() if p["mode"] in {"read", "mut"}]
                if len(borrowed) != 1 or ret["origin"] != borrowed[0]["id"] or (ret["mode"] == "mut" and borrowed[0]["mode"] != "mut"):
                    _fail("E_RIR_RETURN", "Returned borrow needs the unique compatible borrowed parameter")
            if type(fn["external"]) is not bool:
                _fail("E_RIR_FUNCTION", "external must be boolean")
            if fn["external"]:
                if declared:
                    _fail("E_RIR_GENERIC", "External generic functions have no modelled ABI")
                oid = fn["obligation"]
                if not isinstance(oid, str) or oid not in self.doc["obligations"] or self.doc["obligations"][oid]["function"] != name:
                    _fail("E_RIR_EXTERNAL", "External declaration is missing its obligation")
                if _list(fn["locals"]) or _list(fn["blocks"]) or fn["entry"] is not None:
                    _fail("E_RIR_EXTERNAL", "External declarations cannot supply checked bodies")
                self.assumptions[oid] = self.doc["obligations"][oid]
            elif fn["obligation"] is not None:
                _fail("E_RIR_FUNCTION", "Internal declaration cannot masquerade as external")
        for oid, obligation in self.doc["obligations"].items():
            if oid not in self.assumptions:
                _fail("E_RIR_EXTERNAL", "Unbound external obligation")
        for tid, descriptor in self.types.items():
            if descriptor["kind"] == "parameter":
                owner = self.functions.get(descriptor["function"])
                if owner is None or tid not in owner.get("type_params", []):
                    _fail("E_RIR_GENERIC", "Unbound type parameter declaration")

    def check_type_scope(self, tid: str, fn: dict) -> None:
        self.type_(tid)
        if not self.type_parameters[tid] <= set(fn.get("type_params", [])):
            _fail("E_RIR_GENERIC", "A type parameter escaped its declaring function")

    def instantiate(self, tid: str, mapping: dict[str, str], depth: int = 0,
                    memo: dict[str, str] | None = None) -> str:
        """Substitute a call signature and verify each instantiated type shape.

        The existing table is not trusted to give a generic instantiation the
        right fields. For example Box<Buffer> cannot silently substitute a
        scalar payload for the declared Box<T>. This does not prove source
        refinement; it checks the supplied graph's own polymorphic contract.
        """
        if depth > 128:
            _fail("E_RIR_LIMIT", "Generic substitution exceeds type depth budget")
        if not self.type_parameters[tid] & mapping.keys():
            return tid
        if tid in mapping:
            return mapping[tid]
        if memo is None:
            memo = {}
        if tid in memo:
            return memo[tid]
        desc = self.type_(tid)
        kind = desc["kind"]
        if kind in {"scalar", "parameter"}:
            return tid
        sub = lambda child: self.instantiate(child, mapping, depth + 1, memo)
        expected = dict(desc)
        if kind in {"buffer", "array", "slice"}:
            element = sub(desc["element"])
            expected["element"] = element
            result = "Buffer<" + element + ">" if kind == "buffer" else "[" + element + "]" if kind == "slice" else f"[{element}; {desc['length']}]"
        else:
            args = [sub(child) for child in desc["args"]]
            expected["args"] = args
            result = desc["name"] + ("<" + ", ".join(args) + ">" if args else "")
            if kind == "struct":
                expected["fields"] = [{"name": field["name"], "type": sub(field["type"])} for field in desc["fields"]]
            else:
                expected["variants"] = [{"name": variant["name"], "fields": [sub(child) for child in variant["fields"]]} for variant in desc["variants"]]
        if self.type_(result) != expected:
            _fail("E_RIR_GENERIC", "Instantiated aggregate layout differs from the declared generic shape")
        memo[tid] = result
        return result

    def slot(self, sid: object) -> dict:
        sid = _id(sid)
        if sid not in self.slots:
            _fail("E_RIR_SLOT", f"Unknown slot {sid}")
        return self.slots[sid]

    def live(self, sid: str, state: _State) -> None:
        typ = self.slot(sid)["type"]
        if self.owned[typ] and self.params.get(sid, {}).get("mode") not in {"read", "mut"} and sid not in state.owners:
            _fail("E_RIR_USE_AFTER_MOVE", f"Owned slot {sid} is not live")

    def place(self, value: object, state: _State) -> tuple[str, tuple[str, ...], str]:
        p = _fields(value, {"root", "path"}, "place")
        root = _id(p["root"])
        self.live(root, state)
        typ = self.slot(root)["type"]
        path = tuple(_id(x) for x in _list(p["path"], 128))
        for step in path:
            desc = self.type_(typ)
            if desc["kind"] == "struct":
                fields = {f["name"]: f["type"] for f in desc["fields"]}
                if step not in fields:
                    _fail("E_RIR_PLACE", f"Unknown field {step}")
                typ = fields[step]
            elif desc["kind"] in {"buffer", "array", "slice"} and step == "*":
                typ = desc["element"]
            else:
                _fail("E_RIR_PLACE", "Invalid field or conservative index path")
        return root, path, typ

    def mutable(self, root: str) -> bool:
        return self.params[root]["mode"] == "mut" if root in self.params else self.slots[root]["mutable"]

    def access(self, root: str, path: tuple[str, ...], mode: str, state: _State) -> None:
        if mode == "write" and not self.mutable(root):
            _fail("E_RIR_MUTABILITY", "Mutation requires a mutable root")
        for loan in state.loans.values():
            if _overlap((root, path), loan[:2]) and (mode == "write" or loan[2] == "mut"):
                _fail("E_RIR_LOAN_CONFLICT", "Direct access conflicts with a live loan")
        if mode == "write":
            state.variants.pop(root, None)

    def consume(self, sid: str, state: _State) -> None:
        if sid not in state.owners:
            _fail("E_RIR_USE_AFTER_MOVE", f"Cannot consume non-live owner {sid}")
        if any(loan[0] == sid for loan in state.loans.values()):
            _fail("E_RIR_LOAN_CONFLICT", "Cannot move/drop an owner during a loan")
        state.owners.remove(sid)

    def produce(self, sid: str, state: _State) -> None:
        typ = self.slot(sid)["type"]
        if sid in self.params:
            _fail("E_RIR_OWNERSHIP", "Parameter storage cannot be reacquired")
        if any(loan[0] == sid for loan in state.loans.values()):
            _fail("E_RIR_LOAN_CONFLICT", "Cannot overwrite borrowed destination storage")
        # A Copy enum can reuse abstract storage. Any earlier switch fact
        # describes the old value, regardless of whether this is pack, call
        # output or an unpack destination. A later unpack needs a fresh edge.
        state.variants.pop(sid, None)
        if self.owned[typ]:
            if sid in state.owners:
                _fail("E_RIR_DOUBLE_OWNER", f"Owner destination {sid} is already live/borrowed")
            state.owners.add(sid)

    def compatible_borrow(self, actual: str, expected: str) -> bool:
        if actual == expected:
            return True
        a, e = self.type_(actual), self.type_(expected)
        return e["kind"] == "slice" and a["kind"] in {"buffer", "array", "slice"} and a["element"] == e["element"]

    def payload(self, typ: str, variant: object) -> list[str]:
        desc = self.type_(typ)
        if desc["kind"] == "struct" and variant is None:
            return [f["type"] for f in desc["fields"]]
        if desc["kind"] == "enum" and isinstance(variant, str):
            for v in desc["variants"]:
                if v["name"] == variant:
                    return v["fields"]
        _fail("E_RIR_AGGREGATE", "Invalid struct/enum payload selection")

    def op_shape(self, op: object) -> str:
        if not isinstance(op, dict):
            _fail("E_RIR_OP", "Operation must be an object")
        name = op.get("op")
        fields = {"acquire": {"dest", "kind"}, "move": {"src", "dest"}, "drop": {"src"},
                  "pack": {"dest", "variant", "fields"}, "unpack": {"src", "variant", "dests"},
                  "borrow": {"id", "place", "mode", "type"}, "end_borrow": {"id"},
                  "call": {"function", "args", "result", "result_loan", "obligation"},
                  "foreign": {"function", "args", "result", "result_loan", "obligation"},
                  "use": {"loan" if "loan" in op else "place", "mode"}}
        if not isinstance(name, str) or name not in fields:
            _fail("E_RIR_OP", f"Unknown operation {name}")
        _fields(op, fields[name] | {"op"} | ({"type_args"} if name in {"call", "foreign"} and "type_args" in op else set()), "operation")
        return name

    def operation(self, op: dict, state: _State) -> None:
        name = self.op_shape(op)
        self.operation_count += 1
        if self.operation_count > 100000:
            _fail("E_RIR_LIMIT", "Resource graph exceeds operation budget")
        if name == "acquire":
            typ = self.slot(op["dest"])["type"]
            expected = {"buffer": "Buffer<u8>", "try_buffer": "Result<Buffer<u8>, u8>"}.get(op["kind"])
            if typ != expected:
                _fail("E_RIR_ACQUIRE", "Only explicitly modelled buffer constructors can acquire")
            self.produce(op["dest"], state)
        elif name == "move":
            src, dest = op["src"], op["dest"]
            if src == dest or self.slot(src)["type"] != self.slot(dest)["type"]:
                _fail("E_RIR_MOVE", "Move requires distinct identically typed slots")
            self.consume(src, state)
            self.produce(dest, state)
            if src in state.variants:
                state.variants[dest] = state.variants.pop(src)
        elif name == "drop":
            self.slot(op["src"])
            self.consume(op["src"], state)
            state.variants.pop(op["src"], None)
        elif name == "pack":
            dest = op["dest"]
            types = self.payload(self.slot(dest)["type"], op["variant"])
            sources = _list(op["fields"], 128)
            if len(types) != len(sources) or dest in sources:
                _fail("E_RIR_AGGREGATE", "Pack needs every typed field and a distinct destination")
            for sid, typ in zip(sources, types):
                if self.slot(sid)["type"] != typ:
                    _fail("E_RIR_TYPE", "Pack field type differs")
                if self.owned[typ]:
                    self.consume(sid, state)
                    state.variants.pop(sid, None)
                else:
                    self.live(sid, state)
                    self.access(sid, (), "read", state)
            self.produce(dest, state)
        elif name == "unpack":
            src = op["src"]
            typ = self.slot(src)["type"]
            fields = self.payload(typ, op["variant"])
            dests = _list(op["dests"], 128)
            if len(fields) != len(dests) or len(set(dests)) != len(dests) or src in dests:
                _fail("E_RIR_AGGREGATE", "Unpack needs distinct destinations for every field")
            if self.types[typ]["kind"] == "enum" and state.variants.get(src) != op["variant"]:
                _fail("E_RIR_VARIANT", "Unpack requires the matching switch-edge fact")
            self.live(src, state)
            if self.owned[typ]:
                self.consume(src, state)
            else:
                self.access(src, (), "read", state)
            state.variants.pop(src, None)
            for dest, expected in zip(dests, fields):
                if self.slot(dest)["type"] != expected:
                    _fail("E_RIR_TYPE", "Unpack payload type differs")
                self.produce(dest, state)
        elif name == "borrow":
            lid = _id(op["id"])
            if lid in state.loans:
                _fail("E_RIR_LOAN", "Duplicate live loan")
            root, path, typ = self.place(op["place"], state)
            mode = _mode(op["mode"], {"read", "mut"})
            self.type_(op["type"])
            if not self.compatible_borrow(typ, op["type"]):
                _fail("E_RIR_TYPE", "Borrowed pointee type differs")
            self.access(root, path, "write" if mode == "mut" else "read", state)
            state.loans[lid] = (root, path, mode, op["type"])
        elif name == "end_borrow":
            if _id(op["id"]) not in state.loans:
                _fail("E_RIR_LOAN", "Cannot end a missing loan")
            del state.loans[op["id"]]
        elif name == "use":
            mode = _mode(op["mode"], {"read", "write"})
            if "loan" in op:
                loan = state.loans.get(_id(op["loan"]))
                if loan is None or mode == "write" and loan[2] != "mut":
                    _fail("E_RIR_LOAN", "Missing or immutable loan access")
            else:
                root, path, _ = self.place(op["place"], state)
                self.access(root, path, mode, state)
        else:
            self.call(op, state)

    def call(self, op: dict, state: _State) -> None:
        callee = self.functions.get(_id(op["function"]))
        if callee is None or callee["external"] != (op["op"] == "foreign"):
            _fail("E_RIR_CALL", "Call kind does not match a declared function")
        if op["obligation"] != callee["obligation"]:
            _fail("E_RIR_EXTERNAL", "Call omitted or changed its external obligation")
        type_args = _list(op.get("type_args", []), 64)
        type_params = callee.get("type_params", [])
        if len(type_args) != len(type_params):
            _fail("E_RIR_GENERIC", "Call must supply exactly the declared type arguments")
        if type_params:
            self.generic_calls_checked += 1
        mapping = {}
        for parameter, actual in zip(type_params, type_args):
            actual = _id(actual)
            descriptor = self.type_(actual)
            self.check_type_scope(actual, self.functions[self.function])
            bound = self.types[parameter]["bound"]
            if descriptor["kind"] == "slice" or self.owned[actual] != (bound == "Owned"):
                _fail("E_RIR_GENERIC", "Type argument violates its sized Copy/Owned constraint")
            mapping[parameter] = actual
        params = [{**param, "type": self.instantiate(param["type"], mapping)} for param in callee["params"]]
        ret = {**callee["returns"], "type": self.instantiate(callee["returns"]["type"], mapping)}
        args = _list(op["args"], 128)
        if len(args) != len(callee["params"]):
            _fail("E_RIR_CALL", "Call arity differs")
        origin_loan = None
        seen_loans = {}
        for arg, param in zip(args, params):
            _fields(arg, {"kind", "id"}, "call argument")
            sid = _id(arg["id"])
            mode = param["mode"]
            if mode in {"read", "mut"}:
                loan = state.loans.get(sid)
                if arg["kind"] != "borrow" or loan is None or (mode == "mut" and loan[2] != "mut") or not self.compatible_borrow(loan[3], param["type"]):
                    _fail("E_RIR_CALL", "Borrow argument differs from its signature")
                if sid in seen_loans and (mode == "mut" or seen_loans[sid] == "mut"):
                    _fail("E_RIR_LOAN_CONFLICT", "One mutable loan cannot serve two arguments")
                seen_loans[sid] = mode
                if callee["returns"]["origin"] == param["id"]:
                    origin_loan = sid
                if mode == "mut":
                    state.variants.pop(loan[0], None)
            else:
                if self.slot(sid)["type"] != param["type"] or arg["kind"] != ("owner" if mode == "take" else "value"):
                    _fail("E_RIR_CALL", "Value/owner argument differs from its signature")
                self.live(sid, state)
                if mode == "take":
                    self.consume(sid, state)
                    state.variants.pop(sid, None)
                else:
                    self.access(sid, (), "read", state)
        if ret["mode"] == "value":
            if op["result_loan"] is not None:
                _fail("E_RIR_CALL", "Value call cannot create a loan")
            if ret["type"] == "Unit":
                if op["result"] is not None:
                    _fail("E_RIR_CALL", "Unit call has no result slot")
            else:
                if self.slot(op["result"])["type"] != ret["type"]:
                    _fail("E_RIR_CALL", "Call result type differs")
                self.produce(op["result"], state)
        else:
            result = _id(op["result_loan"])
            if op["result"] is not None or origin_loan is None or result in state.loans:
                _fail("E_RIR_CALL", "Borrowed call needs a fresh result loan and its origin")
            root, path, _, _ = state.loans.pop(origin_loan)
            # The call's exact projection is abstract. Retain the entire input
            # place as a conservative overlap region for the returned view.
            state.loans[result] = (root, path, ret["mode"], ret["type"])

    def terminator(self, term: dict, state: _State, fn: dict) -> list[tuple[str, _State]]:
        if not isinstance(term, dict):
            _fail("E_RIR_TERM", "Missing terminator")
        op = term.get("op")
        if op == "jump":
            _fields(term, {"op", "target"}, "jump")
            return [(_id(term["target"]), state)]
        if op == "branch":
            _fields(term, {"op", "condition", "then", "else"}, "branch")
            if self.slot(term["condition"])["type"] != "bool":
                _fail("E_RIR_TYPE", "Branch needs an abstract boolean value")
            self.access(term["condition"], (), "read", state)
            return [(_id(term["then"]), state.copy()), (_id(term["else"]), state)]
        if op == "switch":
            _fields(term, {"op", "src", "cases"}, "switch")
            sid = term["src"]
            typ = self.type_(self.slot(sid)["type"])
            if typ["kind"] != "enum":
                _fail("E_RIR_TYPE", "Switch needs an enum")
            self.live(sid, state)
            self.access(sid, (), "read", state)
            cases = _list(term["cases"], 128)
            found, edges = set(), []
            for case in cases:
                _fields(case, {"variant", "target"}, "switch case")
                variant = _id(case["variant"])
                if variant in found:
                    _fail("E_RIR_VARIANT", "Duplicate switch variant")
                found.add(variant)
                branch = state.copy()
                branch.variants[sid] = variant
                edges.append((_id(case["target"]), branch))
            if found != {v["name"] for v in typ["variants"]}:
                _fail("E_RIR_VARIANT", "Switch must cover every declared variant")
            return edges
        if op == "return":
            _fields(term, {"op", "value", "loan"}, "return")
            ret = fn["returns"]
            if ret["mode"] == "value":
                if term["loan"] is not None:
                    _fail("E_RIR_RETURN", "Value return cannot export a loan")
                if ret["type"] == "Unit":
                    if term["value"] is not None:
                        _fail("E_RIR_RETURN", "Unit return cannot export a value")
                else:
                    sid = term["value"]
                    if self.slot(sid)["type"] != ret["type"]:
                        _fail("E_RIR_RETURN", "Return type differs")
                    self.live(sid, state)
                    if self.owned[ret["type"]]:
                        self.consume(sid, state)
                    else:
                        self.access(sid, (), "read", state)
            else:
                loan = state.loans.get(_id(term["loan"]))
                if (term["value"] is not None or loan is None or loan[0] != ret["origin"]
                        or loan[2] != ret["mode"] or not self.compatible_borrow(loan[3], ret["type"])):
                    _fail("E_RIR_RETURN", "Returned borrow escapes its declared input/mode")
                del state.loans[term["loan"]]
            if state.owners:
                _fail("E_RIR_LEAK", "Normal/early return leaves owned values live: " + ", ".join(sorted(state.owners)))
            if state.loans:
                _fail("E_RIR_LOAN_ESCAPE", "Normal/early return leaves undeclared loans live")
            return []
        _fail("E_RIR_TERM", f"Unknown terminator {op}")

    def term_targets(self, term: object) -> list[str]:
        """Check the structural CFG even where a block is unreachable."""
        if not isinstance(term, dict):
            _fail("E_RIR_TERM", "Missing terminator")
        name = term.get("op")
        fields = {"jump": {"target"}, "branch": {"condition", "then", "else"},
                  "switch": {"src", "cases"}, "return": {"value", "loan"}}
        if not isinstance(name, str) or name not in fields:
            _fail("E_RIR_TERM", f"Unknown terminator {name}")
        _fields(term, fields[name] | {"op"}, "terminator")
        if name == "jump":
            return [_id(term["target"])]
        if name == "branch":
            self.slot(term["condition"])
            return [_id(term["then"]), _id(term["else"])]
        if name == "switch":
            self.slot(term["src"])
            targets = []
            for case in _list(term["cases"], 128):
                _fields(case, {"variant", "target"}, "switch case")
                _id(case["variant"])
                targets.append(_id(case["target"]))
            return targets
        if term["value"] is not None:
            self.slot(term["value"])
        if term["loan"] is not None:
            _id(term["loan"])
        return []

    def body(self, fn: dict) -> dict:
        self.function = fn["name"]
        self.params = {p["id"]: p for p in fn["params"]}
        self.slots = {p["id"]: {"type": p["type"], "mutable": p["mode"] == "mut"} for p in fn["params"]}
        for local in _list(fn["locals"], 16384):
            _fields(local, {"id", "type", "mutable"}, "local slot")
            sid = _id(local["id"])
            self.type_(local["type"])
            self.check_type_scope(local["type"], fn)
            if sid in self.slots or type(local["mutable"]) is not bool or self.types[local["type"]]["kind"] == "slice":
                _fail("E_RIR_SLOT", "Duplicate/invalid local or owned unsized slice")
            self.slots[sid] = local
        blocks = {}
        for block in _list(fn["blocks"], 4096):
            _fields(block, {"id", "ops", "term"}, "basic block")
            bid = _id(block["id"])
            if bid in blocks:
                _fail("E_RIR_CFG", "Duplicate basic block")
            blocks[bid] = block
            for op in _list(block["ops"], 16384):
                self.op_shape(op)  # Unknown operations also fail in unreachable blocks.
                self.static_operation_count += 1
                if self.static_operation_count > 100000:
                    _fail("E_RIR_LIMIT", "Resource graph exceeds total operation budget")
        for block in blocks.values():
            if any(target not in blocks for target in self.term_targets(block["term"])):
                _fail("E_RIR_CFG", "A branch target is missing, possibly in unreachable code")
        entry = _id(fn["entry"])
        if entry not in blocks:
            _fail("E_RIR_CFG", "Entry block is missing")
        initial = _State({p["id"] for p in fn["params"] if p["mode"] == "take"})
        incoming = {entry: initial}
        pending = deque([entry])
        exits = 0
        while pending:
            bid = pending.popleft()
            self.block = bid
            block = blocks[bid]
            state = incoming[bid].copy()
            for op in block["ops"]:
                self.operation(op, state)
            edges = self.terminator(block["term"], state, fn)
            if not edges:
                exits += 1
            for dest, outgoing in edges:
                if dest not in blocks:
                    _fail("E_RIR_CFG", f"Missing branch target {dest}")
                if dest in incoming:
                    if incoming[dest] != outgoing:
                        _fail("E_RIR_JOIN", f"Owners, loans or variant facts disagree at join/backedge {dest}")
                else:
                    incoming[dest] = outgoing.copy()
                    pending.append(dest)
        return {"function": fn["name"], "reachable_blocks": len(incoming), "total_blocks": len(blocks), "normal_exits": exits}

    def run(self) -> dict:
        _fields(self.doc, {"schema", "source_sha256", "project_sha256", "value_semantics", "types", "functions", "obligations", "claims"}, "resource IR")
        if self.doc["schema"] not in {SCHEMA, LEGACY_SCHEMA} or self.doc["value_semantics"] != "copied_values_abstract_not_executable":
            _fail("E_RIR_SCHEMA", "Unsupported resource IR profile")
        if self.doc["claims"] != _CLAIMS or any(type(v) is not bool for v in self.doc["claims"].values()):
            _fail("E_RIR_CLAIM", "Resource IR cannot claim source refinement, native use or foreign soundness")
        for name in ("source_sha256", "project_sha256"):
            value = self.doc[name]
            if value is not None and (not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value)):
                _fail("E_RIR_SCHEMA", "Malformed source/project identity")
        self.validate_types()
        self.validate_signatures()
        reports = [self.body(fn) for fn in self.functions.values() if not fn["external"]]
        return {"schema": "hepta.resource-ir-validation.v1", "ok": True,
                "status": "resource_cfg_verified_with_external_assumptions" if self.assumptions else "resource_cfg_verified",
                "functions": reports, "operations_checked": self.operation_count,
                "generic_functions_checked": sum(bool(fn.get("type_params")) for fn in self.functions.values()),
                "generic_calls_checked": self.generic_calls_checked,
                "owned_types": sorted(k for k, v in self.owned.items() if v),
                "external_obligations": self.assumptions, "diagnostics": [], "claims": dict(_CLAIMS)}


def verify_resource_ir(document: object) -> dict:
    """Verify the declared JSON graph without invoking any source checker."""
    verifier = _Verifier(document)
    try:
        report = verifier.run()
        report["ir_sha256"] = hashlib.sha256(json.dumps(document, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()
        return report
    except (ResourceIRError, TypeError, ValueError, KeyError, RecursionError) as exc:
        return {"schema": "hepta.resource-ir-validation.v1", "ok": False, "status": "rejected",
                "diagnostics": [{"code": getattr(exc, "code", "E_RIR_SCHEMA"), "message": str(exc),
                                 "function": verifier.function, "block": verifier.block}], "claims": dict(_CLAIMS)}


def main(argv=None) -> int:
    """Check one bounded JSON graph without loading a source-language frontend."""
    import argparse
    from pathlib import Path

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("graph", type=Path, help="A hepta.resource-ir.v2 JSON graph (legacy v1 accepted)")
    args = parser.parse_args(argv)

    def unique_fields(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                _fail("E_RIR_JSON", f"Duplicate JSON field: {key}")
            result[key] = value
        return result

    try:
        with args.graph.open("rb") as stream:
            data = stream.read(16 * 1024 * 1024 + 1)
        if len(data) > 16 * 1024 * 1024:
            _fail("E_RIR_LIMIT", "Serialized resource graph exceeds 16 MiB")
        document = json.loads(data.decode("utf-8"), object_pairs_hook=unique_fields,
                              parse_constant=lambda value: _fail("E_RIR_JSON", f"Invalid JSON constant: {value}"))
        report = verify_resource_ir(document)
    except (OSError, ValueError, RecursionError) as exc:
        report = {"schema": "hepta.resource-ir-validation.v1", "ok": False,
                  "status": "rejected", "claims": dict(_CLAIMS),
                  "diagnostics": [{"code": getattr(exc, "code", "E_RIR_JSON"), "message": str(exc)}]}
    # These hashes are supplied by the graph producer, not checked against source.
    report["source_binding_verified"] = False
    print(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
