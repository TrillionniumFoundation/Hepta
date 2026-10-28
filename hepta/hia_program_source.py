"""Checked Hepta AST to the standalone, closed-block HIA program format.

This adapter is a compiler pass, not an interpreter: it emits explicit typed
instructions, block arguments and resource operations.  Its output executes
without source text, the Hepta parser, or a native Rust compiler.  Source-level
records are scalarized, and concrete Results use a tag and both payloads.  An
inactive buffer payload is a real empty owner which is explicitly consumed.

The profile is deliberately bounded: integer/Boolean values, concrete records,
byte buffers, concrete Results, direct calls and structured control flow.
Closed generic calls/records are specialized as AST nodes before CFG lowering.
Foreign code, tasks, stored references, floats and unbounded specialization reject.
Scalarization is an internal calling convention, not a C aggregate ABI claim.
Public scalar entries are selected from the original declarations before
specialization or scalarization and retained in the verified Core exports.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
import hashlib
from typing import Any

from .ast import Expr, Function, MatchArm, Program, Stmt, Type
from .checker import check
from .parser import parse
from .hia_program import HIAProgramRejected, VerifiedProgram, verify_program
from .hia_schema import SCHEMA as SCHEMA_V1, SCHEMA_V8


class HIAProgramSourceRejected(ValueError):
    """A checked source lies outside the explicit standalone HIA profile."""


def _reject(message: str) -> None:
    raise HIAProgramSourceRejected("E_HIA_SOURCE: " + message)


class _Specialize:
    """Finite concrete AST instantiation; never renders or reparses source.

    A template is not an executable function.  Every emitted instance is checked
    again with its concrete types and then verified by the standalone HIA gate.
    The type-depth and instance budgets also reject polymorphic growth recursion.
    """
    def __init__(self, program, checked):
        self.program, self.checked = program, checked
        self.functions = {fn.name: fn for fn in program.functions}
        self.records = {record.name: record for record in program.structs}
        self.names = set(self.functions) | set(self.records)
        self.instances, self.record_instances = {}, {}
        self.pending, self.output, self.output_records, self.inventory = [], [], [], []

    def substituted(self, typ, mapping, depth=0):
        if depth > 32:
            _reject("generic specialization exceeds the 32-level concrete type limit")
        if typ.name in mapping:
            if typ.args or typ.length is not None or typ.lifetimes:
                _reject("malformed generic parameter use")
            return self.substituted(mapping[typ.name], {}, depth + 1)
        return replace(typ, args=tuple(self.substituted(arg, mapping, depth + 1) for arg in typ.args))

    def name(self, kind, original, args):
        if len(self.instances) + len(self.record_instances) >= 128:
            _reject("generic specialization exceeds the 128-instance function/record budget")
        # Args were depth checked before representation/hash construction.
        suffix = hashlib.sha256(repr((kind, original, args)).encode()).hexdigest()[:16]
        name = "hia_specialized_" + kind + "_" + original + "_" + suffix
        if name in self.names:
            _reject("specialized symbol collides with an existing declaration")
        self.names.add(name)
        self.inventory.append({"kind": kind, "template": original,
                               "arguments": list(map(str, args)), "instance": name})
        return name

    def typ(self, typ, mapping):
        concrete = self.substituted(typ, mapping)
        record = self.records.get(concrete.name)
        if record is not None and record.type_params:
            if len(record.type_params) != len(concrete.args) or concrete.lifetimes:
                _reject("generic record must have closed concrete type arguments")
            key = (record.name, concrete.args)
            if key not in self.record_instances:
                name = self.name("record", record.name, concrete.args)
                self.record_instances[key] = name
                bindings = dict(zip(record.type_params, concrete.args))
                self.output_records.append(replace(record, name=name, type_params=(),
                    fields=[replace(member, type=self.typ(member.type, bindings)) for member in record.fields]))
            return Type(self.record_instances[key])
        return replace(concrete, args=tuple(self.typ(arg, {}) for arg in concrete.args))

    def instance(self, function, args):
        args = tuple(self.substituted(arg, {}) for arg in args)
        if len(args) != len(function.type_params):
            _reject("generic function argument count is not concrete")
        key = (function.name, args)
        if key not in self.instances:
            name = self.name("fn", function.name, args) if args else function.name
            self.instances[key] = name
            self.pending.append((function, args, name))
        return self.instances[key]

    def expression(self, expr, mapping):
        children = [self.expression(child, mapping) for child in expr.children]
        value = self.payload(expr.value, mapping)
        args = tuple(self.typ(arg, mapping) for arg in expr.type_args)
        if expr.kind == "call" and expr.value in self.functions:
            target = self.functions[expr.value]
            concrete = tuple(self.substituted(arg, mapping) for arg in expr.type_args)
            value, args = self.instance(target, concrete), ()
        elif expr.kind == "struct":
            checked_type = self.checked.expr_types.get(id(expr))
            if checked_type is None:
                _reject("generic record construction has no checked type")
            concrete = self.typ(checked_type, mapping)
            value = {**value, "name": concrete.name}
            args = ()
        elif expr.kind == "variant":
            checked_type = self.checked.expr_types.get(id(expr))
            if checked_type is None or checked_type.name != "Result":
                _reject("only builtin Result is supported during generic specialization")
            args = self.typ(checked_type, mapping).args
        return replace(expr, value=value, children=children, type_args=args)

    def payload(self, value, mapping):
        if isinstance(value, Expr):
            return self.expression(value, mapping)
        if isinstance(value, Type):
            return self.typ(value, mapping)
        if isinstance(value, Stmt):
            return replace(value, data=self.payload(value.data, mapping))
        if isinstance(value, MatchArm):
            return replace(value, body=self.payload(value.body, mapping))
        if isinstance(value, list):
            return [self.payload(item, mapping) for item in value]
        if isinstance(value, tuple):
            return tuple(self.payload(item, mapping) for item in value)
        if isinstance(value, dict):
            return {key: self.payload(item, mapping) for key, item in value.items()}
        return value

    def run(self):
        for record in self.program.structs:
            if not record.type_params:
                self.output_records.append(replace(record,
                    fields=[replace(member, type=self.typ(member.type, {})) for member in record.fields]))
        for fn in self.program.functions:
            if not fn.type_params:
                self.instance(fn, ())
        while self.pending:
            fn, args, name = self.pending.pop(0)
            mapping = dict(zip(fn.type_params, args))
            concrete = replace(fn, name=name, type_params=(), type_bounds={},
                params=[replace(param, type=self.typ(param.type, mapping)) for param in fn.params],
                return_type=self.typ(fn.return_type, mapping), body=self.payload(fn.body, mapping))
            self.output.append(concrete)
        result = replace(self.program, structs=self.output_records, functions=self.output)
        return result, self.inventory


_SCALARS = {"bool", "i8", "u8", "i16", "u16", "i32", "u32",
            "i64", "u64", "isize", "usize"}
_RESOURCE = {"buffer", "readbuf", "mutbuf"}
_BINARY = {"+": "int.add.checked", "-": "int.sub.checked",
           "*": "int.mul.checked", "/": "int.div.checked",
           "%": "int.rem.checked", "<<": "int.shl.checked",
           ">>": "int.shr.checked", "&": "bit.and", "|": "bit.or",
           "^": "bit.xor", "==": "compare.eq", "!=": "compare.ne",
           "<": "compare.lt", "<=": "compare.le", ">": "compare.gt",
           ">=": "compare.ge"}


@dataclass
class _Value:
    typ: Type
    atoms: list[str | None]
    types: list[str]
    # Locally created loans, in creation order.  Parameter loans are not ours
    # to end.  A caller ends these after the complete argument evaluation/call.
    loans: list[str] = field(default_factory=list)
    origin: tuple[int, tuple[int, ...]] | None = None
    borrow_mode: str | None = None
    borrow_parents: list[int] = field(default_factory=list)

    def clone(self) -> "_Value":
        return _Value(self.typ, list(self.atoms), list(self.types),
                      list(self.loans), self.origin, self.borrow_mode, list(self.borrow_parents))


@dataclass
class _State:
    block: dict
    values: dict[int, _Value]
    env: dict[str, int]
    keep: set[int]

    def clone(self, block: dict) -> "_State":
        return _State(block, {k: v.clone() for k, v in self.values.items()},
                      dict(self.env), set(self.keep))

    def prune(self, keys=None) -> None:
        wanted = set(self.env.values()) | self.keep if keys is None else set(keys)
        self.values = {k: v for k, v in self.values.items() if k in wanted}


class _Lower:
    def __init__(self, program: Program, checked, module: str | None, *, exports, core_schema=SCHEMA_V1):
        if type(core_schema) is not str or core_schema not in {SCHEMA_V1, SCHEMA_V8}:
            _reject("source lowering supports explicit Core v1 or returned-loan Core v8")
        self.program, self.checked = program, checked
        self.core_schema = core_schema
        self.module = module or program.name
        self.structs = {s.name: s for s in program.structs}
        self.functions = {f.name: f for f in program.functions}
        self.serial = self.value_serial = self.block_serial = 0
        self.blocks: list[dict] = []
        self.current: Function | None = None
        self.mutable_parameters: list[int] = []
        self.signatures: dict[str, dict] = {}
        self.source_map: list[dict] = []
        self.exports = tuple(exports)

    def fresh(self, prefix="v") -> str:
        self.serial += 1
        return f"{prefix}{self.serial}"

    def layout(self, typ: Type, mode="value", seen=()) -> list[tuple[tuple[str, ...], str]]:
        if typ.lifetimes or typ.length is not None:
            _reject("stored references and fixed-array layouts are outside this profile")
        if typ.name == "Unit" and not typ.args:
            return []
        if typ.name in _SCALARS and not typ.args:
            return [((), typ.name)]
        if typ.name in {"Buffer", "slice"} and typ.args == (Type("u8"),):
            if typ.name == "slice" and mode not in {"read", "mut"}:
                _reject("a slice requires an explicit borrowed parameter")
            return [((), {"read": "readbuf", "mut": "mutbuf"}.get(mode, "buffer"))]
        if typ.name == "Result" and len(typ.args) == 2 and mode not in {"read", "mut"}:
            result = [(("tag",), "bool")]
            for tag, payload in zip(("Ok", "Err"), typ.args):
                result += [((tag, *path), leaf) for path, leaf in self.layout(payload, seen=seen)]
            return result
        record = self.structs.get(typ.name)
        if record is not None and not typ.args and not record.type_params and not record.lifetime_params:
            if typ.name in seen:
                _reject("recursive record layout")
            result = []
            for member in record.fields:
                result += [((member.name, *path), leaf)
                           for path, leaf in self.layout(member.type, mode, (*seen, typ.name))]
            return result
        _reject("unsupported concrete type " + str(typ))

    def typ(self, expr: Expr) -> Type:
        typ = self.checked.expr_types.get(id(expr))
        if typ is None:
            _reject("expression is absent from the fresh checked AST")
        return typ

    def value(self, state: _State, typ: Type, atoms, types=None, *, loans=(), origin=None, borrow_mode=None, borrow_parents=()) -> int:
        self.value_serial += 1
        ident = self.value_serial
        state.values[ident] = _Value(typ, list(atoms), list(types or [t for _, t in self.layout(typ)]),
                                     list(loans), origin, borrow_mode, list(borrow_parents))
        return ident

    def get(self, state: _State, key: int) -> _Value:
        value = state.values.get(key)
        if value is None or any(atom is None for atom in value.atoms):
            _reject("use of a consumed resource or unavailable value")
        return value

    def scalar(self, state: _State, key: int) -> str:
        value = self.get(state, key)
        if len(value.atoms) != 1 or value.types[0] in _RESOURCE:
            _reject("operation requires one scalar value")
        return value.atoms[0]

    def emit(self, state: _State, op: str, args=(), types=(), attrs=None) -> list[str]:
        if state.block["term"] is not None:
            _reject("instruction after a terminated block")
        out = [{"name": self.fresh(), "type": typ} for typ in types]
        state.block["ops"].append({"op": op, "args": list(args), "out": out, "attrs": attrs or {}})
        return [item["name"] for item in out]

    def const(self, state, typ: str, value) -> int:
        return self.value(state, Type(typ), self.emit(state, "const", types=[typ], attrs={"value": value}))

    def consume(self, state: _State, name: str) -> None:
        for value in state.values.values():
            value.atoms = [None if atom == name else atom for atom in value.atoms]
            had_loans = bool(value.loans)
            value.loans = [loan for loan in value.loans if loan != name]
            if had_loans and not value.loans:
                value.origin = None
                value.borrow_mode = None

    def end_loans(self, state: _State, key: int) -> None:
        value = state.values[key]
        for name in reversed(list(value.loans)):
            self.emit(state, "loan.end", [name])
            self.consume(state, name)
        value.loans = []
        value.origin = None
        value.borrow_mode = None
        parents, value.borrow_parents = value.borrow_parents, []
        for parent in reversed(parents):
            self.end_loans(state, parent)

    def new_block(self, state: _State, keys=None) -> tuple[_State, list[tuple[int, int]], list[str]]:
        self.block_serial += 1
        block = {"id": f"b{self.block_serial}", "params": [], "ops": [], "term": None}
        self.blocks.append(block)
        new = state.clone(block)
        if keys is not None:
            new.prune(keys)
        spec, incoming, renames, resource_aliases = [], [], {}, {}
        for key, value in new.values.items():
            for index, (atom, typ) in enumerate(zip(value.atoms, value.types)):
                if atom is None:
                    continue
                # Linear aliases introduced by a projection refer to the same
                # SSA capability.  Scalars need separate phi parameters because
                # assignments can make formerly equal values differ on an edge.
                if typ in _RESOURCE and atom in resource_aliases:
                    name = resource_aliases[atom]
                else:
                    name = self.fresh("p")
                    block["params"].append({"name": name, "type": typ})
                    spec.append((key, index))
                    incoming.append(atom)
                    if typ in _RESOURCE:
                        resource_aliases[atom] = name
                value.atoms[index] = name
                renames[atom] = name
        for value in new.values.values():
            value.loans = [renames[name] for name in value.loans]
        return new, spec, incoming

    def edge(self, state: _State, target: _State, spec) -> dict:
        args = []
        for key, index in spec:
            value = state.values.get(key)
            if value is None or index >= len(value.atoms) or value.atoms[index] is None:
                _reject("incompatible ownership or binding state across a CFG edge")
            args.append(value.atoms[index])
        # Check every aliased linear occurrence, not just the representative.
        expected = {}
        for key, target_value in target.values.items():
            value = state.values.get(key)
            if value is None or value.types != target_value.types:
                _reject("incompatible value layout across a CFG edge")
            for actual, renamed, typ in zip(value.atoms, target_value.atoms, value.types):
                if (actual is None) != (renamed is None):
                    _reject("path-dependent resource consumption")
                if actual is not None and typ in _RESOURCE:
                    if renamed in expected and expected[renamed] != actual:
                        _reject("path-dependent linear alias relation")
                    expected[renamed] = actual
        return {"target": target.block["id"], "args": args}

    def jump(self, state, target, spec):
        state.block["term"] = {"op": "jump", **self.edge(state, target, spec)}

    def branch(self, state, condition, yes, yes_spec, no, no_spec):
        state.block["term"] = {"op": "branch", "cond": condition,
                               "then": self.edge(state, yes, yes_spec),
                               "else": self.edge(state, no, no_spec)}

    def merge(self, states: list[_State], keys) -> _State | None:
        if not states:
            return None
        for state in states:
            state.prune(keys)
        if len(states) == 1:
            return states[0]
        joined, spec, _ = self.new_block(states[0], keys)
        for state in states:
            self.jump(state, joined, spec)
        return joined

    def place(self, state, expr: Expr) -> tuple[int, tuple[int, ...], Type]:
        if expr.kind == "name" and expr.value in state.env:
            key = state.env[expr.value]
            value = state.values[key]
            return key, tuple(range(len(value.atoms))), value.typ
        if expr.kind == "field":
            key, indices, base = self.place(state, expr.children[0])
            record = self.structs.get(base.name)
            if record is None:
                _reject("field projection requires a concrete record")
            offset = 0
            for member in record.fields:
                count = len(self.layout(member.type))
                if member.name == expr.value:
                    return key, indices[offset:offset + count], member.type
                offset += count
        _reject("borrow and assignment places must be local records or fields")

    def defaults(self, state, typ: Type) -> list[str]:
        out = []
        for _, leaf in self.layout(typ):
            if leaf == "buffer":
                zero = self.const(state, "usize", 0)
                out += self.emit(state, "buffer.new", [self.scalar(state, zero)], ["buffer"])
            else:
                out += self.emit(state, "const", types=[leaf], attrs={"value": False if leaf == "bool" else 0})
        return out

    def borrowed(self, state, expr: Expr, mode: str) -> tuple[_State, int]:
        key, indices, typ = self.place(state, expr)
        self.source_access(state, key, indices, write=mode == "mut")
        original = state.values[key]
        atoms, types, loans = [], [], []
        for index in indices:
            atom, leaf = original.atoms[index], original.types[index]
            if atom is None:
                _reject("borrow of consumed owner")
            if leaf in _RESOURCE:
                target = "readbuf" if mode == "read" else "mutbuf"
                name = self.emit(state, "borrow." + mode, [atom], [target])[0]
                atoms.append(name); types.append(target); loans.append(name)
            else:
                atoms.append(atom); types.append(leaf)
        return state, self.value(state, typ, atoms, types, loans=loans,
                                 origin=(key, indices), borrow_mode=mode)

    def source_access(self, state, key, indices, *, write=False):
        """Preserve source exclusivity for scalarized mutable record fields.

        Buffer capabilities are independently verified by HIA.  Scalarized
        records have no runtime address, so overlapping source borrows must be
        rejected here rather than silently choosing a copy/writeback ordering.
        """
        for value in state.values.values():
            if value.origin is None:
                continue
            root, borrowed_indices = value.origin
            if root == key and set(indices) & set(borrowed_indices) and (write or value.borrow_mode == "mut"):
                _reject("overlapping source access while a scalarized borrow is live")

    def expr(self, state: _State, expr: Expr | None) -> tuple[_State, int]:
        if expr is None:
            return state, self.value(state, Type("Unit"), [])
        typ = self.typ(expr)
        if expr.type_args and expr.kind != "variant":
            _reject("generic calls must be concretized before HIA lowering")
        if expr.kind in {"int", "bool"}:
            return state, self.const(state, typ.name, expr.value)
        if expr.kind == "name":
            if expr.value not in state.env:
                _reject("unbound source local " + expr.value)
            origin = state.env[expr.value]
            value = self.get(state, origin)
            self.source_access(state, origin, range(len(value.atoms)))
            return state, self.value(state, typ, value.atoms, value.types)
        if expr.kind == "field":
            root = expr
            while root.kind == "field":
                root = root.children[0]
            if root.kind == "name":
                key, indices, _ = self.place(state, expr)
                self.source_access(state, key, indices)
                original = state.values[key]
                atoms = [original.atoms[index] for index in indices]
                if any(atom is None for atom in atoms):
                    _reject("field access after resource consumption")
                return state, self.value(state, typ, atoms, [original.types[index] for index in indices])
            state, base_key = self.expr(state, expr.children[0])
            base = self.get(state, base_key)
            record = self.structs.get(base.typ.name)
            if record is None:
                _reject("field of unsupported value")
            offset = 0
            for member in record.fields:
                count = len(self.layout(member.type))
                if member.name == expr.value:
                    atoms, types = base.atoms[offset:offset + count], base.types[offset:offset + count]
                    if not any(leaf in _RESOURCE for leaf in types):
                        # Reading a Copy field completes this immediate borrow;
                        # its scalar value no longer carries the resource view.
                        self.end_loans(state, base_key)
                        return state, self.value(state, typ, atoms, types)
                    return state, self.value(state, typ, atoms, types, loans=base.loans,
                                             borrow_parents=[base_key])
                offset += count
            _reject("missing checked record field")
        if expr.kind == "struct":
            parts = {}
            for name, child in zip(expr.value["fields"], expr.children):
                state, key = self.expr(state, child)
                parts[name] = key
            atoms, types = [], []
            for member in self.structs[typ.name].fields:
                value = self.get(state, parts[member.name])
                atoms += value.atoms; types += value.types
            return state, self.value(state, typ, atoms, types)
        if expr.kind == "variant" and typ.name == "Result":
            if expr.value.get("enum") != "Result" or expr.value.get("variant") not in {"Ok", "Err"} or len(expr.children) != 1:
                _reject("only concrete one-payload Results are supported")
            state, payload = self.expr(state, expr.children[0])
            tag = expr.value["variant"]
            bit = self.const(state, "bool", tag == "Ok")
            inactive = self.defaults(state, typ.args[1 if tag == "Ok" else 0])
            live = list(self.get(state, payload).atoms)
            atoms = [self.scalar(state, bit)] + (live + inactive if tag == "Ok" else inactive + live)
            return state, self.value(state, typ, atoms)
        if expr.kind == "unary":
            mode = expr.value
            if mode in {"read", "mut"}:
                return self.borrowed(state, expr.children[0], mode)
            # The signed minimum literal is not a representable positive value.
            if mode == "-" and expr.children[0].kind == "int":
                return state, self.const(state, typ.name, -expr.children[0].value)
            state, key = self.expr(state, expr.children[0])
            value = self.get(state, key)
            if mode == "move":
                atoms = []
                for atom, leaf in zip(list(value.atoms), value.types):
                    if leaf == "buffer":
                        atoms += self.emit(state, "owner.move", [atom], [leaf])
                        self.consume(state, atom)
                    elif leaf in {"readbuf", "mutbuf"}:
                        _reject("stored/moved borrowed values are outside source profile")
                    else:
                        atoms.append(atom)
                return state, self.value(state, typ, atoms, value.types)
            if mode == "+":
                return state, key
            op = "int.neg.checked" if mode == "-" else "bool.not" if typ.name == "bool" else "bit.not"
            if mode not in {"-", "!"}:
                _reject("unsupported unary operation")
            return state, self.value(state, typ, self.emit(state, op, [self.scalar(state, key)], [typ.name]))
        if expr.kind == "binary" and expr.value in {"&&", "||"}:
            state, left = self.expr(state, expr.children[0])
            condition = self.scalar(state, left)
            keys = set(state.values)
            result_key = self.value(state, typ, [condition])
            keys.add(result_key)
            rhs, rhs_spec, _ = self.new_block(state, keys)
            short, short_spec, _ = self.new_block(state, keys)
            if expr.value == "&&":
                self.branch(state, condition, rhs, rhs_spec, short, short_spec)
            else:
                self.branch(state, condition, short, short_spec, rhs, rhs_spec)
            rhs, right = self.expr(rhs, expr.children[1])
            rhs.values[result_key] = self.get(rhs, right).clone()
            short.values[result_key] = self.get(short, left).clone()
            state = self.merge([rhs, short], keys)
            return state, result_key
        if expr.kind == "binary" and expr.value in _BINARY:
            state, left = self.expr(state, expr.children[0])
            state, right = self.expr(state, expr.children[1])
            return state, self.value(state, typ, self.emit(state, _BINARY[expr.value],
                [self.scalar(state, left), self.scalar(state, right)], [typ.name]))
        if expr.kind == "cast":
            state, value = self.expr(state, expr.children[0])
            if typ.name not in _SCALARS - {"bool"} or self.typ(expr.children[0]).name not in _SCALARS - {"bool"}:
                _reject("HIA source casts require integers")
            return state, self.value(state, typ, self.emit(state, "int.cast", [self.scalar(state, value)],
                                                           [typ.name], {"mode": "wrap"}))
        if expr.kind == "index":
            state, base = self.expr(state, expr.children[0])
            value = self.get(state, base)
            if len(value.atoms) != 1 or value.types[0] not in _RESOURCE:
                _reject("only byte buffer indexing is supported")
            view = self.emit(state, "borrow.read", value.atoms, ["readbuf"])[0]
            view_key = self.value(state, Type("slice", (Type("u8"),)), [view], ["readbuf"], loans=[view])
            state, index = self.expr(state, expr.children[1])
            view = self.get(state, view_key).atoms[0]
            result = self.emit(state, "buffer.load", [view, self.scalar(state, index)], ["u8"])
            self.end_loans(state, view_key)
            self.end_loans(state, base)
            return state, self.value(state, typ, result)
        if expr.kind == "call":
            return self.call(state, expr)
        _reject("unsupported source expression " + expr.kind)

    def call(self, state, expr):
        typ, name = self.typ(expr), expr.value
        arguments = []
        for child in expr.children:
            state, key = self.expr(state, child)
            arguments.append(key)
        if name in {"buffer", "try_buffer"}:
            if len(arguments) != 1:
                _reject("wrong buffer arity")
            size = self.scalar(state, arguments[0])
            if name == "buffer":
                return state, self.value(state, typ, self.emit(state, "buffer.new", [size], ["buffer"]))
            owner, success = self.emit(state, "buffer.try_new", [size], ["buffer", "bool"])
            error = self.emit(state, "const", types=["u8"], attrs={"value": 1})[0]
            return state, self.value(state, typ, [success, owner, error])
        if name in {"drop", "release"}:
            if len(arguments) != 1:
                _reject("wrong owner release arity")
            value = self.get(state, arguments[0])
            for atom, leaf in zip(list(value.atoms), value.types):
                if leaf == "buffer":
                    self.emit(state, "owner.drop", [atom]); self.consume(state, atom)
                elif leaf in {"readbuf", "mutbuf"}:
                    _reject("cannot drop an incoming borrowed capability")
            return state, self.value(state, Type("Unit"), [])
        if name == "len":
            if len(arguments) != 1:
                _reject("wrong len arity")
            value = self.get(state, arguments[0])
            if len(value.atoms) != 1 or value.types[0] not in _RESOURCE:
                _reject("len requires a byte owner or view")
            atoms = self.emit(state, "buffer.len", value.atoms, ["usize"])
            self.end_loans(state, arguments[0])
            return state, self.value(state, typ, atoms)
        if name == "assert":
            if len(arguments) != 1:
                _reject("wrong assertion arity")
            condition = self.scalar(state, arguments[0])
            good, good_spec, _ = self.new_block(state)
            bad, bad_spec, _ = self.new_block(state)
            self.branch(state, condition, good, good_spec, bad, bad_spec)
            bad.block["term"] = {"op": "trap", "code": "user"}
            return good, self.value(good, Type("Unit"), [])
        if name in {"wrapping_add", "wrapping_sub", "wrapping_mul", "min", "max"}:
            if len(arguments) != 2:
                _reject("wrong integer builtin arity")
            args = [self.scalar(state, key) for key in arguments]
            if name.startswith("wrapping_"):
                atoms = self.emit(state, "int." + name[9:] + ".wrap", args, [typ.name])
            else:
                condition = self.emit(state, "compare.lt" if name == "min" else "compare.gt", args, ["bool"])[0]
                atoms = self.emit(state, "select", [condition, *args], [typ.name])
            return state, self.value(state, typ, atoms)
        fn = self.functions.get(name)
        if fn is None or fn.extern_c:
            _reject("foreign or unknown call " + str(name))
        if fn.return_mode != "value" and self.core_schema != SCHEMA_V8:
            return self.inline_borrow_return(state, fn, arguments)
        signature = self.signatures[name]
        args = [atom for key in arguments for atom in self.get(state, key).atoms]
        types = [leaf for key in arguments for leaf in self.get(state, key).types]
        if types != signature["params"]:
            _reject("argument mode differs from lowered signature for " + name)
        atoms = self.emit(state, "call", args, signature["returns"], {"function": name})
        for atom, leaf in zip(args, types):
            if leaf == "buffer":
                self.consume(state, atom)
        result_types = [leaf for _, leaf in self.layout(fn.return_type, fn.return_mode)]
        count = len(result_types)
        origin_argument = None
        if fn.return_mode != "value":
            origin_argument = arguments[next(i for i, p in enumerate(fn.params) if p.name == fn.return_origin)]
            parent = self.get(state, origin_argument)
            result = self.value(state, typ, atoms[:count], result_types,
                                loans=[*parent.loans, *atoms[:count]], origin=parent.origin,
                                borrow_mode=fn.return_mode, borrow_parents=[origin_argument])
        else:
            result = self.value(state, typ, atoms[:count], result_types)
        offset = count
        for param, key in zip(fn.params, arguments):
            value = state.values[key]
            if param.mode == "mut":
                if value.origin is None:
                    _reject("mutable source argument lacks an addressable origin")
                original_key, indices = value.origin
                original = state.values[original_key]
                for part, leaf in zip(indices, value.types):
                    if leaf not in _RESOURCE:
                        original.atoms[part] = atoms[offset]; offset += 1
            if key != origin_argument:
                self.end_loans(state, key)
        return state, result

    def inline_borrow_return(self, state, fn, arguments):
        if len(fn.body or []) != 1 or fn.body[0].kind != "return":
            _reject("borrow-return helper must be one checked projection return")
        expression = fn.body[0].data["expr"]
        if expression.kind != "unary" or expression.value not in {"read", "mut"}:
            _reject("borrow-return helper must return an explicit projection borrow")
        original_env = state.env
        state.env = {param.name: key for param, key in zip(fn.params, arguments)}
        state, result = self.expr(state, expression)
        state.env = original_env
        value = state.values[result]
        parents = [loan for key in arguments for loan in state.values[key].loans]
        value.loans = parents + value.loans
        value.borrow_parents = list(arguments)
        # Type is a slice although projection borrows retain the source's Buffer
        # type internally.  Runtime representation remains one checked view.
        value.typ = fn.return_type
        return state, result

    def scoped(self, statements, state):
        before = dict(state.env)
        state = self.sequence(statements, state)
        if state is not None:
            state.env = before
        return state

    def sequence(self, statements: list[Stmt], state: _State) -> _State | None:
        for stmt in statements:
            if state is None:
                break
            d = stmt.data
            if stmt.kind == "let":
                state, value_key = self.expr(state, d["expr"])
                value = self.get(state, value_key)
                if value.loans or value.origin is not None:
                    _reject("stored local borrows require the explicit lifetime profile")
                key = self.value(state, value.typ, value.atoms, value.types)
                state.env[d["name"]] = key
            elif stmt.kind == "assign":
                # Hepta's established assignment semantics evaluate the RHS
                # before the destination index and its mutable borrow.
                state, value_key = self.expr(state, d["expr"])
                if d["target"].kind == "index":
                    target = d["target"]
                    state, index = self.expr(state, target.children[1])
                    state, view = self.borrowed(state, target.children[0], "mut")
                    self.emit(state, "buffer.store", [self.get(state, view).atoms[0],
                              self.scalar(state, index), self.scalar(state, value_key)])
                    self.end_loans(state, view)
                else:
                    key, indices, _ = self.place(state, d["target"])
                    self.source_access(state, key, indices, write=True)
                    value = self.get(state, value_key)
                    old = state.values[key]
                    selected_types = [old.types[index] for index in indices]
                    if selected_types != value.types:
                        _reject("assignment value and destination layouts differ")
                    if any(typ in _RESOURCE for typ in selected_types):
                        # Fresh source checking proves that this named owned
                        # field, including its Copy members, was fully moved
                        # out and that every enclosing record is still live.
                        # Check the erased owner slots independently: restoring
                        # a field must never overwrite a live capability or
                        # turn a borrowed slot into a new owner.  Scalar atoms
                        # are immutable copies, so their old aliases remain
                        # valid while this destination receives new values.
                        if (d["target"].kind != "field" or value.loans
                                or value.origin is not None
                                or any(old.types[index] != "buffer" or old.atoms[index] is not None
                                       for index in indices if old.types[index] in _RESOURCE)):
                            _reject("resource restoration requires a fully moved named owned field")
                    for index, atom in zip(indices, value.atoms):
                        old.atoms[index] = atom
            elif stmt.kind == "expr":
                state, value = self.expr(state, d["expr"])
                self.end_loans(state, value)
            elif stmt.kind == "return":
                state, value = self.expr(state, d.get("expr"))
                result = list(self.get(state, value).atoms)
                for key in self.mutable_parameters:
                    param = state.values[key]
                    result += [atom for atom, leaf in zip(param.atoms, param.types) if leaf not in _RESOURCE]
                state.block["term"] = {"op": "ret", "values": result}
                state = None
            elif stmt.kind == "if":
                state, value = self.expr(state, d["condition"])
                condition = self.scalar(state, value)
                state.prune()
                keys = set(state.values)
                yes, yes_spec, _ = self.new_block(state)
                no, no_spec, _ = self.new_block(state)
                self.branch(state, condition, yes, yes_spec, no, no_spec)
                branches = [self.scoped(d["then"], yes), self.scoped(d["else"], no)]
                state = self.merge([branch for branch in branches if branch is not None], keys)
            elif stmt.kind == "while":
                state = self.loop(state, lambda current: self.expr(current, d["condition"]),
                                  lambda current: self.scoped(d["body"], current))
            elif stmt.kind == "for":
                state, start = self.expr(state, d["start"])
                state, end = self.expr(state, d["end"])
                saved_env = dict(state.env)
                loop_value = self.get(state, start)
                index = self.value(state, loop_value.typ, loop_value.atoms, loop_value.types)
                state.env[d["name"]] = index
                state.keep.add(end)

                def condition(current):
                    atoms = self.emit(current, "compare.lt", [self.scalar(current, index), self.scalar(current, end)], ["bool"])
                    return current, self.value(current, Type("bool"), atoms)

                def body(current):
                    current = self.scoped(d["body"], current)
                    if current is not None:
                        one = self.const(current, loop_value.types[0], 1)
                        atoms = self.emit(current, "int.add.checked", [self.scalar(current, index), self.scalar(current, one)], loop_value.types)
                        current.values[index].atoms = atoms
                    return current

                state = self.loop(state, condition, body)
                state.keep.discard(end)
                state.env = saved_env
            elif stmt.kind == "match":
                state, result = self.expr(state, d["expr"])
                value = self.get(state, result)
                if value.typ.name != "Result":
                    _reject("only concrete Result matching is supported")
                arms = {arm.pattern.variant: arm for arm in d["arms"]}
                if set(arms) != {"Ok", "Err"} or len(d["arms"]) != 2:
                    _reject("Result match requires both variants exactly once")
                state.prune(set(state.env.values()) | state.keep | {result})
                keys = set(state.env.values()) | state.keep
                yes, yes_spec, _ = self.new_block(state)
                no, no_spec, _ = self.new_block(state)
                self.branch(state, value.atoms[0], yes, yes_spec, no, no_spec)
                ok_count = len(self.layout(value.typ.args[0]))
                branches = []
                for tag, branch in (("Ok", yes), ("Err", no)):
                    result_value = self.get(branch, result)
                    if tag == "Ok":
                        active, inactive = slice(1, 1 + ok_count), slice(1 + ok_count, None)
                        payload_type = value.typ.args[0]
                    else:
                        active, inactive = slice(1 + ok_count, None), slice(1, 1 + ok_count)
                        payload_type = value.typ.args[1]
                    live_atoms = list(result_value.atoms[active])
                    live_types = list(result_value.types[active])
                    for atom, leaf in zip(list(result_value.atoms[inactive]), result_value.types[inactive]):
                        if leaf == "buffer":
                            self.emit(branch, "owner.drop", [atom]); self.consume(branch, atom)
                    # Destructuring changes only the compile-time names, not the
                    # runtime owner.  Its unique SSA capability is retained.
                    original_env = dict(branch.env)
                    arm = arms[tag]
                    if len(arm.pattern.bindings) != 1:
                        _reject("Result payload pattern requires one binding")
                    branch.env[arm.pattern.bindings[0]] = self.value(branch, payload_type, live_atoms, live_types)
                    branch = self.sequence(arm.body, branch)
                    if branch is not None:
                        branch.env = original_env
                        branches.append(branch)
                state = self.merge(branches, keys)
            else:
                _reject("unsupported source statement " + stmt.kind)
            if state is not None:
                state.prune()
        return state

    def loop(self, state, condition, body):
        state.prune()
        keys = set(state.values)
        header, header_spec, _ = self.new_block(state)
        self.jump(state, header, header_spec)
        # The condition may create additional CFG blocks (notably short
        # circuit operators) and append temporaries to the original header
        # state.  Backedges target the original block interface, not that
        # subsequently mutated expression-evaluation environment.
        header_interface = header.clone(header.block)
        condition_state, value = condition(header)
        name = self.scalar(condition_state, value)
        condition_state.prune(keys)
        inside, inside_spec, _ = self.new_block(condition_state)
        outside, outside_spec, _ = self.new_block(condition_state)
        self.branch(condition_state, name, inside, inside_spec, outside, outside_spec)
        back = body(inside)
        if back is not None:
            back.prune(keys)
            self.jump(back, header_interface, header_spec)
        return outside

    def function(self, fn):
        self.current, self.blocks, self.mutable_parameters = fn, [], []
        self.block_serial += 1
        entry = {"id": f"b{self.block_serial}", "params": [], "ops": [], "term": None}
        self.blocks.append(entry)
        state = _State(entry, {}, {}, set())
        origins = {}
        for param in fn.params:
            leaves = self.layout(param.type, param.mode)
            atoms = []
            for _, typ in leaves:
                name = self.fresh("arg")
                entry["params"].append({"name": name, "type": typ})
                atoms.append(name)
            key = self.value(state, param.type, atoms, [typ for _, typ in leaves])
            origins[param.name] = list(atoms)
            state.env[param.name] = key
            if param.mode == "mut":
                self.mutable_parameters.append(key)
                state.keep.add(key)
        state = self.sequence(fn.body, state)
        if state is not None:
            if fn.return_type != Type("Unit"):
                _reject("non-unit function falls through")
            outputs = [atom for key in self.mutable_parameters
                       for atom, leaf in zip(state.values[key].atoms, state.values[key].types)
                       if leaf not in _RESOURCE]
            state.block["term"] = {"op": "ret", "values": outputs}
        result = {"name": fn.name, "params": entry["params"],
                "returns": self.signatures[fn.name]["returns"], "effects": [],
                "entry": entry["id"], "blocks": self.blocks}
        if self.core_schema == SCHEMA_V8 and fn.return_mode != "value":
            result["return_loans"] = [origins[fn.return_origin][0]] + [None] * (len(result["returns"]) - 1)
        return result

    def lower(self):
        if not self.checked.ok or self.checked.assumptions:
            _reject("checked source without foreign assumptions is required")
        if self.program.imports or self.program.enums or len(self.functions) > 128:
            _reject("one bounded module with concrete records and builtin Result is required")
        for record in self.program.structs:
            self.layout(Type(record.name))
        for fn in self.program.functions:
            if (fn.extern_c or fn.body is None or fn.type_params or fn.lifetime_params
                    or fn.effects - {"alloc", "block", "panic", "write"}):
                _reject("unsupported function contract " + fn.name)
            if fn.return_lifetime:
                _reject("stored lifetime returns are outside this profile")
            if fn.return_mode != "value" and self.core_schema == SCHEMA_V8:
                origin = next((p for p in fn.params if p.name == fn.return_origin), None)
                if (origin is None or origin.mode not in {"read", "mut"}
                        or origin.type.name not in {"Buffer", "slice"}
                        or self.layout(origin.type, origin.mode) not in [[((), "readbuf")], [((), "mutbuf")]]
                        or self.layout(fn.return_type, fn.return_mode) not in [[((), "readbuf")], [((), "mutbuf")]]):
                    _reject("v8 borrowed return requires one explicit byte-view parameter origin")
            elif fn.return_mode != "value":
                if len(fn.body) != 1 or fn.body[0].kind != "return":
                    _reject("every borrow-return declaration must be an inline projection helper")
                projection = fn.body[0].data["expr"]
                if projection.kind != "unary" or projection.value not in {"read", "mut"}:
                    _reject("borrow-return helper must return an explicit projection borrow")
                root = projection.children[0]
                while root.kind == "field":
                    root = root.children[0]
                if root.kind != "name" or root.value not in {p.name for p in fn.params if p.mode in {"read", "mut"}}:
                    _reject("borrow-return helper must project an incoming borrowed parameter")
            params = [leaf for param in fn.params for _, leaf in self.layout(param.type, param.mode)]
            returns = [leaf for _, leaf in self.layout(fn.return_type, fn.return_mode)]
            returns += [leaf for param in fn.params if param.mode == "mut"
                        for _, leaf in self.layout(param.type, param.mode) if leaf not in _RESOURCE]
            if fn.export_c and (any(param.type.name not in _SCALARS for param in fn.params)
                                or fn.return_type.name not in _SCALARS | {"Unit"}):
                _reject("aggregate scalarization does not preserve a public C ABI")
            self.signatures[fn.name] = {"params": params, "returns": returns}
        functions = [self.function(fn) for fn in self.program.functions
                     if fn.return_mode == "value" or self.core_schema == SCHEMA_V8]
        # Infer a conservative effect fixed point from actual emitted operations.
        by_name = {fn["name"]: fn for fn in functions}
        effects, calls = {}, {}
        for fn in functions:
            local, invoked = set(), set()
            if any(typ in {"readbuf", "mutbuf"} for typ in fn["returns"]):
                local.add("read")
            for block in fn["blocks"]:
                if block["term"]["op"] == "trap":
                    local.add("trap")
                for instruction in block["ops"]:
                    op = instruction["op"]
                    if op == "call":
                        invoked.add(instruction["attrs"]["function"])
                    if op in {"buffer.new", "buffer.try_new", "owner.drop"}:
                        local.add("alloc")
                    if op in {"buffer.len", "buffer.load", "borrow.read", "borrow.mut"}:
                        local.add("read")
                    if op == "buffer.store":
                        local.update({"read", "write"})
                    if op.endswith(".checked") or op in {"buffer.new", "buffer.load", "buffer.store"}:
                        local.add("trap")
            effects[fn["name"]], calls[fn["name"]] = local, invoked
        changed = True
        while changed:
            changed = False
            for name in effects:
                combined = effects[name] | set().union(*(effects[callee] for callee in calls[name]))
                if combined != effects[name]:
                    effects[name] = combined; changed = True
        for name, fn in by_name.items():
            fn["effects"] = sorted(effects[name])
        return {"schema": self.core_schema, "module": self.module,
                "exports": list(self.exports), "functions": functions}


def _prepare(program):
    if not isinstance(program, Program):
        _reject("expected the shared Hepta Program AST")
    fresh = check(program)
    if not fresh.ok:
        _reject("source checking failed: " + "; ".join(d.message for d in fresh.diagnostics[:8]))
    # An aggregate, borrowed scalar, or generic instance may flatten to the
    # same primitive signature as a public C scalar function.  Its source
    # calling convention does not thereby become a scalar C ABI.  Record this
    # boundary before generic instantiation erases those original distinctions.
    # Preserve the established convenience entrypoints for ordinary value
    # scalar functions, including functions without an explicit export marker.
    def scalar(typ, *, unit=False):
        return (typ.name in _SCALARS | ({"Unit"} if unit else set())
                and not typ.args and typ.length is None and not typ.lifetimes)
    exports = tuple(sorted(fn.name for fn in program.functions
        if not fn.extern_c and not fn.type_params and not fn.lifetime_params
        and fn.return_mode == "value" and scalar(fn.return_type, unit=True)
        and all(p.mode == "value" and scalar(p.type) for p in fn.params)))
    instances = []
    if any(fn.type_params for fn in program.functions) or any(record.type_params for record in program.structs):
        if (program.imports or program.enums or fresh.assumptions
                or any(fn.lifetime_params or fn.return_lifetime or fn.extern_c
                       or fn.effects - {"alloc", "block", "panic", "write"} for fn in program.functions)
                or any(record.lifetime_params for record in program.structs)):
            _reject("generic specialization requires the same closed, concrete HIA source profile")
        program, instances = _Specialize(program, fresh).run()
        fresh = check(program)
        if not fresh.ok:
            _reject("concrete instance checking failed: " + "; ".join(d.message for d in fresh.diagnostics[:8]))
    return program, fresh, instances, exports


def lower_program(program: Program, checked=None, *, module: str | None = None,
                  core_schema: str = SCHEMA_V1) -> VerifiedProgram:
    """Lower an actual AST directly; the supplied check receipt is never trusted.

    Rechecking binds expression types to these AST objects.  No source text is
    generated, reparsed or needed by the resulting HIA executable program.
    """
    program, fresh, _, exports = _prepare(program)
    return verify_program(_Lower(program, fresh, module, exports=exports, core_schema=core_schema).lower())


def lower_source(source: str, *, path="<hia-source>", module: str | None = None,
                 core_schema: str = SCHEMA_V1) -> VerifiedProgram:
    """Parse once at the source boundary, then lower/check the standalone HIA."""
    if type(source) is not str or len(source.encode("utf-8")) > 1024 * 1024:
        _reject("source must be UTF-8 text within the one MiB limit")
    return lower_program(parse(source, path), module=module, core_schema=core_schema)


def source_report(source: str, *, path="<hia-source>", module: str | None = None,
                  core_schema: str = SCHEMA_V1) -> dict:
    """Describe the exact finite source adaptation without claiming refinement."""
    program = parse(source, path)
    concrete, checked, instances, exports = _prepare(program)
    result = verify_program(_Lower(concrete, checked, module, exports=exports, core_schema=core_schema).lower())
    emitted = {fn["name"] for fn in result.as_dict()["functions"]}
    specialized = {row["template"] for row in instances if row["kind"] == "fn"}
    return {"schema": "hepta.hia-source-lowering.v1", "ok": True,
            "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
            "program_sha256": result.sha256,
            "core_schema": core_schema,
            "functions": [{"name": fn.name, "status": ("template_specialized" if fn.name in specialized else "template_uninstantiated")
                           if fn.type_params else "lowered" if fn.name in emitted else "inlined_borrow_projection"}
                          for fn in program.functions],
            "specializations": [{**row, "status": "lowered" if row["instance"] in emitted else
                                 "scalarized_record" if row["kind"] == "record" else "inlined_borrow_projection"}
                                for row in instances],
            "claims": {"standalone_program": True, "direct_ast_to_cfg": True,
                       "primitive_returned_loans": core_schema == SCHEMA_V8,
                       "closed_generic_instances_checked": True,
                       "all_possible_generic_instantiations_proved": False,
                       "source_text_required_for_execution": False,
                       "source_to_ir_refinement_proved": False,
                       "c_aggregate_abi_preserved_by_scalarization": False}}


def lower_c_multi_owner(database, *, clang="clang") -> dict:
    """Migrate a captured C subset with structurally recognized byte owners.

    This extends the existing Clang project frontend locally, without treating
    an entire fixture AST as a template.  Each guarded calloc creates one owner
    and nests the remaining source CFG in its success arm.  The source's own
    cleanup statements are translated; the checker rejects a missing release.
    Counts must be unchanged unsigned parameters, and an explicit leading
    zero-count return is required.  Custom allocators, pointer escape, malloc,
    realloc and arbitrary pointer expressions are rejected.

    The generated Hepta text is a reviewable migration product, parsed once as
    source input.  Execution and LLVM generation consume only verified HIA.
    """
    from .c_project import capture_project, verify_capture
    from .c_translation import CTranslator, Expression, ident
    from .c_migrate import MigrationRejected

    def children(node):
        return node.get("inner", [])

    def unwrap(node):
        while node.get("kind") in {"ImplicitCastExpr", "CStyleCastExpr", "ParenExpr"} and len(children(node)) == 1:
            node = children(node)[0]
        return node

    def reference(node):
        node = unwrap(node)
        return node.get("referencedDecl", {}) if node.get("kind") == "DeclRefExpr" else {}

    def call(node):
        node = unwrap(node)
        if node.get("kind") != "CallExpr" or not children(node):
            return None, []
        return reference(children(node)[0]).get("name"), children(node)[1:]

    def zero_guards(node):
        node = unwrap(node)
        inner = children(node)
        if node.get("kind") == "BinaryOperator" and node.get("opcode") == "||" and len(inner) == 2:
            return zero_guards(inner[0]) | zero_guards(inner[1])
        if node.get("kind") == "BinaryOperator" and node.get("opcode") == "==" and len(inner) == 2:
            for left, right in (inner, list(reversed(inner))):
                if unwrap(right).get("kind") == "IntegerLiteral" and int(unwrap(right).get("value", -1)) == 0:
                    ref = reference(left)
                    return {ref["id"]} if ref.get("kind") == "ParmVarDecl" else set()
        return set()

    class MultiOwner(CTranslator):
        def __init__(self, capture):
            super().__init__(capture)
            self.owners = {}
            self.guarded = set()
            self.owner_count = 0

        def stmt(self, node, depth=1):
            if node.get("kind") == "CompoundStmt":
                return self.sequence(children(node), depth)
            name, args = call(node)
            if name == "free":
                if len(args) != 1 or reference(args[0]).get("id") not in self.owners:
                    raise MigrationRejected("E_C_HIA_OWNER", "free must consume a known byte owner")
                owner = self.owners[reference(args[0])["id"]]
                return ["    " * depth + f"drop(move {owner});"]
            return super().stmt(node, depth)

        def sequence(self, nodes, depth=1):
            output = []
            index = 0
            while index < len(nodes):
                node = nodes[index]
                decls = children(node)
                if node.get("kind") == "DeclStmt" and len(decls) == 1 and decls[0].get("kind") == "VarDecl":
                    declaration = decls[0]
                    initializer = children(declaration)
                    allocator, args = call(initializer[0]) if len(initializer) == 1 else (None, [])
                    if allocator in {"calloc", "malloc", "realloc", "aligned_alloc"}:
                        if allocator != "calloc" or len(args) != 2:
                            raise MigrationRejected("E_C_HIA_OWNER", "Only calloc(count,1) has modeled multi-owner initialization")
                        raw = declaration.get("type", {}).get("desugaredQualType", declaration.get("type", {}).get("qualType", ""))
                        if raw not in {"unsigned char *", "uint8_t *"} or declaration.get("storageClass"):
                            raise MigrationRejected("E_C_HIA_OWNER", "Allocation must initialize an automatic byte pointer")
                        count_ref = reference(args[0])
                        count = self.bindings.get(count_ref.get("id"))
                        if (count_ref.get("kind") != "ParmVarDecl" or count_ref.get("id") not in self.guarded
                                or count is None or count.typ != "usize"
                                or unwrap(args[1]).get("kind") != "IntegerLiteral"
                                or int(unwrap(args[1]).get("value", -1)) != 1):
                            raise MigrationRejected("E_C_HIA_OWNER", "calloc extent needs an unchanged, zero-guarded size_t parameter and element size one")
                        if index + 1 >= len(nodes):
                            raise MigrationRejected("E_C_HIA_OWNER", "Allocation needs its immediate null failure branch")
                        guard = nodes[index + 1]
                        parts = children(guard)
                        predicate = unwrap(parts[0]) if parts else {}
                        if (guard.get("kind") != "IfStmt" or len(parts) != 2
                                or predicate.get("kind") != "UnaryOperator" or predicate.get("opcode") != "!"
                                or len(children(predicate)) != 1
                                or reference(children(predicate)[0]).get("id") != declaration["id"]):
                            raise MigrationRejected("E_C_HIA_OWNER", "Allocation failure must be an immediate if(!owner) branch")
                        failure = parts[1]
                        failure_nodes = children(failure) if failure.get("kind") == "CompoundStmt" else [failure]
                        if not failure_nodes or failure_nodes[-1].get("kind") != "ReturnStmt":
                            raise MigrationRejected("E_C_HIA_OWNER", "Allocation failure branch must return after explicit prior-owner cleanup")
                        # The failed pointer is intentionally not bound in the
                        # failure arm.  Its source cleanup may only use earlier
                        # successfully acquired owners.
                        failure_lines = self.sequence(failure_nodes, depth + 2)
                        self.counter += 1
                        owner = "owner_" + ident(declaration["name"]) + "_" + str(self.counter)
                        self.bindings[declaration["id"]] = Expression(owner, "slice:u8")
                        self.binding_modes[owner] = "mut"
                        self.owners[declaration["id"]] = owner
                        self.owner_count += 1
                        success_lines = self.sequence(nodes[index + 2:], depth + 2)
                        pad = "    " * depth
                        output += [pad + f"match try_buffer({count.text}) {{",
                                   pad + "    Result::Err(allocation_error) => {", *failure_lines,
                                   pad + "    },", pad + f"    Result::Ok(acquired_{owner}) => {{",
                                   # Pattern bindings are immutable by default;
                                   # move into a mutable local for C writes.
                                   pad + f"        let mut {owner} = move acquired_{owner};",
                                   *success_lines, pad + "    },", pad + "}"]
                        return output
                output += self.stmt(node, depth)
                index += 1
            return output

        def emit_multi(self):
            self.collect()
            pieces = ["module c_multi_owner_migrated;"]
            reports = []
            for key, fn in sorted(self.functions.items()):
                if self.records or any(param["pointer"] for param in fn["params"]):
                    raise MigrationRejected("E_C_HIA_OWNER", "This source profile accepts scalar interfaces and local owned byte arrays")
                self.current, self.bindings, self.binding_modes, self.counter = fn, {}, {}, 0
                self.owners, self.guarded = {}, set()
                params, entry = [], []
                parameter_ids = {param["id"] for param in fn["params"]}
                pending = [fn["body"]]
                while pending:
                    node = pending.pop()
                    kids = children(node)
                    if ((node.get("kind") in {"BinaryOperator", "CompoundAssignOperator"}
                         and node.get("opcode", "").endswith("=") and node.get("opcode") not in {"==", "!=", ">=", "<="})
                            or node.get("kind") == "UnaryOperator" and node.get("opcode") in {"++", "--"}):
                        if kids and reference(kids[0]).get("id") in parameter_ids:
                            raise MigrationRejected("E_C_HIA_OWNER", "Captured allocation parameters may not be reassigned")
                    pending.extend(child for child in kids if isinstance(child, dict))
                # Only leading guards are credited: nested/late conditions do
                # not justify a nonzero allocation on every reaching path.
                for node in children(fn["body"]):
                    parts = children(node)
                    if node.get("kind") != "IfStmt" or len(parts) != 2:
                        break
                    body = children(parts[1]) if parts[1].get("kind") == "CompoundStmt" else [parts[1]]
                    if len(body) != 1 or body[0].get("kind") != "ReturnStmt":
                        break
                    self.guarded.update(zero_guards(parts[0]))
                for param in fn["params"]:
                    name = "p_" + param["name"]
                    params.append(f"{name}: {param['type']}")
                    local = "v_" + param["name"]
                    self.bindings[param["id"]] = Expression(local, param["type"])
                    entry.append(f"    let mut {local}: {param['type']} = {name};")
                lines = self.sequence(children(fn["body"]))
                pieces.append(f"pub fn {fn['hepta_name']}({', '.join(params)}) -> {fn['return']} effects {{alloc,block,panic,write}} {{\n"
                              + "\n".join(entry + lines) + "\n}")
                fn["inventory"].update(status="function_converted", reason=None)
                reports.append({"source": fn["name"], "hia": fn["hepta_name"],
                                "parameters": [param["type"] for param in fn["params"]], "returns": fn["return"]})
            return "\n\n".join(pieces) + "\n", reports

    capture = capture_project(database, clang=clang)
    translator = MultiOwner(capture)
    source, functions = translator.emit_multi()
    verified = lower_source(source, path="<captured-c-multi-owner>")
    verify_capture(capture)
    project = [row for row in translator.inventory if row["status"] != "system_or_compiler_declaration"]
    return {"program": verified, "source": source, "functions": functions,
            "capture": capture, "declarations": translator.inventory,
            "declaration_inventory_complete": translator.inventory_complete,
            "active_project_declarations": len(project), "owners_lowered": translator.owner_count,
            "claims": {"structural_ast_translation": True, "whole_program_ast_template": False,
                       "original_c_implementation_linked_into_target": False,
                       "source_equivalence_proved": False, "all_c_cpp_supported": False,
                       "custom_allocator_semantics_preserved": False},
            "allocation_contract": {"count_domain": "positive size_t at most isize::MAX after explicit zero guard",
                                    "allocation_outcome": "same declared refusal policy in differential qualification",
                                    "original_allocator_replacements_proved_equivalent": False}}
