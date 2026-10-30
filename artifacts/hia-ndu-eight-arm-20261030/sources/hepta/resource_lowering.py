"""Lower checked Hepta syntax into the independently checked resource CFG.

This pass is a conservative, explicitly unproved abstraction. Scalars have
abstract values; owned aggregate transfers and loans are explicit operations.
The graph is not a complete executable instruction stream. Source backends
consume verified type/layout metadata, and owned LLVM derives finite Drop
plans from it; scalar expressions and control flow still lower from checked
source. This partial consumption does not establish source/native refinement.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib

from .ast import Type
from .checker import _contains_capability, LINEAR, substitute_type, return_origin_index
from .resource_ir import SCHEMA, STORED_SCHEMA, LABELLED_VIEW_SCHEMA, ResourceIRError, _CLAIMS, _EXTERNAL_REQUIREMENTS, verify_resource_ir
from .static_resource_contracts import finite_static_contract_allowed


_PRIMITIVES = {"i8", "i16", "i32", "i64", "i128", "isize", "u8", "u16", "u32", "u64", "u128", "usize", "f32", "f64", "bool", "Unit"}
_SCALAR_BUILTINS = {"wrapping_add", "wrapping_sub", "wrapping_mul", "min", "max", "assert", "print_i64"}


def _unsupported(message: str) -> None:
    raise ResourceIRError("E_RIR_LOWER_UNSUPPORTED", message)


@dataclass
class _Value:
    id: str | None
    type: Type
    kind: str = "value"
    mode: str = "value"
    temporary: bool = False


class _Types:
    def __init__(self, program):
        self.program = program
        self.structs = {s.name: s for s in program.structs}
        self.enums = {e.name: e for e in program.enums}
        self.table = {}
        self.views = {}
        self.view_scalars = {}
        from .borrowed_storage import contains_storage
        for declaration in program.structs:
            if not (declaration.lifetime_params or any(contains_storage(f.type, self.structs, self.enums) for f in declaration.fields)):
                continue
            if (declaration.repr_c or declaration.type_params or len(declaration.lifetime_params) != 1):
                _unsupported("Independent stored views require one region, no repr(C) or type generics")
            refs = [field for field in declaration.fields if field.type.name in {"ref_read", "ref_mut"}]
            scalars = [field for field in declaration.fields if field not in refs]
            if len(refs) != 1 or len(scalars) > 4:
                _unsupported("Only one stored u8-slice loan and up to four Copy scalar fields are modelled")
            field = refs[0]
            if (field.type.args != (Type("slice", (Type("u8"),)),)
                    or field.type.lifetimes != declaration.lifetime_params
                    or any(item.type.name not in _PRIMITIVES - {"Unit"}
                           or item.type.args or item.type.lifetimes or item.type.length is not None
                           for item in scalars)):
                _unsupported("Stored view fields must be one direct u8 loan plus plain Copy scalars")
            self.views[declaration.name] = (field.name, field.type.name[4:])
            self.view_scalars[declaration.name] = {item.name: item.type for item in scalars}
        # A separate wire version prevents old v4 readers from silently
        # ignoring the labels or assuming that they were never initialized.
        self.labelled_views_present = any(self.view_scalars.values())
        for fn in program.functions:
            if (fn.lifetime_params or contains_storage(fn.return_type, self.structs, self.enums)
                    or any(contains_storage(p.type, self.structs, self.enums) for p in fn.params)):
                _unsupported("Stored view parameters/returns and named function regions require another resource profile")
        self.parameters = {}
        self.owned_parameters = set()
        for fn in program.functions:
            self.parameters[fn.name] = {}
            for name in fn.type_params:
                key = "@" + fn.name + "::" + name
                bound = fn.type_bounds.get(name, "Copy")
                self.table[key] = {"kind": "parameter", "function": fn.name, "name": name, "bound": bound}
                self.parameters[fn.name][name] = Type(key)
                if bound == "Owned":
                    self.owned_parameters.add(key)

    def add(self, typ: Type) -> str:
        key = str(typ)
        if key in self.table:
            return key
        if typ.name in self.views:
            if typ.args or typ.lifetimes != ("_",):
                _unsupported("Stored view resources are confined to inferred local regions")
            field, mode = self.views[typ.name]
            self.table[key] = {"kind": "view", "name": typ.name, "field": field,
                               "mode": mode, "pointee": self.add(Type("slice", (Type("u8"),)))}
            if self.labelled_views_present:
                self.table[key]["scalars"] = [
                    {"name": name, "type": self.add(label)}
                    for name, label in self.view_scalars[typ.name].items()]
        elif typ.name in _PRIMITIVES and not typ.args:
            self.table[key] = {"kind": "scalar", "name": typ.name}
        elif typ.name in {"Buffer", "array", "slice"}:
            if len(typ.args) != 1 or typ.name == "Buffer" and typ.args[0] != Type("u8"):
                _unsupported("Only the concrete Buffer<u8> and copied-element arrays/slices are modelled")
            element = self.add(typ.args[0])
            self.table[key] = {"kind": "buffer" if typ.name == "Buffer" else typ.name, "element": element}
            if typ.name == "array":
                self.table[key]["length"] = typ.length
        elif typ.name == "Result":
            if len(typ.args) != 2:
                _unsupported("Result requires two concrete arguments")
            args = [self.add(t) for t in typ.args]
            self.table[key] = {"kind": "enum", "name": "Result", "args": args,
                               "variants": [{"name": "Ok", "fields": [args[0]]}, {"name": "Err", "fields": [args[1]]}]}
        elif typ.name in self.structs or typ.name in self.enums:
            declaration = self.structs.get(typ.name) or self.enums[typ.name]
            if len(declaration.type_params) != len(typ.args):
                _unsupported("Resource lowering requires concrete aggregate type arguments")
            args = [self.add(t) for t in typ.args]
            mapping = dict(zip(declaration.type_params, typ.args))
            if typ.name in self.structs:
                self.table[key] = {"kind": "struct", "name": typ.name, "args": args, "fields": []}
                self.table[key]["fields"] = [{"name": p.name, "type": self.add(substitute_type(p.type, mapping))} for p in declaration.fields]
            else:
                self.table[key] = {"kind": "enum", "name": typ.name, "args": args, "variants": []}
                self.table[key]["variants"] = [{"name": v.name, "fields": [self.add(substitute_type(t, mapping)) for t in v.fields]} for v in declaration.variants]
        else:
            _unsupported(f"Resource lowering has no semantics for {typ}; raw pointers, tasks and unresolved generics are rejected")
        return key

    def owned(self, typ: Type) -> bool:
        if typ.name in self.views:
            return self.views[typ.name][1] == "mut"
        return _contains_capability(typ, LINEAR | self.owned_parameters, self.structs, self.enums)

    def fields(self, typ: Type, variant: str | None = None) -> list[Type]:
        if typ.name == "Result":
            return [typ.args[0] if variant == "Ok" else typ.args[1]]
        declaration = self.structs.get(typ.name) or self.enums[typ.name]
        mapping = dict(zip(declaration.type_params, typ.args))
        if variant is None:
            return [substitute_type(f.type, mapping) for f in declaration.fields]
        return [substitute_type(t, mapping) for v in declaration.variants if v.name == variant for t in v.fields]


class _FunctionLowerer:
    def __init__(self, program, checked, fn, types: _Types, signatures: dict):
        self.program, self.checked, self.fn, self.types, self.signatures = program, checked, fn, types, signatures
        self.local_counter = self.loan_counter = 0
        self.blocks = []
        self.locals = []
        self.env: dict[str, _Value] = {}
        self.mapping = types.parameters[fn.name]
        self.out = signatures[fn.name]
        for param, signature in zip(fn.params, self.out["params"]):
            self.env[param.name] = _Value(signature["id"], self.resolve(param.type), "owner" if param.mode == "take" else "value", param.mode)
        self.current = self.new_block()
        self.out["entry"] = self.current["id"]

    def typ(self, expr) -> Type:
        typ = self.checked.expr_types.get(id(expr))
        if typ is None:
            _unsupported("Expression type is missing from this exact checked AST")
        return self.resolve(typ)

    def resolve(self, typ: Type) -> Type:
        resolved = substitute_type(typ, self.mapping)
        self.types.add(resolved)
        return resolved

    def new_block(self) -> dict:
        block = {"id": "b" + str(len(self.blocks)), "ops": [], "term": None}
        self.blocks.append(block)
        return block

    def slot(self, typ: Type, *, mutable: bool = False) -> _Value:
        key = self.types.add(typ)
        sid = "v" + str(self.local_counter)
        self.local_counter += 1
        self.locals.append({"id": sid, "type": key, "mutable": mutable})
        if typ.name in self.types.views:
            return _Value(sid, typ, "view", self.types.views[typ.name][1], True)
        return _Value(sid, typ, "owner" if self.types.owned(typ) else "value")

    def loan_id(self) -> str:
        lid = "l" + str(self.loan_counter)
        self.loan_counter += 1
        return lid

    def emit(self, op: str, **fields) -> None:
        if self.current is None:
            _unsupported("Unreachable source statements cannot be lowered")
        self.current["ops"].append({"op": op, **fields})

    def finish(self, op: str, **fields) -> None:
        if self.current is None or self.current["term"] is not None:
            _unsupported("Invalid source control flow")
        self.current["term"] = {"op": op, **fields}
        self.current = None

    def copy_value(self, value: _Value) -> _Value:
        if value.kind == "view":
            _unsupported("Stored views cannot be erased into copied scalar values")
        if value.kind == "borrow" and not self.types.owned(value.type) and value.type.name != "slice":
            self.emit("use", loan=value.id, mode="read")
            self.end(value)
            return self.slot(value.type)
        if value.kind != "value":
            _unsupported("An owned/borrowed value cannot be erased into an abstract scalar")
        return value

    def place(self, expr) -> dict:
        if self.view_projection(expr) is not None:
            _unsupported("Reborrowing/passing a stored view field needs an explicit reborrow profile")
        if expr.kind == "name" and expr.value in self.env:
            return {"root": self.env[expr.value].id, "path": []}
        if expr.kind == "field":
            result = self.place(expr.children[0])
            result["path"].append(str(expr.value))
            return result
        if expr.kind == "index":
            result = self.place(expr.children[0])
            self.copy_value(self.expression(expr.children[1]))
            result["path"].append("*")
            return result
        _unsupported("Borrowed places require a named root, a known field, or a conservative index")

    def scalar_view_projection(self, expr) -> _Value | None:
        """Access one checked copied label only while its view is live.

        The scalar's *value* remains abstract in the independent resource
        verifier; an existing borrow is never converted into ownership.
        """
        if expr.kind != "field" or len(expr.children) != 1 or expr.children[0].kind != "name":
            return None
        view = self.env.get(expr.children[0].value)
        if (view is None or
                expr.value not in self.types.view_scalars.get(view.type.name, {})):
            return None
        return view

    def view_projection(self, expr) -> _Value | None:
        path = []
        base = expr
        while base.kind in {"field", "index"}:
            path.append((base.kind, base.value))
            base = base.children[0]
        value = self.env.get(base.value) if base.kind == "name" else None
        if value is None or value.type.name not in self.types.views:
            return None
        field, _ = self.types.views[value.type.name]
        path.reverse()
        if not path or path[0] != ("field", field) or len(path) > 2 or len(path) == 2 and path[1][0] != "index":
            _unsupported("Only the stored u8-slice field and its elements may be projected")
        return value

    def end_shared_views(self, values) -> None:
        for value in values:
            if value.kind == "view" and value.mode == "read":
                self.emit("end_view", src=value.id)

    def borrow(self, expr, mode: str, expected: Type | None = None) -> _Value:
        if expr.kind == "unary" and expr.value in {"read", "mut"}:
            expr = expr.children[0]
        typ = expected or self.typ(expr)
        self.types.add(typ)
        if expr.kind == "call":
            value = self.expression(expr)
            if value.kind != "borrow" or mode == "mut" and value.mode != "mut":
                _unsupported("Borrow call result must retain a compatible borrowed mode")
            return value
        place = self.place(expr)
        lid = self.loan_id()
        self.emit("borrow", id=lid, place=place, mode=mode, type=str(typ))
        return _Value(lid, typ, "borrow", mode)

    def end(self, value: _Value) -> None:
        if value.kind == "borrow":
            self.emit("end_borrow", id=value.id)

    def projection_indices(self, expr) -> None:
        """Evaluate nested projection operands from the base outwards.

        Walking the AST towards its root discovers outer indices first. Source
        execution evaluates the innermost index first; reversing this order can
        hide a resource consumption before a later index reads that resource.
        """
        indices = []
        while expr.kind in {"field", "index"}:
            if expr.kind == "index":
                indices.append(expr.children[1])
            expr = expr.children[0]
        for index in reversed(indices):
            self.copy_value(self.expression(index))

    def expression(self, expr) -> _Value:
        typ = self.typ(expr)
        kind = expr.kind
        if kind in {"int", "float", "bool", "string"}:
            if self.types.owned(typ):
                _unsupported("An abstract literal cannot create an owner")
            return self.slot(typ)
        if kind == "name":
            if expr.value not in self.env:
                _unsupported("Unknown local expression")
            value = self.env[expr.value]
            if value.kind == "view":
                if value.mode == "mut":
                    _unsupported("Exclusive stored view values require an explicit move")
                self.emit("use_view", src=value.id, mode="read")
                return value
            if self.types.owned(typ):
                _unsupported("Owned names require explicit move or borrowing")
            self.emit("use", place={"root": value.id, "path": []}, mode="read")
            return value
        if kind == "unary":
            if expr.value == "move":
                child = expr.children[0]
                if typ.name in self.types.views:
                    if self.types.views[typ.name][1] == "read" or child.kind == "struct":
                        return self.expression(child)
                    if child.kind != "name" or child.value not in self.env:
                        _unsupported("Exclusive stored views move only as whole local values")
                    result = self.slot(typ)
                    self.emit("move_view", src=self.env[child.value].id, dest=result.id)
                    return result
                if child.kind in {"call", "struct", "variant"} and self.types.owned(typ):
                    value = self.expression(child)
                    if value.kind != "owner":
                        _unsupported("Fresh owner transfer cannot consume a borrowed function result")
                    return value
                if not self.types.owned(typ):
                    return self.copy_value(self.expression(child))
                result = self.slot(typ)
                if child.kind == "name" and child.value in self.env:
                    self.emit("move", src=self.env[child.value].id, dest=result.id)
                elif child.kind == "field":
                    self.emit("take_field", place=self.place(child), dest=result.id)
                else:
                    _unsupported("Owners move only from whole names or named struct fields")
                return result
            if expr.value in {"read", "mut"}:
                return self.borrow(expr, expr.value, typ)
            self.copy_value(self.expression(expr.children[0]))
            return self.slot(typ)
        if kind == "binary" and expr.value in {"&&", "||"}:
            condition = self.copy_value(self.expression(expr.children[0]))
            right, skip, join = self.new_block(), self.new_block(), self.new_block()
            self.finish("branch", condition=condition.id,
                        then=right["id"] if expr.value == "&&" else skip["id"],
                        **{"else": skip["id"] if expr.value == "&&" else right["id"]})
            self.current = right
            self.copy_value(self.expression(expr.children[1]))
            self.finish("jump", target=join["id"])
            self.current = skip
            self.finish("jump", target=join["id"])
            self.current = join
            return self.slot(typ)
        if kind in {"binary", "cast", "array"}:
            for child in expr.children:
                self.copy_value(self.expression(child))
            return self.slot(typ)
        if kind in {"field", "index"}:
            label_view = self.scalar_view_projection(expr)
            if label_view is not None:
                self.emit("use_view", src=label_view.id, mode="read")
                return self.slot(typ)
            stored = self.view_projection(expr)
            if stored is not None:
                if kind != "index":
                    _unsupported("A stored slice is used through len or indexed access")
                self.projection_indices(expr)
                self.emit("use_view", src=stored.id, mode="read")
                return self.slot(typ)
            if self.types.owned(typ):
                _unsupported("Partial owned-field moves are not modelled")
            # Normal named projections preserve field-disjointness. A view
            # returned by a call retains its conservative input-region loan.
            base = expr
            while base.kind in {"field", "index"}:
                base = base.children[0]
            if base.kind == "call":
                view = self.expression(base)
                if view.kind != "borrow":
                    _unsupported("Projection from temporary aggregate values is outside this profile")
                self.projection_indices(expr)
                self.emit("use", loan=view.id, mode="read")
                self.end(view)
            else:
                self.emit("use", place=self.place(expr), mode="read")
            return self.slot(typ)
        if kind in {"struct", "variant"}:
            if typ.name in self.types.views:
                field, mode = self.types.views[typ.name]
                labels = self.types.view_scalars[typ.name]
                if (kind != "struct" or not isinstance(expr.value, dict)
                        or not isinstance(expr.value.get("fields"), list)
                        or len(expr.value["fields"]) != 1 + len(labels)
                        or len(expr.children) != 1 + len(labels)
                        or set(expr.value["fields"]) != {field, *labels}):
                    _unsupported("Stored view requires its one loan and every declared scalar field")
                loan = None
                scalar_values = {}
                # Match the source order, not a reordered struct declaration.
                # A later field expression may read the original buffer and
                # must conflict with a prior exclusive borrow when applicable.
                for name, child in zip(expr.value["fields"], expr.children):
                    if name == field:
                        loan = self.borrow(child, mode, Type("slice", (Type("u8"),)))
                    else:
                        value = self.copy_value(self.expression(child))
                        if (value.kind != "value" or value.id is None
                                or value.type != labels[name]):
                            _unsupported("Stored view label must be an exact Copy scalar value")
                        scalar_values[name] = value.id
                if loan is None:
                    _unsupported("Stored view loan was not constructed")
                result = self.slot(typ)
                metadata = ({"scalars": [{"name": name, "src": scalar_values[name]}
                                        for name in labels]}
                            if self.types.labelled_views_present else {})
                self.emit("bind_view", dest=result.id, loan=loan.id, **metadata)
                return result
            values = []
            for child in expr.children:
                value = self.expression(child)
                # A Copy field reads a returned view immediately. Keeping its
                # loan until all later field expressions complete invents an
                # overlap that neither source/native evaluator performs.
                values.append(self.copy_value(value) if value.kind == "borrow" else value)
            variant = expr.value["variant"] if kind == "variant" else None
            if kind == "struct":
                ordered = dict(zip(expr.value["fields"], values))
                values = [ordered[f.name] for f in self.types.structs[typ.name].fields]
            result = self.slot(typ)
            self.emit("pack", dest=result.id, variant=variant, fields=[v.id for v in values])
            return result
        if kind == "call":
            return self.call(expr, typ)
        _unsupported(f"Unsupported expression {kind}")

    def call(self, expr, typ: Type) -> _Value:
        name, args = expr.value, expr.children
        if name in {"buffer", "try_buffer"}:
            for arg in args:
                self.copy_value(self.expression(arg))
            result = self.slot(typ)
            self.emit("acquire", dest=result.id, kind=name)
            return result
        if name in {"release", "drop"}:
            owner = self.expression(args[0])
            if owner.kind == "view":
                if name != "drop" or owner.mode != "mut":
                    _unsupported("Only explicit drop consumes an exclusive stored view")
                self.emit("end_view", src=owner.id)
                return _Value(None, Type("Unit"))
            if owner.kind != "owner":
                _unsupported("Drop requires an explicit owned transfer")
            self.emit("drop", src=owner.id)
            return _Value(None, Type("Unit"))
        if name == "len":
            stored = self.view_projection(args[0])
            if stored is not None:
                self.emit("use_view", src=stored.id, mode="read")
                return self.slot(typ)
            view = self.borrow(args[0], "read")
            self.emit("use", loan=view.id, mode="read")
            self.end(view)
            return self.slot(typ)
        if name in _SCALAR_BUILTINS:
            for arg in args:
                self.copy_value(self.expression(arg))
            return _Value(None, typ) if typ.name == "Unit" else self.slot(typ)
        if name not in self.signatures:
            _unsupported(f"Builtin {name} has no resource transition model (tasks, raw memory and concurrency are excluded)")
        callee = self.signatures[name]
        original = next(f for f in self.program.functions if f.name == name)
        type_args = [self.resolve(t) for t in expr.type_args]
        instantiated = dict(zip(original.type_params, type_args))
        values, call_args = [], []
        for arg, param in zip(args, callee["params"]):
            param_index = len(values)
            parameter_type = substitute_type(original.params[param_index].type, instantiated)
            self.types.add(parameter_type)
            if param["mode"] in {"read", "mut"}:
                value = self.borrow(arg, param["mode"], parameter_type)
            else:
                value = self.expression(arg)
                if param["mode"] == "value":
                    value = self.copy_value(value)
                if value.kind != ("owner" if param["mode"] == "take" else "value"):
                    _unsupported("Call argument cannot erase ownership or references")
            values.append(value)
            call_args.append({"kind": value.kind, "id": value.id})
        ret = callee["returns"]
        if ret["mode"] == "value":
            result = _Value(None, typ) if typ.name == "Unit" else self.slot(typ)
            result_loan = None
        else:
            result = _Value(self.loan_id(), typ, "borrow", ret["mode"])
            result_loan = result.id
        self.emit("foreign" if callee["external"] else "call", function=name, args=call_args,
                  result=None if result_loan else result.id, result_loan=result_loan,
                  obligation=callee["obligation"], **({"type_args": [str(t) for t in type_args]} if original.type_params else {}))
        for param, value in zip(callee["params"], values):
            if value.kind == "borrow" and not (result_loan and ret["origin"] == param["id"]):
                self.end(value)
        return result

    def statements(self, body: list, binding_env: dict[str, _Value] | None = None) -> None:
        previous = self.env
        if binding_env is not None:
            self.env = binding_env
        entry_names = set(self.env)
        for statement in body:
            if self.current is None:
                _unsupported("Checked source contains an unreachable statement")
            data = statement.data
            if statement.kind == "let":
                value = self.expression(data["expr"])
                if value.kind == "borrow":
                    value = self.copy_value(value)
                typ = self.resolve(data["type"]) if data.get("type") is not None else value.type
                binding = self.slot(typ, mutable=bool(data["mutable"]))
                if value.kind == "view":
                    self.emit("move_view" if value.mode == "mut" else "copy_view", src=value.id, dest=binding.id)
                    if value.mode == "read" and value.temporary:
                        self.emit("end_view", src=value.id)
                    binding.temporary = False
                elif value.kind == "owner":
                    self.emit("move", src=value.id, dest=binding.id)
                self.env[data["name"]] = binding
            elif statement.kind == "assign":
                # Both native backends evaluate the right-hand side before the
                # assignment place. Materialize copied values (and end any
                # returned loan) before evaluating the target's calls/indices.
                value = self.expression(data["expr"])
                view = self.scalar_view_projection(data["target"])
                if view is not None:
                    # Assignment evaluates its RHS before the target. The
                    # Copied label belongs to this view *record*, never its
                    # borrowed origin. Do not upgrade slice permissions.
                    value = self.copy_value(value)
                    label = data["target"].value
                    if (self.types.view_scalars[view.type.name][label] != value.type
                            or value.id is None or value.kind != "value"):
                        _unsupported("Stored Copy field assignment needs its original checked scalar type")
                    self.emit("write_view_scalar", src=view.id, field=label, value=value.id)
                    continue
                stored = self.view_projection(data["target"])
                if stored is not None:
                    if data["target"].kind != "index":
                        _unsupported("Stored reference fields cannot be reassigned in this profile")
                    self.copy_value(value)
                    self.projection_indices(data["target"])
                    self.emit("use_view", src=stored.id, mode="write")
                    continue
                owned_target = self.types.owned(self.typ(data["target"]))
                if not owned_target:
                    value = self.copy_value(value)
                base = data["target"]
                while base.kind in {"field", "index"}:
                    base = base.children[0]
                if base.kind == "call":
                    view = self.expression(base)
                    if view.kind != "borrow" or view.mode != "mut":
                        _unsupported("Assignment through a returned view requires a mutable loan")
                    self.projection_indices(data["target"])
                    self.emit("use", loan=view.id, mode="write")
                    self.end(view)
                else:
                    place = self.place(data["target"])
                    if owned_target:
                        if value.kind != "owner":
                            _unsupported("Owned field restoration requires an explicit transferred value")
                        self.emit("init_field", place=place, src=value.id)
                    else:
                        self.emit("use", place=place, mode="write")
            elif statement.kind == "expr":
                value = self.expression(data["expr"])
                if value.kind == "view" and value.mode == "read":
                    if value.temporary:
                        self.emit("end_view", src=value.id)
                    continue
                if value.kind == "borrow":
                    value = self.copy_value(value)
                if value.kind != "value":
                    _unsupported("An expression statement cannot discard an owner or loan")
            elif statement.kind == "return":
                expr = data["expr"]
                if self.fn.return_mode in {"read", "mut"}:
                    value = self.borrow(expr, self.fn.return_mode, self.resolve(self.fn.return_type))
                    if value.mode != self.fn.return_mode:
                        _unsupported("Mode-changing returned call views need an explicit reborrow model")
                    self.end_shared_views(self.env.values())
                    self.finish("return", value=None, loan=value.id)
                else:
                    value = self.expression(expr) if expr is not None else _Value(None, Type("Unit"))
                    if value.kind == "borrow":
                        value = self.copy_value(value)
                    self.end_shared_views(self.env.values())
                    self.finish("return", value=value.id, loan=None)
            elif statement.kind == "unsafe":
                self.statements(data["body"], dict(self.env))
            elif statement.kind == "if":
                condition = self.copy_value(self.expression(data["condition"]))
                yes, no = self.new_block(), self.new_block()
                self.finish("branch", condition=condition.id, then=yes["id"], **{"else": no["id"]})
                continuation = []
                for block, source in ((yes, data["then"]), (no, data.get("else", []))):
                    self.current = block
                    self.statements(source, dict(self.env))
                    if self.current is not None:
                        continuation.append(self.current)
                self.current = None
                if continuation:
                    join = self.new_block()
                    for block in continuation:
                        block["term"] = {"op": "jump", "target": join["id"]}
                    self.current = join
            elif statement.kind == "match":
                value = self.expression(data["expr"])
                arms = [(self.new_block(), arm) for arm in data["arms"]]
                self.finish("switch", src=value.id, cases=[{"variant": arm.pattern.variant, "target": block["id"]} for block, arm in arms])
                continuation = []
                for block, arm in arms:
                    self.current = block
                    fields = self.types.fields(value.type, arm.pattern.variant)
                    bindings = [self.slot(t) for t in fields]
                    self.emit("unpack", src=value.id, variant=arm.pattern.variant, dests=[v.id for v in bindings])
                    env = dict(self.env)
                    env.update((name, binding) for name, binding in zip(arm.pattern.bindings, bindings) if name != "_")
                    self.statements(arm.body, env)
                    if self.current is not None:
                        for binding in bindings:
                            if self.types.owned(binding.type) and binding.type.name in self.types.structs:
                                self.emit("forget", src=binding.id)
                        continuation.append(self.current)
                self.current = None
                if continuation:
                    join = self.new_block()
                    for block in continuation:
                        block["term"] = {"op": "jump", "target": join["id"]}
                    self.current = join
            elif statement.kind in {"for", "while"}:
                env = dict(self.env)
                if statement.kind == "for":
                    self.copy_value(self.expression(data["start"]))
                    bound = self.copy_value(self.expression(data["end"]))
                    env[data["name"]] = self.slot(bound.type)
                header, loop, after = self.new_block(), self.new_block(), self.new_block()
                self.finish("jump", target=header["id"])
                self.current = header
                condition = self.copy_value(self.expression(data["condition"])) if statement.kind == "while" else self.slot(Type("bool"))
                self.finish("branch", condition=condition.id, then=loop["id"], **{"else": after["id"]})
                self.current = loop
                self.statements(data["body"], env)
                if self.current is not None:
                    self.finish("jump", target=header["id"])
                self.current = after
            else:
                _unsupported(f"Unsupported statement {statement.kind}")
        if self.current is not None:
            for name in sorted(set(self.env) - entry_names):
                value = self.env[name]
                if value.kind == "view" and value.mode == "read":
                    self.emit("end_view", src=value.id)
                    continue
                if self.types.owned(value.type) and value.type.name in self.types.structs:
                    # No destructor is implicit: the independent verifier
                    # rejects forgetting any remaining owned payload/loan.
                    self.emit("forget", src=value.id)
        if binding_env is not None:
            self.env = previous

    def lower(self) -> dict:
        self.statements(self.fn.body)
        if self.current is not None:
            if self.fn.return_type != Type("Unit"):
                _unsupported("A non-Unit body without an explicit modeled return is unsupported")
            self.finish("return", value=None, loan=None)
        self.out["locals"], self.out["blocks"] = self.locals, self.blocks
        return self.out


def lower_resource_ir(program, checked, *, project_sha256: str | None = None) -> dict:
    """Translate this checked AST and require the independent verifier to pass.

    `checked` must belong to the same AST objects. Their correspondence and the
    source-to-IR abstraction remain obligations of the caller/implementation.
    """
    if not getattr(checked, "ok", False):
        raise ResourceIRError("E_RIR_LOWER_REJECTED", "Cannot lower a rejected frontend result")
    from .runtime_io import has_io_profile
    if has_io_profile(program):
        _unsupported("The I/O reactor profile, including unused I/O declarations, requires another lowering profile")
    types = _Types(program)
    for primitive in ("Unit", "bool", "usize"):
        types.add(Type(primitive))
    signatures, obligations = {}, {}
    for fn in program.functions:
        # The current Resource IR abstracts *ownership*, not cost. Its
        # source-facing lowerer may admit only the closed effect-derived
        # zero-cost clauses also admitted by the owned LLVM backend. Runtime
        # task-group budgets and all unknown resource kinds still reject.
        if not finite_static_contract_allowed(fn, checked):
            _unsupported("Unknown, ill-typed or effect-inconsistent static resource clause")
        mapping = types.parameters[fn.name]
        params = [{"id": "p" + str(i), "type": types.add(substitute_type(p.type, mapping)), "mode": p.mode} for i, p in enumerate(fn.params)]
        origin = return_origin_index(fn)
        signature = {"name": fn.name, "params": params,
                     "returns": {"type": types.add(substitute_type(fn.return_type, mapping)), "mode": fn.return_mode,
                                 "origin": params[origin]["id"] if fn.return_mode != "value" and origin is not None else None},
                     "external": fn.extern_c, "obligation": "foreign:" + fn.name if fn.extern_c else None,
                     "locals": [], "entry": None, "blocks": []}
        if fn.type_params:
            signature["type_params"] = [str(mapping[name]) for name in fn.type_params]
        signatures[fn.name] = signature
        if fn.extern_c:
            obligations[signature["obligation"]] = {"function": fn.name, "status": "assumed_not_verified", "requirements": list(_EXTERNAL_REQUIREMENTS)}
    for fn in program.functions:
        if not fn.extern_c:
            _FunctionLowerer(program, checked, fn, types, signatures).lower()
    doc = {"schema": (LABELLED_VIEW_SCHEMA if types.labelled_views_present
                       else STORED_SCHEMA if types.views else SCHEMA), "source_sha256": hashlib.sha256(program.source.encode()).hexdigest(),
           "project_sha256": project_sha256, "value_semantics": "copied_values_abstract_not_executable",
           "types": types.table, "functions": list(signatures.values()), "obligations": obligations,
           "claims": dict(_CLAIMS)}
    validation = verify_resource_ir(doc)
    if not validation["ok"]:
        error = validation["diagnostics"][0]
        raise ResourceIRError(error["code"], f"Resource lowering failed independent verification in {error.get('function')}:{error.get('block')}: {error['message']}")
    return doc
