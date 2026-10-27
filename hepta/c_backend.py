"""Independent AST -> C11/GCC path for a deliberately bounded language subset.

No Rust source, compiler, metadata or borrow checker participates in this path.
The frontend checker is shared; borrowing is checked conservatively here. This
backend is not a proof of the complete language's memory model.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from dataclasses import replace

from .ast import Diagnostic, Enum, EnumVariant, HeptaError, Type
from .checker import is_owned_type, place_path, places_overlap, substitute_type
from .native_local_views import local_slice_view_layouts

SCALARS = {"u8": "uint8_t", "i8": "int8_t", "u16": "uint16_t", "i16": "int16_t",
           "u32": "uint32_t", "i32": "int32_t", "u64": "uint64_t", "i64": "int64_t",
           "usize": "size_t", "isize": "intptr_t", "f32": "float", "f64": "double", "bool": "bool", "Unit": "void"}
INTS = set(SCALARS) - {"f32", "f64", "bool", "Unit"}


def fail(code, message, span=None):
    raise HeptaError(Diagnostic(code, message, **({"span": span} if span else {}), phase="c_backend"))


def _hash(data):
    return hashlib.sha256(data).hexdigest()


class CEmitter:
    def __init__(self, program, checked, crate_type):
        if not checked.ok:
            fail("E_C_BACKEND_UNCHECKED", "C lowering requires a successful frontend check")
        from .borrowed_storage import has_borrowed_storage
        stored = has_borrowed_storage(program)
        self.program, self.checked, self.crate_type = program, checked, crate_type
        self.structs = {s.name: s for s in program.structs}
        self.enums = {s.name: s for s in program.enums}
        self.enums["Result"] = Enum("Result", [EnumVariant("Ok", [Type("A")]), EnumVariant("Err", [Type("B")])], ("A", "B"))
        self.functions = {f.name: f for f in program.functions}
        self.declarations, self.types, self.active = [], {}, set()
        self.helpers = set()
        self.counter = 0
        self.params = {}
        self.mapping = {}
        self.current = None
        self.instances = {}
        self.pending = []
        self.drops = {}
        self.runtime = False
        self.resource_graph = None
        self.views = {}
        # The owned and returned-view profiles do not borrow Rust's checker.
        # Their abstract bodies, including unused generic bodies, must pass
        # the separate, data-only resource verifier before C emission begins.
        self.resource_checked = (stored or any(is_owned_type(program, t) for t in checked.expr_types.values())
                                 or any(f.type_params or f.return_mode != "value" for f in program.functions))
        if self.resource_checked:
            from .resource_ir import ResourceIRError, verify_resource_ir
            from .resource_lowering import lower_resource_ir
            try:
                self.resource_graph = lower_resource_ir(program, checked)
                verdict = verify_resource_ir(json.loads(json.dumps(self.resource_graph)))
                if not verdict["ok"]:
                    fail("E_C_RESOURCE_IR", "Independent C ownership gate rejected: " + str(verdict["diagnostics"]))
            except ResourceIRError as error:
                if stored and error.code == "E_RIR_LOWER_UNSUPPORTED":
                    fail("E_C_BORROW_STORAGE", "Unsupported native local view shape: " + str(error))
                fail("E_C_RESOURCE_IR", f"Independent C ownership gate rejected {error.code}: {error}")
            try:
                self.views = local_slice_view_layouts(program, self.resource_graph["types"])
            except ValueError as error:
                fail("E_C_BORROW_STORAGE", str(error))

    def resolve(self, typ):
        return substitute_type(typ, self.mapping)

    def fields(self, typ):
        st = self.structs[typ.name]
        mapping = dict(zip(st.type_params, typ.args))
        return [replace(p, type=substitute_type(p.type, mapping)) for p in st.fields]

    def variants(self, typ):
        enum = self.enums[typ.name]
        mapping = dict(zip(enum.type_params, typ.args))
        return [(v.name, [substitute_type(t, mapping) for t in v.fields]) for v in enum.variants]

    def instance(self, fn, args=()):
        args = tuple(args)
        if len(args) != len(fn.type_params):
            fail("E_C_SPECIALIZATION", "Concrete generic argument count does not match declaration", fn.span)
        pending = [(t, 0) for t in args]
        nodes = 0
        while pending:
            typ, depth = pending.pop()
            nodes += 1
            if depth > 64 or nodes > 4096:
                fail("E_C_SPECIALIZATION_LIMIT", "C type arguments exceed the 64-level/4096-node bound", fn.span)
            pending.extend((t, depth + 1) for t in typ.args)
        key = (fn.name, args)
        if key not in self.instances:
            if len(self.instances) >= 512 or len(str(args)) > 4096:
                fail("E_C_SPECIALIZATION_LIMIT", "C specialization exceeds the explicit 512-instance/4096-character type limit", fn.span)
            name = (fn.name if fn.extern_c or fn.export_c else "__hepta_cb_fn_" + fn.name)
            if args:
                name = "__hepta_cb_generic_" + str(len(self.instances)) + "_" + fn.name
            self.instances[key] = name
            self.pending.append((fn, args))
        return self.instances[key]

    def typ(self, t):
        if t.name in SCALARS and not t.args:
            return SCALARS[t.name]
        if t in self.types:
            if t in self.active:
                fail("E_C_BACKEND_SUBSET", "Recursive C backend type definitions are not yet supported")
            return self.types[t]
        if t.name in {"raw_const", "raw_mut"}:
            if t.args[0].name == "array":
                fail("E_C_BACKEND_SUBSET", "Pointers to arrays require C declarator lowering not yet supported here")
            child = self.typ(t.args[0])
            name = "__hepta_cb_ptr_" + str(len(self.types))
            self.types[t] = name
            self.declarations.append(f"typedef {'const ' if t.name == 'raw_const' else ''}{child} *{name};")
            return name
        if t.name == "slice":
            fail("E_C_BACKEND_SUBSET", "Slices must occur as read/mut parameters")
        if t.name == "Buffer" and t.args == (Type("u8"),):
            self.runtime = True
            self.types[t] = "__hepta_cb_buffer"
            self.declarations.append("typedef struct { uint8_t *data; size_t len; } __hepta_cb_buffer;")
            return self.types[t]
        if t.name not in self.structs and t.name not in self.enums and t.name != "array":
            fail("E_C_BACKEND_SUBSET", f"C backend does not yet lower {t}")
        if t.name == "array" and (not t.length or t.args[0].name == "Unit"):
            fail("E_C_BACKEND_SUBSET", "Zero-length and Unit-element arrays are not supported by the C backend")
        if len(self.active) > 128 or len(self.types) >= 4096:
            fail("E_C_SPECIALIZATION_LIMIT", "C value types exceed the 128-level/4096-type bound")
        name = "__hepta_cb_aggregate_" + str(len(self.types))
        self.types[t] = name
        self.active.add(t)
        if t in self.views:
            view = self.views[t]
            fields = self.slice_type(Type("slice", (Type("u8"),)), view["mode"]) + " h_" + view["field"] + ";"
        elif t.name == "array":
            fields = self.typ(t.args[0]) + f" data[{t.length}];"
        elif t.name in self.enums:
            variants = self.variants(t)
            payloads = []
            for variant, types in variants:
                fields = " ".join(("uint8_t" if f.name == "Unit" else self.typ(f)) + f" f_{i};" for i, f in enumerate(types)) or "uint8_t empty;"
                payloads.append("struct { " + fields + " } v_" + variant + ";")
            fields = "uint32_t tag; union { " + " ".join(payloads) + " } payload;"
        else:
            st = self.structs[t.name]
            concrete_fields = self.fields(t)
            if not st.fields:
                fail("E_C_BACKEND_SUBSET", "Empty structs are not supported by the C backend")
            if any(f.type.name == "Unit" for f in concrete_fields):
                fail("E_C_BACKEND_SUBSET", "Unit fields are not supported by the C backend")
            if st.repr_c and any(f.type.name == "array" for f in concrete_fields):
                fail("E_C_BACKEND_SUBSET", "repr(C) array fields are not yet supported in the independent backend")
            fields = " ".join(self.typ(f.type) + " h_" + f.name + ";" for f in concrete_fields)
        self.active.remove(t)
        self.declarations.append(f"typedef struct {{ {fields} }} {name};")
        return name

    def slice_type(self, t, mode):
        # Internal view descriptors must not inhabit the source nominal-type
        # namespace (a user may validly declare c_slice_read<T>).
        key = ("borrowed_slice", mode, t.args)
        if key not in self.types:
            elem = self.typ(t.args[0])
            name = f"__hepta_cb_slice_{len(self.types)}"
            self.types[key] = name
            self.declarations.append(f"typedef struct {{ {'const ' if mode == 'read' else ''}{elem} *data; size_t len; }} {name};")
        return self.types[key]

    def fn_name(self, fn, args=()):
        return self.instance(fn, args)

    def parameter(self, p):
        if p.type.name == "slice":
            return self.slice_type(p.type, p.mode) + " h_" + p.name
        if p.type.name == "Unit":
            if p.mode != "value":
                fail("E_C_BACKEND_SUBSET", "Borrowed Unit needs a separate addressable representation", p.span)
            return "uint8_t h_" + p.name
        return ("const " if p.mode == "read" else "") + self.typ(p.type) + (" *" if p.mode in {"read", "mut"} else " ") + "h_" + p.name

    def signature(self, fn, args=()):
        mapping = dict(zip(fn.type_params, args))
        returns = substitute_type(fn.return_type, mapping)
        if fn.return_mode != "value":
            result = (self.slice_type(returns, fn.return_mode) if returns.name == "slice" else
                      ("const " if fn.return_mode == "read" else "") + self.typ(returns) + " *")
        else:
            result = self.typ(returns)
        params = [replace(p, type=substitute_type(p.type, mapping)) for p in fn.params]
        return result + " " + self.fn_name(fn, args) + "(" + (", ".join(self.parameter(p) for p in params) or "void") + ")"

    def expr_type(self, e):
        t = self.checked.expr_types.get(id(e))
        if t is None:
            fail("E_C_BACKEND_TYPE", "Missing checked expression type", e.span)
        return self.resolve(t)

    def temp(self, t, expression, lines):
        if t.name == "Unit":
            lines.append(expression + ";")
            return "((void)0)"
        self.counter += 1
        name = f"__hepta_cb_v{self.counter}"
        lines.append(self.typ(t) + " " + name + " = " + expression + ";")
        return name

    @staticmethod
    def root(e):
        while e.kind in {"field", "index", "unary"} and e.children:
            e = e.children[0]
        return e.value if e.kind == "name" else None

    def check_borrows(self, call, fn):
        if self.resource_checked:
            # The independent CFG gate checks overlapping and nested loans,
            # including loans returned by another call and later owner moves.
            return
        borrowed = []
        for arg, param in zip(call.children, fn.params):
            if param.mode in {"read", "mut"}:
                place = place_path(arg.children[0]) if arg.kind == "unary" and arg.children else None
                if place is None:
                    fail("E_C_BORROW", "C borrow arguments require named places", arg.span)
                for old_place, old_mode in borrowed:
                    if places_overlap(old_place, place) and "mut" in {old_mode, param.mode}:
                        fail("E_C_BORROW", "Overlapping borrows are rejected; distinct named struct fields are disjoint", arg.span)
                borrowed.append((place, param.mode))
        if borrowed:
            def visit(e):
                if e.kind == "call" and e.value in self.functions:
                    effects = self.checked.effects.get(e.value, set()) | self.functions[e.value].effects
                    if effects - {"panic"}:
                        fail("E_C_BORROW", "Effectful nested call in a borrowed argument list is unsupported", e.span)
                for child in e.children:
                    visit(child)
            for arg in call.children:
                visit(arg)

    def place(self, e, lines):
        if e.kind == "name":
            p = self.params.get(e.value)
            name = "h_" + e.value
            return f"(*{name})" if p and p.mode in {"read", "mut"} and p.type.name != "slice" else name
        if e.kind == "field":
            return "(" + self.place(e.children[0], lines) + ").h_" + e.value
        if e.kind == "index":
            base, index = e.children
            self.require_nonmutating(index)
            data, length = self.sequence(base, lines)
            ix = self.value(index, lines)
            lines.append(f"if ({ix} >= {length}) abort();")
            return f"({data})[{ix}]"
        if e.kind == "call" and e.value in self.functions and self.functions[e.value].return_mode != "value":
            if self.expr_type(e).name == "slice":
                fail("E_C_BACKEND_PLACE", "Use a returned slice as a sequence, not an aggregate place", e.span)
            return "(*" + self.view(e, lines) + ")"
        fail("E_C_BACKEND_PLACE", "C backend requires a named place for this operation", e.span)

    def require_nonmutating(self, e):
        if e.kind == "call" and e.value in self.functions:
            effects = self.checked.effects.get(e.value, set()) | self.functions[e.value].effects
            if effects - {"panic"}:
                fail("E_C_BACKEND_EVALUATION", "Effectful nested calls in index/raw-store operands are conservatively rejected", e.span)
        for child in e.children:
            self.require_nonmutating(child)

    def sequence(self, e, lines):
        t = self.expr_type(e)
        if t.name not in {"array", "slice", "Buffer"}:
            fail("E_C_BACKEND_SUBSET", "Only fixed arrays, borrowed slices and Buffer<u8> are supported sequences", e.span)
        if e.kind == "call" and t.name == "slice":
            p = self.view(e, lines)
        else:
            p = self.place(e, lines)
        return f"({p}).data", str(t.length) if t.name == "array" else f"({p}).len"

    def borrowed(self, arg, typ, mode, lines):
        child = arg.children[0] if arg.kind == "unary" and arg.value in {"read", "mut"} else arg
        if typ.name == "slice":
            data, length = self.sequence(child, lines)
            return f"({self.slice_type(typ, mode)}){{{data}, {length}}}"
        return "&(" + self.place(child, lines) + ")"

    def call(self, expr, lines):
        fn = self.functions[expr.value]
        self.check_borrows(expr, fn)
        args = tuple(self.resolve(t) for t in expr.type_args)
        mapping = dict(zip(fn.type_params, args))
        values = []
        for arg, original in zip(expr.children, fn.params):
            param = replace(original, type=substitute_type(original.type, mapping))
            if param.mode in {"read", "mut"}:
                # Store the pointer/pair before evaluating the next argument.
                # This follows the same ordered loan evaluation as the gate.
                value = self.borrowed(arg, param.type, param.mode, lines)
                typ = (self.slice_type(param.type, param.mode) if param.type.name == "slice" else
                       ("const " if param.mode == "read" else "") + self.typ(param.type) + " *")
                self.counter += 1
                name = f"__hepta_cb_arg{self.counter}"
                lines.append(typ + " " + name + " = " + value + ";")
                values.append(name)
            else:
                value = self.value(arg, lines)
                values.append("0" if param.type.name == "Unit" else value)
        return self.fn_name(fn, args) + "(" + ", ".join(values) + ")"

    def view(self, expr, lines):
        fn = self.functions.get(expr.value) if expr.kind == "call" else None
        if fn is None or fn.return_mode == "value":
            fail("E_C_BACKEND_VIEW", "Expected a checked returned borrow", expr.span)
        typ = self.expr_type(expr)
        native = (self.slice_type(typ, fn.return_mode) if typ.name == "slice" else
                  ("const " if fn.return_mode == "read" else "") + self.typ(typ) + " *")
        call = self.call(expr, lines)
        self.counter += 1
        name = f"__hepta_cb_view{self.counter}"
        lines.append(native + " " + name + " = " + call + ";")
        return name

    def drop_helper(self, typ):
        if typ in self.drops:
            return self.drops[typ][0]
        name = "__hepta_cb_drop_" + str(len(self.drops))
        native = self.typ(typ)
        self.drops[typ] = (name, None)
        lines = []
        if typ in self.views:
            if self.views[typ]["mode"] != "mut":
                fail("E_C_BORROW_STORAGE", "Only exclusive views admit explicit end")
            lines.append("(void)value;")
        elif typ.name == "Buffer":
            lines.append("free(value.data);")
        elif typ.name in self.structs:
            for field in self.fields(typ):
                if is_owned_type(self.program, field.type):
                    lines.append(self.drop_helper(field.type) + "(value.h_" + field.name + ");")
        elif typ.name in self.enums:
            lines.append("switch (value.tag) {")
            for index, (variant, fields) in enumerate(self.variants(typ)):
                lines.append(f"case {index}: {{")
                for i, field in enumerate(fields):
                    if is_owned_type(self.program, field):
                        lines.append(self.drop_helper(field) + f"(value.payload.v_{variant}.f_{i});")
                lines.append("break; }")
            lines.append("default: abort(); }")
        else:
            fail("E_C_BACKEND_DROP", f"No C destructor for owned type {typ}")
        self.drops[typ] = (name, f"static void {name}({native} value) {{ " + " ".join(lines) + " }")
        return name

    def integer_helper(self, t):
        self.helpers.add(t.name)
        return "__hepta_cb_" + t.name + "_"

    def value(self, e, lines):
        t = self.expr_type(e)
        k = e.kind
        if k == "name":
            if t.name == "slice":
                fail("E_C_BACKEND_SUBSET", "Borrowed slices cannot be copied as values", e.span)
            expression = "((void)0)" if t.name == "Unit" else self.place(e, lines)
        elif k == "int":
            expression = f"({self.typ(t)})" + (f"UINT64_C({e.value})" if t.name.startswith("u") else f"INT64_C({e.value})")
        elif k == "float":
            if not math.isfinite(e.value):
                fail("E_C_BACKEND_LITERAL", "Nonfinite literals are unsupported", e.span)
            expression = f"({self.typ(t)})({e.value!r})"
        elif k == "bool":
            expression = "true" if e.value else "false"
        elif k == "array":
            values = [self.value(x, lines) for x in e.children]
            expression = f"({self.typ(t)}){{ .data = {{" + ", ".join(values) + "} }"
        elif k == "struct":
            if t in self.views:
                view = self.views[t]
                if e.value["fields"] != [view["field"]] or len(e.children) != 1:
                    fail("E_C_BORROW_STORAGE", "Stored view differs from its verified layout", e.span)
                values = [self.borrowed(e.children[0], Type("slice", (Type("u8"),)), view["mode"], lines)]
            else:
                values = [self.value(x, lines) for x in e.children]
            expression = f"({self.typ(t)}){{ " + ", ".join(".h_" + n + " = " + v for n, v in zip(e.value["fields"], values)) + " }"
        elif k == "variant":
            values = [self.value(x, lines) for x in e.children]
            variants = self.variants(t)
            index = next(i for i, (name, _) in enumerate(variants) if name == e.value["variant"])
            fields = variants[index][1]
            payload = ", ".join(f".f_{i} = " + ("0" if field.name == "Unit" else value)
                                for i, (field, value) in enumerate(zip(fields, values))) or ".empty = 0"
            expression = f"({self.typ(t)}){{ .tag = {index}, .payload.v_{e.value['variant']} = {{ {payload} }} }}"
        elif k == "field":
            if self.root(e) is not None or (e.children[0].kind == "call" and
                    e.children[0].value in self.functions and self.functions[e.children[0].value].return_mode != "value"):
                expression = self.place(e, lines)
            else:
                base = self.value(e.children[0], lines)
                expression = "(" + base + ").h_" + e.value
        elif k == "index":
            expression = self.place(e, lines)
        elif k == "unary":
            child = e.children[0]
            if e.value in {"read", "mut"}:
                fail("E_C_BORROW", "Borrow outside a parameter position", e.span)
            if e.value == "-" and child.kind == "int" and t.name == "isize" and child.value == 1 << 63:
                expression = "INTPTR_MIN"
            elif e.value == "-" and child.kind == "int" and t.name.startswith("i") and t.name[1:].isdigit() and child.value == 1 << (int(t.name[1:]) - 1):
                expression = f"INT{t.name[1:]}_MIN"
            else:
                val = self.value(child, lines)
                if e.value == "move":
                    expression = val
                elif e.value == "-" and t.name in INTS:
                    expression = self.integer_helper(t) + f"sub(0, {val})"
                elif e.value == "!" and t.name in INTS:
                    expression = self.integer_helper(t) + f"bits(~(uint64_t){val})"
                else:
                    expression = f"({e.value}{val})"
        elif k == "binary":
            left = self.value(e.children[0], lines)
            if e.value in {"&&", "||"}:
                result = self.temp(Type("bool"), left, lines)
                inner = []
                right = self.value(e.children[1], inner)
                lines.append(f"if ({'!' if e.value == '||' else ''}{result}) {{ " + " ".join(inner) + f" {result} = {right}; }}")
                return result
            right = self.value(e.children[1], lines)
            if t.name in INTS and e.value in {"+", "-", "*", "/", "%", "<<", ">>", "&", "|", "^"}:
                operation = {"+": "add", "-": "sub", "*": "mul", "/": "div", "%": "rem", "<<": "shl", ">>": "shr", "&": "and", "|": "or", "^": "xor"}[e.value]
                expression = self.integer_helper(t) + f"{operation}({left}, {right})"
            elif t.name in {"f32", "f64"} and e.value == "%":
                expression = ("fmodf" if t.name == "f32" else "fmod") + f"({left}, {right})"
            else:
                expression = f"({left} {e.value} {right})"
        elif k == "cast":
            source = self.expr_type(e.children[0])
            val = self.value(e.children[0], lines)
            if source.name in INTS and t.name in INTS:
                expression = self.integer_helper(t) + f"bits((uint64_t){val})"
            elif source == t or (source.name == "raw_mut" and t.name == "raw_const"):
                expression = f"({self.typ(t)}){val}"
            else:
                fail("E_C_BACKEND_CAST", "Only integer casts and mut-to-const pointer casts are currently supported", e.span)
        elif k == "call":
            if e.value in self.functions:
                fn = self.functions[e.value]
                if fn.return_mode != "value":
                    if t.name == "slice" or is_owned_type(self.program, t):
                        fail("E_C_BACKEND_VIEW", "Borrowed owners/slices require immediate borrowing or sequence access", e.span)
                    expression = "(*" + self.view(e, lines) + ")"
                else:
                    expression = self.call(e, lines)
            elif e.value in {"buffer", "try_buffer"}:
                size = self.value(e.children[0], lines)
                expression = ("__hepta_cb_buffer_new" if e.value == "buffer" else "__hepta_cb_try_buffer") + "(" + size + ")"
            elif e.value in {"release", "drop"}:
                owner_type = self.expr_type(e.children[0])
                owner = self.value(e.children[0], lines)
                lines.append(self.drop_helper(owner_type) + "(" + owner + ");")
                return "((void)0)"
            elif e.value == "len":
                arg = e.children[0]
                if arg.kind == "unary":
                    arg = arg.children[0]
                _, expression = self.sequence(arg, lines)
            elif e.value in {"wrapping_add", "wrapping_sub", "wrapping_mul", "min", "max"}:
                args = [self.value(x, lines) for x in e.children]
                expression = self.integer_helper(t) + e.value + "(" + ", ".join(args) + ")"
            elif e.value == "assert":
                val = self.value(e.children[0], lines)
                lines.append(f"if (!{val}) abort();")
                return "((void)0)"
            elif e.value == "print_i64":
                val = self.value(e.children[0], lines)
                expression = f'((void)printf("%" PRId64 "\\n", {val}))'
            elif e.value in {"load", "store", "volatile_load", "volatile_store"}:
                if e.value in {"store", "volatile_store"}:
                    for child in e.children:
                        self.require_nonmutating(child)
                args = [self.value(x, lines) for x in e.children]
                if e.value.startswith("volatile_"):
                    element = self.typ(self.expr_type(e.children[0]).args[0])
                    const = "const " if e.value == "volatile_load" else ""
                    place = f"((volatile {const}{element} *)({args[0]}))[{args[1]}]"
                    expression = place if e.value == "volatile_load" else f"({place} = {args[2]})"
                else:
                    expression = f"({args[0]})[{args[1]}]" if e.value == "load" else f"(({args[0]})[{args[1]}] = {args[2]})"
            elif e.value in {"ptr_read", "ptr_mut"}:
                expression, _ = self.sequence(e.children[0].children[0], lines)
            else:
                fail("E_C_BACKEND_SUBSET", f"Builtin {e.value} is not supported by the C backend", e.span)
        else:
            fail("E_C_BACKEND_SUBSET", f"Expression {k} is not supported by the C backend", e.span)
        return self.temp(t, expression, lines)

    def block(self, body):
        lines = []
        for s in body:
            d = s.data
            lines.append("\n#line " + str(s.span.line) + " " + json.dumps(s.span.path))
            if s.kind == "let":
                v = self.value(d["expr"], lines)
                t = self.resolve(d["type"]) if d.get("type") else self.expr_type(d["expr"])
                if t.name != "Unit":
                    lines.append(self.typ(t) + " h_" + d["name"] + " = " + v + ";")
            elif s.kind == "assign":
                value = self.value(d["expr"], lines)
                if self.expr_type(d["target"]).name != "Unit":
                    place = self.place(d["target"], lines)
                    lines.append(place + " = " + value + ";")
            elif s.kind == "return":
                if self.current.return_mode != "value":
                    value = self.borrowed(d["expr"], self.resolve(self.current.return_type), self.current.return_mode, lines)
                else:
                    value = self.value(d["expr"], lines) if d.get("expr") else None
                lines.append("return" + (" " + value if value and self.expr_type(d["expr"]).name != "Unit" else "") + ";")
            elif s.kind == "expr":
                self.value(d["expr"], lines)
            elif s.kind == "unsafe":
                lines.append("{ " + self.block(d["body"]) + " }")
            elif s.kind == "if":
                cond = self.value(d["condition"], lines)
                lines.append(f"if ({cond}) {{ " + self.block(d["then"]) + " } else { " + self.block(d.get("else", [])) + " }")
            elif s.kind == "match":
                typ = self.expr_type(d["expr"])
                value = self.value(d["expr"], lines)
                variants = self.variants(typ)
                lines.append(f"switch ({value}.tag) {{")
                for arm in d["arms"]:
                    index = next(i for i, (name, _) in enumerate(variants) if name == arm.pattern.variant)
                    lines.append(f"case {index}: {{")
                    for i, (name, field) in enumerate(zip(arm.pattern.bindings, variants[index][1])):
                        if name != "_" and field.name != "Unit":
                            lines.append(self.typ(field) + f" h_{name} = {value}.payload.v_{arm.pattern.variant}.f_{i};")
                    lines.append(self.block(arm.body))
                    lines.append("break; }")
                lines.append("default: abort(); }")
            elif s.kind == "while":
                condition = []
                cond = self.value(d["condition"], condition)
                lines.append("while (true) { " + " ".join(condition) + f" if (!{cond}) break; " + self.block(d["body"]) + " }")
            elif s.kind == "for":
                begin = self.value(d["start"], lines)
                end = self.value(d["end"], lines)
                t = self.expr_type(d["start"])
                lines.append(f"for ({self.typ(t)} h_{d['name']} = {begin}; h_{d['name']} < {end}; ++h_{d['name']}) {{ " + self.block(d["body"]) + " }")
            else:
                fail("E_C_BACKEND_SUBSET", f"Statement {s.kind} is unsupported", s.span)
        return "\n".join(lines)

    def helper_source(self):
        lines = []
        for name in sorted(self.helpers):
            t = SCALARS[name]
            signed = name.startswith("i")
            u = {"isize": "uintptr_t", "usize": "size_t"}.get(name, SCALARS.get("u" + name[1:]))
            prefix = "__hepta_cb_" + name + "_"
            lines.append(f"static inline {t} {prefix}bits(uint64_t x) {{ {u} bits = ({u})x; {t} out; memcpy(&out, &bits, sizeof out); return out; }}")
            for op, builtin in [("add", "add"), ("sub", "sub"), ("mul", "mul")]:
                lines.append(f"static inline {t} {prefix}{op}({t} a, {t} b) {{ {t} r; if (__builtin_{builtin}_overflow(a,b,&r)) abort(); return r; }}")
            minimum = "INTPTR_MIN" if name == "isize" else f"INT{name[1:]}_MIN"
            bad = f" || (a == {minimum} && b == -1)" if signed else ""
            for operation, operator in [("div", "/"), ("rem", "%")]:
                lines.append(f"static inline {t} {prefix}{operation}({t} a, {t} b) {{ if (b == 0{bad}) abort(); return a {operator} b; }}")
            for operation, operator in [("wrapping_add", "+"), ("wrapping_sub", "-"), ("wrapping_mul", "*"), ("and", "&"), ("or", "|"), ("xor", "^")]:
                lines.append(f"static inline {t} {prefix}{operation}({t} a, {t} b) {{ return {prefix}bits((uint64_t)a {operator} (uint64_t)b); }}")
            for operation, operator in [("min", "<"), ("max", ">")]:
                lines.append(f"static inline {t} {prefix}{operation}({t} a, {t} b) {{ return a {operator} b ? a : b; }}")
            lines.append(f"static inline {t} {prefix}shl({t} a, {t} b) {{ if ((uint64_t)b >= sizeof(a)*CHAR_BIT) abort(); return {prefix}bits((uint64_t)a << b); }}")
            # Arithmetic right shift is explicit: no implementation-defined signed shift.
            fill = f" if (a < 0 && b) x |= UINT64_MAX << (sizeof(a)*CHAR_BIT - b);" if signed else ""
            lines.append(f"static inline {t} {prefix}shr({t} a, {t} b) {{ if ((uint64_t)b >= sizeof(a)*CHAR_BIT) abort(); uint64_t x = (uint64_t)({u})a >> b;{fill} return {prefix}bits(x); }}")
        return "\n".join(lines)

    def runtime_source(self):
        if not self.runtime:
            return ""
        result = Type("Result", (Type("Buffer", (Type("u8"),)), Type("u8")))
        result_name = self.typ(result)
        return r'''
static bool __hepta_cb_allocate(size_t size, __hepta_cb_buffer *out) {
    if (size > PTRDIFF_MAX) return false;
    uint8_t *data = size ? calloc(size, sizeof(uint8_t)) : NULL;
    if (size && !data) return false;
    *out = (__hepta_cb_buffer){data, size};
    return true;
}
static __hepta_cb_buffer __hepta_cb_buffer_new(size_t size) {
    __hepta_cb_buffer out;
    if (!__hepta_cb_allocate(size, &out)) abort();
    return out;
}
''' + f'''
static {result_name} __hepta_cb_try_buffer(size_t size) {{
    __hepta_cb_buffer out;
    if (!__hepta_cb_allocate(size, &out))
        return ({result_name}){{.tag=1, .payload.v_Err={{.f_0=1}}}};
    return ({result_name}){{.tag=0, .payload.v_Ok={{.f_0=out}}}};
}}
'''

    @staticmethod
    def retain_source_lines(source):
        """Keep every generated instruction at its owning Hepta statement.

        A single #line before a source statement is insufficient: the C
        preprocessor increments that number for each emitted temporary. Reset
        it before every physical generated line, retaining nested statement
        directives as more specific origins.
        """
        directive = None
        lines = []
        for line in source.splitlines():
            if line.lstrip().startswith("#line "):
                directive = line.strip()
            elif line.strip():
                if directive is not None:
                    lines.append(directive)
                lines.append(line)
        return "\n".join(lines)

    def emit(self):
        for st in self.program.structs:
            if not st.type_params and not st.lifetime_params:
                self.typ(Type(st.name))
        for enum in self.program.enums:
            if not enum.type_params:
                self.typ(Type(enum.name))
        for fn in self.program.functions:
            if not fn.type_params:
                self.instance(fn)
        signatures = []
        bodies = []
        index = 0
        while index < len(self.pending):
            fn, args = self.pending[index]
            index += 1
            self.mapping = dict(zip(fn.type_params, args))
            self.current = fn
            signature = self.signature(fn, args)
            signatures.append(signature)
            if fn.extern_c:
                continue
            self.params = {p.name: replace(p, type=self.resolve(p.type)) for p in fn.params}
            directive = "#line " + str(fn.span.line) + " " + json.dumps(fn.span.path)
            bodies.append(self.retain_source_lines(directive + "\n" + signature + " {\n" + self.block(fn.body or []) + "\n}"))
        if self.crate_type == "bin":
            main = self.functions.get("main")
            if not main or main.params or main.return_type.name not in {"Unit", "i32"} or main.extern_c or main.export_c:
                fail("E_C_ENTRYPOINT", "A C binary requires a non-FFI main() -> Unit or i32")
            expression = self.fn_name(main) + "()"
            bodies.append("int main(void) { " + (expression + "; return 0;" if main.return_type.name == "Unit" else "return " + expression + ";") + " }")
        includes = "\n".join("#include <" + name + ">" for name in ["stdint.h", "stddef.h", "stdbool.h", "inttypes.h", "limits.h", "stdlib.h", "stdio.h", "string.h", "math.h"])
        runtime = self.runtime_source()
        drops = "\n".join("static void " + name + "(" + self.typ(typ) + " value);" for typ, (name, _) in self.drops.items())
        drops += "\n" + "\n".join(body for _, body in self.drops.values())
        return "/* Hepta independent C11/GCC backend. No Rust compiler involved. */\n" + includes + "\n_Static_assert(CHAR_BIT == 8 && sizeof(size_t) == 8 && sizeof(intptr_t) == 8, \"C backend requires the qualified 64-bit data model\");\n" + "\n".join(self.declarations) + "\n" + self.helper_source() + "\n" + runtime + "\n" + drops + "\n" + "\n".join(s + ";" for s in signatures) + "\n" + "\n".join(bodies) + "\n"


def emit_c(program, checked, *, crate_type="bin") -> str:
    return CEmitter(program, checked, crate_type).emit()


def compile_c(source: str, *, cc=None, crate_type="bin", output=None, check_only=False,
              optimize=True, link_args=None, target=None, sanitize=False,
              optimization_profile="default", debug_info=False) -> dict:
    if optimization_profile not in {"default", "unroll"} or (optimization_profile != "default" and not optimize):
        fail("E_C_OPTIMIZATION", "C optimization profile must be default or unroll; unroll requires optimization")
    if target:
        fail("E_C_TARGET", "The C backend currently supports the native GCC target only; use an explicit cross compiler in a future qualified profile")
    if crate_type not in {"bin", "obj", "staticlib", "cdylib"}:
        fail("E_C_CRATE_TYPE", "C backend supports bin, obj, staticlib and cdylib")
    compiler = shutil.which(cc or os.environ.get("CC", "gcc"))
    if not compiler:
        fail("E_C_TOOLCHAIN", "A GCC-compatible native C compiler is required")
    version = subprocess.run([compiler, "--version"], capture_output=True, text=True, timeout=30)
    triple = subprocess.run([compiler, "-dumpmachine"], capture_output=True, text=True, timeout=30)
    if version.returncode or triple.returncode or not version.stdout or not triple.stdout.strip():
        fail("E_C_TOOLCHAIN", "C compiler identity queries failed")
    artifact = Path(output).resolve() if output else None
    if debug_info and artifact is None:
        fail("E_DEBUG_OUTPUT", "Debug builds need an explicit output to retain their generated source")
    if artifact:
        artifact.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="hepta-c-") as td:
        directory = Path(td)
        cfile, generated = directory / "program.c", directory / "artifact"
        retained_debug = None
        if debug_info:
            from .debug_info import retain_debug_source
            cfile, retained_debug = retain_debug_source(source, artifact, "c")
        else:
            cfile.write_text(source)
        flags = ["-std=c11", "-O3" if optimize else "-O0", "-fexcess-precision=standard", "-ffp-contract=off", "-fno-strict-aliasing", "-Wall", "-Wextra", "-Werror=implicit-function-declaration", "-Werror=incompatible-pointer-types"]
        if optimization_profile == "unroll":
            flags.append("-funroll-loops")
        if debug_info:
            flags += ["-g3", "-fno-omit-frame-pointer"]
        if sanitize:
            flags += ["-fsanitize=undefined", "-fno-sanitize-recover=all"]
        command = [compiler, *flags, str(cfile), "-o", str(generated)]
        if check_only or crate_type in {"obj", "staticlib"}:
            command += ["-c"]
        elif crate_type == "cdylib":
            command += ["-shared", "-fPIC"]
        if not check_only and crate_type in {"bin", "cdylib"}:
            command += [*(link_args or []), "-lm"]
        p = subprocess.run(command, capture_output=True, text=True, timeout=120)
        ok = p.returncode == 0 and generated.is_file() and generated.stat().st_size > 0
        diagnostics = [] if ok else [{"code": "E_C_COMPILE", "message": p.stderr or "C compiler produced no nonempty artifact", "phase": "c_backend"}]
        if ok and crate_type == "staticlib" and not check_only:
            archive = directory / "library.a"
            ar = shutil.which("ar")
            if not ar:
                fail("E_C_TOOLCHAIN", "ar is required for a C static library")
            subprocess.run([ar, "rcs", str(archive), str(generated)], check=True, capture_output=True, timeout=30)
            generated = archive
        result = {"ok": ok, "status": "gcc_checked" if ok else "rejected", "diagnostics": diagnostics,
                  "backend": "c11-gcc", "rustc_used": False, "target": triple.stdout.strip(),
                  "toolchain": {"path": compiler, "version": version.stdout.strip(), "executable_sha256": _hash(Path(compiler).read_bytes())},
                  "source_sha256": _hash(source.encode()), "flags": flags, "check_only": check_only,
                  "crate_type": crate_type, "link_args": link_args or [],
                  "optimization_profile": optimization_profile}
        if debug_info:
            result["debug_info"] = retained_debug
        if ok:
            result["validation_artifact_sha256"] = _hash(generated.read_bytes())
            if artifact:
                with tempfile.NamedTemporaryFile(prefix=".hepta-c-artifact-", dir=artifact.parent, delete=False) as staged:
                    staged.write(generated.read_bytes())
                    staged_name = Path(staged.name)
                try:
                    if crate_type == "bin" and not check_only:
                        staged_name.chmod(0o755)
                    os.replace(staged_name, artifact)
                finally:
                    staged_name.unlink(missing_ok=True)
                result.update(artifact=str(artifact), artifact_bytes=artifact.stat().st_size,
                              artifact_sha256=_hash(artifact.read_bytes()))
        return result
