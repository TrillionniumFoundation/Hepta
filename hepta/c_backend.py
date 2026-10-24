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

from .ast import Diagnostic, HeptaError, Type

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
        if getattr(program, "enums", None) or getattr(program, "unions", None):
            fail("E_C_BACKEND_SUBSET", "ADT lowering is not yet supported by the C backend")
        if any(getattr(item, "type_params", ()) for item in [*program.structs, *program.functions]):
            fail("E_C_BACKEND_SUBSET", "Generic declarations require an explicit monomorphization pass before C lowering")
        self.program, self.checked, self.crate_type = program, checked, crate_type
        self.structs = {s.name: s for s in program.structs}
        self.functions = {f.name: f for f in program.functions}
        self.declarations, self.types, self.active = [], {}, set()
        self.helpers = set()
        self.counter = 0
        self.params = {}

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
        if t.name not in self.structs and t.name != "array":
            fail("E_C_BACKEND_SUBSET", f"C backend does not yet lower {t}")
        if t.name in self.structs and t.args:
            fail("E_C_BACKEND_SUBSET", "Generic structs must be concretely instantiated before C lowering")
        if t.name == "array" and (not t.length or t.args[0].name == "Unit"):
            fail("E_C_BACKEND_SUBSET", "Zero-length and Unit-element arrays are not supported by the C backend")
        name = "__hepta_cb_type_" + (t.name if t.name != "array" else "array_" + str(len(self.types)))
        self.types[t] = name
        self.active.add(t)
        if t.name == "array":
            fields = self.typ(t.args[0]) + f" data[{t.length}];"
        else:
            st = self.structs[t.name]
            if not st.fields:
                fail("E_C_BACKEND_SUBSET", "Empty structs are not supported by the C backend")
            if any(f.type.name == "Unit" for f in st.fields):
                fail("E_C_BACKEND_SUBSET", "Unit fields are not supported by the C backend")
            if st.repr_c and any(f.type.name == "array" for f in st.fields):
                fail("E_C_BACKEND_SUBSET", "repr(C) array fields are not yet supported in the independent backend")
            fields = " ".join(self.typ(f.type) + " h_" + f.name + ";" for f in st.fields)
        self.active.remove(t)
        self.declarations.append(f"typedef struct {{ {fields} }} {name};")
        return name

    def slice_type(self, t, mode):
        key = Type("c_slice_" + mode, t.args)
        if key not in self.types:
            elem = self.typ(t.args[0])
            name = f"__hepta_cb_slice_{len(self.types)}"
            self.types[key] = name
            self.declarations.append(f"typedef struct {{ {'const ' if mode == 'read' else ''}{elem} *data; size_t len; }} {name};")
        return self.types[key]

    def fn_name(self, fn):
        return fn.name if fn.extern_c or fn.export_c else "__hepta_cb_fn_" + fn.name

    def parameter(self, p):
        if p.type.name == "slice":
            return self.slice_type(p.type, p.mode) + " h_" + p.name
        return ("const " if p.mode == "read" else "") + self.typ(p.type) + (" *" if p.mode in {"read", "mut"} else " ") + "h_" + p.name

    def signature(self, fn):
        if fn.return_type.name == "slice" or getattr(fn, "type_params", None) or getattr(fn, "generics", None):
            fail("E_C_BACKEND_SUBSET", "Uninstantiated generics and returned slices are unsupported", fn.span)
        return self.typ(fn.return_type) + " " + self.fn_name(fn) + "(" + (", ".join(self.parameter(p) for p in fn.params) or "void") + ")"

    def expr_type(self, e):
        t = self.checked.expr_types.get(id(e))
        if t is None:
            fail("E_C_BACKEND_TYPE", "Missing checked expression type", e.span)
        return t

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
        borrowed = []
        for arg, param in zip(call.children, fn.params):
            if param.mode in {"read", "mut"}:
                root = self.root(arg)
                if root is None:
                    fail("E_C_BORROW", "C borrow arguments require named places", arg.span)
                for old_root, old_mode in borrowed:
                    if old_root == root and "mut" in {old_mode, param.mode}:
                        fail("E_C_BORROW", "Overlapping borrows of the same root are rejected conservatively", arg.span)
                borrowed.append((root, param.mode))
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
        if t.name not in {"array", "slice"}:
            fail("E_C_BACKEND_SUBSET", "Only fixed arrays and borrowed slices are supported sequences", e.span)
        p = self.place(e, lines)
        return f"({p}).data", str(t.length) if t.name == "array" else f"({p}).len"

    def integer_helper(self, t):
        self.helpers.add(t.name)
        return "__hepta_cb_" + t.name + "_"

    def value(self, e, lines):
        t = self.expr_type(e)
        k = e.kind
        if k == "name":
            if t.name == "slice":
                fail("E_C_BACKEND_SUBSET", "Borrowed slices cannot be copied as values", e.span)
            expression = self.place(e, lines)
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
            values = [self.value(x, lines) for x in e.children]
            expression = f"({self.typ(t)}){{ " + ", ".join(".h_" + n + " = " + v for n, v in zip(e.value["fields"], values)) + " }"
        elif k == "field":
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
                self.check_borrows(e, fn)
                values = []
                for arg, param in zip(e.children, fn.params):
                    if param.mode in {"read", "mut"}:
                        child = arg.children[0]
                        if param.type.name == "slice":
                            data, length = self.sequence(child, lines)
                            values.append(f"({self.slice_type(param.type, param.mode)}){{{data}, {length}}}")
                        else:
                            values.append("&(" + self.place(child, lines) + ")")
                    else:
                        values.append(self.value(arg, lines))
                expression = self.fn_name(fn) + "(" + ", ".join(values) + ")"
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
            elif e.value in {"load", "store"}:
                if e.value == "store":
                    for child in e.children:
                        self.require_nonmutating(child)
                args = [self.value(x, lines) for x in e.children]
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
            if s.kind == "let":
                v = self.value(d["expr"], lines)
                t = d.get("type") or self.expr_type(d["expr"])
                lines.append(self.typ(t) + " h_" + d["name"] + " = " + v + ";")
            elif s.kind == "assign":
                value = self.value(d["expr"], lines)
                place = self.place(d["target"], lines)
                lines.append(place + " = " + value + ";")
            elif s.kind == "return":
                value = self.value(d["expr"], lines) if d.get("expr") else None
                lines.append("return" + (" " + value if value and self.expr_type(d["expr"]).name != "Unit" else "") + ";")
            elif s.kind == "expr":
                self.value(d["expr"], lines)
            elif s.kind == "unsafe":
                lines.append("{ " + self.block(d["body"]) + " }")
            elif s.kind == "if":
                cond = self.value(d["condition"], lines)
                lines.append(f"if ({cond}) {{ " + self.block(d["then"]) + " } else { " + self.block(d.get("else", [])) + " }")
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

    def emit(self):
        for st in self.program.structs:
            self.typ(Type(st.name))
        signatures = [self.signature(fn) for fn in self.program.functions]
        bodies = []
        for fn, signature in zip(self.program.functions, signatures):
            if fn.extern_c:
                continue
            self.params = {p.name: p for p in fn.params}
            bodies.append(signature + " {\n" + self.block(fn.body or []) + "\n}")
        if self.crate_type == "bin":
            main = self.functions.get("main")
            if not main or main.params or main.return_type.name not in {"Unit", "i32"} or main.extern_c or main.export_c:
                fail("E_C_ENTRYPOINT", "A C binary requires a non-FFI main() -> Unit or i32")
            expression = self.fn_name(main) + "()"
            bodies.append("int main(void) { " + (expression + "; return 0;" if main.return_type.name == "Unit" else "return " + expression + ";") + " }")
        includes = "\n".join("#include <" + name + ">" for name in ["stdint.h", "stddef.h", "stdbool.h", "inttypes.h", "limits.h", "stdlib.h", "stdio.h", "string.h", "math.h"])
        return "/* Hepta independent C11/GCC backend. No Rust compiler involved. */\n" + includes + "\n_Static_assert(CHAR_BIT == 8 && sizeof(size_t) == 8 && sizeof(intptr_t) == 8, \"C backend requires the qualified 64-bit data model\");\n" + "\n".join(self.declarations) + "\n" + self.helper_source() + "\n" + "\n".join(s + ";" for s in signatures) + "\n" + "\n".join(bodies) + "\n"


def emit_c(program, checked, *, crate_type="bin") -> str:
    return CEmitter(program, checked, crate_type).emit()


def compile_c(source: str, *, cc=None, crate_type="bin", output=None, check_only=False,
              optimize=True, link_args=None, target=None, sanitize=False) -> dict:
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
    if artifact:
        artifact.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="hepta-c-") as td:
        directory = Path(td)
        cfile, generated = directory / "program.c", directory / "artifact"
        cfile.write_text(source)
        flags = ["-std=c11", "-O3" if optimize else "-O0", "-fexcess-precision=standard", "-ffp-contract=off", "-fno-strict-aliasing", "-Wall", "-Wextra", "-Werror=implicit-function-declaration", "-Werror=incompatible-pointer-types"]
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
                  "crate_type": crate_type, "link_args": link_args or []}
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
