"""AST-only Rust lowering and an actual native backend validation gate.

The bootstrap deliberately delegates borrow checking and machine-code generation
to a pinned rustc. It never treats frontend acceptance as complete validation.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, fields, is_dataclass
from pathlib import Path
import shutil
import subprocess
import tempfile

from .ast import Diagnostic, Expr, Function, HeptaError, Program, Span, Stmt, Type
from .checker import is_owned_type
from .runtime_concurrency import GROUP_RUNTIME, GROUP_TYPE_NAMES


RUST_VERSION = "1.90.0"
PRIMITIVES = {"u8", "u16", "u32", "u64", "u128", "usize", "i8", "i16", "i32", "i64", "i128", "isize", "f32", "f64", "bool"}
C_TYPES = {"u8": "uint8_t", "u16": "uint16_t", "u32": "uint32_t", "u64": "uint64_t",
           "i8": "int8_t", "i16": "int16_t", "i32": "int32_t", "i64": "int64_t",
           "usize": "size_t", "isize": "intptr_t", "f32": "float", "f64": "double", "Unit": "void"}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def rust_type(t: Type, type_params: set[str] | frozenset[str] = frozenset()) -> str:
    if t.name in type_params:
        return "G_" + t.name
    if t.name == "TaskGroup":
        return "HeptaTaskGroup"
    if t.name == "Sender":
        return "HeptaSender"
    if t.name == "Task":
        return "HeptaTask"
    if t.name == "Cancellation":
        return "HeptaCancellation"
    if t.name == "Unit":
        return "()"
    if t.name in PRIMITIVES:
        return t.name
    if t.name == "array":
        return f"[{rust_type(t.args[0], type_params)}; {t.length}]"
    if t.name == "slice":
        return f"[{rust_type(t.args[0], type_params)}]"
    if t.name == "Buffer":
        return f"std::vec::Vec<{rust_type(t.args[0], type_params)}>"
    if t.name in ("raw_const", "raw_mut"):
        return f"*{'const' if t.name == 'raw_const' else 'mut'} {rust_type(t.args[0], type_params)}"
    name = "core::result::Result" if t.name == "Result" else "H_" + t.name
    return name + ("<" + ", ".join(rust_type(arg, type_params) for arg in t.args) + ">" if t.args else "")


def c_decl(t: Type, name: str, const: bool = False) -> str:
    if t.name in ("raw_const", "raw_mut"):
        decorated = "*" + (" const " if const else "") + name
        if t.args[0].name == "array":
            decorated = f"({decorated})"
        return c_decl(t.args[0], decorated, t.name == "raw_const")
    if t.name == "array":
        return c_decl(t.args[0], f"{name}[{t.length}]", const)
    if t.name in ("slice", "Buffer", "bool", "u128", "i128"):
        raise HeptaError(Diagnostic("E_C_TYPE", f"{t} has no supported C boundary representation", phase="abi"))
    base = C_TYPES.get(t.name, "hepta_" + t.name)
    return (("const " if const else "") + base + " " + name).strip()


class Emitter:
    def __init__(self, program: Program, checked, no_std: bool = False, crate_type: str = "rlib"):
        self.program = program
        self.checked = checked
        self.no_std = no_std
        self.crate_type = crate_type
        self.params: dict[str, str] = {}
        self.type_params: set[str] = set()
        self.functions = {f.name: f for f in program.functions}

    def typ(self, typ: Type) -> str:
        return rust_type(typ, self.type_params)

    def constructor(self, typ: Type) -> str:
        return self.typ(typ).replace("<", "::<", 1)

    def generics(self, params: tuple[str, ...], *, copy_bound: bool = True) -> str:
        return "<" + ", ".join("G_" + name + (": core::marker::Copy" if copy_bound else "") for name in params) + ">" if params else ""

    @staticmethod
    def variant_name(enum_name: str, variant_name: str) -> str:
        return variant_name if enum_name == "Result" else "V_" + variant_name

    def expr(self, e: Expr) -> str:
        kind = e.kind
        typ = self.checked.expr_types.get(id(e))
        if kind == "int":
            suffix = typ.name if typ and typ.name in PRIMITIVES - {"bool", "f32", "f64"} else "i64"
            return f"{e.value}{suffix}"
        if kind == "float":
            suffix = typ.name if typ and typ.name in {"f32", "f64"} else "f64"
            return f"{e.value!r}{suffix}"
        if kind == "bool":
            return "true" if e.value else "false"
        if kind == "name":
            name = "h_" + e.value
            return "(*" + name + ")" if self.params.get(e.value) in {"read", "mut"} else name
        if kind == "array":
            return "[" + ", ".join(self.expr(x) for x in e.children) + "]"
        if kind == "struct":
            return self.constructor(typ) + " { " + ", ".join(
                "h_" + name + ": " + self.expr(value)
                for name, value in zip(e.value["fields"], e.children)) + " }"
        if kind == "variant":
            name = self.constructor(typ) + "::" + self.variant_name(e.value["enum"], e.value["variant"])
            return name + ("(" + ", ".join(self.expr(child) for child in e.children) + ")" if e.children else "")
        if kind == "field":
            return f"({self.expr(e.children[0])}).h_{e.value}"
        if kind == "index":
            return f"({self.expr(e.children[0])})[{self.expr(e.children[1])}]"
        if kind == "cast":
            return f"({self.expr(e.children[0])} as {self.typ(e.value)})"
        if kind == "binary":
            return f"({self.expr(e.children[0])} {e.value} {self.expr(e.children[1])})"
        if kind == "unary":
            value = e.children[0]
            emitted = self.expr(value)
            if e.value == "move":
                return emitted
            if e.value in {"read", "mut"}:
                return "(" + ("&mut " if e.value == "mut" else "&") + emitted + ")"
            if e.value == "-" and value.kind in {"int", "float"}:
                return "(-" + emitted + ")"
            return f"({e.value}{emitted})"
        if kind == "call":
            if e.value == "spawn":
                return "__hepta_rt_spawn(h_" + e.children[0].value + ", " + self.expr(e.children[1]) + ")"
            if e.value == "group_spawn":
                return "__hepta_group_spawn(" + self.expr(e.children[0]) + ", h_" + e.children[1].value + ", " + self.expr(e.children[2]) + ")"
            args = [self.expr(x) for x in e.children]
            group_calls = {"task_group": "__hepta_group_new", "group_send": "__hepta_group_send",
                           "group_receive": "__hepta_group_receive", "group_seal": "__hepta_group_seal",
                           "group_snapshot": "__hepta_group_snapshot", "group_fail": "__hepta_group_fail"}
            if e.value in group_calls:
                return group_calls[e.value] + "(" + ", ".join(args) + ")"
            if e.value in {"group_join", "group_drain_and_join", "group_cancel_and_join"}:
                mode = {"group_join": 0, "group_drain_and_join": 1, "group_cancel_and_join": 2}[e.value]
                return "__hepta_group_join(" + args[0] + ", " + str(mode) + "u8)"
            if e.value in {"join", "cancel_and_join"}:
                return "__hepta_rt_join(" + args[0] + ", " + ("true" if e.value == "cancel_and_join" else "false") + ")"
            if e.value == "cancelled":
                return "(" + args[0] + ").flag.load(std::sync::atomic::Ordering::Acquire)"
            if e.value == "len":
                return f"({args[0]}).len()"
            if e.value in {"wrapping_add", "wrapping_sub", "wrapping_mul", "min", "max"}:
                return f"({args[0]}).{e.value}({args[1]})"
            if e.value == "buffer":
                return f"std::vec![0u8; {args[0]}]"
            if e.value == "try_buffer":
                return f"__hepta_try_buffer({args[0]})"
            if e.value in {"release", "drop"}:
                return f"core::mem::drop({args[0]})"
            if e.value == "assert":
                return f"assert!({args[0]})"
            if e.value == "print_i64":
                return f"std::println!(\"{{}}\", {args[0]})"
            if e.value in {"ptr_read", "ptr_mut"}:
                method = "as_ptr" if e.value == "ptr_read" else "as_mut_ptr"
                return f"({args[0]}).{method}()"
            if e.value == "load":
                return f"(*({args[0]}).add({args[1]}))"
            if e.value == "store":
                return f"{{ *({args[0]}).add({args[1]}) = {args[2]}; }}"
            generics = "::<" + ", ".join(self.typ(t) for t in e.type_args) + ">" if e.type_args else ""
            call = "h_" + e.value + generics + "(" + ", ".join(args) + ")"
            fn = self.functions.get(e.value)
            return "(*" + call + ")" if fn is not None and fn.return_mode in {"read", "mut"} else call
        raise HeptaError(Diagnostic("E_BACKEND_AST", f"Unsupported expression {kind}", e.span, phase="lower"))

    def block(self, body: list[Stmt], level: int = 0) -> str:
        indent = "    " * level
        lines = ["{"]
        for s in body:
            prefix = "    " * (level + 1)
            lines.append(prefix + "// hepta-source: " + json.dumps({"event": "begin", "kind": "statement", "span": asdict(s.span)}, ensure_ascii=True, separators=(",", ":")))
            d = s.data
            if s.kind == "let":
                t = d.get("type") or self.checked.expr_types.get(id(d["expr"]))
                annotation = ": " + self.typ(t) if t else ""
                line = "let " + ("mut " if d.get("mutable") else "") + "h_" + d["name"] + annotation + " = " + self.expr(d["expr"]) + ";"
            elif s.kind == "assign":
                line = self.expr(d["target"]) + " = " + self.expr(d["expr"]) + ";"
            elif s.kind == "return":
                line = "return" + (" " + self.expr(d["expr"]) if d.get("expr") else "") + ";"
            elif s.kind == "expr":
                line = self.expr(d["expr"]) + ";"
            elif s.kind == "if":
                line = "if " + self.expr(d["condition"]) + " " + self.block(d["then"], level + 1)
                if d.get("else"):
                    line += " else " + self.block(d["else"], level + 1)
            elif s.kind == "match":
                typ = self.checked.expr_types[id(d["expr"])]
                line = "match " + self.expr(d["expr"]) + " {\n"
                for arm in d["arms"]:
                    pattern = arm.pattern
                    path = ("core::result::Result" if typ.name == "Result" else "H_" + typ.name) + "::" + self.variant_name(typ.name, pattern.variant)
                    if pattern.bindings:
                        path += "(" + ", ".join("_" if name == "_" else "h_" + name for name in pattern.bindings) + ")"
                    line += "    " * (level + 2) + path + " => " + self.block(arm.body, level + 2) + ",\n"
                line += prefix + "}"
            elif s.kind == "for":
                line = "for h_" + d["name"] + " in " + self.expr(d["start"]) + ".." + self.expr(d["end"]) + " " + self.block(d["body"], level + 1)
            elif s.kind == "while":
                line = "while " + self.expr(d["condition"]) + " " + self.block(d["body"], level + 1)
            elif s.kind == "unsafe":
                line = "unsafe " + self.block(d["body"], level + 1)
            else:
                raise HeptaError(Diagnostic("E_BACKEND_AST", f"Unsupported statement {s.kind}", s.span, phase="lower"))
            lines.append(prefix + line)
            lines.append(prefix + '// hepta-source: {"event":"end"}')
        lines.append(indent + "}")
        return "\n".join(lines)

    def param(self, p) -> str:
        t = self.typ(p.type)
        if p.mode == "read":
            t = "&" + t
        elif p.mode == "mut":
            t = "&mut " + t
        return "h_" + p.name + ": " + t

    def emit(self) -> str:
        # Runtime types can occur only in an enum payload or an explicit
        # generic argument, even when no expression produces that type.
        all_types: list[Type] = []
        pending = [self.program, *self.checked.expr_types.values()]
        while pending:
            value = pending.pop()
            if isinstance(value, Type):
                all_types.append(value)
                pending.extend(value.args)
            elif is_dataclass(value):
                pending.extend(getattr(value, item.name) for item in fields(value))
            elif isinstance(value, dict):
                pending.extend(value.values())
            elif isinstance(value, (list, tuple)):
                pending.extend(value)
        lines = ["// Generated by Hepta 0.2.0 from checked AST; do not edit.",
                 "#![allow(non_camel_case_types, unused, unused_parens)]"]
        if self.no_std:
            if any(t.name == "Buffer" for t in all_types) or any("io" in e or "alloc" in e or "spawn" in e for e in self.checked.effects.values()):
                raise HeptaError(Diagnostic("E_NO_STD", "This unit requires hosted allocation, I/O, or tasks", phase="lower"))
            if self.crate_type == "bin":
                raise HeptaError(Diagnostic("E_NO_STD_ENTRY", "Bare-metal entrypoints are not implemented; build a no_std object or library", phase="lower"))
            lines.append("#![no_std]")
        uses_groups = any(t.name in GROUP_TYPE_NAMES for t in all_types)
        if uses_groups or any(t.name in {"Task", "Cancellation"} for t in all_types):
            if self.no_std:
                raise HeptaError(Diagnostic("E_NO_STD", "Hosted tasks require the optional thread runtime", phase="lower"))
            lines.append(TASK_RUNTIME)
        if uses_groups:
            lines.append(GROUP_RUNTIME)
        if any(t.name == "Buffer" for t in all_types):
            lines.append(BUFFER_RUNTIME)
        for st in self.program.structs:
            self.type_params = set(st.type_params)
            if st.repr_c:
                lines.append("#[repr(C)]")
            if not is_owned_type(self.program, Type(st.name)):
                lines.append("#[derive(Clone, Copy)]")
            lines.append("pub struct H_" + st.name + self.generics(st.type_params, copy_bound=False) + " { " + ", ".join("pub h_" + f.name + ": " + self.typ(f.type) for f in st.fields) + " }")
        for enum in self.program.enums:
            self.type_params = set(enum.type_params)
            if not is_owned_type(self.program, Type(enum.name)):
                lines.append("#[derive(Clone, Copy)]")
            variants = [self.variant_name(enum.name, variant.name) + ("(" + ", ".join(self.typ(t) for t in variant.fields) + ")" if variant.fields else "") for variant in enum.variants]
            lines.append("pub enum H_" + enum.name + self.generics(enum.type_params, copy_bound=False) + " { " + ", ".join(variants) + " }")
        for fn in self.program.functions:
            self.params = {p.name: p.mode for p in fn.params}
            self.type_params = set(fn.type_params)
            return_prefix = "&" if fn.return_mode == "read" else "&mut " if fn.return_mode == "mut" else ""
            signature = "fn h_" + fn.name + self.generics(fn.type_params) + "(" + ", ".join(self.param(p) for p in fn.params) + ") -> " + return_prefix + self.typ(fn.return_type)
            lines.append("// hepta-source: " + json.dumps({"event": "begin", "kind": "declaration", "span": asdict(fn.span)}, ensure_ascii=True, separators=(",", ":")))
            if fn.extern_c:
                lines.append('extern "C" { #[link_name = ' + json.dumps(fn.name) + "] pub " + signature + "; }")
            else:
                if fn.export_c:
                    lines.append("#[export_name = " + json.dumps(fn.name) + "]")
                lines.append(("pub " if fn.public or fn.export_c else "") + ('extern "C" ' if fn.export_c else "") + signature + " " + self.block(fn.body or []))
            lines.append('// hepta-source: {"event":"end"}')
        if self.crate_type == "bin":
            main = next((f for f in self.program.functions if f.name == "main" and f.body is not None), None)
            if main is None or main.params or main.return_type.name not in {"Unit", "i32"}:
                raise HeptaError(Diagnostic("E_ENTRYPOINT", "A binary requires fn main() -> Unit or i32", phase="lower"))
            lines.append("fn main() { " + ("h_main();" if main.return_type.name == "Unit" else "std::process::exit(h_main());") + " }")
        if self.no_std and self.crate_type in {"staticlib", "cdylib", "obj"}:
            lines.append("#[panic_handler] fn hepta_abort(_: &core::panic::PanicInfo<'_>) -> ! { loop { core::hint::spin_loop(); } }")
        return "\n".join(lines) + "\n"


BUFFER_RUNTIME = r'''
fn __hepta_try_buffer(size: usize) -> core::result::Result<std::vec::Vec<u8>, u8> {
    let mut bytes = std::vec::Vec::new();
    if bytes.try_reserve_exact(size).is_err() {
        return Err(1u8);
    }
    // Successful reservation proves capacity >= size. u8 initialization cannot
    // call user code or allocate again; no uninitialized bytes are exposed.
    bytes.resize(size, 0u8);
    Ok(bytes)
}
'''


TASK_RUNTIME = r'''
pub struct HeptaCancellation {
    flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
}
pub struct HeptaTask {
    handle: std::thread::JoinHandle<u64>,
    flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
}
fn __hepta_rt_spawn(
    worker: fn(std::vec::Vec<u8>, &HeptaCancellation) -> u64,
    data: std::vec::Vec<u8>,
) -> HeptaTask {
    let flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let cancellation = HeptaCancellation { flag: std::sync::Arc::clone(&flag) };
    let handle = std::thread::spawn(move || worker(data, &cancellation));
    HeptaTask { handle, flag }
}
fn __hepta_rt_join(task: HeptaTask, cancel: bool) -> u64 {
    let HeptaTask { handle, flag } = task;
    if cancel { flag.store(true, std::sync::atomic::Ordering::Release); }
    handle.join().expect("Hepta task panicked")
}
'''


def emit_rust(program: Program, checked, no_std=False, crate_type="rlib") -> str:
    return Emitter(program, checked, no_std, crate_type).emit()


def emit_header(program: Program) -> str:
    guard = "HEPTA_" + program.name.upper() + "_H"
    lines = ["/* Generated by Hepta 0.2.0. ABI is target-specific. */", f"#ifndef {guard}", f"#define {guard}",
             "#include <stdint.h>", "#include <stddef.h>", '#ifdef __cplusplus\nextern "C" {\n#endif']
    structs = {s.name: s for s in program.structs if s.repr_c}
    for name in structs:
        lines.append(f"typedef struct hepta_{name} hepta_{name};")
    emitted, active = set(), set()
    def complete_dependencies(t, complete=True):
        # A pointer permits an incomplete struct pointee, but it does not permit
        # an array with incomplete elements (even behind multiple pointers).
        if t.name == "array":
            return complete_dependencies(t.args[0], True)
        if t.name in {"raw_const", "raw_mut"}:
            return complete_dependencies(t.args[0], False)
        return {t.name} if complete and t.name in structs else set()
    def emit_struct(name):
        if name in emitted:
            return
        if name in active:
            raise HeptaError(Diagnostic("E_C_RECURSIVE_LAYOUT", "Recursive by-value C struct", phase="abi"))
        active.add(name)
        st = structs[name]
        for p in st.fields:
            for dep in sorted(complete_dependencies(p.type)):
                emit_struct(dep)
        lines.append(f"struct hepta_{name} {{")
        for p in st.fields:
            lines.append("    " + c_decl(p.type, p.name) + ";")
        lines.append("};")
        active.remove(name)
        emitted.add(name)
    for name in structs:
        emit_struct(name)
    for fn in program.functions:
        if fn.export_c or fn.extern_c:
            params = ", ".join(c_decl(p.type, p.name) for p in fn.params) or "void"
            lines.append(c_decl(fn.return_type, fn.name + "(" + params + ")") + ";")
    lines += ['#ifdef __cplusplus\n}\n#endif', f"#endif /* {guard} */", ""]
    return "\n".join(lines)


def find_rustc(explicit: str | None = None) -> str:
    selected = explicit if explicit is not None else os.environ.get("RUSTC")
    if selected is not None:
        resolved = shutil.which(selected) if not Path(selected).is_file() else selected
        if not resolved or not Path(resolved).is_file() or not os.access(resolved, os.X_OK):
            raise HeptaError(Diagnostic("E_TOOLCHAIN", "The explicitly selected Rust compiler is unavailable: " + selected, phase="backend"))
        return str(Path(resolved).resolve())
    candidates = [shutil.which("rustc"),
                  str(Path(__file__).resolve().parents[2] / "toolchains" / ("rust-" + RUST_VERSION) / "bin/rustc")]
    for candidate in candidates:
        if candidate and Path(candidate).is_file() and os.access(candidate, os.X_OK):
            return str(Path(candidate).resolve())
    raise HeptaError(Diagnostic("E_TOOLCHAIN", "rustc is required for native and borrow validation; set RUSTC or --rustc", phase="backend"))


def toolchain_info(rustc: str) -> dict:
    p = subprocess.run([rustc, "-vV"], text=True, capture_output=True, timeout=30)
    if p.returncode:
        raise HeptaError(Diagnostic("E_TOOLCHAIN", "rustc version query failed", notes=[p.stderr], phase="backend"))
    fields = dict(line.split(": ", 1) for line in p.stdout.splitlines() if ": " in line)
    if (not p.stdout.startswith("rustc ") or fields.get("binary") != "rustc"
            or fields.get("release") != RUST_VERSION or not fields.get("host")
            or not fields.get("commit-hash")):
        raise HeptaError(Diagnostic("E_TOOLCHAIN_IDENTITY", "This prototype requires the pinned rustc " + RUST_VERSION + " with a complete -vV identity", notes=[p.stdout[:1000]], phase="backend"))
    prefix = Path(rustc).resolve().parent.parent
    sysroot = prefix if (prefix / "lib" / "rustlib").is_dir() else None
    return {"path": rustc, "version": p.stdout.strip(), "host": fields.get("host"),
            "executable_sha256": sha256(Path(rustc).read_bytes()),
            "sysroot": str(sysroot) if sysroot else None,
            "sysroot_discovery": "verified_compiler_prefix" if sysroot else "compiler_default"}


def compile_rust(source: str, *, rustc: str | None = None, target: str | None = None,
                 crate_type: str = "rlib", output: str | Path | None = None,
                 check_only: bool = False, optimize: bool = True, link_args: list[str] | None = None) -> dict:
    compiler = find_rustc(rustc)
    info = toolchain_info(compiler)
    # Rust normally discovers its sysroot through its executable location.
    # An isolated empty-/proc environment needs that location made explicit.
    # Keep the conventional-prefix check narrow; nonstandard host wrappers
    # retain their existing compiler-managed sysroot discovery.
    sysroot = info["sysroot"]
    linker = None
    if (target is None and not check_only and not link_args
            and crate_type in {"bin", "cdylib", "dylib", "proc-macro"}
            and not shutil.which("cc")):
        # On Debian-like hosts cc can be an /etc/alternatives symlink. Do not
        # mount host /etc into the sandbox to follow it; use visible GCC.
        visible_gcc = shutil.which("gcc")
        if visible_gcc:
            linker = str(Path(visible_gcc).resolve())
    artifact = Path(output).resolve() if output is not None else None
    if artifact:
        artifact.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".hepta-native-", dir=artifact.parent if artifact else None) as td:
        generated = Path(td) / "program.rs"
        generated.write_text(source)
        native_out = Path(td) / (artifact.name if artifact else "checked.rmeta")
        # rustc intentionally emits empty/no metadata for bins and staticlibs.
        # A library metadata pass checks the same lowered bodies and borrows;
        # the subsequent real build separately checks the requested link kind.
        native_type = "lib" if check_only or crate_type in {"obj", "rlib"} else crate_type
        cmd = [compiler, str(generated), "--edition=2021", "--crate-name=hepta_program",
               "--crate-type=" + native_type, "-C", "opt-level=" + ("3" if optimize else "0"),
               "-C", "overflow-checks=yes", "-C", "panic=abort", "-C", "codegen-units=1",
               "--error-format=json", "-o", str(native_out)]
        if sysroot:
            cmd += ["--sysroot", str(sysroot)]
        if linker:
            cmd += ["-C", "linker=" + linker]
        if target:
            cmd += ["--target", target]
        if check_only:
            cmd += ["--emit=metadata"]
        elif crate_type == "obj":
            cmd += ["--emit=obj"]
        for arg in link_args or []:
            cmd += ["-C", "link-arg=" + arg]
        flags = ["edition=2021", "opt-level=" + ("3" if optimize else "0"),
                 "overflow-checks=yes", "panic=abort", "codegen-units=1"]
        if sysroot:
            flags.append("sysroot=" + sysroot)
        if linker:
            flags.append("linker=" + linker)
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        except subprocess.TimeoutExpired:
            return {"ok": False, "status": "unknown", "diagnostics": [{"code": "E_BACKEND_TIMEOUT", "message": "rustc exceeded 120 seconds", "phase": "backend"}], "toolchain": info}
        diagnostics = []
        for line in p.stderr.splitlines():
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                if p.returncode:
                    diagnostics.append({"code": "E_BACKEND", "message": line, "phase": "backend"})
                continue
            if d.get("level") == "error":
                diagnostics.append({"code": (d.get("code") or {}).get("code", "E_RUSTC"),
                                    "message": d.get("message", "backend error"), "phase": "backend",
                                    "rendered": d.get("rendered"), "generated_spans": d.get("spans", [])})
        from .source_map import map_diagnostics
        diagnostics = map_diagnostics(source, diagnostics, generated_path=str(generated))
        result = {"ok": p.returncode == 0, "status": "rustc_checked" if p.returncode == 0 else "rejected",
                  "diagnostics": diagnostics, "toolchain": info, "target": target or info["host"],
                  "flags": flags,
                  "crate_type": crate_type, "rust_sha256": sha256(source.encode()), "check_only": check_only,
                  "rustc_crate_type": native_type,
                  "sysroot": str(sysroot) if sysroot else None, "linker": linker,
                  "link_args": link_args or []}
        if p.returncode == 0 and (not native_out.is_file() or native_out.stat().st_size == 0):
            result["ok"] = False
            result["status"] = "rejected"
            result["diagnostics"].append({"code": "E_BACKEND_ARTIFACT", "message": "Backend exited successfully without the expected nonempty artifact", "phase": "backend"})
            return result
        if p.returncode == 0:
            result["validation_artifact_sha256"] = sha256(native_out.read_bytes())
        if p.returncode == 0 and artifact and native_out.is_file():
            os.replace(native_out, artifact)
            result["artifact"] = str(artifact)
            result["artifact_sha256"] = sha256(artifact.read_bytes())
            result["artifact_bytes"] = artifact.stat().st_size
        return result
