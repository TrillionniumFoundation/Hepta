"""Conservative bootstrap type, effect and linear-resource checks.

This pass does not prove Rust lifetimes or borrow soundness.  The native backend
must still run rustc; foreign contracts and raw memory obligations remain trust
boundaries.  Unsupported constructs fail closed rather than losing metadata.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Any

from .ast import Diagnostic, Enum, EnumVariant, Expr, Function, Param, Program, Span, Stmt, Struct, Type
from .runtime_concurrency import GROUP, GROUP_BUILTINS, GROUP_TYPE_NAMES, REPORT, SENDER, report_struct


INTS = {"i8", "i16", "i32", "i64", "i128", "isize", "u8", "u16", "u32", "u64", "u128", "usize"}
FLOATS = {"f32", "f64"}
PRIMITIVES = INTS | FLOATS | {"bool", "Unit"}
EFFECTS = {"alloc", "panic", "io", "block", "spawn", "ffi", "unsafe", "write"}
C_KEYWORDS = {"auto", "break", "case", "char", "const", "continue", "default", "do", "double", "else", "enum", "extern", "float", "for", "goto", "if", "inline", "int", "long", "register", "restrict", "return", "short", "signed", "sizeof", "static", "struct", "switch", "typedef", "union", "unsigned", "void", "volatile", "while", "_Alignas", "_Alignof", "_Atomic", "_Bool", "_Complex", "_Generic", "_Imaginary", "_Noreturn", "_Static_assert", "_Thread_local"}
CPP_KEYWORDS = {"alignas", "alignof", "and", "and_eq", "asm", "atomic_cancel", "atomic_commit", "atomic_noexcept", "bitand", "bitor", "bool", "catch", "char8_t", "char16_t", "char32_t", "class", "compl", "concept", "consteval", "constexpr", "constinit", "const_cast", "co_await", "co_return", "co_yield", "decltype", "delete", "dynamic_cast", "explicit", "export", "false", "friend", "mutable", "namespace", "new", "noexcept", "not", "not_eq", "nullptr", "operator", "or", "or_eq", "private", "protected", "public", "reflexpr", "reinterpret_cast", "requires", "static_assert", "static_cast", "synchronized", "template", "this", "thread_local", "throw", "true", "try", "typeid", "typename", "using", "virtual", "wchar_t", "xor", "xor_eq"}
C_TYPEDEF_NAMES = {"size_t", "ptrdiff_t", "wchar_t", "max_align_t", "intptr_t", "uintptr_t", "intmax_t", "uintmax_t"} | {f"{prefix}{middle}{bits}_t" for prefix in ("int", "uint") for middle in ("", "_least", "_fast") for bits in (8, 16, 32, 64)}
C_HEADER_MACRO = re.compile(r"(?:U?INT[A-Z0-9_]*_(?:MAX|MIN|C)|SIZE_MAX|PTRDIFF_.*|SIG_ATOMIC_.*|WCHAR_.*|WINT_.*)\Z")
BUILTINS = {"len", "wrapping_add", "wrapping_sub", "wrapping_mul", "buffer", "try_buffer", "release", "drop", "assert", "print_i64", "load", "store", "ptr_read", "ptr_mut", "min", "max", "spawn", "join", "cancel_and_join", "cancelled"} | GROUP_BUILTINS
LINEAR = {"Buffer", "Task", "TaskGroup"}
ERROR = Type("<error>")
UNIT = Type("Unit")
BOOL = Type("bool")
USIZE = Type("usize")
I64 = Type("i64")
F64 = Type("f64")
BUFFER_U8 = Type("Buffer", (Type("u8"),))
BUFFER_RESULT = Type("Result", (BUFFER_U8, Type("u8")))
TASK_U64 = Type("Task", (Type("u64"),))
CANCELLATION = Type("Cancellation")
RESERVED_TYPES = PRIMITIVES | BUILTINS | GROUP_TYPE_NAMES | {"Buffer", "Task", "Cancellation", "Result", "array", "slice", "raw_const", "raw_mut"}


def substitute_type(typ: Type, mapping: dict[str, Type]) -> Type:
    """Capture-free substitution: type parameter names cannot shadow types."""
    if typ.name in mapping and not typ.args and typ.length is None:
        return mapping[typ.name]
    return Type(typ.name, tuple(substitute_type(arg, mapping) for arg in typ.args), typ.length)


def _contains_capability(typ: Type, names: set[str], structs: dict[str, Struct],
                         enums: dict[str, Enum], seen: frozenset[str] = frozenset()) -> bool:
    """Conservatively inspect concrete arguments and nominal payloads iteratively.

    Nominal names stop recursive declarations from exhausting Python's stack.
    Arguments are inspected even in pointer/phantom positions: those positions
    cannot be used to hide resource or scoped runtime capabilities in this
    bounded language profile.
    """
    pending = [typ]
    visited = set(seen)
    while pending:
        current = pending.pop()
        if current.name in names:
            return True
        pending.extend(current.args)
        if current.name in visited:
            continue
        visited.add(current.name)
        decl = structs.get(current.name) or enums.get(current.name)
        if decl is not None:
            mapping = dict(zip(decl.type_params, current.args))
            payloads = [f.type for f in decl.fields] if isinstance(decl, Struct) else [t for v in decl.variants for t in v.fields]
            pending.extend(substitute_type(t, mapping) for t in payloads)
    return False


def is_owned_type(program: Program, typ: Type) -> bool:
    """Public resource classification for checked AST consumers and verifiers.

    Classification is not validation: arrays/pointers containing resources and
    nested task handles are still rejected separately by the checker.
    """
    return _contains_capability(typ, LINEAR, {s.name: s for s in program.structs},
                                {e.name: e for e in program.enums})


def place_path(expr: Expr) -> tuple[str, tuple[str, ...]] | None:
    """Named place identity; '*' represents an index with unproved overlap."""
    path = []
    while expr.kind in {"field", "index"} and expr.children:
        path.append(str(expr.value) if expr.kind == "field" else "*")
        expr = expr.children[0]
    return (expr.value, tuple(reversed(path))) if expr.kind == "name" else None


def places_overlap(left: tuple[str, tuple[str, ...]], right: tuple[str, tuple[str, ...]]) -> bool:
    if left[0] != right[0]:
        return False
    for a, b in zip(left[1], right[1]):
        if "*" in {a, b}:
            return True
        if a != b:
            return False
    # Equal paths, or one path naming an ancestor of the other, overlap.
    return True


@dataclass
class CheckResult:
    diagnostics: list[Diagnostic] = field(default_factory=list)
    effects: dict[str, set[str]] = field(default_factory=dict)
    expr_types: dict[int, Type] = field(default_factory=dict)
    assumptions: list[dict] = field(default_factory=list)
    resource_contracts: list[dict] = field(default_factory=list)
    owned_types: set[Type] = field(default_factory=set)

    @property
    def ok(self) -> bool:
        return not self.diagnostics


@dataclass(frozen=True)
class _Binding:
    ident: int
    name: str
    type: Type
    mutable: bool
    mode: str
    span: Span


@dataclass
class _Flow:
    live: set[int]
    normal: bool = True


class _Checker:
    def __init__(self, program: Program):
        self.program = program
        self.result = CheckResult()
        self.structs: dict[str, Struct] = {"GroupReport": report_struct()}
        self.enums: dict[str, Enum] = {"Result": Enum("Result", [EnumVariant("Ok", [Type("$ResultOk")]), EnumVariant("Err", [Type("$ResultErr")])], ("$ResultOk", "$ResultErr"), True)}
        self.type_params: set[str] = set()
        self.owned_type_params: set[str] = set()
        self.functions: dict[str, Function] = {}
        self.local_effects: dict[str, set[str]] = {}
        self.calls: dict[str, set[str]] = {}
        self.current: Function | None = None
        self.next_binding = 0
        self.bindings: dict[int, _Binding] = {}
        self._assumption_keys: set[tuple] = set()
        self.worker_sites: list[tuple[str, Span]] = []

    def error(self, code: str, message: str, span: Span, *notes: str) -> None:
        self.result.diagnostics.append(Diagnostic(code, message, span, list(notes)))

    def remember(self, expr: Expr, typ: Type) -> Type:
        self.result.expr_types[id(expr)] = typ
        if self.contains_linear(typ):
            self.result.owned_types.add(typ)
        return typ

    def effect(self, *effects: str) -> None:
        if self.current is not None:
            self.local_effects[self.current.name].update(effects)

    def compatible(self, actual: Type, expected: Type, span: Span) -> bool:
        if ERROR in (actual, expected):
            return False
        if actual != expected:
            self.error("E_TYPE", f"expected {expected}, found {actual}", span)
            return False
        return True

    def contains_linear(self, typ: Type, seen: frozenset[str] = frozenset()) -> bool:
        return self.contains_capability(typ, LINEAR | self.owned_type_params, seen)

    def contains_cancellation(self, typ: Type, seen: frozenset[str] = frozenset()) -> bool:
        return self.contains_capability(typ, {"Cancellation"}, seen)

    def contains_capability(self, typ: Type, names: set[str], seen: frozenset[str] = frozenset()) -> bool:
        return _contains_capability(typ, names, self.structs, self.enums, seen)

    def contains_sender(self, typ: Type, seen: frozenset[str] = frozenset()) -> bool:
        return self.contains_capability(typ, {"Sender"}, seen)

    def generic_arguments(self, params: tuple[str, ...], args: tuple[Type, ...], span: Span, *, allow_owned: bool = False,
                          bounds: dict[str, str] | None = None) -> dict[str, Type]:
        if len(params) != len(args):
            self.error("E_GENERIC_ARITY", f"expected {len(params)} explicit type argument(s), found {len(args)}", span)
        for index, arg in enumerate(args):
            self.valid_type(arg, span)
            scoped = self.contains_capability(arg, {"Task", "TaskGroup"})
            bound = (bounds or {}).get(params[index], "Copy") if index < len(params) else "Copy"
            if (self.contains_linear(arg) and not allow_owned and bound != "Owned") or scoped or self.contains_cancellation(arg) or self.contains_sender(arg) or arg.name == "slice":
                detail = ("sized values without scoped runtime capabilities" if allow_owned else
                          "sized Owned values without scoped runtime capabilities" if bound == "Owned" else "sized Copy values")
                self.error("E_GENERIC_COPY", f"generic arguments must be {detail}; {arg} is not supported", span)
            elif not allow_owned and bound == "Owned" and not self.contains_linear(arg):
                self.error("E_GENERIC_OWNED", f"Owned parameter requires a sized owned resource value; {arg} is not owned", span)
        return {name: args[index] if index < len(args) else ERROR for index, name in enumerate(params)}

    def declaration_parameters(self, params: tuple[str, ...], span: Span, fields: list[Type] | None = None,
                               bounds: dict[str, str] | None = None) -> None:
        seen: set[str] = set()
        for name in params:
            if name in seen or name in RESERVED_TYPES or name in self.structs or name in self.enums:
                self.error("E_GENERIC_PARAMETER", f"duplicate or shadowing generic parameter {name}", span)
            seen.add(name)
        self.type_params = set(params)
        self.owned_type_params = {name for name in params if (bounds or {}).get(name) == "Owned"}
        for name, bound in (bounds or {}).items():
            if name not in self.type_params or bound not in {"Copy", "Owned"}:
                self.error("E_GENERIC_BOUND", f"unsupported constraint {name}: {bound}; expected Copy or Owned", span)
        if fields is not None:
            used: set[str] = set()
            def collect(typ: Type) -> None:
                used.add(typ.name)
                for arg in typ.args:
                    collect(arg)
            for typ in fields:
                collect(typ)
            for name in set(params) - used:
                self.error("E_GENERIC_UNUSED", f"generic parameter {name} must occur in a payload or field", span)

    def nominal_type(self, name: str, args: tuple[Type, ...], expected: Type | None, span: Span) -> Type:
        decl = self.structs.get(name) or self.enums.get(name)
        if decl is None:
            return ERROR
        if not args and expected is not None and expected.name == name:
            args = expected.args
        typ = Type(name, args)
        self.valid_type(typ, span)
        return typ

    def valid_owned_payload_shapes(self, typ: Type, span: Span) -> bool:
        """Instantiation must not hide resources in unsupported containers.

        Declarations such as Box<T> { values: [T; 2] } are valid for Copy T,
        but substituting Buffer must still trigger the array restriction.
        The finite (nominal, owned-argument mask) worklist also handles recursive
        declarations without recursive Python traversal or expanding forever.
        """
        pending = [typ]
        visited: set[tuple[str, tuple[bool, ...]]] = set()
        good = True
        while pending:
            current = pending.pop()
            if current.name in {"array", "slice", "Buffer", "raw_const", "raw_mut"}:
                if any(self.contains_linear(arg) for arg in current.args):
                    self.error("E_NESTED_LINEAR", f"instantiated payload {current} hides resources in an unsupported container", span)
                    good = False
                continue
            decl = self.structs.get(current.name) or self.enums.get(current.name)
            if decl is None:
                continue
            key = (current.name, tuple(self.contains_linear(arg) for arg in current.args))
            if key in visited:
                continue
            visited.add(key)
            mapping = dict(zip(decl.type_params, current.args))
            payloads = [f.type for f in decl.fields] if isinstance(decl, Struct) else [t for v in decl.variants for t in v.fields]
            pending.extend(substitute_type(t, mapping) for t in payloads)
        return good

    def valid_type(self, typ: Type, span: Span, *, allow_slice: bool = False, allow_cancellation: bool = False, allow_sender: bool = False) -> bool:
        name = typ.name
        if name in self.type_params:
            if typ.args or typ.length is not None:
                self.error("E_TYPE_FORM", f"generic parameter {name} cannot take type arguments", span)
                return False
            return True
        if name == "TaskGroup":
            if typ.args or typ.length is not None:
                self.error("E_GROUP_TYPE", "TaskGroup does not take type parameters", span)
                return False
            return True
        if name == "Sender":
            if not allow_sender or typ != SENDER:
                self.error("E_SENDER_TYPE", "Sender<u64> is an unconstructible capability supported only as a read parameter", span)
                return False
            return True
        if name == "Cancellation":
            if not allow_cancellation or typ.args or typ.length is not None:
                self.error("E_CANCELLATION_TYPE", "Cancellation is an unconstructible control capability supported only as a read parameter", span)
                return False
            return True
        if name in PRIMITIVES:
            if typ.args or typ.length is not None:
                self.error("E_TYPE_FORM", f"{name} does not take type arguments or a length", span)
                return False
            return True
        if name in ("array", "slice", "Buffer", "Task", "raw_const", "raw_mut"):
            if len(typ.args) != 1:
                self.error("E_TYPE_FORM", f"{name} requires exactly one element type", span)
                return False
            if name == "array":
                if type(typ.length) is not int or typ.length < 0:
                    self.error("E_ARRAY_LENGTH", "array length must be a nonnegative integer", span)
                    return False
            elif typ.length is not None:
                self.error("E_TYPE_FORM", f"{name} does not take an array length", span)
                return False
            if name == "slice" and not allow_slice:
                self.error("E_UNSIZED", "slice types are supported only as read/mut parameters", span)
                return False
            good = self.valid_type(typ.args[0], span)
            if name == "Task" and typ != TASK_U64:
                self.error("E_TASK_TYPE", "the bootstrap supports Task<u64> only", span)
                good = False
            if self.contains_linear(typ.args[0]):
                self.error("E_NESTED_LINEAR", "nested linear values are unsupported; keep Buffer and Task as top-level owners", span)
                good = False
            return good
        if name in self.structs or name in self.enums:
            decl = self.structs.get(name) or self.enums[name]
            previous_errors = len(self.result.diagnostics)
            self.generic_arguments(decl.type_params, typ.args, span, allow_owned=True)
            if typ.length is not None:
                self.error("E_TYPE_FORM", f"{name} cannot take an array length", span)
            if self.contains_capability(typ, {"Task", "TaskGroup"}):
                self.error("E_NESTED_LINEAR", f"type {name} contains a scoped task resource", span)
                return False
            if self.contains_cancellation(typ):
                self.error("E_CANCELLATION_TYPE", f"type {name} contains a Cancellation capability", span)
                return False
            if self.contains_sender(typ):
                self.error("E_SENDER_TYPE", f"type {name} contains a Sender capability", span)
                return False
            self.valid_owned_payload_shapes(typ, span)
            return len(self.result.diagnostics) == previous_errors
        self.error("E_UNKNOWN_TYPE", f"unknown type {typ}", span)
        return False

    def c_type(self, typ: Type, *, position: str, seen: frozenset[str] = frozenset()) -> bool:
        if typ.name == "Unit":
            return position in ("return", "pointee")
        if typ.name in (INTS - {"i128", "u128"}) | FLOATS:
            return not typ.args
        if typ.name in ("raw_const", "raw_mut") and len(typ.args) == 1:
            return self.c_type(typ.args[0], position="pointee", seen=seen)
        if typ.name == "array" and len(typ.args) == 1:
            return position in ("field", "pointee") and type(typ.length) is int and typ.length > 0 and self.c_type(typ.args[0], position="field", seen=seen)
        if typ.name in self.structs:
            struct = self.structs[typ.name]
            if not struct.repr_c or not struct.fields or struct.type_params or typ.args:
                return False
            if typ.name in seen:
                return position == "pointee"
            return all(self.c_type(f.type, position="field", seen=seen | {typ.name}) for f in struct.fields)
        return False

    def check_struct_cycles(self) -> None:
        declarations = {**self.structs, **self.enums}
        fields = {name: [f.type for f in decl.fields] if isinstance(decl, Struct) else [t for variant in decl.variants for t in variant.fields] for name, decl in declarations.items()}
        # Track which generic arguments participate in value layout. Merely
        # occurring behind a raw pointer does not make an argument recursive.
        by_value_params: dict[str, set[str]] = {name: set() for name in declarations}
        def walk(typ: Type, params: set[str], want_params: bool) -> set[str]:
            if typ.name in ("raw_const", "raw_mut"):
                return set()
            if typ.name in params:
                return {typ.name} if want_params else set()
            decl = declarations.get(typ.name)
            result = {typ.name} if decl is not None and not want_params else set()
            arguments = typ.args
            if decl is not None:
                arguments = tuple(arg for name, arg in zip(decl.type_params, typ.args) if name in by_value_params[typ.name])
            for arg in arguments:
                result.update(walk(arg, params, want_params))
            return result
        changed = True
        while changed:
            changed = False
            for name, decl in declarations.items():
                before = len(by_value_params[name])
                for typ in fields[name]:
                    by_value_params[name].update(walk(typ, set(decl.type_params), True))
                changed = changed or len(by_value_params[name]) != before
        adjacency = {name: set().union(*(walk(typ, set(decl.type_params), False) for typ in fields[name])) for name, decl in declarations.items()}
        done: set[str] = set()
        visiting: set[str] = set()
        for root in declarations:
            if root in done:
                continue
            stack = [(root, False)]
            while stack:
                name, leaving = stack.pop()
                if leaving:
                    visiting.discard(name)
                    done.add(name)
                    continue
                if name in visiting:
                    self.error("E_RECURSIVE_LAYOUT", f"type {name} has a recursive by-value layout", declarations[name].span)
                    continue
                if name in done:
                    continue
                visiting.add(name)
                stack.append((name, True))
                stack.extend((dep, False) for dep in sorted(adjacency[name], reverse=True))

    def c_identifier(self, name: str, span: Span, position: str) -> None:
        typedefs = C_TYPEDEF_NAMES | {"hepta_" + n for n, st in self.structs.items() if st.repr_c}
        if name in C_KEYWORDS | CPP_KEYWORDS:
            reason = "a reserved C/C++ keyword"
        elif name in typedefs:
            reason = "a standard or generated header typedef"
        elif name in {"NULL", "offsetof"} or C_HEADER_MACRO.fullmatch(name) or name.startswith("HEPTA_"):
            reason = "a name reserved for generated-header macros"
        elif name.startswith("__") or (len(name) > 1 and name[0] == "_" and name[1].isupper()) or (position == "symbol" and name.startswith("_")):
            reason = "an implementation-reserved C/C++ identifier"
        else:
            return
        self.error("E_C_IDENTIFIER", f"C boundary {position} {name} conflicts with {reason}", span, "boundary identifiers are not silently renamed; use a nonreserved source name")

    def declarations(self) -> None:
        for imported in self.program.imports:
            self.error("E_IMPORT_UNRESOLVED", f"import {imported.name} requires module loading before checking", imported.span)
        for struct in self.program.structs:
            if struct.name in self.structs or struct.name in RESERVED_TYPES:
                self.error("E_DUPLICATE", f"duplicate or reserved type name {struct.name}", struct.span)
            else:
                self.structs[struct.name] = struct
        for enum in self.program.enums:
            if enum.name in self.enums or enum.name in self.structs or enum.name in RESERVED_TYPES:
                self.error("E_DUPLICATE", f"duplicate or reserved type name {enum.name}", enum.span)
            else:
                self.enums[enum.name] = enum
        for fn in self.program.functions:
            if fn.name in self.functions or fn.name in self.structs or fn.name in self.enums or fn.name in RESERVED_TYPES:
                self.error("E_DUPLICATE", f"duplicate or reserved function name {fn.name}", fn.span)
            else:
                self.functions[fn.name] = fn
                self.local_effects[fn.name] = set()
                self.calls[fn.name] = set()
        for struct in self.structs.values():
            self.declaration_parameters(struct.type_params, struct.span, [f.type for f in struct.fields])
            seen: set[str] = set()
            for member in struct.fields:
                if member.name in seen:
                    self.error("E_DUPLICATE", f"duplicate field {member.name} in {struct.name}", member.span)
                seen.add(member.name)
                self.valid_type(member.type, member.span)
                if self.contains_capability(member.type, {"Task", "TaskGroup"}):
                    self.error("E_NESTED_LINEAR", f"field {struct.name}.{member.name} contains a scoped task resource", member.span)
                if member.mode != "value":
                    self.error("E_FIELD_MODE", "struct fields cannot carry parameter ownership modes", member.span)
                if struct.repr_c:
                    self.c_identifier(member.name, member.span, "field")
            if struct.repr_c and not self.c_type(Type(struct.name), position="field"):
                self.error("E_C_ABI", f"repr(C) struct {struct.name} is not in the supported C ABI subset", struct.span)
        for enum in self.program.enums:
            self.declaration_parameters(enum.type_params, enum.span, [t for variant in enum.variants for t in variant.fields])
            if not enum.variants:
                self.error("E_ENUM_EMPTY", "empty enums are not supported", enum.span)
            seen_variants: set[str] = set()
            for variant in enum.variants:
                if variant.name in seen_variants:
                    self.error("E_DUPLICATE", f"duplicate variant {enum.name}::{variant.name}", variant.span)
                seen_variants.add(variant.name)
                for typ in variant.fields:
                    self.valid_type(typ, variant.span)
                    if self.contains_capability(typ, {"Task", "TaskGroup"}):
                        self.error("E_NESTED_LINEAR", f"variant {enum.name}::{variant.name} contains a scoped task resource", variant.span)
                    if self.contains_cancellation(typ):
                        self.error("E_CANCELLATION_TYPE", f"variant {enum.name}::{variant.name} contains a Cancellation capability", variant.span)
                    if self.contains_sender(typ):
                        self.error("E_SENDER_TYPE", f"variant {enum.name}::{variant.name} contains a Sender capability", variant.span)
        self.type_params = set()
        self.owned_type_params = set()
        self.check_struct_cycles()
        for fn in self.functions.values():
            self.declaration_parameters(fn.type_params, fn.span, bounds=fn.type_bounds)
            if fn.type_params and (fn.extern_c or fn.export_c or fn.name == "main"):
                self.error("E_GENERIC_BOUNDARY", "generic functions cannot be C boundary symbols or main entrypoints", fn.span)
            for effect in fn.effects - EFFECTS:
                self.error("E_UNKNOWN_EFFECT", f"unknown effect {effect}", fn.span)
            if fn.return_mode not in {"value", "read", "mut"}:
                self.error("E_RETURN_MODE", f"unsupported return mode {fn.return_mode}", fn.span)
            self.valid_type(fn.return_type, fn.span, allow_slice=fn.return_mode in {"read", "mut"})
            if fn.return_mode in {"read", "mut"}:
                origins = [p for p in fn.params if p.mode in {"read", "mut"}]
                if len(origins) != 1:
                    self.error("E_BORROW_RETURN_SOURCE", "a borrowed return requires exactly one read/mut source parameter", fn.span)
                elif fn.return_mode == "mut" and origins[0].mode != "mut":
                    self.error("E_READ_ONLY", "a mutable borrowed return requires a mutable source parameter", fn.span)
            if self.contains_capability(fn.return_type, {"Task", "TaskGroup"}):
                self.error("E_TASK_SCOPE", "Task/TaskGroup handles cannot escape through a function return; join them in their creating scope", fn.span)
            seen: set[str] = set()
            for param in fn.params:
                if param.name in seen:
                    self.error("E_DUPLICATE", f"duplicate parameter {param.name}", param.span)
                seen.add(param.name)
                if param.mode not in {"value", "read", "mut", "take"}:
                    self.error("E_PARAMETER_MODE", f"unknown parameter mode {param.mode}", param.span)
                self.valid_type(param.type, param.span, allow_slice=param.mode in {"read", "mut"}, allow_cancellation=param.mode == "read", allow_sender=param.mode == "read")
                if self.contains_linear(param.type) and param.mode == "value":
                    self.error("E_LINEAR_MODE", f"owning resource parameter {param.name} must use take", param.span)
                if param.type == UNIT:
                    self.error("E_UNIT_PARAMETER", "Unit parameters are not supported", param.span)
                if self.contains_capability(param.type, {"Task", "TaskGroup"}):
                    self.error("E_TASK_SCOPE", "Task/TaskGroup parameters are unsupported; handles remain local until joined", param.span)
            if fn.extern_c or fn.export_c:
                self.c_identifier(fn.name, fn.span, "symbol")
                if fn.return_mode != "value":
                    self.error("E_C_ABI", "borrowed returns do not have a C ABI in this profile", fn.span)
                if not self.c_type(fn.return_type, position="return"):
                    self.error("E_C_ABI", f"return type {fn.return_type} is not supported at a C boundary", fn.span)
                for param in fn.params:
                    self.c_identifier(param.name, param.span, "parameter")
                    if param.mode != "value" or not self.c_type(param.type, position="parameter"):
                        self.error("E_C_ABI", f"parameter {param.name}: {param.mode} {param.type} is not supported at a C boundary", param.span)
            if fn.extern_c:
                if fn.body is not None:
                    self.error("E_EXTERN_BODY", "extern C declarations cannot have a body", fn.span)
                if "ffi" not in fn.effects:
                    self.error("E_EFFECT", f"extern function {fn.name} must declare ffi", fn.span)
                self.local_effects[fn.name] = (fn.effects & EFFECTS) | {"ffi"}
                self.result.assumptions.append({"kind": "extern_contract", "function": fn.name, "abi": "C", "declared_effects": sorted(fn.effects), "parameters": [{"name": p.name, "type": str(p.type)} for p in fn.params], "return_type": str(fn.return_type), "status": "assumed_not_verified", "obligations": ["foreign implementation obeys the declared ABI and effect upper bound", "caller establishes pointer validity, lifetime, alignment, initialization and aliasing obligations"]})
            elif fn.body is None:
                self.error("E_MISSING_BODY", f"function {fn.name} requires a body", fn.span)
            self.check_resource_syntax(fn)
        self.type_params = set()
        self.owned_type_params = set()

    def check_resource_syntax(self, fn: Function) -> None:
        for key, value in fn.resources.items():
            if key == "heap_allocations":
                valid = type(value) is int and value == 0
            elif key in {"may_block", "may_suspend", "may_spawn"}:
                valid = type(value) is bool and value is False
            else:
                self.error("E_RESOURCE_UNSUPPORTED", f"unsupported resource clause {key}", fn.span)
                continue
            if not valid:
                self.error("E_RESOURCE_UNSUPPORTED", f"unsupported value for resource clause {key}: {value!r}", fn.span, "bootstrap supports heap_allocations=0 and may_block/may_suspend/may_spawn=false only")

    def bind(self, name: str, typ: Type, mutable: bool, mode: str, span: Span, env: dict[str, _Binding], live: set[int]) -> _Binding:
        if name in env:
            self.error("E_DUPLICATE_LOCAL", f"binding {name} is already in scope; shadowing is unsupported", span)
        if name in self.functions:
            self.error("E_NAME_COLLISION", f"binding {name} would shadow a function name", span, "the bootstrap reserves function names in local scopes")
        self.next_binding += 1
        binding = _Binding(self.next_binding, name, typ, mutable, mode, span)
        env[name] = binding
        self.bindings[binding.ident] = binding
        if self.contains_linear(typ) and mode not in {"read", "mut"}:
            live.add(binding.ident)
        return binding

    def live_error(self, live: set[int], span: Span, context: str) -> None:
        if live:
            names = ", ".join(self.bindings[i].name for i in sorted(live))
            self.error("E_LINEAR_UNCONSUMED", f"unconsumed linear owner(s) on {context}: {names}", span, "consume resource values with release/drop/take/return or consuming match, and task handles with join/cancel_and_join, on every normal exit")

    def require_transfer(self, expr: Expr, typ: Type, *, context: str, fresh: bool = True) -> None:
        """A resource place never becomes an implicit copy or implicit move."""
        if not self.contains_linear(typ):
            return
        if self.returned_borrow_mode(expr) is not None:
            self.error("E_MOVE_BORROW", f"{context} cannot take ownership of a borrowed function result", expr.span)
            return
        explicit = expr.kind == "unary" and expr.value == "move"
        created = expr.kind in {"call", "struct", "variant"}
        if not explicit and not (fresh and created):
            self.error("E_MOVE_REQUIRED", f"{context} of an owned value requires an explicit move or fresh result", expr.span)

    def hint(self, expr: Expr, env: dict[str, _Binding]) -> Type | None:
        if expr.kind == "name" and expr.value in env:
            return env[expr.value].type
        if expr.kind == "cast" and isinstance(expr.value, Type):
            return expr.value
        if expr.kind == "binary":
            if expr.value in {"==", "!=", "<", "<=", ">", ">=", "&&", "||"}:
                return BOOL
            for child in expr.children:
                found = self.hint(child, env)
                if found is not None:
                    return found
        if expr.kind == "call":
            if expr.value in self.functions:
                fn = self.functions[expr.value]
                return substitute_type(fn.return_type, dict(zip(fn.type_params, expr.type_args)))
            if expr.value in {"len"}:
                return USIZE
            if expr.value == "buffer":
                return BUFFER_U8
            if expr.value == "try_buffer":
                return BUFFER_RESULT
            if expr.value == "spawn":
                return TASK_U64
            if expr.value in {"join", "cancel_and_join"}:
                return Type("u64")
            if expr.value == "cancelled":
                return BOOL
            if expr.value == "task_group":
                return GROUP
            if expr.value in {"group_join", "group_drain_and_join", "group_cancel_and_join", "group_snapshot"}:
                return REPORT
            if expr.value in {"group_spawn", "group_send", "group_receive"}:
                return BOOL
            if expr.value in {"group_send_timeout", "group_receive_timeout"}:
                return Type("Result", (BOOL, Type("u8")))
        if expr.kind == "unary" and expr.children:
            return self.hint(expr.children[0], env)
        if expr.kind == "field" and expr.children:
            base = self.hint(expr.children[0], env)
            if base is not None and base.name in self.structs:
                for f in self.structs[base.name].fields:
                    if f.name == expr.value:
                        return substitute_type(f.type, dict(zip(self.structs[base.name].type_params, base.args)))
        if expr.kind == "index" and expr.children:
            base = self.hint(expr.children[0], env)
            if base is not None and base.name in {"array", "slice", "Buffer"} and base.args:
                return base.args[0]
        return None

    def variant_expr(self, expr: Expr, env: dict[str, _Binding], live: set[int], unsafe_depth: int, expected: Type | None) -> Type:
        value = expr.value
        enum = self.enums[value["enum"]]
        typ = self.nominal_type(enum.name, expr.type_args, expected, expr.span)
        mapping = dict(zip(enum.type_params, typ.args))
        variant = next((v for v in enum.variants if v.name == value["variant"]), None)
        if variant is None:
            self.error("E_UNKNOWN_VARIANT", f"enum {enum.name} has no variant {value['variant']}", expr.span)
            for child in expr.children:
                self.expr(child, env, live, unsafe_depth)
            return typ
        if not variant.fields and value.get("tuple"):
            self.error("E_VARIANT_FORM", "unit variants do not take parentheses", expr.span)
        if len(expr.children) != len(variant.fields):
            self.error("E_VARIANT_ARITY", f"{enum.name}::{variant.name} expects {len(variant.fields)} payload value(s)", expr.span)
        for index, child in enumerate(expr.children):
            field_type = substitute_type(variant.fields[index], mapping) if index < len(variant.fields) else None
            actual = self.expr(child, env, live, unsafe_depth, field_type)
            if field_type is not None:
                self.compatible(actual, field_type, child.span)
            self.require_transfer(child, actual, context="enum payload initialization")
            if self.contains_cancellation(actual):
                self.error("E_CANCELLATION_TYPE", "Cancellation capabilities cannot be enum payloads", child.span)
            if self.contains_sender(actual):
                self.error("E_SENDER_TYPE", "Sender capabilities cannot be enum payloads", child.span)
        return typ

    def numeric_hint(self, expressions: list[Expr], env: dict[str, _Binding], expected: Type | None = None) -> Type:
        if expected is not None and expected.name in INTS | FLOATS | {"bool"}:
            return expected
        for expr in expressions:
            hint = self.hint(expr, env)
            if hint is not None:
                return hint
        return F64 if any(e.kind == "float" for e in expressions) else I64

    def root_binding(self, expr: Expr, env: dict[str, _Binding]) -> _Binding | None:
        while True:
            if expr.kind in {"field", "index"} and expr.children:
                expr = expr.children[0]
                continue
            fn = self.functions.get(expr.value) if expr.kind == "call" else None
            if fn is not None and fn.return_mode in {"read", "mut"}:
                origins = [i for i, p in enumerate(fn.params) if p.mode in {"read", "mut"}]
                if len(origins) == 1 and origins[0] < len(expr.children):
                    arg = expr.children[origins[0]]
                    if arg.kind == "unary" and arg.value in {"read", "mut"} and arg.children:
                        expr = arg.children[0]
                        continue
            break
        return env.get(expr.value) if expr.kind == "name" else None

    def returned_borrow_mode(self, expr: Expr) -> str | None:
        while expr.kind in {"field", "index"} and expr.children:
            expr = expr.children[0]
        fn = self.functions.get(expr.value) if expr.kind == "call" else None
        return fn.return_mode if fn is not None and fn.return_mode in {"read", "mut"} else None

    def lvalue(self, expr: Expr, env: dict[str, _Binding], live: set[int], unsafe_depth: int, *, mutable: bool) -> Type:
        typ = self.expr(expr, env, live, unsafe_depth)
        binding = self.root_binding(expr, env)
        returned = self.returned_borrow_mode(expr)
        if binding is None or (expr.kind not in {"name", "field", "index"} and returned is None):
            self.error("E_LVALUE", "a named place is required here", expr.span)
        elif mutable and not (binding.mutable or binding.mode == "mut"):
            self.error("E_IMMUTABLE", f"{binding.name} is not mutable", expr.span)
        if mutable and binding is not None and binding.mode == "read":
            self.error("E_READ_ONLY", f"cannot mutate read parameter {binding.name}", expr.span)
        if mutable and returned == "read":
            self.error("E_READ_ONLY", "cannot mutate through a read function result", expr.span)
        return typ

    def borrow(self, expr: Expr, mode: str, expected: Type | None, env: dict[str, _Binding], live: set[int], unsafe_depth: int) -> Type:
        if expr.kind != "unary" or expr.value != mode or len(expr.children) != 1:
            self.error("E_BORROW_MODE", f"argument requires explicit {mode} borrowing", expr.span)
            typ = self.expr(expr, env, live, unsafe_depth, expected)
        else:
            typ = self.lvalue(expr.children[0], env, live, unsafe_depth, mutable=mode == "mut")
            self.remember(expr, typ)
        if expected is not None:
            if expected.name == "slice" and typ.name in {"array", "Buffer"} and typ.args == expected.args:
                pass
            else:
                self.compatible(typ, expected, expr.span)
        return typ

    def argument(self, expr: Expr, param: Param, env: dict[str, _Binding], live: set[int], unsafe_depth: int) -> Type:
        if param.mode in {"read", "mut"}:
            return self.borrow(expr, param.mode, param.type, env, live, unsafe_depth)
        if param.mode == "take" and (expr.kind != "unary" or expr.value != "move"):
            self.error("E_MOVE_REQUIRED", f"take parameter {param.name} requires explicit move", expr.span)
        typ = self.expr(expr, env, live, unsafe_depth, param.type)
        self.compatible(typ, param.type, expr.span)
        if self.contains_linear(typ) and param.mode != "take":
            self.error("E_LINEAR_USE", "linear resources require explicit ownership or borrowing modes", expr.span)
        return typ

    def require_unsafe(self, expr: Expr, unsafe_depth: int, operation: str) -> None:
        self.effect("unsafe")
        if unsafe_depth == 0:
            self.error("E_UNSAFE_REQUIRED", f"{operation} requires an explicit unsafe block", expr.span)
        if self.current is not None:
            key = (self.current.name, operation, expr.span.start)
            if key not in self._assumption_keys:
                self._assumption_keys.add(key)
                self.result.assumptions.append({"kind": "unsafe_obligation", "function": self.current.name, "operation": operation, "path": expr.span.path, "line": expr.span.line, "status": "not_proved_by_frontend"})

    def expr(self, expr: Expr, env: dict[str, _Binding], live: set[int], unsafe_depth: int, expected: Type | None = None) -> Type:
        kind = expr.kind
        typ = ERROR
        if kind in {"name", "call"} and isinstance(expr.value, str) and "::" in expr.value:
            prefix, variant = expr.value.rsplit("::", 1)
            if prefix in self.enums:
                expr.value = {"enum": prefix, "variant": variant, "tuple": kind == "call"}
                expr.kind = kind = "variant"
        if kind == "variant":
            typ = self.variant_expr(expr, env, live, unsafe_depth, expected)
        elif kind == "int":
            typ = expected if expected is not None and expected.name in INTS else I64
            if type(expr.value) is not int:
                self.error("E_LITERAL", "invalid integer literal", expr.span)
            else:
                # Pointer-sized integers are checked for the active target by rustc.
                bits = int(typ.name[1:]) if typ.name[1:].isdigit() else None
                if bits is not None:
                    lower = -(1 << (bits - 1)) if typ.name.startswith("i") else 0
                    upper = (1 << (bits - (1 if typ.name.startswith("i") else 0))) - 1
                    if not lower <= expr.value <= upper:
                        self.error("E_INTEGER_RANGE", f"integer literal does not fit {typ}", expr.span)
                elif expr.value < 0 and typ.name == "usize":
                    self.error("E_INTEGER_RANGE", "negative literal does not fit usize", expr.span)
        elif kind == "float":
            typ = expected if expected is not None and expected.name in FLOATS else F64
            import math
            if not isinstance(expr.value, (float, int)) or not math.isfinite(expr.value):
                self.error("E_LITERAL", "floating literal must be finite", expr.span)
        elif kind == "bool":
            typ = BOOL
        elif kind == "name":
            if expr.type_args:
                self.error("E_GENERIC_CONTEXT", "explicit type arguments require a function call or constructor", expr.span)
            binding = env.get(expr.value)
            if binding is None:
                self.error("E_UNKNOWN_NAME", f"unknown name {expr.value}", expr.span)
            else:
                typ = binding.type
                if self.contains_linear(typ) and binding.mode not in {"read", "mut"} and binding.ident not in live:
                    self.error("E_USE_AFTER_MOVE", f"linear resource {binding.name} has already been moved", expr.span)
        elif kind == "call":
            if expr.value in BUILTINS:
                typ = self.builtin(expr, env, live, unsafe_depth, expected)
            elif expr.value in self.functions:
                fn = self.functions[expr.value]
                mapping = self.generic_arguments(fn.type_params, expr.type_args, expr.span, bounds=fn.type_bounds)
                if self.current is not None:
                    self.calls[self.current.name].add(fn.name)
                if len(expr.children) != len(fn.params):
                    self.error("E_ARITY", f"{fn.name} expects {len(fn.params)} argument(s), found {len(expr.children)}", expr.span)
                for index, arg in enumerate(expr.children):
                    if index < len(fn.params):
                        param = fn.params[index]
                        self.argument(arg, Param(param.name, substitute_type(param.type, mapping), param.mode, param.span), env, live, unsafe_depth)
                    else:
                        self.expr(arg, env, live, unsafe_depth)
                if fn.extern_c:
                    self.require_unsafe(expr, unsafe_depth, f"extern call {fn.name}")
                    self.effect("ffi")
                elif "unsafe" in fn.effects:
                    self.require_unsafe(expr, unsafe_depth, f"call to unsafe-effect function {fn.name}")
                typ = substitute_type(fn.return_type, mapping)
            else:
                self.error("E_UNKNOWN_FUNCTION", f"unknown function {expr.value}", expr.span)
                for child in expr.children:
                    self.expr(child, env, live, unsafe_depth)
        elif kind == "unary":
            if len(expr.children) != 1:
                self.error("E_AST", "unary expression requires one operand", expr.span)
            elif expr.value in {"read", "mut"}:
                operand = self.expr(expr.children[0], env, live, unsafe_depth, expected)
                self.error("E_BORROW_CONTEXT", "read/mut borrowing is supported only in borrow-parameter argument positions", expr.span)
                typ = operand
            elif expr.value == "move":
                child = expr.children[0]
                typ = self.expr(child, env, live, unsafe_depth, expected)
                if typ.name == "Cancellation":
                    self.error("E_CANCELLATION_TYPE", "Cancellation capabilities cannot be moved or owned", expr.span)
                if typ.name == "Sender":
                    self.error("E_SENDER_TYPE", "Sender capabilities cannot be moved or owned", expr.span)
                if self.contains_linear(typ):
                    if self.returned_borrow_mode(child) is not None:
                        self.error("E_MOVE_BORROW", "cannot move a borrowed function result", expr.span)
                    elif child.kind == "name" and child.value in env:
                        binding = env[child.value]
                        if binding.mode in {"read", "mut"}:
                            self.error("E_MOVE_BORROW", f"cannot move borrowed resource {binding.name}", expr.span)
                        else:
                            live.discard(binding.ident)
                    elif child.kind not in {"call", "struct", "variant"}:
                        self.error("E_MOVE_PLACE", "resource move requires an owner name or a fresh function result", expr.span)
            elif expr.value in {"-", "!"}:
                child = expr.children[0]
                desired = expected if expected is not None else self.numeric_hint([child], env)
                # The magnitude of a signed minimum is valid only directly under '-'.
                if expr.value == "-" and child.kind == "int" and desired.name.startswith("i") and desired.name[1:].isdigit() and child.value == 1 << (int(desired.name[1:]) - 1):
                    typ = self.remember(child, desired)
                else:
                    typ = self.expr(child, env, live, unsafe_depth, desired)
                if expr.value == "-":
                    if typ.name not in FLOATS and not (typ.name in INTS and typ.name.startswith("i")):
                        self.error("E_UNARY_TYPE", f"unary - does not accept {typ}", expr.span)
                    elif typ.name in INTS:
                        self.effect("panic")
                elif typ.name not in INTS | {"bool"}:
                    self.error("E_UNARY_TYPE", f"unary ! does not accept {typ}", expr.span)
            else:
                self.error("E_UNARY_OPERATOR", f"unsupported unary operator {expr.value}", expr.span)
                for child in expr.children:
                    self.expr(child, env, live, unsafe_depth)
        elif kind == "binary":
            if len(expr.children) != 2:
                self.error("E_AST", "binary expression requires two operands", expr.span)
            else:
                op = expr.value
                arithmetic = {"+", "-", "*", "/", "%"}
                integer_ops = {"<<", ">>", "&", "|", "^"}
                comparisons = {"==", "!=", "<", "<=", ">", ">="}
                logical = {"&&", "||"}
                hint = BOOL if op in logical else self.numeric_hint(expr.children, env, expected if op in arithmetic | integer_ops else None)
                lhs = self.expr(expr.children[0], env, live, unsafe_depth, hint)
                before_rhs = set(live)
                rhs = self.expr(expr.children[1], env, live, unsafe_depth, lhs)
                if op in logical and live != before_rhs:
                    self.error("E_LINEAR_SHORT_CIRCUIT", "a short-circuited operand cannot consume a linear owner", expr.span)
                    live.update(before_rhs)
                self.compatible(rhs, lhs, expr.span)
                if op in logical:
                    self.compatible(lhs, BOOL, expr.span)
                    typ = BOOL
                elif op in arithmetic:
                    if lhs.name not in INTS | FLOATS:
                        self.error("E_BINARY_TYPE", f"operator {op} requires numeric operands", expr.span)
                    if lhs.name in INTS:
                        self.effect("panic")
                    typ = lhs
                elif op in integer_ops:
                    if lhs.name not in INTS and not (op in {"&", "|", "^"} and lhs == BOOL):
                        self.error("E_BINARY_TYPE", f"operator {op} requires integer operands", expr.span)
                    if op in {"<<", ">>"}:
                        self.effect("panic")
                    typ = lhs
                elif op in comparisons:
                    if lhs.name not in INTS | FLOATS | {"bool"} or (lhs == BOOL and op not in {"==", "!="}):
                        self.error("E_BINARY_TYPE", f"operator {op} does not accept {lhs}", expr.span)
                    typ = BOOL
                else:
                    self.error("E_BINARY_OPERATOR", f"unsupported binary operator {op}", expr.span)
        elif kind == "array":
            element = expected.args[0] if expected is not None and expected.name == "array" and len(expected.args) == 1 else None
            if element is None and expr.children:
                element = self.numeric_hint(expr.children, env) if all(c.kind in {"int", "float"} for c in expr.children) else self.hint(expr.children[0], env)
            for child in expr.children:
                child_type = self.expr(child, env, live, unsafe_depth, element)
                if element is None:
                    element = child_type
                self.compatible(child_type, element, child.span)
                if self.contains_linear(child_type):
                    self.error("E_NESTED_LINEAR", "linear resources cannot be stored in arrays", child.span)
                if self.contains_cancellation(child_type):
                    self.error("E_CANCELLATION_TYPE", "Cancellation capabilities cannot be stored in arrays", child.span)
                if self.contains_sender(child_type):
                    self.error("E_SENDER_TYPE", "Sender capabilities cannot be stored in arrays", child.span)
            if element is None:
                self.error("E_ARRAY_INFERENCE", "empty arrays require an explicit array type", expr.span)
                element = ERROR
            typ = Type("array", (element,), len(expr.children))
        elif kind == "index":
            if len(expr.children) != 2:
                self.error("E_AST", "index expression requires a base and index", expr.span)
            else:
                base = self.expr(expr.children[0], env, live, unsafe_depth)
                index = self.expr(expr.children[1], env, live, unsafe_depth, USIZE)
                self.compatible(index, USIZE, expr.children[1].span)
                self.effect("panic")
                if base.name in {"array", "slice", "Buffer"} and len(base.args) == 1:
                    typ = base.args[0]
                    if base.name == "Buffer" and self.root_binding(expr.children[0], env) is None:
                        self.error("E_LINEAR_TEMPORARY", "bind a fresh Buffer before indexing and release it explicitly", expr.span)
                else:
                    self.error("E_INDEX_TYPE", f"cannot index {base}; raw pointers require load/store", expr.span)
        elif kind == "field":
            if len(expr.children) != 1:
                self.error("E_AST", "field expression requires one base", expr.span)
            else:
                base = self.expr(expr.children[0], env, live, unsafe_depth)
                struct = self.structs.get(base.name)
                member = next((f for f in struct.fields if f.name == expr.value), None) if struct else None
                if member is None:
                    self.error("E_UNKNOWN_FIELD", f"type {base} has no field {expr.value}", expr.span)
                else:
                    typ = substitute_type(member.type, dict(zip(struct.type_params, base.args)))
                    if self.contains_linear(base) and self.root_binding(expr.children[0], env) is None:
                        self.error("E_LINEAR_TEMPORARY", "bind a fresh resource aggregate before projecting a field and consume it explicitly", expr.span)
        elif kind == "cast":
            if len(expr.children) != 1 or not isinstance(expr.value, Type):
                self.error("E_AST", "cast requires one operand and a type", expr.span)
            else:
                source = self.expr(expr.children[0], env, live, unsafe_depth)
                typ = expr.value
                self.valid_type(typ, expr.span)
                if source.name in INTS | FLOATS and typ.name in INTS | FLOATS:
                    pass
                elif source.name == "raw_mut" and typ.name == "raw_const" and source.args == typ.args:
                    self.require_unsafe(expr, unsafe_depth, "raw pointer cast")
                else:
                    self.error("E_CAST", f"unsupported cast from {source} to {typ}", expr.span, "only numeric casts and unsafe raw mut to raw const casts with the same pointee are supported")
        elif kind == "struct":
            if not isinstance(expr.value, dict):
                self.error("E_AST", "malformed struct expression", expr.span)
            else:
                name = expr.value.get("name")
                if name == "GroupReport":
                    self.error("E_REPORT_CONSTRUCTION", "GroupReport values can only be returned by the runtime", expr.span)
                fields = expr.value.get("fields", [])
                struct = self.structs.get(name)
                if struct is None:
                    self.error("E_UNKNOWN_TYPE", f"unknown struct {name}", expr.span)
                    for child in expr.children:
                        self.expr(child, env, live, unsafe_depth)
                else:
                    typ = self.nominal_type(name, expr.type_args, expected, expr.span)
                    mapping = dict(zip(struct.type_params, typ.args))
                    members = {f.name: f for f in struct.fields}
                    if len(fields) != len(expr.children):
                        self.error("E_AST", "struct field/value count mismatch", expr.span)
                    if len(fields) != len(set(fields)):
                        self.error("E_DUPLICATE_FIELD", f"duplicate initializer field in {name}", expr.span)
                    missing = set(members) - set(fields)
                    extra = set(fields) - set(members)
                    if missing or extra:
                        self.error("E_STRUCT_FIELDS", f"invalid fields for {name}: missing {sorted(missing)}, unknown {sorted(extra)}", expr.span)
                    for index, child in enumerate(expr.children):
                        member = members.get(fields[index]) if index < len(fields) else None
                        member_type = substitute_type(member.type, mapping) if member else None
                        actual = self.expr(child, env, live, unsafe_depth, member_type)
                        if member:
                            self.compatible(actual, member_type, child.span)
                        self.require_transfer(child, actual, context="struct field initialization")
                        if self.contains_cancellation(actual):
                            self.error("E_CANCELLATION_TYPE", "Cancellation capabilities cannot be stored in struct fields", child.span)
                        if self.contains_sender(actual):
                            self.error("E_SENDER_TYPE", "Sender capabilities cannot be stored in struct fields", child.span)
        else:
            self.error("E_EXPRESSION", f"unsupported expression kind {kind}", expr.span)
            for child in expr.children:
                self.expr(child, env, live, unsafe_depth)
        return self.remember(expr, typ)

    def builtin(self, expr: Expr, env: dict[str, _Binding], live: set[int], unsafe_depth: int, expected: Type | None) -> Type:
        name = expr.value
        if expr.type_args:
            self.error("E_GENERIC_ARITY", f"builtin {name} does not accept explicit type arguments", expr.span)
        args = expr.children
        if name in GROUP_BUILTINS:
            return self.group_builtin(expr, env, live, unsafe_depth)
        arity = {"len": 1, "wrapping_add": 2, "wrapping_sub": 2, "wrapping_mul": 2, "buffer": 1, "try_buffer": 1, "release": 1, "drop": 1, "assert": 1, "print_i64": 1, "load": 2, "store": 3, "ptr_read": 1, "ptr_mut": 1, "min": 2, "max": 2, "spawn": 2, "join": 1, "cancel_and_join": 1, "cancelled": 1}[name]
        if len(args) != arity:
            self.error("E_ARITY", f"{name} expects {arity} argument(s), found {len(args)}", expr.span)
            for arg in args:
                self.expr(arg, env, live, unsafe_depth)
            return ERROR
        if name == "spawn":
            worker_expr, data = args
            worker = self.functions.get(worker_expr.value) if worker_expr.kind == "name" else None
            if worker is None or worker_expr.value in env or worker.extern_c or worker.body is None or worker.type_params or worker_expr.type_args:
                self.error("E_TASK_WORKER", "spawn requires the name of a locally defined worker function", worker_expr.span)
                self.remember(worker_expr, ERROR)
                if worker_expr.kind != "name":
                    self.expr(worker_expr, env, live, unsafe_depth)
            else:
                self.remember(worker_expr, Type("<function>"))
                valid = (len(worker.params) == 2 and worker.params[0].type == BUFFER_U8 and worker.params[0].mode == "take" and worker.params[1].type == CANCELLATION and worker.params[1].mode == "read" and worker.return_type == Type("u64"))
                if not valid:
                    self.error("E_TASK_WORKER", "worker must have signature (data: take Buffer<u8>, cancel: read Cancellation) -> u64", worker_expr.span)
                if self.current is not None:
                    self.calls[self.current.name].add(worker.name)
                self.worker_sites.append((worker.name, worker_expr.span))
            self.argument(data, Param("data", BUFFER_U8, "take", data.span), env, live, unsafe_depth)
            self.effect("alloc", "block", "spawn", "panic")
            return TASK_U64
        if name in {"join", "cancel_and_join"}:
            self.argument(args[0], Param("task", TASK_U64, "take", args[0].span), env, live, unsafe_depth)
            self.effect("block", "alloc", "panic")
            return Type("u64")
        if name == "cancelled":
            self.borrow(args[0], "read", CANCELLATION, env, live, unsafe_depth)
            return BOOL
        if name in {"wrapping_add", "wrapping_sub", "wrapping_mul", "min", "max"}:
            hint = self.numeric_hint(args, env, expected)
            left = self.expr(args[0], env, live, unsafe_depth, hint)
            right = self.expr(args[1], env, live, unsafe_depth, left)
            self.compatible(right, left, args[1].span)
            if left.name not in INTS:
                self.error("E_BUILTIN_TYPE", f"{name} requires integers", expr.span)
            return left
        if name == "len":
            before = set(live)
            if args[0].kind == "unary" and args[0].value == "read":
                typ = self.borrow(args[0], "read", None, env, live, unsafe_depth)
            else:
                typ = self.expr(args[0], env, live, unsafe_depth)
            if typ.name not in {"array", "slice", "Buffer"}:
                self.error("E_BUILTIN_TYPE", f"len requires an array, slice or Buffer, found {typ}", expr.span)
            if typ.name == "Buffer":
                place = args[0].children[0] if args[0].kind == "unary" and args[0].value == "read" else args[0]
                if self.root_binding(place, env) is None or live != before:
                    self.error("E_LINEAR_TEMPORARY", "len borrows a named Buffer; it cannot consume or discard an owner", args[0].span)
            return USIZE
        if name in {"buffer", "try_buffer"}:
            actual = self.expr(args[0], env, live, unsafe_depth, USIZE)
            self.compatible(actual, USIZE, args[0].span)
            self.effect("alloc", "block")
            if name == "buffer":
                self.effect("panic")
            return BUFFER_U8 if name == "buffer" else BUFFER_RESULT
        if name in {"release", "drop"}:
            if args[0].kind != "unary" or args[0].value != "move":
                self.error("E_MOVE_REQUIRED", f"{name} requires an explicit move", args[0].span)
            typ = self.expr(args[0], env, live, unsafe_depth)
            if not self.contains_linear(typ) or self.contains_capability(typ, {"Task", "TaskGroup"}):
                self.error("E_BUILTIN_TYPE", f"{name} requires a Buffer or owned data aggregate; task handles must be joined, found {typ}", expr.span)
            self.effect("alloc", "block")
            return UNIT
        if name in {"assert", "print_i64"}:
            required = BOOL if name == "assert" else I64
            actual = self.expr(args[0], env, live, unsafe_depth, required)
            self.compatible(actual, required, args[0].span)
            self.effect(*({"panic"} if name == "assert" else {"io", "block", "alloc", "panic"}))
            return UNIT
        if name in {"ptr_read", "ptr_mut"}:
            mode = "read" if name == "ptr_read" else "mut"
            typ = self.borrow(args[0], mode, None, env, live, unsafe_depth)
            self.require_unsafe(expr, unsafe_depth, name)
            if typ.name not in {"array", "slice", "Buffer"} or len(typ.args) != 1:
                self.error("E_BUILTIN_TYPE", f"{name} requires an array, slice or Buffer borrow", expr.span)
                return ERROR
            return Type("raw_const" if mode == "read" else "raw_mut", typ.args)
        if name in {"load", "store"}:
            self.require_unsafe(expr, unsafe_depth, name)
            ptr = self.expr(args[0], env, live, unsafe_depth)
            offset = self.expr(args[1], env, live, unsafe_depth, USIZE)
            self.compatible(offset, USIZE, args[1].span)
            if ptr.name not in {"raw_const", "raw_mut"} or len(ptr.args) != 1:
                self.error("E_BUILTIN_TYPE", f"{name} requires a raw pointer", expr.span)
                if name == "store":
                    self.expr(args[2], env, live, unsafe_depth)
                return ERROR
            if name == "store":
                self.effect("write")
                if ptr.name != "raw_mut":
                    self.error("E_READ_ONLY", "store requires a mutable raw pointer", expr.span)
                value = self.expr(args[2], env, live, unsafe_depth, ptr.args[0])
                self.compatible(value, ptr.args[0], args[2].span)
                return UNIT
            return ptr.args[0]
        self.error("E_BUILTIN", f"unsupported builtin {name}", expr.span)
        return ERROR

    def group_builtin(self, expr: Expr, env: dict[str, _Binding], live: set[int], unsafe_depth: int) -> Type:
        """A bounded group is an explicit runtime budget capability, not a global bound."""
        name, args = expr.value, expr.children
        arity = {"task_group": 3, "group_spawn": 3, "group_send": 2,
                 "group_receive": 2, "group_seal": 1, "group_join": 1,
                 "group_drain_and_join": 1, "group_cancel_and_join": 1,
                 "group_snapshot": 1, "group_fail": 2, "group_cancel": 1,
                 "group_send_timeout": 3, "group_receive_timeout": 3}[name]
        if len(args) != arity:
            self.error("E_ARITY", f"{name} expects {arity} argument(s), found {len(args)}", expr.span)
            for arg in args:
                self.expr(arg, env, live, unsafe_depth)
            return ERROR
        if name == "task_group":
            for arg in args:
                actual = self.expr(arg, env, live, unsafe_depth, USIZE)
                self.compatible(actual, USIZE, arg.span)
            if args[2].kind == "int" and args[2].value == 0:
                self.error("E_GROUP_CAPACITY", "bounded group queue capacity must be positive", args[2].span)
            self.effect("alloc", "block", "panic")
            self.result.resource_contracts.append({
                "kind": "task_group", "scope": "one_runtime_instance",
                "enforcement": "runtime_admission_and_fixed_queue",
                "function": self.current.name if self.current else None,
                "path": expr.span.path, "line": expr.span.line,
                "limits": {key: arg.value if arg.kind == "int" else "dynamic_runtime_value"
                           for key, arg in zip(("admitted_tasks", "admitted_input_bytes", "queued_u64_values"), args)},
                "excludes": ["other_group_instances", "allocations_before_submission", "worker_internal_allocations", "thread_stacks", "runtime_metadata", "process_RSS", "CPU_time"],
            })
            return GROUP
        if name == "group_spawn":
            self.borrow(args[0], "mut", GROUP, env, live, unsafe_depth)
            worker_expr = args[1]
            worker = self.functions.get(worker_expr.value) if worker_expr.kind == "name" else None
            if worker is None or worker_expr.value in env or worker.extern_c or worker.body is None:
                self.error("E_TASK_WORKER", "group_spawn requires a locally defined worker function name", worker_expr.span)
                self.remember(worker_expr, ERROR)
                if worker_expr.kind != "name":
                    self.expr(worker_expr, env, live, unsafe_depth)
            else:
                self.remember(worker_expr, Type("<function>"))
                valid = (not getattr(worker, "type_params", ())
                         and not getattr(worker_expr, "type_args", ())
                         and len(worker.params) == 3
                         and worker.params[0].type == BUFFER_U8 and worker.params[0].mode == "take"
                         and worker.params[1].type == CANCELLATION and worker.params[1].mode == "read"
                         and worker.params[2].type == SENDER and worker.params[2].mode == "read"
                         and worker.return_type == Type("u64"))
                if not valid:
                    self.error("E_TASK_WORKER", "group worker must accept (take Buffer<u8>, read Cancellation, read Sender<u64>) and return u64", worker_expr.span)
                if self.current is not None:
                    self.calls[self.current.name].add(worker.name)
                self.worker_sites.append((worker.name, worker_expr.span))
            self.argument(args[2], Param("data", BUFFER_U8, "take", args[2].span), env, live, unsafe_depth)
            self.effect("alloc", "block", "spawn", "panic", "write")
            return BOOL
        if name in {"group_join", "group_drain_and_join", "group_cancel_and_join"}:
            self.argument(args[0], Param("group", GROUP, "take", args[0].span), env, live, unsafe_depth)
            self.effect("alloc", "block", "panic", "write")
            return REPORT
        if name in {"group_send", "group_send_timeout", "group_fail"}:
            self.borrow(args[0], "read", SENDER, env, live, unsafe_depth)
            actual = self.expr(args[1], env, live, unsafe_depth, Type("u64"))
            self.compatible(actual, Type("u64"), args[1].span)
            if name == "group_fail" and args[1].kind == "int" and args[1].value == 0:
                self.error("E_GROUP_FAILURE_CODE", "group_fail requires a nonzero error code", args[1].span)
            if name == "group_send_timeout":
                actual = self.expr(args[2], env, live, unsafe_depth, Type("u64"))
                self.compatible(actual, Type("u64"), args[2].span)
            self.effect("alloc", "block", "panic", "write")
            return Type("Result", (BOOL, Type("u8"))) if name == "group_send_timeout" else (BOOL if name == "group_send" else UNIT)
        if name in {"group_receive", "group_receive_timeout"}:
            self.borrow(args[0], "read", GROUP, env, live, unsafe_depth)
            self.borrow(args[1], "mut", Type("u64"), env, live, unsafe_depth)
            if name == "group_receive_timeout":
                actual = self.expr(args[2], env, live, unsafe_depth, Type("u64"))
                self.compatible(actual, Type("u64"), args[2].span)
            self.effect("alloc", "block", "panic", "write")
            return Type("Result", (BOOL, Type("u8"))) if name == "group_receive_timeout" else BOOL
        if name in {"group_seal", "group_cancel"}:
            self.borrow(args[0], "mut", GROUP, env, live, unsafe_depth)
            self.effect("alloc", "block", "panic", "write")
            return UNIT
        if name == "group_snapshot":
            self.borrow(args[0], "read", GROUP, env, live, unsafe_depth)
            self.effect("alloc", "block", "panic")
            return REPORT
        self.error("E_BUILTIN", f"unsupported group operation {name}", expr.span)
        return ERROR

    def block(self, statements: list[Stmt], env: dict[str, _Binding], incoming: set[int], unsafe_depth: int = 0, *, scoped: bool = True) -> _Flow:
        env = dict(env)
        live = set(incoming)
        local_owners: set[int] = set()
        normal = True
        for stmt in statements:
            if not normal:
                self.error("E_UNREACHABLE", "unreachable statements are unsupported in the bootstrap", stmt.span)
                # Still resolve their expressions/types/effects, without changing the real exit state.
                self.statement(stmt, dict(env), set(live), unsafe_depth, set())
                continue
            flow = self.statement(stmt, env, live, unsafe_depth, local_owners)
            live = flow.live
            normal = flow.normal
        if scoped and normal:
            remaining = live & local_owners
            self.live_error(remaining, statements[-1].span if statements else (self.current.span if self.current else Span()), "scope exit")
            live -= local_owners
        return _Flow(live, normal)

    def statement(self, stmt: Stmt, env: dict[str, _Binding], live: set[int], unsafe_depth: int, local_owners: set[int]) -> _Flow:
        data = stmt.data
        if stmt.kind == "let":
            declared = data.get("type")
            if declared is not None:
                self.valid_type(declared, stmt.span)
            expr = data["expr"]
            actual = self.expr(expr, env, live, unsafe_depth, declared)
            typ = declared or actual
            if declared is not None:
                self.compatible(actual, declared, expr.span)
            self.require_transfer(expr, typ, context="resource initialization")
            if self.contains_cancellation(typ):
                self.error("E_CANCELLATION_TYPE", "Cancellation capabilities cannot be copied into local value bindings", stmt.span)
            if self.contains_sender(typ):
                self.error("E_SENDER_TYPE", "Sender capabilities cannot be copied into local value bindings", stmt.span)
            if typ.name == "slice":
                self.error("E_UNSIZED", "slice values cannot be local owned bindings", stmt.span)
            binding = self.bind(data["name"], typ, bool(data.get("mutable")), "value", stmt.span, env, live)
            if self.contains_linear(typ):
                local_owners.add(binding.ident)
        elif stmt.kind == "assign":
            target = data["target"]
            target_type = self.lvalue(target, env, live, unsafe_depth, mutable=True)
            actual = self.expr(data["expr"], env, live, unsafe_depth, target_type)
            self.compatible(actual, target_type, stmt.span)
            if self.contains_linear(target_type) or self.contains_linear(actual):
                self.error("E_LINEAR_REASSIGN", "linear resources cannot be reassigned", stmt.span)
            if self.contains_cancellation(target_type) or self.contains_cancellation(actual):
                self.error("E_CANCELLATION_TYPE", "Cancellation capabilities cannot be reassigned", stmt.span)
            if self.contains_sender(target_type) or self.contains_sender(actual):
                self.error("E_SENDER_TYPE", "Sender capabilities cannot be reassigned", stmt.span)
            binding = self.root_binding(target, env)
            if binding is not None and binding.mode == "mut":
                self.effect("write")
        elif stmt.kind == "return":
            assert self.current is not None
            expr = data.get("expr")
            if self.current.return_mode in {"read", "mut"}:
                if expr is None:
                    self.error("E_BORROW_RETURN_SOURCE", "a borrowed return requires an explicit source place", stmt.span)
                else:
                    self.borrow(expr, self.current.return_mode, self.current.return_type, env, live, unsafe_depth)
                    place = expr.children[0] if expr.kind == "unary" and expr.children else expr
                    origin = self.root_binding(place, env)
                    sources = [p for p in self.current.params if p.mode in {"read", "mut"}]
                    if len(sources) != 1 or origin is None or origin.name != sources[0].name or origin.mode not in {"read", "mut"}:
                        self.error("E_BORROW_RETURN_SOURCE", "returned borrow must originate in the unique borrowed input, never a local or owned parameter", stmt.span)
                self.live_error(live, stmt.span, "borrowed return")
                return _Flow(live, False)
            if expr is None:
                actual = UNIT
            else:
                actual = self.expr(expr, env, live, unsafe_depth, self.current.return_type)
            self.compatible(actual, self.current.return_type, stmt.span)
            if self.current.return_type.name == "Buffer" and (expr is None or expr.kind != "unary" or expr.value != "move"):
                self.error("E_MOVE_REQUIRED", "returning a Buffer requires explicit move", stmt.span)
            elif expr is not None:
                self.require_transfer(expr, actual, context="return")
            self.live_error(live, stmt.span, "return")
            return _Flow(live, False)
        elif stmt.kind == "expr":
            typ = self.expr(data["expr"], env, live, unsafe_depth)
            if self.contains_linear(typ):
                self.error("E_LINEAR_DISCARD", "a linear resource expression cannot be discarded", stmt.span)
            if self.contains_cancellation(typ):
                self.error("E_CANCELLATION_TYPE", "Cancellation is a borrowed capability, not a standalone value", stmt.span)
            if self.contains_sender(typ):
                self.error("E_SENDER_TYPE", "Sender is a borrowed capability, not a standalone value", stmt.span)
        elif stmt.kind == "if":
            condition = self.expr(data["condition"], env, live, unsafe_depth, BOOL)
            self.compatible(condition, BOOL, data["condition"].span)
            then = self.block(data["then"], env, live, unsafe_depth)
            otherwise = self.block(data.get("else", []), env, live, unsafe_depth)
            if then.normal and otherwise.normal:
                if then.live != otherwise.live:
                    self.error("E_LINEAR_BRANCH", "both continuing branches must leave the same linear owners live", stmt.span)
                return _Flow(then.live | otherwise.live)
            if then.normal:
                return then
            if otherwise.normal:
                return otherwise
            return _Flow(set(), False)
        elif stmt.kind == "match":
            typ = self.expr(data["expr"], env, live, unsafe_depth)
            self.require_transfer(data["expr"], typ, context="consuming match")
            enum = self.enums.get(typ.name)
            if enum is None:
                self.error("E_MATCH_TYPE", f"match requires an enum value, found {typ}", data["expr"].span)
            mapping = dict(zip(enum.type_params, typ.args)) if enum else {}
            variants = {v.name: v for v in enum.variants} if enum else {}
            covered: set[str] = set()
            continuing: list[_Flow] = []
            for arm in data["arms"]:
                pattern = arm.pattern
                variant = variants.get(pattern.variant) if pattern.enum_name == typ.name else None
                if pattern.enum_name != typ.name:
                    self.error("E_PATTERN_TYPE", f"pattern {pattern.enum_name}::{pattern.variant} does not match {typ}", pattern.span)
                elif variant is None:
                    self.error("E_UNKNOWN_VARIANT", f"enum {typ.name} has no variant {pattern.variant}", pattern.span)
                elif pattern.variant in covered:
                    self.error("E_MATCH_DUPLICATE", f"variant {pattern.variant} is matched more than once", pattern.span)
                else:
                    covered.add(pattern.variant)
                fields = variant.fields if variant else []
                if len(fields) != len(pattern.bindings):
                    self.error("E_PATTERN_ARITY", f"pattern expects {len(fields)} payload binding(s), found {len(pattern.bindings)}", pattern.span)
                arm_env = dict(env)
                arm_live = set(live)
                arm_owners: set[int] = set()
                for index, name in enumerate(pattern.bindings):
                    field_type = substitute_type(fields[index], mapping) if index < len(fields) else ERROR
                    if name == "_":
                        if self.contains_linear(field_type):
                            self.error("E_LINEAR_DISCARD", "an owned match payload must be bound and explicitly consumed", pattern.span)
                        continue
                    binding = self.bind(name, field_type, False, "value", pattern.span, arm_env, arm_live)
                    if self.contains_linear(field_type):
                        arm_owners.add(binding.ident)
                flow = self.block(arm.body, arm_env, arm_live, unsafe_depth)
                if flow.normal:
                    self.live_error(flow.live & arm_owners, arm.span, "match arm exit")
                    flow.live -= arm_owners
                    continuing.append(flow)
            missing = set(variants) - covered
            if missing:
                self.error("E_MATCH_EXHAUSTIVE", f"match is missing variant(s): {', '.join(sorted(missing))}", stmt.span)
            if enum is None or missing:
                continuing.append(_Flow(set(live)))
            if not continuing:
                return _Flow(set(), False)
            if any(flow.live != continuing[0].live for flow in continuing[1:]):
                self.error("E_LINEAR_BRANCH", "all continuing match arms must leave the same linear owners live", stmt.span)
            return _Flow(set().union(*(flow.live for flow in continuing)))
        elif stmt.kind == "for":
            start = self.expr(data["start"], env, live, unsafe_depth, self.numeric_hint([data["start"], data["end"]], env))
            end = self.expr(data["end"], env, live, unsafe_depth, start)
            self.compatible(end, start, stmt.span)
            if start.name not in INTS:
                self.error("E_RANGE_TYPE", "for ranges require integer bounds", stmt.span)
            loop_env = dict(env)
            self.bind(data["name"], start, False, "value", stmt.span, loop_env, live)
            body = self.block(data["body"], loop_env, live, unsafe_depth)
            if body.normal and body.live != live:
                self.error("E_LINEAR_LOOP", "loop body must preserve incoming linear ownership on every continuing iteration", stmt.span)
            return _Flow(live)
        elif stmt.kind == "while":
            before = set(live)
            condition = self.expr(data["condition"], env, live, unsafe_depth, BOOL)
            self.compatible(condition, BOOL, stmt.span)
            if before != live:
                self.error("E_LINEAR_LOOP", "a repeated loop condition cannot consume a linear owner", stmt.span)
            body = self.block(data["body"], env, before, unsafe_depth)
            if body.normal and body.live != before:
                self.error("E_LINEAR_LOOP", "loop body must preserve incoming linear ownership on every continuing iteration", stmt.span)
            return _Flow(before)
        elif stmt.kind == "unsafe":
            self.effect("unsafe")
            return self.block(data["body"], env, live, unsafe_depth + 1)
        else:
            self.error("E_STATEMENT", f"unsupported statement kind {stmt.kind}", stmt.span)
        return _Flow(live)

    def finish_effects(self) -> None:
        inferred = {name: set(effects) for name, effects in self.local_effects.items()}
        changed = True
        while changed:
            changed = False
            for name, callees in self.calls.items():
                before = len(inferred[name])
                for callee in callees:
                    inferred[name].update(inferred[callee])
                    # Callers rely on declared upper bounds, including external assumptions.
                    inferred[name].update(self.functions[callee].effects & EFFECTS)
                changed = changed or len(inferred[name]) != before
        self.result.effects = inferred
        for worker, span in self.worker_sites:
            forbidden = (inferred[worker] | self.functions[worker].effects) & {"spawn", "unsafe", "ffi"}
            if forbidden:
                self.error("E_TASK_WORKER_EFFECT", f"worker {worker} has unsupported transitive effect(s): {', '.join(sorted(forbidden))}", span, "bootstrap workers cannot spawn nested tasks or perform unchecked unsafe/foreign operations; cancellation is cooperative and termination is not proved")
        for name, fn in self.functions.items():
            missing = inferred[name] - fn.effects
            if missing:
                self.error("E_EFFECT", f"function {name} does not declare inferred effect(s): {', '.join(sorted(missing))}", fn.span)
            upper = inferred[name] | (fn.effects & EFFECTS)
            forbidden = {"heap_allocations": "alloc", "may_block": "block", "may_spawn": "spawn"}
            for clause, effect in forbidden.items():
                if clause in fn.resources and effect in upper:
                    self.error("E_RESOURCE", f"resource clause {clause} conflicts with {effect} effect in {name}", fn.span)

    def run(self) -> CheckResult:
        self.declarations()
        for fn in self.functions.values():
            if fn.extern_c or fn.body is None:
                continue
            self.current = fn
            self.type_params = set(fn.type_params)
            self.owned_type_params = {name for name in fn.type_params if fn.type_bounds.get(name) == "Owned"}
            env: dict[str, _Binding] = {}
            live: set[int] = set()
            for param in fn.params:
                self.bind(param.name, param.type, False, param.mode, param.span, env, live)
            flow = self.block(fn.body, env, live, scoped=False)
            if flow.normal:
                self.live_error(flow.live, fn.body_span, "function exit")
                if fn.return_type != UNIT:
                    self.error("E_MISSING_RETURN", f"function {fn.name} can reach its end without returning {fn.return_type}", fn.span)
        self.current = None
        self.type_params = set()
        self.owned_type_params = set()
        self.finish_effects()
        return self.result


def check(program: Program) -> CheckResult:
    """Check the bootstrap subset; rustc must subsequently validate native borrows."""
    return _Checker(program).run()
