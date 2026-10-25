"""Versioned syntax model shared by the Hepta bootstrap compiler passes."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Span:
    start: int = 0
    end: int = 0
    line: int = 1
    column: int = 1
    path: str = "<input>"


@dataclass
class Diagnostic:
    code: str
    message: str
    span: Span = field(default_factory=Span)
    notes: list[str] = field(default_factory=list)
    phase: str = "check"

    def to_dict(self) -> dict:
        return {"code": self.code, "message": self.message, "phase": self.phase,
                "span": {"path": self.span.path, "start": self.span.start,
                         "end": self.span.end, "line": self.span.line,
                         "column": self.span.column}, "notes": self.notes}


class HeptaError(Exception):
    def __init__(self, diagnostic: Diagnostic):
        self.diagnostic = diagnostic
        super().__init__(diagnostic.message)


@dataclass(frozen=True)
class Type:
    name: str
    args: tuple[Type, ...] = ()
    length: int | None = None
    lifetimes: tuple[str, ...] = ()

    def __str__(self) -> str:
        if self.name in ("ref_read", "ref_mut") and len(self.args) == len(self.lifetimes) == 1:
            return f"{self.name[4:]} '{self.lifetimes[0]} {self.args[0]}"
        if self.name == "slice":
            return f"[{self.args[0]}]"
        if self.name == "array":
            return f"[{self.args[0]}; {self.length}]"
        if self.name in ("raw_const", "raw_mut"):
            return f"raw {'const' if self.name == 'raw_const' else 'mut'} {self.args[0]}"
        arguments = ["'" + name for name in self.lifetimes] + list(map(str, self.args))
        return self.name + ("<" + ", ".join(arguments) + ">" if arguments else "")


@dataclass
class Expr:
    kind: str
    value: Any = None
    children: list[Expr] = field(default_factory=list)
    span: Span = field(default_factory=Span)
    type_args: tuple[Type, ...] = ()


@dataclass
class Stmt:
    kind: str
    data: dict[str, Any] = field(default_factory=dict)
    span: Span = field(default_factory=Span)


@dataclass
class Param:
    name: str
    type: Type
    mode: str = "value"
    span: Span = field(default_factory=Span)
    lifetime: str | None = None


@dataclass
class Struct:
    name: str
    fields: list[Param]
    repr_c: bool = False
    span: Span = field(default_factory=Span)
    type_params: tuple[str, ...] = ()
    public: bool = False
    lifetime_params: tuple[str, ...] = ()


@dataclass
class EnumVariant:
    name: str
    fields: list[Type] = field(default_factory=list)
    span: Span = field(default_factory=Span)


@dataclass
class Enum:
    name: str
    variants: list[EnumVariant]
    type_params: tuple[str, ...] = ()
    public: bool = False
    span: Span = field(default_factory=Span)


@dataclass
class Pattern:
    enum_name: str
    variant: str
    bindings: list[str] = field(default_factory=list)
    span: Span = field(default_factory=Span)


@dataclass
class MatchArm:
    pattern: Pattern
    body: list[Stmt]
    span: Span = field(default_factory=Span)


@dataclass
class Import:
    name: str
    alias: str
    span: Span = field(default_factory=Span)


@dataclass
class Function:
    name: str
    params: list[Param]
    return_type: Type
    effects: set[str]
    body: list[Stmt] | None
    public: bool = False
    extern_c: bool = False
    export_c: bool = False
    resources: dict[str, Any] = field(default_factory=dict)
    span: Span = field(default_factory=Span)
    body_span: Span = field(default_factory=Span)
    type_params: tuple[str, ...] = ()
    # Borrowed returns name one input origin (or infer the unique borrowed
    # input). They are immediate places, not first-class stored references.
    return_mode: str = "value"
    # Function-only finite capability constraints. Missing entries retain the
    # historical Copy constraint; Owned means a checked, sized resource value.
    type_bounds: dict[str, str] = field(default_factory=dict)
    return_origin: str | None = None
    lifetime_params: tuple[str, ...] = ()
    return_lifetime: str | None = None


@dataclass
class Program:
    name: str
    structs: list[Struct]
    functions: list[Function]
    source: str
    path: str = "<input>"
    enums: list[Enum] = field(default_factory=list)
    imports: list[Import] = field(default_factory=list)
