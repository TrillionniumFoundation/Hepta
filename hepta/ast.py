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

    def __str__(self) -> str:
        if self.name == "slice":
            return f"[{self.args[0]}]"
        if self.name == "array":
            return f"[{self.args[0]}; {self.length}]"
        if self.name in ("raw_const", "raw_mut"):
            return f"raw {'const' if self.name == 'raw_const' else 'mut'} {self.args[0]}"
        return self.name + ("<" + ", ".join(map(str, self.args)) + ">" if self.args else "")


@dataclass
class Expr:
    kind: str
    value: Any = None
    children: list[Expr] = field(default_factory=list)
    span: Span = field(default_factory=Span)


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


@dataclass
class Struct:
    name: str
    fields: list[Param]
    repr_c: bool = False
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


@dataclass
class Program:
    name: str
    structs: list[Struct]
    functions: list[Function]
    source: str
    path: str = "<input>"
