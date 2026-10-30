"""Restricted, typed Hepta migration-only IR for the first C migration slice.

This is NOT the production whole-language IR or a soundness proof. Only
side-effect-free, scalar, copy-only functions can be represented here.
Unknown operations are rejected instead of lowered to unchecked source text.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import re


# The migration IR can also be called without the C importer. Only validated
# ASCII Hepta symbol spellings may be interpolated into emitted source.
_SYMBOL = re.compile(r"[A-Za-z][A-Za-z0-9_]*\Z", re.ASCII)
_RESERVED = frozenset({
    "module", "import", "fn", "pub", "extern", "export", "effects", "resources",
    "as", "let", "mut", "take", "move", "read", "unsafe", "struct", "enum",
    "match", "if", "else", "return", "for", "while", "true", "false",
    "wrapping_add", "wrapping_sub", "wrapping_mul", "len", "assert", "main",
})


NUMERIC = frozenset({"i32", "u32"})
ARITHMETIC = frozenset({"+", "-", "*"})
COMPARISON = frozenset({"==", "!=", "<", "<=", ">", ">="})


class IRValidationError(ValueError):
    pass


def _check_symbol(name: str) -> None:
    if not isinstance(name, str) or not _SYMBOL.fullmatch(name) or name in _RESERVED:
        raise IRValidationError(f"unsupported Hepta migration IR identifier: {name!r}")


@dataclass(frozen=True)
class Expr:
    kind: str
    ty: str
    value: str = ""
    args: tuple["Expr", ...] = ()


@dataclass(frozen=True)
class Stmt:
    kind: str
    expr: Expr
    then_body: tuple["Stmt", ...] = ()
    else_body: tuple["Stmt", ...] = ()


@dataclass(frozen=True)
class Function:
    name: str
    params: tuple[tuple[str, str], ...]
    result: str
    body: tuple[Stmt, ...]


def _expr(expr: Expr, names: dict[str, str]) -> set[str]:
    if expr.kind == "var":
        if expr.args or names.get(expr.value) != expr.ty:
            raise IRValidationError("variable not bound with the stated type")
        return set()
    if expr.kind == "literal":
        # Scalar values need at most ten decimal digits. Reject overlong or
        # malformed direct-IR input *before* Python's potentially expensive
        # decimal-to-int conversion (which can raise a raw ValueError).
        if (expr.args or expr.ty not in NUMERIC or not isinstance(expr.value, str)
                or len(expr.value) > 10 or not expr.value.isascii()
                or not expr.value.isdecimal()):
            raise IRValidationError("invalid integer literal")
        number = int(expr.value)
        high = 2**31 - 1 if expr.ty == "i32" else 2**32 - 1
        if number > high:
            raise IRValidationError("integer literal exceeds scalar range")
        return set()
    if expr.kind == "neg":
        if len(expr.args) != 1 or expr.ty != "i32" or expr.args[0].ty != "i32":
            raise IRValidationError("negative expression requires i32")
        return _expr(expr.args[0], names) | {"panic"}
    if expr.kind in {"arith", "compare"}:
        if len(expr.args) != 2 or expr.args[0].ty != expr.args[1].ty or expr.args[0].ty not in NUMERIC:
            raise IRValidationError("operator operands must share a supported scalar type")
        if expr.kind == "arith" and (expr.value not in ARITHMETIC or expr.ty != expr.args[0].ty):
            raise IRValidationError("invalid arithmetic operation")
        if expr.kind == "compare" and (expr.value not in COMPARISON or expr.ty != "bool"):
            raise IRValidationError("invalid comparison operation")
        effects = _expr(expr.args[0], names) | _expr(expr.args[1], names)
        if expr.kind == "arith" and expr.ty == "i32":
            effects.add("panic")
        return effects
    raise IRValidationError(f"unsupported expression node: {expr.kind}")


def _block(body: tuple[Stmt, ...], names: dict[str, str], result: str) -> set[str]:
    if len(body) != 1:
        raise IRValidationError("every block must have exactly one terminal statement")
    statement = body[0]
    effects = _expr(statement.expr, names)
    if statement.kind == "return":
        if statement.then_body or statement.else_body or statement.expr.ty != result:
            raise IRValidationError("return type or control flow mismatch")
        return effects
    if statement.kind == "if":
        if statement.expr.ty != "bool" or not statement.then_body or not statement.else_body:
            raise IRValidationError("if requires bool condition and two terminating branches")
        return effects | _block(statement.then_body, names, result) | _block(statement.else_body, names, result)
    raise IRValidationError(f"unsupported statement node: {statement.kind}")


def check_function(function: Function) -> frozenset[str]:
    _check_symbol(function.name)
    if function.result not in NUMERIC or not function.body:
        raise IRValidationError("unsupported result or empty function")
    names: dict[str, str] = {}
    for name, ty in function.params:
        _check_symbol(name)
        if name in names or ty not in NUMERIC:
            raise IRValidationError("duplicate or unsupported parameter")
        names[name] = ty
    return frozenset(_block(function.body, names, function.result))


def function_hash(function: Function) -> str:
    check_function(function)
    encoded = json.dumps(asdict(function), sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def emit_expr(expr: Expr) -> str:
    if expr.kind == "var":
        return expr.value
    if expr.kind == "literal":
        return f"({expr.value} as {expr.ty})"
    if expr.kind == "neg":
        return f"(-{emit_expr(expr.args[0])})"
    if expr.kind == "compare":
        return f"({emit_expr(expr.args[0])} {expr.value} {emit_expr(expr.args[1])})"
    if expr.kind == "arith":
        a, b = (emit_expr(arg) for arg in expr.args)
        if expr.ty == "u32":
            op = {"+": "wrapping_add", "-": "wrapping_sub", "*": "wrapping_mul"}[expr.value]
            return f"{op}({a}, {b})"
        return f"({a} {expr.value} {b})"
    raise IRValidationError("invalid expression")


def _emit_body(body: tuple[Stmt, ...], indent: str) -> list[str]:
    stmt = body[0]
    if stmt.kind == "return":
        return [indent + "return " + emit_expr(stmt.expr) + ";"]
    return ([indent + "if " + emit_expr(stmt.expr) + " {"]
            + _emit_body(stmt.then_body, indent + "    ")
            + [indent + "} else {"]
            + _emit_body(stmt.else_body, indent + "    ")
            + [indent + "}"])


def emit_function(function: Function) -> str:
    effects = check_function(function)
    args = ", ".join(f"{name}: {ty}" for name, ty in function.params)
    effect_clause = ", ".join(sorted(effects))
    start = f'export "C" fn {function.name}({args}) -> {function.result} effects {{ {effect_clause} }} {{'
    return "\n".join([start] + _emit_body(function.body, "    ") + ["}"])
