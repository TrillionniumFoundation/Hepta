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

from .lexer import KEYWORDS


# Enforce the C pilot's strict public-name policy at the IR boundary too.
# The Clang importer checks names, but IR is a public, independently callable API.
_ASCII_PILOT_IDENT = re.compile(r"[A-Za-z][A-Za-z_0-9]*\Z", re.ASCII)
_RESERVED_PILOT_IDENT = KEYWORDS | frozenset({
    "wrapping_add", "wrapping_sub", "wrapping_mul", "len", "assert", "main",
})


def _require_pilot_identifier(value: str) -> None:
    if (not isinstance(value, str) or not _ASCII_PILOT_IDENT.fullmatch(value)
            or value in _RESERVED_PILOT_IDENT):
        raise IRValidationError("invalid or reserved migration IR identifier")


NUMERIC = frozenset({"i32", "u32"})
ARITHMETIC = frozenset({"+", "-", "*"})
COMPARISON = frozenset({"==", "!=", "<", "<=", ">", ">="})


class IRValidationError(ValueError):
    pass


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
        # 32-bit values need at most ten decimal digits. Check type and
        # length before int(): long untrusted IR literals otherwise raise
        # Python's digit-conversion ValueError or consume unbounded work.
        if (expr.args or expr.ty not in NUMERIC
                or not isinstance(expr.value, str) or not expr.value
                or len(expr.value) > 10
                or not expr.value.isascii() or not expr.value.isdecimal()):
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


# This public IR can be constructed without the bounded Clang importer.
# Check its shape iteratively before recursive checking, hashing or emission:
# malformed/unhashable fields and cyclic or explosively shared trees must
# fail with IRValidationError, not Python exceptions or unbounded work.
_MAX_IR_DEPTH = 128
_MAX_IR_NODES = 4096
_MAX_IR_PARAMS = 256
_MAX_IR_TOKEN_LENGTH = 256


def _preflight_shape(function: Function) -> None:
    if (not isinstance(function, Function)
            or not isinstance(function.name, str)
            or len(function.name) > _MAX_IR_TOKEN_LENGTH
            or not isinstance(function.params, tuple)
            or len(function.params) > _MAX_IR_PARAMS
            or not isinstance(function.result, str)
            or len(function.result) > 16
            or not isinstance(function.body, tuple)):
        raise IRValidationError("invalid migration IR function shape")
    for item in function.params:
        if (not isinstance(item, tuple) or len(item) != 2
                or not isinstance(item[0], str)
                or not isinstance(item[1], str)
                or len(item[0]) > _MAX_IR_TOKEN_LENGTH
                or len(item[1]) > 16):
            raise IRValidationError("invalid migration IR parameter shape")

    pending: list[tuple[str, object, int]] = [("block", function.body, 0)]
    examined = 0
    while pending:
        category, item, depth = pending.pop()
        examined += 1
        if examined > _MAX_IR_NODES or depth > _MAX_IR_DEPTH:
            raise IRValidationError("migration IR structural budget exceeded")
        if category == "block":
            if not isinstance(item, tuple) or len(item) != 1:
                raise IRValidationError("invalid migration IR block shape")
            pending.append(("stmt", item[0], depth + 1))
        elif category == "stmt":
            if (not isinstance(item, Stmt) or not isinstance(item.kind, str)
                    or len(item.kind) > 16
                    or not isinstance(item.then_body, tuple)
                    or not isinstance(item.else_body, tuple)):
                raise IRValidationError("invalid migration IR statement shape")
            if item.kind == "if":
                pending.append(("block", item.then_body, depth + 1))
                pending.append(("block", item.else_body, depth + 1))
            elif item.kind != "return":
                raise IRValidationError("unsupported migration IR statement")
            pending.append(("expr", item.expr, depth + 1))
        else:
            if (not isinstance(item, Expr)
                    or not isinstance(item.kind, str)
                    or not isinstance(item.ty, str)
                    or len(item.ty) > 16
                    or len(item.kind) > 16
                    or not isinstance(item.value, str)
                    or len(item.value) > _MAX_IR_TOKEN_LENGTH
                    or not isinstance(item.args, tuple)
                    or len(item.args) > 2):
                raise IRValidationError("invalid migration IR expression shape")
            for arg in item.args:
                pending.append(("expr", arg, depth + 1))


def check_function(function: Function) -> frozenset[str]:
    _preflight_shape(function)
    _require_pilot_identifier(function.name)
    if function.result not in NUMERIC or not function.body:
        raise IRValidationError("unsupported result or empty function")
    names: dict[str, str] = {}
    for name, ty in function.params:
        _require_pilot_identifier(name)
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
