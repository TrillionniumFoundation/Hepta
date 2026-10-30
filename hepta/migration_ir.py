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
_MAX_IR_TEXT_CHARS = 128
_MAX_IR_PARAMS = 64


def _bounded_text(value: object) -> bool:
    # Exact built-in strings only: a str subclass may override __format__ and
    # emit different code than the bytes checked or hashed by the IR validator.
    return type(value) is str and len(value) <= _MAX_IR_TEXT_CHARS
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
    if not _bounded_text(name) or not _SYMBOL.fullmatch(name) or name in _RESERVED:
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


# All public IR consumers (validation, emission, hashing) share a recursive
# implementation. Validate tree size iteratively before any recursive walk.
# These are deliberately conservative migration-subset limits, not a universal
# language-wide resource guarantee.
_MAX_IR_DEPTH = 64
_MAX_IR_NODES = 4096


def _check_structure_budget(function: Function) -> None:
    # Do not accept extensible record/tuple subclasses: their overridden
    # field access or iteration can change between validation and emission.
    if (type(function) is not Function or type(function.body) is not tuple
            or type(function.params) is not tuple
            or len(function.params) > _MAX_IR_PARAMS
            or not _bounded_text(function.name)
            or not _bounded_text(function.result)):
        raise IRValidationError("invalid migration IR function structure")
    for parameter in function.params:
        if (type(parameter) is not tuple or len(parameter) != 2
                or not all(_bounded_text(field) for field in parameter)):
            raise IRValidationError("invalid migration IR parameter structure")

    # Reject oversized tuples in O(1) before inspecting any child. A linear
    # type scan before this gate would make the declared node budget a poor
    # CPU bound for a direct caller-supplied IR.
    if len(function.body) > _MAX_IR_NODES:
        raise IRValidationError("migration IR node budget exceeded")
    if any(type(node) is not Stmt for node in function.body):
        raise IRValidationError("invalid migration IR function statement types")
    pending: list[tuple[Expr | Stmt, int]] = [(node, 1) for node in function.body]
    if len(pending) > _MAX_IR_NODES:
        raise IRValidationError("migration IR node budget exceeded")
    visited = 0
    while pending:
        node, depth = pending.pop()
        visited += 1
        if visited > _MAX_IR_NODES or depth > _MAX_IR_DEPTH:
            raise IRValidationError("migration IR depth or node budget exceeded")
        if type(node) is Expr:
            if not all(_bounded_text(field) for field in (node.kind, node.ty, node.value)):
                raise IRValidationError("invalid migration IR expression fields")
            if type(node.args) is not tuple:
                raise IRValidationError("invalid migration IR expression child types")
            if len(node.args) > _MAX_IR_NODES - visited - len(pending):
                raise IRValidationError("migration IR node budget exceeded")
            if any(type(child) is not Expr for child in node.args):
                raise IRValidationError("invalid migration IR expression child types")
            children = node.args
        elif type(node) is Stmt:
            if not _bounded_text(node.kind):
                raise IRValidationError("invalid migration IR statement kind")
            if type(node.then_body) is not tuple or type(node.else_body) is not tuple:
                raise IRValidationError("invalid migration IR statement branches")
            if 1 + len(node.then_body) + len(node.else_body) > _MAX_IR_NODES - visited - len(pending):
                raise IRValidationError("migration IR node budget exceeded")
            if (type(node.expr) is not Expr
                    or any(type(child) is not Stmt for child in node.then_body)
                    or any(type(child) is not Stmt for child in node.else_body)):
                raise IRValidationError("invalid migration IR statement child types")
            children = (node.expr,) + node.then_body + node.else_body
        else:
            raise IRValidationError("invalid migration IR tree node")
        if type(children) is not tuple:
            raise IRValidationError("invalid migration IR child sequence")
        if len(children) > _MAX_IR_NODES - visited - len(pending):
            raise IRValidationError("migration IR node budget exceeded")
        pending.extend((child, depth + 1) for child in children)


def check_function(function: Function) -> frozenset[str]:
    _check_structure_budget(function)
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


def _emit_expr_unchecked(expr: Expr) -> str:
    if expr.kind == "var":
        return expr.value
    if expr.kind == "literal":
        return f"({expr.value} as {expr.ty})"
    if expr.kind == "neg":
        return f"(-{_emit_expr_unchecked(expr.args[0])})"
    if expr.kind == "compare":
        return f"({_emit_expr_unchecked(expr.args[0])} {expr.value} {_emit_expr_unchecked(expr.args[1])})"
    if expr.kind == "arith":
        a, b = (_emit_expr_unchecked(arg) for arg in expr.args)
        if expr.ty == "u32":
            op = {"+": "wrapping_add", "-": "wrapping_sub", "*": "wrapping_mul"}[expr.value]
            return f"{op}({a}, {b})"
        return f"({a} {expr.value} {b})"
    raise IRValidationError("invalid expression")


def emit_expr(expr: Expr, *, bindings: tuple[tuple[str, str], ...] = ()) -> str:
    """Validate standalone expressions before emitting any raw source.

    This importable helper has no implicit parameter scope. Callers supplying
    variable references must provide explicit, validated parameter bindings.
    emit_function() instead validates the entire Function once and uses the
    private emitter only on that accepted structure.
    """
    if type(expr) is not Expr:
        raise IRValidationError("invalid standalone migration IR expression")
    if expr.ty == "bool":
        true_stmt = Stmt("return", Expr("literal", "i32", "1"))
        false_stmt = Stmt("return", Expr("literal", "i32", "0"))
        body = (Stmt("if", expr, (true_stmt,), (false_stmt,)),)
        result = "i32"
    else:
        body = (Stmt("return", expr),)
        result = expr.ty
    check_function(Function("expression_probe", bindings, result, body))
    return _emit_expr_unchecked(expr)


def _emit_body(body: tuple[Stmt, ...], indent: str) -> list[str]:
    stmt = body[0]
    if stmt.kind == "return":
        return [indent + "return " + _emit_expr_unchecked(stmt.expr) + ";"]
    return ([indent + "if " + _emit_expr_unchecked(stmt.expr) + " {"]
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
