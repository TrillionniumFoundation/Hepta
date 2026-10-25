"""Clang-AST C scalar migration pilot. Strict subset; never silent rewriting.

Only independent pure integer functions are candidates. No pointers, global
state, casts, user-defined types or C++ are accepted. Syntax/semantic validation
of emitted Hepta is mandatory before writing. The source C semantics and target
ABI are *not* generally proven equivalent by this migration pilot.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import re
import tempfile

from .clang_capture import CaptureRejected, run_bounded

_IDENT = re.compile(r"[A-Za-z_][A-Za-z_0-9]*\Z")
_TYPES = {"int32_t": "i32", "uint32_t": "u32", "int64_t": "i64", "uint64_t": "u64",
          "int": "i32", "unsigned int": "u32", "long long": "i64", "unsigned long long": "u64",
          "long": "i64", "unsigned long": "u64"}
_ARITH = {"+", "-", "*"}
_DIVMOD = {"/", "%"}
_LOGICAL = {"&&", "||"}
_BITS = {"&", "|", "^"}
_SHIFTS = {"<<", ">>"}
_CMP = {"==", "!=", "<", "<=", ">", ">="}
_CASTS = {"LValueToRValue", "NoOp"}
# Original spelling -> (Hepta scalar type, Clang VarDecl ID, emitted identifier).
# The third field allows hygienic names for loop-scoped variables without
# manufacturing C++ lexical scopes or trusting variable spelling alone.
_Local = tuple[str, str, str]


class MigrationRejected(ValueError):
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


def _run(args: list[str], *, input_text: str | None = None) -> str:
    try:
        proc = run_bounded(args, input_text=input_text, timeout=30,
                           stdout_limit=32_000_000, stderr_limit=1_000_000)
    except CaptureRejected as exc:
        code = "E_CLANG_SIZE" if exc.code == "E_CAPTURE_OUTPUT_SIZE" else "E_CLANG_ENV"
        raise MigrationRejected(code, f"{exc.code}: {exc}") from exc
    if proc.returncode:
        raise MigrationRejected("E_CLANG_REJECT", proc.stderr[-5000:] or "Clang exited with failure")
    return proc.stdout


def _load_bounded_clang_ast(raw: str, *, max_bytes: int = 32_000_000,
                            max_depth: int = 128, max_nodes: int = 250_000) -> dict:
    """Bound the strict C/C++ AST after file-backed Clang capture.

    The capture layer bounds tool output bytes, but json.loads and recursive
    scalar walkers need independent shape limits. Verify all JSON values with
    an iterative worklist before passing source nodes to the single lowerer.
    This does not sandbox Clang or establish source semantic equivalence.
    """
    if (not isinstance(raw, str) or any(type(n) is not int or n <= 0
                                        for n in (max_bytes, max_depth, max_nodes))):
        raise MigrationRejected("E_CLANG_AST_LIMIT", "Invalid AST input or budgets")
    if len(raw) > max_bytes or len(raw.encode("utf-8")) > max_bytes:
        raise MigrationRejected("E_CLANG_AST_LIMIT", "Clang AST text exceeds byte budget")

    def reject_constant(value: str):
        raise ValueError("Nonfinite JSON constant: " + value)

    try:
        root = json.loads(raw, parse_constant=reject_constant)
    except (ValueError, RecursionError, OverflowError) as exc:
        raise MigrationRejected("E_CLANG_AST_FORMAT",
                                "Malformed or excessively nested Clang AST JSON") from exc
    if not isinstance(root, dict) or root.get("kind") != "TranslationUnitDecl":
        raise MigrationRejected("E_CLANG_AST_FORMAT", "Expected a complete Clang translation unit")
    pending = [(root, 0)]
    visited = 0
    while pending:
        value, depth = pending.pop()
        visited += 1
        if visited > max_nodes or depth > max_depth:
            raise MigrationRejected("E_CLANG_AST_LIMIT", "AST node/depth budget exceeded")
        if isinstance(value, dict):
            pending.extend((part, depth + 1) for part in value.values())
        elif isinstance(value, list):
            pending.extend((part, depth + 1) for part in value)
        elif not (value is None or isinstance(value, (str, int, bool))
                  or (type(value) is float and math.isfinite(value))):
            raise MigrationRejected("E_CLANG_AST_FORMAT", "Unsupported Clang JSON AST value")
    return root


def _data_model(clang: str) -> dict:
    macros = _run([clang, "-std=c11", "-dM", "-E", "-x", "c", "-"], input_text="")
    defines = dict(m.groups() for line in macros.splitlines()
                   if (m := re.fullmatch(r"#define (__SIZEOF_(?:INT|LONG|LONG_LONG|POINTER)__)(?:\s+)(\d+)", line)))
    char_bits = re.search(r"(?m)^#define __CHAR_BIT__\s+(\d+)\s*$", macros)
    if (defines.get("__SIZEOF_INT__") != "4" or defines.get("__SIZEOF_LONG_LONG__") != "8"
            or char_bits is None or char_bits.group(1) != "8"):
        raise MigrationRejected("E_C_DATA_MODEL", "pilot requires 8-bit C bytes, 32-bit int and 64-bit long long")
    return {"char_bit": 8, "sizeof_int": 4, "sizeof_long": int(defines.get("__SIZEOF_LONG__", 0)),
            "sizeof_long_long": 8, "sizeof_pointer": int(defines.get("__SIZEOF_POINTER__", 0)),
            "target": _run([clang, "-dumpmachine"]).strip(),
            "clang_version": _run([clang, "--version"]).splitlines()[0]}


def _typ(qual: str, model: dict) -> str:
    qual = qual.strip()
    resolved = _TYPES.get(qual)
    if resolved is None or (qual in {"long", "unsigned long"} and model["sizeof_long"] != 8):
        raise MigrationRejected("E_C_TYPE", f"Unsupported or target-dependent C type: {qual}")
    return resolved


def _decl_type(node: dict, model: dict) -> str:
    t = node.get("type", {})
    return _typ(t.get("qualType", ""), model)


def _expr(node: dict, args: dict[str, str], model: dict, expected: str,
          locals: dict[str, _Local] | None = None) -> tuple[str, str]:
    # Locals are admitted only through the function-prefix declaration gate.
    # Clang declaration identity is checked on every read: matching by spelling
    # alone would accept unrelated or out-of-scope VarDecl nodes.
    locals = {} if locals is None else locals
    kind = node.get("kind")
    inner = node.get("inner", [])
    if kind in {"ImplicitCastExpr", "ParenExpr"}:
        if len(inner) != 1:
            raise MigrationRejected("E_C_AST", "Malformed Clang cast/parenthesis")
        if kind == "ImplicitCastExpr":
            cast = node.get("castKind")
            if cast == "IntegralCast" and inner[0].get("kind") == "IntegerLiteral" and _decl_type(node, model) == expected:
                # Only compile-time constants provably representable in the target
                # type may undergo automatic widening/promotion in this pilot.
                return _expr(inner[0], args, model, expected, locals)
            if cast not in _CASTS:
                raise MigrationRejected("E_C_CAST", "C integer/pointer casts require a checked target representation")
        return _expr(inner[0], args, model, expected, locals)
    if kind == "IntegerLiteral":
        try:
            value = int(node["value"])
        except (KeyError, ValueError) as exc:
            raise MigrationRejected("E_C_INTEGER", "Unsupported integer literal") from exc
        width = 32 if expected.endswith("32") else 64
        signed = expected.startswith("i")
        minimum, maximum = (-(1 << (width-1)), (1 << (width-1)) - 1) if signed else (0, (1 << width) - 1)
        if not minimum <= value <= maximum:
            raise MigrationRejected("E_C_INTEGER", "Integer literal is outside the target type")
        return str(value), expected
    if kind == "DeclRefExpr":
        decl = node.get("referencedDecl", {})
        name = decl.get("name", "")
        if decl.get("kind") == "ParmVarDecl":
            actual = args.get(name)
        elif decl.get("kind") == "VarDecl":
            local = locals.get(name)
            actual = local[0] if (local is not None
                                  and isinstance(decl.get("id"), str)
                                  and decl["id"] == local[1]) else None
        else:
            actual = None
        if actual is None:
            raise MigrationRejected("E_C_REF", "Reference is not a checked parameter or initialized local")
        if actual != expected:
            raise MigrationRejected("E_C_PROMOTION", "C integer promotions require a separate checked lowering")
        return (local[2] if decl.get("kind") == "VarDecl" else name), expected
    if kind == "UnaryOperator" and node.get("opcode") == "!" and len(inner) == 1:
        # Accept logical negation only when its operand is itself a checked
        # Boolean/comparison expression. General C integer truthiness remains
        # outside this profile; !x must not turn into a guessed Hepta cast.
        if expected != "bool" or node.get("type", {}).get("qualType") not in {"int", "bool"}:
            raise MigrationRejected("E_C_LOGICAL", "Logical negation requires a Boolean condition")
        operand, actual = _predicate(inner[0], args, model, locals)
        if actual != "bool":
            raise MigrationRejected("E_C_LOGICAL", "Logical operand must be a checked Boolean expression")
        return f"(!{operand})", "bool"
    if kind == "UnaryOperator" and node.get("opcode") in {"+", "-", "~"} and len(inner) == 1:
        op = node["opcode"]
        # The integral promotions of narrower C integer types change the
        # width/representation of ~ and -; this profile only admits exact
        # u32/u64 (or signed +/-) operations whose result is already checked.
        if _decl_type(node, model) != expected:
            raise MigrationRejected("E_C_UNARY_PROMOTION", "C unary expression has an unmodeled promotion")
        rendered, typ = _expr(inner[0], args, model, expected, locals)
        if op == "~":
            if not expected.startswith("u"):
                raise MigrationRejected("E_C_BITWISE", "Signed bitwise complement is not in the portable profile")
            # Hepta integer ! is fixed-width bitwise NOT, not Boolean negation.
            return f"(!{rendered})", typ
        if op == "-" and expected.startswith("u"):
            # Unsigned C negation is well-defined modulo 2^N, not checked
            # signed arithmetic. Reuse the existing zero-cost builtin.
            return f"wrapping_sub(0, {rendered})", typ
        return f"({op}{rendered})", typ
    if kind == "BinaryOperator" and len(inner) == 2:
        op = node.get("opcode")
        if op in _LOGICAL:
            # C/C++ logical operators return int/bool, respectively. Accept
            # only pure comparison/Boolean operands and retain their original
            # left-to-right short-circuit behavior through Hepta && / ||.
            if expected != "bool" or node.get("type", {}).get("qualType") not in {"int", "bool"}:
                raise MigrationRejected("E_C_LOGICAL", "Logical operations are supported only as Boolean conditions")
            left, left_type = _predicate(inner[0], args, model, locals)
            right, right_type = _predicate(inner[1], args, model, locals)
            if (left_type, right_type) != ("bool", "bool"):
                raise MigrationRejected("E_C_LOGICAL", "Logical operands must have checked Boolean semantics")
            return f"({left} {op} {right})", "bool"
        if op in _CMP:
            # C comparisons yield int, whereas Hepta comparisons yield bool.
            # This expression is only consumed as a statement condition.
            lhs_type = _decl_type(inner[0], model)
            left, _ = _expr(inner[0], args, model, lhs_type, locals)
            right, _ = _expr(inner[1], args, model, lhs_type, locals)
            return f"({left} {op} {right})", "bool"
        if op not in _ARITH | _BITS | _SHIFTS | _DIVMOD:
            raise MigrationRejected("E_C_OPERATOR", f"Unsupported C operator: {op}")
        if op in _DIVMOD:
            # C11/C++20 and Hepta truncate signed division toward zero,
            # and integer remainder follows that quotient. Zero divisors,
            # and signed MIN / -1, are undefined in C/C++ and checked/aborted
            # in Hepta. Require Clang's *evaluated* scalar result type rather
            # than silently losing usual arithmetic conversions.
            if (_decl_type(node, model) != expected
                    or _decl_type(inner[0], model) != expected
                    or _decl_type(inner[1], model) != expected):
                raise MigrationRejected("E_C_DIVMOD_PROMOTION",
                                        "Division operands/result need the exact checked scalar type")
            # Clang may already have an IntegralCast on a representable
            # literal. The existing _expr cast gate checks that case; any
            # unmodeled promotions still reject rather than changing signedness.
        if op in _BITS and expected.startswith("i"):
            raise MigrationRejected("E_C_BITWISE", "Signed C bitwise operations require target-specific semantics")
        # Division and modulo are evaluated once per operand and use Hepta's
        # checked integer operators. No new C-defined behavior is claimed
        # for signed overflow or zero divisors.
        # Unsigned C11/C++20 shifts match Hepta's fixed-width shift for all
        # defined counts (0 <= count < bit width). Hepta aborts for bad counts;
        # those inputs are already undefined in the original C/C++ program.
        # Signed shifts have different implementation/overflow obligations.
        if op in _SHIFTS and not expected.startswith("u"):
            raise MigrationRejected("E_C_SHIFT_SIGNED", "Signed C/C++ shifts require a separate defined-behavior proof")
        if op in _SHIFTS:
            # C11/C++20 promote the two operands independently: the left
            # operand determines the result type, but the shift count may be
            # an int/i32, u32, i64 or u64. A shared expected type silently
            # rejects valid mixed-width callers (and invites wrong casts).
            if _decl_type(node, model) != expected or _decl_type(inner[0], model) != expected:
                raise MigrationRejected("E_C_SHIFT_PROMOTION",
                                        "Shift result/left promotions are outside the defined scalar profile")
            left, _ = _expr(inner[0], args, model, expected, locals)
            count_type = _decl_type(inner[1], model)
            if count_type not in {"i32", "u32", "i64", "u64"}:
                raise MigrationRejected("E_C_SHIFT_COUNT", "Unsupported C shift count type")
            right, _ = _expr(inner[1], args, model, count_type, locals)
            # Hepta's current shift checker expects the same integer type on
            # each side. On C-defined counts [0,width) this cast is exact;
            # negative or oversized counts are already undefined in C/C++,
            # and are not claimed equivalent to Hepta's checked panic.
            if count_type != expected:
                right = f"({right} as {expected})"
        else:
            left, _ = _expr(inner[0], args, model, expected, locals)
            right, _ = _expr(inner[1], args, model, expected, locals)
        if op in _ARITH and expected.startswith("u"):
            builtin = {"+": "wrapping_add", "-": "wrapping_sub", "*": "wrapping_mul"}[op]
            return f"{builtin}({left}, {right})", expected
        return f"({left} {op} {right})", expected
    raise MigrationRejected("E_C_EXPRESSION", f"Unsupported C expression: {kind}")


def _predicate(node: dict, args: dict[str, str], model: dict,
               locals: dict[str, _Local]) -> tuple[str, str]:
    """Convert a restricted side-effect-free C/C++ scalar truth value to bool.

    Strict logical and comparison syntax is delegated to the existing _expr
    owner, not reimplemented. Integer truthiness has precise source semantics:
    zero is false, every nonzero value is true. Pointer/foreign conversion,
    overloads and hidden side effects still fail closed in _expr.
    """
    if not isinstance(node, dict):
        raise MigrationRejected("E_C_PREDICATE", "Malformed predicate AST")
    kind = node.get("kind")
    operands = node.get("inner", [])
    if not isinstance(operands, list):
        raise MigrationRejected("E_C_PREDICATE", "Malformed predicate operands")
    if kind in {"ParenExpr", "ImplicitCastExpr"}:
        if (len(operands) != 1 or (kind == "ImplicitCastExpr" and
                                  node.get("castKind") not in _CASTS | {"IntegralToBoolean"})):
            raise MigrationRejected("E_C_PREDICATE", "Unsupported predicate cast")
        return _predicate(operands[0], args, model, locals)
    if ((kind == "BinaryOperator" and node.get("opcode") in _CMP | _LOGICAL)
            or (kind == "UnaryOperator" and node.get("opcode") == "!")):
        return _expr(node, args, model, "bool", locals)
    # All other admitted predicates must first be valid scalar values in the
    # existing source lowerer. No functions, assignment expressions, ++/--,
    # pointer access or unmodeled integer promotions enter this fallback.
    typ = _decl_type(node, model)
    if typ not in {"i32", "u32", "i64", "u64"}:
        raise MigrationRejected("E_C_PREDICATE", "Unsupported integer truth value")
    value, actual = _expr(node, args, model, typ, locals)
    if actual != typ:
        raise MigrationRejected("E_C_PREDICATE", "Scalar type changed in predicate")
    return f"({value} != 0)", "bool"


def _ternary(node: dict, args: dict[str, str], model: dict, expected: str,
             locals: dict[str, _Local]) -> tuple[str, str, str]:
    """Translate only type-preserving, side-effect-free scalar branches.

    C's comparison result may have integer type; our _expr normalizes the
    condition to bool. The branch expressions themselves remain strictly
    restricted by the same C/C++ scalar expression checker.
    """
    if node.get("kind") != "ConditionalOperator":
        raise MigrationRejected("E_C_CONDITIONAL", "Expected ordinary ternary expression")
    children = node.get("inner", [])
    if len(children) != 3 or _decl_type(node, model) != expected:
        raise MigrationRejected("E_C_CONDITIONAL", "Ternary result type is unsupported")
    condition, condition_type = _predicate(children[0], args, model, locals)
    positive, positive_type = _expr(children[1], args, model, expected, locals)
    negative, negative_type = _expr(children[2], args, model, expected, locals)
    if (condition_type != "bool" or positive_type != expected or negative_type != expected):
        raise MigrationRejected("E_C_CONDITIONAL", "Ternary branches change scalar type")
    return condition, positive, negative


def _stmt(node: dict, args: dict[str, str], model: dict, ret: str, depth: int = 1,
          locals: dict[str, _Local] | None = None,
          reserved_names: set[str] | None = None) -> list[str]:
    locals = {} if locals is None else locals
    indent = "    " * depth
    kind = node.get("kind")
    children = node.get("inner", [])
    if kind == "CompoundStmt":
        return [line for child in children
                for line in _stmt(child, args, model, ret, depth, locals, reserved_names)]
    if kind == "BinaryOperator" and node.get("opcode") == "=" and len(children) == 2:
        target = children[0]
        ref = target.get("referencedDecl", {}) if target.get("kind") == "DeclRefExpr" else {}
        name = ref.get("name")
        local = locals.get(name)
        if (local is None or ref.get("kind") != "VarDecl"
                or ref.get("id") != local[1]):
            raise MigrationRejected("E_C_ASSIGN", "Only a known initialized scalar local may be assigned")
        if children[1].get("kind") == "ConditionalOperator":
            test, on_true, on_false = _ternary(children[1], args, model, local[0], locals)
            return [f"{indent}if {test} {{",
                    f"{indent}    {local[2]} = {on_true};",
                    f"{indent}}} else {{",
                    f"{indent}    {local[2]} = {on_false};",
                    f"{indent}}}"]
        value, value_type = _expr(children[1], args, model, local[0], locals)
        if value_type != local[0]:
            raise MigrationRejected("E_C_ASSIGN", "Assignment type conversion not in checked subset")
        return [f"{indent}{local[2]} = {value};"]
    if kind == "UnaryOperator" and node.get("opcode") in {"++", "--"} and len(children) == 1:
        # Standalone pre/post increment/decrement has no observed value.
        # Only the exact Clang declaration ID of a validated local is admitted.
        operand = children[0]
        ref = operand.get("referencedDecl", {}) if isinstance(operand, dict) and operand.get("kind") == "DeclRefExpr" else {}
        name = ref.get("name")
        local = locals.get(name)
        if (local is None or ref.get("kind") != "VarDecl" or ref.get("id") != local[1]
                or _decl_type(node, model) != local[0]):
            raise MigrationRejected("E_C_INCREMENT", "Only increment/decrement of an initialized scalar local is supported")
        op = "+" if node["opcode"] == "++" else "-"
        emitted = local[2]
        if local[0].startswith("u"):
            builtin = "wrapping_add" if op == "+" else "wrapping_sub"
            result = f"{builtin}({emitted}, 1)"
        else:
            result = f"({emitted} {op} 1)"
        return [f"{indent}{emitted} = {result};"]
    if kind == "ForStmt":
        # Clang's five slots: initializer, condition-variable declaration,
        # condition, increment, and body. For the strict subset no continue,
        # break, goto, in-loop declaration, or observed step return exists.
        # Thus init; while (condition) { body; increment; } is equivalent
        # on the source language's defined signed-arithmetic input domain.
        if (len(children) != 5 or children[1] is not None
                or any(part is None for part in (children[0], children[2], children[3], children[4]))):
            raise MigrationRejected("E_C_FOR_SHAPE", "For requires explicit init, comparison, step and body")
        initial, _, condition, advance, loop_body = children
        if (loop_body.get("kind") != "CompoundStmt"
                or not ((advance.get("kind") == "BinaryOperator" and advance.get("opcode") == "=")
                        or (advance.get("kind") == "UnaryOperator"
                            and advance.get("opcode") in {"++", "--"}))):
            raise MigrationRejected("E_C_FOR_SHAPE", "For requires scalar step and compound body")
        scoped_locals = locals
        if initial.get("kind") == "DeclStmt":
            # This C11/C++20 for-initializer lives only through condition,
            # body and step. The scalar has no destructor or pointer aliases.
            # Lift its declaration to the equivalent start of a new while
            # segment, but rename by stable source offset to prevent capture
            # of a preceding/succeeding loop's same-spelled identifier.
            defs = initial.get("inner", [])
            if len(defs) != 1 or defs[0].get("kind") != "VarDecl":
                raise MigrationRejected("E_C_FOR_DECL", "For supports exactly one scalar declaration")
            var = defs[0]
            var_name = var.get("name")
            var_id = var.get("id")
            offset = var.get("loc", {}).get("offset")
            if (not isinstance(var_name, str) or not _IDENT.fullmatch(var_name)
                    or var_name.startswith("__") or not isinstance(var_id, str)
                    or not isinstance(offset, int) or offset < 0):
                raise MigrationRejected("E_C_FOR_DECL", "For variable identity is missing or invalid")
            if (var.get("storageClass") is not None or var.get("tls") is not None
                    or var.get("constexpr") or var.get("isConstexpr") or var.get("inline")
                    or var.get("init") is None or len(var.get("inner", [])) != 1):
                raise MigrationRejected("E_C_FOR_DECL", "For variable must be a single initialized automatic scalar")
            emitted = f"hepta_for_{offset}_{var_name}"
            if (reserved_names is None or emitted in reserved_names
                    or emitted in (binding[2] for binding in locals.values())):
                raise MigrationRejected("E_C_FOR_HYGIENE", "For variable collides with a source or generated name")
            var_type = _decl_type(var, model)
            initializer, actual = _expr(var["inner"][0], args, model, var_type, locals)
            if actual != var_type:
                raise MigrationRejected("E_C_FOR_DECL", "For initializer changes scalar type")
            scoped_locals = dict(locals)
            scoped_locals[var_name] = (var_type, var_id, emitted)
            initial_lines = [f"{indent}let mut {emitted}: {var_type} = {initializer};"]
        elif initial.get("kind") == "BinaryOperator" and initial.get("opcode") == "=":
            initial_lines = _stmt(initial, args, model, ret, depth, locals, reserved_names)
        else:
            raise MigrationRejected("E_C_FOR_SHAPE", "For requires a checked local assignment or declaration")
        predicate, predicate_type = _predicate(condition, args, model, scoped_locals)
        if predicate_type != "bool":
            raise MigrationRejected("E_C_CONDITION", "Only Boolean comparison for conditions are supported")
        lines = initial_lines + [f"{indent}while {predicate} {{"]
        lines.extend(_stmt(loop_body, args, model, ret, depth + 1, scoped_locals, reserved_names))
        lines.extend(_stmt(advance, args, model, ret, depth + 1, scoped_locals, reserved_names))
        lines.append(f"{indent}}}")
        return lines
    if kind == "DoStmt" and len(children) == 2:
        # do {body} while (condition) is equivalent to body; while (cond)
        # {body} only when the body has no declarations or jump-control
        # constructs. Those would create different lifetimes/control flow
        # after duplication, and must remain outside this strict scalar L1.
        body, condition = children
        if body.get("kind") != "CompoundStmt":
            raise MigrationRejected("E_C_DO_SHAPE", "Do loop body must be braced")
        stack = [body]
        while stack:
            current = stack.pop()
            if not isinstance(current, dict):
                raise MigrationRejected("E_C_DO_SHAPE", "Malformed do-loop AST")
            if current.get("kind") in {"DeclStmt", "DoStmt", "ForStmt",
                                       "BreakStmt", "ContinueStmt", "GotoStmt", "ReturnStmt"}:
                raise MigrationRejected("E_C_DO_SCOPE", "Do loop has unsupported declarations or jumps")
            stack.extend(item for item in current.get("inner", []) if isinstance(item, dict))
        rendered, actual = _predicate(condition, args, model, locals)
        if actual != "bool":
            raise MigrationRejected("E_C_DO_CONDITION", "Only explicit Boolean do-loop comparisons are supported")
        first = _stmt(body, args, model, ret, depth, locals, reserved_names)
        repeated = _stmt(body, args, model, ret, depth + 1, locals, reserved_names)
        if sum(map(len, first + repeated)) > 32768:
            raise MigrationRejected("E_C_DO_LIMIT", "Duplicated do-loop body exceeds bounded scalar profile")
        return first + [f"{indent}while {rendered} {{"] + repeated + [f"{indent}}}"]
    if kind == "WhileStmt" and len(children) == 2:
        condition, condition_type = _predicate(children[0], args, model, locals)
        if condition_type != "bool":
            raise MigrationRejected("E_C_CONDITION", "Only explicit Boolean while conditions are supported")
        body = children[1]
        if body.get("kind") != "CompoundStmt":
            raise MigrationRejected("E_C_LOOP", "While loop body requires an explicit compound statement")
        lines = [f"{indent}while {condition} {{"]
        lines.extend(_stmt(body, args, model, ret, depth + 1, locals, reserved_names))
        lines.append(f"{indent}}}")
        return lines
    if kind == "ReturnStmt" and len(children) == 1:
        if children[0].get("kind") == "ConditionalOperator":
            test, on_true, on_false = _ternary(children[0], args, model, ret, locals)
            return [f"{indent}if {test} {{",
                    f"{indent}    return {on_true};",
                    f"{indent}}} else {{",
                    f"{indent}    return {on_false};",
                    f"{indent}}}"]
        expression, typ = _expr(children[0], args, model, ret, locals)
        if typ != ret:
            raise MigrationRejected("E_C_RETURN", "C comparison or implicit conversion is not a Hepta integer return")
        return [f"{indent}return {expression};"]
    if kind == "IfStmt" and len(children) in (2, 3):
        cond, typ = _predicate(children[0], args, model, locals)
        if typ != "bool":
            raise MigrationRejected("E_C_CONDITION", "C integer truthiness requires an explicit checked conversion")
        result = [f"{indent}if {cond} {{"]
        result.extend(_stmt(children[1], args, model, ret, depth + 1, locals, reserved_names))
        result.append(f"{indent}}}")
        if len(children) == 3:
            result.append(f"{indent}else {{")
            result.extend(_stmt(children[2], args, model, ret, depth + 1, locals, reserved_names))
            result.append(f"{indent}}}")
        return result
    raise MigrationRejected("E_C_STATEMENT", f"Unsupported C statement: {kind}")


def _function(decl: dict, model: dict) -> dict:
    name = decl.get("name", "")
    if not _IDENT.fullmatch(name) or name.startswith("__"):
        raise MigrationRejected("E_C_NAME", "Unsupported C function identifier")
    typ = decl.get("type", {}).get("qualType", "")
    if "(" not in typ:
        raise MigrationRejected("E_C_FUNCTION", "Missing C function signature")
    if typ.endswith("()") or decl.get("storageClass") or decl.get("inline") or decl.get("isImplicit"):
        raise MigrationRejected("E_C_FUNCTION", "Unprototyped, static, inline or implicit functions are unsupported")
    ret = _typ(typ.split("(", 1)[0], model)
    parts = decl.get("inner", [])
    if any(x.get("kind") not in {"ParmVarDecl", "CompoundStmt"} for x in parts):
        raise MigrationRejected("E_C_ATTRIBUTE", "Function attributes or other declarations require explicit ABI lowering")
    body = [x for x in parts if x.get("kind") == "CompoundStmt"]
    if len(body) != 1:
        raise MigrationRejected("E_C_FUNCTION", "Only functions with a single C compound body are supported")
    params = [x for x in parts if x.get("kind") == "ParmVarDecl"]
    if "..." in typ or len(params) > 32:
        raise MigrationRejected("E_C_FUNCTION", "Variadic or oversized C function signature")
    args = {}
    for p in params:
        n = p.get("name", "")
        if not _IDENT.fullmatch(n) or n in args or n.startswith("__"):
            raise MigrationRejected("E_C_NAME", "Unnamed, duplicate or reserved C parameter")
        args[n] = _decl_type(p, model)
    # Guard hygienic generated loop names against every original source
    # variable in this function (including nested and later declarations).
    reserved_names = set(args)
    pending = [body[0]]
    while pending:
        node = pending.pop()
        if not isinstance(node, dict):
            continue
        if node.get("kind") in {"VarDecl", "ParmVarDecl"}:
            declared = node.get("name")
            if isinstance(declared, str):
                reserved_names.add(declared)
        pending.extend(child for child in node.get("inner", []) if isinstance(child, dict))
    # Deliberately narrow scope recovery: initialized local declarations must
    # be a simple prefix of the function's top-level block. Nested declarations,
    # shadowing, multiple declarators and arbitrary initialization are rejected.
    # This guarantees every local use is in its declared scope without claiming
    # support for general C/C++ lexical scopes, lifetimes or definite assignment.
    locals: dict[str, _Local] = {}
    rendered: list[str] = []
    saw_executable = False
    for item in body[0].get("inner", []):
        if item.get("kind") == "DeclStmt":
            if saw_executable:
                raise MigrationRejected("E_C_LOCAL_SCOPE", "Local declarations must precede executable statements")
            decls = item.get("inner", [])
            if len(decls) != 1 or decls[0].get("kind") != "VarDecl":
                raise MigrationRejected("E_C_LOCAL_DECL", "Only single scalar local declarations are supported")
            var = decls[0]
            # Static / thread-local / constexpr declarations are not ordinary
            # automatic mutable locals. Dropping their storage duration would
            # silently change original C or C++ program behavior.
            if (var.get("storageClass") is not None or var.get("tls") is not None
                    or var.get("constexpr") or var.get("isConstexpr")
                    or var.get("inline")):
                raise MigrationRejected("E_C_LOCAL_STORAGE", "Nonautomatic or special local storage is unsupported")
            local_name = var.get("name", "")
            local_id = var.get("id")
            if (not _IDENT.fullmatch(local_name) or local_name.startswith("__")
                    or local_name in args or local_name in locals
                    or not isinstance(local_id, str)):
                raise MigrationRejected("E_C_LOCAL_NAME", "Local is unnamed, shadowed or lacks Clang identity")
            if var.get("init") is None or len(var.get("inner", [])) != 1:
                raise MigrationRejected("E_C_LOCAL_INIT", "Locals require one explicit scalar initializer")
            local_type = _decl_type(var, model)
            initial, init_type = _expr(var["inner"][0], args, model, local_type, locals)
            if init_type != local_type:
                raise MigrationRejected("E_C_LOCAL_INIT", "Local initializer changes scalar type")
            rendered.append(f"    let mut {local_name}: {local_type} = {initial};")
            locals[local_name] = (local_type, local_id, local_name)
        else:
            saw_executable = True
            rendered.extend(_stmt(item, args, model, ret, locals=locals, reserved_names=reserved_names))
    if not rendered:
        raise MigrationRejected("E_C_EMPTY", "Empty C function cannot satisfy a scalar return")
    signature = ", ".join(f"{p}: {t}" for p, t in args.items())
    # The fully closed scalar subset contains no calls, allocation, blocking,
    # suspension or task creation. Preserve these verified limits as explicit
    # Hepta resource contracts instead of relying on a comment-level claim.
    resources = "resources {heap_allocations=0;may_block=false;may_suspend=false;may_spawn=false;}"
    source = (f"export \"C\" fn {name}({signature}) -> {ret} effects {{panic}} "
              + resources + " {\n" + "\n".join(rendered) + "\n}\n")
    return {"name": name, "source": source, "params": args, "returns": ret}


def migrate_c(path: str | Path, output: str | Path, *, clang: str = "clang") -> dict:
    """Return explicit migration evidence; never write a partial conversion."""
    src, dest = Path(path).resolve(), Path(output).absolute()
    report = {"schema": "hepta.migrate-c.v0", "ok": False, "status": "rejected",
              "profile": "strict_scalar_pilot", "source": str(src), "output": str(dest),
              "source_equivalence_proved": False, "whole_language_soundness_proved": False,
              "native_validation": "not_run", "converted": [], "rejected": []}
    try:
        if (src == dest or not src.is_file() or src.suffix != ".c"
                or dest.suffix != ".hepta" or dest.is_symlink()):
            raise MigrationRejected("E_C_PATH", "Require existing .c source and distinct non-symlink .hepta destination")
        source = src.read_bytes()
        if len(source) > 256_000:
            raise MigrationRejected("E_C_SIZE", "Pilot source exceeds 256 KB")
        report["source_sha256"] = hashlib.sha256(source).hexdigest()
        model = _data_model(clang)
        report["target_model"] = model
        # A strict single-file source snapshot is insufficient when included
        # headers/macros influence the actual Clang AST. Bind a real -E/-P
        # preprocessing snapshot to the same compiler/target, then compare it
        # again before publishing any generated Hepta. This is not a complete
        # compilation database or external-header provenance attestation.
        preprocess_cmd = [clang, "-std=c11", "-E", "-P", str(src)]
        preprocessed_sha256 = hashlib.sha256(_run(preprocess_cmd).encode("utf-8")).hexdigest()
        report["preprocessed_sha256"] = preprocessed_sha256
        ast_json = _run([clang, "-std=c11", "-fsyntax-only", "-Werror",
                        "-Xclang", "-ast-dump=json", str(src)])
        root = _load_bounded_clang_ast(ast_json)
        if root.get("kind") != "TranslationUnitDecl":
            raise MigrationRejected("E_C_AST", "Clang did not return a translation unit")
        declarations = []
        unsupported_toplevel = []
        active_file = None
        for node in root.get("inner", []):
            node_file = node.get("loc", {}).get("file")
            if node_file:
                active_file = Path(node_file).resolve()
            loc = node.get("loc", {})
            if active_file != src:
                continue
            begin = node.get("range", {}).get("begin", {}).get("offset")
            end = node.get("range", {}).get("end", {}).get("offset")
            if not isinstance(begin, int) or not isinstance(end, int) or not (0 <= begin <= end < len(source)):
                continue
            if node.get("kind") == "FunctionDecl" and any(
                    x.get("kind") == "CompoundStmt" for x in node.get("inner", [])):
                declarations.append(node)
            else:
                # The pilot claims a whole-translation-unit conversion.
                # Globals, typedefs and prototypes may carry ABI/linkage state:
                # never accept the file and silently omit those declarations.
                unsupported_toplevel.append(f"{node.get('kind')}: {node.get('name', '<anonymous>')}")
        if unsupported_toplevel:
            raise MigrationRejected("E_C_TOPLEVEL", "Unsupported source declarations: " +
                                    ", ".join(unsupported_toplevel[:12]))
        if not declarations:
            raise MigrationRejected("E_C_NO_FUNCTIONS", "No ordinary C function definitions found")
        translated = []
        seen = set()
        for decl in declarations:
            try:
                part = _function(decl, model)
                if part["name"] in seen:
                    raise MigrationRejected("E_C_DUPLICATE", "Duplicate function or overload")
                seen.add(part["name"])
                translated.append(part)
            except MigrationRejected as exc:
                report["rejected"].append({"name": decl.get("name"), "code": exc.code, "message": str(exc)})
        if report["rejected"]:
            report["status"] = "unsupported_source"
            return report
        program = "module c_migrated;\n\n" + "\n".join(x["source"] for x in translated)
        if src.read_bytes() != source:
            raise MigrationRejected("E_C_SOURCE_RACE", "C source changed during Clang analysis")
        from .checker import check
        from .parser import parse
        checked = check(parse(program, str(dest)))
        if not checked.ok:
            report["rejected"] = [x.to_dict() for x in checked.diagnostics]
            report["status"] = "hepta_frontend_rejected"
            return report
        if dest.exists():
            raise MigrationRejected("E_C_EXISTS", "Refusing to overwrite an existing .hepta destination")
        dest.parent.mkdir(parents=True, exist_ok=True)
        if dest.is_symlink():
            raise MigrationRejected("E_C_SYMLINK", "Refusing a symlink destination")
        staged = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=dest.parent,
                                             prefix=".hepta-migrate-", delete=False) as f:
                staged = Path(f.name)
                f.write(program)
                f.flush()
                os.fsync(f.fileno())
            if src.read_bytes() != source:
                raise MigrationRejected("E_C_SOURCE_RACE", "C source changed before publication")
            if hashlib.sha256(_run(preprocess_cmd).encode("utf-8")).hexdigest() != preprocessed_sha256:
                raise MigrationRejected("E_C_PREPROCESS_RACE", "Clang preprocessed source/headers changed before publication")
            # Atomic same-filesystem hard-link publication: the completely
            # written, fsynced staged inode becomes visible in one operation.
            # os.link fails without replacing a concurrent existing name.
            # This is NOT a multi-file transaction or proof of crash durability.
            try:
                os.link(staged, dest)
            except FileExistsError as exc:
                raise MigrationRejected("E_C_EXISTS", "Destination appeared during conversion") from exc
            except OSError as exc:
                raise MigrationRejected("E_C_PUBLISH", "Atomic publish unavailable: " + str(exc)) from exc
        finally:
            if staged is not None:
                staged.unlink(missing_ok=True)
        report.update({"ok": True, "status": "frontend_checked_not_native_qualified",
                       "converted": [{k: v for k, v in x.items() if k != "source"} for x in translated],
                       "output_sha256": hashlib.sha256(program.encode()).hexdigest(),
                       "native_validation": "not_run", "frontend": "passed"})
        return report
    except (MigrationRejected, UnicodeError, json.JSONDecodeError) as exc:
        report["rejected"].append({"code": getattr(exc, "code", "E_C_INPUT"), "message": str(exc)})
        return report


def migrate_c_project(database: str | Path, output_directory: str | Path, *,
                      contracts: dict | None = None, clang: str = "clang",
                      rustc: str | None = None, verify_native: bool = False) -> dict:
    """Migrate the bounded project profile; see docs/C_MIGRATION.md.

    This separate entry point preserves the original fail-closed scalar pilot.
    It returns a complete declaration inventory and explicit pointer contracts.
    """
    from .c_migration_project import migrate_project
    return migrate_project(database, output_directory, contracts=contracts,
                           clang=clang, rustc=rustc, verify_native=verify_native)
