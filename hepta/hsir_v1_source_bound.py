"""Fail-closed PR14 source-bound scalar HSIR to PR37 native checked-HSIR equivalence.

Never reinterpret an untrusted source-bound v0 typed-string AST as a frozen
structural AST. Instead reparse and check the *exact source bytes* using the
consumer's existing checker, then compare both typed AST representations
node-for-node over a strictly finite scalar profile.

This is an evidence-bearing *equivalence check of accepted AST representations*
for one source and profile. It is not a proof of whole-language semantics,
Rust-level safety, unsafe FFI validity or machine codegen correctness.
"""
from __future__ import annotations

from hashlib import sha256
import re

from .hsir_v1 import HSIRV1Rejected, verify_v1


class SourceBoundRejected(ValueError):
    pass


_TYPES = frozenset({"i32", "i64", "u32", "u64", "bool"})
_NUMERIC = _TYPES - {"bool"}
_BIN_ARITH = frozenset({"+", "-", "*", "/", "%"})
_BIN_CMP = frozenset({"==", "!=", "<", "<=", ">", ">="})
_BIN_LOGICAL = frozenset({"&&", "||"})
_IDENTIFIER = re.compile(r"[a-zA-Z_][a-zA-Z0-9_]*\Z")
_MAX_DEPTH = 48
_MAX_FUNCTIONS = 256


def _fail(what: str):
    raise SourceBoundRejected("E_SOURCE_BOUND_" + what)


def _empty(value) -> bool:
    return value == [] or value == {}


def _typename(src, dest, *, numeric=False) -> str:
    if not isinstance(src, str) or src not in (_NUMERIC if numeric else _TYPES):
        _fail("TYPE")
    if not isinstance(dest, dict) or dest != {"type": src, "args": [], "length": None}:
        _fail("TYPE_EQUIVALENCE")
    return src


def _span(src, dest):
    if not isinstance(src, dict) or not isinstance(dest, dict) or src != dest:
        _fail("SPAN")
    if (set(src) != {"path", "start", "end", "line", "column"}
            or not isinstance(src["path"], str)
            or any(type(src[k]) is not int or src[k] < 0
                   for k in ("start", "end", "line", "column"))
            or src["start"] > src["end"]):
        _fail("SPAN")


def _expression(src, dest, depth=0) -> bool:
    if depth > _MAX_DEPTH:
        _fail("DEPTH")
    if (not isinstance(src, dict) or not isinstance(dest, dict)
            or set(src) != {"node", "op", "type", "value", "args", "type_args", "span"}
            or set(dest) != {"node", "operation", "result_type", "value",
                            "operands", "type_args", "span"}
            or src["node"] != dest["node"] or src["node"] != "expr"):
        _fail("EXPRESSION_SHAPE")
    op, ty = src["op"], _typename(src["type"], dest["result_type"])
    if op != dest["operation"] or src["type_args"] != [] or dest["type_args"] != []:
        _fail("EXPRESSION_PROFILE")
    _span(src["span"], dest["span"])
    if (not isinstance(src["args"], list) or not isinstance(dest["operands"], list)
            or len(src["args"]) != len(dest["operands"])):
        _fail("EXPRESSION_ARITY")
    value = src["value"]
    if op == "name":
        if (not isinstance(value, str) or not _IDENT.fullmatch(value)
                or len(src["args"]) or ty not in _TYPES):
            _fail("NAME")
    elif op == "int":
        if type(value) is not int or len(src["args"]) or ty not in _NUMERIC:
            _fail("LITERAL")
    elif op == "bool":
        if type(value) is not bool or len(src["args"]) or ty != "bool":
            _fail("LITERAL")
    elif op == "unary":
        if len(src["args"]) != 1 or not isinstance(value, str) or value not in {"-", "!"}:
            _fail("UNARY")
    elif op == "binary":
        if len(src["args"]) != 2 or not isinstance(value, str) or value not in (_BIN_ARITH | _BIN_CMP | _BIN_LOGICAL):
            _fail("BINARY")
    else:
        # No calls, casts, float, generic instantiation, moves, raw memory,
        # indexing, field access, structured values or implicit conversions.
        _fail("UNSUPPORTED_EXPR")
    if type(value) is not type(dest["value"]) or value != dest["value"]:
        _fail("EXPRESSION_VALUE")
    for a, b in zip(src["args"], dest["operands"]):
        _expression(a, b, depth + 1)
    if op == "unary":
        operand = src["args"][0]["type"]
        if value == "-" and (ty not in {"i32", "i64"} or operand != ty):
            _fail("UNARY_TYPE")
        if value == "!" and (ty != "bool" or operand != "bool"):
            _fail("UNARY_TYPE")
    if op == "binary":
        left, right = (x["type"] for x in src["args"])
        if value in _BIN_ARITH and not (left == right == ty and ty in _NUMERIC):
            _fail("BINARY_TYPE")
        if value in _BIN_CMP and not (left == right and left in _NUMERIC and ty == "bool"):
            _fail("BINARY_TYPE")
        if value in _BIN_LOGICAL and not (left == right == ty == "bool"):
            _fail("BINARY_TYPE")
    return op in {"unary", "binary"} and value in (_BIN_ARITH | {"-"})


def _statements(src, dest, depth=0) -> bool:
    if depth > _MAX_DEPTH or not isinstance(src, list) or not isinstance(dest, list) or len(src) != len(dest):
        _fail("STATEMENTS")
    may_panic = False
    for a, b in zip(src, dest):
        if (not isinstance(a, dict) or not isinstance(b, dict)
                or set(a) != {"node", "op", "data", "span"}
                or set(b) != {"node", "operation", "fields", "span"}
                or a["node"] != b["node"] or a["node"] != "stmt"
                or a["op"] != b["operation"]):
            _fail("STATEMENT_SHAPE")
        _span(a["span"], b["span"])
        d, f, kind = a["data"], b["fields"], a["op"]
        if not isinstance(d, dict) or not isinstance(f, dict) or set(d) != set(f):
            _fail("FIELDS")
        if kind == "let":
            if set(d) != {"name", "type", "mutable", "expr"}:
                _fail("LET")
            name = d["name"]
            if (not isinstance(name, str) or not _IDENT.fullmatch(name)
                    or name != f["name"] or type(d["mutable"]) is not bool
                    or d["mutable"] != f["mutable"]):
                _fail("LET")
            if d["type"] is None:
                if f["type"] is not None:
                    _fail("LET_TYPE")
            else:
                type_obj = d["type"]
                if not isinstance(type_obj, dict) or set(type_obj) != {"node", "name", "args", "length"}:
                    _fail("LET_TYPE")
                if type_obj["node"] != "type" or type_obj["args"] != [] or type_obj["length"] is not None:
                    _fail("LET_TYPE")
                _typename(type_obj["name"], f["type"])
            may_panic |= _expression(d["expr"], f["expr"], depth + 1)
        elif kind == "assign":
            if set(d) != {"target", "expr"}:
                _fail("ASSIGN")
            _expression(d["target"], f["target"], depth + 1)
            if d["target"]["op"] != "name":
                _fail("ASSIGN_TARGET")
            may_panic |= _expression(d["expr"], f["expr"], depth + 1)
        elif kind in {"return", "expr"}:
            if set(d) != {"expr"} or d["expr"] is None:
                _fail("RETURN_EXPR")
            may_panic |= _expression(d["expr"], f["expr"], depth + 1)
        elif kind == "if":
            if set(d) != {"condition", "then", "else"}:
                _fail("IF")
            may_panic |= _expression(d["condition"], f["condition"], depth + 1)
            if d["condition"]["type"] != "bool":
                _fail("CONDITION")
            may_panic |= _statements(d["then"], f["then"], depth + 1)
            may_panic |= _statements(d["else"], f["else"], depth + 1)
        elif kind == "while":
            if set(d) != {"condition", "body"}:
                _fail("WHILE")
            may_panic |= _expression(d["condition"], f["condition"], depth + 1)
            if d["condition"]["type"] != "bool":
                _fail("CONDITION")
            may_panic |= _statements(d["body"], f["body"], depth + 1)
        else:
            _fail("UNSUPPORTED_STMT")
    return may_panic


def recheck_source_bound(envelope: dict, source_text: str, source_path: str, *,
                         verified_project_sha256: str | None = None):
    """Produce PR37's native typed snapshot only after exact two-view agreement.

    The consumer never generates structural expression types from a string
    type in an imported payload: all structural types come from a freshly
    parsed and checked source via the existing PR37 compiler.
    """
    try:
        verify_v1(envelope)
    except HSIRV1Rejected as exc:
        raise SourceBoundRejected("E_SOURCE_BOUND_V1_IDENTITY: " + str(exc)) from exc
    if envelope["producer"]["wire_profile"] != "source_bound_v0":
        _fail("PRODUCER")
    if not isinstance(source_text, str) or not isinstance(source_path, str) or not source_path:
        _fail("SOURCE_REQUIRED")
    old = envelope["opaque_producer_payload"]
    if old.get("path") != source_path or sha256(source_text.encode("utf-8")).hexdigest() != old["source_sha256"]:
        _fail("SOURCE_IDENTITY")
    for field in ("imports", "structs", "enums", "external_obligations",
                  "volatile_accesses", "foreign_assumptions", "resource_contracts",
                  "owned_types", "untyped_expressions"):
        if not _empty(old.get(field)):
            _fail("UNSUPPORTED_GLOBAL_" + field.upper())
    project_sha = old.get("project_sha256")
    if project_sha is not None:
        # PR14 CLI includes its resolved project identity. Require the active
        # PR37 project loader to independently reproduce that exact identity;
        # never trust a 64-hex claim in an imported producer on its own.
        if (not isinstance(verified_project_sha256, str)
                or verified_project_sha256 != project_sha):
            _fail("PROJECT_IDENTITY")
    if old.get("all_expressions_typed") is not True:
        _fail("UNTYPED_PROJECT")
    from .checker import check
    from .parser import parse
    from .hsir import lower_checked_program
    try:
        program = parse(source_text, source_path)
        checked = check(program)
        if not checked.ok:
            _fail("RECHECK_REJECTED")
        native = lower_checked_program(program, checked)
        current = native.as_dict()
    except SourceBoundRejected:
        raise
    except (ValueError, TypeError, OverflowError, RecursionError) as exc:
        raise SourceBoundRejected("E_SOURCE_BOUND_RECHECK_FAILED: " + str(exc)) from exc
    if (current["source_sha256"] != old["source_sha256"]
            or current["program"] != old.get("module")
            or not _empty(current["imports"]) or not _empty(current["structs"])
            or not _empty(current["enums"])
            or not _empty(current.get("external_assumptions"))
            or not _empty(current.get("resource_contracts"))):
        _fail("PROGRAM_EQUIVALENCE")
    a, b = old.get("functions"), current.get("functions")
    if not isinstance(a, list) or len(a) > _MAX_FUNCTIONS or not isinstance(b, list) or len(a) != len(b):
        _fail("FUNCTION_INVENTORY")
    for orig, new, parsed in zip(a, b, program.functions):
        if (not isinstance(orig, dict) or not isinstance(new, dict)
                or orig.get("name") != new.get("name") or new["name"] != parsed.name
                or orig.get("path") != source_path
                or orig.get("public") is not new.get("public")
                or orig.get("extern_c") is not False or orig.get("export_c") is not False
                or new.get("direction") != "local" or new.get("abi") != "hepta_unstable"
                or orig.get("type_params") != [] or orig.get("type_bounds") != {}
                or orig.get("lifetime_params") not in (None, [])
                or orig.get("return_lifetime") is not None
                or orig.get("return_mode", "value") != "value"
                or orig.get("return_origin") is not None
                or not _empty(orig.get("resources")) or not _empty(new["resource_contract"])):
            _fail("FUNCTION_PROFILE")
        _span(orig.get("declaration_span"), new.get("span"))
        expected_body = {key: getattr(parsed.body_span, key)
                         for key in ("path", "start", "end", "line", "column")}
        _span(orig.get("body_span"), expected_body)
        _typename(orig.get("returns"), new.get("return_type"))
        params, new_params = orig.get("params"), new.get("param_types")
        if not isinstance(params, list) or not isinstance(new_params, list) or len(params) != len(new_params):
            _fail("PARAMETERS")
        for left, right in zip(params, new_params):
            if (not isinstance(left, dict) or not isinstance(right, dict)
                    or left.get("name") != right.get("name")
                    or left.get("mode") != "value" or right.get("ownership") != "value"
                    or left.get("lifetime") is not None):
                _fail("PARAMETER_OWNERSHIP")
            _typename(left.get("type"), right.get("type"))
            _span(left.get("span"), right.get("span"))
        declared, inferred = orig.get("declared_effects"), orig.get("inferred_effects")
        if declared not in ([], ["panic"]) or inferred not in ([], ["panic"]):
            _fail("EFFECTS")
        if declared != new.get("declared_effects") or inferred != new.get("inferred_transitive_effects"):
            _fail("EFFECT_EQUIVALENCE")
        may_panic = _statements(orig.get("body"), new.get("body"))
        if may_panic and "panic" not in declared:
            _fail("PANIC_CONTRACT")
    return native
