"""Fail-closed PR#14 HSIR source-bound -> PR#37 scalar HSIR representation.

Only plain scalar, non-foreign, allocation-free syntax is admitted. This
*structural* translation does not prove code semantics, trust a checked flag,
or permit native machine-code generation. The original v1 remains attached.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from .hsir_v1 import HSIRV1Rejected, integrate_v0, verify_v1

BRIDGE_SCHEMA = "hepta.hsir.scalar-bridge.v1"
# Deliberately smaller than the full PR#37 SSA scalar type set; widen only
# after cross-backend arithmetic/ABI and floating point semantics checks.
SCALARS = frozenset({"i32", "u32", "i64", "u64", "bool"})
ALLOWED_BINARY = frozenset({"+", "-", "*", "/", "%", "==", "!=", "<", "<=", ">", ">=", "&&", "||"})
ALLOWED_UNARY = frozenset({"-", "!"})
MAX_EXPRESSION_DEPTH = 64
MAX_FUNCTIONS = 256
MAX_NODES = 16384
KEY_SPAN = frozenset({"path", "start", "end", "line", "column"})
SAFE_CLAIMS = {"lifetimes_fully_modeled": False, "pointer_provenance_proved": False,
               "source_semantics_refined": False, "native_backend_equivalence_proved": False}


class ScalarBridgeRejected(ValueError):
    """The submitted HSIR requires semantics not covered by this scalar pilot."""


def _error(reason: str) -> None:
    raise ScalarBridgeRejected("E_HSIR_SCALAR_" + reason)


def _require_keys(value: Any, required: set[str], optional: set[str] | None = None) -> dict:
    if not isinstance(value, dict):
        _error("SHAPE")
    keys = set(value)
    if not required <= keys or keys - (required | (optional or set())):
        _error("UNKNOWN_OR_MISSING_FIELDS")
    return value


def _sha(value: dict) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False, allow_nan=False).encode("utf-8")).hexdigest()


def _span(value: Any) -> dict:
    _require_keys(value, set(KEY_SPAN))
    if (not isinstance(value["path"], str) or not value["path"] or
        any(type(value[x]) is not int or value[x] < 0 for x in ("start", "end", "line", "column")) or
        value["start"] > value["end"] or value["line"] == 0 or value["column"] == 0):
        _error("SPAN")
    return dict(value)


def _type(value: Any) -> dict:
    if type(value) is not str or value not in SCALARS:
        _error("TYPE_OR_RESOURCE")
    return {"type": value, "args": [], "length": None}


def _declared_type(value: Any) -> dict:
    """Recognize the exact Type encoding produced by PR#14's _Encoder."""
    _require_keys(value, {"node", "name", "args", "length"})
    if value["node"] != "type" or value["args"] != [] or value["length"] is not None:
        _error("TYPE_OR_RESOURCE")
    return _type(value["name"])


class _Converter:
    def __init__(self, source_path: str):
        self.expressions = 0
        self.nodes = 0
        self.source_path = source_path

    def span(self, value: Any) -> dict:
        span = _span(value)
        if span["path"] != self.source_path:
            _error("CROSS_SOURCE_SPAN")
        return span

    def _enter(self, depth: int) -> None:
        self.nodes += 1
        if depth > MAX_EXPRESSION_DEPTH or self.nodes > MAX_NODES:
            _error("LIMIT")

    def expr(self, node: Any, depth: int = 0) -> dict:
        self._enter(depth)
        _require_keys(node, {"node", "op", "type", "value", "args", "type_args", "span"})
        if node["node"] != "expr" or not isinstance(node["args"], list) or node["type_args"] != []:
            _error("EXPRESSION")
        operation = node["op"]
        if operation not in {"name", "int", "bool", "unary", "binary"}:
            _error("EXPRESSION_OR_EFFECT")
        ty = _type(node["type"])
        arity = {"name": 0, "int": 0, "bool": 0, "unary": 1, "binary": 2}[operation]
        if len(node["args"]) != arity:
            _error("EXPRESSION_ARITY")
        value = node["value"]
        if operation == "name":
            if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", value):
                _error("NAME")
        elif operation == "int":
            if type(value) is not int or ty["type"] == "bool":
                _error("LITERAL")
        elif operation == "bool":
            if type(value) is not bool or ty["type"] != "bool":
                _error("LITERAL")
        elif operation == "unary":
            if value not in ALLOWED_UNARY:
                _error("OPERATOR")
            if value == "!" and ty["type"] != "bool":
                _error("UNARY_TYPE")
        elif operation == "binary":
            if value not in ALLOWED_BINARY:
                _error("OPERATOR")
            if value in {"==", "!=", "<", "<=", ">", ">=", "&&", "||"} and ty["type"] != "bool":
                _error("BINARY_TYPE")
        args = [self.expr(x, depth+1) for x in node["args"]]
        # The v0 producer is not trusted merely because its digest matches.
        # Independently check the arithmetic operator's declared result type.
        if operation == "unary":
            operand_type = args[0]["result_type"]["type"]
            if value == "!" and (operand_type != "bool" or ty["type"] != "bool"):
                _error("UNARY_TYPE")
            if value == "-" and (operand_type not in {"i32", "i64"} or ty["type"] != operand_type):
                _error("UNARY_TYPE")
        if operation == "binary":
            left, right = (x["result_type"]["type"] for x in args)
            if left != right:
                _error("BINARY_OPERAND_TYPE")
            if value in {"&&", "||"}:
                if left != "bool" or ty["type"] != "bool":
                    _error("BINARY_TYPE")
            elif value in {"==", "!=", "<", "<=", ">", ">="}:
                if ty["type"] != "bool" or (value not in {"==", "!="} and left == "bool"):
                    _error("BINARY_TYPE")
            elif left not in SCALARS - {"bool"} or ty["type"] != left:
                _error("BINARY_TYPE")
        self.expressions += 1
        return {"node": "expr", "operation": operation, "result_type": ty,
                "value": value, "operands": args, "type_args": [], "span": self.span(node["span"])}

    def stmt(self, node: Any, depth: int = 0) -> dict:
        self._enter(depth)
        _require_keys(node, {"node", "op", "data", "span"})
        if node["node"] != "stmt" or not isinstance(node["data"], dict):
            _error("STATEMENT")
        op, data = node["op"], node["data"]
        if op == "let":
            _require_keys(data, {"name", "expr", "mutable"}, {"type"})
            if type(data["mutable"]) is not bool or not isinstance(data["name"], str):
                _error("LET")
            fields = {"name": data["name"], "expr": self.expr(data["expr"], depth+1),
                      "mutable": data["mutable"], "type": _declared_type(data["type"]) if data.get("type") is not None else None}
        elif op == "assign":
            _require_keys(data, {"target", "expr"})
            fields = {"target": self.expr(data["target"], depth+1),
                      "expr": self.expr(data["expr"], depth+1)}
            if fields["target"]["operation"] != "name":
                _error("ASSIGNMENT_TARGET")
        elif op == "expr":
            _require_keys(data, {"expr"})
            fields = {"expr": self.expr(data["expr"], depth+1)}
        elif op == "return":
            _require_keys(data, {"expr"})
            fields = {"expr": self.expr(data["expr"], depth+1)}
        elif op == "if":
            _require_keys(data, {"condition", "then", "else"})
            fields = {"condition": self.expr(data["condition"], depth+1),
                      "then": self.statements(data["then"], depth+1),
                      "else": self.statements(data["else"], depth+1)}
            if fields["condition"]["result_type"]["type"] != "bool":
                _error("CONDITION")
        elif op == "while":
            _require_keys(data, {"condition", "body"})
            fields = {"condition": self.expr(data["condition"], depth+1),
                      "body": self.statements(data["body"], depth+1)}
            if fields["condition"]["result_type"]["type"] != "bool":
                _error("CONDITION")
        else:
            _error("STATEMENT_OR_RESOURCE")
        return {"node": "stmt", "operation": op, "fields": fields, "span": self.span(node["span"])}

    def statements(self, nodes: Any, depth: int = 0) -> list[dict]:
        if not isinstance(nodes, list):
            _error("STATEMENTS")
        return [self.stmt(node, depth) for node in nodes]


def _verify_scalar_function(function: dict) -> None:
    """Independently check scalar bindings, mutability, and effect promises.

    A producer hash alone is not a type-check attestation. We do not try to
    recognize captures or nested block declarations: those fail closed.
    """
    scalars = {param["name"]: param["type"]["type"] for param in function["param_types"]}
    if len(scalars) != len(function["param_types"]):
        _error("DUPLICATE_PARAMETER")
    writable = set()
    panic_required = False

    def check_expression(node: dict) -> str:
        nonlocal panic_required
        kind, ty = node["operation"], node["result_type"]["type"]
        if kind == "name":
            name = node["value"]
            if name not in scalars or scalars[name] != ty:
                _error("UNBOUND_OR_WRONG_NAME_TYPE")
        elif kind == "int":
            val = node["value"]
            bits = 32 if ty in ("u32", "i32") else 64 if ty in ("u64", "i64") else None
            if bits is None:
                _error("INTEGER_TYPE")
            signed = ty.startswith("i")
            low = -(1 << (bits - 1)) if signed else 0
            high = (1 << (bits - 1)) - 1 if signed else (1 << bits) - 1
            if not low <= val <= high:
                _error("INTEGER_RANGE")
        elif kind in ("binary", "unary"):
            if node["value"] in {"+", "-", "*", "/", "%"}:
                panic_required = True
        for operand in node["operands"]:
            check_expression(operand)
        return ty

    def check_block(statements: list[dict], nesting: int = 0) -> None:
        for statement in statements:
            kind, fields = statement["operation"], statement["fields"]
            if kind == "let":
                if nesting or fields["name"] in scalars:
                    _error("NESTED_OR_SHADOWING_LOCAL")
                result = check_expression(fields["expr"])
                if fields["type"] is not None and fields["type"]["type"] != result:
                    _error("LOCAL_INITIALIZER_TYPE")
                scalars[fields["name"]] = result
                if fields["mutable"]:
                    writable.add(fields["name"])
            elif kind == "assign":
                target = fields["target"]
                name = target["value"]
                if name not in writable or name not in scalars:
                    _error("IMMUTABLE_OR_UNBOUND_ASSIGNMENT")
                if check_expression(target) != check_expression(fields["expr"]):
                    _error("ASSIGNMENT_TYPE")
            elif kind == "return":
                if check_expression(fields["expr"]) != function["return_type"]["type"]:
                    _error("RETURN_TYPE")
            elif kind == "expr":
                check_expression(fields["expr"])
            elif kind == "if":
                if check_expression(fields["condition"]) != "bool":
                    _error("CONDITION_TYPE")
                check_block(fields["then"], nesting+1)
                check_block(fields["else"], nesting+1)
            elif kind == "while":
                if check_expression(fields["condition"]) != "bool":
                    _error("CONDITION_TYPE")
                check_block(fields["body"], nesting+1)
            else:
                _error("STATEMENT")

    check_block(function["body"])
    if panic_required and ("panic" not in function["declared_effects"] or
                           "panic" not in function["inferred_transitive_effects"]):
        _error("PANIC_EFFECT_UNDERCLAIMED")


def source_bound_to_frozen(source_v1: dict) -> dict:
    """Translate only a PR#14 checked-source-bound, pure scalar closed subset.

    Returns the PR#36-shaped *candidate* and its independently regenerated v1
    identity. The entire PR#14 payload remains in the original envelope.
    """
    try:
        verify_v1(source_v1)
    except HSIRV1Rejected as exc:
        raise ScalarBridgeRejected("E_HSIR_SCALAR_V1_IDENTITY: " + str(exc)) from exc
    producer = source_v1["producer"]
    if producer["wire_profile"] != "source_bound_v0":
        _error("WRONG_PRODUCER")
    source = source_v1["opaque_producer_payload"]
    _require_keys(source, {"schema", "profile", "module", "path", "source_sha256", "project_sha256",
                           "imports", "structs", "enums", "functions", "untyped_expressions",
                           "all_expressions_typed", "external_obligations", "volatile_accesses",
                           "foreign_assumptions", "resource_contracts", "owned_types", "claims", "sha256"})
    if (source["imports"] != [] or source["structs"] != [] or source["enums"] != [] or
        source["external_obligations"] != [] or source["volatile_accesses"] != [] or
        source["foreign_assumptions"] not in ([], {}) or source["resource_contracts"] not in ([], {}) or
        source["owned_types"] != [] or source["all_expressions_typed"] is not True or
        source["untyped_expressions"] != []):
        _error("NON_SCALAR_OR_EXTERNAL_OBLIGATION")
    functions = source["functions"]
    if not isinstance(functions, list) or not (1 <= len(functions) <= MAX_FUNCTIONS):
        _error("FUNCTION_COUNT")
    mapped_functions = []
    cv = _Converter(source["path"])
    seen_functions = set()
    for fn in functions:
        _require_keys(fn, {"name", "path", "declaration_span", "body_span", "public", "extern_c",
                           "export_c", "type_params", "type_bounds", "params", "returns",
                           "return_mode", "return_origin", "declared_effects", "inferred_effects",
                           "resources", "body"}, {"lifetime_params", "return_lifetime"})
        name = fn["name"]
        if fn["path"] != source["path"] or cv.span(fn["body_span"])["path"] != source["path"]:
            _error("CROSS_SOURCE_SPAN")
        if (not isinstance(name, str) or not name or name in seen_functions or
            fn["extern_c"] is not False or fn["export_c"] is not False or
            type(fn["public"]) is not bool or fn["type_params"] != [] or fn["type_bounds"] != {} or
            fn.get("lifetime_params", []) != [] or fn.get("return_lifetime") is not None or
            fn["return_mode"] != "value" or fn["return_origin"] is not None or
            fn["resources"] not in ({}, []) or fn["declared_effects"] not in ([], ["panic"]) or
            fn["inferred_effects"] not in ([], ["panic"])):
            _error("FUNCTION_SEMANTICS")
        seen_functions.add(name)
        params = fn["params"]
        if not isinstance(params, list):
            _error("PARAMETERS")
        seen_params = set()
        mapped_params = []
        for p in params:
            _require_keys(p, {"name", "mode", "type", "span"}, {"lifetime"})
            if (not isinstance(p["name"], str) or not p["name"] or p["name"] in seen_params or
                p["mode"] != "value" or p.get("lifetime") is not None):
                _error("RESOURCE_PARAMETER")
            seen_params.add(p["name"])
            mapped_params.append({"name": p["name"], "ownership": "value",
                                  "type": _type(p["type"]), "span": cv.span(p["span"])})
        converted_fn = {
            "name": name, "param_types": mapped_params, "return_type": _type(fn["returns"]),
            "declared_effects": list(fn["declared_effects"]),
            "inferred_transitive_effects": list(fn["inferred_effects"]),
            "resource_contract": {}, "type_parameters": [],
            "abi": "hepta_unstable", "direction": "local", "public": fn["public"],
            "body": cv.statements(fn["body"]), "span": cv.span(fn["declaration_span"]),
        }
        _verify_scalar_function(converted_fn)
        mapped_functions.append(converted_fn)
    candidate = {
        "schema": "hepta.hsir.v0", "status": "checked_frontend_snapshot_not_proved",
        "program": source["module"], "source_sha256": source["source_sha256"],
        "imports": [], "structs": [], "enums": [], "functions": mapped_functions,
        "external_assumptions": [], "resource_contracts": {},
        "claims": dict(SAFE_CLAIMS), "typed_expression_count": cv.expressions,
    }
    candidate["sha256"] = _sha(candidate)
    translated_v1 = integrate_v0(candidate, expected_source_sha256=producer["source_sha256"])
    return {"source_hsir_v1": source_v1, "mapped_hsir_v1": translated_v1,
            "projection_profile": "closed_scalar_non_ffi_no_resource_operations",
            "source_project_sha256": producer["project_sha256"],
            "source_hsir_v0_sha256": producer["legacy_sha256"],
            "mapped_hsir_v0_sha256": candidate["sha256"],
            "claims": {"structural_scalar_mapping_checked": True,
                       "semantic_equivalence_proven": False,
                       "borrow_lifetimes_proved": False,
                       "pointer_provenance_proved": False,
                       "native_codegen_authorized": False}}
