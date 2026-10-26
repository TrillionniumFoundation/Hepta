"""Fail-closed scalar compatibility view over canonical Hepta semantic IR.

PR #14's hepta.semantic_ir is the sole authority for checked source
semantics. This adapter exists only to feed the experimental CFG/SSA verifier
imported from PR #37. It does not re-check an AST, grant new effects, prove
lowering correctness, or broaden the CFG/SSA subset.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import re
from typing import Any

from .semantic_ir import lower_checked_program as _lower_canonical

CANONICAL_SCHEMA = "hepta.hsir.v0"
SCHEMA = "hepta.hsir.scalar.v1"
_STATUS = "checked_frontend_snapshot_not_proved"
_SCALARS = frozenset({"bool", "i8", "i16", "i32", "i64", "i128", "isize",
                      "u8", "u16", "u32", "u64", "u128", "usize", "f32", "f64"})
_TYPES = _SCALARS | {"Unit"}
_EXPR = frozenset({"name", "int", "float", "bool", "binary", "unary", "cast"})
_STMT = frozenset({"let", "assign", "expr", "return", "if", "while", "for"})
# Canonical Stmt.data must be lossless at every nesting level. Reject
# unexpected keys rather than allowing a new semantic effect to reach the
# scalar CFG/SSA bridge where it could otherwise be silently ignored.
_STMT_DATA_FIELDS = {
    "let": frozenset({"name", "type", "mutable", "expr"}),
    "assign": frozenset({"target", "expr"}),
    "expr": frozenset({"expr"}),
    "return": frozenset({"expr"}),
    "if": frozenset({"condition", "then", "else"}),
    "while": frozenset({"condition", "body"}),
    "for": frozenset({"name", "start", "end", "body"}),
}
_HASH = re.compile(r"[0-9a-f]{64}\Z")
# Fixed upstream v0 semantic inventory, not an alternative AST encoder.
# An added/missing field requires a review of the scalar projection boundary.
_CANONICAL_FIELDS = frozenset({
    "schema", "profile", "module", "path", "source_sha256", "project_sha256",
    "imports", "structs", "enums", "functions", "untyped_expressions",
    "all_expressions_typed", "external_obligations", "volatile_accesses",
    "foreign_assumptions", "resource_contracts", "owned_types", "claims", "sha256",
})
_CANONICAL_CLAIMS = frozenset({
    "native_borrow_validation", "translation_correctness_proved",
    "whole_language_soundness_proved", "foreign_contracts_proved",
})
# The upstream encoder emits these exact fields in the strict scalar profile.
# Unknown function/parameter/node attributes cannot be silently discarded:
# a future encoder's new property might affect ownership, ABI or effects.
_FUNCTION_FIELDS = frozenset({
    "name", "path", "declaration_span", "body_span", "public",
    "extern_c", "export_c", "type_params", "type_bounds", "params",
    "returns", "return_mode", "return_origin", "declared_effects",
    "inferred_effects", "resources", "body",
})
_PARAMETER_FIELDS = frozenset({"name", "mode", "type", "span"})
_EXPR_FIELDS = frozenset({"node", "op", "type", "value", "args", "type_args", "span"})
_STMT_FIELDS = frozenset({"node", "op", "data", "span"})
_TYPE_FIELDS = frozenset({"node", "name", "args", "length"})
# Closed schema of the *derived* scalar snapshot. It can be supplied to the
# structural CFG consumer directly; the latter must not trust a self-resealed
# JSON object merely because its SHA-256 matches.
_DERIVED_FIELDS = frozenset({
    "schema", "status", "program", "source_sha256", "source_semantic_sha256",
    "project_sha256", "imports", "structs", "enums", "functions",
    "external_assumptions", "resource_contracts", "typed_expression_count",
    "claims",
})
_DERIVED_FUNCTION_FIELDS = frozenset({
    "name", "param_types", "return_type", "declared_effects",
    "inferred_transitive_effects", "resource_contract", "type_parameters",
    "abi", "direction", "public", "body", "span",
})
_DERIVED_CLAIMS = {
    "lifetimes_fully_modeled": False, "pointer_provenance_proved": False,
    "source_semantics_refined": False, "native_backend_equivalence_proved": False,
    "canonical_semantics_still_authoritative": True,
}
_DERIVED_EXPR_FIELDS = frozenset({
    "node", "operation", "result_type", "value", "operands", "type_args", "span",
})
_DERIVED_STMT_FIELDS = frozenset({"node", "operation", "fields", "span"})
# Closed scalar syntax shape: a digest alone cannot give an expression an
# additional operand, silently change a literal's type, or alter a statement's
# control-flow structure without independent source verification.
_SCALAR_EXPR_ARITY = {"name": 0, "int": 0, "float": 0, "bool": 0,
                      "binary": 2, "unary": 1, "cast": 1}


class HSIRRejected(ValueError):
    """The canonical source is invalid or outside this scalar bridge."""


@dataclass(frozen=True)
class HSIRSnapshot:
    schema: str
    canonical_json: str
    sha256: str

    def as_dict(self) -> dict:
        if self.schema != SCHEMA or not isinstance(self.canonical_json, str) or not isinstance(self.sha256, str):
            raise HSIRRejected("E_HSIR_SNAPSHOT: malformed snapshot")
        if len(self.canonical_json.encode("utf-8")) > 32_000_000:
            raise HSIRRejected("E_HSIR_SNAPSHOT: bounded scalar snapshot exceeds 32 MB")
        if sha256(self.canonical_json.encode("utf-8")).hexdigest() != self.sha256:
            raise HSIRRejected("E_HSIR_SNAPSHOT: changed snapshot content")
        try:
            obj = json.loads(self.canonical_json)
        except (TypeError, ValueError) as exc:
            raise HSIRRejected("E_HSIR_SNAPSHOT: invalid JSON") from exc
        if not isinstance(obj, dict) or obj.get("schema") != SCHEMA or obj.get("status") != _STATUS:
            raise HSIRRejected("E_HSIR_SNAPSHOT: schema/status mismatch")
        try:
            canonical = _json(obj)
        except (TypeError, ValueError) as exc:
            raise HSIRRejected("E_HSIR_SNAPSHOT: noncanonical or nonfinite snapshot") from exc
        if canonical != self.canonical_json:
            raise HSIRRejected("E_HSIR_SNAPSHOT: noncanonical serialized snapshot")
        _validate_derived_snapshot(obj)
        return {**obj, "sha256": self.sha256}


def _reject(reason: str) -> None:
    raise HSIRRejected("E_HSIR_BRIDGE: " + reason)


def _json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":"))


def _validate_derived_node(value: Any, depth: int = 0) -> int:
    """Validate closed scalar expression/statement nesting. Return expr count."""
    if depth > 256:
        _reject("derived scalar node nesting exceeded")
    if value is None or isinstance(value, (str, int, float, bool)):
        return 0
    if isinstance(value, list):
        return sum(_validate_derived_node(item, depth + 1) for item in value)
    if not isinstance(value, dict):
        _reject("derived scalar value must be structured")
    if set(value) == {"type", "args", "length"}:
        if (not isinstance(value["type"], str) or value["type"] not in _TYPES or value["args"] != []
                or value["length"] is not None):
            _reject("derived scalar type is not closed")
        return 0
    if set(value) == {"path", "start", "end", "line", "column"}:
        if (not isinstance(value["path"], str)
                or not all(type(value[key]) is int for key in ("start", "end", "line", "column"))
                or value["start"] < 0 or value["end"] < value["start"]
                or value["line"] < 1 or value["column"] < 1):
            _reject("derived scalar source span is malformed")
        return 0
    kind = value.get("node")
    if kind == "expr":
        if (set(value) != _DERIVED_EXPR_FIELDS
                or not isinstance(value.get("operation"), str)
                or value.get("operation") not in _EXPR
                or value.get("type_args") != [] or not isinstance(value.get("operands"), list)):
            _reject("derived scalar expression contains unreviewed semantics")
        op, operands, literal = value["operation"], value["operands"], value["value"]
        if len(operands) != _SCALAR_EXPR_ARITY[op]:
            _reject("derived scalar expression arity differs from checked source syntax")
        if (op == "name" and (not isinstance(literal, str) or not literal)
                or op == "int" and type(literal) is not int
                or op == "float" and type(literal) is not float
                or op == "bool" and type(literal) is not bool
                or op in {"binary", "unary"} and not isinstance(literal, str)
                or op == "cast" and (not isinstance(literal, dict)
                                     or set(literal) != {"type", "args", "length"})):
            _reject("derived scalar expression has invalid operation payload")
        if not isinstance(value["span"], dict):
            _reject("derived scalar expression is missing its source span")
        _validate_derived_node(value["result_type"], depth + 1)
        _validate_derived_node(value["span"], depth + 1)
        return (1 + _validate_derived_node(literal, depth + 1)
                + _validate_derived_node(operands, depth + 1))
    if kind == "stmt":
        operation, fields = value.get("operation"), value.get("fields")
        if (set(value) != _DERIVED_STMT_FIELDS
                or not isinstance(operation, str)
                or operation not in _STMT_DATA_FIELDS or not isinstance(fields, dict)
                or set(fields) != _STMT_DATA_FIELDS[operation]):
            _reject("derived scalar statement contains unreviewed semantics")
        if not isinstance(value["span"], dict):
            _reject("derived scalar statement is missing its source span")
        if operation == "let":
            if (not isinstance(fields["name"], str) or not fields["name"]
                    or type(fields["mutable"]) is not bool
                    or (fields["type"] is not None and
                        (not isinstance(fields["type"], dict)
                         or set(fields["type"]) != {"type", "args", "length"}))
                    or not isinstance(fields["expr"], dict)):
                _reject("derived scalar declaration has invalid binding/type/value")
        elif operation == "assign":
            if (not isinstance(fields["target"], dict)
                    or fields["target"].get("operation") != "name"
                    or not isinstance(fields["expr"], dict)):
                _reject("derived scalar assignment is not a supported named place")
        elif operation == "expr":
            if not isinstance(fields["expr"], dict):
                _reject("derived scalar expression statement lacks a value")
        elif operation == "return":
            if fields["expr"] is not None and not isinstance(fields["expr"], dict):
                _reject("derived scalar return has malformed value")
        elif operation in {"if", "while"}:
            condition = fields["condition"]
            if (not isinstance(condition, dict)
                    or condition.get("result_type") != {"type": "bool", "args": [], "length": None}
                    or not isinstance(fields["then" if operation == "if" else "body"], list)
                    or (operation == "if" and not isinstance(fields["else"], list))):
                _reject("derived scalar branch/loop has invalid condition or block")
        elif operation == "for":
            if (not isinstance(fields["name"], str) or not fields["name"]
                    or not isinstance(fields["start"], dict)
                    or not isinstance(fields["end"], dict)
                    or not isinstance(fields["body"], list)):
                _reject("derived scalar range loop is malformed")
        _validate_derived_node(value["span"], depth + 1)
        return sum(_validate_derived_node(item, depth + 1) for item in fields.values())
    _reject("unreviewed derived scalar node")


def _validate_derived_snapshot(obj: dict) -> None:
    claims = obj.get("claims")
    # Python considers False == 0 and True == 1. A rehashed integer claim
    # must not masquerade as proof or as canonical-encoder authority.
    if (set(obj) != _DERIVED_FIELDS or not isinstance(claims, dict)
            or set(claims) != set(_DERIVED_CLAIMS)
            or any(claims[key] is not expected
                   for key, expected in _DERIVED_CLAIMS.items())):
        _reject("derived snapshot inventory/claims differ from reviewed scalar subset")
    if (not isinstance(obj.get("source_sha256"), str)
            or _HASH.fullmatch(obj["source_sha256"]) is None
            or not isinstance(obj.get("source_semantic_sha256"), str)
            or _HASH.fullmatch(obj["source_semantic_sha256"]) is None
            or (obj.get("project_sha256") is not None
                and (not isinstance(obj["project_sha256"], str)
                     or _HASH.fullmatch(obj["project_sha256"]) is None))):
        _reject("derived snapshot lacks source/semantic identity")
    if any(not isinstance(obj.get(name), list) or obj[name]
           for name in ("imports", "structs", "enums", "external_assumptions")):
        _reject("derived scalar snapshot must not contain foreign or nominal content")
    if not isinstance(obj.get("functions"), list):
        _reject("derived snapshot requires function inventory")
    count = 0
    for fn in obj["functions"]:
        if (not isinstance(fn, dict) or set(fn) != _DERIVED_FUNCTION_FIELDS
                or not isinstance(fn.get("name"), str)
                or type(fn.get("public")) is not bool
                or fn.get("type_parameters") != []
                or not isinstance(fn.get("direction"), str)
                or fn.get("direction") not in {"local", "export"}
                or not isinstance(fn.get("abi"), str)
                or fn.get("abi") not in {"C", "hepta_unstable"}
                or not isinstance(fn.get("body"), list)
                or not isinstance(fn.get("param_types"), list)
                or not isinstance(fn.get("resource_contract"), dict)):
            _reject("derived function has unsupported ownership, ABI or metadata")
        _validate_derived_node(fn["return_type"])
        _validate_derived_node(fn["span"])
        for param in fn["param_types"]:
            if (not isinstance(param, dict)
                    or set(param) != {"name", "ownership", "type", "span"}
                    or param.get("ownership") != "value"
                    or not isinstance(param.get("name"), str)):
                _reject("derived scalar parameter ownership differs")
            _validate_derived_node(param["type"])
            _validate_derived_node(param["span"])
        count += _validate_derived_node(fn["body"])
    if type(obj.get("typed_expression_count")) is not int or count != obj["typed_expression_count"]:
        _reject("derived expression inventory is not complete")


def _type(obj: Any, context: str) -> dict:
    """Do not invent an ABI/ownership shape from an arbitrary type string."""
    if isinstance(obj, str):
        name = obj
    elif (isinstance(obj, dict) and set(obj) == _TYPE_FIELDS
          and obj.get("node") == "type"
          and obj.get("args") == [] and obj.get("length") is None):
        name = obj.get("name")
    else:
        _reject(f"{context}: unsupported type structure")
    if not isinstance(name, str) or name not in _TYPES:
        _reject(f"{context}: type {name!r} is outside scalar bridge")
    return {"type": name, "args": [], "length": None}


def _value(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, list):
        return [_value(v) for v in value]
    if not isinstance(value, dict):
        _reject("unsupported semantic value")
    if "node" not in value:
        if not all(isinstance(k, str) for k in value):
            _reject("non-string semantic key")
        return {k: _value(v) for k, v in value.items()}
    kind = value["node"]
    if kind == "type":
        return _type(value, "embedded type")
    if kind == "expr":
        if set(value) != _EXPR_FIELDS:
            _reject("unreviewed scalar expression fields")
        if (not isinstance(value.get("op"), str) or value.get("op") not in _EXPR
                or value.get("type_args") not in ([], None)):
            _reject(f"unhandled expression {value.get('op')!r}")
        if not isinstance(value.get("args"), list):
            _reject("malformed expression operands")
        return {"node": "expr", "operation": value["op"],
                "result_type": _type(value.get("type"), "expression"),
                "value": _value(value.get("value")),
                "operands": [_value(v) for v in value["args"]],
                "type_args": [], "span": value.get("span")}
    if kind == "stmt":
        if set(value) != _STMT_FIELDS:
            _reject("unreviewed scalar statement fields")
        operation, data = value.get("op"), value.get("data")
        if not isinstance(operation, str) or operation not in _STMT or not isinstance(data, dict):
            _reject(f"unhandled statement {operation!r}")
        if set(data) != _STMT_DATA_FIELDS[operation]:
            _reject(f"unreviewed {operation} statement data fields")
        return {"node": "stmt", "operation": operation,
                "fields": _value(data), "span": value.get("span")}
    _reject(f"unhandled semantic node {kind!r}")


def from_canonical_snapshot(source: dict[str, Any]) -> HSIRSnapshot:
    """Convert a checked canonical HSIR snapshot to the PR #37 scalar shape.

    The source digest is recomputed before conversion and included in the
    derived snapshot. No structurally unsupported node is silently omitted.
    This is an integrity and subset check, not independent type validation.
    """
    if not isinstance(source, dict) or source.get("schema") != CANONICAL_SCHEMA:
        _reject("requires canonical hepta.hsir.v0, not a derived scalar snapshot")
    parent_digest = source.get("sha256")
    if not isinstance(parent_digest, str) or _HASH.fullmatch(parent_digest) is None:
        _reject("missing canonical snapshot identity")
    parent = {k: v for k, v in source.items() if k != "sha256"}
    try:
        observed_digest = sha256(_json(parent).encode("utf-8")).hexdigest()
    except (TypeError, ValueError, RecursionError) as exc:
        raise HSIRRejected("E_HSIR_BRIDGE: canonical snapshot is not serializable") from exc
    if observed_digest != parent_digest:
        _reject("canonical snapshot checksum mismatch")
    if set(source) != _CANONICAL_FIELDS:
        _reject("canonical HSIR field inventory differs from reviewed v0 semantics")
    if (source.get("profile") != "checked_typed_ast_not_verified_mir"
            or source.get("all_expressions_typed") is not True
            or source.get("untyped_expressions")):
        _reject("source has not established a fully typed checked AST")
    claims = source.get("claims")
    if (not isinstance(claims, dict) or set(claims) != _CANONICAL_CLAIMS
            or any(v is not False for v in claims.values())):
        _reject("source claims exceed canonical prototype guarantees")
    # Missing inventories, falsey non-list values and hidden owned types must
    # never be interpreted as proof that this scalar projection is complete.
    restricted = ("imports", "structs", "enums", "external_obligations",
                  "foreign_assumptions", "volatile_accesses", "owned_types")
    if any(not isinstance(source[k], list) or source[k] for k in restricted):
        _reject("nominal/owned types or external obligations require dedicated lowering")
    if not isinstance(source.get("functions"), list):
        _reject("missing function inventory")
    if not isinstance(source.get("source_sha256"), str) or _HASH.fullmatch(source["source_sha256"]) is None:
        _reject("missing source content identity")

    functions = []
    count = 0
    for fn in source["functions"]:
        if not isinstance(fn, dict) or set(fn) != _FUNCTION_FIELDS or not isinstance(fn.get("name"), str):
            _reject("missing or unreviewed function semantic fields")
        if (fn.get("type_params") or fn.get("lifetime_params") or fn.get("return_mode") != "value"
                or fn.get("return_origin") is not None or fn.get("extern_c")
                or fn.get("type_bounds")):
            _reject(f"{fn['name']}: lifetime, generic or foreign declaration not yet supported")
        if fn.get("body") is None or not isinstance(fn.get("body"), list):
            _reject(f"{fn['name']}: body is required")
        if not isinstance(fn.get("params"), list):
            _reject(f"{fn['name']}: malformed parameters")
        params = []
        for p in fn["params"]:
            if (not isinstance(p, dict) or set(p) != _PARAMETER_FIELDS
                    or p.get("mode") != "value" or not isinstance(p.get("name"), str)):
                _reject(f"{fn['name']}: borrowed/owned parameters require ownership-aware SSA")
            params.append({"name": p["name"], "ownership": "value",
                           "type": _type(p.get("type"), "parameter"), "span": p.get("span")})
        body = _value(fn["body"])
        count += sum(1 for _ in _walk_expressions(body))
        functions.append({"name": fn["name"], "param_types": params,
                          "return_type": _type(fn.get("returns"), "result"),
                          "declared_effects": fn.get("declared_effects"),
                          "inferred_transitive_effects": fn.get("inferred_effects"),
                          "resource_contract": fn.get("resources"),
                          "type_parameters": [],
                          "abi": "C" if fn.get("export_c") else "hepta_unstable",
                          "direction": "export" if fn.get("export_c") else "local",
                          "public": fn.get("public"), "body": body,
                          "span": fn.get("declaration_span")})
    payload = {
        "schema": SCHEMA, "status": _STATUS,
        "program": source.get("module"), "source_sha256": source["source_sha256"],
        "source_semantic_sha256": parent_digest,
        "project_sha256": source.get("project_sha256"),
        "imports": [], "structs": [], "enums": [], "functions": functions,
        "external_assumptions": [], "resource_contracts": source.get("resource_contracts"),
        "typed_expression_count": count,
        "claims": {"lifetimes_fully_modeled": False,
                   "pointer_provenance_proved": False,
                   "source_semantics_refined": False,
                   "native_backend_equivalence_proved": False,
                   "canonical_semantics_still_authoritative": True},
    }
    encoded = _json(payload)
    return HSIRSnapshot(SCHEMA, encoded, sha256(encoded.encode("utf-8")).hexdigest())


def _walk_expressions(obj: Any):
    if isinstance(obj, dict):
        if obj.get("node") == "expr":
            yield obj
        for value in obj.values():
            yield from _walk_expressions(value)
    elif isinstance(obj, list):
        for value in obj:
            yield from _walk_expressions(value)


def lower_checked_program(program: Any, checked: Any, *,
                          project_sha256: str | None = None) -> HSIRSnapshot:
    """One canonical checked semantic producer, with optional exact project graph."""
    return from_canonical_snapshot(
        _lower_canonical(program, checked, project_sha256=project_sha256))

def verify_checked_source_projection(program: Any, checked: Any,
                                    snapshot: HSIRSnapshot, *,
                                    project_sha256: str | None = None) -> dict:
    """Re-derive the scalar view from the *same* sole canonical producer.

    This source-identity gate catches rehashed scalar snapshots submitted as
    though they came from the checked AST. It neither independently proves
    source semantics nor verifies the native LLVM backend.
    """
    if not isinstance(snapshot, HSIRSnapshot):
        raise HSIRRejected("E_HSIR_SOURCE_ORIGIN: typed scalar snapshot required")
    canonical = _lower_canonical(
        program, checked, project_sha256=project_sha256)
    expected = from_canonical_snapshot(canonical)
    if snapshot != expected:
        raise HSIRRejected("E_HSIR_SOURCE_ORIGIN: derived snapshot differs from checked source")
    payload = snapshot.as_dict()
    if payload.get("source_semantic_sha256") != canonical["sha256"]:
        raise HSIRRejected("E_HSIR_SOURCE_ORIGIN: canonical semantic digest disagrees")
    result = {
        "schema": "hepta.hsir.source-origin.v1",
        "status": "exact_source_rederived_not_semantic_refinement_proof",
        "canonical_schema": CANONICAL_SCHEMA,
        "canonical_sha256": canonical["sha256"],
        "derived_schema": SCHEMA,
        "derived_sha256": snapshot.sha256,
        "source_sha256": canonical["source_sha256"],
        "claims": {
            "canonical_semantic_producer_unique": True,
            "checked_source_projection_rederived": True,
            "whole_language_soundness_proven": False,
            "native_backend_refinement_proven": False,
        },
    }
    # Preserve the frozen no-project v1 receipt shape. A project-bound
    # semantic receipt has a new version rather than silently extending v1.
    if project_sha256 is not None:
        result["schema"] = "hepta.hsir.source-origin.v2"
        result["project_sha256"] = canonical["project_sha256"]
    return result
