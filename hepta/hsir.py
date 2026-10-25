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

SCHEMA = "hepta.hsir.v0"
_STATUS = "checked_frontend_snapshot_not_proved"
_SCALARS = frozenset({"bool", "i8", "i16", "i32", "i64", "i128", "isize",
                      "u8", "u16", "u32", "u64", "u128", "usize", "f32", "f64"})
_TYPES = _SCALARS | {"Unit"}
_EXPR = frozenset({"name", "int", "float", "bool", "binary", "unary", "cast"})
_STMT = frozenset({"let", "assign", "expr", "return", "if", "while", "for"})
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
# This scalar SSA adapter has no semantics for allocation, IO, FFI, raw
# pointers, blocking, spawning or arbitrary unsafe effects. The canonical
# frontend retains authority for full-language effect derivation.
_SCALAR_EFFECTS = frozenset({"panic"})
_SCALAR_RESOURCE_CLAUSES = frozenset({
    "heap_allocations", "may_block", "may_suspend", "may_spawn",
})


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
        if sha256(self.canonical_json.encode("utf-8")).hexdigest() != self.sha256:
            raise HSIRRejected("E_HSIR_SNAPSHOT: changed snapshot content")
        try:
            obj = json.loads(self.canonical_json)
        except (TypeError, ValueError) as exc:
            raise HSIRRejected("E_HSIR_SNAPSHOT: invalid JSON") from exc
        if not isinstance(obj, dict) or obj.get("schema") != SCHEMA or obj.get("status") != _STATUS:
            raise HSIRRejected("E_HSIR_SNAPSHOT: schema/status mismatch")
        return {**obj, "sha256": self.sha256}


def _reject(reason: str) -> None:
    raise HSIRRejected("E_HSIR_BRIDGE: " + reason)


def _json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":"))


def _type(obj: Any, context: str) -> dict:
    """Do not invent an ABI/ownership shape from an arbitrary type string."""
    if isinstance(obj, str):
        name = obj
    elif (isinstance(obj, dict) and obj.get("node") == "type"
          and obj.get("args") == [] and obj.get("length") is None):
        name = obj.get("name")
    else:
        _reject(f"{context}: unsupported type structure")
    if name not in _TYPES:
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
        if value.get("op") not in _EXPR or value.get("type_args") not in ([], None):
            _reject(f"unhandled expression {value.get('op')!r}")
        if not isinstance(value.get("args"), list):
            _reject("malformed expression operands")
        return {"node": "expr", "operation": value["op"],
                "result_type": _type(value.get("type"), "expression"),
                "value": _value(value.get("value")),
                "operands": [_value(v) for v in value["args"]],
                "type_args": [], "span": value.get("span")}
    if kind == "stmt":
        if value.get("op") not in _STMT or not isinstance(value.get("data"), dict):
            _reject(f"unhandled statement {value.get('op')!r}")
        return {"node": "stmt", "operation": value["op"],
                "fields": _value(value["data"]), "span": value.get("span")}
    _reject(f"unhandled semantic node {kind!r}")


def from_canonical_snapshot(source: dict[str, Any]) -> HSIRSnapshot:
    """Convert a checked canonical HSIR snapshot to the PR #37 scalar shape.

    The source digest is recomputed before conversion and included in the
    derived snapshot. No structurally unsupported node is silently omitted.
    This is an integrity and subset check, not independent type validation.
    """
    if not isinstance(source, dict) or source.get("schema") != SCHEMA:
        _reject("requires canonical hepta.hsir.v0")
    parent_digest = source.get("sha256")
    if not isinstance(parent_digest, str) or _HASH.fullmatch(parent_digest) is None:
        _reject("missing canonical snapshot identity")
    parent = {k: v for k, v in source.items() if k != "sha256"}
    if sha256(_json(parent).encode("utf-8")).hexdigest() != parent_digest:
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
        if not isinstance(fn, dict) or not isinstance(fn.get("name"), str):
            _reject("invalid function")
        if (fn.get("type_params") or fn.get("lifetime_params") or fn.get("return_mode") != "value"
                or fn.get("return_origin") is not None or fn.get("extern_c")
                or fn.get("type_bounds")):
            _reject(f"{fn['name']}: lifetime, generic or foreign declaration not yet supported")
        if fn.get("body") is None or not isinstance(fn.get("body"), list):
            _reject(f"{fn['name']}: body is required")
        if not isinstance(fn.get("params"), list):
            _reject(f"{fn['name']}: malformed parameters")
        declared = fn.get("declared_effects")
        inferred = fn.get("inferred_effects")
        if (not isinstance(declared, list) or not isinstance(inferred, list)
                or any(not isinstance(effect, str) or effect not in _SCALAR_EFFECTS
                       for effect in [*declared, *inferred])
                or len(set(declared)) != len(declared)
                or len(set(inferred)) != len(inferred)
                or not set(inferred).issubset(declared)):
            _reject(f"{fn['name']}: effects exceed the reviewed scalar SSA profile")
        resources = fn.get("resources")
        if not isinstance(resources, dict) or set(resources) - _SCALAR_RESOURCE_CLAUSES:
            _reject(f"{fn['name']}: unsupported scalar resource contract")
        for key, value in resources.items():
            if key == "heap_allocations":
                if type(value) is not int or value != 0:
                    _reject(f"{fn['name']}: heap allocation contract requires integer zero")
            elif value is not False:
                _reject(f"{fn['name']}: scalar nonblocking resource contract must be false")
        params = []
        for p in fn["params"]:
            if not isinstance(p, dict) or p.get("mode") != "value" or not isinstance(p.get("name"), str):
                _reject(f"{fn['name']}: borrowed/owned parameters require ownership-aware SSA")
            params.append({"name": p["name"], "ownership": "value",
                           "type": _type(p.get("type"), "parameter"), "span": p.get("span")})
        body = _value(fn["body"])
        count += sum(1 for _ in _walk_expressions(body))
        functions.append({"name": fn["name"], "param_types": params,
                          "return_type": _type(fn.get("returns"), "result"),
                          "declared_effects": declared,
                          "inferred_transitive_effects": inferred,
                          "resource_contract": resources,
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


def lower_checked_program(program: Any, checked: Any) -> HSIRSnapshot:
    """Reference frontend checker -> single canonical semantic IR -> scalar adapter."""
    return from_canonical_snapshot(_lower_canonical(program, checked))
