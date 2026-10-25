"""Source-revalidated PR14 -> PR37 scalar CFG/SSA interoperability gate.

Never reinterpret the PR14 typed display strings as a general proof of Rust-like
ownership. Only byte-matched source that the destination Hepta compiler
independently parses, checks and validates *natively* may enter its SSA path.
All foreign, resource-owning, borrowing and generic constructs fail closed.
"""
from __future__ import annotations

from hashlib import sha256
import json

from .hsir_v1 import HSIRV1Rejected, integrate_v0, verify_v1
from .hsir_v1_ssa import V1SSARejected, lower_verified_v1_scalar_ssa


class SourceBoundReconcileRejected(ValueError):
    pass


SCALARS = frozenset({"bool", "i8", "i16", "i32", "i64", "i128", "isize",
                     "u8", "u16", "u32", "u64", "u128", "usize", "f32", "f64"})
BINARY = frozenset({"+", "-", "*", "/", "%", "==", "!=", "<", "<=", ">", ">=",
                     "&&", "||", "&", "|", "^", "<<", ">>"})
_UNARY = frozenset({"-", "!"})
_MAX_SOURCE = 1024 * 1024
_MAX_DEPTH = 64


def fail(reason: str) -> None:
    raise SourceBoundReconcileRejected("E_SOURCE_BOUND_SSA_" + reason)


def simple_type(value):
    if not isinstance(value, str) or value not in SCALARS:
        fail("NONSCALAR_TYPE")
    return {"type": value, "args": [], "length": None}


def value_type(value):
    if (not isinstance(value, dict) or value.get("node") != "type" or
            not isinstance(value.get("name"), str) or
            value.get("args") != [] or value.get("length") is not None or
            set(value) != {"node", "name", "args", "length"}):
        fail("COMPLEX_TYPE")
    return simple_type(value["name"])


def expr(node, depth=0):
    if depth > _MAX_DEPTH or not isinstance(node, dict) or node.get("node") != "expr":
        fail("EXPRESSION_SHAPE")
    if set(node) != {"node", "op", "type", "value", "args", "type_args", "span"}:
        fail("EXPRESSION_FIELDS")
    kind, operands = node["op"], node["args"]
    arity = {"int": 0, "bool": 0, "float": 0, "name": 0,
             "binary": 2, "unary": 1, "cast": 1}.get(kind)
    if arity is None or not isinstance(operands, list) or len(operands) != arity:
        fail("EXPRESSION_OPERATOR")
    if node["type_args"] != []:
        fail("GENERIC_EXPRESSION")
    ty = simple_type(node["type"])
    value = node["value"]
    if kind == "binary" and value not in BINARY:
        fail("BINARY_OPERATOR")
    if kind == "unary" and value not in _UNARY:
        fail("UNARY_OPERATOR")
    if kind == "name" and (not isinstance(value, str) or not value or "::" in value):
        fail("NONLOCAL_NAME")
    if kind == "int" and (type(value) is not int or ty["type"] not in SCALARS - {"bool", "f32", "f64"}):
        fail("INTEGER_LITERAL")
    if kind == "bool" and (type(value) is not bool or ty["type"] != "bool"):
        fail("BOOLEAN_LITERAL")
    if kind == "float" and (type(value) not in (int, float) or ty["type"] not in {"f32", "f64"}):
        fail("FLOAT_LITERAL")
    if kind == "cast":
        value = value_type(value)
        if value != ty:
            fail("CAST_TYPE")
    return {"node": "expr", "operation": kind, "result_type": ty,
            "value": value, "operands": [expr(child, depth + 1) for child in operands],
            "type_args": []}


def body(stmts, depth=0):
    if depth > _MAX_DEPTH or not isinstance(stmts, list):
        fail("STATEMENTS_SHAPE")
    out = []
    for stmt in stmts:
        if not isinstance(stmt, dict) or set(stmt) != {"node", "op", "data", "span"} or stmt["node"] != "stmt":
            fail("STATEMENT_FIELDS")
        op, data = stmt["op"], stmt["data"]
        if not isinstance(data, dict):
            fail("STATEMENT_SHAPE")
        if op == "let":
            if set(data) != {"name", "type", "mutable", "expr"} or type(data["mutable"]) is not bool:
                fail("LET_SHAPE")
            if not isinstance(data["name"], str) or not data["name"]:
                fail("LET_NAME")
            fields = {"name": data["name"], "type": None if data["type"] is None else value_type(data["type"]),
                      "mutable": data["mutable"], "expr": expr(data["expr"], depth + 1)}
        elif op == "assign":
            if set(data) != {"target", "expr"}:
                fail("ASSIGN_FIELDS")
            target = expr(data["target"], depth + 1)
            if target["operation"] != "name":
                fail("ASSIGN_NONLOCAL")
            fields = {"target": target, "expr": expr(data["expr"], depth + 1)}
        elif op in ("expr", "return"):
            if set(data) != {"expr"} or data["expr"] is None:
                fail("STATEMENT_EXPRESSION")
            fields = {"expr": expr(data["expr"], depth + 1)}
        elif op == "while":
            if set(data) != {"condition", "body"}:
                fail("WHILE_SHAPE")
            cond = expr(data["condition"], depth + 1)
            if cond["result_type"]["type"] != "bool":
                fail("CONDITION_TYPE")
            fields = {"condition": cond, "body": body(data["body"], depth + 1)}
        elif op == "if":
            if set(data) != {"condition", "then", "else"}:
                fail("IF_SHAPE")
            cond = expr(data["condition"], depth + 1)
            if cond["result_type"]["type"] != "bool":
                fail("CONDITION_TYPE")
            fields = {"condition": cond, "then": body(data["then"], depth + 1),
                      "else": body(data["else"], depth + 1)}
        else:
            fail("UNSUPPORTED_STATEMENT")
        out.append({"node": "stmt", "operation": op, "fields": fields})
    return out


def no_spans(value):
    if isinstance(value, dict):
        return {k: no_spans(v) for k, v in value.items() if k != "span"}
    if isinstance(value, list):
        return [no_spans(v) for v in value]
    return value


def require_safe_source_bound(legacy):
    if any(legacy.get(field) not in ([], {}) for field in
           ("external_obligations", "foreign_assumptions", "volatile_accesses", "owned_types", "resource_contracts")):
        fail("EXTERNAL_OR_OWNED")
    if legacy.get("imports") != [] or legacy.get("structs") != [] or legacy.get("enums") != []:
        fail("MULTIMODULE_OR_TYPES")
    if legacy.get("all_expressions_typed") is not True or legacy.get("untyped_expressions") != []:
        fail("UNTYPED")
    fs = legacy.get("functions")
    if not isinstance(fs, list) or not fs:
        fail("EMPTY_FUNCTIONS")
    results = []
    for fn in fs:
        if not isinstance(fn, dict) or not isinstance(fn.get("name"), str):
            fail("FUNCTION")
        if fn.get("extern_c") is not False or type(fn.get("export_c")) is not bool:
            fail("FOREIGN")
        if (fn.get("return_mode") != "value" or fn.get("return_origin") is not None or
                fn.get("type_params") != [] or fn.get("lifetime_params", []) != [] or
                fn.get("type_bounds") not in ({}, None) or fn.get("return_lifetime") is not None):
            fail("BORROW_OR_GENERIC")
        if fn.get("resources") not in ({}, None):
            fail("RESOURCE_CLAUSE")
        if any(fn.get(which) not in ([], ["panic"]) for which in ("declared_effects", "inferred_effects")):
            fail("EFFECT")
        params = fn.get("params")
        if not isinstance(params, list):
            fail("PARAMETERS")
        parameters = []
        for p in params:
            if (not isinstance(p, dict) or not isinstance(p.get("name"), str) or
                    p.get("mode") != "value" or p.get("lifetime") is not None):
                fail("BORROWED_PARAMETER")
            parameters.append({"name": p["name"], "type": simple_type(p.get("type")),
                               "ownership": "value"})
        if not isinstance(fn.get("body"), list):
            fail("FUNCTION_BODY")
        results.append({"name": fn["name"], "param_types": parameters,
                        "return_type": simple_type(fn.get("returns")),
                        "declared_effects": fn["declared_effects"],
                        "inferred_transitive_effects": fn["inferred_effects"],
                        "resource_contract": {}, "abi": "C" if fn["export_c"] else "hepta_unstable",
                        "direction": "export" if fn["export_c"] else "local",
                        "public": fn.get("public", False), "body": body(fn["body"])})
    if len({f["name"] for f in results}) != len(results):
        fail("DUPLICATE_FUNCTION")
    return results


def assert_same_derived_semantics(original, derived):
    expected = require_safe_source_bound(original)
    actual = derived.get("functions")
    if not isinstance(actual, list) or len(actual) != len(expected):
        fail("FUNCTION_INVENTORY")
    for left, right in zip(expected, actual):
        if not isinstance(right, dict):
            fail("TARGET_FUNCTION_SHAPE")
        for field in left:
            if no_spans(left[field]) != no_spans(right.get(field)):
                fail("DIVERGENT_" + field.upper())


def reconcile_source_bound_to_ssa(envelope, source: str, *, path: str = "<input>", rustc=None):
    """Recompile the exact source under the destination compiler, then compare.

    This API is intentionally native-only; a caller cannot claim compatibility
    by supplying an unchecked frontend report or by rehashing fake safety tags.
    """
    try:
        verify_v1(envelope)
    except HSIRV1Rejected as exc:
        raise SourceBoundReconcileRejected("E_SOURCE_BOUND_SSA_V1_IDENTITY: " + str(exc)) from exc
    if envelope["producer"]["wire_profile"] != "source_bound_v0":
        fail("UNSUPPORTED_PRODUCER")
    if not isinstance(source, str) or len(source.encode("utf-8")) > _MAX_SOURCE:
        fail("SOURCE_LIMIT")
    source_sha = sha256(source.encode("utf-8")).hexdigest()
    if envelope["producer"]["source_sha256"] != source_sha:
        fail("SOURCE_SHA_MISMATCH")
    legacy = envelope["opaque_producer_payload"]
    require_safe_source_bound(legacy)
    # This compiler invocation executes real native Rust borrow/type checking.
    from .pipeline import analyze
    checked = analyze(source, path, rustc=rustc, native=True, backend="rust", crate_type="rlib")
    if (not checked.report.get("ok") or checked.report.get("status") != "checked" or
            checked.report.get("checks", {}).get("rust_borrows_types") != "rustc_checked"):
        fail("NATIVE_REVALIDATION")
    from .hsir import lower_checked_program
    target = lower_checked_program(checked.program, checked.checked).as_dict()
    if target.get("source_sha256") != source_sha:
        fail("TARGET_SOURCE_SHA")
    assert_same_derived_semantics(legacy, target)
    try:
        qualified = lower_verified_v1_scalar_ssa(integrate_v0(target, expected_source_sha256=source_sha))
    except (HSIRV1Rejected, V1SSARejected) as exc:
        raise SourceBoundReconcileRejected("E_SOURCE_BOUND_SSA_TARGET_IR: " + str(exc)) from exc
    result = {"schema": "hepta.source-bound-ssa.reconciliation.v1",
              "status": "native_rechecked_scalar_subset_not_semantics_proved",
              "source_sha256": source_sha,
              "source_bound_v1_sha256": envelope["sha256"],
              "source_bound_v0_sha256": envelope["producer"]["legacy_sha256"],
              "recompiled_frozen_v0_sha256": target["sha256"],
              "ssa_verified": qualified,
              "external_project_identity_revalidated": False,
              "native_reference_validation": checked.report,
              "claims": {"exact_source_bytes_matched": True,
                         "source_bound_scalar_structure_compared": True,
                         "native_target_compiler_passed": True,
                         "general_lifetimes_proved": False,
                         "source_to_ir_equivalence_proved": False,
                         "safe_for_native_codegen_without_separate_gate": False,
                         "whole_language_soundness_proved": False}}
    canonical = json.dumps(result, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False, allow_nan=False).encode("utf-8")
    result["sha256"] = sha256(canonical).hexdigest()
    return result
