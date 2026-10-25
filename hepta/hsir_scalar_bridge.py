"""Strict source-bound-v0 -> frozen-snapshot-v0 *scalar analysis* bridge.

The result is for structural CFG/SSA verification ONLY. It does not grant
native code generation, equivalence, memory safety or foreign-call authority.
The original v1 envelope remains the immutable provenance root.
"""
from __future__ import annotations

import hashlib
import json
import math
import re

SCALARS = frozenset({"i8", "i16", "i32", "i64", "i128", "isize", "u8", "u16", "u32", "u64", "u128", "usize", "bool", "f32", "f64"})
BINARY = frozenset({"+", "-", "*", "/", "%", "==", "!=", "<", "<=", ">", ">=", "&&", "||", "&", "|", "^", "<<", ">>"})
ARITY = {"int": 0, "float": 0, "bool": 0, "name": 0, "binary": 2, "unary": 1}
STATEMENT_FIELDS = {"let": {"name", "type", "mutable", "expr"},
                    "assign": {"target", "expr"},
                    "expr": {"expr"}, "return": {"expr"},
                    "if": {"condition", "then", "else"},
                    "while": {"condition", "body"}}
SHA = re.compile(r"[0-9a-f]{64}\Z")

class ScalarBridgeRejected(ValueError):
    pass

def reject(code):
    raise ScalarBridgeRejected("E_SOURCE_SCALAR_" + code)

def exact_keys(node, allowed, code):
    if not isinstance(node, dict) or set(node) != allowed:
        reject(code)

def scalar_type(name):
    if not isinstance(name, str) or name not in SCALARS:
        reject("TYPE")
    return {"type": name, "args": [], "length": None}

def span(value):
    exact_keys(value, {"path", "start", "end", "line", "column"}, "SPAN")
    if (not isinstance(value["path"], str) or not value["path"] or
        any(type(value[k]) is not int for k in ("start", "end", "line", "column")) or
        value["start"] < 0 or value["end"] < value["start"] or
        value["line"] < 1 or value["column"] < 1):
        reject("SPAN")
    return dict(value)

def type_value(t):
    if t is None:
        return None
    exact_keys(t, {"node", "name", "args", "length"}, "TYPE_NODE")
    if t["node"] != "type" or t["args"] != [] or t["length"] is not None:
        reject("TYPE_NODE")
    return scalar_type(t["name"])

def expr(node, depth=0):
    if depth > 64:
        reject("DEPTH")
    exact_keys(node, {"node", "op", "type", "value", "args", "type_args", "span"}, "EXPR_SHAPE")
    if node["node"] != "expr" or not isinstance(node["args"], list) or node["type_args"] != []:
        reject("EXPR_SHAPE")
    op, value = node["op"], node["value"]
    if op not in ARITY or len(node["args"]) != ARITY[op]:
        reject("EXPR_OPERATION")
    ty = scalar_type(node["type"])
    if op == "binary" and value not in BINARY - {"&&", "||"}:
        # Short-circuit panic behavior needs dedicated expression CFG lowering.
        reject("BINARY")
    if op == "unary" and value not in ("-", "!"):
        reject("UNARY")
    if op == "name" and (not isinstance(value, str) or not value or "::" in value):
        reject("NAME")
    if op == "int" and (type(value) is not int or node["type"] not in SCALARS - {"bool", "f32", "f64"}):
        reject("INTEGER")
    if op == "bool" and (type(value) is not bool or node["type"] != "bool"):
        reject("BOOLEAN")
    if op == "float" and (type(value) not in (int, float) or node["type"] not in ("f32", "f64") or not math.isfinite(value)):
        reject("FLOAT")
    operands = [expr(x, depth+1) for x in node["args"]]
    return {"node": "expr", "operation": op, "result_type": ty,
            "value": value, "operands": operands, "type_args": [], "span": span(node["span"])}

def statements(nodes, depth=0):
    if not isinstance(nodes, list) or depth > 64:
        reject("STMT_LIST")
    output = []
    for node in nodes:
        exact_keys(node, {"node", "op", "data", "span"}, "STMT_SHAPE")
        op, fields = node["op"], node["data"]
        if node["node"] != "stmt" or op not in STATEMENT_FIELDS:
            reject("STMT_OPERATION")
        exact_keys(fields, STATEMENT_FIELDS[op], "STMT_FIELDS")
        if op == "let":
            if type(fields["mutable"]) is not bool or not isinstance(fields["name"], str) or not fields["name"]:
                reject("LET")
            converted = {"name": fields["name"], "type": type_value(fields["type"]),
                         "mutable": fields["mutable"], "expr": expr(fields["expr"])}
        elif op == "assign":
            converted = {"target": expr(fields["target"]), "expr": expr(fields["expr"])}
        elif op == "expr":
            converted = {"expr": expr(fields["expr"])}
        elif op == "return":
            converted = {"expr": expr(fields["expr"]) if fields["expr"] is not None else None}
        elif op == "if":
            converted = {"condition": expr(fields["condition"]),
                         "then": statements(fields["then"], depth+1),
                         "else": statements(fields["else"], depth+1)}
        else:
            converted = {"condition": expr(fields["condition"]),
                         "body": statements(fields["body"], depth+1)}
        output.append({"node": "stmt", "operation": op, "fields": converted,
                       "span": span(node["span"])})
    return output

def empty(x):
    return x in (None, [], {}, ())

def effects(x):
    if not isinstance(x, list) or x != sorted(set(x)) or not set(x) <= {"panic"}:
        reject("EFFECTS")
    return list(x)

def lower_source_bound_scalar(legacy):
    """Translate a proved-*shape* subset; preserve complete provenance externally.

    Caller MUST validate HSIR v1 wrapper and embedded legacy hash first.
    Returned frozen-format tree is a new derived artifact, not a v0 producer.
    """
    if not isinstance(legacy, dict) or legacy.get("schema") != "hepta.hsir.v0" or legacy.get("profile") != "checked_typed_ast_not_verified_mir":
        reject("PROFILE")
    # Producer v0 is pinned: rejecting unknown fields prevents new resource or
    # provenance semantics from being silently discarded by this translator.
    exact_keys(legacy, {"schema", "profile", "module", "path", "source_sha256",
                        "project_sha256", "imports", "structs", "enums", "functions",
                        "untyped_expressions", "all_expressions_typed", "external_obligations",
                        "volatile_accesses", "foreign_assumptions", "resource_contracts",
                        "owned_types", "claims", "sha256"}, "PROGRAM_FIELDS")
    if any(not empty(legacy.get(k)) for k in ("imports", "structs", "enums", "owned_types", "volatile_accesses", "external_obligations", "foreign_assumptions", "resource_contracts")):
        reject("PROGRAM_RESOURCE_OR_EXTERNAL")
    if legacy.get("all_expressions_typed") is not True or legacy.get("untyped_expressions") != []:
        reject("UNTYPED")
    source = legacy.get("source_sha256")
    if not isinstance(source, str) or not SHA.fullmatch(source):
        reject("SOURCE_ID")
    if not isinstance(legacy.get("module"), str) or not isinstance(legacy.get("functions"), list):
        reject("PROGRAM")
    functions, expression_count, seen = [], 0, set()
    for f in legacy["functions"]:
        if not isinstance(f, dict) or not isinstance(f.get("name"), str) or not f["name"] or f["name"] in seen:
            reject("FUNCTION")
        seen.add(f["name"])
        if (not isinstance(f.get("path"), str) or not f["path"] or
            type(f.get("public")) is not bool):
            reject("FUNCTION")
        span(f.get("body_span"))
        permitted = {"name", "path", "declaration_span", "body_span", "public",
                     "extern_c", "export_c", "type_params", "type_bounds", "params",
                     "returns", "return_mode", "return_origin", "declared_effects",
                     "inferred_effects", "resources", "body"}
        optional = {"lifetime_params", "return_lifetime"}
        if not permitted.issubset(f) or set(f) - permitted - optional:
            reject("FUNCTION_FIELDS")
        if (f.get("extern_c") is not False or type(f.get("export_c")) is not bool or
            not empty(f.get("type_params")) or not empty(f.get("lifetime_params")) or
            not empty(f.get("type_bounds")) or not empty(f.get("resources")) or
            f.get("return_mode") != "value" or f.get("return_origin") is not None or
            not empty(f.get("return_lifetime"))):
            reject("FUNCTION_RESOURCE_OR_BORROW")
        params = f.get("params")
        if not isinstance(params, list):
            reject("PARAMETERS")
        new_params, param_names = [], set()
        for p in params:
            if not isinstance(p, dict) or p.get("mode") != "value" or p.get("lifetime") is not None:
                reject("OWNERSHIP")
            name = p.get("name")
            if not isinstance(name, str) or not name or name in param_names:
                reject("PARAMETERS")
            param_names.add(name)
            new_params.append({"name": name, "type": scalar_type(p.get("type")),
                               "ownership": "value", "span": span(p.get("span"))})
        body = statements(f.get("body"))
        def count_expressions(tree):
            nonlocal expression_count
            todo = [tree]
            while todo:
                item = todo.pop()
                if isinstance(item, dict):
                    if item.get("node") == "expr":
                        expression_count += 1
                    todo.extend(item.values())
                elif isinstance(item, list):
                    todo.extend(item)
        count_expressions(body)
        direction = "export" if f["export_c"] else "local"
        functions.append({"name": f["name"], "param_types": new_params,
                          "return_type": scalar_type(f.get("returns")),
                          "declared_effects": effects(f.get("declared_effects")),
                          "inferred_transitive_effects": effects(f.get("inferred_effects")),
                          "resource_contract": {}, "type_parameters": [],
                          "abi": "C" if direction == "export" else "hepta_unstable",
                          "direction": direction, "public": f.get("public") is True,
                          "body": body, "span": span(f.get("declaration_span"))})
    result = {"schema": "hepta.hsir.v0", "status": "checked_frontend_snapshot_not_proved",
              "program": legacy["module"], "source_sha256": source, "imports": [],
              "structs": [], "enums": [], "functions": functions,
              "external_assumptions": [], "resource_contracts": [],
              "typed_expression_count": expression_count,
              "claims": {"lifetimes_fully_modeled": False, "pointer_provenance_proved": False,
                         "source_semantics_refined": False, "native_backend_equivalence_proved": False}}
    raw = json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    return raw, digest
