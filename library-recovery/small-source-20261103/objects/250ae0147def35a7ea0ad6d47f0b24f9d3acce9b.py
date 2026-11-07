"""Checked HSIR-v1 exchange -> existing pr36 scalar CFG/SSA/verify consumer.

The frozen producer passes unchanged. PR#14 source-bound input is admitted only
through a strict, allocation-free scalar mapping with no FFI, owner, borrow,
lifetime or external-obligation semantics. Neither path authorizes LLVM codegen.
"""
from __future__ import annotations

from hashlib import sha256
import json

from .hsir_v1 import HSIRV1Rejected, verify_v1


class V1SSARejected(ValueError):
    pass


def lower_verified_v1_scalar_ssa(envelope: dict) -> dict:
    """Run existing typed CFG -> scalar SSA -> independent SSA verification.

    The input snapshot is checked twice: its v1 projection must reconstruct
    exactly from the original v0 payload, and all output graph identities
    must match the original legacy source and one another.
    """
    try:
        verify_v1(envelope)
    except HSIRV1Rejected as exc:
        raise V1SSARejected("E_V1_SSA_IDENTITY: " + str(exc)) from exc
    original_producer = envelope["producer"]
    mapped = envelope
    bridge_receipt = None
    if original_producer["wire_profile"] == "source_bound_v0":
        from .hsir_v1_scalar_bridge import ScalarBridgeRejected, source_bound_to_frozen
        try:
            bridge_receipt = source_bound_to_frozen(envelope)
        except ScalarBridgeRejected as exc:
            raise V1SSARejected("E_V1_SSA_UNSUPPORTED_PRODUCER: " + str(exc)) from exc
        mapped = bridge_receipt["mapped_hsir_v1"]
    elif original_producer["wire_profile"] != "frozen_snapshot_v0":
        raise V1SSARejected("E_V1_SSA_UNSUPPORTED_PRODUCER")
    try:
        verify_v1(mapped)
    except HSIRV1Rejected as exc:
        raise V1SSARejected("E_V1_SSA_MAPPED_IDENTITY: " + str(exc)) from exc
    producer = mapped["producer"]
    from .hsir import HSIRSnapshot
    from .cfg import lower_hsir_cfg
    from .ssa import lower_cfg_scalar_ssa
    from .ssa_verify import verify_scalar_ssa

    legacy = dict(mapped["opaque_producer_payload"])
    # P1 scalar projection cannot discharge external foreign contracts. A
    # checksum-bound declaration is still an unproved obligation.
    if legacy.get("external_assumptions") not in ([], {}):
        raise V1SSARejected("E_V1_SSA_FOREIGN_ASSUMPTIONS: nonempty unverified external contract")
    digest = legacy.pop("sha256")
    source_json = json.dumps(legacy, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False, allow_nan=False)
    if sha256(source_json.encode("utf-8")).hexdigest() != digest:
        raise V1SSARejected("E_V1_SSA_SOURCE_HASH")
    snapshot = HSIRSnapshot("hepta.hsir.v0", source_json, digest)
    cfg = lower_hsir_cfg(snapshot)
    ssa = lower_cfg_scalar_ssa(cfg)
    check = verify_scalar_ssa(ssa, cfg)
    cfg_data, ssa_data, checked_data = cfg.as_dict(), ssa.as_dict(), check.as_dict()
    if (cfg_data.get("source_hsir_sha256") != producer["legacy_sha256"] or
        cfg_data.get("source_sha256") != producer["source_sha256"] or
        ssa_data.get("source_cfg_sha256") != cfg.sha256 or
        checked_data.get("cfg_sha256") != cfg.sha256 or
        checked_data.get("ssa_sha256") != ssa.sha256):
        raise V1SSARejected("E_V1_SSA_LINK_IDENTITY")
    output = {"schema": "hepta.ssa.integration.v1",
              "status": "structural_scalar_ssa_only_not_codegen_qualified",
              "source_hsir_v1_sha256": envelope["sha256"],
              "lowered_hsir_v1_sha256": mapped["sha256"],
              "source_hsir_v0_sha256": original_producer["legacy_sha256"],
              "lowered_hsir_v0_sha256": producer["legacy_sha256"],
              "source_project_sha256": original_producer.get("project_sha256"),
              "source_sha256": producer["source_sha256"],
              "scalar_mapping": ({"profile": bridge_receipt["projection_profile"],
                                  "source_v0_sha256": bridge_receipt["source_hsir_v0_sha256"],
                                  "mapped_v0_sha256": bridge_receipt["mapped_hsir_v0_sha256"],
                                  "semantics_proved": False} if bridge_receipt is not None else None),
              "cfg": cfg_data, "ssa": ssa_data, "ssa_verification": checked_data,
              "claims": {"structural_ssa_verified": True,
                         "source_to_ir_semantics_proved": False,
                         "memory_safety_proved": False,
                         "native_codegen_qualified_by_adapter": False,
                         "foreign_contracts_proved": False}}
    canonical = json.dumps(output, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False, allow_nan=False)
    output["sha256"] = sha256(canonical.encode("utf-8")).hexdigest()
    return output


def _project_source_bound_scalar(envelope: dict) -> dict:
    """Only PR#14 non-FFI scalar expressions; reject unmodeled ownership.

    This is an inspect-only candidate transformation. The independent CFG/SSA
    verifier still runs, but neither a hash nor a checked flag proves behavior.
    """
    from .hsir_v1 import integrate_v0
    source = envelope["opaque_producer_payload"]
    def reject(reason):
        raise V1SSARejected("E_V1_SSA_SOURCE_PROFILE: " + reason)
    if (set(source) != {"schema", "profile", "module", "path", "source_sha256",
                        "project_sha256", "imports", "structs", "enums", "functions",
                        "untyped_expressions", "all_expressions_typed", "external_obligations",
                        "volatile_accesses", "foreign_assumptions", "resource_contracts",
                        "owned_types", "claims", "sha256"} or
        any(source[key] != [] for key in ("imports", "structs", "enums",
            "external_obligations", "volatile_accesses", "untyped_expressions", "owned_types")) or
        source["foreign_assumptions"] not in ([], {}) or
        source["resource_contracts"] not in ([], {}) or
        source["all_expressions_typed"] is not True):
        reject("unmodeled declarations or external obligations")
    allowed = {"i32", "i64", "u32", "u64", "bool"}
    counter = [0]
    def shape(obj, required):
        if not isinstance(obj, dict) or set(obj) != set(required):
            reject("missing or unknown syntax field")
    def dtype(t):
        if type(t) is not str or t not in allowed:
            reject("resource or unsupported scalar type")
        return {"type":t, "args":[], "length":None}
    def span(s):
        shape(s, ("path", "start", "end", "line", "column"))
        if (s["path"] != source["path"] or any(type(s[x]) is not int for x in
            ("start", "end", "line", "column")) or s["start"] < 0 or
            s["end"] < s["start"] or s["line"] < 1 or s["column"] < 1):
            reject("source span mismatch")
        return dict(s)
    def count(depth):
        counter[0] += 1
        if depth > 64 or counter[0] > 16000:
            reject("AST depth or size")
    def expr(x, depth=0):
        count(depth)
        shape(x, ("node", "op", "type", "value", "args", "type_args", "span"))
        arities = {"name":0, "int":0, "bool":0, "unary":1, "binary":2}
        k = x["op"]
        if (x["node"] != "expr" or k not in arities or not isinstance(x["args"], list) or
            len(x["args"]) != arities[k] or x["type_args"] != []):
            reject("unsupported expression or generic argument")
        dst = dtype(x["type"])
        operands = [expr(a, depth+1) for a in x["args"]]
        v = x["value"]
        if k == "name":
            if not isinstance(v, str) or not v.isidentifier(): reject("invalid variable")
        elif k == "int":
            if type(v) is not int or x["type"] == "bool": reject("invalid integer")
        elif k == "bool":
            if type(v) is not bool or x["type"] != "bool": reject("invalid boolean")
        elif k == "unary":
            if v == "!":
                if x["type"] != "bool" or operands[0]["result_type"]["type"] != "bool": reject("unary type")
            elif v == "-":
                if x["type"] not in ("i32", "i64") or operands[0]["result_type"] != dst: reject("unary type")
            else: reject("unsupported unary operator")
        else:
            if v not in {"+", "-", "*", "/", "%", "<", "<=", ">", ">=", "==", "!=", "&&", "||"}:
                reject("unsupported binary operator")
            left, right = (a["result_type"]["type"] for a in operands)
            if left != right: reject("operand type mismatch")
            if v in {"&&", "||"}:
                if left != "bool" or x["type"] != "bool": reject("boolean operator type")
            elif v in {"<", "<=", ">", ">="}:
                if left == "bool" or x["type"] != "bool": reject("comparison type")
            elif v in {"==", "!="}:
                if x["type"] != "bool": reject("comparison result")
            elif left == "bool" or x["type"] != left:
                reject("arithmetic type")
        return {"node":"expr", "operation":k, "result_type":dst, "value":v,
                "operands":operands, "type_args":[], "span":span(x["span"])}
    def stmts(items, depth=0):
        if not isinstance(items, list): reject("missing statement list")
        out = []
        for item in items:
            count(depth)
            shape(item, ("node", "op", "data", "span"))
            if item["node"] != "stmt" or not isinstance(item["data"],dict): reject("invalid statement")
            kind, d = item["op"], item["data"]
            if kind == "let":
                shape(d, ("name", "type", "mutable", "expr"))
                t = d["type"]
                if t is not None:
                    shape(t, ("node", "name", "args", "length"))
                    if t["node"] != "type" or t["args"] != [] or t["length"] is not None:
                        reject("declared resource type")
                if not isinstance(d["name"],str) or type(d["mutable"]) is not bool:
                    reject("invalid binding")
                fields = {"name":d["name"], "type":dtype(t["name"]) if t is not None else None,
                          "mutable":d["mutable"], "expr":expr(d["expr"],depth+1)}
            elif kind == "assign":
                shape(d, ("target", "expr"))
                fields = {"target":expr(d["target"],depth+1), "expr":expr(d["expr"],depth+1)}
                if fields["target"]["operation"] != "name": reject("nonlocal assignment")
            elif kind in ("expr", "return"):
                shape(d, ("expr",))
                fields = {"expr":expr(d["expr"],depth+1)}
            elif kind == "if":
                shape(d, ("condition", "then", "else"))
                fields = {"condition":expr(d["condition"],depth+1),
                          "then":stmts(d["then"],depth+1), "else":stmts(d["else"],depth+1)}
            elif kind == "while":
                shape(d, ("condition", "body"))
                fields = {"condition":expr(d["condition"],depth+1), "body":stmts(d["body"],depth+1)}
            else: reject("resource, unsafe, call or unmodeled statement")
            if kind in ("if","while") and fields["condition"]["result_type"]["type"] != "bool":
                reject("nonboolean branch condition")
            out.append({"node":"stmt", "operation":kind, "fields":fields, "span":span(item["span"])})
        return out
    converted = []
    for fn in source["functions"]:
        expected = {"name", "path", "declaration_span", "body_span", "public", "extern_c",
                    "export_c", "type_params", "type_bounds", "params", "returns", "return_mode",
                    "return_origin", "declared_effects", "inferred_effects", "resources", "body"}
        if (not isinstance(fn,dict) or not expected <= set(fn) or
            set(fn) - expected - {"lifetime_params", "return_lifetime"} or
            fn["path"] != source["path"] or fn["extern_c"] is not False or
            fn["export_c"] is not False or fn["type_params"] != [] or fn["type_bounds"] != {} or
            fn.get("lifetime_params",[]) != [] or fn.get("return_lifetime") is not None or
            fn["return_mode"] != "value" or fn["return_origin"] is not None or
            fn["resources"] not in ({},[]) or
            fn["declared_effects"] not in ([],["panic"]) or fn["inferred_effects"] not in ([],["panic"])):
            reject("unsupported function ownership or effect")
        params = []
        if not isinstance(fn["params"],list): reject("invalid parameters")
        for p in fn["params"]:
            if (not isinstance(p,dict) or not {"name","mode","type","span"} <= set(p) or
                set(p) - {"name","mode","type","span","lifetime"} or p["mode"] != "value" or
                p.get("lifetime") is not None):
                reject("resource or borrowed parameter")
            params.append({"name":p["name"],"ownership":"value",
                           "type":dtype(p["type"]),"span":span(p["span"])})
        span(fn["body_span"])
        converted.append({"name":fn["name"],"param_types":params,"return_type":dtype(fn["returns"]),
                          "declared_effects":fn["declared_effects"],
                          "inferred_transitive_effects":fn["inferred_effects"],
                          "resource_contract":{},"type_parameters":[],"abi":"hepta_unstable",
                          "direction":"local","public":fn["public"],"body":stmts(fn["body"]),
                          "span":span(fn["declaration_span"])})
    count_expr = 0
    pending = [converted]
    while pending:
        value = pending.pop()
        if isinstance(value,dict):
            count_expr += value.get("node") == "expr"
            pending.extend(value.values())
        elif isinstance(value,list): pending.extend(value)
    from .hsir_v1 import integrate_v0
    payload = {"schema":"hepta.hsir.v0", "status":"checked_frontend_snapshot_not_proved",
               "program":source["module"], "source_sha256":source["source_sha256"],
               "imports":[],"structs":[],"enums":[],"functions":converted,
               "external_assumptions":[],"resource_contracts":{},"typed_expression_count":count_expr,
               "claims":{"lifetimes_fully_modeled":False,"pointer_provenance_proved":False,
                         "source_semantics_refined":False,"native_backend_equivalence_proved":False}}
    payload["sha256"] = sha256(json.dumps(payload,sort_keys=True,separators=(",",":"),ensure_ascii=False,allow_nan=False).encode()).hexdigest()
    return integrate_v0(payload,expected_source_sha256=source["source_sha256"])
