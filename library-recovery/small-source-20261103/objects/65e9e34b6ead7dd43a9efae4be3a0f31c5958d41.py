"""Pure source-bound v0 -> frozen SSA input: exact metadata and semantic subset.

Tests exercise a representative PR#14 AST-v0 wire shape. These are independent
of native rustc and not a proof of source-to-IR refinement.
"""
import copy
import hashlib
import json
import sys
from pathlib import Path
import unittest
from unittest.mock import patch
import types
from dataclasses import dataclass

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from hepta.hsir_v1 import integrate_v0, verify_v1
from hepta.hsir_v1_scalar_bridge import ScalarBridgeRejected, source_bound_to_frozen

S = {"path": "src/accumulate.hepta", "start": 0, "end": 1, "line": 1, "column": 1}

def expr(op, ty, value=None, *args):
    return {"node": "expr", "op": op, "type": ty, "value": value,
            "args": list(args), "type_args": [], "span": S}

def n(key, ty="i32"):
    return expr("name", ty, key)

def i(k):
    return expr("int", "i32", k)

def lt(a,b):
    return expr("binary", "bool", "<", a,b)

def add(a,b):
    return expr("binary", "i32", "+", a,b)

def st(op, data):
    return {"node": "stmt", "op": op, "data": data, "span": S}

def local(name, value):
    return st("let", {"name":name, "expr":value, "mutable":True,
                      "type":{"node":"type", "name":"i32", "args":[], "length":None}})

def assign(name, value):
    return st("assign", {"target":n(name),"expr":value})

def source_doc():
    # Similar to PR#14's checked output: local scalar loop and branch PHI.
    body = [local("total", i(0)), local("j", i(0)),
            st("while",{"condition":lt(n("j"),n("amount")), "body":[
                st("if",{"condition":lt(n("j"),i(4)),
                         "then":[assign("total", add(n("total"),n("j")))],
                         "else":[assign("total", add(n("total"),i(1)))]}),
                assign("j", add(n("j"),i(1)))]}),
            st("return",{"expr":n("total")})]
    doc = {"schema":"hepta.hsir.v0", "profile":"checked_typed_ast_not_verified_mir",
           "module":"accumulate", "path":S["path"],
           "source_sha256":"a"*64, "project_sha256": "b"*64,
           "imports":[], "structs":[], "enums":[],
           "functions":[{"name":"accumulate", "path":S["path"],
                         "declaration_span":S, "body_span":S, "public":True,
                         "extern_c":False, "export_c":False,
                         "type_params":[], "type_bounds":{},
                         "params":[{"name":"amount", "type":"i32", "mode":"value", "span":S}],
                         "returns":"i32", "return_mode":"value", "return_origin":None,
                         "declared_effects":["panic"],"inferred_effects":["panic"],
                         "resources":{}, "body":body}],
           "untyped_expressions":[], "all_expressions_typed":True,
           "external_obligations":[], "volatile_accesses":[], "foreign_assumptions":[],
           "resource_contracts":{}, "owned_types":[],
           "claims":{"native_borrow_validation":False,
                     "translation_correctness_proved":False,
                     "whole_language_soundness_proved":False,
                     "foreign_contracts_proved":False}}
    return sign(doc)

def sign(doc):
    d=copy.deepcopy(doc)
    d.pop("sha256",None)
    raw=json.dumps(d, sort_keys=True,separators=(",",":"),ensure_ascii=False,allow_nan=False).encode()
    d["sha256"]=hashlib.sha256(raw).hexdigest()
    return d

def bridge(source=None):
    return source_bound_to_frozen(integrate_v0(source or source_doc()))

# Two explicit interpreters with bounded loops, for finite *defined* i32 inputs.
# They do not test native machine code, nor language-wide equivalence.
def eval_fn(body, args, *, mapped):
    state=dict(args)
    count=[0]
    def eval_expr(e):
        kind=e["operation" if mapped else "op"]
        value=e["value"]
        if kind=="name": return state[value]
        if kind=="int": return value
        if kind=="bool": return value
        operands=e["operands" if mapped else "args"]
        if kind=="unary":
            a=eval_expr(operands[0]); return -a if value=="-" else not a
        a=eval_expr(operands[0]); b=eval_expr(operands[1])
        return {"+":lambda:a+b,"-":lambda:a-b,"*":lambda:a*b,
                "<":lambda:a<b,">":lambda:a>b,"==":lambda:a==b,
                "!=":lambda:a!=b,"<=":lambda:a<=b,">=":lambda:a>=b}[value]()
    def run(statements):
        for node in statements:
            count[0]+=1
            if count[0]>10000: raise ValueError("unbounded interpretation")
            op=node["operation" if mapped else "op"]
            d=node["fields" if mapped else "data"]
            if op=="let": state[d["name"]]=eval_expr(d["expr"])
            elif op=="assign": state[d["target"]["value"]]=eval_expr(d["expr"])
            elif op=="return": return True, eval_expr(d["expr"])
            elif op=="if":
                result=run(d["then"] if eval_expr(d["condition"]) else d["else"])
                if result: return result
            elif op=="while":
                while eval_expr(d["condition"]):
                    result=run(d["body"])
                    if result: return result
            else: raise AssertionError(op)
        return None
    result=run(body)
    return result[1]

class ScalarBridgeTests(unittest.TestCase):
    def test_loop_control_and_v1_chain_reconstruct(self):
        r=bridge()
        verify_v1(r["source_hsir_v1"])
        verify_v1(r["mapped_hsir_v1"])
        original=r["source_hsir_v1"]["opaque_producer_payload"]
        mapped=r["mapped_hsir_v1"]["opaque_producer_payload"]
        self.assertEqual(mapped["status"],"checked_frontend_snapshot_not_proved")
        self.assertEqual(mapped["typed_expression_count"], 21)
        self.assertEqual(mapped["source_sha256"],original["source_sha256"])
        self.assertFalse(r["claims"]["native_codegen_authorized"])
        self.assertEqual(r["source_project_sha256"], "b"*64)

    def test_scalar_defined_domain_differential(self):
        r=bridge()
        original=r["source_hsir_v1"]["opaque_producer_payload"]["functions"][0]["body"]
        mapped=r["mapped_hsir_v1"]["opaque_producer_payload"]["functions"][0]["body"]
        for amount in range(-15,60):
            self.assertEqual(eval_fn(original,{"amount":amount},mapped=False),
                             eval_fn(mapped,{"amount":amount},mapped=True))

    def test_determinism_and_original_preserved(self):
        origin=source_doc()
        a=bridge(origin)
        b=bridge(copy.deepcopy(origin))
        self.assertEqual(a,b)
        self.assertEqual(a["source_hsir_v1"]["opaque_producer_payload"], origin)
        self.assertNotEqual(a["source_hsir_v0_sha256"],a["mapped_hsir_v0_sha256"])

    def rejected(self, mutate, code):
        d=source_doc()
        mutate(d)
        with self.assertRaisesRegex(ScalarBridgeRejected, code):
            bridge(sign(d))

    def test_mutable_borrow_rejected(self):
        self.rejected(lambda d:d["functions"][0]["params"][0].update(mode="mut"),"RESOURCE_PARAMETER")

    def test_non_scalar_type_rejected(self):
        self.rejected(lambda d:d["functions"][0].update(returns="Buffer<u8>"),"TYPE_OR_RESOURCE")

    def test_external_obligation_rejected(self):
        self.rejected(lambda d:d["external_obligations"].append({"status":"unproved"}),"NON_SCALAR")

    def test_foreign_assumption_rejected(self):
        self.rejected(lambda d:d["foreign_assumptions"].append("external"),"NON_SCALAR")

    def test_unknown_expression_rejected(self):
        self.rejected(lambda d:d["functions"][0]["body"][0]["data"]["expr"].update(op="call"),"EXPRESSION_OR_EFFECT")

    def test_unknown_statement_rejected(self):
        self.rejected(lambda d:d["functions"][0]["body"].append(st("unsafe",{"body":[]})),"STATEMENT_OR_RESOURCE")

    def test_extra_undocumented_semantics_rejected(self):
        self.rejected(lambda d:d["functions"][0].update(unmodelled_ownership=True),"UNKNOWN_OR_MISSING_FIELDS")

    def test_source_module_ast_rejected(self):
        self.rejected(lambda d:d["structs"].append({"name":"Unmodelled"}),"NON_SCALAR")

    def test_generic_declaration_rejected(self):
        self.rejected(lambda d:d["functions"][0]["type_params"].append("T"),"FUNCTION_SEMANTICS")

    def test_invalid_span_rejected(self):
        self.rejected(lambda d:d["functions"][0]["declaration_span"].update(start=4,end=3),"SPAN")

    def test_mismatched_arithmetic_operand_types_rejected(self):
        self.rejected(lambda d:d["functions"][0]["body"][2]["data"]["condition"]["args"][1].update(type="u64"),"BINARY_OPERAND_TYPE")

    def test_wrong_arity_rejected(self):
        self.rejected(lambda d:d["functions"][0]["body"][2]["data"]["condition"]["args"].pop(),"EXPRESSION_ARITY")

    def test_invalid_resource_contract_rejected(self):
        self.rejected(lambda d:d["functions"][0].update(resources={"heap_allocations":0}),"FUNCTION_SEMANTICS")

    def test_forged_v1_proof_claim_rejected(self):
        snap=integrate_v0(source_doc())
        snap["claims"]["source_to_ir_refinement_proved"]=True
        with self.assertRaisesRegex(ScalarBridgeRejected,"V1_IDENTITY"):
            source_bound_to_frozen(snap)

    def test_cross_source_span_rejected(self):
        self.rejected(lambda d:d["functions"][0]["params"][0]["span"].update(path="other.hepta"),"CROSS_SOURCE_SPAN")

    def test_explicit_lifetime_rejected(self):
        self.rejected(lambda d:d["functions"][0].update(lifetime_params=["a"]),"FUNCTION_SEMANTICS")

    def test_function_ffi_effect_rejected(self):
        self.rejected(lambda d:d["functions"][0].update(inferred_effects=["ffi","panic"]),"FUNCTION_SEMANTICS")

    def test_valid_source_bound_flows_through_adapter_with_identity_receipt(self):
        from hepta.hsir_v1_ssa import lower_verified_v1_scalar_ssa
        from hashlib import sha256
        import json
        @dataclass(frozen=True)
        class Snap:
            schema: str
            canonical_json: str
            sha256: str
            def as_dict(self):
                return {**json.loads(self.canonical_json), "sha256":self.sha256}
        def snap(schema, obj):
            source=json.dumps(obj, sort_keys=True, separators=(",",":"), ensure_ascii=False)
            return Snap(schema,source,sha256(source.encode()).hexdigest())
        def fake_cfg(h):
            self.assertEqual(h.schema,"hepta.hsir.v0")
            self.assertEqual(sha256(h.canonical_json.encode()).hexdigest(),h.sha256)
            frozen=json.loads(h.canonical_json)
            self.assertEqual(frozen["status"],"checked_frontend_snapshot_not_proved")
            return snap("hepta.cfg.v0",{"source_hsir_sha256":h.sha256,
                                       "source_sha256":frozen["source_sha256"]})
        def fake_ssa(cfg):
            return snap("hepta.ssa.scalar.v0",{"source_cfg_sha256":cfg.sha256})
        def fake_verifier(ssa, cfg):
            return snap("hepta.ssa.verify.v0",{"cfg_sha256":cfg.sha256,
                                               "ssa_sha256":ssa.sha256})
        with patch.dict(sys.modules,{
            "hepta.hsir":types.SimpleNamespace(HSIRSnapshot=Snap),
            "hepta.cfg":types.SimpleNamespace(lower_hsir_cfg=fake_cfg),
            "hepta.ssa":types.SimpleNamespace(lower_cfg_scalar_ssa=fake_ssa),
            "hepta.ssa_verify":types.SimpleNamespace(verify_scalar_ssa=fake_verifier),
        }):
            original=integrate_v0(source_doc())
            out=lower_verified_v1_scalar_ssa(original)
        self.assertEqual(out["source_hsir_v1_sha256"],original["sha256"])
        self.assertEqual(out["source_hsir_v0_sha256"],original["producer"]["legacy_sha256"])
        self.assertNotEqual(out["source_hsir_v0_sha256"],out["lowered_hsir_v0_sha256"])
        self.assertEqual(out["source_project_sha256"],"b"*64)
        self.assertEqual(out["scalar_mapping"]["source_v0_sha256"],out["source_hsir_v0_sha256"])
        self.assertEqual(out["scalar_mapping"]["mapped_v0_sha256"],out["lowered_hsir_v0_sha256"])
        self.assertFalse(out["claims"]["native_codegen_qualified_by_adapter"])

    def test_duplicate_function_rejected_by_upstream_integrator(self):
        from hepta.hsir_v1 import HSIRV1Rejected
        d=source_doc()
        d["functions"].append(copy.deepcopy(d["functions"][0]))
        with self.assertRaisesRegex(HSIRV1Rejected, "DUPLICATE_FUNCTION"):
            integrate_v0(sign(d))

if __name__=="__main__": unittest.main()
