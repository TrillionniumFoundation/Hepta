import copy
import importlib.util
import json
import pathlib
import unittest

from hepta import hsir_scalar_bridge as sb

SPAN = {"path": "s.hepta", "start": 0, "end": 3, "line": 1, "column": 1}

def expr(op, typ, value, *args):
    return {"node": "expr", "op": op, "type": typ, "value": value,
            "args": list(args), "type_args": [], "span": dict(SPAN)}

def stmt(op, **data):
    return {"node": "stmt", "op": op, "data": data, "span": dict(SPAN)}

def typ(name):
    return {"node": "type", "name": name, "args": [], "length": None}

def func():
    n = expr("name", "i32", "n")
    x = expr("name", "i32", "x")
    zero = expr("int", "i32", 0)
    one = expr("int", "i32", 1)
    return {
        "name": "count", "path": "s.hepta", "declaration_span": dict(SPAN), "body_span": dict(SPAN),
        "public": True, "extern_c": False, "export_c": False,
        "type_params": [], "type_bounds": {}, "params": [{"name": "n", "mode": "value", "type": "i32", "span": dict(SPAN)}],
        "returns": "i32", "return_mode": "value", "return_origin": None,
        "declared_effects": ["panic"], "inferred_effects": ["panic"],
        "resources": {}, "body": [
            stmt("let", name="x", type=typ("i32"), mutable=True, expr=zero),
            stmt("while", condition=expr("binary", "bool", "<", x, n), body=[
                stmt("if", condition=expr("binary", "bool", "<", x, expr("int", "i32", 4)),
                     then=[stmt("assign", target=x, expr=expr("binary", "i32", "+", x, one))],
                     **{"else": [stmt("assign", target=x, expr=expr("binary", "i32", "+", x, one))]})]),
            stmt("return", expr=x),
        ],
    }

def sample():
    return {"schema": "hepta.hsir.v0", "profile": "checked_typed_ast_not_verified_mir",
            "module": "example", "path": "s.hepta", "source_sha256": "a" * 64,
            "project_sha256": None, "imports": [], "structs": [], "enums": [],
            "functions": [func()], "untyped_expressions": [], "all_expressions_typed": True,
            "external_obligations": [], "volatile_accesses": [], "foreign_assumptions": [],
            "resource_contracts": [], "owned_types": [],
            "claims": {"native_borrow_validation": False,
                       "translation_correctness_proved": False,
                       "whole_language_soundness_proved": False,
                       "foreign_contracts_proved": False}, "sha256": "b" * 64}

class BridgeTests(unittest.TestCase):
    def test_real_ast_shape_loop_branch_and_deterministic_identity(self):
        original = sample()
        raw, sha = sb.lower_source_bound_scalar(original)
        data = json.loads(raw)
        self.assertEqual(data["functions"][0]["body"][1]["operation"], "while")
        self.assertEqual(data["functions"][0]["body"][1]["fields"]["body"][0]["operation"], "if")
        self.assertEqual(data["functions"][0]["body"][0]["fields"]["type"]["type"], "i32")
        self.assertEqual(data["functions"][0]["param_types"][0]["ownership"], "value")
        self.assertEqual(data["source_sha256"], original["source_sha256"])
        self.assertEqual((raw, sha), sb.lower_source_bound_scalar(copy.deepcopy(original)))
        self.assertEqual(data["typed_expression_count"], 16)  # typed expression occurrences
        self.assertFalse(data["claims"]["source_semantics_refined"])

    def test_effects_and_export_direction(self):
        p=sample(); p["functions"][0]["export_c"]=True
        raw,_=sb.lower_source_bound_scalar(p)
        f=json.loads(raw)["functions"][0]
        self.assertEqual((f["direction"],f["abi"]),("export","C"))

    def reject(self, mutate, label):
        p=sample();mutate(p)
        with self.assertRaisesRegex(sb.ScalarBridgeRejected,label):
            sb.lower_source_bound_scalar(p)

    def test_reject_borrowed_param(self):
        self.reject(lambda p:p["functions"][0]["params"][0].update(mode="read"),"OWNERSHIP")
    def test_reject_owned_return(self):
        self.reject(lambda p:p["functions"][0].update(returns="Buffer<u8>"),"TYPE")
    def test_reject_lifetime_origin(self):
        self.reject(lambda p:p["functions"][0].update(return_origin="n"),"BORROW")
    def test_reject_ffi_assumptions(self):
        self.reject(lambda p:p.update(external_obligations=[{"function":"foreign"}]),"RESOURCE_OR_EXTERNAL")
    def test_reject_system_effects(self):
        self.reject(lambda p:p["functions"][0].update(declared_effects=["alloc"]),"EFFECTS")
    def test_reject_resource_contracts(self):
        self.reject(lambda p:p["functions"][0].update(resources={"heap_allocations":0}),"BORROW")
    def test_reject_generic(self):
        self.reject(lambda p:p["functions"][0].update(type_params=["T"]),"BORROW")
    def test_reject_unsafe_operations(self):
        self.reject(lambda p:p["functions"][0]["body"][0].update(op="unsafe"),"STMT_OPERATION")
    def test_reject_function_calls(self):
        self.reject(lambda p:p["functions"][0]["body"][0]["data"].update(expr=expr("call","i32","callee")),"EXPR_OPERATION")
    def test_reject_untyped(self):
        self.reject(lambda p:p["functions"][0]["body"][0]["data"]["expr"].update(type=None),"TYPE")
    def test_reject_duplicate_param(self):
        self.reject(lambda p:p["functions"][0]["params"].append(copy.deepcopy(p["functions"][0]["params"][0])),"PARAMETERS")
    def test_reject_extra_statement_metadata(self):
        self.reject(lambda p:p["functions"][0]["body"][0]["data"].update(hidden_effect=True),"STMT_FIELDS")
    def test_reject_bad_span(self):
        self.reject(lambda p:p["functions"][0]["body"][0].update(span={"path":"s", "start":6,"end":2,"line":1,"column":1}),"SPAN")
    def test_reject_retained_cpp_object(self):
        self.reject(lambda p:p.update(owned_types=["CppObject"]),"RESOURCE_OR_EXTERNAL")
    def test_reject_imported_system_scope(self):
        self.reject(lambda p:p.update(imports=[{"name":"ffi","alias":"ffi"}]),"RESOURCE_OR_EXTERNAL")
    def test_reject_unknown_function_field(self):
        self.reject(lambda p:p["functions"][0].update(hidden_borrow=True),"FUNCTION_FIELDS")
    def test_reject_unknown_program_field(self):
        self.reject(lambda p:p.update(hardware_dma_contract={}),"PROGRAM_FIELDS")
    def test_reject_short_circuit_with_possible_panic(self):
        self.reject(lambda p:p["functions"][0]["body"][0]["data"].update(expr=expr("binary","bool","&&",expr("bool","bool",True),expr("bool","bool",False))),"BINARY")
    def test_reject_nan_floating_literal(self):
        self.reject(lambda p:p["functions"][0]["body"][0]["data"].update(expr=expr("float","f64",float("nan"))),"FLOAT")

    def test_reject_cast(self):
        self.reject(lambda p:p["functions"][0]["body"][0]["data"].update(expr=expr("cast","u8",typ("u8"),expr("int","i32",123))),"EXPR_OPERATION")

if __name__=="__main__":unittest.main()
