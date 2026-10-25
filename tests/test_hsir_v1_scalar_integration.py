"""Standalone negative/positive qualification for PR14 -> PR37 scalar HSIR."""
import copy
import hashlib
import json
import unittest

from hepta.hsir_v1 import integrate_v0, verify_v1
from hepta.hsir_v1_scalar_bridge import ScalarBridgeRejected, source_bound_to_frozen

S = {"path": "m.hepta", "start": 0, "end": 1, "line": 1, "column": 1}

def expr(kind, typ, value=None, *args):
    return {"node": "expr", "op": kind, "type": typ, "value": value,
            "args": list(args), "type_args": [], "span": S}

def n(name): return expr("name", "i32", name)
def i(value): return expr("int", "i32", value)
def binary(op, typ, left, right): return expr("binary", typ, op, left, right)
def stmt(op, **data): return {"node": "stmt", "op": op, "data": data, "span": S}

def sign(value):
    doc = copy.deepcopy(value)
    doc.pop("sha256", None)
    raw = json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()
    doc["sha256"] = hashlib.sha256(raw).hexdigest()
    return doc

def source():
    body = [stmt("let", name="count", type={"node":"type", "name":"i32", "args":[], "length":None},
                 mutable=True, expr=i(0)),
            stmt("while", condition=binary("<", "bool", n("count"), n("max_count")), body=[
                stmt("assign", target=n("count"), expr=binary("+", "i32", n("count"), i(1)))]),
            stmt("return", expr=n("count"))]
    return sign({"schema": "hepta.hsir.v0", "profile": "checked_typed_ast_not_verified_mir",
        "module": "m", "path": "m.hepta", "source_sha256": "a"*64, "project_sha256": "b"*64,
        "imports":[], "structs":[], "enums":[], "functions":[{"name":"accumulate",
        "path":"m.hepta", "declaration_span":S, "body_span":S, "public":True,
        "extern_c":False, "export_c":False, "type_params":[], "type_bounds":{},
        "params":[{"name":"max_count", "type":"i32", "mode":"value", "span":S}],
        "returns":"i32", "return_mode":"value", "return_origin":None,
        "declared_effects":["panic"], "inferred_effects":["panic"],
        "resources":{}, "body":body}],
        "untyped_expressions":[], "all_expressions_typed":True,
        "external_obligations":[], "volatile_accesses":[], "foreign_assumptions":[],
        "resource_contracts":{}, "owned_types":[],
        "claims":{"native_borrow_validation":False,"translation_correctness_proved":False,
            "whole_language_soundness_proved":False,"foreign_contracts_proved":False}})

def convert(doc): return source_bound_to_frozen(integrate_v0(doc))

class ScalarTests(unittest.TestCase):
    def invalid(self, edit, code):
        doc = source()
        edit(doc)
        with self.assertRaisesRegex(ScalarBridgeRejected, code):
            convert(sign(doc))

    def test_scalar_path_reconstructs_twice(self):
        result = convert(source())
        verify_v1(result["source_hsir_v1"])
        verify_v1(result["mapped_hsir_v1"])
        self.assertEqual(result, convert(source()))
        self.assertFalse(result["claims"]["native_codegen_authorized"])
        self.assertEqual(result["source_project_sha256"], "b"*64)
        self.assertEqual(result["mapped_hsir_v0_sha256"], result["mapped_hsir_v1"]["producer"]["legacy_sha256"])

    def test_unknown_name_is_rejected(self):
        self.invalid(lambda d:d["functions"][0]["body"][-1]["data"]["expr"].update(value="ghost"), "UNBOUND_OR_WRONG_NAME_TYPE")

    def test_false_variable_type_is_rejected(self):
        self.invalid(lambda d:d["functions"][0]["body"][-1]["data"]["expr"].update(type="u64"), "UNBOUND_OR_WRONG_NAME_TYPE")

    def test_mutability_is_not_ignored(self):
        self.invalid(lambda d:d["functions"][0]["body"][0]["data"].update(mutable=False), "IMMUTABLE_OR_UNBOUND_ASSIGNMENT")

    def test_parameter_borrow_rejected(self):
        self.invalid(lambda d:d["functions"][0]["params"][0].update(mode="read"), "RESOURCE_PARAMETER")

    def test_return_type_rejected(self):
        self.invalid(lambda d:d["functions"][0].update(returns="u32"), "RETURN_TYPE")

    def test_initializer_type_rejected(self):
        self.invalid(lambda d:d["functions"][0]["body"][0]["data"]["type"].update(name="u32"), "LOCAL_INITIALIZER_TYPE")

    def test_foreign_contract_rejected(self):
        self.invalid(lambda d:d["foreign_assumptions"].append({"foreign":"unknown"}), "NON_SCALAR")
        self.invalid(lambda d:d["external_obligations"].append({"reason":"raw_pointer"}), "NON_SCALAR")

    def test_unmodeled_ownership_rejected(self):
        self.invalid(lambda d:d["functions"][0].update(return_mode="mut"), "FUNCTION_SEMANTICS")
        self.invalid(lambda d:d["owned_types"].append("Buffer<u8>"), "NON_SCALAR")

    def test_unknown_expression_rejected(self):
        self.invalid(lambda d:d["functions"][0]["body"][0]["data"]["expr"].update(op="call"), "EXPRESSION_OR_EFFECT")

    def test_integer_width_checked(self):
        self.invalid(lambda d:d["functions"][0]["body"][0]["data"]["expr"].update(value=2**40), "INTEGER_RANGE")

    def test_effect_contract_checked(self):
        self.invalid(lambda d:d["functions"][0].update(declared_effects=[]), "PANIC_EFFECT_UNDERCLAIMED")
        self.invalid(lambda d:d["functions"][0].update(inferred_effects=[]), "PANIC_EFFECT_UNDERCLAIMED")

    def test_shadowing_rejected(self):
        self.invalid(lambda d:d["functions"][0]["body"][0]["data"].update(name="max_count"), "NESTED_OR_SHADOWING_LOCAL")

    def test_wrong_source_path_rejected(self):
        self.invalid(lambda d:d["functions"][0]["declaration_span"].update(path="other.hepta"), "CROSS_SOURCE_SPAN")

    def test_wrong_expr_width_rejected(self):
        self.invalid(lambda d:d["functions"][0]["body"][1]["data"]["condition"]["args"][0].update(type="u32"), "BINARY_OPERAND_TYPE")

if __name__ == "__main__": unittest.main()
