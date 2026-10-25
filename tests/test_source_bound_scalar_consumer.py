"""Real PR37 checker and CFG/SSA tests for narrowly accepting PR14 HSIR v0.

The test emitter reproduces PR14's documented/source-verified *wire shape*,
but is not the independently executing PR14 compiler. Qualification against
the actual external producer must be run separately on an identical snapshot.
"""
from __future__ import annotations

from dataclasses import dataclass, fields, is_dataclass
from hashlib import sha256
import json
import subprocess
import sys
import unittest

from hepta.ast import Expr, Stmt, Type, Span
from hepta.checker import check
from hepta.hsir import lower_checked_program
from hepta.hsir_v1 import integrate_v0
from hepta.hsir_v1_source_bound import SourceBoundRejected, recheck_source_bound
from hepta.hsir_v1_ssa import V1SSARejected, lower_verified_v1_scalar_ssa
from hepta.parser import parse


SOURCE = """module scalar;
pub fn accumulate(n: i32) -> i32 effects {panic} {
    let mut total: i32 = 0;
    let mut i: i32 = 0;
    while i < n {
        if i < 4 {
            total = total + i;
        } else {
            total = total + 1;
        }
        i = i + 1;
    }
    return total;
}
"""
PATH = "scalar.hepta"


def sign(value):
    obj = json.loads(json.dumps(value))
    obj.pop("sha256", None)
    obj["sha256"] = sha256(json.dumps(obj, sort_keys=True, separators=(",", ":"),
                                    ensure_ascii=False, allow_nan=False).encode()).hexdigest()
    return obj


def pr14_shaped_snapshot(source=SOURCE, path=PATH):
    program = parse(source, path)
    checked = check(program)
    if not checked.ok:
        raise AssertionError([d.to_dict() for d in checked.diagnostics])

    def enc(obj):
        if isinstance(obj, Expr):
            return {"node": "expr", "op": obj.kind,
                    "type": str(checked.expr_types[id(obj)]),
                    "value": enc(obj.value), "args": [enc(v) for v in obj.children],
                    "type_args": [str(t) for t in obj.type_args], "span": enc(obj.span)}
        if isinstance(obj, Stmt):
            return {"node": "stmt", "op": obj.kind,
                    "data": enc(obj.data), "span": enc(obj.span)}
        if isinstance(obj, Type):
            return {"node": "type", "name": obj.name,
                    "args": [enc(v) for v in obj.args], "length": obj.length}
        if isinstance(obj, Span):
            return {key: getattr(obj, key)
                    for key in ("path", "start", "end", "line", "column")}
        if isinstance(obj, dict):
            return {key: enc(value) for key, value in sorted(obj.items())}
        if isinstance(obj, (tuple, list)):
            return [enc(value) for value in obj]
        if obj is None or isinstance(obj, (str, bool, int, float)):
            return obj
        raise TypeError(type(obj).__name__)

    functions = []
    for fn in program.functions:
        functions.append({
            "name": fn.name, "path": fn.span.path, "public": fn.public,
            "declaration_span": enc(fn.span), "body_span": enc(fn.body_span),
            "extern_c": fn.extern_c, "export_c": fn.export_c,
            "type_params": list(fn.type_params), "type_bounds": {},
            "params": [{"name": p.name, "mode": p.mode, "type": str(p.type),
                        "span": enc(p.span)} for p in fn.params],
            "returns": str(fn.return_type), "return_mode": "value",
            "return_origin": None, "declared_effects": sorted(fn.effects),
            "inferred_effects": sorted(checked.effects.get(fn.name, ())),
            "resources": enc(fn.resources), "body": enc(fn.body),
        })
    return sign({
        "schema": "hepta.hsir.v0", "profile": "checked_typed_ast_not_verified_mir",
        "module": program.name, "path": program.path,
        "source_sha256": sha256(source.encode()).hexdigest(), "project_sha256": None,
        "imports": [], "structs": [], "enums": [], "functions": functions,
        "untyped_expressions": [], "all_expressions_typed": True,
        "external_obligations": [], "volatile_accesses": [],
        "foreign_assumptions": enc(checked.assumptions),
        "resource_contracts": enc(checked.resource_contracts),
        "owned_types": sorted(str(x) for x in getattr(checked, "owned_types", ())),
        "claims": {"native_borrow_validation": False,
                   "translation_correctness_proved": False,
                   "whole_language_soundness_proved": False,
                   "foreign_contracts_proved": False},
    })


class SourceBoundScalarTests(unittest.TestCase):
    def report(self, doc=None, *, source=SOURCE, path=PATH):
        payload = pr14_shaped_snapshot(source, path) if doc is None else doc
        envelope = integrate_v0(payload)
        return lower_verified_v1_scalar_ssa(envelope, source_text=source, source_path=path)

    def test_real_while_and_if_phi_matches_pr37_native(self):
        report = self.report()
        native_program = parse(SOURCE, PATH)
        native = lower_checked_program(native_program, check(native_program))
        self.assertEqual(report["consumer_hsir_v0_sha256"], native.sha256)
        self.assertEqual(report["source_sha256"], sha256(SOURCE.encode()).hexdigest())
        self.assertTrue(report["independent_scalar_reparse_checked"])
        self.assertGreater(sum(f["phi_count"] for f in report["ssa_verification"]["functions"]), 0)
        self.assertFalse(report["claims"]["native_codegen_qualified_by_adapter"])

    def test_deterministic_output(self):
        self.assertEqual(self.report(), self.report())

    def test_rejects_same_sha_with_different_source_bytes(self):
        with self.assertRaisesRegex(V1SSARejected, "SOURCE_IDENTITY"):
            self.report(source=SOURCE + " // changed", doc=pr14_shaped_snapshot())

    def test_rejects_source_bound_without_actual_source(self):
        with self.assertRaisesRegex(V1SSARejected, "SOURCE_REQUIRED"):
            lower_verified_v1_scalar_ssa(integrate_v0(pr14_shaped_snapshot()))

    def test_rejects_forged_type_even_when_legacy_hash_is_recomputed(self):
        doc = pr14_shaped_snapshot()
        doc["functions"][0]["body"][0]["data"]["expr"]["type"] = "u64"
        with self.assertRaisesRegex(V1SSARejected, "TYPE_EQUIVALENCE"):
            self.report(sign(doc))

    def test_rejects_changed_ownership_even_when_rehashed(self):
        doc = pr14_shaped_snapshot()
        doc["functions"][0]["params"][0]["mode"] = "mut"
        with self.assertRaisesRegex(V1SSARejected, "PARAMETER_OWNERSHIP"):
            self.report(sign(doc))

    def test_rejects_unverified_external_assumptions(self):
        doc = pr14_shaped_snapshot()
        doc["external_obligations"] = [{"function": "accumulate", "status": "unverified"}]
        with self.assertRaisesRegex(V1SSARejected, "UNSUPPORTED_GLOBAL"):
            self.report(sign(doc))

    def test_rejects_changed_effect_even_when_rehashed(self):
        doc = pr14_shaped_snapshot()
        doc["functions"][0]["declared_effects"] = []
        with self.assertRaisesRegex(V1SSARejected, "EFFECT_EQUIVALENCE"):
            self.report(sign(doc))

    def test_rejects_unsafe_expression_reinterpretation(self):
        doc = pr14_shaped_snapshot()
        expr = doc["functions"][0]["body"][2]["data"]["condition"]
        expr["op"] = "call"
        with self.assertRaisesRegex(V1SSARejected, "EXPRESSION_PROFILE|UNSUPPORTED_EXPR"):
            self.report(sign(doc))

    def test_cli_exposes_source_bound_option_without_running_compiler(self):
        proc = subprocess.run([sys.executable, "-m", "hepta", "ssa-v1-verify", "--help"],
                              capture_output=True, text=True, timeout=30)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("--source-bound-hsir", proc.stdout)


if __name__ == "__main__":
    unittest.main()
