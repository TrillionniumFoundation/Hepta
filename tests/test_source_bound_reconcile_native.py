"""Native-source qualification for the PR14 source-bound to PR37 SSA bridge.

Requires a working pinned rustc. No mock is used here: the exact source is
parsed, checked, submitted to rustc, compared against the legacy semantic
tree, then lowered through the real CFG/SSA/independent verifier.
"""
from __future__ import annotations

import hashlib
import json
from copy import deepcopy
import unittest

from hepta.hsir_v1 import integrate_v0
from hepta.source_bound_reconcile import (
    SourceBoundReconcileRejected, reconcile_source_bound_to_ssa,
)

SOURCE = """module p1_source;
fn add(a: i32, b: i32) -> i32 effects { panic } {
    return a + b;
}
"""


def canonical_sha256(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                      ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def source_bound_v0(operator="+"):
    span = {"path": "<input>", "start": 0, "end": 0, "line": 1, "column": 1}
    def expression(kind, value, arguments=()):
        return {"node": "expr", "op": kind, "type": "i32", "value": value,
                "args": list(arguments), "type_args": [], "span": span}
    lhs = expression("name", "a")
    rhs = expression("name", "b")
    op = expression("binary", operator, (lhs, rhs))
    return_stmt = {"node": "stmt", "op": "return", "data": {"expr": op}, "span": span}
    snapshot = {
        "schema": "hepta.hsir.v0",
        "profile": "checked_typed_ast_not_verified_mir",
        "module": "p1_source",
        "path": "<input>",
        "source_sha256": hashlib.sha256(SOURCE.encode()).hexdigest(),
        "project_sha256": None,
        "imports": [], "structs": [], "enums": [],
        "functions": [{
            "name": "add", "path": "<input>", "public": False,
            "extern_c": False, "export_c": False, "type_params": [], "type_bounds": {},
            "params": [{"name": "a", "mode": "value", "type": "i32", "span": span},
                       {"name": "b", "mode": "value", "type": "i32", "span": span}],
            "returns": "i32", "return_mode": "value", "return_origin": None,
            "declared_effects": ["panic"], "inferred_effects": ["panic"],
            "resources": {}, "body": [return_stmt],
        }],
        "untyped_expressions": [], "all_expressions_typed": True,
        "external_obligations": [], "volatile_accesses": [], "foreign_assumptions": [],
        "resource_contracts": {}, "owned_types": [],
        "claims": {"native_borrow_validation": False,
                   "translation_correctness_proved": False,
                   "whole_language_soundness_proved": False,
                   "foreign_contracts_proved": False},
    }
    snapshot["sha256"] = canonical_sha256(snapshot)
    return integrate_v0(snapshot)


class SourceBoundNativeTests(unittest.TestCase):
    def test_real_native_scalar_round_trip(self):
        output = reconcile_source_bound_to_ssa(source_bound_v0(), SOURCE)
        self.assertEqual(output["native_reference_validation"]["checks"]["rust_borrows_types"],
                         "rustc_checked")
        self.assertTrue(output["claims"]["source_bound_scalar_structure_compared"])
        self.assertTrue(output["ssa_verified"]["ssa_verification"]["claims"]["ssa_edge_uses_checked"])
        self.assertFalse(output["claims"]["whole_language_soundness_proved"])

    def test_rehashed_legacy_body_divergence_still_rejected(self):
        # A self-consistently rehashed PR14 candidate is insufficient: it must
        # agree with the separately checked AST derived from the exact source.
        forged = source_bound_v0("-")
        with self.assertRaisesRegex(SourceBoundReconcileRejected, "DIVERGENT_BODY"):
            reconcile_source_bound_to_ssa(forged, SOURCE)


if __name__ == "__main__":
    unittest.main()
