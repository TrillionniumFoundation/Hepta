"""P0/P1: bridge PR #14's sole HSIR authority into PR #37's scalar SSA."""
from __future__ import annotations

import copy
import hashlib
import json
import unittest

from hepta.checker import check
from hepta.parser import parse
from hepta.semantic_ir import lower_checked_program as canonical_hsir
from hepta.hsir import HSIRRejected, HSIRSnapshot, from_canonical_snapshot, lower_checked_program
from hepta.cfg import lower_hsir_cfg
from hepta.ssa import lower_cfg_scalar_ssa
from hepta.ssa_verify import verify_scalar_ssa


_SOURCE = """\
module bridge_scalar;
export "C" fn accumulate(n: i32) -> i32 effects { panic } {
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


def _checked(source: str):
    program = parse(source, "p0_p1_bridge.hepta")
    result = check(program)
    if not result.ok:
        raise AssertionError([d.to_dict() for d in result.diagnostics])
    return program, result


def _reseal(snapshot: dict) -> dict:
    ret = copy.deepcopy(snapshot)
    ret.pop("sha256", None)
    encoded = json.dumps(ret, sort_keys=True, ensure_ascii=False,
                         allow_nan=False, separators=(",", ":")).encode("utf-8")
    ret["sha256"] = hashlib.sha256(encoded).hexdigest()
    return ret


class HSIRBridgeTests(unittest.TestCase):
    def test_sole_authority_and_checked_scalar_ssa(self):
        program, checked = _checked(_SOURCE)
        canonical = canonical_hsir(program, checked)
        bridge = lower_checked_program(program, checked)
        self.assertEqual(bridge.as_dict()["source_semantic_sha256"], canonical["sha256"])
        self.assertEqual(bridge.as_dict(), from_canonical_snapshot(canonical).as_dict())
        cfg = lower_hsir_cfg(bridge)
        ssa = lower_cfg_scalar_ssa(cfg)
        verifier = verify_scalar_ssa(ssa, cfg)
        self.assertTrue(verifier.as_dict())
        self.assertGreater(ssa.as_dict()["functions"][0]["phi_count"], 0)
        self.assertFalse(bridge.as_dict()["claims"]["source_semantics_refined"])
        self.assertFalse(ssa.as_dict()["claims"]["native_backend_refinement_proven"])

    def test_fresh_source_is_deterministic_and_binds_changes(self):
        a, ac = _checked(_SOURCE)
        b, bc = _checked(_SOURCE)
        self.assertEqual(lower_checked_program(a, ac).sha256, lower_checked_program(b, bc).sha256)
        edited, ec = _checked(_SOURCE.replace("total + 1", "total + 2"))
        self.assertNotEqual(lower_checked_program(a, ac).sha256, lower_checked_program(edited, ec).sha256)

    def test_tampered_canonical_rejected_even_if_frontend_was_valid(self):
        a, ac = _checked(_SOURCE)
        canonical = canonical_hsir(a, ac)
        damaged = copy.deepcopy(canonical)
        damaged["functions"][0]["returns"] = "u64"
        with self.assertRaisesRegex(HSIRRejected, "checksum"):
            from_canonical_snapshot(damaged)
        forged = copy.deepcopy(canonical)
        forged["claims"]["translation_correctness_proved"] = True
        with self.assertRaisesRegex(HSIRRejected, "claims"):
            from_canonical_snapshot(_reseal(forged))
        snap = from_canonical_snapshot(canonical)
        with self.assertRaises(HSIRRejected):
            HSIRSnapshot(snap.schema, snap.canonical_json, "0" * 64).as_dict()

    def test_resealed_derived_snapshot_cannot_bypass_scalar_schema(self):
        program, checked = _checked(_SOURCE)
        snap = lower_checked_program(program, checked)
        baseline = snap.as_dict()
        self.assertTrue(lower_hsir_cfg(snap))
        for name, mutate in {
            "elevated_claim": lambda x: x["claims"].update(pointer_provenance_proved=True),
            "extra_function_metadata": lambda x: x["functions"][0].update(implicit_unsafe=True),
            "missing_statement_field": lambda x: x["functions"][0]["body"][0]["fields"].pop("mutable"),
            "injected_nested_effect": lambda x: x["functions"][0]["body"][2]["fields"]["body"][0]["fields"].update(ffi=True),
            "hidden_expression": lambda x: x.update(typed_expression_count=0),
            "unknown_top_level": lambda x: x.update(pointer_proof=True),
        }.items():
            with self.subTest(case=name):
                payload = copy.deepcopy(baseline)
                payload.pop("sha256")
                mutate(payload)
                encoded = json.dumps(payload, sort_keys=True, ensure_ascii=False,
                                     allow_nan=False, separators=(",", ":"))
                forged = HSIRSnapshot(snap.schema, encoded, hashlib.sha256(encoded.encode()).hexdigest())
                with self.assertRaises(HSIRRejected):
                    forged.as_dict()
                with self.assertRaises(HSIRRejected):
                    lower_hsir_cfg(forged)

    def test_resealed_but_elided_or_unreviewed_semantics_rejected(self):
        a, ac = _checked(_SOURCE)
        canonical = canonical_hsir(a, ac)
        changes = {
            "missing_external_obligations": lambda obj: obj.pop("external_obligations"),
            "missing_owned_types": lambda obj: obj.pop("owned_types"),
            "missing_foreign_assumptions": lambda obj: obj.pop("foreign_assumptions"),
            "unknown_semantic_field": lambda obj: obj.update(new_proof_claim=True),
            "falsey_external_inventory": lambda obj: obj.update(foreign_assumptions=0),
            "hidden_owned_type": lambda obj: obj["owned_types"].append("Buffer<u8>"),
            "missing_proof_claims": lambda obj: obj.update(claims={}),
        }
        for name, change in changes.items():
            with self.subTest(name=name):
                source = copy.deepcopy(canonical)
                change(source)
                with self.assertRaises(HSIRRejected):
                    from_canonical_snapshot(_reseal(source))

    def test_resealed_nested_semantic_fields_cannot_disappear(self):
        a, ac = _checked(_SOURCE)
        canonical = canonical_hsir(a, ac)
        mutations = {
            "function_extra_effect_metadata": lambda x: x["functions"][0].update(unknown_abi_effect=True),
            "function_resource_contract_missing": lambda x: x["functions"][0].pop("resources"),
            "parameter_extra_loan_metadata": lambda x: x["functions"][0]["params"][0].update(loan_provenance="unknown"),
            "parameter_span_missing": lambda x: x["functions"][0]["params"][0].pop("span"),
            "expression_extra_operands": lambda x: x["functions"][0]["body"][0]["data"]["expr"].update(new_unsafe_effect=True),
            "statement_extra_ownership": lambda x: x["functions"][0]["body"][0].update(implicit_drop=True),
            "let_data_extra_drop": lambda x: x["functions"][0]["body"][0]["data"].update(implicit_drop=True),
            "let_data_missing_mutability": lambda x: x["functions"][0]["body"][0]["data"].pop("mutable"),
            "while_data_extra_effect": lambda x: x["functions"][0]["body"][2]["data"].update(implicit_ffi=True),
            "nested_if_data_extra_effect": lambda x: x["functions"][0]["body"][2]["data"]["body"][0]["data"].update(implicit_spawn=True),
            "return_data_extra_ownership": lambda x: x["functions"][0]["body"][3]["data"].update(consume_owner=True),
        }
        for name, mutation in mutations.items():
            with self.subTest(name=name):
                changed = copy.deepcopy(canonical)
                mutation(changed)
                with self.assertRaises(HSIRRejected):
                    from_canonical_snapshot(_reseal(changed))

    def test_resealed_derived_expression_and_statement_shapes_rejected(self):
        p, checked = _checked(_SOURCE)
        base = lower_checked_program(p, checked).as_dict()
        def check_rejection(mutate):
            payload = copy.deepcopy(base)
            payload.pop("sha256")
            mutate(payload)
            encoded = json.dumps(payload, sort_keys=True, ensure_ascii=False,
                                 allow_nan=False, separators=(",", ":"))
            forged = HSIRSnapshot("hepta.hsir.v0", encoded,
                                  hashlib.sha256(encoded.encode()).hexdigest())
            with self.assertRaises(HSIRRejected):
                forged.as_dict()
        cases = {
            "extra_binary_operand": lambda x: x["functions"][0]["body"][2]["fields"]["condition"]["operands"].append(
                copy.deepcopy(x["functions"][0]["body"][0]["fields"]["expr"])),
            "bool_as_integer_literal": lambda x: x["functions"][0]["body"][0]["fields"]["expr"].update(value=True),
            "changed_let_mutability": lambda x: x["functions"][0]["body"][0]["fields"].update(mutable="yes"),
            "mangled_while_body": lambda x: x["functions"][0]["body"][2]["fields"].update(body=0),
            "numeric_condition": lambda x: x["functions"][0]["body"][2]["fields"]["condition"].update(
                result_type={"type": "i32", "args": [], "length": None}),
            "malformed_return": lambda x: x["functions"][0]["body"][3]["fields"].update(expr="already_returned"),
        }
        for label, mutation in cases.items():
            with self.subTest(case=label):
                check_rejection(mutation)

    def test_unhashable_resealed_hsir_metadata_rejects_with_language_error(self):
        program, checked = _checked(_SOURCE)
        canonical = canonical_hsir(program, checked)
        source_mutations = {
            "unhashable_return": lambda x: x["functions"][0].update(returns=[]),
            "unhashable_expr_op": lambda x: x["functions"][0]["body"][0]["data"]["expr"].update(op=[]),
            "unhashable_stmt_op": lambda x: x["functions"][0]["body"][0].update(op=[]),
        }
        for label, mutation in source_mutations.items():
            with self.subTest(source=label):
                altered = copy.deepcopy(canonical)
                mutation(altered)
                with self.assertRaises(HSIRRejected):
                    from_canonical_snapshot(_reseal(altered))

        parent = lower_checked_program(program, checked).as_dict()
        derived_mutations = {
            "unhashable_type": lambda x: x["functions"][0]["return_type"].update(type=[]),
            "unhashable_operation": lambda x: x["functions"][0]["body"][0]["fields"]["expr"].update(operation=[]),
            "unhashable_stmt": lambda x: x["functions"][0]["body"][0].update(operation=[]),
            "unhashable_abi": lambda x: x["functions"][0].update(abi=[]),
            "unhashable_direction": lambda x: x["functions"][0].update(direction=[]),
        }
        for label, mutation in derived_mutations.items():
            with self.subTest(derived=label):
                snapshot = copy.deepcopy(parent)
                snapshot.pop("sha256")
                mutation(snapshot)
                encoded = json.dumps(snapshot, sort_keys=True, ensure_ascii=False,
                                     allow_nan=False, separators=(",", ":"))
                forged = HSIRSnapshot("hepta.hsir.v0", encoded,
                                      hashlib.sha256(encoded.encode()).hexdigest())
                with self.assertRaises(HSIRRejected):
                    forged.as_dict()

    def test_refuses_c_ffis_generic_types_or_resource_ownership(self):
        a, ac = _checked(_SOURCE)
        canonical = canonical_hsir(a, ac)
        changes = {
            "raw_boundary": lambda o: o["external_obligations"].append({"status": "assumed"}),
            "foreign": lambda o: o["functions"][0].update(extern_c=True),
            "borrowing": lambda o: o["functions"][0]["params"][0].update(mode="read"),
            "generic": lambda o: o["functions"][0].update(type_params=["T"]),
            "owned": lambda o: o["functions"][0].update(returns="Buffer<u8>"),
            "new_expression": lambda o: o["functions"][0]["body"][0]["data"]["expr"].update(op="call"),
        }
        for name, change in changes.items():
            with self.subTest(name=name):
                bad = copy.deepcopy(canonical)
                change(bad)
                with self.assertRaises(HSIRRejected):
                    from_canonical_snapshot(_reseal(bad))


if __name__ == "__main__":
    unittest.main()
