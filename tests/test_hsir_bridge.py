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

    def test_real_checked_noalloc_scalar_contract_preserved(self):
        source = _SOURCE.replace(
            "effects { panic } {",
            "effects { panic } resources {heap_allocations=0;may_block=false;"
            "may_suspend=false;may_spawn=false;} {",
        )
        program, checked = _checked(source)
        bridge = lower_checked_program(program, checked).as_dict()
        self.assertEqual(bridge["functions"][0]["resource_contract"], {
            "heap_allocations": 0,
            "may_block": False,
            "may_suspend": False,
            "may_spawn": False,
        })
        self.assertFalse(bridge["claims"]["source_semantics_refined"])

    def test_resealed_effect_or_resource_elevation_is_not_scalar_ssa(self):
        a, ac = _checked(_SOURCE)
        canonical = canonical_hsir(a, ac)
        changes = {
            "effect_missing": lambda o: o["functions"][0].pop("declared_effects"),
            "effect_ffi": lambda o: o["functions"][0].update(declared_effects=["panic", "ffi"]),
            "effect_unsafe": lambda o: o["functions"][0].update(inferred_effects=["unsafe"]),
            "effect_allocation": lambda o: o["functions"][0].update(declared_effects=["alloc", "panic"]),
            "effect_scalar_mismatch": lambda o: o["functions"][0].update(declared_effects=[]),
            "effect_duplicate": lambda o: o["functions"][0].update(declared_effects=["panic", "panic"]),
            "resource_bad_key": lambda o: o["functions"][0].update(resources={"stack_bytes": 1024}),
            "resource_forged_bool_zero": lambda o: o["functions"][0].update(resources={"heap_allocations": False}),
            "resource_nonzero_alloc": lambda o: o["functions"][0].update(resources={"heap_allocations": 1}),
            "resource_may_block": lambda o: o["functions"][0].update(resources={"may_block": True}),
            "resource_invalid_type": lambda o: o["functions"][0].update(resources={"may_spawn": 0}),
        }
        for name, change in changes.items():
            with self.subTest(name=name):
                forged = copy.deepcopy(canonical)
                change(forged)
                with self.assertRaises(HSIRRejected):
                    from_canonical_snapshot(_reseal(forged))

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
