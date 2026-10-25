"""HSIR v0 must serialize checked source structure without hiding obligations."""
from __future__ import annotations

import unittest

from hepta.ast import Diagnostic
from hepta.checker import CheckResult, check
from hepta.hsir import HSIRRejected, lower_checked_program
from hepta.parser import parse


class HSIRTests(unittest.TestCase):
    SOURCE = """module hsir_fixture;
repr(C) struct Payload { value: u32 }
export "C" fn take_number(x: i32) -> i32 effects { panic }
resources { heap_allocations = 0; may_block = false; may_suspend = false; may_spawn = false; }
{
    if x > 0 { return x + 1; }
    return x;
}
"""

    def test_deterministic_checked_typed_snapshot(self):
        program = parse(self.SOURCE)
        result = check(program)
        self.assertTrue(result.ok, [d.to_dict() for d in result.diagnostics])
        one = lower_checked_program(program, result).as_dict()
        two = lower_checked_program(program, result).as_dict()
        self.assertEqual(one, two)
        tampered = lower_checked_program(program, result)
        forged = tampered.as_dict()
        forged["functions"][0]["name"] = "tampered"
        self.assertNotEqual(forged, tampered.as_dict())
        self.assertEqual(one["schema"], "hepta.hsir.v0")
        self.assertGreater(one["typed_expression_count"], 0)
        fn = one["functions"][0]
        self.assertEqual(fn["param_types"][0]["ownership"], "value")
        self.assertEqual(fn["return_type"]["type"], "i32")
        self.assertEqual(fn["abi"], "C")
        self.assertIn("panic", fn["inferred_transitive_effects"])
        self.assertFalse(one["claims"]["native_backend_equivalence_proved"])
        self.assertFalse(one["claims"]["pointer_provenance_proved"])

    def test_snapshot_identity_rechecked_at_export(self):
        from hepta.hsir import HSIRSnapshot
        program = parse(self.SOURCE)
        snapshot = lower_checked_program(program, check(program))
        self.assertEqual(snapshot.as_dict()["sha256"], snapshot.sha256)
        forged = HSIRSnapshot(snapshot.schema, snapshot.canonical_json + " ", snapshot.sha256)
        with self.assertRaisesRegex(HSIRRejected, "digest mismatch"):
            forged.as_dict()
        forged = HSIRSnapshot("different.schema", snapshot.canonical_json, snapshot.sha256)
        with self.assertRaisesRegex(HSIRRejected, "snapshot schema"):
            forged.as_dict()

    def test_unchecked_input_rejected(self):
        program = parse(self.SOURCE)
        unchecked = CheckResult(diagnostics=[Diagnostic("E_FAKE", "unchecked")])
        with self.assertRaisesRegex(HSIRRejected, "UNCHECKED"):
            lower_checked_program(program, unchecked)

    def test_missing_expression_type_rejected(self):
        program = parse(self.SOURCE)
        with self.assertRaisesRegex(HSIRRejected, "UNTYPED"):
            lower_checked_program(program, CheckResult())

    def test_structured_change_affects_snapshot_identity(self):
        left = parse(self.SOURCE)
        right = parse(self.SOURCE.replace("return x + 1;", "return x + 2;"))
        a, b = check(left), check(right)
        self.assertTrue(a.ok)
        self.assertTrue(b.ok)
        self.assertNotEqual(lower_checked_program(left, a).sha256,
                            lower_checked_program(right, b).sha256)


if __name__ == "__main__":
    unittest.main()
