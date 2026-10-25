"""P0: sole canonical Hepta semantics and source-bound scalar IR promotion."""
from __future__ import annotations

import copy
from hashlib import sha256
import json
import unittest

from hepta.checker import check
from hepta.parser import parse
from hepta.hsir import (
    HSIRRejected, HSIRSnapshot, lower_checked_program,
    verify_checked_source_projection,
)

_SOURCE = """\
module source_authority;
export "C" fn f(a: i32) -> i32 effects { panic } {
    return a + 1;
}
"""


def checked(source=_SOURCE):
    program = parse(source, "source_authority.hepta")
    result = check(program)
    if not result.ok:
        raise AssertionError([d.to_dict() for d in result.diagnostics])
    return program, result


class SourceAuthorityTests(unittest.TestCase):
    def test_rederived_canonical_and_scalar_origin_receipt(self):
        program, result = checked()
        ir = lower_checked_program(program, result)
        receipt = verify_checked_source_projection(program, result, ir)
        self.assertEqual(receipt["canonical_schema"], "hepta.hsir.v0")
        self.assertEqual(receipt["derived_sha256"], ir.sha256)
        self.assertTrue(receipt["claims"]["checked_source_projection_rederived"])
        self.assertFalse(receipt["claims"]["native_backend_refinement_proven"])
        self.assertFalse(receipt["claims"]["whole_language_soundness_proven"])

    def test_rehashed_derived_value_cannot_claim_source_identity(self):
        program, result = checked()
        ir = lower_checked_program(program, result)
        forged = copy.deepcopy(ir.as_dict())
        forged["functions"][0]["body"][0]["fields"]["expr"]["operands"][1]["value"] = 2
        forged.pop("sha256")
        wire = json.dumps(forged, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False)
        candidate = HSIRSnapshot(ir.schema, wire, sha256(wire.encode()).hexdigest())
        candidate.as_dict()  # Structurally valid; SHA can be recomputed.
        with self.assertRaisesRegex(HSIRRejected, "SOURCE_ORIGIN"):
            verify_checked_source_projection(program, result, candidate)

    def test_stale_source_snapshot_rejected(self):
        program, result = checked()
        snapshot = lower_checked_program(program, result)
        next_program, next_result = checked(_SOURCE.replace("a + 1", "a + 2"))
        with self.assertRaisesRegex(HSIRRejected, "SOURCE_ORIGIN"):
            verify_checked_source_projection(next_program, next_result, snapshot)

    def test_derived_type_must_be_the_only_approved_snapshot(self):
        program, result = checked()
        with self.assertRaisesRegex(HSIRRejected, "SOURCE_ORIGIN"):
            verify_checked_source_projection(program, result, {"sha256": "0" * 64})


if __name__ == "__main__":
    unittest.main()
