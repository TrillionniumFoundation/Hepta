"""P1: source-bound resource graphs are not self-attesting proof objects."""
from __future__ import annotations

import copy
import unittest

from hepta.checker import check
from hepta.parser import parse
from hepta.resource_ir import ResourceIRError, verify_resource_ir
from hepta.resource_lowering import lower_resource_ir, verify_resource_source_origin


_SOURCE = "fn main()->Unit effects {alloc,block,panic} {let b=buffer(4);drop(move b);}"


def accepted(source=_SOURCE):
    program = parse(source, "resource_origin.hepta")
    checked = check(program)
    if not checked.ok:
        raise AssertionError([d.to_dict() for d in checked.diagnostics])
    return program, checked


class ResourceSourceOriginTests(unittest.TestCase):
    def test_strict_checked_source_resource_origin_receipt(self):
        program, checked = accepted()
        graph = lower_resource_ir(program, checked)
        self.assertTrue(verify_resource_ir(graph)["ok"])
        receipt = verify_resource_source_origin(program, checked, graph)
        self.assertEqual(receipt["schema"], "hepta.resource.source-origin.v1")
        self.assertEqual(receipt["canonical_hsir_schema"], "hepta.hsir.v0")
        self.assertEqual(receipt["source_sha256"], graph["source_sha256"])
        self.assertTrue(receipt["claims"]["checked_source_rederived"])
        self.assertFalse(receipt["claims"]["source_to_ir_refinement_proved"])
        self.assertFalse(receipt["claims"]["native_codegen_uses_resource_ir"])

    def test_rehashed_resource_source_id_is_not_binding(self):
        program, checked = accepted()
        graph = lower_resource_ir(program, checked)
        forged = copy.deepcopy(graph)
        forged["source_sha256"] = "0" * 64
        # An independent graph verifier never sees the checked source AST.
        self.assertTrue(verify_resource_ir(forged)["ok"])
        with self.assertRaises(ResourceIRError) as origin:
            verify_resource_source_origin(program, checked, forged)
        self.assertEqual(origin.exception.code, "E_RIR_SOURCE_ORIGIN")
        forged = copy.deepcopy(graph)
        forged["project_sha256"] = "1" * 64
        self.assertTrue(verify_resource_ir(forged)["ok"])
        with self.assertRaises(ResourceIRError) as origin:
            verify_resource_source_origin(program, checked, forged)
        self.assertEqual(origin.exception.code, "E_RIR_SOURCE_ORIGIN")

    def test_different_accepted_source_rejects_stale_graph(self):
        original, checked = accepted()
        graph = lower_resource_ir(original, checked)
        revised, revised_checked = accepted(_SOURCE.replace("buffer(4)", "buffer(5)"))
        self.assertTrue(verify_resource_ir(graph)["ok"])
        with self.assertRaises(ResourceIRError) as origin:
            verify_resource_source_origin(revised, revised_checked, graph)
        self.assertEqual(origin.exception.code, "E_RIR_SOURCE_ORIGIN")


if __name__ == "__main__":
    unittest.main()
