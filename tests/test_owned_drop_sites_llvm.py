"""Native owned Drop call sites must match the verified Resource IR inventory.

These source-facing regressions need a full Hepta checkout; pure inventory
tests in test_owned_drop_sites.py can run independently of the compiler.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from hepta.llvm_owned_backend import LLVMOwnedRejected, emit_owned_llvm, _Emitter
from hepta.owned_drop_sites import VerifiedDropSites, qualify_drop_sites
from hepta.pipeline import analyze
from hepta.resource_lowering import lower_resource_ir
from hepta.resource_ir import verify_resource_ir


SOURCE = """
struct Pair {data:Buffer<u8>,tag:u64}
export "C" fn resource_drop()->u64 effects {alloc,block,panic} {
    let pair:Pair=Pair{data:buffer(4),tag:7};
    let value=pair.tag;
    drop(move pair);
    return value;
}
"""


def checked():
    result = analyze(SOURCE, "<owned-drop-sites>", native=False, crate_type="cdylib")
    if not result.report["ok"]:
        raise AssertionError(result.report)
    return result


class OwnedDropNativeSiteTests(unittest.TestCase):
    def test_real_source_explicit_drop_is_authorized(self):
        src = checked()
        ir = emit_owned_llvm(src.program, src.checked)
        self.assertEqual(ir.functions, ("resource_drop",))
        self.assertIn("call void @__hepta_owned_drop", ir.text)
        self.assertIn("call void @free(ptr %data)", ir.text)

    def test_missing_and_extra_verified_drop_sites_fail_before_native(self):
        src = checked()
        for name, inventory in (
            ("missing", (("resource_drop", ()),)),
            ("wrong_type", (("resource_drop", (("Buffer<u8>", 1),)),)),
            ("excess", (("resource_drop", (("Pair", 2),)),)),
            ("wrong_function", (("unrelated", (("Pair", 1),)),)),
        ):
            with self.subTest(case=name):
                def distorted(graph, verified):
                    original = qualify_drop_sites(graph, verified)
                    return VerifiedDropSites(original.resource_ir_sha256, inventory)
                with patch("hepta.llvm_owned_backend.qualify_drop_sites",
                           side_effect=distorted):
                    with self.assertRaisesRegex(LLVMOwnedRejected, "E_LLVM_OWNED_DROP_SITE"):
                        emit_owned_llvm(src.program, src.checked)

    def test_source_bound_graph_digest_and_claims_required(self):
        src = checked()
        cases = (
            lambda receipt: receipt.update(ir_sha256="0" * 64),
            lambda receipt: receipt["claims"].update(native_codegen_uses_this_ir=True),
            lambda receipt: receipt["claims"].update(whole_language_soundness_proved=0),
        )
        for mutate in cases:
            with self.subTest(mutation=cases.index(mutate)):
                def forged(graph):
                    original = verify_resource_ir(graph)
                    original = dict(original, claims=dict(original["claims"]))
                    mutate(original)
                    return original
                with patch("hepta.llvm_owned_backend.verify_resource_ir",
                           side_effect=forged):
                    with self.assertRaisesRegex(LLVMOwnedRejected, "E_LLVM_OWNED_RESOURCE"):
                        emit_owned_llvm(src.program, src.checked)

    def test_internal_emitter_cannot_omit_verified_resource_gate(self):
        src = checked()
        graph = lower_resource_ir(src.program, src.checked)
        with self.assertRaisesRegex(LLVMOwnedRejected, "E_LLVM_OWNED_DROP_SITE"):
            _Emitter(src.program, src.checked, resource_types=graph["types"])
        with self.assertRaisesRegex(LLVMOwnedRejected, "E_LLVM_OWNED_DROP_PLAN"):
            _Emitter(src.program, src.checked,
                     resource_drop_sites=VerifiedDropSites("0" * 64, ()))

    def test_forged_site_graph_identity_rejects(self):
        src = checked()
        def forged(graph, verified):
            original = qualify_drop_sites(graph, verified)
            return VerifiedDropSites("f" * 64, original.functions)
        with patch("hepta.llvm_owned_backend.qualify_drop_sites", side_effect=forged):
            with self.assertRaisesRegex(LLVMOwnedRejected, "E_LLVM_OWNED_DROP_SITE"):
                emit_owned_llvm(src.program, src.checked)


if __name__ == "__main__":
    unittest.main()
