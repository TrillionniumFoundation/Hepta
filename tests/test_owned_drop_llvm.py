"""Finite concrete Drop helper generation consumes verified Resource IR layout."""
import unittest
from unittest.mock import patch

from hepta.llvm_owned_backend import LLVMOwnedRejected, emit_owned_llvm
from hepta.owned_drop_plan import DropPlan, derive_resource_drop_plan
from hepta.pipeline import analyze


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
    result = analyze(SOURCE, "<owned-drop-hia>", native=False, crate_type="cdylib")
    if not result.report["ok"]:
        raise AssertionError(result.report)
    return result


class OwnedNativeResourceDropTests(unittest.TestCase):
    def test_concrete_owner_drop_uses_verified_layout(self):
        src = checked()
        result = emit_owned_llvm(src.program, src.checked)
        self.assertIn("define internal void @__hepta_owned_drop", result.text)
        self.assertIn("call void @free(ptr %data)", result.text)
        self.assertEqual(result.functions, ("resource_drop",))

    def test_forged_child_ownership_rejects_before_compilation(self):
        src = checked()

        def wrong(types, name):
            if name == "Pair":
                return DropPlan("struct", fields=(
                    ("data", "Buffer<u8>", False), ("tag", "u64", False)))
            return derive_resource_drop_plan(types, name)

        with patch("hepta.llvm_owned_backend.derive_resource_drop_plan", side_effect=wrong):
            with self.assertRaisesRegex(LLVMOwnedRejected, "E_LLVM_OWNED_DROP_PLAN"):
                emit_owned_llvm(src.program, src.checked)

    def test_forged_resource_field_order_rejects_before_compilation(self):
        src = checked()

        def wrong(types, name):
            if name == "Pair":
                return DropPlan("struct", fields=(
                    ("tag", "u64", False), ("data", "Buffer<u8>", True)))
            return derive_resource_drop_plan(types, name)

        with patch("hepta.llvm_owned_backend.derive_resource_drop_plan", side_effect=wrong):
            with self.assertRaisesRegex(LLVMOwnedRejected, "E_LLVM_OWNED_DROP_PLAN"):
                emit_owned_llvm(src.program, src.checked)


if __name__ == "__main__":
    unittest.main()
