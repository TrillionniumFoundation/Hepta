"""P1/P5 integration: static resource rules must agree in the checked IR and LLVM."""
from __future__ import annotations

import unittest

from hepta.pipeline import analyze
from hepta.resource_ir import ResourceIRError, verify_resource_ir
from hepta.resource_lowering import lower_resource_ir
from hepta.llvm_owned_backend import emit_owned_llvm, _resources_allowed


SAFE = """\
module resource_static;
export "C" fn constrained(value:u32)->u32
effects {panic}
resources {heap_allocations=0;may_block=false;may_suspend=false;may_spawn=false;} {
    return value + 1;
}
"""


def checked(source=SAFE):
    result = analyze(source, "resource_static.hepta", native=False)
    if not result.report["ok"]:
        raise AssertionError(result.report.get("diagnostics"))
    return result


class ResourceStaticCompilerTests(unittest.TestCase):
    def test_checked_static_contract_reaches_both_resource_ir_and_native_emitter(self):
        analysis = checked()
        self.assertTrue(_resources_allowed(analysis.program.functions[0], analysis.checked))
        graph = lower_resource_ir(analysis.program, analysis.checked)
        report = verify_resource_ir(graph)
        self.assertTrue(report["ok"], report)
        ir = emit_owned_llvm(analysis.program, analysis.checked)
        self.assertEqual(ir.functions, ("constrained",))
        self.assertIn("define", ir.text)
        self.assertEqual(ir.resource_ir_sha256, report["ir_sha256"])

    def test_bool_integer_masquerade_rejected_by_both_paths(self):
        for resource, fake_value in (
            ("heap_allocations", False),
            ("may_block", 0), ("may_spawn", 0), ("may_suspend", 0)
        ):
            with self.subTest(resource=resource):
                analysis = checked()
                analysis.program.functions[0].resources[resource] = fake_value
                self.assertFalse(_resources_allowed(analysis.program.functions[0], analysis.checked))
                with self.assertRaisesRegex(ResourceIRError, "E_RIR_LOWER_UNSUPPORTED"):
                    lower_resource_ir(analysis.program, analysis.checked)

    def test_unreviewed_runtime_budget_does_not_enter_owner_ir(self):
        analysis = checked()
        analysis.program.functions[0].resources["max_tasks"] = 8
        self.assertFalse(_resources_allowed(analysis.program.functions[0], analysis.checked))
        with self.assertRaisesRegex(ResourceIRError, "E_RIR_LOWER_UNSUPPORTED"):
            lower_resource_ir(analysis.program, analysis.checked)

    def test_transitive_allocation_or_blocking_invalidates_zero_cost_guarantee(self):
        for effect in ("alloc", "block", "spawn", "ffi", "unsafe", "io"):
            with self.subTest(effect=effect):
                analysis = checked()
                analysis.checked.effects["constrained"].add(effect)
                self.assertFalse(_resources_allowed(analysis.program.functions[0], analysis.checked))
                with self.assertRaisesRegex(ResourceIRError, "E_RIR_LOWER_UNSUPPORTED"):
                    lower_resource_ir(analysis.program, analysis.checked)

    def test_unconstrained_legacy_functions_keep_original_resource_ir(self):
        analysis = checked("""\
module resource_static;
export "C" fn unconstrained(value:u32)->u32 effects {panic} {
    return value + 1;
}
""")
        graph = lower_resource_ir(analysis.program, analysis.checked)
        self.assertTrue(verify_resource_ir(graph)["ok"])


if __name__ == "__main__":
    unittest.main()
