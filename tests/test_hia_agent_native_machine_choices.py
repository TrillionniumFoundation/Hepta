"""Exercise v2 machine plans through the unchanged eleven-tool boundary."""
from __future__ import annotations

import json
import unittest

from tests import test_hia_agent_native_tools as existing


class ExplicitMachineChoicesTests(existing.MachinePlanTests):
    def prepare(self):
        program, plan = super().prepare()
        plan.update(schema="hepta.hia.agent.machine-plan.v2",
                    function_order=["select_value"],
                    scratch_registers={"r10": "r11", "r11": "r10"},
                    instruction_selection={"move_immediate": "mov32_if_exact", "alu_immediate": "imm8_if_exact"},
                    function_alignment=32)
        return program, plan

    def test_separate_checks_and_assumptions_remain_in_verification_receipt(self):
        program, plan = self.prepare()
        _ref, result = self.plan_verify(program, plan)
        check = result["checks"][0]
        evidence = json.loads(self.session.read(check["evidence_artifact"]))
        assumptions = json.loads(self.session.read(check["assumptions_artifact"]))
        self.assertEqual({item["choice"] for item in evidence["choice_checks"]},
                         {"block_layout", "scratch_registers", "instruction_selection", "function_layout"})
        self.assertTrue(evidence["same_slots"])
        self.assertFalse(evidence["implicit_optimizer_used"])
        self.assertFalse(assumptions["assumptions_proved_here"])
        self.assertFalse(assumptions["universal_core_to_machine_refinement_proved"])


if __name__ == "__main__":
    unittest.main()
