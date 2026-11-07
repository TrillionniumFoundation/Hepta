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


class ScalarRegisterChoicesTests(existing.MachinePlanTests):
    def prepare(self):
        program, plan = super().prepare()
        plan.update(schema="hepta.hia.agent.machine-plan.v3",
                    function_order=["select_value"],
                    scratch_registers={"r10": "r11", "r11": "r10"},
                    instruction_selection={"move_immediate": "mov32_if_exact", "alu_immediate": "imm8_if_exact",
                                           "scalar_select": "cmov_scalar"},
                    function_alignment=32,
                    value_registers={"select_value": {"choose": "r12", "yes_value": "r12", "no_value": "r12"}})
        return program, plan

    def test_register_lifetimes_are_retained_without_claiming_identical_slots(self):
        program, plan = self.prepare()
        _ref, result = self.plan_verify(program, plan)
        check = result["checks"][0]
        evidence = json.loads(self.session.read(check["evidence_artifact"]))
        checks = {item["choice"]: item for item in evidence["choice_checks"]}
        self.assertEqual(set(checks), {"block_layout", "scratch_registers", "instruction_selection",
                                      "function_layout", "value_registers", "scalar_select"})
        self.assertEqual(checks["value_registers"]["witness"]["functions"]["select_value"]["callee_saved_registers"], ["r12"])
        self.assertFalse(evidence["same_slots"])
        self.assertFalse(evidence["implicit_optimizer_used"])
        assumptions = json.loads(self.session.read(check["assumptions_artifact"]))
        self.assertFalse(assumptions["universal_core_to_machine_refinement_proved"])

    def test_unknown_value_register_assignment_is_refused_through_domain_tools(self):
        program, plan = self.prepare()
        plan["value_registers"]["select_value"]["missing"] = "r13"
        plan_ref = self.session.artifact(plan)
        self.reject("hia_verify", self.session.arguments(candidate=program, base_program=None,
            validation_profile=self.session.profiles["validation"],
            subject={"kind": "agent_machine_plan", "backend_profile": self.session.backend,
                     "plan_profile": self.session.profiles["plan"], "plan": plan_ref}, claims=["lowering_refinement"]))


if __name__ == "__main__":
    unittest.main()
