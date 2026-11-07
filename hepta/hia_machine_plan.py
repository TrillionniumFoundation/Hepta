"""Checked, explicit Agent choices for the finite direct x86-64 backend.

Plans select reviewed realizations. They never supply bytes, remove Core checks,
change effects, or ask the backend to search for a profitable realization. The
preservation claim is conditional on the canonical lowering and encoder.
"""
from __future__ import annotations

from copy import deepcopy

LAYOUT_V1 = "hepta.hia.agent.block-layout.v1"
MACHINE_V2 = "hepta.hia.agent.machine-plan.v2"
SCRATCH = frozenset({"r10", "r11"})
MOVE_CHOICES = frozenset({"movabs", "mov32_if_exact"})
ALU_CHOICES = frozenset({"imm32", "imm8_if_exact"})
ALIGNMENTS = frozenset({1, 16, 32, 64})


class MachinePlanRejected(ValueError):
    """A plan exceeds the explicitly reviewed machine-choice surface."""


def _require(ok, message):
    if not ok:
        raise MachinePlanRejected("E_HIA_MACHINE_PLAN: " + message)


def _permutation(order, names, label):
    _require(type(order) is list and len(order) == len(names)
             and all(type(name) is str for name in order)
             and set(order) == set(names), label + " must name every member exactly once")


def validate_plan(checked, plan):
    """Freeze a plan against an already reverified immutable Core document."""
    _require(type(plan) is dict, "plan must be an object")
    schema = plan.get("schema")
    _require(type(schema) is str and schema in {LAYOUT_V1, MACHINE_V2}, "unknown plan schema")
    fields = {"schema", "core_sha256", "block_order"}
    if schema == MACHINE_V2:
        fields |= {"function_order", "scratch_registers", "instruction_selection", "function_alignment"}
    _require(set(plan) == fields, "plan has missing or unreviewed fields")
    _require(plan["core_sha256"] == checked.sha256, "plan belongs to a different Core")
    functions = {fn["name"]: fn for fn in checked.as_dict()["functions"]}
    orders = plan["block_order"]
    _require(type(orders) is dict and (bool(orders) or schema == MACHINE_V2), "invalid block order map")
    for name, order in orders.items():
        _require(type(name) is str and name in functions, "unknown function in block order")
        _permutation(order, [block["id"] for block in functions[name]["blocks"]], "block order")
    if schema == MACHINE_V2:
        _permutation(plan["function_order"], functions, "function order")
        registers = plan["scratch_registers"]
        _require(type(registers) is dict and set(registers) == SCRATCH
                 and all(type(value) is str for value in registers.values())
                 and set(registers.values()) == SCRATCH,
                 "scratch assignment must bijectively rename only r10 and r11")
        choices = plan["instruction_selection"]
        _require(type(choices) is dict and set(choices) == {"move_immediate", "alu_immediate"},
                 "instruction choices must be explicit and complete")
        _require(type(choices["move_immediate"]) is str and choices["move_immediate"] in MOVE_CHOICES,
                 "unreviewed immediate move encoding")
        _require(type(choices["alu_immediate"]) is str and choices["alu_immediate"] in ALU_CHOICES,
                 "unreviewed immediate arithmetic encoding")
        _require(type(plan["function_alignment"]) is int and plan["function_alignment"] in ALIGNMENTS,
                 "unreviewed function alignment")
    return deepcopy(plan)


def code_options(plan):
    if plan is None or plan["schema"] == LAYOUT_V1:
        return {}
    return {"scratch_registers": dict(plan["scratch_registers"]),
            "move_immediate": plan["instruction_selection"]["move_immediate"],
            "alu_immediate": plan["instruction_selection"]["alu_immediate"]}


def preservation_checks(plan):
    """Separate claims, with no promotion to whole-backend refinement."""
    checks = [{"choice": "block_layout", "checked": True,
               "rule": "exact block permutations; every terminator transfers explicitly"}]
    if plan["schema"] == MACHINE_V2:
        checks.extend([
            {"choice": "scratch_registers", "checked": True,
             "rule": "bijection on explicit caller-clobbered r10/r11; implicit ISA and ABI registers fixed"},
            {"choice": "instruction_selection", "checked": True,
             "rule": "mov32 only for exact u32; imm8 only for exact sign-extended i8; flags preserved"},
            {"choice": "function_layout", "checked": True,
             "rule": "exact function permutation, symbol relocations retained, NOPs only between functions"},
        ])
    return checks
