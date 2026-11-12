"""Checked, explicit Agent choices for the finite direct x86-64 backend.

Plans select reviewed realizations. They never supply bytes, remove Core checks,
change effects, or ask the backend to search for a profitable realization. The
preservation claim is conditional on the canonical lowering and encoder.
"""
from __future__ import annotations

from contextvars import ContextVar

_NATIVE_OWNER = ContextVar('hia_machine_plan_native_owner', default=None)

LAYOUT_V1 = "hepta.hia.agent.block-layout.v1"
MACHINE_V2 = "hepta.hia.agent.machine-plan.v2"
MACHINE_V3 = "hepta.hia.agent.machine-plan.v3"
MACHINE_V4 = "hepta.hia.agent.machine-plan.v4"
SCRATCH = frozenset({"r10", "r11"})
VALUE_REGISTERS = ("rbx", "r12", "r13", "r14", "r15")
LEAF_VALUE_REGISTERS = ("r8", "r9")
# Exact finite opcode inventory audited against _Function.operation and its
# helpers. Returning calls, allocation/bulk helpers and buffer.swap (implicit
# r8 scratch) are deliberately excluded. Future opcodes do not inherit access.
LEAF_VALUE_OPS = frozenset({
    "const", "int.add.wrap", "int.add.checked", "int.sub.wrap", "int.sub.checked",
    "int.mul.wrap", "int.mul.checked", "int.div.checked", "int.rem.checked",
    "int.shl.checked", "int.shr.checked", "int.neg.checked", "int.cast",
    "bit.and", "bit.or", "bit.xor", "bit.not", "compare.eq", "compare.ne",
    "compare.lt", "compare.le", "compare.gt", "compare.ge",
    "bool.and", "bool.or", "bool.not", "select",
    "buffer.len", "buffer.load", "buffer.store",
})
VALUE_TYPES = frozenset({f"{sign}{width}" for sign in ("i", "u") for width in (8, 16, 32, 64)}) | {
    "isize", "usize", "bool"}
MOVE_CHOICES = frozenset({"movabs", "mov32_if_exact"})
ALU_CHOICES = frozenset({"imm32", "imm8_if_exact"})
SELECT_CHOICES = frozenset({"branch", "cmov_scalar"})
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


def _terminal_arguments(term):
    if term["op"] == "ret":
        return term["values"]
    if term["op"] == "jump":
        return term["args"]
    if term["op"] == "branch":
        return [term["cond"], *term["then"]["args"], *term["else"]["args"]]
    return []


def _reference_register_assignment_witness(checked, assignments, *, allow_leaf_registers=False):
    """Independently check caller-supplied scalar register lifetimes.

    Verified Core blocks are closed: every incoming value is an explicit block
    parameter. Intervals therefore stop at each terminator. Edge arguments are
    copied to disjoint temporary stack slots before any target parameter is
    assigned, including backedge permutations. Parameters and dead definitions
    still occupy their definition point, since emitting a dead write can clobber
    a live value. Inputs and outputs at one instruction deliberately interfere;
    no instruction-specific read-before-write assumption is needed here.

    This validates an assignment, not a register allocator or profitability
    search. v3 uses only the fixed callee-saved set. v4 additionally admits
    r8/r9 only in functions whose complete lowering has no returning call or
    implicit write to these registers. All reaching edges retain staged copies.
    """
    _require(type(assignments) is dict, "value_registers must be a function map")
    functions = {fn["name"]: fn for fn in checked.as_dict()["functions"]}
    _require(all(type(name) is str and name in functions for name in assignments),
             "unknown function in value register assignment")
    witnesses = {}
    allowed = VALUE_REGISTERS + (LEAF_VALUE_REGISTERS if allow_leaf_registers else ())
    for name, mapping in assignments.items():
        _require(type(mapping) is dict and all(type(value) is str and type(reg) is str
                 and reg in allowed for value, reg in mapping.items()),
                 "value registers must be explicit assignments admitted by this plan version")
        fn = functions[name]
        leaf_registers = [reg for reg in LEAF_VALUE_REGISTERS if reg in mapping.values()]
        leaf_ops = sorted({op["op"] for block in fn["blocks"] for op in block["ops"]})
        if leaf_registers:
            _require(all(op in LEAF_VALUE_OPS for op in leaf_ops),
                     "caller-clobbered value registers require a leaf opcode whitelist; no calls, swap or allocation/bulk helpers")
            _require(all(p["type"] in VALUE_TYPES | {"readbuf", "mutbuf"} for p in fn["params"])
                     and all(t in VALUE_TYPES for t in fn["returns"]),
                     "leaf registers require scalar/borrowed parameters and scalar returns")
        definitions = {p["name"]: p["type"] for block in fn["blocks"]
                       for p in block["params"] + [p for op in block["ops"] for p in op["out"]]}
        _require(all(value in definitions and definitions[value] in VALUE_TYPES for value in mapping),
                 "register assignment requires an existing integer or boolean SSA value")
        intervals = []
        for block in fn["blocks"]:
            starts = {p["name"]: 0 for p in block["params"]}
            for position, op in enumerate(block["ops"], 1):
                starts.update({p["name"]: position for p in op["out"]})
            ends = dict(starts)
            for position, op in enumerate(block["ops"], 1):
                for value in op["args"]:
                    ends[value] = position
            for value in _terminal_arguments(block["term"]):
                ends[value] = len(block["ops"]) + 1
            by_register = {reg: [] for reg in allowed}
            for value in sorted(starts):
                if value in mapping:
                    row = {"block": block["id"], "value": value, "type": definitions[value],
                           "register": mapping[value], "first": starts[value], "last": ends[value]}
                    intervals.append(row)
                    by_register[mapping[value]].append(row)
            for register, rows in by_register.items():
                rows.sort(key=lambda row: (row["first"], row["value"]))
                for left, right in zip(rows, rows[1:]):
                    _require(left["last"] < right["first"],
                             f"interfering values {name}/{block['id']}: "
                             f"{left['value']} and {right['value']} share {register}")
        witnesses[name] = {"callee_saved_registers": [reg for reg in VALUE_REGISTERS if reg in mapping.values()],
                           "intervals": intervals}
        if allow_leaf_registers:
            witnesses[name].update(caller_clobbered_leaf_registers=leaf_registers,
                                   leaf_opcode_inventory=leaf_ops if leaf_registers else [])
    return {"rule": "closed-block inclusive lifetimes; all edge sources staged before target writes",
            "functions": witnesses}


def _reference_validate_plan(checked, plan):
    """Freeze a plan against an already reverified immutable Core document."""
    _require(type(plan) is dict, "plan must be an object")
    # Capture exact built-in JSON data before inspecting any plan field. The
    # existing Core decoder rejects subclasses/hooks, cycles and oversized
    # trees, then returns a detached bounded snapshot. Checking caller-owned
    # values and only deepcopying afterwards lets copying hooks or concurrent
    # mutation change the plan after its register lifetimes were checked.
    from .hia_program import HIAProgramRejected, _decode
    try:
        plan, _ = _decode(plan)
    except HIAProgramRejected as exc:
        raise MachinePlanRejected("E_HIA_MACHINE_PLAN: plan requires bounded plain JSON data") from exc
    schema = plan.get("schema")
    _require(type(schema) is str and schema in {LAYOUT_V1, MACHINE_V2, MACHINE_V3, MACHINE_V4}, "unknown plan schema")
    fields = {"schema", "core_sha256", "block_order"}
    if schema in {MACHINE_V2, MACHINE_V3, MACHINE_V4}:
        fields |= {"function_order", "scratch_registers", "instruction_selection", "function_alignment"}
    if schema in {MACHINE_V3, MACHINE_V4}:
        fields.add("value_registers")
    _require(set(plan) == fields, "plan has missing or unreviewed fields")
    _require(plan["core_sha256"] == checked.sha256, "plan belongs to a different Core")
    functions = {fn["name"]: fn for fn in checked.as_dict()["functions"]}
    orders = plan["block_order"]
    _require(type(orders) is dict and (bool(orders) or schema in {MACHINE_V2, MACHINE_V3, MACHINE_V4}), "invalid block order map")
    for name, order in orders.items():
        _require(type(name) is str and name in functions, "unknown function in block order")
        _permutation(order, [block["id"] for block in functions[name]["blocks"]], "block order")
    if schema in {MACHINE_V2, MACHINE_V3, MACHINE_V4}:
        _permutation(plan["function_order"], functions, "function order")
        registers = plan["scratch_registers"]
        _require(type(registers) is dict and set(registers) == SCRATCH
                 and all(type(value) is str for value in registers.values())
                 and set(registers.values()) == SCRATCH,
                 "scratch assignment must bijectively rename only r10 and r11")
        choices = plan["instruction_selection"]
        choice_fields = {"move_immediate", "alu_immediate"} | ({"scalar_select"} if schema in {MACHINE_V3, MACHINE_V4} else set())
        _require(type(choices) is dict and set(choices) == choice_fields,
                 "instruction choices must be explicit and complete")
        _require(type(choices["move_immediate"]) is str and choices["move_immediate"] in MOVE_CHOICES,
                 "unreviewed immediate move encoding")
        _require(type(choices["alu_immediate"]) is str and choices["alu_immediate"] in ALU_CHOICES,
                 "unreviewed immediate arithmetic encoding")
        _require(type(plan["function_alignment"]) is int and plan["function_alignment"] in ALIGNMENTS,
                 "unreviewed function alignment")
        if schema in {MACHINE_V3, MACHINE_V4}:
            _require(type(choices["scalar_select"]) is str and choices["scalar_select"] in SELECT_CHOICES,
                     "unreviewed scalar select encoding")
            if schema == MACHINE_V4:
                register_assignment_witness(checked, plan["value_registers"], allow_leaf_registers=True)
            else:
                register_assignment_witness(checked, plan["value_registers"])
    return plan  # This exact detached snapshot was checked and is emitted.


def _reference_code_options(plan):
    if plan is None or plan["schema"] == LAYOUT_V1:
        return {}
    return {"scratch_registers": dict(plan["scratch_registers"]),
            "move_immediate": plan["instruction_selection"]["move_immediate"],
            "alu_immediate": plan["instruction_selection"]["alu_immediate"]}


def _reference_preservation_checks(plan, checked=None):
    """Separate claims, with no promotion to whole-backend refinement."""
    checks = [{"choice": "block_layout", "checked": True,
               "rule": "exact block permutations; every terminator transfers explicitly"}]
    if plan["schema"] in {MACHINE_V2, MACHINE_V3, MACHINE_V4}:
        checks.extend([
            {"choice": "scratch_registers", "checked": True,
             "rule": "bijection on explicit caller-clobbered r10/r11; implicit ISA and ABI registers fixed"},
            {"choice": "instruction_selection", "checked": True,
             "rule": "mov32 only for exact u32; imm8 only for exact sign-extended i8; flags preserved"},
            {"choice": "function_layout", "checked": True,
             "rule": "exact function permutation, symbol relocations retained, NOPs only between functions"},
        ])
    if plan["schema"] in {MACHINE_V3, MACHINE_V4}:
        _require(checked is not None and plan["core_sha256"] == checked.sha256,
                 "register preservation witness requires the exact verified Core")
        checks.extend([
            {"choice": "value_registers", "checked": True,
             "rule": "noninterfering scalar lifetimes; staged edge copies; all used callee-saved registers saved/restored",
             "witness": (register_assignment_witness(checked, plan["value_registers"], allow_leaf_registers=True)
                         if plan["schema"] == MACHINE_V4 else register_assignment_witness(checked, plan["value_registers"]))},
            {"choice": "scalar_select", "checked": True,
             "rule": "explicit branch or register-only CMOV; all operands already defined scalars; MOV loads preserve TEST flags"},
        ])
        if plan["schema"] == MACHINE_V4:
            checks.append({"choice": "caller_clobbered_leaf_values", "checked": True,
                "rule": "r8/r9 only; exact leaf opcode inventory; no returning call; no implicit r8/r9 scratch; scalar values; inclusive lifetimes; staged entry/edge copies",
                "trap_rule": "all trap paths call abort then UD2 and have no returning continuation"})
    return checks


# Operator-only selection.  No field of the caller's plan selects an image.
def _native_owner():
    import os
    from .hia_machine_plan_native import SELECTOR, installed_machine_plan
    captured = _NATIVE_OWNER.get()
    if captured is not None:
        return captured
    path = os.environ.get(SELECTOR)
    return installed_machine_plan(path) if path else None


def validate_plan(checked, plan):
    selected = _native_owner()
    if selected is None:
        return _reference_validate_plan(checked, plan)
    token = _NATIVE_OWNER.set(selected)
    try:
        return selected.validate(checked, plan)
    finally:
        _NATIVE_OWNER.reset(token)


def register_assignment_witness(checked, assignments, *, allow_leaf_registers=False):
    selected = _native_owner()
    if selected is None:
        return _reference_register_assignment_witness(
            checked, assignments, allow_leaf_registers=allow_leaf_registers)
    token = _NATIVE_OWNER.set(selected)
    try:
        return selected.witness(checked, assignments, allow_leaf_registers=allow_leaf_registers)
    finally:
        _NATIVE_OWNER.reset(token)


def code_options(plan):
    selected = _native_owner()
    if selected is None:
        return _reference_code_options(plan)
    token = _NATIVE_OWNER.set(selected)
    try:
        return selected.code_options(plan)
    finally:
        _NATIVE_OWNER.reset(token)


def preservation_checks(plan, checked=None):
    selected = _native_owner()
    if selected is None:
        return _reference_preservation_checks(plan, checked)
    token = _NATIVE_OWNER.set(selected)
    try:
        return selected.preservation_checks(plan, checked)
    finally:
        _NATIVE_OWNER.reset(token)


# Used only to distinguish the original public continuation from a caller's
# explicitly replaced hook at the HIA-issued GLOBAL observation boundary.
_NATIVE_PUBLIC_WITNESS = register_assignment_witness


def native_implementation_identity():
    selected = _native_owner()
    if selected is None:
        return b''
    return (b'machine-plan-v2\0' + selected.image_sha256.encode() + b'\0' +
            selected.admitted_source_sha256.encode())
