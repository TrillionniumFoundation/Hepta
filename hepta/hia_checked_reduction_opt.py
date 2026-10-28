"""Reverified closed form for an exact unsigned checked-add counting loop.

The rule is deliberately structural. It does not accept annotations saying a
loop is pure or its operands are invariant. It checks every operation, incoming
edge and carried value, then re-verifies the complete resulting Core program.
"""
from __future__ import annotations

from dataclasses import dataclass

from .hia_program import HIAProgramRejected, VerifiedProgram, verify_program
from .hia_schema import PRIMITIVE_SCHEMAS


PASS_ID = "checked-unsigned-reduction.v1"
_UNSIGNED = frozenset({"u8", "u16", "u32", "u64", "usize"})


@dataclass(frozen=True)
class CheckedReductionOptimization:
    program: VerifiedProgram
    before_sha256: str
    after_sha256: str
    replacements: int
    claims: dict


def _edges(block):
    term = block["term"]
    if term["op"] == "jump":
        yield term
    elif term["op"] == "branch":
        yield term["then"]
        yield term["else"]


def _output(operation, typ):
    if len(operation["out"]) == 1 and operation["out"][0]["type"] == typ:
        return operation["out"][0]["name"]
    return None


def _match(function, header):
    if header["id"] == function["entry"] or len(header["ops"]) != 1:
        return None
    compare = header["ops"][0]
    if compare["op"] != "compare.lt" or compare["attrs"]:
        return None
    condition = _output(compare, "bool")
    names = [param["name"] for param in header["params"]]
    types = [param["type"] for param in header["params"]]
    index, count = compare["args"]
    if not condition or index not in names or count not in names or index == count:
        return None
    index_slot, count_slot = names.index(index), names.index(count)
    typ = types[index_slot]
    if typ not in _UNSIGNED or types[count_slot] != typ:
        return None
    term = header["term"]
    if (term["op"] != "branch" or term["cond"] != condition
            or term["then"]["args"] != names or condition in term["else"]["args"]):
        return None
    blocks = {block["id"]: block for block in function["blocks"]}
    body = blocks[term["then"]["target"]]
    if (body["id"] in {header["id"], function["entry"]}
            or term["else"]["target"] in {header["id"], body["id"]}
            or [param["type"] for param in body["params"]] != types
            or len(body["ops"]) != 3):
        return None
    constants = [op for op in body["ops"] if op["op"] == "const"]
    adds = [op for op in body["ops"] if op["op"] == "int.add.checked"]
    if len(constants) != 1 or len(adds) != 2:
        return None
    one = constants[0]
    one_name = _output(one, typ)
    if not one_name or one["args"] or one["attrs"] != {"value": 1}:
        return None
    body_names = [param["name"] for param in body["params"]]
    increments = [op for op in adds if op["args"] == [body_names[index_slot], one_name]]
    if len(increments) != 1:
        return None
    increment = increments[0]
    reduction = next(op for op in adds if op is not increment)
    next_index, next_sum = _output(increment, typ), _output(reduction, typ)
    if not next_index or not next_sum or increment["attrs"] or reduction["attrs"]:
        return None
    accumulator, value = reduction["args"]
    if accumulator not in body_names or value not in body_names:
        return None
    sum_slot, value_slot = body_names.index(accumulator), body_names.index(value)
    # Count and value may be the same invariant. Neither may be the changing
    # index or accumulator. All four arithmetic values have the exact same type.
    if (sum_slot == index_slot or count_slot == sum_slot
            or value_slot in {sum_slot, index_slot}
            or types[sum_slot] != typ or types[value_slot] != typ):
        return None
    expected_back = list(body_names)
    expected_back[index_slot], expected_back[sum_slot] = next_index, next_sum
    if body["term"] != {"op": "jump", "target": header["id"], "args": expected_back}:
        return None
    incoming_header, incoming_body = [], []
    for predecessor in function["blocks"]:
        for edge in _edges(predecessor):
            if edge["target"] == header["id"]:
                incoming_header.append((predecessor, edge))
            if edge["target"] == body["id"]:
                incoming_body.append(predecessor["id"])
    if len(incoming_header) != 2 or incoming_body != [header["id"]]:
        return None
    preheaders = [(block, edge) for block, edge in incoming_header if block["id"] != body["id"]]
    if len(preheaders) != 1:
        return None
    preheader, edge = preheaders[0]
    if preheader["term"]["op"] != "jump" or edge is not preheader["term"]:
        return None
    zeros = {_output(op, typ) for op in preheader["ops"]
             if op["op"] == "const" and not op["args"] and op["attrs"] == {"value": 0}}
    if edge["args"][index_slot] not in zeros or edge["args"][sum_slot] not in zeros:
        return None
    return body["id"], typ, index, count, names[sum_slot], names[value_slot]


def _fresh_result(function):
    names = {param["name"] for block in function["blocks"] for param in block["params"]}
    names.update(param["name"] for block in function["blocks"]
                 for op in block["ops"] for param in op["out"])
    serial = 0
    while "hia_reduction_result_" + str(serial) in names:
        serial += 1
    return "hia_reduction_result_" + str(serial)


def rewrite_checked_unsigned_reduction(program) -> CheckedReductionOptimization:
    """Replace sum=0; i=0; while i<count: sum+=value; i+=1 by count*value.

    All arithmetic is checked and unsigned, at one identical Core type. Partial
    sums are nondecreasing: a checked addition traps iff the final mathematical
    product exceeds the type maximum. The index cannot overflow while i<count.
    No resource event, read, write, call or other trap occurs inside the matched
    loop. Other carried values and all outside operations are retained exactly.
    On success the final index is count, including the count=0 case.

    This is an implementation argument plus executable controls, not a machine-
    checked universal refinement proof. Instruction budgets and host scheduling
    are explicitly outside this optional transformation's equivalence contract.
    """
    before = verify_program(program)
    data = before.as_dict()
    if before.structured_bytes is not None or data["schema"] not in PRIMITIVE_SCHEMAS:
        raise HIAProgramRejected("checked reduction requires primitive Core identity", "E_HIA_OPT_PROFILE")
    replacements = 0
    for function in data["functions"]:
        for header in tuple(function["blocks"]):
            if header not in function["blocks"]:
                continue
            match = _match(function, header)
            if match is None:
                continue
            body_id, typ, index, count, accumulator, value = match
            result = _fresh_result(function)
            edge = header["term"]["else"]
            substitute = {index: count, accumulator: result}
            header["ops"] = [{"op": "int.mul.checked", "args": [count, value],
                              "out": [{"name": result, "type": typ}], "attrs": {}}]
            header["term"] = {"op": "jump", "target": edge["target"],
                              "args": [substitute.get(name, name) for name in edge["args"]]}
            function["blocks"] = [block for block in function["blocks"] if block["id"] != body_id]
            replacements += 1
    after = verify_program(data) if replacements else before
    return CheckedReductionOptimization(after, before.sha256, after.sha256, replacements, {
        "whole_program_reverified": True,
        "same_unsigned_type_zero_initialization_and_invariants_checked": True,
        "loop_has_no_resource_events_or_memory_effects": True,
        "owner_loan_transition_sequence_preserved": True,
        "checked_overflow_semantics_preserved": True,
        "wire_schema_preserved": True,
        "instruction_step_budget_equivalence": False,
        "host_interruption_equivalence": False,
        "host_allocation_failure_equivalence": False,
        "formal_backend_refinement_proved": False,
        "whole_language_soundness_proved": False,
        "real_application_performance_proved": False,
    })
