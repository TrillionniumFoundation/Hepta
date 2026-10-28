"""Reverified replacement of one closed, full-view byte-store loop.

The matcher recognizes the loop's actual Core dataflow. It accepts no producer
annotation, assumed bounds, arbitrary loop invariant, or model proof claim.
Step limits, host interruption and host allocation failures are not equivalence
claims; the registered rule preserves the declared primitive Core behavior.
"""
from __future__ import annotations

from dataclasses import dataclass

from .hia_program import HIAProgramRejected, VerifiedProgram, verify_program
from .hia_schema import SCHEMA, SCHEMA_V2, SCHEMA_V3, SCHEMA_V4, SCHEMA_V5, SCHEMA_V6


PASS_ID = "full-view-fill-loop.v1"
_SCHEMAS = frozenset((SCHEMA, SCHEMA_V2, SCHEMA_V3, SCHEMA_V4, SCHEMA_V5, SCHEMA_V6))


@dataclass(frozen=True)
class FillLoopOptimization:
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


def _one_output(operation, kind):
    if len(operation["out"]) == 1 and operation["out"][0]["type"] == kind:
        return operation["out"][0]["name"]
    return None


def _match(function, header):
    # Checking the complete two-block body is intentional: an extra read,
    # checked arithmetic expression, call or resource event changes the rule.
    if header["id"] == function["entry"] or len(header["ops"]) != 2:
        return None
    length, compare = header["ops"]
    if (length["op"] != "buffer.len" or compare["op"] != "compare.lt"
            or length["attrs"] or compare["attrs"]):
        return None
    extent = _one_output(length, "usize")
    condition = _one_output(compare, "bool")
    params = header["params"]
    names = [param["name"] for param in params]
    types = [param["type"] for param in params]
    view = length["args"][0]
    index, bound = compare["args"]
    if (not extent or not condition or bound != extent
            or view not in names or index not in names):
        return None
    view_slot, index_slot = names.index(view), names.index(index)
    if types[view_slot] != "mutbuf" or types[index_slot] != "usize":
        return None
    term = header["term"]
    if (term["op"] != "branch" or term["cond"] != condition
            or term["then"]["args"] != names
            or index in term["else"]["args"] or condition in term["else"]["args"]):
        return None
    blocks = {block["id"]: block for block in function["blocks"]}
    body = blocks[term["then"]["target"]]
    if (body["id"] in {header["id"], function["entry"]}
            or term["else"]["target"] in {header["id"], body["id"]}
            or [param["type"] for param in body["params"]] != types
            or len(body["ops"]) != 3):
        return None
    by_opcode = {operation["op"]: operation for operation in body["ops"]}
    if set(by_opcode) != {"const", "buffer.store", "int.add.checked"}:
        return None
    one, store, add = (by_opcode[name] for name in ("const", "buffer.store", "int.add.checked"))
    one_name, next_index = _one_output(one, "usize"), _one_output(add, "usize")
    body_names = [param["name"] for param in body["params"]]
    if (one["args"] or one["attrs"] != {"value": 1}
            or not one_name or not next_index or store["attrs"] or store["out"] or add["attrs"]
            or store["args"][:2] != [body_names[view_slot], body_names[index_slot]]
            or store["args"][2] not in body_names
            or add["args"] != [body_names[index_slot], one_name]):
        return None
    value_slot = body_names.index(store["args"][2])
    if types[value_slot] != "u8":
        return None
    back = body["term"]
    expected_back = list(body_names)
    expected_back[index_slot] = next_index
    if back != {"op": "jump", "target": header["id"], "args": expected_back}:
        return None
    incoming_header, incoming_body = [], []
    for predecessor in function["blocks"]:
        for edge in _edges(predecessor):
            if edge["target"] == header["id"]:
                incoming_header.append((predecessor, edge))
            if edge["target"] == body["id"]:
                incoming_body.append(predecessor["id"])
    if incoming_body != [header["id"]] or len(incoming_header) != 2:
        return None
    preheaders = [(predecessor, edge) for predecessor, edge in incoming_header
                  if predecessor["id"] != body["id"]]
    if len(preheaders) != 1:
        return None
    preheader, edge = preheaders[0]
    if preheader["term"]["op"] != "jump" or edge is not preheader["term"]:
        return None
    initial_index = edge["args"][index_slot]
    if not any(operation == {"op": "const", "args": [],
                "out": [{"name": initial_index, "type": "usize"}], "attrs": {"value": 0}}
               for operation in preheader["ops"]):
        return None
    return body["id"], names[value_slot]


def rewrite_full_view_fill_loop(program) -> FillLoopOptimization:
    """Recognize zero..len(the same view), unit stride, invariant u8 stores.

    Every loop-carried value other than the index is unchanged. The exclusive
    loan and owner pass through without starting/ending resources. The unsigned
    increment cannot overflow while index < length. The exact view length is
    obtained in the header, so neither a caller-supplied limit nor a different
    owner's extent can justify replacing an out-of-bounds loop with a fill.
    """
    baseline = verify_program(program)
    data = baseline.as_dict()
    if baseline.structured_bytes is not None or data["schema"] not in _SCHEMAS:
        raise HIAProgramRejected("fill-loop rewrite requires primitive v1-v6", "E_HIA_OPT_PROFILE")
    replacements = 0
    for function in data["functions"]:
        for header in tuple(function["blocks"]):
            if header not in function["blocks"]:
                continue
            match = _match(function, header)
            if match is None:
                continue
            body_id, byte = match
            exit_edge = header["term"]["else"]
            header["ops"] = [header["ops"][0], {
                "op": "buffer.fill", "args": [header["ops"][0]["args"][0], byte],
                "out": [], "attrs": {},
            }]
            header["term"] = {"op": "jump", "target": exit_edge["target"], "args": exit_edge["args"]}
            function["blocks"] = [block for block in function["blocks"] if block["id"] != body_id]
            replacements += 1
    if replacements:
        if data["schema"] == SCHEMA:
            data["schema"] = SCHEMA_V2
        result = verify_program(data)
    else:
        result = baseline
    return FillLoopOptimization(result, baseline.sha256, result.sha256, replacements, {
        "whole_program_reverified": True,
        "full_view_extent_and_unit_stride_checked": True,
        "owner_loan_transition_sequence_preserved": True,
        "instruction_step_budget_equivalence": False,
        "host_interruption_equivalence": False,
        "host_allocation_failure_equivalence": False,
        "formal_backend_refinement_proved": False,
        "whole_language_soundness_proved": False,
    })
