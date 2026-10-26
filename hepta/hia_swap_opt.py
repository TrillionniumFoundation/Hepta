"""Optional, verifier-gated four-operation byte-swap peephole into HIA v4."""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from .hia_program import SCHEMA_V4, VerifiedProgram, verify_program


@dataclass(frozen=True)
class ByteSwapOptimization:
    program: VerifiedProgram
    before_sha256: str
    after_sha256: str
    replacements: int
    claims: dict


def _uses(function):
    used = Counter()
    for block in function["blocks"]:
        for op in block["ops"]:
            used.update(op["args"])
        term = block["term"]
        if term["op"] == "ret":
            used.update(term["values"])
        elif term["op"] == "jump":
            used.update(term["args"])
        elif term["op"] == "branch":
            used[term["cond"]] += 1
            used.update(term["then"]["args"])
            used.update(term["else"]["args"])
    return used


def _match(a, b, c, d, uses):
    if [item["op"] for item in (a, b, c, d)] != [
            "buffer.load", "buffer.load", "buffer.store", "buffer.store"]:
        return None
    if not all(item["attrs"] == {} for item in (a, b, c, d)):
        return None
    if len(a["out"]) != 1 or len(b["out"]) != 1:
        return None
    first, second = a["out"][0], b["out"][0]
    if first["type"] != "u8" or second["type"] != "u8":
        return None
    # Neither loaded SSA value may escape into other operations or CFG edges.
    if uses[first["name"]] != 1 or uses[second["name"]] != 1:
        return None
    loan, left = a["args"]
    other_loan, right = b["args"]
    if loan != other_loan or c["args"] != [loan, left, second["name"]] or d["args"] != [loan, right, first["name"]]:
        return None
    if c["out"] or d["out"]:
        return None
    return {"op": "buffer.swap", "args": [loan, left, right], "out": [], "attrs": {}}


def rewrite_byte_swap(program) -> ByteSwapOptimization:
    """Rewrite only a proven finite local pattern; reverify the entire result.

    This accepts HIA v1-v4, preserves all interfaces/effects/other operations,
    and has no reliance on caller-supplied optimization/equivalence claims.
    It does not certify LLVM/refinement or unspecified source C/C++ behavior.
    """
    base = verify_program(program)
    data = base.as_dict()
    replacements = 0
    for function in data["functions"]:
        uses = _uses(function)
        for block in function["blocks"]:
            original = block["ops"]
            result = []
            index = 0
            while index < len(original):
                candidate = (_match(*original[index:index + 4], uses)
                             if index + 4 <= len(original) else None)
                if candidate is None:
                    result.append(original[index])
                    index += 1
                else:
                    result.append(candidate)
                    index += 4
                    replacements += 1
            block["ops"] = result
    if replacements:
        data["schema"] = SCHEMA_V4
        checked = verify_program(data)
    else:
        checked = base
    return ByteSwapOptimization(
        program=checked, before_sha256=base.sha256,
        after_sha256=checked.sha256, replacements=replacements,
        claims={"whole_program_reverified": True,
                "unsafe_pointer_aliasing_inferred": False,
                "source_equivalence_proved": False,
                "backend_refinement_proved": False,
                "whole_language_soundness_proved": False},
    )
