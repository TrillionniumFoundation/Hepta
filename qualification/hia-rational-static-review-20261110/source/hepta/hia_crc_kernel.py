"""Finite CRC bit-step proposals tied to the captured application function.

``calculate(state ^ byte, polynomial)`` performs one reflected CRC byte step.
The two polynomial specializations retain the complete generic fallback.  The
source bridge is checked against the actual captured C-to-HIA function using
the independent bounded-unroll validator, rather than trusting this generator.
"""
from __future__ import annotations

import copy

from .hia_bounded_unroll import validate_bounded_translation
from .hia_program import HIAProgramRejected, verify_program
from .hia_specialization import propose_guarded_specializations

POLYNOMIALS = (0xEDB88320, 0x82F63B78)


def _op(name, args, out, typ="u32", **attrs):
    return {"op": name, "args": list(args), "out": [{"name": out, "type": typ}], "attrs": attrs}


def _steps(state, polynomial, prefix):
    one, zero = prefix + "one", prefix + "zero"
    operations = [_op("const", [], one, value=1), _op("const", [], zero, value=0)]
    for index in range(8):
        stem = prefix + str(index) + "_"
        low, odd, shifted, mixed, value = (stem + part for part in ("low", "odd", "shift", "mix", "value"))
        operations += [_op("bit.and", [state, one], low),
            _op("compare.ne", [low, zero], odd, "bool"),
            _op("int.shr.checked", [state, one], shifted),
            _op("bit.xor", [shifted, polynomial], mixed),
            _op("select", [odd, mixed, shifted], value)]
        state = value
    return operations, state


def kernel():
    params = [{"name": "state", "type": "u32"}, {"name": "polynomial", "type": "u32"}]
    ops, answer = _steps("state", "polynomial", "crc_")
    fn = {"name": "calculate", "params": params, "returns": ["u32"], "effects": ["trap"],
          "entry": "entry", "blocks": [{"id": "entry", "params": params, "ops": ops,
                                        "term": {"op": "ret", "values": [answer]}}]}
    return verify_program({"schema": "hepta.hia.program.v1", "module": "crc_bit_kernel",
                           "functions": [fn]}).as_dict()


def candidates():
    proposals = propose_guarded_specializations(kernel(), function="calculate",
        assumptions=[{"parameter": "polynomial", "value": p} for p in POLYNOMIALS])
    return {"baseline": kernel(), "ieee_guard": proposals[0]["program"],
            "castagnoli_guard": proposals[1]["program"]}


def step(state, polynomial):
    """Independent integer oracle; no Core generator, evaluator or LLVM calls."""
    if any(type(x) is not int or not 0 <= x < 2**32 for x in (state, polynomial)):
        raise ValueError("exact u32 arguments required")
    for _ in range(8):
        state = (state >> 1) ^ (polynomial if state & 1 else 0)
    return state


def source_wrapper(document, *, function="c_checksum_byte", kernel_document=None):
    """Propose a straight-line replacement; admission requires a fresh bridge."""
    original = verify_program(document)
    value = original.as_dict()
    fn = next((f for f in value["functions"] if f["name"] == function), None)
    if (fn is None or [p["type"] for p in fn["params"]] != ["u32", "u8", "u32"]
            or fn["returns"] != ["u32"] or function not in original.scalar_entrypoints):
        raise HIAProgramRejected("CRC bridge requires public (u32,u8,u32)->u32", "E_HIA_CRC_PROFILE")
    state, byte, polynomial = (p["name"] for p in fn["params"])
    ops = [_op("int.cast", [byte], "crc_byte", mode="wrap"),
           _op("bit.xor", [state, "crc_byte"], "crc_combined")]
    # Inline the exact baseline Core that the bank will compile. Do not merely
    # regenerate a similar-looking loop body: a changed baseline must change
    # this proof obligation even if the CRC proposal helper remains unchanged.
    baseline = verify_program(kernel() if kernel_document is None else kernel_document)
    functions = baseline.as_dict()["functions"]
    if (len(functions) != 1 or functions[0]["name"] != "calculate"
            or [p["type"] for p in functions[0]["params"]] != ["u32", "u32"]
            or functions[0]["returns"] != ["u32"] or len(functions[0]["blocks"]) != 1
            or set(functions[0]["effects"]) - {"trap"}
            or functions[0]["blocks"][0]["term"]["op"] != "ret"):
        raise HIAProgramRejected("CRC bridge requires the exact one-block scalar baseline", "E_HIA_CRC_PROFILE")
    block = functions[0]["blocks"][0]
    names = {p["name"]: argument for p, argument in zip(functions[0]["params"], ("crc_combined", polynomial))}
    names.update({p["name"]: f"crc_kernel_{index}" for index, p in
                  enumerate(p for op in block["ops"] for p in op["out"])})
    body = copy.deepcopy(block["ops"])
    for op in body:
        op["args"] = [names[name] for name in op["args"]]
        for out in op["out"]:
            out["name"] = names[out["name"]]
    answer = names[block["term"]["values"][0]]
    fn.update(entry="crc_entry", effects=["trap"], blocks=[{"id": "crc_entry",
        "params": fn["params"], "ops": ops + body,
        "term": {"op": "ret", "values": [answer]}}])
    return verify_program(value).as_dict()


def validate_source_bridge(document, *, function="c_checksum_byte", kernel_document=None, timeout_ms=10000):
    """Freshly prove finite termination and the actual captured Core relation."""
    baseline = verify_program(kernel() if kernel_document is None else kernel_document)
    receipt = validate_bounded_translation(document, source_wrapper(document, function=function, kernel_document=baseline),
        function=function, max_backedges=8, timeout_ms=timeout_ms)
    receipt["kernel_sha256"] = baseline.sha256
    return receipt
