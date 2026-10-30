"""Untrusted fixed-polynomial CRC byte proposals in the existing scalar Core.

The captured Filecheck byte update remains the proof source.  A guarded fast
body replaces its eight dependent bit steps with eight parallel contributions
and a balanced XOR tree.  Every other polynomial executes an unchanged clone
of the original kernel.  Generated constants and this algebraic explanation
grant no authority: every consumer must freshly prove translation and selected
LLVM, then use the existing finite native execution gate.
"""
from __future__ import annotations

import copy

from .hia_crc_kernel import POLYNOMIALS, candidates as legacy_candidates, kernel
from .hia_finite_context import checked_profile
from .hia_specialization import _clone_blocks, _fresh


LABELS = ("baseline", "ieee_guard", "castagnoli_guard", "linear_ieee",
          "linear_castagnoli", "linear_dual")


def _op(name, args, out, typ="u32", **attrs):
    return {"op": name, "args": list(args), "out": [{"name": out, "type": typ}],
            "attrs": attrs}


def basis(polynomial):
    """Propose F_p(1 << i), i=0..7; never substitute this into the proof source.

    After eight steps, the highest input-byte bit contributes exactly p.  Each
    lower input bit advances that contribution once more.  All intermediates
    are unsigned 32-bit values.  This finite generator is not a proof checker.
    """
    if type(polynomial) is not int or not 0 <= polynomial < 2**32:
        raise ValueError("exact u32 polynomial required")
    values = [polynomial]
    for _ in range(7):
        value = values[-1]
        values.append((value >> 1) ^ (polynomial if value & 1 else 0))
    return tuple(reversed(values))


def _linear_block(polynomial, names, block_id, *, shared_basis=False):
    """Only pure u32/Boolean operations; constant shift count is exactly eight."""
    params = [{"name": names("state"), "type": "u32"}]
    params += ([{"name": names(f"basis_arg_{i}"), "type": "u32"} for i in range(8)]
               if shared_basis else [{"name": names("polynomial"), "type": "u32"}])
    state = params[0]["name"]
    zero, eight, upper = (names(part) for part in ("zero", "eight", "upper"))
    ops = [_op("const", [], zero, value=0), _op("const", [], eight, value=8),
           _op("int.shr.checked", [state, eight], upper)]
    contributions = [upper]
    values = (None,) * 8 if shared_basis else basis(polynomial)
    for index, value in enumerate(values):
        bit, low, odd, contribution = (
            names(f"{part}_{index}") for part in ("bit", "low", "odd", "part"))
        constant = params[index + 1]["name"] if shared_basis else names(f"basis_{index}")
        ops.extend([
            _op("const", [], bit, value=1 << index),
            _op("bit.and", [state, bit], low),
            _op("compare.ne", [low, zero], odd, "bool"),
        ])
        if not shared_basis:
            ops.append(_op("const", [], constant, value=value))
        ops.append(_op("select", [odd, constant, zero], contribution))
        contributions.append(contribution)
    level = 0
    while len(contributions) > 1:
        combined = []
        for index in range(0, len(contributions) - 1, 2):
            out = names(f"xor_{level}_{index // 2}")
            ops.append(_op("bit.xor", contributions[index:index + 2], out))
            combined.append(out)
        if len(contributions) % 2:
            combined.append(contributions[-1])
        contributions = combined
        level += 1
    return {"id": block_id, "params": params, "ops": ops,
            "term": {"op": "ret", "values": contributions}}


def _guarded(polynomials):
    document = kernel()
    fn = document["functions"][0]
    used_values = {p["name"] for p in fn["params"]}
    used_blocks = set()
    generic, generic_entry = _clone_blocks(fn, "crc_original", used_values, used_blocks)
    guard_ids = [_fresh("crc_guard", used_blocks) for _ in polynomials]
    shared_basis = len(polynomials) > 1
    fast_ids = [_fresh("crc_linear", used_blocks) for _ in range(1 if shared_basis else len(polynomials))]
    fast, guards = [], []
    names = lambda stem: _fresh("crc_linear_" + stem, used_values)
    if shared_basis:
        fast.append(_linear_block(None, names, fast_ids[0], shared_basis=True))
    for index, polynomial in enumerate(polynomials):
        if not shared_basis:
            fast.append(_linear_block(polynomial, names, fast_ids[index]))
        params = copy.deepcopy(fn["params"]) if index == 0 else [
            {"name": _fresh("crc_guard_arg", used_values), "type": "u32"} for _ in range(2)]
        constant = _fresh("crc_polynomial", used_values)
        condition = _fresh("crc_matches", used_values)
        operations = [
            _op("const", [], constant, value=polynomial),
            _op("compare.eq", [params[1]["name"], constant], condition, "bool"),
        ]
        fast_args = [params[0]["name"], constant]
        if shared_basis:
            fast_args = [params[0]["name"]]
            for basis_value in basis(polynomial):
                argument = _fresh("crc_basis_argument", used_values)
                operations.append(_op("const", [], argument, value=basis_value))
                fast_args.append(argument)
        guards.append({"id": guard_ids[index], "params": params, "ops": operations,
            "term": {"op": "branch", "cond": condition,
            "then": {"target": fast_ids[0] if shared_basis else fast_ids[index], "args": fast_args},
            "else": {"target": guard_ids[index + 1] if index + 1 < len(polynomials) else generic_entry,
                     "args": [p["name"] for p in params]}}})
    fn.update(entry=guard_ids[0], blocks=[*guards, *generic, *fast])
    return checked_profile(document).as_dict()


def candidates():
    """All six candidates, including the three unchanged legacy controls.

    The complete pool is available to any fixed or dynamic policy.  In
    particular, a dynamic policy cannot exclude the static dual-polynomial
    candidate from its baseline comparison.
    """
    result = legacy_candidates()
    result.update(linear_ieee=_guarded((POLYNOMIALS[0],)),
                  linear_castagnoli=_guarded((POLYNOMIALS[1],)),
                  linear_dual=_guarded(POLYNOMIALS))
    assert tuple(result) == LABELS
    for document in result.values():
        checked_profile(document)
    return result
